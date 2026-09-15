"""Layer 3 — synchronous output inspection (blocks the response path).

Every tool response is scanned BEFORE being returned to the agent.
If a threat is found, the response is redacted and the session circuit
breaker is tripped. The agent receives a safe, sanitised response — never
the raw PII or injected payload.

Redaction rules:
  PII patterns  → [REDACTED:pii_credit_card], [REDACTED:pii_ssn], etc.
  Injection     → [BLOCKED:output_injection] replaces the matched phrase
"""
from __future__ import annotations

import asyncio
import re
import time
from typing import Any

import structlog

from app.config import settings
from app.core.circuit_breaker import CircuitBreaker
from app.detection.patterns import detect_pii
from app.models.schemas import OutputInspectionResult, ThreatDetail

log = structlog.get_logger(__name__)

# Grey-zone lexical signals: an output that mentions an imperative action,
# a URL, an email, or credentials but did NOT hard-match a deterministic
# pattern is "clean-but-suspicious" — a candidate for async LLM adjudication.
_GREY_ZONE = re.compile(
    r"\b(send|forward|share|transfer|wire|withdraw|deposit|pay|unlock|delete|"
    r"remove|grant|revoke|disable|execute|run|export|upload|email|ignore|"
    r"disregard|override|reveal|leak)\b|https?://|@[a-z0-9.-]+\.[a-z]{2,}|"
    r"\b(password|api[_\s]?key|token|secret|credential)\b",
    re.IGNORECASE,
)

# Hold references to fire-and-forget escalation tasks so they aren't GC'd.
_escalation_tasks: set = set()


def _output_grey_zone(text: str) -> bool:
    """True if an output is clean by patterns but lexically suspicious."""
    return len(text) >= 12 and bool(_GREY_ZONE.search(text))

# Output-specific injection patterns (supplement schema-layer patterns).
_OUTPUT_PATTERNS: list[tuple[str, "re.Pattern[str]"]] = [
    ("output_exfiltration_url",
     re.compile(
         # Non-DOTALL + possessive-safe: pre-check for "http" before running
         # to avoid catastrophic backtracking on inputs with no URL present.
         r"(send|post|upload|exfiltrate|forward)\s+[^\n]{0,80}https?://\S+",
         re.IGNORECASE,
     )),
    ("output_ignore_instructions",
     re.compile(
         r"ignore\s+(all\s+)?(previous|prior|above)\s+instructions?",
         re.IGNORECASE,
     )),
    ("output_credential_leak",
     re.compile(
         r"(password|secret|api[_\s]?key|token|credential)\s*[=:]\s*\S+",
         re.IGNORECASE,
     )),
    ("output_prompt_injection",
     re.compile(
         r"(assistant|system)\s*:\s*(ignore|disregard|forget)",
         re.IGNORECASE,
     )),
    ("output_conceal_action",
     re.compile(
         r"do\s+not\s+(tell|inform|notify|mention)\s+(the\s+)?(user|operator|human)",
         re.IGNORECASE,
     )),
    ("output_email_exfiltration",
     re.compile(
         r"\b(send|email|forward|share)\b[^\n]{0,80}\b(to|at)\b[^\n]{0,40}@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}",
         re.IGNORECASE,
     )),
    ("output_financial_transfer",
     re.compile(
         r"\b(transfer|wire|withdraw|deposit)\b[^\n]{0,60}\b(account|wallet|bitcoin|btc|usd|eur)\b",
         re.IGNORECASE,
     )),
    ("output_hidden_instruction",
     re.compile(
         r"(hidden|secret|silent|invisible)\s+(instruction|command|action|step)",
         re.IGNORECASE,
     )),
]

MAX_OUTPUT_BYTES = 1_048_576  # 1 MB — truncate before scanning


def redact_output(text: str) -> tuple[str, list[ThreatDetail]]:
    """Scan and redact threats from output text.

    Returns (redacted_text, threats). The redacted text is safe to return
    to the agent — all PII and injection payloads are replaced with tags.
    """
    threats = _scan_output(text)
    if not threats:
        return text, []

    redacted = text
    from app.detection.patterns import PII_PATTERNS
    for name, pattern in PII_PATTERNS:
        redacted = pattern.sub(f"[REDACTED:{name}]", redacted)
    for name, pattern in _OUTPUT_PATTERNS:
        redacted = pattern.sub("[BLOCKED:output_injection]", redacted)

    return redacted, threats


def _scan_output(text: str) -> list[ThreatDetail]:
    """Scan output text for injection + PII patterns. Returns a list of threats."""
    threats: list[ThreatDetail] = []

    # Existing injection patterns
    for name, pattern in _OUTPUT_PATTERNS:
        m = pattern.search(text)
        if m:
            threats.append(ThreatDetail(
                tool="output",
                threat_type="OUTPUT_INJECTION",
                pattern=name,
                match=m.group(0).strip()[:200],
                confidence=0.90,
            ))

    # LLM06: PII detection — SSN, credit cards, passwords, AWS keys, etc.
    pii_hit = detect_pii(text)
    if pii_hit:
        threats.append(ThreatDetail(
            tool="output",
            threat_type="SENSITIVE_DISCLOSURE",
            pattern=pii_hit["pattern"],
            match=pii_hit["match"],
            confidence=pii_hit["confidence"],
        ))

    return threats


async def _llm_escalate(
    session_id: str,
    tool_name: str,
    text: str,
    circuit_breaker: CircuitBreaker,
) -> None:
    """Off-path LLM adjudication of a grey-zone output.

    Runs after the (already-returned) response. A positive verdict trips the
    session circuit breaker so the NEXT tool call is blocked — the async-output
    design: the agent is never slowed, but a confirmed threat still stops the
    session before it can act again.
    """
    from app.core.llm_analyzer import classify_injection
    try:
        verdict = await asyncio.wait_for(
            classify_injection(
                text[:2000],
                provider=settings.llm_provider,
                ollama_url=settings.ollama_url,
                ollama_model=settings.ollama_model,
                api_key=settings.anthropic_api_key,
                model=settings.llm_analysis_model,
            ),
            timeout=settings.llm_timeout_secs,
        )
    except Exception:
        return
    if verdict and verdict.get("is_attack"):
        await circuit_breaker.trip(session_id, f"L3-llm:{tool_name}:{verdict.get('attack_type')}")
        log.warning("output_llm_escalation_tripped", session=session_id,
                    tool=tool_name, attack_type=verdict.get("attack_type"),
                    confidence=verdict.get("confidence"), provider=verdict.get("provider"))


async def inspect_output(
    session_id: str,
    tool_name: str,
    output: Any,
    circuit_breaker: CircuitBreaker,
) -> tuple[OutputInspectionResult, str]:
    """Inspect and redact tool output synchronously on the response path.

    Returns (result, safe_output). safe_output has all PII and injection
    payloads replaced with redaction tags — always return this to the agent,
    never the raw output when threats are present.
    """
    t0 = time.perf_counter()

    if isinstance(output, str):
        text = output
    else:
        import json
        try:
            text = json.dumps(output, default=str)
        except Exception:
            text = str(output)

    if len(text.encode("utf-8")) > MAX_OUTPUT_BYTES:
        text = text[:MAX_OUTPUT_BYTES]

    redacted_text, threats = redact_output(text)

    if threats:
        reason = f"L3:{tool_name}:{threats[0].pattern}"
        await circuit_breaker.trip(session_id, reason)
        log.warning(
            "output_threat_redacted",
            session=session_id, tool=tool_name,
            threats=[t.model_dump() for t in threats],
            redacted=redacted_text != text,
        )

    # Grey-zone escalation (opt-in): clean by patterns but lexically suspicious →
    # queue an off-path LLM check that can trip the breaker for the next call.
    # Fire-and-forget so the response path stays sub-millisecond.
    llm_escalated = False
    if (not threats and settings.output_llm_escalation
            and settings.llm_analysis_enabled and _output_grey_zone(text)):
        task = asyncio.create_task(
            _llm_escalate(session_id, tool_name, text, circuit_breaker))
        _escalation_tasks.add(task)
        task.add_done_callback(_escalation_tasks.discard)
        llm_escalated = True
        log.info("output_llm_escalation_queued", session=session_id, tool=tool_name)

    result = OutputInspectionResult(
        session_id=session_id,
        tool_name=tool_name,
        passed=not threats,
        threats=threats,
        circuit_tripped=bool(threats),
        latency_ms=round((time.perf_counter() - t0) * 1000, 3),
        llm_escalated=llm_escalated,
    )
    return result, redacted_text
