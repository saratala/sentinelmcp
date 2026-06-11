"""Layer 3 — async output inspection (never blocks the response path).

The agent receives the tool response immediately. A copy is handed to
``inspect_output`` which runs the scan and trips the circuit breaker if a
threat is found. The next call from this session will be blocked.

In production this is dispatched as a Celery task. In this module we expose
the core inspection logic so it can be called directly (e.g. from the Celery
task or from tests) without pulling in the Celery machinery.
"""
from __future__ import annotations

import re
import time
from typing import Any

import structlog

from app.core.circuit_breaker import CircuitBreaker
from app.models.schemas import OutputInspectionResult, ThreatDetail

log = structlog.get_logger(__name__)

# Output-specific injection patterns (supplement schema-layer patterns).
_OUTPUT_PATTERNS: list[tuple[str, "re.Pattern[str]"]] = [
    ("output_exfiltration_url",
     re.compile(
         r"(send|post|upload|exfiltrate|forward)\s+.{0,80}https?://\S+",
         re.IGNORECASE | re.DOTALL,
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
    ("output_hidden_instruction",
     re.compile(
         r"(hidden|secret|silent|invisible)\s+(instruction|command|action|step)",
         re.IGNORECASE,
     )),
]

MAX_OUTPUT_BYTES = 1_048_576  # 1 MB — truncate before scanning


def _scan_output(text: str) -> list[ThreatDetail]:
    """Scan output text for injection patterns. Returns a list of threats."""
    threats: list[ThreatDetail] = []
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
    return threats


async def inspect_output(
    session_id: str,
    tool_name: str,
    output: Any,
    circuit_breaker: CircuitBreaker,
) -> OutputInspectionResult:
    """Inspect tool output and trip the circuit breaker if a threat is found.

    This is the hot function called by the Celery task. It must never be
    awaited on the response path — always dispatch asynchronously.
    """
    t0 = time.perf_counter()

    # Coerce output to a string for pattern matching.
    if isinstance(output, str):
        text = output
    else:
        import json
        try:
            text = json.dumps(output, default=str)
        except Exception:
            text = str(output)

    # Truncate to prevent runaway scan time on huge payloads.
    if len(text.encode("utf-8")) > MAX_OUTPUT_BYTES:
        text = text[:MAX_OUTPUT_BYTES]

    threats = _scan_output(text)

    if threats:
        reason = f"OUTPUT_INJECTION:{tool_name}:{threats[0].pattern}"
        await circuit_breaker.trip(session_id, reason)
        log.warning(
            "output_injection_detected",
            session=session_id, tool=tool_name,
            threats=[t.model_dump() for t in threats],
        )

    result = OutputInspectionResult(
        session_id=session_id,
        tool_name=tool_name,
        passed=not threats,
        threats=threats,
        circuit_tripped=bool(threats),
        latency_ms=round((time.perf_counter() - t0) * 1000, 3),
    )
    return result
