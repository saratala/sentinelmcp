"""Regex injection-pattern library used by the schema-layer semantic scan.

These are deterministic heuristics (no LLM in the hot path). They must never
fire on the clean-tool fixtures — see tests/fixtures/clean_tools.json.

Covers OWASP LLM Top 10:
  LLM01 Prompt Injection      — injection_patterns + encoded_injection_patterns
  LLM05 Supply Chain          — used by schema hash-watch + rug pull detection
  LLM06 Sensitive Disclosure  — pii_patterns (output layer)
  LLM08 Excessive Agency      — dangerous_action_patterns (param/output layer)
"""
from __future__ import annotations

import base64
import re
from typing import Optional

# ── LLM01: Prompt injection patterns (schema descriptions) ───────────────────

_RAW_PATTERNS: list[tuple[str, str]] = [
    ("ignore_previous_instructions",
     r"ignore\s+(all\s+)?(previous|prior|above)\s+instructions?"),
    ("exfiltration_url",
     r"(export|send|exfiltrate|upload|post|forward)\s+[^\n]{0,50}(to|at|via)\s+https?://"),
    ("conceal_from_user",
     r"do\s+not\s+(tell|inform|notify|mention)\s+(the\s+)?(user|operator|human)"),
    ("hidden_instruction",
     r"(hidden|secret|silent|invisible)\s+(instruction|command|action|step)"),
    ("covert_destructive_action",
     r"(also|additionally|secretly).{0,30}(delete|drop|wipe|truncate|remove)"),
    ("code_injection",
     r"<[^>]+>.*?(script|eval|exec|system|os\.)"),
    ("system_prompt_extraction",
     r"system\s+prompt\s*(:|is|=)"),
    ("credential_dump",
     r"(read|dump|print|output)\s+(all\s+)?(env|environment|credentials?|tokens?|keys?)"),
    # LLM08: Excessive agency — dangerous direct actions in tool descriptions
    ("dangerous_action_drop_table",
     r"\b(drop|truncate|delete)\s+(table|database|schema|collection)\b"),
    ("dangerous_action_exec",
     r"\b(exec(ute)?|eval|shell|subprocess|os\.system)\s*[\(\[]"),
    ("dangerous_action_privilege",
     # Require a privileged object after grant/revoke so legitimate phrases like
     # "grant a teammate read access" don't false-positive; keep sudo/chmod/setuid.
     # No nested unbounded quantifier — avoids catastrophic backtracking (ReDoS).
     r"\b(grant|revoke)\s+(all\s+)?(privileges?|permissions?|admin(istrator)?|root|superuser)\b|grant\s+all\s+access|\bsudo\b|chmod\s+777|setuid"),
    # IPI: Financial transaction exfiltration (InjecAgent DH gap)
    ("financial_transfer",
     r"\b(transfer|wire|send|withdraw|deposit|pay)\b[^\n]{0,60}\b(account|wallet|bitcoin|btc|usd|eur)\b"),
    # IPI: Email-based data exfiltration (InjecAgent DS gap)
    ("email_exfiltration",
     r"\b(send|email|forward|share)\b[^\n]{0,80}\b(to|at)\b[^\n]{0,40}@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"),
    # IPI: Account security tampering
    ("security_control_disable",
     r"\b(disable|turn\s+off|deactivate|bypass)\b[^\n]{0,40}\b(two.factor|2fa|mfa|authentication|verification)\b"),
    ("credential_share",
     r"\b(share|send|forward|give)\b[^\n]{0,40}\b(password|passwd|credential|token|secret)\b"),
    # IPI: Covert file moves (hidden dirs, tmp)
    ("covert_file_move",
     r"\b(move|copy|cp|mv)\b[^\n]{0,60}\b(\.hidden|\.ssh|/tmp|/var/tmp|/dev/shm)\b"),
]

INJECTION_PATTERNS: list[tuple[str, "re.Pattern[str]"]] = [
    (name, re.compile(pattern, re.IGNORECASE | re.DOTALL))
    for name, pattern in _RAW_PATTERNS
]

# ── LLM01: Encoded / obfuscated injection detection ──────────────────────────
# Attackers encode payloads as base64 or unicode escapes to bypass regex.

_B64_MIN_LEN = 20  # ignore tiny base64 tokens (common in IDs)

def _decode_b64_segments(text: str) -> str:
    """Extract and decode any plausible base64 segments found in text."""
    decoded_parts: list[str] = []
    for token in re.findall(r"[A-Za-z0-9+/]{%d,}={0,2}" % _B64_MIN_LEN, text):
        # Real base64 payloads contain +, /, or = padding; CamelCase identifiers don't.
        if not any(c in token for c in ("+", "/", "=")):
            continue
        try:
            decoded = base64.b64decode(token + "==").decode("utf-8", errors="ignore")
            # Reject binary garbage: require ≥80% printable ASCII to avoid
            # catastrophic backtracking when injection patterns run on the decoded bytes.
            printable = sum(0x20 <= ord(c) < 0x7F for c in decoded)
            if decoded and printable / len(decoded) >= 0.8:
                decoded_parts.append(decoded)
        except Exception:
            pass
    return " ".join(decoded_parts)

def _decode_unicode_escapes(text: str) -> str:
    """Decode \\uXXXX and \\xXX sequences that may hide injection payloads.

    Only transforms text that actually contains backslash-escape sequences. This
    is critical: ``unicode_escape`` mangles ordinary non-ASCII (accented) text
    into ever-changing mojibake, and because the caller recursively re-scans the
    decoded output, that would cause runaway recursion / a DoS hang on any tool
    text containing characters like "é" or "¿". Returning the text unchanged when
    no escapes are present makes the decode idempotent and breaks that loop.
    """
    if "\\u" not in text and "\\x" not in text:
        return text
    try:
        return text.encode("utf-8").decode("unicode_escape", errors="ignore")
    except Exception:
        return text

def detect_encoded_injection(text: str) -> Optional[dict]:
    """Detect injection attempts hidden in base64 or unicode-escaped payloads."""
    # Invisible-Unicode concealment (approval-view fidelity) is checked first —
    # it is the highest-fidelity signal because legitimate tool text never
    # carries tag-block or bidi-override control characters.
    hidden = detect_invisible_unicode(text)
    if hidden:
        return hidden

    b64_decoded = _decode_b64_segments(text)
    if b64_decoded:
        hit = detect_injection(b64_decoded)
        if hit:
            return {**hit, "pattern": f"encoded_b64:{hit['pattern']}", "confidence": 0.88}

    uni_decoded = _decode_unicode_escapes(text)
    if uni_decoded != text:
        hit = detect_injection(uni_decoded)
        if hit:
            return {**hit, "pattern": f"encoded_unicode:{hit['pattern']}", "confidence": 0.85}

    return None


# ── LLM01: Invisible-Unicode / approval-view fidelity detection ───────────────
# The "approval-view fidelity gap": a tool description or output can carry text
# that is INVISIBLE to the human reviewing an approval dialog but is tokenized
# and acted upon by the model. Vectors: the Unicode Tag block (U+E0000–U+E007F,
# which maps ASCII into non-rendering codepoints), zero-width characters, and
# bidirectional overrides. We detect the divergence between the human-rendered
# view and the model-ingested view, decode any hidden instruction, and rescan it.

# Tag block — ASCII smuggled as non-rendering codepoints (U+E0020–U+E007E ↔ 0x20–0x7E).
_TAG_LO, _TAG_HI = 0xE0000, 0xE007F
# Zero-width / invisible format characters.
_ZERO_WIDTH = {0x200B, 0x200C, 0x200D, 0x2060, 0x2061, 0x2062, 0x2063, 0xFEFF, 0x180E}
# Bidirectional overrides — reorder rendering to hide/scramble text.
_BIDI_OVERRIDE = {0x202A, 0x202B, 0x202C, 0x202D, 0x202E, 0x2066, 0x2067, 0x2068, 0x2069}


def _decode_tag_block(text: str) -> str:
    """Decode Unicode Tag-block codepoints back to the ASCII they smuggle."""
    out = []
    for ch in text:
        cp = ord(ch)
        if 0xE0020 <= cp <= 0xE007E:
            out.append(chr(cp - 0xE0000))
        elif cp == 0xE0001:  # language tag / cancel — marks a tag sequence
            continue
    return "".join(out)


def detect_invisible_unicode(text: str) -> Optional[dict]:
    """Detect content concealed from the human approval view via invisible Unicode.

    Returns a hit describing the concealment class and any decoded hidden text.
    If the hidden text itself decodes to a known injection, that is surfaced too.
    Near-zero false positives: legitimate tool descriptions/outputs do not contain
    tag-block, bidi-override, or runs of zero-width characters.
    """
    tag_chars = [c for c in text if _TAG_LO <= ord(c) <= _TAG_HI]
    if tag_chars:
        hidden_text = _decode_tag_block(text)
        result = {
            "pattern": "invisible_unicode_tag_block",
            "match": f"{len(tag_chars)} hidden tag-block char(s)",
            "hidden_text": hidden_text[:200],
            "confidence": 0.97,
        }
        inner = detect_injection(hidden_text) if hidden_text else None
        if inner:
            result["decoded_threat"] = inner["pattern"]
            result["confidence"] = 0.98
        return result

    bidi = [c for c in text if ord(c) in _BIDI_OVERRIDE]
    if bidi:
        return {
            "pattern": "invisible_unicode_bidi_override",
            "match": f"{len(bidi)} bidirectional-override char(s)",
            "confidence": 0.9,
        }

    # Zero-width: a single ZWJ can be legitimate (emoji), so require a run —
    # binary/zero-width-encoded payloads use many.
    zw = [c for c in text if ord(c) in _ZERO_WIDTH]
    if len(zw) >= 3:
        return {
            "pattern": "invisible_unicode_zero_width",
            "match": f"{len(zw)} zero-width char(s)",
            "confidence": 0.88,
        }

    return None

# ── LLM06: PII detection patterns (output layer) ─────────────────────────────

_PII_PATTERNS: list[tuple[str, str]] = [
    ("pii_ssn",
     r"\b\d{3}[-\s]?\d{2}[-\s]?\d{4}\b"),
    ("pii_credit_card",
     r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b"),
    ("pii_email_bulk",
     r"([a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}[,;\s]{0,3}){3,}"),
    ("pii_phone",
     r"\b(\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b"),
    ("pii_password_field",
     r"\"?(password|passwd|pwd|secret|api[_\-]?key|auth[_\-]?token)\"?\s*[=:]\s*[\"']?[^\s\"',]{6,}"),
    ("pii_aws_key",
     r"\b(AKIA|ASIA|AROA)[A-Z0-9]{16}\b"),
    ("pii_private_key_header",
     r"-----BEGIN\s+(RSA\s+)?PRIVATE KEY-----"),
]

PII_PATTERNS: list[tuple[str, "re.Pattern[str]"]] = [
    (name, re.compile(pattern, re.IGNORECASE))
    for name, pattern in _PII_PATTERNS
]

def detect_pii(text: str) -> Optional[dict]:
    """Return the first PII match found in output text, or None if clean."""
    for name, pattern in PII_PATTERNS:
        m = pattern.search(text)
        if m:
            # Redact the actual value in the match text for safe logging
            raw = m.group(0).strip()[:80]
            redacted = raw[:4] + "***REDACTED***" if len(raw) > 4 else "***REDACTED***"
            return {
                "pattern": name,
                "match": redacted,
                "confidence": 0.92,
            }
    return None

# ── LLM08: Dangerous action patterns (parameter values) ──────────────────────
# Detect destructive or privileged actions embedded in tool call arguments.

_DANGEROUS_ARG_PATTERNS: list[tuple[str, str]] = [
    ("sql_drop",       r"\b(drop|truncate)\s+(table|database|schema)\b"),
    ("sql_delete_all", r"\bdelete\s+from\s+\w+\s*(?:where\s+1\s*=\s*1|;|$)"),
    ("shell_exec",     r"[;&|`]\s*(rm\s+-rf|dd\s+if=|mkfs|:\(\)\{|fork\s*bomb)"),
    ("path_traversal", r"\.\.[/\\]{1,2}(etc|proc|sys|windows)"),
    ("ssrf_internal",  r"https?://(localhost|127\.|10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.)"),
    ("cmd_injection",  r"[;&|`\$\(\)]\s*(whoami|id|cat\s+/etc|wget|curl\s+.+\|)"),
]

DANGEROUS_ARG_PATTERNS: list[tuple[str, "re.Pattern[str]"]] = [
    (name, re.compile(pattern, re.IGNORECASE | re.DOTALL))
    for name, pattern in _DANGEROUS_ARG_PATTERNS
]

def detect_dangerous_args(text: str) -> Optional[dict]:
    """Detect dangerous/destructive patterns in tool call argument values."""
    for name, pattern in DANGEROUS_ARG_PATTERNS:
        m = pattern.search(text)
        if m:
            return {
                "pattern": name,
                "match": m.group(0).strip()[:200],
                "confidence": 0.93,
            }
    return None


def detect_injection(text: str) -> Optional[dict]:
    """Return the first injection match in ``text`` as a dict, or None if clean.

    Checks plain-text patterns first, then encoded variants.
    """
    for name, pattern in INJECTION_PATTERNS:
        m = pattern.search(text)
        if m:
            return {
                "pattern": name,
                "match": m.group(0).strip()[:200],
                "confidence": 0.95,
            }
    return detect_encoded_injection(text)
