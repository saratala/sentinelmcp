"""Regex injection-pattern library used by the schema-layer semantic scan.

These are deterministic heuristics (no LLM in the hot path). They must never
fire on the clean-tool fixtures — see tests/fixtures/clean_tools.json.
"""
from __future__ import annotations

import re
from typing import Optional

# Compiled once at import. Each entry: (name, compiled_pattern).
_RAW_PATTERNS: list[tuple[str, str]] = [
    ("ignore_previous_instructions",
     r"ignore\s+(all\s+)?(previous|prior|above)\s+instructions?"),
    ("exfiltration_url",
     r"(export|send|exfiltrate|upload|post|forward)\s+.{0,50}(to|at|via)\s+https?://"),
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
]

INJECTION_PATTERNS: list[tuple[str, "re.Pattern[str]"]] = [
    (name, re.compile(pattern, re.IGNORECASE | re.DOTALL))
    for name, pattern in _RAW_PATTERNS
]


def detect_injection(text: str) -> Optional[dict]:
    """Return the first injection match in ``text`` as a dict, or None if clean."""
    for name, pattern in INJECTION_PATTERNS:
        m = pattern.search(text)
        if m:
            return {
                "pattern": name,
                "match": m.group(0).strip()[:200],
                "confidence": 0.95,
            }
    return None
