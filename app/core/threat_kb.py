"""Threat knowledge base — human-readable explanations for every threat type.

Powers ``GET /gateway/threats/explain`` and the SDK's ``client.explain(...)``.
This is a static, curated reference (no LLM, no I/O) so it is safe to call in
any path: given a ``threat_type`` it returns what the attack is, why it matters,
how SentinelMCP detects it, and how to remediate — each mapped to the OWASP LLM
Top 10. Results are enriched at call time with any matching SMCP registry
advisories.
"""
from __future__ import annotations

from typing import Optional

from app.core.registry import check_indicators, list_entries

# ── Curated explanations, keyed by canonical threat_type ─────────────────────
# Every entry maps to an OWASP LLM Top 10 control. Aliases (below) fold the
# many attack_type spellings used across the registry and detectors onto these.
_KB: dict[str, dict] = {
    "TOOL_POISONING": {
        "owasp_id": "LLM01",
        "title": "Tool poisoning",
        "explanation": (
            "A malicious MCP server hides instructions inside a tool's name or "
            "description. Because agents feed tool descriptions to the LLM, the "
            "hidden text is executed as if the user wrote it — exfiltrating data, "
            "escalating privileges, or suppressing warnings to the user."
        ),
        "detection": (
            "Layer 1 deep-scans every tool description on first connect with the "
            "injection pattern set and the policy engine, and cross-checks the "
            "known-bad registry."
        ),
        "mitigation": (
            "Never expose raw tool descriptions to the model without validation. "
            "Pin tool schemas by hash, require signed tool manifests, and route "
            "all MCP traffic through the gateway so descriptions are scanned "
            "before they reach the LLM context."
        ),
    },
    "PROMPT_INJECTION": {
        "owasp_id": "LLM01",
        "title": "Prompt injection",
        "explanation": (
            "Untrusted content instructs the model to ignore its guardrails or "
            "prior instructions. In MCP this arrives indirectly — via tool "
            "descriptions or tool outputs — so the user never sees the payload."
        ),
        "detection": (
            "Layers 1 and 3 scan descriptions and outputs for imperative "
            "override phrases ('ignore previous instructions', 'send all…')."
        ),
        "mitigation": (
            "Treat all tool content as untrusted data, not instructions. Keep a "
            "strict system prompt, and validate/quarantine tool output before it "
            "re-enters the model context."
        ),
    },
    "OBFUSCATED_INJECTION": {
        "owasp_id": "LLM01",
        "title": "Encoded / obfuscated injection",
        "explanation": (
            "The same injection payload, hidden behind base64, unicode escapes, "
            "or other encodings to slip past naive keyword filters."
        ),
        "detection": (
            "SentinelMCP decodes base64 segments and unicode escapes first, then "
            "re-scans the decoded text with the full pattern set."
        ),
        "mitigation": (
            "Normalize and decode all tool content before inspection; reject "
            "descriptions that decode into instruction-like text."
        ),
    },
    "RUG_PULL": {
        "owasp_id": "LLM05",
        "title": "Rug pull (schema swap mid-session)",
        "explanation": (
            "A server passes validation on first contact, then silently changes a "
            "tool's schema or description to a malicious version after it has "
            "earned trust — a supply-chain attack against the tool itself."
        ),
        "detection": (
            "Layer 1 pins a SHA-256 hash of each server's tool set and "
            "re-validates in the background; any change to a previously-clean "
            "server that introduces a payload is flagged RUG_PULL."
        ),
        "mitigation": (
            "Pin tool schemas by hash and alert on any drift. Re-validate on a "
            "short interval and block the session until a human reviews the "
            "change."
        ),
    },
    "SUPPLY_CHAIN": {
        "owasp_id": "LLM05",
        "title": "Supply-chain / shadow MCP server",
        "explanation": (
            "An agent is pointed at an unapproved or compromised MCP server — a "
            "'shadow' server that bypasses monitoring, or a dependency that has "
            "been tampered with upstream."
        ),
        "detection": (
            "Layer 0 allowlist rejects any proxy target that is not explicitly "
            "approved; the registry flags known-bad servers and indicators."
        ),
        "mitigation": (
            "Enforce a server allowlist, require signed/attested tool manifests, "
            "and audit every server an agent is allowed to reach."
        ),
    },
    "OUTPUT_INJECTION": {
        "owasp_id": "LLM02",
        "title": "Insecure output handling",
        "explanation": (
            "A tool returns content crafted to hijack the agent's next step — "
            "injected instructions, markup, or links that act on the model or a "
            "downstream system that trusts the output verbatim."
        ),
        "detection": (
            "Layer 3 inspects every output asynchronously; if a payload is found "
            "the circuit breaker blocks the next call in that session."
        ),
        "mitigation": (
            "Never pass raw tool output to a privileged sink. Sanitize and "
            "encode outputs, and gate follow-on actions behind the circuit "
            "breaker."
        ),
    },
    "SENSITIVE_DISCLOSURE": {
        "owasp_id": "LLM06",
        "title": "Sensitive information disclosure",
        "explanation": (
            "A tool response leaks PII, secrets, or credentials — API keys, "
            "tokens, card numbers, or personal data — into the model context or "
            "the transcript."
        ),
        "detection": (
            "Layer 3 scans outputs with the PII/secret pattern set and redacts "
            "or blocks before the data spreads further."
        ),
        "mitigation": (
            "Apply least-privilege to tool credentials, redact sensitive fields "
            "at the boundary, and log disclosures to the audit trail for review."
        ),
    },
    "CREDENTIAL_THEFT": {
        "owasp_id": "LLM06",
        "title": "Credential theft",
        "explanation": (
            "MCP aggregates many service credentials behind one agent; a single "
            "malicious tool that reads env vars or config can harvest all of "
            "them at once."
        ),
        "detection": (
            "Layers 1 and 3 flag tools and outputs that reference credential "
            "stores or attempt to read and forward secrets."
        ),
        "mitigation": (
            "Scope each credential to a single tool, never expose the full "
            "environment to a tool process, and rotate on any suspected leak."
        ),
    },
    "DATA_EXFILTRATION": {
        "owasp_id": "LLM06",
        "title": "Data exfiltration",
        "explanation": (
            "An attacker routes data to an external, attacker-controlled "
            "destination — typically an exfiltration URL embedded in a tool "
            "description or triggered by a crafted argument."
        ),
        "detection": (
            "Exfiltration-URL and 'send all' patterns are caught at Layer 1 "
            "(descriptions) and Layer 3 (outputs)."
        ),
        "mitigation": (
            "Egress-filter tool network access, block unknown destinations, and "
            "require approval for any tool that makes outbound requests."
        ),
    },
    "SEMANTIC_MOSAIC": {
        "owasp_id": "LLM08",
        "title": "Semantic mosaic",
        "explanation": (
            "No single call is malicious, but a sequence of benign-looking calls "
            "assembles sensitive data or a dangerous action — e.g. read a "
            "customer list, then their balances, then post them externally."
        ),
        "detection": (
            "Layer 4 tracks a per-session context window with TF-IDF category "
            "scoring and fires when the cross-category risk score exceeds 0.75."
        ),
        "mitigation": (
            "Apply intent-aware, session-level policy — not just per-call checks. "
            "Rate-limit sensitive category combinations and require step-up "
            "review when a session's risk score climbs."
        ),
    },
    "EXCESSIVE_AGENCY": {
        "owasp_id": "LLM08",
        "title": "Excessive agency",
        "explanation": (
            "A tool is granted more capability than the task needs — direct "
            "destructive actions (delete, transfer, grant access) reachable "
            "without a human in the loop."
        ),
        "detection": (
            "Layer 2 scans parameter values for dangerous actions; the policy "
            "engine can require approval for high-impact tools."
        ),
        "mitigation": (
            "Constrain tool permissions to the minimum, and require explicit "
            "confirmation for irreversible or outward-facing actions."
        ),
    },
    "ACCOUNT_TAKEOVER": {
        "owasp_id": "LLM08",
        "title": "Account takeover",
        "explanation": (
            "A tool is coerced into granting access, resetting credentials, or "
            "adding a principal the attacker controls — turning agent agency "
            "into persistent unauthorized access."
        ),
        "detection": (
            "Layer 2 dangerous-action scanning plus policy rules on access-"
            "granting tools flag these before execution."
        ),
        "mitigation": (
            "Gate all access-granting and credential-changing tools behind human "
            "approval and strong authorization checks."
        ),
    },
    "PARAM_VIOLATION": {
        "owasp_id": "LLM07",
        "title": "Parameter violation",
        "explanation": (
            "A tool call carries arguments that violate the tool's declared "
            "schema — extra fields, wrong types, or smuggled payloads used to "
            "exploit a lax server."
        ),
        "detection": (
            "Layer 2 does strict JSON-Schema validation on every call in under a "
            "millisecond with no I/O."
        ),
        "mitigation": (
            "Enforce strict schemas server-side too (reject additional "
            "properties), and validate every argument before execution."
        ),
    },
}

# Fold alternate spellings used across detectors and the registry onto the
# canonical keys above.
_ALIASES: dict[str, str] = {
    "INDIRECT_PROMPT_INJECTION": "PROMPT_INJECTION",
    "ENCODED_INJECTION": "OBFUSCATED_INJECTION",
    "DANGEROUS_ACTION": "EXCESSIVE_AGENCY",
    "PII_DISCLOSURE": "SENSITIVE_DISCLOSURE",
    "PII_LEAK": "SENSITIVE_DISCLOSURE",
    "CONTEXT_MOSAIC": "SEMANTIC_MOSAIC",
    "SHADOW_MCP": "SUPPLY_CHAIN",
}

_UNKNOWN = {
    "owasp_id": "",
    "title": "Unrecognized threat type",
    "explanation": (
        "No curated explanation exists for this threat type yet. See the "
        "matching registry advisories (if any) for details."
    ),
    "detection": "",
    "mitigation": (
        "Route the traffic through the gateway and review the threat details "
        "and audit log for the specific pattern that fired."
    ),
}


def canonical_type(threat_type: str) -> str:
    """Normalize a threat_type string to its canonical KB key."""
    t = (threat_type or "").strip().upper()
    return _ALIASES.get(t, t)


def explain(threat_type: str, pattern: str = "", context: str = "") -> dict:
    """Return a structured explanation for a threat type.

    Args:
        threat_type: e.g. "TOOL_POISONING", "SENSITIVE_DISCLOSURE".
        pattern: the specific pattern/SMCP id that fired, if known — used to
            surface the exact registry advisory.
        context: optional extra text (e.g. the matched snippet) scanned against
            the registry to attach related advisories.

    Returns:
        A dict with owasp_id, explanation, detection, mitigation, references,
        and any related SMCP registry advisories.
    """
    key = canonical_type(threat_type)
    base = _KB.get(key, _UNKNOWN)

    # Attach registry advisories: exact SMCP id from `pattern`, plus any
    # indicators found in `context`, plus advisories that share the OWASP id.
    related: dict[str, dict] = {}
    from app.core.registry import get_entry

    if pattern:
        entry = get_entry(pattern.strip().upper())
        if entry:
            related[entry["id"]] = entry
    for hit in check_indicators(context) if context else []:
        entry = get_entry(hit["smcp_id"])
        if entry:
            related[entry["id"]] = entry
    if base.get("owasp_id"):
        for entry in list_entries():
            if entry.get("owasp") == base["owasp_id"]:
                related.setdefault(entry["id"], entry)

    advisories = [
        {
            "smcp_id": e["id"],
            "title": e.get("title", ""),
            "severity": e.get("severity", ""),
            "attack_type": e.get("attack_type", ""),
            "references": e.get("references", []),
        }
        for e in related.values()
    ]

    refs = sorted({r for e in related.values() for r in e.get("references", [])})

    return {
        "threat_type": key,
        "owasp_id": base["owasp_id"],
        "title": base["title"],
        "explanation": base["explanation"],
        "detection": base["detection"],
        "mitigation": base["mitigation"],
        "pattern": pattern,
        "known": key in _KB,
        "related_advisories": advisories,
        "references": refs,
    }
