"""Closed-loop detection synthesis — turn offensive probe findings into defenses.

SentinelMCP is unusual in owning both an offensive probe and a defensive gateway
backed by a policy engine and a threat registry. This module closes the loop:
a CONFIRMED (VULNERABLE) probe finding is automatically converted into
(1) a versioned registry advisory the gateway consults on future connections, and
(2) where a reusable indicator exists, a live policy-engine detection rule —
so a vulnerability discovered by red-teaming one server immediately hardens the
gateway's defenses across the fleet, with no human authoring the rule.

The synthesis is deterministic and idempotent (stable IDs derived from the
server + attack type), so re-running a probe never creates duplicate artifacts.
"""
from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from typing import Optional
from urllib.parse import urlparse

import structlog

from app.core import registry
from app.core.policy_engine import get_policy_engine

log = structlog.get_logger(__name__)

# Probe attack_type → (registry attack_type, OWASP id, detection layer).
_ATTACK_MAP: dict[str, tuple[str, str, int]] = {
    "prompt_injection": ("TOOL_POISONING", "LLM01", 1),
    "rug_pull":         ("RUG_PULL", "LLM05", 1),
    "pii_leak":         ("SENSITIVE_DISCLOSURE", "LLM06", 3),
    "sql_injection":    ("DANGEROUS_ACTION", "LLM07", 2),
    "path_traversal":   ("DANGEROUS_ACTION", "LLM07", 2),
    "ssrf":             ("DANGEROUS_ACTION", "LLM07", 2),
    "dos":              ("MODEL_DOS", "LLM04", 2),
}

# Attack types for which a payload/indicator generalizes into a reusable rule.
_RULE_KEYWORDS: dict[str, list[str]] = {
    "sql_injection":  ["' or 1=1", "'; drop table", "union select"],
    "path_traversal": ["../../../etc/passwd", "..\\..\\..\\windows"],
    "ssrf":           ["169.254.169.254", "metadata.google.internal"],
}


def _host(server_url: str) -> str:
    try:
        return urlparse(server_url).netloc or server_url
    except Exception:
        return server_url


def _stable_id(server_url: str, attack: str) -> str:
    """Deterministic advisory id so re-probing updates rather than duplicates."""
    h = hashlib.sha256(f"{_host(server_url)}|{attack}".encode()).hexdigest()[:8]
    return f"SMCP-AUTO-{h.upper()}"


def synthesize_from_finding(finding: dict, server_url: str,
                            now: Optional[str] = None) -> Optional[dict]:
    """Convert one VULNERABLE probe finding into defense artifacts.

    Returns {"advisory": {...}, "rule": {...}|None} or None if the finding is
    not actionable (not VULNERABLE, or unknown attack type).
    """
    if finding.get("verdict") != "VULNERABLE":
        return None
    attack = finding.get("attack_type", "")
    if attack not in _ATTACK_MAP:
        return None

    reg_type, owasp, layer = _ATTACK_MAP[attack]
    now = now or datetime.now(timezone.utc).strftime("%Y-%m-%d")
    smcp_id = _stable_id(server_url, attack)
    host = _host(server_url)
    evidence = str(finding.get("evidence", ""))[:200]

    advisory = {
        "id": smcp_id,
        "severity": finding.get("severity", "HIGH"),
        "title": f"{attack.replace('_', ' ').title()} confirmed on {host} (auto-synthesized)",
        "attack_type": reg_type,
        "owasp": owasp,
        "description": (
            f"SentinelMCP's active probe confirmed a {attack} vulnerability on "
            f"{host}. {finding.get('details', '')}"[:400]
        ),
        "indicators": _RULE_KEYWORDS.get(attack, []),
        "tool_name_patterns": [],
        "detection_layer": f"L{layer}",
        "references": [],
        "published": now,
        "source": "auto_synthesized_probe",
        "origin_server": server_url,
        "evidence": evidence,
    }

    rule: Optional[dict] = None
    keywords = _RULE_KEYWORDS.get(attack)
    if keywords:
        rule = {
            "name": f"auto_{attack}_{smcp_id.split('-')[-1].lower()}",
            "layer": layer,
            "type": "keyword",
            "keywords": keywords,
            "threat_type": reg_type,
            "owasp_id": owasp,
            "confidence": 0.95,
            "enabled": True,
        }
    return {"advisory": advisory, "rule": rule}


def harden_from_report(report: dict, persist: bool = True,
                       now: Optional[str] = None) -> dict:
    """Synthesize and install defenses from every VULNERABLE finding in a report.

    Adds advisories to the registry and rules to the live policy engine. Returns
    a summary of what was installed. Safe to call repeatedly (idempotent).
    """
    server_url = report.get("server_url", "")
    engine = get_policy_engine()
    advisories: list[str] = []
    rules: list[str] = []

    for finding in report.get("findings", []):
        arts = synthesize_from_finding(finding, server_url, now=now)
        if not arts:
            continue
        registry.add_entry(arts["advisory"], persist=persist)
        advisories.append(arts["advisory"]["id"])
        if arts["rule"]:
            engine.add_rule(arts["rule"], persist=persist)
            rules.append(arts["rule"]["name"])

    from app.core import metrics
    for _ in advisories:
        metrics.hardening_synth_total.labels("advisory").inc()
    for _ in rules:
        metrics.hardening_synth_total.labels("rule").inc()

    log.info("closed_loop_hardening", server=server_url,
             advisories=len(advisories), rules=len(rules))
    return {
        "server_url": server_url,
        "advisories_created": advisories,
        "rules_installed": rules,
        "summary": (
            f"Hardened gateway from {len(advisories)} confirmed finding(s): "
            f"{len(advisories)} registry advisory(ies), {len(rules)} live rule(s)."
        ),
    }
