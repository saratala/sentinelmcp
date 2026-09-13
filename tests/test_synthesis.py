"""Tests for the closed-loop detection synthesis (probe finding → live defense).

Verifies the novel mechanism: a confirmed VULNERABLE probe finding is converted
into a registry advisory and (where a reusable indicator exists) a live policy
rule that actually fires. All deterministic; persist=False keeps tests hermetic.
"""
from __future__ import annotations

import pytest

from app.core import registry
from app.core.policy_engine import get_policy_engine
from app.core.synthesis import (
    _stable_id,
    harden_from_report,
    synthesize_from_finding,
)

SERVER = "http://target-mcp.example.com:8001"


def _finding(attack, verdict="VULNERABLE", severity="HIGH"):
    return {
        "attack_type": attack, "verdict": verdict, "severity": severity,
        "owasp_id": "LLM07", "details": f"{attack} confirmed", "evidence": "['sql']",
    }


def test_protected_finding_yields_nothing():
    assert synthesize_from_finding(_finding("sql_injection", verdict="PROTECTED"), SERVER) is None


def test_unknown_attack_yields_nothing():
    assert synthesize_from_finding(_finding("mystery_attack"), SERVER) is None


def test_injection_finding_yields_advisory_and_rule():
    arts = synthesize_from_finding(_finding("sql_injection"), SERVER, now="2026-09-13")
    assert arts is not None
    adv = arts["advisory"]
    assert adv["id"].startswith("SMCP-AUTO-")
    assert adv["attack_type"] == "DANGEROUS_ACTION"
    assert adv["owasp"] == "LLM07"
    assert adv["source"] == "auto_synthesized_probe"
    assert arts["rule"] is not None
    assert arts["rule"]["layer"] == 2


def test_prompt_injection_advisory_without_rule():
    """A finding with no reusable payload indicator gets an advisory but no rule."""
    arts = synthesize_from_finding(_finding("prompt_injection"), SERVER)
    assert arts is not None
    assert arts["advisory"]["attack_type"] == "TOOL_POISONING"
    assert arts["rule"] is None


def test_stable_id_is_deterministic():
    a = _stable_id(SERVER, "sql_injection")
    b = _stable_id(SERVER, "sql_injection")
    c = _stable_id(SERVER, "ssrf")
    assert a == b and a != c


def test_harden_installs_live_rule_that_fires():
    report = {
        "server_url": SERVER,
        "findings": [_finding("sql_injection"), _finding("prompt_injection", verdict="PROTECTED")],
    }
    res = harden_from_report(report, persist=False, now="2026-09-13")

    # advisory landed in the registry and is queryable
    assert len(res["advisories_created"]) == 1
    assert registry.get_entry(res["advisories_created"][0]) is not None

    # the synthesized rule now fires live in the policy engine (layer 2)
    assert len(res["rules_installed"]) == 1
    hits = get_policy_engine().scan("do '; DROP TABLE users; now", layer=2)
    assert any(h.name == res["rules_installed"][0] for h in hits)


def test_harden_is_idempotent():
    report = {"server_url": SERVER, "findings": [_finding("ssrf")]}
    r1 = harden_from_report(report, persist=False, now="2026-09-13")
    r2 = harden_from_report(report, persist=False, now="2026-09-13")
    assert r1["advisories_created"] == r2["advisories_created"]
