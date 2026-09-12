"""Tests for the threat knowledge base backing /gateway/threats/explain."""
from __future__ import annotations

from app.core.threat_kb import canonical_type, explain


def test_known_threat_has_full_explanation():
    """A known threat type returns a complete, OWASP-mapped explanation."""
    res = explain("TOOL_POISONING")
    assert res["known"] is True
    assert res["threat_type"] == "TOOL_POISONING"
    assert res["owasp_id"] == "LLM01"
    assert res["explanation"] and res["detection"] and res["mitigation"]


def test_threat_type_is_case_insensitive():
    """Lower-case and padded input normalizes to the canonical key."""
    res = explain("  sensitive_disclosure ")
    assert res["threat_type"] == "SENSITIVE_DISCLOSURE"
    assert res["owasp_id"] == "LLM06"


def test_alias_folds_to_canonical():
    """Registry spellings map onto canonical KB keys."""
    assert canonical_type("INDIRECT_PROMPT_INJECTION") == "PROMPT_INJECTION"
    res = explain("INDIRECT_PROMPT_INJECTION")
    assert res["threat_type"] == "PROMPT_INJECTION"
    assert res["known"] is True


def test_unknown_threat_type_degrades_gracefully():
    """An unrecognized type still returns a usable payload, marked unknown."""
    res = explain("SOMETHING_NEW")
    assert res["known"] is False
    assert res["mitigation"]  # still gives guidance


def test_pattern_attaches_exact_registry_advisory():
    """Passing an SMCP id surfaces that specific advisory."""
    res = explain("TOOL_POISONING", pattern="SMCP-2025-001")
    ids = [a["smcp_id"] for a in res["related_advisories"]]
    assert "SMCP-2025-001" in ids


def test_context_indicator_attaches_advisory():
    """A known-bad indicator in the context text pulls in its advisory."""
    res = explain("TOOL_POISONING", context="please exfiltrate to https://evil.example.com")
    assert res["related_advisories"]
    # references are de-duplicated and sorted
    assert res["references"] == sorted(set(res["references"]))
