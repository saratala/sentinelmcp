"""Tests for the shareable branded probe report renderer."""
from __future__ import annotations

from app.gateway.probe_report import render_probe_report

REPORT = {
    "server_url": "https://customer-mcp.example.com",
    "tested_at": "2026-09-15T10:30:00Z",
    "risk_score": 7.4, "risk_level": "HIGH",
    "vulnerabilities_found": 2, "total_attacks": 7,
    "recommendation": "Address 2 critical findings before connecting production agents.",
    "findings": [
        {"attack_type": "sql_injection", "verdict": "VULNERABLE", "severity": "HIGH",
         "owasp_id": "LLM07", "evidence": "['syntax error']", "details": "SQL error leakage"},
        {"attack_type": "prompt_injection", "verdict": "PROTECTED", "severity": "LOW",
         "owasp_id": "LLM01", "details": "clean"},
    ],
}


def test_report_is_self_contained_html():
    html = render_probe_report(REPORT)
    assert html.startswith("<!DOCTYPE html>")
    assert "<style>" in html and "</html>" in html  # inline CSS, no external assets


def test_report_includes_key_fields():
    html = render_probe_report(REPORT)
    assert "customer-mcp.example.com" in html
    assert "7.4" in html and "HIGH" in html
    assert "sql_injection" in html
    assert "OWASP LLM Top 10" in html


def test_vulnerable_findings_get_remediation():
    html = render_probe_report(REPORT)
    # The SQL finding's remediation guidance must appear.
    assert "Parameterize queries" in html


def test_hardening_section_shows_closed_loop_when_present():
    r = dict(REPORT, hardening={"advisories_created": ["SMCP-AUTO-1"],
                                "rules_installed": ["auto_sql_1"]})
    html = render_probe_report(r)
    assert "1 registry advisory" in html
    assert "1 live detection rule" in html


def test_html_escapes_untrusted_fields():
    r = dict(REPORT, server_url="https://evil.example.com/<script>alert(1)</script>")
    html = render_probe_report(r)
    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;" in html


def test_safe_server_shows_no_vuln_language():
    r = {"server_url": "https://good.example.com", "tested_at": "2026-09-15T00:00:00Z",
         "risk_score": 0, "risk_level": "SAFE", "vulnerabilities_found": 0,
         "total_attacks": 7, "recommendation": "Server appears secure.", "findings": []}
    html = render_probe_report(r)
    assert "No exploitable findings" in html
