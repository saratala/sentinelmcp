"""End-to-end closed-loop proof — probe → confirm → synthesize → block.

Runs the REAL probe functions against the deliberately-vulnerable demo MCP
server in-process (httpx ASGITransport, no network/Docker), then hardens from
the findings and confirms a synthesized rule fires live. This is the credible
artifact behind the closed-loop demo.
"""
from __future__ import annotations

import httpx
import pytest

from app.core.policy_engine import get_policy_engine
from app.core.synthesis import harden_from_report
from app.gateway.probe_router import (
    probe_path_traversal,
    probe_pii_leak,
    probe_prompt_injection,
    probe_sql_injection,
    probe_ssrf,
)
from demo.vulnerable_mcp_server import app as vuln_app

URL = "http://vuln/"


@pytest.mark.asyncio
async def test_probe_finds_real_vulns_then_gateway_self_hardens():
    transport = httpx.ASGITransport(app=vuln_app)
    async with httpx.AsyncClient(transport=transport, base_url="http://vuln") as client:
        findings = []
        for fn in (probe_prompt_injection, probe_sql_injection,
                   probe_path_traversal, probe_ssrf, probe_pii_leak):
            f = await fn(client, URL, 5.0)
            findings.append(f.model_dump())

    verdicts = {f["attack_type"]: f["verdict"] for f in findings}
    # The vulnerable server should be caught on multiple classes.
    vulnerable = [a for a, v in verdicts.items() if v == "VULNERABLE"]
    assert "sql_injection" in vulnerable
    assert "prompt_injection" in vulnerable
    assert len(vulnerable) >= 3

    # Close the loop: synthesize live defenses from the confirmed findings.
    report = {"server_url": "http://vuln:8003", "findings": findings}
    res = harden_from_report(report, persist=False)

    assert res["advisories_created"], "expected auto-synthesized advisories"
    assert res["rules_installed"], "expected at least one live rule (sql/path/ssrf)"

    # The synthesized rule now fires live in the policy engine (layer 2).
    engine = get_policy_engine()
    hits = engine.scan("run this: '; DROP TABLE users; --", layer=2)
    assert any(h.name in res["rules_installed"] for h in hits), \
        "synthesized rule should block a matching payload after hardening"
