"""Active probe — red-team penetration testing for MCP servers.

POST /probe  — run attack probes against a target MCP server
GET  /probe/attacks — list available attacks and OWASP mappings
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import time
from typing import Any, Optional

import httpx
import structlog
from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, HttpUrl

from app.core.auth import require_api_key
from app.core.rate_limit import limiter

log = structlog.get_logger(__name__)
router = APIRouter(prefix="/probe", tags=["probe"])

# ── Data models ───────────────────────────────────────────────────────────────

class ProbeFinding(BaseModel):
    attack_type: str
    verdict: str          # VULNERABLE | PROTECTED | INCONCLUSIVE
    severity: str         # CRITICAL | HIGH | MEDIUM | LOW
    owasp_id: str
    details: str
    evidence: str = ""    # truncated to 200 chars
    latency_ms: float = 0.0


class ProbeRequest(BaseModel):
    server_url: str
    attacks: list[str] = ["all"]
    timeout_secs: int = 10


class ProbeReport(BaseModel):
    server_url: str
    tested_at: str
    total_attacks: int
    vulnerabilities_found: int
    risk_score: float
    risk_level: str
    findings: list[ProbeFinding]
    recommendation: str
    owasp_coverage: list[str]


SEVERITY_WEIGHTS = {"CRITICAL": 10, "HIGH": 7, "MEDIUM": 4, "LOW": 1}

ALL_ATTACKS = [
    "prompt_injection", "rug_pull", "pii_leak",
    "sql_injection", "path_traversal", "ssrf", "dos",
]

ATTACK_OWASP = {
    "prompt_injection": "LLM01",
    "rug_pull": "LLM05",
    "pii_leak": "LLM06",
    "sql_injection": "LLM07",
    "path_traversal": "LLM07",
    "ssrf": "LLM07",
    "dos": "LLM04",
}

# ── MCP JSON-RPC helpers ──────────────────────────────────────────────────────

def _rpc(method: str, params: dict | None = None) -> dict:
    return {"jsonrpc": "2.0", "id": 1, "method": method, "params": params or {}}


async def _call(client: httpx.AsyncClient, url: str, payload: dict, timeout: float) -> dict:
    try:
        r = await client.post(url, json=payload, timeout=timeout)
        return r.json()
    except Exception as e:
        return {"error": str(e)}


async def _tools_list(client: httpx.AsyncClient, url: str, timeout: float) -> list[dict]:
    resp = await _call(client, url, _rpc("tools/list"), timeout)
    return resp.get("result", {}).get("tools", [])


async def _tools_call(
    client: httpx.AsyncClient,
    url: str,
    tool_name: str,
    arguments: dict,
    timeout: float,
) -> dict:
    payload = _rpc("tools/call", {"name": tool_name, "arguments": arguments})
    return await _call(client, url, payload, timeout)

# ── Individual probe functions ────────────────────────────────────────────────

async def probe_prompt_injection(
    client: httpx.AsyncClient, url: str, timeout: float
) -> ProbeFinding:
    from app.detection.patterns import detect_injection
    t0 = time.perf_counter()
    tools = await _tools_list(client, url, timeout)
    if not tools:
        return ProbeFinding(
            attack_type="prompt_injection", verdict="INCONCLUSIVE",
            severity="LOW", owasp_id="LLM01",
            details="Could not retrieve tool list",
            latency_ms=round((time.perf_counter() - t0) * 1000, 2),
        )
    vulnerable_tools = []
    for tool in tools:
        desc = tool.get("description", "") + " " + json.dumps(tool.get("inputSchema", {}))
        if detect_injection(desc):
            vulnerable_tools.append(tool.get("name", "?"))
    verdict = "VULNERABLE" if vulnerable_tools else "PROTECTED"
    return ProbeFinding(
        attack_type="prompt_injection",
        verdict=verdict,
        severity="CRITICAL" if verdict == "VULNERABLE" else "LOW",
        owasp_id="LLM01",
        details=(
            f"Tool definitions contain prompt injection patterns: {vulnerable_tools}"
            if vulnerable_tools else "No injection patterns found in tool definitions"
        ),
        evidence=str(vulnerable_tools)[:200],
        latency_ms=round((time.perf_counter() - t0) * 1000, 2),
    )


async def probe_rug_pull(
    client: httpx.AsyncClient, url: str, timeout: float
) -> ProbeFinding:
    t0 = time.perf_counter()
    tools1 = await _tools_list(client, url, timeout)
    await asyncio.sleep(0.2)
    tools2 = await _tools_list(client, url, timeout)

    def _hash(tools):
        return hashlib.sha256(json.dumps(sorted(
            [json.dumps(t, sort_keys=True) for t in tools]
        )).encode()).hexdigest()

    if not tools1:
        return ProbeFinding(
            attack_type="rug_pull", verdict="INCONCLUSIVE", severity="LOW",
            owasp_id="LLM05", details="Could not retrieve tool list",
            latency_ms=round((time.perf_counter() - t0) * 1000, 2),
        )
    h1, h2 = _hash(tools1), _hash(tools2)
    verdict = "VULNERABLE" if h1 != h2 else "PROTECTED"
    return ProbeFinding(
        attack_type="rug_pull",
        verdict=verdict,
        severity="CRITICAL" if verdict == "VULNERABLE" else "LOW",
        owasp_id="LLM05",
        details=(
            f"Tool schema changed between calls! h1={h1[:8]} h2={h2[:8]}"
            if verdict == "VULNERABLE" else "Tool schema stable across calls"
        ),
        evidence=f"hash_before={h1[:16]} hash_after={h2[:16]}",
        latency_ms=round((time.perf_counter() - t0) * 1000, 2),
    )


async def probe_pii_leak(
    client: httpx.AsyncClient, url: str, timeout: float
) -> ProbeFinding:
    from app.detection.patterns import detect_pii
    t0 = time.perf_counter()
    tools = await _tools_list(client, url, timeout)
    leaky_tools = []
    for tool in tools[:5]:  # test first 5 tools
        resp = await _tools_call(client, url, tool.get("name", ""), {}, timeout)
        resp_text = json.dumps(resp)
        pii = detect_pii(resp_text)
        if pii:
            leaky_tools.append({"tool": tool.get("name"), "pii_type": pii["pattern"]})
    verdict = "VULNERABLE" if leaky_tools else "PROTECTED"
    return ProbeFinding(
        attack_type="pii_leak",
        verdict=verdict,
        severity="HIGH" if verdict == "VULNERABLE" else "LOW",
        owasp_id="LLM06",
        details=(
            f"PII found in tool responses: {leaky_tools}"
            if leaky_tools else "No PII detected in tool responses"
        ),
        evidence=str(leaky_tools)[:200],
        latency_ms=round((time.perf_counter() - t0) * 1000, 2),
    )


async def probe_sql_injection(
    client: httpx.AsyncClient, url: str, timeout: float
) -> ProbeFinding:
    t0 = time.perf_counter()
    tools = await _tools_list(client, url, timeout)
    sql_payloads = [
        "'; DROP TABLE users; --",
        "1 OR 1=1",
        "' UNION SELECT * FROM secrets --",
    ]
    indicators_vulnerable = ["syntax error", "sql", "database", "table", "column"]
    found_indicators = []
    for tool in tools[:3]:
        for payload in sql_payloads:
            # Try to find a string-type parameter
            schema = tool.get("inputSchema", {})
            props = schema.get("properties", {})
            if not props:
                continue
            first_param = next(iter(props))
            resp = await _tools_call(client, url, tool["name"], {first_param: payload}, timeout)
            resp_text = json.dumps(resp).lower()
            for ind in indicators_vulnerable:
                if ind in resp_text:
                    found_indicators.append(ind)
    verdict = "VULNERABLE" if found_indicators else "PROTECTED"
    return ProbeFinding(
        attack_type="sql_injection",
        verdict=verdict,
        severity="HIGH" if verdict == "VULNERABLE" else "LOW",
        owasp_id="LLM07",
        details=(
            f"SQL error indicators in responses: {found_indicators}"
            if found_indicators else "No SQL error indicators found"
        ),
        evidence=str(found_indicators)[:200],
        latency_ms=round((time.perf_counter() - t0) * 1000, 2),
    )


async def probe_path_traversal(
    client: httpx.AsyncClient, url: str, timeout: float
) -> ProbeFinding:
    t0 = time.perf_counter()
    tools = await _tools_list(client, url, timeout)
    payloads = ["../../../etc/passwd", "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts"]
    indicators = ["root:", "daemon:", "nobody:", "localhost", "[drivers]"]
    found = []
    for tool in tools[:3]:
        schema = tool.get("inputSchema", {})
        props = schema.get("properties", {})
        if not props:
            continue
        first_param = next(iter(props))
        for payload in payloads:
            resp = await _tools_call(client, url, tool["name"], {first_param: payload}, timeout)
            resp_text = json.dumps(resp)
            for ind in indicators:
                if ind in resp_text:
                    found.append(ind)
    verdict = "VULNERABLE" if found else "PROTECTED"
    return ProbeFinding(
        attack_type="path_traversal",
        verdict=verdict,
        severity="HIGH" if verdict == "VULNERABLE" else "LOW",
        owasp_id="LLM07",
        details=(
            f"Path traversal indicators: {found}"
            if found else "No path traversal exposure detected"
        ),
        evidence=str(found)[:200],
        latency_ms=round((time.perf_counter() - t0) * 1000, 2),
    )


async def probe_ssrf(
    client: httpx.AsyncClient, url: str, timeout: float
) -> ProbeFinding:
    t0 = time.perf_counter()
    tools = await _tools_list(client, url, timeout)
    ssrf_payloads = [
        "http://169.254.169.254/latest/meta-data/",
        "http://metadata.google.internal/",
        "http://localhost:22",
    ]
    indicators = ["ami-id", "instance-id", "computeMetadata", "SSH", "OpenSSH"]
    found = []
    for tool in tools[:3]:
        schema = tool.get("inputSchema", {})
        props = schema.get("properties", {})
        if not props:
            continue
        first_param = next(iter(props))
        for payload in ssrf_payloads:
            resp = await _tools_call(client, url, tool["name"], {first_param: payload}, timeout)
            resp_text = json.dumps(resp)
            for ind in indicators:
                if ind in resp_text:
                    found.append(ind)
    verdict = "VULNERABLE" if found else "PROTECTED"
    return ProbeFinding(
        attack_type="ssrf",
        verdict=verdict,
        severity="CRITICAL" if verdict == "VULNERABLE" else "LOW",
        owasp_id="LLM07",
        details=(
            f"SSRF metadata access detected: {found}"
            if found else "No SSRF vulnerability detected"
        ),
        evidence=str(found)[:200],
        latency_ms=round((time.perf_counter() - t0) * 1000, 2),
    )


async def probe_dos(
    client: httpx.AsyncClient, url: str, timeout: float
) -> ProbeFinding:
    t0 = time.perf_counter()
    tools = await _tools_list(client, url, timeout)
    # Measure baseline
    baseline_times = []
    for _ in range(3):
        t = time.perf_counter()
        await _tools_list(client, url, 2.0)
        baseline_times.append((time.perf_counter() - t) * 1000)
    baseline_avg = sum(baseline_times) / len(baseline_times)

    # Send large payload
    large_payload = "A" * 100_000
    tools_to_test = tools[:2] if tools else []
    post_times = []
    for tool in tools_to_test:
        schema = tool.get("inputSchema", {})
        props = schema.get("properties", {})
        if not props:
            continue
        first_param = next(iter(props))
        t = time.perf_counter()
        await _tools_call(client, url, tool["name"], {first_param: large_payload}, timeout)
        post_times.append((time.perf_counter() - t) * 1000)

    if not post_times:
        return ProbeFinding(
            attack_type="dos", verdict="INCONCLUSIVE", severity="LOW",
            owasp_id="LLM04", details="No testable tools found",
            latency_ms=round((time.perf_counter() - t0) * 1000, 2),
        )
    post_avg = sum(post_times) / len(post_times)
    ratio = post_avg / max(baseline_avg, 1)
    verdict = "VULNERABLE" if ratio > 5 else "PROTECTED"
    return ProbeFinding(
        attack_type="dos",
        verdict=verdict,
        severity="HIGH" if verdict == "VULNERABLE" else "LOW",
        owasp_id="LLM04",
        details=f"Baseline: {baseline_avg:.0f}ms, After 100KB payload: {post_avg:.0f}ms (ratio: {ratio:.1f}x)",
        evidence=f"baseline_ms={baseline_avg:.0f} post_payload_ms={post_avg:.0f}",
        latency_ms=round((time.perf_counter() - t0) * 1000, 2),
    )

# ── Dispatch table ────────────────────────────────────────────────────────────

_PROBE_FNS = {
    "prompt_injection": probe_prompt_injection,
    "rug_pull": probe_rug_pull,
    "pii_leak": probe_pii_leak,
    "sql_injection": probe_sql_injection,
    "path_traversal": probe_path_traversal,
    "ssrf": probe_ssrf,
    "dos": probe_dos,
}

# ── Routes ────────────────────────────────────────────────────────────────────

@router.get("/attacks")
async def list_attacks() -> dict:
    """List all available attack probes and their OWASP mappings."""
    return {
        "attacks": [
            {
                "name": k,
                "owasp_id": ATTACK_OWASP[k],
                "description": {
                    "prompt_injection": "Scan tool descriptions for injected instructions (LLM01)",
                    "rug_pull": "Detect schema changes between tool/list calls (LLM05)",
                    "pii_leak": "Call tools with empty args, scan responses for PII (LLM06)",
                    "sql_injection": "Send SQL payloads, check for error indicator leakage (LLM07)",
                    "path_traversal": "Send ../etc/passwd paths, check for file content (LLM07)",
                    "ssrf": "Send cloud metadata URLs, check if server makes requests (LLM07)",
                    "dos": "Send 100KB payload, measure latency impact (LLM04)",
                }[k],
            }
            for k in ALL_ATTACKS
        ],
        "total": len(ALL_ATTACKS),
    }


@router.post("")
@limiter.limit("5/minute")
async def run_probe(
    request: Request,
    body: ProbeRequest,
    tenant_id: str = Depends(require_api_key),
) -> ProbeReport:
    """Run penetration test probes against a target MCP server.

    Returns a full security report with per-attack findings, risk score, and recommendations.
    Rate limited to 5/minute — probing is expensive and should not be abused.
    """
    from datetime import datetime, timezone

    attacks = body.attacks
    if "all" in attacks:
        attacks = ALL_ATTACKS

    invalid = [a for a in attacks if a not in _PROBE_FNS]
    if invalid:
        raise HTTPException(400, detail=f"Unknown attacks: {invalid}. Valid: {ALL_ATTACKS}")

    log.info("probe_started", server_url=body.server_url, attacks=attacks, tenant=tenant_id)

    async with httpx.AsyncClient(follow_redirects=True) as client:
        tasks = [
            _PROBE_FNS[attack](client, body.server_url, float(body.timeout_secs))
            for attack in attacks
        ]
        findings = await asyncio.gather(*tasks, return_exceptions=True)

    # Replace exceptions with INCONCLUSIVE findings
    clean_findings = []
    for i, f in enumerate(findings):
        if isinstance(f, Exception):
            clean_findings.append(ProbeFinding(
                attack_type=attacks[i], verdict="INCONCLUSIVE", severity="LOW",
                owasp_id=ATTACK_OWASP.get(attacks[i], "LLM07"),
                details=f"Probe error: {f}",
            ))
        else:
            clean_findings.append(f)

    vulnerable = [f for f in clean_findings if f.verdict == "VULNERABLE"]
    total_weight = sum(SEVERITY_WEIGHTS.get(f.severity, 0) for f in vulnerable)
    max_weight = len(attacks) * SEVERITY_WEIGHTS["CRITICAL"]
    risk_score = round(min(10.0, (total_weight / max(max_weight, 1)) * 10), 2)

    if risk_score >= 8:
        risk_level = "CRITICAL"
    elif risk_score >= 6:
        risk_level = "HIGH"
    elif risk_score >= 3:
        risk_level = "MEDIUM"
    elif risk_score > 0:
        risk_level = "LOW"
    else:
        risk_level = "SAFE"

    if risk_level == "SAFE":
        recommendation = "Server appears secure. Continue monitoring with regular probes."
    elif risk_level in ("LOW", "MEDIUM"):
        recommendation = f"Address {len(vulnerable)} vulnerability(ies). Review OWASP LLM Top 10 mitigations."
    else:
        recommendation = (
            f"URGENT: {len(vulnerable)} critical vulnerability(ies) found. "
            "Deploy SentinelMCP proxy immediately to block attacks."
        )

    owasp_ids = list({f.owasp_id for f in clean_findings})

    log.warning(
        "probe_complete",
        server_url=body.server_url,
        risk_level=risk_level,
        risk_score=risk_score,
        vulnerabilities=len(vulnerable),
        tenant=tenant_id,
    )

    return ProbeReport(
        server_url=body.server_url,
        tested_at=datetime.now(timezone.utc).isoformat(),
        total_attacks=len(clean_findings),
        vulnerabilities_found=len(vulnerable),
        risk_score=risk_score,
        risk_level=risk_level,
        findings=clean_findings,
        recommendation=recommendation,
        owasp_coverage=owasp_ids,
    )
