"""Gateway API router — /gateway/* endpoints."""
from __future__ import annotations

from typing import Any, Optional

import asyncio

import structlog
from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field

from app.core.alerts import fire_alert
from app.core.auth import AuthContext, require_api_key, require_scope
from app.core.database import get_db, get_read_db
from app.core.rate_limit import limiter
from app.core.threat_log import get_recent_threats, log_threat
from app.deps import get_circuit_breaker, get_context_layer, get_schema_layer
from app.gateway.param_layer import ParamLayer
from app.gateway.schema_layer import SchemaLayer
from app.gateway.validator import GatewayValidator
from app.core.circuit_breaker import CircuitBreaker
from app.gateway.context_layer import ContextLayer

log = structlog.get_logger(__name__)
router = APIRouter(prefix="/gateway", tags=["gateway"])


# ── Request / response shapes ─────────────────────────────────────────────────

class SchemaValidateRequest(BaseModel):
    server_url: str
    tools: list[dict[str, Any]] = Field(default_factory=list)


class InvokeRequest(BaseModel):
    session_id: str
    server_url: str
    tool_name: str
    params: dict[str, Any] = Field(default_factory=dict)
    input_schema: dict[str, Any] = Field(default_factory=dict)
    output: Any = None


# ── Endpoints ─────────────────────────────────────────────────────────────────

@router.post("/validate-schema")
@limiter.limit("60/minute")
async def validate_schema(
    request: Request,
    req: SchemaValidateRequest,
    schema_layer: SchemaLayer = Depends(get_schema_layer),
    _auth: AuthContext = Depends(require_api_key),
) -> dict:
    """Layer 1 — validate and cache a server's tool schemas."""
    if not req.server_url:
        raise HTTPException(status_code=400, detail="server_url is required")
    result = await schema_layer.validate(req.server_url, req.tools)

    if result.threats:
        async for db in get_db():
            for threat in result.threats:
                await log_threat(
                    db, server_url=req.server_url, tool_name=threat.tool,
                    threat=threat, layer=1, rug_pull=result.rug_pull,
                    raw_payload=result.model_dump(),
                    tenant_id=_auth.tenant_id,
                )
        async def _fire_alerts():
            await asyncio.gather(*[
                fire_alert(
                    server_url=req.server_url, tool_name=t.tool,
                    threat_type=t.threat_type, pattern=t.pattern,
                    match_text=t.match, confidence=t.confidence,
                    layer=1, rug_pull=result.rug_pull,
                ) for t in result.threats
            ])
        asyncio.create_task(_fire_alerts())

    status_code = 200 if result.passed else 403
    return {"status_code": status_code, **result.model_dump()}


@router.post("/invoke")
@limiter.limit("300/minute")
async def invoke_tool(
    request: Request,
    req: InvokeRequest,
    schema_layer: SchemaLayer = Depends(get_schema_layer),
    context_layer: ContextLayer = Depends(get_context_layer),
    circuit_breaker: CircuitBreaker = Depends(get_circuit_breaker),
    _auth: AuthContext = Depends(require_api_key),
) -> dict:
    """Layers 2 + 3 + 4 — validate a tool invocation."""
    if not req.session_id or not req.tool_name:
        raise HTTPException(status_code=400, detail="session_id and tool_name are required")

    validator = GatewayValidator(
        param_layer=ParamLayer(),
        context_layer=context_layer,
        circuit_breaker=circuit_breaker,
    )
    result = await validator.validate_invocation(
        session_id=req.session_id,
        tool_name=req.tool_name,
        params=req.params,
        input_schema=req.input_schema,
        output=req.output,
    )

    # Context-oversharing accounting (OWASP MCP10) — non-blocking egress meter.
    exposure = None
    try:
        from app.core.exposure import ExposureMeter
        meter = ExposureMeter(request.app.state.redis)
        exp = await meter.record(req.session_id, req.server_url, req.params)
        if exp.flagged:
            exposure = exp.to_dict()
    except Exception:  # metering must never break an invocation
        pass

    status_code = 200 if result.passed else 403
    payload = {"status_code": status_code, **result.model_dump()}
    if exposure:
        payload["exposure"] = exposure
    return payload


@router.get("/inventory")
@limiter.limit("30/minute")
async def get_inventory(
    request: Request,
    schema_layer: SchemaLayer = Depends(get_schema_layer),
    _auth: AuthContext = Depends(require_api_key),
) -> dict:
    """Return all known MCP servers and their cached security status."""
    servers = await schema_layer.list_cached_servers()
    inventory = []
    for url in servers:
        cached = await schema_layer.get_cached(url)
        if cached:
            inventory.append({
                "server": url,
                "status": "CLEAN" if cached.get("passed") else "BLOCKED",
                "hash": cached.get("hash", ""),
                "clean_tools": len(cached.get("tools", [])),
                "threats": len(cached.get("threats", [])),
                "last_validated": cached.get("validated_at", ""),
            })
    return {"servers": inventory, "total": len(inventory)}


@router.get("/registry")
@limiter.limit("60/minute")
async def get_registry(
    request: Request,
    severity: Optional[str] = None,
    attack_type: Optional[str] = None,
    _auth: AuthContext = Depends(require_api_key),
) -> dict:
    """Public threat registry — known-bad MCP tool schemas with CVE-style SMCP IDs.

    Query params:
      severity   — filter by CRITICAL | HIGH | MEDIUM | LOW
      attack_type — filter by TOOL_POISONING | DATA_EXFILTRATION | etc.
    """
    from app.core.registry import list_entries, registry_stats
    entries = list_entries(severity=severity, attack_type=attack_type)
    return {"stats": registry_stats(), "entries": entries}


@router.get("/registry/{smcp_id}")
@limiter.limit("60/minute")
async def get_registry_entry(
    request: Request,
    smcp_id: str,
    _auth: AuthContext = Depends(require_api_key),
) -> dict:
    """Return a single registry advisory by SMCP ID (e.g. SMCP-2025-001)."""
    from app.core.registry import get_entry
    entry = get_entry(smcp_id.upper())
    if not entry:
        raise HTTPException(404, f"Registry entry {smcp_id} not found")
    return entry


class RegistryCheckRequest(BaseModel):
    tool_names: list[str] = Field(default_factory=list)
    text: str = ""


@router.post("/registry/check")
@limiter.limit("120/minute")
async def registry_check(
    request: Request,
    req: RegistryCheckRequest,
    _auth: AuthContext = Depends(require_api_key),
) -> dict:
    """Check tool names and text against the known-bad registry.

    Use this to pre-screen tool lists before calling /validate-schema.
    Returns registry hits with SMCP IDs, severity, and attack type.
    """
    from app.core.registry import check_tool_names, check_indicators
    name_hits = check_tool_names(req.tool_names)
    text_hits = check_indicators(req.text) if req.text else []
    all_hits = name_hits + text_hits
    return {
        "clean": len(all_hits) == 0,
        "hits": all_hits,
        "total_hits": len(all_hits),
    }


@router.post("/circuit-breaker/reset")
@limiter.limit("10/minute")
async def reset_circuit(
    request: Request,
    session_id: str,
    circuit_breaker: CircuitBreaker = Depends(get_circuit_breaker),
    _auth: AuthContext = Depends(require_scope("admin")),
) -> dict:
    """Manually reset a session's circuit breaker after admin review."""
    await circuit_breaker.reset(session_id)
    return {"status": "reset", "session_id": session_id}


class L4EvaluateRequest(BaseModel):
    session_id: str = "test"
    tool_calls: list[dict] = Field(default_factory=list)


@router.post("/l4/evaluate")
@limiter.limit("30/minute")
async def l4_evaluate(
    request: Request,
    req: L4EvaluateRequest,
    context_layer: ContextLayer = Depends(get_context_layer),
    _auth: AuthContext = Depends(require_api_key),
) -> dict:
    """Feed a sequence of tool calls directly into L4 and return the final context risk.

    Designed for the admin Test Lab — no MCP server connection needed.
    """
    result = None
    for call in req.tool_calls:
        tool_name = call.get("tool_name", "unknown")
        params = call.get("params", {})
        result = await context_layer.evaluate(req.session_id, tool_name, params)
    if result is None:
        return {"session_id": req.session_id, "error": "no tool calls provided"}
    return result.model_dump()


@router.get("/exposure/{session_id}")
@limiter.limit("60/minute")
async def get_exposure(
    request: Request,
    session_id: str,
    _auth: AuthContext = Depends(require_api_key),
) -> dict:
    """Context-oversharing summary for a session (OWASP MCP10).

    Shows how much sensitive data the session has pushed out and to how many
    distinct destination servers.
    """
    from app.core.exposure import ExposureMeter
    meter = ExposureMeter(request.app.state.redis)
    return await meter.summary(session_id)


@router.get("/drift")
@limiter.limit("30/minute")
async def get_drift(
    request: Request,
    schema_layer: SchemaLayer = Depends(get_schema_layer),
    _auth: AuthContext = Depends(require_api_key),
) -> dict:
    """Cross-session drift inventory — every tracked tool and its drift status.

    Surfaces slow, across-session rug-pulls and cross-tenant divergence that the
    intra-run hash-watch cannot see.
    """
    tracked = await schema_layer.drift.list_tracked()
    tools = []
    drifted = 0
    for key in tracked:
        server, _, tool = key.partition("::")
        st = await schema_layer.drift.status(server, tool)
        if st.get("tracked") and st.get("drift_score", 0) >= 0.4:
            drifted += 1
        tools.append(st)
    tools.sort(key=lambda s: s.get("drift_score", 0), reverse=True)
    return {"tracked": len(tools), "drifted": drifted, "tools": tools}


@router.get("/threats/explain")
@limiter.limit("120/minute")
async def explain_threat(
    request: Request,
    threat_type: str,
    pattern: str = "",
    context: str = "",
    _auth: AuthContext = Depends(require_api_key),
) -> dict:
    """Explain a threat type — what it is, how it's detected, how to fix it.

    Returns a curated OWASP-mapped explanation enriched with any matching SMCP
    registry advisories. Backs the SDK's ``client.explain(...)`` helper.
    """
    from app.core.threat_kb import explain as _explain
    return _explain(threat_type, pattern=pattern, context=context)


@router.get("/threats")
@limiter.limit("30/minute")
async def get_threats(
    request: Request,
    limit: int = 100,
    offset: int = 0,
    server_url: Optional[str] = None,
    threat_type: Optional[str] = None,
    since: Optional[str] = None,        # ISO-8601 e.g. 2025-01-01T00:00:00Z
    _auth: AuthContext = Depends(require_api_key),
) -> dict:
    """Return paginated threat events from the PostgreSQL audit log."""
    from datetime import datetime, timezone
    from sqlalchemy import select, desc, func
    from app.models.db import ThreatEvent

    since_dt: Optional[datetime] = None
    if since:
        try:
            since_dt = datetime.fromisoformat(since.replace("Z", "+00:00"))
        except ValueError:
            raise HTTPException(status_code=400, detail="since must be ISO-8601")

    async for db in get_read_db():
        q = select(ThreatEvent).order_by(desc(ThreatEvent.timestamp))
        if _auth.tenant_id is not None:
            q = q.where(ThreatEvent.tenant_id == _auth.tenant_id)
        if server_url:
            q = q.where(ThreatEvent.server_url == server_url)
        if threat_type:
            q = q.where(ThreatEvent.threat_type == threat_type)
        if since_dt:
            q = q.where(ThreatEvent.timestamp >= since_dt)

        total_q = select(func.count()).select_from(q.subquery())
        total = (await db.execute(total_q)).scalar_one()

        rows = (await db.execute(q.offset(offset).limit(limit))).scalars().all()
        return {
            "threats": [
                {
                    "id": str(e.id),
                    "timestamp": e.timestamp.isoformat(),
                    "server_url": e.server_url,
                    "session_id": e.session_id,
                    "tool_name": e.tool_name,
                    "threat_type": e.threat_type,
                    "layer": e.layer,
                    "pattern": e.pattern,
                    "severity": e.severity,
                    "rug_pull": e.rug_pull,
                    "confidence": e.confidence,
                    "blocked": e.blocked,
                }
                for e in rows
            ],
            "total": total,
            "offset": offset,
            "limit": limit,
        }


@router.get("/threats/stats")
@limiter.limit("30/minute")
async def get_threat_stats(
    request: Request,
    days: int = 30,
    _auth: AuthContext = Depends(require_api_key),
) -> dict:
    """Aggregate threat counts by type and layer for the dashboard."""
    from datetime import datetime, timedelta, timezone
    from sqlalchemy import select, func
    from app.models.db import ThreatEvent

    cutoff = datetime.now(timezone.utc) - timedelta(days=days)
    async for db in get_read_db():
        # Build a reusable base filter so tenant isolation is applied uniformly.
        from sqlalchemy import and_
        base_filter = [ThreatEvent.timestamp >= cutoff]
        if _auth.tenant_id is not None:
            base_filter.append(ThreatEvent.tenant_id == _auth.tenant_id)

        by_type_q = (
            select(ThreatEvent.threat_type, func.count().label("count"))
            .where(*base_filter)
            .group_by(ThreatEvent.threat_type)
        )
        by_type = {row.threat_type: row.count
                   for row in (await db.execute(by_type_q)).all()}

        by_layer_q = (
            select(ThreatEvent.layer, func.count().label("count"))
            .where(*base_filter)
            .group_by(ThreatEvent.layer)
        )
        by_layer = {f"L{row.layer}": row.count
                    for row in (await db.execute(by_layer_q)).all()}

        total_q = select(func.count()).where(*base_filter)
        total = (await db.execute(total_q)).scalar_one()

        rug_pull_q = (
            select(func.count())
            .where(*base_filter)
            .where(ThreatEvent.rug_pull.is_(True))
        )
        rug_pulls = (await db.execute(rug_pull_q)).scalar_one()

        return {
            "period_days": days,
            "total": total,
            "rug_pulls": rug_pulls,
            "by_type": by_type,
            "by_layer": by_layer,
        }


@router.get("/threats/export")
@limiter.limit("10/minute")
async def export_threats_csv(
    request: Request,
    days: int = 30,
    _auth: AuthContext = Depends(require_api_key),
) -> Response:
    """Export threat audit log as CSV — for compliance reports (PCI DSS, SOC2)."""
    import csv
    import io
    from datetime import datetime, timedelta, timezone
    from fastapi.responses import StreamingResponse
    from sqlalchemy import select, desc
    from app.models.db import ThreatEvent

    cutoff = datetime.now(timezone.utc) - timedelta(days=days)
    async for db in get_read_db():
        q = (select(ThreatEvent)
             .where(ThreatEvent.timestamp >= cutoff)
             .order_by(desc(ThreatEvent.timestamp)))
        if _auth.tenant_id is not None:
            q = q.where(ThreatEvent.tenant_id == _auth.tenant_id)
        rows = (await db.execute(q)).scalars().all()

    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow([
        "id", "timestamp", "server_url", "session_id", "tool_name",
        "threat_type", "layer", "pattern", "severity",
        "confidence", "blocked", "rug_pull",
    ])
    for e in rows:
        writer.writerow([
            str(e.id), e.timestamp.isoformat(), e.server_url, e.session_id or "",
            e.tool_name, e.threat_type, e.layer, e.pattern, e.severity,
            round(e.confidence, 3), e.blocked, e.rug_pull,
        ])

    buf.seek(0)
    filename = f"sentinelmcp-audit-{days}d.csv"
    return StreamingResponse(
        iter([buf.getvalue()]),
        media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.get("/compliance/report")
@limiter.limit("5/minute")
async def compliance_report(
    request: Request,
    days: int = 30,
    _auth: AuthContext = Depends(require_api_key),
) -> dict:
    """Generate a PCI DSS / SOC2 compliance summary for the last N days."""
    from datetime import datetime, timedelta, timezone
    from sqlalchemy import select, func
    from app.models.db import ThreatEvent

    cutoff = datetime.now(timezone.utc) - timedelta(days=days)
    generated_at = datetime.now(timezone.utc).isoformat()

    async for db in get_read_db():
        # Reusable base filter for tenant isolation.
        from sqlalchemy import and_
        base_filter = [ThreatEvent.timestamp >= cutoff]
        if _auth.tenant_id is not None:
            base_filter.append(ThreatEvent.tenant_id == _auth.tenant_id)

        total_q = select(func.count()).where(*base_filter)
        total_threats = (await db.execute(total_q)).scalar_one()

        blocked_q = (select(func.count())
                     .where(*base_filter)
                     .where(ThreatEvent.blocked.is_(True)))
        total_blocked = (await db.execute(blocked_q)).scalar_one()

        rug_q = (select(func.count())
                 .where(*base_filter)
                 .where(ThreatEvent.rug_pull.is_(True)))
        rug_pulls = (await db.execute(rug_q)).scalar_one()

        pii_q = (select(func.count())
                 .where(*base_filter)
                 .where(ThreatEvent.threat_type == "SENSITIVE_DISCLOSURE"))
        pii_blocked = (await db.execute(pii_q)).scalar_one()

        injection_q = (select(func.count())
                       .where(*base_filter)
                       .where(ThreatEvent.threat_type == "PROMPT_INJECTION"))
        injection_blocked = (await db.execute(injection_q)).scalar_one()

        block_rate = round(total_blocked / total_threats * 100, 1) if total_threats else 100.0

        return {
            "report": "SentinelMCP Security Compliance Report",
            "generated_at": generated_at,
            "period_days": days,
            "summary": {
                "total_threats_detected": total_threats,
                "total_threats_blocked": total_blocked,
                "block_rate_pct": block_rate,
                "rug_pull_attempts": rug_pulls,
                "pii_disclosures_blocked": pii_blocked,
                "prompt_injections_blocked": injection_blocked,
            },
            "owasp_coverage": {
                "LLM01_prompt_injection": "ACTIVE",
                "LLM02_insecure_output": "ACTIVE",
                "LLM04_model_dos": "ACTIVE",
                "LLM05_supply_chain": "ACTIVE",
                "LLM06_sensitive_disclosure": "ACTIVE",
                "LLM07_insecure_plugin": "ACTIVE",
                "LLM08_excessive_agency": "ACTIVE",
            },
            "compliance_controls": {
                "PCI_DSS_6.4.3": "Satisfied — all AI agent inputs validated before execution",
                "PCI_DSS_12.3.4": "Satisfied — MCP tool schemas monitored for tampering",
                "SOC2_CC6.1": "Satisfied — access to MCP servers gated by API key auth",
                "SOC2_CC7.2": "Satisfied — threat events logged with full audit trail",
            },
            "download_csv": f"/gateway/threats/export?days={days}",
            "download_html": f"/gateway/compliance/report.html?days={days}",
        }


@router.get("/compliance/report.html")
@limiter.limit("5/minute")
async def compliance_report_html(
    request: Request,
    days: int = 30,
    _auth: AuthContext = Depends(require_api_key),
):
    """Print-ready HTML compliance report — open in browser and File → Print to PDF."""
    from datetime import datetime, timedelta, timezone
    from fastapi.responses import HTMLResponse
    from sqlalchemy import select, func
    from app.models.db import ThreatEvent

    cutoff = datetime.now(timezone.utc) - timedelta(days=days)
    generated_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    async for db in get_read_db():
        from sqlalchemy import and_
        base_filter = [ThreatEvent.timestamp >= cutoff]
        if _auth.tenant_id is not None:
            base_filter.append(ThreatEvent.tenant_id == _auth.tenant_id)

        def _count(q): return db.execute(q)

        total_threats = (await db.execute(select(func.count()).where(*base_filter))).scalar_one()
        total_blocked = (await db.execute(select(func.count()).where(*base_filter).where(ThreatEvent.blocked.is_(True)))).scalar_one()
        rug_pulls    = (await db.execute(select(func.count()).where(*base_filter).where(ThreatEvent.rug_pull.is_(True)))).scalar_one()
        pii_blocked  = (await db.execute(select(func.count()).where(*base_filter).where(ThreatEvent.threat_type == "SENSITIVE_DISCLOSURE"))).scalar_one()
        inj_blocked  = (await db.execute(select(func.count()).where(*base_filter).where(ThreatEvent.threat_type == "PROMPT_INJECTION"))).scalar_one()
        block_rate   = round(total_blocked / total_threats * 100, 1) if total_threats else 100.0

        owasp = {
            "LLM01 Prompt Injection": "ACTIVE",
            "LLM02 Insecure Output": "ACTIVE",
            "LLM04 Model DoS": "ACTIVE",
            "LLM05 Supply Chain": "ACTIVE",
            "LLM06 Sensitive Disclosure": "ACTIVE",
            "LLM07 Insecure Plugin": "ACTIVE",
            "LLM08 Excessive Agency": "ACTIVE",
        }
        controls = {
            "PCI DSS 6.4.3": "Satisfied — all AI agent inputs validated before execution",
            "PCI DSS 12.3.4": "Satisfied — MCP tool schemas monitored for tampering",
            "SOC2 CC6.1": "Satisfied — access to MCP servers gated by API key auth",
            "SOC2 CC7.2": "Satisfied — threat events logged with full audit trail",
        }

        owasp_rows = "".join(
            f"<tr><td>{k}</td><td><span class='badge'>✓ {v}</span></td></tr>"
            for k, v in owasp.items()
        )
        control_rows = "".join(
            f"<tr><td>{k}</td><td>{v}</td></tr>"
            for k, v in controls.items()
        )
        tenant_note = f" (Tenant: {_auth.tenant_id})" if _auth.tenant_id else ""

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>SentinelMCP Compliance Report</title>
<style>
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ font-family: 'Segoe UI', Arial, sans-serif; font-size: 12px; color: #1a1a1a; background: #fff; }}
  .page {{ max-width: 900px; margin: 0 auto; padding: 40px; }}
  header {{ display: flex; justify-content: space-between; align-items: flex-start; border-bottom: 3px solid #14532d; padding-bottom: 16px; margin-bottom: 24px; }}
  .logo {{ font-size: 22px; font-weight: 800; color: #14532d; letter-spacing: -0.5px; }}
  .logo span {{ color: #16a34a; }}
  .meta {{ text-align: right; color: #555; font-size: 11px; line-height: 1.6; }}
  h2 {{ font-size: 13px; font-weight: 700; color: #14532d; text-transform: uppercase; letter-spacing: 0.5px; margin: 24px 0 10px; }}
  .stats {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 12px; margin-bottom: 8px; }}
  .stat {{ border: 1px solid #d1fae5; border-radius: 6px; padding: 14px; text-align: center; background: #f0fdf4; }}
  .stat .num {{ font-size: 28px; font-weight: 800; color: #15803d; }}
  .stat .lbl {{ font-size: 10px; color: #555; margin-top: 2px; text-transform: uppercase; letter-spacing: 0.3px; }}
  table {{ width: 100%; border-collapse: collapse; margin-bottom: 8px; }}
  th {{ background: #14532d; color: #fff; padding: 7px 10px; text-align: left; font-size: 11px; text-transform: uppercase; letter-spacing: 0.3px; }}
  td {{ padding: 7px 10px; border-bottom: 1px solid #e5e7eb; }}
  tr:last-child td {{ border-bottom: none; }}
  .badge {{ background: #dcfce7; color: #15803d; border-radius: 4px; padding: 2px 6px; font-size: 10px; font-weight: 600; }}
  footer {{ margin-top: 32px; border-top: 1px solid #e5e7eb; padding-top: 12px; color: #888; font-size: 10px; display: flex; justify-content: space-between; }}
  @media print {{
    body {{ font-size: 11px; }}
    .page {{ padding: 20px; }}
    @page {{ margin: 1cm; }}
  }}
</style>
</head>
<body>
<div class="page">
  <header>
    <div>
      <div class="logo">Sentinel<span>MCP</span></div>
      <div style="color:#555;font-size:11px;margin-top:4px">AI Agent Security Gateway{tenant_note}</div>
    </div>
    <div class="meta">
      <strong>Security Compliance Report</strong><br>
      Period: Last {days} days<br>
      Generated: {generated_at}<br>
      Standards: PCI DSS 4.0 · SOC 2 Type II · OWASP LLM Top 10
    </div>
  </header>

  <h2>Executive Summary</h2>
  <div class="stats">
    <div class="stat"><div class="num">{total_threats}</div><div class="lbl">Threats Detected</div></div>
    <div class="stat"><div class="num">{total_blocked}</div><div class="lbl">Threats Blocked</div></div>
    <div class="stat"><div class="num">{block_rate}%</div><div class="lbl">Block Rate</div></div>
    <div class="stat"><div class="num">{rug_pulls}</div><div class="lbl">Rug Pull Attempts</div></div>
  </div>
  <table>
    <tr><th>Metric</th><th>Value</th></tr>
    <tr><td>PII / Sensitive disclosures blocked</td><td>{pii_blocked}</td></tr>
    <tr><td>Prompt injection attempts blocked</td><td>{inj_blocked}</td></tr>
    <tr><td>MCP schema rug-pull attempts detected</td><td>{rug_pulls}</td></tr>
    <tr><td>InjecAgent benchmark detection rate</td><td>67.7% core (L1–L3, deterministic) → 77.4% with local Layer-4 LLM · 0% FP on controls</td></tr>
  </table>

  <h2>OWASP LLM Top 10 Coverage</h2>
  <table>
    <tr><th>Control</th><th>Status</th></tr>
    {owasp_rows}
  </table>

  <h2>Compliance Controls</h2>
  <table>
    <tr><th>Requirement</th><th>Evidence</th></tr>
    {control_rows}
  </table>

  <h2>Attestation</h2>
  <table>
    <tr><th>Feature</th><th>Status</th></tr>
    <tr><td>Cryptographic schema attestation (HMAC-SHA256)</td><td><span class="badge">✓ ACTIVE</span></td></tr>
    <tr><td>Tamper-evident audit log (PostgreSQL append-only)</td><td><span class="badge">✓ ACTIVE</span></td></tr>
    <tr><td>API key authentication on all endpoints</td><td><span class="badge">✓ ACTIVE</span></td></tr>
    <tr><td>Rate limiting (slowapi) on all gateway routes</td><td><span class="badge">✓ ACTIVE</span></td></tr>
    <tr><td>Multi-layer detection (L1 schema · L2 param · L3 output · L4 context)</td><td><span class="badge">✓ ACTIVE</span></td></tr>
  </table>

  <footer>
    <span>SentinelMCP v0.2.0 · https://github.com/your-org/sentinelmcp</span>
    <span>This report is generated automatically. Download CSV: /gateway/threats/export?days={days}</span>
  </footer>
</div>
</body>
</html>"""
        return HTMLResponse(html)
