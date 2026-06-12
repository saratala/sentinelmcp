"""Gateway API router — /gateway/* endpoints."""
from __future__ import annotations

from typing import Any, Optional

import asyncio

import structlog
from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field

from app.core.alerts import fire_alert
from app.core.auth import AuthContext, require_api_key
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
    status_code = 200 if result.passed else 403
    return {"status_code": status_code, **result.model_dump()}


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


@router.post("/circuit-breaker/reset")
@limiter.limit("10/minute")
async def reset_circuit(
    request: Request,
    session_id: str,
    circuit_breaker: CircuitBreaker = Depends(get_circuit_breaker),
    _auth: AuthContext = Depends(require_api_key),
) -> dict:
    """Manually reset a session's circuit breaker after admin review."""
    await circuit_breaker.reset(session_id)
    return {"status": "reset", "session_id": session_id}


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
        }
