"""Threat log writer — persists every detected threat to PostgreSQL.

Called from the gateway layers after any threat is confirmed. Never blocks
the hot path — called with fire-and-forget via asyncio.create_task where needed.
"""
from __future__ import annotations
from typing import Optional

import structlog
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.db import ThreatEvent
from app.models.schemas import ThreatDetail

log = structlog.get_logger(__name__)


async def log_threat(
    session: AsyncSession,
    *,
    server_url: str,
    tool_name: str,
    threat: ThreatDetail,
    layer: int,
    session_id: Optional[str] = None,
    rug_pull: bool = False,
    raw_payload: dict | None = None,
    tenant_id: Optional[str] = None,
) -> ThreatEvent:
    """Persist one threat event to the database and return the row."""
    event = ThreatEvent(
        server_url=server_url,
        session_id=session_id,
        tool_name=tool_name,
        threat_type=threat.threat_type,
        layer=layer,
        pattern=threat.pattern,
        match_text=threat.match,
        confidence=threat.confidence,
        severity="CRITICAL" if rug_pull else "HIGH",
        blocked=True,
        rug_pull=rug_pull,
        raw_payload=raw_payload or {},
        tenant_id=tenant_id,
    )
    session.add(event)
    await session.flush()

    log.info(
        "threat_logged",
        id=str(event.id),
        type=threat.threat_type,
        server=server_url,
        tool=tool_name,
        layer=layer,
    )
    return event


async def get_recent_threats(
    session: AsyncSession,
    limit: int = 100,
    server_url: str | None = None,
) -> list[ThreatEvent]:
    """Return the most recent threat events, optionally filtered by server."""
    from sqlalchemy import select, desc

    q = select(ThreatEvent).order_by(desc(ThreatEvent.timestamp)).limit(limit)
    if server_url:
        q = q.where(ThreatEvent.server_url == server_url)

    result = await session.execute(q)
    return list(result.scalars().all())
