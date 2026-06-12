"""SQLAlchemy ORM models — threat log, audit trail."""
from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import (
    JSON,
    Boolean,
    DateTime,
    Float,
    Index,
    String,
    Text,
    Uuid,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class Base(DeclarativeBase):
    pass


class ThreatEvent(Base):
    """One structured threat log entry — written for every detected attack."""

    __tablename__ = "threat_events"

    id: Mapped[uuid.UUID] = mapped_column(
        Uuid, primary_key=True, default=uuid.uuid4
    )
    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, index=True
    )

    # Where the threat came from
    server_url: Mapped[str] = mapped_column(String(512), index=True)
    session_id: Mapped[Optional[str]] = mapped_column(String(256), nullable=True, index=True)
    tool_name: Mapped[str] = mapped_column(String(256))

    # What was detected
    threat_type: Mapped[str] = mapped_column(String(64), index=True)
    layer: Mapped[int] = mapped_column()           # 1-4
    pattern: Mapped[str] = mapped_column(String(128))
    match_text: Mapped[str] = mapped_column(Text)
    confidence: Mapped[float] = mapped_column(Float)

    # Outcome
    severity: Mapped[str] = mapped_column(String(16), default="HIGH")
    blocked: Mapped[bool] = mapped_column(Boolean, default=True)
    rug_pull: Mapped[bool] = mapped_column(Boolean, default=False)

    # Tenant isolation — which API key triggered this event
    tenant_id: Mapped[Optional[str]] = mapped_column(String(128), nullable=True, index=True)

    # Full payload for SIEM / audit
    raw_payload: Mapped[dict] = mapped_column(JSON, default=dict)


class ApiKey(Base):
    """Per-tenant API key registry — stored as SHA-256 hash, never raw."""

    __tablename__ = "api_keys"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
    last_used_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    # Identity
    label: Mapped[str] = mapped_column(String(256), index=True)  # e.g. "acme-corp-prod"
    tenant_id: Mapped[str] = mapped_column(String(128), index=True)

    # Security
    key_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    key_prefix: Mapped[str] = mapped_column(String(16))  # first 8 chars for display

    # Scopes and limits
    rate_limit_per_min: Mapped[int] = mapped_column(default=600)
    active: Mapped[bool] = mapped_column(Boolean, default=True, index=True)
    expires_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
