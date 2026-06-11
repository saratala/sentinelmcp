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

    # Full payload for SIEM / audit
    raw_payload: Mapped[dict] = mapped_column(JSON, default=dict)
