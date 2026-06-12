"""Per-tenant API key management.

Keys are generated with secrets.token_urlsafe(32), stored as SHA-256 hashes
in both Postgres (durable) and Redis (fast lookup cache).
The raw key is shown exactly once at creation — we never store it.

Key format:  sk-<32 url-safe chars>
Prefix:      first 8 chars used for display / support lookup (e.g. sk-abc123)
"""
from __future__ import annotations

import hashlib
import secrets
from datetime import datetime, timezone
from typing import Optional

import structlog
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.db import ApiKey

log = structlog.get_logger(__name__)

_REDIS_TTL = 3600  # cache each key lookup for 1 hour


def _hash(raw: str) -> str:
    return hashlib.sha256(raw.encode()).hexdigest()


async def create_key(
    db: AsyncSession,
    redis,
    *,
    label: str,
    tenant_id: str,
    rate_limit_per_min: int = 600,
    expires_at: Optional[datetime] = None,
) -> tuple[str, ApiKey]:
    """Generate a new API key, persist its hash, return (raw_key, ApiKey row).

    The raw_key is shown only once. Store it in your secrets manager.
    """
    raw = f"sk-{secrets.token_urlsafe(32)}"
    key_hash = _hash(raw)
    prefix = raw[:10]

    row = ApiKey(
        label=label,
        tenant_id=tenant_id,
        key_hash=key_hash,
        key_prefix=prefix,
        rate_limit_per_min=rate_limit_per_min,
        expires_at=expires_at,
        active=True,
    )
    db.add(row)
    await db.flush()

    # Cache in Redis for fast lookup
    await redis.setex(f"apikey:{key_hash}", _REDIS_TTL,
                      f"{tenant_id}:{label}")

    log.info("api_key_created", tenant=tenant_id, label=label, prefix=prefix)
    return raw, row


async def revoke_key(
    db: AsyncSession,
    redis,
    *,
    key_id: str,
) -> bool:
    """Deactivate a key by UUID. Returns True if found and revoked."""
    result = await db.execute(
        update(ApiKey)
        .where(ApiKey.id == key_id)
        .values(active=False)
        .returning(ApiKey.key_hash, ApiKey.tenant_id)
    )
    row = result.first()
    if not row:
        return False

    # Remove from Redis cache immediately
    await redis.delete(f"apikey:{row.key_hash}")
    log.info("api_key_revoked", key_id=key_id, tenant=row.tenant_id)
    return True


async def list_keys(
    db: AsyncSession,
    tenant_id: Optional[str] = None,
) -> list[ApiKey]:
    """List all active keys, optionally filtered by tenant."""
    q = select(ApiKey).where(ApiKey.active.is_(True)).order_by(ApiKey.created_at.desc())
    if tenant_id:
        q = q.where(ApiKey.tenant_id == tenant_id)
    result = await db.execute(q)
    return list(result.scalars().all())


async def validate_key(
    db: AsyncSession,
    redis,
    raw_key: str,
) -> Optional[str]:
    """Validate a raw API key. Returns tenant_id on success, None on failure.

    Checks Redis first (fast), falls back to Postgres, updates last_used_at.
    """
    key_hash = _hash(raw_key)

    # Fast path — Redis cache
    cached = await redis.get(f"apikey:{key_hash}")
    if cached:
        tenant_id = cached.split(":")[0]
        return tenant_id

    # Slow path — Postgres
    result = await db.execute(
        select(ApiKey).where(
            ApiKey.key_hash == key_hash,
            ApiKey.active.is_(True),
        )
    )
    row = result.scalar_one_or_none()
    if not row:
        return None

    # Check expiry
    if row.expires_at and row.expires_at < datetime.now(timezone.utc):
        return None

    # Update last_used and warm the cache
    await db.execute(
        update(ApiKey)
        .where(ApiKey.key_hash == key_hash)
        .values(last_used_at=datetime.now(timezone.utc))
    )
    await redis.setex(f"apikey:{key_hash}", _REDIS_TTL,
                      f"{row.tenant_id}:{row.label}")

    return row.tenant_id
