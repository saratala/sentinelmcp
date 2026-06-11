"""API key authentication for all gateway endpoints.

Keys are passed in the X-Sentinel-Key header. In production, keys are stored
in Redis (hashed) so they can be rotated without a redeploy.
For local dev a single SENTINEL_API_KEY env var is accepted.
"""
from __future__ import annotations

import hashlib
import secrets

import structlog
from fastapi import Header, HTTPException, Request, status

from app.config import settings

log = structlog.get_logger(__name__)

_DEV_KEY_HASH = hashlib.sha256(
    settings.api_key.encode()
).hexdigest() if settings.api_key else None


def _hash_key(key: str) -> str:
    """Return the SHA-256 hex digest of an API key."""
    return hashlib.sha256(key.encode()).hexdigest()


async def require_api_key(
    request: Request,
    x_sentinel_key: str = Header(..., alias="X-Sentinel-Key"),
) -> str:
    """FastAPI dependency — validates the X-Sentinel-Key header.

    Returns the raw key on success so downstream code can use it as a
    session/tenant identifier if needed.
    """
    if not x_sentinel_key:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="X-Sentinel-Key header is required",
        )

    key_hash = _hash_key(x_sentinel_key)

    # Check Redis key store first (production path).
    redis = getattr(request.app.state, "redis", None)
    if redis is not None:
        stored = await redis.get(f"apikey:{key_hash}")
        if stored:
            return x_sentinel_key

    # Fall back to the env-var dev key.
    if _DEV_KEY_HASH and secrets.compare_digest(key_hash, _DEV_KEY_HASH):
        return x_sentinel_key

    log.warning("invalid_api_key", key_prefix=x_sentinel_key[:8] + "...")
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid API key",
    )


async def provision_key(redis, label: str) -> str:
    """Generate a new API key, store its hash in Redis, and return the raw key.

    Call this once per customer during onboarding. The raw key is shown only
    once — store it securely.
    """
    raw_key = f"sk-{secrets.token_urlsafe(32)}"
    key_hash = _hash_key(raw_key)
    await redis.set(f"apikey:{key_hash}", label)
    log.info("api_key_provisioned", label=label)
    return raw_key
