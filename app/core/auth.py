"""API key authentication for all gateway endpoints.

Keys are passed in the X-Sentinel-Key header. In production, keys are stored
in Redis (hashed) so they can be rotated without a redeploy.
For local dev a single SENTINEL_API_KEY env var is accepted.
"""
from __future__ import annotations

import hashlib
import secrets
import time

import structlog
from fastapi import Header, HTTPException, Request, status
from fastapi.security import OAuth2PasswordBearer, HTTPBearer, HTTPAuthorizationCredentials

from app.config import settings

log = structlog.get_logger(__name__)

_DEV_KEY_HASH = hashlib.sha256(
    settings.api_key.encode()
).hexdigest() if settings.api_key else None

# JWKS key cache: {"keys": [...], "expires": float}
_jwks_cache: dict = {}


def _hash_key(key: str) -> str:
    """Return the SHA-256 hex digest of an API key."""
    return hashlib.sha256(key.encode()).hexdigest()


async def verify_jwt(token: str) -> str:
    """Decode and validate a Bearer JWT. Returns the tenant_id claim.

    Uses JWKS (RS256) if SENTINEL_JWKS_URL is configured, otherwise falls back
    to HS256 with SENTINEL_JWT_SECRET. Raises HTTPException on any failure.
    """
    try:
        from jose import jwt as jose_jwt, JWTError
    except ImportError:
        raise HTTPException(
            status_code=status.HTTP_501_NOT_IMPLEMENTED,
            detail="python-jose is not installed; JWT auth is unavailable",
        )

    try:
        if settings.jwks_url:
            # Fetch / use cached JWKS keys
            now = time.time()
            if not _jwks_cache or _jwks_cache.get("expires", 0) < now:
                import httpx
                async with httpx.AsyncClient() as client:
                    resp = await client.get(settings.jwks_url, timeout=5.0)
                    resp.raise_for_status()
                    _jwks_cache["keys"] = resp.json().get("keys", [])
                    _jwks_cache["expires"] = now + 3600

            key = _jwks_cache["keys"]
            claims = jose_jwt.decode(
                token,
                key,
                algorithms=["RS256"],
                audience=settings.jwt_audience or None,
                issuer=settings.jwt_issuer or None,
            )
        else:
            if not settings.jwt_secret:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="No JWT secret or JWKS URL configured",
                )
            claims = jose_jwt.decode(
                token,
                settings.jwt_secret,
                algorithms=["HS256"],
                audience=settings.jwt_audience or None,
                issuer=settings.jwt_issuer or None,
            )
    except JWTError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Invalid JWT: {exc}",
        )

    tenant_id: str = claims.get("tenant_id") or claims.get("sub") or ""
    if not tenant_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="JWT missing tenant_id and sub claims",
        )
    return tenant_id


async def require_api_key(
    request: Request,
    x_sentinel_key: str = Header(None, alias="X-Sentinel-Key"),
) -> str:
    """FastAPI dependency — validates the X-Sentinel-Key header.

    Falls back to Bearer JWT authentication if X-Sentinel-Key is absent.
    Returns the raw API key or JWT tenant_id on success so downstream code
    can use it as a session/tenant identifier if needed.
    """
    # --- Bearer JWT path ---
    if not x_sentinel_key:
        authorization: str = request.headers.get("Authorization", "")
        if authorization.startswith("Bearer "):
            token = authorization[len("Bearer "):]
            return await verify_jwt(token)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="X-Sentinel-Key header or Bearer token is required",
        )

    # --- API key path ---
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
