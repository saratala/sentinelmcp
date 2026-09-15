"""API key authentication for all gateway endpoints.

Keys are passed in the X-Sentinel-Key header. In production, keys are stored
in Redis (hashed) so they can be rotated without a redeploy.
For local dev a single SENTINEL_API_KEY env var is accepted.
"""
from __future__ import annotations

import hashlib
import secrets
import time
from dataclasses import dataclass
from typing import Optional

import structlog
from fastapi import Depends, Header, HTTPException, Request, status
from fastapi.security import OAuth2PasswordBearer, HTTPBearer, HTTPAuthorizationCredentials

from app.config import settings


from dataclasses import field

# ── Role-based access control ────────────────────────────────────────────────
# Scopes attached to an API key. "admin" implies every other scope.
#   read    — read-only endpoints (registry, threats, inventory, drift, exposure)
#   gateway — validate/invoke/proxy/adapters (the data path)
#   probe   — the active red-team probe
#   admin   — key management, allowlist, circuit-breaker reset (privileged ops)
ALL_SCOPES: tuple[str, ...] = ("read", "gateway", "probe", "admin")


@dataclass
class AuthContext:
    """Carries the authenticated identity for a single request.

    ``key`` holds the raw API key (or the JWT ``tenant_id`` string for Bearer
    requests — kept for backwards compatibility with code that used the old
    ``str`` return value).

    ``tenant_id`` is ``None`` for plain API-key requests where no tenant is
    known (single-tenant / dev setups) and is the JWT ``sub`` / ``tenant_id``
    claim for Bearer JWT requests.  Query code should only filter by
    ``tenant_id`` when it is not ``None``.

    ``scopes`` is the set of RBAC scopes granted to the key. Legacy keys and the
    dev/env key default to all scopes for backwards compatibility.
    """

    key: str
    tenant_id: Optional[str] = None
    scopes: list[str] = field(default_factory=lambda: list(ALL_SCOPES))

    def has_scope(self, scope: str) -> bool:
        """True if this identity holds ``scope`` (admin implies everything)."""
        return "admin" in self.scopes or scope in self.scopes


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
    return tenant_id  # raw string — caller wraps in AuthContext


def _record_auth_failure(request: Request, reason: str, key_prefix: str = "") -> None:
    """Emit a structured audit event + metric for an auth/authorization failure."""
    from app.core import metrics
    route = getattr(request.scope.get("route"), "path", None) or request.url.path
    client = request.client.host if request.client else "unknown"
    request_id = getattr(request.state, "request_id", None)
    log.warning(
        "auth_failure",
        reason=reason, route=route, client_ip=client,
        key_prefix=key_prefix or None, request_id=request_id,
    )
    metrics.auth_failures_total.labels(reason, route).inc()


async def require_api_key(
    request: Request,
    x_sentinel_key: str = Header(None, alias="X-Sentinel-Key"),
) -> AuthContext:
    """FastAPI dependency — validates the X-Sentinel-Key header.

    Falls back to Bearer JWT authentication if X-Sentinel-Key is absent.
    Returns an :class:`AuthContext` on success.  ``AuthContext.tenant_id`` is
    set to the JWT ``tenant_id`` / ``sub`` claim for Bearer requests and is
    ``None`` for plain API-key requests (backwards-compatible single-tenant
    behaviour — callers must only filter by tenant when it is not ``None``).
    """
    # --- Bearer JWT path ---
    if not x_sentinel_key:
        authorization: str = request.headers.get("Authorization", "")
        if authorization.startswith("Bearer "):
            token = authorization[len("Bearer "):]
            tenant_id = await verify_jwt(token)
            return AuthContext(key=tenant_id, tenant_id=tenant_id)
        _record_auth_failure(request, "missing_credentials")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="X-Sentinel-Key header or Bearer token is required",
        )

    # --- API key path ---
    key_hash = _hash_key(x_sentinel_key)

    # Check Redis key store first (production path).
    # The value stored by provision_key is a plain label string.  If the value
    # is a JSON object with a "tenant_id" field we extract it; otherwise
    # tenant_id stays None (single-tenant / legacy keys).
    redis = getattr(request.app.state, "redis", None)
    if redis is not None:
        stored = await redis.get(f"apikey:{key_hash}")
        if stored:
            tenant_id: Optional[str] = None
            # Legacy keys were plain strings and carry no scopes → grant all
            # (backwards compatible; only keys created WITH scopes are limited).
            scopes: list[str] = list(ALL_SCOPES)
            try:
                import json as _json
                meta = _json.loads(stored)
                if isinstance(meta, dict):
                    tenant_id = meta.get("tenant_id") or None
                    if isinstance(meta.get("scopes"), list) and meta["scopes"]:
                        scopes = [str(s) for s in meta["scopes"]]
            except (ValueError, TypeError):
                pass  # plain label string — legacy key, all scopes
            return AuthContext(key=x_sentinel_key, tenant_id=tenant_id, scopes=scopes)

    # Fall back to the env-var dev key — the admin bootstrap key (all scopes).
    if _DEV_KEY_HASH and secrets.compare_digest(key_hash, _DEV_KEY_HASH):
        return AuthContext(key=x_sentinel_key, tenant_id=None, scopes=list(ALL_SCOPES))

    _record_auth_failure(request, "invalid_api_key", key_prefix=x_sentinel_key[:8] + "...")
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid API key",
    )


def require_scope(*required: str):
    """Dependency factory enforcing that the caller holds one of ``required``.

    Usage:
        @router.post("", dependencies=[Depends(require_scope("admin"))])
        async def handler(_auth: AuthContext = Depends(require_scope("probe"))): ...

    Denials are audited (structured ``auth_failure`` event + metric) and return
    403. ``admin`` satisfies any requirement.
    """
    async def _dep(request: Request,
                   ctx: AuthContext = Depends(require_api_key)) -> AuthContext:
        if not any(ctx.has_scope(s) for s in required):
            _record_auth_failure(
                request, f"missing_scope:{'|'.join(required)}",
                key_prefix=(ctx.key or "")[:8])
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Insufficient scope — requires one of: {list(required)}",
            )
        return ctx
    return _dep


async def provision_key(redis, label: str, scopes: Optional[list[str]] = None) -> str:
    """Generate a new API key, store its hash + scopes in Redis, return the raw key.

    Call this once per customer during onboarding. The raw key is shown only
    once — store it securely. ``scopes`` defaults to all scopes.
    """
    import json as _json
    raw_key = f"sk-{secrets.token_urlsafe(32)}"
    key_hash = _hash_key(raw_key)
    meta = {"label": label, "scopes": list(scopes) if scopes else list(ALL_SCOPES)}
    await redis.set(f"apikey:{key_hash}", _json.dumps(meta))
    log.info("api_key_provisioned", label=label, scopes=meta["scopes"])
    return raw_key
