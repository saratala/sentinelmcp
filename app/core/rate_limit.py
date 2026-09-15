"""Rate limiting via slowapi (wraps the `limits` library).

Gateway endpoints are rate-limited per API key (falling back to client IP).

Storage:
  * Empty ``SENTINEL_RATE_LIMIT_STORAGE_URI`` → in-memory (per-process). Fine for
    a single instance; NOT correct behind a load balancer (each replica keeps its
    own counters, so a client effectively gets N× the limit).
  * A Redis URI → limits are shared across all gateway instances (HA-correct).

Limits are configurable via env (``SENTINEL_RATE_LIMIT_DEFAULT`` /
``SENTINEL_RATE_LIMIT_PROBE``) so ops can tune without a redeploy. Individual
routes can pass ``probe_limit`` (a callable) to pick up the tuned probe limit.
"""
from __future__ import annotations

import structlog
from fastapi import Request
from slowapi import Limiter
from slowapi.util import get_remote_address

from app.config import settings

log = structlog.get_logger(__name__)


def _key_from_api_key(request: Request) -> str:
    """Rate-limit by API key header, falling back to IP address."""
    key = request.headers.get("X-Sentinel-Key")
    return key if key else get_remote_address(request)


def _build_limiter() -> Limiter:
    storage_uri = settings.rate_limit_storage_uri.strip() or None
    kwargs = {
        "key_func": _key_from_api_key,
        "enabled": settings.rate_limit_enabled,
        "default_limits": [settings.rate_limit_default],
    }
    if storage_uri:
        try:
            limiter = Limiter(storage_uri=storage_uri, **kwargs)
            log.info("rate_limiter_storage", backend="redis")
            return limiter
        except Exception as exc:  # never let a storage misconfig break startup
            log.warning("rate_limiter_storage_fallback",
                        error=str(exc), detail="falling back to in-memory storage")
    return Limiter(**kwargs)


limiter = _build_limiter()


def probe_limit() -> str:
    """Callable limit for the probe route — reads the tuned value at call time."""
    return settings.rate_limit_probe
