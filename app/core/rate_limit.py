"""Rate limiting via slowapi (wraps limits library).

All public gateway endpoints are rate-limited per API key.
Limits are intentionally generous for legitimate agent workloads
but tight enough to stop credential stuffing and abuse.
"""
from __future__ import annotations

from fastapi import Request
from slowapi import Limiter
from slowapi.util import get_remote_address


def _key_from_api_key(request: Request) -> str:
    """Rate-limit by API key header, falling back to IP address."""
    key = request.headers.get("X-Sentinel-Key")
    return key if key else get_remote_address(request)


limiter = Limiter(key_func=_key_from_api_key)
