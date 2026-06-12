"""Redis connection pool and helpers for the gateway.

Supports two connection modes:
- Direct connection (default): uses SENTINEL_REDIS_URL
- Redis Sentinel (HA): activated when SENTINEL_REDIS_SENTINEL_URLS is set
"""
from __future__ import annotations

from typing import Optional

import redis.asyncio as redis
from redis.asyncio.sentinel import Sentinel

from app.config import settings

_client: Optional[redis.Redis] = None


def get_redis() -> redis.Redis:
    """Return the shared async Redis client, creating the pool on first use.

    When ``SENTINEL_REDIS_SENTINEL_URLS`` is set the client is obtained via
    Redis Sentinel so that automatic master failover is handled transparently.
    Falls back to a direct connection when the variable is empty.
    """
    global _client
    if _client is None:
        if settings.redis_sentinel_urls:
            # HA mode — connect through Sentinel
            sentinel_hosts = [
                (host.strip(), int(port))
                for entry in settings.redis_sentinel_urls.split(",")
                for host, port in [entry.strip().rsplit(":", 1)]
            ]
            sentinel_kwargs: dict = {}
            if settings.redis_password:
                sentinel_kwargs["password"] = settings.redis_password

            sentinel = Sentinel(
                sentinel_hosts,
                sentinel_kwargs=sentinel_kwargs,
                password=settings.redis_password or None,
                decode_responses=True,
            )
            _client = sentinel.master_for(
                settings.redis_sentinel_master,
                redis_class=redis.Redis,
            )
        else:
            # Direct connection (default / non-HA)
            kwargs: dict = {"encoding": "utf-8", "decode_responses": True}
            if settings.redis_password:
                kwargs["password"] = settings.redis_password
            _client = redis.from_url(settings.redis_url, **kwargs)
    return _client


async def close_redis() -> None:
    """Close the shared Redis client and drop the pool."""
    global _client
    if _client is not None:
        await _client.aclose()
        _client = None
