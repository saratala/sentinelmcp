"""Redis connection pool and helpers for the gateway."""
from __future__ import annotations

from typing import Optional

import redis.asyncio as redis

from app.config import settings

_client: Optional[redis.Redis] = None


def get_redis() -> redis.Redis:
    """Return the shared async Redis client, creating the pool on first use."""
    global _client
    if _client is None:
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
