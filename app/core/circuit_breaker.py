"""Per-session circuit breaker for Layer 3.

When async output inspection finds a threat the circuit breaker trips for that
session. The NEXT call from the same session is blocked — the current call
already returned to the agent (async inspection never blocks).

State lives in Redis so it survives API restarts and is visible across instances.
"""
from __future__ import annotations

import time
from typing import Any, Optional

import structlog

log = structlog.get_logger(__name__)

# Redis key prefix and default TTL for open circuit entries.
CB_PREFIX = "cb:"
CB_TTL = 3600  # 1 hour — open circuits expire automatically


class CircuitBreaker:
    """Redis-backed per-session circuit breaker."""

    def __init__(self, redis_client: Any, prefix: str = CB_PREFIX,
                 ttl: int = CB_TTL) -> None:
        self._redis = redis_client
        self._prefix = prefix
        self._ttl = ttl

    def _key(self, session_id: str) -> str:
        """Return the Redis key for a session's circuit-breaker state."""
        return f"{self._prefix}{session_id}"

    async def is_open(self, session_id: str) -> bool:
        """Return True if the circuit is open (session is blocked)."""
        return bool(await self._redis.exists(self._key(session_id)))

    async def trip(self, session_id: str, reason: str) -> None:
        """Open the circuit for ``session_id`` and record the reason."""
        await self._redis.set(
            self._key(session_id),
            reason,
            ex=self._ttl,
        )
        log.warning("circuit_breaker_tripped", session=session_id, reason=reason)

    async def reset(self, session_id: str) -> None:
        """Manually close the circuit (e.g. after admin review)."""
        await self._redis.delete(self._key(session_id))
        log.info("circuit_breaker_reset", session=session_id)

    async def get_reason(self, session_id: str) -> Optional[str]:
        """Return the trip reason for an open circuit, or None if closed."""
        return await self._redis.get(self._key(session_id))
