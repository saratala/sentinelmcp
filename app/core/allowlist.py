"""LLM05: MCP Server Allowlist — shadow server / supply chain protection.

Maintains a Redis-backed set of approved MCP server URLs. When enabled,
any request to an unknown server is rejected before L1 schema validation runs.

Usage:
  # Allow a server
  await allowlist.add("https://mcp.internal.company.com")

  # Check before proxying
  if not await allowlist.is_allowed(target_url):
      return blocked_response

  # Disable allowlist enforcement (permissive mode, default)
  SENTINEL_ALLOWLIST_ENABLED=false
"""
from __future__ import annotations

from typing import Any

import structlog

from app.config import settings

log = structlog.get_logger(__name__)

_ALLOWLIST_KEY = "sentinel:allowlist"


class ServerAllowlist:
    """Redis-backed allowlist of approved MCP server URLs."""

    def __init__(self, redis_client: Any) -> None:
        self._redis = redis_client

    async def add(self, server_url: str) -> None:
        await self._redis.sadd(_ALLOWLIST_KEY, server_url.rstrip("/"))
        log.info("allowlist_server_added", server=server_url)

    async def remove(self, server_url: str) -> None:
        await self._redis.srem(_ALLOWLIST_KEY, server_url.rstrip("/"))
        log.info("allowlist_server_removed", server=server_url)

    async def list_allowed(self) -> list[str]:
        members = await self._redis.smembers(_ALLOWLIST_KEY)
        return sorted(members)

    async def is_allowed(self, server_url: str) -> bool:
        """Return True if the server is allowed OR allowlist enforcement is off."""
        if not settings.allowlist_enabled:
            return True
        members = await self._redis.smembers(_ALLOWLIST_KEY)
        if not members:
            # Empty allowlist + enforcement on = block everything (fail-safe)
            log.warning("allowlist_empty_block", server=server_url)
            return False
        return server_url.rstrip("/") in members

    async def count(self) -> int:
        return await self._redis.scard(_ALLOWLIST_KEY)
