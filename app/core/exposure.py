"""Context-oversharing DLP meter — OWASP Agentic/MCP "context oversharing".

Point-in-time PII scanning (Layer 3) answers "does this one response leak data?".
It cannot answer "how much sensitive data has this agent session pushed out, and
to how many destinations?" — the oversharing question OWASP MCP10 raises and that
no public tool quantifies. This meter accumulates, per session, the volume and
categories of sensitive data flowing OUT to each destination server, and flags
two conditions: (1) cumulative sensitive egress to one server exceeding a budget,
and (2) sensitive data fanning out across too many distinct destinations.

Redis-backed, deterministic (reuses the Layer-3 PII pattern set), and cheap.
"""
from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from typing import Any

import structlog

from app.detection.patterns import PII_PATTERNS

log = structlog.get_logger(__name__)


def scan_sensitive(text: str) -> dict[str, int]:
    """Count sensitive items in text by category (reusing the L3 PII patterns)."""
    counts: dict[str, int] = {}
    for name, pattern in PII_PATTERNS:
        n = len(pattern.findall(text or ""))
        if n:
            counts[name] = counts.get(name, 0) + n
    return counts


@dataclass
class ExposureResult:
    session_id: str
    server_url: str
    items_this_call: int = 0
    categories: dict[str, int] = field(default_factory=dict)
    cumulative_to_server: int = 0
    distinct_destinations: int = 1
    over_budget: bool = False
    fan_out_exceeded: bool = False
    reason: str = ""

    @property
    def flagged(self) -> bool:
        return self.over_budget or self.fan_out_exceeded

    def to_dict(self) -> dict:
        return {
            "session_id": self.session_id,
            "server_url": self.server_url,
            "items_this_call": self.items_this_call,
            "categories": self.categories,
            "cumulative_to_server": self.cumulative_to_server,
            "distinct_destinations": self.distinct_destinations,
            "over_budget": self.over_budget,
            "fan_out_exceeded": self.fan_out_exceeded,
            "flagged": self.flagged,
            "reason": self.reason,
        }


class ExposureMeter:
    """Per-session accounting of sensitive-data egress to destination servers."""

    def __init__(self, redis_client: Any, per_server_budget: int = 5,
                 fan_out_limit: int = 3, ttl: int = 3600) -> None:
        self._redis = redis_client
        self._budget = per_server_budget      # max sensitive items to one server
        self._fan_out = fan_out_limit          # max distinct servers receiving sensitive data
        self._ttl = ttl

    def _key(self, session_id: str) -> str:
        return f"exposure:{session_id}"

    def _flatten(self, params: Any) -> str:
        try:
            return json.dumps(params, default=str)
        except Exception:
            return str(params)

    async def record(self, session_id: str, server_url: str,
                     params: Any) -> ExposureResult:
        """Record sensitive egress for one outbound tool call and score oversharing."""
        cats = scan_sensitive(self._flatten(params))
        items = sum(cats.values())
        result = ExposureResult(session_id=session_id, server_url=server_url,
                                items_this_call=items, categories=cats)

        key = self._key(session_id)
        raw = await self._redis.get(key)
        state = json.loads(raw) if raw else {"servers": {}}

        srv = state["servers"].setdefault(server_url, 0)
        if items:
            srv += items
            state["servers"][server_url] = srv

        result.cumulative_to_server = state["servers"].get(server_url, 0)
        # Count only destinations that have actually received sensitive data.
        sensitive_dests = [s for s, n in state["servers"].items() if n > 0]
        result.distinct_destinations = len(sensitive_dests)

        if result.cumulative_to_server > self._budget:
            result.over_budget = True
            result.reason = (
                f"{result.cumulative_to_server} sensitive items sent to "
                f"{server_url} exceeds budget of {self._budget}"
            )
        if result.distinct_destinations > self._fan_out:
            result.fan_out_exceeded = True
            fan_msg = (f"sensitive data fanned out to {result.distinct_destinations} "
                       f"destinations (limit {self._fan_out})")
            result.reason = f"{result.reason}; {fan_msg}" if result.reason else fan_msg

        await self._redis.set(key, json.dumps(state), ex=self._ttl)

        if result.flagged:
            log.warning("context_oversharing_detected", **result.to_dict())
        return result

    async def summary(self, session_id: str) -> dict:
        """Return the session's cumulative sensitive-egress picture."""
        raw = await self._redis.get(self._key(session_id))
        if not raw:
            return {"session_id": session_id, "tracked": False}
        state = json.loads(raw)
        servers = state.get("servers", {})
        sensitive = {s: n for s, n in servers.items() if n > 0}
        return {
            "session_id": session_id, "tracked": True,
            "total_sensitive_items": sum(sensitive.values()),
            "destinations": len(sensitive),
            "by_server": sensitive,
            "over_budget_servers": [s for s, n in sensitive.items() if n > self._budget],
            "fan_out_exceeded": len(sensitive) > self._fan_out,
        }
