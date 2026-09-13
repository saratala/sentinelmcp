"""Cross-session / fleet drift detection — temporal rug-pull defense.

Intra-run hash-watch (Layer 1) catches a tool description that changes *within*
one session. It is blind to the slower, more dangerous class: a description that
mutates gradually **across sessions and days**, or that is served *differently to
different tenants* (a targeted attack). This module maintains a longitudinal
fingerprint history per (server, tool) in Redis and scores semantic drift against
the first-seen baseline, plus cross-tenant divergence.

Deterministic (stdlib ``difflib`` similarity, no ML), Redis-backed, and separate
from the short-lived schema cache so history persists for weeks. This is the
temporal wedge the market research flagged as largely unmet.
"""
from __future__ import annotations

import json
import re
import time
from dataclasses import dataclass, field
from difflib import SequenceMatcher
from typing import Any

import structlog

log = structlog.get_logger(__name__)

_WORD = re.compile(r"[a-z0-9]+")


def _fingerprint(description: str) -> str:
    """Normalize a description into a comparable token fingerprint."""
    tokens = _WORD.findall((description or "").lower())
    # Sorted unique tokens: robust to reordering, sensitive to meaning change.
    return " ".join(sorted(set(tokens)))


def _similarity(a: str, b: str) -> float:
    """Return a 0–1 similarity ratio between two fingerprints."""
    if not a and not b:
        return 1.0
    if not a or not b:
        return 0.0
    return SequenceMatcher(None, a, b).ratio()


@dataclass
class DriftResult:
    server_url: str
    tool_name: str
    drifted: bool = False
    drift_score: float = 0.0          # 1 - similarity_to_baseline
    similarity_to_baseline: float = 1.0
    distinct_versions: int = 1
    baseline_age_days: float = 0.0
    cross_tenant_divergence: bool = False
    reason: str = ""

    def to_dict(self) -> dict:
        return {
            "server_url": self.server_url,
            "tool_name": self.tool_name,
            "drifted": self.drifted,
            "drift_score": round(self.drift_score, 4),
            "similarity_to_baseline": round(self.similarity_to_baseline, 4),
            "distinct_versions": self.distinct_versions,
            "baseline_age_days": round(self.baseline_age_days, 2),
            "cross_tenant_divergence": self.cross_tenant_divergence,
            "reason": self.reason,
        }


class DriftMonitor:
    """Longitudinal per-(server, tool) fingerprint history with drift scoring."""

    def __init__(self, redis_client: Any, max_history: int = 50,
                 ttl: int = 30 * 24 * 3600, drift_threshold: float = 0.6) -> None:
        self._redis = redis_client
        self._max = max_history
        self._ttl = ttl
        # drift when similarity to baseline drops below this (i.e. >40% changed)
        self._threshold = drift_threshold

    def _key(self, server_url: str, tool_name: str) -> str:
        return f"drift:{server_url}::{tool_name}"

    async def record_and_score(self, server_url: str, tool_name: str,
                               description: str, tenant: str = "default",
                               now: float | None = None) -> DriftResult:
        """Record a description fingerprint and score drift vs the baseline."""
        now = now if now is not None else time.time()
        fp = _fingerprint(description)
        key = self._key(server_url, tool_name)

        raw = await self._redis.lrange(key, 0, -1)
        history = [json.loads(r) for r in raw] if raw else []

        result = DriftResult(server_url=server_url, tool_name=tool_name)

        if history:
            baseline = history[0]
            sim = _similarity(baseline["fp"], fp)
            result.similarity_to_baseline = sim
            result.drift_score = round(1.0 - sim, 4)
            result.baseline_age_days = (now - baseline["ts"]) / 86400.0
            distinct = {h["fp"] for h in history} | {fp}
            result.distinct_versions = len(distinct)

            # Cross-tenant divergence: the same tool is being served a materially
            # different description to different tenants (targeted attack signal).
            tenant_fps = {h.get("tenant", "default"): h["fp"] for h in history}
            for t, other_fp in tenant_fps.items():
                if t != tenant and _similarity(other_fp, fp) < self._threshold:
                    result.cross_tenant_divergence = True
                    break

            if sim < self._threshold and result.distinct_versions > 1:
                result.drifted = True
                result.reason = (
                    f"description drifted {result.drift_score:.0%} from baseline "
                    f"seen {result.baseline_age_days:.1f}d ago "
                    f"({result.distinct_versions} distinct versions)"
                )
            elif result.cross_tenant_divergence:
                result.drifted = True
                result.reason = "tool description diverges across tenants (targeted-attack signal)"

        # Append current observation; keep baseline (index 0) + recent tail.
        entry = json.dumps({"fp": fp, "ts": now, "tenant": tenant})
        if not history:
            await self._redis.rpush(key, entry)
        else:
            # Preserve baseline at head; trim the middle, keep recent tail.
            await self._redis.rpush(key, entry)
            await self._redis.ltrim(key, -(self._max - 1), -1)
            # Re-assert the baseline at the head if trimming dropped it.
            head = await self._redis.lrange(key, 0, 0)
            if head and json.loads(head[0]).get("ts") != history[0]["ts"]:
                await self._redis.lpush(key, json.dumps(history[0]))
        await self._redis.expire(key, self._ttl)

        if result.drifted:
            log.warning("cross_session_drift_detected", server=server_url,
                        tool=tool_name, **result.to_dict())
        return result

    async def status(self, server_url: str, tool_name: str) -> dict:
        """Return the current recorded drift status for a tool (no new record)."""
        raw = await self._redis.lrange(self._key(server_url, tool_name), 0, -1)
        if not raw:
            return {"server_url": server_url, "tool_name": tool_name, "tracked": False}
        history = [json.loads(r) for r in raw]
        baseline, current = history[0], history[-1]
        sim = _similarity(baseline["fp"], current["fp"])
        return {
            "server_url": server_url, "tool_name": tool_name, "tracked": True,
            "observations": len(history),
            "distinct_versions": len({h["fp"] for h in history}),
            "similarity_to_baseline": round(sim, 4),
            "drift_score": round(1.0 - sim, 4),
            "baseline_age_days": round((current["ts"] - baseline["ts"]) / 86400.0, 2),
        }

    async def list_tracked(self) -> list[str]:
        """Return all tracked ``server::tool`` keys (drift inventory)."""
        keys = await self._redis.keys("drift:*")
        return [k[len("drift:"):] for k in keys]
