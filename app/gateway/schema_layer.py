"""Layer 1 — schema cache, SHA-256 hash-watch, and rug-pull detection.

On first contact a server's tool schemas are deep-scanned for injection and the
result is cached in Redis under a SHA-256 hash with a short TTL. Subsequent
validations are ~0ms cache hits while the hash is unchanged. A hash change (or a
background re-validation) triggers a fresh deep scan; if a previously-clean
server now carries an injection payload it is flagged as a RUG_PULL.
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import time
from datetime import datetime, timezone
from typing import Any, Awaitable, Callable, Optional

import structlog

from app.config import settings
from app.core.policy_engine import get_policy_engine
from app.detection.patterns import detect_injection
from app.models.schemas import SchemaValidationResult, ThreatDetail

log = structlog.get_logger(__name__)

# A fetcher pulls the current tool list for a server (used by re-validation).
ToolFetcher = Callable[[str], Awaitable[list]]


def schema_hash(tools: list) -> str:
    """Return a deterministic SHA-256 hex digest of a tool-schema list."""
    canonical = json.dumps(tools, sort_keys=True, ensure_ascii=True, default=str)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _now_iso() -> str:
    """Return the current UTC time as an ISO-8601 string with a trailing Z."""
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


class SchemaLayer:
    """Schema-layer validator backed by a Redis schema cache."""

    def __init__(self, redis_client: Any, ttl: Optional[int] = None,
                 key_prefix: Optional[str] = None) -> None:
        self._redis = redis_client
        self._ttl = ttl if ttl is not None else settings.schema_cache_ttl
        self._prefix = key_prefix if key_prefix is not None else settings.schema_key_prefix

    def _key(self, server_url: str) -> str:
        """Return the Redis cache key for a server."""
        return f"{self._prefix}{server_url}"

    async def get_cached(self, server_url: str) -> Optional[dict]:
        """Return the cached schema record for a server, or None if absent."""
        raw = await self._redis.get(self._key(server_url))
        return json.loads(raw) if raw else None

    async def invalidate(self, server_url: str) -> None:
        """Drop a server's cached schema, forcing a deep scan on next validate."""
        await self._redis.delete(self._key(server_url))

    async def list_cached_servers(self) -> list[str]:
        """Return all server URLs currently present in the schema cache."""
        keys = await self._redis.keys(f"{self._prefix}*")
        plen = len(self._prefix)
        return [k[plen:] for k in keys]

    @staticmethod
    def _deep_scan(tools: list) -> tuple[list[ThreatDetail], list[dict]]:
        """Scan every tool's name+description for injection. Returns (threats, clean)."""
        threats: list[ThreatDetail] = []
        clean: list[dict] = []
        engine = get_policy_engine()
        for tool in tools:
            name = str(tool.get("name", "")) if isinstance(tool, dict) else ""
            desc = str(tool.get("description", "")) if isinstance(tool, dict) else ""
            text = f"{name} {desc}"

            # Built-in patterns first
            hit = detect_injection(text)
            if hit:
                threats.append(ThreatDetail(
                    tool=name, threat_type="TOOL_POISONING",
                    pattern=hit["pattern"], match=hit["match"],
                    confidence=hit["confidence"],
                ))
                continue

            # Policy-engine rules (YAML-driven, hot-reloadable)
            policy_hits = engine.scan(text, layer=1)
            if policy_hits:
                h = policy_hits[0]
                threats.append(ThreatDetail(
                    tool=name, threat_type=h.threat_type,
                    pattern=h.name, match=h.match,
                    confidence=h.confidence,
                ))
                continue

            clean.append(tool)
        return threats, clean

    async def _store(self, server_url: str, new_hash: str,
                     result: SchemaValidationResult) -> None:
        """Persist a validation result to Redis under the schema TTL."""
        record = {
            "hash": new_hash,
            "passed": result.passed,
            "tools": result.clean_tools,
            "threats": [t.model_dump() for t in result.threats],
            "validated_at": result.validated_at,
        }
        await self._redis.set(self._key(server_url), json.dumps(record), ex=self._ttl)

    async def validate(self, server_url: str, tools: list) -> SchemaValidationResult:
        """Validate a server's tool schemas, using the cache and detecting rug pulls."""
        t0 = time.perf_counter()
        new_hash = schema_hash(tools)
        cached = await self.get_cached(server_url)

        # Fast path — cache hit with an unchanged hash. ~0ms, no rescan.
        if cached is not None and cached.get("hash") == new_hash:
            return SchemaValidationResult(
                server_url=server_url, schema_hash=new_hash,
                passed=cached.get("passed", True), cache_hit=True,
                is_new_server=False, schema_changed=False,
                threats=[ThreatDetail(**t) for t in cached.get("threats", [])],
                clean_tools=cached.get("tools", []),
                total_tools=len(tools), blocked_tools=len(cached.get("threats", [])),
                validated_at=cached.get("validated_at", ""),
                latency_ms=round((time.perf_counter() - t0) * 1000, 3),
            )

        # Slow path — new server or changed hash. Deep scan.
        is_new = cached is None
        hash_changed = cached is not None and cached.get("hash") != new_hash
        threats, clean = self._deep_scan(tools)

        # Rug pull: a previously-clean server now ships an injection payload.
        rug_pull = bool(hash_changed and cached.get("passed") and threats)
        if rug_pull:
            for t in threats:
                t.threat_type = "RUG_PULL"

        result = SchemaValidationResult(
            server_url=server_url, schema_hash=new_hash,
            passed=not threats, cache_hit=False, is_new_server=is_new,
            schema_changed=hash_changed, rug_pull=rug_pull,
            threats=threats, clean_tools=clean,
            total_tools=len(tools), blocked_tools=len(threats),
            validated_at=_now_iso(),
            latency_ms=round((time.perf_counter() - t0) * 1000, 3),
        )

        if rug_pull:
            log.warning("rug_pull_detected", server=server_url,
                        old_hash=cached.get("hash"), new_hash=new_hash,
                        threats=[t.model_dump() for t in threats])
        elif threats:
            log.warning("tool_poisoning_detected", server=server_url,
                        new_hash=new_hash, threats=[t.model_dump() for t in threats])
        elif hash_changed:
            log.info("schema_changed_clean", server=server_url,
                     old_hash=cached.get("hash"), new_hash=new_hash)

        await self._store(server_url, new_hash, result)
        return result


class BackgroundRevalidator:
    """Periodically re-fetches and re-validates every cached server's schemas."""

    def __init__(self, schema_layer: SchemaLayer, fetch_tools: ToolFetcher,
                 interval: Optional[int] = None) -> None:
        self._layer = schema_layer
        self._fetch = fetch_tools
        self._interval = interval if interval is not None else settings.revalidation_interval
        self._task: Optional[asyncio.Task] = None
        self._stopped = asyncio.Event()

    async def run_once(self) -> list[SchemaValidationResult]:
        """Re-validate every cached server once. Returns each server's result."""
        servers = await self._layer.list_cached_servers()
        results: list[SchemaValidationResult] = []
        for server_url in servers:
            try:
                tools = await self._fetch(server_url)
            except Exception as exc:  # fetch failure must not abort the sweep
                log.error("revalidation_fetch_failed", server=server_url, error=str(exc))
                continue
            result = await self._layer.validate(server_url, tools)
            if result.rug_pull:
                log.warning("revalidation_rug_pull", server=server_url)
            results.append(result)
        return results

    async def _loop(self) -> None:
        """Run ``run_once`` every ``interval`` seconds until stopped."""
        while not self._stopped.is_set():
            try:
                await self.run_once()
            except Exception as exc:  # keep the loop alive across sweep errors
                log.error("revalidation_sweep_failed", error=str(exc))
            try:
                await asyncio.wait_for(self._stopped.wait(), timeout=self._interval)
            except asyncio.TimeoutError:
                pass

    def start(self) -> None:
        """Start the background re-validation loop as an asyncio task."""
        if self._task is None or self._task.done():
            self._stopped.clear()
            self._task = asyncio.create_task(self._loop())

    async def stop(self) -> None:
        """Signal the loop to stop and await its completion."""
        self._stopped.set()
        if self._task is not None:
            await self._task
            self._task = None
