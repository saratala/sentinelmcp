"""SentinelMCP SDK — async and sync clients.

Quick start:
    from sentinelmcp_sdk import SentinelClient
    sentinel = SentinelClient(api_key="sk-...")
    result = sentinel.analyze("http://my-mcp-server:8001")
    print(result.verdict)  # PASS or BLOCK
"""
from __future__ import annotations

import asyncio
import json
from typing import Any, Optional

import httpx

from .exceptions import AuthError, GatewayError, RateLimitError, SentinelError


class SentinelResult:
    """Result from a SentinelMCP analysis."""

    def __init__(self, raw: dict):
        self.raw = raw
        self.verdict: str = raw.get("verdict", "PASS")
        self.threats_found: int = raw.get("threats_found", 0)
        self.threats: list[dict] = raw.get("threats", [])
        self.latency_ms: float = raw.get("latency_ms", 0.0)
        self.recommendation: str = raw.get("recommendation", "")
        self.owasp_ids: list[str] = raw.get("owasp_ids", [])
        self.session_id: str = raw.get("session_id", "")

    @property
    def is_blocked(self) -> bool:
        return self.verdict == "BLOCK"

    @property
    def is_safe(self) -> bool:
        return self.verdict == "PASS"

    def __repr__(self) -> str:
        return f"SentinelResult(verdict={self.verdict!r}, threats={self.threats_found})"


class AsyncSentinelClient:
    """Async client for the SentinelMCP gateway API."""

    def __init__(
        self,
        api_key: str,
        gateway_url: str = "http://localhost:8888",
        timeout: float = 30.0,
    ):
        self.api_key = api_key
        self.gateway_url = gateway_url.rstrip("/")
        self._timeout = timeout
        self._client: Optional[httpx.AsyncClient] = None

    def _headers(self) -> dict:
        return {"X-Sentinel-Key": self.api_key, "Content-Type": "application/json"}

    async def _get_client(self) -> httpx.AsyncClient:
        if self._client is None or self._client.is_closed:
            self._client = httpx.AsyncClient(
                base_url=self.gateway_url,
                headers=self._headers(),
                timeout=self._timeout,
            )
        return self._client

    def _raise_for_status(self, resp: httpx.Response) -> None:
        if resp.status_code == 401:
            raise AuthError("Invalid API key or JWT token", 401)
        if resp.status_code == 429:
            raise RateLimitError("Rate limit exceeded", 429)
        if resp.status_code >= 500:
            raise GatewayError(f"Gateway error: {resp.text[:200]}", resp.status_code)
        if resp.status_code >= 400:
            raise SentinelError(f"Request error {resp.status_code}: {resp.text[:200]}", resp.status_code)

    async def analyze(
        self,
        server_url: str,
        tool_calls: Optional[list[dict]] = None,
        session_id: Optional[str] = None,
    ) -> SentinelResult:
        """Analyze an MCP server or specific tool calls for security threats.

        Args:
            server_url: The MCP server URL to analyze.
            tool_calls: Optional list of tool calls to check, e.g.
                [{"name": "query_db", "arguments": {"query": "SELECT *"}}]
            session_id: Optional session identifier for context tracking.

        Returns:
            SentinelResult with verdict (PASS/BLOCK), threats, and OWASP IDs.
        """
        client = await self._get_client()
        payload = {
            "server_url": server_url,
            "tool_calls": tool_calls or [],
        }
        if session_id:
            payload["session_id"] = session_id
        resp = await client.post("/proxy/analyze", json=payload)
        self._raise_for_status(resp)
        return SentinelResult(resp.json())

    async def explain(
        self,
        threat_type: str,
        pattern: str = "",
        context: str = "",
    ) -> dict:
        """Get a detailed explanation of a threat type.

        Args:
            threat_type: e.g. "PROMPT_INJECTION", "SENSITIVE_DISCLOSURE"
            pattern: The specific pattern that triggered the threat.
            context: Additional context about the threat.

        Returns:
            Dict with explanation, mitigation, and OWASP reference.
        """
        client = await self._get_client()
        resp = await client.get(
            "/gateway/threats/explain",
            params={"threat_type": threat_type, "pattern": pattern, "context": context},
        )
        self._raise_for_status(resp)
        return resp.json()

    async def report(self, days: int = 30) -> dict:
        """Get a compliance report for the past N days.

        Returns:
            Dict with PCI DSS and SOC2 compliance mappings, threat statistics.
        """
        client = await self._get_client()
        resp = await client.get("/gateway/compliance/report", params={"days": days})
        self._raise_for_status(resp)
        return resp.json()

    async def probe(
        self,
        server_url: str,
        attacks: Optional[list[str]] = None,
        timeout_secs: int = 10,
    ) -> dict:
        """Run a penetration test against an MCP server.

        Args:
            server_url: Target MCP server URL.
            attacks: List of attack types, or ["all"] for all attacks.
            timeout_secs: Per-probe timeout.

        Returns:
            ProbeReport dict with findings, risk score, and recommendations.
        """
        client = await self._get_client()
        payload = {
            "server_url": server_url,
            "attacks": attacks or ["all"],
            "timeout_secs": timeout_secs,
        }
        resp = await client.post("/probe", json=payload)
        self._raise_for_status(resp)
        return resp.json()

    async def threats(
        self,
        days: int = 7,
        threat_type: Optional[str] = None,
        limit: int = 100,
    ) -> dict:
        """List recent threat events.

        Returns:
            Dict with list of threats and pagination info.
        """
        client = await self._get_client()
        params = {"days": days, "limit": limit}
        if threat_type:
            params["threat_type"] = threat_type
        resp = await client.get("/gateway/threats", params=params)
        self._raise_for_status(resp)
        return resp.json()

    async def stats(self) -> dict:
        """Get threat statistics (counts by type and layer)."""
        client = await self._get_client()
        resp = await client.get("/gateway/threats/stats")
        self._raise_for_status(resp)
        return resp.json()

    async def health(self) -> dict:
        """Check gateway health and per-layer latency."""
        client = await self._get_client()
        resp = await client.get("/health")
        self._raise_for_status(resp)
        return resp.json()

    async def create_key(self, label: str, tenant_id: str, rate_limit_per_min: int = 600) -> dict:
        """Create a new per-tenant API key. Returns the raw key once — store it securely."""
        client = await self._get_client()
        resp = await client.post("/keys", json={
            "label": label,
            "tenant_id": tenant_id,
            "rate_limit_per_min": rate_limit_per_min,
        })
        self._raise_for_status(resp)
        return resp.json()

    async def close(self) -> None:
        """Close the underlying HTTP client."""
        if self._client and not self._client.is_closed:
            await self._client.aclose()

    async def __aenter__(self) -> "AsyncSentinelClient":
        return self

    async def __aexit__(self, *args) -> None:
        await self.close()


class SentinelClient:
    """Synchronous client for the SentinelMCP gateway API.

    Wraps AsyncSentinelClient using asyncio.run() for blocking calls.

    Quick start:
        from sentinelmcp_sdk import SentinelClient
        sentinel = SentinelClient(api_key="sk-...")
        result = sentinel.analyze("http://my-mcp-server:8001")
        if result.is_blocked:
            raise Exception(f"Blocked: {result.threats}")
    """

    def __init__(
        self,
        api_key: str,
        gateway_url: str = "http://localhost:8888",
        timeout: float = 30.0,
    ):
        self._async = AsyncSentinelClient(api_key=api_key, gateway_url=gateway_url, timeout=timeout)

    def _run(self, coro):
        try:
            loop = asyncio.get_event_loop()
            if loop.is_running():
                import concurrent.futures
                with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
                    future = pool.submit(asyncio.run, coro)
                    return future.result()
            return loop.run_until_complete(coro)
        except RuntimeError:
            return asyncio.run(coro)

    def analyze(self, server_url: str, tool_calls: Optional[list[dict]] = None, session_id: Optional[str] = None) -> SentinelResult:
        return self._run(self._async.analyze(server_url, tool_calls, session_id))

    def explain(self, threat_type: str, pattern: str = "", context: str = "") -> dict:
        return self._run(self._async.explain(threat_type, pattern, context))

    def report(self, days: int = 30) -> dict:
        return self._run(self._async.report(days))

    def probe(self, server_url: str, attacks: Optional[list[str]] = None, timeout_secs: int = 10) -> dict:
        return self._run(self._async.probe(server_url, attacks, timeout_secs))

    def threats(self, days: int = 7, threat_type: Optional[str] = None, limit: int = 100) -> dict:
        return self._run(self._async.threats(days, threat_type, limit))

    def stats(self) -> dict:
        return self._run(self._async.stats())

    def health(self) -> dict:
        return self._run(self._async.health())

    def create_key(self, label: str, tenant_id: str, rate_limit_per_min: int = 600) -> dict:
        return self._run(self._async.create_key(label, tenant_id, rate_limit_per_min))
