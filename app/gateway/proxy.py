"""MCP transparent proxy — JSON-RPC 2.0 gateway with 4-layer validation.

Intercepts every MCP call between an AI agent and a real MCP server:
  tools/list      → L1 schema validation before returning tools to agent
  tools/call      → L2+L4 concurrent validation; L3 async on response
  everything else → transparent forward (initialize, ping, resources/list, …)

Usage:
  Agent configures SentinelMCP as its MCP server URL.
  Sends header X-MCP-Target pointing at the real MCP server.
  SentinelMCP proxies all traffic, blocking threats invisibly.
"""
from __future__ import annotations

import asyncio
import time
import uuid
from typing import Any, Optional

import httpx
import structlog

from app.core.circuit_breaker import CircuitBreaker
from app.core.database import get_db
from app.core.threat_log import log_threat
from app.gateway.context_layer import ContextLayer
from app.gateway.output_layer import inspect_output
from app.gateway.param_layer import ParamLayer
from app.gateway.schema_layer import SchemaLayer
from app.gateway.validator import GatewayValidator
from app.models.schemas import ThreatDetail

log = structlog.get_logger(__name__)

PROXY_TIMEOUT = 30.0  # seconds for forwarded requests


def _jsonrpc_error(id: Any, code: int, message: str, data: Any = None) -> dict:
    err: dict = {"code": code, "message": message}
    if data is not None:
        err["data"] = data
    return {"jsonrpc": "2.0", "id": id, "error": err}


def _jsonrpc_ok(id: Any, result: Any) -> dict:
    return {"jsonrpc": "2.0", "id": id, "result": result}


class MCPProxy:
    """Transparent JSON-RPC 2.0 proxy with full 4-layer validation."""

    def __init__(
        self,
        schema_layer: SchemaLayer,
        context_layer: ContextLayer,
        circuit_breaker: CircuitBreaker,
    ) -> None:
        self._schema = schema_layer
        self._validator = GatewayValidator(
            param_layer=ParamLayer(),
            context_layer=context_layer,
            circuit_breaker=circuit_breaker,
        )
        self._cb = circuit_breaker
        # Cache tool inputSchemas so L2 can validate tools/call params.
        # key: (target_url, tool_name) → inputSchema dict
        self._tool_schemas: dict[tuple[str, str], dict] = {}

    async def handle(
        self,
        body: dict,
        target_url: str,
        session_id: str,
    ) -> dict:
        """Handle one JSON-RPC request. Returns a JSON-RPC response dict."""
        method = body.get("method", "")
        rpc_id = body.get("id")
        t0 = time.perf_counter()

        log.debug("proxy_request", method=method, target=target_url, session=session_id)

        if method == "tools/list":
            return await self._handle_tools_list(body, target_url, session_id, rpc_id)

        if method == "tools/call":
            return await self._handle_tools_call(body, target_url, session_id, rpc_id, t0)

        # Transparent forward for: initialize, ping, resources/list,
        # prompts/list, completion/complete, logging/setLevel, etc.
        return await self._forward(target_url, body)

    # ── tools/list ────────────────────────────────────────────────────────────

    async def _handle_tools_list(
        self, body: dict, target_url: str, session_id: str, rpc_id: Any
    ) -> dict:
        """Forward tools/list, run L1 schema validation, block if poisoned."""
        # Forward to real server first to get current tool list.
        upstream = await self._forward(target_url, body)
        if "error" in upstream:
            return upstream

        tools = upstream.get("result", {}).get("tools", [])
        if not tools:
            return upstream

        # L1 — schema validation + rug pull detection
        schema_result = await self._schema.validate(target_url, tools)

        if not schema_result.passed:
            await self._log_schema_threats(target_url, session_id, schema_result)
            log.warning("proxy_tools_list_blocked",
                        target=target_url, threats=len(schema_result.threats))
            return _jsonrpc_error(
                rpc_id, -32001,
                "SentinelMCP: server blocked — tool poisoning detected",
                data={
                    "threats": [t.model_dump() for t in schema_result.threats],
                    "rug_pull": schema_result.rug_pull,
                    "sentinel": True,
                },
            )

        # Cache inputSchemas for L2 validation on subsequent tools/call
        for tool in tools:
            key = (target_url, tool.get("name", ""))
            self._tool_schemas[key] = tool.get("inputSchema", {})

        return upstream

    # ── tools/call ────────────────────────────────────────────────────────────

    async def _handle_tools_call(
        self, body: dict, target_url: str, session_id: str, rpc_id: Any, t0: float
    ) -> dict:
        """L2+L4 validate params, forward if clean, L3 inspect response async."""
        params = body.get("params", {})
        tool_name = params.get("name", "")
        arguments = params.get("arguments", {})

        # Retrieve cached inputSchema (from prior tools/list call)
        input_schema = self._tool_schemas.get(
            (target_url, tool_name),
            {"type": "object", "properties": {}},
        )

        # L2 + L4 concurrent validation
        invocation = await self._validator.validate_invocation(
            session_id=session_id,
            tool_name=tool_name,
            params=arguments,
            input_schema=input_schema,
        )

        latency_ms = round((time.perf_counter() - t0) * 1000, 2)

        if not invocation.passed:
            reason = "circuit breaker open" if invocation.blocked_by_circuit else "validation failed"
            log.warning("proxy_tools_call_blocked",
                        tool=tool_name, session=session_id, reason=reason)
            return _jsonrpc_error(
                rpc_id, -32002,
                f"SentinelMCP: tool call blocked — {reason}",
                data={
                    "tool": tool_name,
                    "sentinel": True,
                    "latency_ms": latency_ms,
                    "param_errors": invocation.param_result.errors if invocation.param_result else [],
                    "context_risk": invocation.context_result.risk_score if invocation.context_result else 0,
                },
            )

        # Forward clean call to real MCP server
        upstream = await self._forward(target_url, body)

        # L3 — fire-and-forget output inspection (never blocks response)
        output_text = self._extract_output_text(upstream)
        if output_text:
            asyncio.create_task(
                inspect_output(session_id, tool_name, output_text, self._cb)
            )

        log.info("proxy_tools_call_forwarded",
                 tool=tool_name, session=session_id, latency_ms=latency_ms)
        return upstream

    # ── helpers ───────────────────────────────────────────────────────────────

    async def _forward(self, target_url: str, body: dict) -> dict:
        """Forward a JSON-RPC request to the real MCP server."""
        try:
            async with httpx.AsyncClient(timeout=PROXY_TIMEOUT) as client:
                resp = await client.post(
                    target_url,
                    json=body,
                    headers={"Content-Type": "application/json"},
                )
                resp.raise_for_status()
                return resp.json()
        except httpx.TimeoutException:
            return _jsonrpc_error(body.get("id"), -32300, "MCP server timeout")
        except httpx.HTTPStatusError as e:
            return _jsonrpc_error(body.get("id"), -32300,
                                  f"MCP server error: {e.response.status_code}")
        except Exception as e:
            log.error("proxy_forward_error", error=str(e), target=target_url)
            return _jsonrpc_error(body.get("id"), -32300, f"Upstream unreachable: {e}")

    def _extract_output_text(self, upstream: dict) -> Optional[str]:
        """Extract text content from a tools/call JSON-RPC response for L3 scan."""
        result = upstream.get("result", {})
        # MCP tools/call result: {"content": [{"type": "text", "text": "..."}]}
        content = result.get("content", [])
        texts = [c.get("text", "") for c in content if c.get("type") == "text"]
        if texts:
            return "\n".join(texts)
        # Fallback: stringify the whole result
        if result:
            import json
            return json.dumps(result)[:4096]
        return None

    async def _log_schema_threats(
        self, server_url: str, session_id: str, schema_result: Any
    ) -> None:
        """Persist schema threats to PostgreSQL threat log."""
        try:
            async for db in get_db():
                for threat in schema_result.threats:
                    await log_threat(
                        db,
                        server_url=server_url,
                        tool_name=threat.tool,
                        threat=threat,
                        layer=1,
                        rug_pull=schema_result.rug_pull,
                        raw_payload=schema_result.model_dump(),
                        session_id=session_id,
                    )
        except Exception as e:
            log.error("proxy_threat_log_error", error=str(e))
