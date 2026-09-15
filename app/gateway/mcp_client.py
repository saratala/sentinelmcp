"""Minimal MCP client for the active probe.

Real MCP servers speak **Streamable HTTP**: the client must (1) POST an
``initialize`` request and reuse the returned ``Mcp-Session-Id`` on subsequent
calls, and (2) accept responses as either JSON or an SSE (``text/event-stream``)
stream. This client does both, and falls back to plain HTTP JSON-RPC for the
simple demo servers that don't implement the handshake — so the probe works
against real open-source MCP servers (directly or via an stdio→HTTP bridge) as
well as the bundled demo targets.
"""
from __future__ import annotations

import json
from typing import Any

import httpx

_PROTOCOL_VERSION = "2025-06-18"
_INITIALIZE = {
    "jsonrpc": "2.0", "id": 0, "method": "initialize",
    "params": {
        "protocolVersion": _PROTOCOL_VERSION,
        "capabilities": {},
        "clientInfo": {"name": "sentinelmcp-probe", "version": "0.2.0"},
    },
}


def parse_response(resp: httpx.Response) -> dict:
    """Parse an MCP HTTP response as JSON, or extract the JSON from an SSE stream."""
    ctype = resp.headers.get("content-type", "")
    body = resp.text
    is_sse = "text/event-stream" in ctype or body.lstrip().startswith(("event:", "data:"))
    if is_sse:
        # Collect ``data:`` payloads and return the last one that parses as a
        # JSON-RPC response (SSE may carry multiple events).
        datas = [line[5:].strip() for line in body.splitlines() if line.startswith("data:")]
        for chunk in reversed(datas):
            try:
                return json.loads(chunk)
            except (ValueError, TypeError):
                continue
        return {"error": "unparseable SSE response"}
    try:
        return resp.json()
    except (ValueError, TypeError):
        return {"error": "non-JSON response"}


class MCPClient:
    """Session-aware MCP transport over an existing httpx.AsyncClient."""

    def __init__(self, http: httpx.AsyncClient, url: str, timeout: float) -> None:
        self._http = http
        self._url = url
        self._timeout = timeout
        self._session_id: str | None = None
        self._initialized = False
        self.mode: str | None = None   # "streamable" | "simple" (after first use)

    def _headers(self) -> dict:
        h = {"Content-Type": "application/json",
             "Accept": "application/json, text/event-stream"}
        if self._session_id:
            h["Mcp-Session-Id"] = self._session_id
        return h

    async def _post(self, payload: dict) -> httpx.Response:
        resp = await self._http.post(self._url, json=payload,
                                     headers=self._headers(), timeout=self._timeout)
        sid = resp.headers.get("mcp-session-id")
        if sid:
            self._session_id = sid
        return resp

    async def _ensure_initialized(self) -> None:
        """Perform the MCP initialize handshake once; detect simple servers."""
        if self._initialized:
            return
        self._initialized = True
        try:
            resp = await self._post(_INITIALIZE)
            data = parse_response(resp)
            if isinstance(data, dict) and isinstance(data.get("result"), dict) \
                    and data["result"].get("protocolVersion"):
                self.mode = "streamable"
                try:  # best-effort: complete the handshake
                    await self._post({"jsonrpc": "2.0", "method": "notifications/initialized",
                                      "params": {}})
                except Exception:
                    pass
            else:
                self.mode = "simple"
        except Exception:
            self.mode = "simple"

    async def list_tools(self) -> list[dict]:
        """Return the server's tool list ([] on any failure)."""
        try:
            await self._ensure_initialized()
            resp = await self._post({"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}})
            data = parse_response(resp)
            return data.get("result", {}).get("tools", []) if isinstance(data, dict) else []
        except Exception:
            return []

    async def call_tool(self, name: str, arguments: dict) -> dict:
        """Invoke a tool and return the raw JSON-RPC response ({error:…} on failure)."""
        try:
            await self._ensure_initialized()
            resp = await self._post({
                "jsonrpc": "2.0", "id": 2, "method": "tools/call",
                "params": {"name": name, "arguments": arguments},
            })
            return parse_response(resp)
        except Exception as exc:
            return {"error": str(exc)}
