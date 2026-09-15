"""Tests for the MCP Streamable-HTTP client used by the active probe."""
from __future__ import annotations

import json

import httpx
import pytest
import respx

from app.gateway.mcp_client import MCPClient, parse_response

URL = "http://mcp.test/mcp"


def _resp(content_type, body):
    return httpx.Response(200, headers={"content-type": content_type}, content=body)


def test_parse_json_response():
    r = _resp("application/json", json.dumps({"result": {"ok": True}}))
    assert parse_response(r)["result"]["ok"] is True


def test_parse_sse_response():
    sse = "event: message\ndata: " + json.dumps({"result": {"tools": [{"name": "t"}]}}) + "\n\n"
    r = _resp("text/event-stream", sse)
    assert parse_response(r)["result"]["tools"][0]["name"] == "t"


def test_parse_sse_returns_last_valid_event():
    sse = ("data: not json\n\n"
           "data: " + json.dumps({"result": {"v": 2}}) + "\n\n")
    r = _resp("text/event-stream", sse)
    assert parse_response(r)["result"]["v"] == 2


def _streamable_handler(request):
    """A real-ish MCP server: initialize returns a session; responses are SSE."""
    body = json.loads(request.content)
    method = body.get("method")
    if method == "initialize":
        return httpx.Response(
            200, headers={"content-type": "application/json", "mcp-session-id": "sess-123"},
            json={"jsonrpc": "2.0", "id": 0,
                  "result": {"protocolVersion": "2025-06-18", "capabilities": {},
                             "serverInfo": {"name": "real", "version": "1"}}})
    if method == "notifications/initialized":
        return httpx.Response(202)
    if method == "tools/list":
        # Requires the session header the client captured from initialize.
        assert request.headers.get("mcp-session-id") == "sess-123"
        sse = "event: message\ndata: " + json.dumps(
            {"jsonrpc": "2.0", "id": 1, "result": {"tools": [{"name": "run_query"}]}}) + "\n\n"
        return httpx.Response(200, headers={"content-type": "text/event-stream"}, content=sse)
    if method == "tools/call":
        sse = "data: " + json.dumps(
            {"jsonrpc": "2.0", "id": 2, "result": {"content": [{"type": "text", "text": "ok"}]}}) + "\n\n"
        return httpx.Response(200, headers={"content-type": "text/event-stream"}, content=sse)
    return httpx.Response(400)


@pytest.mark.asyncio
@respx.mock
async def test_streamable_server_handshake_and_sse():
    respx.post(URL).mock(side_effect=_streamable_handler)
    async with httpx.AsyncClient() as http:
        mcp = MCPClient(http, URL, timeout=5)
        tools = await mcp.list_tools()
        assert mcp.mode == "streamable"
        assert tools == [{"name": "run_query"}]
        call = await mcp.call_tool("run_query", {"q": "1"})
        assert call["result"]["content"][0]["text"] == "ok"


def _simple_handler(request):
    """A simple demo server: no initialize handshake, plain JSON tools/list."""
    body = json.loads(request.content)
    if body.get("method") == "initialize":
        return httpx.Response(200, json={"jsonrpc": "2.0", "id": 0,
                                         "error": {"code": -32601, "message": "unknown"}})
    if body.get("method") == "tools/list":
        return httpx.Response(200, json={"jsonrpc": "2.0", "id": 1,
                                         "result": {"tools": [{"name": "get_weather"}]}})
    return httpx.Response(200, json={"jsonrpc": "2.0", "result": {}})


@pytest.mark.asyncio
@respx.mock
async def test_simple_server_falls_back():
    respx.post(URL).mock(side_effect=_simple_handler)
    async with httpx.AsyncClient() as http:
        mcp = MCPClient(http, URL, timeout=5)
        tools = await mcp.list_tools()
        assert mcp.mode == "simple"
        assert tools == [{"name": "get_weather"}]


@pytest.mark.asyncio
@respx.mock
async def test_unreachable_server_returns_empty():
    respx.post(URL).mock(side_effect=httpx.ConnectError("refused"))
    async with httpx.AsyncClient() as http:
        mcp = MCPClient(http, URL, timeout=2)
        assert await mcp.list_tools() == []
        assert "error" in await mcp.call_tool("x", {})
