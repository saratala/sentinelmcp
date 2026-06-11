"""FastAPI router for the MCP transparent proxy endpoint.

Single endpoint: POST /proxy
Headers:
  X-MCP-Target:   URL of the real MCP server (required)
  X-Session-ID:   AI agent session identifier (auto-generated if omitted)
  X-Sentinel-Key: API key (standard auth)

The agent configures this URL as its MCP server endpoint.
SentinelMCP intercepts all JSON-RPC calls transparently.
"""
from __future__ import annotations

import uuid

import structlog
from fastapi import APIRouter, Depends, Header, HTTPException, Request

from app.core.auth import require_api_key
from app.core.rate_limit import limiter
from app.deps import get_circuit_breaker, get_context_layer, get_schema_layer
from app.gateway.proxy import MCPProxy

log = structlog.get_logger(__name__)

router = APIRouter(tags=["proxy"])


@router.post("/proxy", dependencies=[Depends(require_api_key)])
@limiter.limit("600/minute")
async def mcp_proxy(
    request: Request,
    x_mcp_target: str = Header(..., description="URL of the real MCP server"),
    x_session_id: str = Header(default="", description="Agent session ID"),
    schema_layer=Depends(get_schema_layer),
    context_layer=Depends(get_context_layer),
    circuit_breaker=Depends(get_circuit_breaker),
) -> dict:
    """Transparent MCP proxy — intercepts and validates all JSON-RPC traffic."""
    body = await request.json()

    if not body.get("jsonrpc"):
        raise HTTPException(status_code=400, detail="Not a JSON-RPC request")

    session_id = x_session_id or str(uuid.uuid4())
    # Ensure URL always has a path — httpx sends an empty path without it, causing 404
    from urllib.parse import urlparse as _up
    _p = _up(x_mcp_target)
    target_url = x_mcp_target if _p.path else x_mcp_target.rstrip("/") + "/"

    proxy = MCPProxy(
        schema_layer=schema_layer,
        context_layer=context_layer,
        circuit_breaker=circuit_breaker,
    )

    result = await proxy.handle(body, target_url, session_id)

    # Return HTTP 200 always — errors are in JSON-RPC error field per spec.
    # Exception: circuit breaker / schema block returns 403 so agents can detect.
    if "error" in result and result["error"].get("data", {}).get("sentinel"):
        return result  # FastAPI will serialize; client reads error.code

    return result
