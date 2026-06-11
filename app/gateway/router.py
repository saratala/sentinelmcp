"""Gateway API router — /gateway/* endpoints."""
from __future__ import annotations

from typing import Any

import structlog
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from app.deps import get_circuit_breaker, get_context_layer, get_schema_layer
from app.gateway.param_layer import ParamLayer
from app.gateway.schema_layer import SchemaLayer
from app.gateway.validator import GatewayValidator
from app.core.circuit_breaker import CircuitBreaker
from app.gateway.context_layer import ContextLayer

log = structlog.get_logger(__name__)
router = APIRouter(prefix="/gateway", tags=["gateway"])


# ── Request / response shapes ─────────────────────────────────────────────────

class SchemaValidateRequest(BaseModel):
    server_url: str
    tools: list[dict[str, Any]] = Field(default_factory=list)


class InvokeRequest(BaseModel):
    session_id: str
    server_url: str
    tool_name: str
    params: dict[str, Any] = Field(default_factory=dict)
    input_schema: dict[str, Any] = Field(default_factory=dict)
    output: Any = None


# ── Endpoints ─────────────────────────────────────────────────────────────────

@router.post("/validate-schema")
async def validate_schema(
    req: SchemaValidateRequest,
    schema_layer: SchemaLayer = Depends(get_schema_layer),
) -> dict:
    """Layer 1 — validate and cache a server's tool schemas."""
    if not req.server_url:
        raise HTTPException(status_code=400, detail="server_url is required")
    result = await schema_layer.validate(req.server_url, req.tools)
    status_code = 200 if result.passed else 403
    return {"status_code": status_code, **result.model_dump()}


@router.post("/invoke")
async def invoke_tool(
    req: InvokeRequest,
    schema_layer: SchemaLayer = Depends(get_schema_layer),
    context_layer: ContextLayer = Depends(get_context_layer),
    circuit_breaker: CircuitBreaker = Depends(get_circuit_breaker),
) -> dict:
    """Layers 2 + 3 + 4 — validate a tool invocation."""
    if not req.session_id or not req.tool_name:
        raise HTTPException(status_code=400, detail="session_id and tool_name are required")

    validator = GatewayValidator(
        param_layer=ParamLayer(),
        context_layer=context_layer,
        circuit_breaker=circuit_breaker,
    )
    result = await validator.validate_invocation(
        session_id=req.session_id,
        tool_name=req.tool_name,
        params=req.params,
        input_schema=req.input_schema,
        output=req.output,
    )
    status_code = 200 if result.passed else 403
    return {"status_code": status_code, **result.model_dump()}


@router.get("/inventory")
async def get_inventory(
    schema_layer: SchemaLayer = Depends(get_schema_layer),
) -> dict:
    """Return all known MCP servers and their cached security status."""
    servers = await schema_layer.list_cached_servers()
    inventory = []
    for url in servers:
        cached = await schema_layer.get_cached(url)
        if cached:
            inventory.append({
                "server": url,
                "status": "CLEAN" if cached.get("passed") else "BLOCKED",
                "hash": cached.get("hash", ""),
                "clean_tools": len(cached.get("tools", [])),
                "threats": len(cached.get("threats", [])),
                "last_validated": cached.get("validated_at", ""),
            })
    return {"servers": inventory, "total": len(inventory)}


@router.post("/circuit-breaker/reset")
async def reset_circuit(
    session_id: str,
    circuit_breaker: CircuitBreaker = Depends(get_circuit_breaker),
) -> dict:
    """Manually reset a session's circuit breaker after admin review."""
    await circuit_breaker.reset(session_id)
    return {"status": "reset", "session_id": session_id}
