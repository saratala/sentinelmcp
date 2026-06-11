"""FastAPI router for the MCP transparent proxy and analyze endpoints.

POST /proxy
  Transparent MCP proxy. Agent sets X-MCP-Target to the real server URL.
  Response includes X-Sentinel-Latency header with per-layer timing JSON.

POST /proxy/analyze
  Pre-flight analysis. Submit planned tool calls; get a full threat report
  before the agent executes anything.
"""
from __future__ import annotations

import asyncio
import json
import time
import uuid
from typing import Any, Optional
from urllib.parse import urlparse as _urlparse

import structlog
from fastapi import APIRouter, Depends, Header, HTTPException, Request, Response
from pydantic import BaseModel, Field

from app.core.allowlist import ServerAllowlist
from app.core.auth import require_api_key
from app.core.rate_limit import limiter
from app.deps import get_circuit_breaker, get_context_layer, get_schema_layer
from app.gateway.param_layer import ParamLayer
from app.gateway.proxy import MCPProxy
from app.gateway.validator import GatewayValidator

log = structlog.get_logger(__name__)
router = APIRouter(tags=["proxy"])


def _make_proxy(schema_layer, context_layer, circuit_breaker) -> MCPProxy:
    return MCPProxy(
        schema_layer=schema_layer,
        context_layer=context_layer,
        circuit_breaker=circuit_breaker,
    )


# ── POST /proxy ───────────────────────────────────────────────────────────────

@router.post("/proxy", dependencies=[Depends(require_api_key)])
@limiter.limit("600/minute")
async def mcp_proxy(
    request: Request,
    response: Response,
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

    _p = _urlparse(x_mcp_target)
    target_url = x_mcp_target if _p.path else x_mcp_target.rstrip("/") + "/"

    # LLM05: allowlist check before any validation
    allowlist = ServerAllowlist(request.app.state.redis)
    if not await allowlist.is_allowed(target_url):
        log.warning("proxy_allowlist_blocked", target=target_url, session=session_id)
        return {
            "jsonrpc": "2.0", "id": body.get("id"),
            "error": {
                "code": -32003,
                "message": "SentinelMCP: server not in allowlist — shadow MCP blocked",
                "data": {"target": target_url, "sentinel": True,
                         "owasp": "LLM05"},
            },
        }

    proxy = _make_proxy(schema_layer, context_layer, circuit_breaker)
    result, timing = await proxy.handle(body, target_url, session_id)

    response.headers["X-Sentinel-Latency"] = json.dumps(timing)
    response.headers["X-Sentinel-Session"] = session_id
    return result


# ── POST /proxy/analyze ───────────────────────────────────────────────────────

class PlannedToolCall(BaseModel):
    name: str
    arguments: dict[str, Any] = Field(default_factory=dict)


class AnalyzeRequest(BaseModel):
    server_url: str
    session_id: str = ""
    prompt: str = ""
    tool_calls: list[PlannedToolCall]


class ToolAnalysis(BaseModel):
    tool: str
    verdict: str          # PASS | BLOCK
    reason: str = ""
    l1_schema: str = ""   # PASS | BLOCK | SKIPPED
    l2_ms: float = 0.0
    l4_ms: float = 0.0
    total_ms: float = 0.0
    context_risk: float = 0.0
    categories: dict[str, float] = Field(default_factory=dict)
    param_errors: list[str] = Field(default_factory=list)


class AnalyzeResponse(BaseModel):
    prompt: str
    server_url: str
    session_id: str
    schema_verdict: str   # PASS | BLOCK | ERROR
    schema_threats: int = 0
    overall: str          # PASS | BLOCK
    tool_analyses: list[ToolAnalysis]
    threats_found: int
    total_latency_ms: float
    recommendation: str


@router.post("/proxy/analyze", dependencies=[Depends(require_api_key)],
             response_model=AnalyzeResponse)
@limiter.limit("60/minute")
async def analyze(
    request: Request,
    body: AnalyzeRequest,
    schema_layer=Depends(get_schema_layer),
    context_layer=Depends(get_context_layer),
    circuit_breaker=Depends(get_circuit_breaker),
) -> AnalyzeResponse:
    """Pre-flight threat analysis for a planned agent session.

    Fetches the server's tool list, runs L1 schema validation, then validates
    every planned tool call through L2 + L4. Returns a full report without
    actually executing anything.
    """
    t_start = time.perf_counter()
    session_id = body.session_id or f"analyze-{uuid.uuid4().hex[:8]}"

    _p = _urlparse(body.server_url)
    target_url = body.server_url if _p.path else body.server_url.rstrip("/") + "/"

    proxy = _make_proxy(schema_layer, context_layer, circuit_breaker)
    validator = GatewayValidator(
        param_layer=ParamLayer(),
        context_layer=context_layer,
        circuit_breaker=circuit_breaker,
    )

    # ── Step 1: fetch tool list + L1 schema validation ─────────────────────
    tools_rpc = {"jsonrpc": "2.0", "id": 0, "method": "tools/list", "params": {}}
    list_result, list_timing = await proxy.handle(tools_rpc, target_url, session_id)

    if "error" in list_result and list_result["error"].get("data", {}).get("sentinel"):
        # Server is poisoned — no point validating calls
        total_ms = round((time.perf_counter() - t_start) * 1000, 2)
        return AnalyzeResponse(
            prompt=body.prompt,
            server_url=body.server_url,
            session_id=session_id,
            schema_verdict="BLOCK",
            schema_threats=list_timing.get("threats", 0),
            overall="BLOCK",
            tool_analyses=[],
            threats_found=list_timing.get("threats", 0),
            total_latency_ms=total_ms,
            recommendation=(
                "Server blocked at schema layer. Do not connect this AI agent "
                "to this MCP server. Review the threat details for CVE matches."
            ),
        )

    if "error" in list_result:
        raise HTTPException(status_code=502, detail=f"Could not reach MCP server: {list_result['error']['message']}")

    # Build inputSchema cache from the fetched tools
    tools = list_result.get("result", {}).get("tools", [])
    tool_schema_map = {t["name"]: t.get("inputSchema", {}) for t in tools}

    # ── Step 2: validate each planned tool call ────────────────────────────
    analyses: list[ToolAnalysis] = []
    threats_found = 0

    for call in body.tool_calls:
        t_call = time.perf_counter()
        input_schema = tool_schema_map.get(call.name, {"type": "object", "properties": {}})

        invocation = await validator.validate_invocation(
            session_id=session_id,
            tool_name=call.name,
            params=call.arguments,
            input_schema=input_schema,
        )

        call_ms = round((time.perf_counter() - t_call) * 1000, 2)
        l2 = invocation.param_result.latency_ms if invocation.param_result else 0.0
        l4 = invocation.context_result.latency_ms if invocation.context_result else 0.0
        risk = invocation.context_result.risk_score if invocation.context_result else 0.0
        categories = invocation.context_result.category_scores if invocation.context_result else {}

        verdict = "PASS" if invocation.passed else "BLOCK"
        reason = ""
        param_errors: list[str] = []

        if not invocation.passed:
            threats_found += 1
            if invocation.blocked_by_circuit:
                reason = "circuit_breaker"
            elif invocation.param_result and not invocation.param_result.passed:
                reason = "param_violation"
                param_errors = invocation.param_result.errors
            else:
                reason = "context_mosaic"

        analyses.append(ToolAnalysis(
            tool=call.name,
            verdict=verdict,
            reason=reason,
            l1_schema="PASS",
            l2_ms=round(l2, 3),
            l4_ms=round(l4, 3),
            total_ms=call_ms,
            context_risk=round(risk, 3),
            categories=categories,
            param_errors=param_errors,
        ))

    overall = "BLOCK" if threats_found > 0 else "PASS"
    total_ms = round((time.perf_counter() - t_start) * 1000, 2)

    if overall == "PASS":
        recommendation = (
            f"All {len(body.tool_calls)} planned tool calls are safe to execute. "
            "No threats detected across schema, parameters, or context."
        )
    else:
        blocked = [a.tool for a in analyses if a.verdict == "BLOCK"]
        recommendation = (
            f"{threats_found} of {len(body.tool_calls)} tool calls will be blocked: "
            f"{', '.join(blocked)}. Review context risk scores — "
            "a high cross-category score indicates a semantic mosaic attack pattern."
        )

    return AnalyzeResponse(
        prompt=body.prompt,
        server_url=body.server_url,
        session_id=session_id,
        schema_verdict="PASS",
        schema_threats=0,
        overall=overall,
        tool_analyses=analyses,
        threats_found=threats_found,
        total_latency_ms=total_ms,
        recommendation=recommendation,
    )


# ── Allowlist management (LLM05) ─────────────────────────────────────────────

@router.get("/allowlist", dependencies=[Depends(require_api_key)])
async def get_allowlist(request: Request) -> dict:
    """List all approved MCP server URLs."""
    al = ServerAllowlist(request.app.state.redis)
    return {
        "enabled": request.app.state.__dict__.get("allowlist_enabled", False),
        "servers": await al.list_allowed(),
        "count": await al.count(),
    }


@router.post("/allowlist", dependencies=[Depends(require_api_key)])
async def add_to_allowlist(request: Request, body: dict) -> dict:
    """Add an MCP server URL to the allowlist."""
    server_url = body.get("server_url", "").strip()
    if not server_url:
        raise HTTPException(status_code=400, detail="server_url required")
    al = ServerAllowlist(request.app.state.redis)
    await al.add(server_url)
    return {"added": server_url, "total": await al.count()}


@router.delete("/allowlist", dependencies=[Depends(require_api_key)])
async def remove_from_allowlist(request: Request, body: dict) -> dict:
    """Remove an MCP server URL from the allowlist."""
    server_url = body.get("server_url", "").strip()
    if not server_url:
        raise HTTPException(status_code=400, detail="server_url required")
    al = ServerAllowlist(request.app.state.redis)
    await al.remove(server_url)
    return {"removed": server_url, "total": await al.count()}
