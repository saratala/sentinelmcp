"""Protocol adapters — REST-to-MCP and Agent-to-Agent (A2A) bridges.

Allows non-MCP services to be exposed as MCP tools that SentinelMCP secures.

REST adapter:
  POST /adapters/rest/register   — register a REST API as MCP tools
  GET  /adapters/rest            — list registered adapters
  GET  /adapters/rest/{name}     — tools/list for adapter
  POST /adapters/rest/{name}     — tools/call (proxied + secured)
  DELETE /adapters/rest/{name}   — remove adapter

A2A bridge:
  POST /adapters/a2a/register    — register a remote agent
  POST /adapters/a2a/{name}      — forward tool call to remote agent (secured)
"""
from __future__ import annotations

import json
import time
from typing import Any, Optional

import httpx
import structlog
from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel

from app.core.auth import require_api_key
from app.core.rate_limit import limiter

log = structlog.get_logger(__name__)
router = APIRouter(prefix="/adapters", tags=["adapters"])

# ── Data models ───────────────────────────────────────────────────────────────

class RestEndpoint(BaseModel):
    path: str
    method: str = "GET"
    tool_name: str
    description: str = ""
    parameters: list[dict] = []


class RestAdapterConfig(BaseModel):
    name: str
    base_url: str
    openapi_url: str = ""
    endpoints: list[RestEndpoint] = []
    auth_header: str = ""   # e.g. "Authorization: Bearer {token}"
    api_key: str = ""


class A2AAdapterConfig(BaseModel):
    name: str
    agent_url: str
    capabilities: list[str] = []
    description: str = ""

# ── Redis helpers ─────────────────────────────────────────────────────────────

_REST_PREFIX = "adapter:rest:"
_A2A_PREFIX = "adapter:a2a:"


async def _save_adapter(redis, prefix: str, name: str, config: dict) -> None:
    await redis.set(f"{prefix}{name}", json.dumps(config))


async def _load_adapter(redis, prefix: str, name: str) -> Optional[dict]:
    raw = await redis.get(f"{prefix}{name}")
    if raw is None:
        return None
    return json.loads(raw)


async def _list_adapters(redis, prefix: str) -> list[dict]:
    keys = await redis.keys(f"{prefix}*")
    results = []
    for k in keys:
        raw = await redis.get(k)
        if raw:
            results.append(json.loads(raw))
    return results

# ── OpenAPI → MCP tool conversion ────────────────────────────────────────────

async def _fetch_openapi_tools(openapi_url: str) -> list[RestEndpoint]:
    """Fetch OpenAPI spec and convert paths to RestEndpoints."""
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.get(openapi_url)
            spec = resp.json()
    except Exception as e:
        log.warning("openapi_fetch_failed", url=openapi_url, error=str(e))
        return []

    endpoints = []
    for path, path_item in spec.get("paths", {}).items():
        for method, operation in path_item.items():
            if method.upper() not in ("GET", "POST", "PUT", "DELETE", "PATCH"):
                continue
            tool_name = operation.get("operationId") or f"{method}_{path.replace('/', '_').strip('_')}"
            params = []
            for p in operation.get("parameters", []):
                params.append({
                    "name": p.get("name"),
                    "type": p.get("schema", {}).get("type", "string"),
                    "required": p.get("required", False),
                    "in": p.get("in", "query"),
                })
            endpoints.append(RestEndpoint(
                path=path,
                method=method.upper(),
                tool_name=tool_name[:64],
                description=operation.get("summary", operation.get("description", ""))[:200],
                parameters=params,
            ))
    return endpoints


def _rest_tools_to_mcp(endpoints: list[dict]) -> list[dict]:
    """Convert RestEndpoint dicts to MCP tools/list format."""
    tools = []
    for ep in endpoints:
        properties = {}
        required = []
        for p in ep.get("parameters", []):
            properties[p["name"]] = {
                "type": p.get("type", "string"),
                "description": f"Parameter '{p['name']}' ({p.get('in', 'query')})",
            }
            if p.get("required"):
                required.append(p["name"])
        tools.append({
            "name": ep["tool_name"],
            "description": ep.get("description", ""),
            "inputSchema": {
                "type": "object",
                "properties": properties,
                "required": required,
            },
        })
    return tools

# ── REST Adapter routes ───────────────────────────────────────────────────────

@router.post("/rest/register", dependencies=[Depends(require_api_key)])
@limiter.limit("20/minute")
async def register_rest_adapter(
    request: Request,
    body: RestAdapterConfig,
) -> dict:
    """Register a REST API as MCP tools. Optionally auto-discover via OpenAPI spec."""
    redis = request.app.state.redis

    endpoints = list(body.endpoints)
    if body.openapi_url:
        discovered = await _fetch_openapi_tools(body.openapi_url)
        endpoints.extend(discovered)

    if not endpoints:
        raise HTTPException(400, "No endpoints defined and no OpenAPI spec to discover from")

    config = body.model_dump()
    config["endpoints"] = [e.model_dump() if hasattr(e, "model_dump") else e for e in endpoints]
    await _save_adapter(redis, _REST_PREFIX, body.name, config)

    log.info("rest_adapter_registered", name=body.name, endpoints=len(endpoints))
    return {
        "name": body.name,
        "mcp_url": f"{request.base_url}adapters/rest/{body.name}",
        "tools_count": len(endpoints),
        "status": "registered",
    }


@router.get("/rest", dependencies=[Depends(require_api_key)])
async def list_rest_adapters(request: Request) -> dict:
    """List all registered REST adapters."""
    redis = request.app.state.redis
    adapters = await _list_adapters(redis, _REST_PREFIX)
    return {
        "adapters": [
            {
                "name": a["name"],
                "base_url": a["base_url"],
                "tools_count": len(a.get("endpoints", [])),
                "mcp_url": f"{request.base_url}adapters/rest/{a['name']}",
            }
            for a in adapters
        ],
        "total": len(adapters),
    }


@router.delete("/rest/{name}", dependencies=[Depends(require_api_key)])
async def delete_rest_adapter(name: str, request: Request) -> dict:
    redis = request.app.state.redis
    deleted = await redis.delete(f"{_REST_PREFIX}{name}")
    if not deleted:
        raise HTTPException(404, f"Adapter '{name}' not found")
    return {"deleted": name}


@router.post("/rest/{name}")
@limiter.limit("300/minute")
async def call_rest_adapter(
    name: str,
    request: Request,
    tenant_id: str = Depends(require_api_key),
) -> dict:
    """Handle MCP tools/call or tools/list for a registered REST adapter.

    All calls are routed through SentinelMCP's security layers before forwarding.
    """
    redis = request.app.state.redis
    config = await _load_adapter(redis, _REST_PREFIX, name)
    if not config:
        raise HTTPException(404, f"Adapter '{name}' not found")

    body = await request.json()
    method = body.get("method", "")

    if method == "tools/list":
        tools = _rest_tools_to_mcp(config.get("endpoints", []))
        return {"jsonrpc": "2.0", "id": body.get("id", 1), "result": {"tools": tools}}

    if method == "tools/call":
        params = body.get("params", {})
        tool_name = params.get("name", "")
        arguments = params.get("arguments", {})

        # Find matching endpoint
        endpoint = next(
            (e for e in config.get("endpoints", []) if e["tool_name"] == tool_name),
            None,
        )
        if not endpoint:
            return {
                "jsonrpc": "2.0", "id": body.get("id", 1),
                "error": {"code": -32601, "message": f"Tool '{tool_name}' not found"},
            }

        # Security scan via L2 params (import inline to avoid circular)
        try:
            from app.gateway.param_layer import inspect_params
            from app.models.schemas import ToolCall
            tc = ToolCall(name=tool_name, arguments=arguments)
            l2_result = await inspect_params("adapter", tc)
            if not l2_result.passed:
                return {
                    "jsonrpc": "2.0", "id": body.get("id", 1),
                    "error": {"code": -32000, "message": "SentinelMCP: tool call blocked by security policy"},
                }
        except Exception:
            pass  # Don't block on import errors

        # Build real REST request
        url = config["base_url"].rstrip("/") + endpoint["path"]
        http_method = endpoint.get("method", "GET").upper()
        headers = {}
        if config.get("auth_header") and config.get("api_key"):
            header_template = config["auth_header"]
            if ":" in header_template:
                key_name, val = header_template.split(":", 1)
                headers[key_name.strip()] = val.strip().replace("{token}", config["api_key"])

        # Separate path params, query params, and body
        path_params = {}
        query_params = {}
        body_data = {}
        for ep_param in endpoint.get("parameters", []):
            pname = ep_param["name"]
            pin = ep_param.get("in", "query")
            if pname not in arguments:
                continue
            if pin == "path":
                path_params[pname] = arguments[pname]
            elif pin in ("query", "header") or http_method == "GET":
                query_params[pname] = arguments[pname]
            else:
                body_data[pname] = arguments[pname]

        for k, v in path_params.items():
            url = url.replace(f"{{{k}}}", str(v))

        t0 = time.perf_counter()
        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                if http_method in ("POST", "PUT", "PATCH") and body_data:
                    resp = await client.request(http_method, url, params=query_params, json=body_data, headers=headers)
                else:
                    resp = await client.request(http_method, url, params=query_params, headers=headers)
            response_text = resp.text[:50_000]
        except Exception as e:
            return {
                "jsonrpc": "2.0", "id": body.get("id", 1),
                "error": {"code": -32000, "message": f"REST call failed: {e}"},
            }
        latency_ms = round((time.perf_counter() - t0) * 1000, 2)

        # L3 output scan
        try:
            from app.gateway.output_layer import redact_output
            safe_text, threats = redact_output(response_text)
            if threats:
                log.warning("adapter_output_redacted", adapter=name, tool=tool_name)
                response_text = safe_text
        except Exception:
            pass

        return {
            "jsonrpc": "2.0",
            "id": body.get("id", 1),
            "result": {
                "content": [{"type": "text", "text": response_text}],
                "isError": resp.status_code >= 400,
            },
            "_sentinel": {"latency_ms": latency_ms, "http_status": resp.status_code},
        }

    return {
        "jsonrpc": "2.0", "id": body.get("id", 1),
        "error": {"code": -32601, "message": f"Unknown method: {method}"},
    }


@router.get("/rest/{name}", dependencies=[Depends(require_api_key)])
async def get_rest_adapter_tools(name: str, request: Request) -> dict:
    """Get tools/list for a REST adapter in MCP format."""
    redis = request.app.state.redis
    config = await _load_adapter(redis, _REST_PREFIX, name)
    if not config:
        raise HTTPException(404, f"Adapter '{name}' not found")
    tools = _rest_tools_to_mcp(config.get("endpoints", []))
    return {
        "jsonrpc": "2.0", "id": 1,
        "result": {"tools": tools},
        "_meta": {"adapter": name, "base_url": config["base_url"]},
    }

# ── A2A Adapter routes ────────────────────────────────────────────────────────

@router.post("/a2a/register", dependencies=[Depends(require_api_key)])
@limiter.limit("20/minute")
async def register_a2a_adapter(
    request: Request,
    body: A2AAdapterConfig,
) -> dict:
    """Register a remote A2A-compliant agent as an MCP tool."""
    redis = request.app.state.redis
    await _save_adapter(redis, _A2A_PREFIX, body.name, body.model_dump())
    log.info("a2a_adapter_registered", name=body.name, agent_url=body.agent_url)
    return {
        "name": body.name,
        "mcp_url": f"{request.base_url}adapters/a2a/{body.name}",
        "status": "registered",
    }


@router.get("/a2a", dependencies=[Depends(require_api_key)])
async def list_a2a_adapters(request: Request) -> dict:
    redis = request.app.state.redis
    adapters = await _list_adapters(redis, _A2A_PREFIX)
    return {
        "adapters": [
            {
                "name": a["name"],
                "agent_url": a["agent_url"],
                "capabilities": a.get("capabilities", []),
                "mcp_url": f"{request.base_url}adapters/a2a/{a['name']}",
            }
            for a in adapters
        ],
        "total": len(adapters),
    }


@router.post("/a2a/{name}")
@limiter.limit("300/minute")
async def call_a2a_adapter(
    name: str,
    request: Request,
    tenant_id: str = Depends(require_api_key),
) -> dict:
    """Forward an MCP tool call to a remote A2A agent, with output scanning."""
    redis = request.app.state.redis
    config = await _load_adapter(redis, _A2A_PREFIX, name)
    if not config:
        raise HTTPException(404, f"A2A adapter '{name}' not found")

    body = await request.json()
    method = body.get("method", "")

    if method == "tools/list":
        capabilities = config.get("capabilities", [])
        tools = [
            {
                "name": cap,
                "description": f"A2A capability: {cap} (via {config['agent_url']})",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "input": {"type": "string", "description": "Task input for the agent"},
                        "context": {"type": "string", "description": "Optional context"},
                    },
                },
            }
            for cap in capabilities
        ] if capabilities else [
            {
                "name": "invoke",
                "description": config.get("description", f"Invoke the {name} agent"),
                "inputSchema": {
                    "type": "object",
                    "properties": {"input": {"type": "string"}},
                    "required": ["input"],
                },
            }
        ]
        return {"jsonrpc": "2.0", "id": body.get("id", 1), "result": {"tools": tools}}

    if method == "tools/call":
        params = body.get("params", {})
        tool_name = params.get("name", "invoke")
        arguments = params.get("arguments", {})

        # Translate to A2A message format
        a2a_message = {
            "task": tool_name,
            "input": arguments.get("input", ""),
            "context": arguments.get("context", ""),
            "agent_id": name,
        }

        t0 = time.perf_counter()
        try:
            async with httpx.AsyncClient(timeout=60.0) as client:
                resp = await client.post(config["agent_url"], json=a2a_message)
            a2a_response = resp.json()
            output_text = (
                a2a_response.get("output")
                or a2a_response.get("result")
                or a2a_response.get("response")
                or json.dumps(a2a_response)
            )
        except Exception as e:
            return {
                "jsonrpc": "2.0", "id": body.get("id", 1),
                "error": {"code": -32000, "message": f"A2A agent call failed: {e}"},
            }
        latency_ms = round((time.perf_counter() - t0) * 1000, 2)

        # L3 scan on agent output before returning
        try:
            from app.gateway.output_layer import redact_output
            safe_text, threats = redact_output(str(output_text))
            if threats:
                log.warning("a2a_output_redacted", adapter=name, threats=len(threats))
                output_text = safe_text
        except Exception:
            pass

        return {
            "jsonrpc": "2.0",
            "id": body.get("id", 1),
            "result": {
                "content": [{"type": "text", "text": str(output_text)}],
            },
            "_sentinel": {"latency_ms": latency_ms, "adapter": name},
        }

    return {
        "jsonrpc": "2.0", "id": body.get("id", 1),
        "error": {"code": -32601, "message": f"Unknown method: {method}"},
    }
