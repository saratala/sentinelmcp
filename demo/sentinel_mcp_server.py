#!/usr/bin/env python3
"""SentinelMCP as an MCP Server — expose security analysis as callable tools.

Any agent (Claude, LangChain, AutoGPT, CrewAI) can add SentinelMCP to their
MCP tool list and call:
  - sentinel_analyze   : full security analysis of an MCP server or tool call
  - sentinel_explain   : explain why a specific threat was detected (RAG-backed)
  - sentinel_report    : compliance summary for a session or time window

This is a standard JSON-RPC 2.0 MCP server (Streamable HTTP transport).
The tools are backed by a LangGraph agent with FAISS RAG over OWASP knowledge.

Usage:
  # Start the MCP server (default port 8889):
  python demo/sentinel_mcp_server.py

  # Test with curl:
  curl -s http://localhost:8889/ \\
    -H "Content-Type: application/json" \\
    -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}'

  # Add to Claude Code ~/.claude.json:
  {
    "mcpServers": {
      "sentinelmcp": {
        "type": "http",
        "url": "http://localhost:8889",
        "headers": {"X-Sentinel-Key": "dev-key-123"}
      }
    }
  }

  # Call from any agent:
  use_mcp_tool("sentinelmcp", "sentinel_analyze", {
    "server_url": "http://my-mcp-server:8001",
    "tool_calls": [{"name": "query_db", "arguments": {"query": "SELECT *"}}]
  })
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
import sys
import time
from typing import Any

import httpx
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

# ── Config ────────────────────────────────────────────────────────────────────

GATEWAY     = os.getenv("SENTINEL_GATEWAY_URL", "http://localhost:8888")
API_KEY     = os.getenv("SENTINEL_API_KEY",     "dev-key-123")
SERVER_PORT = int(os.getenv("SENTINEL_MCP_PORT", "8889"))
SERVER_NAME = "sentinelmcp"
SERVER_VER  = "0.2.0"

logging.basicConfig(level=logging.INFO,
                    format="%(asctime)s  %(levelname)s  %(message)s")
log = logging.getLogger(__name__)

# ── Tool definitions (what the agent sees) ────────────────────────────────────

TOOLS = [
    {
        "name": "sentinel_analyze",
        "description": (
            "Analyze an MCP server or planned tool calls for security threats. "
            "Uses SentinelMCP's 4-layer detection engine: schema validation (L1), "
            "parameter scanning (L2), output inspection (L3), and context risk "
            "accumulation (L4). Returns verdict (PASS/BLOCK), detected threats with "
            "OWASP IDs, per-layer latency, and actionable recommendations. "
            "Call this before connecting to any new MCP server or executing "
            "high-risk tool calls in an agentic pipeline."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "server_url": {
                    "type": "string",
                    "description": "URL of the MCP server to analyze",
                },
                "session_id": {
                    "type": "string",
                    "description": "Agent session ID for context tracking (optional)",
                },
                "tool_calls": {
                    "type": "array",
                    "description": "Planned tool calls to validate before execution",
                    "items": {
                        "type": "object",
                        "properties": {
                            "name": {"type": "string"},
                            "arguments": {"type": "object"},
                        },
                        "required": ["name"],
                    },
                },
            },
            "required": ["server_url"],
        },
    },
    {
        "name": "sentinel_explain",
        "description": (
            "Explain a detected threat in plain language using OWASP LLM Top 10 "
            "knowledge. Given a threat type (e.g. PROMPT_INJECTION, RUG_PULL, "
            "SENSITIVE_DISCLOSURE) or a pattern name, returns: what the attack is, "
            "how it works in MCP contexts, which OWASP LLM category it maps to, "
            "known CVEs, and specific mitigation steps. "
            "Useful for security reports, incident response, and developer education."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "threat_type": {
                    "type": "string",
                    "description": "Threat type or OWASP ID (e.g. PROMPT_INJECTION, LLM01, RUG_PULL)",
                },
                "pattern": {
                    "type": "string",
                    "description": "Specific pattern name from detection (optional, adds detail)",
                },
                "context": {
                    "type": "string",
                    "description": "Additional context about the incident (optional)",
                },
            },
            "required": ["threat_type"],
        },
    },
    {
        "name": "sentinel_report",
        "description": (
            "Generate a compliance security report for the SentinelMCP gateway. "
            "Returns total threats blocked, block rate, breakdown by OWASP category, "
            "and compliance control status for PCI DSS and SOC2. "
            "Use this to assess overall AI agent security posture, "
            "or to produce evidence for a compliance audit."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "days": {
                    "type": "integer",
                    "description": "Number of days to include in the report (default: 30)",
                    "default": 30,
                },
            },
        },
    },
]

# ── Gateway client ─────────────────────────────────────────────────────────────

_HEADERS = {"X-Sentinel-Key": API_KEY, "Content-Type": "application/json"}


async def _call_gateway(path: str, payload: dict, method: str = "POST") -> dict:
    async with httpx.AsyncClient(timeout=15) as client:
        if method == "GET":
            r = await client.get(f"{GATEWAY}{path}", headers=_HEADERS,
                                 params=payload)
        else:
            r = await client.post(f"{GATEWAY}{path}", headers=_HEADERS,
                                  json=payload)
        return r.json()


# ── Tool implementations ──────────────────────────────────────────────────────

async def _sentinel_analyze(args: dict) -> str:
    server_url = args.get("server_url", "")
    session_id = args.get("session_id", f"mcp-tool-{int(time.time())}")
    tool_calls = args.get("tool_calls", [])

    if not tool_calls:
        # No tool calls — just validate the server schema via proxy tools/list
        result = await _call_gateway("/proxy", {
            "jsonrpc": "2.0", "id": 1,
            "method": "tools/list", "params": {},
        } , method="POST")
        # We need the X-MCP-Target header — use analyze endpoint instead
        payload = {
            "server_url": server_url,
            "session_id": session_id,
            "tool_calls": [],
        }
        result = await _call_gateway("/proxy/analyze", payload)
    else:
        payload = {
            "server_url": server_url,
            "session_id": session_id,
            "tool_calls": [
                {"name": tc.get("name", "unknown"),
                 "arguments": tc.get("arguments", {})}
                for tc in tool_calls
            ],
        }
        result = await _call_gateway("/proxy/analyze", payload)

    if "detail" in result:
        return json.dumps({
            "verdict": "ERROR",
            "error": result["detail"],
            "server_url": server_url,
        }, indent=2)

    # Format for agent consumption
    verdict = result.get("overall", "UNKNOWN")
    threats = result.get("threats_found", 0)
    analyses = result.get("tool_analyses", [])

    blocked_tools = [a for a in analyses if a.get("verdict") == "BLOCK"]

    output = {
        "verdict": verdict,
        "server_url": server_url,
        "session_id": session_id,
        "schema_verdict": result.get("schema_verdict", "UNKNOWN"),
        "threats_found": threats,
        "total_latency_ms": result.get("total_latency_ms", 0),
        "recommendation": result.get("recommendation", ""),
        "blocked_calls": [
            {
                "tool": b["tool"],
                "reason": b.get("reason", ""),
                "context_risk": b.get("context_risk", 0),
                "param_errors": b.get("param_errors", []),
            }
            for b in blocked_tools
        ],
        "owasp_ids": _map_owasp(blocked_tools),
    }
    return json.dumps(output, indent=2)


async def _sentinel_explain(args: dict) -> str:
    threat_type = args.get("threat_type", "").upper()
    pattern = args.get("pattern", "")
    context = args.get("context", "")

    # Lazy import — only load when the tool is actually called
    try:
        from demo.sentinel_agent import SentinelRAGAgent
        agent = SentinelRAGAgent()
        return await asyncio.get_event_loop().run_in_executor(
            None, agent.explain, threat_type, pattern, context
        )
    except Exception as e:
        # Fallback to static knowledge if RAG agent unavailable
        return _static_explain(threat_type, pattern)


async def _sentinel_report(args: dict) -> str:
    days = int(args.get("days", 30))
    result = await _call_gateway("/gateway/compliance/report", {"days": days},
                                  method="GET")
    if "detail" in result:
        return json.dumps({"error": result["detail"]})
    return json.dumps(result, indent=2)


def _map_owasp(blocked: list[dict]) -> list[str]:
    """Map param_errors and reasons to OWASP IDs."""
    ids = set()
    for b in blocked:
        reason = b.get("reason", "")
        errors = " ".join(b.get("param_errors", []))
        text = f"{reason} {errors}".lower()
        if "injection" in text or "inject" in text:
            ids.add("LLM01")
        if "pii" in text or "sensitive" in text or "disclosure" in text:
            ids.add("LLM06")
        if "dangerous_arg" in text or "sql" in text or "path_traversal" in text:
            ids.add("LLM07")
        if "context_mosaic" in text or "circuit" in text:
            ids.add("LLM08")
        if "allowlist" in text or "supply" in text:
            ids.add("LLM05")
        if "payload" in text and "large" in text:
            ids.add("LLM04")
    return sorted(ids)


def _static_explain(threat_type: str, pattern: str) -> str:
    from demo.sentinel_knowledge import DOCUMENTS
    # Find best matching document
    q = threat_type.upper()
    for doc in DOCUMENTS:
        types_upper = [t.upper() for t in doc["threat_types"]]
        if (q in types_upper
                or q == doc["owasp_id"]
                or q in doc["owasp_id"]
                or any(q in t for t in types_upper)):
            return json.dumps({
                "threat_type": threat_type,
                "owasp_id": doc["owasp_id"],
                "title": doc["title"],
                "explanation": doc["content"],
                "cve_refs": doc["cve_refs"],
                "source": "static_knowledge",
            }, indent=2)
    return json.dumps({
        "threat_type": threat_type,
        "owasp_id": "UNKNOWN",
        "explanation": f"No static knowledge found for {threat_type}. "
                       "Ensure the SentinelMCP RAG agent is running for deeper analysis.",
    }, indent=2)


# ── MCP JSON-RPC handler ──────────────────────────────────────────────────────

TOOL_DISPATCH = {
    "sentinel_analyze": _sentinel_analyze,
    "sentinel_explain": _sentinel_explain,
    "sentinel_report":  _sentinel_report,
}


app = FastAPI(title="SentinelMCP MCP Server")


@app.post("/")
@app.get("/")
async def handle_rpc(request: Request) -> JSONResponse:
    try:
        body = await request.json()
    except Exception:
        return _err(None, -32700, "Parse error")

    rpc_id = body.get("id")
    method = body.get("method", "")
    params = body.get("params", {})

    log.info("rpc  method=%s  id=%s", method, rpc_id)

    if method == "initialize":
        return _ok(rpc_id, {
            "protocolVersion": "2024-11-05",
            "serverInfo": {"name": SERVER_NAME, "version": SERVER_VER},
            "capabilities": {"tools": {}},
        })

    if method == "tools/list":
        return _ok(rpc_id, {"tools": TOOLS})

    if method == "tools/call":
        tool_name = params.get("name", "")
        arguments = params.get("arguments", {})
        fn = TOOL_DISPATCH.get(tool_name)
        if not fn:
            return _err(rpc_id, -32601, f"Unknown tool: {tool_name}")
        try:
            text = await fn(arguments)
            return _ok(rpc_id, {
                "content": [{"type": "text", "text": text}],
                "isError": False,
            })
        except Exception as exc:
            log.exception("tool error  tool=%s", tool_name)
            return _ok(rpc_id, {
                "content": [{"type": "text", "text": f"Tool error: {exc}"}],
                "isError": True,
            })

    if method == "ping":
        return _ok(rpc_id, {})

    return _err(rpc_id, -32601, f"Method not found: {method}")


def _ok(rpc_id: Any, result: Any) -> JSONResponse:
    return JSONResponse({"jsonrpc": "2.0", "id": rpc_id, "result": result})


def _err(rpc_id: Any, code: int, message: str) -> JSONResponse:
    return JSONResponse({"jsonrpc": "2.0", "id": rpc_id,
                         "error": {"code": code, "message": message}})


# ── Server startup ────────────────────────────────────────────────────────────

def main() -> None:
    import uvicorn

    log.info("SentinelMCP MCP Server starting on port %d", SERVER_PORT)
    log.info("Gateway: %s", GATEWAY)
    log.info("")
    log.info("Add to Claude Code ~/.claude.json:")
    log.info('  "mcpServers": {')
    log.info('    "sentinelmcp": {')
    log.info('      "type": "http",')
    log.info('      "url": "http://localhost:%d",', SERVER_PORT)
    log.info('      "headers": {"X-Sentinel-Key": "%s"}', API_KEY)
    log.info("    }")
    log.info("  }")
    log.info("")
    log.info("Tools available:")
    for t in TOOLS:
        log.info("  %-22s  %s", t["name"], t["description"][:60] + "...")

    uvicorn.run(app, host="0.0.0.0", port=SERVER_PORT, log_level="warning")


if __name__ == "__main__":
    main()
