"""Demo: clean MCP server — real JSON-RPC 2.0 + legacy REST endpoint."""
from __future__ import annotations

import uvicorn
from fastapi import FastAPI
from fastapi.responses import JSONResponse

app = FastAPI(title="Clean MCP Server (Demo)")

TOOLS = [
    {
        "name": "query_database",
        "description": "Query the customer database using a SQL statement. Returns results as JSON.",
        "inputSchema": {
            "type": "object",
            "properties": {"query": {"type": "string"}},
            "required": ["query"],
        },
    },
    {
        "name": "get_weather",
        "description": "Returns current weather for a given city.",
        "inputSchema": {
            "type": "object",
            "properties": {"city": {"type": "string"}},
            "required": ["city"],
        },
    },
    {
        "name": "send_email",
        "description": "Send an email to a recipient with a subject and body.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "to": {"type": "string"},
                "subject": {"type": "string"},
                "body": {"type": "string"},
            },
            "required": ["to", "subject", "body"],
        },
    },
    {
        "name": "list_files",
        "description": "List files in the user's workspace directory matching a glob pattern.",
        "inputSchema": {
            "type": "object",
            "properties": {"pattern": {"type": "string"}},
            "required": ["pattern"],
        },
    },
]

TOOL_MAP = {t["name"]: t for t in TOOLS}

# ── JSON-RPC 2.0 endpoint (real MCP protocol) ─────────────────────────────────

@app.post("/")
async def jsonrpc(request_body: dict) -> dict:
    method = request_body.get("method")
    rpc_id = request_body.get("id")

    if method == "initialize":
        return {
            "jsonrpc": "2.0", "id": rpc_id,
            "result": {
                "protocolVersion": "2024-11-05",
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "clean-demo-server", "version": "1.0.0"},
            },
        }

    if method == "tools/list":
        return {"jsonrpc": "2.0", "id": rpc_id, "result": {"tools": TOOLS}}

    if method == "tools/call":
        params = request_body.get("params", {})
        tool_name = params.get("name")
        arguments = params.get("arguments", {})

        if tool_name not in TOOL_MAP:
            return {"jsonrpc": "2.0", "id": rpc_id,
                    "error": {"code": -32601, "message": f"Tool not found: {tool_name}"}}

        # Simulated tool responses
        if tool_name == "query_database":
            result_text = f"Query '{arguments.get('query')}' returned 3 rows: [{{id:1}}, {{id:2}}, {{id:3}}]"
        elif tool_name == "get_weather":
            result_text = f"Weather in {arguments.get('city', 'unknown')}: 72°F, partly cloudy"
        elif tool_name == "send_email":
            result_text = f"Email sent to {arguments.get('to')} with subject '{arguments.get('subject')}'"
        elif tool_name == "list_files":
            result_text = f"Files matching '{arguments.get('pattern')}': report.pdf, data.csv, notes.txt"
        else:
            result_text = "OK"

        return {
            "jsonrpc": "2.0", "id": rpc_id,
            "result": {"content": [{"type": "text", "text": result_text}]},
        }

    if method == "ping":
        return {"jsonrpc": "2.0", "id": rpc_id, "result": {}}

    return {"jsonrpc": "2.0", "id": rpc_id,
            "error": {"code": -32601, "message": f"Method not found: {method}"}}


# ── Legacy REST endpoint (used by demo.py pre-flight check) ───────────────────

@app.get("/tools")
async def get_tools() -> dict:
    return {"server_url": "http://demo-clean:8001", "tools": TOOLS}


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8001, log_level="warning")
