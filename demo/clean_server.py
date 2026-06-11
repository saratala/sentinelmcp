"""Demo: clean MCP server — all legitimate tools, no injection."""
from __future__ import annotations

import uvicorn
from fastapi import FastAPI

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


@app.get("/tools")
async def get_tools() -> dict:
    """Return the server's tool manifest."""
    return {"server_url": "http://localhost:8001", "tools": TOOLS}


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8001, log_level="warning")
