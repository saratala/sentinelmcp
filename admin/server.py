"""SentinelMCP Admin Server — controls Docker services and proxies gateway calls.

Runs on the HOST (not inside Docker) so it can execute docker compose commands.
Start with: .venv/bin/python admin/server.py
"""
from __future__ import annotations

import asyncio
import json
import os
import subprocess
import sys
from pathlib import Path
from typing import AsyncIterator

import httpx
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

PROJECT_DIR = Path(__file__).parent.parent
COMPOSE_FILE = PROJECT_DIR / "docker-compose.yml"
GATEWAY_URL = "http://localhost:8888"
SENTINEL_KEY = os.environ.get("SENTINEL_API_KEY", "dev-key-123")

app = FastAPI(title="SentinelMCP Admin", docs_url=None)
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

# ── Service definitions ───────────────────────────────────────────────────────

SERVICES = [
    {
        "name": "api",
        "label": "SentinelMCP Gateway",
        "description": "Core security gateway — 4-layer threat detection",
        "port": 8888,
        "url": "http://localhost:8888/docs",
        "url_label": "Swagger Docs",
        "category": "core",
        "profiles": [],
    },
    {
        "name": "worker",
        "label": "Celery Worker",
        "description": "Async background task processor",
        "port": None,
        "url": None,
        "category": "core",
        "profiles": [],
    },
    {
        "name": "dashboard",
        "label": "React Dashboard",
        "description": "Live threat feed and latency charts",
        "port": 5173,
        "url": "http://localhost:5173",
        "url_label": "Open Dashboard",
        "category": "ui",
        "profiles": [],
    },
    {
        "name": "grafana",
        "label": "Grafana",
        "description": "OWASP threat analytics — admin / sentinel",
        "port": 3000,
        "url": "http://localhost:3000",
        "url_label": "Open Grafana",
        "category": "ui",
        "profiles": [],
    },
    {
        "name": "jaeger",
        "label": "Jaeger (OTEL)",
        "description": "Distributed traces — per-layer span timings",
        "port": 16686,
        "url": "http://localhost:16686",
        "url_label": "Open Jaeger",
        "category": "observability",
        "profiles": ["observability"],
    },
    {
        "name": "demo-clean",
        "label": "Clean MCP Server",
        "description": "Safe demo server — no injection patterns",
        "port": 8001,
        "url": None,
        "category": "demo",
        "profiles": ["demo"],
    },
    {
        "name": "demo-poisoned",
        "label": "Poisoned MCP Server",
        "description": "Vulnerable demo — prompt injection + SQL",
        "port": 8002,
        "url": None,
        "category": "demo",
        "profiles": ["demo"],
    },
    {
        "name": "sentinel-mcp-server",
        "label": "SentinelMCP as MCP Server",
        "description": "Exposes SentinelMCP as 3 callable MCP tools",
        "port": 8889,
        "url": None,
        "category": "demo",
        "profiles": ["demo"],
    },
    {
        "name": "redis",
        "label": "Redis",
        "description": "Schema cache, API key store, session state",
        "port": 6379,
        "url": None,
        "category": "infra",
        "profiles": [],
    },
    {
        "name": "postgres",
        "label": "Postgres",
        "description": "Audit log, threat events, API keys",
        "port": 5432,
        "url": None,
        "category": "infra",
        "profiles": [],
    },
]

# ── Docker helpers ────────────────────────────────────────────────────────────

def _compose_cmd(*args: str, profiles: list[str] | None = None) -> list[str]:
    cmd = ["docker", "compose", "-f", str(COMPOSE_FILE)]
    for p in (profiles or []):
        cmd += ["--profile", p]
    return cmd + list(args)


def _run(cmd: list[str], capture: bool = True) -> tuple[int, str]:
    result = subprocess.run(
        cmd, cwd=PROJECT_DIR,
        capture_output=capture, text=True, timeout=120,
    )
    output = (result.stdout + result.stderr).strip()
    return result.returncode, output


def _get_service_info(name: str) -> dict:
    svc = next((s for s in SERVICES if s["name"] == name), None)
    return svc or {}


def _docker_ps() -> dict[str, str]:
    """Return {service_name: status_string} for all running containers."""
    rc, out = _run(["docker", "compose", "-f", str(COMPOSE_FILE), "ps", "--format", "json"])
    if rc != 0:
        return {}
    statuses = {}
    for line in out.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
            svc = obj.get("Service", "")
            state = obj.get("State", "")
            health = obj.get("Health", "")
            status = obj.get("Status", state)
            statuses[svc] = health if health else state
        except Exception:
            pass
    return statuses


# ── Routes ────────────────────────────────────────────────────────────────────

@app.get("/admin/services")
async def list_services() -> list[dict]:
    statuses = _docker_ps()
    result = []
    for svc in SERVICES:
        name = svc["name"]
        state = statuses.get(name, "stopped")
        result.append({**svc, "status": state})
    return result


@app.post("/admin/services/{name}/start")
async def start_service(name: str) -> dict:
    svc = _get_service_info(name)
    if not svc:
        raise HTTPException(404, f"Unknown service: {name}")
    profiles = svc.get("profiles", [])
    cmd = _compose_cmd("up", "-d", name, profiles=profiles)
    rc, out = _run(cmd)
    return {"ok": rc == 0, "output": out, "service": name}


@app.post("/admin/services/{name}/stop")
async def stop_service(name: str) -> dict:
    svc = _get_service_info(name)
    if not svc:
        raise HTTPException(404, f"Unknown service: {name}")
    cmd = _compose_cmd("stop", name)
    rc, out = _run(cmd)
    return {"ok": rc == 0, "output": out, "service": name}


@app.post("/admin/services/{name}/restart")
async def restart_service(name: str) -> dict:
    svc = _get_service_info(name)
    if not svc:
        raise HTTPException(404, f"Unknown service: {name}")
    profiles = svc.get("profiles", [])
    cmd = _compose_cmd("restart", name, profiles=profiles)
    rc, out = _run(cmd)
    return {"ok": rc == 0, "output": out, "service": name}


@app.post("/admin/services/{name}/build")
async def build_service(name: str) -> dict:
    svc = _get_service_info(name)
    if not svc:
        raise HTTPException(404, f"Unknown service: {name}")
    buildable = ["api", "worker", "dashboard", "demo-clean", "demo-poisoned", "sentinel-mcp-server"]
    if name not in buildable:
        return {"ok": True, "output": f"{name} uses a pre-built image — no build needed.", "service": name}
    cmd = _compose_cmd("build", name)
    rc, out = _run(cmd, capture=True)
    return {"ok": rc == 0, "output": out[-3000:], "service": name}


@app.get("/admin/services/{name}/logs")
async def stream_logs(name: str, lines: int = 50):
    async def _generate() -> AsyncIterator[str]:
        proc = await asyncio.create_subprocess_exec(
            "docker", "compose", "-f", str(COMPOSE_FILE),
            "logs", "--tail", str(lines), "--no-color", name,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
            cwd=PROJECT_DIR,
        )
        async for line in proc.stdout:
            yield line.decode("utf-8", errors="replace")
        await proc.wait()
    return StreamingResponse(_generate(), media_type="text/plain")


# ── Gateway proxy routes (for the test lab) ──────────────────────────────────

async def _gw(method: str, path: str, body: dict | None = None) -> dict:
    async with httpx.AsyncClient(timeout=30) as client:
        headers = {"X-Sentinel-Key": SENTINEL_KEY}
        if method == "GET":
            r = await client.get(f"{GATEWAY_URL}{path}", headers=headers)
        else:
            r = await client.post(f"{GATEWAY_URL}{path}", json=body, headers=headers)
        r.raise_for_status()
        return r.json()


@app.get("/admin/gateway/health")
async def gw_health():
    try:
        return await _gw("GET", "/health")
    except Exception as e:
        raise HTTPException(502, str(e))


@app.get("/admin/gateway/stats")
async def gw_stats():
    try:
        return await _gw("GET", "/gateway/threats/stats")
    except Exception as e:
        raise HTTPException(502, str(e))


@app.get("/admin/gateway/threats")
async def gw_threats():
    try:
        return await _gw("GET", "/gateway/threats?limit=20&days=7")
    except Exception as e:
        raise HTTPException(502, str(e))


@app.get("/admin/gateway/report")
async def gw_report():
    try:
        return await _gw("GET", "/gateway/compliance/report")
    except Exception as e:
        raise HTTPException(502, str(e))


class ProbeBody(BaseModel):
    server_url: str
    attacks: list[str] = ["all"]


@app.post("/admin/gateway/probe")
async def gw_probe(body: ProbeBody):
    try:
        return await _gw("POST", "/probe", {"server_url": body.server_url, "attacks": body.attacks})
    except Exception as e:
        raise HTTPException(502, str(e))


class AnalyzeBody(BaseModel):
    server_url: str


@app.post("/admin/gateway/analyze")
async def gw_analyze(body: AnalyzeBody):
    try:
        return await _gw("POST", "/proxy/analyze", {"server_url": body.server_url, "tool_calls": []})
    except Exception as e:
        raise HTTPException(502, str(e))


# ── Serve SPA ─────────────────────────────────────────────────────────────────

@app.get("/", response_class=HTMLResponse)
async def serve_spa():
    html = (Path(__file__).parent / "index.html").read_text()
    return HTMLResponse(html)


if __name__ == "__main__":
    import uvicorn
    print("SentinelMCP Admin UI → http://localhost:9000")
    uvicorn.run(app, host="0.0.0.0", port=9000, log_level="warning")
