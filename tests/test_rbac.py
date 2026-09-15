"""Tests for scoped API keys (RBAC): scope model + route enforcement."""
from __future__ import annotations

import fakeredis.aioredis
import httpx
import pytest
import pytest_asyncio

from app.core.auth import AuthContext, provision_key
from app.gateway.context_layer import ContextLayer
from app.gateway.schema_layer import SchemaLayer
from app.core.circuit_breaker import CircuitBreaker
from app.main import create_app


# ── Scope model ───────────────────────────────────────────────────────────────

def test_admin_implies_all_scopes():
    ctx = AuthContext(key="k", scopes=["admin"])
    assert ctx.has_scope("probe") and ctx.has_scope("read") and ctx.has_scope("gateway")


def test_narrow_scope_only_grants_itself():
    ctx = AuthContext(key="k", scopes=["read"])
    assert ctx.has_scope("read")
    assert not ctx.has_scope("probe")
    assert not ctx.has_scope("admin")


def test_default_context_has_all_scopes():
    # Legacy / dev keys default to all scopes for backwards compatibility.
    assert AuthContext(key="k").has_scope("admin")


# ── Route enforcement ─────────────────────────────────────────────────────────

@pytest_asyncio.fixture
async def app_and_redis():
    app = create_app()
    redis = fakeredis.aioredis.FakeRedis(decode_responses=True)
    app.state.redis = redis
    app.state.schema_layer = SchemaLayer(redis)
    app.state.context_layer = ContextLayer(redis)
    app.state.circuit_breaker = CircuitBreaker(redis)
    app.state.limiter.enabled = False
    return app, redis


@pytest_asyncio.fixture
async def client(app_and_redis):
    app, _ = app_and_redis
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://t") as c:
        yield c


@pytest.mark.asyncio
async def test_probe_scope_key_allowed_admin_route_denied(app_and_redis, client):
    _, redis = app_and_redis
    probe_key = await provision_key(redis, "scanner", scopes=["probe"])

    # A probe-scoped key can reach /probe (gets past auth to the target guard: 400).
    r = await client.post("/probe", headers={"X-Sentinel-Key": probe_key}, json={
        "server_url": "http://169.254.169.254/", "attacks": ["all"], "authorized": True})
    assert r.status_code == 400  # blocked by SSRF guard, NOT 403 — auth passed

    # ...but cannot manage keys (admin scope required) → 403.
    r = await client.get("/keys", headers={"X-Sentinel-Key": probe_key})
    assert r.status_code == 403
    assert "scope" in r.json()["detail"].lower()


@pytest.mark.asyncio
async def test_read_scope_key_cannot_probe(app_and_redis, client):
    _, redis = app_and_redis
    read_key = await provision_key(redis, "viewer", scopes=["read"])
    r = await client.post("/probe", headers={"X-Sentinel-Key": read_key}, json={
        "server_url": "https://x.example.com", "attacks": ["all"], "authorized": True})
    assert r.status_code == 403


@pytest.mark.asyncio
async def test_admin_key_reaches_admin_route(app_and_redis, client):
    """An admin-scoped key passes the scope check on an admin-only route."""
    _, redis = app_and_redis
    admin_key = await provision_key(redis, "root", scopes=["admin"])
    # circuit-breaker reset is admin-scoped and Redis-only (no Postgres).
    r = await client.post("/gateway/circuit-breaker/reset",
                          headers={"X-Sentinel-Key": admin_key},
                          params={"session_id": "s1"})
    assert r.status_code == 200


@pytest.mark.asyncio
async def test_non_admin_key_denied_on_admin_route(app_and_redis, client):
    _, redis = app_and_redis
    gw_key = await provision_key(redis, "gw", scopes=["gateway"])
    r = await client.post("/gateway/circuit-breaker/reset",
                          headers={"X-Sentinel-Key": gw_key}, params={"session_id": "s1"})
    assert r.status_code == 403


@pytest.mark.asyncio
async def test_legacy_plain_key_has_all_scopes(app_and_redis, client):
    """A legacy plain-string key (pre-RBAC) is treated as fully scoped."""
    _, redis = app_and_redis
    from app.core.auth import _hash_key
    raw = "sk-legacy-plain"
    await redis.set(f"apikey:{_hash_key(raw)}", "legacy-label")  # old format
    r = await client.post("/probe", headers={"X-Sentinel-Key": raw}, json={
        "server_url": "http://169.254.169.254/", "attacks": ["all"], "authorized": True})
    assert r.status_code == 400  # auth+scope passed; blocked only by SSRF guard


@pytest.mark.asyncio
async def test_missing_scope_is_audited(app_and_redis, client):
    from app.core import metrics
    _, redis = app_and_redis
    read_key = await provision_key(redis, "viewer", scopes=["read"])
    before = metrics.auth_failures_total.labels("missing_scope:probe", "/probe")._value.get()
    await client.post("/probe", headers={"X-Sentinel-Key": read_key}, json={
        "server_url": "https://x.example.com", "authorized": True})
    after = metrics.auth_failures_total.labels("missing_scope:probe", "/probe")._value.get()
    assert after == before + 1
