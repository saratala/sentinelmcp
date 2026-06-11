"""Tests for API key authentication and rate limiting."""
from __future__ import annotations

import pytest
import pytest_asyncio
import fakeredis.aioredis
from httpx import AsyncClient, ASGITransport

from app.main import create_app
from app.core.auth import provision_key, _hash_key

VALID_KEY = "dev-key-123"  # matches SENTINEL_API_KEY default in config


@pytest_asyncio.fixture
async def redis_client():
    client = fakeredis.aioredis.FakeRedis(decode_responses=True)
    yield client
    await client.aclose()


@pytest_asyncio.fixture
async def client(redis_client):
    """Test client with a fully wired app using fake Redis."""
    app = create_app()

    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as ac:
        # Manually wire state (bypasses lifespan for test speed)
        from app.gateway.schema_layer import SchemaLayer
        from app.gateway.context_layer import ContextLayer
        from app.core.circuit_breaker import CircuitBreaker

        app.state.redis = redis_client
        app.state.schema_layer = SchemaLayer(redis_client)
        app.state.context_layer = ContextLayer(redis_client)
        app.state.circuit_breaker = CircuitBreaker(redis_client)
        yield ac


SCHEMA_PAYLOAD = {
    "server_url": "https://test.example.com",
    "tools": [
        {"name": "get_weather", "description": "Returns weather for a city."}
    ],
}


# ── Auth happy path ───────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_valid_key_passes(client):
    r = await client.post(
        "/gateway/validate-schema",
        json=SCHEMA_PAYLOAD,
        headers={"X-Sentinel-Key": VALID_KEY},
    )
    assert r.status_code == 200


@pytest.mark.asyncio
async def test_health_endpoint_no_auth_required(client):
    r = await client.get("/health")
    assert r.status_code == 200


# ── Auth attack path ──────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_missing_key_rejected(client):
    r = await client.post("/gateway/validate-schema", json=SCHEMA_PAYLOAD)
    assert r.status_code == 422  # missing required header → FastAPI validation error


@pytest.mark.asyncio
async def test_wrong_key_rejected(client):
    r = await client.post(
        "/gateway/validate-schema",
        json=SCHEMA_PAYLOAD,
        headers={"X-Sentinel-Key": "wrong-key-xyz"},
    )
    assert r.status_code == 401


@pytest.mark.asyncio
async def test_empty_key_rejected(client):
    r = await client.post(
        "/gateway/validate-schema",
        json=SCHEMA_PAYLOAD,
        headers={"X-Sentinel-Key": " "},
    )
    assert r.status_code == 401


@pytest.mark.asyncio
async def test_invoke_requires_auth(client):
    r = await client.post(
        "/gateway/invoke",
        json={
            "session_id": "s1",
            "server_url": "https://test.example.com",
            "tool_name": "get_weather",
            "params": {"city": "NYC"},
            "input_schema": {},
        },
    )
    assert r.status_code == 422  # missing header


@pytest.mark.asyncio
async def test_inventory_requires_auth(client):
    r = await client.get("/gateway/inventory")
    assert r.status_code == 422


# ── Redis-provisioned key ─────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_provisioned_key_accepted(client, redis_client):
    raw_key = await provision_key(redis_client, "test-customer")
    r = await client.post(
        "/gateway/validate-schema",
        json=SCHEMA_PAYLOAD,
        headers={"X-Sentinel-Key": raw_key},
    )
    assert r.status_code == 200


@pytest.mark.asyncio
async def test_provision_key_stores_hash(redis_client):
    raw_key = await provision_key(redis_client, "acme-corp")
    stored = await redis_client.get(f"apikey:{_hash_key(raw_key)}")
    assert stored == "acme-corp"


@pytest.mark.asyncio
async def test_revoked_key_rejected(client, redis_client):
    raw_key = await provision_key(redis_client, "revoke-me")
    # Revoke by deleting from Redis
    await redis_client.delete(f"apikey:{_hash_key(raw_key)}")
    r = await client.post(
        "/gateway/validate-schema",
        json=SCHEMA_PAYLOAD,
        headers={"X-Sentinel-Key": raw_key},
    )
    assert r.status_code == 401
