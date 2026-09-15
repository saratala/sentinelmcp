"""Tests for observability + request hardening: correlation IDs, metrics, guards."""
from __future__ import annotations

import fakeredis.aioredis
import httpx
import pytest
import pytest_asyncio

from app.core.circuit_breaker import CircuitBreaker
from app.gateway.context_layer import ContextLayer
from app.gateway.schema_layer import SchemaLayer
from app.config import settings
from app.main import create_app

KEY = {"X-Sentinel-Key": settings.api_key}


@pytest_asyncio.fixture
async def client():
    app = create_app()
    redis = fakeredis.aioredis.FakeRedis(decode_responses=True)
    app.state.redis = redis
    app.state.schema_layer = SchemaLayer(redis)
    app.state.context_layer = ContextLayer(redis)
    app.state.circuit_breaker = CircuitBreaker(redis)
    app.state.limiter.enabled = False
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://t") as c:
        yield c
    await redis.aclose()


@pytest.mark.asyncio
async def test_correlation_id_generated_and_returned(client):
    r = await client.get("/health")
    assert "X-Request-ID" in r.headers
    assert len(r.headers["X-Request-ID"]) >= 16


@pytest.mark.asyncio
async def test_correlation_id_propagated_when_supplied(client):
    r = await client.get("/health", headers={"X-Request-ID": "trace-abc-123"})
    assert r.headers["X-Request-ID"] == "trace-abc-123"


@pytest.mark.asyncio
async def test_metrics_endpoint_exposes_prometheus(client):
    await client.get("/health")  # generate at least one request
    r = await client.get("/metrics")
    assert r.status_code == 200
    body = r.text
    assert "sentinelmcp_http_requests_total" in body
    assert "sentinelmcp_http_request_duration_seconds" in body


@pytest.mark.asyncio
async def test_auth_failure_increments_metric(client):
    from app.core import metrics
    before = metrics.auth_failures_total.labels("invalid_api_key", "/gateway/registry")._value.get()
    r = await client.get("/gateway/registry", headers={"X-Sentinel-Key": "nope"})
    assert r.status_code == 401
    after = metrics.auth_failures_total.labels("invalid_api_key", "/gateway/registry")._value.get()
    assert after == before + 1


@pytest.mark.asyncio
async def test_missing_credentials_recorded(client):
    from app.core import metrics
    before = metrics.auth_failures_total.labels("missing_credentials", "/gateway/registry")._value.get()
    r = await client.get("/gateway/registry")
    assert r.status_code == 401
    after = metrics.auth_failures_total.labels("missing_credentials", "/gateway/registry")._value.get()
    assert after == before + 1


@pytest.mark.asyncio
async def test_oversized_body_rejected_with_413(client):
    # Declare a Content-Length beyond the default 5 MB limit.
    big = "x" * (6 * 1024 * 1024)
    r = await client.post("/gateway/registry/check", headers=KEY,
                          json={"tool_names": [], "text": big})
    assert r.status_code == 413
    assert "too large" in r.json()["detail"].lower()
