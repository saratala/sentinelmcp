"""Tests for the context-oversharing DLP meter (OWASP MCP10)."""
from __future__ import annotations

import pytest
import pytest_asyncio

from app.core.exposure import ExposureMeter, scan_sensitive

SESSION = "agent-session-1"
SRV = "https://sink-a.example.com"


@pytest_asyncio.fixture
async def meter(redis_client):
    # Small budgets so tests are cheap to trip.
    return ExposureMeter(redis_client, per_server_budget=3, fan_out_limit=2)


def test_scan_sensitive_counts_categories():
    text = "email a@b.com ssn 123-45-6789 card 4111111111111111"
    cats = scan_sensitive(text)
    assert sum(cats.values()) >= 2  # ssn + credit card at minimum


@pytest.mark.asyncio
async def test_no_sensitive_data_not_flagged(meter):
    r = await meter.record(SESSION, SRV, {"query": "list open tickets"})
    assert r.items_this_call == 0
    assert r.flagged is False


@pytest.mark.asyncio
async def test_per_server_budget_trips(meter):
    # Each call sends 2 sensitive items; budget is 3 → second call exceeds it.
    payload = {"ssn": "123-45-6789", "card": "4111111111111111"}
    r1 = await meter.record(SESSION, SRV, payload)
    assert r1.over_budget is False
    r2 = await meter.record(SESSION, SRV, payload)
    assert r2.over_budget is True
    assert r2.cumulative_to_server >= 4


@pytest.mark.asyncio
async def test_fan_out_across_destinations_trips(meter):
    payload = {"ssn": "123-45-6789"}
    await meter.record(SESSION, "https://s1.example.com", payload)
    await meter.record(SESSION, "https://s2.example.com", payload)
    r = await meter.record(SESSION, "https://s3.example.com", payload)
    assert r.fan_out_exceeded is True
    assert r.distinct_destinations == 3


@pytest.mark.asyncio
async def test_summary_reports_cumulative_picture(meter):
    await meter.record(SESSION, SRV, {"ssn": "123-45-6789", "card": "4111111111111111"})
    await meter.record(SESSION, SRV, {"ssn": "987-65-4321"})
    s = await meter.summary(SESSION)
    assert s["tracked"] is True
    assert s["destinations"] == 1
    assert s["total_sensitive_items"] >= 3
    assert SRV in s["by_server"]


@pytest.mark.asyncio
async def test_summary_untracked_session(meter):
    s = await meter.summary("never-seen")
    assert s["tracked"] is False
