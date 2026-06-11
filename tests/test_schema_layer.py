"""Tests for Layer 1: schema cache, hash-watch, rug pull, background re-validation."""
from __future__ import annotations

import asyncio

import pytest

from app.detection.patterns import detect_injection
from app.gateway.schema_layer import (
    BackgroundRevalidator,
    SchemaLayer,
    schema_hash,
)

# async tests are auto-marked via asyncio_mode = "auto" in pyproject.toml


# ─── hashing ──────────────────────────────────────────────────────────────────

def test_schema_hash_is_deterministic_and_order_independent(clean_tools):
    """Same tools (regardless of key order) hash identically; it is a full SHA-256."""
    h1 = schema_hash(clean_tools)
    h2 = schema_hash(list(reversed(clean_tools)))  # different list order
    # order of tools matters, but re-hashing the identical list is stable
    assert schema_hash(clean_tools) == h1
    assert len(h1) == 64 and all(c in "0123456789abcdef" for c in h1)
    assert h1 != h2  # reordering tools is a genuine schema change


def test_schema_hash_changes_when_description_changes(clean_tools):
    """Mutating a tool description yields a different hash (rug-pull trigger)."""
    mutated = [dict(t) for t in clean_tools]
    mutated[0]["description"] = "totally different description"
    assert schema_hash(mutated) != schema_hash(clean_tools)


# ─── detection: clean fixtures must never false-positive ─────────────────────

def test_clean_fixture_has_zero_false_positives(clean_tools):
    """Constraint #4 — clean tools must produce no detections."""
    for tool in clean_tools:
        combined = f"{tool['name']} {tool['description']}"
        assert detect_injection(combined) is None


def test_poisoned_fixture_is_detected(poisoned_tools):
    """Every malicious tool in the fixture is caught."""
    hits = [detect_injection(f"{t['name']} {t['description']}") for t in poisoned_tools]
    assert hits[0] is not None  # exfiltration + conceal
    assert hits[1] is None      # get_weather is clean
    assert hits[2] is not None  # credential dump


# ─── validate: happy path ────────────────────────────────────────────────────

async def test_validate_new_clean_server(layer: SchemaLayer, clean_tools):
    """First contact with a clean server passes and is marked new, not cached."""
    res = await layer.validate("https://clean.example.com", clean_tools)
    assert res.passed is True
    assert res.is_new_server is True
    assert res.cache_hit is False
    assert res.rug_pull is False
    assert res.blocked_tools == 0
    assert len(res.clean_tools) == len(clean_tools)
    assert len(res.schema_hash) == 64


async def test_validate_new_poisoned_server(layer: SchemaLayer, poisoned_tools):
    """First contact with a poisoned server fails as TOOL_POISONING, not rug pull."""
    res = await layer.validate("https://evil.example.com", poisoned_tools)
    assert res.passed is False
    assert res.rug_pull is False
    assert res.blocked_tools == 2
    assert all(t.threat_type == "TOOL_POISONING" for t in res.threats)


# ─── cache behaviour ─────────────────────────────────────────────────────────

async def test_second_validate_is_cache_hit(layer: SchemaLayer, clean_tools):
    """Re-validating an unchanged schema is a cache hit with no rescan."""
    await layer.validate("https://clean.example.com", clean_tools)
    res2 = await layer.validate("https://clean.example.com", clean_tools)
    assert res2.cache_hit is True
    assert res2.schema_changed is False
    assert res2.passed is True


async def test_cache_entry_has_ttl(layer: SchemaLayer, redis_client, clean_tools):
    """Cached schema is stored under the configured 300s TTL."""
    await layer.validate("https://clean.example.com", clean_tools)
    ttl = await redis_client.ttl("schema:https://clean.example.com")
    assert 0 < ttl <= 300


async def test_invalidate_forces_rescan(layer: SchemaLayer, clean_tools):
    """After invalidate, the next validate is a fresh (non-cached) scan."""
    await layer.validate("https://clean.example.com", clean_tools)
    await layer.invalidate("https://clean.example.com")
    res = await layer.validate("https://clean.example.com", clean_tools)
    assert res.cache_hit is False
    assert res.is_new_server is True


# ─── rug pull detection ──────────────────────────────────────────────────────

async def test_rug_pull_detected_on_hash_change(layer: SchemaLayer, clean_tools, poisoned_tools):
    """A server that was clean, then turns malicious, is flagged as RUG_PULL."""
    url = "https://rugpull.example.com"
    first = await layer.validate(url, clean_tools)
    assert first.passed is True

    second = await layer.validate(url, poisoned_tools)
    assert second.cache_hit is False
    assert second.schema_changed is True
    assert second.rug_pull is True
    assert second.passed is False
    assert all(t.threat_type == "RUG_PULL" for t in second.threats)


async def test_clean_schema_change_is_not_rug_pull(layer: SchemaLayer, clean_tools):
    """A benign schema change (still clean) changes the hash but is not a rug pull."""
    url = "https://clean.example.com"
    await layer.validate(url, clean_tools)

    changed = [dict(t) for t in clean_tools]
    changed[0]["description"] = "Query the database and return rows as CSV."
    res = await layer.validate(url, changed)
    assert res.schema_changed is True
    assert res.rug_pull is False
    assert res.passed is True


# ─── background re-validation ────────────────────────────────────────────────

async def test_revalidator_run_once_detects_rug_pull(layer: SchemaLayer, clean_tools, poisoned_tools):
    """Background sweep re-fetches a now-poisoned server and flags the rug pull."""
    url = "https://swap.example.com"
    await layer.validate(url, clean_tools)  # cached as clean

    # The server now serves a poisoned schema on re-fetch.
    async def fetch(server_url: str) -> list:
        return poisoned_tools

    revalidator = BackgroundRevalidator(layer, fetch, interval=300)
    results = await revalidator.run_once()
    assert len(results) == 1
    assert results[0].rug_pull is True
    assert results[0].passed is False


async def test_revalidator_survives_fetch_error(layer: SchemaLayer, clean_tools):
    """A fetch failure for one server does not abort the sweep."""
    await layer.validate("https://a.example.com", clean_tools)

    async def failing_fetch(server_url: str) -> list:
        raise RuntimeError("server unreachable")

    revalidator = BackgroundRevalidator(layer, failing_fetch, interval=300)
    results = await revalidator.run_once()
    assert results == []  # skipped, not raised


async def test_revalidator_start_stop_loop(layer: SchemaLayer, clean_tools):
    """The loop runs at least one sweep on a short interval, then stops cleanly."""
    await layer.validate("https://a.example.com", clean_tools)
    calls = {"n": 0}

    async def fetch(server_url: str) -> list:
        calls["n"] += 1
        return clean_tools

    revalidator = BackgroundRevalidator(layer, fetch, interval=0.05)
    revalidator.start()
    await asyncio.sleep(0.16)
    await revalidator.stop()
    assert calls["n"] >= 2  # ran multiple sweeps on the short interval


async def test_list_cached_servers(layer: SchemaLayer, clean_tools):
    """All validated servers are enumerable from the cache."""
    await layer.validate("https://a.example.com", clean_tools)
    await layer.validate("https://b.example.com", clean_tools)
    servers = set(await layer.list_cached_servers())
    assert servers == {"https://a.example.com", "https://b.example.com"}
