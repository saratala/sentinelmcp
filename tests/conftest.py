"""Shared pytest fixtures: an in-memory (fakeredis) client and a SchemaLayer."""
from __future__ import annotations

import json
from pathlib import Path

import fakeredis.aioredis
import pytest
import pytest_asyncio

from app.gateway.schema_layer import SchemaLayer

FIXTURES = Path(__file__).parent / "fixtures"


def load_fixture(name: str) -> dict:
    """Load a JSON fixture from tests/fixtures by file name."""
    return json.loads((FIXTURES / name).read_text())


@pytest_asyncio.fixture
async def redis_client():
    """Provide a clean in-memory Redis client per test."""
    client = fakeredis.aioredis.FakeRedis(decode_responses=True)
    await client.flushall()
    yield client
    await client.aclose()


@pytest_asyncio.fixture
async def layer(redis_client):
    """Provide a SchemaLayer wired to the in-memory Redis, TTL=300s."""
    return SchemaLayer(redis_client, ttl=300, key_prefix="schema:")


@pytest.fixture
def clean_tools() -> list:
    """The clean tool fixture list."""
    return load_fixture("clean_tools.json")["tools"]


@pytest.fixture
def poisoned_tools() -> list:
    """The poisoned tool fixture list."""
    return load_fixture("poisoned_tools.json")["tools"]
