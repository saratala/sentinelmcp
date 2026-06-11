"""Tests for Layer 2 — parameter validation."""
from __future__ import annotations

import pytest

from app.gateway.param_layer import ParamLayer

SCHEMA_SIMPLE = {
    "type": "object",
    "properties": {
        "query": {"type": "string"},
        "limit": {"type": "integer"},
    },
    "required": ["query"],
}

SCHEMA_STRICT = {
    "type": "object",
    "properties": {
        "city": {"type": "string"},
    },
    "required": ["city"],
    "additionalProperties": False,
}

SCHEMA_NESTED = {
    "type": "object",
    "properties": {
        "user": {
            "type": "object",
            "properties": {
                "name": {"type": "string"},
                "age": {"type": "integer"},
            },
            "required": ["name"],
        },
    },
    "required": ["user"],
}


@pytest.fixture
def layer() -> ParamLayer:
    return ParamLayer()


# ── Happy path ────────────────────────────────────────────────────────────────

def test_valid_params_pass(layer):
    result = layer.validate("query_database", {"query": "SELECT 1"}, SCHEMA_SIMPLE)
    assert result.passed
    assert result.errors == []
    assert result.latency_ms < 5.0


def test_optional_field_present_passes(layer):
    result = layer.validate("query_database", {"query": "x", "limit": 10}, SCHEMA_SIMPLE)
    assert result.passed


def test_optional_field_absent_passes(layer):
    result = layer.validate("query_database", {"query": "x"}, SCHEMA_SIMPLE)
    assert result.passed


def test_strict_schema_exact_fields(layer):
    result = layer.validate("get_weather", {"city": "Boston"}, SCHEMA_STRICT)
    assert result.passed


def test_nested_object_valid(layer):
    result = layer.validate("create_user", {"user": {"name": "Alice", "age": 30}}, SCHEMA_NESTED)
    assert result.passed


def test_empty_schema_any_params_pass(layer):
    result = layer.validate("flexible_tool", {"anything": "goes"}, {})
    assert result.passed


# ── Attack path ───────────────────────────────────────────────────────────────

def test_missing_required_field_rejected(layer):
    result = layer.validate("query_database", {}, SCHEMA_SIMPLE)
    assert not result.passed
    assert any("query" in e for e in result.errors)


def test_wrong_type_rejected(layer):
    result = layer.validate("query_database", {"query": 12345}, SCHEMA_SIMPLE)
    assert not result.passed
    assert any("string" in e for e in result.errors)


def test_undeclared_param_rejected_when_strict(layer):
    result = layer.validate("get_weather", {"city": "NYC", "injected": "evil"}, SCHEMA_STRICT)
    assert not result.passed
    assert any("injected" in e for e in result.errors)


def test_undeclared_param_allowed_when_not_strict(layer):
    # additionalProperties not set → defaults to True → extra keys allowed
    result = layer.validate("query_database", {"query": "x", "extra": "ok"}, SCHEMA_SIMPLE)
    assert result.passed


def test_nested_type_mismatch_rejected(layer):
    result = layer.validate("create_user", {"user": {"name": 999}}, SCHEMA_NESTED)
    assert not result.passed
    assert any("string" in e for e in result.errors)


def test_nested_required_field_missing(layer):
    result = layer.validate("create_user", {"user": {"age": 30}}, SCHEMA_NESTED)
    assert not result.passed
    assert any("name" in e for e in result.errors)


def test_oversized_payload_rejected(layer):
    small_layer = ParamLayer(max_payload_bytes=10)
    result = small_layer.validate("tool", {"data": "x" * 100}, SCHEMA_SIMPLE)
    assert not result.passed
    assert any("too large" in e for e in result.errors)


def test_integer_field_type_correct(layer):
    result = layer.validate("query_database", {"query": "x", "limit": 5}, SCHEMA_SIMPLE)
    assert result.passed


def test_float_rejected_for_integer_field(layer):
    result = layer.validate("query_database", {"query": "x", "limit": 5.5}, SCHEMA_SIMPLE)
    assert not result.passed


# ── Result shape ──────────────────────────────────────────────────────────────

def test_result_contains_tool_name(layer):
    result = layer.validate("my_tool", {"query": "x"}, SCHEMA_SIMPLE)
    assert result.tool_name == "my_tool"


def test_latency_under_one_ms_for_small_payload(layer):
    result = layer.validate("query_database", {"query": "SELECT 1"}, SCHEMA_SIMPLE)
    assert result.latency_ms < 1.0
