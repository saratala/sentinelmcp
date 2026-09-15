"""Tests for the production preflight — refuse to boot with insecure defaults."""
from __future__ import annotations

from app.config import Settings, production_preflight


def test_development_is_always_clean():
    """In development the checks are advisory only — never block startup."""
    assert production_preflight(Settings(environment="development")) == []
    assert production_preflight(Settings()) == []  # default env


def test_production_flags_dev_key_and_wildcard_cors():
    # Explicit kwargs so the scenario is deterministic regardless of the CI env
    # (which may set SENTINEL_API_KEY / SENTINEL_CORS_ORIGINS).
    errors = production_preflight(Settings(
        environment="production", api_key="dev-key-123", cors_origins="*"))
    joined = " ".join(errors)
    assert any("SENTINEL_API_KEY" in e for e in errors)
    assert "CORS" in joined
    assert len(errors) >= 2


def test_production_flags_disabled_auth():
    errors = production_preflight(Settings(
        environment="production", api_key="strong", cors_origins="https://a.com",
        schema_signing_secret="s", redis_password="p", auth_enabled=False))
    assert any("AUTH" in e.upper() for e in errors)


def test_fully_hardened_production_passes():
    errors = production_preflight(Settings(
        environment="production",
        api_key="a-strong-random-key",
        auth_enabled=True,        # explicit — CI sets SENTINEL_AUTH_ENABLED=false
        cors_origins="https://app.example.com",
        schema_signing_secret="hmac-secret",
        redis_password="redis-pass",
    ))
    assert errors == []


def test_cors_origin_parsing():
    assert Settings(cors_origins="*").cors_origin_list == ["*"]
    assert Settings(cors_origins="https://a.com, https://b.com").cors_origin_list == \
        ["https://a.com", "https://b.com"]


def test_is_production_flag():
    assert Settings(environment="production").is_production is True
    assert Settings(environment="PROD").is_production is True
    assert Settings(environment="staging").is_production is False
