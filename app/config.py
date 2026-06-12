"""Application settings sourced from environment variables (pydantic-settings)."""
from __future__ import annotations

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Central configuration. All values overridable via environment variables."""

    model_config = SettingsConfigDict(env_prefix="SENTINEL_", env_file=".env", extra="ignore")

    # Auth
    api_key: str = "dev-key-123"          # override via SENTINEL_API_KEY in production
    auth_enabled: bool = True             # set SENTINEL_AUTH_ENABLED=false for local dev

    # Redis — set SENTINEL_REDIS_PASSWORD in production (non-empty enables AUTH)
    redis_url: str = "redis://localhost:6379/0"
    redis_password: str = ""   # SENTINEL_REDIS_PASSWORD

    # PostgreSQL
    postgres_url: str = "postgresql+asyncpg://sentinel:sentinel@localhost/sentinelmcp"

    # Layer 1 — schema cache
    schema_cache_ttl: int = 300            # seconds — Redis TTL on cached schemas
    revalidation_interval: int = 300       # seconds — background re-validation cadence
    schema_key_prefix: str = "schema:"     # Redis key namespace for cached schemas

    # Celery (Layer 3 async dispatch)
    celery_broker_url: str = "redis://localhost:6379/1"
    celery_result_backend: str = "redis://localhost:6379/1"

    # LLM05: Server allowlist — set true to block unknown MCP servers
    allowlist_enabled: bool = False   # SENTINEL_ALLOWLIST_ENABLED=true in production

    # SIEM sinks (all optional — leave blank to disable)
    splunk_hec_url: str = ""
    splunk_hec_token: str = ""
    datadog_api_key: str = ""
    webhook_url: str = ""

    # OpenTelemetry
    otel_endpoint: str = ""          # SENTINEL_OTEL_ENDPOINT e.g. http://localhost:4317
    otel_service_name: str = "sentinelmcp"  # SENTINEL_OTEL_SERVICE_NAME

    # JWT / OAuth
    jwt_issuer: str = ""             # SENTINEL_JWT_ISSUER
    jwt_audience: str = ""           # SENTINEL_JWT_AUDIENCE
    jwt_secret: str = ""             # SENTINEL_JWT_SECRET (HS256 shared secret)
    jwks_url: str = ""               # SENTINEL_JWKS_URL (RS256 JWKS endpoint)


def get_settings() -> Settings:
    """Return a fresh Settings instance read from the environment."""
    return Settings()


settings = get_settings()
