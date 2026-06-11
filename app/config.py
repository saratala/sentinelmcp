"""Application settings sourced from environment variables (pydantic-settings)."""
from __future__ import annotations

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Central configuration. All values overridable via environment variables."""

    model_config = SettingsConfigDict(env_prefix="SENTINEL_", env_file=".env", extra="ignore")

    # Auth
    api_key: str = "dev-key-123"          # override via SENTINEL_API_KEY in production
    auth_enabled: bool = True             # set SENTINEL_AUTH_ENABLED=false for local dev

    # Redis
    redis_url: str = "redis://localhost:6379/0"

    # PostgreSQL
    postgres_url: str = "postgresql+asyncpg://sentinel:sentinel@localhost/sentinelmcp"

    # Layer 1 — schema cache
    schema_cache_ttl: int = 300            # seconds — Redis TTL on cached schemas
    revalidation_interval: int = 300       # seconds — background re-validation cadence
    schema_key_prefix: str = "schema:"     # Redis key namespace for cached schemas

    # Celery (Layer 3 async dispatch)
    celery_broker_url: str = "redis://localhost:6379/1"
    celery_result_backend: str = "redis://localhost:6379/1"

    # SIEM sinks (all optional — leave blank to disable)
    splunk_hec_url: str = ""
    splunk_hec_token: str = ""
    datadog_api_key: str = ""
    webhook_url: str = ""


def get_settings() -> Settings:
    """Return a fresh Settings instance read from the environment."""
    return Settings()


settings = get_settings()
