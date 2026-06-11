"""Application settings sourced from environment variables (pydantic-settings)."""
from __future__ import annotations

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Central configuration. All values overridable via environment variables."""

    model_config = SettingsConfigDict(env_prefix="SENTINEL_", env_file=".env", extra="ignore")

    # Redis
    redis_url: str = "redis://localhost:6379/0"

    # Layer 1 — schema cache
    schema_cache_ttl: int = 300            # seconds — Redis TTL on cached schemas
    revalidation_interval: int = 300       # seconds — background re-validation cadence
    schema_key_prefix: str = "schema:"     # Redis key namespace for cached schemas


def get_settings() -> Settings:
    """Return a fresh Settings instance read from the environment."""
    return Settings()


settings = get_settings()
