"""Application settings sourced from environment variables (pydantic-settings)."""
from __future__ import annotations

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Central configuration. All values overridable via environment variables."""

    model_config = SettingsConfigDict(env_prefix="SENTINEL_", env_file=".env", extra="ignore")

    # Deployment — set SENTINEL_ENVIRONMENT=production to enforce the startup
    # preflight (rejects insecure dev defaults). Anything else = development.
    environment: str = "development"      # SENTINEL_ENVIRONMENT
    # CORS allowed origins, comma-separated. "*" is permitted only outside prod.
    cors_origins: str = "*"               # SENTINEL_CORS_ORIGINS

    # Auth
    api_key: str = "dev-key-123"          # override via SENTINEL_API_KEY in production
    auth_enabled: bool = True             # set SENTINEL_AUTH_ENABLED=false for local dev

    # Redis — set SENTINEL_REDIS_PASSWORD in production (non-empty enables AUTH)
    redis_url: str = "redis://localhost:6379/0"
    redis_password: str = ""   # SENTINEL_REDIS_PASSWORD

    # PostgreSQL
    postgres_url: str = "postgresql+asyncpg://sentinel:sentinel@localhost/sentinelmcp"

    # Layer 1 — schema cache
    schema_signing_secret: str = ""        # SENTINEL_SCHEMA_SIGNING_SECRET — HMAC key for attestation
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
    slack_webhook_url: str = ""        # SENTINEL_SLACK_WEBHOOK_URL
    pagerduty_routing_key: str = ""    # SENTINEL_PAGERDUTY_ROUTING_KEY

    # OpenTelemetry
    otel_endpoint: str = ""          # SENTINEL_OTEL_ENDPOINT e.g. http://localhost:4317
    otel_service_name: str = "sentinelmcp"  # SENTINEL_OTEL_SERVICE_NAME

    # JWT / OAuth
    jwt_issuer: str = ""             # SENTINEL_JWT_ISSUER
    jwt_audience: str = ""           # SENTINEL_JWT_AUDIENCE
    jwt_secret: str = ""             # SENTINEL_JWT_SECRET (HS256 shared secret)
    jwks_url: str = ""               # SENTINEL_JWKS_URL (RS256 JWKS endpoint)

    # Redis Sentinel (HA mode) — set SENTINEL_REDIS_SENTINEL_URLS to enable
    redis_sentinel_urls: str = ""    # comma-separated host:port, e.g. "sentinel-1:26379,sentinel-2:26380"
    redis_sentinel_master: str = "mymaster"  # Sentinel master name

    # PostgreSQL read replica (HA mode) — set SENTINEL_POSTGRES_REPLICA_URL to enable
    postgres_replica_url: str = ""   # e.g. postgresql+asyncpg://sentinel:pass@postgres-replica:5432/sentinelmcp

    # Layer 4 — LLM-based semantic analysis for grey-zone risk scores
    llm_analysis_enabled: bool = True          # SENTINEL_LLM_ANALYSIS_ENABLED
    # Provider: "auto" (default) | "ollama" | "anthropic"
    # auto = use Ollama if SENTINEL_OLLAMA_URL is reachable, else Anthropic if key set, else skip
    llm_provider: str = "auto"                 # SENTINEL_LLM_PROVIDER
    ollama_url: str = "http://localhost:11434" # SENTINEL_OLLAMA_URL
    ollama_model: str = "qwen2.5:7b"          # SENTINEL_OLLAMA_MODEL
    # ANTHROPIC_API_KEY uses the standard key name (no SENTINEL_ prefix)
    anthropic_api_key: str = Field(default="", validation_alias="ANTHROPIC_API_KEY")
    llm_analysis_model: str = "claude-haiku-4-5-20251001"  # SENTINEL_LLM_ANALYSIS_MODEL (Anthropic)
    llm_grey_zone_min: float = 0.35            # SENTINEL_LLM_GREY_ZONE_MIN
    llm_grey_zone_max: float = 0.75            # SENTINEL_LLM_GREY_ZONE_MAX
    # Timeout for LLM call: 8s for local Ollama, 3s for cloud Anthropic
    llm_timeout_secs: float = 8.0             # SENTINEL_LLM_TIMEOUT_SECS
    # Layer 3 — async LLM escalation of grey-zone outputs (opt-in; off by default
    # so it never adds latency/cost unless explicitly enabled in production).
    # When on, a clean-but-suspicious output is re-checked by the LLM off the
    # response path; a positive verdict trips the circuit breaker for the NEXT call.
    output_llm_escalation: bool = False        # SENTINEL_OUTPUT_LLM_ESCALATION


    # ── Derived helpers ──────────────────────────────────────────────────────
    @property
    def is_production(self) -> bool:
        return self.environment.strip().lower() in ("production", "prod")

    @property
    def cors_origin_list(self) -> list[str]:
        """Parse the comma-separated CORS origins into a list."""
        return [o.strip() for o in self.cors_origins.split(",") if o.strip()] or ["*"]


# Known-insecure defaults that must not survive into production.
_DEV_API_KEY = "dev-key-123"


def production_preflight(s: "Settings") -> list[str]:
    """Return a list of fatal misconfigurations for a production deployment.

    Empty list ⇒ safe to boot. Non-empty ⇒ the app refuses to start in
    ``SENTINEL_ENVIRONMENT=production`` so an insecure gateway is never exposed.
    In development the list is always empty (checks are advisory only).
    """
    if not s.is_production:
        return []
    errors: list[str] = []
    if s.api_key == _DEV_API_KEY:
        errors.append("SENTINEL_API_KEY is still the dev default 'dev-key-123' — set a strong key.")
    if not s.auth_enabled:
        errors.append("SENTINEL_AUTH_ENABLED is false in production — auth must be on.")
    if "*" in s.cors_origin_list:
        errors.append("SENTINEL_CORS_ORIGINS is '*' in production — pin explicit origins.")
    if not s.schema_signing_secret:
        errors.append("SENTINEL_SCHEMA_SIGNING_SECRET is unset — schema attestation is disabled.")
    if not s.redis_password and s.redis_url.startswith("redis://"):
        errors.append("SENTINEL_REDIS_PASSWORD is unset and Redis is unencrypted (redis://).")
    return errors


def get_settings() -> Settings:
    """Return a fresh Settings instance read from the environment."""
    return Settings()


settings = get_settings()
