"""SentinelMCP — production FastAPI application.

Lifespan: opens Redis on startup, attaches all gateway components to app.state,
starts the background re-validator, and tears everything down cleanly on shutdown.
"""
from __future__ import annotations

from contextlib import asynccontextmanager

import structlog
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from slowapi.errors import RateLimitExceeded

from app.config import settings
from app.core.circuit_breaker import CircuitBreaker
from app.core.database import close_engine, create_tables
from app.core.rate_limit import limiter
from app.core.redis import close_redis, get_redis
from app.gateway.context_layer import ContextLayer
from app.gateway.router import router as gateway_router
from app.gateway.schema_layer import BackgroundRevalidator, SchemaLayer

log = structlog.get_logger(__name__)


async def _noop_fetcher(server_url: str) -> list:
    """Default tool fetcher — returns empty list (real impl fetches from MCP server)."""
    return []


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Startup: wire Redis + gateway components. Shutdown: clean teardown."""
    redis = get_redis()

    app.state.schema_layer = SchemaLayer(redis)
    app.state.context_layer = ContextLayer(redis)
    app.state.circuit_breaker = CircuitBreaker(redis)
    app.state.redis = redis

    revalidator = BackgroundRevalidator(
        schema_layer=app.state.schema_layer,
        fetch_tools=_noop_fetcher,
        interval=settings.revalidation_interval,
    )
    revalidator.start()
    app.state.revalidator = revalidator

    await create_tables()
    log.info("sentinelmcp_started", redis_url=settings.redis_url)
    yield

    await revalidator.stop()
    await close_redis()
    await close_engine()
    log.info("sentinelmcp_stopped")


def create_app() -> FastAPI:
    """Construct and return the FastAPI application."""
    app = FastAPI(
        title="SentinelMCP — AI Agent Security Gateway",
        description="Every tool, verified.",
        version="0.2.0",
        lifespan=lifespan,
    )

    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_methods=["GET", "POST"],
        allow_headers=["*"],
    )

    # Rate limiter state + 429 handler
    app.state.limiter = limiter

    @app.exception_handler(RateLimitExceeded)
    async def rate_limit_handler(request: Request, exc: RateLimitExceeded) -> JSONResponse:
        return JSONResponse(
            status_code=429,
            content={"detail": f"Rate limit exceeded: {exc.detail}"},
        )

    app.include_router(gateway_router)

    @app.get("/health")
    async def health() -> dict:
        """Liveness check."""
        return {"status": "ok", "version": "0.2.0"}

    return app


app = create_app()
