"""FastAPI dependency injectors for Redis-backed gateway components."""
from __future__ import annotations

from fastapi import Request

from app.core.circuit_breaker import CircuitBreaker
from app.core.redis import get_redis
from app.gateway.context_layer import ContextLayer
from app.gateway.schema_layer import SchemaLayer


def get_schema_layer(request: Request) -> SchemaLayer:
    """Return the SchemaLayer stored on app state."""
    return request.app.state.schema_layer


def get_context_layer(request: Request) -> ContextLayer:
    """Return the ContextLayer stored on app state."""
    return request.app.state.context_layer


def get_circuit_breaker(request: Request) -> CircuitBreaker:
    """Return the CircuitBreaker stored on app state."""
    return request.app.state.circuit_breaker
