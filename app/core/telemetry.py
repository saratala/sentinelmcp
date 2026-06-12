"""OpenTelemetry tracing setup for SentinelMCP.

Set SENTINEL_OTEL_ENDPOINT to enable (e.g. http://localhost:4317 for Jaeger).
Leave blank to disable — all functions become no-ops.
"""
from __future__ import annotations

import contextlib
from typing import Any

try:
    from opentelemetry import trace
    from opentelemetry.sdk.resources import Resource
    from opentelemetry.sdk.trace import TracerProvider
    from opentelemetry.sdk.trace.export import BatchSpanProcessor
    from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter
    from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor
    try:
        from opentelemetry.instrumentation.redis import RedisInstrumentor
        _HAS_REDIS_INSTR = True
    except ImportError:
        _HAS_REDIS_INSTR = False
    _HAS_OTEL = True
except ImportError:
    _HAS_OTEL = False

_tracer = None


def setup_telemetry(app) -> None:
    """Wire OTEL into the FastAPI app. No-op if SENTINEL_OTEL_ENDPOINT is unset."""
    global _tracer
    from app.config import settings
    if not settings.otel_endpoint or not _HAS_OTEL:
        return

    resource = Resource(attributes={
        "service.name": settings.otel_service_name,
        "service.version": "0.2.0",
        "deployment.environment": "production",
    })
    provider = TracerProvider(resource=resource)
    exporter = OTLPSpanExporter(endpoint=settings.otel_endpoint, insecure=True)
    provider.add_span_processor(BatchSpanProcessor(exporter))
    trace.set_tracer_provider(provider)
    _tracer = trace.get_tracer("sentinelmcp")

    FastAPIInstrumentor.instrument_app(app)
    if _HAS_REDIS_INSTR:
        RedisInstrumentor().instrument()


def get_tracer():
    """Return the active tracer, or a no-op tracer if OTEL is disabled."""
    if _tracer is not None:
        return _tracer
    if _HAS_OTEL:
        return trace.get_tracer("sentinelmcp.noop")
    return _NoopTracer()


@contextlib.contextmanager
def layer_span(layer_name: str, attrs: dict | None = None):
    """Context manager that wraps a gateway layer in an OTEL span."""
    if not _HAS_OTEL or _tracer is None:
        yield None
        return

    with _tracer.start_as_current_span(f"sentinel.{layer_name}") as span:
        if attrs:
            for k, v in attrs.items():
                span.set_attribute(k, str(v))
        yield span


class _NoopTracer:
    """Fallback tracer when OTEL is not installed."""
    def start_as_current_span(self, name, **kwargs):
        return _NoopSpan()


class _NoopSpan:
    def __enter__(self): return self
    def __exit__(self, *a): pass
    def set_attribute(self, k, v): pass
