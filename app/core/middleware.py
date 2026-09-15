"""ASGI middleware: correlation IDs, request metrics, and request hardening.

ObservabilityMiddleware
  - Assigns/propagates an ``X-Request-ID`` and binds it (plus the OTel
    ``trace_id`` when tracing is on) into the structlog context, so every log
    line emitted while handling the request carries the same correlation id.
  - Records per-route RED metrics (count, latency, in-flight).

RequestGuardMiddleware
  - Rejects oversized request bodies (413) before they are parsed, and enforces
    a per-request timeout (504) — reducing the DoS surface on the proxy path.
"""
from __future__ import annotations

import asyncio
import time
import uuid

import structlog
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

from app.config import settings
from app.core import metrics

log = structlog.get_logger(__name__)


def _route_template(request: Request) -> str:
    """Return the matched route's path template (low-cardinality metric label)."""
    route = request.scope.get("route")
    return getattr(route, "path", None) or "unmatched"


def _trace_id() -> str | None:
    try:
        from opentelemetry import trace
        ctx = trace.get_current_span().get_span_context()
        if ctx and ctx.trace_id:
            return format(ctx.trace_id, "032x")
    except Exception:
        return None
    return None


class ObservabilityMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        request_id = request.headers.get("X-Request-ID") or uuid.uuid4().hex
        request.state.request_id = request_id

        structlog.contextvars.clear_contextvars()
        bound = {"request_id": request_id, "method": request.method,
                 "path": request.url.path}
        tid = _trace_id()
        if tid:
            bound["trace_id"] = tid
        structlog.contextvars.bind_contextvars(**bound)

        metrics.http_requests_in_flight.inc()
        t0 = time.perf_counter()
        status = 500
        try:
            response = await call_next(request)
            status = response.status_code
            response.headers["X-Request-ID"] = request_id
            return response
        finally:
            metrics.http_requests_in_flight.dec()
            route = _route_template(request)
            metrics.http_request_duration.labels(request.method, route).observe(
                time.perf_counter() - t0)
            metrics.http_requests_total.labels(request.method, route, str(status)).inc()
            structlog.contextvars.clear_contextvars()


class RequestGuardMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next) -> Response:
        # Body-size guard — reject before parsing when Content-Length is declared.
        cl = request.headers.get("content-length")
        if cl:
            try:
                if int(cl) > settings.max_request_bytes:
                    metrics.requests_rejected_total.labels("body_too_large").inc()
                    log.warning("request_rejected_body_too_large",
                                content_length=int(cl), limit=settings.max_request_bytes,
                                path=request.url.path)
                    return JSONResponse(status_code=413,
                                        content={"detail": "Request body too large"})
            except ValueError:
                pass

        # Per-request timeout guard.
        try:
            return await asyncio.wait_for(
                call_next(request), timeout=settings.request_timeout_secs)
        except asyncio.TimeoutError:
            metrics.requests_rejected_total.labels("timeout").inc()
            log.warning("request_timeout", path=request.url.path,
                        timeout_secs=settings.request_timeout_secs)
            return JSONResponse(status_code=504, content={"detail": "Request timed out"})
