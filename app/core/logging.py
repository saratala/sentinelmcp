"""Structured logging configuration.

Configures structlog so every log line automatically carries the per-request
correlation context (``request_id``, ``trace_id``) bound by the observability
middleware. JSON output in production (SIEM-ready); human-readable console in
dev. Call :func:`configure_logging` once at application startup.
"""
from __future__ import annotations

import logging

import structlog

from app.config import settings


def configure_logging() -> None:
    """Configure structlog + stdlib logging levels from settings."""
    level = getattr(logging, settings.log_level.upper(), logging.INFO)
    logging.basicConfig(format="%(message)s", level=level)

    shared = [
        structlog.contextvars.merge_contextvars,   # inject request_id / trace_id
        structlog.processors.add_log_level,
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
    ]
    renderer = (
        structlog.processors.JSONRenderer()
        if (settings.log_json or settings.is_production)
        else structlog.dev.ConsoleRenderer()
    )

    structlog.configure(
        processors=shared + [renderer],
        wrapper_class=structlog.make_filtering_bound_logger(level),
        logger_factory=structlog.PrintLoggerFactory(),
        cache_logger_on_first_use=True,
    )
