"""Celery tasks for async output inspection (Layer 3).

The API forks tool outputs here immediately after returning to the agent.
This task runs the full output scan and trips the circuit breaker if a
threat is found — the agent sees the threat block on its NEXT call.
"""
from __future__ import annotations

import asyncio

from celery import Celery

from app.config import settings

celery_app = Celery(
    "sentinelmcp",
    broker=settings.celery_broker_url,
    backend=settings.celery_result_backend,
)

celery_app.conf.update(
    task_serializer="json",
    result_serializer="json",
    accept_content=["json"],
    timezone="UTC",
    enable_utc=True,
)


@celery_app.task(name="inspect_output", bind=True, max_retries=2)
def inspect_output_task(self, session_id: str, tool_name: str, output: object) -> dict:
    """Async output inspection task dispatched by the gateway on every invocation."""
    from app.core.circuit_breaker import CircuitBreaker
    from app.core.redis import get_redis
    from app.gateway.output_layer import inspect_output

    async def _run() -> dict:
        redis = get_redis()
        cb = CircuitBreaker(redis)
        result = await inspect_output(session_id, tool_name, output, cb)
        return result.model_dump()

    try:
        return asyncio.run(_run())
    except Exception as exc:
        raise self.retry(exc=exc, countdown=2)
