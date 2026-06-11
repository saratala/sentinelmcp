"""Gateway validator — orchestrates all 4 layers for a tool invocation.

Layer 1 (schema) runs at connection time via SchemaLayer directly.
Layers 2, 3, and 4 run here on every tool invocation:
  - Layer 2 (param): blocking, synchronous, <1ms
  - Layer 3 (output): async, never blocks the response
  - Layer 4 (context): async, runs in parallel with Layer 2
"""
from __future__ import annotations

import asyncio
from typing import Any

import structlog

from app.core.circuit_breaker import CircuitBreaker
from app.gateway.context_layer import ContextLayer
from app.gateway.output_layer import inspect_output
from app.gateway.param_layer import ParamLayer
from app.models.schemas import (
    ContextRiskResult,
    InvocationResult,
    ParamValidationResult,
)

log = structlog.get_logger(__name__)


class GatewayValidator:
    """Orchestrates Layers 2, 3, and 4 for every tool invocation."""

    def __init__(
        self,
        param_layer: ParamLayer,
        context_layer: ContextLayer,
        circuit_breaker: CircuitBreaker,
    ) -> None:
        self._params = param_layer
        self._context = context_layer
        self._cb = circuit_breaker

    async def validate_invocation(
        self,
        session_id: str,
        tool_name: str,
        params: dict[str, Any],
        input_schema: dict[str, Any],
        output: Any = None,
    ) -> InvocationResult:
        """Validate one tool invocation through Layers 2, 3, and 4.

        Returns immediately after Layer 2 + 4. Layer 3 (output) is only
        dispatched when ``output`` is provided and runs as a fire-and-forget
        coroutine — it never blocks this method's return.
        """
        # Gate: check circuit breaker before doing any work.
        if await self._cb.is_open(session_id):
            reason = await self._cb.get_reason(session_id)
            log.warning("circuit_breaker_blocked", session=session_id, reason=reason)
            return InvocationResult(
                session_id=session_id,
                tool_name=tool_name,
                passed=False,
                blocked_by_circuit=True,
                circuit_reason=reason or "",
            )

        # Layer 2 (sync, <1ms) + Layer 4 (async, <3ms) run concurrently.
        param_result: ParamValidationResult
        context_result: ContextRiskResult

        param_result, context_result = await asyncio.gather(
            asyncio.to_thread(
                self._params.validate, tool_name, params, input_schema
            ),
            self._context.evaluate(session_id, tool_name, params),
        )

        # Layer 3 — fire and forget. Agent already has the output; we inspect async.
        if output is not None:
            asyncio.create_task(
                inspect_output(session_id, tool_name, output, self._cb)
            )

        passed = param_result.passed and not context_result.alerted

        if not param_result.passed:
            log.warning("invocation_blocked_params", session=session_id,
                        tool=tool_name, errors=param_result.errors)
        if context_result.alerted:
            log.warning("invocation_blocked_mosaic", session=session_id,
                        tool=tool_name, risk_score=context_result.risk_score)

        return InvocationResult(
            session_id=session_id,
            tool_name=tool_name,
            passed=passed,
            param_result=param_result,
            context_result=context_result,
            blocked_by_circuit=False,
        )
