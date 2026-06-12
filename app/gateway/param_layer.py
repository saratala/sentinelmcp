"""Layer 2 — parameter validation (blocking, <1ms).

Every tool invocation passes through here before reaching the MCP server.
Validates that params strictly conform to the tool's declared JSON Schema:
no undeclared keys, correct types, no oversized payloads.
No external calls are made — this must stay under 1ms.
"""
from __future__ import annotations

import time
from typing import Any, Optional

import structlog

from app.core.policy_engine import get_policy_engine
from app.detection.patterns import detect_dangerous_args
from app.models.schemas import ParamValidationResult

log = structlog.get_logger(__name__)

# Maximum allowed size of the serialised params payload (bytes).
MAX_PAYLOAD_BYTES = 65_536  # 64 KB


def _check_type(value: Any, schema: dict, path: str) -> Optional[str]:
    """Return an error string if ``value`` doesn't match ``schema``, else None."""
    json_type = schema.get("type")
    type_map: dict[str, type | tuple[type, ...]] = {
        "string": str,
        "number": (int, float),
        "integer": int,
        "boolean": bool,
        "array": list,
        "object": dict,
        "null": type(None),
    }
    if json_type and json_type in type_map:
        expected = type_map[json_type]
        if not isinstance(value, expected):
            return f"{path}: expected {json_type}, got {type(value).__name__}"
    return None


def _validate_object(params: dict, schema: dict, path: str = "") -> list[str]:
    """Recursively validate ``params`` against an object JSON Schema."""
    errors: list[str] = []
    properties: dict = schema.get("properties", {})
    required: list[str] = schema.get("required", [])
    additional = schema.get("additionalProperties", True)

    # Missing required fields.
    for field in required:
        if field not in params:
            errors.append(f"{path}.{field}: required field missing")

    # Undeclared fields when additionalProperties is false.
    if additional is False:
        for key in params:
            if key not in properties:
                errors.append(f"{path}.{key}: undeclared parameter not allowed")

    # Type-check declared fields and recurse into nested objects.
    for key, value in params.items():
        if key not in properties:
            continue
        prop_schema = properties[key]
        field_path = f"{path}.{key}" if path else key
        type_error = _check_type(value, prop_schema, field_path)
        if type_error:
            errors.append(type_error)
        elif prop_schema.get("type") == "object" and isinstance(value, dict):
            errors.extend(_validate_object(value, prop_schema, field_path))

    return errors


class ParamLayer:
    """Layer 2 — synchronous parameter validator (no I/O, no external calls)."""

    def __init__(self, max_payload_bytes: int = MAX_PAYLOAD_BYTES) -> None:
        self._max_bytes = max_payload_bytes

    def validate(
        self,
        tool_name: str,
        params: dict[str, Any],
        input_schema: dict[str, Any],
    ) -> ParamValidationResult:
        """Validate ``params`` against ``input_schema``. Returns result synchronously."""
        t0 = time.perf_counter()

        # Payload size guard — prevents memory-exhaustion via oversized inputs.
        try:
            import json
            payload_size = len(json.dumps(params).encode("utf-8"))
        except (TypeError, ValueError):
            payload_size = 0

        if payload_size > self._max_bytes:
            return ParamValidationResult(
                tool_name=tool_name, passed=False,
                errors=[f"payload too large: {payload_size} bytes (max {self._max_bytes})"],
                latency_ms=round((time.perf_counter() - t0) * 1000, 3),
            )

        errors = _validate_object(params, input_schema)

        # LLM07/08: Dangerous argument detection
        import json as _json
        flat_args = _json.dumps(params, default=str)

        danger = detect_dangerous_args(flat_args)
        if danger:
            errors.append(f"dangerous_arg:{danger['pattern']}:{danger['match'][:60]}")
            log.warning("dangerous_arg_detected", tool=tool_name,
                        pattern=danger["pattern"])

        # Policy-engine rules (YAML-driven, layer 2)
        if not danger:
            engine = get_policy_engine()
            for hit in engine.scan(flat_args, layer=2):
                errors.append(f"policy:{hit.name}:{hit.match[:60]}")
                log.warning("policy_param_hit", tool=tool_name, rule=hit.name)

        result = ParamValidationResult(
            tool_name=tool_name,
            passed=not errors,
            errors=errors,
            latency_ms=round((time.perf_counter() - t0) * 1000, 3),
        )

        if errors:
            log.warning("param_validation_failed", tool=tool_name, errors=errors)

        return result
