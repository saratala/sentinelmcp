"""Pydantic request/response models for all gateway layers."""
from __future__ import annotations

from typing import Any, Optional

from pydantic import BaseModel, ConfigDict, Field


class Tool(BaseModel):
    """A single MCP tool advertised by a server. Extra fields (e.g. inputSchema) are kept."""

    model_config = ConfigDict(extra="allow")

    name: str = ""
    description: str = ""


class ThreatDetail(BaseModel):
    """A single detected threat within a tool schema or output."""

    tool: str
    threat_type: str            # TOOL_POISONING | RUG_PULL | OUTPUT_INJECTION
    pattern: str
    match: str
    confidence: float


class SchemaValidationResult(BaseModel):
    """Outcome of validating one server's tool schemas through Layer 1."""

    server_url: str
    schema_hash: str
    passed: bool
    cache_hit: bool = False
    is_new_server: bool = False
    schema_changed: bool = False
    rug_pull: bool = False
    threats: list[ThreatDetail] = Field(default_factory=list)
    clean_tools: list[dict[str, Any]] = Field(default_factory=list)
    total_tools: int = 0
    blocked_tools: int = 0
    validated_at: str = ""
    latency_ms: float = 0.0


# ── Layer 2 ───────────────────────────────────────────────────────────────────

class ParamValidationResult(BaseModel):
    """Outcome of validating one tool invocation's parameters through Layer 2."""

    tool_name: str
    passed: bool
    errors: list[str] = Field(default_factory=list)
    latency_ms: float = 0.0


# ── Layer 3 ───────────────────────────────────────────────────────────────────

class OutputInspectionResult(BaseModel):
    """Outcome of inspecting one tool's output through Layer 3."""

    session_id: str
    tool_name: str
    passed: bool
    threats: list[ThreatDetail] = Field(default_factory=list)
    circuit_tripped: bool = False
    latency_ms: float = 0.0


# ── Layer 4 ───────────────────────────────────────────────────────────────────

class ContextRiskResult(BaseModel):
    """Outcome of evaluating one tool call's semantic mosaic risk through Layer 4."""

    session_id: str
    tool_name: str
    window_size: int = 0
    category_scores: dict[str, float] = Field(default_factory=dict)
    risk_score: float = 0.0
    alerted: bool = False
    latency_ms: float = 0.0


# ── Orchestrated invocation result ───────────────────────────────────────────

class InvocationResult(BaseModel):
    """Aggregated result from Layers 2, 3, and 4 for one tool invocation."""

    session_id: str
    tool_name: str
    passed: bool
    blocked_by_circuit: bool = False
    circuit_reason: str = ""
    param_result: Optional[ParamValidationResult] = None
    context_result: Optional[ContextRiskResult] = None
