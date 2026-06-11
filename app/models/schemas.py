"""Pydantic request/response models for the schema layer (Layer 1)."""
from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class Tool(BaseModel):
    """A single MCP tool advertised by a server. Extra fields (e.g. inputSchema) are kept."""

    model_config = ConfigDict(extra="allow")

    name: str = ""
    description: str = ""


class ThreatDetail(BaseModel):
    """A single detected threat within a tool schema."""

    tool: str
    threat_type: str            # TOOL_POISONING | RUG_PULL
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
