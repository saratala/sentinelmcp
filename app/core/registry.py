"""MCP Server Registry — known-bad tool schema database.

Loads the registry/known_bad.json feed on startup and provides:
  - check_tool_names()  — flag tool names matching known attack patterns
  - check_indicators()  — flag text matching known attack indicators
  - get_entry()         — retrieve a full SMCP advisory by ID
  - list_entries()      — return the full registry (for the public feed endpoint)

The registry is checked as part of L1 schema validation, before the regex
deep-scan, so known patterns are caught with zero regex overhead.
"""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Optional

import structlog

log = structlog.get_logger(__name__)

_REGISTRY_PATH = Path(__file__).parent.parent.parent / "registry" / "known_bad.json"

_REGISTRY: dict = {}
_TOOL_NAME_INDEX: dict[str, list[str]] = {}   # tool_name_pattern -> [smcp_id, ...]
_INDICATOR_INDEX: list[tuple[str, re.Pattern, str]] = []  # (smcp_id, pattern, severity)


def _load() -> None:
    global _REGISTRY
    try:
        data = json.loads(_REGISTRY_PATH.read_text())
        _REGISTRY = {e["id"]: e for e in data.get("entries", [])}
        _build_indices()
        log.info("registry_loaded", entries=len(_REGISTRY), path=str(_REGISTRY_PATH))
    except Exception as exc:
        log.warning("registry_load_failed", error=str(exc))


def _build_indices() -> None:
    global _TOOL_NAME_INDEX, _INDICATOR_INDEX
    _TOOL_NAME_INDEX = {}
    _INDICATOR_INDEX = []

    for smcp_id, entry in _REGISTRY.items():
        for pattern in entry.get("tool_name_patterns", []):
            key = pattern.lower()
            _TOOL_NAME_INDEX.setdefault(key, []).append(smcp_id)

        severity = entry.get("severity", "MEDIUM")
        for indicator in entry.get("indicators", []):
            try:
                compiled = re.compile(re.escape(indicator), re.IGNORECASE)
                _INDICATOR_INDEX.append((smcp_id, compiled, severity))
            except re.error:
                pass


def check_tool_names(tool_names: list[str]) -> list[dict]:
    """Return registry hits for any tool name matching a known-bad pattern."""
    hits = []
    for name in tool_names:
        key = name.lower()
        for pattern_key, smcp_ids in _TOOL_NAME_INDEX.items():
            if pattern_key in key or key in pattern_key:
                for smcp_id in smcp_ids:
                    entry = _REGISTRY.get(smcp_id, {})
                    hits.append({
                        "smcp_id": smcp_id,
                        "tool_name": name,
                        "severity": entry.get("severity", "MEDIUM"),
                        "title": entry.get("title", ""),
                        "attack_type": entry.get("attack_type", ""),
                        "detection_layer": entry.get("detection_layer", "L1"),
                    })
    return hits


def check_indicators(text: str) -> list[dict]:
    """Return registry hits for any known-bad indicator found in text."""
    hits = []
    for smcp_id, pattern, severity in _INDICATOR_INDEX:
        m = pattern.search(text)
        if m:
            entry = _REGISTRY.get(smcp_id, {})
            hits.append({
                "smcp_id": smcp_id,
                "match": m.group(0),
                "severity": severity,
                "title": entry.get("title", ""),
                "attack_type": entry.get("attack_type", ""),
                "detection_layer": entry.get("detection_layer", "L1"),
            })
    return hits


def get_entry(smcp_id: str) -> Optional[dict]:
    return _REGISTRY.get(smcp_id)


def list_entries(severity: Optional[str] = None, attack_type: Optional[str] = None) -> list[dict]:
    entries = list(_REGISTRY.values())
    if severity:
        entries = [e for e in entries if e.get("severity") == severity.upper()]
    if attack_type:
        entries = [e for e in entries if e.get("attack_type") == attack_type.upper()]
    return sorted(entries, key=lambda e: e.get("published", ""), reverse=True)


def registry_stats() -> dict:
    severities = {}
    attack_types = {}
    for e in _REGISTRY.values():
        s = e.get("severity", "UNKNOWN")
        a = e.get("attack_type", "UNKNOWN")
        severities[s] = severities.get(s, 0) + 1
        attack_types[a] = attack_types.get(a, 0) + 1
    return {
        "total": len(_REGISTRY),
        "by_severity": severities,
        "by_attack_type": attack_types,
        "version": json.loads(_REGISTRY_PATH.read_text()).get("version", "unknown"),
        "updated": json.loads(_REGISTRY_PATH.read_text()).get("updated", "unknown"),
    }


# Load on import
_load()
