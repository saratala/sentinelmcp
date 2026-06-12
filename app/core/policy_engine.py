"""Policy-as-code engine — load detection rules from YAML, hot-reload on change.

Rules live in policies/default.yaml (and any *.yaml in the policies/ dir).
The engine is checked every 60 seconds; file changes take effect without
restarting the gateway.

Usage:
  engine = PolicyEngine()
  hits = engine.scan(text, layer=1)   # returns list of PolicyHit
  # hits is empty → clean; non-empty → threat detected
"""
from __future__ import annotations

import hashlib
import os
import re
import threading
import time
from pathlib import Path
from typing import Optional

import structlog
import yaml

log = structlog.get_logger(__name__)

POLICIES_DIR = Path(__file__).parent.parent.parent / "policies"
RELOAD_INTERVAL = 60  # seconds


class PolicyRule:
    def __init__(self, raw: dict) -> None:
        self.name: str = raw["name"]
        self.layer: int = int(raw["layer"])
        self.rule_type: str = raw.get("type", "regex")
        self.threat_type: str = raw.get("threat_type", "UNKNOWN")
        self.confidence: float = float(raw.get("confidence", 0.9))
        self.enabled: bool = raw.get("enabled", True)
        self.owasp_id: str = raw.get("owasp_id", "")

        if self.rule_type == "regex":
            self._pattern = re.compile(raw["pattern"], re.IGNORECASE | re.DOTALL)
            self._keywords: list[str] = []
        else:
            self._pattern = None
            self._keywords = [k.lower() for k in raw.get("keywords", [])]

    def match(self, text: str) -> Optional[str]:
        """Return matched text if rule fires, else None."""
        if not self.enabled:
            return None
        if self._pattern:
            m = self._pattern.search(text)
            return m.group(0)[:200] if m else None
        # keyword match
        lower = text.lower()
        for kw in self._keywords:
            if kw in lower:
                return kw
        return None


class PolicyHit:
    def __init__(self, rule: PolicyRule, match: str) -> None:
        self.name = rule.name
        self.layer = rule.layer
        self.threat_type = rule.threat_type
        self.confidence = rule.confidence
        self.owasp_id = rule.owasp_id
        self.match = match

    def to_dict(self) -> dict:
        return {
            "pattern": self.name,
            "threat_type": self.threat_type,
            "confidence": self.confidence,
            "owasp_id": self.owasp_id,
            "match": self.match[:200],
            "source": "policy_engine",
        }


class PolicyEngine:
    """Thread-safe policy engine with hot-reload."""

    def __init__(self, policies_dir: Path = POLICIES_DIR) -> None:
        self._dir = policies_dir
        self._rules: list[PolicyRule] = []
        self._file_hash: str = ""
        self._lock = threading.RLock()
        self._load()
        self._start_watcher()

    def _load(self) -> None:
        rules: list[PolicyRule] = []
        combined_content = ""

        if not self._dir.exists():
            log.warning("policies_dir_missing", path=str(self._dir))
            return

        for path in sorted(self._dir.glob("*.yaml")):
            try:
                content = path.read_text()
                combined_content += content
                data = yaml.safe_load(content)
                for raw in data.get("rules", []):
                    try:
                        rules.append(PolicyRule(raw))
                    except Exception as e:
                        log.warning("policy_rule_error", rule=raw.get("name"), error=str(e))
                log.info("policy_file_loaded", path=path.name, rules=len(rules))
            except Exception as e:
                log.error("policy_file_load_error", path=str(path), error=str(e))

        new_hash = hashlib.md5(combined_content.encode()).hexdigest()
        with self._lock:
            self._rules = rules
            self._file_hash = new_hash

        log.info("policies_loaded", total_rules=len(rules))

    def _start_watcher(self) -> None:
        def _watch():
            while True:
                time.sleep(RELOAD_INTERVAL)
                try:
                    combined = ""
                    for path in sorted(self._dir.glob("*.yaml")):
                        combined += path.read_text()
                    new_hash = hashlib.md5(combined.encode()).hexdigest()
                    if new_hash != self._file_hash:
                        log.info("policies_changed_reloading")
                        self._load()
                except Exception as e:
                    log.error("policy_watcher_error", error=str(e))

        t = threading.Thread(target=_watch, daemon=True)
        t.start()

    def scan(self, text: str, layer: int) -> list[PolicyHit]:
        """Scan text against all rules for the given layer. Returns hits."""
        with self._lock:
            rules = [r for r in self._rules if r.layer == layer and r.enabled]

        hits: list[PolicyHit] = []
        for rule in rules:
            matched = rule.match(text)
            if matched:
                hits.append(PolicyHit(rule, matched))
        return hits

    def rule_count(self, layer: Optional[int] = None) -> int:
        with self._lock:
            if layer is None:
                return len(self._rules)
            return sum(1 for r in self._rules if r.layer == layer and r.enabled)


# Module-level singleton — shared across the gateway
_engine: Optional[PolicyEngine] = None


def get_policy_engine() -> PolicyEngine:
    global _engine
    if _engine is None:
        _engine = PolicyEngine()
    return _engine
