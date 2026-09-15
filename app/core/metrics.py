"""Prometheus metrics for SentinelMCP — scraped at GET /metrics.

Security-relevant counters (threats, probe runs, auth failures, circuit-breaker
trips, drift, oversharing, rate-limits) plus RED metrics (rate/errors/duration)
for every HTTP route. Import-safe: if prometheus_client is unavailable the
helpers degrade to no-ops so the app still runs.
"""
from __future__ import annotations

try:
    from prometheus_client import CONTENT_TYPE_LATEST, Counter, Gauge, Histogram, generate_latest
    _ENABLED = True
except Exception:  # pragma: no cover - prometheus_client is a declared dep
    _ENABLED = False
    CONTENT_TYPE_LATEST = "text/plain"


def _counter(name, doc, labels=()):
    return Counter(name, doc, labels) if _ENABLED else _Noop()


def _hist(name, doc, labels=()):
    return Histogram(name, doc, labels) if _ENABLED else _Noop()


def _gauge(name, doc):
    return Gauge(name, doc) if _ENABLED else _Noop()


class _Noop:
    """No-op metric so callers never need to check whether metrics are enabled."""
    def labels(self, *a, **k):
        return self
    def inc(self, *a, **k):
        pass
    def observe(self, *a, **k):
        pass
    def set(self, *a, **k):
        pass


# ── HTTP (RED) ────────────────────────────────────────────────────────────────
http_requests_total = _counter(
    "sentinelmcp_http_requests_total", "HTTP requests", ["method", "route", "status"])
http_request_duration = _hist(
    "sentinelmcp_http_request_duration_seconds", "HTTP request latency", ["method", "route"])
http_requests_in_flight = _gauge(
    "sentinelmcp_http_requests_in_flight", "In-flight HTTP requests")

# ── Security ─────────────────────────────────────────────────────────────────
threats_total = _counter(
    "sentinelmcp_threats_total", "Threats/findings detected", ["threat_type", "layer", "source"])
probe_runs_total = _counter(
    "sentinelmcp_probe_runs_total", "Active probe runs", ["risk_level"])
probe_findings_total = _counter(
    "sentinelmcp_probe_findings_total", "Active probe findings",
    ["attack_type", "severity", "verdict"])
auth_failures_total = _counter(
    "sentinelmcp_auth_failures_total", "Authentication/authorization failures", ["reason", "route"])
circuit_breaker_trips_total = _counter(
    "sentinelmcp_circuit_breaker_trips_total", "Circuit-breaker trips", ["layer"])
drift_detections_total = _counter(
    "sentinelmcp_drift_detections_total", "Cross-session drift detections")
oversharing_events_total = _counter(
    "sentinelmcp_context_oversharing_total", "Context-oversharing events flagged")
rate_limited_total = _counter(
    "sentinelmcp_rate_limited_total", "Requests rejected by the rate limiter", ["route"])
requests_rejected_total = _counter(
    "sentinelmcp_requests_rejected_total", "Requests rejected by the request guard", ["reason"])
hardening_synth_total = _counter(
    "sentinelmcp_hardening_synthesized_total", "Closed-loop artifacts synthesized", ["kind"])


def record_threat(threat_type: str, layer, source: str = "detection") -> None:
    """Increment the threat counter from anywhere a finding is produced."""
    threats_total.labels(str(threat_type or "UNKNOWN"), f"L{layer}", source).inc()


def metrics_payload() -> tuple[bytes, str]:
    """Return (body, content_type) for the /metrics endpoint."""
    if not _ENABLED:
        return b"# prometheus_client not installed\n", CONTENT_TYPE_LATEST
    return generate_latest(), CONTENT_TYPE_LATEST
