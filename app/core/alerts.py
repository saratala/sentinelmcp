"""SIEM alert integrations — Splunk HEC, Datadog, Slack, PagerDuty, and generic webhook.

Every confirmed threat fires all configured sinks concurrently.
Failures are logged but never raise — alerting must never block the gateway.
"""
from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from typing import Any, Optional

import httpx
import structlog

from app.config import settings

log = structlog.get_logger(__name__)


def _base_event(
    server_url: str,
    tool_name: str,
    threat_type: str,
    pattern: str,
    match_text: str,
    confidence: float,
    layer: int,
    session_id: Optional[str] = None,
    rug_pull: bool = False,
) -> dict[str, Any]:
    """Build a normalised event dict shared across all sinks."""
    return {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "source": "sentinelmcp",
        "severity": "CRITICAL" if rug_pull else "HIGH",
        "server_url": server_url,
        "session_id": session_id,
        "tool_name": tool_name,
        "threat_type": threat_type,
        "layer": layer,
        "pattern": pattern,
        "match": match_text,
        "confidence": confidence,
        "rug_pull": rug_pull,
    }


async def _send_splunk(event: dict) -> None:
    """Send one event to Splunk HTTP Event Collector."""
    if not settings.splunk_hec_url or not settings.splunk_hec_token:
        return
    payload = {"event": event, "sourcetype": "sentinelmcp:threat"}
    async with httpx.AsyncClient(timeout=5) as client:
        r = await client.post(
            settings.splunk_hec_url,
            json=payload,
            headers={"Authorization": f"Splunk {settings.splunk_hec_token}"},
        )
        r.raise_for_status()


async def _send_datadog(event: dict) -> None:
    """Send one event to Datadog Events API."""
    if not settings.datadog_api_key:
        return
    payload = {
        "title": f"SentinelMCP: {event['threat_type']} on {event['tool_name']}",
        "text": f"Pattern: {event['pattern']}\nMatch: {event['match']}",
        "priority": "normal",
        "alert_type": "error",
        "tags": [
            f"server:{event['server_url']}",
            f"threat:{event['threat_type']}",
            f"layer:{event['layer']}",
        ],
    }
    async with httpx.AsyncClient(timeout=5) as client:
        r = await client.post(
            "https://api.datadoghq.com/api/v1/events",
            json=payload,
            headers={"DD-API-KEY": settings.datadog_api_key},
        )
        r.raise_for_status()


async def _send_webhook(event: dict) -> None:
    """POST the event payload to a generic webhook URL."""
    if not settings.webhook_url:
        return
    async with httpx.AsyncClient(timeout=5) as client:
        r = await client.post(settings.webhook_url, json=event)
        r.raise_for_status()


# Severity helpers shared by Slack and PagerDuty sinks.
_SEVERITY_COLOR = {
    "CRITICAL": "#FF0000",
    "HIGH": "#FFA500",
    "MEDIUM": "#FFFF00",
    "LOW": "#36A64F",
}

_PAGERDUTY_SEVERITY = {
    "CRITICAL": "critical",
    "HIGH": "error",
    "MEDIUM": "warning",
    "LOW": "info",
}


async def _send_slack(event: dict) -> None:
    """Send a Slack notification via an Incoming Webhook URL.

    Only fires for HIGH or CRITICAL severity so low-noise signals don't flood
    the channel.  The severity is derived from the ``severity`` field set by
    ``_base_event`` (CRITICAL when rug_pull=True, HIGH otherwise).
    """
    if not settings.slack_webhook_url:
        return

    severity: str = event.get("severity", "HIGH").upper()
    if severity not in ("CRITICAL", "HIGH"):
        return

    color = _SEVERITY_COLOR.get(severity, "#FFA500")
    summary = (
        f"[{severity}] SentinelMCP detected *{event['threat_type']}* "
        f"on tool `{event['tool_name']}`"
    )
    payload = {
        "text": summary,
        "attachments": [
            {
                "color": color,
                "fields": [
                    {"title": "Threat Type", "value": event["threat_type"], "short": True},
                    {"title": "Tool", "value": event["tool_name"], "short": True},
                    {"title": "Layer", "value": str(event["layer"]), "short": True},
                    {"title": "Session ID", "value": event.get("session_id") or "n/a", "short": True},
                    {"title": "Timestamp", "value": event["timestamp"], "short": False},
                ],
            }
        ],
    }
    async with httpx.AsyncClient(timeout=5) as client:
        r = await client.post(settings.slack_webhook_url, json=payload)
        r.raise_for_status()


async def _send_pagerduty(event: dict) -> None:
    """Trigger a PagerDuty incident via the Events API v2.

    Uses a dedup_key based on session_id + threat_type so that repeated alerts
    from the same session are de-duplicated rather than creating a flood of
    individual incidents.
    """
    if not settings.pagerduty_routing_key:
        return

    severity: str = event.get("severity", "HIGH").upper()
    pd_severity = _PAGERDUTY_SEVERITY.get(severity, "error")

    session_id = event.get("session_id") or "unknown"
    dedup_key = f"sentinel-{session_id}-{event['threat_type']}"

    payload = {
        "routing_key": settings.pagerduty_routing_key,
        "event_action": "trigger",
        "dedup_key": dedup_key,
        "payload": {
            "summary": (
                f"SentinelMCP [{severity}]: {event['threat_type']} on {event['tool_name']}"
            ),
            "severity": pd_severity,
            "source": "sentinelmcp",
            "component": event["tool_name"],
            "custom_details": {
                "threat_type": event["threat_type"],
                "layer": event["layer"],
                "pattern": event["pattern"],
                "match": event["match"],
                "confidence": event["confidence"],
                "session_id": session_id,
                "server_url": event["server_url"],
                "rug_pull": event.get("rug_pull", False),
                "timestamp": event["timestamp"],
            },
        },
    }
    async with httpx.AsyncClient(timeout=5) as client:
        r = await client.post(
            "https://events.pagerduty.com/v2/enqueue",
            json=payload,
        )
        r.raise_for_status()


async def fire_alert(
    server_url: str,
    tool_name: str,
    threat_type: str,
    pattern: str,
    match_text: str,
    confidence: float,
    layer: int,
    session_id: Optional[str] = None,
    rug_pull: bool = False,
) -> None:
    """Fire all configured SIEM sinks concurrently for one threat event.

    Never raises — individual sink failures are logged and swallowed so a
    broken SIEM config cannot disrupt the gateway.
    """
    event = _base_event(
        server_url=server_url,
        tool_name=tool_name,
        threat_type=threat_type,
        pattern=pattern,
        match_text=match_text,
        confidence=confidence,
        layer=layer,
        session_id=session_id,
        rug_pull=rug_pull,
    )

    sinks = [
        _send_splunk(event),
        _send_datadog(event),
        _send_webhook(event),
        _send_slack(event),
        _send_pagerduty(event),
    ]
    results = await asyncio.gather(*sinks, return_exceptions=True)

    for sink_name, result in zip(["splunk", "datadog", "webhook", "slack", "pagerduty"], results):
        if isinstance(result, Exception):
            log.warning("siem_alert_failed", sink=sink_name, error=str(result))
        else:
            log.debug("siem_alert_sent", sink=sink_name)
