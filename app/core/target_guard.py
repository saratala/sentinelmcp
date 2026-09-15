"""Target guard for the active probe — prevent it being weaponized (SSRF).

The probe issues attacker-style requests to a caller-supplied URL. Without a
guard, that turns the gateway into an SSRF primitive: a caller could aim it at
cloud-metadata endpoints (to steal credentials) or at internal infrastructure.

Policy:
  * ALWAYS block cloud-metadata + link-local targets (169.254.0.0/16 and the
    well-known metadata hostnames) — never a legitimate MCP server, and the
    classic SSRF pivot to cloud credentials.
  * OPTIONALLY block private/loopback ranges (RFC1918, 127.0.0.0/8, localhost).
    This is OFF by default because scanning *internal* MCP servers in-VPC is a
    legitimate, marketed use case; SaaS deployments turn it on.

DNS-rebinding is out of scope for this deterministic check; when private-blocking
is on we make a best-effort hostname resolution but fail open on resolver errors.
"""
from __future__ import annotations

import ipaddress
import socket
from urllib.parse import urlparse

import structlog

log = structlog.get_logger(__name__)

# Hostnames that resolve to the cloud metadata service — always blocked.
_METADATA_HOSTS = {
    "metadata.google.internal", "metadata", "169.254.169.254",
    "100.100.100.200",  # Alibaba Cloud metadata
}
_LINK_LOCAL = ipaddress.ip_network("169.254.0.0/16")


def _as_ip(host: str):
    try:
        return ipaddress.ip_address(host)
    except ValueError:
        return None


def _resolve(host: str) -> list:
    try:
        socket.setdefaulttimeout(1.0)
        infos = socket.getaddrinfo(host, None)
        return [ipaddress.ip_address(i[4][0]) for i in infos]
    except Exception:
        return []  # fail open — resolution errors must not break legitimate probes


def check_probe_target(url: str, *, block_private: bool = False) -> tuple[bool, str]:
    """Return (allowed, reason). ``reason`` is empty when allowed."""
    host = (urlparse(url).hostname or "").lower()
    if not host:
        return False, "target URL has no host"

    if host in _METADATA_HOSTS:
        return False, "target is a cloud-metadata endpoint"

    ip = _as_ip(host)
    candidates = [ip] if ip is not None else (_resolve(host) if block_private else [])

    for c in candidates:
        if c in _LINK_LOCAL or c.is_link_local:
            return False, "target is a link-local / metadata address"
        if c.is_reserved or c.is_multicast or c.is_unspecified:
            return False, "target is a reserved/multicast/unspecified address"
        if block_private and (c.is_private or c.is_loopback):
            return False, "target is a private/internal address (probe_block_private_targets)"

    if block_private and host in ("localhost", "ip6-localhost"):
        return False, "target is loopback (probe_block_private_targets)"

    return True, ""
