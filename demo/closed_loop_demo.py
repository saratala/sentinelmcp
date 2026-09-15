"""SentinelMCP — Closed-Loop Hardening demo.

The differentiator no other MCP-security tool has: the offensive probe doesn't
just *report* vulnerabilities — a confirmed finding automatically hardens the
defensive gateway (registry advisory + live detection rule), fleet-wide, with no
human authoring. This script shows the before/after.

Prerequisites (Docker):
    docker-compose up -d                      # gateway + redis + postgres
    docker-compose --profile demo up -d       # + the vulnerable demo server
    python demo/closed_loop_demo.py

Or point it anywhere:
    SENTINEL_GATEWAY_URL=http://localhost:8888 \
    VULN_SERVER_URL=http://localhost:8003 \
    SENTINEL_API_KEY=dev-key-123 python demo/closed_loop_demo.py
"""
from __future__ import annotations

import os
import sys

import httpx

GATEWAY = os.getenv("SENTINEL_GATEWAY_URL", "http://localhost:8888")
# URL the GATEWAY uses to reach the target (compose service name inside Docker).
VULN = os.getenv("VULN_SERVER_URL", "http://vulnerable-mcp:8003")
KEY = os.getenv("SENTINEL_API_KEY", "dev-key-123")
H = {"X-Sentinel-Key": KEY, "Content-Type": "application/json"}

RED, GREEN, YELLOW, CYAN, BOLD, RESET = (
    "\033[91m", "\033[92m", "\033[93m", "\033[96m", "\033[1m", "\033[0m")


def banner(text: str, c: str = CYAN) -> None:
    print(f"\n{c}{BOLD}{'─'*64}{RESET}\n{c}{BOLD}  {text}{RESET}\n{c}{BOLD}{'─'*64}{RESET}")


def preflight(client: httpx.Client) -> None:
    banner("Pre-flight")
    try:
        client.get(f"{GATEWAY}/health", timeout=3).raise_for_status()
        print(f"  {GREEN}✓{RESET}  SentinelMCP gateway reachable")
    except Exception as exc:
        print(f"  {RED}✗{RESET}  gateway unreachable → {exc}")
        print("\n  Start it:  docker-compose up -d && docker-compose --profile demo up -d\n")
        sys.exit(1)


def count_auto_advisories(client: httpx.Client) -> int:
    r = client.get(f"{GATEWAY}/gateway/registry", headers=H, params={"attack_type": ""})
    entries = r.json().get("entries", [])
    return sum(1 for e in entries if str(e.get("id", "")).startswith("SMCP-AUTO-"))


def probe(client: httpx.Client, harden: bool) -> dict:
    r = client.post(f"{GATEWAY}/probe", headers=H, timeout=60,
                    json={"server_url": VULN, "attacks": ["all"], "harden": harden})
    r.raise_for_status()
    return r.json()


def invoke_exploit(client: httpx.Client) -> dict:
    """Send a known exploit payload through the gateway invoke path."""
    r = client.post(f"{GATEWAY}/gateway/invoke", headers=H, json={
        "session_id": "closed-loop-demo", "server_url": VULN, "tool_name": "run_query",
        "params": {"q": "'; DROP TABLE users; --"},
        "input_schema": {"type": "object", "properties": {"q": {"type": "string"}}},
    })
    return r.json()


def main() -> None:
    print(f"\n{BOLD}{CYAN}SentinelMCP — Closed-Loop Hardening{RESET}")
    print(f"{CYAN}Offense hardens defense, automatically.{RESET}")

    with httpx.Client(timeout=30) as client:
        preflight(client)

        banner("Step 1 — Probe the target (report only)", YELLOW)
        before = probe(client, harden=False)
        vulns = before.get("vulnerabilities_found", 0)
        print(f"  Target      : {VULN}")
        print(f"  Risk level  : {RED}{before.get('risk_level')}{RESET} "
              f"(score {before.get('risk_score')})")
        print(f"  Vulnerabilities found: {RED}{vulns}{RESET}")
        for f in before.get("findings", []):
            if f["verdict"] == "VULNERABLE":
                print(f"    {RED}•{RESET} {f['attack_type']:16} [{f['owasp_id']}] {f['severity']}")
        pre = count_auto_advisories(client)
        print(f"\n  Auto-synthesized advisories in registry: {pre}  "
              f"(gateway not yet hardened for this server)")

        banner("Step 2 — Probe again WITH --harden (close the loop)", CYAN)
        after = probe(client, harden=True)
        hard = after.get("hardening") or {}
        print(f"  {GREEN}✓ Synthesized defenses from confirmed findings:{RESET}")
        print(f"    registry advisories : {hard.get('advisories_created', [])}")
        print(f"    live rules installed: {hard.get('rules_installed', [])}")
        post = count_auto_advisories(client)
        print(f"\n  Auto-synthesized advisories in registry: {pre} → {GREEN}{post}{RESET}")

        banner("Step 3 — The gateway now enforces what the probe found", GREEN)
        result = invoke_exploit(client)
        blocked = result.get("status_code") == 403 or not result.get("passed", True)
        if blocked:
            print(f"  {GREEN}🛡  BLOCKED{RESET} — the exploit payload is now rejected at invoke")
            print(f"     (deterministic layers + the auto-synthesized rule)")
        else:
            print(f"  {YELLOW}payload passed — check that harden installed a layer-2 rule{RESET}")
        print(f"\n  {BOLD}A vulnerability discovered by red-teaming one server just "
              f"hardened the gateway — no human wrote a signature.{RESET}")

    print(f"\n{GREEN}{BOLD}Closed-loop demo complete.{RESET}\n")


if __name__ == "__main__":
    main()
