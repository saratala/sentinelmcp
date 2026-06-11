# SentinelMCP — Project SKILL
**Read this at the start of every session. This is the authoritative project context.**

---

## What we're building

SentinelMCP is an **AI Agent Security Gateway** for MCP (Model Context Protocol)
connections. It sits between AI agents and MCP servers, detecting tool poisoning,
rug pulls, shadow servers, and credential theft — with under 5ms overhead on
tool invocations.

**Tagline: "Every tool, verified."**

<!-- MESSAGING DECISIONS (locked — change only after discussion with Sarat)
     Descriptor : "AI Agent Security Gateway"
       - "AI Agent" scopes the category precisely
       - "Security" is instantly understood by CISOs, no decoding required
       - "Gateway" signals infrastructure, not a bolt-on tool
     Tagline    : "Every tool, verified."
       - Positive promise (not "zero trust" / "nothing trusted")
       - "Every" signals completeness — no gaps
       - "verified" is credible in a regulated-industry sale

     Rejected options (keep for reference):
       - "zero-trust gateway"       — evokes network/identity, sounds negative
       - "AI runtime integrity"     — technically precise but requires decoding
       - "Trusted AI agents, by design" — outcome-first but vague
       - "The integrity layer"      — infrastructure positioning, too abstract
       - "Securified"               — portmanteau, too informal for CISO sale -->

**Target customer:** Enterprise CISOs and AI Platform Engineering leads at
fintech, healthcare, and regulated industries running AI agents with MCP in
production.

**Business model:** $2,500/mo Starter · $8,000/mo Growth · Enterprise custom.
Target: 10 enterprise customers = $600K–$1.2M ARR Year 1.

**Exit strategy:** Acquisition by Palo Alto Networks, CrowdStrike, or SentinelOne
at $30–80M in 3 years.

---

## Why SentinelMCP exists

MCP is the enterprise standard for connecting AI agents to tools — 78% of
enterprise AI teams run it in production. It has critical, actively-exploited
security gaps:

- **CVE-2025-54136** (CVSS 9.4) — tool description injection
- **CVE-2025-49596** — schema rug-pull mid-session

No purpose-built security gateway exists. This is the window.

### The six attack vectors we defend against

| # | Attack | Description |
|---|---|---|
| 1 | **Tool poisoning** | Hidden instructions embedded in tool descriptions |
| 2 | **Rug pulls** | Schema swapped silently mid-session |
| 3 | **Shadow MCP servers** | Unauthorized servers bypassing monitoring |
| 4 | **Credential theft** | MCP aggregates API keys — one breach = everything |
| 5 | **Supply chain** | Malicious packages on public MCP registries |
| 6 | **Semantic mosaic** | Benign-looking calls that assemble sensitive data at scale |

### Core architectural insight — never violate this

**One-time schema validation is broken. Per-request validation is too slow.**
We use a 4-layer hybrid that gives full coverage at <5ms overhead:

| Layer | When | Latency | What it catches |
|---|---|---|---|
| 1: Schema | Discovery + hash-watch | ~0ms cached | Poisoning, rug pulls |
| 2: Parameter | Every call, BLOCKING | <1ms | Smuggling, escalation |
| 3: Output | Every call, ASYNC | 0ms blocking | Output injection |
| 4: Context | Every call, PARALLEL | <3ms | Semantic mosaic |

**The async output trick:** Fork the response — agent gets it immediately,
inspector gets a copy via Celery. Circuit breaker blocks the NEXT call if a
threat is found. This is how we achieve <5ms while inspecting every output.

---

## Competitive moat

We beat MintMCP, Bifrost, Kong, and Azure APIM on four capabilities nobody
else has:

- Tool poisoning detection
- Rug pull alerts
- Shadow MCP server discovery
- Intent-aware policy engine

Plus in-VPC deployment — non-negotiable for regulated industries.

**Why Anthropic won't build this:** They build models, not security
infrastructure. A tool they ship would only protect Claude — they need a neutral
layer and have a conflict of interest.

**Why CrowdStrike/Palo Alto won't move fast enough:** They will, in 18–24
months. Our window is getting to 10 enterprise customers first. Data moat +
reference customers + SOC 2 = defensible position.

---

## The demo that closes design partners

Build this early — Sarat runs it for every CISO conversation. Must run in one
command: `docker-compose up && python demo.py`

1. Start `clean_server.py` and `poisoned_server.py`
2. Start SentinelMCP gateway
3. Connect agent to clean server → tools pass validation
4. Connect agent to poisoned server → attack intercepted in real time
5. Show threat log: CVE pattern match, confidence score, alert fired
6. Show latency: <5ms overhead in both cases

---

## Founder context

**Sarat** — 19 years in payment infrastructure and PCI compliance (WEX Inc,
Senior Engineering Manager). Ships fast, knows Python and React, catches anything
that violates security or latency constraints. Write to that standard.

**Working relationship:**
- Build complete feature (implementation + tests) → Sarat reviews in VS Code
- Autonomous: new files, tests, fixing your own failures, configs, Dockerfiles
- Requires Sarat's approval: changes to existing working code, auth/security
  config, anything customer-facing, architectural decisions not in this doc
- When blocked: say "BLOCKED: [specific question]" — never guess on security

---

## 90-day milestones

| Week | Goal |
|---|---|
| 1–2 | Working POC + website live |
| 3–6 | 3 design partners running SentinelMCP in staging |
| 7–10 | $500K SAFE signed from security angels |
| 11–13 | $300K ARR, 5 paying customers |

**Angel targets:** Cyber Mentor Fund, SYN Ventures, Operator Collective, YC
alumni with security background, former CISOs turned angels.

**Design partner targets:** CISOs at fintechs and healthcare companies running
Claude Code, Cursor, or any MCP-connected AI agents in production.

**Pitch hook:** Lead with CVE-2025-54136 (CVSS 9.4). Real exploit, real
enterprises affected, no dedicated solution. Sarat has 19 years in regulated
payment infrastructure — he's the founder this problem needs.

---

## Tech stack — never deviate without asking

| Layer | Technology | Notes |
|---|---|---|
| Backend | FastAPI (Python 3.12, async throughout) | All endpoints async def |
| Cache | Redis 7 | Schema cache, session state, circuit breakers |
| Queue | Celery + Redis | Async output inspection, background re-validation |
| Database | PostgreSQL 16 | Threat log, customer config, audit trail |
| ML/Detection | scikit-learn (TF-IDF) + regex patterns | No external LLM calls in hot path |
| Auth | API key (header: X-Sentinel-Key) + JWT for dashboard | Key rotation built in |
| Infra | Docker + Railway (dev) → Kubernetes/Helm (enterprise) | |
| Frontend | React 18 + Tailwind | Dashboard only, not public site |
| Testing | pytest + pytest-asyncio + httpx | 80%+ coverage required |
| Logging | structlog → JSON → SIEM-ready | Every threat event logged |

---

## Architecture — the 4 validation layers

### Layer 1: Schema layer (discovery time + hash-watch)
- Deep semantic scan on first connection
- SHA-256 hash cached in Redis with TTL=300s
- Background task re-validates every 5 minutes regardless
- Hash change → immediate re-validation → rug pull alert if threat found
- **Latency budget: ~0ms on cache hit, ~20ms on new schema**

### Layer 2: Parameter layer (every invocation, blocking)
- JSON Schema strict validation of input params
- Reject undeclared params, type mismatches, oversized payloads
- **Latency budget: <1ms always**

### Layer 3: Output layer (every invocation, ASYNC — never blocks)
- Fork response: agent gets it immediately, inspector gets a copy
- Celery task inspects output for injection patterns
- Threat found → circuit breaker raises on NEXT call from this session
- **Latency budget: 0ms blocking. Async SLA: <2s to alert**

### Layer 4: Context layer (every invocation, parallel)
- Sliding window (last 20 calls) per agent session
- TF-IDF classifies data categories accessed (email/calendar/files/creds/pii)
- Semantic mosaic score: alert when risk_score > 0.75
- **Latency budget: <3ms, runs in parallel not serially**

---

## Project structure

```
sentinelmcp/
├── app/
│   ├── main.py              # FastAPI app, lifespan, middleware
│   ├── config.py            # Settings via pydantic-settings
│   ├── deps.py              # FastAPI dependencies (auth, db, redis)
│   │
│   ├── gateway/
│   │   ├── router.py        # /gateway/* endpoints
│   │   ├── validator.py     # Orchestrates all 4 layers
│   │   ├── schema_layer.py  # Layer 1: schema cache + rug pull
│   │   ├── param_layer.py   # Layer 2: param validation
│   │   ├── output_layer.py  # Layer 3: async output inspection
│   │   └── context_layer.py # Layer 4: semantic mosaic
│   │
│   ├── detection/
│   │   ├── patterns.py      # Regex injection pattern library (50+)
│   │   ├── classifier.py    # TF-IDF model for semantic classification
│   │   └── threat_intel.py  # CVE feed ingestion + pattern updates
│   │
│   ├── models/
│   │   ├── schemas.py       # Pydantic request/response models
│   │   └── db.py            # SQLAlchemy ORM models
│   │
│   ├── core/
│   │   ├── redis.py         # Redis connection pool + helpers
│   │   ├── circuit_breaker.py # Per-session circuit breaker logic
│   │   └── alerts.py        # SIEM webhooks (Splunk/Datadog/generic)
│   │
│   └── api/
│       ├── inventory.py     # Server inventory endpoints
│       ├── threats.py       # Threat log endpoints
│       └── admin.py         # Allowlist management
│
├── dashboard/               # React frontend
│   ├── src/
│   │   ├── App.jsx
│   │   ├── pages/
│   │   │   ├── ThreatFeed.jsx
│   │   │   ├── Inventory.jsx
│   │   │   └── Latency.jsx
│   │   └── components/
│
├── worker/
│   └── tasks.py             # Celery tasks (output inspection, re-validation)
│
├── tests/
│   ├── test_schema_layer.py
│   ├── test_param_layer.py
│   ├── test_output_layer.py
│   ├── test_context_layer.py
│   └── fixtures/
│       ├── clean_tools.json
│       └── poisoned_tools.json
│
├── helm/                    # Kubernetes deployment chart
├── docker-compose.yml       # Local dev: API + Redis + Postgres + Worker
├── Dockerfile
├── pyproject.toml
└── SKILL.md                 # This file — single source of truth
```

---

## Coding standards — always follow these

**Python:**
- All endpoints `async def`, all DB calls `await`
- Pydantic v2 models for all request/response shapes
- `structlog` for all logging — no `print()` in production code
- Type hints everywhere — no bare `dict` or `list`
- Docstring on every public function: one line, what it does, not how
- Max function length: 40 lines. Extract if longer.
- Error handling: never swallow exceptions silently. Log + re-raise or return structured error.

**Security (non-negotiable):**
- No secrets in code. All config via environment variables + pydantic-settings.
- All SQL via SQLAlchemy ORM — no raw SQL strings.
- Input validation on every endpoint, even internal ones.
- Rate limiting on all public endpoints via slowapi.
- Threat patterns must never cause false positives on common MCP tools (test against fixtures).

**Testing:**
- Every new function gets a test.
- Test both the happy path AND the attack path.
- Fixtures in `tests/fixtures/` — never hardcode test data inline.
- Target: `pytest --cov=app --cov-report=term-missing` shows >80%.

**Git:**
- Commit after every working feature. Never commit broken code.
- Commit message format: `feat: add schema layer hash-watch` / `fix: circuit breaker race condition`
- One feature per commit. No "misc fixes" commits.

---

## Key constraints — never violate

1. **<5ms latency on tool invocations** — Layer 2 must never call an external API or LLM
2. **Output inspection never blocks** — Layer 3 is always async, always Celery
3. **No customer data leaves their VPC** — all processing local, no cloud callbacks
4. **Zero false positives on clean tools** — run fixtures/clean_tools.json, must pass 100%
5. **Every threat gets a structured log entry** — SIEM integration depends on this

---

## How to run locally

```bash
# Start all services
docker-compose up -d

# Run API
uvicorn app.main:app --reload --port 8888

# Run worker
celery -A worker.tasks worker --loglevel=info

# Run tests
pytest tests/ -v --cov=app

# Test live detection
curl -X POST http://localhost:8888/gateway/validate \
  -H "X-Sentinel-Key: dev-key-123" \
  -H "Content-Type: application/json" \
  -d @tests/fixtures/poisoned_tools.json
```

---

## Current build status

- [x] POC gateway (basic detection, single file)
- [x] Layer 1: Schema cache + rug pull detection
- [ ] Layer 2: Parameter validation
- [ ] Layer 3: Async output inspection + circuit breaker
- [ ] Layer 4: Context accumulation + semantic mosaic
- [ ] Auth + rate limiting
- [ ] PostgreSQL threat log
- [ ] SIEM integrations (Splunk + Datadog)
- [ ] Helm chart for enterprise deployment
- [ ] Dashboard (React)
- [ ] SOC 2 evidence collection
- [ ] One-command demo (`docker-compose up && python demo.py`)
- [ ] Railway deployment (live demo URL)

---

## Session prompt template

Start every Claude session with:

```
SentinelMCP session.
Read SKILL.md for full context.
Today's goal: [what you want to build]
Current status: [what's already built / paste relevant existing code]
Constraints: [anything specific to this session]
Build it, write tests, commit-ready output.
```
