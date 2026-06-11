# SentinelMCP — Project SKILL
**Read this at the start of every session. This is the authoritative project context.**

---

## What we're building

SentinelMCP is a zero-trust security gateway for MCP (Model Context Protocol) connections.
It sits between AI agents and MCP servers, detecting tool poisoning, rug pulls, shadow servers,
and credential theft in real time — with under 5ms overhead on tool invocations.

**Target customer:** Enterprise CISOs and AI Platform Engineering leads at fintech, healthcare,
and regulated industries running AI agents with MCP in production.

**Business model:** $2,500–$8,000/month SaaS. In-VPC deployment. LLM-agnostic.

**Exit strategy:** Acquisition by Palo Alto Networks, CrowdStrike, or SentinelOne at $30–80M in 3 years.

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
└── SKILL.md                 # This file
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
- [ ] Layer 1: Schema cache + rug pull detection
- [ ] Layer 2: Parameter validation
- [ ] Layer 3: Async output inspection + circuit breaker
- [ ] Layer 4: Context accumulation + semantic mosaic
- [ ] Auth + rate limiting
- [ ] PostgreSQL threat log
- [ ] SIEM integrations (Splunk + Datadog)
- [ ] Helm chart for enterprise deployment
- [ ] Dashboard (React)
- [ ] SOC 2 evidence collection

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
