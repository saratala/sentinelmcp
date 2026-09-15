#!/usr/bin/env python3
"""Latency benchmark — proves the deterministic gateway overhead is < 5 ms.

Measures the per-layer detection cost and the end-to-end blocking invocation
path (Layers 2+3+4 via GatewayValidator, backed by in-memory fakeredis), and
reports p50/p95/p99 over many iterations plus a concurrent-load throughput run.

The async Layer-3 LLM escalation is OFF the response path by design and is
therefore excluded from these numbers (it never blocks a call). This benchmark
measures the deterministic path that every tool call traverses.

Usage:
    python benchmarks/latency_runner.py [--iterations 5000] [--concurrency 50]
"""
from __future__ import annotations

import argparse
import asyncio
import statistics
import sys
import time
from pathlib import Path

_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(_ROOT))

import fakeredis.aioredis  # noqa: E402

from app.detection.patterns import (  # noqa: E402
    detect_injection, detect_invisible_unicode, detect_pii,
)
from app.gateway.param_layer import ParamLayer  # noqa: E402
from app.gateway.output_layer import _scan_output  # noqa: E402
from app.gateway.context_layer import _score_text, _mosaic_risk  # noqa: E402

# Representative (benign) inputs — the common case the hot path must stay fast on.
DESC = "Query the customer database and return rows matching the given filter."
PARAMS = {"query": "SELECT id, name FROM customers WHERE region = 'EU' LIMIT 50"}
SCHEMA = {"type": "object", "properties": {"query": {"type": "string"}}, "required": ["query"]}
OUTPUT = "Returned 50 rows. Top region: EU. No anomalies detected in the result set."


def _pct(samples_ms: list[float], q: float) -> float:
    """Return the q-th percentile (0-100) of a sample list, in ms."""
    if not samples_ms:
        return 0.0
    s = sorted(samples_ms)
    k = min(len(s) - 1, int(round((q / 100.0) * (len(s) - 1))))
    return s[k]


def _time_sync(fn, iterations: int) -> list[float]:
    times = []
    for _ in range(iterations):
        t0 = time.perf_counter()
        fn()
        times.append((time.perf_counter() - t0) * 1000.0)
    return times


def _stats(name: str, samples: list[float]) -> dict:
    return {
        "layer": name,
        "p50_ms": round(_pct(samples, 50), 4),
        "p95_ms": round(_pct(samples, 95), 4),
        "p99_ms": round(_pct(samples, 99), 4),
        "mean_ms": round(statistics.fmean(samples), 4),
        "max_ms": round(max(samples), 4),
    }


async def _e2e_samples(iterations: int) -> list[float]:
    """End-to-end blocking invocation path (L2+L3+L4) via GatewayValidator."""
    from app.gateway.validator import GatewayValidator
    from app.gateway.context_layer import ContextLayer
    from app.core.circuit_breaker import CircuitBreaker

    redis = fakeredis.aioredis.FakeRedis(decode_responses=True)
    validator = GatewayValidator(
        param_layer=ParamLayer(),
        context_layer=ContextLayer(redis),
        circuit_breaker=CircuitBreaker(redis),
    )
    times = []
    for i in range(iterations):
        t0 = time.perf_counter()
        await validator.validate_invocation(
            session_id=f"bench-{i % 20}", tool_name="query_db",
            params=PARAMS, input_schema=SCHEMA, output=OUTPUT,
        )
        times.append((time.perf_counter() - t0) * 1000.0)
    await redis.aclose()
    return times


async def _concurrent_throughput(total: int, concurrency: int) -> dict:
    """Run `total` invocations `concurrency`-at-a-time; report throughput + latency."""
    from app.gateway.validator import GatewayValidator
    from app.gateway.context_layer import ContextLayer
    from app.core.circuit_breaker import CircuitBreaker

    redis = fakeredis.aioredis.FakeRedis(decode_responses=True)
    validator = GatewayValidator(
        param_layer=ParamLayer(), context_layer=ContextLayer(redis),
        circuit_breaker=CircuitBreaker(redis),
    )
    sem = asyncio.Semaphore(concurrency)
    latencies: list[float] = []

    async def one(i: int):
        async with sem:
            t0 = time.perf_counter()
            await validator.validate_invocation(
                session_id=f"c-{i % 50}", tool_name="query_db",
                params=PARAMS, input_schema=SCHEMA, output=OUTPUT)
            latencies.append((time.perf_counter() - t0) * 1000.0)

    t_start = time.perf_counter()
    await asyncio.gather(*[one(i) for i in range(total)])
    wall = time.perf_counter() - t_start
    await redis.aclose()
    return {
        "requests": total, "concurrency": concurrency,
        "wall_secs": round(wall, 3),
        "throughput_rps": round(total / wall, 1) if wall else 0.0,
        "p50_ms": round(_pct(latencies, 50), 4),
        "p95_ms": round(_pct(latencies, 95), 4),
        "p99_ms": round(_pct(latencies, 99), 4),
    }


def main() -> None:
    ap = argparse.ArgumentParser(description="SentinelMCP latency benchmark")
    ap.add_argument("--iterations", type=int, default=5000)
    ap.add_argument("--concurrency", type=int, default=50)
    ap.add_argument("--budget-ms", type=float, default=5.0)
    args = ap.parse_args()
    n = args.iterations

    print(f"Latency benchmark — {n} iterations per layer\n" + "=" * 66)

    # Per-layer deterministic micro-benchmarks.
    param = ParamLayer()
    per_layer = [
        _stats("L1 schema  (detect_injection)", _time_sync(lambda: detect_injection(DESC), n)),
        _stats("L1 unicode (approval-fidelity)", _time_sync(lambda: detect_invisible_unicode(DESC), n)),
        _stats("L2 param   (ParamLayer)", _time_sync(lambda: param.validate("t", PARAMS, SCHEMA), n)),
        _stats("L3 output  (scan+pii)", _time_sync(lambda: (_scan_output(OUTPUT), detect_pii(OUTPUT)), n)),
        _stats("L4 context (tf-idf+mosaic)", _time_sync(lambda: _mosaic_risk(_score_text(DESC)), n)),
    ]
    hdr = f"{'layer':<34}{'p50':>9}{'p95':>9}{'p99':>9}{'max':>9}"
    print(hdr + "\n" + "-" * 70)
    for r in per_layer:
        print(f"{r['layer']:<34}{r['p50_ms']:>9.4f}{r['p95_ms']:>9.4f}"
              f"{r['p99_ms']:>9.4f}{r['max_ms']:>9.4f}")

    # End-to-end blocking path.
    e2e = _stats("end-to-end (L2+L3+L4)", asyncio.run(_e2e_samples(min(n, 3000))))
    print("-" * 70)
    print(f"{e2e['layer']:<34}{e2e['p50_ms']:>9.4f}{e2e['p95_ms']:>9.4f}"
          f"{e2e['p99_ms']:>9.4f}{e2e['max_ms']:>9.4f}")

    # Concurrent load.
    load = asyncio.run(_concurrent_throughput(min(n, 3000), args.concurrency))
    print("=" * 66)
    print(f"Concurrent load: {load['requests']} reqs @ {load['concurrency']} concurrency → "
          f"{load['throughput_rps']} req/s  (p95 {load['p95_ms']}ms, p99 {load['p99_ms']}ms)")

    # Verdict against the stated budget (end-to-end p95).
    budget = args.budget_ms
    ok = e2e["p95_ms"] < budget
    print("=" * 66)
    print(f"VERDICT: end-to-end p95 = {e2e['p95_ms']}ms "
          f"{'<' if ok else '>='} {budget}ms budget → {'PASS ✅' if ok else 'FAIL ❌'}")

    # Persist a reproducible scorecard.
    out = _ROOT / "benchmarks" / "results" / "latency.md"
    out.parent.mkdir(parents=True, exist_ok=True)
    lines = [
        "# SentinelMCP — Latency Benchmark",
        "",
        f"Deterministic gateway overhead, {n} iterations/layer. Measures the path "
        "every tool call traverses; the async L3 LLM escalation is off-path and excluded.",
        "",
        "| Layer | p50 (ms) | p95 (ms) | p99 (ms) | max (ms) |",
        "|-------|---------:|---------:|---------:|---------:|",
    ]
    for r in per_layer + [e2e]:
        lines.append(f"| {r['layer']} | {r['p50_ms']} | {r['p95_ms']} | {r['p99_ms']} | {r['max_ms']} |")
    lines += [
        "",
        f"**Concurrent load:** {load['requests']} requests @ {load['concurrency']} "
        f"concurrency → {load['throughput_rps']} req/s (p95 {load['p95_ms']}ms, p99 {load['p99_ms']}ms).",
        "",
        f"**Verdict:** end-to-end p95 = {e2e['p95_ms']}ms vs {budget}ms budget → "
        f"{'PASS' if ok else 'FAIL'}.",
        "",
        "_Reproduce: `make benchmark-latency` (uses in-memory fakeredis; a networked "
        "Redis adds its round-trip, typically < 1ms on localhost)._",
    ]
    out.write_text("\n".join(lines))
    print(f"  scorecard → {out}")
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
