# SentinelMCP — Latency Benchmark

Deterministic gateway overhead, 3000 iterations/layer. Measures the path every tool call traverses; the async L3 LLM escalation is off-path and excluded.

| Layer | p50 (ms) | p95 (ms) | p99 (ms) | max (ms) |
|-------|---------:|---------:|---------:|---------:|
| L1 schema  (detect_injection) | 0.0231 | 0.0262 | 0.0277 | 0.3343 |
| L1 unicode (approval-fidelity) | 0.005 | 0.0052 | 0.0053 | 0.0105 |
| L2 param   (ParamLayer) | 0.008 | 0.0083 | 0.0085 | 6.8283 |
| L3 output  (scan+pii) | 0.0261 | 0.0266 | 0.0289 | 0.0491 |
| L4 context (tf-idf+mosaic) | 0.272 | 0.2824 | 0.3032 | 8.2911 |
| end-to-end (L2+L3+L4) | 0.6611 | 0.6818 | 0.7135 | 3.3554 |

**Concurrent load:** 3000 requests @ 50 concurrency → 1642.3 req/s (p95 30.4081ms, p99 39.1495ms).

**Verdict:** end-to-end p95 = 0.6818ms vs 5.0ms budget → PASS.

_Reproduce: `make benchmark-latency` (uses in-memory fakeredis; a networked Redis adds its round-trip, typically < 1ms on localhost)._