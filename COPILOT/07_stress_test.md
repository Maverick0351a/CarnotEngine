# Task 07 — Stress & Overhead Measurement
**Prompt:**
Extend `scripts/stress_test.sh` to prefer `hey`/`wrk2`, parse outputs to capture p95/p99 latency and throughput. Parse loader logs to compute correlation failure rate and ring buffer drops (via counters map). Write `metrics.json` and summarize in `docs/OVERHEAD_RESULTS.md`.

**Acceptance:**
- `metrics.json` present with latency & drop rates; WORKLOG updated.
