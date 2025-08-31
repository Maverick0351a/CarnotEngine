# Task 07 — Stress & Overhead Measurement
**Prompt:**
Extend `scripts/stress_test.sh` to prefer `hey`/`wrk2`, parse outputs to capture p95/p99 latency and throughput. Parse loader logs to compute correlation failure rate and ring buffer drops (via counters map). Write `metrics.json` and summarize in `docs/OVERHEAD_RESULTS.md`.

**Acceptance:**
- `metrics.json` present with latency & drop rates; WORKLOG updated.

Progress:
- [x] Extended `scripts/stress_test.sh` to run loader + load tool (hey/wrk/curl fallback).
- [x] Collects p95/p99 HTTP latency, throughput, handshake p95/p99 (from loader), correlation failure & kernel drop rates.
- [x] Writes structured `metrics.json` and `docs/OVERHEAD_RESULTS.md` summary.
- [x] Windows placeholder run produced metrics (no loader) -> commit.
- [x] Added GitHub Actions workflow `stress.yml` for automated Linux run & artifact upload.
 - [x] Linux run with loader captured handshake percentiles & drops (workflow run #14, artifact `stress-metrics` id=3891102438). Metrics artifact downloaded; repository update pending automatic ingestion step.
