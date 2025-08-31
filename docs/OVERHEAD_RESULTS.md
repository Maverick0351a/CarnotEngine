# Overhead & Stress Test Results

Windows baseline (no eBPF loader – runtime metrics disabled):

| Metric | Value |
|--------|-------|
| Target | https://example.org |
| Duration (s) | 5 |
| Tool | pwsh-curl |
| Requests | 86 |
| Requests/sec | 17.2 |
| HTTP p95 (ms) | 69.955 |
| HTTP p99 (ms) | 562.734 |
| Loader Mode | disabled-windows |
| Handshake p95 (ms) | - |
| Handshake p99 (ms) | - |
| Events Received | 0 |
| Handshakes Emitted | 0 |
| Correlation Timeouts | 0 |
| Kernel Drops | 0 |
| Correlation Failure Rate | 0 |
| Kernel Drop Rate | 0 |

> Next: run on Linux with eBPF loader active to capture handshake latency & kernel drop metrics.

---

## Linux CI Run (GitHub Actions, ubuntu-24.04, Run #14)

| Metric | Value |
|--------|-------|
| Target | https://example.org |
| Duration (s) | 30 |
| Tool | hey |
| Requests/sec | 495.9491 |
| HTTP p95 (ms) | 208.1 |
| HTTP p99 (ms) | 217.1 |
| Loader Mode | enabled |
| Handshake p95 (ms) | - |
| Handshake p99 (ms) | - |
| Events Received | 0 |
| Handshakes Emitted | 0 |
| Correlation Timeouts | 0 |
| Kernel Drops | 0 |
| Correlation Failure Rate | - |
| Kernel Drop Rate | - |

Note: The loader failed early to create the first BPF map due to MEMLOCK limits (`operation not permitted (MEMLOCK may be too low, consider rlimit.RemoveMemlock)`). As a result, handshake events were not captured (all zero / null) for this run. HTTP load metrics are still valid. To enable handshake metrics in CI we can (a) add a pre-run step `ulimit -l unlimited` or (b) call `rlimit.RemoveMemlock()` in the Go loader before loading the collection. After that change, a subsequent run should populate handshake percentiles and event/drop counters.
