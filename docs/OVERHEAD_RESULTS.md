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
