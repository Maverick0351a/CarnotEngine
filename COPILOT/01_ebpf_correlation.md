# Task 01 — eBPF Correlation & Metrics (Go Loader)
**Prompt (paste into Copilot Chat):**
Implement correlation in `carnot-agent/ebpf-core/go-loader/main.go`:
- Key by **TID** with TTL (2s default) to combine `EVT_SNI_SET`, `EVT_GROUPS_SET`, `EVT_HANDSHAKE_RET` into one JSON per handshake.
- Add `-out runtime.jsonl` to write one JSONL per handshake.
- Metrics: `eventsReceived`, `handshakesEmitted`, `correlationTimeouts`, `cacheEvictions`, `kernel_drops` (read from BPF `counters` map index 1).
- Log metrics every 5s; print final summary on SIGINT.
- After emitting handshake, delete the cache entry to avoid thread reuse pollution.

**Commands to run:**
```bash
cd carnot-agent/ebpf-core
make
cd go-loader && go build -o bin/carnot-ebpf-loader ./...
sudo ./bin/carnot-ebpf-loader -obj ../openssl_handshake.bpf.o -out runtime.jsonl -libssl /lib/x86_64-linux-gnu/libssl.so.3
# In another shell, generate traffic:
curl -sS https://example.org >/dev/null
```

**Acceptance Criteria:**
- `runtime.jsonl` contains aggregated handshake lines with `sni`, `groups_offered`, `pid`, `tid`, `success`.
- Metrics show low or zero `kernel_drops` and `correlationTimeouts` for this simple case.
- WORKLOG.md updated with commands and outcomes.
