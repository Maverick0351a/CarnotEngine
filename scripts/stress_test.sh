#!/usr/bin/env bash
set -euo pipefail

# --- Args / Defaults ---
TARGET="${1:-https://example.org}"
DURATION="${2:-30}"            # seconds for load tool
OUT_METRICS="${3:-metrics.json}"
LOADER_BIN="${LOADER_BIN:-carnot-agent/ebpf-core/go-loader/bin/carnot-ebpf-loader}"
BPF_OBJ="${BPF_OBJ:-carnot-agent/ebpf-core/openssl_handshake.bpf.o}"
LIBSSL_PATH="${LIBSSL_PATH:-/lib/x86_64-linux-gnu/libssl.so.3}"
RUNTIME_JSON="${RUNTIME_JSON:-runtime.jsonl}"
LOADER_METRICS_JSON="${LOADER_METRICS_JSON:-loader_metrics.json}"
DOC_OUT="docs/OVERHEAD_RESULTS.md"

echo "[stress] Target=${TARGET} duration=${DURATION}s loader=${LOADER_BIN}" >&2
START_TS=$(date -Iseconds)

LOADER_MODE=enabled
if [ "$(uname -s 2>/dev/null || echo Unknown)" != "Linux" ]; then
  echo "[stress] Non-Linux host detected; eBPF loader disabled (runtime metrics unavailable)." >&2
  LOADER_MODE=disabled
elif [ ! -x "${LOADER_BIN}" ]; then
  echo "[stress] Loader binary not found at ${LOADER_BIN}; continuing without runtime metrics." >&2
  LOADER_MODE=disabled
fi

# --- Start loader (background) ---
LOADER_LOG=loader_stress.log
if [ "$LOADER_MODE" = enabled ]; then
  "${LOADER_BIN}" -obj "${BPF_OBJ}" -out "${RUNTIME_JSON}" -metrics "${LOADER_METRICS_JSON}" -libssl "${LIBSSL_PATH}" 2>&1 | tee "${LOADER_LOG}" &
  LOADER_PID=$!
  echo "[stress] Started loader pid=${LOADER_PID}" >&2
  sleep 2
fi

# --- Run load tool ---
TOOL="curl-loop"
if command -v hey >/dev/null 2>&1; then
  TOOL="hey"
  echo "[stress] Using hey" >&2
  hey -z ${DURATION}s -disable-keepalive "${TARGET}" > hey.out 2>&1 || true
elif command -v wrk >/dev/null 2>&1; then
  TOOL="wrk"
  echo "[stress] Using wrk" >&2
  wrk -d${DURATION}s -c50 -t2 "${TARGET}" > wrk.out 2>&1 || true
else
  echo "[stress] Fallback curl loop" >&2
  END=$((SECONDS + DURATION))
  REQS=0
  while [ $SECONDS -lt $END ]; do curl -sS --max-time 5 -o /dev/null "${TARGET}" && REQS=$((REQS+1)) || true; done
  echo "requests=${REQS}" > curl.out
fi

END_TS=$(date -Iseconds)

# --- Stop loader ---
if [ "$LOADER_MODE" = enabled ]; then
  kill ${LOADER_PID} >/dev/null 2>&1 || true
  wait ${LOADER_PID} 2>/dev/null || true
fi

# --- Parse load tool metrics ---
reqs_per_sec="null"; p95_lat_ms="null"; p99_lat_ms="null"
case "$TOOL" in
  hey)
    # Requests/sec: 1234.56
    if grep -q "Requests/sec:" hey.out; then
      reqs_per_sec=$(grep "Requests/sec:" hey.out | awk '{print $2}')
    fi
    # Latency distribution lines: '  95% in 0.0209 secs'
    if grep -q "95% in" hey.out; then p95_lat_ms=$(grep "95% in" hey.out | awk '{print $3*1000}'); fi
    if grep -q "99% in" hey.out; then p99_lat_ms=$(grep "99% in" hey.out | awk '{print $3*1000}'); fi
    ;;
  wrk)
    # Requests/sec: 1567.12
    if grep -q "Requests/sec:" wrk.out; then reqs_per_sec=$(grep "Requests/sec:" wrk.out | awk '{print $2}'); fi
    # Latency Distribution section
    if grep -q "  95%" wrk.out; then p95_lat_ms=$(grep "  95%" wrk.out | awk '{print $2}'); fi
    if grep -q "  99%" wrk.out; then p99_lat_ms=$(grep "  99%" wrk.out | awk '{print $2}'); fi
    # wrk prints values like 62.50ms; strip 'ms'
    p95_lat_ms=$(echo "$p95_lat_ms" | sed 's/ms$//' || true)
    p99_lat_ms=$(echo "$p99_lat_ms" | sed 's/ms$//' || true)
    ;;
  curl-loop)
    # Rough throughput from curl loop
    loops=$(awk -F= '/requests=/{print $2}' curl.out 2>/dev/null || echo 0)
    if [ "$loops" -gt 0 ]; then reqs_per_sec=$(awk -v r="$loops" -v d="$DURATION" 'BEGIN{printf "%.2f", r/d}'); fi
    ;;
esac

# --- Parse loader metrics & logs ---
events_received=0; handshakes_emitted=0; correlation_timeouts=0; kernel_drops=0; handshake_p95_ms="null"; handshake_p99_ms="null"
if [ "$LOADER_MODE" = enabled ] && [ -f "${LOADER_METRICS_JSON}" ]; then
  events_received=$(grep -E '"eventsReceived"' "${LOADER_METRICS_JSON}" | tail -1 | sed 's/[^0-9]*//g' || echo 0)
  handshakes_emitted=$(grep -E '"handshakesEmitted"' "${LOADER_METRICS_JSON}" | tail -1 | sed 's/[^0-9]*//g' || echo 0)
  correlation_timeouts=$(grep -E '"correlationTimeouts"' "${LOADER_METRICS_JSON}" | tail -1 | sed 's/[^0-9]*//g' || echo 0)
  kernel_drops=$(grep -E '"kernel_drops"' "${LOADER_METRICS_JSON}" | tail -1 | sed 's/[^0-9]*//g' || echo 0)
  handshake_p95_ms=$(grep -E '"P95DurationMs"' "${LOADER_METRICS_JSON}" | tail -1 | sed 's/[^0-9.]*//g' || echo null)
  handshake_p99_ms=$(grep -E '"P99DurationMs"' "${LOADER_METRICS_JSON}" | tail -1 | sed 's/[^0-9.]*//g' || echo null)
fi

# Compute derived rates
correlation_failure_rate="null"; kernel_drop_rate="null"
if [ "$handshakes_emitted" -gt 0 ]; then
  correlation_failure_rate=$(awk -v c="$correlation_timeouts" -v h="$handshakes_emitted" 'BEGIN{printf "%.6f", c/h}')
fi
if [ "$events_received" -gt 0 ]; then
  kernel_drop_rate=$(awk -v kd="$kernel_drops" -v e="$events_received" 'BEGIN{printf "%.6f", kd/e}')
fi

# --- Write metrics JSON ---
cat > "${OUT_METRICS}" <<EOF
{
  "target": "${TARGET}",
  "start": "${START_TS}",
  "end": "${END_TS}",
  "duration_s": ${DURATION},
  "tool": "${TOOL}",
  "requests_per_sec": ${reqs_per_sec},
  "latency_p95_ms": ${p95_lat_ms},
  "latency_p99_ms": ${p99_lat_ms},
  "loader_mode": "${LOADER_MODE}",
  "handshake_p95_ms": ${handshake_p95_ms},
  "handshake_p99_ms": ${handshake_p99_ms},
  "events_received": ${events_received},
  "handshakes_emitted": ${handshakes_emitted},
  "correlation_timeouts": ${correlation_timeouts},
  "kernel_drops": ${kernel_drops},
  "correlation_failure_rate": ${correlation_failure_rate},
  "kernel_drop_rate": ${kernel_drop_rate}
}
EOF
echo "[stress] Wrote ${OUT_METRICS}" >&2

# --- Summarize to docs ---
mkdir -p docs
cat > "${DOC_OUT}" <<EOF
# Overhead & Stress Test Results

| Metric | Value |
|--------|-------|
| Target | ${TARGET} |
| Duration (s) | ${DURATION} |
| Tool | ${TOOL} |
| Requests/sec | ${reqs_per_sec} |
| HTTP p95 (ms) | ${p95_lat_ms} |
| HTTP p99 (ms) | ${p99_lat_ms} |
| Handshake p95 (ms) | ${handshake_p95_ms} |
| Handshake p99 (ms) | ${handshake_p99_ms} |
| Events Received | ${events_received} |
| Handshakes Emitted | ${handshakes_emitted} |
| Correlation Timeouts | ${correlation_timeouts} |
| Kernel Drops | ${kernel_drops} |
| Correlation Failure Rate | ${correlation_failure_rate} |
| Kernel Drop Rate | ${kernel_drop_rate} |

> Generated $(date -Iseconds). Values depend on hardware & network; compare deltas across revisions for regression detection.
EOF
echo "[stress] Wrote ${DOC_OUT}" >&2
