#!/usr/bin/env bash
set -euo pipefail

# Simple eBPF handshake + drop counter smoke test.
# Requires: Linux (or WSL2), root (for uprobes), clang, make, bpftool, libbpf-dev, Go toolchain, hey, jq.

OBJ_DIR="carnot-agent/ebpf-core"
LOADER_DIR="carnot-agent/ebpf-core/go-loader"
OUT_JSON="integrations/runtime/runtime.jsonl"
METRICS_JSON="integrations/runtime/metrics.json"
LIBSSL_PATH="/lib/x86_64-linux-gnu/libssl.so.3"
MODE="normal" # or small
DURATION="20s"
CONCURRENCY=100
LOADER_EXTRA_ARGS="${LOADER_EXTRA_ARGS:-}"

usage(){ cat <<EOF
Usage: $0 [-m normal|small] [-d duration] [-c concurrency]
  -m  Ring buffer mode: normal (512KiB) or small (32KiB w/ expected drops)
  -d  Load generation duration (default 20s)
  -c  Concurrency for hey (default 100)
EOF
}
while getopts m:d:c:h opt; do
  case $opt in
    m) MODE=$OPTARG ;;
    d) DURATION=$OPTARG ;;
    c) CONCURRENCY=$OPTARG ;;
    h) usage; exit 0 ;;
  esac
done

echo "[*] Mode: $MODE  Duration: $DURATION  Concurrency: $CONCURRENCY"
command -v clang >/dev/null || { echo "clang required"; exit 1; }
command -v bpftool >/dev/null || { echo "bpftool required"; exit 1; }
command -v go >/dev/null || { echo "go toolchain required"; exit 1; }
command -v hey >/dev/null || { echo "hey required (go install github.com/rakyll/hey@latest)"; exit 1; }
command -v jq >/dev/null || { echo "jq required"; exit 1; }

sudo test -r "$LIBSSL_PATH" || { echo "Cannot read $LIBSSL_PATH (adjust -libssl path)"; exit 1; }

pushd "$OBJ_DIR" >/dev/null
make clean || true
if [ "$MODE" = "small" ]; then
  echo "[*] Building SMALL_RB variant (8KB ring buffer)"
  make BPF_CFLAGS="-O2 -g -target bpf -D__TARGET_ARCH_x86 -DSMALL_RB"
else
  make
fi
popd >/dev/null

pushd "$LOADER_DIR" >/dev/null
go build -o bin/carnot-ebpf-loader ./...
popd >/dev/null

mkdir -p "$(dirname "$OUT_JSON")"
sudo "$LOADER_DIR"/bin/carnot-ebpf-loader \
  -obj "$OBJ_DIR"/openssl_handshake.bpf.o \
  -out "$OUT_JSON" \
  -metrics "$METRICS_JSON" \
  -libssl "$LIBSSL_PATH" $LOADER_EXTRA_ARGS &
LOADER_PID=$!
echo "[*] Loader PID $LOADER_PID"
sleep 1

echo "[*] Generating HTTPS traffic"
if [ "$MODE" = "small" ]; then
  # Multiple short high-concurrency bursts to trigger ringbuf reservation failures
  TOTAL=${DURATION%s}
  [ "$TOTAL" -lt 8 ] && TOTAL=8
  BURSTS=6
  PER=$(( TOTAL / BURSTS ))
  [ "$PER" -lt 1 ] && PER=1
  echo "[*] Small mode: TOTAL=${TOTAL}s BURSTS=${BURSTS} PER=${PER}s concurrency=$(( CONCURRENCY * 3 ))"
  for i in $(seq 1 $BURSTS); do
    hey -z "${PER}s" -c $(( CONCURRENCY * 3 )) -disable-keepalive https://example.org || true
  done
else
  hey -z "$DURATION" -c "$CONCURRENCY" -disable-keepalive https://example.org || true
fi
if [ "$MODE" = "small" ]; then
  # Allow extra time for periodic metrics flush (5s interval) after bursts
  sleep 6
else
  sleep 5
fi
sudo kill "$LOADER_PID" || true
wait "$LOADER_PID" 2>/dev/null || true

echo "[*] Metrics summary:" 
jq '{eventsReceived, handshakesEmitted, kernel_drops, kernel_drop_rate}' "$METRICS_JSON" || cat "$METRICS_JSON"

if [ "$MODE" = "small" ]; then
  echo "[*] Expect kernel_drops > 0 (SMALL_RB)"
  jq 'select(.kernel_drops == 0) | error("Expected drops but saw zero")' "$METRICS_JSON" 2>/dev/null || true
else
  echo "[*] Expect kernel_drops near zero (normal ring buffer)"
fi

echo "[*] Done. Handshake samples:"
head -n 5 "$OUT_JSON" || true