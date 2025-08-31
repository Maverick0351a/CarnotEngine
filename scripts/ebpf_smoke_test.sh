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
LOADGEN="curl"  # curl (default, uses OpenSSL on ubuntu) or hey (Go TLS -> will NOT trigger libssl uprobes)
TARGET_URL="https://example.org"

usage(){ cat <<EOF
Usage: $0 [-m normal|small] [-d duration] [-c concurrency] [-g curl|hey] [-u url]
  -m  Ring buffer mode: normal (512KiB) or small (32KiB w/ expected drops)
  -d  Load generation duration (default 20s)
  -c  Concurrency for hey (default 100)
  -g  Load generator: curl (default) or hey. Use curl to exercise OpenSSL uprobes.
  -u  Target URL (default https://example.org)
EOF
}
while getopts m:d:c:g:u:h opt; do
  case $opt in
    m) MODE=$OPTARG ;;
    d) DURATION=$OPTARG ;;
    c) CONCURRENCY=$OPTARG ;;
  g) LOADGEN=$OPTARG ;;
  u) TARGET_URL=$OPTARG ;;
    h) usage; exit 0 ;;
  esac
done

echo "[*] Mode: $MODE  Duration: $DURATION  Concurrency: $CONCURRENCY  LoadGen: $LOADGEN  URL: $TARGET_URL"
command -v clang >/dev/null || { echo "clang required"; exit 1; }
command -v bpftool >/dev/null || { echo "bpftool required"; exit 1; }
command -v go >/dev/null || { echo "go toolchain required"; exit 1; }
if [ "$LOADGEN" = "hey" ]; then
  command -v hey >/dev/null || { echo "hey required (go install github.com/rakyll/hey@latest)"; exit 1; }
else
  command -v curl >/dev/null || { echo "curl required"; exit 1; }
fi
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
gen_with_curl() {
  local total_s=${DURATION%s}
  [ "$total_s" -lt 1 ] && total_s=1
  local end=$(( $(date +%s) + total_s ))
  while [ $(date +%s) -lt $end ]; do
    # fire a burst of concurrency background curls
    for i in $(seq 1 $CONCURRENCY); do
      curl -sS --max-time 8 --http1.1 "$TARGET_URL" -o /dev/null &
    done
    wait
  done
}

gen_with_curl_small() {
  local total_s=${DURATION%s}; [ "$total_s" -lt 8 ] && total_s=8
  local bursts=6
  local per=$(( total_s / bursts )); [ "$per" -lt 1 ] && per=1
  echo "[*] Small mode curl bursts: TOTAL=${total_s}s BURSTS=${bursts} PER=${per}s concurrency=$(( CONCURRENCY * 3 ))"
  for b in $(seq 1 $bursts); do
    for i in $(seq 1 $(( CONCURRENCY * 3 )) ); do
      curl -sS --max-time 8 --http1.1 "$TARGET_URL" -o /dev/null &
    done
    wait
    sleep $per
  done
}

if [ "$LOADGEN" = "hey" ]; then
  if [ "$MODE" = "small" ]; then
    TOTAL=${DURATION%s}; [ "$TOTAL" -lt 8 ] && TOTAL=8; BURSTS=6; PER=$(( TOTAL / BURSTS )); [ "$PER" -lt 1 ] && PER=1
    echo "[*] Small mode (hey): TOTAL=${TOTAL}s BURSTS=${BURSTS} PER=${PER}s concurrency=$(( CONCURRENCY * 3 ))"
    for i in $(seq 1 $BURSTS); do
      hey -z "${PER}s" -c $(( CONCURRENCY * 3 )) -disable-keepalive "$TARGET_URL" || true
    done
  else
    hey -z "$DURATION" -c "$CONCURRENCY" -disable-keepalive "$TARGET_URL" || true
  fi
else
  if [ "$MODE" = "small" ]; then
    gen_with_curl_small
  else
    gen_with_curl
  fi
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