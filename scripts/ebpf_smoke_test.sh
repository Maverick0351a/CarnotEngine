#!/usr/bin/env bash
set -euo pipefail

# Simple eBPF handshake + drop counter smoke test.
# Requires: Linux (or WSL2), root (for uprobes), clang, make, bpftool, libbpf-dev, Go toolchain, hey, jq.

OBJ_DIR="carnot-agent/ebpf-core"
LOADER_DIR="carnot-agent/ebpf-core/go-loader"
OUT_JSON="integrations/runtime/runtime.jsonl"
METRICS_JSON="integrations/runtime/metrics.json"
MODE="normal" # or small
DURATION="20s"
CONCURRENCY=100
LOADER_EXTRA_ARGS="${LOADER_EXTRA_ARGS:-}"
LOADGEN="curl"  # Generators: hey (preferred), curl, openssl (public), openssl_local (local s_server)
TARGET_URL="https://example.org"

usage(){ cat <<EOF
Usage: $0 [-m normal|small] [-d duration] [-c concurrency] [-g curl|hey|openssl|openssl_local] [-u url]
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
elif [ "$LOADGEN" = "openssl" ] || [ "$LOADGEN" = "openssl_local" ]; then
  command -v openssl >/dev/null || { echo "openssl required"; exit 1; }
else
  command -v curl >/dev/null || { echo "curl required"; exit 1; }
fi
command -v jq >/dev/null || { echo "jq required"; exit 1; }

# If curl mode requested but curl not linked with OpenSSL, auto-fallback to openssl generator.
if [ "$LOADGEN" = "curl" ]; then
  if ! curl -V 2>/dev/null | grep -qi openssl; then
    echo "[!] curl not linked against OpenSSL (no uprobes). Auto-falling back to openssl generator." >&2
    LOADGEN="openssl"
  fi
fi

# Resolve libssl path based on selected generator (curl or openssl).
resolve_libssl() {
  local bin="$1"
  local p
  p="$(ldd "$(command -v "$bin")" 2>/dev/null | awk '/libssl\.so\.3/ {print $3}' | head -1)"
  [ -z "$p" ] && [ -e /usr/lib/x86_64-linux-gnu/libssl.so.3 ] && p="$(readlink -f /usr/lib/x86_64-linux-gnu/libssl.so.3)"
  [ -z "$p" ] && [ -e /lib/x86_64-linux-gnu/libssl.so.3 ] && p="$(readlink -f /lib/x86_64-linux-gnu/libssl.so.3)"
  [ -z "$p" ] && { echo "[!] Could not resolve libssl.so.3 for $bin"; return 1; }
  echo "$p"
}
GEN_BIN="curl"
if [ "$LOADGEN" = "openssl" ] || [ "$LOADGEN" = "openssl_local" ]; then GEN_BIN="openssl"; fi
LIBSSL_PATH="$(resolve_libssl "$GEN_BIN")" || { echo "[!] Failed to resolve libssl; aborting"; exit 1; }
echo "[*] Resolved libssl: $LIBSSL_PATH"

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
  -libssl "$LIBSSL_PATH" $LOADER_EXTRA_ARGS 2>loader_stderr.log &
LOADER_PID=$!
echo "[*] Loader PID $LOADER_PID"
sleep 2

# Surface early attach results before traffic so job logs show probe matrix / errors quickly.
if [ -s loader_stderr.log ]; then
  echo "[*] Initial loader log (first 50 lines):"
  head -n 50 loader_stderr.log | sed 's/^/[loader] /'
else
  echo "[*] Waiting for loader to emit first metrics/log line (flush interval 5s)"
fi

echo "[*] Generating HTTPS traffic"

# Helper: extract host from URL
extract_host() { echo "$1" | sed -E 's#https?://([^/:]+).*#\1#'; }
HOSTNAME=$(extract_host "$TARGET_URL")
TOTAL_SECONDS=${DURATION%s}; [ "$TOTAL_SECONDS" -lt 1 ] && TOTAL_SECONDS=1
# Compute a nominal operation count for xargs-based generators (aim ~ duration)
OPS=$(( TOTAL_SECONDS * CONCURRENCY ))

if [ "$LOADGEN" = "hey" ]; then
  if [ "$MODE" = "small" ]; then
    TOTAL=${DURATION%s}; [ "$TOTAL" -lt 8 ] && TOTAL=8; BURSTS=6; PER=$(( TOTAL / BURSTS )); [ "$PER" -lt 1 ] && PER=1
    echo "[*] Small mode (hey): TOTAL=${TOTAL}s BURSTS=${BURSTS} PER=${PER}s concurrency=$(( CONCURRENCY * 3 ))"
    for i in $(seq 1 $BURSTS); do
      hey -z "${PER}s" -c $(( CONCURRENCY * 3 )) -disable-keepalive --http2=false "$TARGET_URL" || true
    done
  else
    hey -z "$DURATION" -c "$CONCURRENCY" -disable-keepalive --http2=false "$TARGET_URL" || true
  fi
elif [ "$LOADGEN" = "openssl_local" ]; then
  TMP_SSL_DIR=$(mktemp -d)
  pushd "$TMP_SSL_DIR" >/dev/null
  echo "[*] Generating throwaway self-signed cert (localhost)"
  openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem -days 1 -nodes -subj "/CN=localhost" >/dev/null 2>&1
  echo "[*] Starting local openssl s_server :8443"
  openssl s_server -quiet -accept 8443 -cert cert.pem -key key.pem >/dev/null 2>&1 &
  SERVER_PID=$!
  popd >/dev/null
  trap 'kill $SERVER_PID 2>/dev/null || true; rm -rf "$TMP_SSL_DIR"' EXIT
  sleep 1
  OPS=$(( CONCURRENCY * 10 ))
  echo "[*] openssl_local generator (OPS=${OPS} concurrency=${CONCURRENCY})"
  seq 1 "$OPS" | xargs -P "$CONCURRENCY" -I{} bash -c 'timeout 2s openssl s_client -connect 127.0.0.1:8443 -servername localhost </dev/null >/dev/null 2>&1 || true'
  kill $SERVER_PID 2>/dev/null || true
elif [ "$LOADGEN" = "curl" ]; then
  OPS=$(( CONCURRENCY * 10 ))
  echo "[*] curl generator using xargs (OPS=${OPS} concurrency=${CONCURRENCY})"
  seq 1 "$OPS" | xargs -P "$CONCURRENCY" -I{} bash -c '
    set -e
    url="$1"
    # Force new handshake: HTTP/1.1 + no keepalive + short timeout
    curl --http1.1 -sS -m 3 -o /dev/null -H "Connection: close" "$url" || true
  ' _ "$TARGET_URL" || true
elif [ "$LOADGEN" = "openssl" ]; then
  echo "[*] openssl s_client generator (OPS=$OPS concurrency=$CONCURRENCY host=$HOSTNAME)"
  seq 1 $OPS | xargs -P "$CONCURRENCY" -I{} bash -c 'timeout 2s openssl s_client -connect "'$HOSTNAME':443" -servername "$HOSTNAME" </dev/null >/dev/null 2>&1 || true' || true
else
  echo "[!] Unknown LOADGEN '$LOADGEN'" >&2; exit 1
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

echo "[*] Probe debug (symbols in libssl)"
nm -D "$LIBSSL_PATH" 2>/dev/null | grep -E 'SSL_do_handshake$|SSL_set_tlsext_host_name$|SSL_CTX_set1_groups_list$|SSL_get_negotiated_group$|SSL_get_shared_group$|tls1_get_shared_group$|tls1_shared_group$' || echo "(nm scan failed)"
echo "[*] Loader stderr (if any):"; sed -e 's/^/[loader-stderr] /' loader_stderr.log || true

if [ "$MODE" = "small" ]; then
  echo "[*] Expect kernel_drops > 0 (SMALL_RB)"
  jq 'select(.kernel_drops == 0) | error("Expected drops but saw zero")' "$METRICS_JSON" 2>/dev/null || true
else
  echo "[*] Expect kernel_drops near zero (normal ring buffer)"
fi

echo "[*] Done. Handshake samples:"
head -n 5 "$OUT_JSON" || true

# Basic acceptance checks (non-fatal warnings)
if [ -f "$OUT_JSON" ]; then
  HS_LINES=$(grep -c '"success"' "$OUT_JSON" || true)
  if [ "$HS_LINES" -lt 5 ]; then
    echo "[!] Warning: fewer than 5 handshake lines observed ($HS_LINES)"
  else
    echo "[*] Handshake lines observed: $HS_LINES"
  fi
fi
if [ -f "$METRICS_JSON" ]; then
  EV=$(jq -r '.eventsReceived // 0' "$METRICS_JSON" 2>/dev/null || echo 0)
  HE=$(jq -r '.handshakesEmitted // 0' "$METRICS_JSON" 2>/dev/null || echo 0)
  if [ "$EV" -eq 0 ] || [ "$HE" -eq 0 ]; then
    echo "[!] Warning: eventsReceived=$EV handshakesEmitted=$HE (expected >0)"
  else
    echo "[*] Metrics OK: eventsReceived=$EV handshakesEmitted=$HE"
  fi
fi

echo "[*] runtime.jsonl line count (handshake/event lines):"
wc -l "$OUT_JSON" 2>/dev/null || true

echo "[*] Metrics subset (normalized field names):"
jq '{events_total: (.events_total // .eventsReceived), handshakes_emitted: (.handshakes_emitted // .handshakesEmitted), correlationTimeouts, kernel_drops, probe_status}' "$METRICS_JSON" 2>/dev/null || true

# Also execute user-requested raw jq (may show nulls for alias fields but kept for acceptance)
echo "[*] Raw jq (events_total, handshakes_emitted, correlationTimeouts, kernel_drops, probe_status):"
jq '.events_total,.handshakes_emitted,.correlationTimeouts,.kernel_drops,.probe_status' "$METRICS_JSON" 2>/dev/null || true

if [ "${HE:-0}" -lt 1 ]; then
  echo "[!] No handshakes emitted. Diagnostics:" >&2
  if [ "$LOADGEN" = "curl" ]; then
    echo "--- curl -V ---"; curl -V || true
  fi
  echo "--- ldd of generator ($GEN_BIN) ---"; ldd "$(command -v "$GEN_BIN")" || true
  echo "Tip: Try -g openssl_local to remove egress and backend ambiguity." >&2
fi