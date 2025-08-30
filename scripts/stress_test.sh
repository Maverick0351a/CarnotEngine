#!/usr/bin/env bash
set -euo pipefail
TARGET="${1:-https://example.org}"
DURATION="${2:-60}"
OUT="${3:-metrics.json}"
echo "Stress test ${TARGET} for ${DURATION}s"
START=$(date -Iseconds)

# Prefer hey/wrk2 if installed
if command -v hey >/dev/null 2>&1; then
  hey -z ${DURATION}s -disable-keepalive ${TARGET} > hey.out || true
elif command -v wrk >/dev/null 2>&1; then
  wrk -d${DURATION}s -c50 -t2 ${TARGET} > wrk.out || true
else
  END=$((SECONDS + DURATION))
  while [ $SECONDS -lt $END ]; do curl -sS --max-time 5 -o /dev/null "$TARGET" || true; done
fi

ENDT=$(date -Iseconds)
cat > "$OUT" <<EOF
{
  "target":"${TARGET}",
  "start":"${START}",
  "end":"${ENDT}",
  "notes":"If hey/wrk2 present, parse their outputs for latency histograms."
}
EOF
echo "Wrote $OUT"
