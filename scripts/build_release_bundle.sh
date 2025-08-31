#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DIST="$ROOT/dist"
ART_DIR="$ROOT/artifacts"
mkdir -p "$DIST"

echo "[1/3] Collect assessment artifacts"
if compgen -G "$ART_DIR/assessment-*" > /dev/null; then
  TMP_LIST=$(mktemp)
  for d in "$ART_DIR"/assessment-*; do
    [ -d "$d" ] || continue
    name=$(basename "$d")
    zip_name="${name}.zip"
    echo "  Zipping $d -> $DIST/$zip_name"
    (cd "$d"; zip -qr "$DIST/$zip_name" .)
  done
else
  echo "No assessment-*/ directories found under artifacts/. Run scripts/run_assessment.sh first." >&2
fi

echo "[2/3] Include metadata manifest"
MANIFEST="$DIST/assessments_manifest.json"
{
  echo '['
  first=1
  for z in "$DIST"/assessment-*.zip; do
    [ -f "$z" ] || continue
    sz=$(stat -c%s "$z" 2>/dev/null || wc -c < "$z")
    ts=$(date -u +%Y-%m-%dT%H:%M:%SZ)
    if [ $first -eq 0 ]; then echo ','; fi
    first=0
    echo " {\"file\":\"$(basename "$z")\",\"size_bytes\":$sz,\"timestamp\":\"$ts\"}"
  done
  echo ']'
} > "$MANIFEST"

echo "[3/3] Done. Files in $DIST:"
ls -1 "$DIST"
