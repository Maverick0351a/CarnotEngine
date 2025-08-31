#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT="$ROOT/artifacts/assessment-$(date +%Y%m%d-%H%M%S)"
mkdir -p "$OUT"

echo "[1/8] Static scan"
cd "$ROOT/carnot-cli"; pip install -q -e .
carnot "$ROOT/carnot-cli/examples" -o "$OUT/static.bom.json" --context "$ROOT/carnot-cli/examples/context.json"

echo "[2/8] AWS inventory"
if [ "${SKIP_AWS:-0}" -eq 0 ]; then
  python3 "$ROOT/integrations/aws/aws_inventory.py" > "$OUT/aws.bom.json" || echo '{"observations":[]}' > "$OUT/aws.bom.json"
else echo '{"observations":[]}' > "$OUT/aws.bom.json"; fi

echo "[3/8] Runtime collection"
if [ "${SKIP_EBPF:-0}" -eq 0 ]; then
  cd "$ROOT/carnot-agent/ebpf-core"; make
  cd go-loader && go build -o bin/carnot-ebpf-loader ./...
  sudo ./bin/carnot-ebpf-loader -obj ../openssl_handshake.bpf.o -out "$OUT/runtime.jsonl" -libssl /lib/x86_64-linux-gnu/libssl.so.3 &
  LOADER=$!; sleep 5; curl -sS https://example.org >/dev/null || true; sleep 2; sudo kill $LOADER || true
  cd "$ROOT"; python3 integrations/runtime/ebpf_to_bom.py --in "$OUT/runtime.jsonl" --out "$OUT/runtime.bom.json" --asset-id host:demo
else echo '{"schema":"carnot.v2.1.cryptobom","observations":[]}' > "$OUT/runtime.bom.json"; fi

echo "[4/8] Merge"
cd "$ROOT/carnot-merge"; pip install -q -e .
carnot-merge "$OUT/static.bom.json" "$OUT/runtime.bom.json" "$OUT/aws.bom.json" -o "$OUT/merged.json"

echo "[5/8] OPA (warn)"
if [ "${SKIP_OPA:-0}" -eq 0 ]; then \
  opa eval -i "$OUT/merged.json" -d "$ROOT/policies/pqc_migration.rego" "data.carnot.pqc_migration.violation" | tee "$OUT/opa_result.txt"; \
  opa eval -f json -i "$OUT/merged.json" -d "$ROOT/policies/pqc_migration.rego" "data.carnot.pqc_migration.violation" > "$OUT/opa_result.json"; \
fi

echo "[6/8] Attestation"
cd "$ROOT/carnot-attest"; pip install -q -e .
carnot-attest --project "Assessment" --bom "$OUT/merged.json" --out "$OUT"

echo "[7/8] Visualization"
python3 "$ROOT/carnot-attest/report_viz.py" --attestation "$OUT/attestation.json" --out "$OUT/hndl_sankey.png" --violations "$OUT/opa_result.json" || true

echo "[8/8] Bundle"
cd "$OUT"; zip -r "$(basename "$OUT").zip" . >/dev/null; echo "Bundle: $OUT/$(basename "$OUT").zip"
