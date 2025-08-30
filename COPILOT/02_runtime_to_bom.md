# Task 02 — Runtime → CryptoBOM v2.1 & Merge
**Prompt:**
Implement `integrations/runtime/ebpf_to_bom.py` to convert `runtime.jsonl` into `runtime.bom.json` with v2.1 observations. Then run `carnot-merge` to combine static, runtime, and AWS BOMs.

**Commands:**
```bash
python3 integrations/runtime/ebpf_to_bom.py --in artifacts/.../runtime.jsonl --out artifacts/.../runtime.bom.json --asset-id host:demo
cd carnot-merge && pip install -e .
carnot-merge artifacts/.../static.bom.json artifacts/.../runtime.bom.json artifacts/.../aws.bom.json -o artifacts/.../merged.json
```

**Acceptance:**
- `merged.json` includes runtime observations; WORKLOG updated with counts.
