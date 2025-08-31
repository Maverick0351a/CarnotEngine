# Task 08 — HNDL Visualization (Sankey)
**Prompt:**
Produce a Sankey PNG from `attestation.json` using matplotlib’s `Sankey`. Add to the assessment bundle. Optionally add a small bar chart of violations by policy.

**Acceptance:**
- PNG rendered and bundled. WORKLOG updated.

**Implementation Notes:**
- `report_viz.py` now: creates `hndl_sankey.png` from `attestation.json` summary.
- If `opa_result.json` (OPA eval JSON) present, also produces `hndl_sankey_violations.png` bar chart (counts per violation id, color by severity).
- Assessment pipeline updated (`run_assessment.sh` steps 5 & 7) to emit JSON and pass it to viz script.
- Artifacts included in the zipped assessment bundle.

**Done:** Yes (Task 08 complete).
