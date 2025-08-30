# Task 05 — Cloud Run Attestation API
**Prompt:**
Implement `api/main.py` (FastAPI) with POST `/attest` that accepts a BOM JSON and returns attestation JSON+MD. Add `Dockerfile` & `requirements.txt`. Provide `scripts/deploy_cloud_run.sh` with `gcloud run deploy` (min instances 0).

**Commands:**
```bash
gcloud run deploy carnot-attest --source api --region us-central1 --allow-unauthenticated --min-instances 0
```

**Acceptance:**
- Endpoint returns attestation for sample BOM. WORKLOG updated.
