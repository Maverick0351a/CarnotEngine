from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field
from typing import Any, Dict, List, Optional
import hashlib, time, json

app = FastAPI(title="CarnotEngine Attestation API", version="0.1.0")

class BOM(BaseModel):
    schema: Optional[str] = None
    run_id: Optional[str] = None
    observations: Optional[List[Dict[str, Any]]] = Field(default_factory=list)
    summary: Optional[Dict[str, Any]] = None

class Attestation(BaseModel):
    attestation_id: str
    issued_at: str
    bom_run_id: Optional[str]
    findings: List[Dict[str, Any]]
    hndl_exposure_percent: float
    policy_status: str
    markdown: str

@app.post("/attest", response_model=Attestation)
async def attest(bom: BOM):
    # Basic validation
    obs = bom.observations or []
    findings = []
    rsa_legacy = 0
    for o in obs:
        alg = (o.get("group_selected") or o.get("algorithm") or "").upper()
        if alg.startswith("RSA"):
            rsa_legacy += 1
    total = len(obs) or 1
    hndl_percent = min(100.0, (rsa_legacy / total) * 100.0)
    # Simple policy status
    policy_status = "pass" if hndl_percent < 50 else "warn"
    findings.append({"rsa_legacy_observations": rsa_legacy})
    att_id_seed = f"{bom.run_id}-{time.time()}".encode()
    att_id = hashlib.sha256(att_id_seed).hexdigest()[:16]
    md_lines = [
        f"# CarnotEngine Attestation", 
        f"Run ID: {bom.run_id}",
        f"Observations: {len(obs)}", 
        f"RSA Legacy Count: {rsa_legacy}",
        f"HNDL Exposure % (approx): {hndl_percent:.2f}",
        f"Policy Status: {policy_status}",
    ]
    markdown = "\n".join(md_lines)
    return Attestation(attestation_id=att_id, issued_at=time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()), bom_run_id=bom.run_id, findings=findings, hndl_exposure_percent=hndl_percent, policy_status=policy_status, markdown=markdown)

@app.get("/healthz")
async def health():
    return {"status": "ok"}
