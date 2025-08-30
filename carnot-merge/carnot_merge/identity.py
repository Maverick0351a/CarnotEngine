import json, yaml
from typing import Dict, Any, List

def load_rules(path: str) -> Dict[str, Any]:
    return yaml.safe_load(open(path, encoding="utf-8"))

def apply_identity(bom: Dict[str, Any], acm_inventory: List[Dict[str, Any]], rules: Dict[str, Any]) -> Dict[str, Any]:
    defaults = rules.get("defaults", {})
    acm_by_domain = {}
    for o in acm_inventory:
        meta = o.get("crypto_metadata", {})
        dom = (meta.get("domain") or "").lower()
        if dom:
            acm_by_domain[dom] = o
    for obs in bom.get("observations", []):
        for k,v in defaults.items():
            if k not in obs:
                obs[k] = v
        obs.setdefault("identity_confidence", "low")
        sni = (obs.get("sni") or "").lower()
        for dom, cert in acm_by_domain.items():
            if sni.endswith(dom) and dom:
                obs["asset_id"] = cert.get("asset_id") or obs.get("asset_id")
                obs["identity_confidence"] = "high"
                break
        if obs["identity_confidence"] == "low":
            proc = (obs.get("process") or "").lower()
            if any(x in proc for x in ["nginx","haproxy","java","python","node"]):
                obs["identity_confidence"] = "medium"
    return bom
