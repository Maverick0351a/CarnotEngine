#!/usr/bin/env python3
import sys, json
from datetime import datetime

REQUIRED_FIELDS = [
  "bom_ref","source","observation_time","process","pid","tid","success","groups_offered","group_selected","tls_version","cipher"
]

def rfc3339(ts:str)->bool:
    try:
        # Accept a basic subset; loader uses RFC3339Nano but we just ensure 'T' present
        if 'T' not in ts: return False
        datetime.fromisoformat(ts.replace('Z','+00:00'))
        return True
    except Exception:
        return False

def validate_observation(o):
    errs=[]
    for f in REQUIRED_FIELDS:
        if f not in o:
            errs.append(f"missing field {f}")
    if o.get("source") != "runtime.ebpf":
        errs.append("source != runtime.ebpf")
    if 'sni' in o and 'sni_hash' in o:
        errs.append("both sni and sni_hash present (expected only one)")
    if 'sni' not in o and 'sni_hash' not in o:
        errs.append("neither sni nor sni_hash present")
    if not isinstance(o.get('groups_offered'), list):
        errs.append("groups_offered not list")
    if not rfc3339(o.get('observation_time','')):
        errs.append("observation_time not RFC3339")
    return errs

def main(path:str):
    with open(path,'r',encoding='utf-8') as f:
        doc=json.load(f)
    obs=doc.get('observations',[])
    all_errs=[]
    for i,o in enumerate(obs):
        es=validate_observation(o)
        if es:
            all_errs.append({"index":i,"errors":es})
    if all_errs:
        print("Validation FAILED", file=sys.stderr)
        for e in all_errs:
            print(e, file=sys.stderr)
        return 1
    print(f"Validation OK ({len(obs)} observations)")
    return 0

if __name__=='__main__':
    if len(sys.argv)!=2:
        print("usage: validate_bom.py <runtime.bom.json>", file=sys.stderr)
        sys.exit(2)
    sys.exit(main(sys.argv[1]))
