import json, os, argparse, datetime, base64
from nacl.signing import SigningKey
from jinja2 import Template
TEMPLATE_MD = "# Attestation\n\n**Project:** {{ project }}\n**HNDL Exposure:** {{ hndl }}%\n"
def compute_hndl(obs):
    long_life=[o for o in obs if (o.get("secrecy_lifetime_years") or 0)>=10]
    if not long_life: return 0.0
    exposed=0
    for o in long_life:
        if o.get("finding")=="rsa_keygen" and (o.get("size") or 0)<3072:
            exposed+=1
    return round(100.0*exposed/len(long_life),2)
def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("--project", required=True)
    ap.add_argument("--bom", required=True)
    ap.add_argument("--out", default="./out")
    a=ap.parse_args()
    os.makedirs(a.out, exist_ok=True)
    bom=json.load(open(a.bom,encoding="utf-8"))
    obs=bom.get("observations",[])
    hndl=compute_hndl(obs)
    payload={"summary":{"total_observations":len(obs),"hndl_exposure_pct":hndl}}
    md=Template(TEMPLATE_MD).render(project=a.project, hndl=hndl)
    json.dump(payload, open(os.path.join(a.out,"attestation.json"),"w",encoding="utf-8"), indent=2)
    open(os.path.join(a.out,"attestation.md"),"w",encoding="utf-8").write(md)
    print("Wrote attestation to", a.out)
if __name__=="__main__": main()
