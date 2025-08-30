import argparse, json, os, re, ast
EXCLUDE = {".git","node_modules","venv",".venv","build","dist","__pycache__"}
def scan(root):
    obs = []
    for dp, dn, files in os.walk(root):
        dn[:] = [d for d in dn if d not in EXCLUDE]
        for f in files:
            p = os.path.join(dp,f)
            if f.endswith(".py"):
                try:
                    src = open(p,encoding="utf-8",errors="ignore").read()
                    if "rsa.generate_private_key" in src:
                        obs.append({"source":"static.sast","finding":"rsa_keygen","path":os.path.relpath(p,root),"line":1})
                except Exception: pass
    return {"schema":"carnot.v2.1.cryptobom","run_id":"static","summary":{"components":0,"observations":len(obs)},"observations":obs}
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("path")
    ap.add_argument("-o","--out",default="cryptobom.json")
    ap.add_argument("--context",default=None)
    a=ap.parse_args()
    bom = scan(a.path)
    if a.context and os.path.exists(a.context):
        ctx=json.load(open(a.context)); 
        for o in bom["observations"]:
            o.update({k:ctx.get(k) for k in ["asset_id","owner","data_class","secrecy_lifetime_years","exposure"]})
    json.dump(bom,open(a.out,"w",encoding="utf-8"),indent=2); print("Wrote",a.out)
if __name__=="__main__": main()
