import argparse, json, sys
def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("inputs", nargs="+")
    ap.add_argument("-o","--out", default="merged.json")
    a=ap.parse_args()
    observations=[]
    for p in a.inputs:
        try:
            d=json.load(open(p,encoding="utf-8"))
            observations+=d.get("observations",[])
        except Exception:
            pass
    out={"schema":"carnot.v2.1.cryptobom","run_id":"merge","summary":{"components":0,"observations":len(observations)},"observations":observations}
    json.dump(out,open(a.out,"w",encoding="utf-8"),indent=2); print("Wrote",a.out)
if __name__=="__main__": main()
