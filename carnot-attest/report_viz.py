import json, argparse
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.sankey import Sankey
def main():
    ap=argparse.ArgumentParser(); ap.add_argument("--attestation",required=True); ap.add_argument("--out",default="hndl_sankey.png")
    a=ap.parse_args()
    data=json.load(open(a.attestation,encoding="utf-8"))
    s=data.get("summary",{}); total=s.get("total_observations",0); hndl=float(s.get("hndl_exposure_pct",0.0))
    long_life=max(1,int(total*0.3)); exposed=int(long_life*(hndl/100.0)); mitigated=long_life-exposed; other=max(0,total-long_life)
    fig=plt.figure(figsize=(8,6)); sankey=Sankey(unit=None,format='%.0f')
    sankey.add(flows=[total,-long_life,-other],labels=["All","Long-secrecy","Other"],orientations=[0,1,-1])
    sankey.add(flows=[long_life,-exposed,-mitigated],labels=["Long-secrecy","HNDL-exposed","Hybrid/PQC"],orientations=[0,1,-1],prior=0,connect=(1,0))
    sankey.finish(); plt.title("HNDL Exposure Flow"); plt.savefig(a.out,bbox_inches="tight"); print("Wrote",a.out)
if __name__=="__main__": main()
