import json, argparse, os
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.sankey import Sankey

def load_violations(path:str):
    try:
        raw=json.load(open(path,encoding="utf-8"))
    except Exception:
        return []
    # Expect OPA eval -f json structure
    try:
        return raw["result"][0]["expressions"][0]["value"] or []
    except Exception:
        return []

def make_sankey(attestation_path,out_path):
    data=json.load(open(attestation_path,encoding="utf-8"))
    s=data.get("summary",{}); total=s.get("total_observations",0); hndl=float(s.get("hndl_exposure_pct",0.0))
    long_life=max(1,int(total*0.3)); exposed=int(long_life*(hndl/100.0)); mitigated=long_life-exposed; other=max(0,total-long_life)
    fig=plt.figure(figsize=(8,6))
    sankey=Sankey(unit=None,format='%.0f')
    sankey.add(flows=[total,-long_life,-other],labels=["All","Long-secrecy","Other"],orientations=[0,1,-1])
    sankey.add(flows=[long_life,-exposed,-mitigated],labels=["Long-secrecy","HNDL-exposed","Hybrid/PQC"],orientations=[0,1,-1],prior=0,connect=(1,0))
    sankey.finish(); plt.title("HNDL Exposure Flow"); plt.savefig(out_path,bbox_inches="tight"); plt.close(fig)
    print("Wrote",out_path)

def make_violation_bar(violations,out_path_base):
    if not violations:
        return
    counts={}
    severities={}
    for v in violations:
        vid=v.get("id","unknown")
        counts[vid]=counts.get(vid,0)+1
        severities[vid]=v.get("severity","-")
    vids=sorted(counts.keys(), key=lambda k: counts[k], reverse=True)
    vals=[counts[v] for v in vids]
    colors=[]
    palette={"critical":"#8b0000","high":"#d9534f","medium":"#f0ad4e","low":"#5bc0de"}
    for v in vids:
        colors.append(palette.get(severities.get(v,""),"#777777"))
    fig,ax=plt.subplots(figsize=(8,4))
    ax.bar(vids, vals, color=colors)
    ax.set_title("Policy Violations by Rule (count)")
    ax.set_ylabel("Count")
    ax.set_xlabel("Rule ID")
    ax.set_ylim(0, max(vals)+1)
    for i,v in enumerate(vals):
        ax.text(i, v+0.05, str(v), ha='center', va='bottom', fontsize=9)
    plt.tight_layout()
    out_path=f"{os.path.splitext(out_path_base)[0]}_violations.png"
    plt.savefig(out_path,bbox_inches="tight"); plt.close(fig)
    print("Wrote", out_path)

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("--attestation",required=True)
    ap.add_argument("--out",default="hndl_sankey.png")
    ap.add_argument("--violations",help="OPA eval JSON output (optional)")
    a=ap.parse_args()
    make_sankey(a.attestation,a.out)
    if a.violations:
        vs=load_violations(a.violations)
        make_violation_bar(vs,a.out)

if __name__=="__main__":
    main()
