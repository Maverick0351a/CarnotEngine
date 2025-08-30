import json, argparse, time, hashlib

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--in", dest="in_path", required=True, help="Input JSONL from eBPF loader (handshake observations)")
    ap.add_argument("--out", dest="out_path", default="runtime.bom.json", help="Output CryptoBOM v2.1 JSON")
    ap.add_argument("--asset-id", dest="asset_id", default=None)
    ap.add_argument("--owner", default=None)
    ap.add_argument("--data-class", dest="data_class", default=None)
    ap.add_argument("--secrecy", dest="secrecy", type=float, default=None)
    ap.add_argument("--exposure", default=None)
    args = ap.parse_args()

    observations = []
    sni_counts = {}
    with open(args.in_path, "r", encoding="utf-8") as f:
        for line in f:
            if not line.strip():
                continue
            try:
                ev = json.loads(line)
            except json.JSONDecodeError:
                continue
            # Accept any line shaped like our runtime handshake (pid/tid/proc keys)
            if not ("pid" in ev and "tid" in ev and "proc" in ev):
                continue
            sni = ev.get("sni") or None
            if sni:
                sni_counts[sni] = sni_counts.get(sni,0)+1
            negotiated = ev.get("negotiated_group") or ev.get("group_selected")
            obs_id_seed = f"{args.asset_id}-{sni}-{ev.get('proc')}-{negotiated}".encode()
            bom_ref = "rtobs:" + hashlib.sha1(obs_id_seed).hexdigest()[:16]
            obs = {
                "bom_ref": bom_ref,
                "source": "runtime.ebpf",
                "asset_id": args.asset_id,
                "owner": args.owner,
                "data_class": args.data_class,
                "secrecy_lifetime_years": args.secrecy,
                "exposure": args.exposure,
                "time": ev.get("time"),
                "pid": ev.get("pid"),
                "process": ev.get("proc"),
                "sni": sni,
                "groups_offered": ev.get("groups_offered") or [],
                "group_selected": negotiated,
                "success": ev.get("success"),
                "confidence": 0.8
            }
            observations.append(obs)

    out = {
        "schema": "carnot.v2.1.cryptobom",
        "run_id": f"runtime-ebpf-{int(time.time())}",
        "summary": {"components": 0, "observations": len(observations), "unique_snis": len(sni_counts)},
        "observations": observations,
        "metrics": {"sni_counts": sni_counts}
    }
    with open(args.out_path, "w", encoding="utf-8") as w:
        json.dump(out, w, indent=2)
    print(f"Wrote {args.out_path} with {len(observations)} observations.")

if __name__ == "__main__":
    main()
