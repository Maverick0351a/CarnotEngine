# CarnotEngine

[![Stress & Overhead (Linux)](https://github.com/Maverick0351a/CarnotEngine/actions/workflows/stress.yml/badge.svg)](https://github.com/Maverick0351a/CarnotEngine/actions/workflows/stress.yml)
[![eBPF Smoke Test](https://github.com/Maverick0351a/CarnotEngine/workflows/eBPF%20Smoke%20Test/badge.svg)](https://github.com/Maverick0351a/CarnotEngine/actions/workflows/ebpf-smoke.yml)

> Runtime cryptographic inventory → Policy → Attestation → Continuous PQC migration readiness.

Carnot Engine is the quantum‑safe transition control plane: it discovers where your organization uses cryptography (code, runtime, network, PKI/KMS), quantifies Harvest‑Now‑Decrypt‑Later (HNDL) risk, enforces policy‑as‑code, and produces audit‑ready attestations mapped to mandates (e.g., OMB M‑23‑02, NIST FIPS 203/204/205).

**Live Site:** https://carnotengine.pages.dev  
**Samples:** [Sample Attestation (MD)](docs/samples/sample_attestation.md) · [Attestation JSON](docs/samples/sample_attestation.json) · [PCAP Walkthrough](docs/samples/pcap_walkthrough.html)

Latest Smoke (normal vs small ringbuf) snapshot (from metrics.json):
```
eventsReceived: (see workflow artifact)
handshakesEmitted: (see workflow artifact)
kernel_drops(normal): 0
kernel_drops(small): (warning if 0; optional >0)
bpftool_version: (captured in metrics)
build_git_sha: (captured in metrics)
```

### Quick Pipeline (4 Stages)
1. **Runtime Capture** – eBPF/ETW/JFR observe live TLS handshakes (SNI, groups, negotiated group, outcomes) with low overhead.
2. **CryptoBOM** – Normalize & hash observations (bom_ref) for diffing, merging cloud PKI/KMS + static code findings.
3. **Policy Gate** – OPA/Rego evaluates PQC readiness & crypto hygiene (RSA size, legacy hashes, hybrid support, tagging).
4. **Attestation** – Machine (JSON) + human (Markdown) bundle (soon: signed) exposing HNDL % & mandate mapping.

---

## Overview

This consolidated repository merges the Deepthink kit with runnable scaffolding (agents, CLI, attest, merge, proxy, integrations) to prototype runtime-to-BOM correlation using eBPF, plus policy and assessment tooling.

Current prototype focus:
- OpenSSL handshake correlation (TID-keyed) emitting aggregated JSON lines with SNI, offered groups, negotiated group & metrics (eventsReceived, handshakesEmitted, correlationTimeouts, cacheEvictions, kernel_drops).
- Runtime → CryptoBOM conversion utility (`integrations/runtime/ebpf_to_bom.py`).
- AWS KMS / ACM inventory with tag enrichment & tests.
- OPA policy gate (warn mode) + remediation guide.
- Attestation API scaffold (FastAPI) & published sample artifacts.

See `WORKLOG.md` and `COPILOT/` tasks for incremental progress and guidance.

## Modules (What We’re Building)

### CryptoBOM v2.1
Unified, machine‑readable Cryptographic Bill of Materials (CryptoBOM) merging multiple telemetry streams into one system of record.

Sources:
- Static scanner (SAST)
- Runtime agents: Linux eBPF, Windows ETW, Java JFR
- Network: Zeek / tshark captures, interop PCAPs
- Cloud PKI/KMS (AWS first: KMS, ACM)

Identity merge rules link SNI ⇄ ACM certs and apply tag→context enrichment (owner, secrecy lifetime, exposure tier).

### Risk & HNDL Quantification
- Risk engine factors: algorithm strength, exposure surface, secrecy lifetime.
- HNDL Exposure %: what percent of long‑life data remains classical‑only.
- Optional visual (Sankey) to make risk tangible for executives.

### Policy‑as‑Code & Shift‑Left
- OPA/Rego policies (hybrid TLS deadlines, RSA key minimums, enforced crypto‑agility patterns).
- GitHub Actions gate (warn → enforce) with prescriptive remediation messages.
- Crypto‑Agility SDK abstraction (e.g. `Carnot.Sign(policy="PQC-Hybrid")`).

### PQC Interop Lab (`carnot-interop-lab`)
- OpenSSL 3 + OQS provider to demonstrate hybrid / PQC negotiation (with PCAP evidence).
- Not a FIPS module—positioned as an interop & readiness testbed.

### Attestation & Evidence
- Signed attestation bundles (JSON + Markdown) mapped to mandates (OMB M‑23‑02, NIST FIPS 203/204/205 references).
- Embedded: HNDL %, policy pass/fail, evidence pointers (JSONL runtime, PCAPs, metrics, CryptoBOM extract).

### Developer & Ops Ergonomics
- Copilot Ops Pack: paste‑ready task files + enforced `WORKLOG.md` updates.
- VS Code task: end‑to‑end assessment (scan → runtime → merge → attest → visualize).

## Problems We Solve (and For Whom)

### 1. Compliance & Audit (CISO / GRC)
- OMB M‑23‑02 inventory & plan via CryptoBOM v2.1 and prioritized migration roadmap.
- NIST FIPS 203/204/205 mapping: evidence of ML‑KEM / ML‑DSA / SLH‑DSA adoption where applicable.
- Signed, audit‑ready attestation artifacts suited for regulator and board reporting.

### 2. HNDL Risk Reduction (CISO / Data Protection)
- Quantifies how much long‑life data is exposed to future decryption (HNDL %).
- Converts abstract “quantum threat” into concrete percentages, timelines, and proof.

### 3. Full‑Spectrum Discovery (Platform / SRE / AppSec)
- Code: locate hard‑coded algorithms, weak sizes, DIY crypto.
- Runtime: ground‑truth via eBPF / ETW / JFR (resilient to ECH & QUIC middlebox blindness).
- Network: Zeek enrichment & interop PCAPs for negotiated hybrid/PQC sessions.
- PKI/KMS: AWS inventory (KMS keys, ACM certs) enriched with tag‑to‑context.

### 4. Migration Guidance & Enforcement (DevSecOps)
- Policy‑as‑Code: build gating with actionable remediation not just failure.
- Crypto‑Agility SDK: abstract away algorithm churn.
- Interop lab validates PQC/hybrid handshakes pre‑production.

### 5. Procurement & Supply‑Chain Assurance (Vendor Risk)
- Standardized CryptoBOM + attestations = shared language with vendors.
- (Future) CryptoBOM Exchange: compare vendor PQC posture and progress.

## Roadmap Snapshot (High Level)
- [x] Basic eBPF handshake correlation & metrics
- [x] Runtime → CryptoBOM conversion (initial)
- [x] AWS PKI/KMS inventory + tests
- [x] Policy gate (warn) with remediation outputs
- [x] Site + sample attestation & PCAP walkthrough
- [ ] Static scan enrichment & identity linkage
- [ ] Full merged BOM & identity correlation
- [ ] Attestation signing (Sigstore / keyless) & mandate mapping automation
- [ ] PQC interop automation & evidence capture
- [ ] Hybrid group mapping completeness & drift diff UI

## Short About (Copy/Paste for Repo Sidebar)
CarnotEngine: runtime cryptography visibility, PQC readiness scoring, policy‑as‑code, and signed attestation (in progress) — bridging eBPF TLS telemetry, cloud PKI/KMS, and OPA policies into a unified CryptoBOM.

Alternate minimal tagline:
Runtime crypto inventory → PQC readiness → Attestation.

## Contributing
Early prototype stage; issues & PRs welcome once initial scaffolding stabilizes.

## License

Licensed under the Apache License, Version 2.0. See `LICENSE` file for details.
