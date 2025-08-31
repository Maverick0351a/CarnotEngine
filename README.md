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

## Modules (What We’re Building)

### CryptoBOM v2.1
Unified, machine‑readable Cryptographic Bill of Materials merging multiple telemetry streams into one system of record.

Sources:
- Static scanner (SAST)
- Runtime agents: Linux eBPF, Windows ETW, Java JFR
- Network: Zeek / tshark captures, interop PCAPs
- Cloud PKI/KMS (AWS first: KMS, ACM)

Identity merge rules link SNI ⇄ ACM certs and apply tag→context enrichment (owner, secrecy lifetime, exposure tier).

### Risk & HNDL Quantification
- Risk engine factors: algorithm strength, exposure surface, secrecy lifetime.
- HNDL Exposure %: percent of long‑life data still classical‑only.
- Optional visuals (Sankey) to make risk tangible for executives.

### Policy‑as‑Code & Shift‑Left
- OPA/Rego policies (hybrid TLS deadlines, RSA key minimums, crypto‑agility patterns).
- GitHub Actions gate (warn → enforce) with remediation messages.
- Crypto‑Agility SDK abstraction (e.g. `Carnot.Sign(policy="PQC-Hybrid")`).

### PQC Interop Lab (`carnot-interop-lab`)
- OpenSSL 3 + OQS provider to demonstrate hybrid / PQC negotiation (with PCAP evidence).
- Not a FIPS module—positioned as an interop & readiness testbed.

### Attestation & Evidence
- (Planned signed) attestation bundles (JSON + Markdown) mapped to mandates (OMB M‑23‑02, NIST FIPS 203/204/205).
- Embedded: HNDL %, policy pass/fail, evidence pointers (JSONL runtime, PCAPs, metrics, CryptoBOM extract).

### Developer & Ops Ergonomics
- Copilot Ops Pack: paste‑ready task files + enforced `WORKLOG.md` updates.
- VS Code task: end‑to‑end assessment (scan → runtime → merge → attest → visualize).

## Problems We Solve (and For Whom)

### 1. Compliance & Audit (CISO / GRC)
- OMB M‑23‑02 inventory & plan (CryptoBOM v2.1) + prioritized migration roadmap.
- NIST FIPS 203/204/205 mapping evidence (ML‑KEM / ML‑DSA / SLH‑DSA readiness).
- Audit‑ready attestation artifacts.

### 2. HNDL Risk Reduction (CISO / Data Protection)
- Quantifies long‑life data exposure (HNDL %).
- Turns quantum threat into concrete percentages & timelines.

### 3. Full‑Spectrum Discovery (Platform / SRE / AppSec)
- Code: algorithm usage, weak sizes, DIY crypto.
- Runtime: ground‑truth via eBPF / ETW / JFR (resilient to ECH & QUIC opacity).
- Network: Zeek enrichment + interop PCAP negotiated hybrid/PQC sessions.
- PKI/KMS: AWS inventory enriched with tag→context.

### 4. Migration Guidance & Enforcement (DevSecOps)
- Policy‑as‑Code with actionable remediation.
- Crypto‑Agility SDK abstraction.
- Interop lab validation pre‑production.

### 5. Procurement & Supply‑Chain Assurance (Vendor Risk)
- Standardized CryptoBOM + attestation = shared posture language.
- (Future) CryptoBOM Exchange for vendor comparison.

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
	- Optional privacy hashing: `--hash-sni sha256|hmac` (with `--hash-key` for HMAC) removes plaintext SNI replacing with `sni_hash` (hex SHA256 / HMAC-SHA256). Future: IP hashing via `--hash-ip` (flag present; emission TBD).
- Runtime → CryptoBOM conversion utility (`integrations/runtime/ebpf_to_bom.py`).
- AWS KMS / ACM inventory with tag enrichment & tests.
- OPA policy gate (warn mode) + remediation guide.
- Attestation API scaffold (FastAPI) & published sample artifacts.

See `WORKLOG.md` and `COPILOT/` tasks for incremental progress and guidance.



## Short About (Copy/Paste for Repo Sidebar)
CarnotEngine: runtime cryptography visibility, PQC readiness scoring, policy‑as‑code, and signed attestation (in progress) — bridging eBPF TLS telemetry, cloud PKI/KMS, and OPA policies into a unified CryptoBOM.

Alternate minimal tagline:
Runtime crypto inventory → PQC readiness → Attestation.

## Contributing
Early prototype stage; issues & PRs welcome once initial scaffolding stabilizes.

## License

Licensed under the Apache License, Version 2.0. See `LICENSE` file for details.
