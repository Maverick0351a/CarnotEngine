# CarnotEngine

Carnot Engine is the quantum‑safe transition control plane: it discovers where your organization uses cryptography (code, runtime, network, PKI/KMS), quantifies Harvest‑Now‑Decrypt‑Later (HNDL) risk, enforces policy‑as‑code, and produces audit‑ready attestations mapped to mandates (e.g., OMB M‑23‑02, NIST FIPS 203/204/205).

## Overview

This consolidated repository merges the Deepthink kit with runnable scaffolding (agents, CLI, attest, merge, proxy, integrations) to prototype runtime-to-BOM correlation using eBPF, plus policy and assessment tooling.

Key implemented item (current prototype focus):
- OpenSSL handshake correlation (TID-keyed) emitting aggregated JSON lines with SNI, groups, success flag, and metrics (eventsReceived, handshakesEmitted, correlationTimeouts, cacheEvictions, kernel_drops).

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
- [ ] Runtime → CryptoBOM merging
- [ ] Static scan enrichment & identity linkage
- [ ] Policy gate CI integration hardening
- [ ] Attestation signer & mandate mapping automation
- [ ] PQC interop automation & evidence capture

## Contributing
Early prototype stage; issues & PRs welcome once initial scaffolding stabilizes.

## License

Licensed under the Apache License, Version 2.0. See `LICENSE` file for details.
