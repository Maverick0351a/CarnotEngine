# CarnotEngine Crypto Posture Assessment

<img src="logo.png" alt="CarnotEngine" width="180" />

**Company:** DemoCorp  
**Date:** 2025-08-30  
**Prepared By:** CarnotEngine Team (contact@carnotengine.example)  
**Confidentiality:** Proprietary & Confidential – Do not distribute.

---
## Executive Summary
Provide a 2–3 paragraph high‑level summary of crypto posture, key risks, and recommended immediate actions.

- HNDL Exposure: 0%
- Total Observations: 0
- High Severity Policy Violations: 0

## Key Findings
| Category | Finding | Severity | Recommendation |
|----------|---------|----------|----------------|
| Key Management | Example: RSA 2048 key still in use | High | Rotate to >=3072 or hybrid KEM |
| TLS Configuration | Missing hybrid KEM | Medium | Enable PQC hybrid via OQS provider |
| Hash Algorithms | SHA1 usage detected | Medium | Migrate to SHA256+ |
| Cloud Keys | Untagged KMS keys | Low | Add Owner/SecrecyYears tags |

## Risk Snapshot
Embed chart (Sankey + violations bar) in final PDF if available.

## Detailed Observations
Summarize notable observations with context linking to raw artifacts (runtime, static, AWS inventory).

## Policy Violations
Outline each violation with remediation steps referencing `docs/POLICY_GUIDE.md`.

## Recommended Roadmap (Next 90 Days)
1. Immediate (Week 1–2):
2. Short Term (Month 1):
3. Mid Term (Quarter):

## Methodology
Describe data sources: static code scanning, eBPF runtime handshake correlation, AWS inventory, OPA policy evaluation, HNDL exposure calc.

## Appendix
- Attestation Summary
- Metrics (latency overhead)
- Raw JSON Artifacts (attached separately)

---
_Copyright © 2025 CarnotEngine. All rights reserved._
