# Sample Attestation (CarnotEngine)

Generated: 2025-08-30 (demo data)
Capture Window: 5 min
Asset: `host:demo`

## Metrics
| Metric | Value |
|--------|------:|
| Total TLS Handshakes | 1284 |
| Successful | 1279 |
| Failures | 5 |
| Unique SNIs | 42 |
| Hybrid-Ready % | 68% |
| RSA Legacy % | 12% |

## Policy Status: warn
Violations:
1. rsa_min_key_size (3) – Some RSA keys below 3072 bits. Migrate to >=3072 or hybrid KEM.
2. legacy_hash_function (1) – SHA-1 / MD5 usage detected. Deprecate immediately.

Remediation guidance in `docs/POLICY_GUIDE.md`.

## Risk Narrative
~12% of observed handshakes rely on legacy RSA constructs; prioritize migration of top 3 SNIs by volume.

## Sample BOM References
```
bomref:2f9c1c1a
bomref:7bd83e02
bomref:91ad01af
```

---
_This sample is synthetic. Values chosen to illustrate structure._
