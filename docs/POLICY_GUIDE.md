# Policy Guide (PQC Migration)

Friendly remediation guidance referenced by OPA policy messages.

## Rules & Remediation

1. rsa_min_key_size
   - Condition: RSA key size < 3072 bits
   - Remediation: Regenerate key at >= 3072 or migrate to hybrid/PQC KEM per roadmap.
   - Docs: https://www.nist.gov/ (reference draft FIPS 203/205 alignment)

2. legacy_hash_function
   - Condition: Use of SHA1 / MD5 for signing.
   - Remediation: Move to SHA256+ or SHA384 depending on policy; ensure libraries upgraded.

3. missing_hybrid_support
   - Condition: TLS endpoint observed without hybrid group where policy=required.
   - Remediation: Enable OQS provider or configure OpenSSL 3 with required hybrid groups.

4. untagged_cloud_key
   - Condition: KMS key missing Owner / SecrecyYears tags.
   - Remediation: Apply tags Owner=<team> SecrecyYears=<years> to key.

Severity mapping: critical > high > medium > low.
