package carnot.pqc_migration

# Updated to OPA 1.0+ syntax (requires 'contains' for partial set rules and 'if' before bodies).
# Input shape expectation (simplified):
# {
#   "boms": [ {"observations": [...]}, ...],
#   "cloud": [...],
#   "enforce": false
# }

default enforce := false
enforce := input.enforce

# Helper to iterate observations safely even if arrays absent
obs := o if {
	some i
	input.boms[i]
	some j
	o := input.boms[i].observations[j]
}

cloud_key := k if {
	some i
	input.cloud[i]
	k := input.cloud[i]
}

violation contains v if {
	obs.group_selected == "RSA"  # placeholder heuristic
	key_size := to_number(obs.key_size)
	key_size < 3072
	v := {
		"id": "rsa_min_key_size",
		"severity": "high",
		"message": sprintf("RSA key size %d < 3072; rotate to >=3072 or adopt hybrid KEM (see docs/POLICY_GUIDE.md#rsa_min_key_size)", [key_size])
	}
}

violation contains v if {
	lower(obs.hash_alg) == "sha1"
	v := {
		"id": "legacy_hash_function",
		"severity": "medium",
		"message": "Legacy hash SHA1 detected; upgrade to SHA256+ (see docs/POLICY_GUIDE.md#legacy_hash_function)"
	}
}

violation contains v if {
	obs.protocol == "TLS"
	not obs.hybrid_enabled
	v := {
		"id": "missing_hybrid_support",
		"severity": "medium",
		"message": "TLS endpoint missing hybrid KEM; enable OQS provider (see docs/POLICY_GUIDE.md#missing_hybrid_support)"
	}
}

violation contains v if {
	cloud_key.tags_present == false
	v := {
		"id": "untagged_cloud_key",
		"severity": "low",
		"message": sprintf("Cloud key %s missing tags Owner/SecrecyYears; tag for risk scoring (see docs/POLICY_GUIDE.md#untagged_cloud_key)", [cloud_key.asset_id])
	}
}

violation_summary := {"count": count(violation), "by_severity": agg} if {
	sev := [v.severity | v := violation[_]]
	agg := {"critical": count([x | x := sev[_]; x == "critical"]),
					"high": count([x | x := sev[_]; x == "high"]),
					"medium": count([x | x := sev[_]; x == "medium"]),
					"low": count([x | x := sev[_]; x == "low"])}
}

deny contains msg if {
	enforce
	violation_summary.count > 0
	msg := sprintf("Policy enforcement blocked merge: %d violations (see opa_result.json)", [violation_summary.count])
}
