package concord.hipaa.contingency_operations

import rego.v1

# HIPAA §164.310(a)(2)(i) — Contingency Operations (Physical Safeguards).
# Emergency facility-access procedures are documented in policy, not in cloud
# telemetry, so Concord evaluates a signed, version-controlled attestation. The
# procedure must be documented, owned, reviewed within the last 12 months, and
# actually tested within the last 12 months. Evidence is the attestation object
# at input.contingency_operations_attestation.

max_review_age_days := 365

max_test_age_days := 365

required_fields := {
	"emergency_access_procedure",
	"last_tested_at",
	"responsible_role",
	"last_reviewed_at",
}

deny contains msg if {
	not input.contingency_operations_attestation
	msg := "no contingency-operations attestation evidence collected"
}

deny contains msg if {
	some field in required_fields
	missing_or_empty(input.contingency_operations_attestation, field)
	msg := sprintf("contingency-operations attestation is missing required field %q", [field])
}

deny contains msg if {
	input.contingency_operations_attestation.review_age_days > max_review_age_days
	msg := sprintf("contingency-operations attestation last reviewed %d days ago — HIPAA §164.310(a)(2)(i) expects at least annual review", [input.contingency_operations_attestation.review_age_days])
}

deny contains msg if {
	input.contingency_operations_attestation.test_age_days > max_test_age_days
	msg := sprintf("emergency facility-access procedure last tested %d days ago — it must be exercised at least annually", [input.contingency_operations_attestation.test_age_days])
}

deny contains msg if {
	not input.contingency_operations_attestation.signature_verified
	msg := "contingency-operations attestation cosign signature did not verify"
}

missing_or_empty(obj, field) if not obj[field]

missing_or_empty(obj, field) if obj[field] == ""

missing_or_empty(obj, field) if {
	is_array(obj[field])
	count(obj[field]) == 0
}
