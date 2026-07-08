package concord.hipaa.contingency_operations

import rego.v1

# HIPAA §164.310(a)(2)(i) — Contingency Operations (Physical Safeguards).
# Emergency facility-access procedures are documented in policy, not in cloud
# telemetry, so Concord evaluates a signed, version-controlled attestation. It
# is collected from the repository via github/file_glob with frontmatter
# parsing, so each matched file appears in
# input.contingency_operations_attestation.docs with its frontmatter keys plus
# a "path". The procedure must be documented, owned, reviewed within the last
# 12 months, and actually tested within the last 12 months.

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
	input.contingency_operations_attestation
	count(object.get(input.contingency_operations_attestation, "docs", [])) == 0
	msg := "no contingency-operations attestation document found at the configured repository path"
}

deny contains msg if {
	some doc in input.contingency_operations_attestation.docs
	some field in required_fields
	not has_value(doc, field)
	msg := sprintf("contingency-operations attestation is missing required field %q", [field])
}

deny contains msg if {
	some doc in input.contingency_operations_attestation.docs
	doc.review_age_days > max_review_age_days
	msg := sprintf("contingency-operations attestation last reviewed %d days ago — HIPAA §164.310(a)(2)(i) expects at least annual review", [doc.review_age_days])
}

deny contains msg if {
	some doc in input.contingency_operations_attestation.docs
	doc.test_age_days > max_test_age_days
	msg := sprintf("emergency facility-access procedure last tested %d days ago — it must be exercised at least annually", [doc.test_age_days])
}

deny contains msg if {
	some doc in input.contingency_operations_attestation.docs
	not doc.signature_verified == true
	msg := "contingency-operations attestation cosign signature did not verify"
}

has_value(doc, key) if {
	v := doc[key]
	not is_blank(v)
}

is_blank(v) if v == null

is_blank(v) if v == ""

is_blank(v) if {
	is_array(v)
	count(v) == 0
}

is_blank(v) if {
	is_object(v)
	count(v) == 0
}
