package concord.hipaa.policies_retention

import rego.v1

# HIPAA §164.316(b)(1) — Documentation, with the six-year retention period set
# by §164.316(b)(2)(i). Concord evaluates a signed, version-controlled
# attestation that records the enforced retention period and the inventory of
# retained documents. The retention period must be at least six years, the
# inventory must be non-empty, the attestation must be reviewed within the last
# 12 months, and it must be cosign-verified. Evidence is the attestation object
# at input.retention_attestation.

min_retention_years := 6

max_review_age_days := 365

required_fields := {
	"retention_years",
	"document_inventory",
	"last_reviewed_at",
}

deny contains msg if {
	not input.retention_attestation
	msg := "no policies-and-procedures-retention attestation evidence collected"
}

deny contains msg if {
	some field in required_fields
	missing_or_empty(input.retention_attestation, field)
	msg := sprintf("policies-and-procedures-retention attestation is missing required field %q", [field])
}

deny contains msg if {
	input.retention_attestation.retention_years < min_retention_years
	msg := sprintf("HIPAA documentation retention is set to %d years — §164.316(b)(2)(i) requires at least 6 years", [input.retention_attestation.retention_years])
}

deny contains msg if {
	input.retention_attestation.review_age_days > max_review_age_days
	msg := sprintf("policies-and-procedures-retention attestation last reviewed %d days ago — expected at least annual review", [input.retention_attestation.review_age_days])
}

deny contains msg if {
	not input.retention_attestation.signature_verified
	msg := "policies-and-procedures-retention attestation cosign signature did not verify"
}

missing_or_empty(obj, field) if not obj[field]

missing_or_empty(obj, field) if obj[field] == ""

missing_or_empty(obj, field) if {
	is_array(obj[field])
	count(obj[field]) == 0
}
