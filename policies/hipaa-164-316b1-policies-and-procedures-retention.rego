package concord.hipaa.policies_retention

import rego.v1

# HIPAA §164.316(b)(1) — Documentation, with the six-year retention period set
# by §164.316(b)(2)(i). Concord evaluates a signed, version-controlled
# attestation that records the enforced retention period and the inventory of
# retained documents. It is collected from the repository via github/file_glob
# with frontmatter parsing, so each matched file appears in
# input.retention_attestation.docs with its frontmatter keys plus a "path".
# The retention period must be at least six years, the inventory must be
# non-empty, the attestation must be reviewed within the last 12 months, and it
# must be cosign-verified.

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
	input.retention_attestation
	count(object.get(input.retention_attestation, "docs", [])) == 0
	msg := "no policies-and-procedures-retention attestation document found at the configured repository path"
}

deny contains msg if {
	some doc in input.retention_attestation.docs
	some field in required_fields
	not has_value(doc, field)
	msg := sprintf("policies-and-procedures-retention attestation is missing required field %q", [field])
}

deny contains msg if {
	some doc in input.retention_attestation.docs
	doc.retention_years < min_retention_years
	msg := sprintf("HIPAA documentation retention is set to %d years — §164.316(b)(2)(i) requires at least 6 years", [doc.retention_years])
}

deny contains msg if {
	some doc in input.retention_attestation.docs
	doc.review_age_days > max_review_age_days
	msg := sprintf("policies-and-procedures-retention attestation last reviewed %d days ago — expected at least annual review", [doc.review_age_days])
}

deny contains msg if {
	some doc in input.retention_attestation.docs
	not doc.signature_verified == true
	msg := "policies-and-procedures-retention attestation cosign signature did not verify"
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
