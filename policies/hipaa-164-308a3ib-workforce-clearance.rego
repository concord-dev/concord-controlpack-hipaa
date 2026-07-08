package concord.hipaa.workforce_clearance

import rego.v1

# HIPAA §164.308(a)(3)(ii)(B) — Workforce Clearance Procedure.
# The signed attestation must document the clearance/screening procedure, the
# roles it applies to, and the screening provider, be reviewed within the last
# year, and carry a verified signature.

max_review_age_days := 365

required_fields := {
	"clearance_procedure",
	"roles_in_scope",
	"screening_provider",
	"last_reviewed_at",
}

missing(obj, field) if not obj[field]

missing(obj, field) if obj[field] == ""

missing(obj, field) if obj[field] == []

missing(obj, field) if obj[field] == {}

deny contains msg if {
	not input.workforce_clearance_policy
	msg := "no workforce-clearance attestation found at policies/workforce-clearance.yaml"
}

deny contains msg if {
	input.workforce_clearance_policy
	count(object.get(input.workforce_clearance_policy, "docs", [])) == 0
	msg := "no workforce-clearance attestation document found at the configured path"
}

deny contains msg if {
	some doc in input.workforce_clearance_policy.docs
	some field in required_fields
	missing(doc, field)
	msg := sprintf("workforce-clearance attestation is missing required field %q", [field])
}

deny contains msg if {
	some doc in input.workforce_clearance_policy.docs
	doc.review_age_days > max_review_age_days
	msg := sprintf("workforce-clearance last reviewed %d days ago — HIPAA requires review at least every 365 days", [doc.review_age_days])
}

deny contains msg if {
	some doc in input.workforce_clearance_policy.docs
	not doc.signature_verified
	msg := "workforce-clearance attestation signature did not verify"
}

warn contains msg if {
	some doc in input.workforce_clearance_policy.docs
	doc.review_age_days > 300
	doc.review_age_days <= max_review_age_days
	msg := sprintf("workforce-clearance was last reviewed %d days ago — schedule the annual review before it lapses at 365 days", [doc.review_age_days])
}
