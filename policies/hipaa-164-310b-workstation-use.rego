package concord.hipaa.workstation_use

import rego.v1

# HIPAA §164.310(b) — Workstation Use (Physical Safeguards).
# The workstation use policy is a governance document, so Concord evaluates a
# signed, version-controlled attestation. It is collected from the repository
# via github/file_glob with frontmatter parsing, so each matched file appears
# in input.workstation_use_attestation.docs with its frontmatter keys plus a
# "path". It must enumerate acceptable uses, prohibited uses, and approved
# locations for ePHI access, be reviewed within the last 12 months, and be
# cosign-verified.

max_review_age_days := 365

required_fields := {
	"acceptable_use",
	"prohibited_use",
	"approved_locations",
	"last_reviewed_at",
}

deny contains msg if {
	not input.workstation_use_attestation
	msg := "no workstation-use attestation evidence collected"
}

deny contains msg if {
	input.workstation_use_attestation
	count(object.get(input.workstation_use_attestation, "docs", [])) == 0
	msg := "no workstation-use attestation document found at the configured repository path"
}

deny contains msg if {
	some doc in input.workstation_use_attestation.docs
	some field in required_fields
	not has_value(doc, field)
	msg := sprintf("workstation-use attestation is missing required field %q", [field])
}

deny contains msg if {
	some doc in input.workstation_use_attestation.docs
	doc.review_age_days > max_review_age_days
	msg := sprintf("workstation-use attestation last reviewed %d days ago — HIPAA §164.310(b) expects at least annual review", [doc.review_age_days])
}

deny contains msg if {
	some doc in input.workstation_use_attestation.docs
	not doc.signature_verified == true
	msg := "workstation-use attestation cosign signature did not verify"
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
