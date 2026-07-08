package concord.hipaa.workstation_use

import rego.v1

# HIPAA §164.310(b) — Workstation Use (Physical Safeguards).
# The workstation use policy is a governance document, so Concord evaluates a
# signed, version-controlled attestation. It must enumerate acceptable uses,
# prohibited uses, and approved locations for ePHI access, be reviewed within
# the last 12 months, and be cosign-verified. Evidence is the attestation
# object at input.workstation_use_attestation.

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
	some field in required_fields
	missing_or_empty(input.workstation_use_attestation, field)
	msg := sprintf("workstation-use attestation is missing required field %q", [field])
}

deny contains msg if {
	input.workstation_use_attestation.review_age_days > max_review_age_days
	msg := sprintf("workstation-use attestation last reviewed %d days ago — HIPAA §164.310(b) expects at least annual review", [input.workstation_use_attestation.review_age_days])
}

deny contains msg if {
	not input.workstation_use_attestation.signature_verified
	msg := "workstation-use attestation cosign signature did not verify"
}

missing_or_empty(obj, field) if not obj[field]

missing_or_empty(obj, field) if obj[field] == ""

missing_or_empty(obj, field) if {
	is_array(obj[field])
	count(obj[field]) == 0
}
