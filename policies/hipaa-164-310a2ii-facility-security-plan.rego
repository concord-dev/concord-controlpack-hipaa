package concord.hipaa.facility_security_plan

import rego.v1

# HIPAA §164.310(a)(2)(ii) — Facility Security Plan (Physical Safeguards).
# The written plan lives in policy, not cloud telemetry, so Concord evaluates a
# signed, version-controlled attestation. It is collected from the repository
# via github/file_glob with frontmatter parsing, so each matched file appears
# in input.facility_security_plan_attestation.docs with its frontmatter keys
# plus a "path". The plan must enumerate the physical safeguards and the
# theft/tamper protections, be reviewed within the last 12 months, and be
# cosign-verified.

max_review_age_days := 365

required_fields := {
	"physical_safeguards",
	"theft_tamper_protections",
	"last_reviewed_at",
}

deny contains msg if {
	not input.facility_security_plan_attestation
	msg := "no facility-security-plan attestation evidence collected"
}

deny contains msg if {
	input.facility_security_plan_attestation
	count(object.get(input.facility_security_plan_attestation, "docs", [])) == 0
	msg := "no facility-security-plan attestation document found at the configured repository path"
}

deny contains msg if {
	some doc in input.facility_security_plan_attestation.docs
	some field in required_fields
	not has_value(doc, field)
	msg := sprintf("facility-security-plan attestation is missing required field %q", [field])
}

deny contains msg if {
	some doc in input.facility_security_plan_attestation.docs
	doc.review_age_days > max_review_age_days
	msg := sprintf("facility-security-plan attestation last reviewed %d days ago — HIPAA §164.310(a)(2)(ii) expects at least annual review", [doc.review_age_days])
}

deny contains msg if {
	some doc in input.facility_security_plan_attestation.docs
	not doc.signature_verified == true
	msg := "facility-security-plan attestation cosign signature did not verify"
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
