package concord.hipaa.facility_security_plan

import rego.v1

# HIPAA §164.310(a)(2)(ii) — Facility Security Plan (Physical Safeguards).
# The written plan lives in policy, not cloud telemetry, so Concord evaluates a
# signed, version-controlled attestation. The plan must enumerate the physical
# safeguards and the theft/tamper protections, be reviewed within the last 12
# months, and be cosign-verified. Evidence is the attestation object at
# input.facility_security_plan_attestation.

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
	some field in required_fields
	missing_or_empty(input.facility_security_plan_attestation, field)
	msg := sprintf("facility-security-plan attestation is missing required field %q", [field])
}

deny contains msg if {
	input.facility_security_plan_attestation.review_age_days > max_review_age_days
	msg := sprintf("facility-security-plan attestation last reviewed %d days ago — HIPAA §164.310(a)(2)(ii) expects at least annual review", [input.facility_security_plan_attestation.review_age_days])
}

deny contains msg if {
	not input.facility_security_plan_attestation.signature_verified
	msg := "facility-security-plan attestation cosign signature did not verify"
}

missing_or_empty(obj, field) if not obj[field]

missing_or_empty(obj, field) if obj[field] == ""

missing_or_empty(obj, field) if {
	is_array(obj[field])
	count(obj[field]) == 0
}
