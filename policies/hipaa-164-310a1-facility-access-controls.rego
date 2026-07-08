package concord.hipaa.facility_access_controls

import rego.v1

# HIPAA §164.310(a)(1) — Facility Access Controls (Physical Safeguards).
# No cloud API reports who badged into a data center, so Concord evaluates a
# signed, version-controlled attestation of the facility access program. The
# attestation must be current (reviewed within the last 12 months),
# cosign-verified, and populated with the required program elements. Evidence
# is the attestation object at input.facility_access_attestation.

max_review_age_days := 365

required_fields := {
	"access_control_measures",
	"authorized_roles",
	"visitor_policy",
	"last_reviewed_at",
}

deny contains msg if {
	not input.facility_access_attestation
	msg := "no facility-access-controls attestation evidence collected"
}

deny contains msg if {
	some field in required_fields
	missing_or_empty(input.facility_access_attestation, field)
	msg := sprintf("facility-access-controls attestation is missing required field %q", [field])
}

deny contains msg if {
	input.facility_access_attestation.review_age_days > max_review_age_days
	msg := sprintf("facility-access-controls attestation last reviewed %d days ago — HIPAA §164.310(a)(1) expects at least annual review", [input.facility_access_attestation.review_age_days])
}

deny contains msg if {
	not input.facility_access_attestation.signature_verified
	msg := "facility-access-controls attestation cosign signature did not verify"
}

missing_or_empty(obj, field) if not obj[field]

missing_or_empty(obj, field) if obj[field] == ""

missing_or_empty(obj, field) if {
	is_array(obj[field])
	count(obj[field]) == 0
}
