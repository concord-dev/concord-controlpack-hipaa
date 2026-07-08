package concord.hipaa.facility_access_controls

import rego.v1

# HIPAA §164.310(a)(1) — Facility Access Controls (Physical Safeguards).
# No cloud API reports who badged into a data center, so Concord evaluates a
# signed, version-controlled attestation of the facility access program. It is
# collected from the repository via github/file_glob with frontmatter parsing,
# so each matched file appears in input.facility_access_attestation.docs with
# its frontmatter keys plus a "path". The attestation must be current
# (reviewed within the last 12 months), cosign-verified, and populated with
# the required program elements.

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
	input.facility_access_attestation
	count(object.get(input.facility_access_attestation, "docs", [])) == 0
	msg := "no facility-access-controls attestation document found at the configured repository path"
}

deny contains msg if {
	some doc in input.facility_access_attestation.docs
	some field in required_fields
	not has_value(doc, field)
	msg := sprintf("facility-access-controls attestation is missing required field %q", [field])
}

deny contains msg if {
	some doc in input.facility_access_attestation.docs
	doc.review_age_days > max_review_age_days
	msg := sprintf("facility-access-controls attestation last reviewed %d days ago — HIPAA §164.310(a)(1) expects at least annual review", [doc.review_age_days])
}

deny contains msg if {
	some doc in input.facility_access_attestation.docs
	not doc.signature_verified == true
	msg := "facility-access-controls attestation cosign signature did not verify"
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
