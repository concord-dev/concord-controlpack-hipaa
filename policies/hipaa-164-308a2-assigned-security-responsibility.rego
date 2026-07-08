package concord.hipaa.assigned_security_responsibility

import rego.v1

# HIPAA §164.308(a)(2) — Assigned Security Responsibility.
# The signed attestation must name the accountable Security Official (name,
# title, appointment date, and responsibilities), be reviewed within the last
# year, and carry a verified signature.

max_review_age_days := 365

required_fields := {
	"official_name",
	"official_title",
	"appointed_at",
	"responsibilities",
	"last_reviewed_at",
}

# missing is true when the field is absent, an empty string, an empty array,
# or an empty object.
missing(obj, field) if not obj[field]

missing(obj, field) if obj[field] == ""

missing(obj, field) if obj[field] == []

missing(obj, field) if obj[field] == {}

deny contains msg if {
	not input.security_official
	msg := "no assigned-security-responsibility attestation found at policies/security-official.yaml"
}

deny contains msg if {
	input.security_official
	some field in required_fields
	missing(input.security_official, field)
	msg := sprintf("assigned-security-responsibility attestation is missing required field %q", [field])
}

deny contains msg if {
	input.security_official.review_age_days > max_review_age_days
	msg := sprintf("assigned-security-responsibility last reviewed %d days ago — HIPAA requires review at least every 365 days", [input.security_official.review_age_days])
}

deny contains msg if {
	input.security_official
	not input.security_official.signature_verified
	msg := "assigned-security-responsibility attestation signature did not verify"
}

warn contains msg if {
	input.security_official.review_age_days > 300
	input.security_official.review_age_days <= max_review_age_days
	msg := sprintf("assigned-security-responsibility was last reviewed %d days ago — reconfirm the appointment before it lapses at 365 days", [input.security_official.review_age_days])
}
