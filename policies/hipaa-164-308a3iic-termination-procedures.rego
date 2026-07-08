package concord.hipaa.termination_procedures

import rego.v1

# HIPAA §164.308(a)(3)(ii)(C) — Termination Procedures.
# The signed attestation must document the access-revocation steps, a numeric
# completion SLA (hours), and the systems covered, be reviewed within the last
# year, and carry a verified signature.

max_review_age_days := 365

# SLA above which access is left active long enough to warrant attention.
warn_sla_hours := 72

required_fields := {
	"revocation_steps",
	"sla_hours",
	"systems_covered",
	"last_reviewed_at",
}

missing(obj, field) if not obj[field]

missing(obj, field) if obj[field] == ""

missing(obj, field) if obj[field] == []

missing(obj, field) if obj[field] == {}

deny contains msg if {
	not input.termination_procedure
	msg := "no termination-procedure attestation found at policies/access-termination-procedure.yaml"
}

deny contains msg if {
	input.termination_procedure
	count(object.get(input.termination_procedure, "docs", [])) == 0
	msg := "no termination-procedure attestation document found at the configured path"
}

deny contains msg if {
	some doc in input.termination_procedure.docs
	some field in required_fields
	missing(doc, field)
	msg := sprintf("termination-procedure attestation is missing required field %q", [field])
}

# sla_hours must be a number so the revocation window is actually measurable.
deny contains msg if {
	some doc in input.termination_procedure.docs
	doc.sla_hours
	not is_number(doc.sla_hours)
	msg := "termination-procedure sla_hours must be a numeric value expressed in hours"
}

deny contains msg if {
	some doc in input.termination_procedure.docs
	doc.review_age_days > max_review_age_days
	msg := sprintf("termination-procedure last reviewed %d days ago — HIPAA requires review at least every 365 days", [doc.review_age_days])
}

deny contains msg if {
	some doc in input.termination_procedure.docs
	not doc.signature_verified
	msg := "termination-procedure attestation signature did not verify"
}

warn contains msg if {
	some doc in input.termination_procedure.docs
	is_number(doc.sla_hours)
	doc.sla_hours > warn_sla_hours
	msg := sprintf("termination-procedure allows %d hours to revoke access — OCR guidance expects prompt, typically same-day, deactivation", [doc.sla_hours])
}
