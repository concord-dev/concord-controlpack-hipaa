package concord.hipaa.security_incident_procedures

import rego.v1

# HIPAA §164.308(a)(6)(i) — Security Incident Procedures.
# A written incident-response procedure must define scope, responder roles,
# detection/reporting, and escalation, and must be reviewed and tested at
# least annually. Concord reads a cosign-verified attestation
# (input.incident_response_attestation).

max_review_age_days := 365

required_fields := {
	"scope",
	"roles_responsibilities",
	"detection_reporting",
	"escalation_path",
	"last_reviewed_at",
	"last_tested_at",
}

att := input.incident_response_attestation

deny contains msg if {
	not input.incident_response_attestation
	msg := "no incident-response procedure attestation collected"
}

deny contains msg if {
	some field in required_fields
	unset(field)
	msg := sprintf("incident-response procedure attestation is missing required field %q", [field])
}

deny contains msg if {
	att.review_age_days > max_review_age_days
	msg := sprintf("incident-response procedure last reviewed %d days ago — HIPAA requires annual review", [att.review_age_days])
}

deny contains msg if {
	not att.signature_verified
	msg := "incident-response procedure attestation cosign signature did not verify"
}

unset(field) if not att[field]

unset(field) if att[field] == ""
