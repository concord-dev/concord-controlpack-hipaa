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

deny contains msg if {
	not input.incident_response_attestation
	msg := "no incident-response procedure attestation collected"
}

deny contains msg if {
	input.incident_response_attestation
	count(object.get(input.incident_response_attestation, "docs", [])) == 0
	msg := "no incident-response procedure document found at the configured path"
}

deny contains msg if {
	some doc in input.incident_response_attestation.docs
	some field in required_fields
	unset(doc, field)
	msg := sprintf("incident-response procedure attestation is missing required field %q", [field])
}

deny contains msg if {
	some doc in input.incident_response_attestation.docs
	doc.review_age_days > max_review_age_days
	msg := sprintf("incident-response procedure last reviewed %d days ago — HIPAA requires annual review", [doc.review_age_days])
}

deny contains msg if {
	some doc in input.incident_response_attestation.docs
	not doc.signature_verified
	msg := "incident-response procedure attestation cosign signature did not verify"
}

unset(doc, field) if not doc[field]

unset(doc, field) if doc[field] == ""
