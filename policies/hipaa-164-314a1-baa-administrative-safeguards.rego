package concord.hipaa.baa_administrative_safeguards

import rego.v1

# HIPAA §164.314(a)(1) — Business Associate Contracts (Organizational
# Requirements). The BAA must cover the required assurance clauses:
# safeguards, breach notification, subcontractor flowdown, and termination.
# Concord reads a cosign-verified attestation
# (input.baa_clause_attestation) recording per-clause coverage.

max_review_age_days := 365

required_clauses := {
	"safeguards_clause",
	"breach_notification_clause",
	"subcontractor_flowdown_clause",
	"termination_clause",
}

att := input.baa_clause_attestation

deny contains msg if {
	not input.baa_clause_attestation
	msg := "no BAA clause-coverage attestation collected"
}

deny contains msg if {
	some clause in required_clauses
	not att[clause]
	msg := sprintf("business associate agreement does not cover required clause %q", [clause])
}

deny contains msg if {
	unset("last_reviewed_at")
	msg := "BAA clause-coverage attestation is missing required field \"last_reviewed_at\""
}

deny contains msg if {
	att.review_age_days > max_review_age_days
	msg := sprintf("BAA clause coverage last reviewed %d days ago — review the BAA template at least annually", [att.review_age_days])
}

deny contains msg if {
	not att.signature_verified
	msg := "BAA clause-coverage attestation cosign signature did not verify"
}

unset(field) if not att[field]

unset(field) if att[field] == ""
