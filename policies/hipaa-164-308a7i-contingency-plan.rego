package concord.hipaa.contingency_plan

import rego.v1

# HIPAA §164.308(a)(7)(i) — Contingency Plan.
# Requires a data backup plan, a disaster recovery plan, and an emergency
# mode operation plan, all periodically tested and reviewed. Concord reads a
# cosign-verified attestation (input.contingency_plan_attestation).

max_review_age_days := 365

required_fields := {
	"data_backup_plan",
	"disaster_recovery_plan",
	"emergency_mode_plan",
	"last_tested_at",
	"last_reviewed_at",
}

att := input.contingency_plan_attestation

deny contains msg if {
	not input.contingency_plan_attestation
	msg := "no contingency-plan attestation collected"
}

deny contains msg if {
	some field in required_fields
	unset(field)
	msg := sprintf("contingency-plan attestation is missing required field %q", [field])
}

deny contains msg if {
	att.review_age_days > max_review_age_days
	msg := sprintf("contingency plan last reviewed %d days ago — HIPAA requires periodic review and testing", [att.review_age_days])
}

deny contains msg if {
	not att.signature_verified
	msg := "contingency-plan attestation cosign signature did not verify"
}

unset(field) if not att[field]

unset(field) if att[field] == ""
