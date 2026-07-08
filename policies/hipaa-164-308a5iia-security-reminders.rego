package concord.hipaa.security_reminders

import rego.v1

# HIPAA §164.308(a)(5)(ii)(A) — Security Reminders.
# Addressable specification of the Security Awareness and Training standard:
# the workforce must receive periodic security-awareness reminders. Concord
# reads a cosign-verified attestation (input.security_reminders_attestation)
# recording cadence, topics, audience, and the last distribution date.

max_review_age_days := 365

required_fields := {
	"cadence",
	"topics_covered",
	"last_distributed_at",
	"audience",
}

att := input.security_reminders_attestation

deny contains msg if {
	not input.security_reminders_attestation
	msg := "no security-awareness reminder attestation collected"
}

deny contains msg if {
	some field in required_fields
	unset(field)
	msg := sprintf("security-awareness reminder attestation is missing required field %q", [field])
}

deny contains msg if {
	count(att.topics_covered) == 0
	msg := "security-awareness reminder attestation lists no topics_covered"
}

deny contains msg if {
	att.review_age_days > max_review_age_days
	msg := sprintf("security-awareness reminders last refreshed %d days ago — HIPAA expects at least annual reminders", [att.review_age_days])
}

deny contains msg if {
	not att.signature_verified
	msg := "security-awareness reminder attestation cosign signature did not verify"
}

unset(field) if not att[field]

unset(field) if att[field] == ""
