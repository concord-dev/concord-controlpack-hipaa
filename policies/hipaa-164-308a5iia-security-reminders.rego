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

deny contains msg if {
	not input.security_reminders_attestation
	msg := "no security-awareness reminder attestation collected"
}

deny contains msg if {
	input.security_reminders_attestation
	count(object.get(input.security_reminders_attestation, "docs", [])) == 0
	msg := "no security-awareness reminder document found at the configured path"
}

deny contains msg if {
	some doc in input.security_reminders_attestation.docs
	some field in required_fields
	unset(doc, field)
	msg := sprintf("security-awareness reminder attestation is missing required field %q", [field])
}

deny contains msg if {
	some doc in input.security_reminders_attestation.docs
	count(doc.topics_covered) == 0
	msg := "security-awareness reminder attestation lists no topics_covered"
}

deny contains msg if {
	some doc in input.security_reminders_attestation.docs
	doc.review_age_days > max_review_age_days
	msg := sprintf("security-awareness reminders last refreshed %d days ago — HIPAA expects at least annual reminders", [doc.review_age_days])
}

deny contains msg if {
	some doc in input.security_reminders_attestation.docs
	not doc.signature_verified
	msg := "security-awareness reminder attestation cosign signature did not verify"
}

unset(doc, field) if not doc[field]

unset(doc, field) if doc[field] == ""
