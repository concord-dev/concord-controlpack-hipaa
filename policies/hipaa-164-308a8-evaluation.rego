package concord.hipaa.security_evaluation

import rego.v1

# HIPAA §164.308(a)(8) — Evaluation.
# Requires a periodic technical and non-technical evaluation of safeguards,
# with the resulting findings remediated. Concord reads a cosign-verified
# attestation (input.security_evaluation_attestation).

max_review_age_days := 365

required_fields := {
	"last_evaluation_at",
	"evaluator",
	"scope",
}

att := input.security_evaluation_attestation

deny contains msg if {
	not input.security_evaluation_attestation
	msg := "no security-evaluation attestation collected"
}

deny contains msg if {
	some field in required_fields
	unset(field)
	msg := sprintf("security-evaluation attestation is missing required field %q", [field])
}

deny contains msg if {
	not att.findings_remediated
	msg := "security-evaluation attestation does not confirm findings were remediated (findings_remediated)"
}

deny contains msg if {
	att.review_age_days > max_review_age_days
	msg := sprintf("security evaluation last performed %d days ago — HIPAA requires periodic re-evaluation", [att.review_age_days])
}

deny contains msg if {
	not att.signature_verified
	msg := "security-evaluation attestation cosign signature did not verify"
}

unset(field) if not att[field]

unset(field) if att[field] == ""
