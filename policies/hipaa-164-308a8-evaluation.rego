package concord.hipaa.security_evaluation

import rego.v1

# HIPAA §164.308(a)(8) — Evaluation.
# Requires a periodic technical and non-technical evaluation of safeguards,
# with the resulting findings remediated. Concord collects the attestation
# from the repository via github/file_glob with frontmatter parsing, so each
# matched file appears in input.security_evaluation_attestation.docs with its
# frontmatter keys plus a "path".

max_review_age_days := 365

required_fields := {
	"last_evaluation_at",
	"evaluator",
	"scope",
}

deny contains msg if {
	not input.security_evaluation_attestation
	msg := "no security-evaluation attestation collected"
}

deny contains msg if {
	input.security_evaluation_attestation
	count(object.get(input.security_evaluation_attestation, "docs", [])) == 0
	msg := "no security-evaluation attestation document found at the configured repository path"
}

deny contains msg if {
	some doc in input.security_evaluation_attestation.docs
	some field in required_fields
	not has_value(doc, field)
	msg := sprintf("security-evaluation attestation is missing required field %q", [field])
}

deny contains msg if {
	some doc in input.security_evaluation_attestation.docs
	not doc.findings_remediated == true
	msg := "security-evaluation attestation does not confirm findings were remediated (findings_remediated)"
}

deny contains msg if {
	some doc in input.security_evaluation_attestation.docs
	doc.review_age_days > max_review_age_days
	msg := sprintf("security evaluation last performed %d days ago — HIPAA requires periodic re-evaluation", [doc.review_age_days])
}

deny contains msg if {
	some doc in input.security_evaluation_attestation.docs
	not doc.signature_verified == true
	msg := "security-evaluation attestation cosign signature did not verify"
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
