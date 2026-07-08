package concord.hipaa.baa_administrative_safeguards

import rego.v1

# HIPAA §164.314(a)(1) — Business Associate Contracts (Organizational
# Requirements). The BAA must cover the required assurance clauses:
# safeguards, breach notification, subcontractor flowdown, and termination.
# Concord collects the attestation from the repository via github/file_glob
# with frontmatter parsing, so each matched file appears in
# input.baa_clause_attestation.docs with its per-clause coverage keys plus a
# "path".

max_review_age_days := 365

required_clauses := {
	"safeguards_clause",
	"breach_notification_clause",
	"subcontractor_flowdown_clause",
	"termination_clause",
}

deny contains msg if {
	not input.baa_clause_attestation
	msg := "no BAA clause-coverage attestation collected"
}

deny contains msg if {
	input.baa_clause_attestation
	count(object.get(input.baa_clause_attestation, "docs", [])) == 0
	msg := "no BAA clause-coverage attestation document found at the configured repository path"
}

deny contains msg if {
	some doc in input.baa_clause_attestation.docs
	some clause in required_clauses
	not doc[clause] == true
	msg := sprintf("business associate agreement does not cover required clause %q", [clause])
}

deny contains msg if {
	some doc in input.baa_clause_attestation.docs
	not has_value(doc, "last_reviewed_at")
	msg := "BAA clause-coverage attestation is missing required field \"last_reviewed_at\""
}

deny contains msg if {
	some doc in input.baa_clause_attestation.docs
	doc.review_age_days > max_review_age_days
	msg := sprintf("BAA clause coverage last reviewed %d days ago — review the BAA template at least annually", [doc.review_age_days])
}

deny contains msg if {
	some doc in input.baa_clause_attestation.docs
	not doc.signature_verified == true
	msg := "BAA clause-coverage attestation cosign signature did not verify"
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
