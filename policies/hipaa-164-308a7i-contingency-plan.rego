package concord.hipaa.contingency_plan

import rego.v1

# HIPAA §164.308(a)(7)(i) — Contingency Plan.
# Requires a data backup plan, a disaster recovery plan, and an emergency
# mode operation plan, all periodically tested and reviewed. Concord collects
# the attestation from the repository via github/file_glob with frontmatter
# parsing, so each matched file appears in
# input.contingency_plan_attestation.docs with its frontmatter keys plus a
# "path".

max_review_age_days := 365

required_fields := {
	"data_backup_plan",
	"disaster_recovery_plan",
	"emergency_mode_plan",
	"last_tested_at",
	"last_reviewed_at",
}

deny contains msg if {
	not input.contingency_plan_attestation
	msg := "no contingency-plan attestation collected"
}

deny contains msg if {
	input.contingency_plan_attestation
	count(object.get(input.contingency_plan_attestation, "docs", [])) == 0
	msg := "no contingency-plan attestation document found at the configured repository path"
}

deny contains msg if {
	some doc in input.contingency_plan_attestation.docs
	some field in required_fields
	not has_value(doc, field)
	msg := sprintf("contingency-plan attestation is missing required field %q", [field])
}

deny contains msg if {
	some doc in input.contingency_plan_attestation.docs
	doc.review_age_days > max_review_age_days
	msg := sprintf("contingency plan last reviewed %d days ago — HIPAA requires periodic review and testing", [doc.review_age_days])
}

deny contains msg if {
	some doc in input.contingency_plan_attestation.docs
	not doc.signature_verified == true
	msg := "contingency-plan attestation cosign signature did not verify"
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
