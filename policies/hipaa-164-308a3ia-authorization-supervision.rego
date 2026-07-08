package concord.hipaa.authorization_supervision

import rego.v1

# HIPAA §164.308(a)(3)(i) and §164.308(a)(3)(ii)(A) — Workforce Security:
# Authorization and/or Supervision.
# The signed attestation must document how access is authorized, how workforce
# members are supervised, and the role that approves access, be reviewed within
# the last year, and carry a verified signature.

max_review_age_days := 365

required_fields := {
	"authorization_process",
	"supervision_process",
	"approver_role",
	"last_reviewed_at",
}

missing(obj, field) if not obj[field]

missing(obj, field) if obj[field] == ""

missing(obj, field) if obj[field] == []

missing(obj, field) if obj[field] == {}

deny contains msg if {
	not input.authorization_supervision_policy
	msg := "no authorization-and-supervision attestation found at policies/workforce-authorization-supervision.yaml"
}

deny contains msg if {
	input.authorization_supervision_policy
	count(object.get(input.authorization_supervision_policy, "docs", [])) == 0
	msg := "no authorization-and-supervision attestation document found at the configured path"
}

deny contains msg if {
	some doc in input.authorization_supervision_policy.docs
	some field in required_fields
	missing(doc, field)
	msg := sprintf("authorization-and-supervision attestation is missing required field %q", [field])
}

deny contains msg if {
	some doc in input.authorization_supervision_policy.docs
	doc.review_age_days > max_review_age_days
	msg := sprintf("authorization-and-supervision last reviewed %d days ago — HIPAA requires review at least every 365 days", [doc.review_age_days])
}

deny contains msg if {
	some doc in input.authorization_supervision_policy.docs
	not doc.signature_verified
	msg := "authorization-and-supervision attestation signature did not verify"
}

warn contains msg if {
	some doc in input.authorization_supervision_policy.docs
	doc.review_age_days > 300
	doc.review_age_days <= max_review_age_days
	msg := sprintf("authorization-and-supervision was last reviewed %d days ago — schedule the annual review before it lapses at 365 days", [doc.review_age_days])
}
