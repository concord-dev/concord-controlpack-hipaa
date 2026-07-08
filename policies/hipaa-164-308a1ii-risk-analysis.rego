package concord.hipaa.risk_analysis

import rego.v1

# HIPAA §164.308(a)(1)(ii)(A) — Risk Analysis.
# The signed risk-analysis attestation must enumerate the assessment scope,
# the in-scope assets, the identified threats and vulnerabilities, and the
# likelihood/impact rating method, be reviewed within the last year, and
# carry a verified signature.

max_review_age_days := 365

required_fields := {
	"scope",
	"assets_in_scope",
	"threats_identified",
	"vulnerabilities_identified",
	"likelihood_impact_method",
	"last_reviewed_at",
}

# missing is true when the field is absent, an empty string, an empty array,
# or an empty object — an empty value is no better than an absent one.
missing(obj, field) if not obj[field]

missing(obj, field) if obj[field] == ""

missing(obj, field) if obj[field] == []

missing(obj, field) if obj[field] == {}

deny contains msg if {
	not input.risk_analysis
	msg := "no risk-analysis attestation found at policies/risk-analysis.yaml"
}

deny contains msg if {
	input.risk_analysis
	count(object.get(input.risk_analysis, "docs", [])) == 0
	msg := "no risk-analysis attestation document found at the configured path"
}

deny contains msg if {
	some doc in input.risk_analysis.docs
	some field in required_fields
	missing(doc, field)
	msg := sprintf("risk-analysis attestation is missing required field %q", [field])
}

deny contains msg if {
	some doc in input.risk_analysis.docs
	doc.review_age_days > max_review_age_days
	msg := sprintf("risk-analysis last reviewed %d days ago — HIPAA requires review at least every 365 days", [doc.review_age_days])
}

deny contains msg if {
	some doc in input.risk_analysis.docs
	not doc.signature_verified
	msg := "risk-analysis attestation signature did not verify"
}

warn contains msg if {
	some doc in input.risk_analysis.docs
	doc.review_age_days > 300
	doc.review_age_days <= max_review_age_days
	msg := sprintf("risk-analysis was last reviewed %d days ago — schedule the annual review before it lapses at 365 days", [doc.review_age_days])
}
