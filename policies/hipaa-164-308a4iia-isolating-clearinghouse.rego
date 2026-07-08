package concord.hipaa.isolating_clearinghouse

import rego.v1

# HIPAA §164.308(a)(4)(ii)(A) — Isolating Health Care Clearinghouse Functions.
# If the organization performs clearinghouse functions within a larger
# organization, the attestation must declare applicability=true and list the
# controls that isolate the clearinghouse ePHI. If it performs none, it must
# still declare applicability=false with a written justification. Either way
# the document must be current and carry a verified signature.

max_review_age_days := 365

missing(obj, field) if not obj[field]

missing(obj, field) if obj[field] == ""

missing(obj, field) if obj[field] == []

missing(obj, field) if obj[field] == {}

# applicability must be an explicit boolean — a blank field is not a decision.
applicability_declared(doc) if is_boolean(doc.applicability)

deny contains msg if {
	not input.clearinghouse_isolation
	msg := "no clearinghouse-isolation attestation found at policies/clearinghouse-isolation.yaml"
}

deny contains msg if {
	input.clearinghouse_isolation
	count(object.get(input.clearinghouse_isolation, "docs", [])) == 0
	msg := "no clearinghouse-isolation attestation document found at the configured path"
}

deny contains msg if {
	some doc in input.clearinghouse_isolation.docs
	not applicability_declared(doc)
	msg := `clearinghouse-isolation attestation is missing required field "applicability" (must be true or false)`
}

deny contains msg if {
	some doc in input.clearinghouse_isolation.docs
	missing(doc, "last_reviewed_at")
	msg := `clearinghouse-isolation attestation is missing required field "last_reviewed_at"`
}

# When clearinghouse functions ARE performed, isolation controls are required.
deny contains msg if {
	some doc in input.clearinghouse_isolation.docs
	doc.applicability == true
	missing(doc, "isolation_controls")
	msg := "clearinghouse-isolation attests applicability=true but lists no isolation_controls"
}

# When they are NOT performed, a written justification is required.
deny contains msg if {
	some doc in input.clearinghouse_isolation.docs
	doc.applicability == false
	missing(doc, "justification")
	msg := "clearinghouse-isolation attests applicability=false but provides no justification"
}

deny contains msg if {
	some doc in input.clearinghouse_isolation.docs
	doc.review_age_days > max_review_age_days
	msg := sprintf("clearinghouse-isolation last reviewed %d days ago — HIPAA requires review at least every 365 days", [doc.review_age_days])
}

deny contains msg if {
	some doc in input.clearinghouse_isolation.docs
	not doc.signature_verified
	msg := "clearinghouse-isolation attestation signature did not verify"
}

warn contains msg if {
	some doc in input.clearinghouse_isolation.docs
	doc.review_age_days > 300
	doc.review_age_days <= max_review_age_days
	msg := sprintf("clearinghouse-isolation was last reviewed %d days ago — schedule the annual review before it lapses at 365 days", [doc.review_age_days])
}
