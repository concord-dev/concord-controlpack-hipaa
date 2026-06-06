package concord.hipaa.risk_management

import rego.v1

# HIPAA §164.308(a)(1)(ii)(A,B) — Risk Analysis + Risk Management.
# Attestation pattern adapted from OCR HIPAA-audit-protocol expectations:
# the document must be current, owner-attributed, and traceable to a
# treatment plan.

max_review_age_days := 365

required_fields := {
    "approval_date",
    "approving_authority",
    "last_reviewed_at",
    "next_review_due",
    "scope",
    "treatment_summary",
}

deny contains msg if {
    not input.risk_attestation
    msg := "no risk-analysis attestation file found at policies/risk-analysis.yaml"
}

deny contains msg if {
    some field in required_fields
    not input.risk_attestation[field]
    msg := sprintf("risk-analysis attestation is missing required field %q", [field])
}

deny contains msg if {
    input.risk_attestation.review_age_days > max_review_age_days
    msg := sprintf("risk-analysis last reviewed %d days ago — HIPAA requires annual review", [input.risk_attestation.review_age_days])
}

deny contains msg if {
    not input.risk_attestation.signature_verified
    msg := "risk-analysis attestation cosign signature did not verify"
}

warn contains msg if {
    input.risk_attestation.linked_risks_count == 0
    msg := "risk-analysis document has no linked risks in the Concord risk register — add `concord risk add ... --link-attestation`"
}
