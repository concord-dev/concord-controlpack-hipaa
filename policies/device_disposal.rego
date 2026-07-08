package concord.hipaa.device_disposal

import rego.v1

# HIPAA §164.310(d)(2) — Disposal + Media Re-use.

max_review_age_days := 365

required_fields := {
    "approval_date",
    "last_reviewed_at",
    "sanitisation_method",
    "disposal_log",
}

approved_sanitisation_methods := {
    "nist_800_88_clear",
    "nist_800_88_purge",
    "nist_800_88_destroy",
    "physical_shred",
    "degauss",
}

deny contains msg if {
    not input.disposal_attestation
    msg := "no device-disposal attestation file found at policies/device-disposal.yaml"
}

deny contains msg if {
    input.disposal_attestation
    count(object.get(input.disposal_attestation, "docs", [])) == 0
    msg := "no device-disposal attestation document found at the configured path"
}

deny contains msg if {
    some doc in input.disposal_attestation.docs
    some field in required_fields
    not doc[field]
    msg := sprintf("device-disposal attestation is missing required field %q", [field])
}

deny contains msg if {
    some doc in input.disposal_attestation.docs
    not doc.sanitisation_method in approved_sanitisation_methods
    msg := sprintf("sanitisation method %q is not a NIST 800-88 approved technique", [doc.sanitisation_method])
}

deny contains msg if {
    some doc in input.disposal_attestation.docs
    doc.review_age_days > max_review_age_days
    msg := sprintf("device-disposal policy last reviewed %d days ago — annual review required", [doc.review_age_days])
}

deny contains msg if {
    some doc in input.disposal_attestation.docs
    not doc.signature_verified
    msg := "device-disposal attestation cosign signature did not verify"
}

warn contains msg if {
    some doc in input.disposal_attestation.docs
    count(doc.disposal_log) == 0
    msg := "device-disposal log is empty — policy without execution evidence will draw an audit finding"
}
