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
    some field in required_fields
    not input.disposal_attestation[field]
    msg := sprintf("device-disposal attestation is missing required field %q", [field])
}

deny contains msg if {
    not input.disposal_attestation.sanitisation_method in approved_sanitisation_methods
    msg := sprintf("sanitisation method %q is not a NIST 800-88 approved technique", [input.disposal_attestation.sanitisation_method])
}

deny contains msg if {
    input.disposal_attestation.review_age_days > max_review_age_days
    msg := sprintf("device-disposal policy last reviewed %d days ago — annual review required", [input.disposal_attestation.review_age_days])
}

deny contains msg if {
    not input.disposal_attestation.signature_verified
    msg := "device-disposal attestation cosign signature did not verify"
}

warn contains msg if {
    count(input.disposal_attestation.disposal_log) == 0
    msg := "device-disposal log is empty — policy without execution evidence will draw an audit finding"
}
