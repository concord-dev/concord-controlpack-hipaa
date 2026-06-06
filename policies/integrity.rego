package concord.hipaa.integrity

import rego.v1

# HIPAA §164.312(c)(1,2) — Integrity + Authenticate ePHI.
# Adapted from: Prowler `s3_bucket_object_lock`,
# `s3_bucket_default_lock_enabled`, `s3_bucket_object_versioning`,
# `s3_bucket_mfa_delete`.

deny contains msg if {
    not input.ephi_buckets
    msg := "no S3 integrity evidence collected"
}

deny contains msg if {
    some bucket in input.ephi_buckets.buckets
    bucket.tags.ephi == "true"
    not bucket.versioning.enabled
    msg := sprintf("ePHI bucket %q has versioning disabled — overwrites are unrecoverable", [bucket.name])
}

deny contains msg if {
    some bucket in input.ephi_buckets.buckets
    bucket.tags.ephi == "true"
    not has_lock_or_mfa_delete(bucket)
    msg := sprintf("ePHI bucket %q has neither Object Lock nor MFA-Delete configured — integrity guarantee insufficient", [bucket.name])
}

warn contains msg if {
    some bucket in input.ephi_buckets.buckets
    bucket.tags.ephi == "true"
    bucket.object_lock.enabled
    bucket.object_lock.mode != "COMPLIANCE"
    msg := sprintf("ePHI bucket %q Object Lock is in GOVERNANCE mode — switch to COMPLIANCE for tamper-resistance against AWS root", [bucket.name])
}

has_lock_or_mfa_delete(bucket) if {
    bucket.object_lock.enabled
}

has_lock_or_mfa_delete(bucket) if {
    bucket.versioning.mfa_delete == "Enabled"
}
