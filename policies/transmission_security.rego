package concord.hipaa.transmission_security

import rego.v1

# HIPAA §164.312(e) — Transmission Security.
# Adapted from: Prowler `s3_bucket_secure_transport_policy`.

deny contains msg if {
    not input.ephi_bucket_policies
    msg := "no S3 bucket-policy evidence collected"
}

deny contains msg if {
    some bucket in input.ephi_bucket_policies.buckets
    bucket.tags.ephi == "true"
    not enforces_secure_transport(bucket)
    msg := sprintf("ePHI bucket %q does not enforce TLS via bucket policy", [bucket.name])
}

enforces_secure_transport(bucket) if {
    some statement in bucket.policy.Statement
    statement.Effect == "Deny"
    statement.Condition.Bool["aws:SecureTransport"] == "false"
    deny_covers_all_actions(statement)
}

deny_covers_all_actions(statement) if {
    statement.Action == "s3:*"
}

deny_covers_all_actions(statement) if {
    some action in statement.Action
    action == "s3:*"
}
