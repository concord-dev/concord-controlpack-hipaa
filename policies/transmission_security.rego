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

# doc 31 §4 — no fail-open tag gates: a resource with no 'ephi' tag is neither confirmed in-scope
# nor out-of-scope, so every deny above skips it and it would pass silently.
# Warn on the unclassified resource instead of ignoring it.

warn contains msg if {
    some resource in input.ephi_bucket_policies.buckets
    not classified(resource)
    msg := sprintf("S3 bucket %q has no ephi tag, so this control's checks did not apply to it — tag ephi=true to bring it into ePHI scope or ephi=false to confirm it is out of scope", [resource.name])
}

classified(resource) if resource.tags.ephi == "true"

classified(resource) if resource.tags.ephi == "false"
