package concord.hipaa.encryption

import rego.v1

# HIPAA Security Rule §164.308 / §164.312 — ePHI encryption at rest.
# Adapted from: Prowler `s3_bucket_default_encryption`,
# `rds_instance_storage_encrypted`, `ebs_default_encryption`.
# Powerpipe AWS HIPAA benchmark `hipaa_final_omnibus_security_rule_2013`.

deny contains msg if {
    not input.aws_encryption
    msg := "no encryption evidence collected"
}

deny contains msg if {
    some b in input.aws_encryption.buckets
    is_ephi(b)
    not b.encryption.configured
    msg := sprintf("ePHI bucket %q has no encryption-at-rest configured", [b.name])
}

deny contains msg if {
    some r in input.aws_encryption.rds_instances
    is_ephi(r)
    not r.encryption.configured
    msg := sprintf("ePHI RDS instance %q has no encryption-at-rest", [r.identifier])
}

deny contains msg if {
    some v in input.aws_encryption.ebs_volumes
    is_ephi(v)
    not v.encryption.configured
    msg := sprintf("ePHI EBS volume %q has no encryption-at-rest", [v.volume_id])
}

is_ephi(resource) if {
    resource.tags.ephi == "true"
}

# doc 31 §4 — no fail-open tag gates: a resource with no 'ephi' tag is neither confirmed in-scope
# nor out-of-scope, so every deny above skips it and it would pass silently.
# Warn on the unclassified resource instead of ignoring it.

warn contains msg if {
    some resource in input.aws_encryption.buckets
    not classified(resource)
    msg := sprintf("S3 bucket %q has no ephi tag, so this control's checks did not apply to it — tag ephi=true to bring it into ePHI scope or ephi=false to confirm it is out of scope", [resource.name])
}

warn contains msg if {
    some resource in input.aws_encryption.rds_instances
    not classified(resource)
    msg := sprintf("RDS instance %q has no ephi tag, so this control's checks did not apply to it — tag ephi=true to bring it into ePHI scope or ephi=false to confirm it is out of scope", [resource.identifier])
}

warn contains msg if {
    some resource in input.aws_encryption.ebs_volumes
    not classified(resource)
    msg := sprintf("EBS volume %q has no ephi tag, so this control's checks did not apply to it — tag ephi=true to bring it into ePHI scope or ephi=false to confirm it is out of scope", [resource.volume_id])
}

classified(resource) if resource.tags.ephi == "true"

classified(resource) if resource.tags.ephi == "false"
