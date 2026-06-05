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
