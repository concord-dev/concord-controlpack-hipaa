package concord.hipaa.audit_controls

import rego.v1

# HIPAA §164.312(b) — Audit Controls. Combined with §164.530(j)(2)
# six-year retention for HIPAA-relevant documentation.
# Adapted from: Prowler `cloudwatch_log_group_retention_policy_specific_days_enabled`,
# `cloudwatch_log_group_kms_encryption_enabled`.

min_retention_days := 2190

deny contains msg if {
    not input.cloudwatch_logs
    msg := "no CloudWatch Logs evidence collected"
}

deny contains msg if {
    some group in input.cloudwatch_logs.log_groups
    group.holds_ephi
    not group.retention_in_days >= min_retention_days
    msg := sprintf("log group %q retention is %d days — HIPAA requires ≥ %d (6 years)", [group.name, group.retention_in_days, min_retention_days])
}

deny contains msg if {
    some group in input.cloudwatch_logs.log_groups
    group.holds_ephi
    not group.kms_key_id
    msg := sprintf("log group %q is not KMS-encrypted", [group.name])
}

warn contains msg if {
    some group in input.cloudwatch_logs.log_groups
    not group.holds_ephi
    group.retention_in_days < min_retention_days
    msg := sprintf("non-ePHI log group %q retention %d days is below HIPAA floor; mark ephi=false explicitly if intentional", [group.name, group.retention_in_days])
}
