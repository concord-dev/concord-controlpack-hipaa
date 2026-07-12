package concord.hipaa.data_backup

import rego.v1

# HIPAA §164.308(a)(7)(ii)(A) — Data Backup Plan.
# Adapted from: Prowler `rds_instance_backup_enabled`,
# `dynamodb_tables_pitr_enabled`, `backup_plans_exist`,
# `backup_vaults_encrypted_with_kms_cmk`.

min_retention_days := 35

deny contains msg if {
    not input.ephi_backups
    msg := "no backup evidence collected"
}

deny contains msg if {
    some rds in input.ephi_backups.rds_instances
    is_ephi(rds)
    rds.backup_retention_period < min_retention_days
    msg := sprintf("ePHI RDS instance %q has backup retention %d days (HIPAA floor is %d)", [rds.identifier, rds.backup_retention_period, min_retention_days])
}

deny contains msg if {
    some table in input.ephi_backups.dynamodb_tables
    is_ephi(table)
    not table.point_in_time_recovery_enabled
    msg := sprintf("ePHI DynamoDB table %q has point-in-time recovery disabled", [table.name])
}

deny contains msg if {
    some vault in input.ephi_backups.backup_vaults
    vault.holds_ephi
    not vault.locked
    msg := sprintf("backup vault %q holds ePHI but is not vault-locked (tamper-resistant retention required)", [vault.name])
}

warn contains msg if {
    some vault in input.ephi_backups.backup_vaults
    vault.holds_ephi
    vault.locked
    not vault.kms_encrypted
    msg := sprintf("backup vault %q is locked but not KMS-encrypted (use a customer-managed key)", [vault.name])
}

# doc 31 §4 — no fail-open tag gates: a resource with no 'ephi' tag is neither confirmed in-scope
# nor out-of-scope, so every deny above skips it and it would pass silently.
# Warn on the unclassified resource instead of ignoring it.

warn contains msg if {
    some resource in input.ephi_backups.rds_instances
    not classified(resource)
    msg := sprintf("RDS instance %q has no ephi tag, so this control's checks did not apply to it — tag ephi=true to bring it into ePHI scope or ephi=false to confirm it is out of scope", [resource.identifier])
}

warn contains msg if {
    some resource in input.ephi_backups.dynamodb_tables
    not classified(resource)
    msg := sprintf("DynamoDB table %q has no ephi tag, so this control's checks did not apply to it — tag ephi=true to bring it into ePHI scope or ephi=false to confirm it is out of scope", [resource.name])
}

is_ephi(resource) if {
    resource.tags.ephi == "true"
}

classified(resource) if resource.tags.ephi == "true"

classified(resource) if resource.tags.ephi == "false"
