package concord.hipaa.unique_user_id

import rego.v1

# HIPAA §164.312(a)(2)(i) — Unique User Identification.
# Adapted from: Prowler `iam_avoid_root_usage`,
# `iam_no_root_access_key`, `iam_user_no_access_key_setup`.

max_root_idle_days := 90

deny contains msg if {
    not input.iam_identity
    msg := "no IAM evidence collected"
}

deny contains msg if {
    input.iam_identity.account_access_keys_present > 0
    msg := "root account has access keys (HIPAA §164.312(a)(2)(i) prohibits non-unique credentials)"
}

deny contains msg if {
    input.iam_identity.root_last_used_days_ago < max_root_idle_days
    msg := sprintf("root account used %d days ago — investigate; root usage breaks audit-trail attribution", [input.iam_identity.root_last_used_days_ago])
}

deny contains msg if {
    some user in input.iam_identity.shared_credentials
    msg := sprintf("IAM user %q has %d shared credentials — split into per-person accounts", [user.username, user.shared_count])
}

deny contains msg if {
    some user in input.iam_identity.users
    user.is_service_account
    user.has_console_login
    msg := sprintf("service account %q has console login enabled — service accounts must be programmatic-only", [user.username])
}
