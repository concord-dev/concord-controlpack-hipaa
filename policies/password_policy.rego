package concord.hipaa.password_policy

import rego.v1

# HIPAA §164.308(a)(5)(ii)(D) — Password Management.
# Adapted from: Prowler `iam_password_policy_minimum_length_14`,
# `iam_password_policy_lowercase`, `iam_password_policy_uppercase`,
# `iam_password_policy_number`, `iam_password_policy_symbol`,
# `iam_password_policy_reuse_24`, `iam_password_policy_expires_passwords_within_90_days`.

# HIPAA-equivalent floor — derived from NIST SP 800-63B + HHS/OCR
# enforcement patterns.
min_length := 12
max_age_days := 90
min_reuse_prevention := 12

deny contains msg if {
    not input.iam_password_policy
    msg := "no IAM password policy evidence collected"
}

deny contains msg if {
    input.iam_password_policy.minimum_password_length < min_length
    msg := sprintf("password policy length %d is below HIPAA-equivalent floor of %d", [input.iam_password_policy.minimum_password_length, min_length])
}

deny contains msg if {
    not input.iam_password_policy.require_lowercase_characters
    msg := "password policy does not require lowercase characters"
}

deny contains msg if {
    not input.iam_password_policy.require_uppercase_characters
    msg := "password policy does not require uppercase characters"
}

deny contains msg if {
    not input.iam_password_policy.require_numbers
    msg := "password policy does not require numbers"
}

deny contains msg if {
    not input.iam_password_policy.require_symbols
    msg := "password policy does not require symbols"
}

deny contains msg if {
    not input.iam_password_policy.password_reuse_prevention >= min_reuse_prevention
    msg := sprintf("password policy reuse prevention is below %d", [min_reuse_prevention])
}

deny contains msg if {
    not input.iam_password_policy.max_password_age <= max_age_days
    msg := sprintf("password max-age must be <= %d days", [max_age_days])
}
