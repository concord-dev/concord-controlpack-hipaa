package concord.hipaa.workforce_termination

import rego.v1

# HIPAA §164.308(a)(3)(ii)(C) — Termination Procedures.
# Adapted from: SOC 2 CC6.3 offboarding pattern (concord-controlpack-soc2).

# Maximum hours between termination and last-access-revocation.
max_revocation_window_hours := 24

deny contains msg if {
    not input.okta_terminations
    msg := "no Okta termination evidence collected"
}

deny contains msg if {
    some user in input.okta_terminations.users
    user.has_active_session
    msg := sprintf("terminated user %q still has an active session", [user.email])
}

deny contains msg if {
    some user in input.okta_terminations.users
    count(user.active_application_assignments) > 0
    msg := sprintf("terminated user %q still has %d active application assignment(s)", [user.email, count(user.active_application_assignments)])
}

deny contains msg if {
    some user in input.okta_terminations.users
    count(user.admin_role_memberships) > 0
    msg := sprintf("terminated user %q still has admin role(s): %v", [user.email, user.admin_role_memberships])
}

deny contains msg if {
    some user in input.okta_terminations.users
    user.revocation_lag_hours > max_revocation_window_hours
    msg := sprintf("terminated user %q access was revoked %d hours after termination (HIPAA floor is %d)", [user.email, user.revocation_lag_hours, max_revocation_window_hours])
}
