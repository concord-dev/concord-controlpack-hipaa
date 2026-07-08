package concord.hipaa.automatic_logoff

import rego.v1

# HIPAA §164.312(a)(2)(iii) — Automatic Logoff.
# IAM roles tagged ephi=true must cap MaxSessionDuration at or below the
# one-hour threshold so a session cannot outlive the automatic-logoff window.
# Adapted from NIST 800-53 AC-11/AC-12 (session termination) and AWS IAM
# role MaxSessionDuration guidance.
# Evidence: input.iam_roles.roles[].

max_session_seconds := 3600

deny contains msg if {
	not input.iam_roles
	msg := "no IAM role evidence collected"
}

# Fail closed: an ePHI role with no published max session duration.
deny contains msg if {
	some r in input.iam_roles.roles
	is_ephi(r)
	not has_max_session(r)
	msg := sprintf("ePHI role %q does not publish a max session duration — automatic logoff cannot be verified (HIPAA §164.312(a)(2)(iii))", [r.role_name])
}

# ePHI role whose session ceiling exceeds the threshold.
deny contains msg if {
	some r in input.iam_roles.roles
	is_ephi(r)
	has_max_session(r)
	r.max_session_duration_seconds > max_session_seconds
	msg := sprintf("ePHI role %q allows sessions of %d seconds, exceeding the %d-second automatic-logoff threshold (HIPAA §164.312(a)(2)(iii))", [r.role_name, r.max_session_duration_seconds, max_session_seconds])
}

is_ephi(r) if {
	r.tags.ephi == "true"
}

has_max_session(r) if {
	is_number(r.max_session_duration_seconds)
}
