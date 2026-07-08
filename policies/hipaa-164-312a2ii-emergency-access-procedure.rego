package concord.hipaa.emergency_access_procedure

import rego.v1

# HIPAA §164.312(a)(2)(ii) — Emergency Access Procedure.
# A dedicated break-glass IAM role (tag break_glass=true) must exist, its
# trust policy must require MFA (aws:MultiFactorAuthPresent=true), and its
# assumption must be covered by a CloudWatch alarm with a live notification
# action so every emergency use is detected.
# Adapted from AWS Well-Architected SEC03-BP08 (emergency access) and
# CIS AWS Foundations monitoring controls.
# Evidence: input.break_glass.{roles,alarms}.

deny contains msg if {
	not input.break_glass
	msg := "no IAM role / CloudWatch alarm evidence collected"
}

# No dedicated break-glass role exists.
deny contains msg if {
	input.break_glass
	count(break_glass_roles) == 0
	msg := "no dedicated break-glass IAM role (tag break_glass=true) found — emergency access must use an isolated, monitored role (HIPAA §164.312(a)(2)(ii))"
}

# Break-glass role does not require MFA to assume.
deny contains msg if {
	some r in break_glass_roles
	not role_requires_mfa(r)
	msg := sprintf("break-glass role %q trust policy does not require MFA (aws:MultiFactorAuthPresent=true) to assume — HIPAA §164.312(a)(2)(ii)", [r.role_name])
}

# Break-glass role assumption is not covered by a live alarm.
deny contains msg if {
	some r in break_glass_roles
	not role_has_active_alarm(r)
	msg := sprintf("break-glass role %q assumption is not covered by a CloudWatch alarm with an enabled notification action — emergency use would go undetected (HIPAA §164.312(a)(2)(ii))", [r.role_name])
}

break_glass_roles contains r if {
	some r in input.break_glass.roles
	r.tags.break_glass == "true"
}

role_requires_mfa(r) if {
	some stmt in r.assume_role_policy.Statement
	stmt.Effect == "Allow"
	stmt.Condition.Bool["aws:MultiFactorAuthPresent"] == "true"
}

role_has_active_alarm(r) if {
	some a in input.break_glass.alarms
	a.actions_enabled == true
	count(a.alarm_actions) > 0
	contains(a.filter_pattern, r.role_name)
}
