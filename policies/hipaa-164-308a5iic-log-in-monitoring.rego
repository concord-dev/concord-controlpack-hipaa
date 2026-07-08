package concord.hipaa.log_in_monitoring

import rego.v1

# HIPAA §164.308(a)(5)(ii)(C) — Log-in Monitoring.
# A CloudWatch Logs metric filter over the CloudTrail log group must match
# failed console authentications, and that metric must be watched by an
# alarm with an active notification action.
# Adapted from CIS AWS Foundations 3.6 (console authentication-failure alarm)
# and Prowler `cloudwatch_log_metric_filter_authentication_failures`.
# Evidence: input.cloudwatch_alarms.{metric_filters,alarms}.

deny contains msg if {
	not input.cloudwatch_alarms
	msg := "no CloudWatch metric-filter/alarm evidence collected"
}

# No metric filter matches failed console log-ins at all.
deny contains msg if {
	input.cloudwatch_alarms
	count(console_failure_filters) == 0
	msg := "no CloudWatch metric filter matches failed console log-ins (ConsoleLogin + \"Failed authentication\") — HIPAA §164.308(a)(5)(ii)(C)"
}

# A matching filter exists but its metric has no alarm with a live action.
deny contains msg if {
	some f in console_failure_filters
	not metric_has_active_alarm(f.metric_name)
	msg := sprintf("metric filter %q matches failed console log-ins but its metric has no CloudWatch alarm with an enabled notification action — HIPAA §164.308(a)(5)(ii)(C)", [f.filter_name])
}

console_failure_filters contains f if {
	some f in input.cloudwatch_alarms.metric_filters
	contains(f.filter_pattern, "ConsoleLogin")
	contains(f.filter_pattern, "Failed authentication")
}

metric_has_active_alarm(metric) if {
	some a in input.cloudwatch_alarms.alarms
	a.metric_name == metric
	a.actions_enabled == true
	count(a.alarm_actions) > 0
}
