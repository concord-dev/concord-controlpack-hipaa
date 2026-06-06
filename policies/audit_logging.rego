package concord.hipaa.audit_logging

import rego.v1

# HIPAA §164.308(a)(1)(ii)(D) — Information System Activity Review.
# Adapted from: Prowler `cloudtrail_multi_region_enabled`,
# `cloudtrail_log_file_validation_enabled`,
# `cloudtrail_s3_dataevents_read_enabled`, `cloudtrail_s3_dataevents_write_enabled`.
# Powerpipe HIPAA benchmark `hipaa_final_omnibus_security_rule_2013`.

deny contains msg if {
    not input.cloudtrail
    msg := "no CloudTrail evidence collected (AWS collector misconfigured or no credentials)"
}

deny contains msg if {
    not has_multi_region_trail
    msg := "no multi-region CloudTrail trail is logging — HIPAA §164.308(a)(1)(ii)(D) requires audit coverage across every region"
}

deny contains msg if {
    some trail in input.cloudtrail.trails
    trail.is_multi_region_trail
    trail.is_logging
    not trail.log_file_validation_enabled
    msg := sprintf("trail %q has log-file validation disabled — integrity cannot be defended in a breach investigation", [trail.name])
}

warn contains msg if {
    some trail in input.cloudtrail.trails
    trail.is_multi_region_trail
    trail.is_logging
    not records_s3_data_events(trail)
    msg := sprintf("trail %q does not record S3 data events — object-level ePHI access will be invisible", [trail.name])
}

has_multi_region_trail if {
    some trail in input.cloudtrail.trails
    trail.is_multi_region_trail
    trail.is_logging
}

records_s3_data_events(trail) if {
    some selector in trail.event_selectors
    some resource in selector.data_resources
    resource.type == "AWS::S3::Object"
}
