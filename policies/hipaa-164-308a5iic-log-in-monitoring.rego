package concord.hipaa.hipaa_164_308a5iic_log_in_monitoring

import rego.v1
import data.concord.lib.collection
import data.concord.lib.evidence

deny contains msg if {
	not evidence.present(input, "hipaa_164_308a5iic_log_in_monitoring")
	msg := "HIPAA-164.308a5iiC-log-in-monitoring: aws evidence missing"
}

deny contains msg if {
	some r in input.hipaa_164_308a5iic_log_in_monitoring.resources
	not r.compliant
	msg := sprintf("HIPAA-164.308a5iiC-log-in-monitoring: resource %q is non-compliant (reason: %s)", [r.arn, r.reason])
}
