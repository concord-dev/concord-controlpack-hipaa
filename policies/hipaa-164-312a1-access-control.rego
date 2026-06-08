package concord.hipaa.hipaa_164_312a1_access_control

import rego.v1
import data.concord.lib.collection
import data.concord.lib.evidence

deny contains msg if {
	not evidence.present(input, "hipaa_164_312a1_access_control")
	msg := "HIPAA-164.312a1-access-control: aws evidence missing"
}

deny contains msg if {
	some r in input.hipaa_164_312a1_access_control.resources
	not r.compliant
	msg := sprintf("HIPAA-164.312a1-access-control: resource %q is non-compliant (reason: %s)", [r.arn, r.reason])
}
