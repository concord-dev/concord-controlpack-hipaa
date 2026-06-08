package concord.hipaa.hipaa_164_310c_workstation_security

import rego.v1
import data.concord.lib.collection
import data.concord.lib.evidence

deny contains msg if {
	not evidence.present(input, "hipaa_164_310c_workstation_security")
	msg := "HIPAA-164.310c-workstation-security: aws evidence missing"
}

deny contains msg if {
	some r in input.hipaa_164_310c_workstation_security.resources
	not r.compliant
	msg := sprintf("HIPAA-164.310c-workstation-security: resource %q is non-compliant (reason: %s)", [r.arn, r.reason])
}
