package concord.hipaa.hipaa_164_312e2ii_encryption_in_transit

import rego.v1
import data.concord.lib.collection
import data.concord.lib.evidence

deny contains msg if {
	not evidence.present(input, "hipaa_164_312e2ii_encryption_in_transit")
	msg := "HIPAA-164.312e2ii-encryption-in-transit: aws evidence missing"
}

deny contains msg if {
	some r in input.hipaa_164_312e2ii_encryption_in_transit.resources
	not r.compliant
	msg := sprintf("HIPAA-164.312e2ii-encryption-in-transit: resource %q is non-compliant (reason: %s)", [r.arn, r.reason])
}
