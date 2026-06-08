package concord.hipaa.hipaa_164_312d_person_or_entity_authentication

import rego.v1
import data.concord.lib.collection
import data.concord.lib.evidence

deny contains msg if {
	not evidence.present(input, "hipaa_164_312d_person_or_entity_authentication")
	msg := "HIPAA-164.312d-person-or-entity-authentication: aws evidence missing"
}

deny contains msg if {
	some r in input.hipaa_164_312d_person_or_entity_authentication.resources
	not r.compliant
	msg := sprintf("HIPAA-164.312d-person-or-entity-authentication: resource %q is non-compliant (reason: %s)", [r.arn, r.reason])
}
