package concord.hipaa.hipaa_164_310a1_facility_access_controls

import rego.v1
import data.concord.lib.attestation
import data.concord.lib.evidence

deny contains msg if {
	not evidence.present(input, "hipaa_164_310a1_facility_access_controls")
	msg := "HIPAA-164.310a1-facility-access-controls: no signed attestation submitted"
}

deny contains msg if {
	not attestation.not_expired(input.hipaa_164_310a1_facility_access_controls)
	msg := sprintf("HIPAA-164.310a1-facility-access-controls: attestation expired (expires_at=%s)", [input.hipaa_164_310a1_facility_access_controls.expires_at])
}

deny contains msg if {
	not attestation.fresh(input.hipaa_164_310a1_facility_access_controls, 365)
	msg := sprintf("HIPAA-164.310a1-facility-access-controls: attestation not reviewed in 365 days (last_review_at=%s)", [input.hipaa_164_310a1_facility_access_controls.last_review_at])
}
