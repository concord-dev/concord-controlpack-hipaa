package concord.hipaa.hipaa_164_310b_workstation_use

import rego.v1
import data.concord.lib.attestation
import data.concord.lib.evidence

deny contains msg if {
	not evidence.present(input, "hipaa_164_310b_workstation_use")
	msg := "HIPAA-164.310b-workstation-use: no signed attestation submitted"
}

deny contains msg if {
	not attestation.not_expired(input.hipaa_164_310b_workstation_use)
	msg := sprintf("HIPAA-164.310b-workstation-use: attestation expired (expires_at=%s)", [input.hipaa_164_310b_workstation_use.expires_at])
}

deny contains msg if {
	not attestation.fresh(input.hipaa_164_310b_workstation_use, 365)
	msg := sprintf("HIPAA-164.310b-workstation-use: attestation not reviewed in 365 days (last_review_at=%s)", [input.hipaa_164_310b_workstation_use.last_review_at])
}
