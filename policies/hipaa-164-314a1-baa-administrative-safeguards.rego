package concord.hipaa.hipaa_164_314a1_baa_administrative_safeguards

import rego.v1
import data.concord.lib.attestation
import data.concord.lib.evidence

deny contains msg if {
	not evidence.present(input, "hipaa_164_314a1_baa_administrative_safeguards")
	msg := "HIPAA-164.314a1-baa-administrative-safeguards: no signed attestation submitted"
}

deny contains msg if {
	not attestation.not_expired(input.hipaa_164_314a1_baa_administrative_safeguards)
	msg := sprintf("HIPAA-164.314a1-baa-administrative-safeguards: attestation expired (expires_at=%s)", [input.hipaa_164_314a1_baa_administrative_safeguards.expires_at])
}

deny contains msg if {
	not attestation.fresh(input.hipaa_164_314a1_baa_administrative_safeguards, 365)
	msg := sprintf("HIPAA-164.314a1-baa-administrative-safeguards: attestation not reviewed in 365 days (last_review_at=%s)", [input.hipaa_164_314a1_baa_administrative_safeguards.last_review_at])
}
