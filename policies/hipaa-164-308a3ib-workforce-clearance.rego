package concord.hipaa.hipaa_164_308a3ib_workforce_clearance

import rego.v1
import data.concord.lib.attestation
import data.concord.lib.evidence

deny contains msg if {
	not evidence.present(input, "hipaa_164_308a3ib_workforce_clearance")
	msg := "HIPAA-164.308a3iB-workforce-clearance: no signed attestation submitted"
}

deny contains msg if {
	not attestation.not_expired(input.hipaa_164_308a3ib_workforce_clearance)
	msg := sprintf("HIPAA-164.308a3iB-workforce-clearance: attestation expired (expires_at=%s)", [input.hipaa_164_308a3ib_workforce_clearance.expires_at])
}

deny contains msg if {
	not attestation.fresh(input.hipaa_164_308a3ib_workforce_clearance, 365)
	msg := sprintf("HIPAA-164.308a3iB-workforce-clearance: attestation not reviewed in 365 days (last_review_at=%s)", [input.hipaa_164_308a3ib_workforce_clearance.last_review_at])
}
