package concord.hipaa.hipaa_164_308a3ia_authorization_supervision

import rego.v1
import data.concord.lib.attestation
import data.concord.lib.evidence

deny contains msg if {
	not evidence.present(input, "hipaa_164_308a3ia_authorization_supervision")
	msg := "HIPAA-164.308a3iA-authorization-supervision: no signed attestation submitted"
}

deny contains msg if {
	not attestation.not_expired(input.hipaa_164_308a3ia_authorization_supervision)
	msg := sprintf("HIPAA-164.308a3iA-authorization-supervision: attestation expired (expires_at=%s)", [input.hipaa_164_308a3ia_authorization_supervision.expires_at])
}

deny contains msg if {
	not attestation.fresh(input.hipaa_164_308a3ia_authorization_supervision, 365)
	msg := sprintf("HIPAA-164.308a3iA-authorization-supervision: attestation not reviewed in 365 days (last_review_at=%s)", [input.hipaa_164_308a3ia_authorization_supervision.last_review_at])
}
