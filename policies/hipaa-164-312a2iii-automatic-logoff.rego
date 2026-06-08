package concord.hipaa.hipaa_164_312a2iii_automatic_logoff

import rego.v1
import data.concord.lib.attestation
import data.concord.lib.evidence

deny contains msg if {
	not evidence.present(input, "hipaa_164_312a2iii_automatic_logoff")
	msg := "HIPAA-164.312a2iii-automatic-logoff: no signed attestation submitted"
}

deny contains msg if {
	not attestation.not_expired(input.hipaa_164_312a2iii_automatic_logoff)
	msg := sprintf("HIPAA-164.312a2iii-automatic-logoff: attestation expired (expires_at=%s)", [input.hipaa_164_312a2iii_automatic_logoff.expires_at])
}

deny contains msg if {
	not attestation.fresh(input.hipaa_164_312a2iii_automatic_logoff, 365)
	msg := sprintf("HIPAA-164.312a2iii-automatic-logoff: attestation not reviewed in 365 days (last_review_at=%s)", [input.hipaa_164_312a2iii_automatic_logoff.last_review_at])
}
