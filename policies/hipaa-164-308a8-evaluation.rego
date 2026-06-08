package concord.hipaa.hipaa_164_308a8_evaluation

import rego.v1
import data.concord.lib.attestation
import data.concord.lib.evidence

deny contains msg if {
	not evidence.present(input, "hipaa_164_308a8_evaluation")
	msg := "HIPAA-164.308a8-evaluation: no signed attestation submitted"
}

deny contains msg if {
	not attestation.not_expired(input.hipaa_164_308a8_evaluation)
	msg := sprintf("HIPAA-164.308a8-evaluation: attestation expired (expires_at=%s)", [input.hipaa_164_308a8_evaluation.expires_at])
}

deny contains msg if {
	not attestation.fresh(input.hipaa_164_308a8_evaluation, 365)
	msg := sprintf("HIPAA-164.308a8-evaluation: attestation not reviewed in 365 days (last_review_at=%s)", [input.hipaa_164_308a8_evaluation.last_review_at])
}
