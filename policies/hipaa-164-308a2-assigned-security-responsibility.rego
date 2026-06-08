package concord.hipaa.hipaa_164_308a2_assigned_security_responsibility

import rego.v1
import data.concord.lib.attestation
import data.concord.lib.evidence

deny contains msg if {
	not evidence.present(input, "hipaa_164_308a2_assigned_security_responsibility")
	msg := "HIPAA-164.308a2-assigned-security-responsibility: no signed attestation submitted"
}

deny contains msg if {
	not attestation.not_expired(input.hipaa_164_308a2_assigned_security_responsibility)
	msg := sprintf("HIPAA-164.308a2-assigned-security-responsibility: attestation expired (expires_at=%s)", [input.hipaa_164_308a2_assigned_security_responsibility.expires_at])
}

deny contains msg if {
	not attestation.fresh(input.hipaa_164_308a2_assigned_security_responsibility, 365)
	msg := sprintf("HIPAA-164.308a2-assigned-security-responsibility: attestation not reviewed in 365 days (last_review_at=%s)", [input.hipaa_164_308a2_assigned_security_responsibility.last_review_at])
}
