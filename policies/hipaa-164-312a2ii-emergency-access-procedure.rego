package concord.hipaa.hipaa_164_312a2ii_emergency_access_procedure

import rego.v1
import data.concord.lib.attestation
import data.concord.lib.evidence

deny contains msg if {
	not evidence.present(input, "hipaa_164_312a2ii_emergency_access_procedure")
	msg := "HIPAA-164.312a2ii-emergency-access-procedure: no signed attestation submitted"
}

deny contains msg if {
	not attestation.not_expired(input.hipaa_164_312a2ii_emergency_access_procedure)
	msg := sprintf("HIPAA-164.312a2ii-emergency-access-procedure: attestation expired (expires_at=%s)", [input.hipaa_164_312a2ii_emergency_access_procedure.expires_at])
}

deny contains msg if {
	not attestation.fresh(input.hipaa_164_312a2ii_emergency_access_procedure, 365)
	msg := sprintf("HIPAA-164.312a2ii-emergency-access-procedure: attestation not reviewed in 365 days (last_review_at=%s)", [input.hipaa_164_312a2ii_emergency_access_procedure.last_review_at])
}
