package concord.hipaa.hipaa_164_308a6i_security_incident_procedures

import rego.v1
import data.concord.lib.attestation
import data.concord.lib.evidence

deny contains msg if {
	not evidence.present(input, "hipaa_164_308a6i_security_incident_procedures")
	msg := "HIPAA-164.308a6i-security-incident-procedures: no signed attestation submitted"
}

deny contains msg if {
	not attestation.not_expired(input.hipaa_164_308a6i_security_incident_procedures)
	msg := sprintf("HIPAA-164.308a6i-security-incident-procedures: attestation expired (expires_at=%s)", [input.hipaa_164_308a6i_security_incident_procedures.expires_at])
}

deny contains msg if {
	not attestation.fresh(input.hipaa_164_308a6i_security_incident_procedures, 365)
	msg := sprintf("HIPAA-164.308a6i-security-incident-procedures: attestation not reviewed in 365 days (last_review_at=%s)", [input.hipaa_164_308a6i_security_incident_procedures.last_review_at])
}
