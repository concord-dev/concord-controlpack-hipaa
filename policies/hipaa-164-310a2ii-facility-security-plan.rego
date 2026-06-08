package concord.hipaa.hipaa_164_310a2ii_facility_security_plan

import rego.v1
import data.concord.lib.attestation
import data.concord.lib.evidence

deny contains msg if {
	not evidence.present(input, "hipaa_164_310a2ii_facility_security_plan")
	msg := "HIPAA-164.310a2ii-facility-security-plan: no signed attestation submitted"
}

deny contains msg if {
	not attestation.not_expired(input.hipaa_164_310a2ii_facility_security_plan)
	msg := sprintf("HIPAA-164.310a2ii-facility-security-plan: attestation expired (expires_at=%s)", [input.hipaa_164_310a2ii_facility_security_plan.expires_at])
}

deny contains msg if {
	not attestation.fresh(input.hipaa_164_310a2ii_facility_security_plan, 365)
	msg := sprintf("HIPAA-164.310a2ii-facility-security-plan: attestation not reviewed in 365 days (last_review_at=%s)", [input.hipaa_164_310a2ii_facility_security_plan.last_review_at])
}
