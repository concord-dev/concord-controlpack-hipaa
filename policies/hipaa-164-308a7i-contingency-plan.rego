package concord.hipaa.hipaa_164_308a7i_contingency_plan

import rego.v1
import data.concord.lib.attestation
import data.concord.lib.evidence

deny contains msg if {
	not evidence.present(input, "hipaa_164_308a7i_contingency_plan")
	msg := "HIPAA-164.308a7i-contingency-plan: no signed attestation submitted"
}

deny contains msg if {
	not attestation.not_expired(input.hipaa_164_308a7i_contingency_plan)
	msg := sprintf("HIPAA-164.308a7i-contingency-plan: attestation expired (expires_at=%s)", [input.hipaa_164_308a7i_contingency_plan.expires_at])
}

deny contains msg if {
	not attestation.fresh(input.hipaa_164_308a7i_contingency_plan, 365)
	msg := sprintf("HIPAA-164.308a7i-contingency-plan: attestation not reviewed in 365 days (last_review_at=%s)", [input.hipaa_164_308a7i_contingency_plan.last_review_at])
}
