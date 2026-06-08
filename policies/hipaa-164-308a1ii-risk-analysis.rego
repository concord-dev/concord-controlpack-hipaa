package concord.hipaa.hipaa_164_308a1ii_risk_analysis

import rego.v1
import data.concord.lib.attestation
import data.concord.lib.evidence

deny contains msg if {
	not evidence.present(input, "hipaa_164_308a1ii_risk_analysis")
	msg := "HIPAA-164.308a1ii-risk-analysis: no signed attestation submitted"
}

deny contains msg if {
	not attestation.not_expired(input.hipaa_164_308a1ii_risk_analysis)
	msg := sprintf("HIPAA-164.308a1ii-risk-analysis: attestation expired (expires_at=%s)", [input.hipaa_164_308a1ii_risk_analysis.expires_at])
}

deny contains msg if {
	not attestation.fresh(input.hipaa_164_308a1ii_risk_analysis, 365)
	msg := sprintf("HIPAA-164.308a1ii-risk-analysis: attestation not reviewed in 365 days (last_review_at=%s)", [input.hipaa_164_308a1ii_risk_analysis.last_review_at])
}
