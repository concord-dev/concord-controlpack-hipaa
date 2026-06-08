package concord.hipaa.hipaa_164_316b1_policies_and_procedures_retention

import rego.v1
import data.concord.lib.attestation
import data.concord.lib.evidence

deny contains msg if {
	not evidence.present(input, "hipaa_164_316b1_policies_and_procedures_retention")
	msg := "HIPAA-164.316b1-policies-and-procedures-retention: no signed attestation submitted"
}

deny contains msg if {
	not attestation.not_expired(input.hipaa_164_316b1_policies_and_procedures_retention)
	msg := sprintf("HIPAA-164.316b1-policies-and-procedures-retention: attestation expired (expires_at=%s)", [input.hipaa_164_316b1_policies_and_procedures_retention.expires_at])
}

deny contains msg if {
	not attestation.fresh(input.hipaa_164_316b1_policies_and_procedures_retention, 365)
	msg := sprintf("HIPAA-164.316b1-policies-and-procedures-retention: attestation not reviewed in 365 days (last_review_at=%s)", [input.hipaa_164_316b1_policies_and_procedures_retention.last_review_at])
}
