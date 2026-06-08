package concord.hipaa.hipaa_164_310a2i_contingency_operations

import rego.v1
import data.concord.lib.attestation
import data.concord.lib.evidence

deny contains msg if {
	not evidence.present(input, "hipaa_164_310a2i_contingency_operations")
	msg := "HIPAA-164.310a2i-contingency-operations: no signed attestation submitted"
}

deny contains msg if {
	not attestation.not_expired(input.hipaa_164_310a2i_contingency_operations)
	msg := sprintf("HIPAA-164.310a2i-contingency-operations: attestation expired (expires_at=%s)", [input.hipaa_164_310a2i_contingency_operations.expires_at])
}

deny contains msg if {
	not attestation.fresh(input.hipaa_164_310a2i_contingency_operations, 365)
	msg := sprintf("HIPAA-164.310a2i-contingency-operations: attestation not reviewed in 365 days (last_review_at=%s)", [input.hipaa_164_310a2i_contingency_operations.last_review_at])
}
