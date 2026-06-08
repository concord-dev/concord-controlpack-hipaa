package concord.hipaa.hipaa_164_308a4iia_isolating_clearinghouse

import rego.v1
import data.concord.lib.attestation
import data.concord.lib.evidence

deny contains msg if {
	not evidence.present(input, "hipaa_164_308a4iia_isolating_clearinghouse")
	msg := "HIPAA-164.308a4iiA-isolating-clearinghouse: no signed attestation submitted"
}

deny contains msg if {
	not attestation.not_expired(input.hipaa_164_308a4iia_isolating_clearinghouse)
	msg := sprintf("HIPAA-164.308a4iiA-isolating-clearinghouse: attestation expired (expires_at=%s)", [input.hipaa_164_308a4iia_isolating_clearinghouse.expires_at])
}

deny contains msg if {
	not attestation.fresh(input.hipaa_164_308a4iia_isolating_clearinghouse, 365)
	msg := sprintf("HIPAA-164.308a4iiA-isolating-clearinghouse: attestation not reviewed in 365 days (last_review_at=%s)", [input.hipaa_164_308a4iia_isolating_clearinghouse.last_review_at])
}
