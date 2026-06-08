package concord.hipaa.hipaa_164_308b1_business_associate_contracts

import rego.v1
import data.concord.lib.evidence

deny contains msg if {
	not evidence.present(input, "hipaa_164_308b1_business_associate_contracts")
	msg := "HIPAA-164.308b1-business-associate-contracts: vendor evidence missing"
}

deny contains msg if {
	some v in input.hipaa_164_308b1_business_associate_contracts.vendors
	v.tier in {"tier_1", "tier_2"}
	not v.current_cert
	msg := sprintf("HIPAA-164.308b1-business-associate-contracts: %s has no current cert in scope", [v.name])
}
