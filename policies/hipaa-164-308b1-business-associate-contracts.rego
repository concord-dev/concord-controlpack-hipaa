package concord.hipaa.business_associate_contracts

import rego.v1

# HIPAA §164.308(b)(1) — Business Associate Contracts.
# Every business associate that receives ePHI must have a current signed BAA.
# Concord reads a register (input.baa_register.associates[]) and evaluates
# each associate independently: it must be signed and carry a non-empty,
# unexpired term.

deny contains msg if {
	not input.baa_register
	msg := "no business-associate agreement register evidence collected"
}

deny contains msg if {
	some a in input.baa_register.associates
	not a.baa_signed
	msg := sprintf("business associate %q has no signed BAA (baa_signed is not true)", [a.name])
}

deny contains msg if {
	some a in input.baa_register.associates
	missing_expiry(a)
	msg := sprintf("business associate %q BAA has no expiry date recorded", [a.name])
}

deny contains msg if {
	some a in input.baa_register.associates
	not missing_expiry(a)
	time.parse_rfc3339_ns(a.expires_at) < time.now_ns()
	msg := sprintf("business associate %q BAA expired on %s", [a.name, a.expires_at])
}

missing_expiry(a) if not a.expires_at

missing_expiry(a) if a.expires_at == ""
