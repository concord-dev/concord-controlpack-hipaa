package concord.hipaa.business_associate_contracts

import rego.v1

# HIPAA §164.308(b)(1) — Business Associate Contracts.
# Every business associate that receives ePHI must have a current signed BAA.
# Concord collects the register from the repository via github/file_glob with
# frontmatter parsing, so the matched file appears in input.baa_register.docs
# with its frontmatter keys (including the associates[] list) plus a "path".
# Each associate is evaluated independently: it must be signed and carry a
# non-empty, unexpired term.

deny contains msg if {
	not input.baa_register
	msg := "no business-associate agreement register evidence collected"
}

deny contains msg if {
	input.baa_register
	count(object.get(input.baa_register, "docs", [])) == 0
	msg := "no business-associate agreement register document found at the configured repository path"
}

deny contains msg if {
	some doc in input.baa_register.docs
	some a in doc.associates
	not a.baa_signed == true
	msg := sprintf("business associate %q has no signed BAA (baa_signed is not true)", [a.name])
}

deny contains msg if {
	some doc in input.baa_register.docs
	some a in doc.associates
	missing_expiry(a)
	msg := sprintf("business associate %q BAA has no expiry date recorded", [a.name])
}

deny contains msg if {
	some doc in input.baa_register.docs
	some a in doc.associates
	not missing_expiry(a)
	time.parse_rfc3339_ns(a.expires_at) < time.now_ns()
	msg := sprintf("business associate %q BAA expired on %s", [a.name, a.expires_at])
}

missing_expiry(a) if not a.expires_at

missing_expiry(a) if a.expires_at == ""
