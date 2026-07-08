package concord.hipaa.access_control

import rego.v1

# HIPAA §164.312(a)(1) — Access Control (least-privilege).
# Every IAM identity in the ePHI account must avoid full-admin grants:
# neither the AWS-managed AdministratorAccess policy nor an inline/managed
# Allow of Action "*" on Resource "*".
# Adapted from CIS AWS Foundations 1.16 (no full "*:*" administrative
# privileges) and Prowler `iam_policy_no_administrative_privileges`.
# Evidence: input.iam_policies.identities[].attached_policies[].

deny contains msg if {
	not input.iam_policies
	msg := "no IAM policy evidence collected"
}

# Attached to the AWS-managed AdministratorAccess policy.
deny contains msg if {
	some id in input.iam_policies.identities
	some p in id.attached_policies
	p.policy_name == "AdministratorAccess"
	msg := sprintf("IAM %s %q is attached to AdministratorAccess — full-admin grants violate least-privilege for ePHI access (HIPAA §164.312(a)(1))", [identity_type(id), id.name])
}

# Attached to any policy that allows Action "*" on Resource "*".
deny contains msg if {
	some id in input.iam_policies.identities
	some p in id.attached_policies
	some stmt in p.document.Statement
	stmt.Effect == "Allow"
	action_is_wildcard(stmt)
	resource_is_wildcard(stmt)
	msg := sprintf("IAM %s %q attaches policy %q that allows Action \"*\" on Resource \"*\" — violates least-privilege for ePHI access (HIPAA §164.312(a)(1))", [identity_type(id), id.name, p.policy_name])
}

identity_type(id) := t if {
	t := id.type
}

identity_type(id) := "identity" if {
	not id.type
}

action_is_wildcard(stmt) if {
	stmt.Action == "*"
}

action_is_wildcard(stmt) if {
	some a in stmt.Action
	a == "*"
}

resource_is_wildcard(stmt) if {
	stmt.Resource == "*"
}

resource_is_wildcard(stmt) if {
	some r in stmt.Resource
	r == "*"
}
