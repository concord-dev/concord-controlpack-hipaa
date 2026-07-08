package concord.hipaa.person_or_entity_authentication

import rego.v1

# HIPAA §164.312(d) — Person or Entity Authentication.
# Every IAM user with console (password) access must have an active MFA
# device. Adapted from CIS AWS 1.10 (console_mfa) and SOC 2 CC6.1.
# Evidence: AWS IAM credential report (input.iam_credentials.users[]).

deny contains msg if {
	not input.iam_credentials
	msg := "no IAM credential report collected"
}

deny contains msg if {
	some u in input.iam_credentials.users
	u.password_enabled == true
	u.user != "<root_account>"
	not u.mfa_active
	msg := sprintf("IAM user %q has console access without an MFA device — enforce MFA (HIPAA §164.312(d))", [u.user])
}

# Root has its own control (HIPAA-164.312-unique-user-id); surface console-
# enabled root here as advisory rather than duplicating the failure.
warn contains msg if {
	some u in input.iam_credentials.users
	u.user == "<root_account>"
	u.password_enabled == true
	msg := "root account has console access — prefer federated admin access and lock down root"
}
