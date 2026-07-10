# IAM least-privilege is enforced for accounts that access ePHI

`HIPAA-164.312a1-access-control` · framework **hipaa** · severity **critical** · Technical Safeguards

## What this control checks

HIPAA Security Rule §164.312(a)(1) (Access Control) requires technical
policies that grant ePHI access only to those persons and software
programs that have been granted access rights. Concord reads every IAM
identity (user, group, and role) in the ePHI account together with the
managed and inline policies attached to it, and fails any identity that
is attached to the AWS-managed AdministratorAccess policy or to a policy
whose Allow statement grants Action "*" on Resource "*". Such grants are
the antithesis of least-privilege and cannot bound access to ePHI.

## Why it matters

Broad "*/*" grants are the most common way least-privilege erodes in
practice: a role created for one task accumulates AdministratorAccess and
then quietly becomes a path to every ePHI store in the account. OCR
corrective action plans repeatedly require covered entities to demonstrate
role-based, minimum-necessary access under §164.312(a)(1); an
unconstrained admin grant is an immediate audit finding. The check fails
closed — if evidence is missing the control denies rather than assuming
least-privilege holds.

## Evidence

Collected from the `aws` source (`iam_policies` evidence type).

## What a failure looks like

This control reports a finding when any of the following hold:

- no IAM policy evidence collected
- IAM <value> <value> is attached to AdministratorAccess — full-admin grants violate least-privilege for ePHI access (HIPAA §164.312(a)(1))
- IAM <value> <value> attaches policy <value> that allows Action "*" on Resource "*" — violates least-privilege for ePHI access (HIPAA §164.312(a)(1))

## Remediation

Bring each affected resource or attestation listed under *What a failure looks like* into compliance, then re-collect evidence. Estimated effort: **1d**. Automated fix available: **false**.

## How to re-verify

```
concord check --controls <pack>/controls --framework hipaa --control-id HIPAA-164.312a1-access-control
```

A passing run reports this control green; in CI, `concord gate` exits non-zero while it fails.

## Cross-framework mappings

```
  hipaa:
  - "164.312(a)(1)"
  soc2:
  - "CC6.1"
  - "CC6.3"
  nist_800_53:
  - "AC-6"
  cis_aws:
  - "1.16"
```
