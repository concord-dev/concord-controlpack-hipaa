# MFA is enforced for every IAM user with console access

`HIPAA-164.312d-person-or-entity-authentication` · framework **hipaa** · severity **critical** · Technical Safeguards

## What this control checks

HIPAA Security Rule §164.312(d) (Person or Entity Authentication)
requires procedures to verify that a person or entity seeking access to
ePHI is the one claimed. For AWS console access this means multi-factor
authentication on every IAM principal that can sign in with a password.
Concord reads the IAM credential report and fails any console-enabled
user that has no active MFA device. The root account is checked by its
own control (HIPAA-164.312-unique-user-id) and only warned on here.

## Why it matters

Single-factor console access is the most common initial-access vector in
healthcare breaches, and OCR settlements repeatedly cite missing MFA as a
§164.312(d) failure. Enforcing an MFA device on every interactive
identity is the highest-leverage authentication safeguard and a
prerequisite for meaningful access logging.

## Evidence

Collected from the `aws` source (`iam_credential_report` evidence type).

## What a failure looks like

This control reports a finding when any of the following hold:

- no IAM credential report collected
- IAM user <value> has console access without an MFA device — enforce MFA (HIPAA §164.312(d))
- root account has console access — prefer federated admin access and lock down root

## Remediation

Bring each affected resource or attestation listed under *What a failure looks like* into compliance, then re-collect evidence. Estimated effort: **1d**. Automated fix available: **false**.

## How to re-verify

```
concord check --controls <pack>/controls --framework hipaa --control-id HIPAA-164.312d-person-or-entity-authentication
```

A passing run reports this control green; in CI, `concord gate` exits non-zero while it fails.

## Cross-framework mappings

```
  hipaa:
  - "164.312(d)"
  soc2:
  - "CC6.1"
  nist_800_53:
  - "IA-2"
  cis_aws:
  - "1.10"
```
