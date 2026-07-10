# AWS IAM password policy meets HIPAA-equivalent strength requirements

`HIPAA-164.308-password-policy` · framework **hipaa** · severity **high** · Administrative Safeguards

## What this control checks

HIPAA Security Rule §164.308(a)(5)(ii)(D) (Password Management)
requires procedures for creating, changing, and safeguarding
passwords. NIST SP 800-63B is the operational floor most HHS/OCR
auditors apply. Concord verifies the AWS IAM account password
policy meets length, complexity, and reuse criteria.

## Why it matters

Default IAM password policies are too weak for HIPAA-protected
workloads. A 12-character minimum with mixed character classes,
90-day rotation, and reuse-prevention is the floor HHS audits
converge on for cloud accounts holding ePHI.

## Evidence

Collected from the `aws` source (`iam_password_policy` evidence type).

## What a failure looks like

This control reports a finding when any of the following hold:

- no IAM password policy evidence collected
- password policy length <value> is below HIPAA-equivalent floor of <value>
- password policy does not require lowercase characters
- password policy does not require uppercase characters
- password policy does not require numbers
- password policy does not require symbols
- password policy reuse prevention is below <value>
- password max-age must be <= <value> days

## Remediation

Bring each affected resource or attestation listed under *What a failure looks like* into compliance, then re-collect evidence. Estimated effort: **15m**. Automated fix available: **true**.

## How to re-verify

```
concord check --controls <pack>/controls --framework hipaa --control-id HIPAA-164.308-password-policy
```

A passing run reports this control green; in CI, `concord gate` exits non-zero while it fails.

## Cross-framework mappings

```
  hipaa:
  - "164.308(a)(5)(ii)(D)"
  soc2:
  - "CC6.1"
  nist_800_53:
  - "IA-5"
  iso27001:
  - "A.5.17"
  cis_aws:
  - "1.8"
  - "1.9"
```
