# Every IAM identity touching ePHI is uniquely identifiable, root account is unused

`HIPAA-164.312-unique-user-id` · framework **hipaa** · severity **critical** · Technical Safeguards

## What this control checks

HIPAA Security Rule §164.312(a)(2)(i) (Unique User Identification)
requires assigning a unique name and/or number for identifying
and tracking user identity. Concord verifies (a) the AWS root
account has no access keys and has not been used recently,
(b) no IAM users share a console login or access key, and
(c) every IAM access pattern is attributable to a named principal
(no service accounts shared across humans).

## Why it matters

Shared accounts break the entire HIPAA audit-trail story —
if two clinicians share `intake@acme.health`, ePHI access cannot
be attributed to a real person. AWS root usage is the single
highest-severity HIPAA finding because every action is logged
as `root`, which by definition is non-unique.

## Evidence

Collected from the `aws` source (`iam_account_summary` evidence type).

## What a failure looks like

This control reports a finding when any of the following hold:

- no IAM evidence collected
- root account has access keys (HIPAA §164.312(a)(2)(i) prohibits non-unique credentials)
- root account used <value> days ago — investigate; root usage breaks audit-trail attribution
- IAM user <value> has <value> shared credentials — split into per-person accounts
- service account <value> has console login enabled — service accounts must be programmatic-only

## Remediation

Bring each affected resource or attestation listed under *What a failure looks like* into compliance, then re-collect evidence. Estimated effort: **4h**. Automated fix available: **false**.

## How to re-verify

```
concord check --controls <pack>/controls --framework hipaa --control-id HIPAA-164.312-unique-user-id
```

A passing run reports this control green; in CI, `concord gate` exits non-zero while it fails.

## Cross-framework mappings

```
  hipaa:
  - "164.312(a)(2)(i)"
  soc2:
  - "CC6.1"
  nist_800_53:
  - "IA-2"
  - "AC-2"
  iso27001:
  - "A.5.16"
  cis_aws:
  - "1.4"
  - "1.7"
```
