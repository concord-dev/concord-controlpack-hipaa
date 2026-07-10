# Audit log retention meets HIPAA six-year minimum and logs are KMS-encrypted

`HIPAA-164.312-audit-controls` · framework **hipaa** · severity **high** · Technical Safeguards

## What this control checks

HIPAA Security Rule §164.312(b) (Audit Controls) requires hardware,
software, and procedural mechanisms that record and examine
activity in information systems that contain or use ePHI.
§164.530(j)(2) requires policies and procedures (and the
associated audit logs) to be retained for six years. Concord
verifies CloudWatch Logs group retention is ≥ 2,190 days and
that logs are encrypted with a customer-managed KMS key.

## Why it matters

The six-year retention floor is HIPAA-specific and longer than
SOC 2 or ISO 27001. Default CloudWatch retention is "never
expire" which appears safe but typically gets misconfigured to
7 or 30 days for cost reasons. Concord catches that drift.

## Evidence

Collected from the `aws` source (`cloudwatch_log_groups` evidence type).

## What a failure looks like

This control reports a finding when any of the following hold:

- no CloudWatch Logs evidence collected
- log group <value> retention is <value> days — HIPAA requires ≥ <value> (6 years)
- log group <value> is not KMS-encrypted
- non-ePHI log group <value> retention <value> days is below HIPAA floor; mark ephi=false explicitly if intentional

## Remediation

Bring each affected resource or attestation listed under *What a failure looks like* into compliance, then re-collect evidence. Estimated effort: **1h**. Automated fix available: **true**.

## How to re-verify

```
concord check --controls <pack>/controls --framework hipaa --control-id HIPAA-164.312-audit-controls
```

A passing run reports this control green; in CI, `concord gate` exits non-zero while it fails.

## Cross-framework mappings

```
  hipaa:
  - "164.312(b)"
  - "164.530(j)(2)"
  soc2:
  - "CC7.2"
  nist_800_53:
  - "AU-11"
  - "AU-9"
  iso27001:
  - "A.8.15"
```
