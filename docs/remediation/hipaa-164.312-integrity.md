# ePHI buckets enforce versioning and Object Lock so ePHI cannot be silently altered

`HIPAA-164.312-integrity` · framework **hipaa** · severity **critical** · Technical Safeguards

## What this control checks

HIPAA Security Rule §164.312(c)(1) (Integrity) and §164.312(c)(2)
(Mechanism to Authenticate ePHI) require protections to ensure
ePHI has not been altered or destroyed in an unauthorised manner.
Concord verifies every S3 bucket tagged ephi=true has versioning
enabled and Object Lock (or, at minimum, MFA-Delete) configured.

## Why it matters

Without versioning + Object Lock, a single compromised credential
can silently overwrite an ePHI object and the prior version is
unrecoverable. Object Lock in Compliance mode is the strongest
integrity guarantee AWS provides — even AWS root cannot delete a
locked object before its retention expires.

## Evidence

Collected from the `aws` source (`s3_bucket_integrity` evidence type).

## What a failure looks like

This control reports a finding when any of the following hold:

- no S3 integrity evidence collected
- ePHI bucket <value> has versioning disabled — overwrites are unrecoverable
- ePHI bucket <value> has neither Object Lock nor MFA-Delete configured — integrity guarantee insufficient
- ePHI bucket <value> Object Lock is in GOVERNANCE mode — switch to COMPLIANCE for tamper-resistance against AWS root

## Remediation

Bring each affected resource or attestation listed under *What a failure looks like* into compliance, then re-collect evidence. Estimated effort: **2h**. Automated fix available: **true**.

## How to re-verify

```
concord check --controls <pack>/controls --framework hipaa --control-id HIPAA-164.312-integrity
```

A passing run reports this control green; in CI, `concord gate` exits non-zero while it fails.

## Cross-framework mappings

```
  hipaa:
  - "164.312(c)(1)"
  - "164.312(c)(2)"
  soc2:
  - "PI1.1"
  - "P4.2"
  nist_800_53:
  - "SI-7"
  - "AU-9"
  iso27001:
  - "A.8.12"
```
