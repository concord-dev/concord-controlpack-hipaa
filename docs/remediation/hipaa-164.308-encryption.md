# All ePHI data stores have encryption-at-rest enabled

`HIPAA-164.308-encryption` · framework **hipaa** · severity **critical** · Administrative Safeguards

## What this control checks

HIPAA Security Rule §164.308(a)(4)(ii)(B) (Information Access Management
implementation specifications) combined with §164.312(a)(2)(iv)
(Encryption and Decryption) requires that ePHI at rest be encrypted.
Concord verifies S3 buckets, RDS instances, and EBS volumes tagged
ephi=true have encryption-at-rest enabled with KMS.

## Why it matters

Encryption-at-rest is the single most-cited HIPAA technical safeguard
during OCR audits. Unencrypted ePHI is the trigger for breach
notification under the Breach Notification Rule.

## Evidence

Collected from the `aws` source (`storage_encryption` evidence type).

## What a failure looks like

This control reports a finding when any of the following hold:

- no encryption evidence collected
- ePHI bucket <value> has no encryption-at-rest configured
- ePHI RDS instance <value> has no encryption-at-rest
- ePHI EBS volume <value> has no encryption-at-rest

## Remediation

Bring each affected resource or attestation listed under *What a failure looks like* into compliance, then re-collect evidence. Estimated effort: **1d**. Automated fix available: **false**.

## How to re-verify

```
concord check --controls <pack>/controls --framework hipaa --control-id HIPAA-164.308-encryption
```

A passing run reports this control green; in CI, `concord gate` exits non-zero while it fails.

## Cross-framework mappings

```
  hipaa:
  - "164.308(a)(4)(ii)(B)"
  - "164.312(a)(2)(iv)"
  soc2:
  - "C1.1"
```
