# ePHI data stores have automated backups with HIPAA-grade retention

`HIPAA-164.308-data-backup` · framework **hipaa** · severity **critical** · Administrative Safeguards

## What this control checks

HIPAA Security Rule §164.308(a)(7)(ii)(A) (Data Backup Plan)
requires retrievable exact copies of ePHI. Concord verifies that
every RDS instance and DynamoDB table tagged ephi=true has
automated backups enabled with retention ≥ 35 days, and that
AWS Backup vault locking is configured for tamper-resistance.

## Why it matters

Ransomware-encrypted backups are the most common cause of HIPAA
breach-notification events. AWS Backup with vault locking +
point-in-time recovery is the operational floor that OCR auditors
accept for ePHI.

## Evidence

Collected from the `aws` source (`backup_status` evidence type).

## What a failure looks like

This control reports a finding when any of the following hold:

- no backup evidence collected
- ePHI RDS instance <value> has backup retention <value> days (HIPAA floor is <value>)
- ePHI DynamoDB table <value> has point-in-time recovery disabled
- backup vault <value> holds ePHI but is not vault-locked (tamper-resistant retention required)
- backup vault <value> is locked but not KMS-encrypted (use a customer-managed key)

## Remediation

Bring each affected resource or attestation listed under *What a failure looks like* into compliance, then re-collect evidence. Estimated effort: **4h**. Automated fix available: **false**.

## How to re-verify

```
concord check --controls <pack>/controls --framework hipaa --control-id HIPAA-164.308-data-backup
```

A passing run reports this control green; in CI, `concord gate` exits non-zero while it fails.

## Cross-framework mappings

```
  hipaa:
  - "164.308(a)(7)(ii)(A)"
  soc2:
  - "A1.2"
  nist_800_53:
  - "CP-9"
  - "CP-10"
  iso27001:
  - "A.8.13"
```
