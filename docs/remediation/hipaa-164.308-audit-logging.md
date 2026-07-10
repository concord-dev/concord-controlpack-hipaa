# CloudTrail is multi-region, log-file-validated, and recording management + data events

`HIPAA-164.308-audit-logging` · framework **hipaa** · severity **critical** · Administrative Safeguards

## What this control checks

HIPAA Security Rule §164.308(a)(1)(ii)(D) (Information System
Activity Review) requires regular review of records of information
system activity such as audit logs, access reports, and security
incident tracking reports. Concord verifies that AWS CloudTrail
covers every region of the account, validates log integrity,
and records both management and data-plane events.

## Why it matters

OCR's HIPAA enforcement consistently cites missing or partial
CloudTrail coverage as a §164.308 finding. Without log-file
validation, log integrity cannot be defended in a breach
investigation; without data events, S3-object-level ePHI access
is invisible.

## Evidence

Collected from the `aws` source (`cloudtrail_trails` evidence type).

## What a failure looks like

This control reports a finding when any of the following hold:

- no CloudTrail evidence collected (AWS collector misconfigured or no credentials)
- no multi-region CloudTrail trail is logging — HIPAA §164.308(a)(1)(ii)(D) requires audit coverage across every region
- trail <value> has log-file validation disabled — integrity cannot be defended in a breach investigation
- trail <value> does not record S3 data events — object-level ePHI access will be invisible

## Remediation

Bring each affected resource or attestation listed under *What a failure looks like* into compliance, then re-collect evidence. Estimated effort: **2h**. Automated fix available: **false**.

## How to re-verify

```
concord check --controls <pack>/controls --framework hipaa --control-id HIPAA-164.308-audit-logging
```

A passing run reports this control green; in CI, `concord gate` exits non-zero while it fails.

## Cross-framework mappings

```
  hipaa:
  - "164.308(a)(1)(ii)(D)"
  soc2:
  - "CC4.1"
  - "CC7.2"
  nist_800_53:
  - "AU-2"
  - "AU-12"
  iso27001:
  - "A.8.15"
  pci_dss:
  - "10.2"
```
