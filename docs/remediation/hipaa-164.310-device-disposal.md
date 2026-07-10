# Device and media disposal procedure is documented, reviewed, and tied to actual decommissioning events

`HIPAA-164.310-device-disposal` · framework **hipaa** · severity **high** · Physical Safeguards

## What this control checks

HIPAA Security Rule §164.310(d)(2)(i) (Disposal) and (d)(2)(ii)
(Media Re-use) require procedures for the disposal of ePHI and
for removing ePHI from electronic media before re-use. Concord
reads a signed attestation file listing the disposal procedure
+ the trailing-90-days disposal log so that policy and practice
are both verified.

## Why it matters

Cloud-only organisations still own physical devices (laptops,
on-prem disks, ad-hoc backups). OCR audits routinely catch
organisations that have a written disposal policy but no
evidence the policy was followed. The attestation pattern lets
Concord verify both the policy version and the disposal log
in one read.

## Evidence

Collected from the `github` source (`file_glob` evidence type).

## What a failure looks like

This control reports a finding when any of the following hold:

- no device-disposal attestation file found at policies/device-disposal.yaml
- no device-disposal attestation document found at the configured path
- device-disposal attestation is missing required field <value>
- sanitisation method <value> is not a NIST 800-88 approved technique
- device-disposal policy last reviewed <value> days ago — annual review required
- device-disposal attestation cosign signature did not verify
- device-disposal log is empty — policy without execution evidence will draw an audit finding

## Remediation

Bring each affected resource or attestation listed under *What a failure looks like* into compliance, then re-collect evidence. Estimated effort: **1d**. Automated fix available: **false**.

## How to re-verify

```
concord check --controls <pack>/controls --framework hipaa --control-id HIPAA-164.310-device-disposal
```

A passing run reports this control green; in CI, `concord gate` exits non-zero while it fails.

## Cross-framework mappings

```
  hipaa:
  - "164.310(d)(2)(i)"
  - "164.310(d)(2)(ii)"
  soc2:
  - "P4.2"
  nist_800_53:
  - "MP-6"
  iso27001:
  - "A.7.10"
  - "A.7.14"
```
