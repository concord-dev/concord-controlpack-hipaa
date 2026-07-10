# A workstation use policy defines acceptable functions and approved locations for ePHI access

`HIPAA-164.310b-workstation-use` · framework **hipaa** · severity **medium** · Physical Safeguards

## What this control checks

HIPAA Security Rule §164.310(b) (Workstation Use) requires policies and
procedures that specify the proper functions to be performed, the manner in
which those functions are performed, and the physical attributes of the
surroundings of any workstation or class of workstation that can access ePHI.
Concord evaluates a signed, version-controlled attestation of the workstation
use policy. The attestation must enumerate acceptable uses, prohibited uses,
and the approved physical locations for ePHI access, and it must be reviewed
at least annually and cosign-verified.

## Why it matters

Workstations are where ePHI is most often viewed, and a clear use policy is
what lets the workforce distinguish permitted work from risky behavior such as
accessing ePHI over public Wi-Fi or on shared kiosks. Auditors expect an
owner-attributed policy that states what may and may not be done on
ePHI-capable workstations and where they may be used, reviewed within the last
twelve months.

## Evidence

Collected from the `github` source (`file_glob` evidence type).

## What a failure looks like

This control reports a finding when any of the following hold:

- no workstation-use attestation evidence collected
- no workstation-use attestation document found at the configured repository path
- workstation-use attestation is missing required field <value>
- workstation-use attestation last reviewed <value> days ago — HIPAA §164.310(b) expects at least annual review
- workstation-use attestation cosign signature did not verify

## Remediation

Bring each affected resource or attestation listed under *What a failure looks like* into compliance, then re-collect evidence. Estimated effort: **1d**. Automated fix available: **false**.

## How to re-verify

```
concord check --controls <pack>/controls --framework hipaa --control-id HIPAA-164.310b-workstation-use
```

A passing run reports this control green; in CI, `concord gate` exits non-zero while it fails.

## Cross-framework mappings

```
  hipaa:
  - "164.310(b)"
  soc2:
  - "CC5.3"
  nist_800_53:
  - "PL-4"
  iso27001:
  - "A.8.1"
```
