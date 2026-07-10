# Facility access controls limit physical access to systems storing ePHI

`HIPAA-164.310a1-facility-access-controls` · framework **hipaa** · severity **high** · Physical Safeguards

## What this control checks

HIPAA Security Rule §164.310(a)(1) (Facility Access Controls) requires
policies and procedures that limit physical access to the electronic
information systems that house ePHI and the facilities in which they are
housed, while ensuring properly authorized access is allowed. Data-center
badge readers and visitor logs are not reachable as cloud telemetry, so
Concord evaluates a signed, version-controlled attestation of the facility
access program. The attestation must be current, cosign-verified, and
enumerate the access-control measures, the roles authorized for entry, and
the visitor-handling policy.

## Why it matters

Physical access to servers, backup media, or network closets bypasses
every logical safeguard protecting ePHI, and OCR investigations routinely
cite uncontrolled facility access as a §164.310(a)(1) failure. Auditors
expect a documented program that names the authorized roles, describes the
controls that enforce entry restrictions (badge readers, locked cages,
escort rules), governs visitors, and is reviewed at least annually by an
accountable owner.

## Evidence

Collected from the `github` source (`file_glob` evidence type).

## What a failure looks like

This control reports a finding when any of the following hold:

- no facility-access-controls attestation evidence collected
- no facility-access-controls attestation document found at the configured repository path
- facility-access-controls attestation is missing required field <value>
- facility-access-controls attestation last reviewed <value> days ago — HIPAA §164.310(a)(1) expects at least annual review
- facility-access-controls attestation cosign signature did not verify

## Remediation

Bring each affected resource or attestation listed under *What a failure looks like* into compliance, then re-collect evidence. Estimated effort: **1d**. Automated fix available: **false**.

## How to re-verify

```
concord check --controls <pack>/controls --framework hipaa --control-id HIPAA-164.310a1-facility-access-controls
```

A passing run reports this control green; in CI, `concord gate` exits non-zero while it fails.

## Cross-framework mappings

```
  hipaa:
  - "164.310(a)(1)"
  soc2:
  - "CC6.4"
  nist_800_53:
  - "PE-3"
  iso27001:
  - "A.7.2"
```
