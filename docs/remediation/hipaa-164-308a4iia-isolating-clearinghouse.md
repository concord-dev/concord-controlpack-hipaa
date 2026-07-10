# Healthcare clearinghouse functions are isolated, or non-applicability is justified

`HIPAA-164.308a4iiA-isolating-clearinghouse` · framework **hipaa** · severity **medium** · Administrative Safeguards

## What this control checks

HIPAA Security Rule §164.308(a)(4)(ii)(A) (Isolating Health Care
Clearinghouse Functions) is an addressable specification: if a health care
clearinghouse is part of a larger organization, it must implement policies
and procedures that protect the ePHI of the clearinghouse from
unauthorized access by the larger organization. This control reads a
signed attestation from the policy repository. When clearinghouse
functions are performed it confirms the isolation controls are documented;
when they are not, it requires an explicit applicability=false declaration
with a written justification. Either way the attestation must be current
and signed.

## Why it matters

Applicability is itself the audit question here: an organization cannot
silently skip an addressable specification. If it performs clearinghouse
functions, the larger organization must be walled off from that ePHI, and
the isolation controls must be named. If it does not, OCR still expects a
documented, reasoned determination on file rather than an unstated
assumption. This control denies both a claimed-applicable document with no
isolation controls and a not-applicable document with no justification, so
a blank field can never masquerade as compliance.

## Evidence

Collected from the `github` source (`file_glob` evidence type).

## What a failure looks like

This control reports a finding when any of the following hold:

- no clearinghouse-isolation attestation found at policies/clearinghouse-isolation.yaml
- no clearinghouse-isolation attestation document found at the configured path
- clearinghouse-isolation attests applicability=true but lists no isolation_controls
- clearinghouse-isolation attests applicability=false but provides no justification
- clearinghouse-isolation last reviewed <value> days ago — HIPAA requires review at least every 365 days
- clearinghouse-isolation attestation signature did not verify
- clearinghouse-isolation was last reviewed <value> days ago — schedule the annual review before it lapses at 365 days

## Remediation

Bring each affected resource or attestation listed under *What a failure looks like* into compliance, then re-collect evidence. Estimated effort: **1d**. Automated fix available: **false**.

## How to re-verify

```
concord check --controls <pack>/controls --framework hipaa --control-id HIPAA-164.308a4iiA-isolating-clearinghouse
```

A passing run reports this control green; in CI, `concord gate` exits non-zero while it fails.

## Cross-framework mappings

```
  hipaa:
  - "164.308(a)(4)(ii)(A)"
  soc2:
  - "CC6.1"
  nist_800_53:
  - "SC-7"
  - "AC-4"
  iso27001:
  - "A.8.22"
```
