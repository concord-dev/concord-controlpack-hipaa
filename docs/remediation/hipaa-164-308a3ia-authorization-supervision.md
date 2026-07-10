# Workforce authorization and supervision policy is documented and current

`HIPAA-164.308a3iA-authorization-supervision` · framework **hipaa** · severity **medium** · Administrative Safeguards

## What this control checks

HIPAA Security Rule §164.308(a)(3)(i) (Workforce Security) and its
addressable specification §164.308(a)(3)(ii)(A) (Authorization and/or
Supervision) require the organization to ensure that workforce members
have appropriate access to ePHI and that those working in areas where ePHI
might be accessed are supervised. This control reads a signed attestation
from the policy repository and confirms it documents how access is
authorized, how workforce members are supervised, and which role approves
access — and that it has been reviewed within the last year.

## Why it matters

Authorization and supervision are the front door to every downstream
access control: if there is no documented, owner-approved process for
granting and overseeing access, then least-privilege, termination, and
audit controls have nothing to enforce against. Auditors look for a named
approving authority and a written supervision process, because "everyone
is an admin" and unsupervised contractor access are recurring root causes
of ePHI exposure.

## Evidence

Collected from the `github` source (`file_glob` evidence type).

## What a failure looks like

This control reports a finding when any of the following hold:

- no authorization-and-supervision attestation found at policies/workforce-authorization-supervision.yaml
- no authorization-and-supervision attestation document found at the configured path
- authorization-and-supervision attestation is missing required field <value>
- authorization-and-supervision last reviewed <value> days ago — HIPAA requires review at least every 365 days
- authorization-and-supervision attestation signature did not verify
- authorization-and-supervision was last reviewed <value> days ago — schedule the annual review before it lapses at 365 days

## Remediation

Bring each affected resource or attestation listed under *What a failure looks like* into compliance, then re-collect evidence. Estimated effort: **1d**. Automated fix available: **false**.

## How to re-verify

```
concord check --controls <pack>/controls --framework hipaa --control-id HIPAA-164.308a3iA-authorization-supervision
```

A passing run reports this control green; in CI, `concord gate` exits non-zero while it fails.

## Cross-framework mappings

```
  hipaa:
  - "164.308(a)(3)(i)"
  - "164.308(a)(3)(ii)(A)"
  soc2:
  - "CC6.3"
  nist_800_53:
  - "AC-2"
  - "PS-2"
  iso27001:
  - "A.5.15"
  - "A.5.18"
```
