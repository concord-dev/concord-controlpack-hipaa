# Terminated workforce members have no active identity-provider access

`HIPAA-164.308-workforce-termination` · framework **hipaa** · severity **critical** · Administrative Safeguards

## What this control checks

HIPAA Security Rule §164.308(a)(3)(ii)(C) (Termination Procedures)
requires that access to ePHI be terminated when a workforce member's
employment ends. Concord queries the identity provider for every
user marked SUSPENDED, DEPROVISIONED, or DELETED in the last 30
days, and verifies the user has no active session, no active
application assignments, and no admin role memberships.

## Why it matters

Lingering identity-provider access for terminated employees is
one of the most common HIPAA-breach root causes. The 24-hour
window between termination and last-access-revocation is the
operational floor most OCR audits enforce.

## Evidence

Collected from the `okta` source (`terminated_users` evidence type).

## What a failure looks like

This control reports a finding when any of the following hold:

- no Okta termination evidence collected
- terminated user <value> still has an active session
- terminated user <value> still has <value> active application assignment(s)
- terminated user <value> still has admin role(s): <value>
- terminated user <value> access was revoked <value> hours after termination (HIPAA floor is <value>)

## Remediation

Bring each affected resource or attestation listed under *What a failure looks like* into compliance, then re-collect evidence. Estimated effort: **30m**. Automated fix available: **false**.

## How to re-verify

```
concord check --controls <pack>/controls --framework hipaa --control-id HIPAA-164.308-workforce-termination
```

A passing run reports this control green; in CI, `concord gate` exits non-zero while it fails.

## Cross-framework mappings

```
  hipaa:
  - "164.308(a)(3)(ii)(C)"
  soc2:
  - "CC6.3"
  nist_800_53:
  - "PS-4"
  - "AC-2(3)"
  iso27001:
  - "A.6.5"
```
