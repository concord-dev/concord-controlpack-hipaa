# Access-revocation procedure for departing workforce is documented and current

`HIPAA-164.308a3iiC-termination-procedures` · framework **hipaa** · severity **high** · Administrative Safeguards

## What this control checks

HIPAA Security Rule §164.308(a)(3)(ii)(C) (Termination Procedures) is an
addressable specification requiring procedures for terminating access to
ePHI when a workforce member leaves or when their access is no longer
appropriate. This control reads a signed attestation from the policy
repository and confirms it documents the revocation steps, the target
completion SLA in hours, and the systems the procedure covers, and that it
has been reviewed within the last year. It complements the technical
workforce-termination control by verifying that the governing procedure
itself exists and is maintained.

## Why it matters

Orphaned accounts and lingering access after departure are among the most
frequently cited findings in OCR investigations and breach post-mortems.
A credible termination procedure names the concrete steps, a measurable
time bound, and the full set of systems in scope — otherwise "we revoke
access on termination" is unverifiable. This control checks that the
procedure is specific, time-bound, and current rather than aspirational.

## Evidence

Collected from the `github` source (`file_glob` evidence type).

## What a failure looks like

This control reports a finding when any of the following hold:

- no termination-procedure attestation found at policies/access-termination-procedure.yaml
- no termination-procedure attestation document found at the configured path
- termination-procedure attestation is missing required field <value>
- termination-procedure sla_hours must be a numeric value expressed in hours
- termination-procedure last reviewed <value> days ago — HIPAA requires review at least every 365 days
- termination-procedure attestation signature did not verify
- termination-procedure allows <value> hours to revoke access — OCR guidance expects prompt, typically same-day, deactivation

## Remediation

Bring each affected resource or attestation listed under *What a failure looks like* into compliance, then re-collect evidence. Estimated effort: **1d**. Automated fix available: **false**.

## How to re-verify

```
concord check --controls <pack>/controls --framework hipaa --control-id HIPAA-164.308a3iiC-termination-procedures
```

A passing run reports this control green; in CI, `concord gate` exits non-zero while it fails.

## Cross-framework mappings

```
  hipaa:
  - "164.308(a)(3)(ii)(C)"
  soc2:
  - "CC6.2"
  - "CC6.3"
  nist_800_53:
  - "PS-4"
  - "AC-2"
  iso27001:
  - "A.6.5"
```
