# A contingency plan covering data backup, disaster recovery, and emergency mode is current

`HIPAA-164.308a7i-contingency-plan` · framework **hipaa** · severity **high** · Administrative Safeguards

## What this control checks

HIPAA Security Rule §164.308(a)(7)(i) (Contingency Plan) requires policies
and procedures for responding to an emergency or other occurrence that
damages systems containing ePHI. Its implementation specifications mandate
a data backup plan, a disaster recovery plan, and an emergency mode
operation plan. Concord reads a cosign-verified attestation recording each
of these plans plus the dates the contingency plan was last tested and
last reviewed, and fails when any element is missing or stale.

## Why it matters

Ransomware and infrastructure failures are leading causes of ePHI
unavailability, and §164.308(a)(7)(ii)(D) additionally requires periodic
testing and revision of contingency procedures. A backup that has never
been restore-tested, or a recovery plan that is more than a year old,
offers false assurance. Requiring all three plans, a recorded test date,
and a verifiable signature keeps the organisation's resilience posture
honest and auditable.

## Evidence

Collected from the `github` source (`file_glob` evidence type).

## What a failure looks like

This control reports a finding when any of the following hold:

- no contingency-plan attestation collected
- no contingency-plan attestation document found at the configured repository path
- contingency-plan attestation is missing required field <value>
- contingency plan last reviewed <value> days ago — HIPAA requires periodic review and testing
- contingency-plan attestation cosign signature did not verify

## Remediation

Bring each affected resource or attestation listed under *What a failure looks like* into compliance, then re-collect evidence. Estimated effort: **5d**. Automated fix available: **false**.

## How to re-verify

```
concord check --controls <pack>/controls --framework hipaa --control-id HIPAA-164.308a7i-contingency-plan
```

A passing run reports this control green; in CI, `concord gate` exits non-zero while it fails.

## Cross-framework mappings

```
  hipaa:
  - "164.308(a)(7)(i)"
  - "164.308(a)(7)(ii)(D)"
  soc2:
  - "A1.2"
  - "A1.3"
  nist_800_53:
  - "CP-2"
  - "CP-4"
  - "CP-9"
  iso27001:
  - "A.5.30"
  - "A.8.13"
```
