# A periodic technical and non-technical security evaluation is performed and remediated

`HIPAA-164.308a8-evaluation` · framework **hipaa** · severity **medium** · Administrative Safeguards

## What this control checks

HIPAA Security Rule §164.308(a)(8) (Evaluation) requires a periodic
technical and non-technical evaluation, based initially on the standards
of the Security Rule and subsequently on environmental or operational
changes, that establishes the extent to which an entity's safeguards meet
the rule's requirements. Concord reads a cosign-verified attestation
recording the date of the last evaluation, who performed it, its scope,
and whether the resulting findings were remediated.

## Why it matters

An evaluation is only meaningful if it is current, independent, scoped to
the systems that handle ePHI, and — critically — acted upon. A finding
that is identified but never remediated leaves the same gap an auditor
would cite. Concord therefore fails the control when the evaluation is
missing, stale beyond twelve months, lacks a named evaluator or scope, or
when the attestation does not confirm that findings were remediated.

## Evidence

Collected from the `github` source (`file_glob` evidence type).

## What a failure looks like

This control reports a finding when any of the following hold:

- no security-evaluation attestation collected
- no security-evaluation attestation document found at the configured repository path
- security-evaluation attestation is missing required field <value>
- security-evaluation attestation does not confirm findings were remediated (findings_remediated)
- security evaluation last performed <value> days ago — HIPAA requires periodic re-evaluation
- security-evaluation attestation cosign signature did not verify

## Remediation

Bring each affected resource or attestation listed under *What a failure looks like* into compliance, then re-collect evidence. Estimated effort: **3d**. Automated fix available: **false**.

## How to re-verify

```
concord check --controls <pack>/controls --framework hipaa --control-id HIPAA-164.308a8-evaluation
```

A passing run reports this control green; in CI, `concord gate` exits non-zero while it fails.

## Cross-framework mappings

```
  hipaa:
  - "164.308(a)(8)"
  soc2:
  - "CC4.1"
  nist_800_53:
  - "CA-2"
  - "CA-7"
  iso27001:
  - "A.5.35"
  - "A.5.36"
```
