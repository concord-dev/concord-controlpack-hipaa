# Facility access during emergencies is documented and periodically tested

`HIPAA-164.310a2i-contingency-operations` · framework **hipaa** · severity **medium** · Physical Safeguards

## What this control checks

HIPAA Security Rule §164.310(a)(2)(i) (Contingency Operations) requires
procedures that allow facility access to support the restoration of lost
data under the disaster-recovery plan and emergency-mode operations plan
in the event of an emergency. Concord evaluates a signed, version-controlled
attestation of the emergency facility-access procedure. The attestation must
name the emergency access procedure and the responsible role, record when
the procedure was last exercised, and be reviewed at least annually and
cosign-verified.

## Why it matters

An emergency such as a fire, flood, or extended power loss can force
physical access to systems and backup media outside normal controls; if
that access is undocumented or has never been rehearsed, recovery stalls
and ePHI availability is lost. Auditors expect a named, accountable owner,
a written emergency access procedure, and evidence that it has been tested
within the last year so the plan works when it is actually needed.

## Evidence

Collected from the `github` source (`file_glob` evidence type).

## What a failure looks like

This control reports a finding when any of the following hold:

- no contingency-operations attestation evidence collected
- no contingency-operations attestation document found at the configured repository path
- contingency-operations attestation is missing required field <value>
- contingency-operations attestation last reviewed <value> days ago — HIPAA §164.310(a)(2)(i) expects at least annual review
- emergency facility-access procedure last tested <value> days ago — it must be exercised at least annually
- contingency-operations attestation cosign signature did not verify

## Remediation

Bring each affected resource or attestation listed under *What a failure looks like* into compliance, then re-collect evidence. Estimated effort: **1d**. Automated fix available: **false**.

## How to re-verify

```
concord check --controls <pack>/controls --framework hipaa --control-id HIPAA-164.310a2i-contingency-operations
```

A passing run reports this control green; in CI, `concord gate` exits non-zero while it fails.

## Cross-framework mappings

```
  hipaa:
  - "164.310(a)(2)(i)"
  soc2:
  - "A1.2"
  nist_800_53:
  - "CP-2"
  iso27001:
  - "A.5.29"
```
