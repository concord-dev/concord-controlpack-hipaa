# HIPAA policies, procedures, and required documentation are retained for at least six years

`HIPAA-164.316b1-policies-and-procedures-retention` · framework **hipaa** · severity **medium** · Administrative Safeguards

## What this control checks

HIPAA Security Rule §164.316(b)(1) requires that the policies and procedures
implemented to comply with the Security Rule, and the documentation of
required actions, activities, and assessments, be maintained in writing.
§164.316(b)(2)(i) sets the retention period at six years from the date of
creation or the date it was last in effect, whichever is later. Concord
evaluates a signed, version-controlled attestation that records the enforced
retention period and an inventory of the retained documents, and fails if the
retention period is shorter than six years.

## Why it matters

OCR can request years of documentation during an investigation or audit, and
a retention window shorter than the six-year floor leaves the organization
unable to demonstrate that safeguards were in place at the relevant time.
Auditors expect an accountable owner, a documented retention period of at
least six years, and a maintained inventory of the policies and procedures
that are actually being retained, reviewed at least annually.

## Evidence

Collected from the `github` source (`file_glob` evidence type).

## What a failure looks like

This control reports a finding when any of the following hold:

- no policies-and-procedures-retention attestation evidence collected
- no policies-and-procedures-retention attestation document found at the configured repository path
- policies-and-procedures-retention attestation is missing required field <value>
- HIPAA documentation retention is set to <value> years — §164.316(b)(2)(i) requires at least 6 years
- policies-and-procedures-retention attestation last reviewed <value> days ago — expected at least annual review
- policies-and-procedures-retention attestation cosign signature did not verify

## Remediation

Bring each affected resource or attestation listed under *What a failure looks like* into compliance, then re-collect evidence. Estimated effort: **1d**. Automated fix available: **false**.

## How to re-verify

```
concord check --controls <pack>/controls --framework hipaa --control-id HIPAA-164.316b1-policies-and-procedures-retention
```

A passing run reports this control green; in CI, `concord gate` exits non-zero while it fails.

## Cross-framework mappings

```
  hipaa:
  - "164.316(b)(1)"
  - "164.316(b)(2)(i)"
  soc2:
  - "CC5.3"
  nist_800_53:
  - "SI-12"
  iso27001:
  - "A.5.33"
```
