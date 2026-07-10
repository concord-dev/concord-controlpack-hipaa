# Current risk analysis and risk-management plan are documented and reviewed annually

`HIPAA-164.308-risk-management` · framework **hipaa** · severity **high** · Administrative Safeguards

## What this control checks

HIPAA Security Rule §164.308(a)(1)(ii)(A) (Risk Analysis) and
§164.308(a)(1)(ii)(B) (Risk Management) require an accurate and
thorough assessment of risks to ePHI plus a documented plan to
reduce those risks to a reasonable level. Concord reads a signed
attestation file (cosign-verified) from the policy repository
that records the last-reviewed date, the reviewer, and the
risk-treatment plan summary.

## Why it matters

HHS guidance is explicit that risk analysis is the foundational
HIPAA Security Rule control — every other §164.308 implementation
specification flows from it. Auditors expect the document to be
current (reviewed within the last 12 months), authored by an
accountable owner, and traceable to the risks in Concord's risk
register.

## Evidence

Collected from the `github` source (`file_glob` evidence type).

## What a failure looks like

This control reports a finding when any of the following hold:

- no risk-analysis attestation file found at policies/risk-analysis.yaml
- no risk-analysis attestation document found at the configured path
- risk-analysis attestation is missing required field <value>
- risk-analysis last reviewed <value> days ago — HIPAA requires annual review
- risk-analysis attestation cosign signature did not verify
- risk-analysis document has no linked risks in the Concord risk register — add `concord risk add ... --link-attestation`

## Remediation

Bring each affected resource or attestation listed under *What a failure looks like* into compliance, then re-collect evidence. Estimated effort: **2d**. Automated fix available: **false**.

## How to re-verify

```
concord check --controls <pack>/controls --framework hipaa --control-id HIPAA-164.308-risk-management
```

A passing run reports this control green; in CI, `concord gate` exits non-zero while it fails.

## Cross-framework mappings

```
  hipaa:
  - "164.308(a)(1)(ii)(A)"
  - "164.308(a)(1)(ii)(B)"
  soc2:
  - "CC3.1"
  nist_800_53:
  - "RA-3"
  iso27001:
  - "A.5.1"
  - "A.5.4"
```
