# Risk analysis covering ePHI confidentiality, integrity, and availability is current

`HIPAA-164.308a1ii-risk-analysis` · framework **hipaa** · severity **high** · Administrative Safeguards

## What this control checks

HIPAA Security Rule §164.308(a)(1)(ii)(A) (Risk Analysis) requires an
accurate and thorough assessment of the potential risks and
vulnerabilities to the confidentiality, integrity, and availability of all
ePHI the organization creates, receives, maintains, or transmits. This
control reads a signed risk-analysis attestation from the policy
repository and confirms it enumerates the assessment scope, the assets in
scope, the threats and vulnerabilities identified, and the method used to
rate likelihood and impact. It is deliberately distinct from the
risk-management plan under §164.308(a)(1)(ii)(B): this control verifies the
analysis itself, not the treatment of the risks it surfaces.

## Why it matters

OCR treats risk analysis as the foundational safeguard of the entire
Security Rule — the majority of corrective-action plans in OCR enforcement
settlements cite an incomplete, out-of-date, or organization-wide-in-name-only
risk analysis as a root cause. Auditors expect the analysis to cover every
system that touches ePHI rather than a single application, to be reviewed at
least annually, and to carry an accountable owner's verified signature so its
conclusions can be relied on by the downstream risk-management plan.

## Evidence

Collected from the `github` source (`file_glob` evidence type).

## What a failure looks like

This control reports a finding when any of the following hold:

- no risk-analysis attestation found at policies/risk-analysis.yaml
- no risk-analysis attestation document found at the configured path
- risk-analysis attestation is missing required field <value>
- risk-analysis last reviewed <value> days ago — HIPAA requires review at least every 365 days
- risk-analysis attestation signature did not verify
- risk-analysis was last reviewed <value> days ago — schedule the annual review before it lapses at 365 days

## Remediation

Bring each affected resource or attestation listed under *What a failure looks like* into compliance, then re-collect evidence. Estimated effort: **2d**. Automated fix available: **false**.

## How to re-verify

```
concord check --controls <pack>/controls --framework hipaa --control-id HIPAA-164.308a1ii-risk-analysis
```

A passing run reports this control green; in CI, `concord gate` exits non-zero while it fails.

## Cross-framework mappings

```
  hipaa:
  - "164.308(a)(1)(ii)(A)"
  soc2:
  - "CC3.1"
  - "CC3.2"
  nist_800_53:
  - "RA-3"
  iso27001:
  - "A.5.9"
  - "A.8.8"
```
