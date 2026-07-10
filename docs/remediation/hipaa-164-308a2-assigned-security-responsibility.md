# A named Security Official is formally assigned responsibility for the HIPAA program

`HIPAA-164.308a2-assigned-security-responsibility` · framework **hipaa** · severity **high** · Administrative Safeguards

## What this control checks

HIPAA Security Rule §164.308(a)(2) (Assigned Security Responsibility) is a
required implementation specification: the organization must identify the
single security official who is responsible for the development and
implementation of the policies and procedures required by the Security
Rule. This control reads a signed attestation from the policy repository
and confirms it records the official's name, title, appointment date, and
the scope of their responsibilities, and that it has been reviewed within
the last year.

## Why it matters

A named, accountable owner is the anchor for every other Security Rule
safeguard — OCR investigators routinely ask "who is your Security
Official?" as the opening question of an audit, and an organization that
cannot point to one in writing has a per-se §164.308(a)(2) finding. Naming
a role rather than a person, or leaving the appointment stale after
turnover, are the two failure modes this control is designed to catch.

## Evidence

Collected from the `github` source (`file_glob` evidence type).

## What a failure looks like

This control reports a finding when any of the following hold:

- no assigned-security-responsibility attestation found at policies/security-official.yaml
- no assigned-security-responsibility attestation document found at the configured path
- assigned-security-responsibility attestation is missing required field <value>
- assigned-security-responsibility last reviewed <value> days ago — HIPAA requires review at least every 365 days
- assigned-security-responsibility attestation signature did not verify
- assigned-security-responsibility was last reviewed <value> days ago — reconfirm the appointment before it lapses at 365 days

## Remediation

Bring each affected resource or attestation listed under *What a failure looks like* into compliance, then re-collect evidence. Estimated effort: **1d**. Automated fix available: **false**.

## How to re-verify

```
concord check --controls <pack>/controls --framework hipaa --control-id HIPAA-164.308a2-assigned-security-responsibility
```

A passing run reports this control green; in CI, `concord gate` exits non-zero while it fails.

## Cross-framework mappings

```
  hipaa:
  - "164.308(a)(2)"
  soc2:
  - "CC1.3"
  nist_800_53:
  - "PM-2"
  iso27001:
  - "A.5.2"
```
