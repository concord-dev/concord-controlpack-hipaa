# Business associate agreements cover the required administrative-safeguard clauses

`HIPAA-164.314a1-baa-administrative-safeguards` · framework **hipaa** · severity **medium** · Administrative Safeguards

## What this control checks

HIPAA Security Rule §164.314(a)(1) (Organizational Requirements — Business
Associate Contracts) requires that the contract between a covered entity
and a business associate include specific assurances: that the associate
will implement safeguards protecting ePHI, report security incidents,
ensure any subcontractors agree to the same restrictions, and authorize
termination of the contract for material breach. Concord reads a
cosign-verified attestation confirming that the organisation's BAA
template covers each of these clauses and was reviewed within the year.

## Why it matters

A signed BAA that omits the safeguards, breach-notification,
subcontractor-flowdown, or termination clauses fails to provide the
"satisfactory assurances" the rule demands, leaving the covered entity
liable for the associate's conduct. Verifying clause coverage per topic —
rather than trusting that a contract exists — catches template drift and
ensures the flowdown obligations that protect ePHI down the subcontractor
chain are actually present.

## Evidence

Collected from the `github` source (`file_glob` evidence type).

## What a failure looks like

This control reports a finding when any of the following hold:

- no BAA clause-coverage attestation collected
- no BAA clause-coverage attestation document found at the configured repository path
- business associate agreement does not cover required clause <value>
- BAA clause-coverage attestation is missing required field "last_reviewed_at"
- BAA clause coverage last reviewed <value> days ago — review the BAA template at least annually
- BAA clause-coverage attestation cosign signature did not verify

## Remediation

Bring each affected resource or attestation listed under *What a failure looks like* into compliance, then re-collect evidence. Estimated effort: **2d**. Automated fix available: **false**.

## How to re-verify

```
concord check --controls <pack>/controls --framework hipaa --control-id HIPAA-164.314a1-baa-administrative-safeguards
```

A passing run reports this control green; in CI, `concord gate` exits non-zero while it fails.

## Cross-framework mappings

```
  hipaa:
  - "164.314(a)(1)"
  - "164.314(a)(2)(i)"
  soc2:
  - "CC9.2"
  nist_800_53:
  - "SA-9"
  iso27001:
  - "A.5.20"
```
