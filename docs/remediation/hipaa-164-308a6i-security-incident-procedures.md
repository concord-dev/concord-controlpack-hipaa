# A documented incident-response procedure exists and is reviewed annually

`HIPAA-164.308a6i-security-incident-procedures` · framework **hipaa** · severity **high** · Administrative Safeguards

## What this control checks

HIPAA Security Rule §164.308(a)(6)(i) (Security Incident Procedures)
requires covered entities and business associates to implement policies
and procedures to address security incidents. Concord reads a
cosign-verified attestation from the policy repository that records the
procedure's scope, the roles and responsibilities of responders, how
incidents are detected and reported, and the escalation path. The
procedure must have been both reviewed and exercised within the last
twelve months.

## Why it matters

Under §164.308(a)(6)(ii) an entity must identify, respond to, mitigate,
and document security incidents; that is impossible without a written
procedure that names owners and an escalation path in advance of an
event. OCR breach investigations consistently penalise organisations that
cannot produce a current, tested incident-response plan, so Concord fails
the control when any required element is missing, when the plan is stale,
or when the attestation signature does not verify.

## Evidence

Collected from the `github` source (`file_glob` evidence type).

## What a failure looks like

This control reports a finding when any of the following hold:

- no incident-response procedure attestation collected
- no incident-response procedure document found at the configured path
- incident-response procedure attestation is missing required field <value>
- incident-response procedure last reviewed <value> days ago — HIPAA requires annual review
- incident-response procedure attestation cosign signature did not verify

## Remediation

Bring each affected resource or attestation listed under *What a failure looks like* into compliance, then re-collect evidence. Estimated effort: **3d**. Automated fix available: **false**.

## How to re-verify

```
concord check --controls <pack>/controls --framework hipaa --control-id HIPAA-164.308a6i-security-incident-procedures
```

A passing run reports this control green; in CI, `concord gate` exits non-zero while it fails.

## Cross-framework mappings

```
  hipaa:
  - "164.308(a)(6)(i)"
  - "164.308(a)(6)(ii)"
  soc2:
  - "CC7.3"
  - "CC7.4"
  nist_800_53:
  - "IR-4"
  - "IR-8"
  iso27001:
  - "A.5.24"
  - "A.5.26"
```
