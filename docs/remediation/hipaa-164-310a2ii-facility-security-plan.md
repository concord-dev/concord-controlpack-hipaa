# A written facility security plan protects premises and equipment from theft and tampering

`HIPAA-164.310a2ii-facility-security-plan` · framework **hipaa** · severity **medium** · Physical Safeguards

## What this control checks

HIPAA Security Rule §164.310(a)(2)(ii) (Facility Security Plan) requires
policies and procedures to safeguard the facility and the equipment therein
from unauthorized physical access, tampering, and theft. Concord evaluates a
signed, version-controlled attestation of the written facility security plan.
The attestation must enumerate the physical safeguards protecting the premises
and the specific theft- and tamper-protection measures, and it must be reviewed
at least annually and cosign-verified.

## Why it matters

A facility security plan is the written blueprint that ties badge readers,
locks, cameras, alarms, and equipment tamper controls into a coherent program;
without it, individual measures drift and gaps go unnoticed. Auditors expect a
current, owner-attributed plan that names both the physical safeguards in place
and the concrete protections against theft and tampering of equipment that
stores or transmits ePHI.

## Evidence

Collected from the `github` source (`file_glob` evidence type).

## What a failure looks like

This control reports a finding when any of the following hold:

- no facility-security-plan attestation evidence collected
- no facility-security-plan attestation document found at the configured repository path
- facility-security-plan attestation is missing required field <value>
- facility-security-plan attestation last reviewed <value> days ago — HIPAA §164.310(a)(2)(ii) expects at least annual review
- facility-security-plan attestation cosign signature did not verify

## Remediation

Bring each affected resource or attestation listed under *What a failure looks like* into compliance, then re-collect evidence. Estimated effort: **1d**. Automated fix available: **false**.

## How to re-verify

```
concord check --controls <pack>/controls --framework hipaa --control-id HIPAA-164.310a2ii-facility-security-plan
```

A passing run reports this control green; in CI, `concord gate` exits non-zero while it fails.

## Cross-framework mappings

```
  hipaa:
  - "164.310(a)(2)(ii)"
  soc2:
  - "CC6.4"
  nist_800_53:
  - "PE-3"
  - "PE-6"
  iso27001:
  - "A.7.1"
  - "A.7.4"
```
