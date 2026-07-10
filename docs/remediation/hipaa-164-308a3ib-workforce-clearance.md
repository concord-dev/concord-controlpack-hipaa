# Workforce clearance procedure (background screening) is documented and current

`HIPAA-164.308a3iB-workforce-clearance` · framework **hipaa** · severity **medium** · Administrative Safeguards

## What this control checks

HIPAA Security Rule §164.308(a)(3)(ii)(B) (Workforce Clearance Procedure)
is an addressable specification requiring procedures to determine that a
workforce member's access to ePHI is appropriate. In practice this is the
pre-access background-screening and clearance process. This control reads
a signed attestation from the policy repository and confirms it documents
the clearance procedure, the roles it applies to, and the screening
provider, and that it has been reviewed within the last year.

## Why it matters

Granting ePHI access before establishing that a person is suitable for it
inverts the trust model the Security Rule assumes. OCR and downstream
frameworks expect the clearance procedure to be written, to name the roles
in scope (so high-privilege roles are not quietly exempted), and to
identify who performs the screening so the control can be audited rather
than merely asserted. Stale or role-silent procedures are the failure
modes this control catches.

## Evidence

Collected from the `github` source (`file_glob` evidence type).

## What a failure looks like

This control reports a finding when any of the following hold:

- no workforce-clearance attestation found at policies/workforce-clearance.yaml
- no workforce-clearance attestation document found at the configured path
- workforce-clearance attestation is missing required field <value>
- workforce-clearance last reviewed <value> days ago — HIPAA requires review at least every 365 days
- workforce-clearance attestation signature did not verify
- workforce-clearance was last reviewed <value> days ago — schedule the annual review before it lapses at 365 days

## Remediation

Bring each affected resource or attestation listed under *What a failure looks like* into compliance, then re-collect evidence. Estimated effort: **1d**. Automated fix available: **false**.

## How to re-verify

```
concord check --controls <pack>/controls --framework hipaa --control-id HIPAA-164.308a3iB-workforce-clearance
```

A passing run reports this control green; in CI, `concord gate` exits non-zero while it fails.

## Cross-framework mappings

```
  hipaa:
  - "164.308(a)(3)(ii)(B)"
  soc2:
  - "CC1.4"
  nist_800_53:
  - "PS-3"
  iso27001:
  - "A.6.1"
```
