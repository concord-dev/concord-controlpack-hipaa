# Every business associate has a current signed BAA on file

`HIPAA-164.308b1-business-associate-contracts` · framework **hipaa** · severity **high** · Administrative Safeguards

## What this control checks

HIPAA Security Rule §164.308(b)(1) (Business Associate Contracts and Other
Arrangements) permits a covered entity to disclose ePHI to a business
associate only if it obtains satisfactory assurances, documented in a
written contract, that the associate will appropriately safeguard the
information. Concord reads a business-associate register from the policy
repository and checks every associate individually: each must have a
signed BAA with a non-empty, unexpired effective term. A per-associate
check is used deliberately so a single missing or lapsed agreement cannot
be masked by an otherwise healthy register.

## Why it matters

Disclosing ePHI to a vendor without a current signed BAA is a direct HIPAA
violation and a recurring source of OCR settlements. Registers drift as
vendors are added and contracts renew, so a single "we have BAAs"
attestation is not trustworthy. Evaluating each associate for a signed
flag and a live expiry date surfaces exactly which relationship is out of
compliance and needs remediation.

## Evidence

Collected from the `github` source (`file_glob` evidence type).

## What a failure looks like

This control reports a finding when any of the following hold:

- no business-associate agreement register evidence collected
- no business-associate agreement register document found at the configured repository path
- business associate <value> has no signed BAA (baa_signed is not true)
- business associate <value> BAA has no expiry date recorded
- business associate <value> BAA expired on <value>

## Remediation

Bring each affected resource or attestation listed under *What a failure looks like* into compliance, then re-collect evidence. Estimated effort: **2d**. Automated fix available: **false**.

## How to re-verify

```
concord check --controls <pack>/controls --framework hipaa --control-id HIPAA-164.308b1-business-associate-contracts
```

A passing run reports this control green; in CI, `concord gate` exits non-zero while it fails.

## Cross-framework mappings

```
  hipaa:
  - "164.308(b)(1)"
  - "164.314(a)(1)"
  soc2:
  - "CC9.2"
  nist_800_53:
  - "SA-9"
  iso27001:
  - "A.5.19"
  - "A.5.20"
```
