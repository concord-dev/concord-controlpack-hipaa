# Every workstation that can access ePHI is disk-encrypted and MDM-enrolled

`HIPAA-164.310c-workstation-security` · framework **hipaa** · severity **high** · Physical Safeguards

## What this control checks

HIPAA Security Rule §164.310(c) (Workstation Security) requires physical
safeguards for all workstations that access ePHI so that access is restricted
to authorized users. Concord reads the managed-device inventory from the
identity/MDM provider and fails any device flagged as accessing ePHI that is
not centrally managed (MDM-enrolled) or does not have full-disk encryption
enabled. The check is fail-closed: if no device inventory is collected the
control denies rather than passing silently.

## Why it matters

Laptops and desktops that reach ePHI are the endpoints most likely to be lost
or stolen, and an unencrypted or unmanaged device turns a lost laptop into a
reportable breach. Full-disk encryption renders the data unreadable to a
thief, and MDM enrollment gives the organization the ability to enforce
configuration and remotely wipe the device — together they are the baseline
§164.310(c) safeguard for ePHI-capable workstations.

## Evidence

Collected from the `okta` source (`device_inventory` evidence type).

## What a failure looks like

This control reports a finding when any of the following hold:

- no managed-device inventory evidence collected
- workstation <value> accesses ePHI without full-disk encryption enabled — HIPAA §164.310(c)
- workstation <value> accesses ePHI without MDM enrollment — HIPAA §164.310(c)

## Remediation

Bring each affected resource or attestation listed under *What a failure looks like* into compliance, then re-collect evidence. Estimated effort: **2d**. Automated fix available: **false**.

## How to re-verify

```
concord check --controls <pack>/controls --framework hipaa --control-id HIPAA-164.310c-workstation-security
```

A passing run reports this control green; in CI, `concord gate` exits non-zero while it fails.

## Cross-framework mappings

```
  hipaa:
  - "164.310(c)"
  soc2:
  - "CC6.7"
  nist_800_53:
  - "AC-19"
  - "SC-28"
  iso27001:
  - "A.8.1"
```
