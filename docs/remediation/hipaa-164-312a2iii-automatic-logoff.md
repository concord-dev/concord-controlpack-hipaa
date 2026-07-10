# ePHI-scoped IAM roles cap session duration to enforce automatic logoff

`HIPAA-164.312a2iii-automatic-logoff` · framework **hipaa** · severity **medium** · Technical Safeguards

## What this control checks

HIPAA Security Rule §164.312(a)(2)(iii) (Automatic Logoff) requires
electronic procedures that terminate an electronic session after a
predetermined time of inactivity. For federated and assumed AWS access,
the ceiling on a session is the role's MaxSessionDuration. Concord fails
any IAM role tagged ephi=true whose max_session_duration_seconds exceeds
the 3600-second (one-hour) threshold, and fails closed on any ePHI role
that does not publish a max session duration at all.

## Why it matters

A console or CLI session left open on an unattended workstation is a
direct exposure of ePHI; the shorter the maximum session, the smaller
that window. AWS defaults roles to a one-hour session but allows up to
twelve hours, and long-lived sessions are a recurring OCR finding because
they defeat the automatic-logoff safeguard. Bounding ePHI-scoped roles to
one hour forces re-authentication and keeps the effective session aligned
with §164.312(a)(2)(iii).

## Evidence

Collected from the `aws` source (`iam_roles` evidence type).

## What a failure looks like

This control reports a finding when any of the following hold:

- no IAM role evidence collected
- ePHI role <value> does not publish a max session duration — automatic logoff cannot be verified (HIPAA §164.312(a)(2)(iii))
- ePHI role <value> allows sessions of <value> seconds, exceeding the <value>-second automatic-logoff threshold (HIPAA §164.312(a)(2)(iii))

## Remediation

Bring each affected resource or attestation listed under *What a failure looks like* into compliance, then re-collect evidence. Estimated effort: **4h**. Automated fix available: **false**.

## How to re-verify

```
concord check --controls <pack>/controls --framework hipaa --control-id HIPAA-164.312a2iii-automatic-logoff
```

A passing run reports this control green; in CI, `concord gate` exits non-zero while it fails.

## Cross-framework mappings

```
  hipaa:
  - "164.312(a)(2)(iii)"
  soc2:
  - "CC6.1"
  nist_800_53:
  - "AC-11"
  - "AC-12"
```
