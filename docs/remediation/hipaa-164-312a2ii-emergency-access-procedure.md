# Break-glass access uses a dedicated, MFA-gated, alarmed IAM role

`HIPAA-164.312a2ii-emergency-access-procedure` · framework **hipaa** · severity **high** · Technical Safeguards

## What this control checks

HIPAA Security Rule §164.312(a)(2)(ii) (Emergency Access Procedure)
requires a procedure for obtaining necessary ePHI during an emergency.
Concord verifies the technical shape of that procedure: there must be at
least one dedicated break-glass IAM role (tagged break_glass=true), its
trust policy must require multi-factor authentication
(aws:MultiFactorAuthPresent=true) to assume it, and its assumption must
be watched by a CloudWatch alarm with an active notification action so
every emergency use is detected and reviewed.

## Why it matters

Emergency access is a legitimate necessity, but a break-glass path that
is not isolated, MFA-gated, and alarmed becomes a silent backdoor to
ePHI. OCR expects covered entities to show that emergency access is
granted through a controlled, auditable mechanism — not shared admin
credentials — and that each use generates an alert for after-the-fact
review. Requiring MFA on assumption and a live alarm makes the procedure
both usable in a real emergency and defensible in an audit. The check
fails closed: absent evidence, or a role without MFA or alarm coverage,
denies.

## Evidence

Collected from the `aws` source (`iam_roles` evidence type).

## What a failure looks like

This control reports a finding when any of the following hold:

- no IAM role / CloudWatch alarm evidence collected
- no dedicated break-glass IAM role (tag break_glass=true) found — emergency access must use an isolated, monitored role (HIPAA §164.312(a)(2)(ii))
- break-glass role <value> trust policy does not require MFA (aws:MultiFactorAuthPresent=true) to assume — HIPAA §164.312(a)(2)(ii)
- break-glass role <value> assumption is not covered by a CloudWatch alarm with an enabled notification action — emergency use would go undetected (HIPAA §164.312(a)(2)(ii))

## Remediation

Bring each affected resource or attestation listed under *What a failure looks like* into compliance, then re-collect evidence. Estimated effort: **1d**. Automated fix available: **false**.

## How to re-verify

```
concord check --controls <pack>/controls --framework hipaa --control-id HIPAA-164.312a2ii-emergency-access-procedure
```

A passing run reports this control green; in CI, `concord gate` exits non-zero while it fails.

## Cross-framework mappings

```
  hipaa:
  - "164.312(a)(2)(ii)"
  soc2:
  - "CC6.1"
  nist_800_53:
  - "AC-6(2)"
  - "CP-2"
  cis_aws:
  - "1.16"
```
