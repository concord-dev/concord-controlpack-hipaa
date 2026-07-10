# Periodic security-awareness reminders are distributed to the workforce

`HIPAA-164.308a5iiA-security-reminders` · framework **hipaa** · severity **medium** · Administrative Safeguards

## What this control checks

HIPAA Security Rule §164.308(a)(5)(ii)(A) (Security Reminders) is an
addressable implementation specification of the Security Awareness and
Training standard requiring periodic security updates to the workforce.
Concord reads a cosign-verified attestation from the policy repository
that records the reminder cadence, the topics covered, the intended
audience, and the date reminders were last distributed. A reminder
program that is undocumented or more than twelve months stale is treated
as a control failure.

## Why it matters

Workforce members are the most frequently exploited path to ePHI, and OCR
corrective-action plans routinely require an ongoing awareness program
rather than a one-time onboarding briefing. Recording the cadence,
audience, and topics — and attesting to them with a verifiable signature —
demonstrates that reminders are current, reach everyone who touches ePHI,
and cover the threats (phishing, credential hygiene, incident reporting)
that drive real breaches.

## Evidence

Collected from the `github` source (`file_glob` evidence type).

## What a failure looks like

This control reports a finding when any of the following hold:

- no security-awareness reminder attestation collected
- no security-awareness reminder document found at the configured path
- security-awareness reminder attestation is missing required field <value>
- security-awareness reminder attestation lists no topics_covered
- security-awareness reminders last refreshed <value> days ago — HIPAA expects at least annual reminders
- security-awareness reminder attestation cosign signature did not verify

## Remediation

Bring each affected resource or attestation listed under *What a failure looks like* into compliance, then re-collect evidence. Estimated effort: **1d**. Automated fix available: **false**.

## How to re-verify

```
concord check --controls <pack>/controls --framework hipaa --control-id HIPAA-164.308a5iiA-security-reminders
```

A passing run reports this control green; in CI, `concord gate` exits non-zero while it fails.

## Cross-framework mappings

```
  hipaa:
  - "164.308(a)(5)(ii)(A)"
  soc2:
  - "CC2.2"
  nist_800_53:
  - "AT-2"
  iso27001:
  - "A.6.3"
```
