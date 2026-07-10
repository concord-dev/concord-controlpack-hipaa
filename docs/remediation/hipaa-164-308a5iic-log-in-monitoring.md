# Failed console log-in attempts are captured by a metric filter and alarm

`HIPAA-164.308a5iiC-log-in-monitoring` · framework **hipaa** · severity **medium** · Administrative Safeguards

## What this control checks

HIPAA Security Rule §164.308(a)(5)(ii)(C) (Log-in Monitoring) requires
procedures for monitoring log-in attempts and reporting discrepancies.
In AWS this means a CloudWatch Logs metric filter over the CloudTrail
log group that matches failed console authentications, wired to a
CloudWatch alarm with an active notification action. Concord fails the
control when no metric filter matches failed ConsoleLogin events, or
when a matching filter's metric has no alarm with an enabled
notification action.

## Why it matters

Repeated failed console log-ins are the clearest early signal of
credential-stuffing and brute-force attacks against accounts that can
reach ePHI. Without a metric filter and alarm the failures are buried in
CloudTrail and no one is paged, so the discrepancy reporting that
§164.308(a)(5)(ii)(C) mandates never happens. OCR investigators routinely
ask covered entities to demonstrate the alarm and its notification
target, mirroring CIS AWS Foundations 3.6.

## Evidence

Collected from the `aws` source (`cloudwatch_alarms` evidence type).

## What a failure looks like

This control reports a finding when any of the following hold:

- no CloudWatch metric-filter/alarm evidence collected
- no CloudWatch metric filter matches failed console log-ins (ConsoleLogin + "Failed authentication") — HIPAA §164.308(a)(5)(ii)(C)
- metric filter <value> matches failed console log-ins but its metric has no CloudWatch alarm with an enabled notification action — HIPAA §164.308(a)(5)(ii)(C)

## Remediation

Bring each affected resource or attestation listed under *What a failure looks like* into compliance, then re-collect evidence. Estimated effort: **4h**. Automated fix available: **false**.

## How to re-verify

```
concord check --controls <pack>/controls --framework hipaa --control-id HIPAA-164.308a5iiC-log-in-monitoring
```

A passing run reports this control green; in CI, `concord gate` exits non-zero while it fails.

## Cross-framework mappings

```
  hipaa:
  - "164.308(a)(5)(ii)(C)"
  soc2:
  - "CC7.2"
  nist_800_53:
  - "AU-6"
  - "SI-4"
  cis_aws:
  - "3.6"
```
