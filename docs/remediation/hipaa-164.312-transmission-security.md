# ePHI buckets enforce TLS on every request via bucket policy

`HIPAA-164.312-transmission-security` · framework **hipaa** · severity **critical** · Technical Safeguards

## What this control checks

HIPAA Security Rule §164.312(e)(1) (Transmission Security) and
§164.312(e)(2)(ii) (Encryption) require technical measures to
guard against unauthorised access to ePHI transmitted over an
electronic communications network. Concord verifies every S3
bucket tagged ephi=true carries a bucket policy that denies
requests where aws:SecureTransport is false.

## Why it matters

AWS enables TLS but does not enforce it — a misconfigured client
can still PutObject over plaintext HTTP. The bucket-policy Deny
is the only enforcement mechanism that survives misconfigured
clients. This is one of the most-cited HIPAA findings in OCR's
HHS Cloud Computing guidance.

## Evidence

Collected from the `aws` source (`s3_bucket_policy` evidence type).

## What a failure looks like

This control reports a finding when any of the following hold:

- no S3 bucket-policy evidence collected
- ePHI bucket <value> does not enforce TLS via bucket policy

## Remediation

Bring each affected resource or attestation listed under *What a failure looks like* into compliance, then re-collect evidence. Estimated effort: **30m**. Automated fix available: **true**.

## How to re-verify

```
concord check --controls <pack>/controls --framework hipaa --control-id HIPAA-164.312-transmission-security
```

A passing run reports this control green; in CI, `concord gate` exits non-zero while it fails.

## Cross-framework mappings

```
  hipaa:
  - "164.312(e)(1)"
  - "164.312(e)(2)(ii)"
  soc2:
  - "CC6.7"
  nist_800_53:
  - "SC-8"
  - "SC-13"
  iso27001:
  - "A.8.20"
  - "A.8.24"
  pci_dss:
  - "4.1"
  - "4.2"
```
