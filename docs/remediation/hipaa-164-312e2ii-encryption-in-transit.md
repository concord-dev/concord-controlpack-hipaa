# TLS 1.2+ is enforced on every ePHI transmission endpoint

`HIPAA-164.312e2ii-encryption-in-transit` · framework **hipaa** · severity **critical** · Technical Safeguards

## What this control checks

HIPAA Security Rule §164.312(e)(2)(ii) (Encryption) implements the
Transmission Security standard by requiring encryption of ePHI whenever
it is transmitted over an electronic network. Concord inspects the two
endpoints that carry ePHI in a typical AWS estate: S3 buckets tagged
ephi=true and Elastic Load Balancer listeners on load balancers tagged
ephi=true. A bucket must carry a policy that denies requests where
aws:SecureTransport is false; a listener must speak HTTPS/TLS with a
security policy whose minimum protocol is TLS 1.2. Plaintext listeners,
weak TLS policies, and buckets without the SecureTransport deny all fail.

## Why it matters

AWS permits TLS but does not force it — an S3 bucket without a
SecureTransport deny will happily serve ePHI over plaintext HTTP, and an
ELB listener pinned to an ELBSecurityPolicy that still allows TLS 1.0/1.1
is vulnerable to well-known downgrade and BEAST-class attacks. OCR's
guidance on ePHI in the cloud treats unenforced transport encryption as a
reportable exposure, so the enforcement mechanism (bucket-policy deny and
a TLS-1.2-minimum listener policy) must be present, not merely available.
The check fails closed: missing evidence or an unrecognised TLS policy
denies.

## Evidence

Collected from the `aws` source (`aws_tls_endpoints` evidence type).

## What a failure looks like

This control reports a finding when any of the following hold:

- no ePHI transmission-endpoint evidence collected
- ePHI S3 bucket <value> does not deny non-TLS requests (missing aws:SecureTransport=false deny) — HIPAA §164.312(e)(2)(ii)
- ePHI load balancer <value> has a <value> listener on port <value> that transmits ePHI without TLS — HIPAA §164.312(e)(2)(ii)
- ePHI load balancer <value> listener on port <value> uses SSL policy <value> which permits TLS below 1.2 — HIPAA §164.312(e)(2)(ii)

## Remediation

Bring each affected resource or attestation listed under *What a failure looks like* into compliance, then re-collect evidence. Estimated effort: **1d**. Automated fix available: **false**.

## How to re-verify

```
concord check --controls <pack>/controls --framework hipaa --control-id HIPAA-164.312e2ii-encryption-in-transit
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
  cis_aws:
  - "2.1.1"
```
