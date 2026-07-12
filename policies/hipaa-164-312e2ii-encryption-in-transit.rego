package concord.hipaa.encryption_in_transit

import rego.v1

# HIPAA §164.312(e)(2)(ii) — Encryption (Transmission Security).
# Every ePHI transmission endpoint must enforce TLS 1.2+:
#   - S3 buckets tagged ephi=true must deny aws:SecureTransport=false.
#   - ELB listeners on load balancers tagged ephi=true must use HTTPS/TLS
#     with a security policy whose minimum protocol is TLS 1.2.
# Adapted from Prowler `s3_bucket_secure_transport_policy` and
# `elbv2_listeners_underlying_certificate` / TLS-policy checks.
# Evidence: input.ephi_endpoints.{buckets,load_balancers}.

# ELB security policies whose minimum negotiated protocol is TLS 1.2 or 1.3.
tls12plus_policies := {
	"ELBSecurityPolicy-TLS13-1-2-2021-06",
	"ELBSecurityPolicy-TLS13-1-2-Res-2021-06",
	"ELBSecurityPolicy-TLS13-1-2-Ext1-2021-06",
	"ELBSecurityPolicy-TLS13-1-2-Ext2-2021-06",
	"ELBSecurityPolicy-TLS-1-2-2017-01",
	"ELBSecurityPolicy-TLS-1-2-Ext-2018-06",
	"ELBSecurityPolicy-FS-1-2-2019-08",
	"ELBSecurityPolicy-FS-1-2-Res-2019-08",
	"ELBSecurityPolicy-FS-1-2-Res-2020-10",
}

deny contains msg if {
	not input.ephi_endpoints
	msg := "no ePHI transmission-endpoint evidence collected"
}

# S3 bucket that does not deny non-TLS requests.
deny contains msg if {
	some b in input.ephi_endpoints.buckets
	is_ephi(b)
	not bucket_enforces_tls(b)
	msg := sprintf("ePHI S3 bucket %q does not deny non-TLS requests (missing aws:SecureTransport=false deny) — HIPAA §164.312(e)(2)(ii)", [b.name])
}

# ELB listener carrying ePHI over a plaintext protocol.
deny contains msg if {
	some lb in input.ephi_endpoints.load_balancers
	is_ephi(lb)
	some l in lb.listeners
	plaintext_protocol(l)
	msg := sprintf("ePHI load balancer %q has a %s listener on port %d that transmits ePHI without TLS — HIPAA §164.312(e)(2)(ii)", [lb.name, upper(l.protocol), l.port])
}

# ELB listener whose TLS policy permits protocols below TLS 1.2.
deny contains msg if {
	some lb in input.ephi_endpoints.load_balancers
	is_ephi(lb)
	some l in lb.listeners
	encrypted_protocol(l)
	not tls12plus(l)
	msg := sprintf("ePHI load balancer %q listener on port %d uses SSL policy %q which permits TLS below 1.2 — HIPAA §164.312(e)(2)(ii)", [lb.name, l.port, object.get(l, "ssl_policy", "<none>")])
}

is_ephi(x) if {
	x.tags.ephi == "true"
}

bucket_enforces_tls(b) if {
	some stmt in b.policy.Statement
	stmt.Effect == "Deny"
	stmt.Condition.Bool["aws:SecureTransport"] == "false"
	action_covers_all(stmt)
}

action_covers_all(stmt) if {
	stmt.Action == "s3:*"
}

action_covers_all(stmt) if {
	some a in stmt.Action
	a == "s3:*"
}

plaintext_protocol(l) if {
	upper(l.protocol) == "HTTP"
}

plaintext_protocol(l) if {
	upper(l.protocol) == "TCP"
}

encrypted_protocol(l) if {
	upper(l.protocol) == "HTTPS"
}

encrypted_protocol(l) if {
	upper(l.protocol) == "TLS"
}

tls12plus(l) if {
	tls12plus_policies[l.ssl_policy]
}

# doc 31 §4 — no fail-open tag gates: a resource with no 'ephi' tag is neither confirmed in-scope
# nor out-of-scope, so every deny above skips it and it would pass silently.
# Warn on the unclassified resource instead of ignoring it.

warn contains msg if {
	some resource in input.ephi_endpoints.buckets
	not classified(resource)
	msg := sprintf("S3 bucket %q has no ephi tag, so this control's checks did not apply to it — tag ephi=true to bring it into ePHI scope or ephi=false to confirm it is out of scope", [resource.name])
}

warn contains msg if {
	some resource in input.ephi_endpoints.load_balancers
	not classified(resource)
	msg := sprintf("load balancer %q has no ephi tag, so this control's checks did not apply to it — tag ephi=true to bring it into ePHI scope or ephi=false to confirm it is out of scope", [resource.name])
}

classified(resource) if resource.tags.ephi == "true"

classified(resource) if resource.tags.ephi == "false"
