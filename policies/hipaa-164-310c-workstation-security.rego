package concord.hipaa.workstation_security

import rego.v1

# HIPAA §164.310(c) — Workstation Security. Every workstation that can access
# ePHI must have full-disk encryption enabled and be MDM-enrolled so a lost or
# stolen device does not expose ePHI. Concord reads the managed-device
# inventory (input.managed_devices.devices[]) from the identity/MDM provider
# and fails per non-compliant ePHI-accessing device. Fail-closed: no inventory
# is a denial, and a missing encryption/enrollment attribute is treated as
# non-compliant rather than compliant.

deny contains msg if {
	not input.managed_devices
	msg := "no managed-device inventory evidence collected"
}

deny contains msg if {
	some device in input.managed_devices.devices
	device.accesses_ephi == true
	not device.disk_encryption == true
	msg := sprintf("workstation %q accesses ePHI without full-disk encryption enabled — HIPAA §164.310(c)", [device.id])
}

deny contains msg if {
	some device in input.managed_devices.devices
	device.accesses_ephi == true
	not device.mdm_enrolled == true
	msg := sprintf("workstation %q accesses ePHI without MDM enrollment — HIPAA §164.310(c)", [device.id])
}
