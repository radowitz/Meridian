package model

// UnsetLANPrefix / UnsetLANHost stand in for the gateway LAN when a
// topology has none (settings.gateway_lan_ipv4 empty or unparseable).
// Validation rejects such a topology (missing_gateway_lan), so these only
// appear in output compiled without validation (tests, previews). They are
// RFC 5737 documentation addresses: never a real LAN and never anyone's
// network. A stored topology that sets its LAN never reaches them.
const (
	UnsetLANPrefix   = "192.0.2.0/24"
	UnsetLANHost     = "192.0.2.10"
	UnsetLANHostCIDR = "192.0.2.10/24"
	UnsetRouterHost  = "192.0.2.2"
	UnsetLANClient   = "192.0.2.254"
)
