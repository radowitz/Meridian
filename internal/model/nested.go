package model

import "sort"

// Exits that are not reached by a hub directly (docs/architecture.md
// 「挂在中继出口后面的出口」 and 「外部 SOCKS 出口」).
//
// A nested exit (Node.ViaExit) is a managed exit that can only dial out and
// cannot reach a hub: its one tunnel goes to a managed relay exit, which
// forwards between that tunnel and its own tunnels to the hubs while staying
// an ordinary exit itself. One level only: a relay exit is never nested and
// never carries external exits' tunnels for a nested exit.
//
// An external exit (Node.External) is not a host the panel manages: an
// existing, authenticated SOCKS5 proxy (TCP only) that a managed "carrier"
// exit reaches over a tunnel the panel does not manage. The panel never
// logs into it and never builds a bundle for it; everything for it runs on
// the carrier (a transparent TCP redirector, a resolver group whose
// upstream queries go through the proxy over TCP, a health probe).

// ExternalExit describes an external SOCKS exit. The credential (username
// and password) lives only in the restricted credential store under
// CredentialID; the topology holds the reference.
type ExternalExit struct {
	// Carrier is the managed exit that reaches the proxy.
	Carrier string `json:"carrier"`
	// SOCKSAddress / SOCKSPort are the proxy as seen from the carrier
	// (IPv4; typically an address on the carrier's unmanaged tunnel).
	SOCKSAddress string `json:"socks_address"`
	SOCKSPort    int    `json:"socks_port"`
	// Interface is the carrier's interface that routes SOCKSAddress (the
	// unmanaged tunnel). The carrier refuses to reach the proxy through any
	// other interface, so a vanished tunnel fails closed instead of
	// following the carrier's default route.
	Interface string `json:"interface"`
	// CredentialID is a SOCKS credential of the credential store.
	CredentialID string `json:"credential_id"`
}

// IsExternal reports whether n is an external exit.
func IsExternal(n Node) bool { return n.Role == RoleExit && n.External != nil }

// IsNested reports whether n is an exit behind a relay exit.
func IsNested(n Node) bool { return n.Role == RoleExit && n.ViaExit != "" }

// NestedExitsOf lists the nested exits whose relay exit is relayID, sorted
// by ID.
func NestedExitsOf(t Topology, relayID string) []Node {
	var out []Node
	for _, n := range t.Nodes {
		if IsNested(n) && n.ViaExit == relayID && relayID != "" {
			out = append(out, n)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// ExternalExitsOf lists the external exits carried by carrierID, sorted by
// ID.
func ExternalExitsOf(t Topology, carrierID string) []Node {
	var out []Node
	for _, n := range t.Nodes {
		if IsExternal(n) && n.External.Carrier == carrierID && carrierID != "" {
			out = append(out, n)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// IsRelayExit reports whether some nested exit names n as its relay exit.
func IsRelayExit(t Topology, n Node) bool {
	return n.Role == RoleExit && len(NestedExitsOf(t, n.ID)) > 0
}

// HubSideOf is the managed exit the hubs' tunnels reach for exit n: the
// relay exit of a nested exit, the carrier of an external exit, n itself
// otherwise.
func HubSideOf(n Node) string {
	switch {
	case IsNested(n):
		return n.ViaExit
	case IsExternal(n):
		return n.External.Carrier
	}
	return n.ID
}
