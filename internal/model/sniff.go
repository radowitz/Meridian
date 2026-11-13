package model

import "strings"

// SniffSettings is the gateway's name-sniffing TCP forwarder (meridian
// sniff, internal/sniff; docs/architecture.md「按域名嗅探的转发」). Nil or
// Enabled false: the gateway classifies every connection by destination
// address only, exactly as before the forwarder existed (the compiled
// bundle is byte-identical).
//
// With it on, new TCP connections from the LAN and remote access to Ports
// whose destination is not this gateway, a LAN or private address, a
// device pool or a known DoH address are redirected to the forwarder,
// which reads the TLS server_name or HTTP Host and decides the target with
// the ordered rule list; connections without a usable name get exactly the
// target the address classifier gave them. UDP (QUIC included), other
// ports and everything else keep the address path.
type SniffSettings struct {
	Enabled bool `json:"enabled"`
	// Ports are the TCP destination ports that are intercepted (empty: the
	// defaults, 80 and 443). At most MaxSniffPorts; 53, 853, 22 and the
	// forwarder's own port are refused.
	Ports []int `json:"ports,omitempty"`
	// ECHPublicNames are ECH public (outer) names: a ClientHello with an
	// encrypted_client_hello extension whose cleartext server_name is one
	// of them (or under one of them) is decided by address. Any other ECH
	// ClientHello is decided by its cleartext name, which is the real name
	// for the GREASE ECH most browsers send. Nil: the default list
	// (DefaultECHPublicNames); an empty list means none.
	ECHPublicNames []string `json:"ech_public_names,omitempty"`
	// RecordNames keeps the sniffed names in the forwarder's in-memory
	// recent-decision record shown by the panel (never on disk, never in a
	// log). Off by default: names are sensitive.
	RecordNames bool `json:"record_names,omitempty"`
}

// Defaults of the forwarder setting.
var (
	DefaultSniffPorts     = []int{80, 443}
	DefaultECHPublicNames = []string{"cloudflare-ech.com"}
)

// MaxSniffPorts bounds Ports.
const MaxSniffPorts = 16

// SniffOn reports whether the forwarder is enabled.
func (t Topology) SniffOn() bool {
	return t.Settings.Sniff != nil && t.Settings.Sniff.Enabled
}

// EffectivePorts is Ports or the defaults.
func (s *SniffSettings) EffectivePorts() []int {
	if s == nil || len(s.Ports) == 0 {
		return append([]int(nil), DefaultSniffPorts...)
	}
	return append([]int(nil), s.Ports...)
}

// EffectiveECHPublicNames is ECHPublicNames (lower case, without a leading
// or trailing dot) or the defaults when nil.
func (s *SniffSettings) EffectiveECHPublicNames() []string {
	if s == nil || s.ECHPublicNames == nil {
		return append([]string(nil), DefaultECHPublicNames...)
	}
	out := []string{}
	for _, n := range s.ECHPublicNames {
		if n = strings.Trim(strings.ToLower(strings.TrimSpace(n)), "."); n != "" {
			out = append(out, n)
		}
	}
	return out
}
