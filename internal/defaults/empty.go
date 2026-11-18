package defaults

import "github.com/radowitz/meridian/internal/model"

// Empty is what a fresh install starts from: no nodes, links, rules or
// groups, and no LAN address, interface, router address or panel bind.
// Those come from the operator (first-run input or confirmed detection);
// nothing here assumes a particular network. Only the project's own
// internal ranges are set (the fd66::/48 tunnel ULA and the 10.66/fd66
// transit prefixes every topology uses).
//
// Example() and the other *Example() topologies are test fixtures and
// demo data; the panel never loads them into a real installation.
func Empty() model.Topology {
	return model.Topology{
		Settings: model.Settings{
			ULAPrefix:       "fd66::/48",
			TransitV4Prefix: "10.66.200.0/24",
			TransitV6Prefix: "fd66:0:0:ff::/64",
			NAT64:           model.NAT64{Reserved: true, Enabled: false},
		},
	}
}
