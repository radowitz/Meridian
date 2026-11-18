package defaults

import "github.com/radowitz/meridian/internal/model"

// DirectExample is a topology with no relay, no hub and no IX: the gateway
// dials every exit itself (model.Topology.DirectExits). Two exits form
// region group "jp" (automatic: the gateway switches the group's table to
// the next member when the current one stops answering), a third is alone
// in group "us"; every exit is one plain WireGuard tunnel from the
// gateway (direct_wg). Foreign traffic no
// rule matches goes to "jp"; one manual rule pins a documentation domain
// to "us". Documentation addresses only (RFC 5737, RFC 3849);
// docs/architecture.md「直连出口与单中继」.
func DirectExample() model.Topology {
	return model.Topology{
		Settings: model.Settings{
			LANInterface:    "eth0",
			GatewayLANIP:    "192.0.2.88/24",
			ROSIPv4:         "192.0.2.1",
			ROSv6LLA:        "fe80::1",
			LANIPv6Prefix:   "2001:db8:100::/64",
			ULAPrefix:       "fd66::/48",
			PanelBind:       "192.0.2.88:8787",
			DomesticDoT:     []string{"223.5.5.5", "1.12.12.12"},
			TransitV4Prefix: "10.66.200.0/24",
			TransitV6Prefix: "fd66:0:0:ff::/64",
			NAT64:           model.NAT64{Reserved: true},
			DefaultGroup:    "jp",
		},
		Nodes: []model.Node{
			{
				ID: "gw", Name: "网关", Role: model.RoleGateway, Region: "cn", Managed: true, X: 0, Y: 200,
				LANInterface: "eth0", LANIPv4: "192.0.2.88/24", LANIPv6Prefix: "2001:db8:100::/64",
				UnderlayNextHop: "192.0.2.1", PathV4: true,
			},
			{
				ID: "exit-a", Name: "日本出口 A", Role: model.RoleExit, Region: "jp", Managed: true, X: 300, Y: 100,
				WANInterface: "eth0", EndpointV4: "203.0.113.41", PathV4: true, PathV6: true, EgressV4: true, EgressV6: true,
			},
			{
				ID: "exit-b", Name: "日本出口 B", Role: model.RoleExit, Region: "jp", Managed: true, X: 300, Y: 200,
				WANInterface: "eth0", EndpointV4: "203.0.113.42", PathV4: true, EgressV4: true,
			},
			{
				ID: "exit-c", Name: "美国出口", Role: model.RoleExit, Region: "us", Managed: true, X: 300, Y: 300,
				WANInterface: "eth0", EndpointV4: "198.51.100.20", PathV4: true, EgressV4: true,
			},
		},
		Links: []model.Link{
			{ID: "gw-exit-a", Name: "网关 → 日本出口 A", From: "gw", To: "exit-a", Transport: model.TransportDirectWG, Enabled: true},
			{ID: "gw-exit-b", Name: "网关 → 日本出口 B", From: "gw", To: "exit-b", Transport: model.TransportDirectWG, Enabled: true},
			{ID: "gw-exit-c", Name: "网关 → 美国出口", From: "gw", To: "exit-c", Transport: model.TransportDirectWG, Enabled: true},
		},
		Rules: []model.Rule{
			{
				ID: "pin-us", Name: "示例：api.example.com 走美国组", Manual: true, Priority: 10, Enabled: true,
				MatchType: model.MatchDomain, MatchValue: "api.example.com", TargetGroup: "us",
				Domains: []string{"api.example.com"},
			},
		},
		Groups: []model.RegionGroup{
			{ID: "jp", Name: "日本", Region: "jp", Members: []string{"exit-a", "exit-b"}, Mode: model.GroupAuto},
			{ID: "us", Name: "美国", Region: "us", Members: []string{"exit-c"}, Mode: model.GroupAuto},
		},
	}
}
