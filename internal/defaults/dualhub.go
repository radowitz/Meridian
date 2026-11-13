package defaults

import "github.com/radowitz/meridian/internal/model"

// DualHubExample is the IX-as-primary-hub topology with a backup hub:
// gateway → one relay → IX (the managed primary hub: domestic ingress
// 198.51.100.10 for the relay, Hong Kong egress 203.0.113.20 toward the
// exits, SSH through a port-forward on the relay, i.e. its server record
// points at the relay's address) → two datacentre exits; and a backup hub
// the gateway reaches by WG over WSS on port 8443 when the whole main path
// is down. Both hubs have a tunnel to both exits. Documentation addresses
// only (RFC 5737, RFC 3849); docs/architecture.md「主枢纽与备用枢纽」.
func DualHubExample() model.Topology {
	return model.Topology{
		Settings: model.Settings{
			LANInterface:    "eth0",
			GatewayLANIP:    "192.168.100.88/24",
			ROSIPv4:         "192.168.100.1",
			ROSv6LLA:        "fe80::1",
			LANIPv6Prefix:   "2001:db8:100::/64",
			ULAPrefix:       "fd66::/48",
			PanelBind:       "192.168.100.88:8787",
			DomesticDoT:     []string{"223.5.5.5", "1.12.12.12"},
			TransitV4Prefix: "10.66.200.0/24",
			TransitV6Prefix: "fd66:0:0:ff::/64",
			NAT64:           model.NAT64{Reserved: true},
			DefaultGroup:    "hk",
		},
		Nodes: []model.Node{
			{
				ID: "gw", Name: "家宽网关", Role: model.RoleGateway, Region: "cn", Managed: true, X: 0, Y: 200,
				LANInterface: "eth0", LANIPv4: "192.168.100.88/24", LANIPv6Prefix: "2001:db8:100::/64",
				UnderlayNextHop: "192.168.100.1", PathV4: true, PathV6: true,
			},
			{
				ID: "ali", Name: "国内中继", Role: model.RoleRelay, Region: "cn", Managed: true, X: 220, Y: 200,
				WANInterface: "eth0", EndpointV4: "203.0.113.10", PathV4: true,
				WSSListenPort: 8443,
			},
			{
				ID: "ix", Name: "IX（主枢纽）", Role: model.RoleHub, Region: "hk", Managed: true, X: 440, Y: 200,
				HubTier: model.HubPrimary, IXLine: true,
				IngressV4: "198.51.100.10", EndpointV4: "203.0.113.20", WANInterface: "eth0",
				PathV4: true,
			},
			{
				ID: "hk5", Name: "备用枢纽", Role: model.RoleHub, Region: "hk", Managed: true, X: 440, Y: 360,
				HubTier: model.HubBackup, EndpointV4: "203.0.113.30", WANInterface: "eth0",
				WSSListenPort: 8443, PathV4: true,
			},
			{
				ID: "dc1", Name: "香港机房 1", Role: model.RoleExit, Region: "hk", Managed: true, X: 660, Y: 140,
				EndpointV4: "203.0.113.41", WANInterface: "eth0", PathV4: true, EgressV4: true, IXBound: true,
			},
			{
				ID: "dc2", Name: "香港机房 2", Role: model.RoleExit, Region: "hk", Managed: true, X: 660, Y: 260,
				EndpointV4: "203.0.113.42", WANInterface: "eth0", PathV4: true, EgressV4: true,
			},
		},
		Links: []model.Link{
			{ID: "gw-ali", Name: "家宽 → 国内中继", From: "gw", To: "ali", Transport: model.TransportUDPWSSFailover, Enabled: true},
			{ID: "ali-ix", Name: "国内中继 → IX（专线）", From: "ali", To: "ix", Transport: model.TransportDirectWG, Enabled: true},
			{ID: "gw-hk5", Name: "家宽 → 备用枢纽（WSS）", From: "gw", To: "hk5", Transport: model.TransportIXReplacementWSS, Enabled: true, Standby: true},
			{ID: "ix-dc1", From: "ix", To: "dc1", Transport: model.TransportDirectWG, Enabled: true},
			{ID: "ix-dc2", From: "ix", To: "dc2", Transport: model.TransportDirectWG, Enabled: true},
			{ID: "hk5-dc1", From: "hk5", To: "dc1", Transport: model.TransportDirectWG, Enabled: true},
			{ID: "hk5-dc2", From: "hk5", To: "dc2", Transport: model.TransportDirectWG, Enabled: true},
		},
		Rules: []model.Rule{
			{
				ID: "pin-dc2", Name: "示例：钉死 api.example.com 到机房 2", Manual: true, Priority: 10, Enabled: true,
				MatchType: model.MatchDomain, MatchValue: "api.example.com", TargetExit: "dc2",
				Domains: []string{"api.example.com"},
			},
		},
		Groups: []model.RegionGroup{
			{ID: "hk", Name: "香港机房", Region: "hk", Members: []string{"dc1", "dc2"}, Mode: model.GroupAuto, ExcludeResidential: true},
		},
	}
}

// SharedRelaysExample is DualHubExample with a second domestic relay
// ("ali2", plain WireGuard from the gateway, its own tunnel to the IX):
// both relays carry the main path at once, weighted by measured quality
// (docs/architecture.md「多中继同时分担」); the backup hub takes over only
// when every relay is persistently below the usable floor. Documentation
// addresses only.
func SharedRelaysExample() model.Topology {
	t := DualHubExample()
	t.Nodes = append(t.Nodes, model.Node{
		ID: "ali2", Name: "国内中继 2", Role: model.RoleRelay, Region: "cn", Managed: true, X: 220, Y: 320,
		WANInterface: "eth0", EndpointV4: "203.0.113.11", PathV4: true,
	})
	t.Links = append(t.Links,
		model.Link{ID: "gw-ali2", Name: "家宽 → 国内中继 2", From: "gw", To: "ali2", Transport: model.TransportDirectWG, Enabled: true},
		model.Link{ID: "ali2-ix", Name: "国内中继 2 → IX（专线）", From: "ali2", To: "ix", Transport: model.TransportDirectWG, Enabled: true},
	)
	return t
}
