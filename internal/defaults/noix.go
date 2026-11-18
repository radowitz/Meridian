package defaults

import "github.com/radowitz/meridian/internal/model"

// NoIXExample is a topology without any IX: gateway → domestic relay
// ("access", UDP with WSS failover from the gateway, plain WireGuard to the
// hub) → a plain managed primary hub with a public endpoint_v4 → exits; a
// backup hub the gateway reaches by WG over WSS (standby) while the whole
// main path is down. A second relay ("access2") is drawn but both of its
// links are disabled: it carries nothing and is not deployed. One exit is
// dialled by the hubs ("dc1"), the other sits behind NAT and dials in
// ("dc2"). Documentation addresses only (RFC 5737, RFC 3849);
// docs/architecture.md「主路径」.
func NoIXExample() model.Topology {
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
			DefaultGroup:    "hk",
		},
		Nodes: []model.Node{
			{
				ID: "gw", Name: "网关", Role: model.RoleGateway, Region: "cn", Managed: true, X: 0, Y: 200,
				LANInterface: "eth0", LANIPv4: "192.0.2.88/24", LANIPv6Prefix: "2001:db8:100::/64",
				UnderlayNextHop: "192.0.2.1", PathV4: true, PathV6: true,
			},
			{
				ID: "access", Name: "国内中继", Role: model.RoleRelay, Region: "cn", Managed: true, X: 220, Y: 200,
				WANInterface: "eth0", EndpointV4: "203.0.113.10", PathV4: true,
				WSSListenPort: 8443,
			},
			{
				ID: "access2", Name: "国内中继 2", Role: model.RoleRelay, Region: "cn", Managed: true, X: 220, Y: 320,
				WANInterface: "eth0", EndpointV4: "203.0.113.11", PathV4: true,
			},
			{
				ID: "hub", Name: "主枢纽", Role: model.RoleHub, Region: "hk", Managed: true, X: 440, Y: 200,
				HubTier: model.HubPrimary, EndpointV4: "203.0.113.20", WANInterface: "eth0",
				WSSListenPort: 8444, PathV4: true,
			},
			{
				ID: "hkb", Name: "备用枢纽", Role: model.RoleHub, Region: "hk", Managed: true, X: 440, Y: 360,
				HubTier: model.HubBackup, EndpointV4: "203.0.113.30", WANInterface: "eth0",
				WSSListenPort: 8443, PathV4: true,
			},
			{
				ID: "dc1", Name: "香港机房 1", Role: model.RoleExit, Region: "hk", Managed: true, X: 660, Y: 140,
				EndpointV4: "203.0.113.41", WANInterface: "eth0", PathV4: true, EgressV4: true,
			},
			{
				ID: "dc2", Name: "香港机房 2", Role: model.RoleExit, Region: "hk", Managed: true, X: 660, Y: 260,
				WANInterface: "eth0", PathV4: true, EgressV4: true, NatDialOut: true,
			},
		},
		Links: []model.Link{
			{ID: "gw-access", Name: "网关 → 国内中继", From: "gw", To: "access", Transport: model.TransportUDPWSSFailover, Enabled: true},
			{ID: "access-hub", Name: "国内中继 → 主枢纽", From: "access", To: "hub", Transport: model.TransportDirectWG, Enabled: true},
			{ID: "gw-access2", Name: "网关 → 国内中继 2（停用）", From: "gw", To: "access2", Transport: model.TransportDirectWG},
			{ID: "access2-hub", Name: "国内中继 2 → 主枢纽（停用）", From: "access2", To: "hub", Transport: model.TransportDirectWG},
			{ID: "gw-hkb", Name: "网关 → 备用枢纽（WSS）", From: "gw", To: "hkb", Transport: model.TransportIXReplacementWSS, Enabled: true, Standby: true},
			{ID: "hub-dc1", From: "hub", To: "dc1", Transport: model.TransportDirectWG, Enabled: true},
			{ID: "dc2-hub", From: "dc2", To: "hub", Transport: model.TransportDirectWG, Enabled: true},
			{ID: "hkb-dc1", From: "hkb", To: "dc1", Transport: model.TransportDirectWG, Enabled: true},
			{ID: "dc2-hkb", From: "dc2", To: "hkb", Transport: model.TransportDirectWG, Enabled: true},
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

// RelayBackupExample is a topology without any IX whose backup hub is
// reached only through relays: the main group is one relay ("access", plain
// WireGuard to the primary hub), the backup group two relays ("bk1",
// "bk2", WG over WSS to the backup hub). The gateway reaches all three by
// UDP with WSS failover and has no link of its own to the backup hub. It
// shares across the main group; only while every main-group relay is
// completely unreachable does it share across the backup group.
// Documentation addresses only (RFC 5737, RFC 3849);
// docs/architecture.md「主备中继分组」.
func RelayBackupExample() model.Topology {
	t := NoIXExample()
	var nodes []model.Node
	for _, n := range t.Nodes {
		if n.ID != "access2" {
			nodes = append(nodes, n)
		}
	}
	nodes = append(nodes,
		model.Node{
			ID: "bk1", Name: "备用中继 1", Role: model.RoleRelay, Region: "cn", Managed: true, X: 220, Y: 320,
			WANInterface: "eth0", EndpointV4: "203.0.113.12", PathV4: true, WSSListenPort: 8443,
		},
		model.Node{
			ID: "bk2", Name: "备用中继 2", Role: model.RoleRelay, Region: "cn", Managed: true, X: 220, Y: 420,
			WANInterface: "eth0", EndpointV4: "203.0.113.13", PathV4: true, WSSListenPort: 8443,
		},
	)
	t.Nodes = nodes
	t.Links = []model.Link{
		{ID: "gw-access", Name: "网关 → 国内中继", From: "gw", To: "access", Transport: model.TransportUDPWSSFailover, Enabled: true},
		{ID: "access-hub", Name: "国内中继 → 主枢纽", From: "access", To: "hub", Transport: model.TransportDirectWG, Enabled: true},
		{ID: "gw-bk1", Name: "网关 → 备用中继 1", From: "gw", To: "bk1", Transport: model.TransportUDPWSSFailover, Enabled: true},
		{ID: "bk1-hkb", Name: "备用中继 1 → 备用枢纽", From: "bk1", To: "hkb", Transport: model.TransportWGOverWSS, Enabled: true},
		{ID: "gw-bk2", Name: "网关 → 备用中继 2", From: "gw", To: "bk2", Transport: model.TransportUDPWSSFailover, Enabled: true},
		{ID: "bk2-hkb", Name: "备用中继 2 → 备用枢纽", From: "bk2", To: "hkb", Transport: model.TransportWGOverWSS, Enabled: true},
		{ID: "hub-dc1", From: "hub", To: "dc1", Transport: model.TransportDirectWG, Enabled: true},
		{ID: "dc2-hub", From: "dc2", To: "hub", Transport: model.TransportDirectWG, Enabled: true},
		{ID: "hkb-dc1", From: "hkb", To: "dc1", Transport: model.TransportDirectWG, Enabled: true},
		{ID: "dc2-hkb", From: "dc2", To: "hkb", Transport: model.TransportDirectWG, Enabled: true},
	}
	return t
}
