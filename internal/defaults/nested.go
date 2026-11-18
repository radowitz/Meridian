package defaults

import "github.com/radowitz/meridian/internal/model"

// NestedExample is DualHubExample with an exit behind a relay exit: "twnat"
// can only dial out and has no inbound port the hubs could use, so its one
// tunnel goes to the managed exit "dc1" (the relay exit), which forwards
// between that tunnel and its own tunnels to both hubs while staying an
// ordinary member of group "hk". Group "tw" switches between twnat (behind
// dc1) and dc2 (a plain exit). Documentation addresses only.
func NestedExample() model.Topology {
	t := DualHubExample()
	t.Nodes = append(t.Nodes, model.Node{
		ID: "twnat", Name: "台湾 NAT", Role: model.RoleExit, Region: "tw", Managed: true, X: 880, Y: 140,
		WANInterface: "eth0", PathV4: true, EgressV4: true, NatDialOut: true, ViaExit: "dc1",
	})
	t.Links = append(t.Links, model.Link{ID: "twnat-dc1", Name: "台湾 NAT → 香港机房 1（中继出口）", From: "twnat", To: "dc1", Transport: model.TransportDirectWG, Enabled: true})
	t.Groups = append(t.Groups, model.RegionGroup{ID: "tw", Name: "台湾", Region: "tw", Members: []string{"twnat", "dc2"}, Mode: model.GroupAuto})
	t.Rules = append(t.Rules, model.Rule{
		ID: "tw-example", Name: "示例：tw.example.net 走台湾组", Manual: true, Priority: 20, Enabled: true,
		MatchType: model.MatchSuffix, MatchValue: "tw.example.net", TargetGroup: "tw",
	})
	return t
}

// ExternalExample is DualHubExample with an external SOCKS exit: "myext" is a
// small router that already dials the managed exit "dc2" (its carrier) with
// its own WireGuard and offers an authenticated SOCKS5 proxy (TCP only) on
// its tunnel address. The panel never logs into it; everything for it runs
// on dc2. Group "my" holds it alone. The credential id is a placeholder
// (the username and password live only in the credential store).
// Documentation addresses only.
func ExternalExample() model.Topology {
	t := DualHubExample()
	t.Nodes = append(t.Nodes, model.Node{
		ID: "myext", Name: "马来西亚路由器（外部 SOCKS）", Role: model.RoleExit, Region: "my", Managed: false, X: 880, Y: 260,
		PathV4: true, EgressV4: true,
		External: &model.ExternalExit{Carrier: "dc2", SOCKSAddress: "198.51.100.66", SOCKSPort: 1080, Interface: "wg9", CredentialID: "socks-example1"},
	})
	t.Groups = append(t.Groups, model.RegionGroup{ID: "my", Name: "马来西亚", Region: "my", Members: []string{"myext"}, Mode: model.GroupAuto})
	t.Rules = append(t.Rules, model.Rule{
		ID: "my-example", Name: "示例：my.example.net 走马来西亚组", Manual: true, Priority: 30, Enabled: true,
		MatchType: model.MatchSuffix, MatchValue: "my.example.net", TargetGroup: "my",
	})
	return t
}
