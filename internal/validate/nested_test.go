package validate

import (
	"testing"

	"github.com/radowitz/meridian/internal/defaults"
	"github.com/radowitz/meridian/internal/model"
)

func errCodes(t model.Topology) map[string]bool {
	out := map[string]bool{}
	for _, iss := range Run(t).Issues {
		if iss.Severity == SeverityError {
			out[iss.Code] = true
		}
	}
	return out
}

func nodeIdx(t *model.Topology, id string) *model.Node {
	for i := range t.Nodes {
		if t.Nodes[i].ID == id {
			return &t.Nodes[i]
		}
	}
	panic("no node " + id)
}

func TestNestedAndExternalExamplesValid(t *testing.T) {
	for name, topo := range map[string]model.Topology{"nested": defaults.NestedExample(), "external": defaults.ExternalExample()} {
		if c := errCodes(topo); len(c) > 0 {
			t.Errorf("%s example has errors: %v", name, c)
		}
		res := Run(topo)
		for _, p := range res.Paths {
			if p.ExitID == "tw2" && (len(p.Nodes) < 2 || p.Nodes[len(p.Nodes)-2] != "dc1") {
				t.Errorf("tw2 path %v must end dc1 → tw2", p.Nodes)
			}
			if p.ExitID == "my1" && (len(p.Nodes) < 2 || p.Nodes[len(p.Nodes)-2] != "dc2") {
				t.Errorf("my1 path %v must end dc2 → my1", p.Nodes)
			}
		}
	}
}

// A relay exit that dials the hubs itself keeps its endpoint for its
// nested exits.
func TestNestedRelayDialsHubs(t *testing.T) {
	topo := defaults.NestedExample()
	nodeIdx(&topo, "dc1").NatDialOut = true
	for i := range topo.Links {
		if topo.Links[i].ID == "ix-dc1" || topo.Links[i].ID == "hk5-dc1" {
			topo.Links[i].From, topo.Links[i].To = "dc1", topo.Links[i].From
		}
	}
	if c := errCodes(topo); len(c) > 0 {
		t.Fatalf("dial-out relay exit: %v", c)
	}
	// A dial-out exit that is no relay still may not carry an endpoint.
	topo2 := defaults.NestedExample()
	topo2.Nodes = topo2.Nodes[:len(topo2.Nodes)-1]
	topo2.Links = topo2.Links[:len(topo2.Links)-1]
	topo2.Groups = topo2.Groups[:1]
	topo2.Rules = topo2.Rules[:1]
	nodeIdx(&topo2, "dc1").NatDialOut = true
	for i := range topo2.Links {
		if topo2.Links[i].ID == "ix-dc1" || topo2.Links[i].ID == "hk5-dc1" {
			topo2.Links[i].From, topo2.Links[i].To = "dc1", topo2.Links[i].From
		}
	}
	if !errCodes(topo2)["nat_endpoint_forbidden"] {
		t.Fatal("a dial-out exit without nested exits must not keep its endpoint")
	}
}

func TestNestedValidation(t *testing.T) {
	cases := []struct {
		name string
		mut  func(*model.Topology)
		code string
	}{
		{"self", func(t *model.Topology) { nodeIdx(t, "tw2").ViaExit = "tw2" }, "via_exit_loop"},
		{"missing", func(t *model.Topology) { nodeIdx(t, "tw2").ViaExit = "nope" }, "via_exit_not_found"},
		{"not an exit", func(t *model.Topology) { nodeIdx(t, "tw2").ViaExit = "ix" }, "via_exit_not_exit"},
		{"loop", func(t *model.Topology) { nodeIdx(t, "dc1").ViaExit = "tw2" }, "via_exit_loop"},
		{"depth", func(t *model.Topology) {
			t.Nodes = append(t.Nodes, model.Node{ID: "deep", Name: "deep", Role: model.RoleExit, Managed: true, PathV4: true, EgressV4: true, NatDialOut: true, ViaExit: "tw2"})
			t.Links = append(t.Links, model.Link{ID: "deep-tw2", From: "deep", To: "tw2", Transport: model.TransportDirectWG, Enabled: true})
		}, "via_exit_depth"},
		{"not dial-out", func(t *model.Topology) { nodeIdx(t, "tw2").NatDialOut = false }, "via_exit_not_dial_out"},
		{"pure v6", func(t *model.Topology) { n := nodeIdx(t, "tw2"); n.PathV4, n.PathV6 = false, true }, "via_exit_family"},
		{"relay without endpoint", func(t *model.Topology) { nodeIdx(t, "dc1").EndpointV4 = "" }, "via_exit_no_endpoint"},
		{"no link", func(t *model.Topology) { t.Links = t.Links[:len(t.Links)-1] }, "via_exit_link"},
		{"extra hub link", func(t *model.Topology) {
			t.Links = append(t.Links, model.Link{ID: "tw2-ix", From: "tw2", To: "ix", Transport: model.TransportDirectWG, Enabled: true})
		}, "via_exit_link"},
		{"wrong direction", func(t *model.Topology) {
			l := &t.Links[len(t.Links)-1]
			l.From, l.To = l.To, l.From
		}, "via_exit_link"},
		{"relay unreachable", func(t *model.Topology) {
			var keep []model.Link
			for _, l := range t.Links {
				if l.ID != "ix-dc1" {
					keep = append(keep, l)
				}
			}
			t.Links = keep
		}, "via_exit_relay_unreachable"},
		{"relay is external", func(t *model.Topology) {
			t.Nodes = append(t.Nodes, model.Node{ID: "x1", Name: "x1", Role: model.RoleExit, EgressV4: true, PathV4: true,
				External: &model.ExternalExit{Carrier: "dc2", SOCKSAddress: "192.0.2.66", SOCKSPort: 1080, Interface: "wg9", CredentialID: "socks-abcd"}})
			nodeIdx(t, "tw2").ViaExit = "x1"
		}, "via_exit_external"},
		{"endpoint host on a hub", func(t *model.Topology) { nodeIdx(t, "hk5").EndpointHost = "hub.example.net" }, "endpoint_host_not_exit"},
		{"bad endpoint host", func(t *model.Topology) { nodeIdx(t, "dc1").EndpointHost = "Not A Name" }, "bad_endpoint_host"},
	}
	for _, c := range cases {
		topo := defaults.NestedExample()
		c.mut(&topo)
		if !errCodes(topo)[c.code] {
			t.Errorf("%s: want %s, got %v", c.name, c.code, errCodes(topo))
		}
	}
}

func TestExternalValidation(t *testing.T) {
	ext := func(t *model.Topology) *model.Node { return nodeIdx(t, "my1") }
	cases := []struct {
		name string
		mut  func(*model.Topology)
		code string
	}{
		{"managed", func(t *model.Topology) { ext(t).Managed = true }, "external_managed"},
		{"server", func(t *model.Topology) { ext(t).ServerID = "srv-1" }, "external_has_server"},
		{"v6", func(t *model.Topology) { ext(t).EgressV6 = true }, "external_v6"},
		{"endpoint", func(t *model.Topology) { ext(t).EndpointV4 = "203.0.113.99" }, "external_endpoint"},
		{"link", func(t *model.Topology) {
			t.Links = append(t.Links, model.Link{ID: "ix-my1", From: "ix", To: "my1", Transport: model.TransportDirectWG, Enabled: true})
		}, "external_link"},
		{"no carrier", func(t *model.Topology) { ext(t).External.Carrier = "" }, "external_carrier_missing"},
		{"unknown carrier", func(t *model.Topology) { ext(t).External.Carrier = "nope" }, "external_carrier_missing"},
		{"carrier is a hub", func(t *model.Topology) { ext(t).External.Carrier = "ix" }, "external_carrier_not_exit"},
		{"carrier unmanaged", func(t *model.Topology) { nodeIdx(t, "dc2").Managed = false }, "external_carrier_unmanaged"},
		{"bad address", func(t *model.Topology) { ext(t).External.SOCKSAddress = "2001:db8::1" }, "external_socks_address"},
		{"meridian range", func(t *model.Topology) { ext(t).External.SOCKSAddress = "10.66.3.4" }, "external_socks_address"},
		{"port", func(t *model.Topology) { ext(t).External.SOCKSPort = 0 }, "external_socks_port"},
		{"no interface", func(t *model.Topology) { ext(t).External.Interface = "" }, "external_interface"},
		{"interface is the WAN", func(t *model.Topology) { ext(t).External.Interface = "eth0" }, "external_interface"},
		{"interface is a Meridian tunnel", func(t *model.Topology) { ext(t).External.Interface = "m04" }, "external_interface"},
		{"no credential", func(t *model.Topology) { ext(t).External.CredentialID = "" }, "external_credential_missing"},
		{"bad credential id", func(t *model.Topology) { ext(t).External.CredentialID = "key-abcdef" }, "external_credential_missing"},
		{"nested and external", func(t *model.Topology) { ext(t).ViaExit = "dc1" }, "external_nested"},
	}
	for _, c := range cases {
		topo := defaults.ExternalExample()
		c.mut(&topo)
		if !errCodes(topo)[c.code] {
			t.Errorf("%s: want %s, got %v", c.name, c.code, errCodes(topo))
		}
	}
}

// Adding a nested or an external exit to a stored topology renumbers
// nothing that existed.
func TestNestedExternalAllocationStability(t *testing.T) {
	base := defaults.DualHubExample()
	model.MigrateRegionGroups(&base)
	model.MigrateAllocations(&base)
	before := base.Allocations.Clone()
	for name, next := range map[string]model.Topology{"nested": defaults.NestedExample(), "external": defaults.ExternalExample()} {
		model.MigrateRegionGroups(&next)
		next.Allocations = nil
		model.ReconcileAllocations(before, &next)
		for id, s := range before.Links {
			if next.Allocations.Links[id] != s {
				t.Errorf("%s: link %s moved %v → %v", name, id, s, next.Allocations.Links[id])
			}
		}
		for id, s := range before.Exits {
			if next.Allocations.Exits[id] != s {
				t.Errorf("%s: exit %s moved", name, id)
			}
		}
		for id, s := range before.Groups {
			if next.Allocations.Groups[id] != s {
				t.Errorf("%s: group %s moved", name, id)
			}
		}
		if c := errCodes(next); len(c) > 0 {
			t.Errorf("%s with stored allocations: %v", name, c)
		}
	}
}
