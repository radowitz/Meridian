package preflight

import (
	"testing"

	"github.com/radowitz/meridian/internal/model"
)

func TestNoLinkFinding(t *testing.T) {
	top := model.Topology{
		Nodes: []model.Node{
			{ID: "gw", Role: model.RoleGateway, Managed: true},
			{ID: "r", Role: model.RoleRelay, Managed: true},
			{ID: "h", Role: model.RoleHub, Managed: true},
			{ID: "e", Role: model.RoleExit, Managed: true},
			{ID: "ix", Role: model.RoleIX},
			{ID: "linked", Role: model.RoleExit, Managed: true},
		},
		Links: []model.Link{
			{ID: "l1", From: "h", To: "e", Enabled: false},
			{ID: "l2", From: "gw", To: "linked", Enabled: true, Transport: model.TransportDirectWG},
		},
	}
	want := map[string]string{
		"r": "这个节点还没有链路：先在拓扑页把它连到网关",
		"h": "这个节点还没有链路：先在拓扑页把它连到中继或 IX",
		"e": "这个节点还没有链路：先在拓扑页把它连到枢纽",
	}
	for _, id := range []string{"gw", "r", "h", "e", "ix", "linked", "missing"} {
		f := NoLinkFinding(top, id)
		msg, blocked := want[id]
		if (f != nil) != blocked {
			t.Fatalf("%s: finding %v, want blocked=%v", id, f, blocked)
		}
		if f != nil && (f.Severity != Blocking || f.Code != CodeNoLink || f.Message != msg) {
			t.Errorf("%s: %+v", id, f)
		}
	}
	if got := NoLinkFindings(top); len(got) != 3 {
		t.Errorf("NoLinkFindings = %d, want 3", len(got))
	}
}

// A dedicated line alone materialises no tunnel: a hub whose only link is
// the line to an IX with no tunnel is blocked. Behind a legacy IX that has
// an enabled relay tunnel the hub ends that tunnel and is not blocked.
func TestNoLinkDedicatedLine(t *testing.T) {
	base := func(relayTunnel bool) model.Topology {
		top := model.Topology{
			Nodes: []model.Node{
				{ID: "gw", Role: model.RoleGateway, Managed: true},
				{ID: "r", Role: model.RoleRelay, Managed: true},
				{ID: "ix", Role: model.RoleIX},
				{ID: "h", Role: model.RoleHub, Managed: true},
			},
			Links: []model.Link{
				{ID: "line", From: "ix", To: "h", Enabled: true, Transport: model.TransportDedicatedLine},
				{ID: "gw-r", From: "gw", To: "r", Enabled: true, Transport: model.TransportDirectWG},
			},
		}
		if relayTunnel {
			top.Links = append(top.Links, model.Link{ID: "r-ix", From: "r", To: "ix", Enabled: true, Transport: model.TransportDirectWG})
		}
		return top
	}
	if f := NoLinkFinding(base(false), "h"); f == nil || f.Code != CodeNoLink {
		t.Fatalf("hub with only a dedicated line: %v", f)
	}
	if f := NoLinkFinding(base(true), "h"); f != nil {
		t.Fatalf("hub behind an IX with a relay tunnel: %+v", f)
	}
	// A disabled relay tunnel does not count.
	top := base(true)
	top.Links[2].Enabled = false
	if f := NoLinkFinding(top, "h"); f == nil {
		t.Fatal("disabled relay tunnel counted")
	}
}
