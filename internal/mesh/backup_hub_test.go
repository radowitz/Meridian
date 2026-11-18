package mesh_test

import (
	"testing"

	"github.com/radowitz/meridian/internal/compile"
	"github.com/radowitz/meridian/internal/defaults"
	"github.com/radowitz/meridian/internal/mesh"
	"github.com/radowitz/meridian/internal/model"
)

// The backup hub is a host-level Mesh end like the primary: reused when its
// host already is a node, installed otherwise; each hub gets its own leg to
// an exit that answers both on its one Mesh address.
func TestPlanBackupHubMeshEnd(t *testing.T) {
	topo := defaults.DualHubExample()
	topo.Links = append(topo.Links,
		model.Link{ID: "hkb-dc1-mesh", From: "hkb", To: "dc1", Transport: model.TransportCFMesh, Enabled: true, Standby: true},
		model.Link{ID: "ix-dc1-mesh", From: "ix", To: "dc1", Transport: model.TransportCFMesh, Enabled: true, Standby: true},
	)
	hm := map[string]model.HostMeshDetection{
		"ix":  reusable("ix", reuseAddr(0)),
		"dc1": reusable("dc1", reuseAddr(1)),
	}
	topo = mesh.OverlayHostMesh(topo, hm)
	b, err := compile.Compile(topo)
	if err != nil {
		t.Fatal(err)
	}
	p := mesh.BuildPlan(topo, b.Files)
	for _, is := range p.Issues {
		t.Errorf("issue %+v", is)
	}
	hkb, ok := p.Node("hkb")
	if !ok || !hkb.Install || hkb.Role != model.RoleHub {
		t.Fatalf("hkb not planned as an install end: %+v", hkb)
	}
	if ix, _ := p.Node("ix"); ix.Install || !ix.Existing() {
		t.Fatalf("ix should be reused: %+v", ix)
	}
	if len(p.Legs) != 2 {
		t.Fatalf("legs %+v", p.Legs)
	}
	byHub := map[string]mesh.LegPlan{}
	for _, l := range p.Legs {
		byHub[l.HubID] = l
	}
	ix, bk := byHub["ix"], byHub["hkb"]
	if ix.ExitID != "dc1" || bk.ExitID != "dc1" || ix.Interface == bk.Interface || ix.Port == bk.Port {
		t.Fatalf("legs collide: %+v / %+v", ix, bk)
	}
	if ix.Reuse != mesh.ReuseBoth || bk.Reuse != mesh.ReusePending || ix.Network != reuseAddr(1)+"/32" {
		t.Fatalf("reuse kinds: %+v / %+v", ix, bk)
	}
	// Without the hkb edge the backup hub is not part of the plan.
	topo.Links = topo.Links[:len(topo.Links)-2]
	topo.Links = append(topo.Links, model.Link{ID: "ix-dc1-mesh", From: "ix", To: "dc1", Transport: model.TransportCFMesh, Enabled: true, Standby: true})
	b2, err := compile.Compile(topo)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := mesh.BuildPlan(topo, b2.Files).Node("hkb"); ok {
		t.Fatal("hkb planned without a Mesh edge")
	}
}

// Only the backup hub has Mesh edges: the primary hub is not planned at all
// (no detection, install, health check or withdrawal on it).
func TestPlanOnlyBackupHubMeshSkipsPrimary(t *testing.T) {
	topo := defaults.DualHubExample()
	topo.Links = append(topo.Links,
		model.Link{ID: "hkb-dc1-mesh", From: "hkb", To: "dc1", Transport: model.TransportCFMesh, Enabled: true, Standby: true},
	)
	b, err := compile.Compile(topo)
	if err != nil {
		t.Fatal(err)
	}
	p := mesh.BuildPlan(topo, b.Files)
	if _, ok := p.Node("ix"); ok {
		t.Fatalf("primary hub planned without a Mesh edge: %+v", p.Nodes)
	}
	if _, ok := p.Node("hkb"); !ok {
		t.Fatal("backup hub missing from the plan")
	}
	if _, ok := p.Node("dc1"); !ok {
		t.Fatal("exit missing from the plan")
	}
	for _, l := range p.Legs {
		if l.HubID != "hkb" {
			t.Fatalf("leg from %s: %+v", l.HubID, l)
		}
	}
}
