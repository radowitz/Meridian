package mesh_test

import (
	"context"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/radowitz/meridian/internal/compile"
	"github.com/radowitz/meridian/internal/mesh"
	"github.com/radowitz/meridian/internal/model"
)

// Synthetic host-level Mesh nodes: addresses in the Mesh range, a fixed
// interface name, no real host.
const reuseIface = "CloudflareWARP"

func reuseAddr(i int) string { return fmt.Sprintf("100.96.0.%d", 10+i) }

func detectOut(addr string) string {
	return "MESHHOST svc running\nMESHHOST cli present\nMESHHOST addr " + reuseIface + " " + addr + "/32\nMESHHOST done 1\n"
}

func reusable(id, addr string) model.HostMeshDetection {
	return model.HostMeshDetection{NodeID: id, State: model.HostMeshExisting, Reusable: true, Origin: model.MeshOriginExisting, MeshAddr: addr, Iface: reuseIface}
}

// meshEnds lists the primary hub and the exits of enabled Mesh links.
func meshEnds(t *testing.T, topo model.Topology) (string, []string) {
	t.Helper()
	hub, _ := topo.PrimaryHub()
	var exits []string
	for _, l := range topo.Links {
		if l.Transport == model.TransportCFMesh && l.Enabled {
			if l.From == hub.ID {
				exits = append(exits, l.To)
			} else {
				exits = append(exits, l.From)
			}
		}
	}
	return hub.ID, exits
}

func reusePlan(t *testing.T, hm map[string]model.HostMeshDetection) (model.Topology, mesh.Plan) {
	t.Helper()
	topo := mesh.OverlayHostMesh(meshTopo(t), hm)
	b, err := compile.Compile(topo)
	if err != nil {
		t.Fatal(err)
	}
	return topo, mesh.BuildPlan(topo, b.Files)
}

func TestMeshReuseBothEndsNoSidecarNoRoute(t *testing.T) {
	hub, exits := meshEnds(t, meshTopo(t))
	hm := map[string]model.HostMeshDetection{hub: reusable(hub, reuseAddr(0))}
	rem := &fakeRemote{detect: map[string]string{hub: detectOut(reuseAddr(0))}}
	for i, e := range exits {
		hm[e] = reusable(e, reuseAddr(i+1))
		rem.detect[e] = detectOut(reuseAddr(i + 1))
	}
	_, p := reusePlan(t, hm)
	mesh.ApplyHostMesh(&p, hm, false)
	if !p.OK() {
		t.Fatalf("plan issues: %+v", p.Issues)
	}
	if len(p.Routes) != 0 || len(p.Install) != 0 {
		t.Fatalf("both ends reused: no route and nothing to confirm, got %+v / %v", p.Routes, p.Install)
	}
	for _, l := range p.Legs {
		if l.Reuse != mesh.ReuseBoth || l.Network != hm[l.ExitID].MeshAddr+"/32" {
			t.Fatalf("leg %s: reuse %q network %s", l.LinkID, l.Reuse, l.Network)
		}
	}
	d, cf, _ := lifecycleDeployer(t)
	d.Remote = rem
	rem.account = d.AccountID
	j, err := d.Deploy(context.Background(), p)
	if err != nil {
		t.Fatalf("deploy: %v", err)
	}
	if len(cf.nodes) != 0 || len(cf.routes) != 0 || rem.count(mesh.ActConnectorInstall) != 0 || rem.count(mesh.ActInstall) != 0 || rem.count(mesh.ActRefresh) != 0 {
		t.Fatalf("reused nodes must not be registered, installed or re-sealed: cf %d/%d calls %v", len(cf.nodes), len(cf.routes), rem.calls)
	}
	if len(j.Existing) != len(p.Nodes) || len(j.Nodes)+len(j.Remotes)+len(j.Routes) != 0 {
		t.Fatalf("journal must own nothing: %+v", j)
	}
	// The host-node preflight: no sidecar checks, the route check names
	// the Mesh interface.
	for i, c := range rem.calls {
		if c == "preflight/"+hub {
			s := rem.scripts[i]
			if strings.Contains(s, "host_warp") || strings.Contains(s, "docker") || !strings.Contains(s, "grep -v 'dev "+reuseIface+"'") {
				t.Fatalf("hub preflight is not the host-node one:\n%s", s)
			}
		}
	}
	before := len(rem.calls)
	if _, err := d.Withdraw(context.Background()); err != nil {
		t.Fatalf("withdraw: %v", err)
	}
	if rem.count(mesh.ActConnectorRemove) != 0 || rem.count(mesh.ActRestore) != 0 || len(rem.calls) != before {
		t.Fatalf("withdrawal touched a reused node: %v", rem.calls[before:])
	}
}

// The exit already is a node, the hub has none: only the hub gets the
// host-level connector, after the operator confirmed its install plan; the
// exit is never registered, installed or withdrawn.
func TestMeshReuseExitOnlyInstallsConnectorOnHub(t *testing.T) { // the other exits get one as well
	t.Setenv(mesh.RepoKeyFingerprintEnv, testFpr)
	topo := meshTopo(t)
	hub, exits := meshEnds(t, topo)
	ex := exits[0]
	hm := map[string]model.HostMeshDetection{ex: reusable(ex, reuseAddr(1)), hub: installable(hub)}
	for _, e := range exits[1:] {
		hm[e] = installable(e)
	}
	topo = mesh.OverlayHostMesh(topo, hm)
	b, err := compile.Compile(topo)
	if err != nil {
		t.Fatal(err)
	}
	p := mesh.BuildPlan(topo, b.Files)
	q := p
	q.Nodes = append([]mesh.NodeTarget(nil), p.Nodes...)
	mesh.ApplyHostMesh(&q, hm, false)
	if q.OK() || q.Issues[len(q.Issues)-1].Code != "mesh_install_confirm_required" || q.Install[0] != hub || len(q.Install) != len(exits) {
		t.Fatalf("unconfirmed install must be refused: %+v %v", q.Issues, q.Install)
	}
	blocked := installable(hub)
	blocked.Install.Recommended = ""
	blocked.Install.Options[0].Blockers = []string{"主机连不上官方软件源"}
	q = p
	q.Nodes = append([]mesh.NodeTarget(nil), p.Nodes...)
	bm := map[string]model.HostMeshDetection{}
	for k, v := range hm {
		bm[k] = v
	}
	bm[hub] = blocked
	mesh.ApplyHostMesh(&q, bm, true)
	if q.OK() || q.Issues[0].Code != "mesh_install_blocked" || !strings.Contains(q.Issues[0].Message, "软件源") {
		t.Fatalf("a blocked install must stop: %+v", q.Issues)
	}
	mesh.ApplyHostMesh(&p, hm, true)
	if !p.OK() || len(p.Routes) != 0 {
		t.Fatalf("plan: %+v routes %v", p.Issues, p.Routes)
	}
	for _, l := range p.Legs {
		if l.ExitID == ex && (l.Reuse != mesh.ReusePending || l.Network != reuseAddr(1)+"/32") {
			t.Fatalf("leg to the reused exit: %+v", l)
		}
	}
	d, cf, rem := lifecycleDeployer(t)
	rem.detect = map[string]string{ex: detectOut(reuseAddr(1))}
	j, err := d.Deploy(context.Background(), p)
	if err != nil {
		t.Fatalf("deploy: %v", err)
	}
	if rem.has("connector_install/"+ex) || rem.has("connector_preflight/"+ex) || !rem.has("connector_install/"+hub) || !rem.has("detect/"+ex) {
		t.Fatalf("install only on the hub: %v", rem.calls)
	}
	if len(cf.nodes) != len(exits) {
		t.Fatalf("one registration per installed host, got %d", len(cf.nodes))
	}
	for _, n := range cf.nodes {
		if strings.Contains(n.Name, "-"+ex+"-") {
			t.Fatalf("reused exit registered: %s", n.Name)
		}
	}
	if !reflect.DeepEqual(j.Existing, []string{ex}) || len(j.Remotes) != len(exits) || j.Remotes[0].NodeID != hub {
		t.Fatalf("ownership: existing %v remotes %+v", j.Existing, j.Remotes)
	}
	if _, err := d.Withdraw(context.Background()); err != nil {
		t.Fatalf("withdraw: %v", err)
	}
	if rem.has("connector_remove/"+ex) || !rem.has("connector_remove/"+hub) || len(cf.nodes) != 0 {
		t.Fatalf("withdrawal must remove only the hub's connector: %v", rem.calls)
	}
}

func TestMeshReuseHealthRefusesChangedNode(t *testing.T) {
	hub, exits := meshEnds(t, meshTopo(t))
	hm := map[string]model.HostMeshDetection{hub: reusable(hub, reuseAddr(0))}
	rem := &fakeRemote{detect: map[string]string{hub: detectOut("100.96.0.99")}}
	for i, e := range exits {
		hm[e] = reusable(e, reuseAddr(i+1))
		rem.detect[e] = detectOut(reuseAddr(i + 1))
	}
	_, p := reusePlan(t, hm)
	d, cf, _ := lifecycleDeployer(t)
	d.Remote = rem
	rem.account = d.AccountID
	if _, err := d.Deploy(context.Background(), p); err == nil {
		t.Fatal("a reused node whose address changed must fail health")
	}
	if len(cf.routes) != 0 || rem.count(mesh.ActConnectorRemove) != 0 || rem.count(mesh.ActRestore) != 0 {
		t.Fatalf("failure compensation must not touch reused nodes: %v", rem.calls)
	}
}

func TestMeshOverlayOnlyReusableMeshEnds(t *testing.T) {
	topo := meshTopo(t)
	hub, _ := meshEnds(t, topo)
	notReusable := reusable(hub, reuseAddr(0))
	notReusable.Reusable = false
	panel := reusable(hub, reuseAddr(0))
	panel.Origin = model.MeshOriginPanel // a legacy sidecar record
	outside := reusable(hub, "203.0.113.5")
	for name, d := range map[string]model.HostMeshDetection{"not reusable": notReusable, "panel owned": panel, "outside the Mesh range": outside} {
		o := mesh.OverlayHostMesh(topo, map[string]model.HostMeshDetection{hub: d})
		for _, n := range o.Nodes {
			if n.MeshHost != nil {
				t.Fatalf("%s: overlay set %s", name, n.ID)
			}
		}
	}
	// A node the panel installed is a host node too (panel-owned).
	own := reusable(hub, reuseAddr(0))
	own.Origin, own.PanelOwned = model.MeshOriginPanelHost, true
	o := mesh.OverlayHostMesh(topo, map[string]model.HostMeshDetection{hub: own})
	for _, n := range o.Nodes {
		if n.ID == hub && (n.MeshHost == nil || !n.MeshHost.PanelOwned || n.MeshHost.Addr != reuseAddr(0)) {
			t.Fatalf("panel-installed node not overlaid: %+v", n.MeshHost)
		}
	}
	// A topology without Mesh edges is returned as it is.
	plain := meshTopo(t)
	var links []model.Link
	for _, l := range plain.Links {
		if l.Transport != model.TransportCFMesh {
			links = append(links, l)
		}
	}
	plain.Links = links
	o = mesh.OverlayHostMesh(plain, map[string]model.HostMeshDetection{hub: reusable(hub, reuseAddr(0))})
	if !reflect.DeepEqual(o, plain) {
		t.Fatal("overlay changed a topology without Mesh edges")
	}
}
