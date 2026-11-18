package mesh_test

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/radowitz/meridian/internal/mesh"
)

// All Cloudflare responses are in memory; no listener or remote is used.
type lifecycleCF struct {
	nodes      map[string]mesh.CFNode
	routes     map[string]mesh.CFRoute
	seq        int
	failDelete bool
}

func (f *lifecycleCF) CreateNode(_ context.Context, name string) (mesh.CFNode, error) {
	f.seq++
	n := mesh.CFNode{ID: fmt.Sprint(f.seq), Name: name, Status: "healthy"}
	f.nodes[n.ID] = n
	return n, nil
}
func (f *lifecycleCF) GetNode(_ context.Context, id string) (mesh.CFNode, error) {
	n, ok := f.nodes[id]
	if !ok {
		return n, mesh.ErrNotFound
	}
	return n, nil
}
func (f *lifecycleCF) ListNodes(context.Context) ([]mesh.CFNode, error) {
	var out []mesh.CFNode
	for _, n := range f.nodes {
		out = append(out, n)
	}
	return out, nil
}
func (f *lifecycleCF) DeleteNode(_ context.Context, id string) error { delete(f.nodes, id); return nil }
func (f *lifecycleCF) NodeToken(context.Context, string) (string, error) {
	return "synthetic-mesh-token", nil
}
func (f *lifecycleCF) CreateRoute(_ context.Context, network, tunnel, comment string) (mesh.CFRoute, error) {
	f.seq++
	r := mesh.CFRoute{ID: fmt.Sprint(f.seq), Network: network, TunnelID: tunnel, Comment: comment}
	f.routes[r.ID] = r
	return r, nil
}
func (f *lifecycleCF) ListRoutes(_ context.Context, tunnel string) ([]mesh.CFRoute, error) {
	var out []mesh.CFRoute
	for _, r := range f.routes {
		if r.TunnelID == tunnel {
			out = append(out, r)
		}
	}
	return out, nil
}
func (f *lifecycleCF) DeleteRoute(_ context.Context, id string) error {
	if f.failDelete {
		return errors.New("synthetic deletion failure")
	}
	delete(f.routes, id)
	return nil
}

func lifecycleDeployer(t *testing.T) (*mesh.Deployer, *lifecycleCF, *fakeRemote) {
	t.Helper()
	cf := &lifecycleCF{nodes: map[string]mesh.CFNode{}, routes: map[string]mesh.CFRoute{}}
	rem := &fakeRemote{account: strings.Repeat("a", 32)}
	return &mesh.Deployer{Dir: t.TempDir(), CF: cf, AccountID: strings.Repeat("a", 32), Remote: rem}, cf, rem
}
func legSubset(p mesh.Plan, count int) mesh.Plan {
	p.Legs = append([]mesh.LegPlan(nil), p.Legs[:count]...)
	nodes := map[string]bool{}
	links := map[string]bool{}
	for _, l := range p.Legs {
		nodes[l.HubID] = true
		nodes[l.ExitID] = true
		links[l.LinkID] = true
	}
	var ns []mesh.NodeTarget
	for _, n := range p.Nodes {
		if nodes[n.ID] {
			n.HostKey = "SHA256:fake-" + n.ID
			ns = append(ns, n)
		}
	}
	p.Nodes = ns
	var rs []mesh.RoutePlan
	for _, r := range p.Routes {
		if links[r.LinkID] {
			rs = append(rs, r)
		}
	}
	p.Routes = rs
	return p
}

// reprovisioned is p as the panel plans it after the hosts j installed were
// detected (panel-owned host nodes) and the hub and exits re-provisioned:
// those nodes are used as they are, and a leg whose ends are both nodes
// dials the exit's Mesh address.
func reprovisioned(p mesh.Plan, j *mesh.Journal) mesh.Plan {
	addr := map[string][2]string{}
	for _, rm := range j.Remotes {
		if rm.Kind == mesh.RemoteConnector && rm.State == mesh.ResCreated {
			addr[rm.NodeID] = [2]string{rm.MeshAddr, rm.MeshIface}
		}
	}
	p.Nodes = append([]mesh.NodeTarget(nil), p.Nodes...)
	for i := range p.Nodes {
		if a, ok := addr[p.Nodes[i].ID]; ok {
			p.Nodes[i].Install, p.Nodes[i].MeshAddr, p.Nodes[i].MeshIface = false, a[0], a[1]
		}
	}
	p.Install = nil
	p.Legs = append([]mesh.LegPlan(nil), p.Legs...)
	for i := range p.Legs {
		h, e := addr[p.Legs[i].HubID], addr[p.Legs[i].ExitID]
		if h[0] != "" && e[0] != "" {
			p.Legs[i].Network, p.Legs[i].Reuse = e[0]+"/32", mesh.ReuseBoth
		}
	}
	return p
}

// One host-level node per host, shared by its legs: the second run reuses
// the hub the first installed and installs only the new exit; withdrawing
// one leg keeps the shared hub; the last withdrawal removes it with the
// original run's markers.
func TestSharedSidecarIncrementAndLegWithdrawal(t *testing.T) {
	d, cf, rem := lifecycleDeployer(t)
	p := meshPlan(t)
	one, two := legSubset(p, 1), legSubset(p, 2)
	ctx := context.Background()
	first, err := d.Deploy(ctx, one)
	if err != nil {
		t.Fatal(err)
	}
	owner := first.RunID
	hub, _ := one.Hub()
	hubCF := first.Nodes[0].CFID
	rem.calls = nil
	two = reprovisioned(two, first)
	second, err := d.Deploy(ctx, two)
	if err != nil {
		t.Fatal(err)
	}
	if second.Legs[0].State != mesh.StatePublished || second.Legs[1].State != mesh.StatePendingProvision {
		t.Fatalf("legs %+v", second.Legs)
	}
	if len(cf.nodes) != 3 || len(cf.routes) != 0 || len(second.Legs) != 2 {
		t.Fatalf("nodes %d routes %d legs %d", len(cf.nodes), len(cf.routes), len(second.Legs))
	}
	for _, c := range rem.calls {
		if c == "connector_install/"+hub.ID || c == "connector_remove/"+hub.ID {
			t.Fatalf("shared hub rewritten: %s", c)
		}
	}
	if _, ok := cf.nodes[hubCF]; !ok {
		t.Fatal("shared registration lost")
	}
	// A new process reads both per-leg state and original backup ownership.
	restarted := &mesh.Deployer{Dir: d.Dir, CF: cf, AccountID: d.AccountID, Remote: rem}
	rem.calls = nil
	j, err := restarted.WithdrawLeg(ctx, two.Legs[1].LinkID)
	if err != nil {
		t.Fatal(err)
	}
	if j.State != mesh.StatePublished || len(cf.nodes) != 2 || len(cf.routes) != 0 {
		t.Fatalf("partial withdrawal: %+v", j)
	}
	for _, c := range rem.calls {
		if c == "connector_remove/"+hub.ID {
			t.Fatal("withdrawing a leg removed the shared hub")
		}
	}
	rem.calls = nil
	rem.scripts = nil
	j, err = restarted.Withdraw(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if j.State != mesh.StateWithdrawn || len(cf.nodes) != 0 || len(cf.routes) != 0 {
		t.Fatalf("final withdrawal: %+v", j)
	}
	found := false
	for i, c := range rem.calls {
		if c == "connector_remove/"+hub.ID {
			found = true
			if !strings.Contains(rem.scripts[i], "mesh-deploy/"+owner) {
				t.Fatal("restore used incremental run rather than original owner")
			}
		}
	}
	if !found {
		t.Fatal("last reference did not restore hub")
	}
}
func TestIncrementFailureAndRestartPreservePublishedLeg(t *testing.T) {
	for _, stage := range mesh.Stages {
		t.Run(stage, func(t *testing.T) {
			d, cf, rem := lifecycleDeployer(t)
			p := meshPlan(t)
			one, two := legSubset(p, 1), legSubset(p, 2)
			ctx := context.Background()
			first, err := d.Deploy(ctx, one)
			if err != nil {
				t.Fatal(err)
			}
			owner := first.RunID
			two = reprovisioned(two, first)
			d.FailAfter = stage
			rem.calls = nil
			// Force compensation to pause after a host write so a new process has
			// to load and resume the durable incremental rollback boundary.
			if stage == mesh.StageInstall {
				rem.fail = map[string]bool{"connector_remove/" + two.Legs[1].ExitID: true}
			}
			_, err = d.Deploy(ctx, two)
			if err == nil {
				t.Fatal("fault injection succeeded")
			}
			restarted := &mesh.Deployer{Dir: d.Dir, CF: cf, AccountID: d.AccountID, Remote: rem}
			j, err := restarted.Load()
			if err != nil {
				t.Fatal(err)
			}
			if j.State == mesh.StateCompensationFailed {
				rem.fail = nil
				j, err = restarted.Withdraw(ctx)
				if err != nil {
					t.Fatal(err)
				}
			}
			if j.State != mesh.StatePublished || j.RunID != owner || len(cf.routes) != 0 || len(cf.nodes) != 2 {
				t.Fatalf("prior deployment not restored: %+v nodes=%d routes=%d", j, len(cf.nodes), len(cf.routes))
			}
			for _, c := range rem.calls {
				if c == "connector_remove/"+one.Legs[0].HubID || c == "connector_remove/"+one.Legs[0].ExitID {
					t.Fatalf("old sidecar removed: %s", c)
				}
			}
		})
	}
}
func TestLegWithdrawalFailureRestartRetriesSameSelection(t *testing.T) {
	d, cf, rem := lifecycleDeployer(t)
	p := legSubset(meshPlan(t), 2)
	ctx := context.Background()
	if _, err := d.Deploy(ctx, p); err != nil {
		t.Fatal(err)
	}
	// The host removal of the withdrawn leg's exit fails: its Cloudflare
	// registration is kept until the host is restored, then retried.
	rem.fail = map[string]bool{"connector_remove/" + p.Legs[1].ExitID: true}
	j, err := d.WithdrawLeg(ctx, p.Legs[1].LinkID)
	if err == nil || j.State != mesh.StateCompensationFailed {
		t.Fatalf("%+v %v", j, err)
	}
	if len(cf.nodes) != 3 {
		t.Fatal("failed host removal deleted its registration")
	}
	rem.fail = nil
	restarted := &mesh.Deployer{Dir: d.Dir, CF: cf, AccountID: d.AccountID, Remote: rem}
	j, err = restarted.Withdraw(ctx)
	if err != nil || j.State != mesh.StatePublished || len(cf.nodes) != 2 || len(cf.routes) != 0 {
		t.Fatalf("%+v %v", j, err)
	}
}
func TestUnderlayPreflightCoversLegsAndRejectsBadParameters(t *testing.T) {
	d, _, _ := lifecycleDeployer(t)
	first, err := d.Deploy(context.Background(), legSubset(meshPlan(t), 1))
	if err != nil {
		t.Fatal(err)
	}
	p := reprovisioned(legSubset(meshPlan(t), 1), first)
	j := &mesh.Journal{RunID: "0123456789abcdef"}
	for _, n := range p.Nodes {
		script, err := mesh.DeploymentPreflight(j, p, n)
		if err != nil {
			t.Fatal(err)
		}
		for _, want := range []string{"leg_mtu", "reuse_node", "WireGuard"} {
			if !strings.Contains(script, want) {
				t.Errorf("%s missing %s", n.ID, want)
			}
		}
		if strings.Contains(script, "mmesh") || strings.Contains(script, "docker") {
			t.Errorf("%s: sidecar check in a host-node preflight", n.ID)
		}
		if n.ID == p.Legs[0].ExitID && !strings.Contains(script, "leg_udp") {
			t.Fatal("listener not checked")
		}
		if n.ID == p.Legs[0].HubID && (!strings.Contains(script, "leg_blackhole") || !strings.Contains(script, "leg_endpoint") || !strings.Contains(script, "dev CloudflareWARP")) {
			t.Fatal("endpoint/route not checked")
		}
	}
	p.Legs[0].Network = "10.68.0.1/32; touch /tmp/bad"
	if _, err := mesh.DeploymentPreflight(j, p, p.Nodes[0]); err == nil {
		t.Fatal("free form endpoint accepted")
	}
	// A target that is neither a host node nor installed (a sidecar) is refused.
	n := p.Nodes[0]
	n.MeshAddr, n.Install = "", false
	if _, err := mesh.DeploymentPreflight(j, p, n); err == nil {
		t.Fatal("sidecar target accepted")
	}
}

func TestIncrementProcessInterruptionRecoversOriginalOwnership(t *testing.T) {
	d, cf, rem := lifecycleDeployer(t)
	p := meshPlan(t)
	one, two := legSubset(p, 1), legSubset(p, 2)
	ctx := context.Background()
	first, err := d.Deploy(ctx, one)
	if err != nil {
		t.Fatal(err)
	}
	two = reprovisioned(two, first)
	rem.after = func(_ *fakeRemote, key string) {
		if key == "connector_install/"+two.Legs[1].ExitID {
			panic("synthetic process interruption")
		}
	}
	func() {
		defer func() {
			if recover() == nil {
				t.Error("interruption did not occur")
			}
		}()
		_, _ = d.Deploy(ctx, two)
	}()
	rem.after = nil
	restarted := &mesh.Deployer{Dir: d.Dir, CF: cf, AccountID: d.AccountID, Remote: rem}
	pending, err := restarted.Load()
	if err != nil || pending.Baseline == nil || pending.State != mesh.StateRunning {
		t.Fatalf("missing durable boundary: %+v %v", pending, err)
	}
	j, err := restarted.Withdraw(ctx)
	if err != nil || j.RunID != first.RunID || j.State != mesh.StatePublished || len(cf.nodes) != 2 || len(cf.routes) != 0 {
		t.Fatalf("restart recovery: %+v %v", j, err)
	}
}

type cancelInstallRemote struct {
	*fakeRemote
	cancel                  context.CancelFunc
	restoredWithLiveContext bool
}

func (r *cancelInstallRemote) Exec(ctx context.Context, n mesh.NodeTarget, act mesh.Action, script string) (string, string, error) {
	if act == mesh.ActConnectorInstall {
		r.cancel()
		return "", "", ctx.Err()
	}
	if act == mesh.ActConnectorRemove {
		r.restoredWithLiveContext = ctx.Err() == nil
	}
	return r.fakeRemote.Exec(ctx, n, act, script)
}
func TestDeploymentCancellationUsesIndependentRecoveryContext(t *testing.T) {
	d, cf, rem := lifecycleDeployer(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	wrapped := &cancelInstallRemote{fakeRemote: rem, cancel: cancel}
	d.Remote = wrapped
	j, err := d.Deploy(ctx, legSubset(meshPlan(t), 1))
	if err == nil || !wrapped.restoredWithLiveContext || j.State != mesh.StateFailed || len(cf.nodes) != 0 || len(cf.routes) != 0 {
		t.Fatalf("cancel recovery: %+v %v live=%v", j, err, wrapped.restoredWithLiveContext)
	}
}
