package mesh_test

import (
	"context"
	"errors"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/radowitz/meridian/internal/mesh"
	"github.com/radowitz/meridian/internal/model"
)

func TestDeployHappyPathOrderAndUnverifiedDataplane(t *testing.T) {
	f, srv := newFakeCF(t)
	rem := &fakeRemote{}
	d := newDeployer(t, f, srv, rem)
	p := meshPlan(t)
	j, err := d.Deploy(context.Background(), p)
	if err != nil {
		t.Fatal(err)
	}
	if j.State != mesh.StatePublished || j.Dataplane != mesh.DataplaneUnverified {
		t.Fatalf("state %s dataplane %s", j.State, j.Dataplane)
	}
	for _, s := range j.Stages {
		if s.Status != "done" {
			t.Fatalf("stage %s %s", s.Name, s.Status)
		}
	}
	if len(f.routes) != len(p.Routes) || len(f.nodes) != len(p.Nodes) {
		t.Fatalf("cf has %d routes %d nodes, plan %d %d", len(f.routes), len(f.nodes), len(p.Routes), len(p.Nodes))
	}
	// Each route belongs to its exit's node, not the hub's.
	for _, r := range f.routes {
		var owner string
		for _, n := range j.Nodes {
			if n.CFID == r.TunnelID {
				owner = n.NodeID
			}
		}
		ok := false
		for _, pr := range p.Routes {
			if pr.Network == r.Network && pr.ExitID == owner {
				ok = true
			}
		}
		if !ok {
			t.Errorf("route %s published for %s", r.Network, owner)
		}
	}
	// Ordering: every install precedes every health check; health precedes
	// the first route publication; activate is last.
	lastInstall, firstHealth := -1, -1
	for i, c := range rem.calls {
		if strings.HasPrefix(c, "install/") {
			lastInstall = i
		}
		if strings.HasPrefix(c, "health/") && firstHealth < 0 {
			firstHealth = i
		}
	}
	if lastInstall < 0 || firstHealth < lastInstall {
		t.Fatalf("health ran before sidecars were installed: %v", rem.calls)
	}
	if rem.calls[len(rem.calls)-1] != "refresh/hk-hub" {
		t.Fatalf("last remote action %s", rem.calls[len(rem.calls)-1])
	}
	firstRoute := -1
	lastStatus := -1
	for i, l := range f.log {
		if strings.HasPrefix(l, "POST /teamnet/routes") && firstRoute < 0 {
			firstRoute = i
		}
		if strings.HasPrefix(l, "GET /warp_connector/") && !strings.HasSuffix(l, "/token") {
			lastStatus = i
		}
	}
	if firstRoute < lastStatus {
		t.Fatal("a route was published before every node was healthy at Cloudflare")
	}
	// A second deploy is refused while published.
	if _, err := d.Deploy(context.Background(), p); !errors.Is(err, mesh.ErrBusy) {
		t.Fatalf("second deploy: %v", err)
	}
	// Operator withdrawal removes everything and is idempotent.
	j, err = d.Withdraw(context.Background())
	if err != nil || j.State != mesh.StateWithdrawn {
		t.Fatalf("withdraw: %v %v", err, j.State)
	}
	if len(f.routes) != 0 || len(f.nodes) != 0 {
		t.Fatal("withdraw left Cloudflare resources")
	}
	if _, err := d.Withdraw(context.Background()); !errors.Is(err, mesh.ErrNothingToWithdraw) {
		t.Fatalf("second withdraw: %v", err)
	}
}

// Every stage fails once (fault injection after it succeeded); later stages
// never run and everything the run created is withdrawn.
func TestFaultInjectionAtEveryStageCompensates(t *testing.T) {
	for _, stage := range mesh.Stages {
		t.Run(stage, func(t *testing.T) {
			f, srv := newFakeCF(t)
			// A resource the run does not own must survive.
			foreignNode := mesh.CFNode{ID: uuid(), Name: "someone-else", Status: "healthy"}
			f.nodes[foreignNode.ID] = foreignNode
			foreignRoute := mesh.CFRoute{ID: uuid(), Network: "203.0.113.0/24", TunnelID: foreignNode.ID, Comment: "not ours"}
			f.routes[foreignRoute.ID] = foreignRoute
			rem := &fakeRemote{}
			d := newDeployer(t, f, srv, rem)
			d.FailAfter = stage
			j, err := d.Deploy(context.Background(), meshPlan(t))
			var se *mesh.StageError
			if !errors.As(err, &se) || se.Stage != stage || !se.Compensated {
				t.Fatalf("err %v", err)
			}
			if j.State != mesh.StateFailed {
				t.Fatalf("state %s", j.State)
			}
			after := false
			for _, s := range j.Stages {
				if after && s.Status != "skipped" {
					t.Errorf("stage %s after failure is %s", s.Name, s.Status)
				}
				if s.Name == stage {
					after = true
					if s.Status != "failed" {
						t.Errorf("failed stage status %s", s.Status)
					}
				}
			}
			if len(f.nodes) != 1 || len(f.routes) != 1 {
				t.Fatalf("leftovers: %d nodes %d routes", len(f.nodes), len(f.routes))
			}
			if _, ok := f.nodes[foreignNode.ID]; !ok {
				t.Fatal("foreign node removed")
			}
			if _, ok := f.routes[foreignRoute.ID]; !ok {
				t.Fatal("foreign route removed")
			}
			installs, restores := rem.count(mesh.ActInstall), rem.count(mesh.ActRestore)
			if installs != restores {
				t.Fatalf("installs %d restores %d", installs, restores)
			}
			for _, rmt := range j.Remotes {
				if rmt.State != mesh.ResRemoved {
					t.Fatalf("remote %s %s", rmt.NodeID, rmt.State)
				}
			}
			// Idempotent retry: a fresh run after full compensation succeeds.
			d.FailAfter = ""
			if j, err := d.Deploy(context.Background(), meshPlan(t)); err != nil || j.State != mesh.StatePublished {
				t.Fatalf("retry: %v", err)
			}
		})
	}
}

func TestPreflightConflictStopsBeforeCloudflare(t *testing.T) {
	f, srv := newFakeCF(t)
	rem := &fakeRemote{fail: map[string]bool{"preflight/hk-hub": true}}
	d := newDeployer(t, f, srv, rem)
	j, err := d.Deploy(context.Background(), meshPlan(t))
	if err == nil {
		t.Fatal("preflight conflict ignored")
	}
	if len(f.log) != 0 {
		t.Fatalf("cloudflare called after a failed preflight: %v", f.log)
	}
	if rem.count(mesh.ActInstall) != 0 {
		t.Fatal("installed after a failed preflight")
	}
	found := false
	for _, l := range j.StageDetail(mesh.StagePreflight) {
		if strings.Contains(l, "MESH_CONFLICT addr_v4") {
			found = true
		}
	}
	if !found {
		t.Fatal("conflict detail not recorded")
	}
}

func TestHealthFailureNeverPublishesRoutes(t *testing.T) {
	f, srv := newFakeCF(t)
	rem := &fakeRemote{fail: map[string]bool{"health/hk-hub": true}}
	d := newDeployer(t, f, srv, rem)
	if _, err := d.Deploy(context.Background(), meshPlan(t)); err == nil {
		t.Fatal("unhealthy sidecar accepted")
	}
	if f.count("POST /teamnet/routes") != 0 {
		t.Fatal("route published although the sidecar health check failed")
	}
	if len(f.nodes) != 0 {
		t.Fatal("nodes not withdrawn")
	}
	// Cloudflare not healthy also stops before routes.
	f2, srv2 := newFakeCF(t)
	f2.status = "down"
	d2 := newDeployer(t, f2, srv2, &fakeRemote{})
	if _, err := d2.Deploy(context.Background(), meshPlan(t)); err == nil || !strings.Contains(err.Error(), "healthy") {
		t.Fatalf("down node accepted: %v", err)
	}
	if f2.count("POST /teamnet/routes") != 0 || len(f2.nodes) != 0 {
		t.Fatal("down node: routes published or nodes kept")
	}
}

func TestCompensationFailureIsExposedAndRetryable(t *testing.T) {
	f, srv := newFakeCF(t)
	rem := &fakeRemote{fail: map[string]bool{}}
	d := newDeployer(t, f, srv, rem)
	f.failCreateRoute = 2 // the second route fails after the first was published
	f.failDeleteRoute = 1 // and its withdrawal fails once
	j, err := d.Deploy(context.Background(), meshPlan(t))
	var se *mesh.StageError
	if !errors.As(err, &se) || se.Compensated || len(se.CompErrors) == 0 {
		t.Fatalf("compensation failure hidden: %v", err)
	}
	if j.State != mesh.StateCompensationFailed || len(j.CompErrors) == 0 {
		t.Fatalf("state %s comp %v", j.State, j.CompErrors)
	}
	if len(f.routes) != 1 {
		t.Fatalf("expected the one undeletable route to remain, have %d", len(f.routes))
	}
	if _, err := d.Deploy(context.Background(), meshPlan(t)); !errors.Is(err, mesh.ErrBusy) {
		t.Fatal("new deploy allowed while compensation is incomplete")
	}
	j, err = d.Withdraw(context.Background())
	if err != nil || j.State != mesh.StateFailed {
		t.Fatalf("retry withdraw: %v %s", err, j.State)
	}
	if len(f.routes) != 0 || len(f.nodes) != 0 {
		t.Fatal("retry left resources")
	}
	// Restore was not repeated for hosts already restored.
	restores := rem.count(mesh.ActRestore)
	if restores != rem.count(mesh.ActInstall) {
		t.Fatalf("restore ran %d times for %d installs", restores, rem.count(mesh.ActInstall))
	}
}

func TestRemoteRestoreFailureKeepsJournalAndRetries(t *testing.T) {
	f, srv := newFakeCF(t)
	rem := &fakeRemote{fail: map[string]bool{"health/hk-hub": true}, failOnce: map[string]bool{"restore/hk-hub": true}}
	d := newDeployer(t, f, srv, rem)
	j, err := d.Deploy(context.Background(), meshPlan(t))
	if err == nil || j.State != mesh.StateCompensationFailed {
		t.Fatalf("state %v err %v", j.State, err)
	}
	j, err = d.Withdraw(context.Background())
	if err != nil || j.State != mesh.StateFailed {
		t.Fatalf("retry: %v %s", err, j.State)
	}
}

// A route whose create response was lost is found by its run comment and
// withdrawn; a node whose create response was lost by its run name.
func TestLostCreateResponsesAreStillOwned(t *testing.T) {
	f, srv := newFakeCF(t)
	f.routeCreateLost = true
	d := newDeployer(t, f, srv, &fakeRemote{})
	if _, err := d.Deploy(context.Background(), meshPlan(t)); err == nil {
		t.Fatal("lost response treated as success")
	}
	if len(f.routes) != 0 || len(f.nodes) != 0 {
		t.Fatalf("lost-response resources not withdrawn: %d routes %d nodes", len(f.routes), len(f.nodes))
	}
}

func TestTokenRetryDoesNotRecreateNode(t *testing.T) {
	f, srv := newFakeCF(t)
	f.failToken = 2
	d := newDeployer(t, f, srv, &fakeRemote{})
	p := meshPlan(t)
	if _, err := d.Deploy(context.Background(), p); err != nil {
		t.Fatal(err)
	}
	if got := f.count("POST /warp_connector"); got != len(p.Nodes) {
		t.Fatalf("nodes created %d times for %d hosts", got, len(p.Nodes))
	}
}

func TestSecretsNeverPersistedOrReturned(t *testing.T) {
	f, srv := newFakeCF(t)
	rem := &fakeRemote{fail: map[string]bool{"health/us": true}}
	d := newDeployer(t, f, srv, rem)
	_, err := d.Deploy(context.Background(), meshPlan(t))
	if err == nil {
		t.Fatal("expected failure")
	}
	raw, rerr := os.ReadFile(filepath.Join(d.Dir, "deploy.json"))
	if rerr != nil {
		t.Fatal(rerr)
	}
	fi, _ := os.Stat(filepath.Join(d.Dir, "deploy.json"))
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("journal mode %o", fi.Mode().Perm())
	}
	secrets := []string{f.token}
	for _, tok := range f.tokens {
		secrets = append(secrets, tok)
	}
	for _, s := range secrets {
		if strings.Contains(string(raw), s) || strings.Contains(err.Error(), s) {
			t.Fatal("secret leaked into the journal or error")
		}
	}
	// The node token reached the host only inside the install script.
	seen := 0
	for i, sc := range rem.scripts {
		for _, tok := range f.tokens {
			if strings.Contains(sc, tok) {
				if !strings.HasPrefix(rem.calls[i], "install/") {
					t.Fatalf("token sent with %s", rem.calls[i])
				}
				seen++
			}
		}
	}
	if seen == 0 {
		t.Fatal("token never delivered")
	}
}

func TestCFClientShapesAndErrors(t *testing.T) {
	f, srv := newFakeCF(t)
	c := f.client(srv)
	ctx := context.Background()
	n, err := c.CreateNode(ctx, "meridian-x")
	if err != nil || n.ID == "" {
		t.Fatal(err)
	}
	tok, err := c.NodeToken(ctx, n.ID)
	if err != nil || tok == "" {
		t.Fatal(err)
	}
	r, err := c.CreateRoute(ctx, "198.51.100.0/24", n.ID, strings.Repeat("c", 150))
	if err != nil {
		t.Fatal(err)
	}
	if len(f.routes[r.ID].Comment) != 100 {
		t.Fatal("comment not capped at 100 characters")
	}
	list, err := c.ListRoutes(ctx, n.ID)
	if err != nil || len(list) != 1 {
		t.Fatal(err)
	}
	if err := c.DeleteRoute(ctx, r.ID); err != nil {
		t.Fatal(err)
	}
	if err := c.DeleteRoute(ctx, r.ID); !errors.Is(err, mesh.ErrNotFound) {
		t.Fatalf("404 not mapped: %v", err)
	}
	if err := c.DeleteNode(ctx, n.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := c.GetNode(ctx, "../../x"); err == nil {
		t.Fatal("non-uuid id accepted into a path")
	}
	bad := *c
	bad.Token = "wrong-token-value-123456"
	_, err = bad.ListNodes(ctx)
	var ae *mesh.APIError
	if !errors.As(err, &ae) || ae.Status != http.StatusForbidden || strings.Contains(err.Error(), bad.Token) {
		t.Fatalf("auth error: %v", err)
	}
}

func TestCredentialStore(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "mesh")
	s := mesh.CredStore{Dir: dir}
	if _, err := s.Load(); !errors.Is(err, mesh.ErrNoCredentials) {
		t.Fatal(err)
	}
	if err := s.Save(mesh.Credentials{AccountID: "x", APIToken: dummy("t", 16)}); err == nil {
		t.Fatal("bad account accepted")
	}
	if err := s.Save(mesh.Credentials{AccountID: dummy("", 16), APIToken: "has space " + dummy("", 10)}); err == nil {
		t.Fatal("token with whitespace accepted")
	}
	c := mesh.Credentials{AccountID: dummy("", 16), APIToken: dummy("t", 16)}
	if err := s.Save(c); err != nil {
		t.Fatal(err)
	}
	fi, _ := os.Stat(filepath.Join(dir, "cloudflare.json"))
	di, _ := os.Stat(dir)
	if fi.Mode().Perm() != 0o600 || di.Mode().Perm() != 0o700 {
		t.Fatalf("modes %o %o", fi.Mode().Perm(), di.Mode().Perm())
	}
	got, err := s.Load()
	if err != nil || got != c {
		t.Fatal(err)
	}
	if v := got.View(); !v.TokenSet || v.AccountID != c.AccountID {
		t.Fatal("view")
	}
	_ = os.Chmod(filepath.Join(dir, "cloudflare.json"), 0o644)
	if _, err := s.Load(); err == nil {
		t.Fatal("world-readable credentials used")
	}
}

func TestFixedScripts(t *testing.T) {
	a := mesh.DefaultAddressing()
	run := "0123456789abcdef"
	if _, err := mesh.PreflightScript("../x", "hub", a); err == nil {
		t.Fatal("bad run id")
	}
	pre, err := mesh.PreflightScript(run, "hub", a)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"MESH_PREFLIGHT_OK", "default dev mmesh", "via 169.254.66.2 dev mmesh", "via fe80::66:2 dev mmesh", "fe80::66:1", "meridian_mesh_lib", "192.168.100.88"} {
		if !strings.Contains(pre, want) {
			t.Errorf("preflight missing %q", want)
		}
	}
	files := map[string]string{mesh.PathCompose: "services: {}\n", mesh.PathUp: "#!/bin/bash\n"}
	if _, err := mesh.InstallScript(run, files, "tok'en"); err == nil {
		t.Fatal("token with quote accepted")
	}
	tok := dummy("eyJ", 20)
	inst, err := mesh.InstallScript(run, files, tok)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Count(inst, tok) != 1 || !strings.Contains(inst, "put '/etc/meridian/mesh.env' 600") {
		t.Fatal("token must appear once, in the 0600 env file")
	}
	if !strings.Contains(inst, "umask 077") || !strings.Contains(inst, "mesh-sealed") {
		t.Fatal("install script hardening")
	}
	h, _ := mesh.HealthScript(run, a, []string{"10.66.0.0/16"}, []string{"fd66::/48"})
	for _, want := range []string{"ping -6 -c 2 -W 2 -n fe80::66:2%mmesh", "ip -4 neigh show dev mmesh", "via fe80::66:1 dev mmesh-c", "MESH_HEALTH_OK"} {
		if !strings.Contains(h, want) {
			t.Errorf("health missing %q", want)
		}
	}
	rs, _ := mesh.RestoreScript(run, a)
	for _, want := range []string{"sidecar.created", "network.created", "MESH_RESTORE_OK", "nothing from this run"} {
		if !strings.Contains(rs, want) {
			t.Errorf("restore missing %q", want)
		}
	}
}

// deploy/verify-mesh-veth.sh exercises exactly the addressing the compiler
// renders.
func TestNetnsScriptMatchesAddressing(t *testing.T) {
	b, err := os.ReadFile(filepath.Join("..", "..", "deploy", "verify-mesh-veth.sh"))
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	a := mesh.DefaultAddressing()
	for _, want := range []string{a.HostV4CIDR(), a.SidecarV4CIDR(), a.HostV6CIDR(), a.SidecarV6CIDR(), a.HostMAC, a.SidecarMAC,
		"default via " + a.NextHopV4() + " dev mmesh", "default via " + a.NextHopV6() + " dev mmesh", "nud permanent", "NOT-RUN-HERE"} {
		if !strings.Contains(s, want) {
			t.Errorf("verify-mesh-veth.sh missing %q", want)
		}
	}
}

func TestFixedScriptsParse(t *testing.T) {
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("no bash")
	}
	a := mesh.DefaultAddressing()
	run := "0123456789abcdef"
	p := meshPlan(t)
	hub, _ := p.Hub()
	var scripts []string
	for _, role := range []model.Role{model.RoleHub, model.RoleExit} {
		s, _ := mesh.PreflightScript(run, role, a)
		scripts = append(scripts, s)
	}
	inst, _ := mesh.InstallScript(run, hub.Files, dummy("eyJ", 20))
	h, _ := mesh.HealthScript(run, a, p.ReturnV4, p.ReturnV6)
	rf, _ := mesh.RefreshScript(run)
	rs, _ := mesh.RestoreScript(run, a)
	scripts = append(scripts, inst, h, rf, rs)
	for i, s := range scripts {
		f := filepath.Join(t.TempDir(), "s.sh")
		_ = os.WriteFile(f, []byte(s), 0o600)
		if out, err := exec.Command("bash", "-n", f).CombinedOutput(); err != nil {
			t.Errorf("script %d: %v %s", i, err, out)
		}
	}
}
