package api

import (
	"context"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/radowitz/meridian/internal/compile"
	"github.com/radowitz/meridian/internal/defaults"
	"github.com/radowitz/meridian/internal/hostexec"
	"github.com/radowitz/meridian/internal/hubstate"
	"github.com/radowitz/meridian/internal/model"
	"github.com/radowitz/meridian/internal/sshexec"
	"github.com/radowitz/meridian/internal/sshexec/sshtest"
)

type fakeUpstream struct {
	mu  sync.Mutex
	st  hostexec.UpstreamStatus
	err error
}

func (f *fakeUpstream) UpstreamStatus(context.Context) (hostexec.UpstreamStatus, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.st, f.err
}

func (f *fakeUpstream) set(hub, tier string, beat int64) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.st = hostexec.UpstreamStatus{Present: true, ReadAt: time.Now().UTC().Format(time.RFC3339),
		Record: &hostexec.UpstreamState{Beat: beat, Path: "backup", Iface: "m02", Hub: hub, Tier: tier, Since: beat - 100, State: hostexec.UpstreamOK}}
}

type dualBody struct {
	Groups []struct {
		ID     string `json:"id"`
		Actual struct {
			State      string `json:"state"`
			Code       string `json:"code"`
			Active     string `json:"active"`
			HubTier    string `json:"hub_tier"`
			HubNode    string `json:"hub_node"`
			ServerName string `json:"server_name"`
		} `json:"actual"`
		ByHub []struct {
			Tier     string `json:"tier"`
			HubNode  string `json:"hub_node"`
			State    string `json:"state"`
			Code     string `json:"code"`
			Active   string `json:"active"`
			Carrying bool   `json:"carrying"`
		} `json:"actual_by_hub"`
		MemberStatus []struct {
			ID           string `json:"id"`
			ActualActive bool   `json:"actual_active"`
		} `json:"member_status"`
	} `json:"groups"`
	HubStates []struct {
		Tier     string `json:"tier"`
		HubNode  string `json:"hub_node"`
		Carrying bool   `json:"carrying"`
		PlanID   string `json:"plan_id"`
	} `json:"hub_states"`
	Carrying struct {
		Mode  string `json:"mode"`
		Known bool   `json:"known"`
		Tier  string `json:"tier"`
		Hub   string `json:"hub_node"`
		Code  string `json:"code"`
	} `json:"carrying"`
}

type dualHubFixture struct {
	t        *testing.T
	s        *Server
	up       *fakeUpstream
	srv      map[string]*sshtest.Server // hub node → server
	serverID map[string]string
	plan     map[string]string
	mu       sync.Mutex
	answer   map[string]string
}

func newDualHubFixture(t *testing.T) *dualHubFixture {
	t.Helper()
	f := &dualHubFixture{t: t, s: newTest(t), up: &fakeUpstream{}, srv: map[string]*sshtest.Server{}, serverID: map[string]string{}, plan: map[string]string{}, answer: map[string]string{}}
	f.s.Upstream = f.up
	topo := defaults.DualHubExample()
	model.MigrateRegionGroups(&topo)
	if err := f.s.Store.Save(topo); err != nil {
		t.Fatal(err)
	}
	for _, hub := range []string{"ix", "hk5"} {
		hub := hub
		srv, err := sshtest.Start()
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(srv.Close)
		pw := "pw-" + rnd(t, 8)
		srv.SetPassword(pw)
		srv.SetHandler(func(cmd, stdin string) (string, uint32) {
			if cmd != sshexec.GroupStateCommand {
				return "unexpected", 1
			}
			f.mu.Lock()
			defer f.mu.Unlock()
			if a := f.answer[hub]; a != "" {
				return a, 0
			}
			return "", 1
		})
		f.srv[hub] = srv
		rr := do(f.s, http.MethodPost, "/api/ssh-credentials", mustJSON(map[string]any{"name": hub, "kind": "password", "password": pw}))
		var c struct{ Credential credView }
		decode(t, rr, &c)
		rr = do(f.s, http.MethodPost, "/api/servers", mustJSON(map[string]any{"name": "srv-" + hub, "address": srv.Host, "port": srv.Port, "user": "ops", "auth": "password", "credential_id": c.Credential.ID}))
		var sv struct{ Server serverView }
		decode(t, rr, &sv)
		f.serverID[hub] = sv.Server.ID
		rr = do(f.s, http.MethodPost, "/api/servers/"+sv.Server.ID+"/host-key/discover", nil)
		var disc struct{ Discovery sshexec.Discovery }
		decode(t, rr, &disc)
		if rr = do(f.s, http.MethodPost, "/api/servers/"+sv.Server.ID+"/host-key/trust", mustJSON(map[string]string{"fingerprint": disc.Discovery.Fingerprint})); rr.Code != 200 {
			t.Fatal(rr.Body.String())
		}
	}
	topo, _, _ = f.s.Store.Load()
	for i := range topo.Nodes {
		if id, ok := f.serverID[topo.Nodes[i].ID]; ok {
			topo.Nodes[i].ServerID = id
		}
	}
	if err := f.s.Store.Save(topo); err != nil {
		t.Fatal(err)
	}
	for _, hub := range []string{"ix", "hk5"} {
		plans, err := compile.PlanGroupsForHub(topo, hub)
		if err != nil {
			t.Fatal(err)
		}
		f.plan[hub] = compile.GroupPlanID(plans)
	}
	if f.plan["ix"] == f.plan["hk5"] {
		t.Fatal("hubs share a plan ID")
	}
	return f
}

func (f *dualHubFixture) serve(hub, member string) {
	now := time.Now().Unix()
	f.mu.Lock()
	f.answer[hub] = hubOutput(f.plan[hub], now, hubReport("hk", f.plan[hub], now-2, "hop "+member, "active "+member))
	f.mu.Unlock()
}

func (f *dualHubFixture) get(path string, method string) dualBody {
	f.t.Helper()
	rr := do(f.s, method, path, nil)
	if rr.Code != 200 {
		f.t.Fatalf("%s: %d %s", path, rr.Code, rr.Body.String())
	}
	var b dualBody
	decode(f.t, rr, &b)
	if len(b.Groups) != 1 || b.Groups[0].ID != "hk" {
		f.t.Fatalf("groups: %+v", b.Groups)
	}
	return b
}

// With a backup hub the group's actual state is read from the hub the
// gateway says carries the traffic, each hub's report is judged against its
// own plan, and nothing is shown as in use while the carrying hub is
// unknown.
func TestDualHubRuntimeFollowsCarryingHub(t *testing.T) {
	f := newDualHubFixture(t)
	f.serve("ix", "dc1")
	f.serve("hk5", "dc2")
	b := f.get("/api/region-groups/runtime/refresh", http.MethodPost)
	for hub, srv := range f.srv {
		if cmds := srv.Commands(); len(cmds) != 1 || cmds[0] != sshexec.GroupStateCommand {
			t.Fatalf("%s: commands %q", hub, cmds)
		}
	}
	g := b.Groups[0]
	// The gateway has no record yet: carrying unknown, no member in use.
	if b.Carrying.Mode != "dual" || b.Carrying.Known || b.Carrying.Code != "not_recorded" {
		t.Fatalf("carrying: %+v", b.Carrying)
	}
	if g.Actual.State != hubstate.StateUnavailable || g.Actual.Code != CodeCarryingUnknown || g.Actual.Active != "" {
		t.Fatalf("actual without carrying hub: %+v", g.Actual)
	}
	for _, m := range g.MemberStatus {
		if m.ActualActive {
			t.Fatalf("member %s shown in use", m.ID)
		}
	}
	if len(g.ByHub) != 2 || g.ByHub[0].Tier != "primary" || g.ByHub[0].Active != "dc1" || g.ByHub[1].Tier != "backup" || g.ByHub[1].Active != "dc2" ||
		g.ByHub[0].Carrying || g.ByHub[1].Carrying {
		t.Fatalf("per hub: %+v", g.ByHub)
	}
	if len(b.HubStates) != 2 || b.HubStates[0].PlanID != f.plan["ix"] || b.HubStates[1].PlanID != f.plan["hk5"] {
		t.Fatalf("hub states: %+v", b.HubStates)
	}

	// The gateway says the backup carries.
	f.up.set("hk5", "backup", time.Now().Unix())
	b = f.get("/api/region-groups", http.MethodGet)
	g = b.Groups[0]
	if !b.Carrying.Known || b.Carrying.Tier != "backup" || b.Carrying.Hub != "hk5" {
		t.Fatalf("carrying: %+v", b.Carrying)
	}
	if g.Actual.State != hubstate.StateOK || g.Actual.Active != "dc2" || g.Actual.HubTier != "backup" || g.Actual.HubNode != "hk5" || g.Actual.ServerName != "srv-hk5" {
		t.Fatalf("actual from backup: %+v", g.Actual)
	}
	if !b.HubStates[1].Carrying || b.HubStates[0].Carrying {
		t.Fatalf("carrying flags: %+v", b.HubStates)
	}
	// The primary carries.
	f.up.set("ix", "primary", time.Now().Unix())
	if g := f.get("/api/region-groups", http.MethodGet).Groups[0]; g.Actual.Active != "dc1" || g.Actual.HubTier != "primary" {
		t.Fatalf("actual from primary: %+v", g.Actual)
	}
	// A stale record, or one naming a hub the topology does not have as
	// that tier, is not believed.
	f.up.set("ix", "primary", time.Now().Add(-2*time.Minute).Unix())
	if b := f.get("/api/region-groups", http.MethodGet); b.Carrying.Known || b.Carrying.Code != "stale" || b.Groups[0].Actual.Code != CodeCarryingUnknown {
		t.Fatalf("stale: %+v %+v", b.Carrying, b.Groups[0].Actual)
	}
	f.up.set("hk5", "primary", time.Now().Unix())
	if b := f.get("/api/region-groups", http.MethodGet); b.Carrying.Known || b.Carrying.Code != "record_mismatch" {
		t.Fatalf("mismatch: %+v", b.Carrying)
	}
	// Agent down.
	f.up.mu.Lock()
	f.up.err = hostexec.ErrUnavailable
	f.up.mu.Unlock()
	if b := f.get("/api/region-groups", http.MethodGet); b.Carrying.Known || b.Carrying.Code != "agent_unavailable" {
		t.Fatalf("agent down: %+v", b.Carrying)
	}
}

// Identity binding per hub: changing the backup hub's server address
// invalidates the backup's stored read at once, the primary's is
// untouched; reassigning the backup hub to the primary's server does too.
func TestDualHubIdentityPerHub(t *testing.T) {
	f := newDualHubFixture(t)
	f.serve("ix", "dc1")
	f.serve("hk5", "dc2")
	f.get("/api/region-groups/runtime/refresh", http.MethodPost)
	f.up.set("hk5", "backup", time.Now().Unix())
	if g := f.get("/api/region-groups", http.MethodGet).Groups[0]; g.Actual.State != hubstate.StateOK {
		t.Fatalf("before: %+v", g.Actual)
	}
	rr := do(f.s, http.MethodPatch, "/api/servers/"+f.serverID["hk5"], mustJSON(map[string]any{"address": "192.0.2.77"}))
	if rr.Code != 200 {
		t.Fatal(rr.Body.String())
	}
	g := f.get("/api/region-groups", http.MethodGet).Groups[0]
	if g.Actual.State != hubstate.StateUnavailable || g.Actual.Code != hubstate.CodeIdentityChanged || g.Actual.Active != "" {
		t.Fatalf("backup identity change not rejected: %+v", g.Actual)
	}
	if g.ByHub[0].State != hubstate.StateOK || g.ByHub[0].Active != "dc1" {
		t.Fatalf("primary read lost: %+v", g.ByHub[0])
	}
	// Swap: the backup node now runs on the primary's server; the backup's
	// stored read (taken from srv-hk5) does not describe it.
	topo, _, _ := f.s.Store.Load()
	for i := range topo.Nodes {
		if topo.Nodes[i].ID == "hk5" {
			topo.Nodes[i].ServerID = f.serverID["ix"]
		}
		if topo.Nodes[i].ID == "ix" {
			topo.Nodes[i].ServerID = f.serverID["hk5"]
		}
	}
	if err := f.s.Store.Save(topo); err != nil {
		t.Fatal(err)
	}
	g = f.get("/api/region-groups", http.MethodGet).Groups[0]
	for _, h := range g.ByHub {
		if h.Code != hubstate.CodeIdentityChanged {
			t.Fatalf("swapped servers: %+v", g.ByHub)
		}
	}
}

func TestUpstreamEndpointSingleHub(t *testing.T) {
	s := newTest(t)
	rr := do(s, http.MethodGet, "/api/upstream", nil)
	if rr.Code != 200 || !strings.Contains(rr.Body.String(), `"mode":"single"`) || !strings.Contains(rr.Body.String(), `"hub_node":"hk-hub"`) {
		t.Fatal(rr.Body.String())
	}
}
