package api

import (
	"strings"
	"testing"

	"github.com/radowitz/meridian/internal/defaults"
	"github.com/radowitz/meridian/internal/model"
)

// The deployment plan of a topology without an IX (synthetic: defaults
// NoIXExample). Plan generation only: nothing is preflighted or installed.

func noIXPlan(t *testing.T, topo model.Topology) *deployPlan {
	t.Helper()
	topo, servers := orderServers(topo)
	l := &deployLive{t: topo, gw: statusInstall{State: "installed"}, states: map[string]nodeInstallState{},
		bundles: map[string]string{}, idents: map[string]targetIdentity{}, servers: servers}
	return l.plan()
}

func planIDs(p *deployPlan) string {
	var ids []string
	for _, s := range p.Steps {
		ids = append(ids, s.NodeID)
	}
	return strings.Join(ids, ",")
}

func skipOf(p *deployPlan, id string) (planSkip, bool) {
	for _, s := range p.Skipped {
		if s.NodeID == id {
			return s, true
		}
	}
	return planSkip{}, false
}

func TestNoIXDeployPlanOrder(t *testing.T) {
	// One enabled relay; the second relay's links are disabled.
	p := noIXPlan(t, defaults.NoIXExample())
	if got, want := planIDs(p), "dc1,dc2,hkb,hub,access,gw"; got != want {
		t.Fatalf("order %s, want %s", got, want)
	}
	if s, ok := skipOf(p, "access2"); !ok || s.Kind != "inactive" {
		t.Fatalf("access2 not skipped as inactive: %+v", p.Skipped)
	}
	for _, s := range p.Steps {
		if strings.Contains(s.Reason, "IX") || s.NodeID == "ix" {
			t.Fatalf("an IX step or reason in a topology without IX: %+v", s)
		}
	}
	// Two enabled relays: both deployed, one after the other, after the hubs.
	topo := defaults.NoIXExample()
	for i := range topo.Links {
		if strings.Contains(topo.Links[i].ID, "access2") {
			topo.Links[i].Enabled = true
		}
	}
	p = noIXPlan(t, topo)
	if got, want := planIDs(p), "dc1,dc2,hkb,hub,access,access2,gw"; got != want {
		t.Fatalf("two relays: order %s, want %s", got, want)
	}
	if !strings.Contains(p.Steps[4].Reason, "2 台中继") {
		t.Fatalf("relay reason %q", p.Steps[4].Reason)
	}
	// Forcing the inactive relay in (a re-plan) keeps its step.
	topo = defaults.NoIXExample()
	tt, servers := orderServers(topo)
	l := &deployLive{t: tt, gw: statusInstall{State: "installed"}, states: map[string]nodeInstallState{},
		bundles: map[string]string{}, idents: map[string]targetIdentity{}, servers: servers}
	if got := planIDs(l.plan(map[string]bool{"access2": true})); !strings.Contains(got, "access2") {
		t.Fatalf("forced relay dropped: %s", got)
	}
}

// An IX removed from the topology may still have a server record and an
// install record: the plan neither installs nor withdraws it, and has no
// step for it.
func TestNoIXDeployPlanIgnoresRemovedIX(t *testing.T) {
	topo, servers := orderServers(defaults.NoIXExample())
	servers["srv-old-ix"] = model.Server{ID: "srv-old-ix", Name: "old-ix", Address: "192.0.2.200", Port: 22, User: "root", CredentialID: "c1",
		HostKey: model.HostKey{State: model.HostKeyTrusted}}
	l := &deployLive{t: topo, gw: statusInstall{State: "installed"},
		states:  map[string]nodeInstallState{"ix": {NodeID: "ix", State: nodeInSync}},
		bundles: map[string]string{}, idents: map[string]targetIdentity{}, servers: servers}
	p := l.plan()
	if got, want := planIDs(p), "dc1,dc2,hkb,hub,access,gw"; got != want {
		t.Fatalf("order %s, want %s", got, want)
	}
	for _, s := range p.Steps {
		if s.NodeID == "ix" {
			t.Fatalf("a step for the removed IX: %+v", s)
		}
	}
	if _, ok := skipOf(p, "ix"); ok {
		t.Fatal("the removed IX is listed")
	}
}

// With an IX the order and reasons are unchanged.
func TestDeployOrderWithIXUnchanged(t *testing.T) {
	topo, servers := orderServers(defaults.SharedRelaysExample())
	steps, _ := deployOrder(topo, servers, allPending(topo), true)
	if got, want := strings.Join(orderIDs(steps), ","), "dc1,dc2,hkb,ix,access,access2,gw"; got != want {
		t.Fatalf("order %s, want %s", got, want)
	}
	if r := stepOf(steps, "ix").Reason; r != "主枢纽（IX 线路上的受管服务器）：在出口和备用枢纽之后、中继之前" {
		t.Fatalf("ix reason %q", r)
	}
}

// PUT /api/topology: a topology without IX saves with its main path
// gateway → relay → primary hub → exit; with an IX, a relay that bypasses
// it is refused with the unchanged code and wording.
func TestTopologyPutNoIXContract(t *testing.T) {
	s := newTest(t)
	do(s, "GET", "/api/topology", nil)
	topo := defaults.NoIXExample()
	model.MigrateRegionGroups(&topo)
	if err := s.Store.Save(topo); err != nil {
		t.Fatal(err)
	}
	d := fetchDoc(t, s)
	renameGateway(d, "网关（无 IX）")
	expectSaved(t, s, d, "")
	if gatewayName(t, s) != "网关（无 IX）" {
		t.Fatal("not saved")
	}

	ix := defaults.DualHubExample()
	model.MigrateRegionGroups(&ix)
	if err := s.Store.Save(ix); err != nil {
		t.Fatal(err)
	}
	d = fetchDoc(t, s)
	var links []any
	for _, l := range d["links"].([]any) {
		if l.(map[string]any)["id"] != "access-ix" {
			links = append(links, l)
		}
	}
	d["links"] = append(links, map[string]any{"id": "access-hkb", "from": "access", "to": "hkb", "transport": "direct_wg", "enabled": true})
	rr := putDoc(s, d, "")
	if rr.Code == 200 || !strings.Contains(rr.Body.String(), "path_missing_ix") || !strings.Contains(rr.Body.String(), "国内中继、IX 专线、主枢纽") {
		t.Fatalf("IX bypass: %d %s", rr.Code, rr.Body.String())
	}
}

// The backup hub reached through relays (defaults.RelayBackupExample):
// exits → backup hub (its WSS server) → primary hub → relays (main group,
// then the backup group's WSS clients) → gateway.
func TestRelayBackupDeployPlanOrder(t *testing.T) {
	p := noIXPlan(t, defaults.RelayBackupExample())
	if got, want := planIDs(p), "dc1,dc2,hkb,hub,access,bk1,bk2,gw"; got != want {
		t.Fatalf("order %s, want %s", got, want)
	}
	for _, s := range p.Steps {
		switch s.NodeID {
		case "hkb":
			if !strings.Contains(s.Reason, "WSS 服务端先于备用组中继") {
				t.Fatalf("hkb reason %q", s.Reason)
			}
		case "bk1", "bk2":
			if !strings.Contains(s.Reason, "备用组中继") {
				t.Fatalf("%s reason %q", s.NodeID, s.Reason)
			}
		}
	}
}

// PUT /api/topology accepts all three backup forms: none, the gateway's
// own WSS to the backup hub, and the backup hub reached only via relays.
func TestTopologyPutRelayBackupContract(t *testing.T) {
	s := newTest(t)
	do(s, "GET", "/api/topology", nil)
	for _, topo := range []model.Topology{defaults.SharedRelaysExample(), defaults.NoIXExample(), defaults.RelayBackupExample()} {
		model.MigrateRegionGroups(&topo)
		if err := s.Store.Save(topo); err != nil {
			t.Fatal(err)
		}
		d := fetchDoc(t, s)
		renameGateway(d, "网关 R")
		expectSaved(t, s, d, "")
	}
}
