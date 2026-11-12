package pool

import (
	"testing"
	"time"

	"github.com/radowitz/meridian/internal/defaults"
	"github.com/radowitz/meridian/internal/model"
)

func TestPreferredIsIXBoundThenPriority(t *testing.T) {
	hk := Members(defaults.Example(), "hk")
	if len(hk) < 2 {
		t.Fatalf("hk pool = %d members, want at least hk-ix and a backup", len(hk))
	}
	got, ok := Preferred(hk)
	if !ok || got.ID != "hk-ix" || !got.IXBound {
		t.Fatalf("preferred hk = %+v", got)
	}
	for _, n := range hk {
		if n.Residential {
			t.Fatal("residential exit leaked into the default hk pool")
		}
	}
	resi := Members(defaults.Example(), "hk-residential")
	if len(resi) < 2 {
		t.Fatalf("hk-residential = %d, want at least two home-broadband exits", len(resi))
	}
	for _, n := range resi {
		if !n.Residential {
			t.Fatalf("non-residential member %s in hk-residential", n.ID)
		}
	}
	pref, _ := Preferred(resi)
	if pref.ID != "hk-resi" {
		t.Fatalf("residential preferred = %s, want hk-resi (lower id, same priority)", pref.ID)
	}
}

func TestPriorityBeatsIDButNotIX(t *testing.T) {
	nodes := []model.Node{
		{ID: "a", Role: model.RoleExit, Pool: "hk", PoolPriority: 0},
		{ID: "b", Role: model.RoleExit, Pool: "hk", PoolPriority: 5},
		{ID: "c", Role: model.RoleExit, Pool: "hk", IXBound: true, PoolPriority: 9},
	}
	got, _ := Preferred(Members(model.Topology{Nodes: nodes}, "hk"))
	if got.ID != "c" {
		t.Fatalf("IX-bound should win over priority, got %s", got.ID)
	}
	nodes[2].IXBound = false
	got, _ = Preferred(Members(model.Topology{Nodes: nodes}, "hk"))
	if got.ID != "a" {
		t.Fatalf("lower priority should win, got %s", got.ID)
	}
}

func TestSingleFailureDoesNotMove(t *testing.T) {
	rt := Step(Runtime{}, []string{"hk-ix", "hk-2"}, map[string]bool{"hk-ix": false, "hk-2": true}, true, at(0))
	if rt.Active != "hk-ix" {
		t.Fatalf("active = %s after one failure", rt.Active)
	}
	if !rt.Members["hk-ix"].Up || rt.Members["hk-ix"].Fails != 1 {
		t.Fatalf("health = %+v", rt.Members["hk-ix"])
	}
}

func TestThreeFailuresMoveToBackup(t *testing.T) {
	rt := Runtime{}
	now := at(0)
	for i := 0; i < FailsNeed; i++ {
		now = now.Add(5 * time.Second)
		rt = Step(rt, []string{"hk-ix", "hk-2"}, map[string]bool{"hk-ix": false, "hk-2": true}, true, now)
	}
	if rt.Active != "hk-2" {
		t.Fatalf("active = %s, want hk-2", rt.Active)
	}
}

func TestCooldownBlocksReturn(t *testing.T) {
	rt := Runtime{}
	now := at(0)
	for i := 0; i < FailsNeed; i++ {
		now = now.Add(5 * time.Second)
		rt = Step(rt, []string{"hk-ix", "hk-2"}, map[string]bool{"hk-ix": false, "hk-2": true}, true, now)
	}
	// Preferred is down. Feed successes, but the last switch was just now.
	for i := 0; i < RecoversNeed; i++ {
		now = now.Add(5 * time.Second)
		rt = Step(rt, []string{"hk-ix", "hk-2"}, map[string]bool{"hk-ix": true, "hk-2": true}, true, now)
	}
	if rt.Active == "hk-ix" {
		t.Fatal("returned to preferred inside the cooldown")
	}
	now = rt.LastSwitch.Add(Cooldown + time.Second)
	// One more success so the preferred is still up when the cooldown ends.
	rt = Step(rt, []string{"hk-ix", "hk-2"}, map[string]bool{"hk-ix": true, "hk-2": true}, true, now)
	if rt.Active != "hk-ix" {
		t.Fatalf("active = %s after cooldown, want hk-ix", rt.Active)
	}
}

func TestMeshOnlyAfterEveryWGMemberIsDown(t *testing.T) {
	rt := Runtime{}
	now := at(0)
	for i := 0; i < FailsNeed; i++ {
		now = now.Add(5 * time.Second)
		rt = Step(rt, []string{"hk-ix", "hk-2"}, map[string]bool{"hk-ix": false, "hk-2": false}, true, now)
	}
	if rt.Active != MeshHop {
		t.Fatalf("active = %s, want mesh", rt.Active)
	}
	rt = Runtime{}
	now = at(0)
	for i := 0; i < FailsNeed; i++ {
		now = now.Add(5 * time.Second)
		rt = Step(rt, []string{"hk-ix", "hk-2"}, map[string]bool{"hk-ix": false, "hk-2": false}, false, now)
	}
	if rt.Active != "hk-ix" {
		t.Fatalf("without mesh, active = %s, want to stay on the preferred table", rt.Active)
	}
}

func TestMeshIsNotUsedWhileAMemberIsUp(t *testing.T) {
	rt := Runtime{}
	now := at(0)
	for i := 0; i < FailsNeed; i++ {
		now = now.Add(5 * time.Second)
		rt = Step(rt, []string{"hk-ix", "hk-2"}, map[string]bool{"hk-ix": false, "hk-2": true}, true, now)
	}
	if rt.Active != "hk-2" {
		t.Fatalf("active = %s, mesh must not preempt a live WireGuard member", rt.Active)
	}
}

func at(sec int) time.Time {
	return time.Date(2026, 11, 12, 0, 0, sec, 0, time.UTC)
}
