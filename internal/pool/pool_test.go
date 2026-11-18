package pool

import (
	"testing"
	"time"

	"github.com/radowitz/meridian/internal/defaults"
	"github.com/radowitz/meridian/internal/model"
)

func group(t model.Topology, id string) model.RegionGroup {
	g, ok := t.GroupByID(id)
	if !ok {
		panic("no group " + id)
	}
	return g
}

func TestPreferredIsIXBoundThenUserOrder(t *testing.T) {
	topo := defaults.Example()
	hk := Select(topo, group(topo, "hk"), nil)
	if len(hk.Order) < 2 || hk.Target != "hk-ix" || hk.Reason != ReasonPreferred {
		t.Fatalf("hk = %+v", hk)
	}
	for _, id := range hk.Order {
		if n, _ := topo.NodeByID(id); n.Residential {
			t.Fatal("residential exit leaked into the default hk group")
		}
	}
	resi := Select(topo, group(topo, "hk-residential"), nil)
	if len(resi.Order) < 2 || resi.Target != "hk-resi" {
		t.Fatalf("hk-residential = %+v", resi)
	}
	for _, id := range resi.Order {
		if n, _ := topo.NodeByID(id); !n.Residential {
			t.Fatalf("non-residential member %s in hk-residential", id)
		}
	}
}

// Hard constraints filter first, then IX-bound members come before the
// operator's order; every move or exclusion carries a reason.
func TestEffectiveOrderConstraintsThenIXThenUserOrder(t *testing.T) {
	topo := model.Topology{Nodes: []model.Node{
		{ID: "a", Role: model.RoleExit, EgressV6: true},
		{ID: "b", Role: model.RoleExit, EgressV6: true, Residential: true},
		{ID: "c", Role: model.RoleExit, EgressV6: true, IXBound: true},
		{ID: "d", Role: model.RoleExit},
		{ID: "e", Role: model.RoleExit, EgressV6: true},
		{ID: "relay", Role: model.RoleRelay},
	}}
	g := model.RegionGroup{ID: "x", Mode: model.GroupAuto, ExcludeResidential: true, RequireV6: true,
		Members: []string{"a", "b", "c", "d", "ghost", "relay", "e", "a"}}
	order, st := Effective(topo, g, map[string]bool{"a": true, "c": true, "e": false})
	want := []string{"c", "a", "e"}
	if len(order) != len(want) {
		t.Fatalf("order = %v, want %v", order, want)
	}
	for i := range want {
		if order[i] != want[i] {
			t.Fatalf("order = %v, want %v", order, want)
		}
	}
	codes := map[string][]string{}
	for _, m := range st {
		for _, r := range m.Reasons {
			codes[m.ID+"@"+itoa(m.UserPos)] = append(codes[m.ID+"@"+itoa(m.UserPos)], r.Code)
		}
	}
	expect := map[string]string{
		"b@1": WhyResiExcluded, "c@2": WhyIXFirst, "a@0": WhyAfterIX, "d@3": WhyV6Required,
		"ghost@4": WhyMissing, "relay@5": WhyMissing, "e@6": WhyNotSwitchable, "a@7": WhyDuplicate,
	}
	for k, code := range expect {
		found := false
		for _, c := range codes[k] {
			if c == code {
				found = true
			}
		}
		if !found {
			t.Errorf("%s reasons = %v, want %s", k, codes[k], code)
		}
	}
	for _, m := range st {
		if (m.Pos == -1) == m.Eligible {
			t.Errorf("%s: position %d but eligible=%v", m.ID, m.Pos, m.Eligible)
		}
	}
}

func itoa(i int) string { return string(rune('0' + i)) }

func TestManualSelectionAndConstraint(t *testing.T) {
	topo := model.Topology{Nodes: []model.Node{
		{ID: "a", Role: model.RoleExit, IXBound: true},
		{ID: "b", Role: model.RoleExit},
		{ID: "r", Role: model.RoleExit, Residential: true},
	}}
	g := model.RegionGroup{ID: "x", Mode: model.GroupManual, Chosen: "b", Members: []string{"a", "b", "r"}}
	sel := Select(topo, g, nil)
	if sel.Target != "b" || sel.Reason != ReasonChosen || len(sel.Try) != 3 || sel.Try[0] != "b" || sel.Try[1] != "a" {
		t.Fatalf("manual = %+v", sel)
	}
	g.ExcludeResidential, g.Chosen = true, "r"
	sel = Select(topo, g, nil)
	if sel.Target != "a" || sel.Reason != ReasonConstraint {
		t.Fatalf("excluded choice must fall to the first eligible member with reason constraint: %+v", sel)
	}
	g.Members = []string{"r"}
	if sel = Select(topo, g, nil); sel.Target != "" || sel.Reason != ReasonNone {
		t.Fatalf("no eligible member: %+v", sel)
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
	if rt.Active != "hk-2" || rt.Reason != ReasonFailover || rt.LastSwitch != now {
		t.Fatalf("active = %s reason %s, want hk-2 failover", rt.Active, rt.Reason)
	}
}

func failOver(members []string, p Policy) (Runtime, time.Time) {
	rt := Runtime{}
	now := at(0)
	down := map[string]bool{}
	for i, id := range members {
		down[id] = i != 0
	}
	p.Try = members
	for i := 0; i < FailsNeed; i++ {
		now = now.Add(5 * time.Second)
		rt = StepGroup(rt, p, down, now)
	}
	return rt, now
}

// Returning needs the target up, its latest sample a success, an unbroken
// success streak of Cooldown and Cooldown since the last switch.
func TestCooldownBlocksReturn(t *testing.T) {
	members := []string{"hk-ix", "hk-2"}
	rt, now := failOver(members, Policy{})
	both := map[string]bool{"hk-ix": true, "hk-2": true}
	for i := 0; i < RecoversNeed; i++ {
		now = now.Add(5 * time.Second)
		rt = Step(rt, members, both, true, now)
	}
	if rt.Active == "hk-ix" {
		t.Fatal("returned to preferred inside the cooldown")
	}
	streak := rt.Members["hk-ix"].OKSince
	if streak.IsZero() || !rt.Members["hk-ix"].Up {
		t.Fatalf("recovery not tracked: %+v", rt.Members["hk-ix"])
	}
	// Past the switch cooldown but inside the success streak: stay.
	now = rt.LastSwitch.Add(Cooldown + time.Second)
	if now.Sub(streak) >= Cooldown {
		t.Fatal("test setup: streak already long enough")
	}
	rt = Step(rt, members, both, true, now)
	if rt.Active == "hk-ix" {
		t.Fatal("returned before the preferred had a full success streak")
	}
	now = streak.Add(Cooldown)
	rt = Step(rt, members, both, true, now)
	if rt.Active != "hk-ix" || rt.Reason != ReasonPreferred || rt.Alert {
		t.Fatalf("active = %s (%s) after the streak, want hk-ix", rt.Active, rt.Reason)
	}
}

// A preferred failure clears the recovery timer, and a preferred whose
// latest sample failed is never switched back to, even though the
// hysteresis still counts it as up.
func TestPreferredFailureClearsRecoveryAndBlocksReturn(t *testing.T) {
	members := []string{"hk-ix", "hk-2"}
	rt, now := failOver(members, Policy{})
	both := map[string]bool{"hk-ix": true, "hk-2": true}
	for i := 0; i < RecoversNeed; i++ {
		now = now.Add(5 * time.Second)
		rt = Step(rt, members, both, false, now)
	}
	first := rt.Members["hk-ix"].OKSince
	now = first.Add(Cooldown - 5*time.Second)
	rt = Step(rt, members, both, false, now)
	// One failure just before the streak would have completed.
	now = now.Add(5 * time.Second)
	rt = Step(rt, members, map[string]bool{"hk-ix": false, "hk-2": true}, false, now)
	h := rt.Members["hk-ix"]
	if !h.Up || h.LastOK || !h.OKSince.IsZero() {
		t.Fatalf("one failure: want still up by hysteresis, last failed, timer cleared: %+v", h)
	}
	if rt.Active != "hk-2" {
		t.Fatal("switched back to a member whose latest sample failed")
	}
	if CanReturn(rt, "hk-ix", now.Add(time.Hour)) {
		t.Fatal("CanReturn ignores the failed latest sample")
	}
	// The streak restarts from the next success.
	now = now.Add(5 * time.Second)
	rt = Step(rt, members, both, false, now)
	if rt.Members["hk-ix"].OKSince != now || rt.Active != "hk-2" {
		t.Fatalf("streak restart: %+v active %s", rt.Members["hk-ix"], rt.Active)
	}
	rt = Step(rt, members, both, false, now.Add(Cooldown))
	if rt.Active != "hk-ix" {
		t.Fatalf("active = %s after a fresh full streak", rt.Active)
	}
}

func TestMeshOnlyAfterEveryWGMemberIsDown(t *testing.T) {
	rt := Runtime{}
	now := at(0)
	for i := 0; i < FailsNeed; i++ {
		now = now.Add(5 * time.Second)
		rt = Step(rt, []string{"hk-ix", "hk-2"}, map[string]bool{"hk-ix": false, "hk-2": false}, true, now)
	}
	if rt.Active != MeshHop || rt.Reason != ReasonMesh || !rt.Alert {
		t.Fatalf("active = %s (%s), want mesh", rt.Active, rt.Reason)
	}
	rt = Runtime{}
	now = at(0)
	for i := 0; i < FailsNeed; i++ {
		now = now.Add(5 * time.Second)
		rt = Step(rt, []string{"hk-ix", "hk-2"}, map[string]bool{"hk-ix": false, "hk-2": false}, false, now)
	}
	if rt.Active != "hk-ix" || !rt.Alert {
		t.Fatalf("without mesh, active = %s, want to stay on the target table with an alert", rt.Active)
	}
}

func TestCooldownDoesNotKeepADeadBackup(t *testing.T) {
	members := []string{"hk-ix", "hk-2"}
	rt, now := failOver(members, Policy{Mesh: true})
	if rt.Active != "hk-2" {
		t.Fatalf("active = %s, want hk-2", rt.Active)
	}
	switched := rt.LastSwitch
	for i := 0; i < FailsNeed; i++ {
		now = now.Add(5 * time.Second)
		rt = Step(rt, members, map[string]bool{"hk-ix": false, "hk-2": false}, true, now)
	}
	if !now.Before(switched.Add(Cooldown)) {
		t.Fatal("probe sequence left the cooldown window")
	}
	if rt.Active != MeshHop {
		t.Fatalf("active = %s, a dead backup must not stay selected just because the return cooldown has not elapsed", rt.Active)
	}
}

// When every member is dead and there is no Mesh, a dead backup is not
// swapped for the just-failed target.
func TestAllDownWithoutMeshStaysPut(t *testing.T) {
	members := []string{"a", "b"}
	rt, now := failOver(members, Policy{})
	for i := 0; i < FailsNeed; i++ {
		now = now.Add(5 * time.Second)
		rt = Step(rt, members, map[string]bool{"a": false, "b": false}, false, now)
	}
	if rt.Active != "b" {
		t.Fatalf("active = %s, want to stay on b rather than return to the failed target", rt.Active)
	}
}

func TestMeshIsNotUsedWhileAMemberIsUp(t *testing.T) {
	rt, _ := failOver([]string{"hk-ix", "hk-2"}, Policy{Mesh: true})
	if rt.Active != "hk-2" {
		t.Fatalf("active = %s, mesh must not preempt a live WireGuard member", rt.Active)
	}
}

// Manual + hold keeps the chosen member and alerts; it never moves.
func TestManualHoldKeepsChosenAndAlerts(t *testing.T) {
	p := Policy{Manual: true, Hold: true, Mesh: true}
	rt, _ := failOver([]string{"chosen", "other"}, p)
	if rt.Active != "chosen" || rt.Reason != ReasonHeld || !rt.Alert || !rt.LastSwitch.IsZero() {
		t.Fatalf("hold: %+v", rt)
	}
	now := at(100)
	for i := 0; i < RecoversNeed; i++ {
		now = now.Add(5 * time.Second)
		rt = StepGroup(rt, Policy{Try: []string{"chosen", "other"}, Manual: true, Hold: true}, map[string]bool{"chosen": true, "other": true}, now)
	}
	if rt.Active != "chosen" || rt.Reason != ReasonChosen || rt.Alert {
		t.Fatalf("recovered hold: %+v", rt)
	}
}

// Manual + fallback uses the next eligible member while the chosen one is
// down (alerting), and returns under the automatic return rule.
func TestManualFallbackReturnsUnderAutoRules(t *testing.T) {
	try := []string{"chosen", "a", "b"}
	p := Policy{Manual: true}
	rt, now := failOver(try, p)
	if rt.Active != "a" || rt.Reason != ReasonFallback || !rt.Alert {
		t.Fatalf("fallback: %+v", rt)
	}
	p.Try = try
	all := map[string]bool{"chosen": true, "a": true, "b": true}
	for i := 0; i < RecoversNeed; i++ {
		now = now.Add(5 * time.Second)
		rt = StepGroup(rt, p, all, now)
	}
	streak := rt.Members["chosen"].OKSince
	rt = StepGroup(rt, p, map[string]bool{"chosen": false, "a": true, "b": true}, streak.Add(Cooldown))
	if rt.Active != "a" {
		t.Fatal("fallback returned to a chosen member that just failed")
	}
	now = streak.Add(Cooldown + 5*time.Second)
	rt = StepGroup(rt, p, all, now)
	rt = StepGroup(rt, p, all, now.Add(Cooldown))
	if rt.Active != "chosen" || rt.Reason != ReasonChosen || rt.Alert {
		t.Fatalf("fallback return: %+v", rt)
	}
}

// A new target (operator reorder or new choice) restarts the group on it,
// as the hub does after the install.
func TestTargetChangeRestartsOnNewTarget(t *testing.T) {
	rt, now := failOver([]string{"a", "b"}, Policy{})
	if rt.Active != "b" {
		t.Fatal(rt.Active)
	}
	rt = StepGroup(rt, Policy{Try: []string{"c", "a"}}, map[string]bool{"c": true}, now.Add(time.Second))
	if rt.Target != "c" || rt.Active != "c" {
		t.Fatalf("target change: %+v", rt)
	}
	if rt = StepGroup(rt, Policy{}, nil, now); rt.Active != "" || rt.Reason != ReasonNone || !rt.Alert {
		t.Fatalf("empty policy: %+v", rt)
	}
}

func TestLegacyPoolsViewFromGroups(t *testing.T) {
	topo := defaults.Example()
	views := Pools(topo, map[string]bool{"hk": true}, map[string]Runtime{"hk": {Active: "hk-2", Members: map[string]MemberHealth{"hk-ix": {Up: false}}}})
	var hk *View
	for i := range views {
		if views[i].ID == "hk" {
			hk = &views[i]
		}
	}
	if hk == nil || hk.Preferred != "hk-ix" || !hk.MeshBackup || hk.Active != "hk-2" || len(hk.Members) != 2 {
		t.Fatalf("hk view = %+v", hk)
	}
	if hk.Members[0].Up == nil || *hk.Members[0].Up {
		t.Fatal("member health not carried")
	}
}

func at(sec int) time.Time {
	return time.Date(2026, 11, 12, 0, 0, sec, 0, time.UTC)
}
