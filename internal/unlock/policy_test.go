package unlock

import (
	"testing"
	"time"
)

// Deterministic tests of automatic selection with an injectable clock:
// failure switch (two scheduled failures, not one), recovery under the
// hysteresis, all candidates failing, a pinned service, and expired
// evidence. Every result goes through IngestWith, so admission is the same
// as in production.

type clock struct{ now time.Time }

func (c *clock) at() time.Time        { return c.now }
func (c *clock) step(d time.Duration) { c.now = c.now.Add(d) }
func newClock() *clock                { return &clock{now: time.Date(2026, 11, 14, 0, 0, 0, 0, time.UTC)} }
func (c *clock) ob(svc, exit string, k Kind, ok bool) Observation {
	return Observation{Service: svc, ExitID: exit, Kind: k, ObservedAt: c.now, Results: map[Family]bool{FamilyIPv4: ok}}
}

var (
	candMembers = []string{"a", "b", "c"}
	pol         = Policy{TTL: 12 * time.Hour, RequireEvidence: true}
	svcKey      = ServiceKey("svc-x")
	svc         = Service{RuleID: svcKey, Pool: "g", Preferred: "a", Members: candMembers, Probes: []string{"auto-netflix"}, ServiceGroup: "svc-x"}
)

func feed(t *testing.T, snap *Snapshot, c *clock, exit string, k Kind, ok bool) {
	t.Helper()
	snap.Services[svcKey] = ReconcileWith(snap.Services[svcKey], svc, c.at(), pol)
	for _, o := range IngestWith(snap, c.ob(svcKey, exit, k, ok), candMembers, "", c.at(), pol) {
		if !o.Accepted {
			t.Fatalf("not admitted: %+v", o)
		}
	}
	c.step(time.Minute)
}

func decision(snap Snapshot) string { return Decisions(snap, []Service{svc})[svcKey] }

func TestAutoSelectFailureSwitchNeedsTwoScheduledFailures(t *testing.T) {
	c := newClock()
	snap := Snapshot{Services: map[string]State{}}
	feed(t, &snap, c, "b", KindManual, true)
	feed(t, &snap, c, "a", KindScheduled, false)
	if d := decision(snap); d != "" {
		t.Fatalf("one failure moved the service to %s", d)
	}
	feed(t, &snap, c, "a", KindManual, false) // a manual failure does not count
	if d := decision(snap); d != "" {
		t.Fatalf("a manual failure counted: %s", d)
	}
	switchAt := c.at()
	feed(t, &snap, c, "a", KindScheduled, false)
	st := snap.Services[svcKey]
	if d := decision(snap); d != "b" || !st.Demoted || st.SwitchReason != SwitchPreferredFailed || !st.SwitchedAt.Equal(switchAt) {
		t.Fatalf("after two scheduled failures: decision %q state %+v", d, st)
	}
	if !snap.PendingApply {
		t.Fatal("a switch did not mark the install pending")
	}
}

func TestAutoSelectRecoveryHysteresis(t *testing.T) {
	c := newClock()
	snap := Snapshot{Services: map[string]State{}}
	feed(t, &snap, c, "b", KindManual, true)
	feed(t, &snap, c, "a", KindScheduled, false)
	feed(t, &snap, c, "a", KindScheduled, false)
	if decision(snap) != "b" {
		t.Fatal("setup: not demoted")
	}
	feed(t, &snap, c, "a", KindManual, true) // streak starts
	c.step(20 * time.Minute)
	feed(t, &snap, c, "a", KindManual, true)
	if decision(snap) != "b" {
		t.Fatal("returned before the cooldown")
	}
	feed(t, &snap, c, "a", KindManual, false) // any failure restarts the streak
	c.step(15 * time.Minute)
	feed(t, &snap, c, "a", KindManual, true)
	c.step(20 * time.Minute)
	feed(t, &snap, c, "a", KindManual, true)
	if decision(snap) != "b" {
		t.Fatal("the failure did not restart the recovery streak")
	}
	c.step(11 * time.Minute)
	feed(t, &snap, c, "a", KindManual, true)
	st := snap.Services[svcKey]
	if decision(snap) != "" || st.Demoted || st.SwitchReason != SwitchRecovered {
		t.Fatalf("did not return after a fresh 30-minute streak: %+v", st)
	}
}

func TestAutoSelectAllCandidatesFail(t *testing.T) {
	c := newClock()
	snap := Snapshot{Services: map[string]State{}}
	feed(t, &snap, c, "b", KindScheduled, false)
	feed(t, &snap, c, "c", KindScheduled, false)
	feed(t, &snap, c, "a", KindScheduled, false)
	feed(t, &snap, c, "a", KindScheduled, false)
	st := snap.Services[svcKey]
	if decision(snap) != "" || st.Active != "a" || !st.Unavailable || st.SwitchReason != SwitchAllFailed {
		t.Fatalf("all failing: stays on the default member, unavailable: %+v", st)
	}
	// A member never measured is not tried either (RequireEvidence).
	snap2 := Snapshot{Services: map[string]State{}}
	feed(t, &snap2, c, "a", KindScheduled, false)
	feed(t, &snap2, c, "a", KindScheduled, false)
	if st := snap2.Services[svcKey]; decision(snap2) != "" || !st.Unavailable {
		t.Fatalf("moved to an unmeasured member: %+v", st)
	}
	// Without the policy the old behaviour (try an unmeasured member) is kept.
	old := Advance(Advance(State{}, Event{ExitID: "a", Kind: KindScheduled, At: c.at()}, candMembers), Event{ExitID: "a", Kind: KindScheduled, At: c.at()}, candMembers)
	if old.Active != "b" {
		t.Fatalf("zero policy changed: %+v", old)
	}
}

func TestAutoSelectPinWins(t *testing.T) {
	c := newClock()
	snap := Snapshot{Services: map[string]State{}}
	feed(t, &snap, c, "b", KindManual, true)
	feed(t, &snap, c, "a", KindScheduled, false)
	feed(t, &snap, c, "a", KindScheduled, false)
	pinned := svc
	pinned.Pin = true
	if d := Decisions(snap, []Service{pinned}); len(d) != 0 {
		t.Fatalf("a pinned service followed the unlock state: %v", d)
	}
	// A pinned service's results are recorded with a note and never step it.
	before := snap.Services[svcKey]
	IngestWith(&snap, c.ob(svcKey, "a", KindScheduled, true), candMembers, "钉死", c.at(), pol)
	if after := snap.Services[svcKey]; after.Active != before.Active || after.SchedFails != before.SchedFails {
		t.Fatalf("a noted result stepped the state: %+v → %+v", before, after)
	}
}

func TestAutoSelectExpiredEvidence(t *testing.T) {
	c := newClock()
	snap := Snapshot{Services: map[string]State{}}
	feed(t, &snap, c, "b", KindManual, true) // will expire
	c.step(13 * time.Hour)
	feed(t, &snap, c, "c", KindManual, true) // fresh
	feed(t, &snap, c, "a", KindScheduled, false)
	feed(t, &snap, c, "a", KindScheduled, false)
	st := snap.Services[svcKey]
	if decision(snap) != "c" {
		t.Fatalf("an expired success was used as evidence: %+v", st)
	}
	if st.Evidence("b", c.at(), pol) != "expired" || st.Evidence("c", c.at(), pol) != "ok" || st.Evidence("a", c.at(), pol) != "failed" {
		t.Fatalf("evidence view: b=%s c=%s a=%s", st.Evidence("b", c.at(), pol), st.Evidence("c", c.at(), pol), st.Evidence("a", c.at(), pol))
	}
	// Only expired evidence: nowhere to go, stay on the default.
	c2 := newClock()
	snap2 := Snapshot{Services: map[string]State{}}
	feed(t, &snap2, c2, "b", KindManual, true)
	feed(t, &snap2, c2, "c", KindManual, true)
	c2.step(24 * time.Hour)
	feed(t, &snap2, c2, "a", KindScheduled, false)
	feed(t, &snap2, c2, "a", KindScheduled, false)
	if st := snap2.Services[svcKey]; decision(snap2) != "" || !st.Unavailable {
		t.Fatalf("expired successes moved the service: %+v", st)
	}
	// A state stored before KnownAt existed keeps its meaning (an upgrade
	// moves nothing); the next result replaces it with a timed one.
	legacy := State{Preferred: "a", Active: "a", Known: map[string]bool{"b": true, "c": false}}
	if ok, seen := legacy.known("b", c.at(), pol); !seen || !ok {
		t.Fatal("an untimed result lost its meaning on upgrade")
	}
	if _, seen := legacy.known("b", c.at(), Policy{}); !seen {
		t.Fatal("zero policy must keep old results")
	}
}

// The recovery freshness bound is independent of the TTL: an old success
// of the preferred can never trigger a return, however long the TTL.
func TestAutoSelectStaleReturnRefused(t *testing.T) {
	c := newClock()
	snap := Snapshot{Services: map[string]State{}}
	feed(t, &snap, c, "b", KindManual, true)
	feed(t, &snap, c, "a", KindScheduled, false)
	feed(t, &snap, c, "a", KindScheduled, false)
	feed(t, &snap, c, "a", KindManual, true)
	c.step(2 * time.Hour)
	if snap.Services[svcKey].CanReturn(c.at()) {
		t.Fatal("a 2-hour-old success allowed a return")
	}
}
