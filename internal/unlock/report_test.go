package unlock

import (
	"fmt"
	"math/rand"
	"strings"
	"sync"
	"testing"
	"time"
)

func demotedSnap() Snapshot {
	return Snapshot{Services: map[string]State{
		"auto-openai": {Pool: "us", Preferred: "us", Active: "us-2", Demoted: true, Known: map[string]bool{"us-2": true}},
	}}
}

func obs(exit string, ok bool, observed time.Time) Observation {
	return Observation{Service: "auto-openai", ExitID: exit, Kind: KindScheduled, ObservedAt: observed, Results: map[Family]bool{FamilyAny: ok}}
}

// A success that was observed before a newer failure, but delivered after
// it, must not overwrite the failure or start the recovery streak.
func TestLateSuccessCannotOverwriteNewFailure(t *testing.T) {
	snap := demotedSnap()
	now := at(0)
	Ingest(&snap, obs("us", true, now.Add(-40*time.Minute)), members(), "", now.Add(-39*time.Minute))
	Ingest(&snap, obs("us", false, now.Add(-5*time.Minute)), members(), "", now.Add(-4*time.Minute))
	out := Ingest(&snap, obs("us", true, now.Add(-10*time.Minute)), members(), "", now)
	if len(out) != 1 || out[0].Accepted || out[0].Rejected != RejectOutOfOrder {
		t.Fatalf("late success was not rejected: %+v", out)
	}
	st := snap.Services["auto-openai"]
	if !st.PreferredOKAt.IsZero() || st.Known["us"] {
		t.Fatalf("late success changed the state: %+v", st)
	}
	// Even 31 minutes after the first success, the service stays on the backup.
	Ingest(&snap, obs("us-2", true, time.Time{}), members(), "", now.Add(31*time.Minute))
	if st := snap.Services["auto-openai"]; st.Active != "us-2" || !st.Demoted {
		t.Fatalf("returned to a preferred whose newest result is a failure: %+v", st)
	}
	if h := snap.History[len(snap.History)-2]; h.Rejected != RejectOutOfOrder {
		t.Fatalf("rejection not in history: %+v", snap.History)
	}
}

func TestValidityWindow(t *testing.T) {
	snap := demotedSnap()
	now := at(0)
	out := Ingest(&snap, obs("us", true, now.Add(-MaxReportAge-time.Minute)), members(), "", now)
	if out[0].Rejected != RejectStale {
		t.Fatalf("stale report admitted: %+v", out)
	}
	out = Ingest(&snap, obs("us", true, now.Add(MaxClockSkew+time.Minute)), members(), "", now)
	if out[0].Rejected != RejectFuture {
		t.Fatalf("future report admitted: %+v", out)
	}
	if st := snap.Services["auto-openai"]; !st.PreferredOKAt.IsZero() || len(snap.Latest) != 0 {
		t.Fatalf("rejected reports changed state: %+v %+v", st, snap.Latest)
	}
	// Within the window the probe's own time orders, but cooldown uses the
	// receive time: a 50-minute-old success does not shorten the 30 minutes.
	Ingest(&snap, obs("us", true, now.Add(-50*time.Minute)), members(), "", now)
	if st := snap.Services["auto-openai"]; !st.PreferredOKAt.Equal(snap.Clock) {
		t.Fatalf("cooldown must start at the receive time: %+v", st)
	}
	Ingest(&snap, obs("us", true, time.Time{}), members(), "", now.Add(5*time.Minute))
	if st := snap.Services["auto-openai"]; st.Active != "us-2" {
		t.Fatalf("backdated observation skipped the cooldown: %+v", st)
	}
}

func TestDuplicateReplayCountsOnce(t *testing.T) {
	snap := Snapshot{Services: map[string]State{"auto-openai": {Pool: "us", Preferred: "us", Active: "us", Known: map[string]bool{"us-2": true}}}}
	t0 := at(0)
	for i := 0; i < 3; i++ {
		Ingest(&snap, obs("us", false, t0), members(), "", t0.Add(time.Duration(i)*time.Second))
	}
	st := snap.Services["auto-openai"]
	if st.Demoted || st.SchedFails != 1 {
		t.Fatalf("one replayed failure demoted the rule: %+v", st)
	}
	// Failure wins a tie against a success with the same probe time.
	snap2 := demotedSnap()
	Ingest(&snap2, obs("us", true, t0), members(), "", t0)
	out := Ingest(&snap2, obs("us", false, t0), members(), "", t0.Add(time.Second))
	if !out[0].Accepted || !snap2.Services["auto-openai"].PreferredOKAt.IsZero() {
		t.Fatalf("failure at the same instant did not clear the streak: %+v %+v", out, snap2.Services["auto-openai"])
	}
	out = Ingest(&snap2, obs("us", true, t0), members(), "", t0.Add(2*time.Second))
	if out[0].Accepted {
		t.Fatalf("success at the same instant replaced a failure: %+v", out)
	}
}

// Families are separate keys, but an older run of one family cannot undo a
// newer run of another for the same exit.
func TestFamiliesAreKeyedButCannotUndoNewerRun(t *testing.T) {
	snap := demotedSnap()
	now := at(0)
	Ingest(&snap, Observation{Service: "auto-openai", ExitID: "us", Kind: KindScheduled, ObservedAt: now.Add(-2 * time.Minute), Results: map[Family]bool{FamilyIPv4: false}}, members(), "", now.Add(-time.Minute))
	out := Ingest(&snap, Observation{Service: "auto-openai", ExitID: "us", Kind: KindScheduled, ObservedAt: now.Add(-20 * time.Minute), Results: map[Family]bool{FamilyIPv6: true}}, members(), "", now)
	if len(out) != 1 || out[0].Accepted || out[0].Rejected != RejectSuperseded {
		t.Fatalf("older v6 run stepped the state over a newer v4 failure: %+v", out)
	}
	if _, ok := snap.Latest[ResultKey{"auto-openai", "us", FamilyIPv6}.String()]; !ok {
		t.Fatal("v6 result should still be recorded for its own key")
	}
	if st := snap.Services["auto-openai"]; !st.PreferredOKAt.IsZero() || st.Known["us"] {
		t.Fatalf("%+v", st)
	}
	// One run with both families: either family unlocking is enough.
	out = Ingest(&snap, Observation{Service: "auto-openai", ExitID: "us", Kind: KindScheduled, Results: map[Family]bool{FamilyIPv4: false, FamilyIPv6: true}}, members(), "", now.Add(time.Minute))
	if len(out) != 2 || !out[0].Accepted || !out[1].Accepted || !snap.Services["auto-openai"].Known["us"] {
		t.Fatalf("%+v %+v", out, snap.Services["auto-openai"])
	}
}

func TestStampIsStrictlyIncreasing(t *testing.T) {
	var snap Snapshot
	t0 := at(0)
	a := snap.Stamp(t0)
	b := snap.Stamp(t0)
	c := snap.Stamp(t0.Add(-time.Hour)) // wall clock stepped back
	if !b.After(a) || !c.After(b) {
		t.Fatalf("%v %v %v", a, b, c)
	}
}

// Concurrent probes deliver in arbitrary order under the writer lock, as in
// the API. Whatever the arrival order, the newest observation decides: here
// the newest is a failure, so the rule never returns and the streak is clear.
func TestConcurrentReportsNewestWins(t *testing.T) {
	base := at(0)
	for round := 0; round < 50; round++ {
		snap := demotedSnap()
		var mu sync.Mutex
		var wg sync.WaitGroup
		type rep struct {
			ok  bool
			off time.Duration
		}
		reps := []rep{}
		for i := 0; i < 8; i++ {
			reps = append(reps, rep{ok: true, off: time.Duration(i) * time.Minute})
		}
		reps = append(reps, rep{ok: false, off: 9 * time.Minute}) // newest
		rand.New(rand.NewSource(int64(round))).Shuffle(len(reps), func(i, j int) { reps[i], reps[j] = reps[j], reps[i] })
		for i, r := range reps {
			wg.Add(1)
			go func(i int, r rep) {
				defer wg.Done()
				mu.Lock()
				defer mu.Unlock()
				Ingest(&snap, obs("us", r.ok, base.Add(r.off)), members(), "", base.Add(40*time.Minute+time.Duration(i)*time.Second))
			}(i, r)
		}
		wg.Wait()
		st := snap.Services["auto-openai"]
		rec := snap.Latest[ResultKey{"auto-openai", "us", FamilyAny}.String()]
		if rec.OK || !rec.ObservedAt.Equal(base.Add(9*time.Minute)) {
			t.Fatalf("round %d: latest is not the newest observation: %+v", round, rec)
		}
		if !st.PreferredOKAt.IsZero() || st.Known["us"] || st.Active != "us-2" {
			t.Fatalf("round %d: %s", round, fmt.Sprintf("%+v", st))
		}
	}
}

func TestNoteRecordsWithoutAdmitting(t *testing.T) {
	snap := demotedSnap()
	out := Ingest(&snap, obs("jp", true, time.Time{}), members(), "not in pool", at(0))
	if out[0].Accepted || len(snap.Latest) != 0 || snap.History[0].Note != "not in pool" {
		t.Fatalf("%+v %+v", out, snap)
	}
}

func TestParseFamily(t *testing.T) {
	for in, want := range map[string]Family{"": FamilyAny, "IPv4": FamilyIPv4, "6": FamilyIPv6, "v6": FamilyIPv6} {
		if got, ok := ParseFamily(in); !ok || got != want {
			t.Fatalf("%q: %v %v", in, got, ok)
		}
	}
	if _, ok := ParseFamily("ipx"); ok {
		t.Fatal("unknown family accepted")
	}
}

// A panel probe that produced no platform verdict (egress unconfirmed,
// timeout, unrecognised page) is ingested as KindInconclusive: it never
// counts toward the two scheduled failures, but it ends the preferred's
// recovery streak and the exit is no longer a known-good backup.
func TestInconclusiveNeverDemotesButBreaksRecovery(t *testing.T) {
	snap := Snapshot{}
	now := at(0)
	for i := 0; i < 3; i++ {
		ob := Observation{Service: "auto-openai", ExitID: "us", Kind: KindInconclusive, ObservedAt: now.Add(time.Duration(i) * time.Hour),
			Results: map[Family]bool{FamilyIPv4: false, FamilyIPv6: false}}
		Ingest(&snap, ob, members(), "", now.Add(time.Duration(i)*time.Hour+time.Minute))
	}
	st := snap.Services["auto-openai"]
	if st.Demoted || st.SchedFails != 0 || st.Active != "us" {
		t.Fatalf("inconclusive probes demoted the rule: %+v", st)
	}

	snap = demotedSnap()
	Ingest(&snap, obs("us", true, now), members(), "", now)
	if snap.Services["auto-openai"].PreferredOKAt.IsZero() {
		t.Fatal("success did not start the streak")
	}
	inc := Observation{Service: "auto-openai", ExitID: "us", Kind: KindInconclusive, ObservedAt: now.Add(20 * time.Minute),
		Results: map[Family]bool{FamilyIPv4: false}}
	Ingest(&snap, inc, members(), "", now.Add(20*time.Minute))
	Ingest(&snap, obs("us-2", true, time.Time{}), members(), "", now.Add(31*time.Minute))
	st = snap.Services["auto-openai"]
	if !st.PreferredOKAt.IsZero() || st.Active != "us-2" || !st.Demoted {
		t.Fatalf("returned to a preferred whose latest probe had no verdict: %+v", st)
	}
	if snap.History[len(snap.History)-2].Kind != KindInconclusive {
		t.Fatalf("history must say inconclusive: %+v", snap.History)
	}
}

// N4: a reachability-only or unknown probe result reaches Ingest as
// KindInconclusive. However many arrive, on the preferred or on the backup,
// they never demote, never restore and never count as a recovery success.
func TestInconclusiveCanNeitherDemoteNorRestore(t *testing.T) {
	now := at(0)
	inc := func(exit string, d time.Duration) Observation {
		return Observation{Service: "auto-openai", ExitID: exit, Kind: KindInconclusive, ObservedAt: now.Add(d),
			Results: map[Family]bool{FamilyIPv4: false, FamilyIPv6: false}}
	}
	// Not demoted: a run of inconclusive results on the preferred.
	snap := Snapshot{}
	for i := 0; i < 6; i++ {
		d := time.Duration(i) * 20 * time.Minute
		Ingest(&snap, inc("us", d), members(), "", now.Add(d+time.Minute))
		Ingest(&snap, inc("us-2", d), members(), "", now.Add(d+time.Minute))
	}
	if st := snap.Services["auto-openai"]; st.Demoted || st.SchedFails != 0 || st.Active != "us" || st.Unavailable {
		t.Fatalf("inconclusive results moved the rule: %+v", st)
	}
	if d := Decisions(snap, []Service{{RuleID: "auto-openai", Pool: "us", Preferred: "us", Members: members()}}); len(d) != 0 {
		t.Fatalf("inconclusive results produced a decision: %v", d)
	}

	// Demoted: inconclusive results on the preferred for two hours never
	// start the recovery streak, and the backup stays.
	snap = demotedSnap()
	for i := 0; i < 8; i++ {
		d := time.Duration(i) * 15 * time.Minute
		Ingest(&snap, inc("us", d), members(), "", now.Add(d+time.Minute))
	}
	st := snap.Services["auto-openai"]
	if !st.Demoted || st.Active != "us-2" || !st.PreferredOKAt.IsZero() || st.Known["us"] || st.CanReturn(now.Add(3*time.Hour)) {
		t.Fatalf("inconclusive results restored or started recovery: %+v", st)
	}
	// Inconclusive on the backup does not move the rule elsewhere either.
	Ingest(&snap, inc("us-2", 3*time.Hour), members(), "", now.Add(3*time.Hour+time.Minute))
	if st := snap.Services["auto-openai"]; st.Active != "us-2" || !st.Demoted {
		t.Fatalf("inconclusive on the backup moved the rule: %+v", st)
	}
}

// Stale and wrong-exit results are refused before they can step the state.
func TestStaleAndWrongExitResultsRejected(t *testing.T) {
	snap := demotedSnap()
	now := at(0)
	before := snap.Services["auto-openai"]
	out := Ingest(&snap, Observation{Service: "auto-openai", ExitID: "us", Kind: KindManual, ObservedAt: now.Add(-2 * time.Hour),
		Results: map[Family]bool{FamilyIPv4: true}}, members(), "", now)
	if len(out) != 1 || out[0].Accepted || out[0].Rejected != RejectStale {
		t.Fatalf("stale success admitted: %+v", out)
	}
	// An exit that is not a member of the group (the panel passes a note
	// for it) is recorded only.
	out = Ingest(&snap, Observation{Service: "auto-openai", ExitID: "jp", Kind: KindScheduled, ObservedAt: now,
		Results: map[Family]bool{FamilyIPv4: true}}, members(), "出口不在该服务的池里", now)
	if len(out) != 1 || out[0].Accepted || out[0].Note == "" {
		t.Fatalf("wrong-exit result admitted: %+v", out)
	}
	// Even without the note, Advance ignores an exit outside the members.
	Ingest(&snap, Observation{Service: "auto-openai", ExitID: "jp", Kind: KindScheduled, ObservedAt: now.Add(time.Minute),
		Results: map[Family]bool{FamilyIPv4: true}}, members(), "", now.Add(time.Minute))
	after := snap.Services["auto-openai"]
	if after.Active != before.Active || after.Demoted != before.Demoted || after.Known["jp"] || !after.PreferredOKAt.IsZero() {
		t.Fatalf("wrong-exit result changed the state: %+v", after)
	}
}

// Records of an exit that was removed are found for marking, and finding
// them changes nothing: admission still rejects an old replay for that id.
func TestRemovedExitsMarkedAdmissionKept(t *testing.T) {
	snap := Snapshot{Services: map[string]State{"netflix": {Active: "jp", Preferred: "tw"}}}
	t0 := time.Date(2026, 11, 1, 12, 0, 0, 0, time.UTC)
	Ingest(&snap, Observation{Service: "netflix", ExitID: "gone", Kind: KindScheduled, ObservedAt: t0, Results: map[Family]bool{FamilyIPv4: true}}, []string{"tw", "gone"}, "", t0)
	got := RemovedExits(snap, func(id string) bool { return id == "tw" || id == "jp" })
	if len(got) != 1 || got[0] != "gone" {
		t.Fatalf("removed exits %v", got)
	}
	refs := ReferencedExits(snap)
	if strings.Join(refs, ",") != "gone,jp,tw" {
		t.Fatalf("referenced %v", refs)
	}
	before := len(snap.Latest)
	_ = RemovedExits(snap, func(string) bool { return false })
	if len(snap.Latest) != before {
		t.Fatal("marking removed exits changed admission state")
	}
	out := Ingest(&snap, Observation{Service: "netflix", ExitID: "gone", Kind: KindScheduled, ObservedAt: t0.Add(-time.Minute), Results: map[Family]bool{FamilyIPv4: true}}, []string{"tw", "gone"}, "", t0.Add(time.Minute))
	if len(out) != 1 || out[0].Accepted || out[0].Rejected != RejectOutOfOrder {
		t.Fatalf("old replay for a removed exit id: %+v", out)
	}
}
