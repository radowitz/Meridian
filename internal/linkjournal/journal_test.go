package linkjournal

import (
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// clock is the fake clock of the journal tests.
type clock struct {
	mu sync.Mutex
	t  time.Time
}

func newClock() *clock { return &clock{t: time.Date(2026, 3, 1, 8, 0, 0, 0, time.UTC)} }

func (c *clock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *clock) add(d time.Duration) time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
	return c.t
}

func openJ(t *testing.T, dir string, ck *clock, mod func(*Options)) *Journal {
	t.Helper()
	o := Options{Dir: dir, Now: ck.now, noSync: true}
	if mod != nil {
		mod(&o)
	}
	j, err := Open(o)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(j.Close)
	return j
}

func tun(id, state string) Observation {
	return Observation{Class: ClassTunnel, Kind: KindTunnel, ID: id, Label: "隧道 " + id, State: state, Source: SourceHandshake, Evidence: "evidence of " + state}
}

func events(t *testing.T, j *Journal, q Query) []Event {
	t.Helper()
	p, err := j.Query(q)
	if err != nil {
		t.Fatal(err)
	}
	return p.Events
}

func mustEvents(t *testing.T, j *Journal, want int) []Event {
	t.Helper()
	evs := events(t, j, Query{Limit: PageMax})
	if len(evs) != want {
		t.Fatalf("got %d events, want %d: %+v", len(evs), want, evs)
	}
	return evs
}

func current(t *testing.T, j *Journal, kind, id string) CurrentObject {
	t.Helper()
	for _, o := range j.Current().Objects {
		if o.Kind == kind && o.ID == id {
			return o
		}
	}
	t.Fatalf("no object %s/%s in the current view", kind, id)
	return CurrentObject{}
}

func prevFor(ev Event) int64 {
	if ev.PrevForS == nil {
		return -1
	}
	return *ev.PrevForS
}

// The first reading of an object is a baseline: no event, an open duration.
func TestBaselineProducesNoEvent(t *testing.T) {
	ck := newClock()
	j := openJ(t, t.TempDir(), ck, nil)
	j.Observe(ck.now(), []Observation{tun("m00", TunnelOK), tun("m01", TunnelStale), {Class: ClassPath, Kind: KindUpstream, ID: GatewayID, State: "backup", Source: SourceUpstream}})
	mustEvents(t, j, 0)
	st := j.Stats()
	if st.BaselineAt == nil || st.Restored || st.Objects != 3 {
		t.Fatalf("stats after the baseline: %+v", st)
	}
	// An abnormal state found at the baseline is shown as such, open-ended.
	o := current(t, j, KindTunnel, "m01")
	if o.State != TunnelStale || o.Level != LevelAbnormal || !o.SinceOpen || o.ForS != 0 {
		t.Fatalf("baseline object: %+v", o)
	}
	ck.add(30 * time.Second)
	j.Observe(ck.now(), []Observation{tun("m00", TunnelOK), tun("m01", TunnelStale)})
	mustEvents(t, j, 0)
	if o := current(t, j, KindTunnel, "m01"); o.ForS != 30 || !o.SinceOpen {
		t.Fatalf("after 30 s: %+v", o)
	}
}

// A change is one event with the previous state's observed duration; the
// duration of a state that was there at the baseline is a lower bound.
func TestTransitionAndDurations(t *testing.T) {
	ck := newClock()
	j := openJ(t, t.TempDir(), ck, nil)
	t0 := ck.now()
	j.Observe(t0, []Observation{tun("m00", TunnelOK)})
	ck.add(100 * time.Second)
	j.Observe(ck.now(), []Observation{tun("m00", TunnelStale)})
	evs := mustEvents(t, j, 1)
	e := evs[0]
	if e.From != TunnelOK || e.To != TunnelStale || e.Class != ClassTunnel || e.Kind != KindTunnel || e.ID != "m00" || e.Source != SourceHandshake ||
		!e.At.Equal(t0.Add(100*time.Second)) || prevFor(e) != 100 || !e.PrevOpen || e.AfterGap != nil || e.Changes != 0 || e.Evidence != "evidence of stale" || e.Seq == 0 {
		t.Fatalf("first change: %+v", e)
	}
	ck.add(110 * time.Second)
	j.Observe(ck.now(), []Observation{tun("m00", TunnelOK)})
	evs = mustEvents(t, j, 2)
	if e := evs[0]; e.From != TunnelStale || e.To != TunnelOK || prevFor(e) != 110 || e.PrevOpen {
		t.Fatalf("second change (newest first): %+v", e)
	}
	if o := current(t, j, KindTunnel, "m00"); o.State != TunnelOK || o.SinceOpen || o.Level != LevelOK {
		t.Fatalf("current: %+v", o)
	}
	// A pass without a reading of the object changes nothing.
	ck.add(20 * time.Second)
	j.Observe(ck.now(), nil)
	mustEvents(t, j, 2)
}

// After a restart the checkpoint is the reference: an unchanged state is
// no event; a state that changed across a short stop is one event with its
// duration; nothing is invented.
func TestRestartWithCheckpoint(t *testing.T) {
	ck := newClock()
	dir := t.TempDir()
	j := openJ(t, dir, ck, nil)
	t0 := ck.now()
	j.Observe(t0, []Observation{tun("m00", TunnelOK), tun("m01", TunnelOK)})
	ck.add(60 * time.Second)
	j.Observe(ck.now(), []Observation{tun("m00", TunnelOK), tun("m01", TunnelOK)})
	j.Close()

	// A quick restart (20 s, below the gap threshold).
	ck.add(20 * time.Second)
	j = openJ(t, dir, ck, nil)
	if st := j.Stats(); !st.Restored || st.Objects != 2 {
		t.Fatalf("restored stats: %+v", st)
	}
	j.Observe(ck.now(), []Observation{tun("m00", TunnelOK), tun("m01", TunnelStale)})
	evs := mustEvents(t, j, 1)
	if e := evs[0]; e.ID != "m01" || e.From != TunnelOK || e.To != TunnelStale || prevFor(e) != 80 || !e.PrevOpen || e.AfterGap != nil {
		t.Fatalf("change across a short restart: %+v", e)
	}
	// m00 kept its state and its start: the restart did not reset it.
	if o := current(t, j, KindTunnel, "m00"); !o.Since.Equal(t0) || o.ForS != 80 {
		t.Fatalf("m00 after the restart: %+v", o)
	}
	j.Close()

	// Many restarts with unchanged states: never an event.
	for i := 0; i < 5; i++ {
		ck.add(15 * time.Second)
		j = openJ(t, dir, ck, nil)
		j.Observe(ck.now(), []Observation{tun("m00", TunnelOK), tun("m01", TunnelStale)})
		mustEvents(t, j, 1)
		j.Close()
	}
}

// A long stop is a gap: recorded once as "unknown", and no duration spans it.
func TestRestartAfterLongStopIsAGap(t *testing.T) {
	ck := newClock()
	dir := t.TempDir()
	j := openJ(t, dir, ck, nil)
	t0 := ck.now()
	j.Observe(t0, []Observation{tun("m00", TunnelOK), tun("m01", TunnelOK)})
	for i := 0; i < 30; i++ {
		ck.add(10 * time.Second)
		j.Observe(ck.now(), []Observation{tun("m00", TunnelOK), tun("m01", TunnelOK)})
	}
	last := ck.now()
	j.Close()

	ck.add(2 * time.Hour)
	j = openJ(t, dir, ck, nil)
	now := ck.now()
	j.Observe(now, []Observation{tun("m00", TunnelOK), tun("m01", TunnelStale)})
	evs := mustEvents(t, j, 2)
	var gap, chg Event
	for _, e := range evs {
		if e.Class == ClassCollector {
			gap = e
		} else {
			chg = e
		}
	}
	if gap.Kind != KindCollector || gap.From != StateUnknown || gap.To != StateCollecting || gap.Reason != ReasonRestart || prevFor(gap) != 7200 ||
		gap.AfterGap == nil || !gap.AfterGap.From.Equal(last) || !gap.AfterGap.To.Equal(now) {
		t.Fatalf("gap event: %+v", gap)
	}
	// The changed object: its previous state is counted up to the last
	// reading before the gap (300 s), never across it, and marked open.
	if chg.ID != "m01" || chg.From != TunnelOK || chg.To != TunnelStale || prevFor(chg) != 300 || !chg.PrevOpen || chg.AfterGap == nil ||
		!chg.AfterGap.From.Equal(last) || !chg.AfterGap.To.Equal(now) {
		t.Fatalf("change found after the gap: %+v", chg)
	}
	// The unchanged object: no event, and its duration starts again.
	o := current(t, j, KindTunnel, "m00")
	if !o.Since.Equal(now) || !o.SinceOpen || o.ForS != 0 {
		t.Fatalf("unchanged object after the gap: %+v", o)
	}
	if o := current(t, j, KindTunnel, "m01"); !o.SinceOpen {
		t.Fatalf("the state found after the gap began inside it: %+v", o)
	}
}

// Without a checkpoint a restart is a baseline again, whatever the events
// on disk say.
func TestRestartWithoutCheckpointIsBaseline(t *testing.T) {
	ck := newClock()
	dir := t.TempDir()
	j := openJ(t, dir, ck, nil)
	j.Observe(ck.now(), []Observation{tun("m00", TunnelOK)})
	ck.add(10 * time.Second)
	j.Observe(ck.now(), []Observation{tun("m00", TunnelStale)})
	j.Close()
	if err := os.Remove(filepath.Join(dir, checkpointFile)); err != nil {
		t.Fatal(err)
	}
	ck.add(10 * time.Second)
	j = openJ(t, dir, ck, nil)
	j.Observe(ck.now(), []Observation{tun("m00", TunnelOK)})
	evs := mustEvents(t, j, 1) // the one from before; nothing new
	if evs[0].To != TunnelStale || j.Stats().Restored {
		t.Fatalf("events %+v stats %+v", evs, j.Stats())
	}
	if o := current(t, j, KindTunnel, "m00"); !o.SinceOpen || o.State != TunnelOK {
		t.Fatalf("baseline again: %+v", o)
	}
}

// A crash between the event and the checkpoint: the event on disk moves the
// recorded state, so the first pass does not report the change twice.
func TestCrashBetweenEventAndCheckpoint(t *testing.T) {
	ck := newClock()
	dir := t.TempDir()
	j := openJ(t, dir, ck, nil)
	j.Observe(ck.now(), []Observation{tun("m00", TunnelOK)})
	old, err := os.ReadFile(filepath.Join(dir, checkpointFile))
	if err != nil {
		t.Fatal(err)
	}
	ck.add(30 * time.Second)
	j.Observe(ck.now(), []Observation{tun("m00", TunnelStale)})
	mustEvents(t, j, 1)
	j.Close()
	// The checkpoint of before the event comes back (as if the write of the
	// new one never happened).
	if err := os.WriteFile(filepath.Join(dir, checkpointFile), old, 0o600); err != nil {
		t.Fatal(err)
	}
	ck.add(10 * time.Second)
	j = openJ(t, dir, ck, nil)
	j.Observe(ck.now(), []Observation{tun("m00", TunnelStale)})
	evs := mustEvents(t, j, 1)
	if evs[0].To != TunnelStale {
		t.Fatalf("%+v", evs)
	}
	if o := current(t, j, KindTunnel, "m00"); o.State != TunnelStale {
		t.Fatalf("%+v", o)
	}
	// And the sequence numbers go on: no number is used twice.
	ck.add(10 * time.Second)
	j.Observe(ck.now(), []Observation{tun("m00", TunnelOK)})
	evs = mustEvents(t, j, 2)
	if evs[0].Seq <= evs[1].Seq {
		t.Fatalf("sequence numbers: %d then %d", evs[1].Seq, evs[0].Seq)
	}
}

// One object unread for longer than the gap threshold while the others go
// on: its duration restarts, a change found afterwards is marked.
func TestGapOfOneObject(t *testing.T) {
	ck := newClock()
	j := openJ(t, t.TempDir(), ck, nil)
	t0 := ck.now()
	j.Observe(t0, []Observation{tun("m00", TunnelOK), tun("m01", TunnelOK)})
	for i := 0; i < 30; i++ { // 5 minutes without a reading of m01
		ck.add(10 * time.Second)
		j.Observe(ck.now(), []Observation{tun("m00", TunnelOK)})
	}
	if o := current(t, j, KindTunnel, "m01"); !o.Stale || o.State != TunnelOK || o.ForS != 0 {
		t.Fatalf("an unread object is stale, with the last state read: %+v", o)
	}
	if o := current(t, j, KindTunnel, "m00"); o.Stale || o.ForS != 300 {
		t.Fatalf("m00: %+v", o)
	}
	ck.add(10 * time.Second)
	back := ck.now()
	j.Observe(back, []Observation{tun("m00", TunnelOK), tun("m01", TunnelOK)})
	mustEvents(t, j, 0) // same state, no event, no collection gap either
	if o := current(t, j, KindTunnel, "m01"); o.Stale || !o.SinceOpen || !o.Since.Equal(back) {
		t.Fatalf("m01 after its gap: %+v", o)
	}
	// Again, and this time it comes back changed.
	for i := 0; i < 30; i++ {
		ck.add(10 * time.Second)
		j.Observe(ck.now(), []Observation{tun("m00", TunnelOK)})
	}
	ck.add(10 * time.Second)
	j.Observe(ck.now(), []Observation{tun("m00", TunnelOK), tun("m01", TunnelStale)})
	evs := mustEvents(t, j, 1)
	if e := evs[0]; e.AfterGap == nil || !e.PrevOpen || prevFor(e) != -1 || !e.AfterGap.From.Equal(back) {
		// It was read exactly once before the gap (at "back"): no observed
		// length at all.
		t.Fatalf("change after the object's own gap: %+v", e)
	}
}

// A stall of the collector itself (no pass for longer than the threshold)
// is the same gap; a clock stepped back never gives a negative duration.
func TestStallAndClockStep(t *testing.T) {
	ck := newClock()
	j := openJ(t, t.TempDir(), ck, nil)
	j.Observe(ck.now(), []Observation{tun("m00", TunnelOK)})
	ck.add(10 * time.Minute)
	j.Observe(ck.now(), []Observation{tun("m00", TunnelStale)})
	evs := mustEvents(t, j, 2)
	if evs[1].Class != ClassCollector && evs[0].Class != ClassCollector {
		t.Fatalf("no gap event: %+v", evs)
	}
	for _, e := range evs {
		switch e.Class {
		case ClassCollector:
			if e.Reason != ReasonStall || prevFor(e) != 600 {
				t.Fatalf("stall: %+v", e)
			}
		default:
			if e.AfterGap == nil || prevFor(e) != -1 {
				t.Fatalf("change after a stall: %+v", e)
			}
		}
	}
	ck.add(-time.Hour)
	j.Observe(ck.now(), []Observation{tun("m00", TunnelOK)})
	evs = mustEvents(t, j, 4)
	for _, e := range evs {
		if e.PrevForS != nil && *e.PrevForS < 0 {
			t.Fatalf("negative duration: %+v", e)
		}
	}
	var clockEv *Event
	for i := range evs {
		if evs[i].Reason == ReasonClock {
			clockEv = &evs[i]
		}
	}
	if clockEv == nil || clockEv.PrevForS != nil || clockEv.From != StateUnknown {
		t.Fatalf("clock step: %+v", evs)
	}
	if o := current(t, j, KindTunnel, "m00"); o.ForS < 0 || !o.SinceOpen {
		t.Fatalf("%+v", o)
	}
}

// Rapid changes: the first FlapAfter are single events, the rest become one
// record that says how many changes, from when to when — not one outage.
func TestFlapMerging(t *testing.T) {
	ck := newClock()
	j := openJ(t, t.TempDir(), ck, nil)
	j.Observe(ck.now(), []Observation{tun("m00", TunnelOK), tun("m01", TunnelOK)})
	states := []string{TunnelStale, TunnelOK}
	var firstMerged, lastChange time.Time
	const changes = 31
	for i := 0; i < changes; i++ {
		ck.add(10 * time.Second)
		if i == DefaultFlapAfter {
			firstMerged = ck.now()
		}
		lastChange = ck.now()
		j.Observe(ck.now(), []Observation{tun("m00", states[i%2]), tun("m01", TunnelOK)})
	}
	// Still counting: the single events are written, the merged record is
	// open and shown as such.
	p, err := j.Query(Query{})
	if err != nil {
		t.Fatal(err)
	}
	if p.OpenMerged != 1 || len(p.Events) != DefaultFlapAfter+1 || !p.Events[0].Open || p.Events[0].Changes != changes-DefaultFlapAfter || p.Events[0].Seq != 0 {
		t.Fatalf("while flapping: open %d, %d events, first %+v", p.OpenMerged, len(p.Events), p.Events[0])
	}
	if o := current(t, j, KindTunnel, "m00"); o.Flapping == nil || o.Flapping.Changes != changes-DefaultFlapAfter || o.State != TunnelStale {
		t.Fatalf("current while flapping: %+v", o)
	}
	if st := j.Stats(); st.OpenFlaps != 1 || st.Events != DefaultFlapAfter || st.Merged != changes-DefaultFlapAfter {
		t.Fatalf("stats while flapping: %+v", st)
	}
	// Quiet for FlapQuiet: the record is written.
	for i := 0; i < 61; i++ {
		ck.add(10 * time.Second)
		j.Observe(ck.now(), []Observation{tun("m00", TunnelStale), tun("m01", TunnelOK)})
	}
	evs := mustEvents(t, j, DefaultFlapAfter+1)
	var m Event
	for _, e := range evs {
		if e.Changes > 1 {
			m = e
		}
	}
	if m.Changes != changes-DefaultFlapAfter || !m.At.Equal(firstMerged) || m.LastAt == nil || !m.LastAt.Equal(lastChange) || m.Open || m.Seq == 0 ||
		m.From != TunnelOK || m.To != TunnelStale || m.PrevForS != nil || !strings.Contains(m.Evidence, fmt.Sprintf("变化了 %d 次", changes-DefaultFlapAfter)) ||
		!strings.Contains(m.Evidence, "不是一次连续的中断") {
		t.Fatalf("merged record: %+v", m)
	}
	if o := current(t, j, KindTunnel, "m00"); o.Flapping != nil || !o.Since.Equal(lastChange) || o.SinceOpen {
		t.Fatalf("after the flap: %+v", o)
	}
	// The next change is a single event again, with the real duration since
	// the last change of the burst.
	ck.add(10 * time.Second)
	j.Observe(ck.now(), []Observation{tun("m00", TunnelOK), tun("m01", TunnelOK)})
	evs = mustEvents(t, j, DefaultFlapAfter+2)
	if e := evs[0]; e.Changes != 0 || prevFor(e) != int64(ck.now().Sub(lastChange)/time.Second) || e.PrevOpen {
		t.Fatalf("single event after the burst: %+v", e)
	}
	// The quiet tunnel never got an event.
	if got := events(t, j, Query{Kind: KindTunnel, ID: "m01"}); len(got) != 0 {
		t.Fatalf("m01: %+v", got)
	}
}

// A merged record with a single change is written as the plain event it is.
func TestFlapWithOneChangeIsAPlainEvent(t *testing.T) {
	ck := newClock()
	j := openJ(t, t.TempDir(), ck, nil)
	j.Observe(ck.now(), []Observation{tun("m00", TunnelOK)})
	states := []string{TunnelStale, TunnelOK}
	for i := 0; i < DefaultFlapAfter+1; i++ {
		ck.add(20 * time.Second)
		j.Observe(ck.now(), []Observation{tun("m00", states[i%2])})
	}
	at := ck.now()
	for i := 0; i < 61; i++ {
		ck.add(10 * time.Second)
		j.Observe(ck.now(), []Observation{tun("m00", TunnelStale)})
	}
	evs := mustEvents(t, j, DefaultFlapAfter+1)
	for _, e := range evs {
		if e.Changes != 0 || e.LastAt != nil {
			t.Fatalf("no merged record expected: %+v", e)
		}
	}
	var found bool
	for _, e := range evs {
		if e.At.Equal(at) && prevFor(e) == 20 {
			found = true
		}
	}
	if !found {
		t.Fatalf("the fifth change with its duration: %+v", evs)
	}
}

// An object that never stops changing gets one merged record per FlapMax,
// and an open record survives a restart.
func TestFlapNeverQuietAndRestart(t *testing.T) {
	ck := newClock()
	dir := t.TempDir()
	j := openJ(t, dir, ck, nil)
	j.Observe(ck.now(), []Observation{tun("m00", TunnelOK)})
	states := []string{TunnelStale, TunnelOK}
	n := 0
	step := func(k int) {
		for i := 0; i < k; i++ {
			ck.add(10 * time.Second)
			j.Observe(ck.now(), []Observation{tun("m00", states[n%2])})
			n++
		}
	}
	step(100)
	if st := j.Stats(); st.OpenFlaps != 1 || st.Events != DefaultFlapAfter {
		t.Fatalf("%+v", st)
	}
	j.Close()
	ck.add(5 * time.Second)
	j = openJ(t, dir, ck, nil)
	if st := j.Stats(); st.OpenFlaps != 1 {
		t.Fatalf("the open record did not survive the restart: %+v", st)
	}
	step(3 * 360) // three more hours
	evs := events(t, j, Query{Limit: PageMax})
	merged, total := 0, 0
	for _, e := range evs {
		if e.Changes > 1 && !e.Open {
			merged++
			total += e.Changes
			if d := e.LastAt.Sub(e.At); d > DefaultFlapMax+time.Minute {
				t.Fatalf("a merged record spans %s: %+v", d, e)
			}
		}
	}
	if merged < 3 || merged > 4 {
		t.Fatalf("%d merged records in three hours, want 3 or 4", merged)
	}
	if st := j.Stats(); st.Events != DefaultFlapAfter+merged {
		t.Fatalf("only the first single events and one record per hour are written: %+v", st)
	}
	_ = total
}

// The hourly write budget: beyond it events are dropped and counted, the
// states are still tracked.
func TestWriteBudget(t *testing.T) {
	ck := newClock()
	j := openJ(t, t.TempDir(), ck, func(o *Options) { o.WritesPerHour = 50 })
	mk := func(state string) []Observation {
		var obs []Observation
		for i := 0; i < 200; i++ {
			obs = append(obs, tun(fmt.Sprintf("m%03d", i), state))
		}
		return obs
	}
	j.Observe(ck.now(), mk(TunnelOK))
	ck.add(10 * time.Second)
	j.Observe(ck.now(), mk(TunnelStale))
	st := j.Stats()
	if st.Events != 50 || st.DroppedBudget != 150 || st.Written != 50 {
		t.Fatalf("budget: %+v", st)
	}
	for _, o := range j.Current().Objects {
		if o.State != TunnelStale {
			t.Fatalf("a dropped event must not lose the state: %+v", o)
		}
	}
	// An hour later the budget is there again.
	for i := 0; i < 61; i++ {
		ck.add(time.Minute)
		j.Observe(ck.now(), mk(TunnelStale))
	}
	ck.add(time.Minute)
	j.Observe(ck.now(), mk(TunnelOK))
	if st := j.Stats(); st.Events != 100 || st.DroppedBudget != 300 {
		t.Fatalf("budget after an hour: %+v", st)
	}
}

func dirUsage(t *testing.T, dir string) (files int, bytes int64) {
	t.Helper()
	ents, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range ents {
		fi, err := e.Info()
		if err != nil {
			t.Fatal(err)
		}
		if fi.Mode().Perm() != 0o600 || !fi.Mode().IsRegular() {
			t.Fatalf("%s has mode %v", e.Name(), fi.Mode())
		}
		files++
		// What the file system charges: whole blocks.
		bytes += (fi.Size() + blockSlack - 1) / blockSlack * blockSlack
	}
	return files, bytes
}

// A flood on a fake clock: many objects changing for days. The three bounds
// hold at every step, checkpoint and temporary copies included.
func TestBoundsUnderFlood(t *testing.T) {
	ck := newClock()
	dir := t.TempDir()
	const maxEvents, maxBytes = 400, MinBytes
	j := openJ(t, dir, ck, func(o *Options) { o.MaxEvents, o.MaxBytes, o.MaxAge = maxEvents, maxBytes, 48*time.Hour })
	long := strings.Repeat("依据", 400)
	states := []string{TunnelStale, TunnelOK}
	for step := 0; step < 6000; step++ {
		ck.add(time.Minute)
		var obs []Observation
		// 40 objects change on every pass (merged); 260 change every 20
		// minutes, staggered (single events: more than the hourly budget).
		for i := 0; i < 300; i++ {
			st := states[(step+i)%2]
			if i >= 40 {
				st = states[((step+i)/20)%2]
			}
			o := tun(fmt.Sprintf("m%03d", i), st)
			o.Evidence, o.Label = long, long
			obs = append(obs, o)
		}
		j.Observe(ck.now(), obs)
		if step%250 == 0 || step == 5999 {
			st := j.Stats()
			_, used := dirUsage(t, dir)
			if st.Events > maxEvents || used > maxBytes || st.Segments > MaxSegments || st.DiskBytes > maxBytes {
				t.Fatalf("step %d: %d events, %d bytes on disk (%d by size), %d segments", step, st.Events, used, st.DiskBytes, st.Segments)
			}
			if st.Oldest != nil && ck.now().Sub(*st.Oldest) > 48*time.Hour+TrimEvery {
				t.Fatalf("step %d: oldest event is %s old", step, ck.now().Sub(*st.Oldest))
			}
		}
	}
	st := j.Stats()
	if st.DroppedBudget == 0 || st.Merged == 0 || st.Trimmed == 0 || st.WriteErrors != 0 || st.CheckpointError != "" {
		t.Fatalf("the flood exercised nothing: %+v", st)
	}
	// Per hour at most WritesPerHour events were written.
	if perHour := float64(st.Written) / 100; perHour > DefaultWritesPerHour {
		t.Fatalf("%.0f events per hour written", perHour)
	}
	// What is on disk can be read back.
	j.Close()
	j2 := openJ(t, dir, ck, func(o *Options) { o.MaxEvents, o.MaxBytes, o.MaxAge = maxEvents, maxBytes, 48*time.Hour })
	if st2 := j2.Stats(); st2.Events != st.Events || st2.BadLines != 0 {
		t.Fatalf("reopened: %d events (%d bad lines), had %d", st2.Events, st2.BadLines, st.Events)
	}
}

// The default bounds with the largest events the journal writes (texts
// clipped to MaxEvidence and MaxLabel: about 700 bytes a line): the event
// bound is reached first, and the directory stays inside the 16 MiB budget.
func TestDefaultBoundsWorstCase(t *testing.T) {
	if testing.Short() {
		t.Skip("writes 24000 events")
	}
	ck := newClock()
	dir := t.TempDir()
	j := openJ(t, dir, ck, func(o *Options) { o.WritesPerHour = 1 << 30; o.FlapAfter = 1 << 30 })
	long := strings.Repeat("x", 2000)
	states := []string{TunnelStale, TunnelOK}
	j.Observe(ck.now(), []Observation{tun("m00", TunnelOK)})
	for i := 0; i < 24000; i++ {
		ck.add(time.Second)
		o := tun("m00", states[i%2])
		o.Evidence, o.Label = long, long
		j.Observe(ck.now(), []Observation{o})
	}
	st := j.Stats()
	_, used := dirUsage(t, dir)
	if st.Events > DefaultMaxEvents || used > DefaultMaxBytes || st.Bytes > st.Budget.Events {
		t.Fatalf("%d events, %d bytes in segments (share %d), %d on disk", st.Events, st.Bytes, st.Budget.Events, used)
	}
	if st.Events < 14000 {
		t.Fatalf("only %d events kept: the bounds cut far too early", st.Events)
	}
	if st.Bytes/int64(st.Events) > MaxLine {
		t.Fatalf("an event takes %d bytes on average", st.Bytes/int64(st.Events))
	}
	t.Logf("worst case: %d events of %d bytes on average, %d bytes on disk", st.Events, st.Bytes/int64(st.Events), used)
}

// With a small byte budget and a large event bound the byte bound decides:
// the directory never exceeds the budget.
func TestByteBoundDecides(t *testing.T) {
	ck := newClock()
	dir := t.TempDir()
	j := openJ(t, dir, ck, func(o *Options) { o.MaxBytes = MinBytes; o.WritesPerHour = 1 << 30; o.FlapAfter = 1 << 30 })
	long := strings.Repeat("x", 2000)
	states := []string{TunnelStale, TunnelOK}
	j.Observe(ck.now(), []Observation{tun("m00", TunnelOK)})
	for i := 0; i < 9000; i++ {
		ck.add(time.Second)
		o := tun("m00", states[i%2])
		o.Evidence, o.Label = long, long
		j.Observe(ck.now(), []Observation{o})
		if i%500 == 499 {
			if _, used := dirUsage(t, dir); used > MinBytes {
				t.Fatalf("after %d events: %d bytes on disk, budget %d", i+1, used, MinBytes)
			}
		}
	}
	st := j.Stats()
	if st.Events >= 9000 || st.Events < 2500 || st.Bytes > st.Budget.Events || st.Trimmed == 0 {
		t.Fatalf("%d events, %d bytes (share %d), trimmed %d", st.Events, st.Bytes, st.Budget.Events, st.Trimmed)
	}
}

func TestSplitBudget(t *testing.T) {
	b := SplitBudget(0)
	if b.Total != DefaultMaxBytes || b.Events+b.Checkpoint+b.Rewrite != b.Total || b.Events < 14<<20 || b.Checkpoint < 2*MaxCheckpoint || b.Rewrite < SegmentEvents*MaxLine {
		t.Fatalf("%+v", b)
	}
	if _, err := Open(Options{Dir: t.TempDir(), MaxBytes: MinBytes - 1}); err == nil {
		t.Fatal("a budget below the minimum must be refused")
	}
	if _, err := Open(Options{Dir: "relative"}); err == nil {
		t.Fatal("a relative directory must be refused")
	}
}

// Events older than MaxAge are never returned and leave the disk.
func TestMaxAge(t *testing.T) {
	ck := newClock()
	dir := t.TempDir()
	opts := func(o *Options) { o.MaxAge = 24 * time.Hour; o.FlapAfter = 1 << 30; o.GapAfter = 3 * time.Hour }
	j := openJ(t, dir, ck, opts)
	j.Observe(ck.now(), []Observation{tun("m00", TunnelOK)})
	states := []string{TunnelStale, TunnelOK}
	for i := 0; i < 40; i++ { // one change an hour for 40 hours
		ck.add(time.Hour)
		j.Observe(ck.now(), []Observation{tun("m00", states[i%2])})
	}
	evs := events(t, j, Query{Limit: PageMax})
	if len(evs) < 23 || len(evs) > 25 {
		t.Fatalf("%d events returned, want the last 24 hours", len(evs))
	}
	cut := ck.now().Add(-24 * time.Hour)
	for _, e := range evs {
		if e.At.Before(cut) {
			t.Fatalf("an expired event was returned: %+v", e)
		}
	}
	st := j.Stats()
	if st.Events > 26 || st.Trimmed < 14 {
		t.Fatalf("expired events stayed on disk: %+v", st)
	}
	// Reopened: the same events, nothing expired comes back.
	j.Close()
	j = openJ(t, dir, ck, opts)
	if got := events(t, j, Query{Limit: PageMax}); len(got) != len(evs) {
		t.Fatalf("reopened: %d events, had %d", len(got), len(evs))
	}
	// Everything expires.
	ck.add(48 * time.Hour)
	j.Observe(ck.now(), []Observation{tun("m00", TunnelOK)})
	for _, e := range events(t, j, Query{Limit: PageMax}) {
		if e.Class != ClassCollector && e.At.Before(ck.now().Add(-24*time.Hour)) {
			t.Fatalf("expired: %+v", e)
		}
	}
	ck.add(2 * time.Hour)
	j.Observe(ck.now(), []Observation{tun("m00", TunnelOK)})
	if st := j.Stats(); st.Events > 3 {
		t.Fatalf("after two more days: %+v", st)
	}
}

// Between two removals of expired events from disk (TrimEvery) a query
// still never returns one.
func TestMaxAgeBetweenTrims(t *testing.T) {
	ck := newClock()
	j := openJ(t, t.TempDir(), ck, func(o *Options) { o.MaxAge = 2 * time.Hour; o.FlapAfter = 1 << 30 })
	j.Observe(ck.now(), []Observation{tun("m00", TunnelOK)})
	states := []string{TunnelStale, TunnelOK}
	onDisk := 0
	for i := 0; i < 400; i++ { // one change a minute for almost seven hours
		ck.add(time.Minute)
		j.Observe(ck.now(), []Observation{tun("m00", states[i%2])})
		cut := ck.now().Add(-2 * time.Hour)
		evs := events(t, j, Query{Limit: PageMax})
		for _, e := range evs {
			if e.At.Before(cut) {
				t.Fatalf("minute %d: an expired event was returned: %+v", i, e)
			}
		}
		if i > 130 && (len(evs) < 120 || len(evs) > 121) {
			t.Fatalf("minute %d: %d events returned, want the last two hours", i, len(evs))
		}
		if st := j.Stats(); st.Events > len(evs) {
			onDisk++ // expired events not yet removed from disk
		}
	}
	if onDisk == 0 {
		t.Fatal("the test never saw an expired event still on disk: it did not test the query's own filter")
	}
}

// Clear removes everything; the next pass is a baseline, not a gap.
func TestClear(t *testing.T) {
	ck := newClock()
	dir := t.TempDir()
	j := openJ(t, dir, ck, nil)
	j.Observe(ck.now(), []Observation{tun("m00", TunnelOK)})
	ck.add(10 * time.Second)
	j.Observe(ck.now(), []Observation{tun("m00", TunnelStale)})
	if n := j.Clear(); n != 1 {
		t.Fatalf("cleared %d", n)
	}
	if files, _ := dirUsage(t, dir); files != 0 {
		t.Fatalf("%d files left after a clear", files)
	}
	st := j.Stats()
	if st.Events != 0 || st.Objects != 0 || st.ClearedAt == nil || st.DiskBytes != 0 {
		t.Fatalf("%+v", st)
	}
	if len(j.Current().Objects) != 0 {
		t.Fatal("objects left after a clear")
	}
	ck.add(time.Hour) // far beyond the gap threshold
	j.Observe(ck.now(), []Observation{tun("m00", TunnelOK)})
	mustEvents(t, j, 0)
	if o := current(t, j, KindTunnel, "m00"); !o.SinceOpen {
		t.Fatalf("%+v", o)
	}
	ck.add(10 * time.Second)
	j.Observe(ck.now(), []Observation{tun("m00", TunnelStale)})
	mustEvents(t, j, 1)
	// A restart right after a clear (before any pass) is a baseline too.
	j.Clear()
	j.Close()
	ck.add(time.Hour)
	j = openJ(t, dir, ck, nil)
	j.Observe(ck.now(), []Observation{tun("m00", TunnelOK)})
	mustEvents(t, j, 0)
}

// The directory is root-only by mode, the files 0600; a symbolic link is
// neither accepted as the directory nor followed as a file.
func TestPermissionsAndLinks(t *testing.T) {
	ck := newClock()
	base := t.TempDir()
	dir := filepath.Join(base, "journal")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	j := openJ(t, dir, ck, nil)
	j.Observe(ck.now(), []Observation{tun("m00", TunnelOK)})
	ck.add(10 * time.Second)
	j.Observe(ck.now(), []Observation{tun("m00", TunnelStale)})
	fi, err := os.Stat(dir)
	if err != nil || fi.Mode().Perm() != 0o700 {
		t.Fatalf("directory mode %v %v", fi.Mode(), err)
	}
	if files, _ := dirUsage(t, dir); files != 2 { // one segment, the checkpoint
		t.Fatalf("%d files", files)
	}
	j.Close()

	// A file of the journal's own name that is a link: never read, never
	// written through.
	secret := filepath.Join(base, "secret")
	if err := os.WriteFile(secret, []byte(`{"seq":99,"at":"2026-03-01T08:00:00Z","class":"tunnel","kind":"tunnel","id":"evil","from":"a","to":"b"}`+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(secret, filepath.Join(dir, segName(99))); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(dir, checkpointFile)); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(secret, filepath.Join(dir, checkpointFile)); err != nil {
		t.Fatal(err)
	}
	j = openJ(t, dir, ck, nil)
	for _, e := range events(t, j, Query{Limit: PageMax}) {
		if e.ID == "evil" {
			t.Fatal("a linked segment was read")
		}
	}
	if j.Stats().Restored {
		t.Fatal("a linked checkpoint was read")
	}
	j.Close()

	// The directory itself a link: refused.
	link := filepath.Join(base, "link")
	if err := os.Symlink(dir, link); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(Options{Dir: link}); err == nil {
		t.Fatal("a linked directory must be refused")
	}
}

// A torn last line (power loss in the middle of a write) loses that line
// only, and the next event starts a new segment.
func TestTornTail(t *testing.T) {
	ck := newClock()
	dir := t.TempDir()
	j := openJ(t, dir, ck, func(o *Options) { o.FlapAfter = 1 << 30 })
	j.Observe(ck.now(), []Observation{tun("m00", TunnelOK)})
	states := []string{TunnelStale, TunnelOK}
	for i := 0; i < 3; i++ {
		ck.add(10 * time.Second)
		j.Observe(ck.now(), []Observation{tun("m00", states[i%2])})
	}
	j.Close()
	seg := filepath.Join(dir, segName(1))
	b, err := os.ReadFile(seg)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(seg, b[:len(b)-20], 0o600); err != nil {
		t.Fatal(err)
	}
	ck.add(10 * time.Second)
	j = openJ(t, dir, ck, func(o *Options) { o.FlapAfter = 1 << 30 })
	st := j.Stats()
	if st.Events != 2 || st.BadLines != 1 {
		t.Fatalf("after a torn tail: %+v", st)
	}
	j.Observe(ck.now(), []Observation{tun("m00", TunnelOK)})
	if st := j.Stats(); st.Segments != 2 || st.Events != 3 {
		t.Fatalf("the next event must start a new segment: %+v", st)
	}
	// A whole last segment is appended to instead.
	j.Close()
	ck.add(10 * time.Second)
	j = openJ(t, dir, ck, func(o *Options) { o.FlapAfter = 1 << 30 })
	j.Observe(ck.now(), []Observation{tun("m00", TunnelStale)})
	if st := j.Stats(); st.Segments != 2 || st.Events != 4 || st.BadLines != 1 {
		t.Fatalf("a whole segment takes further events: %+v", st)
	}
}

// A segment that cannot be read (here: no permission bits and a directory
// in a segment's place) loses its events only; the journal still opens.
func TestUnreadableSegmentDoesNotStopTheJournal(t *testing.T) {
	ck := newClock()
	dir := t.TempDir()
	j := openJ(t, dir, ck, func(o *Options) { o.FlapAfter = 1 << 30 })
	j.Observe(ck.now(), []Observation{tun("m00", TunnelOK)})
	ck.add(10 * time.Second)
	j.Observe(ck.now(), []Observation{tun("m00", TunnelStale)})
	j.Close()
	if err := os.Mkdir(filepath.Join(dir, segName(500)), 0o700); err != nil {
		t.Fatal(err)
	}
	if os.Geteuid() != 0 {
		if err := os.Chmod(filepath.Join(dir, segName(1)), 0); err != nil {
			t.Fatal(err)
		}
	}
	ck.add(10 * time.Second)
	j, err := Open(Options{Dir: dir, Now: ck.now, noSync: true})
	if err != nil {
		t.Fatalf("the journal did not open: %v", err)
	}
	defer j.Close()
	j.Observe(ck.now(), []Observation{tun("m00", TunnelOK)})
	if st := j.Stats(); st.WriteErrors != 0 || st.Events == 0 {
		t.Fatalf("no event could be written after the damage: %+v", st)
	}
}

func TestQueryFiltersAndPaging(t *testing.T) {
	ck := newClock()
	j := openJ(t, t.TempDir(), ck, func(o *Options) { o.FlapAfter = 1 << 30 })
	start := ck.now()
	base := []Observation{tun("m00", TunnelOK), tun("m01", TunnelOK),
		{Class: ClassPath, Kind: KindUpstream, ID: GatewayID, State: "udp", Source: SourceUpstream},
		{Class: ClassRelay, Kind: KindRelay, ID: "access", State: "active", Source: SourceUpstream}}
	j.Observe(ck.now(), base)
	states := []string{TunnelStale, TunnelOK}
	paths := []string{"backup", "udp"}
	for i := 0; i < 60; i++ {
		ck.add(time.Minute)
		obs := []Observation{tun("m00", states[i%2]), tun("m01", TunnelOK),
			{Class: ClassPath, Kind: KindUpstream, ID: GatewayID, State: paths[(i/10)%2], Source: SourceUpstream},
			{Class: ClassRelay, Kind: KindRelay, ID: "access", State: "active", Source: SourceUpstream}}
		j.Observe(ck.now(), obs)
	}
	all := events(t, j, Query{Limit: PageMax})
	if len(all) != 66 { // 60 tunnel changes, 6 path changes
		t.Fatalf("%d events", len(all))
	}
	for i := 1; i < len(all); i++ {
		if all[i].At.After(all[i-1].At) {
			t.Fatalf("not newest first at %d", i)
		}
	}
	if got := events(t, j, Query{Class: ClassPath, Limit: PageMax}); len(got) != 6 {
		t.Fatalf("class filter: %d", len(got))
	}
	if got := events(t, j, Query{Kind: KindTunnel, ID: "m00", Limit: PageMax}); len(got) != 60 {
		t.Fatalf("object filter: %d", len(got))
	}
	if got := events(t, j, Query{Kind: KindTunnel, ID: "m01", Limit: PageMax}); len(got) != 0 {
		t.Fatalf("object without events: %d", len(got))
	}
	if got := events(t, j, Query{Class: ClassRelay}); len(got) != 0 {
		t.Fatalf("class without events: %d", len(got))
	}
	from, to := start.Add(10*time.Minute), start.Add(20*time.Minute)
	got := events(t, j, Query{From: from.Format(time.RFC3339), To: to.Format(time.RFC3339), Limit: PageMax})
	if len(got) != 12 { // minutes 10..20 inclusive: 11 tunnel changes and one path change
		t.Fatalf("time range: %d events", len(got))
	}
	for _, e := range got {
		if e.At.Before(from) || e.At.After(to) {
			t.Fatalf("outside the range: %+v", e)
		}
	}
	// Paging: every event exactly once, in order.
	seen := map[uint64]bool{}
	q := Query{Limit: 7}
	pages := 0
	for {
		p, err := j.Query(q)
		if err != nil {
			t.Fatal(err)
		}
		pages++
		for _, e := range p.Events {
			if seen[e.Seq] {
				t.Fatalf("event %d returned twice", e.Seq)
			}
			seen[e.Seq] = true
		}
		if p.NextBefore == "" {
			break
		}
		if len(p.Events) != 7 {
			t.Fatalf("a full page has %d events", len(p.Events))
		}
		q.Before = p.NextBefore
	}
	if len(seen) != 66 || pages != 10 {
		t.Fatalf("paging returned %d events in %d pages", len(seen), pages)
	}
	// Paging inside a filter.
	p, _ := j.Query(Query{Class: ClassPath, Limit: 4})
	p2, _ := j.Query(Query{Class: ClassPath, Limit: 4, Before: p.NextBefore})
	if len(p.Events) != 4 || p.NextBefore == "" || len(p2.Events) != 2 || p2.NextBefore != "" {
		t.Fatalf("filtered paging: %d + %d, next %q %q", len(p.Events), len(p2.Events), p.NextBefore, p2.NextBefore)
	}
	// Default page size.
	if p, _ := j.Query(Query{}); len(p.Events) != 66 || p.NextBefore != "" {
		t.Fatalf("default page: %d", len(p.Events))
	}
}

func TestQueryValidation(t *testing.T) {
	bad := []Query{
		{Class: "a b"}, {Kind: "../x"}, {ID: strings.Repeat("a", 97)}, {ID: "-x"}, {From: "yesterday"}, {To: "2026-13-01T00:00:00Z"},
		{From: "2026-03-02T00:00:00Z", To: "2026-03-01T00:00:00Z"}, {Before: "12"}, {Before: "a-b"}, {Before: "1-2-3"}, {Limit: -1}, {Limit: PageMax + 1},
	}
	for _, q := range bad {
		if q.Validate() == nil {
			t.Errorf("accepted %+v", q)
		}
	}
	good := Query{Class: ClassTunnel, Kind: KindTunnel, ID: "m00w", From: "2026-03-01T00:00:00Z", To: "2026-03-02T00:00:00+08:00", Before: "1772352000-17", Limit: PageMax}
	if err := good.Validate(); err != nil {
		t.Fatal(err)
	}
	back, err := QueryFrom(good.Values())
	if err != nil || back != good {
		t.Fatalf("round trip: %+v %v", back, err)
	}
	for _, v := range []url.Values{
		{"class": {"a", "b"}}, {"device": {"192.0.2.1"}}, {"limit": {"0"}}, {"limit": {"x"}}, {"text": {"x"}}, {"id": {"a b"}},
	} {
		if _, err := QueryFrom(v); err == nil {
			t.Errorf("accepted %v", v)
		}
	}
	if q, err := QueryFrom(url.Values{}); err != nil || q != (Query{}) {
		t.Fatalf("empty query: %+v %v", q, err)
	}
}

// One stored event never exceeds MaxLine, whatever a source hands in.
func TestEventLineBound(t *testing.T) {
	ck := newClock()
	dir := t.TempDir()
	j := openJ(t, dir, ck, nil)
	j.Observe(ck.now(), []Observation{tun("m00", TunnelOK)})
	ck.add(10 * time.Second)
	o := tun("m00", TunnelStale)
	o.Evidence, o.Label, o.Reason = strings.Repeat("证", 5000), strings.Repeat("标", 5000), strings.Repeat("r", 5000)
	j.Observe(ck.now(), []Observation{o})
	evs := mustEvents(t, j, 1)
	if len(evs[0].Evidence) > MaxEvidence+4 || len(evs[0].Label) > MaxLabel+4 || !strings.HasSuffix(evs[0].Evidence, "…") {
		t.Fatalf("texts not clipped: %d %d", len(evs[0].Evidence), len(evs[0].Label))
	}
	b, err := os.ReadFile(filepath.Join(dir, segName(1)))
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(strings.TrimRight(string(b), "\n"), "\n") {
		if len(line)+1 > MaxLine {
			t.Fatalf("a stored line has %d bytes", len(line)+1)
		}
	}
	fi, err := os.Stat(filepath.Join(dir, checkpointFile))
	if err != nil || fi.Size() > MaxCheckpoint {
		t.Fatalf("checkpoint: %v %v", fi, err)
	}
}

// More objects than MaxObjects: the extra ones are refused and counted, the
// checkpoint stays inside its bound.
func TestObjectBound(t *testing.T) {
	ck := newClock()
	dir := t.TempDir()
	j := openJ(t, dir, ck, nil)
	var obs []Observation
	for i := 0; i < MaxObjects+50; i++ {
		o := tun(fmt.Sprintf("x%04d", i), TunnelOK)
		o.Evidence, o.Label = strings.Repeat("证", 300), strings.Repeat("标", 100)
		obs = append(obs, o)
	}
	j.Observe(ck.now(), obs)
	st := j.Stats()
	if st.Objects != MaxObjects || st.ObjectsRefused != 50 || st.CheckpointError != "" {
		t.Fatalf("%+v", st)
	}
	fi, err := os.Stat(filepath.Join(dir, checkpointFile))
	if err != nil || fi.Size() > MaxCheckpoint {
		t.Fatalf("checkpoint of %d bytes: %v", fi.Size(), err)
	}
	j.Close()
	j = openJ(t, dir, ck, nil)
	if st := j.Stats(); st.Objects != MaxObjects || !st.Restored {
		t.Fatalf("reopened: %+v", st)
	}
}

// A new object list: objects it no longer names are forgotten, the change
// is one event, the others keep their state.
func TestSetDigest(t *testing.T) {
	ck := newClock()
	dir := t.TempDir()
	j := openJ(t, dir, ck, nil)
	j.SetDigest("aaaa", nil)
	j.Observe(ck.now(), []Observation{tun("m00", TunnelOK), tun("m01", TunnelOK)})
	j.Close()
	ck.add(10 * time.Second)
	j = openJ(t, dir, ck, nil)
	j.SetDigest("aaaa", func(kind, id string) bool { return true })
	mustEvents(t, j, 0)
	j.Close()
	ck.add(10 * time.Second)
	j = openJ(t, dir, ck, nil)
	j.SetDigest("bbbb", func(kind, id string) bool { return id == "m00" })
	evs := mustEvents(t, j, 1)
	if e := evs[0]; e.Class != ClassCollector || e.Kind != KindConfig || e.From != "aaaa" || e.To != "bbbb" || e.Reason != ReasonConfig {
		t.Fatalf("%+v", e)
	}
	j.Observe(ck.now(), []Observation{tun("m00", TunnelOK), tun("m01", TunnelStale)})
	mustEvents(t, j, 1) // m01 is new to this list: a baseline, not a change
	if o := current(t, j, KindTunnel, "m01"); !o.SinceOpen {
		t.Fatalf("%+v", o)
	}
	if o := current(t, j, KindTunnel, "m00"); o.ForS != 20 {
		t.Fatalf("m00 kept its state: %+v", o)
	}
}

// Concurrent passes, queries and reads (run with -race).
func TestConcurrentUse(t *testing.T) {
	ck := newClock()
	j := openJ(t, t.TempDir(), ck, nil)
	j.Observe(ck.now(), []Observation{tun("m00", TunnelOK)})
	var wg sync.WaitGroup
	stop := make(chan struct{})
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				_, _ = j.Query(Query{Class: ClassTunnel})
				_ = j.Current()
				_ = j.Stats()
			}
		}()
	}
	states := []string{TunnelStale, TunnelOK}
	for i := 0; i < 300; i++ {
		j.Observe(ck.add(10*time.Second), []Observation{tun("m00", states[i%2])})
		if i == 150 {
			j.Clear()
		}
	}
	close(stop)
	wg.Wait()
}

// Level and the catalogue: every state the collector derives is listed.
func TestKindsCatalogue(t *testing.T) {
	want := map[string][]string{
		KindUpstream: {"udp", "wss", "main", "backup", "direct", PathNone, PathOther},
		KindHealth:   {HealthOK, HealthDown, HealthDegraded},
		KindRelay:    {"active", "reduced", "standby", "evicted", "recovering", "disabled"},
		KindTunnel:   {TunnelOK, TunnelStale, TunnelNever, TunnelAbsent},
		KindWSS:      {WSSConnected, WSSDisconnected, WSSStopped, WSSRunning},
		KindExternal: {CheckOK, CheckFailed, CheckUnchecked},
		KindTarget:   {CheckOK, CheckFailed, CheckUnchecked},
		KindSource:   {StateSourceOK, StateUnavailable},
	}
	for kind, states := range want {
		var k *KindInfo
		for i := range Kinds {
			if Kinds[i].Kind == kind {
				k = &Kinds[i]
			}
		}
		if k == nil || k.Label == "" || k.Class == "" {
			t.Fatalf("kind %s is not in the catalogue", kind)
		}
		for _, s := range states {
			found := false
			for _, si := range k.States {
				found = found || si.State == s && si.Label != "" && si.Level != ""
			}
			if !found {
				t.Errorf("state %s of %s is not in the catalogue", s, kind)
			}
		}
	}
	for kind, state := range map[string]string{KindTunnel: TunnelStale, KindUpstream: "backup", KindHealth: HealthDown, KindRelay: "evicted", KindWSS: WSSStopped, KindExternal: CheckFailed, KindTarget: CheckFailed} {
		if Level(kind, state) != LevelAbnormal {
			t.Errorf("%s %s must be abnormal", kind, state)
		}
	}
	if Level(KindUpstream, "udp") != LevelOK || Level(KindDesignate, "access") != LevelInfo || Level("nope", "x") != LevelInfo {
		t.Error("levels")
	}
}
