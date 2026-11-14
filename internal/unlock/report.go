package unlock

// Report admission: which probe results may change an unlock State.
//
// Every result is keyed by service, exit and address family (ResultKey).
// The rules below are what Ingest enforces; anything that feeds probe
// results into the snapshot (the /api/unlock/report handler today, a
// panel-run probe later) must call Ingest rather than Advance directly.
//
// Clocks. Two times are kept per result:
//
//   - ObservedAt: when the probe ran. It may come from the reporter. It is
//     used only to order results and to reject stale ones.
//   - ReceivedAt: the panel's own clock when the result arrived, made
//     strictly increasing by Snapshot.Stamp. Cooldowns and freshness use
//     only this, so a reporter cannot backdate the 30-minute return
//     cooldown.
//
// Validity window. A result is rejected as RejectFuture when ObservedAt is
// more than MaxClockSkew after ReceivedAt, and as RejectStale when it is
// more than MaxReportAge before it. MaxReportAge covers the longest
// scheduled probe run (the exit oneshot is bounded at 55 minutes).
//
// Ordering per (service, exit, family). The newest ObservedAt wins:
//
//   - an older ObservedAt than the newest admitted one is RejectOutOfOrder,
//     so a late success cannot overwrite a newer failure;
//   - an equal ObservedAt is RejectDuplicate (a replay of the same probe),
//     except that a failure replaces a success at the same instant
//     (failure wins ties).
//
// One state-machine step per (service, exit) and probe run. After the
// per-family admission, the verdict of the observation is the OR of its
// admitted families (either family unlocking in the exit's own region is
// enough, as in ParseRegionCheckFor). Advance is called only when the
// observation is newer than the last run already applied for that service
// and exit, across all families, or when it is a failure at exactly the
// same instant as an applied success. A v6 result from an earlier run can
// therefore not undo a newer v4 failure. Deliver all families of one run in
// one Observation; a family of an already-applied run that arrives later is
// recorded in Latest but does not step the state again.
//
// Concurrency. Ingest is a pure function of the snapshot. The caller must
// hold a single writer lock around load → Ingest → save (the API uses
// Server.mu). Because admission depends on ObservedAt and not on arrival
// order, probes that run concurrently and deliver in any order end in the
// same state as if they had arrived in ObservedAt order, except that a
// result older than one already applied is recorded as rejected instead of
// being replayed underneath it.

import (
	"sort"
	"strings"
	"time"
)

const (
	// MaxReportAge is the oldest ObservedAt (relative to receipt) accepted.
	MaxReportAge = time.Hour
	// MaxClockSkew is how far ObservedAt may be ahead of the panel clock.
	MaxClockSkew = 2 * time.Minute
)

// Family is the address family a result was measured on.
type Family string

const (
	FamilyAny  Family = "any"
	FamilyIPv4 Family = "ipv4"
	FamilyIPv6 Family = "ipv6"
)

// ParseFamily accepts "", any, 4, v4, ipv4, 6, v6, ipv6 (any case).
func ParseFamily(s string) (Family, bool) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "any":
		return FamilyAny, true
	case "4", "v4", "ipv4", "inet":
		return FamilyIPv4, true
	case "6", "v6", "ipv6", "inet6":
		return FamilyIPv6, true
	default:
		return "", false
	}
}

// Rejection reasons recorded in HistoryEntry.Rejected and Outcome.Rejected.
const (
	RejectStale      = "stale"
	RejectFuture     = "future"
	RejectOutOfOrder = "out_of_order"
	RejectDuplicate  = "duplicate"
	// RejectSuperseded: admitted for its family, but the state already holds
	// an equal-or-newer run for this exit, so the state was not stepped.
	RejectSuperseded = "superseded"
)

// ResultKey identifies one stream of results.
type ResultKey struct {
	Service string
	ExitID  string
	Family  Family
}

func (k ResultKey) String() string {
	return k.Service + "|" + k.ExitID + "|" + string(k.Family)
}

func exitKey(service, exit string) string { return service + "|" + exit }

// ResultRecord is the newest admitted result for a key.
type ResultRecord struct {
	OK         bool      `json:"ok"`
	Kind       Kind      `json:"kind"`
	ObservedAt time.Time `json:"observed_at"`
	ReceivedAt time.Time `json:"received_at"`
}

// Fresh reports whether the record was received within ResultFreshFor of now.
func (r ResultRecord) Fresh(now time.Time) bool {
	return !r.ReceivedAt.IsZero() && !now.Before(r.ReceivedAt) && now.Sub(r.ReceivedAt) <= ResultFreshFor
}

// Stamp returns a panel receive time that is strictly after every earlier
// one, even if the wall clock stepped back or two reports share a tick.
func (snap *Snapshot) Stamp(now time.Time) time.Time {
	now = now.UTC().Round(0)
	if !now.After(snap.Clock) {
		now = snap.Clock.Add(time.Microsecond)
	}
	snap.Clock = now
	return now
}

// Observation is one probe run of one service on one exit. Results holds
// one verdict per measured family (FamilyAny when the probe did not say).
type Observation struct {
	Service    string
	ExitID     string
	Kind       Kind
	ObservedAt time.Time // zero: use the receive time
	Results    map[Family]bool
}

// Outcome is what happened to one family result.
type Outcome struct {
	Service  string `json:"service"`
	ExitID   string `json:"exit_id"`
	Family   Family `json:"family"`
	OK       bool   `json:"ok"`
	Accepted bool   `json:"accepted"`
	Rejected string `json:"rejected,omitempty"`
	Note     string `json:"note,omitempty"`
}

// Ingest admits one observation and, when it is the newest run for its
// service and exit, steps the state machine once. members is the service's
// pool in preference order. A non-empty note records the results without
// admitting them (pinned rule, exit outside the pool). now is the panel
// clock; the caller must hold the snapshot's writer lock.
func Ingest(snap *Snapshot, ob Observation, members []string, note string, now time.Time) []Outcome {
	return IngestWith(snap, ob, members, note, now, Policy{})
}

// IngestWith is Ingest under a policy (result lifetime). Admission is
// exactly the same; the policy only changes which earlier results the
// state machine still counts as evidence when it steps.
func IngestWith(snap *Snapshot, ob Observation, members []string, note string, now time.Time, pol Policy) []Outcome {
	if snap.Services == nil {
		snap.Services = map[string]State{}
	}
	if snap.Latest == nil {
		snap.Latest = map[string]ResultRecord{}
	}
	received := snap.Stamp(now)
	observed := ob.ObservedAt.UTC().Round(0)
	if ob.ObservedAt.IsZero() {
		observed = received
	}
	fams := make([]Family, 0, len(ob.Results))
	for f := range ob.Results {
		fams = append(fams, f)
	}
	sort.Slice(fams, func(i, j int) bool { return fams[i] < fams[j] })

	var out []Outcome
	record := func(f Family, ok bool, rejected, n string) {
		out = append(out, Outcome{Service: ob.Service, ExitID: ob.ExitID, Family: f, OK: ok, Accepted: rejected == "" && n == "", Rejected: rejected, Note: n})
		snap.addHistory(HistoryEntry{
			At: received, ObservedAt: observed, Kind: ob.Kind, Service: ob.Service,
			ExitID: ob.ExitID, Family: f, OK: ok, Rejected: rejected, Note: n,
		})
	}

	if note != "" {
		for _, f := range fams {
			record(f, ob.Results[f], "", note)
		}
		return out
	}
	window := ""
	switch {
	case observed.After(received.Add(MaxClockSkew)):
		window = RejectFuture
	case received.Sub(observed) > MaxReportAge:
		window = RejectStale
	}

	var admitted []Family
	verdict := false
	for _, f := range fams {
		ok := ob.Results[f]
		reason := window
		if reason == "" {
			reason = admit(snap, ResultKey{ob.Service, ob.ExitID, f}, ok, ob.Kind, observed, received)
		}
		if reason != "" {
			record(f, ok, reason, "")
			continue
		}
		admitted = append(admitted, f)
		verdict = verdict || ok
	}
	if len(admitted) == 0 {
		return out
	}
	names := make([]string, len(admitted))
	for i, f := range admitted {
		names[i] = string(f)
	}
	fam := Family(strings.Join(names, "+"))

	if snap.Applied == nil {
		snap.Applied = map[string]ResultRecord{}
	}
	ek := exitKey(ob.Service, ob.ExitID)
	last, seen := snap.Applied[ek]
	step := !seen || observed.After(last.ObservedAt) ||
		(observed.Equal(last.ObservedAt) && !verdict && last.OK)
	if !step {
		// The family results stay in Latest; the outcome says why the
		// state did not move.
		for _, f := range admitted {
			record(f, ob.Results[f], RejectSuperseded, "")
		}
		return out
	}
	snap.Applied[ek] = ResultRecord{OK: verdict, Kind: ob.Kind, ObservedAt: observed, ReceivedAt: received}
	ev := Event{
		Service: ob.Service, ExitID: ob.ExitID, Family: fam, OK: verdict,
		Kind: ob.Kind, At: received, ObservedAt: observed,
	}
	ApplyWith(snap, ev, members, "", pol)
	for _, f := range admitted {
		out = append(out, Outcome{Service: ob.Service, ExitID: ob.ExitID, Family: f, OK: ob.Results[f], Accepted: true})
	}
	return out
}

// admit applies the per-key ordering rule and records an accepted result.
func admit(snap *Snapshot, key ResultKey, ok bool, kind Kind, observed, received time.Time) string {
	k := key.String()
	if last, seen := snap.Latest[k]; seen {
		switch {
		case observed.Before(last.ObservedAt):
			return RejectOutOfOrder
		case observed.Equal(last.ObservedAt) && !(last.OK && !ok):
			return RejectDuplicate
		}
	}
	snap.Latest[k] = ResultRecord{OK: ok, Kind: kind, ObservedAt: observed, ReceivedAt: received}
	return ""
}

// ReferencedExits lists, sorted, every exit id the snapshot mentions: in
// the admitted results (Latest, Applied), the history and the services'
// active and preferred members. The panel uses it to mark records of exits
// that no longer exist in the topology (see RemovedExits).
//
// Nothing here changes admission: Latest and Applied keep their entries
// for removed exits, so an old result replayed for an exit id that comes
// back cannot slip in underneath a newer one.
func ReferencedExits(snap Snapshot) []string {
	set := map[string]bool{}
	add := func(id string) {
		if id != "" {
			set[id] = true
		}
	}
	for k := range snap.Latest {
		parts := strings.SplitN(k, "|", 3)
		if len(parts) >= 2 {
			add(parts[1])
		}
	}
	for k := range snap.Applied {
		if _, exit, ok := strings.Cut(k, "|"); ok {
			add(exit)
		}
	}
	for _, h := range snap.History {
		add(h.ExitID)
	}
	for _, st := range snap.Services {
		add(st.Active)
		add(st.Preferred)
	}
	out := make([]string, 0, len(set))
	for id := range set {
		out = append(out, id)
	}
	sort.Strings(out)
	return out
}

// RemovedExits is ReferencedExits minus the exits that still exist.
func RemovedExits(snap Snapshot, exists func(string) bool) []string {
	out := []string{}
	for _, id := range ReferencedExits(snap) {
		if !exists(id) {
			out = append(out, id)
		}
	}
	return out
}
