package sniff

import (
	"sort"
	"sync"
	"time"
)

// Per-target outcome counters: how the forwarder's connections to each
// target ended (ok, name resolution failed, upstream connect failed, relay
// failed or no response after the connect), since start and over the last
// StatsWindow in one-minute buckets. Each connection is counted once, by
// its final record (Server.finish), in the minute it ended. Bounded:
// one entry per target of the current target file (entries of targets that
// left the file are dropped at the next install), at most maxStatTargets.

// StatsWindow is the span of the "recent" counts.
const (
	StatsWindow    = 15 * time.Minute
	statBuckets    = 15
	maxStatTargets = 256
)

// TargetStat is one target's counters (Health.TargetStats).
type TargetStat struct {
	Target        string `json:"target"`
	OK            uint64 `json:"ok"`
	ResolveFailed uint64 `json:"resolve_failed"`
	DialFailed    uint64 `json:"dial_failed"`
	// RelayFailed: connected, then the upstream reset or failed, or nothing
	// came back (results relay_failed and no_response).
	RelayFailed         uint64     `json:"relay_failed"`
	RecentOK            uint64     `json:"recent_ok"`
	RecentResolveFailed uint64     `json:"recent_resolve_failed"`
	RecentDialFailed    uint64     `json:"recent_dial_failed"`
	RecentRelayFailed   uint64     `json:"recent_relay_failed"`
	LastFailureAt       *time.Time `json:"last_failure_at,omitempty"`
	LastFailure         string     `json:"last_failure,omitempty"`
}

type statKind int

const (
	statOK statKind = iota
	statResolve
	statDial
	statRelay
	statKinds
)

type statBucket struct {
	minute int64
	n      [statKinds]uint64
}

type targetStat struct {
	total   [statKinds]uint64
	buckets [statBuckets]statBucket
	lastAt  time.Time
	last    string
}

type targetStats struct {
	mu sync.Mutex
	m  map[string]*targetStat
}

func (ts *targetStats) add(target string, k statKind, at time.Time, detail string) {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	if ts.m == nil {
		ts.m = map[string]*targetStat{}
	}
	e := ts.m[target]
	if e == nil {
		if len(ts.m) >= maxStatTargets {
			return
		}
		e = &targetStat{}
		ts.m[target] = e
	}
	e.total[k]++
	min := at.Unix() / 60
	b := &e.buckets[min%statBuckets]
	if b.minute < min {
		*b = statBucket{minute: min}
	}
	if b.minute == min { // an older record than the bucket's minute counts in the totals only
		b.n[k]++
	}
	if k != statOK && !at.Before(e.lastAt) {
		e.lastAt, e.last = at, detail
	}
}

// keep drops the entries of targets not in names.
func (ts *targetStats) keep(names map[string]bool) {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	for n := range ts.m {
		if !names[n] {
			delete(ts.m, n)
		}
	}
}

func (ts *targetStats) snapshot(now time.Time) []TargetStat {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	cur := now.Unix() / 60
	out := make([]TargetStat, 0, len(ts.m))
	for n, e := range ts.m {
		s := TargetStat{Target: n, OK: e.total[statOK], ResolveFailed: e.total[statResolve], DialFailed: e.total[statDial],
			RelayFailed: e.total[statRelay], LastFailure: e.last}
		for _, b := range e.buckets {
			if b.minute > cur-statBuckets && b.minute <= cur {
				s.RecentOK += b.n[statOK]
				s.RecentResolveFailed += b.n[statResolve]
				s.RecentDialFailed += b.n[statDial]
				s.RecentRelayFailed += b.n[statRelay]
			}
		}
		if !e.lastAt.IsZero() {
			t := e.lastAt
			s.LastFailureAt = &t
		}
		out = append(out, s)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Target < out[j].Target })
	return out
}
