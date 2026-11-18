package api

import (
	"encoding/json"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"time"
)

// Login lockout, per source address and kept across restarts.
//
// Every failed administrator login counts against its source: the IPv4
// address, or the /64 of an IPv6 address (one host can rotate through its
// whole /64). loginMaxFailures failures within loginFailWindow lock that
// source out for loginLockout; other sources are not affected. The state is
// kept in login-lockout.json (0600) in the data directory so a restart does
// not clear it. The file holds at most loginMaxSources entries; entries
// whose lock and failure window have both expired are dropped, and when
// the table is full the least recently seen source is evicted.

const (
	lockoutFile      = "login-lockout.json"
	loginFailWindow  = 15 * time.Minute
	loginMaxSources  = 256
	lockoutFileLimit = 64 << 10
)

type lockoutEntry struct {
	Failures    int       `json:"failures"`
	LastFailure time.Time `json:"last_failure"`
	LockedUntil time.Time `json:"locked_until,omitempty"`
}

// sourceKey: the lockout key for a request's RemoteAddr ("" when it cannot
// be parsed; those share one entry).
func sourceKey(remote string) string {
	host, _, err := net.SplitHostPort(remote)
	if err != nil {
		host = remote
	}
	ip, err := netip.ParseAddr(host)
	if err != nil {
		return ""
	}
	ip = ip.Unmap().WithZone("")
	if ip.Is6() {
		p, _ := ip.Prefix(64)
		return p.String()
	}
	return ip.String()
}

func (a *Auth) loadLockouts() {
	a.lockouts = map[string]lockoutEntry{}
	b, err := os.ReadFile(filepath.Join(a.dir, lockoutFile))
	if err != nil || len(b) > lockoutFileLimit {
		return
	}
	var m map[string]lockoutEntry
	if json.Unmarshal(b, &m) != nil {
		return
	}
	for k, v := range m {
		a.lockouts[k] = v
	}
	a.pruneLockouts()
}

// pruneLockouts drops expired entries and bounds the table. Caller holds mu.
func (a *Auth) pruneLockouts() {
	now := a.now()
	for k, v := range a.lockouts {
		if !now.Before(v.LockedUntil) && now.Sub(v.LastFailure) >= loginFailWindow {
			delete(a.lockouts, k)
		}
	}
	if len(a.lockouts) <= loginMaxSources {
		return
	}
	keys := make([]string, 0, len(a.lockouts))
	for k := range a.lockouts {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		return a.lockouts[keys[i]].LastFailure.Before(a.lockouts[keys[j]].LastFailure)
	})
	for _, k := range keys[:len(keys)-loginMaxSources] {
		delete(a.lockouts, k)
	}
}

// saveLockouts writes the table (best effort: a write error keeps the
// in-memory lockout working). Caller holds mu.
func (a *Auth) saveLockouts() {
	path := filepath.Join(a.dir, lockoutFile)
	if len(a.lockouts) == 0 {
		_ = os.Remove(path)
		return
	}
	_ = writeJSON0600(path, a.lockouts)
}

// lockedOut reports whether key is locked now. Caller holds mu.
func (a *Auth) lockedOut(key string) bool {
	e, ok := a.lockouts[key]
	return ok && a.now().Before(e.LockedUntil)
}

// recordFailure counts a failed login from key. Caller holds mu.
func (a *Auth) recordFailure(key string) {
	now := a.now()
	e := a.lockouts[key]
	if now.Sub(e.LastFailure) >= loginFailWindow {
		e.Failures = 0
	}
	e.Failures++
	e.LastFailure = now
	if e.Failures >= loginMaxFailures {
		e.Failures = 0
		e.LockedUntil = now.Add(loginLockout)
	}
	a.lockouts[key] = e
	a.pruneLockouts()
	a.saveLockouts()
}

// recordSuccess clears key's failures. Caller holds mu.
func (a *Auth) recordSuccess(key string) {
	if _, ok := a.lockouts[key]; ok {
		delete(a.lockouts, key)
		a.saveLockouts()
	}
}
