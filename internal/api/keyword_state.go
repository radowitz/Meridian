package api

import (
	"context"
	"encoding/json"
	"strconv"
	"sync"
	"time"

	"github.com/radowitz/meridian/internal/compile"
	"github.com/radowitz/meridian/internal/hostexec"
	"github.com/radowitz/meridian/internal/model"
	"github.com/radowitz/meridian/internal/ordered"
	"github.com/radowitz/meridian/internal/sniff"
)

// What a keyword rule matches depends on whether name sniffing is really in
// effect, not on the saved switch alone (wording: ordered.KeywordNote).
//
//	off      the switch is off.
//	on       saved on AND the gateway files match the saved topology (the
//	         install has the current sniff settings) AND the forwarder is
//	         active and ready with usable paths (diagnosis "usable" or
//	         "degraded": the default target works).
//	pending  saved on but anything else: not installed with the current
//	         settings, not running, paths failing or unchecked, or the
//	         install state or the runtime cannot be read. Unknown is never
//	         read as "on".
func (s *Server) keywordState(ctx context.Context, t model.Topology) string {
	if !t.SniffOn() {
		return ordered.KeywordSniffOff
	}
	key := s.keywordKey(t)
	if v, ok := s.kw.get(key); ok {
		return v
	}
	v := s.evalKeywordState(ctx, t)
	// A state read under a cancelled request says nothing; do not keep it.
	if ctx.Err() == nil {
		s.kw.put(key, v)
	}
	return v
}

// lazyKeywordState evaluates the state at most once for one request, and
// only if something asks for it.
func (s *Server) lazyKeywordState(ctx context.Context, t model.Topology) func() string {
	var once sync.Once
	var v string
	return func() string {
		once.Do(func() { v = s.keywordState(ctx, t) })
		return v
	}
}

// kwStateTTL is how long a computed state is reused (the rules page asks
// from several requests at once); the key changes with the topology and the
// installed manifest, so an edit or an install shows at once.
const kwStateTTL = 3 * time.Second

// kwRuntimeBudget bounds the host agent read: a slow agent never slows the
// rule list; the state is then pending.
var kwRuntimeBudget = 5 * time.Second

type kwCache struct {
	mu  sync.Mutex
	key string
	at  time.Time
	val string
}

func (c *kwCache) get(key string) (string, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.key == key && c.val != "" && time.Since(c.at) < kwStateTTL {
		return c.val, true
	}
	return "", false
}

func (c *kwCache) put(key, v string) {
	c.mu.Lock()
	c.key, c.val, c.at = key, v, time.Now()
	c.mu.Unlock()
}

func (c *kwCache) reset() {
	c.mu.Lock()
	c.key, c.val = "", ""
	c.mu.Unlock()
}

// keywordKey: the saved topology and the installed manifest.
func (s *Server) keywordKey(t model.Topology) string {
	k := topologyVersion(t)
	if inst, err := s.applier(true).Installed(); err == nil {
		k += "|" + strconv.FormatInt(inst.Version, 10) + "|" + inst.CreatedAt
	}
	return k
}

func (s *Server) evalKeywordState(ctx context.Context, t model.Topology) string {
	if !s.sniffInstalledCurrent(t) || !s.sniffRunningUsable(ctx) {
		return ordered.KeywordSniffPending
	}
	return ordered.KeywordSniffOn
}

// sniffInstalledCurrent: the installed gateway files equal what the saved
// topology compiles to.
func (s *Server) sniffInstalledCurrent(t model.Topology) bool {
	if s.gatewayInSync != nil {
		return s.gatewayInSync(t)
	}
	ap := s.applier(true)
	inst, err := ap.Installed()
	if err != nil {
		return false
	}
	return s.installState(ap, inst, func() (*compile.Bundle, error) { return s.compileTopo(t) }).State == "in_sync"
}

// sniffRunningUsable reads the forwarder through the host agent.
func (s *Server) sniffRunningUsable(ctx context.Context) bool {
	if s.Sniff == nil {
		return false
	}
	ctx, cancel := context.WithTimeout(ctx, kwRuntimeBudget)
	defer cancel()
	// The read runs aside so that an agent that ignores the context still
	// cannot hold the caller past the budget.
	type res struct {
		st  hostexec.SniffStatus
		err error
	}
	ch := make(chan res, 1)
	go func() {
		st, err := s.Sniff.SniffStatus(ctx)
		ch <- res{st, err}
	}()
	var st hostexec.SniffStatus
	var err error
	select {
	case r := <-ch:
		st, err = r.st, r.err
	case <-ctx.Done():
		return false
	}
	if err != nil || st.Error != "" || !st.Present || st.Active != "active" {
		return false
	}
	var h sniff.Health
	if len(st.Health) == 0 || json.Unmarshal(st.Health, &h) != nil || !h.Ready {
		return false
	}
	d := sniffDiagnose(st)
	return d != nil && (d.Paths == sniffPathsUsable || d.Paths == sniffPathsDegraded)
}
