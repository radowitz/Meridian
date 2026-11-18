package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/radowitz/meridian/internal/hostexec"
	"github.com/radowitz/meridian/internal/model"
	"github.com/radowitz/meridian/internal/ordered"
	"github.com/radowitz/meridian/internal/ruleset"
	"github.com/radowitz/meridian/internal/sniff"
)

// healthyStatus: an active forwarder whose current self-check passed.
func healthyStatus(t *testing.T, defaultStatus string) hostexec.SniffStatus {
	t.Helper()
	now := time.Now()
	h := sniff.Health{Ready: true, TargetsSHA256: "abc", Targets: []string{"direct"}, SelfCheck: &sniff.SelfCheck{
		Version: sniff.SelfCheckVersion, StartedAt: now, FinishedAt: now, TargetsSHA256: "abc", Default: "direct", OK: defaultStatus != sniff.TargetFailed,
		Targets: []sniff.SelfCheckTarget{{Target: "direct", Default: true, Status: defaultStatus}}}}
	b, err := json.Marshal(h)
	if err != nil {
		t.Fatal(err)
	}
	return hostexec.SniffStatus{Present: true, Active: "active", Health: b, ReadAt: now.Format(time.RFC3339), TargetsSHA256: "abc"}
}

func setSniff(t *testing.T, s *Server, on bool) {
	t.Helper()
	if _, err := s.Store.Update(func(tp *model.Topology) (bool, error) {
		tp.Settings.Sniff = &model.SniffSettings{Enabled: on}
		return true, nil
	}); err != nil {
		t.Fatal(err)
	}
}

// The three states: off; on only when installed with the current settings
// AND the forwarder runs with usable paths; everything else (including an
// unreadable runtime or install state) is pending, never on.
func TestKeywordState(t *testing.T) {
	s, _ := importServer(t)
	tp, _ := s.topology()
	if got := s.keywordState(context.Background(), tp); got != ordered.KeywordSniffOff {
		t.Fatalf("off: %s", got)
	}
	setSniff(t, s, true)
	tp, _ = s.topology()
	yes, no := func(model.Topology) bool { return true }, func(model.Topology) bool { return false }
	cases := []struct {
		name string
		sync func(model.Topology) bool
		rt   SniffRuntime
		want string
	}{
		{"healthy", yes, fakeSniffRT{st: healthyStatus(t, sniff.TargetOK)}, ordered.KeywordSniffOn},
		{"not installed with current settings", no, fakeSniffRT{st: healthyStatus(t, sniff.TargetOK)}, ordered.KeywordSniffPending},
		{"not running", yes, fakeSniffRT{st: hostexec.SniffStatus{}}, ordered.KeywordSniffPending},
		{"stopped unit", yes, fakeSniffRT{st: func() hostexec.SniffStatus { x := healthyStatus(t, sniff.TargetOK); x.Active = "failed"; return x }()}, ordered.KeywordSniffPending},
		{"paths failing", yes, fakeSniffRT{st: healthyStatus(t, sniff.TargetFailed)}, ordered.KeywordSniffPending},
		{"paths unchecked", yes, fakeSniffRT{st: hostexec.SniffStatus{Present: true, Active: "active", Health: json.RawMessage(`{"ready":true}`)}}, ordered.KeywordSniffPending},
		{"runtime unreadable", yes, fakeSniffRT{err: errors.New("boom")}, ordered.KeywordSniffPending},
		{"no host agent", yes, nil, ordered.KeywordSniffPending},
	}
	for _, c := range cases {
		s.kw.reset()
		s.gatewayInSync, s.Sniff = c.sync, c.rt
		if c.rt == nil {
			s.Sniff = nil
		}
		if got := s.keywordState(context.Background(), tp); got != c.want {
			t.Errorf("%s: %s, want %s", c.name, got, c.want)
		}
	}
}

// states drives the server into each state.
func states(t *testing.T, s *Server) map[string]func() {
	// Every switch starts from an empty cache.
	wrap := func(f func()) func() { return func() { s.kw.reset(); f() } }
	m := statesRaw(t, s)
	for k, f := range m {
		m[k] = wrap(f)
	}
	return m
}

func statesRaw(t *testing.T, s *Server) map[string]func() {
	return map[string]func(){
		ordered.KeywordSniffOff: func() { setSniff(t, s, false) },
		ordered.KeywordSniffOn: func() {
			setSniff(t, s, true)
			s.gatewayInSync, s.Sniff = func(model.Topology) bool { return true }, fakeSniffRT{st: healthyStatus(t, sniff.TargetOK)}
		},
		ordered.KeywordSniffPending: func() {
			setSniff(t, s, true)
			s.gatewayInSync, s.Sniff = func(model.Topology) bool { return false }, nil
		},
	}
}

// The rule list's note, the drawer's (top-level) note and the rule-set
// row's note all follow the state, from the one wording.
func TestKeywordNoteInAnalysis(t *testing.T) {
	s, _ := importServer(t)
	s.Store.Update(func(tp *model.Topology) (bool, error) {
		tp.Rules = append([]model.Rule{{ID: "kw", Name: "kw", Enabled: true, Manual: true, MatchType: model.MatchKeyword, MatchValue: "vendor", TargetGroup: "jp"}}, tp.Rules...)
		return true, nil
	})
	for state, set := range states(t, s) {
		set()
		var out struct {
			State string   `json:"keyword_state"`
			Note  string   `json:"keyword_note"`
			Notes []string `json:"notes"`
			Rules []struct {
				ID   string `json:"rule_id"`
				Note string `json:"keyword_note"`
			} `json:"rules"`
		}
		rr := do(s, http.MethodGet, "/api/rules/analysis", nil)
		if rr.Code != 200 || json.Unmarshal(rr.Body.Bytes(), &out) != nil {
			t.Fatal(rr.Body.String())
		}
		want := ordered.KeywordNote(state)
		if out.State != state || out.Note != want {
			t.Fatalf("%s: %+v", state, out)
		}
		if n := strings.Join(out.Notes, "\n"); !strings.Contains(n, "关键词规则「kw」："+want) {
			t.Fatalf("%s: list notes %q", state, n)
		}
		found := false
		for _, r := range out.Rules {
			if r.ID == "kw" {
				found = true
				if r.Note != want {
					t.Fatalf("%s: rule note %q", state, r.Note)
				}
			}
		}
		if !found {
			t.Fatal("no kw row")
		}
	}
}

// The three texts say what the state allows and never more.
func TestKeywordNoteWording(t *testing.T) {
	off, on, pend := ordered.KeywordNote(ordered.KeywordSniffOff), ordered.KeywordNote(ordered.KeywordSniffOn), ordered.KeywordNote(ordered.KeywordSniffPending)
	if !strings.Contains(off, "SmartDNS 不能按子串匹配") || strings.Contains(off, "嗅探") {
		t.Fatal(off)
	}
	if !strings.Contains(on, "按子串匹配") || !strings.Contains(on, "UDP") || !strings.Contains(on, "读不到名字") || !strings.Contains(on, "近似") {
		t.Fatal(on)
	}
	if !strings.Contains(pend, "安装并正常运行后") || !strings.Contains(pend, "现在仍") || !strings.Contains(pend, "近似") {
		t.Fatal(pend)
	}
	if ordered.KeywordNote("") != off || ordered.KeywordNote("bogus") != off {
		t.Fatal("unknown state must read as off")
	}
	for _, st := range []string{"", ordered.KeywordSniffOn, ordered.KeywordSniffPending} {
		if n := ordered.KeywordEntriesNote(3, st); !strings.HasPrefix(n, ordered.KeywordEntriesPrefix(3)) || !strings.Contains(n, "不执行") {
			t.Fatal(n)
		}
	}
}

// A stored rule-set preview note (written with sniffing off) is shown for
// the current state, in each state.
func TestKeywordNoteInRuleSetView(t *testing.T) {
	s, _ := importServer(t)
	s.Store.Update(func(tp *model.Topology) (bool, error) {
		tp.RuleSets = []model.RuleSet{{ID: "rs1", Name: "rs1", URL: "https://rules.example.org/p.list"}}
		return true, nil
	})
	if err := s.activateContent("rs1", []byte("DOMAIN-KEYWORD,adword\n"), "surge-list", map[string]int{"keyword": 1},
		nil, []string{ordered.KeywordEntriesNote(1, ordered.KeywordSniffOff), "另一条说明"}, "test", ""); err != nil {
		t.Fatal(err)
	}
	for state, set := range states(t, s) {
		set()
		tp, _ := s.topology()
		v := s.ruleSetView(s.lazyKeywordState(context.Background(), tp), tp, tp.RuleSets[0], s.loadRSStatus())
		st := v["status"].(*RuleSetStatus)
		if len(st.Notes) != 2 || st.Notes[0] != ordered.KeywordEntriesNote(1, state) || st.Notes[1] != "另一条说明" {
			t.Fatalf("%s: %v", state, st.Notes)
		}
	}
}

// The import analysis (flags and the address note) follows the state.
func TestKeywordNoteInImportPreview(t *testing.T) {
	s, f := importServer(t)
	for state, set := range states(t, s) {
		set()
		// Under f.mu: a background prefetch of the previous round may read.
		f.mu.Lock()
		f.body["https://rules.example.org/ads.list"] = "DOMAIN-SUFFIX,ads.example.net\nDOMAIN-KEYWORD,adword\n"
		f.mu.Unlock()
		cfg := strings.Replace(importConfig, "  - MATCH,Others", "  - DOMAIN-KEYWORD,vendor,AI\n  - MATCH,Others", 1)
		rr := do(s, http.MethodPost, "/api/rules/import/preview", importReq(map[string]any{"config": cfg, "fetch_rule_sets": true}))
		if rr.Code != 200 {
			t.Fatal(rr.Body.String())
		}
		body := rr.Body.String()
		// The keyword row's flag (the rule-set flag: mihomo.TestKeywordNotesFollowState).
		if !strings.Contains(body, ordered.KeywordNote(state)) {
			t.Fatalf("%s: preview lacks the notes: %s", state, body)
		}
		for other := range states(t, s) {
			if other != state && (strings.Contains(body, ordered.KeywordNote(other))) {
				t.Fatalf("%s: preview carries the %s note", state, other)
			}
		}
	}
}

// A rule-set list with many keyword rule-sets evaluates the state once; the
// rules page's other requests reuse it within the cache's few seconds, and
// an edit of the topology evaluates again.
func TestKeywordStateEvaluatedOnce(t *testing.T) {
	s, _ := importServer(t)
	setSniff(t, s, true)
	var syncCalls, readCalls atomic.Int32
	s.gatewayInSync = func(model.Topology) bool { syncCalls.Add(1); return true }
	s.Sniff = countingSniff{fakeSniffRT{st: healthyStatus(t, sniff.TargetOK)}, &readCalls}
	s.kw.reset()
	if _, err := s.Store.Update(func(tp *model.Topology) (bool, error) {
		for i := 0; i < 40; i++ {
			id := "rs" + string(rune('a'+i/10)) + string(rune('0'+i%10))
			tp.RuleSets = append(tp.RuleSets, model.RuleSet{ID: id, Name: id, URL: "https://rules.example.org/" + id + ".list"})
		}
		return true, nil
	}); err != nil {
		t.Fatal(err)
	}
	tp, _ := s.topology()
	for _, rs := range tp.RuleSets {
		if err := s.activateContent(rs.ID, []byte("DOMAIN-KEYWORD,adword\n"), "surge-list", map[string]int{"keyword": 1}, nil,
			[]string{ordered.KeywordEntriesNote(1, ordered.KeywordSniffOff)}, "test", ""); err != nil {
			t.Fatal(err)
		}
	}
	rr := do(s, http.MethodGet, "/api/rule-sets", nil)
	if rr.Code != 200 || strings.Count(rr.Body.String(), ordered.KeywordEntriesNote(1, ordered.KeywordSniffOn)) != 40 {
		t.Fatalf("%d %.300s", rr.Code, rr.Body.String())
	}
	if syncCalls.Load() != 1 || readCalls.Load() != 1 {
		t.Fatalf("state evaluated %d times, agent read %d times for one list", syncCalls.Load(), readCalls.Load())
	}
	// The parallel requests of the page reuse it.
	do(s, http.MethodGet, "/api/rules/analysis", nil)
	do(s, http.MethodGet, "/api/rule-sets", nil)
	if syncCalls.Load() != 1 {
		t.Fatalf("cache not used: %d", syncCalls.Load())
	}
	// A topology change is a new key.
	s.Store.Update(func(tp *model.Topology) (bool, error) { tp.Settings.Sniff.Ports = []int{443}; return true, nil })
	do(s, http.MethodGet, "/api/rules/analysis", nil)
	if syncCalls.Load() != 2 {
		t.Fatalf("topology change did not re-evaluate: %d", syncCalls.Load())
	}
}

type countingSniff struct {
	fakeSniffRT
	n *atomic.Int32
}

func (c countingSniff) SniffStatus(ctx context.Context) (hostexec.SniffStatus, error) {
	c.n.Add(1)
	return c.fakeSniffRT.SniffStatus(ctx)
}

// hangingSniff never answers (and ignores its context).
type hangingSniff struct{ release chan struct{} }

func (h hangingSniff) SniffStatus(context.Context) (hostexec.SniffStatus, error) {
	<-h.release
	return hostexec.SniffStatus{}, nil
}

// A hanging host agent does not hold the rule list: the wait is bounded and
// the state falls back to pending.
func TestKeywordStateTimeoutFallsBackToPending(t *testing.T) {
	s, _ := importServer(t)
	setSniff(t, s, true)
	h := hangingSniff{release: make(chan struct{})}
	defer close(h.release)
	s.gatewayInSync, s.Sniff = func(model.Topology) bool { return true }, h
	old := kwRuntimeBudget
	kwRuntimeBudget = 50 * time.Millisecond
	defer func() { kwRuntimeBudget = old }()
	s.kw.reset()
	start := time.Now()
	rr := do(s, http.MethodGet, "/api/rules/analysis", nil)
	if d := time.Since(start); d > 2*time.Second {
		t.Fatalf("analysis waited %s for a hanging agent", d)
	}
	if rr.Code != 200 || !strings.Contains(rr.Body.String(), `"keyword_state":"pending"`) {
		t.Fatal(rr.Body.String())
	}
}

// The held-version reason follows the state like the other notes.
func TestKeywordHeldReasonFollowsState(t *testing.T) {
	s, _ := importServer(t)
	s.Store.Update(func(tp *model.Topology) (bool, error) {
		tp.RuleSets = []model.RuleSet{{ID: "rs1", Name: "rs1", URL: "https://rules.example.org/p.list"}}
		return true, nil
	})
	if err := s.activateContent("rs1", []byte("DOMAIN-SUFFIX,a.example.net\n"), "surge-list", map[string]int{"suffix": 1}, nil, nil, "test", ""); err != nil {
		t.Fatal(err)
	}
	s.updateRSStatus("rs1", func(st *RuleSetStatus) {
		st.State = "held"
		st.Held = &heldVersion{Digest: "d", Format: "surge-list", Counts: map[string]int{"keyword": 2}, Reason: lessExact(&RuleSetStatus{}, ruleset.Parsed{Counts: map[string]int{"keyword": 2}}, ordered.KeywordSniffOff)}
	})
	for state, set := range states(t, s) {
		set()
		tp, _ := s.topology()
		v := s.ruleSetView(s.lazyKeywordState(context.Background(), tp), tp, tp.RuleSets[0], s.loadRSStatus())
		if got, want := v["status"].(*RuleSetStatus).Held.Reason, keywordHeldReason(0, 2, state); got != want {
			t.Fatalf("%s: %q", state, got)
		}
	}
}
