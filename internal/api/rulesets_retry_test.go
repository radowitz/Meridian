package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/radowitz/meridian/internal/model"
)

func TestDueRuleSetsBackoff(t *testing.T) {
	now := time.Date(2026, 1, 2, 12, 0, 0, 0, time.UTC)
	at := func(ago time.Duration) string { return now.Add(-ago).Format(time.RFC3339) }
	tp := model.Topology{RuleSets: []model.RuleSet{{ID: "a", IntervalSec: 86400}}}
	cases := []struct {
		name string
		st   *RuleSetStatus
		due  bool
	}{
		{"never tried", nil, true},
		{"ok recently", &RuleSetStatus{State: "ok", LastAttempt: at(time.Hour)}, false},
		{"ok after interval", &RuleSetStatus{State: "ok", LastAttempt: at(25 * time.Hour)}, true},
		{"1st failure before 5m", &RuleSetStatus{State: "ok", LastError: "x", Failures: 1, LastAttempt: at(4 * time.Minute)}, false},
		{"1st failure after 5m", &RuleSetStatus{State: "ok", LastError: "x", Failures: 1, LastAttempt: at(5 * time.Minute)}, true},
		{"2nd failure at 10m", &RuleSetStatus{State: "ok", LastError: "x", Failures: 2, LastAttempt: at(10 * time.Minute)}, false},
		{"2nd failure at 15m", &RuleSetStatus{State: "ok", LastError: "x", Failures: 2, LastAttempt: at(15 * time.Minute)}, true},
		{"3rd failure at 59m", &RuleSetStatus{State: "ok", LastError: "x", Failures: 3, LastAttempt: at(59 * time.Minute)}, false},
		{"3rd failure at 1h", &RuleSetStatus{State: "ok", LastError: "x", Failures: 3, LastAttempt: at(time.Hour)}, true},
		{"capped: 4th failure waits the interval", &RuleSetStatus{State: "failed", LastError: "x", Failures: 4, LastAttempt: at(2 * time.Hour)}, false},
		{"capped after interval", &RuleSetStatus{State: "failed", LastError: "x", Failures: 9, LastAttempt: at(24 * time.Hour)}, true},
		{"legacy failure without count", &RuleSetStatus{State: "ok", LastError: "x", LastAttempt: at(time.Hour)}, false},
	}
	for _, c := range cases {
		st := map[string]*RuleSetStatus{}
		if c.st != nil {
			st["a"] = c.st
		}
		if got := len(dueRuleSets(tp, st, now)) == 1; got != c.due {
			t.Errorf("%s: due=%v, want %v", c.name, got, c.due)
		}
	}
	// A short interval is never stretched by the backoff.
	short := model.Topology{RuleSets: []model.RuleSet{{ID: "a", IntervalSec: 120}}}
	st := map[string]*RuleSetStatus{"a": {LastError: "x", Failures: 1, LastAttempt: at(2 * time.Minute)}}
	if len(dueRuleSets(short, st, now)) != 1 {
		t.Error("interval shorter than backoff: want due")
	}
}

// flakyFetch fails with a local EPERM for the first n calls.
type flakyFetch struct {
	mu   sync.Mutex
	n    int
	perm bool
	body string
}

func (f *flakyFetch) Get(ctx context.Context, url string) ([]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.perm {
		return nil, errors.New("HTTP 404")
	}
	if f.n > 0 {
		f.n--
		return nil, errors.New("dial tcp: lookup cdn.example.org on 192.0.2.1:53: write udp 192.0.2.2:40000->192.0.2.1:53: write: operation not permitted")
	}
	return []byte(f.body), nil
}

func addRuleSets(t *testing.T, s *Server, ids ...string) {
	t.Helper()
	if _, err := s.Store.Update(func(tp *model.Topology) (bool, error) {
		for _, id := range ids {
			tp.RuleSets = append(tp.RuleSets, model.RuleSet{ID: id, Name: id, URL: "https://rules.example.org/" + id + ".list", Source: "url"})
		}
		return true, nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestFetchRetriesTransientEPERM(t *testing.T) {
	old := transientRetryDelay
	transientRetryDelay = time.Millisecond
	defer func() { transientRetryDelay = old }()
	s, _ := importServer(t)
	f := &flakyFetch{n: 2, body: "DOMAIN-SUFFIX,a.example.net\n"}
	s.RuleSetFetch = func(RuleSetFetchOptions) RuleSetFetcher { return f }
	addRuleSets(t, s, "flaky")
	tp, _ := s.topology()
	rs, _ := tp.RuleSetByID("flaky")
	s.startFetch(tp, rs, true)
	st := s.loadRSStatus()["flaky"]
	if st == nil || st.State != "ok" || st.LastError != "" || st.Failures != 0 {
		t.Fatalf("EPERM then success: %+v", st)
	}

	// A permanent error is not retried in place and counts a failure.
	f.mu.Lock()
	f.perm = true
	f.mu.Unlock()
	s.startFetch(tp, rs, true)
	s.startFetch(tp, rs, true)
	st = s.loadRSStatus()["flaky"]
	if st.State != "ok" || st.LastError == "" || st.Failures != 2 {
		t.Fatalf("permanent failure keeps the old version and counts: %+v", st)
	}
	// Success resets the count.
	f.mu.Lock()
	f.perm = false
	f.mu.Unlock()
	s.startFetch(tp, rs, true)
	if st = s.loadRSStatus()["flaky"]; st.Failures != 0 || st.LastError != "" {
		t.Fatalf("success resets: %+v", st)
	}
}

func TestUpdateAllRuleSets(t *testing.T) {
	s, f := importServer(t)
	ids := []string{"r1", "r2", "r3", "r4", "r5", "r6"}
	addRuleSets(t, s, ids...)
	f.mu.Lock()
	for _, id := range ids[:5] {
		f.body["https://rules.example.org/"+id+".list"] = "DOMAIN-SUFFIX," + id + ".example.net\n"
	}
	f.mu.Unlock()
	rr := do(s, http.MethodPost, "/api/rule-sets/update-all", nil)
	if rr.Code != http.StatusAccepted {
		t.Fatalf("update-all: %d %s", rr.Code, rr.Body.String())
	}
	deadline := time.Now().Add(30 * time.Second)
	var got struct{ Job *rsBulkJob }
	for {
		rr = do(s, http.MethodGet, "/api/rule-sets/update-all", nil)
		_ = json.Unmarshal(rr.Body.Bytes(), &got)
		if got.Job != nil && got.Job.State == "done" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("job not done: %s", rr.Body.String())
		}
		time.Sleep(20 * time.Millisecond)
	}
	if got.Job.Total != 6 || got.Job.Done != 6 || len(got.Job.Failed) != 1 || got.Job.Failed[0] != "r6" {
		t.Fatalf("job: %+v", got.Job)
	}
	for _, id := range ids[:5] {
		if st := s.loadRSStatus()[id]; st == nil || st.State != "ok" {
			t.Errorf("%s: %+v", id, st)
		}
	}
}
