package api

import (
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/radowitz/meridian/internal/model"
	"github.com/radowitz/meridian/internal/probe"
	"github.com/radowitz/meridian/internal/unlock"
)

// Rules on region group "us" (us, us-2), one per adapter (the rule ID is
// the adapter ID, as for the built-in auto-* rules). Fake prober only:
// nothing contacts a platform. The key is the first rule's ID.
func autoServiceServer(t *testing.T, f *fakeProber, probes ...string) (*Server, string) {
	t.Helper()
	s := probeServer(t, f)
	if _, err := s.Store.Update(func(tp *model.Topology) (bool, error) {
		var add []model.Rule
		for _, id := range probes {
			add = append(add, model.Rule{ID: id, Name: id, Enabled: true, Manual: true, MatchType: model.MatchSuffix, MatchValue: id + ".example.net", TargetGroup: "us"})
		}
		tp.Rules = append(add, tp.Rules...)
		tp.RulesOrdered = true
		return true, nil
	}); err != nil {
		t.Fatal(err)
	}
	return s, probes[0]
}

func scheduledRound(t *testing.T, s *Server) probeJob {
	t.Helper()
	forceDue(t, s)
	s.tickUnlock()
	if !s.waitProbeJob(10 * time.Second) {
		t.Fatal("job did not finish")
	}
	return getJobs(t, s).Jobs[0]
}

// An adapter nothing points at is shown only: it cannot be run without
// named exits, and its result is never ingested; nothing is created.
func TestUnownedAdapterShownOnly(t *testing.T) {
	s := probeServer(t, &fakeProber{})
	if rr := do(s, http.MethodPost, "/api/unlock/run", []byte(`{"services":["dazn"]}`)); rr.Code != http.StatusBadRequest {
		t.Fatalf("%d %s", rr.Code, rr.Body.String())
	}
	before, _ := s.topology()
	job := runJob(t, s, `{"services":["dazn"],"exits":["jp"],"families":["ipv4"]}`)
	if len(job.Items) != 1 || job.Items[0].Ingest != "not_ingested:no_owner" || len(job.Items[0].Owners) != 0 {
		t.Fatalf("%+v", job.Items)
	}
	after, _ := s.topology()
	if len(after.Rules) != len(before.Rules) {
		t.Fatal("a probe result created a rule")
	}
}

// The request budget trims a scheduled run per exit, by candidate
// priority, and says so on the skipped items.
func TestScheduledBudgetPerExit(t *testing.T) {
	s, _ := autoServiceServer(t, &fakeProber{}, "fubotv", "youtube-premium")
	if _, err := s.Store.Update(func(tp *model.Topology) (bool, error) {
		tp.Settings.UnlockProbe = &model.UnlockProbeSettings{ExitRequestBudget: 6, ExitConcurrency: 1}
		return true, nil
	}); err != nil {
		t.Fatal(err)
	}
	job := scheduledRound(t, s)
	over := 0
	for _, it := range job.Items {
		if it.Ingest == "not_ingested:over_budget" {
			over++
		}
	}
	if over == 0 {
		t.Fatal("nothing trimmed with a budget of 6")
	}
	// Per exit and family: 2 egress checks + adapter steps ≤ 6 over both
	// families together.
	perExit := map[string]int{}
	for _, it := range job.Items {
		if it.State == itemDone {
			a, _ := probe.Lookup(it.Service)
			perExit[it.ExitID] += a.RequestCost()
		}
	}
	for exit, n := range perExit {
		if n+probe.TraceCost > 6 {
			t.Fatalf("exit %s spent %d requests", exit, n+probe.TraceCost)
		}
	}
}

// More services than the agent takes in one request are split, each part
// with its own egress checks; nothing is lost and nothing exceeds the limit.
func TestProbeSplitsAgentRequests(t *testing.T) {
	f := &fakeProber{}
	s := probeServer(t, f)
	var ids []string
	for _, a := range probe.Catalog {
		ids = append(ids, a.Service)
	}
	if len(ids) <= agentMaxServices {
		t.Skip("catalog fits in one request")
	}
	body, _ := json.Marshal(map[string]any{"services": ids, "exits": []string{"us"}, "families": []string{"ipv4"}})
	job := runJob(t, s, string(body))
	if len(job.Items) != len(ids) {
		t.Fatalf("%d items for %d services", len(job.Items), len(ids))
	}
	for _, it := range job.Items {
		if it.Category == probe.CatFailed {
			t.Fatalf("item failed: %+v", it)
		}
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.reqs) < 2 {
		t.Fatalf("%d agent requests", len(f.reqs))
	}
	for _, r := range f.reqs {
		if len(r.Services) > agentMaxServices {
			t.Fatalf("request with %d services", len(r.Services))
		}
	}
}

func TestRoutingRecentResultsStayDistinctFromKnownEvidence(t *testing.T) {
	s, id := autoServiceServer(t, &fakeProber{}, "fubotv")
	tp, _ := s.topology()
	now := time.Now().UTC()
	at := now.Add(-time.Minute)
	doc := probeResultsDoc{Items: map[string]probeJobItem{
		"fubotv|us|ipv4":   {Service: "fubotv", ExitID: "us", Family: unlock.FamilyIPv4, Category: probe.CatFailed, FinishedAt: &at},
		"fubotv|us-2|ipv4": {Service: "fubotv", ExitID: "us-2", Family: unlock.FamilyIPv4, Category: probe.CatNetworkOK, FinishedAt: &at},
	}}
	views := routingView(tp, unlock.Snapshot{}, now, doc)
	for _, v := range views {
		if v.Key == id {
			if len(v.Candidates) != 2 {
				t.Fatalf("candidates: %+v", v)
			}
			for _, c := range v.Candidates {
				if len(c.Recent) != 1 || c.Recent[0].Expired || !c.Recent[0].At.Equal(at) {
					t.Fatalf("recent: %+v", c)
				}
				want := probe.CatFailed
				if c.ExitID == "us-2" {
					want = probe.CatNetworkOK
				}
				if c.Recent[0].Category != want || c.Evidence != "" {
					t.Fatalf("non-verdict confused with evidence: %+v", c)
				}
			}
			return
		}
	}
	t.Fatal("rule missing")
}
