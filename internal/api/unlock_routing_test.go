package api

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/radowitz/meridian/internal/hostexec"
	"github.com/radowitz/meridian/internal/model"
	"github.com/radowitz/meridian/internal/probe"
	"github.com/radowitz/meridian/internal/unlock"
)

// A service group on region group "us" (us, us-2) with automatic selection
// driven by two adapters. Fake prober only: nothing contacts a platform.
func autoServiceServer(t *testing.T, f *fakeProber, probes ...string) (*Server, string) {
	t.Helper()
	s := probeServer(t, f)
	rr := do(s, http.MethodPost, "/api/service-groups", []byte(`{"name":"Video","target":"group:us"}`))
	if rr.Code != 201 {
		t.Fatal(rr.Body.String())
	}
	var created struct {
		ServiceGroup model.ServiceGroup `json:"service_group"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &created); err != nil {
		t.Fatal(err)
	}
	id := created.ServiceGroup.ID
	if _, err := s.Store.Update(func(tp *model.Topology) (bool, error) {
		tp.Rules = append([]model.Rule{{ID: "vid", Name: "video", Enabled: true, Manual: true, MatchType: model.MatchSuffix, MatchValue: "video.example.net", TargetService: id}}, tp.Rules...)
		tp.RulesOrdered = true
		return true, nil
	}); err != nil {
		t.Fatal(err)
	}
	body, _ := json.Marshal(map[string]any{"select": "auto", "probes": probes})
	if rr := do(s, http.MethodPatch, "/api/service-groups/"+id, body); rr.Code != 200 {
		t.Fatal(rr.Body.String())
	}
	return s, id
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

func TestServiceGroupAutoSwitchAndCombination(t *testing.T) {
	f := &fakeProber{answer: func(req hostexec.ProbeRequest, svc string) probe.Category {
		if a, _ := probe.Lookup(svc); a.Capability == probe.CapReachability {
			return probe.CatNetworkOK
		}
		if svc == "peacock" && req.ExitID == "us" {
			return probe.CatNotUnlocked // one of two adapters fails on the preferred
		}
		return probe.CatUnlocked
	}}
	s, id := autoServiceServer(t, f, "peacock", "youtube-premium")
	key := unlock.ServiceKey(id)

	job := scheduledRound(t, s)
	var seen bool
	for _, it := range job.Items {
		if it.Service == "peacock" && it.ExitID == "us" {
			seen = true
			if it.Ingest != "accepted" || it.IngestBy[key] != "accepted" || !containsStr(it.Owners, key) {
				t.Fatalf("item %+v", it)
			}
		}
		// Only candidates are probed for the service group's adapters.
		if (it.Service == "peacock" || it.Service == "youtube-premium") && it.ExitID != "us" && it.ExitID != "us-2" {
			t.Fatalf("probed a non-candidate exit: %+v", it)
		}
	}
	if !seen {
		t.Fatal("peacock was not probed on us")
	}
	states, _, dec := unlockView(t, s)
	if dec[key] != "" || states[key].SchedFails != 1 {
		t.Fatalf("one scheduled failure already moved it: %+v %v", states[key], dec)
	}
	scheduledRound(t, s)
	states, _, dec = unlockView(t, s)
	st := states[key]
	if dec[key] != "us-2" || st.SwitchReason != unlock.SwitchPreferredFailed || st.SwitchedAt.IsZero() {
		t.Fatalf("after two scheduled failures: %+v %v", st, dec)
	}
	// The decision reaches the compiled bundle (and only through it).
	tp, _ := s.topology()
	if _, err := s.compileTopo(tp); err != nil {
		t.Fatal(err)
	}
	if s.unlockDecisions(tp)[key] != "us-2" {
		t.Fatal("decision not in the compile input")
	}
	// The routing view: candidates with measured evidence, the computed
	// exit (inferred), the reason and time.
	rr := do(s, http.MethodGet, "/api/unlock", nil)
	var v struct {
		Owners   []ownerView    `json:"owners"`
		Schedule map[string]int `json:"schedule"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &v); err != nil {
		t.Fatal(err)
	}
	var ov *ownerView
	for i := range v.Owners {
		if v.Owners[i].Key == key {
			ov = &v.Owners[i]
		}
	}
	if ov == nil || ov.Mode != "auto" || ov.Active != "us-2" || ov.Default != "us" || !ov.Inferred || ov.Rules != 1 || ov.SwitchedAt == nil {
		t.Fatalf("owner view %+v", ov)
	}
	for _, c := range ov.Candidates {
		if (c.ExitID == "us" && c.Evidence != "failed") || (c.ExitID == "us-2" && c.Evidence != "ok") {
			t.Fatalf("candidate %+v", c)
		}
	}
	if v.Schedule["exit_request_budget"] != model.DefaultUnlockExitBudget || v.Schedule["result_ttl_sec"] != 12*3600 {
		t.Fatalf("schedule %v", v.Schedule)
	}

	// Fixed mode: the pin wins at once, the decision disappears.
	if rr := do(s, http.MethodPatch, "/api/service-groups/"+id, []byte(`{"select":""}`)); rr.Code != 200 {
		t.Fatal(rr.Body.String())
	}
	if _, _, dec = unlockView(t, s); dec[key] != "" {
		t.Fatalf("fixed service group still moved: %v", dec)
	}
}

func TestServiceGroupAllCandidatesFailStaysOnDefault(t *testing.T) {
	f := &fakeProber{answer: func(req hostexec.ProbeRequest, svc string) probe.Category {
		if svc == "peacock" {
			return probe.CatNotUnlocked
		}
		if a, _ := probe.Lookup(svc); a.Capability == probe.CapReachability {
			return probe.CatNetworkOK
		}
		return probe.CatUnlocked
	}}
	s, id := autoServiceServer(t, f, "peacock")
	key := unlock.ServiceKey(id)
	scheduledRound(t, s)
	scheduledRound(t, s)
	states, _, dec := unlockView(t, s)
	if dec[key] != "" || !states[key].Unavailable || states[key].Active != "us" {
		t.Fatalf("all failing: %+v %v", states[key], dec)
	}
	rr := do(s, http.MethodGet, "/api/unlock", nil)
	if !strings.Contains(rr.Body.String(), "留在默认出口") {
		t.Fatalf("no warning: %s", rr.Body.String())
	}
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
	if len(after.Rules) != len(before.Rules) || len(after.ServiceGroups) != len(before.ServiceGroups) {
		t.Fatal("a probe result created a rule or service group")
	}
}

// The request budget trims a scheduled run per exit, by candidate
// priority, and says so on the skipped items.
func TestScheduledBudgetPerExit(t *testing.T) {
	s, _ := autoServiceServer(t, &fakeProber{}, "peacock", "youtube-premium")
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

// One adapter is decided in one place: binding a built-in rule's adapter
// to an automatic service group while that rule is enabled is refused.
func TestAutoServiceGroupOwnerConflictRefused(t *testing.T) {
	s, id := autoServiceServer(t, &fakeProber{}, "peacock")
	rr := do(s, http.MethodPatch, "/api/service-groups/"+id, []byte(`{"probes":["auto-netflix"]}`))
	if rr.Code < 400 || !strings.Contains(rr.Body.String(), "unlock_owner_conflict") {
		t.Fatalf("%d %s", rr.Code, rr.Body.String())
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
