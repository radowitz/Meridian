package api

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/radowitz/meridian/internal/hostexec"
	"github.com/radowitz/meridian/internal/probe"
	"github.com/radowitz/meridian/internal/unlock"
)

// N4: reachability-only and unknown results go through unlock.Ingest as
// inconclusive and can neither demote nor restore an exit, even when the
// agent claims more than the adapter declares.
func TestPanelProbeReachabilityAndUnknownNeverSwitch(t *testing.T) {
	f := &fakeProber{answer: func(req hostexec.ProbeRequest, svc string) probe.Category {
		switch svc {
		case "auto-perplexity":
			if req.ExitID == "us" {
				return probe.CatUnlocked // undeclared for a reachability adapter
			}
			return probe.CatNetworkOK
		case "auto-openai":
			if req.ExitID == "us" {
				return probe.CatUnknown // e.g. an anti-bot challenge
			}
			return probe.CatUnlocked
		}
		return probe.CatUnlocked
	}}
	s := probeServer(t, f)
	// Start demoted on us-2 for both services.
	s.mu.Lock()
	snap := s.loadUnlock()
	for _, id := range []string{"auto-perplexity", "auto-openai"} {
		snap.Services[id] = unlock.State{Pool: "us", Preferred: "us", Active: "us-2", Demoted: true, Known: map[string]bool{"us-2": true}}
	}
	if err := s.saveUnlock(snap); err != nil {
		t.Fatal(err)
	}
	s.mu.Unlock()
	for i := 0; i < 3; i++ {
		forceDue(t, s)
		s.tickUnlock()
		if !s.waitProbeJob(10 * time.Second) {
			t.Fatal("job did not finish")
		}
	}
	states, _, dec := unlockView(t, s)
	for _, id := range []string{"auto-perplexity", "auto-openai"} {
		st := states[id]
		if !st.Demoted || st.Active != "us-2" || !st.PreferredOKAt.IsZero() || st.Known["us"] || dec[id] != "us-2" {
			t.Fatalf("%s: a no-verdict result started recovery or switched: %+v %v", id, st, dec)
		}
	}
	job := getJobs(t, s).Jobs[0]
	for _, it := range job.Items {
		if it.Service == "auto-perplexity" && it.ExitID == "us" {
			if it.Category != probe.CatUnknown || it.Grade != probe.GradeUnknown || it.Ingest != "accepted:inconclusive" {
				t.Fatalf("undeclared unlock from a reachability adapter: %+v", it)
			}
		}
		if it.Service == "auto-perplexity" && it.ExitID == "us-2" && (it.Grade != probe.GradeReachability || it.Ingest != "accepted:inconclusive") {
			t.Fatalf("reachability must be inconclusive: %+v", it)
		}
		if it.Validation != probe.Validation {
			t.Fatalf("validation status missing: %+v", it)
		}
	}

	// Not demoted: three scheduled rounds of reachability on the preferred
	// never count as failures either.
	s2 := probeServer(t, &fakeProber{})
	for i := 0; i < 3; i++ {
		forceDue(t, s2)
		s2.tickUnlock()
		if !s2.waitProbeJob(10 * time.Second) {
			t.Fatal("job did not finish")
		}
	}
	states, _, _ = unlockView(t, s2)
	if st := states["auto-grok"]; st.SchedFails != 0 || st.Demoted || st.Unavailable {
		t.Fatalf("reachability counted as a scheduled failure: %+v", st)
	}
}

// wrongExitProber answers every request as if it came from another exit.
type wrongExitProber struct{ fakeProber }

func (w *wrongExitProber) Probe(ctx context.Context, req hostexec.ProbeRequest) (probe.Report, error) {
	rep, err := w.fakeProber.Probe(ctx, req)
	rep.ExitID = "us-2"
	return rep, err
}

func TestPanelProbeWrongExitReportIsNotAVerdict(t *testing.T) {
	s := newTest(t)
	s.Prober = &wrongExitProber{}
	do(s, http.MethodGet, "/api/topology", nil)
	job := runJob(t, s, `{"services":["auto-openai"],"exits":["us"],"families":["ipv4"]}`)
	if len(job.Items) != 1 {
		t.Fatalf("%+v", job.Items)
	}
	it := job.Items[0]
	if it.Category != probe.CatFailed || it.Grade != probe.GradeError || it.Ingest != "accepted:inconclusive" || !strings.Contains(it.Egress, "未确认") {
		t.Fatalf("a report for another exit was credited: %+v", it)
	}
	states, _, _ := unlockView(t, s)
	if states["auto-openai"].Known["us"] || states["auto-openai"].Known["us-2"] {
		t.Fatalf("wrong-exit report changed what is known: %+v", states["auto-openai"])
	}
}

func TestPanelProbeIPv4OnlyAdaptersNotSentOnIPv6(t *testing.T) {
	f := &fakeProber{}
	s := probeServer(t, f)
	// us is dual-stack; KKTV's public method is IPv4-only.
	job := runJob(t, s, `{"services":["auto-kktv","auto-netflix"],"exits":["us"],"families":["ipv6"]}`)
	for _, r := range f.requests() {
		for _, svc := range r.Services {
			if svc == "auto-kktv" {
				t.Fatalf("an IPv4-only adapter was sent on IPv6: %+v", r)
			}
		}
	}
	seen := 0
	for _, it := range job.Items {
		if it.Service == "auto-kktv" {
			seen++
			// Not applicable, not unknown: nothing was sent, nothing ingested.
			if it.State != itemSkipped || it.Ingest != "not_ingested:family_not_supported" || it.Signal != probe.SigFamily ||
				it.Category != probe.CatNotApplicable || it.Grade != probe.GradeNotApplicable {
				t.Fatalf("%+v", it)
			}
		}
	}
	if seen != 1 || len(f.requests()) != 1 {
		t.Fatalf("items %+v requests %+v", job.Items, f.requests())
	}
}

// An agent result of not_applicable is kept only for a family the service's
// check does not support (and then even with an unconfirmed egress, since
// nothing was sent); for any other service it is an unknown category.
// Neither is a verdict.
func TestSanitizeReportNotApplicable(t *testing.T) {
	spec := probe.Spec{ExitID: "us", Family: unlock.FamilyIPv6, Services: []string{"auto-kktv", "auto-netflix"}}
	rep := probe.Report{ExitID: "us", Family: unlock.FamilyIPv6, Results: []probe.Result{
		{Service: "auto-kktv", Family: unlock.FamilyIPv6, Category: probe.CatNotApplicable, Region: "TW"},
		{Service: "auto-netflix", Family: unlock.FamilyIPv6, Category: probe.CatNotApplicable},
	}}
	rep.Egress.Confirmed = false
	out := sanitizeReport(rep, spec)
	got := map[string]probe.Result{}
	for _, r := range out.Results {
		got[r.Service] = r
	}
	if k := got["auto-kktv"]; k.Category != probe.CatNotApplicable || k.Grade != probe.GradeNotApplicable || k.Region != "" || k.Signal != probe.SigFamily {
		t.Fatalf("kktv: %+v", k)
	}
	if n := got["auto-netflix"]; n.Category == probe.CatNotApplicable {
		t.Fatalf("a supported family cannot be not_applicable: %+v", n)
	}
	for _, c := range []probe.Category{probe.CatNotApplicable} {
		if _, has := probe.IngestVerdict(c); has {
			t.Fatal("not_applicable must not be a verdict")
		}
	}
}

func TestUnlockCatalogResultsAndJobAPI(t *testing.T) {
	f := &fakeProber{}
	s := probeServer(t, f)
	rr := do(s, http.MethodGet, "/api/unlock/catalog", nil)
	if rr.Code != 200 {
		t.Fatal(rr.Body.String())
	}
	var cat struct {
		Catalog        []catalogEntry `json:"catalog"`
		Validation     string         `json:"validation"`
		ValidationText string         `json:"validation_text"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &cat); err != nil {
		t.Fatal(err)
	}
	if len(cat.Catalog) != len(probe.Catalog) || len(cat.Catalog) < 24 || cat.Validation != "synthetic_only" || !strings.Contains(cat.ValidationText, "尚未在真实平台上验证") {
		t.Fatalf("catalog: %d %s", len(cat.Catalog), cat.Validation)
	}
	for _, e := range cat.Catalog {
		if e.Capability == "" || len(e.Sources) == 0 || e.Validation != probe.Validation || e.Basis == "" || e.Limits == "" || (e.Probeable && len(e.Hosts) == 0) {
			t.Fatalf("incomplete catalog entry: %+v", e)
		}
		if e.Reachability != (e.Capability == probe.CapReachability) {
			t.Fatalf("reachability flag: %+v", e)
		}
	}

	job := runJob(t, s, `{"services":["auto-openai","auto-netflix"],"groups":["us"],"families":["ipv4"]}`)
	exits := map[string]bool{}
	for _, it := range job.Items {
		exits[it.ExitID] = true
	}
	if !exits["us"] || !exits["us-2"] || len(exits) != 2 {
		t.Fatalf("group selection: %v", exits)
	}
	rr = do(s, http.MethodGet, "/api/unlock/jobs/"+job.ID, nil)
	if rr.Code != 200 || !strings.Contains(rr.Body.String(), job.ID) {
		t.Fatalf("job: %d %s", rr.Code, rr.Body.String())
	}
	if rr := do(s, http.MethodGet, "/api/unlock/jobs/job-nope", nil); rr.Code != http.StatusNotFound {
		t.Fatalf("missing job: %d", rr.Code)
	}

	rr = do(s, http.MethodGet, "/api/unlock/results?service=auto-openai&family=ipv4", nil)
	var res struct {
		Results []resultRow `json:"results"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &res); err != nil {
		t.Fatal(err)
	}
	if len(res.Results) != 2 {
		t.Fatalf("results: %s", rr.Body.String())
	}
	for _, row := range res.Results {
		if row.Service != "auto-openai" || row.Group != "us" || !row.InGroup || row.ServiceActive != "us" || row.IsActive != (row.ExitID == "us") ||
			!row.Ingestible || row.Grade != probe.GradePlatform || len(row.ExitGroups) == 0 || row.EgressIP == "" {
			t.Fatalf("row: %+v", row)
		}
	}
	rr = do(s, http.MethodGet, "/api/unlock/results?group=tw", nil)
	if strings.Contains(rr.Body.String(), `"exit_id":"us"`) {
		t.Fatalf("group filter: %s", rr.Body.String())
	}
	// The results matrix outlives the job ring.
	for i := 0; i < maxProbeJobs+1; i++ {
		runJob(t, s, `{"services":["auto-netflix"],"exits":["hk-resi"],"families":["ipv4"]}`)
	}
	rr = do(s, http.MethodGet, "/api/unlock/results?service=auto-openai", nil)
	if !strings.Contains(rr.Body.String(), `"exit_id":"us-2"`) {
		t.Fatalf("older results lost: %s", rr.Body.String())
	}
}

// Exit-side curl status lines are reachability only: recorded with a note,
// never a success or a scheduled failure.
func TestExitReportAICodesAreRecordedOnly(t *testing.T) {
	s := newTest(t)
	do(s, http.MethodGet, "/api/topology", nil)
	for i := 0; i < 3; i++ {
		rr := do(s, http.MethodPost, "/api/unlock/report", []byte(`{"exit_id":"us","kind":"scheduled","ai":"openai 000\ngemini 200\n"}`))
		if rr.Code != 200 || !strings.Contains(rr.Body.String(), "仅到达性") {
			t.Fatalf("%d %s", rr.Code, rr.Body.String())
		}
	}
	states, _, dec := unlockView(t, s)
	if st := states["auto-openai"]; st.SchedFails != 0 || st.Demoted || st.Known["us"] {
		t.Fatalf("curl status counted as a verdict: %+v", st)
	}
	if st := states["auto-gemini"]; st.Known["us"] {
		t.Fatalf("curl 200 counted as a success: %+v", st)
	}
	if len(dec) != 0 {
		t.Fatalf("decisions: %v", dec)
	}
}
