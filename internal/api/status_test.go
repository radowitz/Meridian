package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/radowitz/meridian/internal/hostexec"
	"github.com/radowitz/meridian/internal/model"
)

type statusResp struct {
	Agent          statusAgent `json:"agent"`
	ListsAvailable bool        `json:"lists_available"`
	ProbeAvailable bool        `json:"probe_available"`
	Install        struct {
		State            string `json:"state"`
		InstalledVersion *int64 `json:"installed_version"`
		AppliedMatches   bool   `json:"applied_matches"`
		Applied          bool   `json:"applied"`
		Error            string `json:"error"`
		Issues           []any  `json:"issues"`
	} `json:"install"`
	Pending *struct {
		ID string `json:"id"`
	} `json:"pending"`
	Jobs map[string]statusJob `json:"jobs"`
}

func getStatus(t *testing.T, s *Server) statusResp {
	t.Helper()
	rr := do(s, http.MethodGet, "/api/status", nil)
	if rr.Code != 200 {
		t.Fatal(rr.Code, rr.Body.String())
	}
	var v statusResp
	if err := json.Unmarshal(rr.Body.Bytes(), &v); err != nil {
		t.Fatal(err)
	}
	return v
}

type downHost struct{}

func (downHost) Do(context.Context, hostexec.Request) (hostexec.Result, error) {
	return hostexec.Result{}, errors.New("dial unix /run/meridian/host.sock: connection refused")
}

type upHost struct{ calls int }

func (u *upHost) Do(_ context.Context, req hostexec.Request) (hostexec.Result, error) {
	u.calls++
	if req.Action != hostexec.ActionHealth {
		return hostexec.Result{}, errors.New("status must only call health")
	}
	return hostexec.Result{OK: true}, nil
}

func TestStatusNothingInstalled(t *testing.T) {
	s := newTest(t)
	v := getStatus(t, s)
	if v.Install.State != "not_installed" || v.Install.InstalledVersion != nil || v.Install.Applied {
		t.Fatalf("%+v", v.Install)
	}
	if v.Agent.OK || v.Agent.Configured || v.Agent.Error == "" {
		t.Fatalf("no host agent configured: %+v", v.Agent)
	}
	if v.Pending != nil || v.ListsAvailable || v.ProbeAvailable {
		t.Fatalf("%+v", v)
	}
	for _, k := range []string{"lists", "unlock", "mesh"} {
		if v.Jobs[k].State != "none" || v.Jobs[k].Running {
			t.Fatalf("%s: %+v", k, v.Jobs[k])
		}
	}
	// Read-only: no snapshot, no host directory appeared.
	for _, sub := range []string{"applied", "previous", "host"} {
		if _, err := os.Stat(filepath.Join(s.DataDir, sub)); err == nil {
			t.Fatalf("status created %s", sub)
		}
	}
}

func TestStatusInSyncThenChangedAndAppliedWithoutInstall(t *testing.T) {
	s, _, _ := installTest(t)
	if rr := do(s, http.MethodPost, "/api/apply", []byte(`{"install":true}`)); rr.Code != 200 {
		t.Fatal(rr.Code, rr.Body.String())
	}
	v := getStatus(t, s)
	if v.Install.State != "in_sync" || v.Install.InstalledVersion == nil || !v.Install.AppliedMatches {
		t.Fatalf("after install: %+v", v.Install)
	}
	if !v.Agent.OK {
		t.Fatalf("%+v", v.Agent)
	}

	// Change the stored topology: changed, and not yet applied either.
	topo, _, _ := s.Store.Load()
	topo.Rules = append(topo.Rules, model.Rule{ID: "status-test", Name: "status test", Manual: true, Enabled: true,
		Priority: 9999, MatchType: "domain", MatchValue: "example.org", TargetGroup: topo.Settings.DefaultGroup})
	if err := s.Store.Save(topo); err != nil {
		t.Fatal(err)
	}
	v = getStatus(t, s)
	if v.Install.State != "changed" || v.Install.AppliedMatches {
		t.Fatalf("after edit: %+v", v.Install)
	}

	// Apply without install updates the snapshot, not the host: still changed.
	if rr := do(s, http.MethodPost, "/api/apply", []byte(`{"install":false}`)); rr.Code != 200 {
		t.Fatal(rr.Code, rr.Body.String())
	}
	v = getStatus(t, s)
	if v.Install.State != "changed" || !v.Install.AppliedMatches {
		t.Fatalf("applied without install must stay changed: %+v", v.Install)
	}
	// The old diff endpoint is fooled by exactly this case.
	if rr := do(s, http.MethodPost, "/api/diff", []byte(`{}`)); rr.Code != 200 {
		t.Fatal(rr.Code)
	}

	if rr := do(s, http.MethodPost, "/api/apply", []byte(`{"install":true}`)); rr.Code != 200 {
		t.Fatal(rr.Code, rr.Body.String())
	}
	if v = getStatus(t, s); v.Install.State != "in_sync" {
		t.Fatalf("after second install: %+v", v.Install)
	}
}

func TestStatusDoesNotCompile(t *testing.T) {
	s := newTest(t)
	do(s, http.MethodGet, "/api/topology", nil)
	topo, _, _ := s.Store.Load()
	var links []model.Link
	for _, l := range topo.Links {
		if l.ID == "ali-ix" || l.ID == "ix-hub" {
			continue
		}
		links = append(links, l)
	}
	topo.Links = links
	topo.Settings.Draft = true
	if err := s.Store.Save(topo); err != nil {
		t.Fatal(err)
	}
	v := getStatus(t, s)
	if v.Install.State != "invalid" || v.Install.Error == "" || len(v.Install.Issues) == 0 {
		t.Fatalf("%+v", v.Install)
	}
}

func TestStatusAgentDownAndUp(t *testing.T) {
	s := newTest(t)
	s.Host = downHost{}
	s.Lists = nil
	v := getStatus(t, s)
	if v.Agent.OK || !v.Agent.Configured || v.Agent.Error == "" || v.ListsAvailable {
		t.Fatalf("%+v", v)
	}
	u := &upHost{}
	s.Host = u
	s.Lists = &fakeLists{}
	v = getStatus(t, s)
	if !v.Agent.OK || !v.ListsAvailable || u.calls != 1 {
		t.Fatalf("%+v calls=%d", v, u.calls)
	}
}

func TestStatusJobs(t *testing.T) {
	s := newTest(t)
	now := time.Now().UTC()

	// Lists: running, then done.
	s.listsJob = &listsJob{ID: "lists-1", State: "running", StartedAt: now}
	if v := getStatus(t, s); v.Jobs["lists"].State != "running" || !v.Jobs["lists"].Running || v.Jobs["lists"].ID != "lists-1" {
		t.Fatalf("%+v", v.Jobs["lists"])
	}
	fin := now.Add(time.Second)
	s.listsJob = &listsJob{ID: "lists-1", State: "failed", StartedAt: now, FinishedAt: &fin, Error: "agent unreachable"}
	if v := getStatus(t, s); v.Jobs["lists"].State != "failed" || v.Jobs["lists"].Running || v.Jobs["lists"].Error == "" {
		t.Fatalf("%+v", v.Jobs["lists"])
	}

	// Unlock: last finished job, then a running one.
	if err := s.saveJobs(probeJobsDoc{Jobs: []probeJob{{ID: "job-1", Kind: "manual", State: "done", CreatedAt: now, FinishedAt: &fin,
		Items: []probeJobItem{{Service: "netflix", ExitID: "hk-a", Family: "ipv4", State: "done"}}}}}); err != nil {
		t.Fatal(err)
	}
	v := getStatus(t, s)
	if v.Jobs["unlock"].State != "done" || v.Jobs["unlock"].Running || v.Jobs["unlock"].ID != "job-1" {
		t.Fatalf("%+v", v.Jobs["unlock"])
	}
	s.job = &jobHandle{id: "job-2"}
	v = getStatus(t, s)
	if v.Jobs["unlock"].State != "running" || !v.Jobs["unlock"].Running || v.Jobs["unlock"].ID != "job-2" {
		t.Fatalf("%+v", v.Jobs["unlock"])
	}
	s.job = nil

	// Mesh: each journal state; running and compensating count as running.
	if err := os.MkdirAll(s.meshDir(), 0o700); err != nil {
		t.Fatal(err)
	}
	for state, running := range map[string]bool{"running": true, "compensating": true, "published": false, "failed": false, "compensation_failed": false, "withdrawn": false} {
		j := map[string]any{"schema": 3, "run_id": "run-" + state, "state": state, "started": now.Format(time.RFC3339), "updated": now.Format(time.RFC3339),
			"stages": []any{}, "nodes": []any{}, "routes": []any{}, "remotes": []any{}, "targets": []any{}, "dataplane": "unverified"}
		b, _ := json.Marshal(j)
		if err := os.WriteFile(filepath.Join(s.meshDir(), "deploy.json"), b, 0o600); err != nil {
			t.Fatal(err)
		}
		m := getStatus(t, s).Jobs["mesh"]
		if m.State != state || m.Running != running || m.ID != "run-"+state {
			t.Fatalf("%s: %+v", state, m)
		}
	}
	// A broken journal is reported, not hidden.
	if err := os.WriteFile(filepath.Join(s.meshDir(), "deploy.json"), []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	if m := getStatus(t, s).Jobs["mesh"]; m.State != "error" || m.Error == "" {
		t.Fatalf("%+v", m)
	}
}

func TestStatusReportsPendingTransaction(t *testing.T) {
	s, _, _ := installTest(t)
	s.Activate = func() error { return errors.New("activation failed") }
	// A failed and compensated install leaves no pending transaction.
	do(s, http.MethodPost, "/api/apply", []byte(`{"install":true}`))
	if v := getStatus(t, s); v.Pending != nil || v.Install.State != "not_installed" {
		t.Fatalf("%+v", v)
	}
	// An interrupted one is reported.
	j := `{"id":"txn-test","kind":"apply","install":true,"phase":"host","attempt":0,"from":{},"to":{},"before":{"applied":-1,"previous":-1},"after":{"applied":1,"previous":-1},"started":"2026-11-13T00:00:00Z"}`
	if err := os.MkdirAll(filepath.Join(s.DataDir, "host"), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(s.DataDir, "host", "journal.json"), []byte(j), 0o600); err != nil {
		t.Fatal(err)
	}
	if v := getStatus(t, s); v.Pending == nil || v.Pending.ID != "txn-test" {
		t.Fatalf("%+v", v.Pending)
	}
}
