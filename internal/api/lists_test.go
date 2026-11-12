package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/radowitz/meridian/internal/hostexec"
	"github.com/radowitz/meridian/internal/lists"
)

type fakeLists struct {
	mu      sync.Mutex
	reqs    []hostexec.ListsRequest
	release chan struct{}
	err     error
	status  lists.Status
}

func (f *fakeLists) UpdateLists(ctx context.Context, req hostexec.ListsRequest) (lists.Report, error) {
	f.mu.Lock()
	f.reqs = append(f.reqs, req)
	rel := f.release
	f.mu.Unlock()
	if rel != nil {
		<-rel
	}
	if f.err != nil {
		return lists.Report{}, f.err
	}
	now := time.Now()
	return lists.Report{Policy: lists.Policy(req.Policy), StartedAt: now, FinishedAt: now, OK: true,
		Lists: []lists.ListResult{{List: "geosite:cn", Kind: "geosite", Updated: true, Source: "domestic", Count: 3}}}, nil
}

func (f *fakeLists) ListsStatus(ctx context.Context) (lists.Status, error) {
	return f.status, f.err
}

func decodeMap(t *testing.T, b []byte) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("%v: %s", err, b)
	}
	return m
}

func waitJob(t *testing.T, s *Server) map[string]any {
	t.Helper()
	for i := 0; i < 200; i++ {
		rr := do(s, "GET", "/api/lists/job", nil)
		job, _ := decodeMap(t, rr.Body.Bytes())["job"].(map[string]any)
		if job != nil && job["state"] != "running" {
			return job
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("job never finished")
	return nil
}

func TestListsPolicy(t *testing.T) {
	s := newTest(t)
	rr := do(s, "GET", "/api/lists", nil)
	m := decodeMap(t, rr.Body.Bytes())
	if rr.Code != 200 || m["policy"] != "automatic" || m["saved"] != false || m["host_available"] != false {
		t.Fatalf("%d %v", rr.Code, m)
	}
	geo := m["lists"].(map[string]any)["geosite"].([]any)
	if len(geo) < 2 {
		t.Fatalf("geosite names %v", geo)
	}
	if !strings.Contains(rr.Body.String(), "cdn.jsdelivr.net") {
		t.Fatal("sources not shown")
	}
	rr = do(s, "PUT", "/api/lists/policy", []byte(`{"policy":"overseas"}`))
	if rr.Code != 200 || decodeMap(t, rr.Body.Bytes())["policy"] != "overseas" {
		t.Fatalf("%d %s", rr.Code, rr.Body)
	}
	topo, _ := s.topology()
	if topo.Settings.ListSource != "overseas" {
		t.Fatal("policy not persisted in the topology")
	}
	for body, want := range map[string]int{
		`{"policy":"auto"}`:              422,
		`{"policy":"https://evil.test"}`: 422,
		`{}`:                             422,
		`not json`:                       400,
	} {
		rr = do(s, "PUT", "/api/lists/policy", []byte(body))
		m := decodeMap(t, rr.Body.Bytes())
		if rr.Code != want || m["code"] == nil || m["error"] == nil {
			t.Fatalf("%s: %d %v", body, rr.Code, m)
		}
		if want == 422 && m["field"] != "policy" {
			t.Fatalf("%s: field %v", body, m["field"])
		}
	}
	// A stored invalid value is a validation error.
	topo.Settings.ListSource = "mirror"
	rr = do(s, "POST", "/api/validate", mustJSON(topo))
	if !strings.Contains(rr.Body.String(), "bad_list_source") {
		t.Fatalf("validate: %s", rr.Body)
	}
}

func TestListsUpdateJob(t *testing.T) {
	s := newTest(t)
	rr := do(s, "POST", "/api/lists/update", nil)
	if rr.Code != http.StatusServiceUnavailable || decodeMap(t, rr.Body.Bytes())["code"] != codeHostUnavailable {
		t.Fatalf("no host: %d %s", rr.Code, rr.Body)
	}
	f := &fakeLists{release: make(chan struct{})}
	s.Lists = f
	rr = do(s, "POST", "/api/lists/update", []byte(`{"lists":["geosite"],"policy":"domestic"}`))
	if rr.Code != http.StatusAccepted {
		t.Fatalf("%d %s", rr.Code, rr.Body)
	}
	// One at a time.
	rr = do(s, "POST", "/api/lists/update", nil)
	if rr.Code != http.StatusConflict || decodeMap(t, rr.Body.Bytes())["code"] != codeUpdateRunning {
		t.Fatalf("second: %d %s", rr.Code, rr.Body)
	}
	if j := decodeMap(t, do(s, "GET", "/api/lists", nil).Body.Bytes())["job"].(map[string]any); j["state"] != "running" {
		t.Fatalf("job %v", j)
	}
	close(f.release)
	job := waitJob(t, s)
	if job["state"] != "done" || job["report"] == nil {
		t.Fatalf("job %v", job)
	}
	f.mu.Lock()
	req := f.reqs[0]
	f.mu.Unlock()
	// The request carries enumerations and names from the topology only.
	if req.Policy != "domestic" || len(req.Lists) != 1 || req.Lists[0] != "geosite" || len(req.Geosite) < 2 {
		t.Fatalf("request %+v", req)
	}
	if err := hostexec.ValidateLists(req); err != nil {
		t.Fatal(err)
	}
	// The last job survives a restart of the panel.
	s2 := &Server{Store: s.Store, DataDir: s.DataDir}
	if j := waitJob(t, s2); j["id"] != job["id"] {
		t.Fatalf("persisted job %v", j)
	}
	// Default: both kinds, the saved policy.
	f.release = nil
	if rr := do(s, "POST", "/api/lists/update", nil); rr.Code != http.StatusAccepted {
		t.Fatalf("%d %s", rr.Code, rr.Body)
	}
	waitJob(t, s)
	f.mu.Lock()
	req = f.reqs[1]
	f.mu.Unlock()
	if req.Policy != "automatic" || len(req.Lists) != 2 {
		t.Fatalf("default request %+v", req)
	}
	for body, field := range map[string]string{
		`{"lists":["geoip"]}`:               "lists",
		`{"lists":["chnroute","chnroute"]}`: "lists",
		`{"policy":"fastest"}`:              "policy",
	} {
		rr := do(s, "POST", "/api/lists/update", []byte(body))
		if m := decodeMap(t, rr.Body.Bytes()); rr.Code != 422 || m["field"] != field {
			t.Fatalf("%s: %d %v", body, rr.Code, m)
		}
	}
	// An agent failure is a failed job, not a crash.
	f.err = errors.New("host agent busy")
	do(s, "POST", "/api/lists/update", []byte(`{"lists":["chnroute"]}`))
	if j := waitJob(t, s); j["state"] != "failed" || !strings.Contains(j["error"].(string), "busy") {
		t.Fatalf("job %v", j)
	}
	rr = do(s, "GET", "/api/lists/status", nil)
	if rr.Code != http.StatusBadGateway {
		t.Fatalf("status with failing agent: %d", rr.Code)
	}
	f.err = nil
	f.status = lists.Status{Published: map[string]lists.Published{"chnroute4": {Source: "domestic", Count: 6217}}}
	rr = do(s, "GET", "/api/lists/status", nil)
	if rr.Code != 200 || !strings.Contains(rr.Body.String(), `"count":6217`) {
		t.Fatalf("%d %s", rr.Code, rr.Body)
	}
}
