package api

import (
	"context"
	"encoding/json"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	"github.com/radowitz/meridian/internal/hostexec"
	"github.com/radowitz/meridian/internal/model"
)

type latencyFixture struct{ calls atomic.Int32 }

func (f *latencyFixture) ExitLatency(_ context.Context, r hostexec.ExitLatencyRequest) (hostexec.ExitLatencyResult, error) {
	f.calls.Add(1)
	v := 42.25
	return hostexec.ExitLatencyResult{ExitID: r.ExitID, State: "ok", RTTMS: &v, Sent: 3, Received: 3, Interface: "m02", MeasuredAt: time.Now()}, nil
}
func TestExitLatencyIsMeasuredAndNotGroupHealth(t *testing.T) {
	s := newTest(t)
	f := &latencyFixture{}
	s.ExitLatency = f
	s.gatewayInSync = func(model.Topology) bool { return true }
	bad := do(s, http.MethodPost, "/api/exits/latency", []byte(`{"resolver":"1.1.1.1"}`))
	if bad.Code != 400 || f.calls.Load() != 0 {
		t.Fatal("caller controlled target accepted", bad.Body.String())
	}
	r := do(s, http.MethodPost, "/api/exits/latency", []byte(`{}`))
	if r.Code != 200 {
		t.Fatal(r.Code, r.Body.String())
	}
	var view exitLatencyView
	if err := json.Unmarshal(r.Body.Bytes(), &view); err != nil {
		t.Fatal(err)
	}
	if len(view.Rows) == 0 || int(f.calls.Load()) != len(view.Rows) {
		t.Fatalf("no per-exit measurement: %s", r.Body.String())
	}
	for _, x := range view.Rows {
		if x.RTTMS == nil || *x.RTTMS != 42.25 || x.Stale {
			t.Fatalf("%+v", x)
		}
	}
	before := f.calls.Load()
	if do(s, http.MethodGet, "/api/exits/latency", nil).Code != 200 || f.calls.Load() != before {
		t.Fatal("GET sends probes")
	}
	groups := do(s, http.MethodGet, "/api/region-groups", nil)
	var g struct {
		Groups []struct {
			Model modelView `json:"model"`
		} `json:"groups"`
	}
	json.Unmarshal(groups.Body.Bytes(), &g)
	for _, x := range g.Groups {
		if x.Model.Observed {
			t.Fatal("latency was used to mutate failover health")
		}
	}
}

func TestExitLatencyInvalidatesOldPathAndMarksOldSamples(t *testing.T) {
	s := newTest(t)
	s.ExitLatency = &latencyFixture{}
	s.gatewayInSync = func(model.Topology) bool { return true }
	if r := do(s, http.MethodPost, "/api/exits/latency", []byte(`{}`)); r.Code != 200 {
		t.Fatal(r.Body.String())
	}
	s.latencyMu.Lock()
	for id, c := range s.latencyCache {
		c.Result.MeasuredAt = time.Now().Add(-3 * time.Minute)
		s.latencyCache[id] = c
	}
	s.latencyMu.Unlock()
	var v exitLatencyView
	json.Unmarshal(do(s, http.MethodGet, "/api/exits/latency", nil).Body.Bytes(), &v)
	for _, x := range v.Rows {
		if !x.Stale || x.RTTMS == nil {
			t.Fatalf("old sample shown as fresh: %+v", x)
		}
	}
	topo, _ := s.topology()
	topo.Nodes[0].Name += " changed"
	if err := s.Store.Save(topo); err != nil {
		t.Fatal(err)
	}
	v = exitLatencyView{}
	json.Unmarshal(do(s, http.MethodGet, "/api/exits/latency", nil).Body.Bytes(), &v)
	for _, x := range v.Rows {
		if x.State != "not_measured" || x.RTTMS != nil {
			t.Fatalf("old path reused: %+v", x)
		}
	}
}
