package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/radowitz/meridian/internal/hostexec"
)

type stubTraffic struct {
	st  hostexec.TrafficStatus
	err error
}

func (f *stubTraffic) TrafficStatus(context.Context) (hostexec.TrafficStatus, error) {
	return f.st, f.err
}

func getTrafficView(t *testing.T, s *Server) trafficView {
	t.Helper()
	rec := httptest.NewRecorder()
	s.getTraffic(rec, httptest.NewRequest("GET", "/api/traffic", nil))
	if rec.Code != 200 {
		t.Fatalf("%d %s", rec.Code, rec.Body.String())
	}
	var v trafficView
	if err := json.Unmarshal(rec.Body.Bytes(), &v); err != nil {
		t.Fatal(err)
	}
	return v
}

func TestTrafficEndpoint(t *testing.T) {
	if v := getTrafficView(t, &Server{}); v.Available || v.Code != "agent_unavailable" {
		t.Fatalf("%+v", v)
	}
	stub := &stubTraffic{st: hostexec.TrafficStatus{ReadAt: "2026-11-17T00:00:00Z", Counters: []hostexec.TrafficCounter{
		{Name: "traffic_up_domestic", Bytes: 100, Packets: 1, Handle: 5},
		{Name: "traffic_down_foreign", Bytes: 900, Packets: 3, Handle: 8},
	}, Missing: []string{"traffic_up_foreign", "traffic_down_domestic"}}}
	s := &Server{Traffic: stub}
	v := getTrafficView(t, s)
	if !v.Available || v.Reset || v.Counters["up_domestic"].Bytes != 100 || v.Counters["down_foreign"].Packets != 3 || len(v.Missing) != 2 || v.Missing[0] != "up_foreign" {
		t.Fatalf("%+v", v)
	}
	// Growth: no reset.
	stub.st.Counters[0].Bytes = 200
	if v := getTrafficView(t, s); v.Reset || v.Counters["up_domestic"].Bytes != 200 {
		t.Fatalf("%+v", v)
	}
	// Going backwards (apply replaced the table): reset.
	stub.st.Counters[0].Bytes = 10
	if v := getTrafficView(t, s); !v.Reset {
		t.Fatalf("%+v", v)
	}
	// New handle, even with larger values: reset.
	stub.st.Counters[1].Handle, stub.st.Counters[1].Bytes = 9, 5000
	if v := getTrafficView(t, s); !v.Reset {
		t.Fatalf("%+v", v)
	}
	// Counters missing entirely.
	stub.st = hostexec.TrafficStatus{ReadAt: "x", Counters: []hostexec.TrafficCounter{}, Missing: hostexec.TrafficCounterNames}
	if v := getTrafficView(t, s); v.Available || v.Code != "not_installed" {
		t.Fatalf("%+v", v)
	}
	stub.err = errors.New("boom")
	if v := getTrafficView(t, s); v.Available || v.Code != "read_failed" {
		t.Fatalf("%+v", v)
	}
}

func TestTrafficConnections(t *testing.T) {
	n := func(i int) *int { return &i }
	ctr := []hostexec.TrafficCounter{{Name: "traffic_up_domestic", Bytes: 1, Handle: 1}}
	stub := &stubTraffic{st: hostexec.TrafficStatus{ReadAt: "x", Counters: ctr, Connections: &hostexec.ConnCounts{
		ReadAt: "y", Domestic: n(3), Foreign: n(5), Redirected: n(2), Total: n(10)}}}
	s := &Server{Traffic: stub}
	c := getTrafficView(t, s).Connections
	if c == nil || !c.Available || !c.Split || *c.Domestic != 3 || *c.Foreign != 5 || *c.Total != 10 || c.Scope != "lan_and_remote_access" {
		t.Fatalf("%+v", c)
	}
	// Split not available: total only.
	stub.st.Connections = &hostexec.ConnCounts{ReadAt: "y", Total: n(7), Redirected: n(0)}
	if c := getTrafficView(t, s).Connections; !c.Available || c.Split || c.Domestic != nil || *c.Total != 7 {
		t.Fatalf("%+v", c)
	}
	// Read failure: null counts, never 0; counters still available.
	stub.st.Connections = &hostexec.ConnCounts{ReadAt: "y", Error: "no conntrack"}
	rec := httptest.NewRecorder()
	s.getTraffic(rec, httptest.NewRequest("GET", "/api/traffic", nil))
	body := rec.Body.String()
	if !strings.Contains(body, `"total":null`) || !strings.Contains(body, `"code":"read_failed"`) || !strings.Contains(body, `"available":true`) {
		t.Fatal(body)
	}
	// Older agent: no connections at all.
	stub.st.Connections = nil
	if c := getTrafficView(t, s).Connections; c != nil {
		t.Fatalf("%+v", c)
	}
}

func TestTrafficUsagePersistsAcrossPanelAndGatewayRestarts(t *testing.T) {
	s := newTest(t)
	stub := &stubTraffic{st: hostexec.TrafficStatus{BootID: "boot-one", Counters: []hostexec.TrafficCounter{
		{Name: "traffic_up_domestic", Bytes: 100, Handle: 5},
		{Name: "traffic_down_domestic", Bytes: 800, Handle: 6},
		{Name: "traffic_up_foreign", Bytes: 200, Handle: 7},
		{Name: "traffic_down_foreign", Bytes: 900, Handle: 8},
	}}}
	s.Traffic = stub
	if got := getTrafficView(t, s).Usage; got["domestic"] != 900 || got["foreign"] != 1100 {
		t.Fatalf("initial totals: %v", got)
	}
	stub.st.Counters[0].Bytes += 70
	restarted := &Server{Store: s.Store, Traffic: stub}
	if got := getTrafficView(t, restarted).Usage; got["domestic"] != 970 || got["foreign"] != 1100 {
		t.Fatalf("after panel restart: %v", got)
	}
	stub.st.BootID = "boot-two"
	stub.st.Counters[0].Bytes, stub.st.Counters[1].Bytes = 180, 40
	stub.st.Counters[2].Bytes, stub.st.Counters[3].Bytes = 30, 50
	if v := getTrafficView(t, restarted); !v.Reset || v.Usage["domestic"] != 1190 || v.Usage["foreign"] != 1180 {
		t.Fatalf("after gateway reboot: %+v", v)
	}
	stub.err = hostexec.ErrUnavailable
	if v := getTrafficView(t, restarted); v.Available || v.Usage["domestic"] != 1190 {
		t.Fatalf("temporary read failure: %+v", v)
	}
}
