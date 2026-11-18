package api

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/radowitz/meridian/internal/hostexec"
	"github.com/radowitz/meridian/internal/model"
	"github.com/radowitz/meridian/internal/sniff"
)

type fakeSniffRT struct {
	st  hostexec.SniffStatus
	err error
}

func (f fakeSniffRT) SniffStatus(context.Context) (hostexec.SniffStatus, error) { return f.st, f.err }

// GET/PUT /api/sniff: the setting with its defaults, coverage text, the
// runtime passed through; an invalid setting is refused and not saved.
func TestSniffAPI(t *testing.T) {
	s, _ := importServer(t)
	rr := do(s, http.MethodGet, "/api/sniff", nil)
	var out struct {
		Setting  sniffSettingView `json:"setting"`
		Runtime  sniffRuntimeView `json:"runtime"`
		Coverage struct {
			AddressOnly []string `json:"address_only"`
		} `json:"coverage"`
	}
	if rr.Code != 200 || json.Unmarshal(rr.Body.Bytes(), &out) != nil {
		t.Fatal(rr.Body.String())
	}
	if out.Setting.Enabled || len(out.Setting.Ports) != 2 || out.Runtime.Code != "agent_unavailable" || len(out.Coverage.AddressOnly) == 0 {
		t.Fatalf("%+v", out)
	}
	if rr := do(s, http.MethodPut, "/api/sniff", []byte(`{"enabled":true,"ports":[53]}`)); rr.Code != http.StatusUnprocessableEntity {
		t.Fatalf("port 53 saved: %d %s", rr.Code, rr.Body.String())
	}
	if rr := do(s, http.MethodPut, "/api/sniff", []byte(`{"enabled":true,"record_names":true}`)); rr.Code != 200 {
		t.Fatal(rr.Body.String())
	}
	tp, _ := s.topology()
	if !tp.SniffOn() || !tp.Settings.Sniff.RecordNames {
		t.Fatalf("%+v", tp.Settings.Sniff)
	}
	s.Sniff = fakeSniffRT{st: hostexec.SniffStatus{Present: true, Active: "active", Health: json.RawMessage(`{"ready":true}`), Recent: json.RawMessage(`{"connections":[]}`)}}
	rr = do(s, http.MethodGet, "/api/sniff", nil)
	if !strings.Contains(rr.Body.String(), `"ready":true`) || !strings.Contains(rr.Body.String(), `"available":true`) {
		t.Fatal(rr.Body.String())
	}
	s.Sniff = fakeSniffRT{st: hostexec.SniffStatus{}}
	if rr := do(s, http.MethodGet, "/api/sniff", nil); !strings.Contains(rr.Body.String(), `"code":"not_running"`) {
		t.Fatal(rr.Body.String())
	}
}

// The rule tester honours device rules by MAC (it used to ignore them and
// treat the rule as one for every client).
func TestRuleTesterSourceMAC(t *testing.T) {
	s, _ := importServer(t)
	s.Store.Update(func(tp *model.Topology) (bool, error) {
		tp.Rules = append([]model.Rule{
			{ID: "mac", Name: "mac", Enabled: true, Manual: true, MatchType: model.MatchSuffix, MatchValue: "example.net", TargetGroup: "jp", SourceMAC: "02:00:00:00:00:01"},
			{ID: "all", Name: "all", Enabled: true, Manual: true, MatchType: model.MatchSuffix, MatchValue: "example.net", TargetGroup: "us"},
		}, tp.Rules...)
		return true, nil
	})
	for body, want := range map[string]string{
		`{"name":"x.example.net"}`:                                  `"id":"all"`,
		`{"name":"x.example.net","source_mac":"02:00:00:00:00:02"}`: `"id":"all"`,
		`{"name":"x.example.net","source_mac":"02:00:00:00:00:01"}`: `"id":"mac"`,
	} {
		rr := do(s, http.MethodPost, "/api/rules/test", []byte(body))
		if rr.Code != 200 || !strings.Contains(rr.Body.String(), want) {
			t.Errorf("%s: %s", body, rr.Body.String())
		}
	}
	if rr := do(s, http.MethodPost, "/api/rules/test", []byte(`{"name":"x.example.net","source_mac":"nope"}`)); rr.Code != http.StatusUnprocessableEntity {
		t.Fatal(rr.Body.String())
	}
}

// fakeJournalRT is the host agent's status read and journal requests in
// front of a real forwarder journal (sniff.Journal in a temporary
// directory), answering the way hostexec.Agent passes the forwarder's
// answers on.
type fakeJournalRT struct {
	fakeSniffRT
	j      *sniff.Journal
	clears int
}

func (f *fakeJournalRT) body(v any, err error) (hostexec.SniffJournalAnswer, error) {
	if err != nil {
		return hostexec.SniffJournalAnswer{Present: true, Code: "bad_request", Error: err.Error()}, nil
	}
	b, _ := json.Marshal(v)
	return hostexec.SniffJournalAnswer{Present: true, Body: b}, nil
}

func (f *fakeJournalRT) SniffJournal(_ context.Context, q sniff.JournalQuery) (hostexec.SniffJournalAnswer, error) {
	return f.body(f.j.Query(q))
}

func (f *fakeJournalRT) SniffJournalSummary(_ context.Context, q sniff.JournalSummaryQuery) (hostexec.SniffJournalAnswer, error) {
	return f.body(f.j.Summary(q))
}

func (f *fakeJournalRT) SniffJournalClear(context.Context) (hostexec.SniffJournalAnswer, error) {
	f.clears++
	return f.body(map[string]any{"cleared": f.j.Clear()}, nil)
}

const journalMarker = "journal-marker"

func journalRig(t *testing.T, names bool) (*Server, *fakeJournalRT) {
	t.Helper()
	s, _ := importServer(t)
	j, err := sniff.OpenJournal(sniff.JournalConfig{Dir: t.TempDir(), RecordNames: names})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(j.Close)
	now := time.Now().UTC()
	for i := 0; i < 12; i++ {
		j.Add(sniff.ConnRecord{Start: now.Add(-time.Duration(i) * time.Minute), Source: fmt.Sprintf("192.0.2.%d", 10+i%3), MAC: "02:00:00:00:00:0" + fmt.Sprint(i%3),
			Dest: "198.51.100.7:443", Proto: "tls", Name: fmt.Sprintf("%s-%d.example.com", journalMarker, i), Sniffed: true, By: "name",
			RuleIndex: 2, RuleID: journalMarker + "-rule", Target: []string{"direct", "group:hk"}[i%2], Result: []string{"ok", "dial_failed", "ok"}[i%3]})
	}
	j.Flush()
	f := &fakeJournalRT{j: j}
	s.Sniff = f
	return s, f
}

// The journal endpoints: paging and filters passed through, invalid and
// unknown parameters refused before the agent is asked, the summary, the
// clear only with confirmation, names absent when recording is off.
func TestSniffJournalAPI(t *testing.T) {
	s, f := journalRig(t, false)
	var v struct {
		Available bool                 `json:"available"`
		Code      string               `json:"code"`
		Page      sniff.JournalPage    `json:"page"`
		Summary   sniff.JournalSummary `json:"summary"`
		Labels    []model.DeviceLabel  `json:"labels"`
		Scope     struct {
			NotCovered []string `json:"not_covered"`
			NamesOff   []string `json:"names_off"`
		} `json:"scope"`
	}
	get := func(path string) int {
		t.Helper()
		rr := do(s, http.MethodGet, path, nil)
		v.Page, v.Summary = sniff.JournalPage{}, sniff.JournalSummary{}
		if rr.Code == 200 {
			if err := json.Unmarshal(rr.Body.Bytes(), &v); err != nil {
				t.Fatal(err)
			}
		}
		return rr.Code
	}
	if c := get("/api/sniff/journal?device=192.0.2.10&limit=2"); c != 200 || !v.Available || v.Page.Matched != 4 || len(v.Page.Records) != 2 || v.Page.NextBefore == 0 {
		t.Fatalf("%d %+v", c, v.Page)
	}
	next := v.Page.NextBefore
	if c := get(fmt.Sprintf("/api/sniff/journal?device=192.0.2.10&limit=2&before=%d", next)); c != 200 || len(v.Page.Records) != 2 || v.Page.Records[0].ID >= next {
		t.Fatalf("second page %d %+v", c, v.Page)
	}
	if c := get("/api/sniff/journal?result=failed"); c != 200 || v.Page.Matched != 4 {
		t.Fatalf("failed %d", v.Page.Matched)
	}
	if c := get("/api/sniff/journal?target=group:hk"); c != 200 || v.Page.Matched != 6 {
		t.Fatalf("target %d", v.Page.Matched)
	}
	// Names off: not in any record, a text search is refused, the scope says so.
	rr := do(s, http.MethodGet, "/api/sniff/journal", nil)
	if strings.Contains(rr.Body.String(), ".example.com") || len(v.Scope.NamesOff) == 0 || len(v.Scope.NotCovered) < 4 {
		t.Fatalf("names with recording off: %s", rr.Body.String())
	}
	if c := get("/api/sniff/journal?text=marker"); c != http.StatusBadRequest {
		t.Fatalf("text search with names off: %d", c)
	}
	for _, bad := range []string{"/api/sniff/journal?file=/etc/passwd", "/api/sniff/journal?device=gateway", "/api/sniff/journal?limit=5000",
		"/api/sniff/journal?result=all", "/api/sniff/devices?device=192.0.2.10", "/api/sniff/devices?from=yesterday"} {
		if c := get(bad); c != http.StatusBadRequest {
			t.Errorf("%s: %d", bad, c)
		}
	}
	if c := get("/api/sniff/devices"); c != 200 || len(v.Summary.Devices) != 3 || v.Summary.Devices[0].Total != 4 || v.Summary.Devices[0].MAC == "" {
		t.Fatalf("%d %+v", c, v.Summary)
	}
	// Clear: only confirmed.
	for _, body := range []string{``, `{}`, `{"confirm":false}`, `{"confirm":"yes"}`} {
		if rr := do(s, http.MethodPost, "/api/sniff/journal/clear", []byte(body)); rr.Code != http.StatusBadRequest {
			t.Errorf("clear %q: %d", body, rr.Code)
		}
	}
	if f.clears != 0 {
		t.Fatal("cleared without confirmation")
	}
	if rr := do(s, http.MethodPost, "/api/sniff/journal/clear", []byte(`{"confirm":true}`)); rr.Code != 200 || f.clears != 1 || !strings.Contains(rr.Body.String(), `"cleared":12`) {
		t.Fatalf("%d %s", rr.Code, rr.Body.String())
	}
	if c := get("/api/sniff/journal"); c != 200 || v.Page.Matched != 0 {
		t.Fatalf("after clear %d", v.Page.Matched)
	}
	// Without an agent: a plain "unavailable", not an error.
	s.Sniff = nil
	if c := get("/api/sniff/devices"); c != 200 || v.Available || v.Code != "agent_unavailable" {
		t.Fatalf("%d %+v", c, v)
	}
	if rr := do(s, http.MethodPost, "/api/sniff/journal/clear", []byte(`{"confirm":true}`)); rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("clear without agent: %d", rr.Code)
	}
}

// With recording on, names are shown and searchable.
func TestSniffJournalAPINames(t *testing.T) {
	s, _ := journalRig(t, true)
	rr := do(s, http.MethodGet, "/api/sniff/journal?text=MARKER-3", nil)
	if rr.Code != 200 || !strings.Contains(rr.Body.String(), journalMarker+"-3.example.com") || !strings.Contains(rr.Body.String(), `"matched":1`) {
		t.Fatalf("%d %s", rr.Code, rr.Body.String())
	}
}

// Every journal endpoint requires the panel token.
func TestSniffJournalAuth(t *testing.T) {
	s, f := journalRig(t, true)
	s.Token = strings.Repeat("k", 32)
	for _, c := range []struct{ method, path, body string }{
		{"GET", "/api/sniff/journal", ""}, {"GET", "/api/sniff/devices", ""}, {"POST", "/api/sniff/journal/clear", `{"confirm":true}`},
		{"PUT", "/api/sniff/devices/192.0.2.10/label", `{"label":"x"}`}, {"DELETE", "/api/sniff/devices/192.0.2.10/label", ""},
	} {
		var b []byte
		if c.body != "" {
			b = []byte(c.body)
		}
		if rr := do(s, c.method, c.path, b); rr.Code != http.StatusUnauthorized || strings.Contains(rr.Body.String(), journalMarker) {
			t.Errorf("%s %s: %d", c.method, c.path, rr.Code)
		}
	}
	if f.clears != 0 {
		t.Fatal("cleared without the token")
	}
}

// Device labels: create, update, list, delete; invalid ones refused; panel
// data only (not in the topology document).
func TestSniffDeviceLabels(t *testing.T) {
	s, _ := journalRig(t, false)
	put := func(addr, body string) int {
		return do(s, http.MethodPut, "/api/sniff/devices/"+addr+"/label", []byte(body)).Code
	}
	if c := put("192.0.2.10", `{"label":"客厅电视"}`); c != 200 {
		t.Fatal(c)
	}
	if c := put("2001%3Adb8%3A%3A1", `{"label":"tablet"}`); c != 200 { // as the panel escapes it
		t.Fatal(c)
	}
	if c := put("192.0.2.10", `{"label":"书房电视"}`); c != 200 {
		t.Fatal(c)
	}
	for addr, body := range map[string]string{
		"not-an-ip":  `{"label":"x"}`,
		"192.0.2.11": `{"label":""}`,
		"192.0.2.12": `{"label":" padded"}`,
		"192.0.2.13": `{"label":"a\u0007b"}`,
		"192.0.2.14": `{"label":"` + strings.Repeat("长", 65) + `"}`,
		"192.0.2.15": `not json`,
	} {
		if c := put(addr, body); c != http.StatusBadRequest && c != http.StatusUnprocessableEntity {
			t.Errorf("%s %s: %d", addr, body, c)
		}
	}
	rr := do(s, http.MethodGet, "/api/sniff/devices", nil)
	var v struct {
		Labels []model.DeviceLabel `json:"labels"`
	}
	json.Unmarshal(rr.Body.Bytes(), &v)
	if len(v.Labels) != 2 || v.Labels[0].Address != "192.0.2.10" || v.Labels[0].Label != "书房电视" || v.Labels[1].Address != "2001:db8::1" {
		t.Fatalf("%+v", v.Labels)
	}
	if tp := do(s, http.MethodGet, "/api/topology", nil).Body.String(); strings.Contains(tp, "书房电视") || strings.Contains(tp, "192.0.2.10") {
		t.Fatal("a label is in the topology document")
	}
	if c := do(s, http.MethodDelete, "/api/sniff/devices/192.0.2.10/label", nil).Code; c != http.StatusNoContent {
		t.Fatal(c)
	}
	if c := do(s, http.MethodDelete, "/api/sniff/devices/192.0.2.10/label", nil).Code; c != http.StatusNotFound {
		t.Fatal(c)
	}
	rr = do(s, http.MethodGet, "/api/sniff/journal", nil)
	json.Unmarshal(rr.Body.Bytes(), &v)
	if len(v.Labels) != 1 {
		t.Fatalf("%+v", v.Labels)
	}
}

// Privacy: journal content (names, addresses, rule ids of the records) and
// device labels never appear in the topology, its compile output or diff,
// the deployment records, the status and sniff reads (the diagnosis
// included), or the panel's own log — only in the two journal reads.
func TestSniffJournalNeverLeaves(t *testing.T) {
	s, _ := journalRig(t, true)
	var logs bytes.Buffer
	log.SetOutput(&logs)
	defer log.SetOutput(os.Stderr)
	// The journal is read (and a label set) first, so any cache or log
	// would hold it by now.
	for _, p := range []string{"/api/sniff/journal", "/api/sniff/devices", "/api/sniff/journal?device=192.0.2.10"} {
		if rr := do(s, http.MethodGet, p, nil); rr.Code != 200 || (strings.HasPrefix(p, "/api/sniff/journal") && !strings.Contains(rr.Body.String(), journalMarker)) {
			t.Fatalf("%s: %d", p, rr.Code)
		}
	}
	do(s, http.MethodPut, "/api/sniff/devices/192.0.2.10/label", []byte(`{"label":"`+journalMarker+`-label"}`))
	check := func(what, body string) {
		t.Helper()
		if strings.Contains(body, journalMarker) {
			t.Errorf("%s contains journal content", what)
		}
	}
	for _, p := range demoGets {
		if strings.HasPrefix(p, "/api/sniff/journal") || p == "/api/sniff/devices" {
			continue // the journal's own reads
		}
		check("GET "+p, do(s, http.MethodGet, p, nil).Body.String())
	}
	for _, p := range demoPosts {
		check("POST "+p.path, do(s, http.MethodPost, p.path, []byte(p.body)).Body.String())
	}
	check("POST /api/compile", do(s, http.MethodPost, "/api/compile", []byte(`{}`)).Body.String())
	// The stored documents: nothing but the labels key holds journal data.
	for _, key := range []string{"topology", deviceLabelsKey} {
		raw, _, _ := s.Store.Get(key)
		if key == "topology" {
			check("stored topology", raw)
		} else if strings.Contains(raw, journalMarker+"-0.example.com") {
			t.Error("journal records stored by the panel")
		}
	}
	check("panel log", logs.String())
}

// The diagnosis counts a connection that connected and then was reset or
// got no response (recent_relay_failed) as a failure of its target, so a
// tunnel path that connects but carries nothing back is the incident's
// signature, not "usable".
func TestSniffDiagnoseRelayFailures(t *testing.T) {
	h := sniff.Health{Ready: true, Targets: []string{"direct", "group:hk"}, StatsWindowS: 900, TargetStats: []sniff.TargetStat{
		{Target: "direct", RecentOK: 40},
		{Target: "group:hk", RecentOK: 1, RecentRelayFailed: 9, LastFailure: "no_response idle_timeout"},
	}}
	b, _ := json.Marshal(h)
	d := sniffDiagnose(hostexec.SniffStatus{Present: true, Health: b, ReadAt: time.Now().UTC().Format(time.RFC3339)})
	if d == nil || !d.TunnelConcentrated || d.Paths != sniffPathsFailing || !strings.Contains(d.Message, "失败") {
		t.Fatalf("%+v", d)
	}
	for _, x := range d.Targets {
		if x.Target == "group:hk" && (x.RecentRelayFailed != 9 || x.LastFailure != "no_response idle_timeout") {
			t.Fatalf("%+v", x)
		}
	}
}
