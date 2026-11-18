package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/radowitz/meridian/internal/apply"
	"github.com/radowitz/meridian/internal/compile"
	"github.com/radowitz/meridian/internal/dnsjournal"
	"github.com/radowitz/meridian/internal/hostexec"
	"github.com/radowitz/meridian/internal/model"
	"github.com/radowitz/meridian/internal/preflight"
	"github.com/radowitz/meridian/internal/sniff"
)

// fakeDNSLog is the host agent's query-journal requests in front of a real
// dnsjournal.Journal, answering the way hostexec.Agent passes the reader's
// answers on.
type fakeDNSLog struct {
	st     hostexec.DNSJournalStatus
	err    error
	j      *dnsjournal.Journal
	clears int
	// clearErr makes the clear fail.
	clearErr string
	asked    []dnsjournal.Query
	// fault: what the journal's clear meets (nil: the real file system);
	// clearBody: the reader's answer to a clear, instead of the journal's.
	fault     dnsjournal.Fault
	clearBody string
}

func verifiedStatus() hostexec.DNSJournalStatus {
	f := dnsjournal.Facts{Provider: "container", Running: true, Version: "1.2026.11.09-1240", ImageID: "sha256:" + strings.Repeat("0", 64), MountFound: true, MountRW: true}
	return hostexec.DNSJournalStatus{ReadAt: "2026-11-15T12:00:00Z", Facts: f, Capability: dnsjournal.Evaluate(f)}
}

func unverifiedStatus() hostexec.DNSJournalStatus {
	f := dnsjournal.Facts{Provider: "container", Running: true, Version: "1.2026.08.05-0921", ImageID: "sha256:" + strings.Repeat("1", 64), MountFound: true, MountRW: true}
	return hostexec.DNSJournalStatus{ReadAt: "2026-11-15T12:00:00Z", Facts: f, Capability: dnsjournal.Evaluate(f)}
}

func (f *fakeDNSLog) DNSJournalStatus(context.Context) (hostexec.DNSJournalStatus, error) {
	return f.st, f.err
}

func (f *fakeDNSLog) body(v any, err error) (hostexec.DNSJournalAnswer, error) {
	if f.j == nil {
		return hostexec.DNSJournalAnswer{Code: "no_socket", Error: "解析日志服务没有运行"}, nil
	}
	if err != nil {
		return hostexec.DNSJournalAnswer{Present: true, Code: "bad_request", Error: err.Error()}, nil
	}
	b, _ := json.Marshal(v)
	return hostexec.DNSJournalAnswer{Present: true, Body: b}, nil
}

func (f *fakeDNSLog) DNSJournal(_ context.Context, q dnsjournal.Query) (hostexec.DNSJournalAnswer, error) {
	f.asked = append(f.asked, q)
	if f.j == nil {
		return f.body(nil, nil)
	}
	return f.body(f.j.Query(q))
}

func (f *fakeDNSLog) DNSJournalSummary(_ context.Context, q dnsjournal.SummaryQuery) (hostexec.DNSJournalAnswer, error) {
	if f.j == nil {
		return f.body(nil, nil)
	}
	return f.body(f.j.Summary(q))
}

func (f *fakeDNSLog) DNSJournalClear(context.Context) (hostexec.DNSJournalAnswer, error) {
	f.clears++
	if f.clearErr != "" {
		return hostexec.DNSJournalAnswer{Code: "read_failed", Error: f.clearErr}, nil
	}
	if f.j == nil {
		return hostexec.DNSClearOutcome(hostexec.DNSJournalAnswer{Body: json.RawMessage(`{"complete":true,"cleared":0,"raw_bytes":0}`)}), nil
	}
	if f.clearBody != "" {
		return hostexec.DNSClearOutcome(hostexec.DNSJournalAnswer{Present: true, Body: json.RawMessage(f.clearBody)}), nil
	}
	// What the reader answers (dnsjournal.Daemon.Clear), judged the way the
	// agent judges it.
	rep := f.j.Clear()
	res := dnsjournal.ClearResult{Complete: rep.Residual == nil && len(rep.Errors) == 0, Cleared: rep.Cleared, Errors: rep.Errors}
	if x := rep.Residual; x != nil {
		res.Residual = &dnsjournal.ClearResidual{Segments: x.Segments, Records: x.Records, Bytes: x.Bytes}
	}
	return hostexec.DNSClearOutcome(hostexec.DNSJournalAnswer{Present: true, Body: mustJSON(res)}), nil
}

const dnsMarker = "dns-marker"

// dnsRig: a server whose agent has a query journal with records of three
// devices; 192.0.2.10 changed hands (two MACs) and has records without one.
func dnsRig(t *testing.T) (*Server, *fakeDNSLog, time.Time) {
	t.Helper()
	s, _ := importServer(t)
	f := &fakeDNSLog{st: verifiedStatus()}
	j, err := dnsjournal.Open(dnsjournal.Config{Dir: filepath.Join(t.TempDir(), "journal"), Fault: func(op, path string) error {
		if f.fault == nil {
			return nil
		}
		return f.fault(op, path)
	}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(j.Close)
	now := time.Now().UTC().Truncate(time.Second)
	add := func(ago time.Duration, client, mac, name, result, group string) {
		j.Add(dnsjournal.Record{Time: now.Add(-ago), Client: client, MAC: mac, Name: name, QType: 1, Result: result, Group: group, ElapsedMS: 2, Answers: 1})
	}
	for i := 0; i < 6; i++ {
		add(time.Duration(i)*time.Minute, "192.0.2.10", "02:00:00:00:00:01", fmt.Sprintf("%s-%d.example.com", dnsMarker, i), dnsjournal.ResultAnswered, "default")
	}
	add(30*time.Second, "192.0.2.10", "", dnsMarker+"-nomac.example.com", dnsjournal.ResultNoAnswer, "domestic")
	add(40*time.Second, "192.0.2.10", "02:00:00:00:00:99", dnsMarker+"-other.example.com", dnsjournal.ResultAnswered, "default")
	add(50*time.Second, "192.0.2.11", "02:00:00:00:00:02", dnsMarker+"-slow.example.com", dnsjournal.ResultNoAnswerSlow, "g_hk1")
	add(20*time.Hour, "2001:db8:1::20", "02:00:00:00:00:03", dnsMarker+"-v6.example.com", dnsjournal.ResultAnswered, "default")
	j.Flush()
	f.j = j
	s.DNSLog = f
	return s, f, now
}

func getDNSView(t *testing.T, s *Server) dnsLogView {
	t.Helper()
	rr := do(s, http.MethodGet, "/api/dns-log", nil)
	var v dnsLogView
	if rr.Code != 200 || json.Unmarshal(rr.Body.Bytes(), &v) != nil {
		t.Fatalf("%d %s", rr.Code, rr.Body.String())
	}
	return v
}

// GET/PUT /api/dns-log: off by default; the capability gate with its reason;
// enabling needs an acknowledgement and an available capability.
func TestDNSLogSwitchAndCapability(t *testing.T) {
	s, _ := importServer(t)
	v := getDNSView(t, s)
	if v.Setting.Enabled || v.Installed.Enabled || v.Pending != "" || v.Capability.Available || v.Capability.Code != codeDNSLogAgentUnavailable || v.Capability.Reason == "" ||
		v.Bounds.MaxRecords != 50000 || v.Bounds.MaxAgeS != 86400 || v.Bounds.Budget.Total != 32<<20 || v.Bounds.DiskBytes != 30<<20 || v.QTypes["28"] != "AAAA" || len(v.Groups) < 2 {
		t.Fatalf("%+v", v)
	}
	sc, _ := json.Marshal(v.Scope)
	for _, want := range []string{"被规则拦下", "各出口节点", "32 MiB", "默认关闭", "仅按地址", "分不开"} {
		if !strings.Contains(string(sc), want) {
			t.Errorf("scope does not say %q", want)
		}
	}
	put := func(body string) (int, string) {
		rr := do(s, http.MethodPut, "/api/dns-log", []byte(body))
		return rr.Code, rr.Body.String()
	}
	stored := func() bool {
		tp, _ := s.topology()
		return tp.DNSLogOn()
	}
	// No agent: cannot be enabled.
	if c, b := put(`{"enabled":true,"acknowledge":true}`); c != http.StatusConflict || !strings.Contains(b, codeDNSLogUnavailable) || stored() {
		t.Fatalf("%d %s", c, b)
	}
	f := &fakeDNSLog{st: unverifiedStatus()}
	s.DNSLog = f
	v = getDNSView(t, s)
	if v.Capability.Available || v.Capability.Code != dnsjournal.CodeVersionUnproven || !strings.Contains(v.Capability.Reason, "1.2026.08.05-0921") || v.Capability.Action == "" || v.Capability.Facts == nil {
		t.Fatalf("%+v", v.Capability)
	}
	if c, b := put(`{"enabled":true,"acknowledge":true}`); c != http.StatusConflict || !strings.Contains(b, "没有核对过") || stored() {
		t.Fatalf("unverified version enabled: %d %s", c, b)
	}
	for _, e := range []error{hostexec.ErrDNSJournalUnsupported, fmt.Errorf("%w：x", hostexec.ErrUnavailable), errors.New("boom")} {
		s.DNSLog = &fakeDNSLog{err: e}
		if v := getDNSView(t, s); v.Capability.Available || v.Capability.Code == "" || v.Runtime.Available {
			t.Fatalf("%v: %+v", e, v.Capability)
		}
		if c, _ := put(`{"enabled":true,"acknowledge":true}`); c != http.StatusConflict || stored() {
			t.Fatalf("%v: enabled", e)
		}
	}
	f.st = verifiedStatus()
	s.DNSLog = f
	for _, bad := range []string{`{}`, `{"enabled":true}`, `{"enabled":true,"acknowledge":false}`, `not json`, ``} {
		if c, _ := put(bad); c != http.StatusBadRequest || stored() {
			t.Fatalf("%q: %d", bad, c)
		}
	}
	c, b := put(`{"enabled":true,"acknowledge":true}`)
	if c != 200 || !stored() {
		t.Fatalf("%d %s", c, b)
	}
	v = getDNSView(t, s)
	if !v.Setting.Enabled || v.Installed.Enabled || !v.Installed.Known || v.Pending != "enable" || !v.Capability.Available || v.Capability.VerifiedBy != "builtin" {
		t.Fatalf("%+v", v)
	}
	raw, _, _ := s.Store.Get("topology")
	if !strings.Contains(raw, `"dns_log":{"enabled":true}`) {
		t.Fatal("the switch is not in the stored topology")
	}
	// Off needs no acknowledgement and no capability, and leaves no trace.
	f.st = unverifiedStatus()
	if c, b := put(`{"enabled":false}`); c != 200 || stored() {
		t.Fatalf("%d %s", c, b)
	}
	if raw, _, _ := s.Store.Get("topology"); strings.Contains(raw, "dns_log") {
		t.Fatal("the setting, off, stays in the stored topology")
	}
}

// The journal endpoints: paging and filters passed through, invalid and
// unknown parameters refused before the agent is asked, the summary with
// the shared device labels, the clear only with confirmation.
func TestDNSLogJournalAPI(t *testing.T) {
	s, f, now := dnsRig(t)
	var v struct {
		Available bool                  `json:"available"`
		Code      string                `json:"code"`
		Page      dnsjournal.Page       `json:"page"`
		Summary   dnsjournal.Summary    `json:"summary"`
		Labels    []model.DeviceLabel   `json:"labels"`
		Groups    []compile.DNSLogGroup `json:"groups"`
	}
	get := func(path string) int {
		t.Helper()
		rr := do(s, http.MethodGet, path, nil)
		v.Page, v.Summary, v.Labels = dnsjournal.Page{}, dnsjournal.Summary{}, nil
		if rr.Code == 200 {
			if err := json.Unmarshal(rr.Body.Bytes(), &v); err != nil {
				t.Fatal(err)
			}
		}
		return rr.Code
	}
	if c := get("/api/dns-log/journal?device=192.0.2.10&limit=3"); c != 200 || !v.Available || v.Page.Matched != 8 || len(v.Page.Records) != 3 || v.Page.NextBefore == 0 || len(v.Groups) < 2 {
		t.Fatalf("%d %+v", c, v.Page)
	}
	next := v.Page.NextBefore
	if c := get(fmt.Sprintf("/api/dns-log/journal?device=192.0.2.10&limit=3&before=%d", next)); c != 200 || len(v.Page.Records) != 3 || v.Page.Records[0].ID >= next {
		t.Fatalf("second page %d %+v", c, v.Page)
	}
	for path, want := range map[string]int{
		"/api/dns-log/journal":                                                  10,
		"/api/dns-log/journal?result=no_answer_any":                             2,
		"/api/dns-log/journal?result=no_answer_slow":                            1,
		"/api/dns-log/journal?group=g_hk1":                                      1,
		"/api/dns-log/journal?mac=02:00:00:00:00:99":                            1,
		"/api/dns-log/journal?text=NOMAC":                                       1,
		"/api/dns-log/journal?device=2001:db8:1::20":                            1,
		"/api/dns-log/journal?from=" + now.Add(-time.Hour).Format(time.RFC3339): 9,
		"/api/dns-log/journal?to=" + now.Add(-time.Hour).Format(time.RFC3339):   1,
	} {
		if c := get(path); c != 200 || v.Page.Matched != want {
			t.Errorf("%s: %d matched %d, want %d", path, c, v.Page.Matched, want)
		}
	}
	asked := len(f.asked)
	for _, bad := range []string{"?device=nope", "?result=failed", "?group=a%20b", "?mac=zz", "?limit=100000", "?before=x", "?path=/etc/passwd", "?file=audit.log",
		"?from=yesterday", "?device=192.0.2.10&device=192.0.2.11", "?text=" + strings.Repeat("x", 80)} {
		if rr := do(s, http.MethodGet, "/api/dns-log/journal"+bad, nil); rr.Code != http.StatusBadRequest {
			t.Errorf("%s: %d", bad, rr.Code)
		}
	}
	if len(f.asked) != asked {
		t.Fatal("a refused query reached the agent")
	}
	// The summary, with the connection journal's labels.
	if rr := do(s, http.MethodPut, "/api/sniff/devices/192.0.2.10/label", []byte(`{"label":"书房电脑"}`)); rr.Code != 200 {
		t.Fatal(rr.Body.String())
	}
	if c := get("/api/dns-log/devices"); c != 200 || len(v.Summary.Devices) != 3 || len(v.Labels) != 1 || v.Labels[0].Label != "书房电脑" {
		t.Fatalf("%d %+v %+v", c, v.Summary, v.Labels)
	}
	d := v.Summary.Devices[0]
	if d.Device != "192.0.2.10" || d.Total != 8 || len(d.MACs) != 2 || d.NoMAC != 1 || d.ByResult[dnsjournal.ResultNoAnswer] != 1 {
		t.Fatalf("%+v", d)
	}
	if c := get("/api/dns-log/devices?from=" + now.Add(-time.Hour).Format(time.RFC3339)); c != 200 || len(v.Summary.Devices) != 2 {
		t.Fatalf("%d %d", c, len(v.Summary.Devices))
	}
	for _, bad := range []string{"?device=192.0.2.10", "?from=x", "?from=a&from=b"} {
		if rr := do(s, http.MethodGet, "/api/dns-log/devices"+bad, nil); rr.Code != http.StatusBadRequest {
			t.Errorf("devices%s: %d", bad, rr.Code)
		}
	}
	// Clear: only with the confirmation.
	for _, body := range []string{``, `{}`, `{"confirm":false}`} {
		if rr := do(s, http.MethodPost, "/api/dns-log/clear", []byte(body)); rr.Code != http.StatusBadRequest {
			t.Fatalf("clear %q: %d", body, rr.Code)
		}
	}
	if f.clears != 0 {
		t.Fatal("cleared without confirmation")
	}
	if rr := do(s, http.MethodPost, "/api/dns-log/clear", []byte(`{"confirm":true}`)); rr.Code != 200 || f.clears != 1 || !strings.Contains(rr.Body.String(), `"cleared":10`) {
		t.Fatalf("%d %s", rr.Code, rr.Body.String())
	}
	if c := get("/api/dns-log/journal"); c != 200 || v.Page.Matched != 0 {
		t.Fatalf("after clear: %d", v.Page.Matched)
	}
	// No reader: said so, not an error.
	f.j = nil
	if c := get("/api/dns-log/journal"); c != 200 || v.Available || v.Code != "no_socket" {
		t.Fatalf("%d %+v", c, v)
	}
	s.DNSLog = nil
	if c := get("/api/dns-log/devices"); c != 200 || v.Available || v.Code != codeDNSLogAgentUnavailable {
		t.Fatalf("%d %+v", c, v)
	}
	if rr := do(s, http.MethodPost, "/api/dns-log/clear", []byte(`{"confirm":true}`)); rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("clear without an agent: %d", rr.Code)
	}
}

// Every endpoint requires the panel token.
func TestDNSLogAuth(t *testing.T) {
	s, f, _ := dnsRig(t)
	s.Token = strings.Repeat("k", 32)
	at := time.Now().UTC().Format(time.RFC3339)
	for _, c := range []struct{ method, path, body string }{
		{"GET", "/api/dns-log", ""}, {"PUT", "/api/dns-log", `{"enabled":true,"acknowledge":true}`},
		{"GET", "/api/dns-log/journal", ""}, {"GET", "/api/dns-log/devices", ""}, {"POST", "/api/dns-log/clear", `{"confirm":true}`},
		{"GET", "/api/dns-log/related?device=192.0.2.10&at=" + at, ""}, {"GET", "/api/sniff/journal/related?device=192.0.2.10&at=" + at, ""},
	} {
		var b []byte
		if c.body != "" {
			b = []byte(c.body)
		}
		if rr := do(s, c.method, c.path, b); rr.Code != http.StatusUnauthorized || strings.Contains(rr.Body.String(), dnsMarker) {
			t.Errorf("%s %s: %d", c.method, c.path, rr.Code)
		}
	}
	if tp, _ := s.topology(); f.clears != 0 || tp.DNSLogOn() || len(f.asked) != 0 {
		t.Fatal("something happened without the token")
	}
}

// Cross-linking in both directions: by address and a bounded time window,
// with the MAC deciding which of the address's records are the same device.
func TestLogRelated(t *testing.T) {
	s, f, now := dnsRig(t)
	cj, err := sniff.OpenJournal(sniff.JournalConfig{Dir: t.TempDir(), RecordNames: true})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(cj.Close)
	conn := func(ago time.Duration, src, mac, name string) {
		cj.Add(sniff.ConnRecord{Start: now.Add(-ago), Source: src, MAC: mac, Dest: "198.51.100.7:443", Proto: "tls", Name: name, Sniffed: true, By: "name",
			Target: "group:hk", Result: "ok", End: "client_closed"})
	}
	conn(20*time.Second, "192.0.2.10", "02:00:00:00:00:01", "c-same.example.com")
	conn(25*time.Second, "192.0.2.10", "", "c-nomac.example.com")
	conn(35*time.Second, "192.0.2.10", "02:00:00:00:00:99", "c-other.example.com")
	conn(30*time.Second, "192.0.2.11", "02:00:00:00:00:02", "c-device2.example.com")
	conn(3*time.Hour, "192.0.2.10", "02:00:00:00:00:01", "c-old.example.com")
	cj.Flush()
	s.Sniff = &fakeJournalRT{j: cj}

	type view struct {
		relatedView
		Records []json.RawMessage `json:"records"`
	}
	get := func(path string) (view, string) {
		t.Helper()
		rr := do(s, http.MethodGet, path, nil)
		var v view
		if rr.Code != 200 || json.Unmarshal(rr.Body.Bytes(), &v) != nil {
			t.Fatalf("%s: %d %s", path, rr.Code, rr.Body.String())
		}
		return v, rr.Body.String()
	}
	at := now.Add(-30 * time.Second).Format(time.RFC3339)
	// From a query to the connections around it.
	v, body := get("/api/dns-log/related?device=192.0.2.10&mac=02:00:00:00:00:01&at=" + at)
	if !v.Available || v.Listed != 2 || len(v.Records) != 2 || v.OtherMAC != 1 || v.NoMAC != 1 || v.Identity != "partial" || v.WindowS != 120 || v.More ||
		!strings.Contains(body, "c-same.example.com") || !strings.Contains(body, "c-nomac.example.com") || strings.Contains(body, "c-other.example.com") ||
		strings.Contains(body, "c-device2") || strings.Contains(body, "c-old") {
		t.Fatalf("%+v\n%s", v.relatedView, body)
	}
	// No MAC on the query: by address only, and said so.
	v, body = get("/api/dns-log/related?device=192.0.2.10&at=" + at)
	if v.Listed != 3 || v.OtherMAC != 0 || v.Identity != "address" || !strings.Contains(body, "c-other.example.com") {
		t.Fatalf("%+v", v.relatedView)
	}
	// The other device that had the address: only its own.
	v, body = get("/api/dns-log/related?device=192.0.2.10&mac=02:00:00:00:00:99&window=60&at=" + at)
	if v.Listed != 2 || v.OtherMAC != 1 || !strings.Contains(body, "c-other.example.com") || strings.Contains(body, "c-same.example.com") || v.WindowS != 60 {
		t.Fatalf("%+v", v.relatedView)
	}
	// A window that holds nothing.
	if v, _ := get("/api/dns-log/related?device=192.0.2.10&window=5&at=" + now.Add(-time.Hour).Format(time.RFC3339)); v.Listed != 0 || !v.Available || v.Identity != "address" {
		t.Fatalf("%+v", v.relatedView)
	}

	// From a connection to the queries around it.
	v, body = get("/api/sniff/journal/related?device=192.0.2.10&mac=02:00:00:00:00:01&at=" + at)
	if !v.Available || v.OtherMAC != 1 || v.NoMAC != 1 || v.Identity != "partial" || v.Listed != 4 ||
		strings.Contains(body, dnsMarker+"-other") || !strings.Contains(body, dnsMarker+"-nomac") || !strings.Contains(body, dnsMarker+"-0.") || strings.Contains(body, dnsMarker+"-slow") {
		t.Fatalf("%+v\n%s", v.relatedView, body)
	}
	last := f.asked[len(f.asked)-1]
	if last.Device != "192.0.2.10" || last.From == "" || last.To == "" || last.Limit != relatedLimit || last.Text != "" {
		t.Fatalf("the agent was asked %+v", last)
	}
	if from, _ := time.Parse(time.RFC3339, last.From); now.Add(-30*time.Second).Sub(from) != 120*time.Second {
		t.Fatalf("window: from %s", last.From)
	}
	v, _ = get("/api/sniff/journal/related?device=192.0.2.11&mac=02:00:00:00:00:02&at=" + at)
	if v.Listed != 1 || v.Identity != "mac" || v.OtherMAC != 0 {
		t.Fatalf("%+v", v.relatedView)
	}
	// Validation: both directions, the same parameters.
	for _, p := range []string{"/api/dns-log/related", "/api/sniff/journal/related"} {
		for _, bad := range []string{"", "?device=192.0.2.10", "?at=" + at, "?device=nope&at=" + at, "?device=192.0.2.10&at=noon", "?device=192.0.2.10&mac=zz&at=" + at,
			"?device=192.0.2.10&window=0&at=" + at, "?device=192.0.2.10&window=601&at=" + at, "?device=192.0.2.10&window=x&at=" + at,
			"?device=192.0.2.10&limit=5&at=" + at, "?device=192.0.2.10&text=x&at=" + at} {
			if rr := do(s, http.MethodGet, p+bad, nil); rr.Code != http.StatusBadRequest {
				t.Errorf("%s%s: %d", p, bad, rr.Code)
			}
		}
	}
	// One side not available: said so, no error.
	f.j = nil
	if v, _ := get("/api/sniff/journal/related?device=192.0.2.10&at=" + at); v.Available || v.Code != "no_socket" || v.Listed != 0 {
		t.Fatalf("%+v", v.relatedView)
	}
	s.Sniff = nil
	if v, _ := get("/api/dns-log/related?device=192.0.2.10&at=" + at); v.Available || v.Code != "agent_unavailable" {
		t.Fatalf("%+v", v.relatedView)
	}
}

// The whole lifecycle through preflight and install: on and off both show
// in the pre-check and take effect only with an install; an unavailable
// capability blocks; a cancelled pre-check and a failed install change
// nothing; the records are deleted only after the install that turned the
// journal off has succeeded.
func TestDNSLogInstallLifecycle(t *testing.T) {
	s, host, activated := installTest(t)
	hp := &fakeHostPreflight{}
	s.HostPreflight = hp
	f := &fakeDNSLog{st: verifiedStatus()}
	s.DNSLog = f
	type pfOut struct{ Preflight preflightRecord }
	pre := func() preflightRecord {
		t.Helper()
		rr := do(s, http.MethodPost, "/api/host/preflight", nil)
		var out pfOut
		if rr.Code != 200 || json.Unmarshal(rr.Body.Bytes(), &out) != nil {
			t.Fatalf("preflight: %d %s", rr.Code, rr.Body.String())
		}
		return out.Preflight
	}
	finding := func(p preflightRecord, code string) *preflight.Finding {
		for i := range p.Findings {
			if p.Findings[i].Code == code {
				return &p.Findings[i]
			}
		}
		return nil
	}
	install := func(id string) (int, string) {
		t.Helper()
		rr := do(s, http.MethodPost, "/api/apply", mustJSON(map[string]any{"install": true, "preflight_id": id}))
		return rr.Code, rr.Body.String()
	}
	hostFile := func(rel string) string {
		b, _ := os.ReadFile(filepath.Join(host, rel))
		return string(b)
	}
	const conf, unit = "etc/smartdns/smartdns.conf", "etc/systemd/system/" + compile.DNSJournalUnit

	// A first install with the journal off: nothing of it on the host.
	p := pre()
	if finding(p, "dns_log_enable") != nil || finding(p, "dns_log_disable") != nil || finding(p, codeDNSLogBlocked) != nil {
		t.Fatalf("%+v", p.Findings)
	}
	if c, b := install(p.ID); c != 200 || *activated != 1 {
		t.Fatalf("%d %s", c, b)
	}
	baseConf := hostFile(conf)
	if baseConf == "" || strings.Contains(baseConf, "audit-") || hostFile(unit) != "" || f.clears != 0 {
		t.Fatal("the journal is on the host while off")
	}
	raw, err := os.ReadFile("../preflight/testdata/gateway-installed.txt")
	if err != nil {
		t.Fatal(err)
	}
	hp.mu.Lock()
	hp.raw = string(raw)
	hp.mu.Unlock()

	// On: saved, shown by the pre-check, not on the host before the install.
	if rr := do(s, http.MethodPut, "/api/dns-log", []byte(`{"enabled":true,"acknowledge":true}`)); rr.Code != 200 {
		t.Fatal(rr.Body.String())
	}
	if v := getDNSView(t, s); v.Pending != "enable" || v.Installed.Enabled {
		t.Fatalf("%+v", v)
	}
	p = pre()
	en := finding(p, "dns_log_enable")
	if p.Blocking || en == nil || en.Severity != preflight.Info || !strings.Contains(en.Message, "重启一次") || !strings.Contains(en.Message, "1.2026.11.09-1240") || p.FileChanges == nil {
		t.Fatalf("%+v", p.Findings)
	}
	if strings.Join(p.FileChanges.Changed, " ") != "/"+conf+" /usr/local/sbin/meridian-verify.sh" || strings.Join(p.FileChanges.Added, " ") != "/"+unit || len(p.FileChanges.Removed) != 0 {
		t.Fatalf("on: changed %v added %v removed %v", p.FileChanges.Changed, p.FileChanges.Added, p.FileChanges.Removed)
	}
	if hostFile(conf) != baseConf || hostFile(unit) != "" {
		t.Fatal("the pre-check changed the host")
	}
	// The capability goes away between the review and the install (the
	// resolver image was replaced): the install is refused, nothing written.
	f.st = unverifiedStatus()
	if c, b := install(p.ID); c != http.StatusConflict || codeOf(t, []byte(b)) != codePreflightBlocked || !strings.Contains(b, codeDNSLogBlocked) || !strings.Contains(b, "1.2026.08.05-0921") || *activated != 1 {
		t.Fatalf("unverified resolver installed: %d %s", c, b)
	}
	if hostFile(conf) != baseConf {
		t.Fatal("a refused install wrote the audit config")
	}
	if p2 := pre(); !p2.Blocking || finding(p2, codeDNSLogBlocked) == nil || finding(p2, codeDNSLogBlocked).Severity != preflight.Blocking || !strings.Contains(finding(p2, codeDNSLogBlocked).Action, "关闭解析日志") {
		t.Fatalf("%+v", p2.Findings)
	}
	f.st = verifiedStatus()
	p = pre()
	c, b := install(p.ID)
	if c != 200 || *activated != 2 || !strings.Contains(b, compile.DNSJournalUnit) {
		t.Fatalf("%d %s", c, b)
	}
	onConf := hostFile(conf)
	if !compile.SmartDNSAuditOn(onConf) || !strings.Contains(hostFile(unit), "dns-journal --prepare") || f.clears != 0 {
		t.Fatal("the journal was not installed")
	}
	if v := getDNSView(t, s); !v.Installed.Enabled || v.Pending != "" || !v.Setting.Enabled {
		t.Fatalf("%+v", v)
	}
	// On and unchanged: the pre-check announces nothing and changes nothing.
	if p := pre(); finding(p, "dns_log_enable") != nil || len(p.FileChanges.Changed)+len(p.FileChanges.Added)+len(p.FileChanges.Removed) != 0 {
		t.Fatalf("%+v %+v", p.Findings, p.FileChanges)
	}
	// Still recording with a resolver that is no longer verified: said so.
	if v := getDNSView(t, s); v.Runtime.Code != "not_running" {
		t.Fatalf("%+v", v.Runtime)
	}
	f.st = unverifiedStatus()
	f.st.Present, f.st.AuditInstalled = true, true
	if v := getDNSView(t, s); v.Runtime.Code != "unverified_running" || !strings.Contains(v.Runtime.Message, "没有核对过") {
		t.Fatalf("%+v", v.Runtime)
	}
	f.st = verifiedStatus()

	// Off: saved; the pre-check says what will happen; cancelled (no
	// install): still collecting, nothing deleted.
	if rr := do(s, http.MethodPut, "/api/dns-log", []byte(`{"enabled":false}`)); rr.Code != 200 {
		t.Fatal(rr.Body.String())
	}
	p = pre()
	dis := finding(p, "dns_log_disable")
	if p.Blocking || dis == nil || !strings.Contains(dis.Message, "安装成功之后删除") || !strings.Contains(dis.Message, "取消") ||
		strings.Join(p.FileChanges.Removed, " ") != "/"+unit || strings.Join(p.FileChanges.Changed, " ") != "/"+conf+" /usr/local/sbin/meridian-verify.sh" {
		t.Fatalf("off: %+v %+v", p.Findings, p.FileChanges)
	}
	if v := getDNSView(t, s); !v.Installed.Enabled || v.Pending != "disable" || v.Setting.Enabled {
		t.Fatalf("%+v", v)
	}
	if hostFile(conf) != onConf || hostFile(unit) == "" || f.clears != 0 {
		t.Fatal("a cancelled pre-check stopped the collection or deleted records")
	}
	// The install that would turn it off fails and is compensated: still
	// on, nothing deleted.
	okActivate := s.Activate
	fail := true
	s.Activate = func() error {
		if fail {
			fail = false
			return errors.New("meridian-systemd-missing: cannot restart")
		}
		return okActivate()
	}
	if c, b := install(p.ID); c != http.StatusInternalServerError || !strings.Contains(b, `"compensated":true`) {
		t.Fatalf("%d %s", c, b)
	}
	if hostFile(conf) != onConf || hostFile(unit) == "" || f.clears != 0 {
		t.Fatal("a failed install stopped the collection or deleted records")
	}
	if v := getDNSView(t, s); !v.Installed.Enabled || v.Pending != "disable" {
		t.Fatalf("%+v", v)
	}
	// The install succeeds: the config is the one from before, the reader is
	// gone, and only now the records are deleted — once.
	s.Activate = okActivate
	p = pre()
	if c, b := install(p.ID); c != 200 {
		t.Fatalf("%d %s", c, b)
	}
	if hostFile(conf) != baseConf || hostFile(unit) != "" {
		t.Fatal("off did not restore the files")
	}
	if f.clears != 1 {
		t.Fatalf("records deleted %d times after the off install", f.clears)
	}
	if v := getDNSView(t, s); v.Installed.Enabled || v.Pending != "" {
		t.Fatalf("%+v", v)
	}
	// Later installs do not ask again.
	p = pre()
	if c, _ := install(p.ID); c != 200 || f.clears != 1 {
		t.Fatalf("%d clears %d", c, f.clears)
	}

	// On again, then off with a deletion that fails: the install stands and
	// says the records are still there.
	do(s, http.MethodPut, "/api/dns-log", []byte(`{"enabled":true,"acknowledge":true}`))
	if c, b := install(pre().ID); c != 200 {
		t.Fatalf("%d %s", c, b)
	}
	do(s, http.MethodPut, "/api/dns-log", []byte(`{"enabled":false}`))
	f.clearErr = "磁盘只读"
	c, b = install(pre().ID)
	if c != 200 || f.clears != 2 || !strings.Contains(b, "没有删除") || !strings.Contains(b, "清空") {
		t.Fatalf("%d %s", c, b)
	}
	// A runtime rollback to the snapshot that had it on brings the reader
	// back (through the same agent-side guard) and deletes nothing; rolling
	// forward again to the one without it deletes.
	f.clearErr = ""
	if rr := do(s, http.MethodPost, "/api/rollback", []byte(`{"install":true}`)); rr.Code != 200 || hostFile(unit) == "" || f.clears != 2 {
		t.Fatalf("rollback to on: %d %s (clears %d)", rr.Code, rr.Body.String(), f.clears)
	}
	if rr := do(s, http.MethodPost, "/api/rollback", []byte(`{"install":true}`)); rr.Code != 200 || hostFile(unit) != "" || f.clears != 3 {
		t.Fatalf("rollback to off: %d %s (clears %d)", rr.Code, rr.Body.String(), f.clears)
	}
}

// The switch is an independent resource: a whole-document save, an import
// included, never changes it.
func TestDNSLogTopologyContract(t *testing.T) {
	s, _ := importServer(t)
	s.DNSLog = &fakeDNSLog{st: verifiedStatus()}
	doc := func(mut func(m map[string]any)) []byte {
		rr := do(s, http.MethodGet, "/api/topology", nil)
		var m map[string]any
		if err := json.Unmarshal(rr.Body.Bytes(), &m); err != nil {
			t.Fatal(err)
		}
		mut(m["settings"].(map[string]any))
		return mustJSON(m)
	}
	on := func() bool {
		tp, _ := s.topology()
		return tp.DNSLogOn()
	}
	for _, path := range []string{"/api/topology", "/api/topology?import=1", "/api/topology?draft=1"} {
		rr := do(s, http.MethodPut, path, doc(func(st map[string]any) { st["dns_log"] = map[string]any{"enabled": true} }))
		if rr.Code != http.StatusConflict || codeOf(t, rr.Body.Bytes()) != codeIndependentChanged || !strings.Contains(rr.Body.String(), "settings.dns_log") || !strings.Contains(rr.Body.String(), "/api/dns-log") || on() {
			t.Fatalf("%s turned the journal on: %d %s", path, rr.Code, rr.Body.String())
		}
	}
	// Omitted, null or equal: saved, the switch kept.
	for _, mut := range []func(map[string]any){func(st map[string]any) {}, func(st map[string]any) { st["dns_log"] = nil }, func(st map[string]any) { st["dns_log"] = map[string]any{"enabled": false} }} {
		if rr := do(s, http.MethodPut, "/api/topology", doc(mut)); rr.Code != 200 || on() {
			t.Fatalf("%d %s", rr.Code, rr.Body.String())
		}
	}
	if rr := do(s, http.MethodPut, "/api/dns-log", []byte(`{"enabled":true,"acknowledge":true}`)); rr.Code != 200 || !on() {
		t.Fatal(rr.Body.String())
	}
	// A document without the field (the panel's own saves) keeps it on; one
	// that says off is refused.
	if rr := do(s, http.MethodPut, "/api/topology", doc(func(st map[string]any) { delete(st, "dns_log") })); rr.Code != 200 || !on() {
		t.Fatalf("%d %s", rr.Code, rr.Body.String())
	}
	if rr := do(s, http.MethodPut, "/api/topology?import=1", doc(func(st map[string]any) { delete(st, "dns_log") })); rr.Code != 200 || !on() {
		t.Fatalf("import without the field: %d %s", rr.Code, rr.Body.String())
	}
	if rr := do(s, http.MethodPut, "/api/topology", doc(func(st map[string]any) { st["dns_log"] = map[string]any{"enabled": false} })); rr.Code != http.StatusConflict || !on() {
		t.Fatalf("%d %s", rr.Code, rr.Body.String())
	}
	// A topology without a managed gateway cannot have it.
	if _, err := s.Store.Update(func(tp *model.Topology) (bool, error) {
		for i := range tp.Nodes {
			if tp.Nodes[i].Role == model.RoleGateway {
				tp.Nodes[i].Managed = false
			}
		}
		tp.Settings.DNSLog = nil
		return true, nil
	}); err != nil {
		t.Fatal(err)
	}
	if rr := do(s, http.MethodPut, "/api/dns-log", []byte(`{"enabled":true,"acknowledge":true}`)); rr.Code == 200 || on() {
		t.Fatalf("enabled without a managed gateway: %d", rr.Code)
	}
}

// Privacy: query-journal content (names, device addresses of the records)
// never appears in the topology, its compile output or diff, a preflight,
// the status reads or the panel's own log — only in the journal's own
// reads and the two related lookups.
func TestDNSLogNeverLeaves(t *testing.T) {
	s, f, now := dnsRig(t)
	s.HostRoot = t.TempDir()
	s.Activate = func() error { return nil }
	withPeerKeys(t, s)
	s.HostPreflight = &fakeHostPreflight{}
	var logs bytes.Buffer
	log.SetOutput(&logs)
	defer log.SetOutput(os.Stderr)
	if rr := do(s, http.MethodPut, "/api/dns-log", []byte(`{"enabled":true,"acknowledge":true}`)); rr.Code != 200 {
		t.Fatal(rr.Body.String())
	}
	// The journal is read first, so any cache or log would hold it by now.
	at := now.Add(-30 * time.Second).Format(time.RFC3339)
	own := []string{"/api/dns-log/journal", "/api/dns-log/devices", "/api/dns-log/journal?device=192.0.2.10&text=marker", "/api/sniff/journal/related?device=192.0.2.10&at=" + at}
	for _, p := range own {
		if rr := do(s, http.MethodGet, p, nil); rr.Code != 200 || !strings.Contains(rr.Body.String(), dnsMarker) {
			t.Fatalf("%s: %d %s", p, rr.Code, rr.Body.String())
		}
	}
	check := func(what, body string) {
		t.Helper()
		for _, leak := range []string{dnsMarker, "02:00:00:00:00:99"} {
			if strings.Contains(body, leak) {
				t.Errorf("%s contains query-journal content (%s)", what, leak)
			}
		}
	}
	check("GET /api/dns-log", do(s, http.MethodGet, "/api/dns-log", nil).Body.String())
	for _, p := range demoGets {
		check("GET "+p, do(s, http.MethodGet, p, nil).Body.String())
	}
	for _, p := range demoPosts {
		check("POST "+p.path, do(s, http.MethodPost, p.path, []byte(p.body)).Body.String())
	}
	check("POST /api/compile", do(s, http.MethodPost, "/api/compile", []byte(`{}`)).Body.String())
	check("POST /api/diff", do(s, http.MethodPost, "/api/diff", []byte(`{}`)).Body.String())
	// A preflight and an install with the journal on, and what they store.
	rr := do(s, http.MethodPost, "/api/host/preflight", nil)
	check("POST /api/host/preflight", rr.Body.String())
	var out struct{ Preflight preflightRecord }
	json.Unmarshal(rr.Body.Bytes(), &out)
	rr = do(s, http.MethodPost, "/api/apply", mustJSON(map[string]any{"install": true, "preflight_id": out.Preflight.ID}))
	if rr.Code != 200 {
		t.Fatalf("install: %d %s", rr.Code, rr.Body.String())
	}
	check("POST /api/apply", rr.Body.String())
	check("GET /api/host", do(s, http.MethodGet, "/api/host", nil).Body.String())
	check("GET /api/topology (export)", do(s, http.MethodGet, "/api/topology", nil).Body.String())
	// Everything the panel stores and everything it wrote to the host and
	// its data directory.
	for _, key := range []string{"topology", deviceLabelsKey, preflightKey(localNodeID)} {
		raw, _, _ := s.Store.Get(key)
		check("stored "+key, raw)
	}
	for _, root := range []string{s.HostRoot, s.DataDir} {
		filepath.Walk(root, func(p string, fi os.FileInfo, err error) error {
			if err != nil || !fi.Mode().IsRegular() || strings.HasSuffix(p, ".db") || strings.Contains(p, ".db-") {
				return nil
			}
			if b, err := os.ReadFile(p); err == nil {
				check("file "+p, string(b))
			}
			return nil
		})
	}
	// A clear, and a failed read, log nothing of the content either.
	do(s, http.MethodPost, "/api/dns-log/clear", []byte(`{"confirm":true}`))
	f.err = errors.New("agent failure")
	do(s, http.MethodGet, "/api/dns-log", nil)
	check("panel log", logs.String())
}

// POST /api/dns-log/clear tells a complete clear from one that left
// something: 200 {"complete": true} only for the first; otherwise an error
// with "complete": false, what is left (counts) and why (fixed words) — no
// path, no file name, no journal content — the records that are still there
// stay readable, GET /api/dns-log keeps the residue in view, and the same
// request asked again completes.
func TestDNSLogClearIncomplete(t *testing.T) {
	s, f, _ := dnsRig(t)
	var logs bytes.Buffer
	log.SetOutput(&logs)
	defer log.SetOutput(os.Stderr)
	clear := func() (int, map[string]json.RawMessage, string) {
		t.Helper()
		rr := do(s, http.MethodPost, "/api/dns-log/clear", []byte(`{"confirm":true}`))
		var m map[string]json.RawMessage
		if err := json.Unmarshal(rr.Body.Bytes(), &m); err != nil {
			t.Fatalf("%d %s", rr.Code, rr.Body.String())
		}
		return rr.Code, m, rr.Body.String()
	}
	noLeak := func(what, body string) {
		t.Helper()
		for _, leak := range []string{dnsMarker, "example.com", "192.0.2.", "2001:db8", ".jsonl", "dns-0", "/journal", s.DataDir, "denied", "unlinkat", "remove /"} {
			if strings.Contains(body, leak) {
				t.Fatalf("%s carries %q: %s", what, leak, body)
			}
		}
	}

	// A segment cannot be deleted.
	f.fault = func(op, path string) error {
		if op == "remove" {
			return &os.PathError{Op: "unlinkat", Path: path, Err: syscall.EACCES}
		}
		return nil
	}
	code, m, body := clear()
	var residual dnsjournal.ClearResidual
	var errs []dnsjournal.ClearError
	if code != http.StatusInternalServerError || string(m["code"]) != `"`+codeDNSLogClearIncomplete+`"` || string(m["complete"]) != "false" ||
		json.Unmarshal(m["residual"], &residual) != nil || residual.Records != 10 || residual.Segments == 0 || residual.Bytes == 0 ||
		json.Unmarshal(m["errors"], &errs) != nil || len(errs) != 1 || errs[0].Part != dnsjournal.PartJournal || errs[0].Op != "remove" || errs[0].Cause != "permission" {
		t.Fatalf("%d %s", code, body)
	}
	for _, want := range []string{"没有全部清除", "10 条记录", "权限不足", "再清空一次"} {
		if !strings.Contains(body, want) {
			t.Fatalf("the message lacks %q: %s", want, body)
		}
	}
	noLeak("the answer", body)
	// Nothing is reported as gone that is still there.
	var v dnsJournalView
	rr := do(s, http.MethodGet, "/api/dns-log/journal?limit=200", nil)
	var page dnsjournal.Page
	if rr.Code != 200 || json.Unmarshal(rr.Body.Bytes(), &v) != nil || json.Unmarshal(v.Page, &page) != nil || page.Matched != 10 ||
		page.Stats.Residual == nil || page.Stats.Residual.Records != 10 || page.Stats.ClearedAt != nil {
		t.Fatalf("%d %s", rr.Code, rr.Body.String())
	}

	// The reader's health carries the residue (also after it restarted):
	// the status says so, with the counts.
	st := f.j.Stats()
	at := time.Now().UTC()
	f.st.Present = true
	f.st.Health = mustJSON(dnsjournal.Health{Ready: true, Journal: &st, Reader: dnsjournal.TailStats{Following: true, ClearPendingAt: &at, RawResidualFiles: 2, RawResidualBytes: 300}})
	view := getDNSView(t, s)
	if r := view.Runtime.ClearResidual; r == nil || r.Records != 10 || r.Segments != residual.Segments || r.RawFiles != 2 || r.RawBytes != 300 ||
		view.Runtime.Code != codeDNSLogResidual || !strings.Contains(view.Runtime.Message, "10 条记录") || !strings.Contains(view.Runtime.Message, "2 个文件") {
		t.Fatalf("%+v", view.Runtime)
	}
	noLeak("the status", view.Runtime.Message)

	// The retry, once the fault is gone: complete, and the status is clean.
	f.fault = nil
	if code, m, body = clear(); code != 200 || string(m["complete"]) != "true" || !strings.Contains(body, `"cleared":10`) {
		t.Fatalf("%d %s", code, body)
	}
	st = f.j.Stats()
	f.st.Health = mustJSON(dnsjournal.Health{Ready: true, Journal: &st, Reader: dnsjournal.TailStats{Following: true}})
	if view = getDNSView(t, s); view.Runtime.ClearResidual != nil || view.Runtime.Code != "" {
		t.Fatalf("%+v", view.Runtime)
	}

	// A reader that does not say whether it removed everything, and an
	// agent that could not clear at all: neither is a success.
	f.clearBody = `{"cleared":3,"raw_bytes":10}`
	if code, m, body = clear(); code != http.StatusServiceUnavailable || string(m["code"]) != `"`+codeDNSLogClearFailed+`"` || string(m["complete"]) != "false" || !strings.Contains(body, "不能当作已经清空") {
		t.Fatalf("%d %s", code, body)
	}
	f.clearBody = `{"complete":false,"cleared":0,"raw_bytes":0,"residual":{"segments":0,"records":0,"bytes":0,"raw_files":1,"raw_bytes":77},"errors":[{"part":"raw","op":"truncate","cause":"read_only","count":1}]}`
	if code, m, body = clear(); code != http.StatusInternalServerError || string(m["complete"]) != "false" || !strings.Contains(body, "审计文件截断失败（文件系统只读）") ||
		json.Unmarshal(m["residual"], &residual) != nil || residual.RawFiles != 1 || residual.RawBytes != 77 {
		t.Fatalf("%d %s", code, body)
	}
	f.clearBody, f.clearErr = "", "通道超时"
	if code, m, body = clear(); code != http.StatusServiceUnavailable || string(m["complete"]) != "false" || !strings.Contains(body, "没有清空") {
		t.Fatalf("%d %s", code, body)
	}
	f.clearErr = ""

	// The deletion after the install that turned the journal off: an
	// incomplete one is a warning that says what is left.
	f.clearBody = `{"complete":false,"cleared":4,"raw_bytes":0,"residual":{"segments":1,"records":6,"bytes":900,"raw_files":0,"raw_bytes":0},"errors":[{"part":"journal","op":"remove","cause":"busy","count":1}]}`
	rep := &apply.HostReport{Committed: true}
	rep.Diff.UnitsRemoved = []string{compile.DNSJournalUnit}
	if msg := s.dnsLogAfterCommit(rep); !strings.Contains(msg, "没有删除") || !strings.Contains(msg, "6 条记录") || !strings.Contains(msg, "文件被占用") || len(rep.Warnings) != 1 {
		t.Fatalf("%q %v", msg, rep.Warnings)
	}
	noLeak("the panel log", logs.String())
}
