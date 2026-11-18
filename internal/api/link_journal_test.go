package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/radowitz/meridian/internal/compile"
	"github.com/radowitz/meridian/internal/hostexec"
	"github.com/radowitz/meridian/internal/linkjournal"
	"github.com/radowitz/meridian/internal/model"
	"github.com/radowitz/meridian/internal/preflight"
)

// fakeLinkLog is the host agent's link-journal requests in front of a real
// linkjournal.Journal, answering the way hostexec.Agent passes the
// collector's answers on.
type fakeLinkLog struct {
	st     hostexec.LinkJournalStatus
	err    error
	j      *linkjournal.Journal
	clears int
	asked  []linkjournal.Query
}

func (f *fakeLinkLog) LinkJournalStatus(context.Context) (hostexec.LinkJournalStatus, error) {
	return f.st, f.err
}

func (f *fakeLinkLog) body(v any, err error) (hostexec.LinkJournalAnswer, error) {
	if f.err != nil {
		return hostexec.LinkJournalAnswer{}, f.err
	}
	if f.j == nil {
		return hostexec.LinkJournalAnswer{Code: "no_socket", Error: "链路日志采集服务没有运行（没有状态套接字）"}, nil
	}
	if err != nil {
		return hostexec.LinkJournalAnswer{Present: true, Code: "bad_request", Error: err.Error()}, nil
	}
	b, _ := json.Marshal(v)
	return hostexec.LinkJournalAnswer{Present: true, Body: b}, nil
}

func (f *fakeLinkLog) LinkJournalCurrent(context.Context) (hostexec.LinkJournalAnswer, error) {
	if f.j == nil {
		return f.body(nil, nil)
	}
	return f.body(f.j.Current(), nil)
}

func (f *fakeLinkLog) LinkJournal(_ context.Context, q linkjournal.Query) (hostexec.LinkJournalAnswer, error) {
	f.asked = append(f.asked, q)
	if f.j == nil {
		return f.body(nil, nil)
	}
	return f.body(f.j.Query(q))
}

func (f *fakeLinkLog) LinkJournalClear(context.Context) (hostexec.LinkJournalAnswer, error) {
	f.clears++
	if f.j == nil {
		return f.body(nil, nil)
	}
	return f.body(map[string]any{"cleared": f.j.Clear()}, nil)
}

const linkMarker = "link-marker"

func linkObs(class, kind, id, state, evidence string) linkjournal.Observation {
	return linkjournal.Observation{Class: class, Kind: kind, ID: id, Label: "label of " + id, State: state, Source: linkjournal.SourceUpstream, Evidence: evidence}
}

// linkRig: a server whose agent has a link journal: the gateway moved to
// the backup hub, a tunnel went stale and came back, an external exit's
// check is failing, one tunnel has not been read for a while.
func linkRig(t *testing.T) (*Server, *fakeLinkLog, time.Time) {
	t.Helper()
	s, _ := importServer(t)
	j, err := linkjournal.Open(linkjournal.Options{Dir: filepath.Join(t.TempDir(), "journal")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(j.Close)
	now := time.Now().UTC().Truncate(time.Second)
	pass := func(ago time.Duration, path, m00, ext string, withM01 bool) {
		obs := []linkjournal.Observation{
			linkObs(linkjournal.ClassPath, linkjournal.KindUpstream, linkjournal.GatewayID, path, linkMarker+" path "+path),
			linkObs(linkjournal.ClassPath, linkjournal.KindHealth, linkjournal.GatewayID, linkjournal.HealthOK, linkMarker+" health"),
			linkObs(linkjournal.ClassTunnel, linkjournal.KindTunnel, "m00", m00, linkMarker+" m00 "+m00),
			linkObs(linkjournal.ClassExternalExit, linkjournal.KindExternal, "ext1", ext, linkMarker+" ext1 "+ext),
		}
		if withM01 {
			obs = append(obs, linkObs(linkjournal.ClassTunnel, linkjournal.KindTunnel, "m01", linkjournal.TunnelOK, linkMarker+" m01"))
		}
		j.Observe(now.Add(-ago), obs)
	}
	// One pass a minute for an hour; m01 is read for the first ten minutes only.
	for m := 60; m >= 0; m-- {
		path, m00, ext := "udp", linkjournal.TunnelOK, linkjournal.CheckOK
		if m <= 40 {
			path = "backup"
		}
		if m <= 30 && m > 20 {
			m00 = linkjournal.TunnelStale
		}
		if m <= 15 {
			ext = linkjournal.CheckFailed
		}
		pass(time.Duration(m)*time.Minute, path, m00, ext, m >= 50)
	}
	f := &fakeLinkLog{j: j, st: hostexec.LinkJournalStatus{ReadAt: now.Format(time.RFC3339), UnitActive: "active", Present: true, ConfigInstalled: true, Health: json.RawMessage(`{"ready":true}`)}}
	s.LinkLog = f
	return s, f, now
}

func getLinkView(t *testing.T, s *Server) linkLogView {
	t.Helper()
	rr := do(s, http.MethodGet, "/api/link-log", nil)
	var v linkLogView
	if rr.Code != 200 || json.Unmarshal(rr.Body.Bytes(), &v) != nil {
		t.Fatalf("%d %s", rr.Code, rr.Body.String())
	}
	return v
}

// GET /api/link-log: bounds, the scope with its evidence, what is not in
// scope, the objects of the topology, and why there is no data when there
// is none.
func TestLinkLogView(t *testing.T) {
	s, _ := importServer(t)
	v := getLinkView(t, s)
	if v.Bounds.MaxEvents != 20000 || v.Bounds.MaxAgeS != 30*86400 || v.Bounds.Budget.Total != 16<<20 || v.Bounds.DiskBytes != 16<<20 ||
		v.Bounds.Budget.Events+v.Bounds.Budget.Checkpoint+v.Bounds.Budget.Rewrite != 16<<20 || v.Bounds.PageMax != linkjournal.PageMax {
		t.Fatalf("bounds: %+v", v.Bounds)
	}
	if v.Timing.IntervalS != 10 || v.Timing.SlowIntervalS != 30 || v.Timing.HandshakeStaleS != 180 || v.Timing.GapAfterS != 120 || v.Timing.SelfCheckEveryS != 900 || v.Timing.FlapAfter != 4 {
		t.Fatalf("timing: %+v", v.Timing)
	}
	if v.Runtime.Available || v.Runtime.Code != codeLinkLogAgentUnavailable || v.Runtime.Message == "" {
		t.Fatalf("without an agent: %+v", v.Runtime)
	}
	// Nothing is installed yet: the collector comes with the next install.
	if !v.Installed.Known || v.Installed.Enabled || v.Pending != "install" {
		t.Fatalf("installed: %+v pending %q", v.Installed, v.Pending)
	}
	classes := map[string]bool{}
	for _, src := range v.Scope.Sources {
		classes[src.Class] = true
		if src.Source == "" || src.How == "" || src.Cadence == "" || src.Evidence == "" || src.Strength == "" {
			t.Errorf("incomplete source row: %+v", src)
		}
	}
	for _, c := range []string{linkjournal.ClassPath, linkjournal.ClassRelay, linkjournal.ClassTunnel, linkjournal.ClassWSS, linkjournal.ClassExternalExit, linkjournal.ClassSniffTarget, linkjournal.ClassCollector} {
		if !classes[c] {
			t.Errorf("scope has no source for class %s", c)
		}
	}
	sc, _ := json.Marshal(v.Scope)
	for _, want := range []string{"meridian-ext-health", "不在网关宿主机上", "不是「代理已经确认不通」", "间接", "30 天", "16 MiB", "变化了 N 次", "空窗", "没有开关", "预检 → 确认 → 安装", "不含任何设备地址"} {
		if !strings.Contains(string(sc), want) {
			t.Errorf("scope does not say %q", want)
		}
	}
	if len(v.Scope.NotInScope) < 4 || len(v.Scope.Kinds) < 8 || v.Scope.Mode == "" || v.Scope.ModeNote == "" {
		t.Fatalf("scope: mode %q, %d excluded, %d kinds", v.Scope.Mode, len(v.Scope.NotInScope), len(v.Scope.Kinds))
	}
	// The objects are the topology's own: every gateway tunnel, the path.
	topo, _ := s.topology()
	info, err := compile.LinkJournalFor(topo, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(v.Objects) != len(info.Objects) || len(v.Objects) < 2 || len(info.Config.Tunnels) == 0 {
		t.Fatalf("%d objects, the compiler lists %d", len(v.Objects), len(info.Objects))
	}
	var tunnels int
	for _, o := range v.Objects {
		if o.Kind == linkjournal.KindTunnel {
			tunnels++
		}
		if o.Class == "" || o.Kind == "" || o.ID == "" || o.Label == "" {
			t.Errorf("incomplete object: %+v", o)
		}
	}
	if tunnels != len(info.Config.Tunnels) {
		t.Fatalf("%d tunnel objects, %d gateway tunnels", tunnels, len(info.Config.Tunnels))
	}

	// With an agent: old binary, unreachable, read failure, not running.
	f := &fakeLinkLog{err: hostexec.ErrLinkJournalUnsupported}
	s.LinkLog = f
	if v := getLinkView(t, s); v.Runtime.Available || v.Runtime.Code != codeLinkLogAgentOld || !strings.Contains(v.Runtime.Message, "install.sh") {
		t.Fatalf("old agent: %+v", v.Runtime)
	}
	f.err = hostexec.ErrUnavailable
	if v := getLinkView(t, s); v.Runtime.Code != codeLinkLogAgentUnavailable {
		t.Fatalf("%+v", v.Runtime)
	}
	f.err = errors.New("boom")
	if v := getLinkView(t, s); v.Runtime.Code != codeLinkLogReadFailed {
		t.Fatalf("%+v", v.Runtime)
	}
	f.err, f.st = nil, hostexec.LinkJournalStatus{UnitActive: "inactive"}
	if v := getLinkView(t, s); !v.Runtime.Available || v.Runtime.Code != codeLinkLogNotInstalled || !strings.Contains(v.Runtime.Message, "下一次网关安装") {
		t.Fatalf("not installed: %+v", v.Runtime)
	}
	f.st = hostexec.LinkJournalStatus{UnitActive: "active", Present: true, ConfigInstalled: true, Health: json.RawMessage(`{"ready":true,"passes":3}`)}
	if v := getLinkView(t, s); !v.Runtime.Available || v.Runtime.Code != "" || !v.Runtime.Present || !bytes.Contains(v.Runtime.Health, []byte(`"passes":3`)) {
		t.Fatalf("running: %+v", v.Runtime)
	}
}

// The state now and the timeline, with filters and paging.
func TestLinkLogCurrentAndEvents(t *testing.T) {
	s, f, now := linkRig(t)
	rr := do(s, http.MethodGet, "/api/link-log/current", nil)
	var cv linkLogAnswerView
	if rr.Code != 200 || json.Unmarshal(rr.Body.Bytes(), &cv) != nil || !cv.Available || cv.Summary == nil {
		t.Fatalf("%d %s", rr.Code, rr.Body.String())
	}
	sm := cv.Summary
	// The journal's clock runs on: allow a few seconds on every duration.
	about := func(got int64, want time.Duration) bool {
		return got >= int64(want/time.Second) && got <= int64(want/time.Second)+10
	}
	// Which path carries now, since when, with the evidence.
	if sm.Carrying == nil || sm.Carrying.State != "backup" || sm.Carrying.Level != linkjournal.LevelAbnormal || !about(sm.Carrying.ForS, 40*time.Minute) || sm.Carrying.SinceOpen ||
		!strings.Contains(sm.Carrying.Evidence, "path backup") || sm.Health == nil || sm.Health.State != linkjournal.HealthOK {
		t.Fatalf("carrying: %+v health %+v", sm.Carrying, sm.Health)
	}
	// What is abnormal now and for how long: the backup hub (40 min) and
	// the external exit's failing check (15 min); the recovered tunnel is not.
	if len(sm.Abnormal) != 2 || sm.Objects != 5 {
		t.Fatalf("abnormal: %+v", sm.Abnormal)
	}
	for _, o := range sm.Abnormal {
		switch o.Kind {
		case linkjournal.KindUpstream:
		case linkjournal.KindExternal:
			if o.ID != "ext1" || o.State != linkjournal.CheckFailed || !about(o.ForS, 15*time.Minute) || o.Evidence == "" {
				t.Fatalf("external exit: %+v", o)
			}
		default:
			t.Fatalf("unexpected abnormal object: %+v", o)
		}
	}
	// What is unknown now: the tunnel that stopped being read (its last
	// state is shown as such, not as its state now).
	if len(sm.Unknown) != 1 || sm.Unknown[0].ID != "m01" || !sm.Unknown[0].Stale || sm.Unknown[0].State != linkjournal.TunnelOK {
		t.Fatalf("unknown: %+v", sm.Unknown)
	}
	if !bytes.Contains(cv.Current, []byte(`"objects"`)) || sm.LastPass == nil || !sm.LastPass.Equal(now) {
		t.Fatalf("current: %s", cv.Current)
	}

	page := func(q string) (linkjournal.Page, linkLogAnswerView) {
		t.Helper()
		rr := do(s, http.MethodGet, "/api/link-log/events"+q, nil)
		var v linkLogAnswerView
		var p linkjournal.Page
		if rr.Code != 200 || json.Unmarshal(rr.Body.Bytes(), &v) != nil || !v.Available || json.Unmarshal(v.Page, &p) != nil {
			t.Fatalf("%s: %d %s", q, rr.Code, rr.Body.String())
		}
		return p, v
	}
	all, _ := page("")
	if len(all.Events) != 4 { // udp→backup, m00 stale, m00 ok, ext1 failed
		t.Fatalf("%d events: %+v", len(all.Events), all.Events)
	}
	if e := all.Events[0]; e.Kind != linkjournal.KindExternal || e.From != linkjournal.CheckOK || e.To != linkjournal.CheckFailed || e.PrevForS == nil || *e.PrevForS != 45*60 || !e.PrevOpen {
		t.Fatalf("newest event: %+v", e)
	}
	if p, _ := page("?class=tunnel"); len(p.Events) != 2 || p.Events[0].To != linkjournal.TunnelOK || *p.Events[0].PrevForS != 600 || p.Events[0].PrevOpen {
		t.Fatalf("class filter: %+v", p.Events)
	}
	if p, _ := page("?kind=external_exit&id=ext1"); len(p.Events) != 1 {
		t.Fatalf("object filter: %+v", p.Events)
	}
	if p, _ := page("?class=relay"); len(p.Events) != 0 {
		t.Fatalf("%+v", p.Events)
	}
	from := url.QueryEscape(now.Add(-35 * time.Minute).Format(time.RFC3339))
	to := url.QueryEscape(now.Add(-18 * time.Minute).Format(time.RFC3339))
	if p, _ := page("?from=" + from + "&to=" + to); len(p.Events) != 2 || p.Events[0].ID != "m00" || p.Events[1].ID != "m00" {
		t.Fatalf("time range: %+v", p.Events)
	}
	p1, _ := page("?limit=3")
	if len(p1.Events) != 3 || p1.NextBefore == "" {
		t.Fatalf("first page: %d next %q", len(p1.Events), p1.NextBefore)
	}
	p2, _ := page("?limit=3&before=" + p1.NextBefore)
	if len(p2.Events) != 1 || p2.NextBefore != "" || p2.Events[0].To != "backup" {
		t.Fatalf("second page: %+v", p2)
	}
	if got := f.asked[len(f.asked)-1]; got.Limit != 3 || got.Before != p1.NextBefore {
		t.Fatalf("the agent was asked %+v", got)
	}

	// Validation: refused before the agent is asked.
	asked := len(f.asked)
	for _, q := range []string{"?class=a%20b", "?id=..%2Fx", "?from=yesterday", "?limit=0", "?limit=100000", "?before=x", "?device=192.0.2.1", "?class=a&class=b",
		"?from=2026-03-02T00:00:00Z&to=2026-03-01T00:00:00Z", "?path=/etc/shadow"} {
		if rr := do(s, http.MethodGet, "/api/link-log/events"+q, nil); rr.Code != http.StatusBadRequest {
			t.Errorf("%s: %d", q, rr.Code)
		}
	}
	if len(f.asked) != asked {
		t.Fatalf("a refused query reached the agent: %+v", f.asked[asked:])
	}
	if rr := do(s, http.MethodGet, "/api/link-log/current?id=m00", nil); rr.Code != http.StatusBadRequest {
		t.Fatalf("current with a parameter: %d", rr.Code)
	}

	// No collector: an answer that says why, not an error and not a blank.
	f.j = nil
	for _, p := range []string{"/api/link-log/current", "/api/link-log/events"} {
		rr := do(s, http.MethodGet, p, nil)
		var v linkLogAnswerView
		if rr.Code != 200 || json.Unmarshal(rr.Body.Bytes(), &v) != nil || v.Available || v.Code != codeLinkLogNotRunning || v.Message == "" || v.Page != nil || v.Summary != nil {
			t.Fatalf("%s without a collector: %d %s", p, rr.Code, rr.Body.String())
		}
	}
	f.err = hostexec.ErrLinkJournalUnsupported
	rr = do(s, http.MethodGet, "/api/link-log/events", nil)
	var v linkLogAnswerView
	if json.Unmarshal(rr.Body.Bytes(), &v) != nil || v.Code != codeLinkLogAgentOld {
		t.Fatalf("old agent: %s", rr.Body.String())
	}
	s.LinkLog = nil
	rr = do(s, http.MethodGet, "/api/link-log/current", nil)
	if json.Unmarshal(rr.Body.Bytes(), &v) != nil || rr.Code != 200 || v.Code != codeLinkLogAgentUnavailable {
		t.Fatalf("no agent: %s", rr.Body.String())
	}
}

// Clear needs a confirmation and goes through the agent's fixed request.
func TestLinkLogClear(t *testing.T) {
	s, f, _ := linkRig(t)
	for _, body := range []string{``, `{}`, `{"confirm":false}`, `{"confirm":"yes"}`} {
		var b []byte
		if body != "" {
			b = []byte(body)
		}
		if rr := do(s, http.MethodPost, "/api/link-log/clear", b); rr.Code != http.StatusBadRequest {
			t.Errorf("clear with %q: %d", body, rr.Code)
		}
	}
	if f.clears != 0 {
		t.Fatal("an unconfirmed clear reached the agent")
	}
	rr := do(s, http.MethodPost, "/api/link-log/clear", []byte(`{"confirm":true}`))
	if rr.Code != 200 || !strings.Contains(rr.Body.String(), `"cleared":4`) || f.clears != 1 {
		t.Fatalf("%d %s", rr.Code, rr.Body.String())
	}
	if st := f.j.Stats(); st.Events != 0 || st.Objects != 0 {
		t.Fatalf("%+v", st)
	}
	rr = do(s, http.MethodGet, "/api/link-log/events", nil)
	if !strings.Contains(rr.Body.String(), `"events":[]`) {
		t.Fatalf("after the clear: %s", rr.Body.String())
	}
	// Without a collector nothing is cleared, and the answer says so.
	f.j = nil
	if rr := do(s, http.MethodPost, "/api/link-log/clear", []byte(`{"confirm":true}`)); rr.Code != http.StatusServiceUnavailable || !strings.Contains(rr.Body.String(), "没有清空") {
		t.Fatalf("%d %s", rr.Code, rr.Body.String())
	}
	s.LinkLog = nil
	if rr := do(s, http.MethodPost, "/api/link-log/clear", []byte(`{"confirm":true}`)); rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("%d", rr.Code)
	}
}

// Every endpoint requires the panel token.
func TestLinkLogAuth(t *testing.T) {
	s, f, _ := linkRig(t)
	s.Token = strings.Repeat("k", 32)
	for _, c := range []struct{ method, path, body string }{
		{"GET", "/api/link-log", ""}, {"GET", "/api/link-log/current", ""}, {"GET", "/api/link-log/events", ""}, {"GET", "/api/link-log/events?class=tunnel", ""},
		{"POST", "/api/link-log/clear", `{"confirm":true}`},
	} {
		var b []byte
		if c.body != "" {
			b = []byte(c.body)
		}
		if rr := do(s, c.method, c.path, b); rr.Code != http.StatusUnauthorized || strings.Contains(rr.Body.String(), linkMarker) {
			t.Errorf("%s %s: %d", c.method, c.path, rr.Code)
		}
	}
	if f.clears != 0 || len(f.asked) != 0 {
		t.Fatal("something happened without the token")
	}
	// Other methods are not routes.
	s.Token = ""
	for _, c := range []struct{ method, path string }{{"PUT", "/api/link-log"}, {"POST", "/api/link-log/events"}, {"DELETE", "/api/link-log/events"}, {"GET", "/api/link-log/clear"}} {
		if rr := do(s, c.method, c.path, []byte(`{}`)); rr.Code == http.StatusOK {
			t.Errorf("%s %s answered 200", c.method, c.path)
		}
	}
}

// The collector reaches a host only with a gateway install: the files are
// part of the bundle, the pre-check lists them, and nothing else changes.
// On a gateway installed before the collector existed the first pre-check
// announces it; a host binary without the collector blocks the install
// before anything is written.
func TestLinkLogInstallLifecycle(t *testing.T) {
	s, host, activated := installTest(t)
	hp := &fakeHostPreflight{}
	s.HostPreflight = hp
	f := &fakeLinkLog{st: hostexec.LinkJournalStatus{UnitActive: "inactive"}}
	s.LinkLog = f
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
	unit, conf := "etc/systemd/system/"+compile.LinkJournalUnit, strings.TrimPrefix(compile.LinkJournalConfigPath, "/")

	// Before any install: saving, compiling and a pre-check put nothing on
	// the host.
	if v := getLinkView(t, s); v.Pending != "install" || v.Installed.Enabled || v.Runtime.Code != codeLinkLogNotInstalled {
		t.Fatalf("%+v", v)
	}
	p := pre()
	if hostFile(unit) != "" || hostFile(conf) != "" || *activated != 0 {
		t.Fatal("the pre-check put the collector on the host")
	}
	// A first install announces nothing separately (everything is new).
	if finding(p, "link_log_add") != nil || finding(p, codeLinkLogBlocked) != nil {
		t.Fatalf("%+v", p.Findings)
	}
	// A host binary without the collector: blocked, nothing written.
	f.err = hostexec.ErrLinkJournalUnsupported
	pb := pre()
	if b := finding(pb, codeLinkLogBlocked); !pb.Blocking || b == nil || b.Severity != preflight.Blocking || !strings.Contains(b.Action, "install.sh") || b.Resource != compile.LinkJournalUnit {
		t.Fatalf("old host binary: %+v", pb.Findings)
	}
	if c, b := install(pb.ID); c != http.StatusConflict || !strings.Contains(b, codeLinkLogBlocked) || *activated != 0 || hostFile(unit) != "" {
		t.Fatalf("an install on an old host binary went through: %d %s", c, b)
	}
	f.err = nil
	p = pre()
	if c, b := install(p.ID); c != 200 || *activated != 1 {
		t.Fatalf("%d %s", c, b)
	}
	if !strings.Contains(hostFile(unit), "link-journal --config "+compile.LinkJournalConfigPath) || !strings.Contains(hostFile(conf), `"tunnels"`) {
		t.Fatal("the install did not write the collector's unit and object list")
	}
	fi, err := os.Stat(filepath.Join(host, conf))
	if err != nil || fi.Mode().Perm() != 0o644 {
		t.Fatalf("object list mode: %v %v", fi, err)
	}
	m, err := s.applier(true).Installed()
	if err != nil {
		t.Fatal(err)
	}
	var inUnits bool
	for _, u := range m.Units {
		inUnits = inUnits || u == compile.LinkJournalUnit
	}
	if !inUnits {
		t.Fatalf("the collector is not a manifest unit: %v", m.Units)
	}
	if v := getLinkView(t, s); v.Pending != "" || !v.Installed.Enabled || v.Runtime.Code != codeLinkLogNotRunning {
		t.Fatalf("after the install, collector not answering: %+v %+v", v.Installed, v.Runtime)
	}

	// The upgrade case: a gateway installed by a version without the
	// collector. Its manifest and files are the same install without the
	// three link-journal pieces.
	old, err := os.ReadFile(filepath.Join(s.DataDir, "host", "installed", "manifest.json"))
	if err != nil {
		t.Skipf("installed manifest not where this test expects it: %v", err)
	}
	var mf map[string]any
	if err := json.Unmarshal(old, &mf); err != nil {
		t.Fatal(err)
	}
	strip := func(key string, keep func(any) bool) {
		var out []any
		for _, x := range mf[key].([]any) {
			if keep(x) {
				out = append(out, x)
			}
		}
		mf[key] = out
	}
	strip("units", func(x any) bool { return x != compile.LinkJournalUnit })
	strip("files", func(x any) bool {
		p := x.(map[string]any)["path"].(string)
		return p != unit && p != conf
	})
	if err := os.WriteFile(filepath.Join(s.DataDir, "host", "installed", "manifest.json"), mustJSON(mf), 0o600); err != nil {
		t.Fatal(err)
	}
	os.Remove(filepath.Join(host, unit))
	os.Remove(filepath.Join(host, conf))
	raw, err := os.ReadFile("../preflight/testdata/gateway-installed.txt")
	if err != nil {
		t.Fatal(err)
	}
	hp.mu.Lock()
	hp.raw = string(raw)
	hp.mu.Unlock()
	if v := getLinkView(t, s); v.Pending != "install" || v.Installed.Enabled {
		t.Fatalf("upgraded panel, old install: %+v", v)
	}
	// The status bar shows a pending change, and nothing is on the host.
	var st statusView
	if rr := do(s, http.MethodGet, "/api/status", nil); json.Unmarshal(rr.Body.Bytes(), &st) != nil || st.Install.State != "changed" {
		t.Fatalf("status after the upgrade: %s", rr.Body.String())
	}
	if hostFile(unit) != "" {
		t.Fatal("the panel put the collector on the host by itself")
	}
	p = pre()
	add := finding(p, "link_log_add")
	if p.Blocking || add == nil || add.Severity != preflight.Info || !strings.Contains(add.Message, compile.LinkJournalUnit) || !strings.Contains(add.Message, "不含任何流量内容") || p.FileChanges == nil {
		t.Fatalf("upgrade pre-check: %+v", p.Findings)
	}
	// Exactly these files: two added; nothing removed. (The verify script
	// is unchanged here because this "old" install already had the new one;
	// the golden files show it changing on a real upgrade.)
	if strings.Join(p.FileChanges.Added, " ") != "/"+conf+" /"+unit || len(p.FileChanges.Removed) != 0 || len(p.FileChanges.Changed) != 0 {
		t.Fatalf("upgrade: added %v changed %v removed %v", p.FileChanges.Added, p.FileChanges.Changed, p.FileChanges.Removed)
	}
	if hostFile(unit) != "" {
		t.Fatal("the pre-check wrote the unit")
	}
	if c, b := install(p.ID); c != 200 || *activated != 2 || !strings.Contains(b, compile.LinkJournalUnit) {
		t.Fatalf("%d %s", c, b)
	}
	if hostFile(unit) == "" || hostFile(conf) == "" {
		t.Fatal("the upgrade install did not add the collector")
	}
	// Installed: the next pre-check says nothing about it.
	if p := pre(); finding(p, "link_log_add") != nil {
		t.Fatalf("%+v", p.Findings)
	}
}

// Journal content never leaves the handlers: not into the topology, a
// snapshot, an export, a pre-check, a diagnosis, the store or the log.
func TestLinkLogNeverLeaves(t *testing.T) {
	s, f, _ := linkRig(t)
	s.HostRoot = t.TempDir()
	s.Activate = func() error { return nil }
	withPeerKeys(t, s)
	s.HostPreflight = &fakeHostPreflight{}
	var logs bytes.Buffer
	log.SetOutput(&logs)
	defer log.SetOutput(os.Stderr)
	for _, p := range []string{"/api/link-log/current", "/api/link-log/events", "/api/link-log/events?class=tunnel"} {
		if rr := do(s, http.MethodGet, p, nil); rr.Code != 200 || !strings.Contains(rr.Body.String(), linkMarker) {
			t.Fatalf("%s: %d %s", p, rr.Code, rr.Body.String())
		}
	}
	check := func(what, body string) {
		t.Helper()
		if strings.Contains(body, linkMarker) {
			t.Errorf("%s contains link-journal content", what)
		}
	}
	check("GET /api/link-log", do(s, http.MethodGet, "/api/link-log", nil).Body.String())
	for _, p := range demoGets {
		check("GET "+p, do(s, http.MethodGet, p, nil).Body.String())
	}
	for _, p := range demoPosts {
		check("POST "+p.path, do(s, http.MethodPost, p.path, []byte(p.body)).Body.String())
	}
	check("POST /api/compile", do(s, http.MethodPost, "/api/compile", []byte(`{}`)).Body.String())
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
	for _, key := range []string{"topology", preflightKey(localNodeID)} {
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
	do(s, http.MethodPost, "/api/link-log/clear", []byte(`{"confirm":true}`))
	f.err = errors.New("agent failure")
	do(s, http.MethodGet, "/api/link-log", nil)
	do(s, http.MethodGet, "/api/link-log/events", nil)
	check("panel log", logs.String())
	// The topology document has no field for it at all.
	topo, _ := s.topology()
	b, _ := json.Marshal(topo)
	if strings.Contains(string(b), "link_log") || strings.Contains(string(b), "link-journal") {
		t.Fatal("the topology carries a link-journal setting")
	}
	_ = model.Topology{}
}
