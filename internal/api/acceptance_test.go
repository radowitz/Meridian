package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/radowitz/meridian/internal/acceptance"
	"github.com/radowitz/meridian/internal/defaults"
	"github.com/radowitz/meridian/internal/hostexec"
	"github.com/radowitz/meridian/internal/model"
	"github.com/radowitz/meridian/internal/verify"
)

// fakeDrill stands in for meridian-host's drill and path-check requests.
// It keeps one record like the agent does and moves it by script; nothing
// is executed and no host is contacted.
type fakeDrill struct {
	mu       sync.Mutex
	starts   []hostexec.DrillRequest
	cancels  []string
	retries  []string
	releases []string
	paths    []hostexec.PathCheckRequest
	rec      *hostexec.DrillRecord
	running  bool
	// finish is what the record becomes when the drill ends; hold keeps it
	// running until the test closes the channel (or a cancel arrives).
	finish func(r *hostexec.DrillRecord)
	hold   chan struct{}
	// startErr refuses a start; statusErr makes every status read fail.
	startErr, statusErr error
	// retryOK: a retry verifies the restore.
	retryOK bool
	links   []hostexec.PathLink
}

func (f *fakeDrill) DrillStart(_ context.Context, req hostexec.DrillRequest) (hostexec.DrillStatus, error) {
	if err := hostexec.ValidateDrill(req); err != nil {
		return hostexec.DrillStatus{}, err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.starts = append(f.starts, req)
	if f.startErr != nil {
		return hostexec.DrillStatus{Error: f.startErr.Error()}, f.startErr
	}
	now := time.Now().UTC()
	f.rec = &hostexec.DrillRecord{ID: req.RequestID, Kind: req.Kind, Interfaces: req.Interfaces, BackupInterface: req.BackupInterface,
		BlockSeconds: req.BlockSeconds, Fingerprint: req.Fingerprint, Phase: hostexec.DrillActive, StartedAt: now,
		Deadline: now.Add(time.Minute), RestoreDeadline: now.Add(5 * time.Minute), Plan: []string{"删除演练阻断表", "核对快照"}, Expect: "预期的变化",
		Snapshot: hostexec.DrillSnapshot{Upstream: &hostexec.DrillUpstream{Relays: []hostexec.DrillRelayState{{ID: "access", Iface: "m02"}, {ID: "access2", Iface: "m03"}}}}}
	f.running = true
	hold := f.hold
	rec := f.rec
	go func() {
		if hold != nil {
			<-hold
		}
		f.mu.Lock()
		defer f.mu.Unlock()
		if f.rec != rec || !f.running {
			return
		}
		f.end(rec)
	}()
	return f.statusLocked(), nil
}

// end finishes the record (caller holds mu).
func (f *fakeDrill) end(rec *hostexec.DrillRecord) {
	at := time.Now().UTC()
	rec.Phase, rec.Outcome, rec.OwnChangeCleared, rec.FinishedAt = hostexec.DrillRestored, hostexec.DrillMet, true, &at
	rec.Findings = []string{"中继在阻断后约 25 秒 被剔除"}
	rec.Observed = []hostexec.DrillObservation{{AfterMS: 25000, Summary: "路径 main；中继 access evicted 权重 0"}}
	if f.finish != nil {
		f.finish(rec)
	}
	f.running = false
}

func (f *fakeDrill) statusLocked() hostexec.DrillStatus {
	st := hostexec.DrillStatus{Running: f.running}
	if f.rec != nil {
		cp := *f.rec
		st.Record, st.Blocked = &cp, cp.Unresolved()
	}
	return st
}

func (f *fakeDrill) DrillStatus(context.Context) (hostexec.DrillStatus, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.statusErr != nil {
		return hostexec.DrillStatus{}, f.statusErr
	}
	return f.statusLocked(), nil
}

func (f *fakeDrill) DrillCancel(_ context.Context, id string) (hostexec.DrillStatus, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.cancels = append(f.cancels, id)
	if f.rec == nil || f.rec.ID != id {
		return f.statusLocked(), fmt.Errorf("%w（404）：没有这个演练", hostexec.ErrDrillRefused)
	}
	if f.running {
		f.end(f.rec)
		f.rec.Outcome, f.rec.Trigger = hostexec.DrillAborted, "cancel"
	}
	return f.statusLocked(), nil
}

func (f *fakeDrill) DrillRetry(_ context.Context, id string) (hostexec.DrillStatus, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.retries = append(f.retries, id)
	if f.rec == nil || f.rec.ID != id || f.rec.Phase != hostexec.DrillRestoreFailed {
		return f.statusLocked(), fmt.Errorf("%w（409）：不能重试", hostexec.ErrDrillRefused)
	}
	f.rec.Attempts++
	if f.retryOK {
		f.rec.Phase, f.rec.Residual, f.rec.OwnChangeCleared = hostexec.DrillRestored, nil, true
	}
	return f.statusLocked(), nil
}

func (f *fakeDrill) DrillRelease(_ context.Context, id string) (hostexec.DrillStatus, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.releases = append(f.releases, id)
	if f.rec == nil || f.rec.ID != id || f.rec.Phase != hostexec.DrillRestoreFailed || !f.rec.OwnChangeCleared {
		return f.statusLocked(), fmt.Errorf("%w（409）：演练阻断表还在", hostexec.ErrDrillRefused)
	}
	f.rec.Phase = hostexec.DrillReleased
	return f.statusLocked(), nil
}

func (f *fakeDrill) PathCheck(_ context.Context, req hostexec.PathCheckRequest) (hostexec.PathCheckResult, error) {
	if err := hostexec.ValidatePathCheck(req); err != nil {
		return hostexec.PathCheckResult{}, err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.paths = append(f.paths, req)
	res := hostexec.PathCheckResult{CheckedAt: time.Now().UTC()}
	if f.links != nil {
		res.Links = f.links
		return res, nil
	}
	age := int64(30)
	for _, i := range req.Interfaces {
		res.Links = append(res.Links, hostexec.PathLink{Interface: i, State: "up", WireGuard: true, Peers: 1, HandshakeAgeS: &age})
	}
	return res, nil
}

func (f *fakeDrill) started() []hostexec.DrillRequest {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]hostexec.DrillRequest(nil), f.starts...)
}

// fakeDNSProber adds the fixed exit resolver check to the probe fake.
type fakeDNSProber struct {
	*fakeProber
	mu      sync.Mutex
	checks  []hostexec.DNSCheckRequest
	outcome func(exit string) string
}

func (f *fakeDNSProber) DNSCheck(_ context.Context, req hostexec.DNSCheckRequest) (hostexec.DNSCheckResult, error) {
	if err := hostexec.ValidateDNSCheck(req); err != nil {
		return hostexec.DNSCheckResult{}, err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.checks = append(f.checks, req)
	out := "answer"
	if f.outcome != nil {
		out = f.outcome(req.ExitID)
	}
	return hostexec.DNSCheckResult{ExitID: req.ExitID, Resolver: req.Resolver, Name: hostexec.DNSCheckName, QType: "A", Outcome: out, Answers: 1, DurationMS: 12, CheckedAt: time.Now().UTC()}, nil
}

// healthHost answers the health action.
type healthHost struct {
	mu   sync.Mutex
	reqs []hostexec.Request
	fail bool
}

func (h *healthHost) Do(_ context.Context, req hostexec.Request) (hostexec.Result, error) {
	if err := hostexec.Validate(req); err != nil {
		return hostexec.Result{}, err
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	h.reqs = append(h.reqs, req)
	res := hostexec.Result{RequestID: req.RequestID, Action: req.Action, OK: !h.fail, Steps: []hostexec.Step{{Name: "health meridian.service", OK: !h.fail}}}
	if h.fail {
		res.Error = "health meridian.service 失败"
		return res, errors.New(res.Error)
	}
	return res, nil
}

// accFixture is a panel with the shared-relays topology (two relays, a
// backup hub) installed on a temporary root, and fakes for every host
// request. All addresses and names are the topology's synthetic ones.
type accFixture struct {
	t     *testing.T
	s     *Server
	drill *fakeDrill
	up    *fakeUpstream
	dns   *fakeDNSProber
	now   time.Time
	mu    sync.Mutex
}

func newAccFixture(t *testing.T, install bool) *accFixture {
	t.Helper()
	return newAccFixtureOn(t, install, defaults.SharedRelaysExample())
}

// newAccFixtureOn is newAccFixture on another synthetic topology.
func newAccFixtureOn(t *testing.T, install bool, topo model.Topology) *accFixture {
	t.Helper()
	f := &accFixture{t: t, s: newTest(t), drill: &fakeDrill{}, up: &fakeUpstream{}, now: time.Now().UTC()}
	s := f.s
	s.HostRoot = t.TempDir()
	s.Activate = func() error { return nil }
	model.MigrateRegionGroups(&topo)
	if err := s.Store.Save(topo); err != nil {
		t.Fatal(err)
	}
	withPeerKeys(t, s)
	if install {
		if rr := do(s, http.MethodPost, "/api/apply", []byte(`{"install":true}`)); rr.Code != 200 {
			t.Fatalf("install: %d %s", rr.Code, rr.Body.String())
		}
	}
	stored, _, _ := s.Store.Load()
	if stored.RelaySharing() {
		f.up.st = hostexec.UpstreamStatus{Present: true, Record: sharedRecord(t, stored, time.Now().Unix())}
		// Both relays carrying, whatever the sample of sharedRecord graded.
		for i := range f.up.st.Record.Relays {
			f.up.st.Record.Relays[i].Status, f.up.st.Record.Relays[i].Weight = "active", 500
		}
	}
	f.dns = &fakeDNSProber{fakeProber: &fakeProber{}}
	s.Drill, s.Upstream, s.Prober = f.drill, f.up, f.dns
	s.AccPoll = 2 * time.Millisecond
	s.clock = func() time.Time { f.mu.Lock(); defer f.mu.Unlock(); return f.now }
	return f
}

func (f *accFixture) advance(d time.Duration) {
	f.mu.Lock()
	f.now = f.now.Add(d)
	f.mu.Unlock()
}

type accBody struct {
	Fingerprint string `json:"fingerprint"`
	Config      struct {
		State            string `json:"state"`
		InstalledVersion int64  `json:"installed_version"`
	} `json:"config"`
	Running *struct {
		ID     string `json:"id"`
		ItemID string `json:"item_id"`
		Drill  bool   `json:"drill"`
		Phase  string `json:"phase"`
	} `json:"running"`
	Drill struct {
		Available bool   `json:"available"`
		Blocked   bool   `json:"blocked"`
		Running   bool   `json:"running"`
		ItemID    string `json:"item_id"`
		Record    *struct {
			ID       string   `json:"id"`
			Phase    string   `json:"phase"`
			Residual []string `json:"residual"`
		} `json:"record"`
	} `json:"drill"`
	Items []struct {
		ID         string   `json:"id"`
		Mode       string   `json:"mode"`
		Action     string   `json:"action"`
		Needs      []string `json:"needs"`
		Applicable bool     `json:"applicable"`
		Reason     string   `json:"reason"`
		Runnable   bool     `json:"runnable"`
		RunBlocked string   `json:"run_blocked"`
		State      string   `json:"state"`
		Targets    []struct {
			ID         string `json:"id"`
			Selectable bool   `json:"selectable"`
		} `json:"targets"`
		Parts []struct {
			Part   string                   `json:"part"`
			Latest *acceptance.StoredResult `json:"latest"`
			Valid  *acceptance.StoredResult `json:"valid"`
		} `json:"parts"`
		History        []acceptance.StoredResult `json:"history"`
		ConfigEvidence []struct {
			ID     string `json:"id"`
			Status string `json:"status"`
		} `json:"config_evidence"`
	} `json:"items"`
	Summary map[string]int `json:"summary"`
}

func (f *accFixture) view() accBody {
	f.t.Helper()
	rr := do(f.s, http.MethodGet, "/api/acceptance", nil)
	if rr.Code != 200 {
		f.t.Fatalf("GET /api/acceptance: %d %s", rr.Code, rr.Body.String())
	}
	var b accBody
	decode(f.t, rr, &b)
	return b
}

func (f *accFixture) item(b accBody, id string) int {
	f.t.Helper()
	for i := range b.Items {
		if b.Items[i].ID == id {
			return i
		}
	}
	f.t.Fatalf("no item %s", id)
	return -1
}

// wait polls until no item is being carried out.
func (f *accFixture) wait() accBody {
	f.t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for {
		b := f.view()
		if b.Running == nil {
			return b
		}
		if time.Now().After(deadline) {
			f.t.Fatalf("still running: %+v", b.Running)
		}
		time.Sleep(2 * time.Millisecond)
	}
}

func (f *accFixture) post(path string, body any) (int, map[string]any) {
	f.t.Helper()
	var raw []byte
	if body != nil {
		raw = mustJSON(body)
	}
	rr := do(f.s, http.MethodPost, path, raw)
	var m map[string]any
	_ = json.Unmarshal(rr.Body.Bytes(), &m)
	return rr.Code, m
}

func (f *accFixture) prepare(id string, body map[string]any) string {
	f.t.Helper()
	code, m := f.post("/api/acceptance/items/"+id+"/prepare", body)
	if code != 200 {
		f.t.Fatalf("prepare %s: %d %v", id, code, m)
	}
	cf, _ := m["confirmation"].(map[string]any)
	tok, _ := cf["token"].(string)
	if len(tok) != 32 || cf["fingerprint"] == "" || m["restore"] == "" {
		f.t.Fatalf("confirmation: %v", m)
	}
	return tok
}

// The catalog as the page reads it: every item, what applies, what can be
// started, nothing verified before anything ran.
func TestAcceptanceCatalogView(t *testing.T) {
	f := newAccFixture(t, true)
	b := f.view()
	if len(b.Items) != len(acceptance.Catalog()) || len(b.Fingerprint) != 64 || b.Config.State != "in_sync" || b.Config.InstalledVersion == 0 {
		t.Fatalf("%d items, fp %q, config %+v", len(b.Items), b.Fingerprint, b.Config)
	}
	for _, it := range b.Items {
		if it.Applicable && it.State != acceptance.StateNotRun {
			t.Errorf("%s is %s before anything ran", it.ID, it.State)
		}
		if it.Mode == acceptance.ModeManual && it.Runnable {
			t.Errorf("manual item %s is runnable", it.ID)
		}
	}
	for id, want := range map[string]bool{"relay-removal": true, "hub-failover": true, "ipv6-firewall-reload": true, "gateway-health": false, "dns-leak": true, "config-audit": true} {
		it := b.Items[f.item(b, id)]
		if !it.Applicable || it.Runnable != want {
			// gateway-health needs s.Host, which this fixture leaves nil.
			t.Errorf("%s: applicable %v runnable %v (%s %s)", id, it.Applicable, it.Runnable, it.Reason, it.RunBlocked)
		}
	}
	// What does not apply says why and is not counted as unverified.
	for _, id := range []string{"remote-access", "sniff-client", "integration-netns-sniff"} {
		if it := b.Items[f.item(b, id)]; it.Applicable || it.Reason == "" || it.Runnable {
			t.Errorf("%s: %+v", id, it)
		}
	}
	rel := b.Items[f.item(b, "relay-removal")]
	if len(rel.Targets) != 2 || rel.Targets[0].ID != "access" || !rel.Targets[0].Selectable {
		t.Fatalf("relay targets: %+v", rel.Targets)
	}
	if ev := b.Items[f.item(b, "dns-leak")].ConfigEvidence; len(ev) < 3 || ev[0].Status != "pass" {
		t.Fatalf("config evidence: %+v", ev)
	}
	if b.Summary[acceptance.StateNotRun] == 0 || b.Summary["not_applicable"] < 3 {
		t.Fatalf("summary: %v", b.Summary)
	}
	// The summary the other pages link from: every item, the leak
	// checklist's rows mapped to their own items, no host request.
	var sum struct {
		Items []struct {
			ID         string `json:"id"`
			State      string `json:"state"`
			Applicable bool   `json:"applicable"`
			Valid      []struct {
				Part string `json:"part"`
			} `json:"valid"`
		} `json:"items"`
		LeakItems map[string]string `json:"leak_items"`
	}
	decode(t, do(f.s, http.MethodGet, "/api/acceptance/summary", nil), &sum)
	if len(sum.Items) != len(b.Items) || sum.LeakItems["tunnel_cut"] != "tunnel-cut" || sum.LeakItems["netns_reload_no_leak"] != "integration-netns-reload" || sum.LeakItems["dnsleak_client"] != "dns-leak" {
		t.Fatalf("summary: %d items, %v", len(sum.Items), sum.LeakItems)
	}
	if rr := do(f.s, http.MethodPost, "/api/acceptance/items/no-such/run", nil); rr.Code != 404 {
		t.Fatalf("unknown item: %d", rr.Code)
	}

	// Nothing installed: no drill, no host check; the config audit still runs.
	g := newAccFixture(t, false)
	gb := g.view()
	if gb.Config.State != "not_installed" {
		t.Fatalf("%+v", gb.Config)
	}
	for _, id := range []string{"relay-removal", "hub-failover", "ipv6-firewall-reload", "dns-leak", "mesh-e2e"} {
		if it := gb.Items[g.item(gb, id)]; it.Runnable || (it.Applicable && it.RunBlocked == "") {
			t.Errorf("%s runnable without an install: %+v", id, it)
		}
	}
	if code, m := g.post("/api/acceptance/items/ipv6-firewall-reload/prepare", nil); code != 409 || m["code"] != codeAccNotApplicable {
		t.Fatalf("prepare without an install: %d %v", code, m)
	}
	if len(g.drill.started()) != 0 {
		t.Fatal("a drill reached the host")
	}
}

// The config audit fills the configuration part of every item that has
// one, and passes nothing else: an item with a sign-off stays unverified.
func TestAcceptanceConfigAuditAndSignoff(t *testing.T) {
	f := newAccFixture(t, true)
	if code, m := f.post("/api/acceptance/items/config-audit/run", nil); code != 202 {
		t.Fatalf("run: %d %v", code, m)
	}
	b := f.wait()
	audit := b.Items[f.item(b, "config-audit")]
	// The result is what verify.CheckBundle says about this topology's
	// compiled text, and it says what such a result does not prove.
	stored, _, _ := f.s.Store.Load()
	bundle, err := f.s.compileTopo(stored)
	if err != nil {
		t.Fatal(err)
	}
	wantState := acceptance.StateVerified
	for _, v := range verify.CheckBundle(stored, bundle.Files) {
		if v.Scope == verify.ScopeAutomated && v.Status == verify.Fail {
			wantState = acceptance.StateFailed
		}
	}
	if audit.State != wantState || audit.Parts[0].Valid == nil || audit.Parts[0].Valid.Part != acceptance.PartConfig || !strings.Contains(strings.Join(audit.Parts[0].Valid.Details, "\n"), "不能证明实机不泄露") {
		t.Fatalf("want %s: %+v", wantState, audit)
	}
	dns := b.Items[f.item(b, "dns-leak")]
	if dns.State != acceptance.StatePartial || dns.Parts[0].Valid == nil || dns.Parts[0].Valid.Outcome != acceptance.OutcomePass || dns.Parts[1].Valid != nil || dns.Parts[2].Valid != nil {
		t.Fatalf("config evidence alone must leave dns-leak partial: %+v", dns)
	}
	if got := b.Items[f.item(b, "gateway-health")]; got.State != acceptance.StateNotRun {
		t.Fatalf("the audit touched an item without a config part: %+v", got)
	}

	// Sign-off: outcome and note only; the note is redacted; items without
	// a sign-off part cannot be passed by hand.
	for _, bad := range []map[string]any{
		{"outcome": "verified"}, {"outcome": ""}, {"outcome": "pass", "command": "id"}, {"outcome": "pass", "note": strings.Repeat("x", 5000)},
	} {
		if code, m := f.post("/api/acceptance/items/webrtc/signoff", bad); code != 400 {
			t.Fatalf("signoff %v: %d %v", bad, code, m)
		}
	}
	for _, id := range []string{"gateway-health", "relay-removal", "config-audit"} {
		if code, m := f.post("/api/acceptance/items/"+id+"/signoff", map[string]any{"outcome": "pass"}); code != 400 {
			t.Fatalf("signed off %s by hand: %d %v", id, code, m)
		}
	}
	if code, m := f.post("/api/acceptance/items/remote-access/signoff", map[string]any{"outcome": "pass"}); code != 409 || m["code"] != codeAccNotApplicable {
		t.Fatalf("signed off an item that does not apply: %d %v", code, m)
	}
	if code, m := f.post("/api/acceptance/items/webrtc/run", nil); code != 400 {
		t.Fatalf("ran a manual item: %d %v", code, m)
	}
	code, m := f.post("/api/acceptance/items/webrtc/signoff", map[string]any{"outcome": "pass", "note": "测试机 192.0.2.10 截图存档 evidence/webrtc-1.png，srflx 是 198.51.100.20"})
	if code != 200 {
		t.Fatalf("signoff: %d %v", code, m)
	}
	b = f.view()
	w := b.Items[f.item(b, "webrtc")]
	if w.State != acceptance.StateVerified || w.Parts[0].Valid == nil || w.Parts[0].Valid.Method != acceptance.ModeManual {
		t.Fatalf("%+v", w)
	}
	if note := w.Parts[0].Valid.Note; strings.Contains(note, "192.0.2.10") || strings.Contains(note, "198.51.100.20") || !strings.Contains(note, "webrtc-1.png") {
		t.Fatalf("note not redacted: %q", note)
	}
	f.post("/api/acceptance/items/webrtc/signoff", map[string]any{"outcome": "fail", "note": "srflx 是家宽地址"})
	b = f.view()
	if w := b.Items[f.item(b, "webrtc")]; w.State != acceptance.StateFailed || len(w.History) != 2 {
		t.Fatalf("%+v", w)
	}

	// A reinstall changes the installed version: results are kept, stale.
	if rr := do(f.s, http.MethodPost, "/api/apply", []byte(`{"install":true}`)); rr.Code != 200 {
		t.Fatalf("reinstall: %d %s", rr.Code, rr.Body.String())
	}
	after := f.view()
	if after.Fingerprint == b.Fingerprint || after.Config.InstalledVersion == b.Config.InstalledVersion {
		t.Fatalf("fingerprint did not follow the installed version: %s %d", after.Fingerprint, after.Config.InstalledVersion)
	}
	for _, id := range []string{"config-audit", "webrtc", "dns-leak"} {
		it := after.Items[f.item(after, id)]
		if it.State != acceptance.StateStale || len(it.History) == 0 || !it.History[0].Stale {
			t.Errorf("%s after a reinstall: %s %+v", id, it.State, it.History)
		}
		for _, p := range it.Parts {
			if p.Valid != nil {
				t.Errorf("%s: part %s still valid after a reinstall", id, p.Part)
			}
		}
	}
	// A topology change that alters the compiled configuration does the same.
	f.post("/api/acceptance/items/webrtc/signoff", map[string]any{"outcome": "pass"})
	topo, _, _ := f.s.Store.Load()
	topo.Settings.UnlistedDomesticDNS = !topo.Settings.UnlistedDomesticDNS
	if err := f.s.Store.Save(topo); err != nil {
		t.Fatal(err)
	}
	changed := f.view()
	if changed.Config.State != "changed" || changed.Fingerprint == after.Fingerprint || changed.Items[f.item(changed, "webrtc")].State != acceptance.StateStale {
		t.Fatalf("%+v %s", changed.Config, changed.Items[f.item(changed, "webrtc")].State)
	}
}

// Requests carry ids of installed resources only. No command, path, host
// or URL is accepted anywhere, and nothing reaches the host for a refusal.
func TestAcceptanceRejectsFreeForm(t *testing.T) {
	f := newAccFixture(t, true)
	hh := &healthHost{}
	for path, bodies := range map[string][]map[string]any{
		"/api/acceptance/items/relay-removal/prepare": {
			{"target": "access", "command": "id"}, {"target": "access", "path": "/etc/passwd"}, {"target": "access", "url": "http://example.com/"},
			{"target": "access", "host": "example.com"}, {"target": "access", "interfaces": []string{"eth0"}}, {"target": "access", "address": "198.51.100.7"},
		},
		"/api/acceptance/items/relay-removal/run":        {{"confirm_token": "x", "target": "access", "exec": "true"}},
		"/api/acceptance/items/ipv6-firewall-reload/run": {{"script": "reboot"}},
		"/api/acceptance/items/dns-leak/run":             {{"resolver": "198.51.100.53"}, {"name": "example.org"}},
		"/api/acceptance/items/unlock/run":               {{"url": "https://example.com/"}},
		"/api/acceptance/items/mesh-e2e/run":             {{"interfaces": []string{"eth0"}}},
		"/api/acceptance/drill/retry":                    {{"id": "x", "command": "id"}},
		"/api/acceptance/items/webrtc/cancel":            {{"force": true}},
	} {
		for _, body := range bodies {
			if code, m := f.post(path, body); code != 400 {
				t.Errorf("%s %v: %d %v", path, body, code, m)
			}
		}
	}
	// Targets that are not installed resources.
	for _, target := range []string{"no-such-relay", "gw", "ix", "hk-ix", "198.51.100.7", "../access", "m02", "example.com", ""} {
		if code, m := f.post("/api/acceptance/items/relay-removal/prepare", map[string]any{"target": target}); code != 400 || m["code"] != codeAccBadTarget {
			t.Errorf("target %q: %d %v", target, code, m)
		}
	}
	for _, secs := range []int{1, 19, 91, 3600, -5} {
		if code, m := f.post("/api/acceptance/items/relay-removal/prepare", map[string]any{"target": "access", "block_seconds": secs}); code != 400 {
			t.Errorf("block_seconds %d: %d %v", secs, code, m)
		}
	}
	if code, m := f.post("/api/acceptance/items/hub-failover/prepare", map[string]any{"target": "ix"}); code != 400 {
		t.Errorf("hub-failover with a target: %d %v", code, m)
	}
	if code, m := f.post("/api/acceptance/items/ipv6-firewall-reload/prepare", map[string]any{"block_seconds": 30}); code != 400 {
		t.Errorf("reload with a duration: %d %v", code, m)
	}
	// Exits and platforms come from the topology and the probe catalog.
	for _, body := range []map[string]any{{"exits": []string{"no-such-exit"}}, {"exits": []string{"gw"}}, {"services": []string{"no-such-platform"}}, {"services": []string{"https://example.com"}}} {
		if code, m := f.post("/api/acceptance/items/unlock/run", body); code != 400 || m["code"] != codeAccBadTarget {
			t.Errorf("unlock %v: %d %v", body, code, m)
		}
	}
	if code, m := f.post("/api/acceptance/items/dns-leak/run", map[string]any{"exits": []string{"no-such-exit"}}); code != 400 {
		t.Errorf("dns-leak with an unknown exit: %d %v", code, m)
	}
	if code, m := f.post("/api/acceptance/items/gateway-health/run", map[string]any{"exits": []string{"hk-ix"}}); code != 409 && code != 400 {
		t.Errorf("health with exits: %d %v", code, m)
	}
	if len(f.drill.started()) != 0 || len(f.drill.paths) != 0 || len(f.dns.checks) != 0 || len(f.dns.requests()) != 0 || len(hh.reqs) != 0 {
		t.Fatal("a refused request reached the host")
	}
	if b := f.view(); b.Running != nil {
		t.Fatalf("a refused request left a job: %+v", b.Running)
	}
}

// A drill needs a confirmation bound to the action, the target, the
// fingerprint and a deadline; it takes the gateway's locks for its whole
// duration; its result is stored when the host says it restored.
func TestAcceptanceDrillConfirmLocksAndResult(t *testing.T) {
	f := newAccFixture(t, true)
	run := func(body map[string]any) (int, map[string]any) {
		return f.post("/api/acceptance/items/relay-removal/run", body)
	}
	// No confirmation.
	if code, m := run(map[string]any{"target": "access"}); code != 409 || m["code"] != codeAccConfirm {
		t.Fatalf("no confirmation: %d %v", code, m)
	}
	// Confirmed for another relay, another duration, another item.
	tok := f.prepare("relay-removal", map[string]any{"target": "access2"})
	if code, m := run(map[string]any{"target": "access", "confirm_token": tok}); code != 409 || m["code"] != codeAccConfirm {
		t.Fatalf("other target: %d %v", code, m)
	}
	if code, m := run(map[string]any{"target": "access2", "confirm_token": tok}); code != 409 {
		t.Fatalf("the token survived a refused use: %d %v", code, m)
	}
	tok = f.prepare("relay-removal", map[string]any{"target": "access", "block_seconds": 30})
	if code, m := run(map[string]any{"target": "access", "block_seconds": 60, "confirm_token": tok}); code != 409 || m["code"] != codeAccConfirm {
		t.Fatalf("other duration: %d %v", code, m)
	}
	tok = f.prepare("hub-failover", nil)
	if code, m := run(map[string]any{"target": "access", "confirm_token": tok}); code != 409 || m["code"] != codeAccConfirm {
		t.Fatalf("token of another item: %d %v", code, m)
	}
	// Expired.
	tok = f.prepare("relay-removal", map[string]any{"target": "access"})
	f.advance((acceptance.ConfirmTTLSeconds + 1) * time.Second)
	if code, m := run(map[string]any{"target": "access", "confirm_token": tok}); code != 409 || !strings.Contains(fmt.Sprint(m["error"]), "过期") {
		t.Fatalf("expired: %d %v", code, m)
	}
	// The configuration changed after the confirmation.
	tok = f.prepare("relay-removal", map[string]any{"target": "access"})
	topo, _, _ := f.s.Store.Load()
	topo.Settings.UnlistedDomesticDNS = !topo.Settings.UnlistedDomesticDNS
	if err := f.s.Store.Save(topo); err != nil {
		t.Fatal(err)
	}
	if code, m := run(map[string]any{"target": "access", "confirm_token": tok}); code != 409 || m["code"] != codeAccConfirm {
		t.Fatalf("fingerprint changed: %d %v", code, m)
	}
	topo.Settings.UnlistedDomesticDNS = !topo.Settings.UnlistedDomesticDNS
	if err := f.s.Store.Save(topo); err != nil {
		t.Fatal(err)
	}
	if len(f.drill.started()) != 0 {
		t.Fatal("an unconfirmed drill reached the host")
	}

	// Confirmed and started. The host keeps it running until released.
	f.drill.hold = make(chan struct{})
	tok = f.prepare("relay-removal", map[string]any{"target": "access", "block_seconds": 30})
	code, m := run(map[string]any{"target": "access", "block_seconds": 30, "confirm_token": tok})
	if code != 202 {
		t.Fatalf("start: %d %v", code, m)
	}
	st := f.drill.started()
	b := f.view()
	if len(st) != 1 || st[0].Kind != hostexec.DrillRelayIsolation || len(st[0].Interfaces) != 1 || st[0].Interfaces[0] != "m02" || st[0].BlockSeconds != 30 || st[0].Fingerprint != b.Fingerprint {
		t.Fatalf("request to the host: %+v", st)
	}
	if b.Running == nil || b.Running.ItemID != "relay-removal" || !b.Running.Drill || !b.Drill.Running {
		t.Fatalf("%+v %+v", b.Running, b.Drill)
	}
	// Nothing overlaps: no second item, no install, rollback, recovery,
	// withdraw, preflight.
	if code, m := f.post("/api/acceptance/items/config-audit/run", nil); code != 409 || m["code"] != codeAccBusy {
		t.Fatalf("second item: %d %v", code, m)
	}
	for path, body := range map[string]string{"/api/apply": `{"install":true}`, "/api/rollback": `{"install":true}`, "/api/host/recover": ``} {
		rr := do(f.s, http.MethodPost, path, []byte(body))
		if rr.Code != 409 || !strings.Contains(rr.Body.String(), codeAccDrillActive) {
			t.Fatalf("%s during a drill: %d %s", path, rr.Code, rr.Body.String())
		}
	}
	if f.s.lockNode(localNodeID) {
		t.Fatal("the gateway node lock is free during a drill")
	}
	if busy, err := f.s.applier(true).Busy(); err != nil || !busy {
		t.Fatalf("the host transaction lock is free during a drill: %v %v", busy, err)
	}
	if rr := do(f.s, http.MethodPost, "/api/host/withdraw", mustJSON(map[string]any{"confirm": localNodeID})); rr.Code != 409 {
		t.Fatalf("withdraw during a drill: %d %s", rr.Code, rr.Body.String())
	}
	// A dry run and a snapshot-only apply change nothing on the host.
	if rr := do(f.s, http.MethodPost, "/api/apply", []byte(`{"dry_run":true,"install":true}`)); rr.Code != 200 {
		t.Fatalf("dry run during a drill: %d %s", rr.Code, rr.Body.String())
	}
	close(f.drill.hold)
	b = f.wait()
	it := b.Items[f.item(b, "relay-removal")]
	if it.State != acceptance.StateVerified || len(it.History) != 1 {
		t.Fatalf("%+v", it)
	}
	res := it.History[0]
	if res.Outcome != acceptance.OutcomePass || res.Method != acceptance.ModeDrill || res.Action != hostexec.DrillRelayIsolation || res.Target != "access" || res.Fingerprint != b.Fingerprint || res.At.IsZero() || len(res.Details) < 3 {
		t.Fatalf("%+v", res)
	}
	if !f.s.lockNode(localNodeID) {
		t.Fatal("the node lock was not released")
	}
	f.s.unlockNode(localNodeID)
	if busy, _ := f.s.applier(true).Busy(); busy {
		t.Fatal("the transaction lock was not released")
	}
	if rr := do(f.s, http.MethodPost, "/api/apply", []byte(`{"install":true}`)); rr.Code != 200 {
		t.Fatalf("install after the drill: %d %s", rr.Code, rr.Body.String())
	}
}

// The hub drill names every relay of the main path and the backup tunnel
// of the gateway's own record; the reload drill names nothing.
func TestAcceptanceDrillTargetsComeFromInstalledState(t *testing.T) {
	f := newAccFixture(t, true)
	tok := f.prepare("hub-failover", nil)
	if code, m := f.post("/api/acceptance/items/hub-failover/run", map[string]any{"confirm_token": tok}); code != 202 {
		t.Fatalf("hub: %d %v", code, m)
	}
	f.wait()
	tok = f.prepare("ipv6-firewall-reload", nil)
	if code, m := f.post("/api/acceptance/items/ipv6-firewall-reload/run", map[string]any{"confirm_token": tok}); code != 202 {
		t.Fatalf("reload: %d %v", code, m)
	}
	b := f.wait()
	st := f.drill.started()
	if len(st) != 2 {
		t.Fatalf("%+v", st)
	}
	hub := st[0]
	if hub.Kind != hostexec.DrillHubIsolation || strings.Join(hub.Interfaces, ",") != "m02,m03" || hub.BackupInterface != f.up.st.Record.Backup.Iface || hub.BlockSeconds != accDefaultBlock {
		t.Fatalf("hub request: %+v", hub)
	}
	if rl := st[1]; rl.Kind != hostexec.DrillFirewallReload || len(rl.Interfaces) != 0 || rl.BackupInterface != "" || rl.BlockSeconds != 0 {
		t.Fatalf("reload request: %+v", rl)
	}
	// The reload item still needs its human part: measured alone is partial.
	if it := b.Items[f.item(b, "ipv6-firewall-reload")]; it.State != acceptance.StatePartial {
		t.Fatalf("%+v", it)
	}
	// A relay the record does not name, or on an interface that is not
	// installed, is refused before the host hears of it.
	f.up.mu.Lock()
	f.up.st.Record.Relays[1].Iface = "m09"
	f.up.mu.Unlock()
	if code, m := f.post("/api/acceptance/items/relay-removal/prepare", map[string]any{"target": "access2"}); code != 400 || m["code"] != codeAccBadTarget {
		t.Fatalf("relay on an interface that is not installed: %d %v", code, m)
	}
	if code, m := f.post("/api/acceptance/items/hub-failover/prepare", nil); code != 409 {
		t.Fatalf("hub with an interface that is not installed: %d %v", code, m)
	}
	// No upstream record: no drill.
	f.up.mu.Lock()
	f.up.st = hostexec.UpstreamStatus{}
	f.up.mu.Unlock()
	if code, m := f.post("/api/acceptance/items/relay-removal/prepare", map[string]any{"target": "access"}); code != 409 {
		t.Fatalf("no upstream record: %d %v", code, m)
	}
	if len(f.drill.started()) != 2 {
		t.Fatal("a refused drill reached the host")
	}
}

// A cancel goes to the host, which restores; the result is "cancelled".
func TestAcceptanceDrillCancel(t *testing.T) {
	f := newAccFixture(t, true)
	f.drill.hold = make(chan struct{})
	defer close(f.drill.hold)
	tok := f.prepare("relay-removal", map[string]any{"target": "access"})
	if code, m := f.post("/api/acceptance/items/relay-removal/run", map[string]any{"target": "access", "confirm_token": tok}); code != 202 {
		t.Fatalf("start: %d %v", code, m)
	}
	if code, m := f.post("/api/acceptance/items/hub-failover/cancel", nil); code != 409 {
		t.Fatalf("cancel of an item that is not running: %d %v", code, m)
	}
	if code, m := f.post("/api/acceptance/items/relay-removal/cancel", nil); code != 202 {
		t.Fatalf("cancel: %d %v", code, m)
	}
	b := f.wait()
	it := b.Items[f.item(b, "relay-removal")]
	if len(f.drill.cancels) != 1 || it.State != acceptance.StateInconclusive || it.History[0].Outcome != acceptance.OutcomeCancelled {
		t.Fatalf("%v %+v", f.drill.cancels, it)
	}
	if !f.s.lockNode(localNodeID) {
		t.Fatal("locks not released after a cancel")
	}
	f.s.unlockNode(localNodeID)
}

// The host refuses the drill, or cannot be reached: nothing is held and
// nothing is stored as carried out.
func TestAcceptanceDrillRefusedByHost(t *testing.T) {
	f := newAccFixture(t, true)
	f.drill.startErr = fmt.Errorf("%w（409）：上游状态是 degraded，不是 ok：演练没有开始", hostexec.ErrDrillRefused)
	tok := f.prepare("relay-removal", map[string]any{"target": "access"})
	code, m := f.post("/api/acceptance/items/relay-removal/run", map[string]any{"target": "access", "confirm_token": tok})
	if code != 409 || m["code"] != codeAccRefused || !strings.Contains(fmt.Sprint(m["error"]), "degraded") {
		t.Fatalf("%d %v", code, m)
	}
	f.drill.startErr = fmt.Errorf("%w：没有 socket", hostexec.ErrUnavailable)
	tok = f.prepare("relay-removal", map[string]any{"target": "access"})
	if code, m := f.post("/api/acceptance/items/relay-removal/run", map[string]any{"target": "access", "confirm_token": tok}); code != 503 || m["code"] != codeHostUnavailable {
		t.Fatalf("%d %v", code, m)
	}
	b := f.view()
	if b.Running != nil || b.Items[f.item(b, "relay-removal")].State != acceptance.StateNotRun {
		t.Fatalf("%+v", b.Running)
	}
	if !f.s.lockNode(localNodeID) {
		t.Fatal("node lock held after a refusal")
	}
	f.s.unlockNode(localNodeID)
	if busy, _ := f.s.applier(true).Busy(); busy {
		t.Fatal("transaction lock held after a refusal")
	}
	// The gateway is busy with something else: refused before the host.
	f.drill.startErr = nil
	f.s.lockNode(localNodeID)
	tok = f.prepare("relay-removal", map[string]any{"target": "access"})
	if code, m := f.post("/api/acceptance/items/relay-removal/run", map[string]any{"target": "access", "confirm_token": tok}); code != 409 || m["code"] != codeNodeBusy {
		t.Fatalf("busy node: %d %v", code, m)
	}
	f.s.unlockNode(localNodeID)
	if len(f.drill.started()) != 2 {
		t.Fatalf("starts: %d", len(f.drill.started()))
	}
}

// A restore the host could not verify: stored as restore_failed (never a
// pass), the page is told the host is blocked, a retry that verifies
// replaces the result, and a release needs its own confirmation and is
// still not a pass.
func TestAcceptanceDrillRestoreFailedRetryRelease(t *testing.T) {
	f := newAccFixture(t, true)
	f.drill.finish = func(r *hostexec.DrillRecord) {
		r.Phase, r.OwnChangeCleared = hostexec.DrillRestoreFailed, false
		r.Residual = []string{"演练阻断表 inet meridian_drill 删除失败，仍然加载着"}
	}
	tok := f.prepare("hub-failover", nil)
	if code, m := f.post("/api/acceptance/items/hub-failover/run", map[string]any{"confirm_token": tok}); code != 202 {
		t.Fatalf("start: %d %v", code, m)
	}
	b := f.wait()
	it := b.Items[f.item(b, "hub-failover")]
	if it.State != acceptance.StateFailed || it.History[0].Outcome != acceptance.OutcomeRestoreFailed || len(it.History[0].Residual) != 1 {
		t.Fatalf("an unverified restore must not pass, whatever was observed: %+v", it)
	}
	if !b.Drill.Blocked || b.Drill.Record == nil || b.Drill.Record.Phase != hostexec.DrillRestoreFailed || b.Drill.ItemID != "hub-failover" {
		t.Fatalf("%+v", b.Drill)
	}
	id := b.Drill.Record.ID
	// No new drill while this one is unresolved: said before a confirmation.
	if code, m := f.post("/api/acceptance/items/relay-removal/prepare", map[string]any{"target": "access"}); code != 409 || m["code"] != codeAccBlocked {
		t.Fatalf("prepare with an unresolved drill on the host: %d %v", code, m)
	}
	// Release: needs the word, and the host refuses while its block is there.
	if code, m := f.post("/api/acceptance/drill/release", map[string]any{"id": id}); code != 400 || m["code"] != codeConfirmRequired {
		t.Fatalf("release without confirmation: %d %v", code, m)
	}
	if code, m := f.post("/api/acceptance/drill/release", map[string]any{"id": id, "confirm": "release"}); code != 409 {
		t.Fatalf("release with the block loaded: %d %v", code, m)
	}
	// Retry that still fails, then one that verifies.
	if code, m := f.post("/api/acceptance/drill/retry", map[string]any{"id": id}); code != 200 {
		t.Fatalf("retry: %d %v", code, m)
	}
	b = f.view()
	if !b.Drill.Blocked || b.Items[f.item(b, "hub-failover")].State != acceptance.StateFailed {
		t.Fatalf("%+v", b.Drill)
	}
	f.drill.mu.Lock()
	f.drill.retryOK = true
	f.drill.mu.Unlock()
	if code, m := f.post("/api/acceptance/drill/retry", map[string]any{"id": id}); code != 200 {
		t.Fatalf("retry: %d %v", code, m)
	}
	b = f.view()
	it = b.Items[f.item(b, "hub-failover")]
	if b.Drill.Blocked || it.State != acceptance.StateVerified || len(it.History) != 1 || it.History[0].Outcome != acceptance.OutcomePass {
		t.Fatalf("after a verified retry: %+v %+v", b.Drill, it)
	}

	// A restore that fails with the block gone can be released; the result
	// stays restore_failed.
	g := newAccFixture(t, true)
	g.drill.finish = func(r *hostexec.DrillRecord) {
		r.Phase, r.OwnChangeCleared = hostexec.DrillRestoreFailed, true
		r.Residual = []string{"承载路径：演练前 main，现在 backup"}
	}
	tok = g.prepare("hub-failover", nil)
	g.post("/api/acceptance/items/hub-failover/run", map[string]any{"confirm_token": tok})
	gb := g.wait()
	if code, m := g.post("/api/acceptance/drill/release", map[string]any{"id": gb.Drill.Record.ID, "confirm": "release"}); code != 200 {
		t.Fatalf("release: %d %v", code, m)
	}
	gb = g.view()
	git := gb.Items[g.item(gb, "hub-failover")]
	if gb.Drill.Blocked || git.State != acceptance.StateFailed || git.History[0].Outcome != acceptance.OutcomeRestoreFailed || !strings.Contains(git.History[0].Summary, "解除") {
		t.Fatalf("a released drill must not read as restored: %+v %+v", gb.Drill, git)
	}
}

// The panel restarts (or loses the host's answer) while a drill runs: the
// host finishes by itself, and the next read takes its record in, once.
func TestAcceptanceAdoptsDrillAfterPanelRestart(t *testing.T) {
	f := newAccFixture(t, true)
	fp := f.view().Fingerprint
	at := time.Now().UTC()
	f.drill.rec = &hostexec.DrillRecord{ID: "acc-lost", Kind: hostexec.DrillFirewallReload, Fingerprint: fp, Phase: hostexec.DrillRestored,
		Outcome: hostexec.DrillMet, OwnChangeCleared: true, StartedAt: at.Add(-time.Minute), FinishedAt: &at, Expect: "兜底表一直在", Findings: []string{"采样 40 次"}}
	for i := 0; i < 3; i++ {
		b := f.view()
		it := b.Items[f.item(b, "ipv6-firewall-reload")]
		if len(it.History) != 1 || it.History[0].RunID != "acc-lost" || it.History[0].Outcome != acceptance.OutcomePass || it.History[0].Stale {
			t.Fatalf("read %d: %+v", i, it.History)
		}
	}
	// A drill confirmed under an older configuration is adopted as stale.
	g := newAccFixture(t, true)
	g.drill.rec = &hostexec.DrillRecord{ID: "acc-old", Kind: hostexec.DrillRelayIsolation, Fingerprint: strings.Repeat("0", 64), Phase: hostexec.DrillRestored,
		Outcome: hostexec.DrillMet, OwnChangeCleared: true, StartedAt: at, FinishedAt: &at, Interfaces: []string{"m02"}}
	gb := g.view()
	if it := gb.Items[g.item(gb, "relay-removal")]; it.State != acceptance.StateStale || !it.History[0].Stale {
		t.Fatalf("%+v", it)
	}
	// A drill still running on the host (this panel did not start it) is
	// shown, not adopted, and blocks.
	h := newAccFixture(t, true)
	h.drill.rec = &hostexec.DrillRecord{ID: "acc-run", Kind: hostexec.DrillHubIsolation, Fingerprint: fp, Phase: hostexec.DrillActive, StartedAt: at}
	h.drill.running = true
	hb := h.view()
	if !hb.Drill.Running || !hb.Drill.Blocked || len(hb.Items[h.item(hb, "hub-failover")].History) != 0 {
		t.Fatalf("%+v", hb.Drill)
	}
}

// The host stops answering while the panel follows a drill: the panel
// gives up after its limit, releases its locks and says the result is
// unknown, never that the drill passed or was restored.
func TestAcceptanceDrillFollowTimesOut(t *testing.T) {
	f := newAccFixture(t, true)
	f.s.AccDrillLimit = 40 * time.Millisecond
	f.drill.hold = make(chan struct{})
	defer close(f.drill.hold)
	tok := f.prepare("relay-removal", map[string]any{"target": "access"})
	if code, m := f.post("/api/acceptance/items/relay-removal/run", map[string]any{"target": "access", "confirm_token": tok}); code != 202 {
		t.Fatalf("start: %d %v", code, m)
	}
	f.drill.mu.Lock()
	f.drill.statusErr = errors.New("socket closed")
	f.drill.mu.Unlock()
	deadline := time.Now().Add(10 * time.Second)
	for f.s.currentAccJob() != nil {
		if time.Now().After(deadline) {
			t.Fatal("the follower never gave up")
		}
		time.Sleep(2 * time.Millisecond)
	}
	b := f.view()
	it := b.Items[f.item(b, "relay-removal")]
	if len(it.History) != 1 || it.History[0].Outcome != acceptance.OutcomeError || !strings.Contains(it.History[0].Summary, "结果不明") || it.State == acceptance.StateVerified {
		t.Fatalf("%+v", it)
	}
	if b.Drill.Available {
		t.Fatalf("the page was told the host answers: %+v", b.Drill)
	}
	if !f.s.lockNode(localNodeID) {
		t.Fatal("locks held after the follower gave up")
	}
	f.s.unlockNode(localNodeID)
}

// The read-only checks use the fixed requests and installed resources.
func TestAcceptanceReadOnlyChecks(t *testing.T) {
	f := newAccFixture(t, true)
	hh := &healthHost{}
	f.s.Host = hh
	// Health: the installed manifest's resources, nothing else.
	if code, m := f.post("/api/acceptance/items/gateway-health/run", nil); code != 202 {
		t.Fatalf("health: %d %v", code, m)
	}
	b := f.wait()
	if it := b.Items[f.item(b, "gateway-health")]; it.State != acceptance.StateVerified || it.History[0].Action != hostexec.ActionHealth {
		t.Fatalf("%+v", it)
	}
	if len(hh.reqs) != 1 || hh.reqs[0].Action != hostexec.ActionHealth || len(hh.reqs[0].Resources.Interfaces) == 0 || len(hh.reqs[0].Resources.NFTTables) != 2 {
		t.Fatalf("%+v", hh.reqs)
	}
	hh.fail = true
	f.post("/api/acceptance/items/gateway-health/run", nil)
	b = f.wait()
	if it := b.Items[f.item(b, "gateway-health")]; it.State != acceptance.StateFailed {
		t.Fatalf("%+v", it)
	}

	// Resolver check: every checkable exit, the compiled resolver address;
	// an answer is a pass of the measurement, not of the item.
	if code, m := f.post("/api/acceptance/items/dns-leak/run", nil); code != 202 {
		t.Fatalf("dns: %d %v", code, m)
	}
	b = f.wait()
	dns := b.Items[f.item(b, "dns-leak")]
	if len(f.dns.checks) == 0 || dns.State != acceptance.StatePartial || dns.Parts[1].Valid == nil || !strings.Contains(dns.Parts[1].Valid.Summary, "不代表无泄漏") {
		t.Fatalf("%d checks, %+v", len(f.dns.checks), dns)
	}
	for _, c := range f.dns.checks {
		if !strings.HasPrefix(c.Resolver, "fd66:") {
			t.Fatalf("resolver not from the compiled plan: %+v", c)
		}
	}
	f.dns.outcome = func(string) string { return "timeout" }
	f.post("/api/acceptance/items/dns-leak/run", nil)
	b = f.wait()
	if it := b.Items[f.item(b, "dns-leak")]; it.State != acceptance.StateFailed {
		t.Fatalf("%+v", it)
	}

	if it := b.Items[f.item(b, "mesh-e2e")]; it.Applicable || it.Runnable {
		t.Fatalf("mesh-e2e applies to a topology without a Mesh backup: %+v", it)
	}

	// Unlock: the fixed-catalog probe job; a result needs the human part too.
	if code, m := f.post("/api/acceptance/items/unlock/run", map[string]any{"services": []string{"auto-netflix"}, "exits": []string{"dc1"}}); code != 202 {
		t.Fatalf("unlock: %d %v", code, m)
	}
	b = f.wait()
	un := b.Items[f.item(b, "unlock")]
	if len(f.dns.requests()) == 0 || un.State != acceptance.StatePartial || un.History[0].Outcome != acceptance.OutcomePass || !strings.Contains(un.History[0].Summary, "不等于真实平台") {
		t.Fatalf("%d probes, %+v", len(f.dns.requests()), un)
	}
	for _, r := range f.dns.requests() {
		if strings.Join(r.Services, ",") != "auto-netflix" {
			t.Fatalf("probe asked for %v", r.Services)
		}
	}
}

// Path check (the default example has a Mesh backup): the installed tunnel
// interfaces; without a published Mesh run it decides nothing, and a stale
// handshake fails it.
func TestAcceptanceMeshPathCheck(t *testing.T) {
	f := newAccFixtureOn(t, true, defaults.Example())
	b := f.view()
	if it := b.Items[f.item(b, "mesh-e2e")]; !it.Applicable || !it.Runnable {
		t.Fatalf("%+v", it)
	}
	for _, id := range []string{"relay-removal", "hub-failover"} {
		if it := b.Items[f.item(b, id)]; it.Applicable || it.Reason == "" {
			t.Fatalf("%s applies to a single-relay, single-hub topology: %+v", id, it)
		}
		if code, m := f.post("/api/acceptance/items/"+id+"/prepare", map[string]any{"target": "access"}); code != 409 || m["code"] != codeAccNotApplicable {
			t.Fatalf("%s: %d %v", id, code, m)
		}
	}
	if code, m := f.post("/api/acceptance/items/mesh-e2e/run", nil); code != 202 {
		t.Fatalf("paths: %d %v", code, m)
	}
	b = f.wait()
	got := b.Items[f.item(b, "mesh-e2e")]
	if len(f.drill.paths) != 1 || len(f.drill.paths[0].Interfaces) == 0 || got.History[0].Outcome != acceptance.OutcomeInconclusive || got.State == acceptance.StateVerified {
		t.Fatalf("%+v %+v", f.drill.paths, got)
	}
	if !strings.Contains(strings.Join(got.History[0].Details, "\n"), "人工步骤") {
		t.Fatalf("the result does not say what it cannot see: %v", got.History[0].Details)
	}
	for _, i := range f.drill.paths[0].Interfaces {
		if !accTunnelRe.MatchString(i) {
			t.Fatalf("path check named %q", i)
		}
	}
	old := int64(4000)
	f.drill.links = []hostexec.PathLink{{Interface: "m00", State: "up", WireGuard: true, Peers: 1, HandshakeAgeS: &old}}
	f.post("/api/acceptance/items/mesh-e2e/run", nil)
	b = f.wait()
	if got := b.Items[f.item(b, "mesh-e2e")]; got.History[0].Outcome != acceptance.OutcomeFail || got.State != acceptance.StateFailed {
		t.Fatalf("%+v", got.History[0])
	}
}

// A read-only check can be cancelled; what it stores is "cancelled".
func TestAcceptanceCheckCancel(t *testing.T) {
	f := newAccFixture(t, true)
	f.dns.fakeProber.block = true
	if code, m := f.post("/api/acceptance/items/unlock/run", map[string]any{"services": []string{"auto-netflix"}, "exits": []string{"dc1"}}); code != 202 {
		t.Fatalf("unlock: %d %v", code, m)
	}
	deadline := time.Now().Add(10 * time.Second)
	for len(f.dns.requests()) == 0 {
		if time.Now().After(deadline) {
			t.Fatal("the probe never started")
		}
		time.Sleep(2 * time.Millisecond)
	}
	if code, m := f.post("/api/acceptance/items/unlock/cancel", nil); code != 200 {
		t.Fatalf("cancel: %d %v", code, m)
	}
	b := f.wait()
	if it := b.Items[f.item(b, "unlock")]; len(it.History) != 1 || it.History[0].Outcome != acceptance.OutcomeCancelled || it.State == acceptance.StateVerified {
		t.Fatalf("%+v", it)
	}
}

func TestFailoverBackupIface(t *testing.T) {
	files := map[string]string{
		"usr/local/sbin/meridian-failover.sh": "#!/bin/bash\n# upstream paths\nUP_NAME=('udp' 'wss' 'backup')\nUP_IFACE=('m02' 'm02w' 'm04w')\nUP_PROBE=('10.66.0.1' '10.66.0.1' '10.66.9.1')\n",
		"etc/other":                           "x",
	}
	if got := failoverBackupIface(files); got != "m04w" {
		t.Fatalf("%q", got)
	}
	if got := failoverBackupIface(map[string]string{"a": "\nUP_NAME=('udp')\nUP_IFACE=('m02')\n"}); got != "" {
		t.Fatalf("%q", got)
	}
}
