package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/radowitz/meridian/internal/model"
)

// Automatic install of saved rule changes (rules_autoapply.go), against the
// fake host (activation shim, fake preflight). Synthetic data only.

type ruleRig struct {
	s         *Server
	hp        *fakeHostPreflight
	activated *int
	fail      *bool
}

func newRuleRig(t *testing.T) *ruleRig {
	t.Helper()
	s, _, _ := installTest(t)
	n, fail := 0, false
	s.Activate = func() error {
		n++
		if fail {
			fail = false // the compensating activation succeeds
			return errors.New("synthetic activation failure")
		}
		return nil
	}
	hp := &fakeHostPreflight{}
	s.HostPreflight = hp
	s.rulesAuto.gap = 150 * time.Millisecond
	opInstall(t, s)
	if n != 1 {
		t.Fatalf("first install activations %d", n)
	}
	// Outside the coalescing window of nothing.
	s.rulesAuto.lastRun = time.Time{}
	return &ruleRig{s: s, hp: hp, activated: &n, fail: &fail}
}

type ruleResp struct {
	ApplyRequired *bool     `json:"apply_required"`
	FastApply     fastApply `json:"fast_apply"`
}

// putRules saves the stored topology with edit applied through the
// whole-document save, as the panel's rule editor does.
func (r *ruleRig) putRules(t *testing.T, edit func(tp *model.Topology)) (ruleResp, string) {
	t.Helper()
	rr := do(r.s, http.MethodGet, "/api/topology", nil)
	var tp model.Topology
	if err := json.Unmarshal(rr.Body.Bytes(), &tp); err != nil || rr.Code != 200 {
		t.Fatalf("get: %d %v", rr.Code, err)
	}
	edit(&tp)
	// The editor omits the independent resources.
	raw := mustJSON(tp)
	var m map[string]any
	_ = json.Unmarshal(raw, &m)
	for _, k := range []string{"rule_sets", "mihomo_import", "remote_access"} {
		delete(m, k)
	}
	rr = do(r.s, http.MethodPut, "/api/topology", mustJSON(m))
	if rr.Code != 200 {
		t.Fatalf("put: %d %s", rr.Code, rr.Body.String())
	}
	var out ruleResp
	_ = json.Unmarshal(rr.Body.Bytes(), &out)
	return out, rr.Body.String()
}

func addRule(id, value string) func(tp *model.Topology) {
	return func(tp *model.Topology) {
		r := tp.Rules[0]
		r.ID, r.Name, r.MatchType, r.MatchValue, r.Manual = id, "合成 "+id, model.MatchSuffix, value, true
		tp.Rules = append(tp.Rules, r)
	}
}

func (r *ruleRig) hostDNS(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(r.s.HostRoot, "etc", "smartdns", "smartdns.conf"))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func (r *ruleRig) inSync(t *testing.T) bool {
	t.Helper()
	tp, _ := r.s.topology()
	b, err := r.s.compileTopo(tp)
	if err != nil {
		t.Fatal(err)
	}
	d, err := r.s.applier(true).InstalledDiff(b)
	return err == nil && d != nil && d.Empty()
}

func (r *ruleRig) last(t *testing.T) (*rulesAutoRecord, bool) {
	t.Helper()
	rr := do(r.s, http.MethodGet, "/api/rules/auto-apply", nil)
	var out struct {
		Enabled bool             `json:"enabled"`
		Pending bool             `json:"pending"`
		Last    *rulesAutoRecord `json:"last"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &out); err != nil || rr.Code != 200 {
		t.Fatalf("auto-apply: %d %s", rr.Code, rr.Body.String())
	}
	return out.Last, out.Pending
}

func (r *ruleRig) waitIdle(t *testing.T) *rulesAutoRecord {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if l, pending := r.last(t); !pending && l != nil && l.Status != FastScheduled {
			return l
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("the coalesced run did not finish")
	return nil
}

// A rule-only save installs through the gateway transaction: version +1,
// panel in sync, the rule on the host, and a rollback brings it back.
func TestRuleAutoApplyInstallsAndRollsBack(t *testing.T) {
	r := newRuleRig(t)
	v0 := installedVersion(t, r.s)
	out, _ := r.putRules(t, addRule("zz-synth", "synth.example.org"))
	if out.FastApply.Status != FastApplied || out.ApplyRequired == nil || *out.ApplyRequired || out.FastApply.Version != v0+1 {
		t.Fatalf("got %+v", out)
	}
	if installedVersion(t, r.s) != v0+1 || *r.activated != 2 || !r.inSync(t) {
		t.Fatalf("version %d activations %d", installedVersion(t, r.s), *r.activated)
	}
	if !strings.Contains(r.hostDNS(t), "# rule zz-synth ") {
		t.Fatal("rule not on the host")
	}
	if l, _ := r.last(t); l == nil || l.Status != FastApplied || len(l.Files) == 0 {
		t.Fatalf("last %+v", l)
	}
	if rr := do(r.s, http.MethodPost, "/api/rollback", mustJSON(map[string]any{"install": true})); rr.Code != 200 {
		t.Fatalf("rollback: %d %s", rr.Code, rr.Body.String())
	}
	if strings.Contains(r.hostDNS(t), "# rule zz-synth ") {
		t.Fatal("rollback kept the rule")
	}
}

// A save that does not change the rules carries no fast_apply.
func TestRuleAutoApplyAbsentWithoutRuleChange(t *testing.T) {
	r := newRuleRig(t)
	_, body := r.putRules(t, func(tp *model.Topology) {})
	if strings.Contains(body, "fast_apply") {
		t.Fatalf("unexpected: %s", body)
	}
}

func TestRuleAutoApplyRefusals(t *testing.T) {
	cases := []struct {
		name string
		prep func(t *testing.T, r *ruleRig)
		edit func(tp *model.Topology)
		want string
	}{
		{"switch off", func(t *testing.T, r *ruleRig) {
			off := false
			r.s.Store.Update(func(tp *model.Topology) (bool, error) { tp.Settings.RulesAutoApply = &off; return true, nil })
		}, nil, "关闭"},
		{"other pending change", func(t *testing.T, r *ruleRig) {
			r.s.Store.Update(func(tp *model.Topology) (bool, error) {
				tp.Settings.UnlistedDomesticDNS = !tp.Settings.UnlistedDomesticDNS
				return true, nil
			})
		}, nil, "未安装的改动"},
		{"mixed save", nil, func(tp *model.Topology) {
			tp.Settings.UnlistedDomesticDNS = !tp.Settings.UnlistedDomesticDNS
		}, "规则以外"},
		{"preflight blocks", func(t *testing.T, r *ruleRig) {
			r.hp.mu.Lock()
			r.hp.extra = "ipt ipv4 -P FORWARD DROP\nunit docker.service active enabled 5\n"
			r.hp.mu.Unlock()
		}, nil, "阻断"},
		{"node lock held", func(t *testing.T, r *ruleRig) {
			if !r.s.lockNode(localNodeID) {
				t.Fatal("lock")
			}
			t.Cleanup(func() { r.s.unlockNode(localNodeID) })
		}, nil, "网关正忙"},
		{"rate limit", func(t *testing.T, r *ruleRig) {
			now := r.s.now()
			for i := 0; i < rulesAutoHourMax; i++ {
				r.s.recordFastAttempt(rulesFastKey, now.Add(-time.Minute))
			}
		}, nil, "太频繁"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := newRuleRig(t)
			if c.prep != nil {
				c.prep(t, r)
			}
			v0 := installedVersion(t, r.s)
			edit := addRule("zz-synth", "synth.example.org")
			if c.edit != nil {
				e := c.edit
				edit = func(tp *model.Topology) { addRule("zz-synth", "synth.example.org")(tp); e(tp) }
			}
			out, _ := r.putRules(t, edit)
			if out.FastApply.Status != FastSkipped || out.ApplyRequired == nil || !*out.ApplyRequired || !strings.Contains(out.FastApply.Reason, c.want) {
				t.Fatalf("got %+v, want reason with %q", out, c.want)
			}
			if installedVersion(t, r.s) != v0 || *r.activated != 1 {
				t.Fatalf("installed anyway: version %d activations %d", installedVersion(t, r.s), *r.activated)
			}
		})
	}
}

// A preflight warning that needs confirmation stops the automatic install.
func TestRuleAutoApplyPreflightWarning(t *testing.T) {
	r := newRuleRig(t)
	r.hp.mu.Lock()
	r.hp.extra = ruleWarnExtra
	r.hp.mu.Unlock()
	out, _ := r.putRules(t, addRule("zz-synth", "synth.example.org"))
	if out.FastApply.Status != FastSkipped || !strings.Contains(out.FastApply.Reason, "警告") || *r.activated != 1 {
		t.Fatalf("got %+v", out)
	}
}

// A failing install is compensated by the transaction and reported.
func TestRuleAutoApplyFailureCompensated(t *testing.T) {
	r := newRuleRig(t)
	v0 := installedVersion(t, r.s)
	*r.fail = true
	out, _ := r.putRules(t, addRule("zz-synth", "synth.example.org"))
	if out.FastApply.Status != FastFailed || !*out.ApplyRequired || out.FastApply.Reason == "" {
		t.Fatalf("got %+v", out)
	}
	if installedVersion(t, r.s) != v0 || strings.Contains(r.hostDNS(t), "# rule zz-synth ") {
		t.Fatal("failed install left the change")
	}
}

// Saves in quick succession: the first installs, the next ones are
// coalesced into one later install of the final state.
func TestRuleAutoApplyCoalesces(t *testing.T) {
	r := newRuleRig(t)
	// b and c must land in the window however slow the saves are: the gap
	// is an hour until they have, then the coalesced run is due at once.
	r.s.rulesAuto.gap = time.Hour
	v0 := installedVersion(t, r.s)
	a, _ := r.putRules(t, addRule("zz-a", "a.synth.example.org"))
	b, _ := r.putRules(t, addRule("zz-b", "b.synth.example.org"))
	c, _ := r.putRules(t, addRule("zz-c", "c.synth.example.org"))
	r.releaseWindow()
	if a.FastApply.Status != FastApplied || b.FastApply.Status != FastScheduled || c.FastApply.Status != FastScheduled || *b.ApplyRequired {
		t.Fatalf("a %+v b %+v c %+v", a, b, c)
	}
	l := r.waitIdle(t)
	if l.Status != FastApplied || l.Trigger != "coalesced" || l.Version != v0+2 {
		t.Fatalf("last %+v", l)
	}
	if installedVersion(t, r.s) != v0+2 || *r.activated != 3 || !r.inSync(t) {
		t.Fatalf("version %d activations %d", installedVersion(t, r.s), *r.activated)
	}
	if d := r.hostDNS(t); !strings.Contains(d, "# rule zz-b ") || !strings.Contains(d, "# rule zz-c ") {
		t.Fatal("coalesced rules missing")
	}
}

// A non-rule change saved while a coalesced run waits: the run refuses
// (the stale base never installs the other change along).
func TestRuleAutoApplyConcurrentChangeRefused(t *testing.T) {
	// No timing window: the coalesced run is scheduled an hour out and
	// fired by hand after the concurrent change has landed.
	r := newRuleRig(t)
	r.s.rulesAuto.gap = time.Hour
	r.putRules(t, addRule("zz-a", "a.synth.example.org"))
	v1 := installedVersion(t, r.s)
	r.s.rulesAuto.mu.Lock()
	r.s.rulesAuto.lastRun = time.Now()
	r.s.rulesAuto.mu.Unlock()
	b, _ := r.putRules(t, addRule("zz-b", "b.synth.example.org"))
	if b.FastApply.Status != FastScheduled {
		t.Fatalf("b %+v", b)
	}
	r.s.Store.Update(func(tp *model.Topology) (bool, error) {
		tp.Settings.UnlistedDomesticDNS = !tp.Settings.UnlistedDomesticDNS
		return true, nil
	})
	r.s.rulesAuto.mu.Lock()
	if r.s.rulesAuto.timer == nil || !r.s.rulesAuto.timer.Stop() {
		r.s.rulesAuto.mu.Unlock()
		t.Fatal("no pending coalesced run")
	}
	r.s.rulesAuto.mu.Unlock()
	r.s.rulesAutoFire()
	l := r.waitIdle(t)
	if l.Status != FastSkipped || !strings.Contains(l.Reason, "未安装的改动") || installedVersion(t, r.s) != v1 {
		t.Fatalf("last %+v version %d", l, installedVersion(t, r.s))
	}
}

// An operator install between the save and the coalesced run: nothing is
// left to install, and the run says so instead of installing a stale state.
func TestRuleAutoApplyVersionMovedMeanwhile(t *testing.T) {
	r := newRuleRig(t)
	// No timing window: the coalesced run is scheduled an hour out and
	// fired by hand after the operator install.
	r.s.rulesAuto.gap = time.Hour
	r.putRules(t, addRule("zz-a", "a.synth.example.org"))
	if b, _ := r.putRules(t, addRule("zz-b", "b.synth.example.org")); b.FastApply.Status != FastScheduled {
		t.Fatalf("b %+v", b)
	}
	opInstall(t, r.s)
	v := installedVersion(t, r.s)
	r.s.rulesAuto.mu.Lock()
	if r.s.rulesAuto.timer == nil || !r.s.rulesAuto.timer.Stop() {
		r.s.rulesAuto.mu.Unlock()
		t.Fatal("no pending coalesced run")
	}
	r.s.rulesAuto.mu.Unlock()
	r.s.rulesAutoFire()
	l := r.waitIdle(t)
	if l.Status != FastNone || installedVersion(t, r.s) != v {
		t.Fatalf("last %+v", l)
	}
}

// Rule-set saves take the same path; a rule-set URL credential never
// appears in the answer or the record.
func TestRuleAutoApplyRuleSet(t *testing.T) {
	r := newRuleRig(t)
	r.s.RuleSetDir = filepath.Join(t.TempDir(), "rulesets")
	r.s.RuleSetFetch = func(RuleSetFetchOptions) RuleSetFetcher { return noFetch{} }
	const secret = "synthpw-0123456789"
	rr := do(r.s, http.MethodPost, "/api/rule-sets", []byte(`{"name":"合成集","url":"https://rules.example.net/x.list","auth":{"kind":"bearer","token":"`+secret+`"}}`))
	if rr.Code != 201 {
		t.Fatalf("rule-set: %d %s", rr.Code, rr.Body.String())
	}
	if strings.Contains(rr.Body.String(), secret) {
		t.Fatal("secret in the answer")
	}
	var rs ruleResp
	_ = json.Unmarshal(rr.Body.Bytes(), &rs)
	if rs.ApplyRequired == nil || rs.FastApply.Status == "" {
		t.Fatalf("rule-set: %s", rr.Body.String())
	}
	r.waitIdle(t)
	if raw, _, _ := r.s.Store.Get(rulesLastKey); strings.Contains(raw, secret) {
		t.Fatal("secret in the record")
	}
}

// Rule-set content does not enter the compiled bundle: a download or
// update needs no install (the host re-derives the lists).
func TestRuleSetContentIsBundleNeutral(t *testing.T) {
	r := newRuleRig(t)
	r.s.RuleSetDir = filepath.Join(t.TempDir(), "rulesets")
	// The switch only governs saves that change the compile: a download
	// is applied with it off too, with no install transaction.
	off := false
	r.s.Store.Update(func(tp *model.Topology) (bool, error) { tp.Settings.RulesAutoApply = &off; return true, nil })
	v0 := installedVersion(t, r.s)
	tp, _ := r.s.topology()
	before, err := r.s.compileTopo(tp)
	if err != nil {
		t.Fatal(err)
	}
	if err := r.s.activateContent("rs-synth", []byte("DOMAIN-SUFFIX,synth.example.org\n"), "text", nil, nil, nil, "", ""); err != nil {
		t.Fatal(err)
	}
	after, _ := r.s.compileTopo(tp)
	if before.Canonical() != after.Canonical() {
		t.Fatal("content changed the bundle")
	}
	if installedVersion(t, r.s) != v0 || *r.activated != 1 {
		t.Fatalf("download installed: version %d activations %d", installedVersion(t, r.s), *r.activated)
	}
	if l, _ := r.last(t); l != nil {
		t.Fatalf("download left an auto-apply record %+v", l)
	}
}

// ruleWarnExtra: a host report line that gives a warning, nothing blocking
// (INPUT policy DROP).
const ruleWarnExtra = "ipt ipv4 -P INPUT DROP\n"

// noFetch refuses every download (nothing leaves the test).
type noFetch struct{}

func (noFetch) Get(context.Context, string) ([]byte, error) {
	return nil, errors.New("synthetic: no download")
}

// busyRig: a coalesced run is pending while the gateway node lock is held,
// so its first evaluation finds the gateway busy. between runs (in the
// firing goroutine, while no evaluation runs) after each failed attempt;
// it is told the attempt number (1-based).
// holdWindow puts the next save inside the coalescing window however long
// a loaded machine takes to serve it: the gap is an hour until
// releaseWindow, which makes the scheduled run due after 150 ms.
func (r *ruleRig) holdWindow() {
	r.s.rulesAuto.mu.Lock()
	r.s.rulesAuto.gap = time.Hour
	r.s.rulesAuto.lastRun = time.Now()
	r.s.rulesAuto.mu.Unlock()
}

func (r *ruleRig) releaseWindow() {
	r.s.rulesAuto.mu.Lock()
	r.s.rulesAuto.gap = 150 * time.Millisecond
	if r.s.rulesAuto.timer != nil {
		r.s.rulesAuto.timer.Reset(150 * time.Millisecond)
	}
	r.s.rulesAuto.mu.Unlock()
}

func busyRig(t *testing.T, between func(r *ruleRig, attempt int)) (*ruleRig, int64, *int) {
	t.Helper()
	oldWait, oldSleep := rulesAutoBusyWait, rulesAutoSleep
	t.Cleanup(func() { rulesAutoBusyWait, rulesAutoSleep = oldWait, oldSleep })
	r := newRuleRig(t)
	r.s.rulesAuto.gap = 500 * time.Millisecond
	r.putRules(t, addRule("zz-a", "a.synth.example.org"))
	v1 := installedVersion(t, r.s)
	// The next save falls in the window however slowly the machine serves
	// it (an hour-long gap while it is made), then the coalesced run is due
	// after the usual 500 ms.
	r.s.rulesAuto.mu.Lock()
	r.s.rulesAuto.gap = time.Hour
	r.s.rulesAuto.lastRun = time.Now()
	r.s.rulesAuto.mu.Unlock()
	if b, _ := r.putRules(t, addRule("zz-b", "b.synth.example.org")); b.FastApply.Status != FastScheduled {
		t.Fatalf("b %+v", b)
	}
	r.s.rulesAuto.mu.Lock()
	r.s.rulesAuto.gap = 500 * time.Millisecond
	if r.s.rulesAuto.timer != nil {
		r.s.rulesAuto.timer.Reset(500 * time.Millisecond)
	}
	r.s.rulesAuto.mu.Unlock()
	if !r.s.lockNode(localNodeID) {
		t.Fatal("lock")
	}
	locked := true
	unlock := func() {
		if locked {
			locked = false
			r.s.unlockNode(localNodeID)
		}
	}
	t.Cleanup(unlock)
	calls := 0
	rulesAutoBusyWait = 10 * time.Millisecond
	rulesAutoSleep = func(d time.Duration) {
		calls++
		if between != nil {
			between(&ruleRig{s: r.s, hp: r.hp, activated: r.activated, fail: r.fail}, calls)
		}
		if calls == 1 && between != nil {
			unlock()
		}
		time.Sleep(d)
	}
	return r, v1, &calls
}

// Busy for one attempt, then free: the retry installs the final state.
func TestRuleAutoBusyThenApplied(t *testing.T) {
	r, v1, calls := busyRig(t, func(*ruleRig, int) {})
	l := r.waitIdle(t)
	if l.Status != FastApplied || l.Version != v1+1 || *calls != 1 {
		t.Fatalf("last %+v retries %d", l, *calls)
	}
	if installedVersion(t, r.s) != v1+1 || *r.activated != 3 || !r.inSync(t) {
		t.Fatalf("version %d activations %d", installedVersion(t, r.s), *r.activated)
	}
}

// An operator install and a further save during the wait: the installed
// version moved away from the recorded base, so the retry refuses instead
// of installing on a stale snapshot.
func TestRuleAutoBusyVersionChangedRefused(t *testing.T) {
	var v2 int64
	r, _, _ := busyRig(t, func(r *ruleRig, attempt int) {
		if attempt != 1 {
			return
		}
		r.s.unlockNode(localNodeID)
		opInstall(t, r.s)
		v2 = installedVersion(t, r.s)
		r.putRules(t, addRule("zz-c", "c.synth.example.org"))
		r.s.lockNode(localNodeID) // busyRig releases it
	})
	l := r.waitIdle(t)
	if l.Status != FastSkipped || !strings.Contains(l.Reason, "别的版本") || !l.applyRequired() {
		t.Fatalf("last %+v", l)
	}
	if installedVersion(t, r.s) != v2 || *r.activated != 3 {
		t.Fatalf("installed anyway: version %d activations %d", installedVersion(t, r.s), *r.activated)
	}
}

// A configuration or safety change during the wait fails closed.
func TestRuleAutoBusyConditionChangedRefused(t *testing.T) {
	cases := []struct {
		name   string
		change func(r *ruleRig)
		want   string
	}{
		{"non-rule config change", func(r *ruleRig) {
			r.s.Store.Update(func(tp *model.Topology) (bool, error) {
				tp.Settings.UnlistedDomesticDNS = !tp.Settings.UnlistedDomesticDNS
				return true, nil
			})
		}, "未安装的改动"},
		{"switch turned off", func(r *ruleRig) {
			off := false
			r.s.Store.Update(func(tp *model.Topology) (bool, error) { tp.Settings.RulesAutoApply = &off; return true, nil })
		}, "关闭"},
		{"preflight now blocks", func(r *ruleRig) {
			r.hp.mu.Lock()
			r.hp.extra = "ipt ipv4 -P FORWARD DROP\nunit docker.service active enabled 5\n"
			r.hp.mu.Unlock()
		}, "阻断"},
		{"preflight now warns", func(r *ruleRig) {
			r.hp.mu.Lock()
			r.hp.extra = ruleWarnExtra
			r.hp.mu.Unlock()
		}, "警告"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r, v1, _ := busyRig(t, func(r *ruleRig, attempt int) {
				if attempt == 1 {
					c.change(r)
				}
			})
			l := r.waitIdle(t)
			if l.Status != FastSkipped || !strings.Contains(l.Reason, c.want) || !l.applyRequired() {
				t.Fatalf("last %+v, want %q", l, c.want)
			}
			if installedVersion(t, r.s) != v1 || *r.activated != 2 {
				t.Fatalf("installed anyway: version %d activations %d", installedVersion(t, r.s), *r.activated)
			}
		})
	}
}

// Busy throughout: the run gives up after rulesAutoBusyRetries retries and
// records apply required, never applied.
func TestRuleAutoBusyRetriesExhausted(t *testing.T) {
	r, v1, calls := busyRig(t, nil)
	l := r.waitIdle(t)
	if l.Status != FastSkipped || l.Reason != "网关正忙" || !l.applyRequired() || *calls != rulesAutoBusyRetries {
		t.Fatalf("last %+v retries %d", l, *calls)
	}
	if installedVersion(t, r.s) != v1 || *r.activated != 2 {
		t.Fatalf("installed anyway: version %d activations %d", installedVersion(t, r.s), *r.activated)
	}
}

// Saves during the wait start another coalesced run; the gateway
// transactions never overlap and the end state is installed once each.
func TestRuleAutoBusySingleTransaction(t *testing.T) {
	var inFlight, maxInFlight int32
	var mu sync.Mutex
	r, v1, _ := busyRig(t, func(r *ruleRig, attempt int) {
		if attempt == 1 {
			r.putRules(t, addRule("zz-c", "c.synth.example.org"))
		}
	})
	prev := r.s.Activate
	r.s.Activate = func() error {
		mu.Lock()
		inFlight++
		if inFlight > maxInFlight {
			maxInFlight = inFlight
		}
		mu.Unlock()
		time.Sleep(50 * time.Millisecond)
		err := prev()
		mu.Lock()
		inFlight--
		mu.Unlock()
		return err
	}
	// Wait for both runs (the second is scheduled during the first).
	deadline := time.Now().Add(10 * time.Second)
	for !r.inSync(t) && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	l := r.waitIdle(t)
	if maxInFlight > 1 {
		t.Fatalf("overlapping transactions: %d", maxInFlight)
	}
	if !r.inSync(t) || installedVersion(t, r.s) > v1+2 || installedVersion(t, r.s) <= v1 || (l.Status != FastApplied && l.Status != FastNone) {
		t.Fatalf("last %+v version %d (base %d)", l, installedVersion(t, r.s), v1)
	}
	if d := r.hostDNS(t); !strings.Contains(d, "# rule zz-b ") || !strings.Contains(d, "# rule zz-c ") {
		t.Fatal("rules missing")
	}
}

// restartPanel drops this process's in-memory coalescing state and gives
// the server a new boot identity, as a panel restart does (same store).
func (r *ruleRig) restartPanel() {
	r.s.rulesAuto.mu.Lock()
	if r.s.rulesAuto.timer != nil {
		r.s.rulesAuto.timer.Stop()
	}
	r.s.rulesAuto.timer, r.s.rulesAuto.base, r.s.rulesAuto.active = nil, nil, 0
	r.s.rulesAuto.lastRun = time.Time{}
	r.s.rulesAuto.mu.Unlock()
	r.s.deployBootOnce = sync.Once{}
	r.s.deployBoot = ""
}

// T4: a scheduled run lost to a panel restart is persisted as interrupted
// (apply required), stays so across reads and further restarts, never
// installs on its own, and a later save is evaluated afresh.
func TestRuleAutoApplyScheduledLostOnRestart(t *testing.T) {
	r := newRuleRig(t)
	r.s.rulesAuto.gap = time.Hour
	r.putRules(t, addRule("zz-a", "a.synth.example.org"))
	v1 := installedVersion(t, r.s)
	r.s.rulesAuto.mu.Lock()
	r.s.rulesAuto.lastRun = time.Now()
	r.s.rulesAuto.mu.Unlock()
	if b, _ := r.putRules(t, addRule("zz-b", "b.synth.example.org")); b.FastApply.Status != FastScheduled {
		t.Fatalf("b %+v", b)
	}
	// Same process, timer pending: still scheduled.
	if l, pending := r.last(t); !pending || l == nil || l.Status != FastScheduled {
		t.Fatalf("before restart %+v pending %v", l, pending)
	}
	r.restartPanel()
	for i := 0; i < 2; i++ {
		l, pending := r.last(t)
		if pending || l == nil || l.Status != FastSkipped || !l.Interrupted || l.Reason != rulesInterrupted {
			t.Fatalf("read %d after restart %+v pending %v", i, l, pending)
		}
		raw, _, _ := r.s.Store.Get(rulesLastKey)
		if strings.Contains(raw, `"status":"scheduled"`) || !strings.Contains(raw, `"interrupted":true`) {
			t.Fatalf("not persisted: %s", raw)
		}
	}
	r.restartPanel()
	if l, _ := r.last(t); l == nil || l.Status != FastSkipped || !l.Interrupted {
		t.Fatalf("second restart %+v", l)
	}
	time.Sleep(50 * time.Millisecond)
	if installedVersion(t, r.s) != v1 || *r.activated != 2 {
		t.Fatalf("installed without re-validation: version %d activations %d", installedVersion(t, r.s), *r.activated)
	}
	// A new save after the restart: zz-b is still pending, so the gateway is
	// not in sync and the save asks for an install; never "scheduled".
	c, _ := r.putRules(t, addRule("zz-c", "c.synth.example.org"))
	if c.FastApply.Status != FastSkipped || c.ApplyRequired == nil || !*c.ApplyRequired {
		t.Fatalf("c %+v", c)
	}
	if l, _ := r.last(t); l == nil || l.Status != FastSkipped || l.Interrupted {
		t.Fatalf("new save's record %+v", l)
	}
	if installedVersion(t, r.s) != v1 {
		t.Fatal("installed")
	}
}

// T4: a record written before the boot field existed (an older panel) is
// treated as another process's.
func TestRuleAutoApplyLegacyScheduledRecord(t *testing.T) {
	r := newRuleRig(t)
	_ = r.s.Store.Put(rulesLastKey, `{"at":"2026-11-17T00:00:00Z","trigger":"unlock","status":"scheduled","reason":"连续保存已合并，稍后自动生效"}`)
	if l, pending := r.last(t); pending || l == nil || l.Status != FastSkipped || !l.Interrupted {
		t.Fatalf("legacy %+v", l)
	}
}
