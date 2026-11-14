package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/radowitz/meridian/internal/compile"
	"github.com/radowitz/meridian/internal/model"
	"github.com/radowitz/meridian/internal/unlock"
)

// Automatic install of unlock decisions, with an injectable clock and the
// fake host (activation shim, fake preflight). Nothing contacts a host.

type autoRig struct {
	s         *Server
	hp        *fakeHostPreflight
	activated *int
	fail      *bool
	now       time.Time
}

func newAutoRig(t *testing.T, on bool, tune func(*model.UnlockProbeSettings)) *autoRig {
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
	rig := &autoRig{s: s, hp: hp, activated: &n, fail: &fail, now: time.Date(2026, 11, 14, 8, 0, 0, 0, time.UTC)}
	s.clock = func() time.Time { return rig.now }
	// The operator's first install (reviewed preflight), recording the
	// decisions it used.
	rr := do(s, http.MethodPost, "/api/host/preflight", nil)
	var out struct{ Preflight preflightRecord }
	if err := json.Unmarshal(rr.Body.Bytes(), &out); err != nil || rr.Code != 200 {
		t.Fatalf("preflight: %d %s", rr.Code, rr.Body.String())
	}
	if rr := do(s, http.MethodPost, "/api/apply", mustJSON(map[string]any{"install": true, "preflight_id": out.Preflight.ID})); rr.Code != 200 || n != 1 {
		t.Fatalf("first install: %d %s", rr.Code, rr.Body.String())
	}
	if _, err := s.Store.Update(func(tp *model.Topology) (bool, error) {
		p := &model.UnlockProbeSettings{AutoApply: on}
		if tune != nil {
			tune(p)
		}
		tp.Settings.UnlockProbe = p
		return true, nil
	}); err != nil {
		t.Fatal(err)
	}
	return rig
}

// decide puts a rule's unlock state on exit (preferred member when it is
// the group's first), as two scheduled failures would.
func (r *autoRig) decide(t *testing.T, rule, pool, preferred, exit string) {
	t.Helper()
	s := r.s
	s.mu.Lock()
	defer s.mu.Unlock()
	snap := s.loadUnlock()
	st := unlock.State{Pool: pool, Preferred: preferred, Active: exit, Demoted: exit != preferred,
		Known: map[string]bool{preferred: exit == preferred, exit: true}}
	snap.Services[rule] = st
	snap.PendingApply = true
	if err := s.saveUnlock(snap); err != nil {
		t.Fatal(err)
	}
}

func (r *autoRig) run(t *testing.T) *autoCheck {
	t.Helper()
	return r.s.maybeAutoApply("test")
}

func (r *autoRig) pending() bool {
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	return r.s.loadUnlock().PendingApply
}

func TestAutoApplyOffChangesNothing(t *testing.T) {
	r := newAutoRig(t, false, nil)
	r.decide(t, "auto-openai", "us", "us", "us-2")
	if c := r.run(t); c != nil {
		t.Fatalf("evaluated with the setting off: %+v", c)
	}
	if *r.activated != 1 || !r.pending() || len(r.s.loadAuto().Attempts) != 0 || r.s.loadAuto().Last != nil {
		t.Fatal("something changed with auto_apply off")
	}
}

func TestAutoApplyAppliesAndSwitchesBack(t *testing.T) {
	r := newAutoRig(t, true, nil)
	if c := r.run(t); c.Code != AutoNotPending {
		t.Fatalf("nothing pending: %+v", c)
	}
	r.decide(t, "auto-openai", "us", "us", "us-2")
	c := r.run(t)
	if c.Code != AutoApplied || *r.activated != 2 || r.pending() {
		t.Fatalf("apply: %+v activated %d pending %v", c, *r.activated, r.pending())
	}
	for _, f := range c.Files {
		if !strings.HasPrefix(f, "nodes/gw/") {
			t.Fatalf("file %s", f)
		}
	}
	d := r.s.loadAuto()
	if !d.Recorded || d.Installed["auto-openai"] != "us-2" || len(d.Attempts) != 1 || !d.Attempts[0].OK || d.Attempts[0].Decisions["auto-openai"] != "us-2" {
		t.Fatalf("record %+v", d)
	}
	_, hist, _ := unlockView(t, r.s)
	found := false
	for _, h := range hist {
		found = found || strings.Contains(h.Note, "自动安装解锁决定：已安装")
	}
	if !found {
		t.Fatal("no history entry for the automatic install")
	}
	if c := r.run(t); c.Code != AutoNotPending || *r.activated != 2 {
		t.Fatalf("second evaluation reinstalled: %+v", c)
	}
	// Recovery: back to the preferred member, by the same path.
	r.now = r.now.Add(11 * time.Minute)
	r.decide(t, "auto-openai", "us", "us", "us")
	if c := r.run(t); c.Code != AutoApplied || *r.activated != 3 || r.s.loadAuto().Installed["auto-openai"] != "" {
		t.Fatalf("switch back: %+v", c)
	}
}

func TestAutoApplyRefusals(t *testing.T) {
	cases := []struct {
		name string
		prep func(t *testing.T, r *autoRig) func()
		want string
	}{
		{"out of sync before the decision", func(t *testing.T, r *autoRig) func() {
			if _, err := r.s.Store.Update(func(tp *model.Topology) (bool, error) {
				tp.Rules = append([]model.Rule{{ID: "m-new", Name: "new", Enabled: true, Manual: true, MatchType: model.MatchSuffix, MatchValue: "new.example.net", TargetExit: "jp"}}, tp.Rules...)
				return true, nil
			}); err != nil {
				t.Fatal(err)
			}
			return nil
		}, AutoOutOfSync},
		{"a gateway file outside the allow-list", func(t *testing.T, r *autoRig) func() {
			r.s.autoMutate = func(b *compile.Bundle) { b.Files["nodes/gw/usr/local/sbin/meridian-up.sh"] += "\n# x\n" }
			return nil
		}, AutoFilesRefused},
		{"another node's file", func(t *testing.T, r *autoRig) func() {
			r.s.autoMutate = func(b *compile.Bundle) {
				for p := range b.Files {
					if strings.HasPrefix(p, "nodes/us/") {
						b.Files[p] += "\n"
						return
					}
				}
				t.Fatal("no file of node us")
			}
			return nil
		}, AutoFilesRefused},
		{"preflight blocks", func(t *testing.T, r *autoRig) func() {
			r.hp.mu.Lock()
			r.hp.extra = "ipt ipv4 -P FORWARD DROP\nunit docker.service active enabled 5\n"
			r.hp.mu.Unlock()
			return nil
		}, AutoPreflightStop},
		{"node lock held", func(t *testing.T, r *autoRig) func() {
			if !r.s.lockNode(localNodeID) {
				t.Fatal("lock")
			}
			return func() { r.s.unlockNode(localNodeID) }
		}, AutoBusy},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := newAutoRig(t, true, nil)
			done := c.prep(t, r)
			r.decide(t, "auto-openai", "us", "us", "us-2")
			got := r.run(t)
			if done != nil {
				done()
			}
			if got == nil || got.Code != c.want || *r.activated != 1 || !r.pending() {
				t.Fatalf("got %+v (activated %d, pending %v), want %s", got, *r.activated, r.pending(), c.want)
			}
			// The reason is in the panel view.
			rr := do(r.s, http.MethodGet, "/api/unlock", nil)
			if !strings.Contains(rr.Body.String(), `"code":"`+c.want+`"`) {
				t.Fatalf("view lacks the reason: %s", rr.Body.String())
			}
		})
	}
}

func TestAutoApplyRateLimits(t *testing.T) {
	r := newAutoRig(t, true, func(p *model.UnlockProbeSettings) { p.AutoApplyDailyMax = 2 })
	r.decide(t, "auto-openai", "us", "us", "us-2")
	if c := r.run(t); c.Code != AutoApplied {
		t.Fatalf("%+v", c)
	}
	r.now = r.now.Add(5 * time.Minute)
	r.decide(t, "auto-openai", "us", "us", "us")
	if c := r.run(t); c.Code != AutoGap || *r.activated != 2 {
		t.Fatalf("gap: %+v", c)
	}
	r.now = r.now.Add(6 * time.Minute)
	if c := r.run(t); c.Code != AutoApplied || *r.activated != 3 {
		t.Fatalf("after the gap: %+v", c)
	}
	r.now = r.now.Add(11 * time.Minute)
	r.decide(t, "auto-openai", "us", "us", "us-2")
	if c := r.run(t); c.Code != AutoDailyCap || *r.activated != 3 {
		t.Fatalf("daily cap: %+v", c)
	}
	r.now = r.now.Add(24 * time.Hour)
	if c := r.run(t); c.Code != AutoApplied {
		t.Fatalf("next day: %+v", c)
	}
}

func TestAutoApplyFailureCompensatedNoLoop(t *testing.T) {
	r := newAutoRig(t, true, nil)
	before := r.s.loadAuto().Installed
	r.decide(t, "auto-openai", "us", "us", "us-2")
	*r.fail = true
	c := r.run(t)
	// Activations: the failed one, then the compensation's.
	if c.Code != AutoInstallFailed || !r.pending() || *r.activated != 3 {
		t.Fatalf("failure: %+v (activated %d)", c, *r.activated)
	}
	d := r.s.loadAuto()
	if !sameDec(d.Installed, before) || len(d.Attempts) != 1 || d.Attempts[0].OK || !strings.Contains(d.Attempts[0].Code, "compensated") {
		t.Fatalf("record after failure: %+v", d)
	}
	// No retry loop: the tick keeps evaluating but does not install.
	for i := 0; i < 5; i++ {
		r.now = r.now.Add(time.Minute)
		r.s.tickUnlock()
	}
	if *r.activated != 3 || r.s.loadAuto().Last.Code != AutoBackoff {
		t.Fatalf("retried within the back-off: activated %d, last %+v", *r.activated, r.s.loadAuto().Last)
	}
	// After the back-off the same decision is tried once more.
	r.now = r.now.Add(autoBackoff)
	if c := r.run(t); c.Code != AutoApplied || *r.activated != 4 || r.pending() {
		t.Fatalf("after the back-off: %+v", c)
	}
}
