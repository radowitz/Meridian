package api

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/radowitz/meridian/internal/model"
	"github.com/radowitz/meridian/internal/probe"
	"github.com/radowitz/meridian/internal/unlock"
)

// 确认 / 手动 on the unlock page (POST /api/unlock/adopt), AI out of scope
// and the automatic apply of the saves. Synthetic data only.

func identOf(t *testing.T, s *Server, exit string) string {
	t.Helper()
	_, regions, err := s.matrixNow()
	if err != nil {
		t.Fatal(err)
	}
	for _, reg := range regions {
		for _, e := range reg.Exits {
			if e.ID == exit {
				return e.Identity
			}
		}
	}
	t.Fatalf("exit %s not in matrix", exit)
	return ""
}

func adoptJSON(t *testing.T, s *Server, body map[string]any) (int, map[string]any) {
	t.Helper()
	rr := do(s, http.MethodPost, "/api/unlock/adopt", mustJSON(body))
	var out map[string]any
	_ = json.Unmarshal(rr.Body.Bytes(), &out)
	return rr.Code, out
}

func groupOf(t *testing.T, s *Server, id string) model.RegionGroup {
	t.Helper()
	g, ok := mustTopo(t, s).GroupByID(id)
	if !ok {
		t.Fatalf("no group %s", id)
	}
	return g
}

func ruleOf(t *testing.T, s *Server, id string) model.Rule {
	t.Helper()
	for _, r := range mustTopo(t, s).Rules {
		if r.ID == id {
			return r
		}
	}
	t.Fatalf("no rule %s", id)
	return model.Rule{}
}

// The matrix has no AI service or section; AI results stored before are
// read and ignored; "probe everything" sends no AI service anywhere.
func TestUnlockNoAIServices(t *testing.T) {
	f := &fakeProber{}
	s := probeServer(t, f)
	now := time.Now().UTC()
	s.mu.Lock()
	s.recordResults(stampItems(s,
		item("auto-openai", "us", unlock.FamilyIPv4, probe.CatUnlocked, 10, now),
		item("auto-gemini", "us", unlock.FamilyIPv4, probe.CatUnlocked, 10, now),
		item("youtube-premium", "us", unlock.FamilyIPv4, probe.CatUnlocked, 10, now)))
	s.mu.Unlock()
	_, regions, err := s.matrixNow()
	if err != nil {
		t.Fatal(err)
	}
	for _, reg := range regions {
		if reg.Code == "ai" {
			t.Fatal("AI section")
		}
		for _, svc := range reg.Services {
			if probe.IsAI(svc.ID) {
				t.Fatalf("AI service %s in %s", svc.ID, reg.Code)
			}
			if reg.Code == probe.RegionGlobal {
				a, _ := probe.Lookup(svc.ID)
				if a.Section != probe.SectionInternational {
					t.Fatalf("global row %s is %s", svc.ID, a.Section)
				}
			}
		}
	}
	rr := do(s, http.MethodGet, "/api/unlock/results", nil)
	if rr.Code != 200 || strings.Contains(rr.Body.String(), "auto-openai") || strings.Contains(rr.Body.String(), "auto-gemini") {
		t.Fatalf("old AI results shown: %d", rr.Code)
	}
	if !strings.Contains(rr.Body.String(), "youtube-premium") {
		t.Fatal("streaming result lost")
	}
	rr = do(s, http.MethodGet, "/api/unlock/jobs", nil)
	if strings.Contains(rr.Body.String(), `"service":"auto-openai"`) || strings.Contains(rr.Body.String(), `"auto-gemini"`) {
		t.Fatal("AI service in catalog")
	}
	// Probe everything: no AI request to any exit.
	runJob(t, s, `{}`)
	if len(f.requests()) == 0 {
		t.Fatal("nothing probed")
	}
	for _, req := range f.requests() {
		for _, svc := range req.Services {
			if probe.IsAI(svc) {
				t.Fatalf("AI probe %s sent to %s", svc, req.ExitID)
			}
		}
	}
	for _, svc := range []string{"auto-openai", "auto-gemini"} {
		if rr := do(s, http.MethodPost, "/api/unlock/run", mustJSON(map[string]any{"services": []string{svc}})); rr.Code == http.StatusAccepted {
			t.Fatalf("AI run accepted: %s", svc)
		}
		if code, _ := adoptJSON(t, s, map[string]any{"service": svc, "exit": "us"}); code != http.StatusNotFound {
			t.Fatalf("AI adopt %s: %d", svc, code)
		}
	}
	// AI rules keep the US group (the default table).
	for _, id := range []string{"auto-openai", "auto-anthropic", "auto-gemini", "auto-copilot", "auto-perplexity", "auto-grok"} {
		if r := ruleOf(t, s, id); r.TargetGroup != "us" {
			t.Fatalf("%s targets %q", id, r.TargetGroup)
		}
	}
}

// An AI rule is never a service rule of a streaming service, even when it
// carries one of its domains; 确认 leaves it alone.
func TestUnlockAdoptNeverMovesAIRules(t *testing.T) {
	s := probeServer(t, &fakeProber{})
	if _, err := s.Store.Update(func(tp *model.Topology) (bool, error) {
		tp.Rules = append(tp.Rules, model.Rule{ID: "u-mixed", Name: "mixed", Enabled: true, MatchType: model.MatchSuffix, MatchValue: "chatgpt.com",
			Domains: []string{"chatgpt.com", "youtube.com"}, TargetGroup: "us"})
		return true, nil
	}); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	s.mu.Lock()
	s.recordResults(stampItems(s, item("youtube-premium", "jp", unlock.FamilyIPv4, probe.CatUnlocked, 10, now)))
	s.mu.Unlock()
	code, pv := adoptJSON(t, s, map[string]any{"service": "youtube-premium", "exit": "jp", "preview": true})
	if code != 200 || strings.Contains(string(mustJSON(pv["service_rules"])), "u-mixed") {
		t.Fatalf("preview %d %v", code, pv)
	}
	if code, out := adoptJSON(t, s, map[string]any{"service": "youtube-premium", "exit": "jp"}); code != 200 {
		t.Fatalf("adopt %d %v", code, out)
	}
	if r := ruleOf(t, s, "u-mixed"); r.TargetGroup != "us" {
		t.Fatalf("AI rule moved to %q", r.TargetGroup)
	}
	// 手动 to a group or a pinned exit leaves them alone too.
	for _, b := range []map[string]any{
		{"service": "youtube-premium", "group": "jp", "manual": true, "identity": groupIdentOf(t, s, "youtube-premium", "jp")},
		{"service": "youtube-premium", "exit": "us-2", "manual": true, "identity": identOf(t, s, "us-2")},
	} {
		if code, out := adoptJSON(t, s, b); code != 200 {
			t.Fatalf("manual %d %v", code, out)
		}
		if r := ruleOf(t, s, "u-mixed"); r.TargetGroup != "us" || r.TargetExit != "" {
			t.Fatalf("AI rule moved: %+v", r)
		}
	}
	for _, id := range []string{"auto-openai", "auto-gemini"} {
		if r := ruleOf(t, s, id); r.TargetGroup != "us" {
			t.Fatalf("%s moved to %q", id, r.TargetGroup)
		}
	}
}

// groupIdentOf is the identity the matrix shows for a group option of a
// service.
func groupIdentOf(t *testing.T, s *Server, service, group string) string {
	t.Helper()
	_, regions, err := s.matrixNow()
	if err != nil {
		t.Fatal(err)
	}
	for _, reg := range regions {
		for _, svc := range reg.Services {
			if svc.ID != service {
				continue
			}
			for _, g := range svc.Groups {
				if g.ID == group {
					return g.Identity
				}
			}
		}
	}
	return ""
}

func serviceRow(t *testing.T, s *Server, service string) matrixService {
	t.Helper()
	_, regions, err := s.matrixNow()
	if err != nil {
		t.Fatal(err)
	}
	for _, reg := range regions {
		for _, svc := range reg.Services {
			if svc.ID == service {
				return svc
			}
		}
	}
	t.Fatalf("no row %s", service)
	return matrixService{}
}

// rulesListTarget is the rule's target as the Rules page reads it (the
// shared topology, GET /api/topology).
func rulesListTarget(t *testing.T, s *Server, id string) (group, exit string) {
	t.Helper()
	rr := do(s, http.MethodGet, "/api/topology", nil)
	var tp model.Topology
	if err := json.Unmarshal(rr.Body.Bytes(), &tp); err != nil || rr.Code != 200 {
		t.Fatalf("get: %d %v", rr.Code, err)
	}
	for _, r := range tp.Rules {
		if r.ID == id {
			return r.TargetGroup, r.TargetExit
		}
	}
	t.Fatalf("no rule %s", id)
	return "", ""
}

// 手动 to a group (出口组): the rules follow the group; no group changes.
// The matrix lists the group with its preferred exit, and the current
// direction and the Rules page show the new target after the save.
func TestUnlockManualGroup(t *testing.T) {
	s := probeServer(t, &fakeProber{})
	now := time.Now().UTC()
	s.mu.Lock()
	s.recordResults(stampItems(s, item("youtube-premium", "us", unlock.FamilyIPv4, probe.CatUnlocked, 10, now)))
	s.mu.Unlock()
	row := serviceRow(t, s, "youtube-premium")
	if row.Current == nil || row.Current.Group != "us" || row.Current.Pinned || row.Current.Exit == "" {
		t.Fatalf("current %+v", row.Current)
	}
	var jp *matrixGroupOpt
	for i := range row.Groups {
		if row.Groups[i].ID == "jp" {
			jp = &row.Groups[i]
		}
	}
	if jp == nil || jp.Preferred != "jp" || jp.Identity == "" || jp.Name == "" {
		t.Fatalf("groups %+v", row.Groups)
	}
	groups := canonJSON(mustTopo(t, s).Groups)
	body := map[string]any{"service": "youtube-premium", "group": "jp", "manual": true, "identity": jp.Identity}
	body["preview"] = true
	code, pv := adoptJSON(t, s, body)
	if code != 200 || pv["kind"] != "group" || pv["group"] != "jp" || pv["other_rules"].(float64) != 0 {
		t.Fatalf("preview %d %v", code, pv)
	}
	delete(body, "preview")
	code, out := adoptJSON(t, s, body)
	if code != 200 || out["kind"] != "group" || out["group"] != "jp" || out["fast_apply"] == nil {
		t.Fatalf("save %d %v", code, out)
	}
	if r := ruleOf(t, s, "youtube-premium"); r.TargetGroup != "jp" || r.TargetExit != "" {
		t.Fatalf("rule %+v", r)
	}
	if canonJSON(mustTopo(t, s).Groups) != groups {
		t.Fatal("group changed")
	}
	if g, e := rulesListTarget(t, s, "youtube-premium"); g != "jp" || e != "" {
		t.Fatalf("rules list %q %q", g, e)
	}
	if c := serviceRow(t, s, "youtube-premium").Current; c == nil || c.Group != "jp" || c.Exit != "jp" || c.Pinned {
		t.Fatalf("current after %+v", c)
	}
	for _, id := range []string{"auto-openai", "auto-gemini"} {
		if r := ruleOf(t, s, id); r.TargetGroup != "us" {
			t.Fatalf("%s moved to %q", id, r.TargetGroup)
		}
	}
}

// 手动 to an exit (具体节点): the rules pin it, unlocked or not; no group
// changes; the result row still says what was measured.
func TestUnlockManualPin(t *testing.T) {
	s := probeServer(t, &fakeProber{})
	now := time.Now().UTC()
	s.mu.Lock()
	s.recordResults(stampItems(s,
		item("youtube-premium", "us", unlock.FamilyIPv4, probe.CatUnlocked, 10, now),
		item("youtube-premium", "us-2", unlock.FamilyIPv4, probe.CatNotUnlocked, 10, now)))
	s.mu.Unlock()
	id := identOf(t, s, "us-2")
	groups := canonJSON(mustTopo(t, s).Groups)
	code, pv := adoptJSON(t, s, map[string]any{"service": "youtube-premium", "exit": "us-2", "manual": true, "identity": id, "preview": true})
	if code != 200 || pv["kind"] != "exit" || pv["group"] != "" || pv["other_rules"].(float64) != 0 {
		t.Fatalf("preview %d %v", code, pv)
	}
	code, out := adoptJSON(t, s, map[string]any{"service": "youtube-premium", "exit": "us-2", "manual": true, "identity": id})
	if code != 200 || out["kind"] != "exit" || out["exit"] != "us-2" || out["fast_apply"] == nil {
		t.Fatalf("manual %d %v", code, out)
	}
	if r := ruleOf(t, s, "youtube-premium"); r.TargetExit != "us-2" || r.TargetGroup != "" {
		t.Fatalf("rule %+v", r)
	}
	if canonJSON(mustTopo(t, s).Groups) != groups {
		t.Fatal("group changed")
	}
	if g, e := rulesListTarget(t, s, "youtube-premium"); g != "" || e != "us-2" {
		t.Fatalf("rules list %q %q", g, e)
	}
	_, regions, _ := s.matrixNow()
	if c := cellAt(t, regions, "youtube-premium", "us-2"); c.State != cellBlocked {
		t.Fatalf("cell rewritten: %+v", c)
	}
	if c := serviceRow(t, s, "youtube-premium").Current; c == nil || !c.Pinned || c.Exit != "us-2" {
		t.Fatalf("current %+v", c)
	}
	// 确认 of the recommendation (us) moves the rules back to the group.
	if code, out := adoptJSON(t, s, map[string]any{"service": "youtube-premium", "exit": "us"}); code != 200 {
		t.Fatalf("confirm %d %v", code, out)
	}
	if r := ruleOf(t, s, "youtube-premium"); r.TargetGroup != "us" || r.TargetExit != "" {
		t.Fatalf("rule after confirm %+v", r)
	}
}

// Group refusals write nothing: unknown group, out of scope, hard
// constraint, stale or missing identity, a member's identity changed
// between the panel's read and the save.
func TestUnlockManualGroupRefusals(t *testing.T) {
	s := probeServer(t, &fakeProber{})
	before := canonJSON(mustTopo(t, s))
	usID := groupIdentOf(t, s, "peacock", "us")
	if usID == "" {
		t.Fatal("no group identity")
	}
	hkGroup := ""
	for _, g := range mustTopo(t, s).Groups {
		if !g.RequireResidential && containsStr(g.Members, "hk-ix") {
			hkGroup = g.ID
		}
	}
	cases := []struct {
		name string
		body map[string]any
		code int
	}{
		{"unknown group", map[string]any{"service": "peacock", "group": "nope", "manual": true, "identity": usID}, http.StatusBadRequest},
		{"out of scope", map[string]any{"service": "peacock", "group": "jp", "manual": true, "identity": usID}, http.StatusBadRequest},
		{"hard constraint", map[string]any{"service": "auto-netflix", "group": hkGroup, "manual": true, "identity": "x"}, http.StatusConflict},
		{"stale identity", map[string]any{"service": "peacock", "group": "us", "manual": true, "identity": "gv2:0"}, http.StatusConflict},
		{"no identity", map[string]any{"service": "peacock", "group": "us", "manual": true}, http.StatusConflict},
	}
	for _, c := range cases {
		for _, preview := range []bool{true, false} {
			b := map[string]any{}
			for k, v := range c.body {
				b[k] = v
			}
			b["preview"] = preview
			if code, out := adoptJSON(t, s, b); code != c.code {
				t.Fatalf("%s (preview %v): %d %v", c.name, preview, code, out)
			}
			if canonJSON(mustTopo(t, s)) != before {
				t.Fatalf("%s wrote", c.name)
			}
		}
	}
	setNode(t, s, "us-2", func(n *model.Node) { n.EndpointV4 = "198.51.100.78" })
	before = canonJSON(mustTopo(t, s))
	if code, _ := adoptJSON(t, s, map[string]any{"service": "peacock", "group": "us", "manual": true, "identity": usID}); code != http.StatusConflict {
		t.Fatalf("member identity changed: %d", code)
	}
	if canonJSON(mustTopo(t, s)) != before {
		t.Fatal("changed identity wrote")
	}
}

// Refusals write nothing: out of scope, stale identity, no identity, hard
// constraint (residential), unknown service.
func TestUnlockManualRefusals(t *testing.T) {
	s := probeServer(t, &fakeProber{})
	now := time.Now().UTC()
	s.mu.Lock()
	s.recordResults(stampItems(s, item("auto-netflix", "hk-resi", unlock.FamilyIPv4, probe.CatUnlocked, 10, now)))
	s.mu.Unlock()
	before := canonJSON(mustTopo(t, s))
	cases := []struct {
		name string
		body map[string]any
		code int
	}{
		// peacock is a US service: a Japanese exit is outside its scope.
		{"out of scope", map[string]any{"service": "peacock", "exit": "jp", "manual": true, "identity": identOf(t, s, "jp")}, http.StatusBadRequest},
		{"stale identity", map[string]any{"service": "peacock", "exit": "us-2", "manual": true, "identity": "v2:00000000000000000000000000000000"}, http.StatusConflict},
		{"no identity", map[string]any{"service": "peacock", "exit": "us-2", "manual": true}, http.StatusConflict},
		// Netflix rules require residential: the IX-bound HK exit has no
		// residential group.
		{"hard constraint", map[string]any{"service": "auto-netflix", "exit": "hk-ix", "manual": true, "identity": identOf(t, s, "hk-ix")}, http.StatusConflict},
		{"unknown service", map[string]any{"service": "auto-nope", "exit": "us", "manual": true}, http.StatusNotFound},
	}
	for _, c := range cases {
		for _, preview := range []bool{true, false} {
			b := map[string]any{}
			for k, v := range c.body {
				b[k] = v
			}
			b["preview"] = preview
			if code, out := adoptJSON(t, s, b); code != c.code {
				t.Fatalf("%s (preview %v): %d %v", c.name, preview, code, out)
			}
			if canonJSON(mustTopo(t, s)) != before {
				t.Fatalf("%s wrote", c.name)
			}
		}
	}
	// An identity change between the panel's read and the save: 409.
	id := identOf(t, s, "us-2")
	setNode(t, s, "us-2", func(n *model.Node) { n.EndpointV4 = "198.51.100.78" })
	before = canonJSON(mustTopo(t, s))
	if code, _ := adoptJSON(t, s, map[string]any{"service": "peacock", "exit": "us-2", "manual": true, "identity": id}); code != http.StatusConflict {
		t.Fatalf("changed identity: %d", code)
	}
	if canonJSON(mustTopo(t, s)) != before {
		t.Fatal("changed identity wrote")
	}
}

// ---- automatic apply ----------------------------------------------------

// unlockRig is the rule rig with a streaming rule on the US group installed.
func unlockRig(t *testing.T) *ruleRig {
	t.Helper()
	r := newRuleRig(t)
	out, _ := r.putRules(t, func(tp *model.Topology) {
		tp.Rules = append(tp.Rules, model.Rule{ID: "u-yt", Name: "YouTube", Enabled: true, Manual: true, Priority: 160, MatchType: model.MatchSuffix,
			MatchValue: "youtube.com", Domains: []string{"youtube.com"}, TargetGroup: "hk"})
	})
	if out.FastApply.Status != FastApplied {
		t.Fatalf("setup install %+v", out)
	}
	r.s.rulesAuto.lastRun = time.Time{}
	now := time.Now().UTC()
	r.s.mu.Lock()
	r.s.recordResults(stampItems(r.s,
		item("youtube-premium", "us", unlock.FamilyIPv4, probe.CatUnlocked, 10, now),
		item("youtube-premium", "us-2", unlock.FamilyIPv4, probe.CatUnlocked, 400, now)))
	r.s.mu.Unlock()
	return r
}

func fastOf(t *testing.T, out map[string]any) fastApply {
	t.Helper()
	var f fastApply
	if err := json.Unmarshal(mustJSON(out["fast_apply"]), &f); err != nil {
		t.Fatal(err)
	}
	return f
}

// 确认 that only retargets the service rules (the group already prefers the
// exit) installs through the gateway transaction.
func TestUnlockConfirmAutoInstalls(t *testing.T) {
	r := unlockRig(t)
	v0 := installedVersion(t, r.s)
	code, out := adoptJSON(t, r.s, map[string]any{"service": "youtube-premium", "exit": "us"})
	if code != 200 {
		t.Fatalf("confirm %d %v", code, out)
	}
	f := fastOf(t, out)
	if f.Status != FastApplied || f.Version != v0+1 || out["apply_required"] != false {
		t.Fatalf("fast %+v", f)
	}
	if installedVersion(t, r.s) != v0+1 || !r.inSync(t) || !strings.Contains(r.hostDNS(t), "# rule u-yt -> us ") {
		t.Fatalf("not installed: v%d", installedVersion(t, r.s))
	}
	if l, _ := r.last(t); l == nil || l.Trigger != "unlock" || l.Status != FastApplied {
		t.Fatalf("last %+v", l)
	}
}

// 确认 of a member the group does not prefer: the change of the group's
// selection is recognised (the gateway's group lines pass the allowlist),
// but the group is switched on its hub, whose scripts the gateway install
// cannot carry: not installed, the reason names the hub.
func TestUnlockManualGroupMoveNeedsHub(t *testing.T) {
	r := unlockRig(t)
	now := time.Now().UTC()
	r.s.mu.Lock()
	r.s.recordResults(stampItems(r.s, item("youtube-premium", "us", unlock.FamilyIPv4, probe.CatNotUnlocked, 10, now)))
	r.s.mu.Unlock()
	v0 := installedVersion(t, r.s)
	code, out := adoptJSON(t, r.s, map[string]any{"service": "youtube-premium", "exit": "us-2"})
	if code != 200 {
		t.Fatalf("confirm %d %v", code, out)
	}
	f := fastOf(t, out)
	if f.Status != FastSkipped || out["apply_required"] != true || !strings.Contains(f.Reason, "地区组的首选出口由 hk-hub") || !strings.Contains(f.Reason, "需要到部署页安装") || strings.Contains(f.Reason, "nodes/gw") {
		t.Fatalf("fast %+v", f)
	}
	if installedVersion(t, r.s) != v0 || *r.activated != 2 {
		t.Fatalf("installed anyway: v%d", installedVersion(t, r.s))
	}
}

// 手动 to a group or a pinned exit only retargets the service rules: both
// install through the gateway transaction.
func TestUnlockManualAutoInstalls(t *testing.T) {
	for _, kind := range []string{"group", "exit"} {
		t.Run(kind, func(t *testing.T) {
			r := unlockRig(t)
			v0 := installedVersion(t, r.s)
			groups := canonJSON(mustTopo(t, r.s).Groups)
			body := map[string]any{"service": "youtube-premium", "manual": true}
			if kind == "group" {
				body["group"], body["identity"] = "us", groupIdentOf(t, r.s, "youtube-premium", "us")
			} else {
				body["exit"], body["identity"] = "us-2", identOf(t, r.s, "us-2")
			}
			code, out := adoptJSON(t, r.s, body)
			if code != 200 {
				t.Fatalf("manual %d %v", code, out)
			}
			if f := fastOf(t, out); f.Status != FastApplied || f.Version != v0+1 || out["apply_required"] != false {
				t.Fatalf("fast %+v", f)
			}
			if installedVersion(t, r.s) != v0+1 || !r.inSync(t) || canonJSON(mustTopo(t, r.s).Groups) != groups {
				t.Fatalf("not installed: v%d", installedVersion(t, r.s))
			}
			ru := ruleOf(t, r.s, "u-yt")
			if (kind == "group" && (ru.TargetGroup != "us" || ru.TargetExit != "")) || (kind == "exit" && (ru.TargetExit != "us-2" || ru.TargetGroup != "")) {
				t.Fatalf("rule %+v", ru)
			}
		})
	}
}

// 手动 with the switch off, or with another change smuggled in before a
// coalesced run: not installed.
func TestUnlockManualAutoApplyRefusals(t *testing.T) {
	t.Run("switch off", func(t *testing.T) {
		r := unlockRig(t)
		off := false
		r.s.Store.Update(func(tp *model.Topology) (bool, error) { tp.Settings.RulesAutoApply = &off; return true, nil })
		v0 := installedVersion(t, r.s)
		code, out := adoptJSON(t, r.s, map[string]any{"service": "youtube-premium", "exit": "us-2", "manual": true, "identity": identOf(t, r.s, "us-2")})
		if f := fastOf(t, out); code != 200 || f.Status != FastSkipped || !strings.Contains(f.Reason, "关闭") || installedVersion(t, r.s) != v0 {
			t.Fatalf("%d %+v", code, out)
		}
		if ruleOf(t, r.s, "u-yt").TargetExit != "us-2" {
			t.Fatal("rules not saved")
		}
	})
	t.Run("extra", func(t *testing.T) {
		r := unlockRig(t)
		v0 := installedVersion(t, r.s)
		r.s.rulesAuto.lastRun = time.Now()
		code, out := adoptJSON(t, r.s, map[string]any{"service": "youtube-premium", "group": "us", "manual": true, "identity": groupIdentOf(t, r.s, "youtube-premium", "us")})
		if f := fastOf(t, out); code != 200 || f.Status != FastScheduled {
			t.Fatalf("%d %+v", code, out)
		}
		if _, err := r.s.Store.Update(func(tp *model.Topology) (bool, error) {
			for i := range tp.Groups {
				if tp.Groups[i].ID == "us" {
					tp.Groups[i].Members = []string{"us-2", "us"}
				}
			}
			return true, nil
		}); err != nil {
			t.Fatal(err)
		}
		l := r.waitIdle(t)
		if l.Status != FastSkipped || installedVersion(t, r.s) != v0 {
			t.Fatalf("installed with a group change: %+v", l)
		}
	})
}

// The switch off: no automatic install, same edits.
func TestUnlockAutoApplySwitchOff(t *testing.T) {
	r := unlockRig(t)
	off := false
	r.s.Store.Update(func(tp *model.Topology) (bool, error) { tp.Settings.RulesAutoApply = &off; return true, nil })
	v0 := installedVersion(t, r.s)
	code, out := adoptJSON(t, r.s, map[string]any{"service": "youtube-premium", "exit": "us"})
	if f := fastOf(t, out); code != 200 || f.Status != FastSkipped || !strings.Contains(f.Reason, "关闭") || installedVersion(t, r.s) != v0 {
		t.Fatalf("%d %+v", code, out)
	}
	if ruleOf(t, r.s, "u-yt").TargetGroup != "us" {
		t.Fatal("rules not saved")
	}
}

// Preflight findings stop it like a rule save.
func TestUnlockAutoApplyPreflightWarning(t *testing.T) {
	r := unlockRig(t)
	r.hp.mu.Lock()
	r.hp.extra = ruleWarnExtra
	r.hp.mu.Unlock()
	v0 := installedVersion(t, r.s)
	_, out := adoptJSON(t, r.s, map[string]any{"service": "youtube-premium", "exit": "us"})
	if f := fastOf(t, out); f.Status != FastSkipped || !strings.Contains(f.Reason, "警告") || installedVersion(t, r.s) != v0 {
		t.Fatalf("%+v", f)
	}
}

// Coalesced: another rule change, or a changed member set, smuggled in
// before the run refuses the whole install.
func TestUnlockAutoApplyRefusesExtras(t *testing.T) {
	for name, extra := range map[string]func(tp *model.Topology){
		"other rule": func(tp *model.Topology) {
			for i := range tp.Rules {
				if tp.Rules[i].ID == "auto-kktv" {
					tp.Rules[i].MatchValue = "kktv.example.org"
				}
			}
		},
		"member set": func(tp *model.Topology) {
			for i := range tp.Groups {
				if tp.Groups[i].ID == "us" {
					tp.Groups[i].Members = []string{"us"}
				}
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			r := unlockRig(t)
			v0 := installedVersion(t, r.s)
			r.s.rulesAuto.lastRun = time.Now() // inside the coalescing window
			code, out := adoptJSON(t, r.s, map[string]any{"service": "youtube-premium", "exit": "us"})
			if f := fastOf(t, out); code != 200 || f.Status != FastScheduled {
				t.Fatalf("%d %+v", code, out)
			}
			if _, err := r.s.Store.Update(func(tp *model.Topology) (bool, error) { extra(tp); return true, nil }); err != nil {
				t.Fatal(err)
			}
			l := r.waitIdle(t)
			if l.Status != FastSkipped || installedVersion(t, r.s) != v0 {
				t.Fatalf("installed with %s: %+v", name, l)
			}
		})
	}
}

func TestUnlockWhitelistHelpers(t *testing.T) {
	a := []model.Rule{{ID: "x", TargetGroup: "hk"}, {ID: "y", TargetGroup: "hk"}}
	b := []model.Rule{{ID: "x", TargetGroup: "us"}, {ID: "y", TargetGroup: "hk"}}
	if !onlyTargetsDiffer(a, b, map[string]bool{"x": true}) {
		t.Fatal("own target refused")
	}
	if onlyTargetsDiffer(a, b, map[string]bool{"y": true}) {
		t.Fatal("other rule's target accepted")
	}
	c := []model.Rule{{ID: "x", TargetGroup: "us", MatchValue: "z"}, {ID: "y", TargetGroup: "hk"}}
	if onlyTargetsDiffer(a, c, map[string]bool{"x": true}) {
		t.Fatal("another field accepted")
	}
	if !sameMemberSet([]string{"a", "b"}, []string{"b", "a"}) || sameMemberSet([]string{"a", "b"}, []string{"a"}) || sameMemberSet([]string{"a", "a"}, []string{"a", "b"}) {
		t.Fatal("member set")
	}
}

// T5: recommendation → preview → 确认 → stored rules → compile → install.
// The exit the matrix recommended is the one the saved rules reach (the
// row's current direction and the installed gateway rule line), the
// recommendation then reads as adopted; when the install fails the answer
// never claims it is live.
func TestUnlockRecommendationReachesRoute(t *testing.T) {
	for _, failInstall := range []bool{false, true} {
		r := unlockRig(t)
		row := serviceRow(t, r.s, "youtube-premium")
		if row.Recommend == nil || row.Recommend.Adopted {
			t.Fatalf("recommendation %+v", row.Recommend)
		}
		rec := *row.Recommend
		code, pv := adoptJSON(t, r.s, map[string]any{"service": "youtube-premium", "exit": rec.ExitID, "preview": true})
		if code != 200 || pv["exit"] != rec.ExitID || pv["group"] != rec.Group {
			t.Fatalf("preview %d %v", code, pv)
		}
		v0 := installedVersion(t, r.s)
		*r.fail = failInstall
		code, out := adoptJSON(t, r.s, map[string]any{"service": "youtube-premium", "exit": rec.ExitID})
		if code != 200 || out["exit"] != rec.ExitID || out["group"] != rec.Group {
			t.Fatalf("confirm %d %v", code, out)
		}
		if ru := ruleOf(t, r.s, "u-yt"); ru.TargetGroup != rec.Group || ru.TargetExit != "" {
			t.Fatalf("stored target %+v, recommended %+v", ru, rec)
		}
		after := serviceRow(t, r.s, "youtube-premium")
		if after.Current == nil || after.Current.Exit != rec.ExitID || after.Recommend == nil || !after.Recommend.Adopted {
			t.Fatalf("current %+v rec %+v", after.Current, after.Recommend)
		}
		f := fastOf(t, out)
		if failInstall {
			if f.Status == FastApplied || out["apply_required"] != true || installedVersion(t, r.s) != v0 {
				t.Fatalf("failed install reported as live: %+v %v", f, out)
			}
			continue
		}
		if f.Status != FastApplied || !strings.Contains(r.hostDNS(t), "# rule u-yt -> "+rec.ExitID+" ") {
			t.Fatalf("installed %+v", f)
		}
	}
}

// T5: an expired recommendation (the probe result changed after the page
// showed it) refuses 确认 with 409 and writes nothing.
func TestUnlockConfirmStaleRecommendationRefused(t *testing.T) {
	r := unlockRig(t)
	now := time.Now().UTC()
	r.s.mu.Lock()
	r.s.recordResults(stampItems(r.s,
		item("youtube-premium", "us", unlock.FamilyIPv4, probe.CatNotUnlocked, 10, now),
		item("youtube-premium", "us-2", unlock.FamilyIPv4, probe.CatUnlocked, 400, now)))
	r.s.mu.Unlock()
	code, out := adoptJSON(t, r.s, map[string]any{"service": "youtube-premium", "exit": "us"})
	if code != http.StatusConflict {
		t.Fatalf("stale confirm %d %v", code, out)
	}
	if ru := ruleOf(t, r.s, "u-yt"); ru.TargetGroup != "hk" {
		t.Fatalf("written %+v", ru)
	}
}
