package api

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/radowitz/meridian/internal/model"
	"github.com/radowitz/meridian/internal/unlock"
)

type gView struct {
	ID                 string   `json:"id"`
	Mode               string   `json:"mode"`
	Members            []string `json:"members"`
	Chosen             string   `json:"chosen"`
	OnFailure          string   `json:"on_failure"`
	OnFailureEffective string   `json:"on_failure_effective"`
	IsDefault          bool     `json:"is_default"`
	EffectiveOrder     []string `json:"effective_order"`
	Target             string   `json:"target"`
	TargetReason       string   `json:"target_reason"`
	Switchable         bool     `json:"switchable"`
	SwitchOrder        []string `json:"switch_order"`
	MeshBackup         bool     `json:"mesh_backup"`
	Fwmark             string   `json:"fwmark"`
	MemberStatus       []struct {
		ID       string `json:"id"`
		Position int    `json:"position"`
		Eligible bool   `json:"eligible"`
		Active   bool   `json:"active"`
		Reasons  []struct {
			Code string `json:"code"`
		} `json:"reasons"`
		Health *struct {
			Up bool `json:"up"`
		} `json:"health"`
	} `json:"member_status"`
	State struct {
		Active          string  `json:"active"`
		Reason          string  `json:"reason"`
		Alert           bool    `json:"alert"`
		AlertMessage    string  `json:"alert_message"`
		LastSwitch      *string `json:"last_switch"`
		Observed        bool    `json:"observed"`
		Source          string  `json:"source"`
		ReturnBlockedBy string  `json:"return_blocked_by"`
	} `json:"state"`
	InUseBy []struct {
		Kind string `json:"kind"`
		ID   string `json:"id"`
	} `json:"in_use_by"`
}

type apiErr struct {
	Error   string `json:"error"`
	Code    string `json:"code"`
	Field   string `json:"field"`
	InUseBy []struct {
		Kind string `json:"kind"`
		ID   string `json:"id"`
	} `json:"in_use_by"`
}

func groupsOf(t *testing.T, s *Server) map[string]gView {
	t.Helper()
	rr := do(s, http.MethodGet, "/api/region-groups", nil)
	if rr.Code != 200 {
		t.Fatal(rr.Body.String())
	}
	var body struct {
		Groups       []gView        `json:"groups"`
		DefaultGroup string         `json:"default_group"`
		Thresholds   map[string]int `json:"thresholds"`
	}
	decode(t, rr, &body)
	if body.Thresholds["cooldown_sec"] != 120 || body.Thresholds["fails_need"] != 3 {
		t.Fatalf("thresholds %v", body.Thresholds)
	}
	out := map[string]gView{}
	for _, g := range body.Groups {
		out[g.ID] = g
	}
	return out
}

func reasonCodes(g gView, id string) []string {
	var out []string
	for _, m := range g.MemberStatus {
		if m.ID == id {
			for _, r := range m.Reasons {
				out = append(out, r.Code)
			}
		}
	}
	return out
}

func expectErr(t *testing.T, s *Server, method, path, body string, status int, code, field string) apiErr {
	t.Helper()
	rr := do(s, method, path, []byte(body))
	var e apiErr
	decode(t, rr, &e)
	if rr.Code != status || e.Code != code || (field != "" && e.Field != field) || e.Error == "" {
		t.Fatalf("%s %s %s: got %d %+v, want %d %s/%s", method, path, body, rr.Code, e, status, code, field)
	}
	return e
}

func TestRegionGroupListAndViews(t *testing.T) {
	s := newTest(t)
	gs := groupsOf(t, s)
	hk := gs["hk"]
	if !hk.IsDefault || hk.Target != "hk-ix" || hk.TargetReason != "preferred" || !hk.Switchable || !hk.MeshBackup || hk.Fwmark == "" {
		t.Fatalf("hk view %+v", hk)
	}
	if strings.Join(hk.EffectiveOrder, ",") != "hk-ix,hk-2" || strings.Join(hk.SwitchOrder, ",") != "hk-ix,hk-2" {
		t.Fatalf("hk order %v / %v", hk.EffectiveOrder, hk.SwitchOrder)
	}
	if hk.State.Observed || hk.State.Active != "hk-ix" || hk.State.Source != "panel_model" || hk.State.LastSwitch != nil {
		t.Fatalf("hk state %+v", hk.State)
	}
	refs := map[string]bool{}
	for _, r := range hk.InUseBy {
		refs[r.Kind+":"+r.ID] = true
	}
	if !refs["settings:default_group"] || !refs["rule:auto-mytvsuper"] {
		t.Fatalf("hk in_use_by %+v", hk.InUseBy)
	}
	pin := gs["us-pin"]
	if pin.Mode != "manual" || pin.Chosen != "us" || pin.OnFailureEffective != "fallback" || pin.TargetReason != "chosen" {
		t.Fatalf("us-pin %+v", pin)
	}
	v6 := gs["v6"]
	if v6.Switchable || !containsStr(reasonCodes(v6, "v6-exit"), "not_switchable") || len(v6.SwitchOrder) != 1 {
		t.Fatalf("relay-reached group %+v", v6)
	}
	rr := do(s, http.MethodGet, "/api/region-groups/hk-residential", nil)
	if rr.Code != 200 || strings.Contains(rr.Body.String(), "private_key") {
		t.Fatal(rr.Body.String())
	}
	expectErr(t, s, http.MethodGet, "/api/region-groups/nope", "", 404, "not_found", "")
	// The old pool endpoint is backed by the groups.
	rr = do(s, http.MethodGet, "/api/pools", nil)
	if rr.Code != 200 || !strings.Contains(rr.Body.String(), `"id":"us-pin"`) {
		t.Fatal(rr.Body.String())
	}
}

func TestRegionGroupCreatePatchDelete(t *testing.T) {
	s := newTest(t)
	groupsOf(t, s)
	// Second Hong Kong group: manual, chosen hk-2; IX still sorts first in
	// the effective order and the reasons say why.
	rr := do(s, http.MethodPost, "/api/region-groups", []byte(`{"name":"香港手选","region":"hk","mode":"manual","chosen":"hk-2","members":["hk-2","hk-ix"]}`))
	if rr.Code != http.StatusCreated {
		t.Fatal(rr.Body.String())
	}
	var created struct {
		Group         gView `json:"group"`
		ApplyRequired bool  `json:"apply_required"`
	}
	decode(t, rr, &created)
	g := created.Group
	if g.ID != "hk-2" || !created.ApplyRequired || g.Target != "hk-2" || g.TargetReason != "chosen" || g.OnFailureEffective != "hold" {
		t.Fatalf("created %+v", g)
	}
	if strings.Join(g.EffectiveOrder, ",") != "hk-ix,hk-2" || !containsStr(reasonCodes(g, "hk-ix"), "ix_first") || !containsStr(reasonCodes(g, "hk-2"), "after_ix") {
		t.Fatalf("effective order %v reasons %+v", g.EffectiveOrder, g.MemberStatus)
	}
	if strings.Join(g.SwitchOrder, ",") != "hk-2,hk-ix" {
		t.Fatalf("switch order %v", g.SwitchOrder)
	}

	expectErr(t, s, http.MethodPost, "/api/region-groups", `{"id":"hk","name":"x"}`, 409, "conflict", "id")
	expectErr(t, s, http.MethodPost, "/api/region-groups", `{"id":"x1","mode":"manual","chosen":"jp","members":["us"]}`, 422, "chosen_not_eligible", "chosen")
	expectErr(t, s, http.MethodPost, "/api/region-groups", `{"id":"x2","mode":"auto","chosen":"us","members":["us"]}`, 422, "invalid_field", "chosen")
	expectErr(t, s, http.MethodPost, "/api/region-groups", `{"id":"x3","members":["ghost"]}`, 422, "group_member_invalid", "members")
	expectErr(t, s, http.MethodPost, "/api/region-groups", `{"id":"x4","members":["us"],"require_residential":true,"exclude_residential":true}`, 422, "constraint_conflict", "exclude_residential")
	expectErr(t, s, http.MethodPost, "/api/region-groups", `{"id":"Bad ID","members":["us"]}`, 422, "invalid_field", "id")
	expectErr(t, s, http.MethodPost, "/api/region-groups", `{"id":"x5","mode":"sometimes"}`, 422, "invalid_field", "mode")
	expectErr(t, s, http.MethodPost, "/api/region-groups", `not json`, 400, "bad_request", "")

	// Manual → automatic clears the choice and the failure setting.
	rr = do(s, http.MethodPatch, "/api/region-groups/hk-2", []byte(`{"mode":"auto"}`))
	if rr.Code != 200 {
		t.Fatal(rr.Body.String())
	}
	created.Group = gView{}
	decode(t, rr, &created)
	if created.Group.Chosen != "" || created.Group.OnFailure != "" || created.Group.Target != "hk-ix" {
		t.Fatalf("auto %+v", created.Group)
	}
	rr = do(s, http.MethodPatch, "/api/region-groups/hk-2", []byte(`{"mode":"manual","chosen":"hk-2","on_failure":"fallback"}`))
	decode(t, rr, &created)
	if rr.Code != 200 || created.Group.OnFailureEffective != "fallback" {
		t.Fatal(rr.Body.String())
	}
	expectErr(t, s, http.MethodPatch, "/api/region-groups/hk-2", `{"id":"other"}`, 422, "invalid_field", "id")
	expectErr(t, s, http.MethodPatch, "/api/region-groups/hk-2", `{"on_failure":"later"}`, 422, "invalid_field", "on_failure")
	expectErr(t, s, http.MethodPatch, "/api/region-groups/nope", `{"name":"x"}`, 404, "not_found", "")
	// A group change that would break a rule's constraint is refused.
	expectErr(t, s, http.MethodPatch, "/api/region-groups/hk-residential", `{"require_residential":false}`, 422, "residential_required", "require_residential")

	// Delete: refused while referenced, with the referrers.
	e := expectErr(t, s, http.MethodDelete, "/api/region-groups/us", "", 409, "in_use", "")
	if len(e.InUseBy) < 6 || e.InUseBy[0].Kind != "rule" {
		t.Fatalf("in_use_by %+v", e.InUseBy)
	}
	expectErr(t, s, http.MethodDelete, "/api/region-groups/hk", "", 409, "in_use", "")
	rr = do(s, http.MethodDelete, "/api/region-groups/hk-2", nil)
	if rr.Code != 200 {
		t.Fatal(rr.Body.String())
	}
	expectErr(t, s, http.MethodGet, "/api/region-groups/hk-2", "", 404, "not_found", "")

	// Default group.
	expectErr(t, s, http.MethodPut, "/api/region-groups/default", `{"group":"nope"}`, 404, "not_found", "group")
	rr = do(s, http.MethodPut, "/api/region-groups/default", []byte(`{"group":"jp"}`))
	if rr.Code != 200 || !groupsOf(t, s)["jp"].IsDefault {
		t.Fatal(rr.Body.String())
	}
	stored, _ := s.topology()
	if stored.Settings.DefaultGroup != "jp" {
		t.Fatal("default not stored")
	}
	for _, r := range stored.Rules {
		if r.Mode != "" || r.TargetPool != "" {
			t.Fatalf("rule %s carries legacy fields", r.ID)
		}
	}
}

// Reordering a group re-aligns the unlock state: the stale demotion is
// dropped and the new preferred is not a member that just failed.
func TestRegionGroupReorderReconcilesUnlock(t *testing.T) {
	s := newTest(t)
	groupsOf(t, s)
	snap := unlock.Snapshot{Services: map[string]unlock.State{
		"auto-openai": {Pool: "us", Preferred: "us", Active: "us-2", Demoted: true, Known: map[string]bool{"us": false, "us-2": true}},
	}}
	if err := s.saveUnlock(snap); err != nil {
		t.Fatal(err)
	}
	rr := do(s, http.MethodPatch, "/api/region-groups/us", []byte(`{"members":["us-2","us"]}`))
	if rr.Code != 200 {
		t.Fatal(rr.Body.String())
	}
	st := s.loadUnlock().Services["auto-openai"]
	if st.Preferred != "us-2" || st.Active != "us-2" || st.Demoted {
		t.Fatalf("after reorder %+v", st)
	}
	// Back to us first: us's latest result is a failure, so the service
	// stays on us-2 (demoted) instead of returning to the failed member.
	rr = do(s, http.MethodPatch, "/api/region-groups/us", []byte(`{"members":["us","us-2"]}`))
	if rr.Code != 200 {
		t.Fatal(rr.Body.String())
	}
	st = s.loadUnlock().Services["auto-openai"]
	if st.Preferred != "us" || st.Active != "us-2" || !st.Demoted {
		t.Fatalf("reorder onto a failed member %+v", st)
	}
	t2, _ := s.topology()
	if d := s.unlockDecisions(t2); d["auto-openai"] != "us-2" {
		t.Fatalf("decisions %v", d)
	}
}

// Live state: automatic failover with reason and switch time; manual hold
// keeps the chosen member and alerts.
func TestRegionGroupHealthState(t *testing.T) {
	s := newTest(t)
	groupsOf(t, s)
	rr := do(s, http.MethodPost, "/api/region-groups", []byte(`{"id":"jp-hold","region":"jp","mode":"manual","chosen":"jp","members":["jp","sg"]}`))
	if rr.Code != 201 {
		t.Fatal(rr.Body.String())
	}
	obs := []byte(`{"observations":[{"id":"hk-ix","up":false},{"id":"hk-2","up":true},{"id":"jp","up":false},{"id":"sg","up":true}]}`)
	for i := 0; i < 3; i++ {
		rr = do(s, http.MethodPost, "/api/region-groups/health", obs)
		if rr.Code != 200 {
			t.Fatal(rr.Body.String())
		}
	}
	var body struct {
		Groups  []gView  `json:"groups"`
		Flipped []string `json:"flipped"`
	}
	decode(t, rr, &body)
	gs := map[string]gView{}
	for _, g := range body.Groups {
		gs[g.ID] = g
	}
	hk := gs["hk"]
	if !hk.State.Observed || hk.State.Active != "hk-2" || hk.State.Reason != "failover" || hk.State.Alert || hk.State.LastSwitch == nil || hk.State.ReturnBlockedBy != "target_down" {
		t.Fatalf("hk state %+v", hk.State)
	}
	for _, m := range hk.MemberStatus {
		if m.Health == nil || (m.ID == "hk-ix") == m.Health.Up || m.Active != (m.ID == "hk-2") {
			t.Fatalf("member %+v", m)
		}
	}
	hold := gs["jp-hold"]
	if hold.State.Active != "jp" || hold.State.Reason != "held" || !hold.State.Alert || !strings.Contains(hold.State.AlertMessage, "保持不切换") {
		t.Fatalf("hold state %+v", hold.State)
	}
	if !containsStr(body.Flipped, "hk-ix") || !containsStr(body.Flipped, "jp") {
		t.Fatalf("flipped %v", body.Flipped)
	}
	// Switch to fallback: the panel model restarts and then moves to sg.
	rr = do(s, http.MethodPatch, "/api/region-groups/jp-hold", []byte(`{"on_failure":"fallback"}`))
	if rr.Code != 200 {
		t.Fatal(rr.Body.String())
	}
	for i := 0; i < 3; i++ {
		do(s, http.MethodPost, "/api/region-groups/health", obs)
	}
	fb := groupsOf(t, s)["jp-hold"]
	if fb.State.Active != "sg" || fb.State.Reason != "fallback" || !fb.State.Alert || !strings.Contains(fb.State.AlertMessage, "临时使用") {
		t.Fatalf("fallback state %+v", fb.State)
	}
}

// An old client saving legacy pool fields gets them merged into groups.
func TestPutTopologyMigratesLegacyFields(t *testing.T) {
	s := newTest(t)
	t0, _ := s.topology()
	t0.Rules = append(t0.Rules, model.Rule{
		ID: "legacy", Name: "legacy", Manual: true, Priority: 1, Enabled: true,
		MatchType: model.MatchDomain, MatchValue: "legacy.example.com", TargetPool: "jp", Mode: model.ModePin,
	})
	rr := do(s, http.MethodPut, "/api/topology", mustJSON(t0))
	if rr.Code != 200 {
		t.Fatal(rr.Body.String())
	}
	var raw map[string]any
	_ = json.Unmarshal(rr.Body.Bytes(), &raw)
	stored, _ := s.topology()
	for _, r := range stored.Rules {
		if r.ID == "legacy" && (r.TargetGroup != "jp-pin" || r.TargetPool != "" || r.Mode != "") {
			t.Fatalf("legacy rule stored as %+v", r)
		}
	}
	if g, ok := stored.GroupByID("jp-pin"); !ok || g.Chosen != "jp" {
		t.Fatalf("jp-pin %+v", g)
	}
	// A migrated rule that also sends a mode is refused, not rewritten.
	t1, _ := s.topology()
	t1.Rules[0].Mode = model.ModeAuto
	rr = do(s, http.MethodPut, "/api/topology", mustJSON(t1))
	if rr.Code != http.StatusUnprocessableEntity || !strings.Contains(rr.Body.String(), "rule_mode_removed") {
		t.Fatalf("%d %s", rr.Code, rr.Body.String())
	}
}
