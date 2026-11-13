package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/radowitz/meridian/internal/compile"
	"github.com/radowitz/meridian/internal/credentials"
	"github.com/radowitz/meridian/internal/hubstate"
	"github.com/radowitz/meridian/internal/model"
	"github.com/radowitz/meridian/internal/pool"
	"github.com/radowitz/meridian/internal/unlock"
	"github.com/radowitz/meridian/internal/validate"
)

// Region groups: the exits' country/region groups, their mode, order,
// manual choice and live state. See docs/architecture.md「地区组」.
//
// Every group view carries two separate things: "actual", the hub's own
// report read over SSH (region_groups_runtime.go) — the only source that
// may be shown as the member in use — and "model", the panel's computation
// of the hub's state machine from health samples, labelled as such.
// Changes edit the topology only; they take effect through an install
// (POST /api/apply), never directly on a host.

func (s *Server) registerRegionGroups(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/region-groups", s.listGroups)
	mux.HandleFunc("POST /api/region-groups", s.createGroup)
	mux.HandleFunc("POST /api/region-groups/health", s.postGroupHealth)
	mux.HandleFunc("POST /api/region-groups/runtime/refresh", s.refreshGroupRuntime)
	mux.HandleFunc("PUT /api/region-groups/default", s.putDefaultGroup)
	mux.HandleFunc("GET /api/region-groups/{id}", s.getGroup)
	mux.HandleFunc("PATCH /api/region-groups/{id}", s.patchGroup)
	mux.HandleFunc("DELETE /api/region-groups/{id}", s.deleteGroup)
}

// ------------------------------------------------------------- plans ---

// groupPlans is the compiled view of every group. When the topology cannot
// be compiled into tunnels the plans fall back to the effective order with
// no reachability filter (and no dynamic switching).
type groupPlans struct {
	byID     map[string]compile.GroupPlan
	compiled bool
	// planID is compile.GroupPlanID of the compiled plans ("" when the
	// topology does not compile); staleAfter is compile.HubStaleAfter.
	planID     string
	staleAfter time.Duration
}

func plansOf(t model.Topology) groupPlans {
	out := groupPlans{byID: map[string]compile.GroupPlan{}}
	plans, err := compile.PlanGroups(t)
	if err == nil {
		out.compiled = true
		out.planID = compile.GroupPlanID(plans)
		out.staleAfter = compile.HubStaleAfter(plans)
		for _, p := range plans {
			out.byID[p.Group.ID] = p
		}
	}
	return out
}

// plan is the group's compiled plan, or the uncompiled fallback.
func (gp groupPlans) plan(t model.Topology, g model.RegionGroup) compile.GroupPlan {
	if p, ok := gp.byID[g.ID]; ok {
		return p
	}
	sel := pool.Select(t, g, nil)
	p := compile.GroupPlan{Group: g, Selection: sel, Hold: g.EffectiveOnFailure() == model.OnFailureHold}
	if sel.Target != "" {
		if n, ok := t.NodeByID(sel.Target); ok {
			p.Target, p.HasTarget = compile.ExitPlan{Node: n}, true
		}
	}
	return p
}

// ------------------------------------------------------------- views ---

type healthView struct {
	Up      bool       `json:"up"`
	Fails   int        `json:"fails"`
	Goods   int        `json:"goods"`
	LastOK  *bool      `json:"last_ok"`
	OKSince *time.Time `json:"ok_since"`
	LastAt  *time.Time `json:"last_at"`
}

func healthOf(h pool.MemberHealth) *healthView {
	v := &healthView{Up: h.Up, Fails: h.Fails, Goods: h.Goods}
	if h.Seen {
		ok := h.LastOK
		v.LastOK = &ok
	}
	if !h.OKSince.IsZero() {
		t := h.OKSince
		v.OKSince = &t
	}
	if !h.LastAt.IsZero() {
		t := h.LastAt
		v.LastAt = &t
	}
	return v
}

type memberView struct {
	pool.MemberStatus
	// Target: the compiled choice. ActualActive: the hub reported, in
	// state ok, that its group table uses this member. ModelActive: the
	// panel's model puts the group on this member (a computation, never
	// shown as the member in use).
	Target       bool        `json:"target"`
	ActualActive bool        `json:"actual_active"`
	ModelActive  bool        `json:"model_active"`
	Health       *healthView `json:"health"`
}

// actualView is the hub's report for the group (hubstate.Actual) plus an
// alert message; see hubstate for the states.
type actualView struct {
	hubstate.Actual
	AlertMessage string `json:"alert_message,omitempty"`
}

// modelView is the panel's own computation of the hub's state machine
// from health samples (POST /api/region-groups/health). It is never an
// observation of the hub.
type modelView struct {
	// Active is a member ID, "mmesh" (Mesh last hop) or "" (no member).
	Active       string     `json:"active"`
	Reason       string     `json:"reason"`
	Alert        bool       `json:"alert"`
	AlertMessage string     `json:"alert_message,omitempty"`
	LastSwitch   *time.Time `json:"last_switch"`
	// Observed is false until health samples arrived (then Active is the
	// compiled target).
	Observed bool `json:"observed"`
	// Source is always "panel_model".
	Source string `json:"source"`
	// ReturnBlockedBy says why the group has not gone back to its target:
	// target_down, target_last_failed, recovery_timer or switch_cooldown.
	ReturnBlockedBy string     `json:"return_blocked_by,omitempty"`
	ReturnNotBefore *time.Time `json:"return_not_before,omitempty"`
}

type groupView struct {
	model.RegionGroup
	OnFailureEffective model.OnFailure   `json:"on_failure_effective,omitempty"`
	IsDefault          bool              `json:"is_default"`
	EffectiveOrder     []string          `json:"effective_order"`
	Target             string            `json:"target"`
	TargetReason       string            `json:"target_reason"`
	Switchable         bool              `json:"switchable"`
	SwitchOrder        []string          `json:"switch_order"`
	MeshBackup         bool              `json:"mesh_backup"`
	Fwmark             string            `json:"fwmark,omitempty"`
	Table              int               `json:"table,omitempty"`
	MemberStatus       []memberView      `json:"member_status"`
	Actual             actualView        `json:"actual"`
	Model              modelView         `json:"model"`
	InUseBy            []credentials.Ref `json:"in_use_by"`
}

func groupRefs(t model.Topology, id string) []credentials.Ref {
	refs := []credentials.Ref{}
	if t.Settings.DefaultGroup == id {
		refs = append(refs, credentials.Ref{Kind: "settings", ID: "default_group", Name: "默认境外组"})
	}
	for _, r := range t.Rules {
		if r.TargetGroup == id {
			refs = append(refs, credentials.Ref{Kind: "rule", ID: r.ID, Name: r.Name})
		}
	}
	return refs
}

// groupSpec is what hubstate.Evaluate needs about the group.
func (gp groupPlans) spec(t model.Topology, g model.RegionGroup) hubstate.GroupSpec {
	p := gp.plan(t, g)
	pol := p.Policy()
	return hubstate.GroupSpec{ID: g.ID, Dynamic: gp.compiled && p.Dynamic, Members: append([]string(nil), pol.Try...), Mesh: pol.Mesh}
}

func viewGroup(t model.Topology, g model.RegionGroup, plans groupPlans, runtime map[string]pool.Runtime, hub groupHub) groupView {
	p := plans.plan(t, g)
	pol := p.Policy()
	v := groupView{
		RegionGroup:        g,
		OnFailureEffective: g.EffectiveOnFailure(),
		IsDefault:          t.Settings.DefaultGroup == g.ID,
		EffectiveOrder:     append([]string{}, p.Selection.Order...),
		Target:             p.Selection.Target,
		TargetReason:       p.Selection.Reason,
		Switchable:         p.Dynamic,
		SwitchOrder:        append([]string{}, pol.Try...),
		MeshBackup:         p.Mesh,
		MemberStatus:       []memberView{},
		InUseBy:            groupRefs(t, g.ID),
	}
	if v.Members == nil {
		v.Members = []string{}
	}
	if plans.compiled && p.Mark != 0 {
		v.Fwmark = fmt.Sprintf("%#x", p.Mark)
		v.Table = p.Table
	}
	rt, observed := runtime[g.ID]
	if observed && rt.Target != p.Selection.Target {
		observed = false // computed for another target; restarts with the next sample
	}
	st := modelView{Source: "panel_model", Observed: observed, Active: p.Selection.Target, Reason: p.Selection.Reason}
	if p.Selection.Target == "" {
		st.Reason, st.Alert = pool.ReasonNone, true
	}
	if observed {
		st.Active, st.Reason, st.Alert = rt.Active, rt.Reason, rt.Alert
		if !rt.LastSwitch.IsZero() {
			ls := rt.LastSwitch
			st.LastSwitch = &ls
		}
		if rt.Active != rt.Target && rt.Target != "" {
			st.ReturnBlockedBy, st.ReturnNotBefore = returnBlock(rt)
		}
	}
	st.AlertMessage = alertMessage(t, g, st.Alert, st.Reason, st.Active, p.Selection.Target)
	v.Model = st
	act := actualView{Actual: hub.actual(plans, plans.spec(t, g))}
	if act.State == hubstate.StateOK {
		act.AlertMessage = alertMessage(t, g, act.Alert, act.Reason, act.Active, p.Selection.Target)
		if act.Alert && act.AlertMessage == "" {
			act.AlertMessage = "枢纽报告这个组处于告警状态。"
		}
		if act.Hop == hubstate.HopBlackhole {
			act.AlertMessage = strings.TrimSpace(act.AlertMessage + " 枢纽的组路由表现在是黑洞（Mesh 备路未封装或没有可用成员），这个组的流量被丢弃。")
		}
	}
	v.Actual = act
	for _, m := range p.Selection.Members {
		mv := memberView{MemberStatus: m, Target: m.ID == p.Selection.Target, ModelActive: m.ID == st.Active,
			ActualActive: act.State == hubstate.StateOK && act.Active == m.ID}
		if observed {
			if h, ok := rt.Members[m.ID]; ok {
				mv.Health = healthOf(h)
			}
		}
		v.MemberStatus = append(v.MemberStatus, mv)
	}
	return v
}

func returnBlock(rt pool.Runtime) (string, *time.Time) {
	h, ok := rt.Members[rt.Target]
	switch {
	case !ok || !h.Up:
		return "target_down", nil
	case !h.Seen || !h.LastOK || h.OKSince.IsZero():
		return "target_last_failed", nil
	}
	recovered := h.OKSince.Add(pool.Cooldown)
	cool := rt.LastSwitch.Add(pool.Cooldown)
	if cool.After(recovered) {
		return "switch_cooldown", &cool
	}
	return "recovery_timer", &recovered
}

func nodeName(t model.Topology, id string) string {
	if n, ok := t.NodeByID(id); ok && n.Name != "" {
		return n.Name
	}
	return id
}

func alertMessage(t model.Topology, g model.RegionGroup, alert bool, reason, active, target string) string {
	if !alert {
		return ""
	}
	switch reason {
	case pool.ReasonNone:
		return "组内没有可用的出口，引用它的规则不会生效。"
	case pool.ReasonHeld:
		if g.Mode == model.GroupManual {
			return fmt.Sprintf("指定成员 %s 不可用，按设置保持不切换。可以改成「回落」或换一个成员。", nodeName(t, target))
		}
		return fmt.Sprintf("首选 %s 不可用，它只能经中继或 Mesh 到达，枢纽不能切换这个组。", nodeName(t, target))
	case pool.ReasonFallback:
		return fmt.Sprintf("指定成员 %s 不可用，临时使用 %s；恢复后按切回规则回到指定成员。", nodeName(t, target), nodeName(t, active))
	case pool.ReasonMesh:
		return "组内所有 WireGuard 成员都不可用，正在走 Mesh 备路。"
	}
	return fmt.Sprintf("%s 不可用，组内没有其他可用成员。", nodeName(t, target))
}

func thresholds() map[string]int {
	return map[string]int{
		"fails_need":    pool.FailsNeed,
		"recovers_need": pool.RecoversNeed,
		"cooldown_sec":  int(pool.Cooldown / time.Second),
	}
}

// --------------------------------------------------------- handlers ---

func groupNotFound(id string) error {
	return &credentials.Error{Code: credentials.CodeNotFound, Msg: fmt.Sprintf("地区组 %s 不存在", id)}
}

func (s *Server) groupRuntime() map[string]pool.Runtime {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.loadPools().Pools
}

func (s *Server) listGroups(w http.ResponseWriter, r *http.Request) {
	t, err := s.topology()
	if err != nil {
		writeResErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, s.groupsBody(t))
}

func sortedGroups(t model.Topology) []model.RegionGroup {
	gs := append([]model.RegionGroup(nil), t.Groups...)
	sort.SliceStable(gs, func(i, j int) bool { return gs[i].ID < gs[j].ID })
	return gs
}

func (s *Server) getGroup(w http.ResponseWriter, r *http.Request) {
	t, err := s.topology()
	if err != nil {
		writeResErr(w, err)
		return
	}
	g, ok := t.GroupByID(r.PathValue("id"))
	if !ok {
		writeResErr(w, groupNotFound(r.PathValue("id")))
		return
	}
	plans := plansOf(t)
	hub := s.groupHub(t)
	writeJSON(w, http.StatusOK, map[string]any{"group": viewGroup(t, g, plans, s.groupRuntime(), hub), "thresholds": thresholds(), "hub_state": hub.view(t, s.hubReachability(t), plans)})
}

// groupInput is the create/patch body. Absent fields are left unchanged
// (patch) or defaulted (create). members replaces the whole order.
type groupInput struct {
	ID                 *string          `json:"id"`
	Name               *string          `json:"name"`
	Region             *string          `json:"region"`
	Mode               *model.GroupMode `json:"mode"`
	Members            *[]string        `json:"members"`
	Chosen             *string          `json:"chosen"`
	OnFailure          *model.OnFailure `json:"on_failure"`
	RequireResidential *bool            `json:"require_residential"`
	ExcludeResidential *bool            `json:"exclude_residential"`
	RequireV6          *bool            `json:"require_v6"`
	Notes              *string          `json:"notes"`
}

func invalid(field, format string, a ...any) error {
	return &credentials.Error{Code: credentials.CodeInvalid, Field: field, Msg: fmt.Sprintf(format, a...)}
}

func (in groupInput) applyTo(g *model.RegionGroup) error {
	if in.Name != nil {
		g.Name = strings.TrimSpace(*in.Name)
	}
	if in.Region != nil {
		g.Region = strings.TrimSpace(*in.Region)
	}
	if in.Members != nil {
		g.Members = []string{}
		for _, m := range *in.Members {
			g.Members = append(g.Members, strings.TrimSpace(m))
		}
	}
	if in.RequireResidential != nil {
		g.RequireResidential = *in.RequireResidential
	}
	if in.ExcludeResidential != nil {
		g.ExcludeResidential = *in.ExcludeResidential
	}
	if in.RequireV6 != nil {
		g.RequireV6 = *in.RequireV6
	}
	if in.Notes != nil {
		g.Notes = *in.Notes
	}
	if in.Mode != nil {
		switch *in.Mode {
		case model.GroupAuto, model.GroupManual:
		default:
			return invalid("mode", "mode 只能是 auto 或 manual")
		}
		g.Mode = *in.Mode
	}
	if g.Mode == "" {
		g.Mode = model.GroupAuto
	}
	if in.Chosen != nil {
		g.Chosen = strings.TrimSpace(*in.Chosen)
	}
	if in.OnFailure != nil {
		switch *in.OnFailure {
		case "", model.OnFailureHold, model.OnFailureFallback:
		default:
			return invalid("on_failure", "on_failure 只能是 hold 或 fallback")
		}
		g.OnFailure = *in.OnFailure
	}
	if g.Mode == model.GroupAuto {
		// The choice and the failure setting belong to manual mode. Sent
		// together with auto they are a contradiction; left over from an
		// earlier manual setting they are cleared.
		if in.Chosen != nil && g.Chosen != "" {
			return invalid("chosen", "自动模式不能指定成员；要指定成员请把 mode 设为 manual")
		}
		if in.OnFailure != nil && g.OnFailure != "" {
			return invalid("on_failure", "on_failure 只用于手动模式")
		}
		g.Chosen, g.OnFailure = "", ""
	} else if g.OnFailure == "" {
		g.OnFailure = model.OnFailureHold
	}
	if g.Name == "" {
		g.Name = g.ID
	}
	return nil
}

// groupErrors are the validation errors of next that concern group id and
// that prev did not already have.
func groupErrors(prev, next model.Topology, id string) error {
	key := func(i validate.Issue) string {
		return strings.Join([]string{i.Code, i.RuleID, i.NodeID, i.GroupID, i.Field}, "|")
	}
	had := map[string]bool{}
	for _, i := range validate.Run(prev).Issues {
		had[key(i)] = true
	}
	for _, i := range validate.Run(next).Issues {
		if i.Severity != validate.SeverityError || i.GroupID != id || had[key(i)] {
			continue
		}
		code := i.Code
		if code == "bad_id" || code == "duplicate_id" {
			code = credentials.CodeInvalid
		}
		field := i.Field
		if field == "" {
			field = "members"
		}
		return &credentials.Error{Code: code, Field: field, Msg: i.Message}
	}
	return nil
}

// mutateGroups applies fn to the stored topology under the store lock,
// refuses changes that add validation errors for group id, then resets the
// panel's runtime for touched groups and re-aligns unlock states.
func (s *Server) mutateGroups(id string, fn func(t *model.Topology) error) (model.Topology, error) {
	s.resMu.Lock()
	defer s.resMu.Unlock()
	var next model.Topology
	found, err := s.Store.Update(func(t *model.Topology) (bool, error) {
		prev := cloneTopo(*t)
		if err := fn(t); err != nil {
			return false, err
		}
		if err := groupErrors(prev, *t, id); err != nil {
			return false, err
		}
		next = *t
		return true, nil
	})
	if err != nil {
		return model.Topology{}, err
	}
	if !found {
		if _, err := s.topology(); err != nil {
			return model.Topology{}, err
		}
		return s.mutateGroups(id, fn)
	}
	s.afterGroupChange(next, id)
	return next, nil
}

func cloneTopo(t model.Topology) model.Topology {
	c := t
	c.Groups = make([]model.RegionGroup, len(t.Groups))
	for i, g := range t.Groups {
		g.Members = append([]string(nil), g.Members...)
		c.Groups[i] = g
	}
	c.Rules = append([]model.Rule(nil), t.Rules...)
	c.Nodes = append([]model.Node(nil), t.Nodes...)
	return c
}

// afterGroupChange drops the panel's runtime for groups whose target no
// longer matches (they restart on the next sample, as the hub does after
// the install) and reconciles unlock states with the new effective orders.
func (s *Server) afterGroupChange(t model.Topology, id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	doc := s.loadPools()
	changed := false
	for gid, rt := range doc.Pools {
		g, ok := t.GroupByID(gid)
		if !ok {
			delete(doc.Pools, gid)
			changed = true
			continue
		}
		if gid == id || rt.Target != pool.Select(t, g, nil).Target {
			delete(doc.Pools, gid)
			changed = true
		}
	}
	if changed {
		_ = s.savePools(doc)
	}
	s.reconcileUnlockLocked(t)
}

// reconcileUnlockLocked re-aligns every stored unlock state with its
// group (unlock.Reconcile). Call with s.mu held.
func (s *Server) reconcileUnlockLocked(t model.Topology) {
	snap := s.loadUnlock()
	changed := false
	for _, svc := range servicesOf(t) {
		prev, ok := snap.Services[svc.RuleID]
		if !ok {
			continue
		}
		next := unlock.Reconcile(prev, svc)
		if next.Preferred != prev.Preferred || next.Active != prev.Active || next.Pool != prev.Pool || next.Demoted != prev.Demoted {
			snap.Services[svc.RuleID] = next
			changed = true
			if next.Active != prev.Active {
				snap.PendingApply = true
			}
		}
	}
	if changed {
		_ = s.saveUnlock(snap)
	}
}

func (s *Server) createGroup(w http.ResponseWriter, r *http.Request) {
	var in groupInput
	if err := decodeBody(w, r, &in); err != nil {
		writeResErr(w, err)
		return
	}
	var id string
	t, err := s.mutateGroupsCreate(&in, &id)
	if err != nil {
		writeResErr(w, err)
		return
	}
	g, _ := t.GroupByID(id)
	writeJSON(w, http.StatusCreated, map[string]any{"group": s.oneGroupView(t, g), "apply_required": true})
}

func (s *Server) mutateGroupsCreate(in *groupInput, idOut *string) (model.Topology, error) {
	// The ID is fixed before the transaction so groupErrors can filter on it.
	t, err := s.topology()
	if err != nil {
		return model.Topology{}, err
	}
	id := ""
	if in.ID != nil {
		id = strings.TrimSpace(*in.ID)
	}
	if id == "" {
		base := ""
		if in.Region != nil {
			base = *in.Region
		}
		if base == "" && in.Name != nil {
			base = *in.Name
		}
		id = model.NewGroupID(base, t)
	}
	*idOut = id
	return s.mutateGroups(id, func(t *model.Topology) error {
		if _, exists := t.GroupByID(id); exists {
			return &credentials.Error{Code: credentials.CodeConflict, Field: "id", Msg: fmt.Sprintf("地区组 %s 已存在", id)}
		}
		g := model.RegionGroup{ID: id, Members: []string{}}
		if err := in.applyTo(&g); err != nil {
			return err
		}
		t.Groups = append(t.Groups, g)
		return nil
	})
}

func (s *Server) patchGroup(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var in groupInput
	if err := decodeBody(w, r, &in); err != nil {
		writeResErr(w, err)
		return
	}
	if in.ID != nil && strings.TrimSpace(*in.ID) != id {
		writeResErr(w, invalid("id", "地区组 ID 不能修改"))
		return
	}
	t, err := s.mutateGroups(id, func(t *model.Topology) error {
		for i := range t.Groups {
			if t.Groups[i].ID == id {
				g := t.Groups[i]
				g.Members = append([]string(nil), g.Members...)
				if err := in.applyTo(&g); err != nil {
					return err
				}
				t.Groups[i] = g
				return nil
			}
		}
		return groupNotFound(id)
	})
	if err != nil {
		writeResErr(w, err)
		return
	}
	g, _ := t.GroupByID(id)
	writeJSON(w, http.StatusOK, map[string]any{"group": s.oneGroupView(t, g), "apply_required": true})
}

func (s *Server) deleteGroup(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	_, err := s.mutateGroups(id, func(t *model.Topology) error {
		g, ok := t.GroupByID(id)
		if !ok {
			return groupNotFound(id)
		}
		if refs := groupRefs(*t, id); len(refs) > 0 {
			return &credentials.Error{Code: credentials.CodeInUse, InUse: refs,
				Msg: fmt.Sprintf("地区组 %s 仍被 %d 处引用（规则或默认境外组），先改掉这些引用", g.Name, len(refs))}
		}
		out := t.Groups[:0]
		for _, x := range t.Groups {
			if x.ID != id {
				out = append(out, x)
			}
		}
		t.Groups = out
		return nil
	})
	if err != nil {
		writeResErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"deleted": id, "apply_required": true})
}

func (s *Server) putDefaultGroup(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Group string `json:"group"`
	}
	if err := decodeBody(w, r, &body); err != nil {
		writeResErr(w, err)
		return
	}
	id := strings.TrimSpace(body.Group)
	t, err := s.mutateGroups(id, func(t *model.Topology) error {
		if _, ok := t.GroupByID(id); !ok {
			return &credentials.Error{Code: credentials.CodeNotFound, Field: "group", Msg: fmt.Sprintf("地区组 %s 不存在", id)}
		}
		t.Settings.DefaultGroup = id
		return nil
	})
	if err != nil {
		writeResErr(w, err)
		return
	}
	g, _ := t.GroupByID(id)
	writeJSON(w, http.StatusOK, map[string]any{"default_group": id, "group": s.oneGroupView(t, g), "apply_required": true})
}

// ----------------------------------------------------------- health ---

type healthBody struct {
	Observations []struct {
		ID string `json:"id"`
		Up bool   `json:"up"`
	} `json:"observations"`
}

// applyHealth feeds one round of member samples (exit ID → up) into every
// group whose switch order contains the member, with the hub's policy.
// It returns the members whose up/down flipped in any group.
func (s *Server) applyHealth(t model.Topology, in healthBody, now time.Time) ([]string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sample := map[string]bool{}
	for _, ob := range in.Observations {
		if n, ok := t.NodeByID(ob.ID); ok && n.Role == model.RoleExit {
			sample[ob.ID] = ob.Up
		}
	}
	doc := s.loadPools()
	plans := plansOf(t)
	flippedSet := map[string]bool{}
	for _, g := range t.Groups {
		pol := plans.plan(t, g).Policy()
		touched := false
		for _, id := range pol.Try {
			if _, ok := sample[id]; ok {
				touched = true
			}
		}
		if !touched {
			continue
		}
		prev := doc.Pools[g.ID]
		wasUp := map[string]bool{}
		for id, h := range prev.Members {
			wasUp[id] = h.Up
		}
		next := pool.StepGroup(prev, pol, sample, now)
		for id, h := range next.Members {
			if old, ok := wasUp[id]; ok && old != h.Up {
				flippedSet[id] = true
			}
		}
		doc.Pools[g.ID] = next
	}
	if err := s.savePools(doc); err != nil {
		return nil, err
	}
	flipped := make([]string, 0, len(flippedSet))
	for id := range flippedSet {
		flipped = append(flipped, id)
	}
	sort.Strings(flipped)
	if len(flipped) > 0 {
		snap := s.loadUnlock()
		snap.History = append(snap.History, unlock.HistoryEntry{
			At: now, Kind: unlock.KindHealth, Service: "pool",
			ExitID: strings.Join(flipped, ","),
			Note:   "出口健康变化，等待解锁补测。链路状态不直接改自动规则。",
		})
		_ = s.saveUnlock(snap)
	}
	return flipped, nil
}

func (s *Server) readHealth(w http.ResponseWriter, r *http.Request) (model.Topology, []string, bool) {
	body, err := readLimited(r, 1<<20)
	if err != nil {
		writeResErr(w, badRequest())
		return model.Topology{}, nil, false
	}
	var in healthBody
	if err := json.Unmarshal(body, &in); err != nil {
		writeResErr(w, badRequest())
		return model.Topology{}, nil, false
	}
	t, err := s.topology()
	if err != nil {
		writeResErr(w, err)
		return model.Topology{}, nil, false
	}
	flipped, err := s.applyHealth(t, in, time.Now().UTC())
	if err != nil {
		writeResErr(w, err)
		return model.Topology{}, nil, false
	}
	return t, flipped, true
}

func (s *Server) postGroupHealth(w http.ResponseWriter, r *http.Request) {
	t, flipped, ok := s.readHealth(w, r)
	if !ok {
		return
	}
	body := s.groupsBody(t)
	body["flipped"] = flipped
	writeJSON(w, http.StatusOK, body)
}
