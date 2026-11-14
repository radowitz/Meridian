package api

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/radowitz/meridian/internal/compile"
	"github.com/radowitz/meridian/internal/model"
	"github.com/radowitz/meridian/internal/pool"
	"github.com/radowitz/meridian/internal/probe"
	"github.com/radowitz/meridian/internal/unlock"
	"github.com/radowitz/meridian/internal/verify"
)

const (
	unlockKey = "unlock"
	poolKey   = "pool_runtime"
)

// compileTopo compiles t and resolves the WSS tokens from the panel's WSS
// state (generating missing material first). Without a credential store
// the tokens stay and every install path refuses the bundle.
func (s *Server) compileTopo(t model.Topology) (*compile.Bundle, error) {
	return s.compileWith(t, s.unlockDecisions(t))
}

// compileWith is compileTopo with the given unlock decisions.
func (s *Server) compileWith(t model.Topology, dec map[string]string) (*compile.Bundle, error) {
	b, err := compile.CompileWithDecisions(t, dec)
	if err != nil {
		return nil, err
	}
	return s.resolveWSS(t, b), nil
}

func (s *Server) unlockDecisions(t model.Topology) map[string]string {
	return unlock.Decisions(s.loadUnlock(), servicesOf(t))
}

// servicesOf lists every place an unlock decision is made or shown:
//
//   - every enabled rule aimed at a region group (the built-in auto-* rules
//     among them), keyed by its rule ID: the group's effective order is the
//     service's member list (the unlock map never leaves it), and rules of
//     a manual group are pinned (recorded only). Its probe is the adapter
//     with the rule's ID, when there is one;
//   - every service group with probes attached, keyed by
//     unlock.ServiceKey(id): with automatic selection on a region group
//     the group's effective order is the candidate list and the member the
//     group selects is where it stays when no candidate is known good;
//     fixed mode, a manual group, an exit target or direct/reject are pinned
//     (results are recorded and shown, nothing moves).
//
// One adapter is decided in one place only (validate checkServiceSelection
// refuses an automatic service group whose probe is also an enabled
// built-in rule's).
func servicesOf(t model.Topology) []unlock.Service {
	var out []unlock.Service
	for _, r := range t.Rules {
		if !r.Enabled || r.TargetGroup == "" || unlock.IsServiceKey(r.ID) {
			continue
		}
		g, ok := t.GroupByID(r.TargetGroup)
		if !ok {
			continue
		}
		sel := pool.Select(t, g, nil)
		svc := unlock.Service{
			RuleID: r.ID, Name: r.Name, Pool: g.ID,
			Preferred: sel.Target, Members: append([]string{}, sel.Order...),
			Pin: g.Mode == model.GroupManual,
		}
		if probe.Probeable(r.ID) {
			svc.Probes = []string{r.ID}
		}
		out = append(out, svc)
	}
	for _, sg := range t.ServiceGroups {
		if len(sg.Probes) == 0 {
			continue
		}
		svc := unlock.Service{RuleID: unlock.ServiceKey(sg.ID), Name: sg.Name, ServiceGroup: sg.ID, Pin: true, Members: []string{}}
		for _, id := range sg.Probes {
			if probe.Probeable(id) {
				svc.Probes = append(svc.Probes, id)
			}
		}
		switch {
		case sg.TargetGroup != "":
			g, ok := t.GroupByID(sg.TargetGroup)
			if !ok {
				continue
			}
			sel := pool.Select(t, g, nil)
			svc.Pool, svc.Preferred, svc.Members = g.ID, sel.Target, append([]string{}, sel.Order...)
			svc.Pin = sg.Select != model.SelectAuto || g.Mode == model.GroupManual || sg.Default
		case sg.TargetExit != "":
			svc.Preferred, svc.Members = sg.TargetExit, []string{sg.TargetExit}
		}
		out = append(out, svc)
	}
	return out
}

// unlockPolicy is the state machine's policy from the settings: the
// result lifetime (default twice the probe interval), for every service.
func unlockPolicy(t model.Topology) unlock.Policy {
	ttl := 2 * unlock.Interval(t.Settings.UnlockIntervalSec)
	if p := t.Settings.UnlockProbe; p != nil && p.ResultTTLSec > 0 {
		ttl = time.Duration(p.ResultTTLSec) * time.Second
	}
	return unlock.Policy{TTL: ttl}
}

// policyFor adds evidence-only backups for a service group: when no
// candidate has a valid success it stays on the member its group selects
// and the panel warns. Rules aimed at a region group (the built-in auto-*
// rules) keep their earlier behaviour of trying a member never measured.
func policyFor(t model.Topology, svc unlock.Service) unlock.Policy {
	pol := unlockPolicy(t)
	pol.RequireEvidence = svc.ServiceGroup != ""
	return pol
}

// exitConcurrency and exitBudget are the probe restraint settings.
func exitConcurrency(t model.Topology) int {
	if p := t.Settings.UnlockProbe; p != nil && p.ExitConcurrency > 0 && p.ExitConcurrency <= probeExitConcurrency {
		return p.ExitConcurrency
	}
	return model.DefaultUnlockExitConcurrency
}

func exitBudget(t model.Topology) int {
	if p := t.Settings.UnlockProbe; p != nil && p.ExitRequestBudget > 0 {
		return p.ExitRequestBudget
	}
	return model.DefaultUnlockExitBudget
}

func (s *Server) loadUnlock() unlock.Snapshot {
	raw, ok, err := s.Store.Get(unlockKey)
	if err != nil || !ok || raw == "" {
		return unlock.Snapshot{Services: map[string]unlock.State{}}
	}
	var snap unlock.Snapshot
	if json.Unmarshal([]byte(raw), &snap) != nil {
		return unlock.Snapshot{Services: map[string]unlock.State{}}
	}
	if snap.Services == nil {
		snap.Services = map[string]unlock.State{}
	}
	return snap
}

func (s *Server) saveUnlock(snap unlock.Snapshot) error {
	buf, err := json.Marshal(snap)
	if err != nil {
		return err
	}
	return s.Store.Put(unlockKey, string(buf))
}

func (s *Server) clearUnlockPending() {
	s.mu.Lock()
	defer s.mu.Unlock()
	snap := s.loadUnlock()
	if !snap.PendingApply {
		return
	}
	snap.PendingApply = false
	_ = s.saveUnlock(snap)
}

type poolDoc struct {
	Pools map[string]pool.Runtime `json:"pools"`
}

func (s *Server) loadPools() poolDoc {
	raw, ok, err := s.Store.Get(poolKey)
	if err != nil || !ok {
		return poolDoc{Pools: map[string]pool.Runtime{}}
	}
	var doc poolDoc
	if json.Unmarshal([]byte(raw), &doc) != nil || doc.Pools == nil {
		return poolDoc{Pools: map[string]pool.Runtime{}}
	}
	return doc
}

func (s *Server) savePools(doc poolDoc) error {
	buf, err := json.Marshal(doc)
	if err != nil {
		return err
	}
	return s.Store.Put(poolKey, string(buf))
}

// getPools is the legacy pool listing, now one entry per region group.
func (s *Server) getPools(w http.ResponseWriter, r *http.Request) {
	t, err := s.topology()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"pools": pool.Pools(t, meshGroups(t), s.groupRuntime()),
	})
}

// meshGroups: groups whose hub table may fall back to the Mesh sidecar.
func meshGroups(t model.Topology) map[string]bool {
	out := map[string]bool{}
	plans := plansOf(t)
	for _, g := range t.Groups {
		out[g.ID] = plans.plan(t, g).Mesh
	}
	return out
}

// postPoolHealth is the legacy health endpoint; it feeds the region-group
// state machine (POST /api/region-groups/health) and answers in the old shape.
func (s *Server) postPoolHealth(w http.ResponseWriter, r *http.Request) {
	t, flipped, ok := s.readHealth(w, r)
	if !ok {
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"pools":   pool.Pools(t, meshGroups(t), s.groupRuntime()),
		"flipped": flipped,
	})
}

func (s *Server) getUnlock(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	t, err := s.topology()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	snap := s.loadUnlock()
	if snap.NextRun.IsZero() {
		snap.NextRun = time.Now().UTC().Add(unlock.Interval(t.Settings.UnlockIntervalSec))
		_ = s.saveUnlock(snap)
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"services":      servicesOf(t),
		"states":        snap.Services,
		"history":       snap.History,
		"next_run":      snap.NextRun,
		"interval_sec":  int(unlock.Interval(t.Settings.UnlockIntervalSec).Seconds()),
		"pending_apply": snap.PendingApply,
		"decisions":     unlock.Decisions(snap, servicesOf(t)),
		// History entries and states that name these exits belong to exits
		// that were removed from the topology: shown as such, never as
		// current results.
		"removed_exits": unlock.RemovedExits(snap, exitExists(t)),
		// Where each decision is made, its candidates, evidence, exit in use
		// (panel computation) and last switch (unlock_routing.go).
		"owners":     routingView(t, snap, time.Now().UTC()),
		"schedule":   probeSchedule(t),
		"auto_apply": s.autoApplyView(t),
	})
}

type reportBody struct {
	ExitID string `json:"exit_id"`
	Kind   string `json:"kind"`
	// At is when the probe ran (RFC3339). It only orders results and bounds
	// their age (unlock.MaxReportAge); cooldowns use the panel clock.
	At string `json:"at,omitempty"`
	// Family applies to Services, Raw and AI: "", any, ipv4 or ipv6.
	Family   string          `json:"family,omitempty"`
	Services map[string]bool `json:"services,omitempty"`
	Raw      string          `json:"raw,omitempty"`
	// Raw4 / Raw6 are regioncheck output of the -M 4 / -M 6 runs.
	Raw4 string `json:"raw4,omitempty"`
	Raw6 string `json:"raw6,omitempty"`
	AI   string `json:"ai,omitempty"`
}

func (s *Server) postUnlockReport(w http.ResponseWriter, r *http.Request) {
	// Runs after the lock below is released: a decision this report changed
	// may be installed automatically (autoapply.go).
	defer s.maybeAutoApply("report")
	s.mu.Lock()
	defer s.mu.Unlock()
	body, err := readLimited(r, 256<<10)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	var in reportBody
	if err := json.Unmarshal(body, &in); err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	t, err := s.topology()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	exit, ok := t.NodeByID(in.ExitID)
	if !ok || exit.Role != model.RoleExit {
		writeErr(w, http.StatusBadRequest, errors.New("出口不存在"))
		return
	}
	kind := unlock.Kind(in.Kind)
	switch kind {
	case unlock.KindScheduled, unlock.KindManual, unlock.KindHealth:
	default:
		writeErr(w, http.StatusBadRequest, errors.New("kind 只能是 scheduled、manual 或 health"))
		return
	}
	family, ok := unlock.ParseFamily(in.Family)
	if !ok {
		writeErr(w, http.StatusBadRequest, errors.New("family 只能是 ipv4、ipv6 或留空"))
		return
	}
	// The reporter's at only orders results and is checked against the
	// validity window in unlock.Ingest. Hysteresis uses the server clock, so
	// a backdated at cannot use up the 30-minute return cooldown.
	var observed time.Time
	if in.At != "" {
		observed, err = time.Parse(time.RFC3339, in.At)
		if err != nil {
			writeErr(w, http.StatusBadRequest, errors.New("at 需要 RFC3339 时间"))
			return
		}
	}
	if len(in.Services) > 64 {
		writeErr(w, http.StatusBadRequest, errors.New("services 过多"))
		return
	}
	results := map[string]map[unlock.Family]bool{}
	put := func(id string, f unlock.Family, v bool) {
		if results[id] == nil {
			results[id] = map[unlock.Family]bool{}
		}
		if prev, seen := results[id][f]; seen {
			// Same rule as ParseRegionCheckFor: within one family of one
			// run, an acceptable Yes is not erased by another line.
			v = prev || v
		}
		results[id][f] = v
	}
	for k, v := range in.Services {
		if id, ok := canonicalService(k); ok {
			put(id, family, v)
		}
	}
	for k, v := range unlock.ParseRegionCheckFor(in.Raw, exit.Region) {
		put(k, family, v)
	}
	for k, v := range unlock.ParseRegionCheckFor(in.Raw4, exit.Region) {
		put(k, unlock.FamilyIPv4, v)
	}
	for k, v := range unlock.ParseRegionCheckFor(in.Raw6, exit.Region) {
		put(k, unlock.FamilyIPv6, v)
	}
	// The exit's curl lines are reachability only (an HTTP status, any
	// status): they are recorded through Ingest with a note and never step
	// the state machine, so a mere "it answered" can neither restore nor
	// demote an exit (and a timeout, code 000, is not a platform verdict).
	reach := map[string]map[unlock.Family]bool{}
	for k, v := range unlock.ParseAICodes(in.AI) {
		reach[k] = map[unlock.Family]bool{family: v}
	}
	if len(results) == 0 && len(reach) == 0 {
		writeErr(w, http.StatusBadRequest, errors.New("没有识别出的服务结果。未知格式不会被当成失败。"))
		return
	}
	snap := s.loadUnlock()
	svcByID := map[string]unlock.Service{}
	for _, svc := range servicesOf(t) {
		svcByID[svc.RuleID] = svc
	}
	ids := make([]string, 0, len(results))
	for id := range results {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	now := time.Now().UTC()
	var outcomes []unlock.Outcome
	for _, id := range ids {
		svc, found := svcByID[id]
		if !found {
			continue
		}
		note := ingestNote(svc, exit.ID)
		seedState(&snap, svc, now, policyFor(t, svc))
		ob := unlock.Observation{Service: id, ExitID: exit.ID, Kind: kind, ObservedAt: observed, Results: results[id]}
		outcomes = append(outcomes, unlock.IngestWith(&snap, ob, svc.Members, note, now, policyFor(t, svc))...)
	}
	rids := make([]string, 0, len(reach))
	for id := range reach {
		rids = append(rids, id)
	}
	sort.Strings(rids)
	for _, id := range rids {
		svc, found := svcByID[id]
		if !found {
			continue
		}
		seedState(&snap, svc, now, policyFor(t, svc))
		ob := unlock.Observation{Service: id, ExitID: exit.ID, Kind: kind, ObservedAt: observed, Results: reach[id]}
		outcomes = append(outcomes, unlock.IngestWith(&snap, ob, svc.Members, reachOnlyNote, now, policyFor(t, svc))...)
	}
	// An exit-side report does not move NextRun: that is the panel's own
	// probe schedule (unlock_probe.go).
	if err := s.saveUnlock(snap); err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"pending_apply": snap.PendingApply,
		"decisions":     unlock.Decisions(snap, servicesOf(t)),
		"states":        snap.Services,
		"outcomes":      outcomes,
	})
}

// reachOnlyNote marks an exit-side curl status line: reachability, not an
// unlock verdict. Recorded only.
const reachOnlyNote = "仅到达性（出口 curl 的 HTTP 状态码），不是解锁判断：只记录，不计入切换或恢复。"

func canonicalService(name string) (string, bool) {
	if id, ok := unlock.AIRuleID(name); ok {
		return id, true
	}
	switch strings.ToLower(name) {
	case "auto-netflix", "netflix":
		return "auto-netflix", true
	case "auto-disney", "disney":
		return "auto-disney", true
	case "auto-bahamut", "bahamut":
		return "auto-bahamut", true
	case "auto-kktv", "kktv":
		return "auto-kktv", true
	case "auto-linetv", "linetv":
		return "auto-linetv", true
	case "auto-hami", "hami":
		return "auto-hami", true
	case "auto-abema", "abema":
		return "auto-abema", true
	case "auto-mytvsuper", "mytvsuper":
		return "auto-mytvsuper", true
	default:
		if strings.HasPrefix(name, "auto-") {
			return name, true
		}
		return "", false
	}
}

func (s *Server) getLeakcheck(w http.ResponseWriter, r *http.Request) {
	t, err := s.topology()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	b, err := s.compileTopo(t)
	if err != nil {
		writeErr(w, http.StatusUnprocessableEntity, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": verify.CheckBundle(t, b.Files)})
}

func readLimited(r *http.Request, n int64) ([]byte, error) {
	return io.ReadAll(io.LimitReader(r.Body, n))
}

func containsStr(ss []string, s string) bool {
	for _, v := range ss {
		if v == s {
			return true
		}
	}
	return false
}
