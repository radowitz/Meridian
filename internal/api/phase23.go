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
	"github.com/radowitz/meridian/internal/unlock"
	"github.com/radowitz/meridian/internal/verify"
)

const (
	unlockKey = "unlock"
	poolKey   = "pool_runtime"
)

func (s *Server) compileTopo(t model.Topology) (*compile.Bundle, error) {
	return compile.CompileWithDecisions(t, s.unlockDecisions(t))
}

func (s *Server) unlockDecisions(t model.Topology) map[string]string {
	return unlock.Decisions(s.loadUnlock(), servicesOf(t))
}

func servicesOf(t model.Topology) []unlock.Service {
	var out []unlock.Service
	for _, r := range t.Rules {
		if !r.Enabled || r.TargetPool == "" {
			continue
		}
		members := pool.Names(pool.Members(t, r.TargetPool))
		pref := ""
		if len(members) > 0 {
			pref = members[0]
		}
		out = append(out, unlock.Service{
			RuleID: r.ID, Name: r.Name, Pool: r.TargetPool,
			Preferred: pref, Members: members,
			Pin: r.Mode == model.ModePin,
		})
	}
	return out
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

func (s *Server) getPools(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	t, err := s.topology()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	doc := s.loadPools()
	writeJSON(w, http.StatusOK, map[string]any{
		"pools": pool.Pools(t, meshPools(t), doc.Pools),
	})
}

func meshPools(t model.Topology) map[string]bool {
	out := map[string]bool{}
	hub := ""
	memberPool := map[string]string{}
	for _, n := range t.Nodes {
		if n.Role == model.RoleHub {
			hub = n.ID
		}
		if n.Role == model.RoleExit {
			memberPool[n.ID] = n.Pool
		}
	}
	for _, l := range t.Links {
		if l.Transport != model.TransportCFMesh || !l.Enabled {
			continue
		}
		var exit string
		switch {
		case l.From == hub:
			exit = l.To
		case l.To == hub:
			exit = l.From
		default:
			continue
		}
		if p := memberPool[exit]; p != "" {
			out[p] = true
		}
	}
	return out
}

type healthBody struct {
	Observations []struct {
		ID string `json:"id"`
		Up bool   `json:"up"`
	} `json:"observations"`
}

func (s *Server) postPoolHealth(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	body, err := readLimited(r, 1<<20)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	var in healthBody
	if err := json.Unmarshal(body, &in); err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	t, err := s.topology()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	doc := s.loadPools()
	now := time.Now().UTC()
	byPool := map[string]map[string]bool{}
	known := map[string]model.Node{}
	for _, n := range t.Nodes {
		if n.Role == model.RoleExit {
			known[n.ID] = n
		}
	}
	var flipped []string
	for _, ob := range in.Observations {
		n, ok := known[ob.ID]
		if !ok || n.Pool == "" {
			continue
		}
		if byPool[n.Pool] == nil {
			byPool[n.Pool] = map[string]bool{}
		}
		byPool[n.Pool][ob.ID] = ob.Up
		prev, seen := doc.Pools[n.Pool].Members[ob.ID]
		if seen && prev.Up != ob.Up {
			flipped = append(flipped, ob.ID)
		}
	}
	mesh := meshPools(t)
	for name, sample := range byPool {
		members := pool.Names(pool.Members(t, name))
		doc.Pools[name] = pool.Step(doc.Pools[name], members, sample, mesh[name], now)
	}
	if err := s.savePools(doc); err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	if len(flipped) > 0 {
		snap := s.loadUnlock()
		snap.History = append(snap.History, unlock.HistoryEntry{
			At: now, Kind: unlock.KindHealth, Service: "pool",
			ExitID: strings.Join(flipped, ","),
			Note:   "出口健康变化，等待解锁补测。链路状态不直接改自动规则。",
		})
		_ = s.saveUnlock(snap)
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"pools":   pool.Pools(t, mesh, doc.Pools),
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
	for k, v := range unlock.ParseAICodes(in.AI) {
		put(k, family, v)
	}
	if len(results) == 0 {
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
		seedState(&snap, svc)
		ob := unlock.Observation{Service: id, ExitID: exit.ID, Kind: kind, ObservedAt: observed, Results: results[id]}
		outcomes = append(outcomes, unlock.Ingest(&snap, ob, svc.Members, note, now)...)
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
