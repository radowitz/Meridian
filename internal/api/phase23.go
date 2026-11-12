package api

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"os/exec"
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
	ExitID   string          `json:"exit_id"`
	Kind     string          `json:"kind"`
	At       string          `json:"at,omitempty"`
	Services map[string]bool `json:"services,omitempty"`
	Raw      string          `json:"raw,omitempty"`
	AI       string          `json:"ai,omitempty"`
}

func (s *Server) postUnlockReport(w http.ResponseWriter, r *http.Request) {
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
	when := time.Now().UTC()
	if in.At != "" {
		parsed, err := time.Parse(time.RFC3339, in.At)
		if err != nil {
			writeErr(w, http.StatusBadRequest, errors.New("at 需要 RFC3339 时间"))
			return
		}
		when = parsed
	}
	results := map[string]bool{}
	for k, v := range in.Services {
		if id, ok := canonicalService(k); ok {
			results[id] = v
		}
	}
	for k, v := range unlock.ParseRegionCheck(in.Raw) {
		results[k] = v
	}
	for k, v := range unlock.ParseAICodes(in.AI) {
		results[k] = v
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
	for id, okResult := range results {
		svc, found := svcByID[id]
		if !found {
			continue
		}
		ev := unlock.Event{Service: id, ExitID: exit.ID, OK: okResult, Kind: kind, At: when}
		note := ""
		if svc.Pin {
			note = "钉死规则不受解锁结果影响，只记录。"
		} else if !containsStr(svc.Members, exit.ID) {
			note = "出口不在该服务的池里，不改变路由，也不换国家。"
		} else if snap.Services == nil {
			snap.Services = map[string]unlock.State{}
		}
		prev := snap.Services[id]
		if prev.Pool == "" {
			prev.Pool = svc.Pool
			prev.Preferred = svc.Preferred
			prev.Active = svc.Preferred
		}
		snap.Services[id] = prev
		unlock.Apply(&snap, ev, svc.Members, note)
	}
	if kind == unlock.KindScheduled {
		snap.NextRun = when.Add(unlock.Interval(t.Settings.UnlockIntervalSec))
	}
	if err := s.saveUnlock(snap); err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"pending_apply": snap.PendingApply,
		"decisions":     unlock.Decisions(snap, servicesOf(t)),
		"states":        snap.Services,
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

func (s *Server) postUnlockRun(w http.ResponseWriter, r *http.Request) {
	cmd := strings.TrimSpace(os.Getenv("MERIDIAN_UNLOCK_EXEC"))
	if cmd == "" {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{
			"error": "没有配置 MERIDIAN_UNLOCK_EXEC。在出口上运行 regioncheck 容器，再把 JSON 结果 POST 到 /api/unlock/report。面板不会编造探测结果。",
		})
		return
	}
	out, err := exec.Command(cmd).CombinedOutput()
	if err != nil {
		writeErr(w, http.StatusBadGateway, errors.New("解锁探测命令失败"))
		return
	}
	var in reportBody
	if json.Unmarshal(out, &in) != nil {
		writeErr(w, http.StatusBadGateway, errors.New("探测命令没有输出 JSON"))
		return
	}
	if in.Kind == "" {
		in.Kind = string(unlock.KindManual)
	}
	buf, _ := json.Marshal(in)
	req, _ := http.NewRequest(http.MethodPost, "/api/unlock/report", strings.NewReader(string(buf)))
	req.Header = r.Header.Clone()
	rr := newResponseRecorder()
	s.postUnlockReport(rr, req)
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(rr.code)
	_, _ = w.Write(rr.body)
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

// StartUnlockScheduler moves the stored next-run timestamp. It does not
// invent probe results when MERIDIAN_UNLOCK_EXEC is unset.
func (s *Server) StartUnlockScheduler() {
	go func() {
		ticker := time.NewTicker(time.Minute)
		defer ticker.Stop()
		for range ticker.C {
			s.tickUnlock()
		}
	}()
}

func (s *Server) tickUnlock() {
	t, err := s.topology()
	if err != nil {
		return
	}
	snap := s.loadUnlock()
	now := time.Now().UTC()
	if snap.NextRun.IsZero() {
		snap.NextRun = now.Add(unlock.Interval(t.Settings.UnlockIntervalSec))
		_ = s.saveUnlock(snap)
		return
	}
	if now.Before(snap.NextRun) {
		return
	}
	if strings.TrimSpace(os.Getenv("MERIDIAN_UNLOCK_EXEC")) == "" {
		snap.History = append(snap.History, unlock.HistoryEntry{
			At: now, Kind: unlock.KindScheduled, Note: "到达 6 小时定时，但没有配置探测命令，路由保持不变。",
		})
		snap.NextRun = now.Add(unlock.Interval(t.Settings.UnlockIntervalSec))
		_ = s.saveUnlock(snap)
		return
	}
	// The command posts its own report. Only the timestamp moves here if
	// the command is present; the report handler records the results.
	cmd := os.Getenv("MERIDIAN_UNLOCK_EXEC")
	if _, err := exec.Command(cmd).CombinedOutput(); err != nil {
		snap.History = append(snap.History, unlock.HistoryEntry{
			At: now, Kind: unlock.KindScheduled, Note: "定时探测命令失败，路由保持不变。",
		})
	}
	snap.NextRun = now.Add(unlock.Interval(t.Settings.UnlockIntervalSec))
	_ = s.saveUnlock(snap)
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

type memResponse struct {
	code int
	body []byte
	h    http.Header
}

func newResponseRecorder() *memResponse {
	return &memResponse{code: 200, h: http.Header{}}
}

func (m *memResponse) Header() http.Header { return m.h }
func (m *memResponse) WriteHeader(c int)   { m.code = c }
func (m *memResponse) Write(b []byte) (int, error) {
	m.body = append(m.body, b...)
	return len(b), nil
}
