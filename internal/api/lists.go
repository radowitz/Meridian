package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/radowitz/meridian/internal/compile"
	"github.com/radowitz/meridian/internal/hostexec"
	"github.com/radowitz/meridian/internal/lists"
	"github.com/radowitz/meridian/internal/model"
)

// List sources and "update now". The policy is part of the topology
// settings (list_source); an update runs on the host through the agent's
// fixed list action (hostexec /v1/lists): the panel sends the policy, the
// kinds and the category / keyword names compiled from the topology, never
// a URL or path. See docs/architecture.md「名单源」.

// ListsRuntime is the host agent's list action (hostexec.Client in main).
type ListsRuntime interface {
	UpdateLists(ctx context.Context, req hostexec.ListsRequest) (lists.Report, error)
	ListsStatus(ctx context.Context) (lists.Status, error)
}

const (
	listsJobKey = "lists_last_job"

	codeUpdateRunning   = "update_running"
	codeHostUnavailable = "host_unavailable"
	codeInvalidLists    = "invalid_lists"
	codeInvalidField    = "invalid_field"
)

// listsJob is one "update now". State: running, done (the agent ran the
// update; see Report for each list) or failed (the agent was unreachable,
// busy or refused; nothing was changed by this job).
type listsJob struct {
	ID         string        `json:"id"`
	State      string        `json:"state"`
	Policy     lists.Policy  `json:"policy"`
	Lists      []string      `json:"lists"`
	StartedAt  time.Time     `json:"started_at"`
	FinishedAt *time.Time    `json:"finished_at,omitempty"`
	Report     *lists.Report `json:"report,omitempty"`
	Error      string        `json:"error,omitempty"`
}

func (s *Server) registerLists(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/lists", s.getLists)
	mux.HandleFunc("PUT /api/lists/policy", s.putListsPolicy)
	mux.HandleFunc("POST /api/lists/update", s.postListsUpdate)
	mux.HandleFunc("GET /api/lists/job", s.getListsJob)
	mux.HandleFunc("GET /api/lists/status", s.getListsStatus)
}

func writeListsErr(w http.ResponseWriter, status int, code, field, msg string) {
	body := map[string]any{"error": msg, "code": code}
	if field != "" {
		body["field"] = field
	}
	writeJSON(w, status, body)
}

func (s *Server) listsView(t model.Topology) map[string]any {
	p := lists.Effective(t.Settings.ListSource)
	var order []string
	for _, src := range lists.Order(p) {
		order = append(order, src.Name)
	}
	kws := compile.KeywordSpecs(t)
	if kws == nil {
		kws = []lists.Keyword{}
	}
	return map[string]any{
		"policy":   p,
		"saved":    t.Settings.ListSource != "",
		"policies": lists.Policies,
		"order":    order,
		// Compiled-in defaults; the host may override the domestic bases
		// (MERIDIAN_*_BASE_URL on meridian-host). Attempts in a report
		// carry the URLs actually used.
		"sources": []lists.Source{lists.Domestic, lists.Overseas},
		"lists": map[string]any{
			"geosite":  compile.GeositeNames(t),
			"keywords": kws,
			"chnroute": []string{"chnroute4", "chnroute6"},
		},
		"host_available": s.Lists != nil,
		"job":            s.currentListsJob(),
	}
}

func (s *Server) getLists(w http.ResponseWriter, r *http.Request) {
	t, err := s.topology()
	if err != nil {
		writeListsErr(w, http.StatusInternalServerError, "storage_error", "", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, s.listsView(t))
}

func (s *Server) putListsPolicy(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Policy string `json:"policy"`
	}
	if err := decodeBody(w, r, &body); err != nil {
		writeListsErr(w, http.StatusBadRequest, codeBadRequest, "", "请求格式错误")
		return
	}
	p, ok := lists.ParsePolicy(body.Policy)
	if !ok {
		writeListsErr(w, http.StatusUnprocessableEntity, codeInvalidField, "policy", "policy 只能是 domestic、overseas 或 automatic")
		return
	}
	if _, err := s.topology(); err != nil {
		writeListsErr(w, http.StatusInternalServerError, "storage_error", "", err.Error())
		return
	}
	if _, err := s.Store.Update(func(t *model.Topology) (bool, error) {
		if t.Settings.ListSource == string(p) {
			return false, nil
		}
		t.Settings.ListSource = string(p)
		return true, nil
	}); err != nil {
		writeListsErr(w, http.StatusInternalServerError, "storage_error", "", err.Error())
		return
	}
	t, err := s.topology()
	if err != nil {
		writeListsErr(w, http.StatusInternalServerError, "storage_error", "", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, s.listsView(t))
}

// postListsUpdate starts one update on the host and answers 202 with the
// job; poll GET /api/lists/job until state is not "running".
func (s *Server) postListsUpdate(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Lists  []string `json:"lists"`
		Policy string   `json:"policy"`
	}
	// An empty body means: both kinds, the saved policy.
	if err := decodeOptional(r, &body); err != nil {
		writeListsErr(w, http.StatusBadRequest, codeBadRequest, "", "请求格式错误")
		return
	}
	seen := map[string]bool{}
	for _, k := range body.Lists {
		if (k != lists.KindGeosite && k != lists.KindChnroute) || seen[k] {
			writeListsErr(w, http.StatusUnprocessableEntity, codeInvalidField, "lists", "lists 只能是 geosite、chnroute，且不能重复")
			return
		}
		seen[k] = true
	}
	if s.Lists == nil {
		writeListsErr(w, http.StatusServiceUnavailable, codeHostUnavailable, "", hostexec.ErrUnavailable.Error())
		return
	}
	t, err := s.topology()
	if err != nil {
		writeListsErr(w, http.StatusInternalServerError, "storage_error", "", err.Error())
		return
	}
	policy := lists.Effective(t.Settings.ListSource)
	if body.Policy != "" {
		p, ok := lists.ParsePolicy(body.Policy)
		if !ok {
			writeListsErr(w, http.StatusUnprocessableEntity, codeInvalidField, "policy", "policy 只能是 domestic、overseas 或 automatic")
			return
		}
		policy = p
	}
	kinds := body.Lists
	if len(kinds) == 0 {
		kinds = []string{lists.KindGeosite, lists.KindChnroute}
	}
	req := hostexec.ListsRequest{RequestID: "lists-" + randHex(8), Policy: string(policy), Lists: kinds}
	for _, k := range kinds {
		if k == lists.KindGeosite {
			req.Geosite = compile.GeositeNames(t)
			req.Keywords = compile.KeywordSpecs(t)
		}
	}
	// What remains is the topology's own names (too many categories, an
	// invalid keyword in a draft): nothing the request can fix.
	if err := hostexec.ValidateLists(req); err != nil {
		writeListsErr(w, http.StatusUnprocessableEntity, codeInvalidLists, "", "拓扑里的名单无法提交给宿主："+err.Error())
		return
	}
	s.listsMu.Lock()
	if s.listsJob != nil && s.listsJob.State == "running" {
		job := *s.listsJob
		s.listsMu.Unlock()
		writeJSON(w, http.StatusConflict, map[string]any{"error": "名单更新已在进行", "code": codeUpdateRunning, "job": job})
		return
	}
	job := &listsJob{ID: req.RequestID, State: "running", Policy: policy, Lists: kinds, StartedAt: time.Now().UTC()}
	s.listsJob = job
	snapshot := *job
	s.listsMu.Unlock()
	go s.runListsJob(job, req)
	writeJSON(w, http.StatusAccepted, map[string]any{"job": snapshot})
}

func (s *Server) runListsJob(job *listsJob, req hostexec.ListsRequest) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()
	rep, err := s.Lists.UpdateLists(ctx, req)
	now := time.Now().UTC()
	s.listsMu.Lock()
	done := *job
	s.listsMu.Unlock()
	done.FinishedAt = &now
	switch {
	case err != nil && rep.StartedAt.IsZero():
		done.State, done.Error = "failed", err.Error()
	default:
		r := rep
		done.State, done.Report = "done", &r
		if err != nil {
			done.Error = err.Error()
		}
	}
	// Persist before the job reads as finished, so a poller that sees
	// "done" and acts next never races this write.
	if b, err := json.Marshal(done); err == nil {
		_ = s.Store.Put(listsJobKey, string(b))
	}
	s.listsMu.Lock()
	*job = done
	s.listsMu.Unlock()
}

// currentListsJob is the running or last finished job (nil if none).
func (s *Server) currentListsJob() *listsJob {
	s.listsMu.Lock()
	if s.listsJob != nil {
		j := *s.listsJob
		s.listsMu.Unlock()
		return &j
	}
	s.listsMu.Unlock()
	raw, ok, err := s.Store.Get(listsJobKey)
	if err != nil || !ok {
		return nil
	}
	var j listsJob
	if json.Unmarshal([]byte(raw), &j) != nil {
		return nil
	}
	return &j
}

func (s *Server) getListsJob(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"job": s.currentListsJob()})
}

// getListsStatus is the host's own record: the live version of every list
// (source, URL, time, count) and the last update, whoever started it.
func (s *Server) getListsStatus(w http.ResponseWriter, r *http.Request) {
	if s.Lists == nil {
		writeListsErr(w, http.StatusServiceUnavailable, codeHostUnavailable, "", hostexec.ErrUnavailable.Error())
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	st, err := s.Lists.ListsStatus(ctx)
	if err != nil {
		code := http.StatusBadGateway
		if errors.Is(err, hostexec.ErrUnavailable) {
			code = http.StatusServiceUnavailable
		}
		writeListsErr(w, code, codeHostUnavailable, "", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"status": st})
}
