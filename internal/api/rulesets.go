package api

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/radowitz/meridian/internal/hostexec"
	"github.com/radowitz/meridian/internal/lists"
	"github.com/radowitz/meridian/internal/model"
	"github.com/radowitz/meridian/internal/ordered"
	"github.com/radowitz/meridian/internal/ruleset"
)

// Subscribed rule-sets (docs/architecture.md「规则集」). Definitions are part
// of the topology (model.RuleSet, owned by these endpoints); the fetch
// status lives in the panel store (key rulesets_status); the active content
// is written, normalized (ordered.MarshalEntries), to
// <RuleSetDir>/<id>.txt, where the gateway's derive step reads it.
//
// The panel fetches (ruleset.Fetcher: size limit, timeout, no proxy, no
// redirect or connection to loopback, link-local, private or own addresses
// unless the set allows a LAN source), parses, and activates atomically:
// the file is replaced only when parsing succeeded; on any failure the
// previous version stays. A new version that executes fewer of its entries
// in list order than the active one (more keyword or unsupported entries)
// is held back with a warning until the operator activates it.

const rsStatusKey = "rulesets_status"

// RuleSetFetcher downloads one URL (ruleset.Fetcher in production).
type RuleSetFetcher interface {
	Get(ctx context.Context, url string) ([]byte, error)
}

// RuleSetStatus is the fetch state of one rule-set.
type RuleSetStatus struct {
	State     string `json:"state"` // never, fetching, ok, failed, held
	FetchedAt string `json:"fetched_at,omitempty"`
	// The active version.
	Digest      string         `json:"digest,omitempty"`
	Format      string         `json:"format,omitempty"`
	Source      string         `json:"source,omitempty"`
	URL         string         `json:"url,omitempty"`
	Counts      map[string]int `json:"counts,omitempty"`
	Unsupported map[string]int `json:"unsupported,omitempty"`
	Notes       []string       `json:"notes,omitempty"`
	// Last attempt.
	LastAttempt string              `json:"last_attempt,omitempty"`
	LastError   string              `json:"last_error,omitempty"`
	Attempts    []ruleset.Candidate `json:"attempts,omitempty"`
	Held        *heldVersion        `json:"held,omitempty"`
	Applied     string              `json:"applied,omitempty"`
}

type heldVersion struct {
	Digest      string         `json:"digest"`
	Format      string         `json:"format"`
	Counts      map[string]int `json:"counts"`
	Unsupported map[string]int `json:"unsupported,omitempty"`
	Reason      string         `json:"reason"`
	FetchedAt   string         `json:"fetched_at"`
}

type ruleSetState struct {
	mu       sync.Mutex
	fetching map[string]bool
	// prefetch: content fetched for an import preview, by URL (not secret;
	// kept in memory until confirmed or the panel restarts).
	prefetch map[string]prefetched
}

type prefetched struct {
	state   string
	err     string
	parsed  ruleset.Parsed
	content []byte
	at      time.Time
}

func (s *Server) rs() *ruleSetState {
	s.rsOnce.Do(func() {
		s.rsState = &ruleSetState{fetching: map[string]bool{}, prefetch: map[string]prefetched{}}
	})
	return s.rsState
}

func (s *Server) ruleSetDir() string {
	if s.RuleSetDir != "" {
		return s.RuleSetDir
	}
	return filepath.Join(hostexec.DefaultListsDir, lists.RuleSetSubdir)
}

// RuleSetFetchOptions configure one download (see ruleset.Fetcher).
type RuleSetFetchOptions struct {
	AllowLAN bool
	// Deny: the gateway's own and internal ranges (gatewayDeny), refused
	// even with AllowLAN.
	Deny []netip.Prefix
	// Auth is sent to AuthOrigin only (nil: none).
	Auth       *ruleset.Auth
	AuthOrigin string
}

func (s *Server) fetcher(o RuleSetFetchOptions) RuleSetFetcher {
	if s.RuleSetFetch != nil {
		return s.RuleSetFetch(o)
	}
	return &ruleset.Fetcher{AllowLAN: o.AllowLAN, Deny: o.Deny, Auth: o.Auth, AuthOrigin: o.AuthOrigin}
}

// fetchOptions are the download options of a rule-set.
func (s *Server) fetchOptions(t model.Topology, id, url string, allowLAN bool) (RuleSetFetchOptions, error) {
	o := RuleSetFetchOptions{AllowLAN: allowLAN, Deny: gatewayDeny(t)}
	if id == "" {
		return o, nil
	}
	a, err := s.ruleSetAuth(id)
	if err != nil {
		return o, errors.New("读不到这个规则集的订阅认证（凭据存储不可用或文件损坏）")
	}
	if a != nil {
		o.Auth, o.AuthOrigin = a, ruleset.Origin(url)
	}
	return o, nil
}

func (s *Server) registerRuleSets(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/rule-sets", s.listRuleSets)
	mux.HandleFunc("POST /api/rule-sets", s.createRuleSet)
	mux.HandleFunc("PATCH /api/rule-sets/{id}", s.patchRuleSet)
	mux.HandleFunc("DELETE /api/rule-sets/{id}", s.deleteRuleSet)
	mux.HandleFunc("POST /api/rule-sets/{id}/update", s.updateRuleSet)
	mux.HandleFunc("POST /api/rule-sets/{id}/activate-held", s.activateHeld)
	mux.HandleFunc("PUT /api/rule-sets/{id}/auth", s.putRuleSetAuth)
	mux.HandleFunc("DELETE /api/rule-sets/{id}/auth", s.deleteRuleSetAuth)
}

func (s *Server) loadRSStatus() map[string]*RuleSetStatus {
	m, _ := s.loadRSStatusErr()
	return m
}

// loadRSStatusErr retries a busy read: an update must never start from an
// empty map it only got because the read failed.
func (s *Server) loadRSStatusErr() (map[string]*RuleSetStatus, error) {
	var err error
	for i := 0; i < 20; i++ {
		var v string
		var ok bool
		if v, ok, err = s.Store.Get(rsStatusKey); err == nil {
			out := map[string]*RuleSetStatus{}
			if ok {
				if err := json.Unmarshal([]byte(v), &out); err != nil {
					return out, err
				}
			}
			return out, nil
		}
		time.Sleep(50 * time.Millisecond)
	}
	return map[string]*RuleSetStatus{}, err
}

func (s *Server) saveRSStatus(m map[string]*RuleSetStatus) {
	b, _ := json.Marshal(m)
	// A write can meet a busy database while a topology save runs; retry
	// briefly rather than lose a status.
	for i := 0; i < 20; i++ {
		if err := s.Store.Put(rsStatusKey, string(b)); err == nil {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func (s *Server) updateRSStatus(id string, fn func(st *RuleSetStatus)) {
	s.rs().mu.Lock()
	defer s.rs().mu.Unlock()
	m, err := s.loadRSStatusErr()
	if err != nil {
		return
	}
	st := m[id]
	if st == nil {
		st = &RuleSetStatus{State: "never"}
		m[id] = st
	}
	fn(st)
	s.saveRSStatus(m)
}

func ruleSetUsers(t model.Topology, id string) []map[string]any {
	var out []map[string]any
	for i, r := range t.EvalOrder() {
		if r.MatchType == model.MatchRuleSet && r.RuleSet == id {
			out = append(out, map[string]any{"rule_id": r.ID, "name": r.Name, "position": i + 1, "enabled": r.Enabled})
		}
	}
	return out
}

func (s *Server) ruleSetView(t model.Topology, rs model.RuleSet, st map[string]*RuleSetStatus) map[string]any {
	status := st[rs.ID]
	if status == nil {
		status = &RuleSetStatus{State: "never"}
	}
	cp := *status
	status = &cp
	s.rs().mu.Lock()
	if s.rs().fetching[rs.ID] {
		cp.State = "fetching"
	}
	s.rs().mu.Unlock()
	// Nothing about a download is shown with its query string or user
	// information (a status written by an older version may have them).
	if cp.URL != "" {
		cp.URL = ruleset.Redact(cp.URL)
	}
	cp.LastError = redactText(cp.LastError)
	users := ruleSetUsers(t, rs.ID)
	if users == nil {
		users = []map[string]any{}
	}
	cands := ruleset.Candidates(rs.URL, sourceMode(rs), lists.Effective(t.Settings.ListSource))
	for i := range cands {
		cands[i].URL = ruleset.Redact(cands[i].URL)
	}
	if ruleset.HasSecret(rs.URL) {
		rs.URL = ruleset.Redact(rs.URL)
	}
	return map[string]any{
		"rule_set":   rs,
		"status":     status,
		"used_by":    users,
		"candidates": cands,
		// Metadata of the subscription credential (never the material).
		"auth": s.ruleSetAuthView(rs.ID),
	}
}

func sourceMode(rs model.RuleSet) string {
	if rs.Source == "" {
		if _, _, _, _, ok := ruleset.GitHubRaw(rs.URL); ok {
			return ruleset.SourcePolicy
		}
		return ruleset.SourceURL
	}
	return rs.Source
}

func (s *Server) listRuleSets(w http.ResponseWriter, r *http.Request) {
	t, err := s.topology()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	st := s.loadRSStatus()
	out := []map[string]any{}
	for _, rs := range t.RuleSets {
		out = append(out, s.ruleSetView(t, rs, st))
	}
	writeJSON(w, http.StatusOK, map[string]any{"rule_sets": out, "formats": ruleset.Formats})
}

type ruleSetBody struct {
	Name        *string `json:"name"`
	URL         *string `json:"url"`
	Format      *string `json:"format"`
	Source      *string `json:"source"`
	IntervalSec *int    `json:"interval_sec"`
	AllowLAN    *bool   `json:"allow_lan"`
	// Auth (write-only) stores or rotates the subscription credential.
	Auth *authBody `json:"auth,omitempty"`
}

// checkBody refuses a URL that carries a credential (it belongs in auth)
// and an invalid credential, without quoting either.
func (b ruleSetBody) check(w http.ResponseWriter) bool {
	if b.URL != nil && ruleset.HasSecret(strings.TrimSpace(*b.URL)) {
		writeJSON(w, http.StatusUnprocessableEntity, map[string]any{"error": ruleset.ErrURLSecret.Error(), "code": "url_has_secret", "field": "url"})
		return false
	}
	if b.Auth != nil {
		if err := b.Auth.auth().Check(); err != nil {
			writeJSON(w, http.StatusUnprocessableEntity, map[string]any{"error": err.Error(), "code": "bad_auth", "field": "auth"})
			return false
		}
	}
	return true
}

func (b ruleSetBody) apply(rs *model.RuleSet) {
	if b.Name != nil {
		rs.Name = strings.TrimSpace(*b.Name)
	}
	if b.URL != nil {
		rs.URL = strings.TrimSpace(*b.URL)
	}
	if b.Format != nil {
		rs.Format = *b.Format
	}
	if b.Source != nil {
		rs.Source = *b.Source
	}
	if b.IntervalSec != nil {
		rs.IntervalSec = *b.IntervalSec
	}
	if b.AllowLAN != nil {
		rs.AllowLAN = *b.AllowLAN
	}
}

// saveTopologyChecked runs fn on the stored topology and keeps the result
// only when it has no validation error that the previous document did not
// have.
func (s *Server) saveTopologyChecked(fn func(t *model.Topology) error) (model.Topology, []any, error) {
	var issues []any
	var out model.Topology
	if _, err := s.topology(); err != nil { // seeds the store on first use
		return out, nil, err
	}
	_, err := s.Store.Update(func(t *model.Topology) (bool, error) {
		before := map[string]bool{}
		for _, is := range validateIssues(*t) {
			before[is.Code+"|"+is.RuleID+"|"+is.Message] = true
		}
		if err := fn(t); err != nil {
			return false, err
		}
		for _, is := range validateIssues(*t) {
			if !before[is.Code+"|"+is.RuleID+"|"+is.Message] {
				issues = append(issues, is)
			}
		}
		if len(issues) > 0 {
			return false, errValidation
		}
		out = *t
		return true, nil
	})
	return out, issues, err
}

var errValidation = errors.New("validation")

func (s *Server) createRuleSet(w http.ResponseWriter, r *http.Request) {
	var b ruleSetBody
	if err := decodeBody(w, r, &b); err != nil {
		writeErr(w, http.StatusBadRequest, errors.New("请求格式错误"))
		return
	}
	if !b.check(w) {
		return
	}
	var rs model.RuleSet
	b.apply(&rs)
	if rs.Source == "" {
		rs.Source = sourceMode(rs)
	}
	rs.ID = "rs-" + randHex(5)
	t, issues, err := s.saveTopologyChecked(func(t *model.Topology) error {
		t.RuleSets = append(t.RuleSets, rs)
		return nil
	})
	if s.writeSaveErr(w, issues, err) {
		return
	}
	if b.Auth != nil {
		a := b.Auth.auth()
		if err := s.storeRuleSetAuth(rs.ID, a); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "规则集已添加，但订阅认证没有保存：" + ruleset.Scrub(err.Error(), a.Secrets()...) + "。请在规则集上重新设置认证。", "code": "auth_not_stored"})
			return
		}
	}
	s.startFetch(t, rs, false)
	writeJSON(w, http.StatusCreated, s.ruleSetView(t, rs, s.loadRSStatus()))
}

func (s *Server) writeSaveErr(w http.ResponseWriter, issues []any, err error) bool {
	switch {
	case errors.Is(err, errValidation):
		writeJSON(w, http.StatusUnprocessableEntity, map[string]any{"error": "校验未通过，没有保存", "issues": issues})
	case err != nil && strings.HasPrefix(err.Error(), "404:"):
		writeJSON(w, http.StatusNotFound, map[string]any{"error": strings.TrimPrefix(err.Error(), "404:")})
	case err != nil && strings.HasPrefix(err.Error(), "409:"):
		writeJSON(w, http.StatusConflict, map[string]any{"error": strings.TrimPrefix(err.Error(), "409:")})
	case err != nil:
		writeErr(w, http.StatusInternalServerError, err)
	default:
		return false
	}
	return true
}

func (s *Server) patchRuleSet(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var b ruleSetBody
	if err := decodeBody(w, r, &b); err != nil {
		writeErr(w, http.StatusBadRequest, errors.New("请求格式错误"))
		return
	}
	if !b.check(w) {
		return
	}
	var out model.RuleSet
	var oldURL string
	t, issues, err := s.saveTopologyChecked(func(t *model.Topology) error {
		for i := range t.RuleSets {
			if t.RuleSets[i].ID == id {
				oldURL = t.RuleSets[i].URL
				b.apply(&t.RuleSets[i])
				out = t.RuleSets[i]
				return nil
			}
		}
		return errors.New("404:规则集不存在")
	})
	if s.writeSaveErr(w, issues, err) {
		return
	}
	switch {
	case b.Auth != nil:
		a := b.Auth.auth()
		if err := s.storeRuleSetAuth(id, a); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "订阅认证没有保存：" + ruleset.Scrub(err.Error(), a.Secrets()...), "code": "auth_not_stored"})
			return
		}
	case ruleset.Origin(oldURL) != ruleset.Origin(out.URL):
		// A write-only credential must not follow the URL to another
		// origin (that would hand it to whoever runs the new host): it is
		// dropped unless the same request sets a new one.
		if cs, err := s.credStore(); err == nil {
			_ = cs.DeleteRuleSetAuth(id)
		}
	}
	writeJSON(w, http.StatusOK, s.ruleSetView(t, out, s.loadRSStatus()))
}

func (s *Server) deleteRuleSet(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	t, err := s.topology()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	if users := ruleSetUsers(t, id); len(users) > 0 {
		writeJSON(w, http.StatusConflict, map[string]any{"error": "还有规则在用这个规则集，先删除或改掉这些规则", "code": "in_use", "used_by": users})
		return
	}
	_, issues, err := s.saveTopologyChecked(func(t *model.Topology) error {
		for i := range t.RuleSets {
			if t.RuleSets[i].ID == id {
				t.RuleSets = append(t.RuleSets[:i], t.RuleSets[i+1:]...)
				return nil
			}
		}
		return errors.New("404:规则集不存在")
	})
	if s.writeSaveErr(w, issues, err) {
		return
	}
	_ = os.Remove(filepath.Join(s.ruleSetDir(), id+".txt"))
	if cs, err := s.credStore(); err == nil {
		_ = cs.DeleteRuleSetAuth(id)
	}
	s.rs().mu.Lock()
	m := s.loadRSStatus()
	delete(m, id)
	s.saveRSStatus(m)
	s.rs().mu.Unlock()
	writeJSON(w, http.StatusOK, map[string]any{"deleted": id})
}

func (s *Server) updateRuleSet(w http.ResponseWriter, r *http.Request) {
	t, err := s.topology()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	rs, ok := t.RuleSetByID(r.PathValue("id"))
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]any{"error": "规则集不存在"})
		return
	}
	if !s.startFetch(t, rs, false) {
		writeJSON(w, http.StatusConflict, map[string]any{"error": "这个规则集正在下载", "code": "update_running"})
		return
	}
	writeJSON(w, http.StatusAccepted, s.ruleSetView(t, rs, s.loadRSStatus()))
}

func (s *Server) activateHeld(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var body struct {
		Accept bool `json:"accept"`
	}
	if err := decodeBody(w, r, &body); err != nil || !body.Accept {
		writeErr(w, http.StatusBadRequest, errors.New("需要 {\"accept\": true}：确认接受被暂缓版本的说明"))
		return
	}
	p := filepath.Join(s.heldDir(), id+".txt")
	b, err := os.ReadFile(p)
	if err != nil {
		writeJSON(w, http.StatusNotFound, map[string]any{"error": "没有被暂缓的版本"})
		return
	}
	var held *heldVersion
	if x := s.loadRSStatus()[id]; x != nil {
		held = x.Held
	}
	if held == nil {
		writeJSON(w, http.StatusNotFound, map[string]any{"error": "没有被暂缓的版本"})
		return
	}
	if err := s.activateContent(id, b, held.Format, held.Counts, held.Unsupported, nil, "", ""); err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	_ = os.Remove(p)
	t, _ := s.topology()
	rs, _ := t.RuleSetByID(id)
	writeJSON(w, http.StatusOK, s.ruleSetView(t, rs, s.loadRSStatus()))
}

func (s *Server) heldDir() string { return filepath.Join(s.DataDir, "rulesets-held") }

// startFetch runs one fetch in the background; false when one is running.
func (s *Server) startFetch(t model.Topology, rs model.RuleSet, wait bool) bool {
	st := s.rs()
	st.mu.Lock()
	if st.fetching[rs.ID] {
		st.mu.Unlock()
		return false
	}
	st.fetching[rs.ID] = true
	st.mu.Unlock()
	policy := lists.Effective(t.Settings.ListSource)
	run := func() {
		defer func() {
			st.mu.Lock()
			delete(st.fetching, rs.ID)
			st.mu.Unlock()
		}()
		s.fetchOnce(t, rs, policy)
	}
	if wait {
		run()
	} else {
		go run()
	}
	return true
}

// fetchCandidates downloads and parses the first candidate that works.
// Error text never carries a query string or a credential.
func (s *Server) fetchCandidates(ctx context.Context, url, mode, format, behavior string, o RuleSetFetchOptions, p lists.Policy) (ruleset.Parsed, []byte, ruleset.Candidate, []string) {
	var errs []string
	f := s.fetcher(o)
	for _, c := range ruleset.Candidates(url, mode, p) {
		b, err := f.Get(ctx, c.URL)
		if err != nil {
			errs = append(errs, c.Source+": "+redactText(ruleset.Scrub(err.Error(), o.Auth.Secrets()...)))
			continue
		}
		parsed, err := ruleset.Parse(b, format, behavior, c.URL)
		if err != nil {
			errs = append(errs, c.Source+": "+err.Error())
			if errors.Is(err, ruleset.ErrMRS) {
				break
			}
			continue
		}
		return parsed, ordered.MarshalEntries(parsed.Entries), c, nil
	}
	return ruleset.Parsed{}, nil, ruleset.Candidate{}, errs
}

func (s *Server) fetchOnce(t model.Topology, rs model.RuleSet, p lists.Policy) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	now := time.Now().UTC().Format(time.RFC3339)
	o, err := s.fetchOptions(t, rs.ID, rs.URL, rs.AllowLAN)
	if err != nil {
		s.updateRSStatus(rs.ID, func(st *RuleSetStatus) {
			st.LastAttempt, st.LastError = now, err.Error()
			if st.Digest == "" {
				st.State = "failed"
			}
		})
		return
	}
	parsed, content, cand, errs := s.fetchCandidates(ctx, rs.URL, sourceMode(rs), rs.Format, rs.Behavior, o, p)
	if content == nil {
		s.updateRSStatus(rs.ID, func(st *RuleSetStatus) {
			st.LastAttempt, st.LastError = now, strings.Join(errs, "；")
			if st.Digest == "" {
				st.State = "failed"
			}
		})
		return
	}
	cur := s.loadRSStatus()[rs.ID]
	if cur != nil && cur.Digest != "" {
		if reason := lessExact(cur, parsed); reason != "" {
			_ = os.MkdirAll(s.heldDir(), 0o700)
			_ = writeFileAtomic(filepath.Join(s.heldDir(), rs.ID+".txt"), content, 0o600)
			s.updateRSStatus(rs.ID, func(st *RuleSetStatus) {
				st.LastAttempt, st.LastError, st.State = now, "", "held"
				st.Held = &heldVersion{Digest: digestOf(content), Format: parsed.Format, Counts: parsed.Counts, Unsupported: parsed.Unsupported, Reason: reason, FetchedAt: now}
			})
			return
		}
	}
	if err := s.activateContent(rs.ID, content, parsed.Format, parsed.Counts, parsed.Unsupported, parsed.Notes, cand.Source, cand.URL); err != nil {
		s.updateRSStatus(rs.ID, func(st *RuleSetStatus) {
			st.LastAttempt, st.LastError = now, "写入失败，旧版本保留："+err.Error()
		})
	}
}

// lessExact: the new version executes fewer of its entries in list order
// than the active one (more keyword or unsupported entries).
func lessExact(cur *RuleSetStatus, p ruleset.Parsed) string {
	sum := func(m map[string]int) int {
		n := 0
		for _, v := range m {
			n += v
		}
		return n
	}
	if p.Counts["keyword"] > cur.Counts["keyword"] {
		return fmt.Sprintf("新版本的 DOMAIN-KEYWORD 从 %d 条变成 %d 条：这些条目在网关上不执行，含这些词的名字会落到后面的规则", cur.Counts["keyword"], p.Counts["keyword"])
	}
	if sum(p.Unsupported) > sum(cur.Unsupported) {
		return fmt.Sprintf("新版本不能执行的条目从 %d 条变成 %d 条", sum(cur.Unsupported), sum(p.Unsupported))
	}
	return ""
}

func digestOf(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

// activateContent replaces the active content atomically, records it and
// asks the host to re-derive the rule domain-sets (best effort: without a
// host the next install does it).
func (s *Server) activateContent(id string, content []byte, format string, counts, unsupported map[string]int, notes []string, source, url string) error {
	if err := os.MkdirAll(s.ruleSetDir(), 0o755); err != nil {
		return err
	}
	p := filepath.Join(s.ruleSetDir(), id+".txt")
	old, _ := os.ReadFile(p)
	if err := writeFileAtomic(p, content, 0o644); err != nil {
		return err
	}
	now := time.Now().UTC().Format(time.RFC3339)
	s.updateRSStatus(id, func(st *RuleSetStatus) {
		st.State, st.FetchedAt, st.LastAttempt, st.LastError = "ok", now, now, ""
		st.Digest, st.Format, st.Counts, st.Unsupported, st.Notes, st.Held = digestOf(content), format, counts, unsupported, notes, nil
		if source != "" {
			st.Source, st.URL = source, ruleset.Redact(url)
		}
	})
	if string(old) != string(content) {
		s.applyRuleSetsOnHost(id)
	}
	return nil
}

// applyRuleSetsOnHost asks the host agent to re-derive (lists kind
// "rules"); the result is recorded on the rule-set.
func (s *Server) applyRuleSetsOnHost(id string) {
	if s.Lists == nil {
		s.updateRSStatus(id, func(st *RuleSetStatus) { st.Applied = "宿主执行器不可用：下次安装时生效" })
		return
	}
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
		defer cancel()
		t, err := s.topology()
		if err != nil {
			return
		}
		req := hostexec.ListsRequest{RequestID: "rules-" + randHex(8), Policy: string(lists.Effective(t.Settings.ListSource)), Lists: []string{lists.KindRules}}
		rep, err := s.Lists.UpdateLists(ctx, req)
		msg := "已在网关上生效"
		switch {
		case err != nil:
			msg = "宿主没有执行（" + err.Error() + "）：下次安装或名单更新时生效"
		case !rep.OK:
			msg = "宿主没有生效：" + rep.Error
			for _, l := range rep.Lists {
				if l.Error != "" {
					msg += " " + l.Error
				}
			}
		}
		s.updateRSStatus(id, func(st *RuleSetStatus) { st.Applied = msg })
	}()
}

func writeFileAtomic(path string, b []byte, mode os.FileMode) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if err := tmp.Chmod(mode); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(b); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

// activeEntries reads a rule-set's active content.
func (s *Server) activeEntries(id string) ([]ordered.Entry, bool) {
	b, err := os.ReadFile(filepath.Join(s.ruleSetDir(), id+".txt"))
	if err != nil {
		return nil, false
	}
	es, err := ordered.UnmarshalEntries(b)
	return es, err == nil
}

// RunRuleSetScheduler fetches every rule-set whose interval elapsed (default
// 24 h), checking every 10 minutes, until ctx ends.
func (s *Server) RunRuleSetScheduler(ctx context.Context) {
	tick := time.NewTicker(10 * time.Minute)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
		t, err := s.topology()
		if err != nil {
			continue
		}
		for _, rs := range dueRuleSets(t, s.loadRSStatus(), time.Now()) {
			s.startFetch(t, rs, true)
		}
	}
}

// dueRuleSets are the rule-sets whose interval (default 24 h) elapsed since
// their last attempt (successful or not), by ID. A rule-set never tried is
// due at once.
func dueRuleSets(t model.Topology, st map[string]*RuleSetStatus, now time.Time) []model.RuleSet {
	var out []model.RuleSet
	for _, rs := range t.RuleSets {
		iv := time.Duration(rs.IntervalSec) * time.Second
		if iv == 0 {
			iv = 24 * time.Hour
		}
		last := time.Time{}
		if x := st[rs.ID]; x != nil {
			last, _ = time.Parse(time.RFC3339, x.LastAttempt)
		}
		if now.Sub(last) >= iv {
			out = append(out, rs)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}
