package api

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/radowitz/meridian/internal/hostexec"
	"github.com/radowitz/meridian/internal/lists"
	"github.com/radowitz/meridian/internal/mihomo"
	"github.com/radowitz/meridian/internal/model"
	"github.com/radowitz/meridian/internal/ordered"
	"github.com/radowitz/meridian/internal/ruleset"
	"github.com/radowitz/meridian/internal/validate"
)

// Import from mihomo (docs/architecture.md「从 mihomo 导入」), the service
// groups and the rule tester.
//
// The request body carries the operator's config. It is parsed in memory
// (internal/mihomo keeps only rules, rule-providers and proxy-groups);
// the body itself is never stored, logged or returned, and neither is
// anything of the other sections. Preview and confirm are stateless: the
// client sends the same body to both; confirm recomputes the preview and
// writes only when its digest equals the one the operator saw and nothing
// blocks.

type importBody struct {
	Config    string              `json:"config"`
	Selection string              `json:"selection,omitempty"`
	Picks     map[string]string   `json:"picks,omitempty"`
	Mapping   map[string]string   `json:"mapping,omitempty"`
	Drop      []int               `json:"drop,omitempty"`
	Accept    map[string][]string `json:"accept,omitempty"`
	// DisableBuiltin turns off the built-in default rows on confirm.
	DisableBuiltin bool `json:"disable_builtin"`
	ResetServices  bool `json:"reset_services,omitempty"`
	AtStart        bool `json:"at_start,omitempty"`
	// FetchRuleSets starts background downloads of providers the panel
	// has no content for (preview only).
	FetchRuleSets bool   `json:"fetch_rule_sets,omitempty"`
	Digest        string `json:"digest,omitempty"`
}

func (s *Server) registerRulesImport(mux *http.ServeMux) {
	mux.HandleFunc("POST /api/rules/import/preview", s.postImportPreview)
	mux.HandleFunc("POST /api/rules/import/confirm", s.postImportConfirm)
	mux.HandleFunc("GET /api/service-groups", s.listServiceGroups)
	mux.HandleFunc("POST /api/service-groups", s.createServiceGroup)
	mux.HandleFunc("PATCH /api/service-groups/{id}", s.patchServiceGroup)
	mux.HandleFunc("DELETE /api/service-groups/{id}", s.deleteServiceGroup)
	mux.HandleFunc("POST /api/rules/test", s.postRuleTest)
	mux.HandleFunc("GET /api/rules/analysis", s.getRuleAnalysis)
}

func decodeImport(w http.ResponseWriter, r *http.Request) (importBody, error) {
	var b importBody
	raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, mihomo.MaxConfigBytes+(1<<20)))
	if err != nil {
		return b, errors.New("请求过大或读取失败")
	}
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&b); err != nil {
		// Never echo the decoder's message: it can quote the body.
		return b, errors.New("请求格式错误")
	}
	return b, nil
}

func (b importBody) options() (mihomo.Options, error) {
	o := mihomo.Options{UIPicks: b.Picks, Mapping: b.Mapping, Drop: map[int]bool{}, Accept: map[int][]string{},
		DisableBuiltin: b.DisableBuiltin, ResetServices: b.ResetServices, AtStart: b.AtStart}
	sel, err := mihomo.Selection([]byte(b.Selection))
	if err != nil {
		return o, err
	}
	o.Selection = sel
	for _, l := range b.Drop {
		o.Drop[l] = true
	}
	for k, v := range b.Accept {
		n, err := strconv.Atoi(k)
		if err != nil {
			return o, errors.New("accept 的键必须是行号")
		}
		o.Accept[n] = v
	}
	return o, nil
}

// providerContent: what the panel has for a provider: the active content
// of an existing rule-set with the same name or URL, else a prefetch.
func (s *Server) providerContent(t model.Topology, fetch bool) func(mihomo.Provider) mihomo.Content {
	st := s.loadRSStatus()
	policy := lists.Effective(t.Settings.ListSource)
	return func(p mihomo.Provider) mihomo.Content {
		for _, rs := range t.RuleSets {
			if rs.Name == p.Name || rs.URL == p.URL {
				if es, ok := s.activeEntries(rs.ID); ok {
					x := st[rs.ID]
					c := mihomo.Content{State: "available", Entries: es}
					if x != nil {
						c.Format, c.Counts, c.Unsupported = x.Format, x.Counts, x.Unsupported
					}
					return c
				}
			}
		}
		rs := s.rs()
		rs.mu.Lock()
		pf, ok := rs.prefetch[p.URL]
		if !ok && fetch {
			rs.prefetch[p.URL] = prefetched{state: "pending", at: time.Now()}
			go s.prefetch(p, policy)
			pf = prefetched{state: "pending"}
			ok = true
		}
		rs.mu.Unlock()
		if !ok {
			return mihomo.Content{State: "missing"}
		}
		if pf.state != "available" {
			return mihomo.Content{State: pf.state, Error: pf.err}
		}
		es, _ := ordered.UnmarshalEntries(pf.content)
		return mihomo.Content{State: "available", Entries: es, Format: pf.parsed.Format, Counts: pf.parsed.Counts, Unsupported: pf.parsed.Unsupported}
	}
}

func (s *Server) prefetch(p mihomo.Provider, policy lists.Policy) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	format := ""
	if strings.EqualFold(p.Format, "text") {
		format = map[string]string{"classical": ruleset.FormatClashTextClassic, "domain": ruleset.FormatClashTextDomain, "ipcidr": ruleset.FormatClashTextIPCIDR}[strings.ToLower(p.Behavior)]
	}
	mode := ruleset.SourceURL
	if _, _, _, _, ok := ruleset.GitHubRaw(p.URL); ok {
		mode = ruleset.SourcePolicy
	}
	parsed, content, _, errs := s.fetchCandidates(ctx, p.URL, mode, format, p.Behavior, false, policy)
	pf := prefetched{state: "available", parsed: parsed, content: content, at: time.Now()}
	if content == nil {
		pf = prefetched{state: "failed", err: strings.Join(errs, "；"), at: time.Now()}
	}
	s.rs().mu.Lock()
	s.rs().prefetch[p.URL] = pf
	s.rs().mu.Unlock()
}

func (s *Server) buildImport(w http.ResponseWriter, b importBody, fetch bool) (model.Topology, *mihomo.Preview, *mihomo.Plan, bool) {
	t, err := s.topology()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return t, nil, nil, false
	}
	cfg, err := mihomo.Parse(b.Config)
	if err != nil {
		writeJSON(w, http.StatusUnprocessableEntity, map[string]any{"error": err.Error(), "code": "bad_config"})
		return t, nil, nil, false
	}
	o, err := b.options()
	if err != nil {
		writeJSON(w, http.StatusUnprocessableEntity, map[string]any{"error": err.Error(), "code": "bad_selection"})
		return t, nil, nil, false
	}
	p, plan := mihomo.Build(t, cfg, o, s.providerContent(t, fetch))
	// The written result must validate like any rule the panel saves.
	next := t
	next.Rules = append([]model.Rule(nil), t.Rules...)
	mihomo.Apply(&next, plan, b.AtStart, "")
	issues := map[string][]validate.Issue{}
	for _, is := range validateIssues(next) {
		if is.RuleID != "" {
			issues[is.RuleID] = append(issues[is.RuleID], is)
		} else if is.Severity == validate.SeverityError && (is.Field == "service_groups" || is.Code == "bad_rule_set") {
			p.Notes = append(p.Notes, "校验："+is.Message)
			p.Blocking++
			p.CanConfirm = false
		}
	}
	for i := range p.Rows {
		row := &p.Rows[i]
		for _, is := range issues[row.RuleID] {
			sev := mihomo.SevInfo
			if is.Severity == validate.SeverityError {
				sev = mihomo.SevBlock
				if row.Status != "blocked" && row.Status != "dropped" {
					row.Status = "blocked"
					p.Blocking++
				}
			}
			row.Flags = append(row.Flags, mihomo.Flag{Code: is.Code, Severity: sev, Class: "validation", Message: is.Message})
		}
	}
	if p.Blocking > 0 {
		p.CanConfirm = false
	}
	return t, p, plan, true
}

// validateIssues are the validation errors and the rule warnings.
func validateIssues(t model.Topology) []validate.Issue {
	var out []validate.Issue
	for _, is := range validate.Run(t).Issues {
		if is.Severity == validate.SeverityError || is.RuleID != "" {
			out = append(out, is)
		}
	}
	return out
}

func (s *Server) postImportPreview(w http.ResponseWriter, r *http.Request) {
	b, err := decodeImport(w, r)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
		return
	}
	_, p, _, ok := s.buildImport(w, b, b.FetchRuleSets)
	if !ok {
		return
	}
	writeJSON(w, http.StatusOK, p)
}

func (s *Server) postImportConfirm(w http.ResponseWriter, r *http.Request) {
	b, err := decodeImport(w, r)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
		return
	}
	s.raMu.Lock()
	defer s.raMu.Unlock()
	_, p, plan, ok := s.buildImport(w, b, false)
	if !ok {
		return
	}
	if !p.CanConfirm {
		writeJSON(w, http.StatusUnprocessableEntity, map[string]any{"error": "预览里还有阻止确认的条目", "code": "blocked", "preview": p})
		return
	}
	if b.Digest == "" || b.Digest != p.Digest {
		writeJSON(w, http.StatusConflict, map[string]any{"error": "预览已经变化（配置、映射、规则集内容或面板规则变了），请重新预览后再确认", "code": "stale_preview", "preview": p})
		return
	}
	now := time.Now().UTC().Format(time.RFC3339)
	if _, err := s.topology(); err != nil { // seeds the store on first use
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	_, err = s.Store.Update(func(t *model.Topology) (bool, error) {
		mihomo.Apply(t, plan, b.AtStart, now)
		return true, nil
	})
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	for id, c := range plan.ActivateSets {
		if es, ok := s.activeEntries(id); ok && string(ordered.MarshalEntries(es)) == string(ordered.MarshalEntries(c.Entries)) {
			continue
		}
		_ = s.activateContent(id, ordered.MarshalEntries(c.Entries), c.Format, c.Counts, c.Unsupported, nil, "", "")
	}
	writeJSON(w, http.StatusOK, map[string]any{"imported": plan.ImportedCount, "services": len(plan.Services), "rule_sets": len(plan.RuleSets), "default_group": plan.DefaultGroup, "digest": p.Digest})
}

// ---------------------------------------------------------- services ---

func serviceUsers(t model.Topology, id string) []map[string]any {
	var out []map[string]any
	for i, r := range t.EvalOrder() {
		if r.TargetService == id {
			out = append(out, map[string]any{"rule_id": r.ID, "name": r.Name, "position": i + 1})
		}
	}
	return out
}

func (s *Server) listServiceGroups(w http.ResponseWriter, r *http.Request) {
	t, err := s.topology()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	out := []map[string]any{}
	for _, sg := range t.ServiceGroups {
		u := serviceUsers(t, sg.ID)
		if u == nil {
			u = []map[string]any{}
		}
		out = append(out, map[string]any{"service_group": sg, "used_by": u})
	}
	writeJSON(w, http.StatusOK, map[string]any{"service_groups": out})
}

type serviceBody struct {
	Name   *string `json:"name"`
	Target *string `json:"target"` // group:<id>, exit:<id>, direct, reject
}

func setServiceTarget(sg *model.ServiceGroup, spec string) error {
	sg.TargetGroup, sg.TargetExit, sg.TargetAction = "", "", ""
	switch {
	case spec == model.ActionDirect || spec == model.ActionReject:
		sg.TargetAction = spec
	case strings.HasPrefix(spec, "group:"):
		sg.TargetGroup = strings.TrimPrefix(spec, "group:")
	case strings.HasPrefix(spec, "exit:"):
		sg.TargetExit = strings.TrimPrefix(spec, "exit:")
	default:
		return errors.New("target 只能是 group:<id>、exit:<id>、direct 或 reject")
	}
	return nil
}

func (s *Server) createServiceGroup(w http.ResponseWriter, r *http.Request) {
	var b serviceBody
	if err := decodeBody(w, r, &b); err != nil || b.Name == nil || b.Target == nil || strings.TrimSpace(*b.Name) == "" {
		writeErr(w, http.StatusBadRequest, errors.New("需要 name 和 target"))
		return
	}
	sg := model.ServiceGroup{ID: "svc-" + randHex(5), Name: strings.TrimSpace(*b.Name)}
	if err := setServiceTarget(&sg, *b.Target); err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	_, issues, err := s.saveTopologyChecked(func(t *model.Topology) error {
		t.ServiceGroups = append(t.ServiceGroups, sg)
		return nil
	})
	if s.writeSaveErr(w, issues, err) {
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"service_group": sg})
}

// patchServiceGroup re-targets a service group (every rule using it
// follows at the next install). The MATCH group also moves the default
// group. Residential / IPv6 assertions of the rules using it are checked:
// a change that adds a validation error is refused.
func (s *Server) patchServiceGroup(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var b serviceBody
	if err := decodeBody(w, r, &b); err != nil {
		writeErr(w, http.StatusBadRequest, errors.New("请求格式错误"))
		return
	}
	var out model.ServiceGroup
	_, issues, err := s.saveTopologyChecked(func(t *model.Topology) error {
		for i := range t.ServiceGroups {
			sg := &t.ServiceGroups[i]
			if sg.ID != id {
				continue
			}
			if b.Name != nil && strings.TrimSpace(*b.Name) != "" {
				sg.Name = strings.TrimSpace(*b.Name)
			}
			if b.Target != nil {
				if err := setServiceTarget(sg, *b.Target); err != nil {
					return errors.New("409:" + err.Error())
				}
				if sg.Default {
					if sg.TargetGroup == "" {
						return errors.New("409:兜底（MATCH）服务组只能指向地区组")
					}
					t.Settings.DefaultGroup = sg.TargetGroup
				}
			}
			out = *sg
			return nil
		}
		return errors.New("404:服务组不存在")
	})
	if s.writeSaveErr(w, issues, err) {
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"service_group": out})
}

func (s *Server) deleteServiceGroup(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	t, err := s.topology()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	if u := serviceUsers(t, id); len(u) > 0 {
		writeJSON(w, http.StatusConflict, map[string]any{"error": "还有规则指向这个服务组", "code": "in_use", "used_by": u})
		return
	}
	_, issues, err := s.saveTopologyChecked(func(t *model.Topology) error {
		for i := range t.ServiceGroups {
			if t.ServiceGroups[i].ID == id {
				if t.ServiceGroups[i].Default {
					return errors.New("409:兜底（MATCH）服务组不能删除")
				}
				t.ServiceGroups = append(t.ServiceGroups[:i], t.ServiceGroups[i+1:]...)
				return nil
			}
		}
		return errors.New("404:服务组不存在")
	})
	if s.writeSaveErr(w, issues, err) {
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"deleted": id})
}

// ------------------------------------------------------------ tester ---

// refList is the panel's list for the reference interpreter: enabled rules
// in order with their current content (rule-sets from the active files,
// geosite and keyword lists from the gateway's published files when this
// panel can read them).
func (s *Server) refList(t model.Topology) ([]model.Rule, []ordered.Rule, []string, int) {
	var rules []model.Rule
	var refs []ordered.Rule
	var notes []string
	quicAt := -1
	rd := lists.FileReader(s.listsDir())
	content := map[string][]ordered.Entry{}
	for _, r := range t.EvalOrder() {
		if r.Enabled && r.MatchType == model.MatchQUICReject && quicAt < 0 {
			quicAt = len(refs)
		}
		if !r.Enabled || r.MatchType == model.MatchQUICReject {
			continue
		}
		if r.MatchType == model.MatchRuleSet {
			if es, ok := s.activeEntries(r.RuleSet); ok {
				content[r.RuleSet] = es
			} else {
				notes = append(notes, "规则「"+r.Name+"」的规则集还没有内容（什么都不匹配）")
			}
		}
		es := mihomo.Entries(r, content)
		switch r.MatchType {
		case model.MatchGeosite:
			if names, err := rd.Geosite(lists.FileName(r.Geosite)); err == nil {
				for _, n := range names {
					es = append(es, ordered.Entry{Kind: ordered.Suffix, Value: n})
				}
			} else {
				notes = append(notes, "读不到 geosite "+r.Geosite+" 名单，只用了显式域名")
			}
		case model.MatchKeyword:
			notes = append(notes, "关键词规则「"+r.Name+"」在网关上只匹配名单里含这个词的名字；这里按子串判断（mihomo 的语义）")
		}
		tg := t.ResolveTarget(r)
		rules = append(rules, r)
		ref := ordered.Rule{ID: r.ID, Entries: es, Target: tg.Kind + ":" + tg.ID, GeoIPCN: r.MatchType == model.MatchGeoIP && strings.EqualFold(r.MatchValue, "cn")}
		if tg.Kind == model.ActionDirect || tg.Kind == model.ActionReject {
			ref.Action = tg.Kind
		}
		for _, a := range []string{r.SourceIPv4, r.SourceIPv6} {
			if p, err := netip.ParsePrefix(a); err == nil {
				ref.Sources = append(ref.Sources, p)
			} else if ad, err := netip.ParseAddr(a); err == nil {
				ref.Sources = append(ref.Sources, netip.PrefixFrom(ad, ad.BitLen()))
			}
		}
		refs = append(refs, ref)
	}
	return rules, refs, notes, quicAt
}

func (s *Server) listsDir() string {
	if s.ListsDir != "" {
		return s.ListsDir
	}
	return hostexec.DefaultListsDir
}

func (s *Server) postRuleTest(w http.ResponseWriter, r *http.Request) {
	var b struct {
		Name    string `json:"name"`
		Address string `json:"address"`
		Proto   string `json:"proto"`
		Port    int    `json:"port"`
		Source  string `json:"source"`
	}
	if err := decodeBody(w, r, &b); err != nil {
		writeErr(w, http.StatusBadRequest, errors.New("请求格式错误"))
		return
	}
	q := ordered.Query{}
	if b.Name != "" {
		n, ok := ordered.NormDomain(b.Name)
		if !ok {
			writeErr(w, http.StatusUnprocessableEntity, errors.New("域名不合法"))
			return
		}
		q.Name = n
	}
	if b.Address != "" {
		a, err := netip.ParseAddr(strings.TrimSpace(b.Address))
		if err != nil {
			writeErr(w, http.StatusUnprocessableEntity, errors.New("地址不合法"))
			return
		}
		q.Addr = a
	}
	if q.Name == "" && !q.Addr.IsValid() {
		writeErr(w, http.StatusUnprocessableEntity, errors.New("需要域名或地址"))
		return
	}
	t, err := s.topology()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	rules, refs, notes, quicAt := s.refList(t)
	var china []netip.Prefix
	for _, f := range []string{"china.txt", "china6.txt"} {
		if b, err := os.ReadFile(filepath.Join(s.listsDir(), "lists", f)); err == nil {
			if ps, err := lists.ParsePrefixes(f == "china.txt", b, 1); err == nil {
				china = append(china, ps...)
			}
		}
	}
	var dom []string
	if names, err := lists.FileReader(s.listsDir()).Geosite("cn"); err == nil {
		dom = names
	} else {
		notes = append(notes, "读不到内置国内名单（geosite cn）")
	}
	tail := ordered.Tail{Domestic: dom, China: china, DirectTarget: "direct:", Default: "group:" + t.Settings.DefaultGroup}
	// Exactly the decision function a name-deciding process uses.
	req := ordered.Request{Name: q.Name, Addr: q.Addr, Proto: b.Proto, Port: b.Port}
	if b.Source != "" {
		req.Source, _ = netip.ParseAddr(strings.TrimSpace(b.Source))
	}
	m := ordered.Compile(refs, tail, quicAt).Decide(req)
	out := map[string]any{"reason": m.Reason, "target": m.Target, "notes": notes, "quic_rejected": m.QUICRejected}
	if m.Index >= 0 {
		r := rules[m.Index]
		pos := 0
		for i, x := range t.EvalOrder() {
			if x.ID == r.ID {
				pos = i + 1
			}
		}
		out["rule"] = map[string]any{"id": r.ID, "name": r.Name, "position": pos, "origin": r.Origin, "source_line": r.SourceLine}
	}
	if q.Name != "" && !q.Addr.IsValid() {
		out["note_address"] = "只给了域名：没有判断地址规则（IP-CIDR、GEOIP）"
	}
	writeJSON(w, http.StatusOK, out)
}

// getRuleAnalysis is the static ordering analysis of the panel's list:
// per rule, how much earlier rules shadow, keyword and rule-set notes.
func (s *Server) getRuleAnalysis(w http.ResponseWriter, r *http.Request) {
	t, err := s.topology()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	rules, refs, notes, _ := s.refList(t)
	an := ordered.Analyze(refs)
	st := s.loadRSStatus()
	out := []map[string]any{}
	for i, a := range an {
		r := rules[i]
		var by, part []string
		for _, j := range a.ShadowedBy {
			by = append(by, rules[j].ID)
		}
		for _, j := range a.PartlyBy {
			part = append(part, rules[j].ID)
		}
		row := map[string]any{"rule_id": r.ID, "entries": a.Entries, "shadowed": a.Shadowed, "fully_shadowed": a.FullyShadowed, "shadowed_by": by, "partly_by": part, "keywords": a.Keywords}
		if r.MatchType == model.MatchRuleSet {
			if x := st[r.RuleSet]; x != nil {
				row["rule_set"] = map[string]any{"state": x.State, "counts": x.Counts, "unsupported": x.Unsupported, "held": x.Held != nil}
			}
		}
		if r.MatchType == model.MatchKeyword {
			row["keyword_note"] = "网关上只匹配已下载名单里含这个词的域名（SmartDNS 不能按子串匹配）"
		}
		out = append(out, row)
	}
	writeJSON(w, http.StatusOK, map[string]any{"rules": out, "notes": notes,
		"shared_address": "网关按解析出的目的地址分流：两个指向不同目标的名字解析到同一个地址时，该地址按列表里更靠前的规则走。"})
}
