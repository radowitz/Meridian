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
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/radowitz/meridian/internal/compile"
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
	Config string `json:"config"`
	// Selection is mihomo's GET /proxies output: as a JSON string (the
	// pasted text) or as the JSON object itself.
	Selection json.RawMessage     `json:"selection,omitempty"`
	Picks     map[string]string   `json:"picks,omitempty"`
	Mapping   map[string]string   `json:"mapping,omitempty"`
	Drop      []int               `json:"drop,omitempty"`
	Accept    map[string][]string `json:"accept,omitempty"`
	// AcceptCodes accepts every row's flag of these codes (one of
	// mihomo.AcceptCodes); the rows still show individually.
	AcceptCodes []string `json:"accept_codes,omitempty"`
	// DisableBuiltin turns off the built-in default rows on confirm.
	DisableBuiltin bool `json:"disable_builtin"`
	AtStart        bool `json:"at_start,omitempty"`
	// FetchRuleSets starts background downloads of providers the panel
	// has no content for (preview only).
	FetchRuleSets bool   `json:"fetch_rule_sets,omitempty"`
	Digest        string `json:"digest,omitempty"`
}

func (s *Server) registerRulesImport(mux *http.ServeMux) {
	mux.HandleFunc("POST /api/rules/import/preview", s.postImportPreview)
	mux.HandleFunc("POST /api/rules/import/confirm", s.postImportConfirm)
	// Service groups were removed: rules point at region groups directly.
	mux.HandleFunc("/api/service-groups", serviceGroupsGone)
	mux.HandleFunc("/api/service-groups/{id}", serviceGroupsGone)
	mux.HandleFunc("POST /api/rules/retarget", s.postRulesRetarget)
	mux.HandleFunc("POST /api/rules/test", s.postRuleTest)
	mux.HandleFunc("GET /api/rules/auto-apply", s.getRulesAutoApply)
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
		// Never echo the decoder's message: it can quote the body. Say
		// which field when the decoder knows it.
		var te *json.UnmarshalTypeError
		if errors.As(err, &te) && te.Field != "" {
			return b, errors.New("请求格式错误：字段 " + te.Field + " 的类型不对（config 是字符串；selection 是字符串或对象；mapping 是 名字→目标 的对象；drop 是行号数组；accept 是 行号→代码数组；accept_codes 是代码数组）")
		}
		return b, errors.New("请求格式错误：需要 JSON 对象 {\"config\": \"<YAML>\", …}")
	}
	return b, nil
}

// selectionBytes is the selection as GET /proxies JSON: a JSON string's
// content, or the object itself.
func (b importBody) selectionBytes() ([]byte, error) {
	raw := strings.TrimSpace(string(b.Selection))
	switch {
	case raw == "" || raw == "null":
		return nil, nil
	case strings.HasPrefix(raw, "\""):
		var s string
		if err := json.Unmarshal([]byte(raw), &s); err != nil {
			return nil, errors.New("selection 不是合法的 JSON 字符串")
		}
		return []byte(s), nil
	case strings.HasPrefix(raw, "{"):
		return []byte(raw), nil
	}
	return nil, errors.New("selection 必须是 GET /proxies 的输出：JSON 对象，或装着它的字符串")
}

func (b importBody) options() (mihomo.Options, error) {
	o := mihomo.Options{UIPicks: b.Picks, Mapping: b.Mapping, Drop: map[int]bool{}, Accept: map[int][]string{},
		AcceptCodes: map[string]bool{}, DisableBuiltin: b.DisableBuiltin, AtStart: b.AtStart}
	raw, err := b.selectionBytes()
	if err != nil {
		return o, err
	}
	sel, err := mihomo.Selection(raw)
	if err != nil {
		return o, err
	}
	for _, c := range b.AcceptCodes {
		if !slices.Contains(mihomo.AcceptCodes, c) {
			return o, errors.New("accept_codes 里的 " + strconv.Quote(c) + " 不是可接受的代码（" + strings.Join(mihomo.AcceptCodes, "、") + "）")
		}
		o.AcceptCodes[c] = true
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
			go s.prefetch(t, p, policy)
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

func (s *Server) prefetch(t model.Topology, p mihomo.Provider, policy lists.Policy) {
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
	o := RuleSetFetchOptions{Deny: gatewayDeny(t)}
	if p.Auth != nil {
		o.Auth, o.AuthOrigin = p.Auth, ruleset.Origin(p.URL)
	}
	parsed, content, _, errs := s.fetchCandidates(ctx, p.URL, mode, format, p.Behavior, o, policy)
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
		code := "bad_selection"
		if strings.Contains(err.Error(), "accept") {
			code = "bad_accept"
		}
		writeJSON(w, http.StatusUnprocessableEntity, map[string]any{"error": err.Error(), "code": code})
		return t, nil, nil, false
	}
	// The forwarder covers keyword matching on sniffed TCP; the preview
	// relaxes only that (mihomo.NameCoveredCodes).
	o.NameAware = t.SniffOn()
	o.KeywordState = s.keywordState(context.Background(), t)
	p, plan := mihomo.Build(t, cfg, o, s.providerContent(t, fetch))
	// The written result must validate like any rule the panel saves.
	next := t
	next.Rules = append([]model.Rule(nil), t.Rules...)
	mihomo.Apply(&next, plan, b.AtStart, "")
	issues := map[string][]validate.Issue{}
	for _, is := range validateIssues(next) {
		if is.RuleID != "" {
			issues[is.RuleID] = append(issues[is.RuleID], is)
		} else if is.Severity == validate.SeverityError && is.Code == "bad_rule_set" {
			p.Notes = append(p.Notes, "校验："+is.Message)
			p.Blocking++
			p.CanConfirm = false
		}
	}
	for i := range p.Rows {
		row := &p.Rows[i]
		// A row whose target is not mapped yet already blocks; the
		// validation finding (the service group points nowhere) is its
		// consequence, shown once the mapping is complete.
		if slices.ContainsFunc(row.Flags, func(f mihomo.Flag) bool { return f.Class == mihomo.ClassMapping }) {
			continue
		}
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
	locked := true
	defer func() {
		if locked {
			s.raMu.Unlock()
		}
	}()
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
	var before ruleParts
	_, err = s.Store.Update(func(t *model.Topology) (bool, error) {
		before = rulePartsOf(*t)
		mihomo.Apply(t, plan, b.AtStart, now)
		return true, nil
	})
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	// Credentials split off provider URLs go to the credential store
	// (never the topology).
	var authErr []string
	for id, a := range plan.Auth {
		if err := s.storeRuleSetAuth(id, a); err != nil {
			authErr = append(authErr, id)
		}
	}
	for id, c := range plan.ActivateSets {
		if es, ok := s.activeEntries(id); ok && string(ordered.MarshalEntries(es)) == string(ordered.MarshalEntries(c.Entries)) {
			continue
		}
		_ = s.activateContent(id, ordered.MarshalEntries(c.Entries), c.Format, c.Counts, c.Unsupported, nil, "", "")
	}
	out := map[string]any{"imported": plan.ImportedCount, "rule_sets": len(plan.RuleSets), "default_group": plan.DefaultGroup, "digest": p.Digest}
	if len(authErr) > 0 {
		sort.Strings(authErr)
		out["auth_not_stored"] = authErr
		out["warning"] = "这些规则集的订阅认证没有存进凭据存储，请在规则集上重新设置：" + strings.Join(authErr, "、")
	}
	// The install's secret bookkeeping takes raMu.
	s.raMu.Unlock()
	locked = false
	writeJSON(w, http.StatusOK, withRulesAuto(out, s.rulesAutoAfterSave(before, "import")))
}

// ------------------------------------------------------- retarget ---

func serviceGroupsGone(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusGone, map[string]any{"error": "服务组已移除：规则直接指向地区组；按 mihomo 策略组批量改请用 POST /api/rules/retarget", "code": "service_groups_removed"})
}

type retargetBody struct {
	// MihomoGroup selects every rule carrying this policy-group label.
	MihomoGroup string `json:"mihomo_group"`
	// Target: group:<id>, exit:<id>, direct, reject.
	Target string `json:"target"`
}

// postRulesRetarget points every rule labelled with one mihomo policy
// group at a new target, and remembers the choice in the import mapping
// so a later import of the same config resolves the group the same way.
func (s *Server) postRulesRetarget(w http.ResponseWriter, r *http.Request) {
	var b retargetBody
	if err := decodeBody(w, r, &b); err != nil || strings.TrimSpace(b.MihomoGroup) == "" || b.Target == "" {
		writeErr(w, http.StatusBadRequest, errors.New("需要 mihomo_group 和 target"))
		return
	}
	var tgt model.Rule
	switch {
	case b.Target == model.ActionDirect || b.Target == model.ActionReject:
		tgt.TargetAction = b.Target
	case strings.HasPrefix(b.Target, "group:"):
		tgt.TargetGroup = strings.TrimPrefix(b.Target, "group:")
	case strings.HasPrefix(b.Target, "exit:"):
		tgt.TargetExit = strings.TrimPrefix(b.Target, "exit:")
	default:
		writeErr(w, http.StatusBadRequest, errors.New("target 只能是 group:<id>、exit:<id>、direct 或 reject"))
		return
	}
	n := 0
	_, before, issues, err := s.saveRulesChecked(func(t *model.Topology) error {
		for i := range t.Rules {
			ru := &t.Rules[i]
			if ru.MihomoGroup != b.MihomoGroup || ru.MatchType == model.MatchQUICReject {
				continue
			}
			ru.TargetGroup, ru.TargetExit, ru.TargetAction = tgt.TargetGroup, tgt.TargetExit, tgt.TargetAction
			n++
		}
		if n == 0 {
			return errors.New("404:没有规则来自这个策略组")
		}
		if t.MihomoImport == nil {
			t.MihomoImport = &model.MihomoImport{}
		}
		if t.MihomoImport.Mapping == nil {
			t.MihomoImport.Mapping = map[string]string{}
		}
		t.MihomoImport.Mapping[b.MihomoGroup] = b.Target
		return nil
	})
	if s.writeSaveErr(w, issues, err) {
		return
	}
	writeJSON(w, http.StatusOK, withRulesAuto(map[string]any{"updated": n}, s.rulesAutoAfterSave(before, "rules")))
}

// ------------------------------------------------------------ tester ---

// refList is the panel's list for the reference interpreter: enabled rules
// in order with their current content (rule-sets from the active files,
// geosite and keyword lists from the gateway's published files when this
// panel can read them).
func (s *Server) refList(t model.Topology, kwState string) ([]model.Rule, []ordered.Rule, []string, int) {
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
				// The effective entries, by the derivation the gateway uses.
				content[r.RuleSet] = ordered.ApplyExclusions(es, compile.RuleSetExclusions(t, r.RuleSet)).Entries
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
			notes = append(notes, "关键词规则「"+r.Name+"」："+ordered.KeywordNote(kwState)+"；这里按子串判断（mihomo 的语义）")
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
		// A device rule by MAC matches only that device, as on the gateway
		// ("ether saddr"; the forwarder's neighbour lookup). Without this the
		// tester treated it as a rule for every client.
		if r.SourceMAC != "" {
			mac, ok := ordered.NormMAC(r.SourceMAC)
			if !ok {
				mac = "invalid:" + r.SourceMAC // never matches
			}
			ref.SourceMAC = mac
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
		// SourceMAC is the client's MAC (device rules by MAC).
		SourceMAC string `json:"source_mac"`
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
	rules, refs, notes, quicAt := s.refList(t, s.keywordState(r.Context(), t))
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
	if b.SourceMAC != "" {
		mac, ok := ordered.NormMAC(b.SourceMAC)
		if !ok {
			writeErr(w, http.StatusUnprocessableEntity, errors.New("MAC 地址不合法"))
			return
		}
		req.SourceMAC = mac
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
	kwState := s.keywordState(r.Context(), t)
	rules, refs, notes, _ := s.refList(t, kwState)
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
		if a.LegacyLost > 0 {
			var to []string
			for _, j := range a.LegacyLostTo {
				to = append(to, rules[j].ID)
			}
			// The migration difference: before the upgrade the resolver
			// gave these names to this rule (longer name wins); now the
			// earlier rule takes them.
			row["legacy_lost"], row["legacy_lost_to"] = a.LegacyLost, to
		}
		if r.MatchType == model.MatchRuleSet {
			if x := st[r.RuleSet]; x != nil {
				row["rule_set"] = map[string]any{"state": x.State, "counts": x.Counts, "unsupported": x.Unsupported, "held": x.Held != nil}
			}
		}
		if a.Keywords > 0 && r.MatchType != model.MatchKeyword {
			row["keywords_note"] = ordered.KeywordEntriesNote(a.Keywords, kwState)
		}
		if r.MatchType == model.MatchKeyword {
			row["keyword_note"] = ordered.KeywordNote(kwState)
		}
		out = append(out, row)
	}
	writeJSON(w, http.StatusOK, map[string]any{"rules": out, "notes": notes, "keyword_state": kwState, "keyword_note": ordered.KeywordNote(kwState),
		"shared_address": "网关按解析出的目的地址分流：两个指向不同目标的名字解析到同一个地址时，该地址按列表里更靠前的规则走。",
		"upgrade_notes":  upgradeNotes})
}

// upgradeNotes: how name resolution changed with the ordered list (shown
// where the operator orders the rules; docs/architecture.md「升级后的 DNS
// 行为变化」).
var upgradeNotes = []string{
	"升级后，苹果和各系统的联网检测域名不再内置直连：没有规则指向直连时，它们和其它境外域名一样由默认组（或命中规则的目标）的解析器解析并走隧道。需要直连就启用「Apple 直连」模板或加一条直连规则。",
	"升级后，靠前的规则优先于更长的后缀：以前解析器按“最长的名字”在规则之间选，现在按列表顺序第一条命中。结果因此改变的规则在「遮蔽」列标为“升级后变化”。",
	"「未列名单的域名也问国内 DNS」默认关闭，规则和国内名单都不依赖它。",
}
