package mihomo

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/netip"
	"regexp"
	"sort"
	"strings"

	"github.com/radowitz/meridian/internal/model"
	"github.com/radowitz/meridian/internal/ordered"
	"github.com/radowitz/meridian/internal/ruleset"
)

// Flag severities. A "block" flag can only be resolved by dropping the row
// (or fixing the mapping); an "accept" flag also allows confirming once the
// operator accepted the stated alternative for that row; "info" is shown.
const (
	SevBlock  = "block"
	SevAccept = "accept"
	SevInfo   = "info"
)

// Flag is one finding on a row.
type Flag struct {
	Code     string `json:"code"`
	Severity string `json:"severity"`
	// Class is the machine-readable reason (FlagClass): whether the row is
	// inexact only because the data plane classifies by address, or
	// unsupported in any mode, etc.
	Class   string   `json:"class"`
	Message string   `json:"message"`
	By      []string `json:"by,omitempty"`
}

// Flag classes.
const (
	// ClassAddress: inexact only because classification is by destination
	// address learned from DNS (keyword entries the resolver cannot match,
	// the QUIC switch's per-rule exemption, shared addresses). A decision
	// by name (Options.NameAware) does not need the alternative.
	ClassAddress = "address_only"
	// ClassUnsupported: cannot be executed in any mode (process, user
	// agent, URL regex, port, unknown logical rules, GEOIP without data).
	ClassUnsupported = "unsupported"
	// ClassData: content not available yet (a rule-set not downloaded).
	ClassData = "data"
	// ClassMapping: the target is not mapped to the panel.
	ClassMapping = "mapping"
	ClassInfo    = "info"
)

// FlagClass classifies a flag code.
func FlagClass(code string) string {
	switch code {
	case "keyword_expanded", "ruleset_keywords", "quic_semantics", "quic_direct_below":
		return ClassAddress
	case "unsupported_type", "ruleset_partial", "ruleset_unsupported", "geoip_country", "policy_unsupported", "bad_value", "unparsable", "ruleset_missing":
		return ClassUnsupported
	case "ruleset_unavailable":
		return ClassData
	case "target_unmapped", "match_not_group":
		return ClassMapping
	}
	return ClassInfo
}

// TargetView is where a row goes.
type TargetView struct {
	// Kind: service, group, exit, direct, reject ("" unmapped).
	Kind string `json:"kind"`
	ID   string `json:"id,omitempty"`
	Name string `json:"name,omitempty"`
	// Resolved is the service group's own target spec ("group:hk" …).
	Resolved string `json:"resolved,omitempty"`
	// Chain is the mihomo resolution path (policy, its pick, …).
	Chain []string `json:"chain,omitempty"`
}

// Row is one rule of the imported list, in original order.
type Row struct {
	Line   int    `json:"line"`
	Text   string `json:"text"`
	Type   string `json:"type"`
	Value  string `json:"value,omitempty"`
	Policy string `json:"policy,omitempty"`
	// Action: rule (written as a rule), quic (the QUIC switch row), match
	// (the default), tail (GEOIP,CN,DIRECT right before MATCH: the
	// gateway's built-in China fallback), after_match (never reached in
	// mihomo, not written), unsupported.
	Action string      `json:"action"`
	Match  string      `json:"match,omitempty"`
	Target *TargetView `json:"target,omitempty"`
	Flags  []Flag      `json:"flags,omitempty"`
	// Status: ok, blocked (a block flag, or an accept flag not accepted),
	// accepted, dropped, info (not written: match/tail/after_match).
	Status string `json:"status"`
	// Diff against the currently imported rules: new, same, changed.
	Diff string `json:"diff,omitempty"`
	// Position in the panel's list after confirming (1-based; 0 none).
	Position int    `json:"position,omitempty"`
	RuleID   string `json:"rule_id,omitempty"`
}

// Removed is a currently imported rule the new import no longer has.
type Removed struct {
	RuleID string `json:"rule_id"`
	Line   int    `json:"line"`
	Text   string `json:"text"`
}

// MappingRow is one mihomo name that needs a panel target.
type MappingRow struct {
	Name        string       `json:"name"`
	Kind        string       `json:"kind"` // line, selector, proxy
	Mapped      string       `json:"mapped,omitempty"`
	Remembered  bool         `json:"remembered,omitempty"`
	Suggestions []Suggestion `json:"suggestions,omitempty"`
	UsedBy      []int        `json:"used_by,omitempty"`
}

// Suggestion is a proposed mapping target.
type Suggestion struct {
	Value string `json:"value"`
	Label string `json:"label"`
}

// ServiceView is one service group the import creates or updates.
type ServiceView struct {
	ID       string   `json:"id"`
	Name     string   `json:"name"`
	Chain    []string `json:"chain"`
	Target   string   `json:"target,omitempty"`
	Current  string   `json:"current,omitempty"`
	Keep     bool     `json:"keep_current,omitempty"`
	Default  bool     `json:"default,omitempty"`
	Pick     string   `json:"pick"`
	PickFrom string   `json:"pick_from"` // selection, ui, first_member
	UsedBy   []int    `json:"used_by,omitempty"`
	Existing bool     `json:"existing"`
}

// RuleSetView is one provider the rules use.
type RuleSetView struct {
	Name        string         `json:"name"`
	ID          string         `json:"id"`
	URL         string         `json:"url"`
	Behavior    string         `json:"behavior"`
	Existing    bool           `json:"existing"`
	State       string         `json:"state"` // available, pending, failed, missing, unsupported
	Error       string         `json:"error,omitempty"`
	Format      string         `json:"format,omitempty"`
	Counts      map[string]int `json:"counts,omitempty"`
	Unsupported map[string]int `json:"unsupported,omitempty"`
	UsedBy      []int          `json:"used_by,omitempty"`
}

// Content is what the panel has of a provider's rule-set right now.
type Content struct {
	State       string // available, pending, failed, missing
	Error       string
	Format      string
	Entries     []ordered.Entry
	Counts      map[string]int
	Unsupported map[string]int
}

// Options are the operator's choices.
type Options struct {
	// Selection: selector name -> current member (GET /proxies "now", or
	// the operator's picks in the UI, which win).
	Selection map[string]string
	UIPicks   map[string]string
	// Mapping: mihomo name -> "group:<id>", "exit:<id>", "direct", "reject".
	Mapping map[string]string
	Drop    map[int]bool
	Accept  map[int][]string
	// DisableBuiltin turns off the built-in default rows (not manual ones).
	DisableBuiltin bool
	// ResetServices sets existing service groups to the imported target
	// instead of keeping the panel's current one.
	ResetServices bool
	// AtStart puts the imported block before the panel's own rules
	// (default: after them).
	AtStart bool
	// NameAware: the gateway decides name-bearing connections by name
	// (a later forwarder); address-only flags then do not block. Always
	// false today.
	NameAware bool
}

// Preview is the whole result.
type Preview struct {
	Rows       []Row          `json:"rows"`
	Removed    []Removed      `json:"removed,omitempty"`
	Mapping    []MappingRow   `json:"mapping"`
	Services   []ServiceView  `json:"services"`
	RuleSets   []RuleSetView  `json:"rule_sets"`
	Default    *TargetView    `json:"default,omitempty"`
	QUIC       string         `json:"quic,omitempty"`
	Builtin    []string       `json:"builtin_disabled,omitempty"`
	Notes      []string       `json:"notes"`
	Blocking   int            `json:"blocking"`
	CanConfirm bool           `json:"can_confirm"`
	Digest     string         `json:"digest"`
	Summary    map[string]int `json:"summary"`
}

// Plan is what confirming writes.
type Plan struct {
	Rules         []model.Rule
	Services      []model.ServiceGroup
	RuleSets      []model.RuleSet
	DefaultGroup  string
	DisableRules  []string
	Mapping       map[string]string
	ActivateSets  map[string]Content // rule-set ID -> content to activate
	ImportedCount int
}

// Selection parses GET /proxies of mihomo's controller: only selector
// "now" values are kept.
func Selection(b []byte) (map[string]string, error) {
	if len(strings.TrimSpace(string(b))) == 0 {
		return nil, nil
	}
	var doc struct {
		Proxies map[string]struct {
			Type string `json:"type"`
			Now  string `json:"now"`
		} `json:"proxies"`
	}
	if err := json.Unmarshal(b, &doc); err != nil {
		return nil, fmt.Errorf("选中状态不是 mihomo GET /proxies 的 JSON：%v", err)
	}
	out := map[string]string{}
	for name, p := range doc.Proxies {
		if strings.EqualFold(p.Type, "Selector") && p.Now != "" {
			out[name] = p.Now
		}
	}
	return out, nil
}

func idFor(prefix, s string) string {
	h := sha256.Sum256([]byte(s))
	return prefix + hex.EncodeToString(h[:])[:10]
}

var regionPatterns = []struct {
	code string
	re   *regexp.Regexp
}{
	{"hk", regexp.MustCompile(`(?i)(\bhk\b|hong ?kong|香港|🇭🇰)`)},
	{"tw", regexp.MustCompile(`(?i)(\btw\b|taiwan|台湾|台灣|🇹🇼)`)},
	{"jp", regexp.MustCompile(`(?i)(\bjp\b|japan|日本|🇯🇵)`)},
	{"us", regexp.MustCompile(`(?i)(\bus\b|\busa\b|united states|america|美国|美國|🇺🇸)`)},
	{"sg", regexp.MustCompile(`(?i)(\bsg\b|singapore|新加坡|狮城|🇸🇬)`)},
}

var resiRe = regexp.MustCompile(`(?i)(resi|home|isp|家宽|家庭|住宅)`)

func suggest(t model.Topology, name string) []Suggestion {
	var out []Suggestion
	code := ""
	for _, p := range regionPatterns {
		if p.re.MatchString(name) {
			code = p.code
			break
		}
	}
	if code == "" {
		return nil
	}
	resi := resiRe.MatchString(name)
	var groups []model.RegionGroup
	for _, g := range t.Groups {
		if strings.EqualFold(g.Region, code) || strings.EqualFold(g.ID, code) {
			groups = append(groups, g)
		}
	}
	sort.SliceStable(groups, func(i, j int) bool {
		return groups[i].RequireResidential == resi && groups[j].RequireResidential != resi
	})
	for _, g := range groups {
		out = append(out, Suggestion{Value: "group:" + g.ID, Label: "地区组 " + g.Name})
	}
	for _, n := range t.Nodes {
		if n.Role == model.RoleExit && strings.EqualFold(n.Region, code) && (!resi || n.Residential) {
			out = append(out, Suggestion{Value: "exit:" + n.ID, Label: "出口 " + n.Name})
		}
	}
	return out
}

// specOK: a mapping value names an existing target.
func specOK(t model.Topology, spec string) bool {
	switch {
	case spec == model.ActionDirect || spec == model.ActionReject:
		return true
	case strings.HasPrefix(spec, "group:"):
		_, ok := t.GroupByID(strings.TrimPrefix(spec, "group:"))
		return ok
	case strings.HasPrefix(spec, "exit:"):
		n, ok := t.NodeByID(strings.TrimPrefix(spec, "exit:"))
		return ok && n.Role == model.RoleExit
	}
	return false
}

func specLabel(t model.Topology, spec string) string {
	switch {
	case spec == model.ActionDirect:
		return "直连"
	case spec == model.ActionReject:
		return "拒绝"
	case strings.HasPrefix(spec, "group:"):
		if g, ok := t.GroupByID(strings.TrimPrefix(spec, "group:")); ok {
			return "地区组 " + g.Name
		}
	case strings.HasPrefix(spec, "exit:"):
		if n, ok := t.NodeByID(strings.TrimPrefix(spec, "exit:")); ok {
			return "出口 " + n.Name
		}
	}
	return spec
}

func serviceSpec(s model.ServiceGroup) string {
	switch {
	case s.TargetAction != "":
		return s.TargetAction
	case s.TargetGroup != "":
		return "group:" + s.TargetGroup
	case s.TargetExit != "":
		return "exit:" + s.TargetExit
	}
	return ""
}

func setSpec(s *model.ServiceGroup, spec string) {
	s.TargetGroup, s.TargetExit, s.TargetAction = "", "", ""
	switch {
	case spec == model.ActionDirect || spec == model.ActionReject:
		s.TargetAction = spec
	case strings.HasPrefix(spec, "group:"):
		s.TargetGroup = strings.TrimPrefix(spec, "group:")
	case strings.HasPrefix(spec, "exit:"):
		s.TargetExit = strings.TrimPrefix(spec, "exit:")
	}
}

func ruleSpec(r *model.Rule, spec string) {
	r.TargetGroup, r.TargetExit, r.TargetAction, r.TargetService = "", "", "", ""
	switch {
	case spec == model.ActionDirect || spec == model.ActionReject:
		r.TargetAction = spec
	case strings.HasPrefix(spec, "group:"):
		r.TargetGroup = strings.TrimPrefix(spec, "group:")
	case strings.HasPrefix(spec, "exit:"):
		r.TargetExit = strings.TrimPrefix(spec, "exit:")
	case strings.HasPrefix(spec, "service:"):
		r.TargetService = strings.TrimPrefix(spec, "service:")
	}
}

type builder struct {
	t        model.Topology
	cfg      Config
	o        Options
	content  func(Provider) Content
	p        *Preview
	plan     *Plan
	mapRows  map[string]*MappingRow
	services map[string]*ServiceView
	sets     map[string]*RuleSetView
}

// policyKind: how a policy name resolves.
func (b *builder) policyKind(name string) string {
	switch strings.ToUpper(name) {
	case "DIRECT":
		return model.ActionDirect
	case "REJECT", "REJECT-DROP":
		return model.ActionReject
	case "PASS", "COMPATIBLE", "GLOBAL":
		return "unsupported"
	}
	if g, ok := b.cfg.Groups[name]; ok {
		if g.Type == "select" {
			return "selector"
		}
		return "line"
	}
	return "proxy"
}

// resolve follows name through mapping and selector picks to a panel
// target spec. ok false: unmapped (the name needing a mapping is need).
func (b *builder) resolve(name string, line int, depth int) (spec string, chain []string, need string) {
	chain = []string{name}
	if depth > 8 {
		return "", chain, name
	}
	if m := b.o.Mapping[name]; m != "" {
		if specOK(b.t, m) {
			return m, chain, ""
		}
	}
	switch b.policyKind(name) {
	case model.ActionDirect, model.ActionReject:
		return b.policyKind(name), chain, ""
	case "selector":
		pick, _ := b.pick(name)
		if pick == "" {
			return "", chain, name
		}
		s, c, need := b.resolve(pick, line, depth+1)
		return s, append(chain, c...), need
	}
	return "", chain, name
}

// pick is a selector's current member and where it came from.
func (b *builder) pick(name string) (string, string) {
	if v := b.o.UIPicks[name]; v != "" {
		return v, "ui"
	}
	if v := b.o.Selection[name]; v != "" {
		return v, "selection"
	}
	if g, ok := b.cfg.Groups[name]; ok && len(g.Proxies) > 0 {
		return g.Proxies[0], "first_member"
	}
	return "", "first_member"
}

func (b *builder) needMapping(name string, line int) {
	mr := b.mapRows[name]
	if mr == nil {
		kind := b.policyKind(name)
		if kind == "line" || kind == "selector" {
			// keep
		} else {
			kind = "proxy"
		}
		mr = &MappingRow{Name: name, Kind: kind, Suggestions: suggest(b.t, name)}
		if v := b.o.Mapping[name]; v != "" {
			mr.Mapped = v
		}
		b.mapRows[name] = mr
	}
	if len(mr.UsedBy) == 0 || mr.UsedBy[len(mr.UsedBy)-1] != line {
		mr.UsedBy = append(mr.UsedBy, line)
	}
}

// target maps a rule's policy: a selector becomes a service group.
func (b *builder) target(policy string, line int, row *Row) (spec string, ok bool) {
	kind := b.policyKind(policy)
	switch kind {
	case "unsupported":
		row.Flags = append(row.Flags, Flag{Code: "policy_unsupported", Severity: SevBlock, Message: "策略 " + policy + " 不支持"})
		return "", false
	case model.ActionDirect:
		row.Target = &TargetView{Kind: model.ActionDirect, Name: "直连"}
		if strings.EqualFold(policy, "DIRECT") {
			return model.ActionDirect, true
		}
	case model.ActionReject:
		row.Target = &TargetView{Kind: model.ActionReject, Name: "拒绝"}
		if strings.EqualFold(policy, "REJECT-DROP") {
			row.Flags = append(row.Flags, Flag{Code: "reject_drop", Severity: SevInfo, Message: "REJECT-DROP 在网关上同样是拒绝：TCP 立即复位、其它返回 ICMP 端口不可达，不是静默丢弃"})
		}
		return model.ActionReject, true
	}
	if kind == "selector" && b.o.Mapping[policy] == "" {
		sv := b.services[policy]
		if sv == nil {
			pick, from := b.pick(policy)
			sv = &ServiceView{Name: policy, ID: idFor("svc-", policy), Pick: pick, PickFrom: from}
			for _, s := range b.t.ServiceGroups {
				if s.Name == policy {
					sv.ID, sv.Existing, sv.Current = s.ID, true, serviceSpec(s)
				}
			}
			spec, chain, need := b.resolve(pick, line, 1)
			sv.Chain = append([]string{policy}, chain...)
			sv.Target = spec
			if need != "" {
				b.needMapping(need, line)
			}
			if sv.Existing && !b.o.ResetServices && sv.Current != "" {
				sv.Keep = true
			}
			b.services[policy] = sv
		} else if len(sv.UsedBy) > 0 && sv.UsedBy[len(sv.UsedBy)-1] != line {
			// noted below
		}
		sv.UsedBy = append(sv.UsedBy, line)
		eff := sv.Target
		if sv.Keep {
			eff = sv.Current
		}
		row.Target = &TargetView{Kind: "service", ID: sv.ID, Name: policy, Resolved: eff, Chain: sv.Chain}
		if sv.PickFrom == "first_member" && !sv.Keep {
			row.Flags = append(row.Flags, Flag{Code: "selection_unknown", Severity: SevInfo, Message: "没有「" + policy + "」的选中状态，按第一个成员 " + sv.Pick + " 映射；可以导入 GET /proxies 或在服务组里改"})
		}
		if eff == "" {
			row.Flags = append(row.Flags, Flag{Code: "target_unmapped", Severity: SevBlock, Message: "服务组「" + policy + "」最终指向的线路「" + sv.Chain[len(sv.Chain)-1] + "」还没有对应到面板里的地区组或出口（在映射表里指定）"})
			return "", false
		}
		return "service:" + sv.ID, true
	}
	spec, chain, need := b.resolve(policy, line, 0)
	row.Target = &TargetView{Kind: "", Name: policy, Chain: chain}
	if need != "" || spec == "" {
		b.needMapping(need, line)
		row.Flags = append(row.Flags, Flag{Code: "target_unmapped", Severity: SevBlock, Message: "「" + need + "」还没有对应到面板里的地区组或出口（在映射表里指定）"})
		return "", false
	}
	row.Target.Kind, row.Target.Resolved = strings.SplitN(spec+":", ":", 2)[0], spec
	if strings.HasPrefix(spec, "group:") || strings.HasPrefix(spec, "exit:") {
		row.Target.ID = strings.SplitN(spec, ":", 2)[1]
	}
	return spec, true
}

func accepted(o Options, line int, code string) bool {
	for _, c := range o.Accept[line] {
		if c == code {
			return true
		}
	}
	return false
}

// Build computes the preview and the plan.
func Build(t model.Topology, cfg Config, o Options, content func(Provider) Content) (*Preview, *Plan) {
	p := &Preview{Summary: map[string]int{}}
	plan := &Plan{Mapping: map[string]string{}, ActivateSets: map[string]Content{}}
	b := &builder{t: t, cfg: cfg, o: o, content: content, p: p, plan: plan,
		mapRows: map[string]*MappingRow{}, services: map[string]*ServiceView{}, sets: map[string]*RuleSetView{}}
	if b.o.Mapping == nil {
		b.o.Mapping = map[string]string{}
	}
	// Remembered mappings apply unless the request overrides them.
	if t.MihomoImport != nil {
		for k, v := range t.MihomoImport.Mapping {
			if _, ok := b.o.Mapping[k]; !ok && specOK(t, v) {
				b.o.Mapping[k] = v
			}
		}
	}
	parsed := make([]Rule, len(cfg.Rules))
	matchAt := -1
	for i, raw := range cfg.Rules {
		r, err := ParseRule(raw)
		parsed[i] = r
		if err == nil && r.Type == "MATCH" && matchAt < 0 {
			matchAt = i
		}
	}
	seenID := map[string]int{}
	quicSeen := false
	for i, r := range parsed {
		row := Row{Line: r.Line, Text: r.Text, Type: r.Type, Value: r.Payload, Policy: r.Policy, Action: "rule"}
		if _, err := ParseRule(cfg.Rules[i]); err != nil {
			row.Action = "unsupported"
			row.Flags = append(row.Flags, Flag{Code: "unparsable", Severity: SevBlock, Message: err.Error()})
			p.Rows = append(p.Rows, row)
			continue
		}
		var mr model.Rule
		mr.Origin, mr.SourceLine, mr.SourceText, mr.Enabled = model.OriginMihomo, r.Line, r.Text, true
		key := r.Type + "," + r.Payload + "," + r.Policy
		seenID[key]++
		mr.ID = idFor("mh-", fmt.Sprintf("%s#%d", key, seenID[key]))
		mr.Name = r.Type + " " + r.Payload
		if len(mr.Name) > 120 {
			mr.Name = mr.Name[:120]
		}
		write := true
		switch {
		case matchAt >= 0 && i > matchAt:
			row.Action = "after_match"
			row.Flags = append(row.Flags, Flag{Code: "after_match", Severity: SevInfo, Message: "在 MATCH 之后，mihomo 永远走不到这里；不写入（写入会让它在网关上生效，改变语义）"})
			write = false
		case r.Type == "MATCH":
			row.Action = "match"
			write = false
			spec, ok := b.target(r.Policy, r.Line, &row)
			if ok {
				gid := ""
				if strings.HasPrefix(spec, "service:") {
					sv := b.services[r.Policy]
					eff := sv.Target
					if sv.Keep {
						eff = sv.Current
					}
					sv.Default = true
					if strings.HasPrefix(eff, "group:") {
						gid = strings.TrimPrefix(eff, "group:")
					}
				} else if strings.HasPrefix(spec, "group:") {
					gid = strings.TrimPrefix(spec, "group:")
				}
				if gid == "" {
					row.Flags = append(row.Flags, Flag{Code: "match_not_group", Severity: SevBlock, Message: "MATCH 对应网关的默认组，只能落到地区组（不能是直连、拒绝或单个出口）"})
				} else {
					plan.DefaultGroup = gid
					p.Default = row.Target
				}
			}
			row.Flags = append(row.Flags, Flag{Code: "builtin_tail", Severity: SevInfo, Message: "MATCH 映射为默认组。在它之前，网关固定还有两步（优先级最低，排在所有规则之后）：内置国内名单（geosite cn，用国内解析器、直连）和中国地址直连（chnroute，相当于 GEOIP,CN,DIRECT）。所以没有任何规则命中、但解析结果是中国地址的连接直连，不进默认组。"})
		case r.Type == "GEOIP" && strings.EqualFold(r.Payload, "CN") && strings.EqualFold(r.Policy, "DIRECT") && i == matchAt-1:
			row.Action = "tail"
			row.Target = &TargetView{Kind: model.ActionDirect, Name: "直连"}
			row.Flags = append(row.Flags, Flag{Code: "builtin_tail", Severity: SevInfo, Message: "紧挨 MATCH 的 GEOIP,CN,DIRECT 就是网关内置的中国地址直连（chnroute），不另写规则"})
			write = false
		default:
			if shape, ok := QUICShape(r); ok {
				row.Action = "quic"
				write = !quicSeen
				quicSeen = true
				mr.MatchType = model.MatchQUICReject
				mr.Name = "QUIC 开关（" + shape + "）"
				row.Match = "拒绝走隧道的 UDP 443（这一行之上的规则豁免）"
				msg := "识别为 QUIC 开关：这一行之下的规则和默认组走隧道的 UDP 443 被拒绝（ICMP 端口不可达，客户端立即改用 TCP），之上的规则豁免，直连不受影响。与 mihomo 的差别：mihomo 按「不是国内（" + shape + " cn）」判断，网关按「走隧道」判断——之下指向直连的规则在网关上不拒绝 UDP 443，之下指向代理、但名字在 geosite cn 里（或地址在中国）的连接在网关上被拒绝。"
				row.Flags = append(row.Flags, Flag{Code: "quic_semantics", Severity: SevAccept, Message: msg})
				if p.QUIC == "" {
					p.QUIC = shape
				} else {
					row.Flags = append(row.Flags, Flag{Code: "quic_repeated", Severity: SevInfo, Message: "第二条 QUIC 规则：开关只有一个，位置取第一条"})
				}
				break
			}
			if !b.mapMatch(r, &row, &mr) {
				write = false
				break
			}
			spec, ok := b.target(r.Policy, r.Line, &row)
			if ok {
				ruleSpec(&mr, spec)
			}
			if quicSeen && spec == model.ActionDirect {
				row.Flags = append(row.Flags, Flag{Code: "quic_direct_below", Severity: SevAccept, Message: "这条直连规则在 QUIC 开关之下：mihomo 会拒绝它非国内目的地的 UDP 443，网关不拒绝直连流量"})
			}
		}
		if o.Drop[r.Line] {
			row.Status = "dropped"
			write = false
		}
		p.Rows = append(p.Rows, row)
		if write {
			mr.Accepted = append([]string(nil), o.Accept[r.Line]...)
			plan.Rules = append(plan.Rules, mr)
			p.Rows[len(p.Rows)-1].RuleID = mr.ID
		}
	}
	b.finish()
	return p, plan
}

// mapMatch sets the rule's match from the mihomo type.
func (b *builder) mapMatch(r Rule, row *Row, mr *model.Rule) bool {
	v := strings.TrimSpace(r.Payload)
	switch r.Type {
	case "DOMAIN", "DOMAIN-SUFFIX":
		d, ok := ordered.NormDomain(strings.TrimPrefix(v, "."))
		if !ok {
			row.Flags = append(row.Flags, Flag{Code: "bad_value", Severity: SevBlock, Message: "域名不合法"})
			row.Action = "unsupported"
			return false
		}
		mr.MatchType, mr.MatchValue = model.MatchDomain, d
		row.Match = "完整域名 " + d
		if r.Type == "DOMAIN-SUFFIX" {
			mr.MatchType = model.MatchSuffix
			row.Match = "域名后缀 " + d
		}
	case "DOMAIN-KEYWORD":
		k, ok := ordered.NormKeyword(v)
		if !ok {
			row.Flags = append(row.Flags, Flag{Code: "bad_value", Severity: SevBlock, Message: "关键词不合法"})
			row.Action = "unsupported"
			return false
		}
		mr.MatchType, mr.MatchValue = model.MatchKeyword, k
		row.Match = "关键词 " + k
		row.Flags = append(row.Flags, Flag{Code: "keyword_expanded", Severity: SevAccept,
			Message: "SmartDNS 不能按子串匹配域名。可接受的替代：用已下载的 geosite 名单里含「" + k + "」的域名（按后缀）代替关键词——名单之外含这个词的域名不会命中，落到后面的规则。不接受就删掉这一行，或改成具体的后缀规则。"})
	case "IP-CIDR", "IP-CIDR6":
		pr, err := netip.ParsePrefix(v)
		if err != nil {
			row.Flags = append(row.Flags, Flag{Code: "bad_value", Severity: SevBlock, Message: "CIDR 不合法"})
			row.Action = "unsupported"
			return false
		}
		mr.MatchType, mr.MatchValue = model.MatchCIDR, pr.Masked().String()
		row.Match = "目的地址 " + mr.MatchValue
		if r.NoResolve {
			row.Flags = append(row.Flags, Flag{Code: "no_resolve", Severity: SevInfo, Message: "no-resolve：网关总是按目的地址判断，没有影响"})
		}
	case "GEOIP":
		if !strings.EqualFold(v, "CN") {
			row.Flags = append(row.Flags, Flag{Code: "geoip_country", Severity: SevBlock, Message: "网关只有中国地址名单（chnroute），没有其它国家的数据源；GEOIP," + v + " 不能执行"})
			row.Action = "unsupported"
			return false
		}
		mr.MatchType, mr.MatchValue = model.MatchGeoIP, "CN"
		row.Match = "目的地址属于中国（chnroute）"
	case "GEOSITE":
		if !regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`).MatchString(v) {
			row.Flags = append(row.Flags, Flag{Code: "bad_value", Severity: SevBlock, Message: "geosite 名称不合法"})
			row.Action = "unsupported"
			return false
		}
		mr.MatchType, mr.MatchValue, mr.Geosite = model.MatchGeosite, strings.ToLower(v), strings.ToLower(v)
		row.Match = "geosite " + v + "（v2fly 名单，由名单更新下载）"
	case "RULE-SET":
		return b.mapRuleSet(r, row, mr)
	default:
		row.Action = "unsupported"
		why := "类型 " + r.Type + " 网关不能执行"
		switch r.Type {
		case "AND", "OR", "NOT":
			why = "逻辑规则只支持两种 QUIC 写法，这一条不是"
		case "PROCESS-NAME", "PROCESS-PATH", "UID":
			why = "网关看不到客户端的进程"
		case "DST-PORT", "SRC-PORT", "IN-PORT", "NETWORK":
			why = "网关按目的地址分流，不按端口或协议"
		case "SRC-IP-CIDR", "SRC-GEOIP", "SRC-IP-ASN":
			why = "按来源的规则请在面板里写成按设备的手工规则"
		case "IP-ASN":
			why = "没有 ASN 数据源"
		}
		row.Flags = append(row.Flags, Flag{Code: "unsupported_type", Severity: SevBlock, Message: why})
		return false
	}
	return true
}

func (b *builder) mapRuleSet(r Rule, row *Row, mr *model.Rule) bool {
	name := strings.TrimSpace(r.Payload)
	prov, ok := b.cfg.Providers[name]
	if !ok {
		row.Action = "unsupported"
		row.Flags = append(row.Flags, Flag{Code: "ruleset_missing", Severity: SevBlock, Message: "rule-providers 里没有「" + name + "」（请一起粘贴 rule-providers 段）"})
		return false
	}
	sv := b.sets[name]
	if sv == nil {
		sv = &RuleSetView{Name: name, URL: prov.URL, Behavior: prov.Behavior, ID: idFor("rs-", name)}
		for _, rs := range b.t.RuleSets {
			if rs.Name == name || (prov.URL != "" && rs.URL == prov.URL) {
				sv.ID, sv.Existing = rs.ID, true
			}
		}
		switch {
		case !strings.EqualFold(prov.Type, "http"):
			sv.State, sv.Error = "unsupported", "只支持 type: http 的规则集（"+prov.Type+" 不行）"
		case strings.EqualFold(prov.Format, "mrs"):
			sv.State, sv.Error = "unsupported", ruleset.ErrMRS.Error()
		case ruleset.CheckURL(prov.URL) != nil:
			sv.State, sv.Error = "unsupported", "URL 不合法"
		default:
			c := b.content(prov)
			sv.State, sv.Error, sv.Format, sv.Counts, sv.Unsupported = c.State, c.Error, c.Format, c.Counts, c.Unsupported
			if c.State == "available" {
				b.plan.ActivateSets[sv.ID] = c
			}
		}
		b.sets[name] = sv
	}
	sv.UsedBy = append(sv.UsedBy, r.Line)
	mr.MatchType, mr.RuleSet = model.MatchRuleSet, sv.ID
	row.Match = "规则集 " + name
	switch sv.State {
	case "unsupported":
		row.Action = "unsupported"
		row.Flags = append(row.Flags, Flag{Code: "ruleset_unsupported", Severity: SevBlock, Message: sv.Error})
		return false
	case "available":
		if n := sv.Counts["keyword"]; n > 0 {
			row.Flags = append(row.Flags, Flag{Code: "ruleset_keywords", Severity: SevAccept, Message: fmt.Sprintf("规则集里有 %d 条 DOMAIN-KEYWORD，SmartDNS 不能按子串匹配，这些条目不执行（含这些词的名字落到后面的规则）", n)})
		}
		if len(sv.Unsupported) > 0 {
			var parts []string
			for k, v := range sv.Unsupported {
				parts = append(parts, fmt.Sprintf("%s %d", k, v))
			}
			sort.Strings(parts)
			row.Flags = append(row.Flags, Flag{Code: "ruleset_partial", Severity: SevAccept, Message: "规则集只部分生效，不能执行的条目：" + strings.Join(parts, "，")})
		}
	default:
		msg := "规则集还没有下载（" + sv.State + "）"
		if sv.Error != "" {
			msg += "：" + sv.Error
		}
		row.Flags = append(row.Flags, Flag{Code: "ruleset_unavailable", Severity: SevAccept, Message: msg + "。没有内容的规则集什么都不匹配，它的名字会落到后面的规则，所以不能直接启用。可接受的替代：先写入但停用这一行，下载完成后在规则页启用。"})
		if accepted(b.o, r.Line, "ruleset_unavailable") {
			mr.Enabled = false
		}
	}
	return true
}

// finish computes the shadow analysis, the diff, statuses and the digest.
func (b *builder) finish() {
	p, plan, t, o := b.p, b.plan, b.t, b.o
	// Service groups and rule-sets to write.
	for _, name := range sortedKeys(b.services) {
		sv := b.services[name]
		sg := model.ServiceGroup{ID: sv.ID, Name: sv.Name, Origin: model.OriginMihomo, Default: sv.Default}
		eff := sv.Target
		if sv.Keep {
			eff = sv.Current
		}
		setSpec(&sg, eff)
		plan.Services = append(plan.Services, sg)
		p.Services = append(p.Services, *sv)
	}
	for _, name := range sortedKeys(b.sets) {
		sv := b.sets[name]
		p.RuleSets = append(p.RuleSets, *sv)
		if sv.State == "unsupported" {
			continue
		}
		prov := b.cfg.Providers[name]
		rs := model.RuleSet{ID: sv.ID, Name: name, URL: prov.URL, Behavior: strings.ToLower(prov.Behavior), Origin: model.OriginMihomo, Source: ruleset.SourcePolicy}
		if strings.EqualFold(prov.Format, "text") {
			rs.Format = map[string]string{"classical": ruleset.FormatClashTextClassic, "domain": ruleset.FormatClashTextDomain, "ipcidr": ruleset.FormatClashTextIPCIDR}[strings.ToLower(prov.Behavior)]
		}
		if prov.Interval >= 3600 && prov.Interval <= 30*86400 {
			rs.IntervalSec = prov.Interval
		}
		for _, old := range t.RuleSets {
			if old.ID == sv.ID {
				rs.Source, rs.AllowLAN, rs.IntervalSec = old.Source, old.AllowLAN, old.IntervalSec
				if old.Format != "" {
					rs.Format = old.Format
				}
			}
		}
		plan.RuleSets = append(plan.RuleSets, rs)
	}
	for _, name := range sortedKeys(b.mapRows) {
		mr := b.mapRows[name]
		if t.MihomoImport != nil && t.MihomoImport.Mapping[name] != "" && t.MihomoImport.Mapping[name] == mr.Mapped {
			mr.Remembered = true
		}
		p.Mapping = append(p.Mapping, *mr)
	}
	for k, v := range o.Mapping {
		if specOK(t, v) {
			plan.Mapping[k] = v
		}
	}
	// The resulting list, for positions and the shadow analysis.
	own, at := insertAt(t, o.AtStart)
	for _, r := range own {
		if !r.Manual && o.DisableBuiltin && r.Enabled {
			plan.DisableRules = append(plan.DisableRules, r.ID)
			p.Builtin = append(p.Builtin, r.Name)
		}
	}
	list := append(append(append([]model.Rule(nil), own[:at]...), plan.Rules...), own[at:]...)
	disabled := map[string]bool{}
	for _, id := range plan.DisableRules {
		disabled[id] = true
	}
	content := map[string][]ordered.Entry{}
	for id, c := range plan.ActivateSets {
		content[id] = c.Entries
	}
	var refs []ordered.Rule
	var refIDs []string
	label := map[string]string{}
	pos := map[string]int{}
	for i, r := range list {
		pos[r.ID] = i + 1
		if r.Origin == model.OriginMihomo {
			label[r.ID] = fmt.Sprintf("第 %d 行", r.SourceLine)
		} else {
			label[r.ID] = "「" + r.Name + "」"
		}
		if !r.Enabled || disabled[r.ID] || r.MatchType == model.MatchQUICReject {
			continue
		}
		refs = append(refs, ordered.Rule{ID: r.ID, Entries: Entries(r, content)})
		refIDs = append(refIDs, r.ID)
	}
	an := ordered.Analyze(refs)
	byID := map[string]ordered.RuleAnalysis{}
	for i, a := range an {
		byID[refIDs[i]] = a
	}
	// Diff against the current import.
	old := map[string]model.Rule{}
	oldUsed := map[string]bool{}
	for _, r := range t.Rules {
		if r.Origin == model.OriginMihomo {
			old[r.ID] = r
		}
	}
	newIDs := map[string]bool{}
	for _, r := range plan.Rules {
		newIDs[r.ID] = true
	}
	for i := range p.Rows {
		row := &p.Rows[i]
		if row.RuleID != "" {
			row.Position = pos[row.RuleID]
			if prev, ok := old[row.RuleID]; ok {
				oldUsed[row.RuleID] = true
				var cur model.Rule
				for _, r := range plan.Rules {
					if r.ID == row.RuleID {
						cur = r
					}
				}
				if prev.TargetGroup == cur.TargetGroup && prev.TargetExit == cur.TargetExit && prev.TargetService == cur.TargetService && prev.TargetAction == cur.TargetAction && prev.SourceLine == cur.SourceLine {
					row.Diff = "same"
				} else {
					row.Diff = "changed"
				}
			} else {
				row.Diff = "new"
			}
			if a, ok := byID[row.RuleID]; ok {
				var by, part []string
				for _, j := range a.ShadowedBy {
					by = append(by, label[refIDs[j]])
				}
				for _, j := range a.PartlyBy {
					part = append(part, label[refIDs[j]])
				}
				switch {
				case a.FullyShadowed:
					row.Flags = append(row.Flags, Flag{Code: "shadowed", Severity: SevInfo, Message: "被前面的规则完全遮蔽，永远不会命中（与 mihomo 相同）", By: by})
				case a.Shadowed > 0:
					row.Flags = append(row.Flags, Flag{Code: "partly_shadowed", Severity: SevInfo, Message: fmt.Sprintf("%d / %d 个条目被前面的规则遮蔽", a.Shadowed, a.Entries), By: by})
				}
				if len(part) > 0 {
					row.Flags = append(row.Flags, Flag{Code: "partly_shadowed", Severity: SevInfo, Message: "前面的规则先接走了其中更具体的名字或网段", By: part})
				}
			}
		}
		for k := range row.Flags {
			row.Flags[k].Class = FlagClass(row.Flags[k].Code)
		}
		// Status.
		if row.Status == "dropped" {
			continue
		}
		st := "ok"
		if row.Action == "match" || row.Action == "tail" || row.Action == "after_match" {
			st = "info"
		}
		for _, f := range row.Flags {
			if o.NameAware && f.Class == ClassAddress {
				continue
			}
			switch f.Severity {
			case SevBlock:
				st = "blocked"
			case SevAccept:
				if accepted(o, row.Line, f.Code) {
					if st == "ok" {
						st = "accepted"
					}
				} else {
					st = "blocked"
				}
			}
		}
		row.Status = st
		if st == "blocked" {
			p.Blocking++
		}
		p.Summary[st]++
	}
	for id, r := range old {
		if !oldUsed[id] && !newIDs[id] {
			p.Removed = append(p.Removed, Removed{RuleID: id, Line: r.SourceLine, Text: r.SourceText})
		}
	}
	sort.Slice(p.Removed, func(i, j int) bool { return p.Removed[i].Line < p.Removed[j].Line })
	plan.ImportedCount = len(plan.Rules)
	p.Notes = append(p.Notes,
		"顺序：和 mihomo 一样自上而下、第一条命中生效。导入的规则作为一段放在面板规则列表的"+map[bool]string{true: "最前面", false: "手工规则之后"}[o.AtStart]+"；手工规则不会被改动。",
		"直连（DIRECT）= 用国内解析器解析、直连出去，只用于规则（或内置国内名单）明确指定的名字；其它名字由出口的解析器解析并走隧道，即使出口给的是中国地址。",
		"内置国内名单（geosite cn）和中国地址直连（chnroute）排在所有规则之后、默认组之前：规则总是优先。",
		"网关按解析出的目的地址分流：两个指向不同目标的名字解析到同一个地址时，网关分不清它们的连接，该地址按列表里更靠前的规则走。",
		"导入的配置只读取 rules、rule-providers、proxy-groups 三段；proxies 等其它内容在解析后立即丢弃，不保存、不记录、不返回。")
	p.CanConfirm = p.Blocking == 0 && len(plan.Rules)+len(plan.Services) > 0
	p.Digest = plan.digest()
}

// Entries are a rule's match entries for the analysis: static ones, and a
// rule-set's content when given.
func Entries(r model.Rule, content map[string][]ordered.Entry) []ordered.Entry {
	var es []ordered.Entry
	v := strings.TrimPrefix(strings.ToLower(strings.TrimSpace(r.MatchValue)), ".")
	switch r.MatchType {
	case model.MatchDomain:
		if d, ok := ordered.NormDomain(v); ok {
			es = append(es, ordered.Entry{Kind: ordered.Exact, Value: d})
		}
	case model.MatchSuffix:
		if d, ok := ordered.NormDomain(v); ok {
			es = append(es, ordered.Entry{Kind: ordered.Suffix, Value: d})
		}
	case model.MatchKeyword:
		if k, ok := ordered.NormKeyword(v); ok {
			es = append(es, ordered.Entry{Kind: ordered.Keyword, Value: k})
		}
	case model.MatchCIDR:
		if p, err := netip.ParsePrefix(v); err == nil {
			es = append(es, ordered.Entry{Kind: ordered.CIDR, Prefix: p.Masked()})
		} else if a, err := netip.ParseAddr(v); err == nil {
			es = append(es, ordered.Entry{Kind: ordered.CIDR, Prefix: netip.PrefixFrom(a, a.BitLen())})
		}
	case model.MatchRuleSet:
		es = append(es, content[r.RuleSet]...)
	}
	for _, d := range r.Domains {
		if d, ok := ordered.NormDomain(strings.TrimPrefix(d, ".")); ok {
			es = append(es, ordered.Entry{Kind: ordered.Suffix, Value: d})
		}
	}
	return es
}

func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func (plan *Plan) digest() string {
	type setDigest struct {
		ID, Format string
		N          int
	}
	var sets []setDigest
	for _, id := range sortedKeys(plan.ActivateSets) {
		sets = append(sets, setDigest{id, plan.ActivateSets[id].Format, len(plan.ActivateSets[id].Entries)})
	}
	b, _ := json.Marshal(struct {
		R  []model.Rule
		S  []model.ServiceGroup
		RS []model.RuleSet
		D  string
		X  []string
		A  []setDigest
	}{plan.Rules, plan.Services, plan.RuleSets, plan.DefaultGroup, plan.DisableRules, sets})
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

// Apply writes a confirmed plan into t: the previous imported rules are
// replaced by the new block (after the panel's own rules, or before them),
// manual rules are untouched, built-in rows listed are disabled, service
// groups and rule-sets are upserted (imported ones no rule uses any more
// are removed), the default group follows MATCH, and the mapping is
// remembered.
func Apply(t *model.Topology, plan *Plan, atStart bool, now string) {
	disable := map[string]bool{}
	for _, id := range plan.DisableRules {
		disable[id] = true
	}
	own, at := insertAt(*t, atStart)
	for i := range own {
		if disable[own[i].ID] {
			own[i].Enabled = false
		}
	}
	t.Rules = append(append(append([]model.Rule(nil), own[:at]...), plan.Rules...), own[at:]...)
	t.RulesOrdered = true
	// Service groups.
	used := map[string]bool{}
	for _, r := range t.Rules {
		used[r.TargetService] = true
	}
	var svcs []model.ServiceGroup
	planned := map[string]model.ServiceGroup{}
	for _, s := range plan.Services {
		planned[s.ID] = s
	}
	for _, s := range t.ServiceGroups {
		if p, ok := planned[s.ID]; ok {
			s.TargetGroup, s.TargetExit, s.TargetAction, s.Default = p.TargetGroup, p.TargetExit, p.TargetAction, p.Default
			svcs = append(svcs, s)
			delete(planned, s.ID)
			continue
		}
		if s.Origin == model.OriginMihomo && !used[s.ID] {
			continue
		}
		if plan.DefaultGroup != "" {
			s.Default = false
		}
		svcs = append(svcs, s)
	}
	for _, s := range plan.Services {
		if _, ok := planned[s.ID]; ok {
			svcs = append(svcs, s)
		}
	}
	t.ServiceGroups = svcs
	// Rule-sets.
	usedSet := map[string]bool{}
	for _, r := range t.Rules {
		if r.MatchType == model.MatchRuleSet {
			usedSet[r.RuleSet] = true
		}
	}
	plannedSets := map[string]model.RuleSet{}
	for _, rs := range plan.RuleSets {
		plannedSets[rs.ID] = rs
	}
	var sets []model.RuleSet
	for _, rs := range t.RuleSets {
		if p, ok := plannedSets[rs.ID]; ok {
			sets = append(sets, p)
			delete(plannedSets, rs.ID)
			continue
		}
		if rs.Origin == model.OriginMihomo && !usedSet[rs.ID] {
			continue
		}
		sets = append(sets, rs)
	}
	for _, rs := range plan.RuleSets {
		if _, ok := plannedSets[rs.ID]; ok {
			sets = append(sets, rs)
		}
	}
	t.RuleSets = sets
	if plan.DefaultGroup != "" {
		t.Settings.DefaultGroup = plan.DefaultGroup
	}
	if t.MihomoImport == nil {
		t.MihomoImport = &model.MihomoImport{}
	}
	if t.MihomoImport.Mapping == nil {
		t.MihomoImport.Mapping = map[string]string{}
	}
	for k, v := range plan.Mapping {
		t.MihomoImport.Mapping[k] = v
	}
	t.MihomoImport.ImportedAt, t.MihomoImport.Digest, t.MihomoImport.Rules = now, plan.digest(), plan.ImportedCount
}

// insertAt is the panel's own rules (everything not imported, in list
// order) and where the imported block goes: where the previous import
// was, else at the start (atStart) or right after the last manual rule.
// The panel's own rules keep their relative order.
func insertAt(t model.Topology, atStart bool) ([]model.Rule, int) {
	var own []model.Rule
	at, prev := 0, -1
	for _, r := range t.EvalOrder() {
		if r.Origin == model.OriginMihomo {
			if prev < 0 {
				prev = len(own)
			}
			continue
		}
		own = append(own, r)
		if r.Manual && !atStart {
			at = len(own)
		}
	}
	if prev >= 0 {
		return own, prev
	}
	return own, at
}
