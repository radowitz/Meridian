package mihomo

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"strings"
	"testing"

	"github.com/radowitz/meridian/internal/defaults"
	"github.com/radowitz/meridian/internal/model"
	"github.com/radowitz/meridian/internal/ordered"
	"github.com/radowitz/meridian/internal/validate"
)

// Fake credentials that must never leave Parse.
var secrets = []string{"hunter2-fake-password", "0b9c6f1e-0000-4000-8000-fakeuuid0001", "FAKEPRIVATEKEYAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", "sub-token-fake-123", "controller-secret-fake"}

// SynthConfig is a synthetic mihomo config with the structure of a real
// one (anchors and merge keys in proxy-groups, flow maps, quoted names with
// spaces, comments, commented-out rules, the QUIC rules, a rule-set
// exception, duplicate suffixes, specific-before-general, GEOIP,CN and
// MATCH) and a proxies section full of fake secrets.
const SynthConfig = `# synthetic config for tests; every name and address is made up
mixed-port: 7890
secret: controller-secret-fake
proxies:
  - { name: "HK Home 01", type: vless, server: 198.51.100.10, port: 443, uuid: 0b9c6f1e-0000-4000-8000-fakeuuid0001 }
  - name: JP DC 01
    type: wireguard
    server: 203.0.113.20
    private-key: FAKEPRIVATEKEYAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
    password: hunter2-fake-password
proxy-providers:
  Line A: { type: http, url: "https://sub.example.org/api?token=sub-token-fake-123", path: ./a.yaml }
pr: &pr { type: select, proxies: [HK, TW, JP, US, SG, DIRECT] }
proxy-groups:
  - { name: AI Suite, <<: *pr }
  - { name: Streaming, <<: *pr }
  - { name: Others, <<: *pr }
  - { name: Selected, <<: *pr }
  - { name: HK, type: select, proxies: ["LB-HK Line A", "LB-HK Line B"] }
  - { name: TW, type: select, proxies: ["LB-TW Line A"] }
  - { name: JP, type: select, proxies: ["LB-JP Line A"] }
  - { name: US, type: select, proxies: ["LB-US Line A"] }
  - { name: SG, type: select, proxies: ["LB-SG Line A"] }
  - { name: "LB-HK Line A", type: load-balance, use: ["Line A"], filter: "(?i)hk" }
  - { name: "LB-HK Line B", type: load-balance, use: ["Line A"], filter: "(?i)hk.*home" }
  - { name: "LB-TW Line A", type: load-balance, use: ["Line A"], filter: "(?i)tw" }
  - { name: "LB-JP Line A", type: load-balance, use: ["Line A"], filter: "(?i)jp" }
  - { name: "LB-US Line A", type: load-balance, use: ["Line A"], filter: "(?i)us" }
  - { name: "LB-SG Line A", type: url-test, use: ["Line A"], filter: "(?i)sg" }
rule-providers:
  Domestic Special: { type: http, behavior: classical, url: 'https://mirror.example.net/https://raw.githubusercontent.com/org/repo/main/rules/Domestic%20Special.yaml', path: ./r/ds.yaml, interval: 86400 }
  AI: { type: http, behavior: classical, url: 'https://mirror.example.net/https://raw.githubusercontent.com/org/repo/main/rules/AI.yaml', path: ./r/ai.yaml, interval: 86400 }
  Bin: { type: http, behavior: domain, format: mrs, url: 'https://example.org/x.mrs', path: ./r/x.mrs }
rules:
  # AI first, deliberately before the QUIC rule
  - DOMAIN-SUFFIX,ai-vendor.example,AI Suite
  - DOMAIN-KEYWORD,aivendor,AI Suite
  - RULE-SET,AI,AI Suite
  - AND,(AND,(DST-PORT,443),(NETWORK,UDP)),(NOT,((GEOSITE,cn))),REJECT
  - AND,(AND,(DST-PORT,443),(NETWORK,UDP)),(NOT,((GEOIP,CN))),REJECT
  - DOMAIN-SUFFIX,dup.example,Streaming
  - DOMAIN-SUFFIX,dup.example,US
  - DOMAIN-SUFFIX,a.b.example,JP
  - DOMAIN-SUFFIX,b.example,HK
  # - DOMAIN-SUFFIX,commented-out.example,DIRECT
  - DOMAIN,one.special.example,Selected
  - RULE-SET,Domestic Special,DIRECT
  - IP-CIDR,198.51.100.0/24,Others,no-resolve
  - PROCESS-NAME,app.exe,DIRECT
  - RULE-SET,Bin,DIRECT
  - DOMAIN-KEYWORD,cdn-word,DIRECT
  - GEOIP,CN,DIRECT
  - MATCH,Others
  - DOMAIN-SUFFIX,after-match.example,DIRECT
`

func synthTopo() model.Topology {
	t := defaults.Example()
	t.RulesOrdered = true
	return t
}

func content(p Provider) Content {
	switch p.Name {
	case "AI":
		return Content{State: "available", Format: "clash-classical", Counts: map[string]int{"suffix": 2},
			Entries: []ordered.Entry{{Kind: ordered.Suffix, Value: "ai-vendor.example"}, {Kind: ordered.Suffix, Value: "ai2.example"}}}
	case "Domestic Special":
		return Content{State: "available", Format: "clash-classical", Counts: map[string]int{"suffix": 2, "keyword": 1}, Unsupported: map[string]int{"PROCESS-NAME": 3},
			Entries: []ordered.Entry{{Kind: ordered.Suffix, Value: "special.example"}, {Kind: ordered.Suffix, Value: "domestic.example"}, {Kind: ordered.Keyword, Value: "dword"}}}
	}
	return Content{State: "missing"}
}

func TestParseKeepsOnlyRuleSections(t *testing.T) {
	cfg, err := Parse(SynthConfig)
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Rules) != 18 {
		t.Fatalf("rules %d", len(cfg.Rules))
	}
	if cfg.Rules[0].Line != 36 || cfg.Rules[0].Text != "DOMAIN-SUFFIX,ai-vendor.example,AI Suite" {
		t.Fatalf("first rule %+v", cfg.Rules[0])
	}
	g := cfg.Groups["AI Suite"]
	if g.Type != "select" || len(g.Proxies) != 6 || g.Proxies[0] != "HK" {
		t.Fatalf("merge key not applied: %+v", g)
	}
	if cfg.Groups["LB-HK Line A"].Type != "load-balance" || cfg.Providers["Domestic Special"].Behavior != "classical" {
		t.Fatalf("flow maps / quoted names: %+v %+v", cfg.Groups["LB-HK Line A"], cfg.Providers["Domestic Special"])
	}
	b, _ := json.Marshal(cfg)
	for _, s := range secrets {
		if strings.Contains(string(b), s) {
			t.Fatalf("secret %q kept by Parse", s)
		}
	}
	// A broken document reports a line, never the line's text.
	_, err = Parse("proxies:\n  - { name: x, password: hunter2-fake-password\nrules: [\n")
	if err == nil || strings.Contains(err.Error(), "hunter2") {
		t.Fatalf("error leaks text: %v", err)
	}
}

func TestQUICShapes(t *testing.T) {
	for _, s := range []string{
		"AND,(AND,(DST-PORT,443),(NETWORK,UDP)),(NOT,((GEOSITE,cn))),REJECT",
		"AND, (AND,(DST-PORT,443),(NETWORK,UDP)), (NOT,((GEOIP,CN))), REJECT",
	} {
		r, err := ParseRule(RawRule{Text: s})
		if _, ok := QUICShape(r); err != nil || !ok {
			t.Errorf("%s not recognised", s)
		}
	}
	for _, s := range []string{
		"AND,(AND,(DST-PORT,443),(NETWORK,UDP)),(NOT,((GEOSITE,cn))),DIRECT",
		"AND,((DST-PORT,443),(NETWORK,UDP)),REJECT",
		"OR,((DOMAIN,a.example),(DOMAIN,b.example)),REJECT",
	} {
		r, _ := ParseRule(RawRule{Text: s})
		if _, ok := QUICShape(r); ok {
			t.Errorf("%s recognised", s)
		}
	}
}

func TestSelection(t *testing.T) {
	sel, err := Selection([]byte(`{"proxies":{"AI Suite":{"type":"Selector","now":"US"},"US":{"type":"Selector","now":"LB-US Line A"},"LB-US Line A":{"type":"LoadBalance","now":""},"DIRECT":{"type":"Direct"}}}`))
	if err != nil || sel["AI Suite"] != "US" || sel["US"] != "LB-US Line A" || len(sel) != 2 {
		t.Fatalf("%v %v", sel, err)
	}
	if _, err := Selection([]byte("not json")); err == nil {
		t.Fatal("garbage accepted")
	}
}

func findRow(p *Preview, line int) Row {
	for _, r := range p.Rows {
		if r.Line == line {
			return r
		}
	}
	return Row{}
}

func hasFlag(r Row, code string) bool {
	for _, f := range r.Flags {
		if f.Code == code {
			return true
		}
	}
	return false
}

func fullOptions() Options {
	return Options{
		Selection: map[string]string{"AI Suite": "US", "Streaming": "HK", "Others": "HK", "Selected": "JP", "HK": "LB-HK Line B"},
		Mapping: map[string]string{
			"LB-HK Line A": "group:hk", "LB-HK Line B": "group:hk-residential", "LB-US Line A": "group:us",
			"LB-JP Line A": "group:jp", "LB-TW Line A": "group:tw", "LB-SG Line A": "group:sg",
		},
		Drop: map[int]bool{49: true, 50: true}, // PROCESS-NAME, mrs rule-set
		Accept: map[int][]string{
			37: {"keyword_expanded"}, 39: {"quic_semantics"}, 40: {"quic_semantics"},
			47: {"ruleset_keywords", "ruleset_partial", "quic_direct_below"}, 51: {"keyword_expanded", "quic_direct_below"},
		},
		DisableBuiltin: true,
	}
}

func TestPreviewMapping(t *testing.T) {
	topo := synthTopo()
	cfg, err := Parse(SynthConfig)
	if err != nil {
		t.Fatal(err)
	}
	// Without mapping or selection: line groups unmapped, blocking.
	p, _ := Build(topo, cfg, Options{}, content)
	if p.CanConfirm || p.Blocking == 0 {
		t.Fatal("unmapped config confirmable")
	}
	r := findRow(p, 36)
	if !hasFlag(r, "target_unmapped") || !hasFlag(r, "selection_unknown") {
		t.Fatalf("row 45 flags %+v", r.Flags)
	}
	var lbhk *MappingRow
	for i := range p.Mapping {
		if p.Mapping[i].Name == "LB-HK Line A" {
			lbhk = &p.Mapping[i]
		}
	}
	if lbhk == nil || len(lbhk.Suggestions) == 0 || !strings.HasPrefix(lbhk.Suggestions[0].Value, "group:hk") {
		t.Fatalf("no region suggestion for LB-HK: %+v", lbhk)
	}

	p, plan := Build(topo, cfg, fullOptions(), content)
	for _, row := range p.Rows {
		if row.Status == "blocked" {
			t.Errorf("row %d %s blocked: %+v", row.Line, row.Text, row.Flags)
		}
	}
	if !p.CanConfirm {
		t.Fatal("not confirmable")
	}
	// Service selector -> pick -> region selector -> pick -> line group.
	ai := findRow(p, 36)
	if ai.Target.Kind != "service" || ai.Target.Resolved != "group:us" || strings.Join(ai.Target.Chain, ">") != "AI Suite>US>LB-US Line A" {
		t.Fatalf("AI target %+v", ai.Target)
	}
	if v := findRow(p, 41).Target; v.Resolved != "group:hk-residential" {
		t.Fatalf("Streaming -> HK -> LB-HK Line B: %+v", v)
	}
	if v := findRow(p, 42).Target; v.Kind != "service" || v.Resolved != "group:us" {
		t.Fatalf("region selector as a rule target: %+v", v)
	}
	if findRow(p, 39).Action != "quic" || findRow(p, 40).Action != "quic" || p.QUIC != "geosite" {
		t.Fatal("QUIC rules not recognised")
	}
	if !hasFlag(findRow(p, 42), "shadowed") {
		t.Fatalf("duplicate suffix not shadowed: %+v", findRow(p, 42).Flags)
	}
	if hasFlag(findRow(p, 43), "shadowed") || !hasFlag(findRow(p, 44), "partly_shadowed") {
		t.Fatalf("specific-before-general: %+v / %+v", findRow(p, 43).Flags, findRow(p, 44).Flags)
	}
	if findRow(p, 52).Action != "tail" || findRow(p, 53).Action != "match" || findRow(p, 54).Action != "after_match" {
		t.Fatal("tail / match / after match")
	}
	if plan.DefaultGroup != "hk-residential" {
		t.Fatalf("MATCH -> Others -> HK -> LB-HK Line B: %s", plan.DefaultGroup)
	}
	if !hasFlag(findRow(p, 49), "unsupported_type") || findRow(p, 49).Status != "dropped" {
		t.Fatal("PROCESS-NAME")
	}
	// Written: every rule row except QUIC#2, match, tail, after-match, drops.
	var lines []int
	for _, r := range plan.Rules {
		lines = append(lines, r.SourceLine)
	}
	if fmt.Sprint(lines) != "[36 37 38 39 41 42 43 44 46 47 48 51]" {
		t.Fatalf("written lines %v", lines)
	}
	// A mrs provider is unsupported; the AI rule-set is available.
	for _, rs := range p.RuleSets {
		if rs.Name == "Bin" && rs.State != "unsupported" || rs.Name == "AI" && rs.State != "available" {
			t.Fatalf("rule-set %+v", rs)
		}
	}
}

// The written result validates, compiles to the same first-match decisions
// as the reference over the mihomo list, and a re-import shows a diff.
func TestApplyAndReimport(t *testing.T) {
	topo := synthTopo()
	manualBefore := []model.Rule{}
	for _, r := range topo.Rules {
		if r.Manual {
			manualBefore = append(manualBefore, r)
		}
	}
	cfg, _ := Parse(SynthConfig)
	p, plan := Build(topo, cfg, fullOptions(), content)
	if !p.CanConfirm {
		t.Fatal("not confirmable")
	}
	Apply(&topo, plan, false, "2026-11-13T00:00:00Z")
	if res := validate.Run(topo); res.HasErrors() {
		for _, is := range res.Issues {
			if is.Severity == validate.SeverityError {
				t.Errorf("%s %s %s", is.Code, is.RuleID, is.Message)
			}
		}
		t.Fatal("imported topology does not validate")
	}
	// Manual rules untouched (same values, same relative order).
	var manualAfter []model.Rule
	for _, r := range topo.Rules {
		if r.Manual {
			manualAfter = append(manualAfter, r)
		}
	}
	a, _ := json.Marshal(manualBefore)
	b, _ := json.Marshal(manualAfter)
	if string(a) != string(b) {
		t.Fatal("manual rules changed")
	}
	if topo.Settings.DefaultGroup != "hk-residential" || topo.MihomoImport.Mapping["LB-US Line A"] != "group:us" {
		t.Fatalf("default %s mapping %v", topo.Settings.DefaultGroup, topo.MihomoImport.Mapping)
	}
	for _, r := range topo.Rules {
		if !r.Manual && r.Origin == "" && r.Enabled {
			t.Fatalf("built-in row %s still enabled", r.ID)
		}
	}
	// Re-import of a changed config: one rule removed, one added, one
	// retargeted; the remembered mapping is used.
	changed := strings.Replace(SynthConfig, "  - DOMAIN-SUFFIX,a.b.example,JP\n", "  - DOMAIN-SUFFIX,new.example,JP\n", 1)
	changed = strings.Replace(changed, "DOMAIN,one.special.example,Selected", "DOMAIN,one.special.example,DIRECT", 1)
	cfg2, _ := Parse(changed)
	o := fullOptions()
	o.Mapping = nil
	o.Accept[46] = []string{"quic_direct_below"} // now DIRECT, below the QUIC row
	p2, _ := Build(topo, cfg2, o, content)
	if !p2.CanConfirm {
		for _, r := range p2.Rows {
			if r.Status == "blocked" {
				t.Logf("%d %+v", r.Line, r.Flags)
			}
		}
		t.Fatal("re-import with remembered mapping not confirmable")
	}
	if len(p2.Removed) != 2 || findRow(p2, 43).Diff != "new" || findRow(p2, 36).Diff != "same" || findRow(p2, 46).Diff != "new" {
		t.Fatalf("diff: removed %+v, 52 %s, 45 %s, 54 %s", p2.Removed, findRow(p2, 43).Diff, findRow(p2, 36).Diff, findRow(p2, 46).Diff)
	}
}

// The imported list, interpreted as mihomo would (first match) with the
// QUIC rows and the tail removed, and the panel's evaluation of the written
// rules give the same target for every probe name.
func TestImportedOrderMatchesMihomo(t *testing.T) {
	topo := synthTopo()
	topo.Rules = nil // only the import
	cfg, _ := Parse(SynthConfig)
	o := fullOptions()
	p, plan := Build(topo, cfg, o, content)
	if !p.CanConfirm {
		t.Fatal("not confirmable")
	}
	Apply(&topo, plan, false, "now")
	cont := map[string][]ordered.Entry{}
	for id, c := range plan.ActivateSets {
		cont[id] = c.Entries
	}
	// mihomo side: the written rows' source lines in source order.
	var mihomo []ordered.Rule
	var panel []ordered.Rule
	for _, r := range topo.EvalOrder() {
		if !r.Enabled || r.MatchType == model.MatchQUICReject {
			continue
		}
		es := Entries(r, cont)
		tg := topo.ResolveTarget(r)
		target := tg.Kind + ":" + tg.ID
		panel = append(panel, ordered.Rule{ID: r.ID, Entries: es, Target: target, GeoIPCN: r.MatchType == model.MatchGeoIP})
		mihomo = append(mihomo, ordered.Rule{ID: fmt.Sprint(r.SourceLine), Entries: es, Target: target, GeoIPCN: r.MatchType == model.MatchGeoIP})
	}
	tail := ordered.Tail{China: []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24")}, DirectTarget: "direct:", Default: "group:" + topo.Settings.DefaultGroup}
	for _, name := range []string{"ai-vendor.example", "x.ai2.example", "dup.example", "a.b.example", "z.b.example", "one.special.example", "two.special.example", "domestic.example", "unrelated.example"} {
		q := ordered.Query{Name: name, Addr: netip.MustParseAddr("100.64.1.1")}
		if a, b := ordered.Reference(mihomo, tail, q), ordered.Reference(panel, tail, q); a.Target != b.Target {
			t.Errorf("%s: mihomo %s, panel %s", name, a.Target, b.Target)
		}
	}
	// Spot checks of the stated behaviour.
	want := map[string]string{
		"ai-vendor.example":   "group:us",
		"dup.example":         "group:hk-residential", // first of the two dup rules (Streaming -> HK -> LB-HK Line B)
		"a.b.example":         "group:jp",
		"z.b.example":         "group:hk-residential",
		"one.special.example": "group:jp", // the exception before the rule-set
		"two.special.example": "direct:",
	}
	for name, w := range want {
		if got := ordered.Reference(panel, tail, ordered.Query{Name: name}).Target; got != w {
			t.Errorf("%s -> %s, want %s", name, got, w)
		}
	}
}

func TestPreviewNeverEchoesSecrets(t *testing.T) {
	cfg, err := Parse(SynthConfig)
	if err != nil {
		t.Fatal(err)
	}
	p, plan := Build(synthTopo(), cfg, fullOptions(), content)
	b, _ := json.Marshal(struct {
		P *Preview
		L *Plan
	}{p, plan})
	for _, s := range secrets {
		if strings.Contains(string(b), s) {
			t.Fatalf("secret %q in preview or plan", s)
		}
	}
}

// Address-only flags are classified so that a name-deciding gateway can
// relax them; today they block until accepted.
func TestFlagClasses(t *testing.T) {
	cfg, _ := Parse(SynthConfig)
	o := fullOptions()
	delete(o.Accept, 37) // the keyword row
	p, _ := Build(synthTopo(), cfg, o, content)
	r := findRow(p, 37)
	if r.Status != "blocked" || r.Flags[0].Class != ClassAddress {
		t.Fatalf("keyword row %+v", r)
	}
	if f := findRow(p, 49).Flags[0]; f.Class != ClassUnsupported {
		t.Fatalf("PROCESS-NAME class %+v", f)
	}
	o.NameAware = true
	p, _ = Build(synthTopo(), cfg, o, content)
	if findRow(p, 37).Status == "blocked" {
		t.Fatal("address-only flag blocks a name-aware import")
	}
}
