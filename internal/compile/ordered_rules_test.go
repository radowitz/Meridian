package compile

import (
	"encoding/json"
	"fmt"
	"math/rand"
	"net/netip"
	"regexp"
	"strings"
	"testing"

	"github.com/radowitz/meridian/internal/defaults"
	"github.com/radowitz/meridian/internal/lists"
	"github.com/radowitz/meridian/internal/model"
	"github.com/radowitz/meridian/internal/ordered"
	"github.com/radowitz/meridian/internal/ruleset"
	"github.com/radowitz/meridian/internal/sniff"
)

// The gateway as the rendered text describes it: the manifest derived on
// the "host" (ordered.Derive with in-memory list files), the SmartDNS
// domain-rules lines (domain-set -> nftset), and the classify chain of the
// rendered nft file. These tests evaluate the REAL rendered artefacts with
// models of their matchers (SmartDNS longest key, nft chain order) against
// the reference interpreter (ordered.Reference) over the same rule list.

type renderedGateway struct {
	derived ordered.Derived
	dns     *ordered.DNSModel
	// domain-set name -> nft v4 set it writes ("" for SOA rules).
	setOf map[string]string
	// classify chain, in order: v4 set name -> mark.
	chain []chainLine
	def   uint32
	// static elements of the rendered sets.
	static map[string][]netip.Prefix
}

type chainLine struct {
	set  string
	mark uint32
}

var (
	domainRulesRe = regexp.MustCompile(`(?m)^domain-rules /domain-set:(\S+)/ (.*)$`)
	nftsetRe      = regexp.MustCompile(`-nftset #4:inet#meridian#(\w+)`)
	classifyRe    = regexp.MustCompile(`^\s+ip daddr @(\w+) meta mark set (0x[0-9a-f]+) return`)
	catchAllRe    = regexp.MustCompile(`^\s+meta nfproto ipv4 meta mark set (0x[0-9a-f]+) return`)
	setElemsRe    = regexp.MustCompile(`(?s)set (\w+) \{\n[^}]*?elements = \{ ([^}]*) \}`)
)

func parseRendered(t *testing.T, b *Bundle, rd ordered.MemReader) *renderedGateway {
	t.Helper()
	m, err := ordered.ParseManifest([]byte(b.File("nodes/gw/" + strings.TrimPrefix(lists.ManifestPath, "/"))))
	if err != nil {
		t.Fatal(err)
	}
	d, err := ordered.Derive(m, rd)
	if err != nil {
		t.Fatal(err)
	}
	g := &renderedGateway{derived: d, dns: ordered.NewDNSModel(), setOf: map[string]string{}}
	for _, set := range d.Order {
		for _, l := range d.Files[set] {
			if err := g.dns.Add(l, set); err != nil {
				t.Fatal(err)
			}
		}
	}
	conf := b.File("nodes/gw/etc/smartdns/smartdns.conf")
	for _, mm := range domainRulesRe.FindAllStringSubmatch(conf, -1) {
		if n := nftsetRe.FindStringSubmatch(mm[2]); n != nil {
			g.setOf[mm[1]] = n[1]
		} else {
			g.setOf[mm[1]] = ""
		}
	}
	nft := b.File("nodes/gw/etc/nftables.d/meridian.nft")
	g.static = map[string][]netip.Prefix{}
	for _, m := range setElemsRe.FindAllStringSubmatch(nft, -1) {
		for _, e := range strings.Split(m[2], ", ") {
			if p, err := netip.ParsePrefix(e); err == nil {
				g.static[m[1]] = append(g.static[m[1]], p)
			} else if a, err := netip.ParseAddr(e); err == nil {
				g.static[m[1]] = append(g.static[m[1]], netip.PrefixFrom(a, a.BitLen()))
			}
		}
	}
	in := false
	for _, l := range strings.Split(nft, "\n") {
		if strings.HasPrefix(l, "  chain classify {") {
			in = true
			continue
		}
		if in && strings.HasPrefix(l, "  }") {
			break
		}
		if !in {
			continue
		}
		if m := classifyRe.FindStringSubmatch(l); m != nil {
			var mark uint32
			fmt.Sscanf(m[2], "0x%x", &mark)
			g.chain = append(g.chain, chainLine{set: m[1], mark: mark})
		}
		if m := catchAllRe.FindStringSubmatch(l); m != nil {
			fmt.Sscanf(m[1], "0x%x", &g.def)
		}
	}
	return g
}

// resolverLine is the domain-rules line SmartDNS applies to name.
func resolverLine(t *testing.T, b *Bundle, name string) string {
	t.Helper()
	g := parseRendered(t, b, ordered.MemReader{})
	set := g.dns.Lookup(name)
	if set == "" {
		t.Fatalf("no domain rule for %s", name)
	}
	for _, mm := range domainRulesRe.FindAllStringSubmatch(b.File("nodes/gw/etc/smartdns/smartdns.conf"), -1) {
		if mm[1] == set {
			return mm[0]
		}
	}
	t.Fatalf("no domain-rules line for set %s", set)
	return ""
}

// classify: the mark a connection gets after the client resolved name to
// addr through the gateway (learned holds earlier answers).
func (g *renderedGateway) classify(learned map[string]map[netip.Addr]bool, name string, addr netip.Addr, china []netip.Prefix) uint32 {
	if name != "" {
		set := g.dns.Lookup(name)
		nft := "default4"
		if set != "" {
			nft = g.setOf[set]
		}
		if learned[nft] == nil {
			learned[nft] = map[netip.Addr]bool{}
		}
		learned[nft][addr] = true
	}
	for _, c := range g.chain {
		hit := learned[c.set][addr]
		for _, p := range g.derived.CIDR[c.set] {
			hit = hit || p.Contains(addr)
		}
		for _, p := range g.static[c.set] {
			hit = hit || p.Contains(addr)
		}
		if c.set == "chnroute" {
			for _, p := range china {
				hit = hit || p.Contains(addr)
			}
		}
		if hit {
			return c.mark
		}
	}
	return g.def
}

// orderedTopo: the example topology with its rules replaced by rules.
func orderedTopo(rules []model.Rule) model.Topology {
	t := defaults.Example()
	t.Rules = rules
	t.RulesOrdered = true
	return t
}

func rr(id string, mt model.MatchType, v, group string) model.Rule {
	return model.Rule{ID: id, Name: id, Enabled: true, MatchType: mt, MatchValue: v, TargetGroup: group}
}

// TestOrderedRenderedMatchesReference: generated rule lists (exact,
// suffix, rule-sets with exact/suffix/sub/CIDR entries, CIDR rules,
// GEOIP,CN, DIRECT and REJECT targets, region groups and service groups)
// are compiled for the example gateway; every probe's mark from the
// rendered artefacts equals the mark of the rule the reference interpreter
// picks (or of the tail).
func TestOrderedRenderedMatchesReference(t *testing.T) {
	rng := rand.New(rand.NewSource(7))
	names := []string{"example.net", "a.example.net", "b.a.example.net", "example.org", "x.example.org", "y.x.example.org", "cn.example.org"}
	cidrs := []string{"198.51.100.0/24", "198.51.100.0/25", "203.0.113.0/24", "203.0.113.64/26"}
	groups := []string{"us", "hk", "jp", "tw"}
	china := []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24")}
	cases, probes := 0, 0
	for iter := 0; iter < 400; iter++ {
		var rules []model.Rule
		var ref []ordered.Rule
		rd := ordered.MemReader{RuleSets: map[string][]ordered.Entry{}, Geo: map[string][]string{"cn": {"cn.example.org"}}}
		base := defaults.Example()
		base.ServiceGroups = []model.ServiceGroup{{ID: "svc-ai", Name: "AI", TargetGroup: "jp"}, {ID: "svc-x", Name: "X", TargetAction: model.ActionDirect}}
		var rsets []model.RuleSet
		for i, n := 0, 1+rng.Intn(6); i < n; i++ {
			id := fmt.Sprintf("r-%d", i)
			var r model.Rule
			var es []ordered.Entry
			switch rng.Intn(5) {
			case 0:
				v := names[rng.Intn(len(names))]
				r = rr(id, model.MatchDomain, v, "")
				es = []ordered.Entry{{Kind: ordered.Exact, Value: v}}
			case 1:
				v := names[rng.Intn(len(names))]
				r = rr(id, model.MatchSuffix, v, "")
				es = []ordered.Entry{{Kind: ordered.Suffix, Value: v}}
			case 2:
				v := cidrs[rng.Intn(len(cidrs))]
				r = rr(id, model.MatchCIDR, v, "")
				es = []ordered.Entry{{Kind: ordered.CIDR, Prefix: netip.MustParsePrefix(v)}}
			case 3:
				rsID := fmt.Sprintf("rs-%d", i)
				r = rr(id, model.MatchRuleSet, "", "")
				r.RuleSet = rsID
				rsets = append(rsets, model.RuleSet{ID: rsID, Name: rsID, URL: "https://example.org/" + rsID + ".list"})
				for k := 1 + rng.Intn(3); k > 0; k-- {
					switch rng.Intn(4) {
					case 0:
						es = append(es, ordered.Entry{Kind: ordered.Suffix, Value: names[rng.Intn(len(names))]})
					case 1:
						es = append(es, ordered.Entry{Kind: ordered.Exact, Value: names[rng.Intn(len(names))]})
					case 2:
						es = append(es, ordered.Entry{Kind: ordered.Sub, Value: names[rng.Intn(len(names))]})
					default:
						es = append(es, ordered.Entry{Kind: ordered.CIDR, Prefix: netip.MustParsePrefix(cidrs[rng.Intn(len(cidrs))])})
					}
				}
				rd.RuleSets[rsID] = es
			default:
				r = rr(id, model.MatchGeoIP, "CN", "")
			}
			switch rng.Intn(6) {
			case 0:
				r.TargetAction = model.ActionDirect
			case 1:
				r.TargetAction = model.ActionReject
			case 2:
				r.TargetService = "svc-ai"
			default:
				r.TargetGroup = groups[rng.Intn(len(groups))]
			}
			rules = append(rules, r)
			ref = append(ref, ordered.Rule{ID: id, Entries: es, GeoIPCN: r.MatchType == model.MatchGeoIP})
		}
		topo := orderedTopo(rules)
		topo.ServiceGroups = base.ServiceGroups
		topo.RuleSets = rsets
		b, err := Compile(topo)
		if err != nil {
			t.Fatalf("compile: %v", err)
		}
		exits, gps := plans(t, topo)
		rps := planRules(topo, exits, gps, nil)
		markOf := map[string]uint32{}
		for _, rp := range rps {
			markOf[rp.Rule.ID] = rp.Mark
		}
		for i := range ref {
			ref[i].Target = fmt.Sprint(markOf[ref[i].ID])
		}
		g := parseRendered(t, b, rd)
		// The serialized list a name-deciding process loads.
		dec, err := ordered.LoadSnapshot([]byte(b.File("nodes/gw"+DecidePath)), rd, china)
		if err != nil {
			t.Fatal(err)
		}
		tail := ordered.Tail{Domestic: []string{"cn.example.org"}, China: china, DirectTarget: fmt.Sprint(markDomestic), Default: fmt.Sprint(g.def)}
		learned := map[string]map[netip.Addr]bool{}
		next := 0
		addr := func() netip.Addr {
			next++
			switch next % 4 {
			case 0:
				return netip.AddrFrom4([4]byte{198, 51, 100, byte(next)})
			case 1:
				return netip.AddrFrom4([4]byte{192, 0, 2, byte(next)})
			case 2:
				return netip.AddrFrom4([4]byte{203, 0, 113, byte(next)})
			}
			return netip.AddrFrom4([4]byte{100, 70, byte(next), 1})
		}
		for _, n := range append(names, "zz.example.net", "q.b.a.example.net", "w.cn.example.org", "") {
			q := ordered.Query{Name: n, Addr: addr()}
			want := ordered.Reference(ref, tail, q)
			got := g.classify(learned, n, q.Addr, china)
			if fmt.Sprint(got) != want.Target {
				for i, r := range rules {
					t.Logf("rule %d %s %s %s target=%+v entries=%v", i, r.ID, r.MatchType, r.MatchValue, topo.ResolveTarget(r), ref[i].Entries)
				}
				t.Fatalf("probe %+v: rendered mark %#x, reference rule %d (%s) %s", q, got, want.Index, want.Target, want.Reason)
			}
			if d := dec.Decide(ordered.Request{Name: q.Name, Addr: q.Addr}); d.Mark != got {
				t.Fatalf("probe %+v: Decide on decide.json mark %#x (%s), rendered gateway %#x", q, d.Mark, d.Reason, got)
			}
			probes++
		}
		cases++
	}
	t.Logf("%d compiled rule lists, %d probes: rendered gateway == reference", cases, probes)
}

// The reject and QUIC artefacts.
func TestRejectDirectServiceAndQUICRender(t *testing.T) {
	rules := []model.Rule{
		rr("ai", model.MatchSuffix, "ai.example.net", ""),
		{ID: "quic", Name: "QUIC", Enabled: true, MatchType: model.MatchQUICReject},
		rr("ads", model.MatchSuffix, "ads.example.net", ""),
		rr("home", model.MatchSuffix, "home.example.net", ""),
		rr("vid", model.MatchSuffix, "video.example.org", "hk"),
	}
	rules[0].TargetService = "svc-ai"
	rules[2].TargetAction = model.ActionReject
	rules[3].TargetAction = model.ActionDirect
	topo := orderedTopo(rules)
	topo.ServiceGroups = []model.ServiceGroup{{ID: "svc-ai", Name: "AI", TargetGroup: "us"}}
	b, err := Compile(topo)
	if err != nil {
		t.Fatal(err)
	}
	nft := b.File("nodes/gw/etc/nftables.d/meridian.nft")
	guard := b.File("nodes/gw/etc/nftables.d/meridian-guard.nft")
	if l := resolverLine(t, b, "x.ads.example.net"); !strings.Contains(l, "-address #6") || strings.Contains(l, "#6:inet") || strings.Contains(l, "-nameserver domestic") {
		t.Fatalf("reject rule resolver line: %s", l)
	}
	if l := resolverLine(t, b, "home.example.net"); !strings.Contains(l, "-nameserver domestic") {
		t.Fatalf("direct rule resolver line: %s", l)
	}
	exits, gps := plans(t, topo)
	us := mustGroup(t, gps, "us")
	if l := resolverLine(t, b, "ai.example.net"); !strings.Contains(l, "-nameserver "+us.DNSGroup+" ") {
		t.Fatalf("service group rule not resolved by its group: %s (want %s)", l, us.DNSGroup)
	}
	rps := planRules(topo, exits, gps, nil)
	if rps[0].Mark != us.Mark || rps[2].Mark != markReject || rps[3].Mark != markDomestic || !rps[1].QUIC {
		t.Fatalf("marks %+v", rps)
	}
	for _, want := range []string{
		"meta mark 0x65 meta l4proto tcp reject with tcp reset",
		"meta mark 0x65 reject with icmpx port-unreachable",
	} {
		if !strings.Contains(guard, want) || !strings.Contains(nft, want) {
			t.Fatalf("guard lacks %q", want)
		}
	}
	// The reject lines come before the fail-closed drop.
	if strings.Index(guard, "reject with tcp reset") > strings.Index(guard, "fail closed") {
		t.Fatal("reject after the final drop")
	}
	// QUIC: the rule above the switch is exempt, the reject covers exit marks.
	q := nft[strings.Index(nft, "  chain quic {"):]
	q = q[:strings.Index(q, "\n  }\n")]
	if !strings.Contains(q, "udp dport 443 ip daddr @r0 return") || strings.Contains(q, "@r1 ") || strings.Contains(q, "@r2 ") {
		t.Fatalf("exemptions wrong:\n%s", q)
	}
	if !strings.Contains(q, fmt.Sprintf("meta mark %#x-%#x udp dport 443 reject with icmpx port-unreachable", markExitBase, guardLastExitMark(exits, gps...))) {
		t.Fatalf("no QUIC reject:\n%s", q)
	}
	if !strings.Contains(q, `iifname "`) {
		t.Fatal("QUIC chain not limited to the managed ingress")
	}
	// Without the features nothing of it is rendered.
	plain, err := Compile(defaults.Example())
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{"nodes/gw/etc/nftables.d/meridian.nft", "nodes/gw/etc/nftables.d/meridian-guard.nft"} {
		if strings.Contains(plain.File(f), "chain quic") || strings.Contains(plain.File(f), "0x65") {
			t.Fatalf("%s carries reject/QUIC without rules using them", f)
		}
	}
}

// Rules win over the built-in domestic list, in both directions of
// specificity, and gs_apple is gone.
func TestRulesBeforeDomesticList(t *testing.T) {
	rules := []model.Rule{
		rr("a", model.MatchSuffix, "apple.example", "us"),
		rr("b", model.MatchDomain, "direct-host.apple.example", ""),
	}
	rules[1].TargetAction = model.ActionDirect
	// b is under a: dead (a matches it first).
	b, err := Compile(orderedTopo(rules))
	if err != nil {
		t.Fatal(err)
	}
	conf := b.File("nodes/gw/etc/smartdns/smartdns.conf")
	if strings.Contains(conf, "gs_apple") || strings.Contains(conf, "apple.txt") {
		t.Fatal("built-in Apple-direct still rendered")
	}
	rd := ordered.MemReader{Geo: map[string][]string{"cn": {"apple.example", "cdn.apple.example", "pure.cn.example"}}}
	g := parseRendered(t, b, rd)
	for name, want := range map[string]string{
		"apple.example":             "r0",
		"cdn.apple.example":         "r0", // in the domestic list too: the rule wins
		"direct-host.apple.example": "r0", // later rule shadowed
		"pure.cn.example":           "gs_cn",
	} {
		if got := g.dns.Lookup(name); got != want {
			t.Errorf("%s -> %s, want %s", name, got, want)
		}
	}
	if g.derived.Stats["gs_cn"].Shadowed != 2 {
		t.Fatalf("domestic stats %+v", g.derived.Stats["gs_cn"])
	}
}

// A name an explicit proxy rule covers never lands in the domestic (direct)
// sets, even when the built-in domestic list also lists it and the exit's
// resolver answers with a China address: the resolver writes the answer
// into the rule's set, and the classify chain checks the rule's set before
// direct4 and chnroute, so the connection keeps the rule's mark.
func TestProxyRuleNameNeverDirect(t *testing.T) {
	rules := []model.Rule{rr("p", model.MatchSuffix, "proxied.example", "us")}
	tp := orderedTopo(rules)
	b, err := Compile(tp)
	if err != nil {
		t.Fatal(err)
	}
	rd := ordered.MemReader{Geo: map[string][]string{"cn": {"proxied.example", "www.proxied.example", "plain.cn.example"}}}
	g := parseRendered(t, b, rd)
	china := []netip.Prefix{netip.MustParsePrefix("203.0.113.0/24")}
	// The derived domestic set no longer holds the rule's names.
	for _, l := range g.derived.Files["gs_cn"] {
		if strings.Contains(l, "proxied.example") {
			t.Fatalf("domestic set still lists %q", l)
		}
	}
	marks := map[string]uint32{}
	pos := map[string]int{}
	for i, c := range g.chain {
		marks[c.set], pos[c.set] = c.mark, i
	}
	set := g.setOf[g.dns.Lookup("www.proxied.example")]
	if set == "" || set == "direct4" {
		t.Fatalf("www.proxied.example resolves into %q", set)
	}
	for _, tail := range []string{"direct4", "chnroute"} {
		if _, ok := pos[tail]; !ok {
			t.Fatalf("no %s in the classify chain", tail)
		}
		if pos[set] > pos[tail] {
			t.Fatalf("rule set %s after %s in the chain", set, tail)
		}
	}
	learned := map[string]map[netip.Addr]bool{}
	cnAddr := netip.MustParseAddr("203.0.113.9")
	for _, name := range []string{"proxied.example", "www.proxied.example"} {
		got := g.classify(learned, name, cnAddr, china)
		if got != marks[set] || got == marks["direct4"] || got == marks["chnroute"] {
			t.Fatalf("%s at a China address: mark %#x, rule %#x, direct %#x", name, got, marks[set], marks["direct4"])
		}
	}
	if learned["direct4"][cnAddr] {
		t.Fatal("the address entered the direct set")
	}
	// The same address with no rule in front is direct (the chnroute tail).
	if got := g.classify(map[string]map[netip.Addr]bool{}, "", netip.MustParseAddr("203.0.113.77"), china); got != marks["chnroute"] {
		t.Fatalf("unlisted China address: %#x", got)
	}
	// A domestic-only name still goes to the domestic set.
	if s := g.setOf[g.dns.Lookup("plain.cn.example")]; s != "direct4" {
		t.Fatalf("domestic name -> %q", s)
	}
}

// unlisted_domestic_dns is off by default and nothing in the rendered
// gateway depends on it: the example topology renders no dns-split service
// and the same resolver configuration whether the field is absent or false.
func TestUnlistedDomesticDNSDefaultOff(t *testing.T) {
	tp := defaults.Example()
	if tp.Settings.UnlistedDomesticDNS {
		t.Fatal("unlisted_domestic_dns on in the defaults")
	}
	tp.Rules = []model.Rule{rr("p", model.MatchSuffix, "proxied.example", "us")}
	tp.RulesOrdered = true
	b, err := Compile(tp)
	if err != nil {
		t.Fatal(err)
	}
	for f := range b.Files {
		if strings.Contains(f, "dns-split") {
			t.Fatalf("dns-split rendered with the setting off: %s", f)
		}
	}
	if SmartDNSUsesDNSSplit(b.File("nodes/gw/etc/smartdns/smartdns.conf")) {
		t.Fatal("SmartDNS sends names to dns-split with the setting off")
	}
	// Turning it on adds the service; the ordered rules' resolver lines
	// do not change.
	on := tp
	on.Settings.UnlistedDomesticDNS = true
	b2, err := Compile(on)
	if err != nil {
		t.Fatal(err)
	}
	if resolverLine(t, b, "proxied.example") != resolverLine(t, b2, "proxied.example") {
		t.Fatal("a rule's resolver line depends on unlisted_domestic_dns")
	}
}

// TestRuleSetAddressSetsAreDeclared: every address set the manifest names
// (the host's derive step flushes and fills each of them in one nft batch)
// is declared in the gateway ruleset, for targets with and without IPv6.
// On a real gateway the manifest named the IPv6 set of rule-set rules whose
// target carries no IPv6; the ruleset did not declare it, the batch failed
// and the install was rolled back.
func TestRuleSetAddressSetsAreDeclared(t *testing.T) {
	topo := defaults.Example()
	var rules []model.Rule
	rd := ordered.MemReader{RuleSets: map[string][]ordered.Entry{}}
	var targets []string
	for _, g := range topo.Groups {
		targets = append(targets, g.ID)
	}
	for i, g := range targets {
		id := fmt.Sprintf("rs-%d", i)
		r := rr(fmt.Sprintf("r-%d", i), model.MatchRuleSet, "", g)
		r.RuleSet = id
		rules = append(rules, r)
		topo.RuleSets = append(topo.RuleSets, model.RuleSet{ID: id, Name: id, URL: "https://example.org/" + id + ".list"})
		rd.RuleSets[id] = []ordered.Entry{
			{Kind: ordered.Suffix, Value: fmt.Sprintf("s%d.example", i)},
			{Kind: ordered.CIDR, Prefix: netip.MustParsePrefix(fmt.Sprintf("198.51.100.%d/32", i+1))},
			{Kind: ordered.CIDR, Prefix: netip.MustParsePrefix(fmt.Sprintf("2001:db8:%x::/48", i+1))},
		}
	}
	topo.Rules, topo.RulesOrdered = rules, true
	b, err := Compile(topo)
	if err != nil {
		t.Fatal(err)
	}
	m, err := ordered.ParseManifest([]byte(b.File("nodes/gw/etc/meridian/rules/order.conf")))
	if err != nil {
		t.Fatal(err)
	}
	d, err := ordered.Derive(m, rd)
	if err != nil {
		t.Fatal(err)
	}
	nft := b.File("nodes/gw/etc/nftables.d/meridian.nft")
	v4only, dual := 0, 0
	for _, s := range m.Sets {
		if s.CIDR4 == "" {
			continue
		}
		// Coverage is read from the ruleset, not from the manifest under test.
		if strings.Contains(nft, "  set "+s.CIDR4+"6 {") {
			dual++
		} else {
			v4only++
		}
	}
	if v4only == 0 || dual == 0 {
		t.Fatalf("the example topology no longer covers both cases (IPv4-only targets: %d, dual-stack: %d)", v4only, dual)
	}
	if len(d.CIDR) == 0 {
		t.Fatal("no address sets derived")
	}
	for name := range d.CIDR {
		if !strings.Contains(nft, "  set "+name+" {") {
			t.Errorf("the derive batch fills set %s, which the gateway ruleset does not declare", name)
		}
	}
}

// exclusionLines is the stored form of exclusions (model.RuleSet.Exclude).
func exclusionLines(es []ordered.Entry) []string {
	var out []string
	for _, e := range es {
		out = append(out, ruleset.ExclusionLine(e))
	}
	return out
}

// TestRuleSetExclusionsRenderedMatchReference: generated rule lists made
// mostly of rule-sets with exclusions (equal to an entry, broader, narrower,
// keyword, covering/equal/narrower CIDRs, stale), shadowing between the
// sets and later sets that list excluded names exactly, compiled for the
// example gateway. For every probe — names that hit an excluded entry, sit
// beside one, sit under a narrower exclusion or fall to a later set — the
// mark from the rendered artefacts (manifest derived on the "host" with its
// exclusion lines, SmartDNS longest-key model, nft classify chain with the
// derived address sets) and the decision from decide.json equal the strict
// first-match reference with the exclusions applied by definition
// (ordered.Reference, Rule.Exclude).
func TestRuleSetExclusionsRenderedMatchReference(t *testing.T) {
	rng := rand.New(rand.NewSource(1114))
	names := []string{"example.net", "a.example.net", "b.a.example.net", "c.example.net", "d.c.example.net", "example.org", "x.example.org", "y.x.example.org", "cn.example.org"}
	cidrs := []string{"198.51.100.0/24", "198.51.100.0/25", "198.51.100.64/26", "198.51.100.96/27", "203.0.113.0/24", "203.0.113.64/26"}
	groups := []string{"us", "hk", "jp", "tw"}
	china := []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24")}
	entry := func() ordered.Entry {
		switch rng.Intn(7) {
		case 0, 1:
			return ordered.Entry{Kind: ordered.Suffix, Value: names[rng.Intn(len(names))]}
		case 2, 3:
			return ordered.Entry{Kind: ordered.Exact, Value: names[rng.Intn(len(names))]}
		case 4:
			return ordered.Entry{Kind: ordered.Sub, Value: names[rng.Intn(len(names))]}
		}
		return ordered.Entry{Kind: ordered.CIDR, Prefix: netip.MustParsePrefix(cidrs[rng.Intn(len(cidrs))])}
	}
	cases, probes, changed := 0, 0, 0
	for iter := 0; iter < 300; iter++ {
		var rules []model.Rule
		var ref, raw []ordered.Rule
		rd := ordered.MemReader{RuleSets: map[string][]ordered.Entry{}, Geo: map[string][]string{"cn": {"cn.example.org"}}}
		var rsets []model.RuleSet
		for i, n := 0, 2+rng.Intn(5); i < n; i++ {
			id := fmt.Sprintf("r-%d", i)
			var r model.Rule
			var es, excl []ordered.Entry
			if rng.Intn(4) == 0 {
				v := names[rng.Intn(len(names))]
				r = rr(id, model.MatchDomain, v, "")
				es = []ordered.Entry{{Kind: ordered.Exact, Value: v}}
			} else {
				rsID := fmt.Sprintf("rs-%d", i)
				r = rr(id, model.MatchRuleSet, "", "")
				r.RuleSet = rsID
				for k := 1 + rng.Intn(5); k > 0; k-- {
					es = append(es, entry())
				}
				for k := rng.Intn(4); k > 0; k-- {
					switch rng.Intn(4) {
					case 0:
						excl = append(excl, es[rng.Intn(len(es))])
					case 1:
						excl = append(excl, ordered.Entry{Kind: ordered.Keyword, Value: []string{"a.ex", "x.ex", "org"}[rng.Intn(3)]})
					default:
						excl = append(excl, entry())
					}
				}
				// The panel stores (and compile reads) the classical form.
				stored := exclusionLines(excl)
				excl = ruleset.ExclusionEntries(stored)
				rsets = append(rsets, model.RuleSet{ID: rsID, Name: rsID, URL: "https://example.org/" + rsID + ".list", Exclude: stored})
				rd.RuleSets[rsID] = es
			}
			switch rng.Intn(5) {
			case 0:
				r.TargetAction = model.ActionDirect
			case 1:
				r.TargetAction = model.ActionReject
			default:
				r.TargetGroup = groups[rng.Intn(len(groups))]
			}
			rules = append(rules, r)
			ref = append(ref, ordered.Rule{ID: id, Entries: es, Exclude: excl})
			raw = append(raw, ordered.Rule{ID: id, Entries: es})
		}
		topo := orderedTopo(rules)
		topo.RuleSets = rsets
		b, err := Compile(topo)
		if err != nil {
			t.Fatalf("compile: %v", err)
		}
		exits, gps := plans(t, topo)
		markOf := map[string]uint32{}
		for _, rp := range planRules(topo, exits, gps, nil) {
			markOf[rp.Rule.ID] = rp.Mark
		}
		for i := range ref {
			ref[i].Target = fmt.Sprint(markOf[ref[i].ID])
			raw[i].Target = ref[i].Target
		}
		g := parseRendered(t, b, rd)
		dec, err := ordered.LoadSnapshot([]byte(b.File("nodes/gw"+DecidePath)), rd, china)
		if err != nil {
			t.Fatal(err)
		}
		tail := ordered.Tail{Domestic: []string{"cn.example.org"}, China: china, DirectTarget: fmt.Sprint(markDomestic), Default: fmt.Sprint(g.def)}
		learned := map[string]map[netip.Addr]bool{}
		next := 0
		addr := func() netip.Addr {
			next++
			switch next % 4 {
			case 0, 2:
				return netip.AddrFrom4([4]byte{198, 51, 100, byte(next)})
			case 1:
				return netip.AddrFrom4([4]byte{203, 0, 113, byte(next)})
			}
			return netip.AddrFrom4([4]byte{100, 70, byte(next), 1})
		}
		var all []string
		for _, n := range names {
			all = append(all, n, "zz."+n)
		}
		for _, n := range append(all, "", "", "", "") {
			q := ordered.Query{Name: n, Addr: addr()}
			want := ordered.Reference(ref, tail, q)
			if ordered.Reference(raw, tail, q).Target != want.Target {
				changed++
			}
			got := g.classify(learned, n, q.Addr, china)
			if fmt.Sprint(got) != want.Target {
				for i, r := range ref {
					t.Logf("rule %d %s %s mark=%s entries=%v exclude=%v", i, rules[i].ID, rules[i].MatchType, r.Target, r.Entries, r.Exclude)
				}
				t.Fatalf("probe %+v: rendered mark %#x, reference rule %d (%s) %s", q, got, want.Index, want.Target, want.Reason)
			}
			if d := dec.Decide(ordered.Request{Name: q.Name, Addr: q.Addr}); d.Mark != got {
				t.Fatalf("probe %+v: Decide on decide.json mark %#x (%s), rendered gateway %#x", q, d.Mark, d.Reason, got)
			}
			probes++
		}
		cases++
	}
	if changed < probes/40 {
		t.Fatalf("exclusions changed only %d of %d decisions", changed, probes)
	}
	t.Logf("%d compiled lists, %d probes (%d decided differently because of exclusions): rendered gateway == decide.json == reference", cases, probes, changed)
}

// TestRuleSetExclusionsCompileCheck compiles a list of more rule-set rules
// than the set-name collision threshold, with and without exclusions, with
// the forwarder on, and checks the two places names are derived agree:
// every nft set is declared exactly once; every set the manifest names
// (domain-set and address sets) is declared by the resolver config and the
// ruleset; the manifest and decide.json carry the same rule-sets with the
// same exclusions in the same order; the forwarder accepts the compiled
// pair. Exclusions change the manifest, decide.json and the forwarder's
// target file (which pins decide.json's digest) and nothing else.
func TestRuleSetExclusionsCompileCheck(t *testing.T) {
	build := func(withExcl bool) (model.Topology, ordered.MemReader) {
		topo := sniffOn(defaults.Example())
		rd := ordered.MemReader{RuleSets: map[string][]ordered.Entry{}}
		var targets []string
		for _, g := range topo.Groups {
			targets = append(targets, g.ID)
		}
		for i := 0; i < 24; i++ {
			id := fmt.Sprintf("rs-%d", i)
			r := rr(fmt.Sprintf("r-%d", i), model.MatchRuleSet, "", targets[i%len(targets)])
			r.RuleSet = id
			if i == 3 {
				r.Domains = []string{"own.example.org"}
			}
			topo.Rules = append(topo.Rules, r)
			rs := model.RuleSet{ID: id, Name: id, URL: "https://example.org/" + id + ".list"}
			if withExcl && i%3 == 0 {
				rs.Exclude = []string{"DOMAIN-SUFFIX,big" + fmt.Sprint(i) + ".example", "IP-CIDR,198.51.100.0/26", "DOMAIN-KEYWORD,ads", "DOMAIN,gone.example"}
				if i == 3 {
					// Would remove the rule's own name if it applied to it.
					rs.Exclude = append(rs.Exclude, "DOMAIN-SUFFIX,example.org")
				}
			}
			topo.RuleSets = append(topo.RuleSets, rs)
			rd.RuleSets[id] = []ordered.Entry{
				{Kind: ordered.Suffix, Value: fmt.Sprintf("s%d.example", i)},
				{Kind: ordered.Suffix, Value: fmt.Sprintf("big%d.example", i)},
				{Kind: ordered.Exact, Value: fmt.Sprintf("x.big%d.example", i)},
				{Kind: ordered.CIDR, Prefix: netip.MustParsePrefix("198.51.100.0/24")},
				{Kind: ordered.CIDR, Prefix: netip.MustParsePrefix(fmt.Sprintf("2001:db8:%x::/48", i+1))},
			}
		}
		topo.RulesOrdered = true
		return topo, rd
	}
	plainTopo, _ := build(false)
	topo, rd := build(true)
	plain := mustCompile(t, plainTopo)
	b := mustCompile(t, topo)
	gw := "nodes/gw/"
	manifestPath := gw + strings.TrimPrefix(lists.ManifestPath, "/")
	decidePath := gw + strings.TrimPrefix(DecidePath, "/")
	targetsPath := gw + strings.TrimPrefix(SniffTargetsPath, "/")
	for k, v := range b.Files {
		if plain.Files[k] != v && k != manifestPath && k != decidePath && k != targetsPath {
			t.Errorf("exclusions changed %s", k)
		}
	}
	if len(plain.Files) != len(b.Files) {
		t.Fatal("exclusions changed the file set")
	}
	if strings.Contains(plain.File(manifestPath), "exclude-") || strings.Contains(plain.File(decidePath), "exclude") {
		t.Fatal("exclusion text without exclusions")
	}
	nft := b.File(gw + "etc/nftables.d/meridian.nft")
	declared := map[string]int{}
	for _, m := range regexp.MustCompile(`(?m)^  set (\S+) \{`).FindAllStringSubmatch(nft, -1) {
		declared[m[1]]++
	}
	for n, c := range declared {
		if c != 1 {
			t.Errorf("set %s declared %d times", n, c)
		}
	}
	conf := b.File(gw + "etc/smartdns/smartdns.conf")
	m, err := ordered.ParseManifest([]byte(b.File(manifestPath)))
	if err != nil {
		t.Fatal(err)
	}
	type rsRef struct{ id, excl string }
	var fromManifest []rsRef
	for _, s := range m.Sets {
		if s.Name != "gs_cn" && !strings.Contains(conf, "domain-set -name "+s.Name+" ") {
			t.Errorf("manifest set %s has no domain-set in the resolver config", s.Name)
		}
		for _, n := range []string{s.CIDR4, s.CIDR6} {
			if n != "" && declared[n] != 1 {
				t.Errorf("manifest address set %s declared %d times", n, declared[n])
			}
		}
		for _, src := range s.Srcs {
			if src.Kind == ordered.SrcRuleSet {
				fromManifest = append(fromManifest, rsRef{src.Value, string(ordered.MarshalEntries(src.Exclude))})
			}
		}
	}
	var snap ordered.Snapshot
	if err := json.Unmarshal([]byte(b.File(decidePath)), &snap); err != nil {
		t.Fatal(err)
	}
	var fromSnapshot []rsRef
	for _, r := range snap.Rules {
		for _, src := range r.Sources {
			if src.Kind == ordered.SrcRuleSet {
				fromSnapshot = append(fromSnapshot, rsRef{src.Value, string(ordered.MarshalEntries(src.Exclude))})
			}
		}
	}
	if fmt.Sprint(fromManifest) != fmt.Sprint(fromSnapshot) || len(fromManifest) != 24 {
		t.Fatalf("manifest and decide.json disagree:\n%v\n%v", fromManifest, fromSnapshot)
	}
	withExcl := 0
	for _, x := range fromManifest {
		if x.excl != "\n" {
			withExcl++
		}
	}
	if withExcl != 8 {
		t.Fatalf("%d rule-sets carry exclusions", withExcl)
	}
	d, err := ordered.Derive(m, rd)
	if err != nil {
		t.Fatal(err)
	}
	for name := range d.CIDR {
		if declared[name] != 1 {
			t.Errorf("the derive batch fills set %s, declared %d times", name, declared[name])
		}
	}
	// The exclusions took effect on the host's output: rule r-0's
	// domain-set has no big0.example key, its IPv4 address set lost
	// 198.51.100.0/26 (r-1 has no exclusions, but r-0 owns its address
	// range already: list order).
	exits, gps := plans(t, topo)
	setOf := map[string]rulePlan{}
	for _, rp := range planRules(topo, exits, gps, nil) {
		setOf[rp.Rule.ID] = rp
	}
	r0, r1, r3 := setOf["r-0"], setOf["r-1"], setOf["r-3"]
	if strings.Contains(strings.Join(d.Files[r0.Set4], " "), "big0.example") || !strings.Contains(strings.Join(d.Files[r1.Set4], " "), "big1.example") {
		t.Fatalf("%s %v %s %v", r0.Set4, d.Files[r0.Set4], r1.Set4, d.Files[r1.Set4])
	}
	if fmt.Sprint(d.CIDR[r0.CIDR4]) != "[198.51.100.64/26 198.51.100.128/25]" {
		t.Fatalf("%s %v", r0.CIDR4, d.CIDR[r0.CIDR4])
	}
	// Rule r-3's own explicit name is not a rule-set entry: no exclusion
	// touches it.
	if !strings.Contains(strings.Join(d.Files[r3.Set4], " "), "own.example.org") {
		t.Fatalf("%s %v", r3.Set4, d.Files[r3.Set4])
	}
	// The forwarder accepts the compiled pair and decides with the
	// exclusions applied.
	var tf sniff.TargetsFile
	if err := json.Unmarshal([]byte(b.File(targetsPath)), &tf); err != nil {
		t.Fatal(err)
	}
	c, err := ordered.LoadSnapshot([]byte(b.File(decidePath)), rd, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := sniff.New(sniff.Config{}).Install(c, tf.Targets); err != nil {
		t.Fatal(err)
	}
	if d := c.Decide(ordered.Request{Name: "q.big0.example", Addr: netip.MustParseAddr("100.70.0.1")}); d.ID == "r-0" {
		t.Fatalf("excluded name decided by its set: %+v", d)
	}
	if d := c.Decide(ordered.Request{Name: "q.big1.example", Addr: netip.MustParseAddr("100.70.0.1")}); d.ID != "r-1" {
		t.Fatalf("%+v", d)
	}
	if d := c.Decide(ordered.Request{Name: "q.own.example.org", Addr: netip.MustParseAddr("100.70.0.1")}); d.ID != "r-3" {
		t.Fatalf("the rule's own name was excluded: %+v", d)
	}
}
