package compile

import (
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
