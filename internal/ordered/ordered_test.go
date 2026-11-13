package ordered

import (
	"fmt"
	"math/rand"
	"net/netip"
	"testing"
)

func sfx(v string) Entry   { return Entry{Kind: Suffix, Value: v} }
func exact(v string) Entry { return Entry{Kind: Exact, Value: v} }
func kw(v string) Entry    { return Entry{Kind: Keyword, Value: v} }
func cidr(v string) Entry  { return Entry{Kind: CIDR, Prefix: netip.MustParsePrefix(v).Masked()} }

var testTail = Tail{
	Domestic:     []string{"cn.example", "shared.example"},
	China:        []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24")},
	DirectTarget: "DIRECT",
	Default:      "MATCH",
}

// gatewayFor compiles rules with Plan + Derive into the data-plane model.
func gatewayFor(t *testing.T, rules []Rule, tail Tail) *Gateway {
	t.Helper()
	m, chain, rd := Plan(rules, tail)
	// Round-trip the manifest text: the host parses what compile renders.
	pm, err := ParseManifest([]byte(m.Render()))
	if err != nil {
		t.Fatalf("manifest: %v\n%s", err, m.Render())
	}
	d, err := Derive(pm, rd)
	if err != nil {
		t.Fatal(err)
	}
	g, err := NewGateway(d, chain, tail)
	if err != nil {
		t.Fatal(err)
	}
	return g
}

func check(t *testing.T, rules []Rule, tail Tail, qs []Query) {
	t.Helper()
	g := gatewayFor(t, rules, tail)
	for _, q := range qs {
		want := Reference(rules, tail, q)
		got := g.Query(q)
		if want.Index != got.Index || want.Target != got.Target {
			t.Errorf("%+v: reference rule %d (%s, %s), gateway rule %d (%s)", q, want.Index, want.Target, want.Reason, got.Index, got.Target)
		}
	}
}

var nextAddr = 0

func addr() netip.Addr {
	nextAddr++
	return netip.AddrFrom4([4]byte{203, 0, byte(113 + nextAddr/250), byte(nextAddr % 250)})
}

func q(name string) Query { return Query{Name: name, Addr: addr()} }

// The shapes of an operator's mihomo list, written as synthetic rules.
func TestHandWrittenShapes(t *testing.T) {
	cases := []struct {
		name  string
		rules []Rule
		qs    []Query
	}{
		{"duplicate suffix, first wins", []Rule{
			{Target: "A", Entries: []Entry{sfx("dup.example")}},
			{Target: "B", Entries: []Entry{sfx("dup.example")}},
		}, []Query{q("dup.example"), q("x.dup.example")}},
		{"specific before general", []Rule{
			{Target: "A", Entries: []Entry{sfx("a.b.example")}},
			{Target: "B", Entries: []Entry{sfx("b.example")}},
		}, []Query{q("a.b.example"), q("x.a.b.example"), q("b.example"), q("c.b.example")}},
		{"general before specific (specific is dead)", []Rule{
			{Target: "B", Entries: []Entry{sfx("b.example")}},
			{Target: "A", Entries: []Entry{sfx("a.b.example")}},
		}, []Query{q("a.b.example"), q("x.a.b.example"), q("b.example")}},
		{"single-domain exception before the rule-set that contains it", []Rule{
			{Target: "PROXY", Entries: []Entry{exact("one.dom.example")}},
			{Target: "DIRECT", Entries: []Entry{sfx("dom.example"), sfx("other.example"), exact("x.example")}},
		}, []Query{q("one.dom.example"), q("sub.one.dom.example"), q("dom.example"), q("x.example"), q("y.x.example")}},
		{"exact then suffix on the same name", []Rule{
			{Target: "A", Entries: []Entry{exact("same.example")}},
			{Target: "B", Entries: []Entry{sfx("same.example")}},
		}, []Query{q("same.example"), q("w.same.example")}},
		{"suffix then exact on the same name", []Rule{
			{Target: "B", Entries: []Entry{sfx("same.example")}},
			{Target: "A", Entries: []Entry{exact("same.example")}},
		}, []Query{q("same.example"), q("w.same.example")}},
		{"IP rule between domain rules", []Rule{
			{Target: "A", Entries: []Entry{sfx("first.example")}},
			{Target: "IP", Entries: []Entry{cidr("198.51.100.0/24")}},
			{Target: "C", Entries: []Entry{sfx("third.example")}},
		}, []Query{
			{Name: "first.example", Addr: netip.MustParseAddr("198.51.100.1")},
			{Name: "third.example", Addr: netip.MustParseAddr("198.51.100.2")},
			{Name: "third.example", Addr: netip.MustParseAddr("198.18.0.3")},
			{Addr: netip.MustParseAddr("198.51.100.9")},
		}},
		{"rules before the domestic list", []Rule{
			{Target: "PROXY", Entries: []Entry{sfx("app.cn.example")}},
			{Target: "PROXY2", Entries: []Entry{sfx("shared.example")}},
		}, []Query{q("app.cn.example"), q("cn.example"), q("z.cn.example"), q("shared.example"), q("a.shared.example")}},
		{"China address after the rules, before the default", []Rule{
			{Target: "PROXY", Entries: []Entry{sfx("p.example")}},
		}, []Query{
			{Name: "p.example", Addr: netip.MustParseAddr("192.0.2.7")},
			{Name: "u.example", Addr: netip.MustParseAddr("192.0.2.8")},
			{Name: "u2.example", Addr: netip.MustParseAddr("198.18.1.1")},
		}},
		{"GEOIP,CN in the middle", []Rule{
			{Target: "A", Entries: []Entry{sfx("a.example")}},
			{Target: "CNRULE", GeoIPCN: true},
			{Target: "C", Entries: []Entry{sfx("c.example")}},
		}, []Query{
			{Name: "a.example", Addr: netip.MustParseAddr("192.0.2.1")},
			{Name: "c.example", Addr: netip.MustParseAddr("192.0.2.2")},
			{Name: "c.example", Addr: netip.MustParseAddr("198.18.2.2")},
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) { check(t, c.rules, testTail, c.qs) })
	}
}

// Keyword entries are not expressible in SmartDNS: the analysis reports
// them and the data plane does not match them, so the gateway differs from
// the reference exactly there. This test pins that (the panel blocks such
// rules unless the operator accepts the stated alternative).
func TestKeywordIsNotExecuted(t *testing.T) {
	rules := []Rule{
		{Target: "AI", Entries: []Entry{kw("vendor")}},
		{Target: "B", Entries: []Entry{sfx("example")}},
	}
	a := Analyze(rules)
	if a[0].Keywords != 1 {
		t.Fatalf("keyword not reported: %+v", a[0])
	}
	g := gatewayFor(t, rules, testTail)
	qq := q("api.vendor.example")
	if Reference(rules, testTail, qq).Index != 0 || g.Query(qq).Index != 1 {
		t.Fatal("expected the documented keyword difference")
	}
}

// Shared addresses: two names with different targets resolving to one
// address. The gateway decides by address, so the stated behaviour is: the
// earlier rule in list order among the rules that learned the address wins.
func TestSharedAddressEarlierRuleWins(t *testing.T) {
	rules := []Rule{
		{Target: "A", Entries: []Entry{sfx("one.example")}},
		{Target: "B", Entries: []Entry{sfx("two.example")}},
	}
	shared := netip.MustParseAddr("198.18.9.9")
	g := gatewayFor(t, rules, testTail)
	if got := g.Query(Query{Name: "two.example", Addr: shared}); got.Index != 1 {
		t.Fatalf("first lookup: %+v", got)
	}
	// one.example now also resolves to the shared address: from then on
	// connections to it (two.example's included) take rule 0.
	if got := g.Query(Query{Name: "one.example", Addr: shared}); got.Index != 0 {
		t.Fatalf("second lookup: %+v", got)
	}
	if got := g.Query(Query{Name: "two.example", Addr: shared}); got.Index != 0 {
		t.Fatalf("stated behaviour: earlier rule wins for the shared address, got %+v", got)
	}
	// Reversed order: the later-learned name's earlier rule still wins.
	g2 := gatewayFor(t, rules, testTail)
	g2.Query(Query{Name: "one.example", Addr: shared})
	if got := g2.Query(Query{Name: "two.example", Addr: shared}); got.Index != 0 {
		t.Fatalf("stated behaviour (other order), got %+v", got)
	}
}

func TestAnalyzeShadowing(t *testing.T) {
	rules := []Rule{
		{Target: "A", Entries: []Entry{sfx("b.example"), exact("x.example")}},
		{Target: "B", Entries: []Entry{sfx("a.b.example")}},
		{Target: "C", Entries: []Entry{sfx("example"), cidr("198.51.100.0/24")}},
		{Target: "D", Entries: []Entry{cidr("198.51.100.128/25"), cidr("198.51.0.0/16")}},
		{Target: "E", Entries: []Entry{kw("bex"), sfx("q.bexx.test")}},
	}
	a := Analyze(rules)
	if !a[1].FullyShadowed || len(a[1].ShadowedBy) != 1 || a[1].ShadowedBy[0] != 0 {
		t.Errorf("rule 1: %+v", a[1])
	}
	if a[2].FullyShadowed || len(a[2].PartlyBy) == 0 {
		t.Errorf("rule 2 should be partly taken by rule 0/1: %+v", a[2])
	}
	if a[3].Shadowed != 1 || len(a[3].PartlyBy) != 1 || a[3].PartlyBy[0] != 2 {
		t.Errorf("rule 3: %+v", a[3])
	}
	if a[4].Shadowed != 0 || a[4].Keywords != 1 {
		t.Errorf("rule 4: a keyword only shadows entries of later rules: %+v", a[4])
	}
}

// --------------------------------------------------- property tests ---

var labels = []string{"a", "b", "c"}

func universe() []string {
	var out []string
	for _, tld := range []string{"example", "test"} {
		out = append(out, tld)
		for _, l1 := range labels {
			n1 := l1 + "." + tld
			out = append(out, n1)
			for _, l2 := range labels {
				n2 := l2 + "." + n1
				out = append(out, n2)
				out = append(out, labels[0]+"."+n2)
			}
		}
	}
	return out
}

var cidrPool = []string{
	"198.51.100.0/24", "198.51.100.0/25", "198.51.100.128/26", "198.51.100.7/32",
	"198.51.0.0/16", "2001:db8:1::/48", "2001:db8:1:2::/64",
}

// TestDifferentialGenerated compares the reference interpreter and the data
// plane model on generated ordered lists. Every rule has 1-4 entries drawn
// from exact names, suffixes over a three-level universe (so duplicates,
// specific-before-general and general-before-specific, exact/suffix pairs
// on one name and single-name exceptions occur all the time), CIDRs that
// nest and overlap, and GEOIP,CN; the tail has a random domestic list.
// Probes: every universe name plus a child of it, each with a fresh
// address (one in four drawn from the CIDR pool so domain/IP crossings are
// exercised), and bare addresses.
func TestDifferentialGenerated(t *testing.T) {
	rng := rand.New(rand.NewSource(20261113))
	uni := universe()
	lists, probes := 0, 0
	for iter := 0; iter < 3000; iter++ {
		nRules := 1 + rng.Intn(8)
		var rules []Rule
		for i := 0; i < nRules; i++ {
			r := Rule{Target: fmt.Sprintf("T%d", rng.Intn(4))}
			if rng.Intn(12) == 0 {
				r.GeoIPCN = true
			}
			for k := 1 + rng.Intn(4); k > 0; k-- {
				switch rng.Intn(7) {
				case 6:
					r.Entries = append(r.Entries, Entry{Kind: Sub, Value: uni[rng.Intn(len(uni))]})
				case 0, 1:
					r.Entries = append(r.Entries, sfx(uni[rng.Intn(len(uni))]))
				case 2, 3:
					r.Entries = append(r.Entries, exact(uni[rng.Intn(len(uni))]))
				default:
					r.Entries = append(r.Entries, cidr(cidrPool[rng.Intn(len(cidrPool))]))
				}
			}
			rules = append(rules, r)
		}
		tail := testTail
		tail.Domestic = nil
		for k := rng.Intn(3); k > 0; k-- {
			tail.Domestic = append(tail.Domestic, uni[rng.Intn(len(uni))])
		}
		var qs []Query
		next := 0
		fresh := func() netip.Addr {
			next++
			if rng.Intn(4) == 0 {
				switch rng.Intn(4) {
				case 0:
					return netip.AddrFrom4([4]byte{198, 51, 100, byte(next)})
				case 1:
					return netip.AddrFrom4([4]byte{192, 0, 2, byte(next)})
				case 2:
					return netip.AddrFrom16([16]byte{0x20, 0x01, 0x0d, 0xb8, 0, 1, 0, 2, 0, 0, 0, 0, 0, 0, 0, byte(next)})
				default:
					return netip.AddrFrom4([4]byte{198, 51, byte(next), 1})
				}
			}
			return netip.AddrFrom4([4]byte{100, 64 + byte(next/250), byte(next % 250), 1})
		}
		for _, n := range uni {
			qs = append(qs, Query{Name: n, Addr: fresh()}, Query{Name: "zz." + n, Addr: fresh()})
		}
		for k := 0; k < 6; k++ {
			qs = append(qs, Query{Addr: fresh()})
		}
		check(t, rules, tail, qs)
		lists++
		probes += len(qs)
		if t.Failed() {
			for i, r := range rules {
				t.Logf("rule %d %s geoip=%v %v", i, r.Target, r.GeoIPCN, r.Entries)
			}
			t.Logf("domestic %v", tail.Domestic)
			return
		}
	}
	t.Logf("%d generated lists, %d probes, reference == gateway for every probe", lists, probes)
}

func TestManifestRejectsGarbage(t *testing.T) {
	for _, b := range []string{
		"set r0\n",
		ManifestHeader + "\nsuffix example.com\n",
		ManifestHeader + "\nset r0\nsuffix ../etc\n",
		ManifestHeader + "\nset r0\ngeosite ../x\n",
		ManifestHeader + "\nset r0\nruleset UP\n",
		ManifestHeader + "\nset r0\nset r0\n",
		ManifestHeader + "\nset r0\nexec rm\n",
	} {
		if _, err := ParseManifest([]byte(b)); err == nil {
			t.Errorf("accepted %q", b)
		}
	}
}

func TestMergePrefixes(t *testing.T) {
	in := []netip.Prefix{
		netip.MustParsePrefix("198.51.100.0/25"), netip.MustParsePrefix("198.51.100.128/25"),
		netip.MustParsePrefix("198.51.100.7/32"), netip.MustParsePrefix("10.0.0.0/8"), netip.MustParsePrefix("10.1.0.0/16"),
	}
	got := fmt.Sprint(MergePrefixes(in))
	if got != "[10.0.0.0/8 198.51.100.0/24]" {
		t.Fatal(got)
	}
}

// Large rule-sets: Derive stays fast and the result loads without duplicate
// keys.
func TestDeriveLarge(t *testing.T) {
	var es []Entry
	for i := 0; i < 60000; i++ {
		es = append(es, sfx(fmt.Sprintf("h%d.big%d.example", i, i%97)))
	}
	for i := 0; i < 20000; i++ {
		es = append(es, cidr(fmt.Sprintf("10.%d.%d.0/24", i/256, i%256)))
	}
	m := Manifest{Sets: []ManifestSet{{Name: "r0", CIDR4: "r0c", CIDR6: "r0c6"}, {Name: "gs_cn"}}}
	m.Sets[0].Add(SrcSuffix, "big3.example")
	m.Sets[0].Add(SrcRuleSet, "big")
	m.Sets[1].Add(SrcGeosite, "cn")
	d, err := Derive(m, MemReader{RuleSets: map[string][]Entry{"big": es}, Geo: map[string][]string{"cn": {"h3.big3.example", "cn.example"}}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewGateway(d, nil, testTail); err != nil {
		t.Fatal(err)
	}
	if d.Stats["gs_cn"].Shadowed != 1 || d.Stats["r0"].Kept >= 60001 || d.Stats["r0"].Kept < 59000 {
		t.Fatalf("stats %+v %+v", d.Stats["r0"], d.Stats["gs_cn"])
	}
	// 10.0.0.0/24 .. 10.78.31.0/24 merge into a handful of prefixes.
	if n := len(d.CIDR["r0c"]); n == 0 || n > 16 {
		t.Fatalf("cidr after merge: %d", n)
	}
}
