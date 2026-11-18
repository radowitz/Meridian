package ordered

import (
	"encoding/json"
	"fmt"
	"math/rand"
	"net/netip"
	"strings"
	"testing"
)

func subE(v string) Entry { return Entry{Kind: Sub, Value: v} }

// Covers agrees with Matches over a name universe: when Covers(a, b), every
// name b matches is matched by a; when not, some name (from the universe or
// built from b) is matched by b and not by a.
func TestCoversAgreesWithMatches(t *testing.T) {
	uni := universe()
	var names []string
	for _, n := range uni {
		names = append(names, n, "zz."+n, "q."+n, "ex"+strings.ReplaceAll(n, ".", "-")+".test")
	}
	var es []Entry
	for _, n := range uni {
		es = append(es, exact(n), sfx(n), subE(n))
	}
	for _, k := range []string{"a.b", "exa", "b.c", "c.example", "zz", "test"} {
		es = append(es, kw(k))
	}
	for _, a := range es {
		for _, b := range es {
			counter := ""
			matchedByB := 0
			for _, n := range names {
				q := Query{Name: n}
				if b.Matches(q) {
					matchedByB++
					if !a.Matches(q) && counter == "" {
						counter = n
					}
				}
			}
			if Covers(a, b) && counter != "" {
				t.Fatalf("Covers(%v, %v) but %s matches only b", a, b, counter)
			}
			// A keyword b matches names outside any universe; the
			// universe holds a witness for every other pair.
			if !Covers(a, b) && counter == "" && b.Kind != Keyword && matchedByB > 0 {
				t.Fatalf("!Covers(%v, %v) but no name of b escapes a", a, b)
			}
		}
	}
	for _, c := range []struct {
		a, b string
		want bool
	}{
		{"198.51.100.0/24", "198.51.100.0/24", true},
		{"198.51.100.0/24", "198.51.100.64/26", true},
		{"198.51.100.64/26", "198.51.100.0/24", false},
		{"198.51.100.0/24", "2001:db8::/32", false},
	} {
		if got := Covers(cidr(c.a), cidr(c.b)); got != c.want {
			t.Errorf("Covers(%s, %s) = %v", c.a, c.b, got)
		}
	}
}

func TestSubtractPrefixes(t *testing.T) {
	got := subtractPrefixes(netip.MustParsePrefix("198.51.100.0/24"), []netip.Prefix{netip.MustParsePrefix("198.51.100.0/26")})
	if fmt.Sprint(got) != "[198.51.100.64/26 198.51.100.128/25]" {
		t.Fatalf("%v", got)
	}
	got = subtractPrefixes(netip.MustParsePrefix("2001:db8::/32"), []netip.Prefix{netip.MustParsePrefix("2001:db8:8000::/33"), netip.MustParsePrefix("2001:db8::/34")})
	if fmt.Sprint(got) != "[2001:db8:4000::/34]" {
		t.Fatalf("%v", got)
	}
	// Brute force on a /24: the remainder holds exactly the addresses
	// outside every cut.
	rng := rand.New(rand.NewSource(5))
	for iter := 0; iter < 300; iter++ {
		p := netip.MustParsePrefix("198.51.100.0/24")
		var cut []netip.Prefix
		for k := 1 + rng.Intn(3); k > 0; k-- {
			bits := 25 + rng.Intn(8)
			c, _ := netip.AddrFrom4([4]byte{198, 51, 100, byte(rng.Intn(256))}).Prefix(bits)
			cut = append(cut, c)
		}
		rest := subtractPrefixes(p, cut)
		for i := 0; i < 256; i++ {
			a := netip.AddrFrom4([4]byte{198, 51, 100, byte(i)})
			inCut, inRest := false, 0
			for _, c := range cut {
				inCut = inCut || c.Contains(a)
			}
			for _, r := range rest {
				if r.Contains(a) {
					inRest++
				}
			}
			if inCut == (inRest == 1) || inRest > 1 {
				t.Fatalf("cut %v rest %v: %s inCut=%v inRest=%d", cut, rest, a, inCut, inRest)
			}
		}
	}
}

// The edge cases of the definition (docs/architecture.md「规则集的排除条目」).
func TestApplyExclusionsEdgeCases(t *testing.T) {
	content := []Entry{
		sfx("example.com"),              // broad suffix
		exact("a.example.net"),          // exact under an excluded suffix
		sfx("b.example.net"),            // suffix under an excluded suffix
		subE("c.example.net"),           // sub under an excluded suffix
		kw("tracker"),                   // keyword
		exact("ads-cdn.example.org"),    // contains a keyword exclusion
		exact("keep.example.org"),       // untouched
		cidr("198.51.100.0/24"),         // narrower CIDR exclusion inside
		cidr("203.0.113.0/25"),          // inside a broader CIDR exclusion
		cidr("2001:db8:1::/48"),         // equal CIDR exclusion
		exact("same.example.org"),       // equal exclusion
		Entry{Kind: Suffix, Value: "x"}, // a TLD
	}
	excl := []Entry{
		sfx("example.net"),        // 0 broader: removes a, b, c
		exact("same.example.org"), // 1 equal
		exact("a.example.com"),    // 2 narrower: inside example.com
		kw("ads"),                 // 3 keyword: removes ads-cdn
		cidr("198.51.100.0/26"),   // 4 narrower CIDR: cut out
		cidr("203.0.113.0/24"),    // 5 broader CIDR
		cidr("2001:db8:1::/48"),   // 6 equal CIDR
		sfx("gone.example.org"),   // 7 stale
		kw("track"),               // 8 keyword covers the keyword entry
		subE("example.com"),       // 9 narrower: example.com still matches below
	}
	res := ApplyExclusions(content, excl)
	var got []string
	for _, e := range res.Entries {
		got = append(got, e.String())
	}
	want := "suffix:example.com exact:keep.example.org cidr:198.51.100.64/26 cidr:198.51.100.128/25 suffix:x"
	if strings.Join(got, " ") != want {
		t.Fatalf("effective %v\nwant      %s", got, want)
	}
	if res.Removed != 8 {
		t.Errorf("removed %d", res.Removed)
	}
	st := res.Stats
	check := func(i, removed, trimmed int, inside string, stale bool) {
		t.Helper()
		s := st[i]
		in := ""
		if s.Inside != nil {
			in = s.Inside.String()
		}
		if s.Removed != removed || s.Trimmed != trimmed || in != inside || s.Stale() != stale {
			t.Errorf("exclusion %v: removed %d trimmed %d inside %q stale %v", s.Exclusion, s.Removed, s.Trimmed, in, s.Stale())
		}
	}
	check(0, 3, 0, "", false)
	check(1, 1, 0, "", false)
	check(2, 0, 0, "suffix:example.com", false)
	check(3, 1, 0, "", false)
	check(4, 0, 1, "", false)
	check(5, 1, 0, "", false)
	check(6, 1, 0, "", false)
	check(7, 0, 0, "", true)
	check(8, 1, 0, "", false)
	check(9, 0, 0, "suffix:example.com", false)
	// Without exclusions the content is returned as it is.
	if r := ApplyExclusions(content, nil); len(r.Entries) != len(content) || &r.Entries[0] != &content[0] {
		t.Fatal("no-op changed the content")
	}
	// The definition, literally: Reference with Rule.Exclude.
	rules := []Rule{{ID: "set", Target: "A", Entries: content, Exclude: excl}}
	for name, want := range map[string]int{
		"example.com": 0, "z.example.com": 0, "a.example.com": 0, // narrower exclusions remove nothing
		"a.example.net": -1, "q.b.example.net": -1, "example.net": -1,
		"keep.example.org": 0, "same.example.org": -1, "ads-cdn.example.org": -1,
		"my-tracker.example.org": -1, // keyword entry removed by "track"
		"gone.example.org":       -1,
	} {
		if m := Reference(rules, testTail, Query{Name: name}); m.Index != want {
			t.Errorf("%s: rule %d (%s), want %d", name, m.Index, m.Reason, want)
		}
	}
	for a, want := range map[string]int{
		"198.51.100.5": -1, "198.51.100.70": 0, "198.51.100.200": 0, "203.0.113.9": -1, "2001:db8:1::1": -1,
	} {
		if m := Reference(rules, testTail, Query{Addr: netip.MustParseAddr(a)}); m.Index != want {
			t.Errorf("%s: rule %d (%s), want %d", a, m.Index, m.Reason, want)
		}
	}
	// A domain exclusion does not stop a CIDR entry from matching the
	// address of an excluded name.
	if m := Reference(rules, testTail, Query{Name: "a.example.net", Addr: netip.MustParseAddr("198.51.100.70")}); m.Index != 0 || m.Entry.Kind != CIDR {
		t.Errorf("excluded name with a set address: %+v", m)
	}
}

// The motivating case: a subscribed set sends everything to A except two
// broad suffixes; those suffixes also cover exact entries that a later set
// sends to B. Names under the excluded suffixes fall through: to B where B
// lists them, to the default otherwise; names beside them stay with A.
func TestExclusionFallsThroughToLaterRuleSet(t *testing.T) {
	setA := []Entry{sfx("video.example"), sfx("cdn.example"), sfx("big.example"), sfx("huge.example"), exact("x.big.example"), sfx("y.huge.example")}
	setB := []Entry{exact("x.big.example"), exact("z.big.example"), sfx("w.huge.example")}
	rules := []Rule{
		{ID: "a", Target: "A", Entries: setA, Exclude: []Entry{sfx("big.example"), sfx("huge.example")}},
		{ID: "b", Target: "B", Entries: setB},
		{ID: "c", Target: "C", Entries: []Entry{sfx("example")}},
	}
	want := map[string]string{
		"video.example": "A", "s.cdn.example": "A",
		"x.big.example": "B", "z.big.example": "B", "q.w.huge.example": "B",
		"big.example": "C", "o.big.example": "C", "y.huge.example": "C", "q.y.huge.example": "C",
		"other.test": "MATCH",
	}
	g := gatewayFor(t, rules, testTail)
	c := Compile(rules, testTail, -1)
	for name, tg := range want {
		q := Query{Name: name, Addr: addr()}
		ref := Reference(rules, testTail, q)
		if ref.Target != tg {
			t.Errorf("reference %s -> %s, want %s", name, ref.Target, tg)
		}
		if got := g.Query(q); got.Target != tg {
			t.Errorf("gateway %s -> %s, want %s", name, got.Target, tg)
		}
		if d := c.Decide(Request{Name: q.Name, Addr: q.Addr}); d.Target != tg {
			t.Errorf("decide %s -> %s, want %s", name, d.Target, tg)
		}
	}
}

// ApplyExclusions equals the definition (Reference with Rule.Exclude), and
// every evaluation path built on it equals the reference on generated lists
// with shadowing: the data-plane model (manifest with exclusion lines,
// Derive, longest-key resolver, nft chain with the derived address sets)
// and the indexed engine (Compile/Decide), and the serialized decide.json.
// Keyword entries are left out of the data-plane comparison (the resolver
// does not execute them, TestKeywordIsNotExecuted) but kept for Decide.
func TestApplyExclusionsEqualsDefinition(t *testing.T) {
	rng := rand.New(rand.NewSource(20261114))
	uni := universe()
	kws := []string{"a.b", "exa", "b.c", "zz"}
	pool := append(cidrPool, "198.51.100.64/27", "198.51.100.0/26", "2001:db8:1:2:8000::/65")
	lists, probes, changed := 0, 0, 0
	randEntry := func(keywords bool) Entry {
		switch rng.Intn(9) {
		case 0, 1:
			return sfx(uni[rng.Intn(len(uni))])
		case 2, 3:
			return exact(uni[rng.Intn(len(uni))])
		case 4:
			return subE(uni[rng.Intn(len(uni))])
		case 5:
			if keywords {
				return kw(kws[rng.Intn(len(kws))])
			}
			return sfx(uni[rng.Intn(len(uni))])
		}
		return cidr(pool[rng.Intn(len(pool))])
	}
	for iter := 0; iter < 2500; iter++ {
		keywords := iter%2 == 1
		var rules []Rule
		for i := 0; i < 1+rng.Intn(7); i++ {
			r := Rule{ID: fmt.Sprint(i), Target: fmt.Sprintf("T%d", rng.Intn(4)), GeoIPCN: rng.Intn(15) == 0}
			for k := 1 + rng.Intn(6); k > 0; k-- {
				r.Entries = append(r.Entries, randEntry(keywords))
			}
			if rng.Intn(2) == 0 {
				for k := 1 + rng.Intn(3); k > 0; k-- {
					// Exclusions drawn from the rule's own entries, their
					// neighbours and keywords (the resolver path always
					// sees keyword exclusions: they only remove entries).
					switch rng.Intn(3) {
					case 0:
						r.Exclude = append(r.Exclude, r.Entries[rng.Intn(len(r.Entries))])
					case 1:
						r.Exclude = append(r.Exclude, kw(kws[rng.Intn(len(kws))]))
					default:
						r.Exclude = append(r.Exclude, randEntry(false))
					}
				}
			}
			rules = append(rules, r)
		}
		plain := make([]Rule, len(rules))
		for i, r := range rules {
			res := ApplyExclusions(r.Entries, r.Exclude)
			// The per-exclusion figures, by brute force over Covers.
			for _, st := range res.Stats {
				x := st.Exclusion
				removed, inside := 0, false
				for _, e := range r.Entries {
					if x.Kind == CIDR && e.Kind == CIDR && Covers(x, e) || x.Kind != CIDR && Covers(x, e) {
						removed++
					}
				}
				for _, e := range res.Entries {
					if x.Kind != CIDR && Covers(e, x) {
						inside = true
					}
				}
				if st.Removed != removed || (st.Inside != nil) != inside || st.Inside != nil && !Covers(*st.Inside, x) {
					t.Fatalf("rule %v exclusions %v: stat %+v, brute force removed %d inside %v", r.Entries, r.Exclude, st, removed, inside)
				}
			}
			r.Entries = res.Entries
			r.Exclude = nil
			plain[i] = r
		}
		tail := testTail
		c := Compile(rules, tail, -1)
		var g *Gateway
		if !keywords {
			g = gatewayFor(t, rules, tail)
		}
		dec := snapshotOf(t, rules, tail)
		next := 0
		fresh := func() netip.Addr {
			next++
			switch rng.Intn(5) {
			// Every address is used once: the data plane keeps what it
			// learned, and a reused address is the documented shared-address
			// case (TestSharedAddressEarlierRuleWins), not this one.
			case 0:
				return netip.AddrFrom4([4]byte{198, 51, 100, byte(next)})
			case 1:
				return netip.AddrFrom4([4]byte{192, 0, 2, byte(next)})
			case 2:
				return netip.AddrFrom16([16]byte{0x20, 0x01, 0x0d, 0xb8, 0, 1, 0, 2, byte(next * 37), 0, 0, 0, 0, 0, 0, byte(next)})
			}
			return netip.AddrFrom4([4]byte{100, 64 + byte(next/250), byte(next % 250), 1})
		}
		var qs []Query
		for _, n := range uni {
			qs = append(qs, Query{Name: n, Addr: fresh()}, Query{Name: "zz." + n, Addr: fresh()})
		}
		for k := 0; k < 12; k++ {
			qs = append(qs, Query{Addr: fresh()})
		}
		raw := make([]Rule, len(rules))
		for i, r := range rules {
			r.Exclude = nil
			raw[i] = r
		}
		for _, q := range qs {
			want := Reference(rules, tail, q)
			if Reference(raw, tail, q).Index != want.Index {
				changed++
			}
			if p := Reference(plain, tail, q); p.Index != want.Index {
				dump(t, rules)
				t.Fatalf("%+v: definition rule %d (%s), ApplyExclusions rule %d (%s)", q, want.Index, want.Reason, p.Index, p.Reason)
			}
			if d := c.Decide(Request{Name: q.Name, Addr: q.Addr}); d.Index != want.Index {
				dump(t, rules)
				t.Fatalf("%+v: Decide rule %d (%s), reference %d (%s)", q, d.Index, d.Reason, want.Index, want.Reason)
			}
			if d := dec.Decide(Request{Name: q.Name, Addr: q.Addr}); d.Target != want.Target {
				dump(t, rules)
				t.Fatalf("%+v: decide.json %s (%s), reference %s (%s)", q, d.Target, d.Reason, want.Target, want.Reason)
			}
			if g != nil {
				if got := g.Query(q); got.Index != want.Index || got.Target != want.Target {
					dump(t, rules)
					t.Fatalf("%+v: gateway rule %d (%s), reference %d %s (%s)", q, got.Index, got.Target, want.Index, want.Target, want.Reason)
				}
			}
			probes++
		}
		lists++
	}
	if changed < probes/50 {
		t.Fatalf("only %d of %d probes decided differently because of exclusions", changed, probes)
	}
	t.Logf("%d generated lists with exclusions, %d probes (%d decided differently because of exclusions): definition == ApplyExclusions == Decide == decide.json == gateway", lists, probes, changed)
}

func dump(t *testing.T, rules []Rule) {
	for i, r := range rules {
		t.Logf("rule %d %s geo=%v entries=%v exclude=%v", i, r.Target, r.GeoIPCN, r.Entries, r.Exclude)
	}
}

// snapshotOf serializes rules as the gateway compile does (every rule's
// entries as a rule-set with its exclusions) and loads it back.
func snapshotOf(t *testing.T, rules []Rule, tail Tail) *Compiled {
	t.Helper()
	s := Snapshot{Version: SnapshotVersion, QUICAt: -1, Tail: SnapshotTail{DomesticGeosite: "cn", Default: tail.Default}}
	rd := MemReader{RuleSets: map[string][]Entry{}, Geo: map[string][]string{"cn": tail.Domestic}}
	for i, r := range rules {
		id := fmt.Sprintf("rs-%d", i)
		rd.RuleSets[id] = r.Entries
		s.Rules = append(s.Rules, SnapshotRule{ID: r.ID, Target: r.Target, GeoIPCN: r.GeoIPCN, Sources: []Source{{Kind: SrcRuleSet, Value: id, Exclude: r.Exclude}}})
	}
	b, err := json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}
	c, err := LoadSnapshot(b, rd, tail.China)
	if err != nil {
		t.Fatal(err)
	}
	c.tail.DirectTarget = tail.DirectTarget
	return c
}

func TestManifestExclusions(t *testing.T) {
	var m Manifest
	set := ManifestSet{Name: "r0", CIDR4: "r0c"}
	set.AddRuleSet("rs-a", []Entry{sfx("example.com"), exact("a.example.org"), subE("b.example.org"), kw("ads"), cidr("198.51.100.0/26"), cidr("2001:db8::/48")})
	set.Add(SrcSuffix, "own.example.net")
	m.Sets = append(m.Sets, set)
	text := m.Render()
	for _, l := range []string{"ruleset rs-a\nexclude-suffix example.com\nexclude-exact a.example.org\nexclude-sub b.example.org\nexclude-keyword ads\nexclude-cidr 198.51.100.0/26\nexclude-cidr 2001:db8::/48\nsuffix own.example.net\n"} {
		if !strings.Contains(text, l) {
			t.Fatalf("manifest:\n%s", text)
		}
	}
	back, err := ParseManifest([]byte(text))
	if err != nil {
		t.Fatal(err)
	}
	if back.Render() != text || len(back.Sets[0].Srcs[0].Exclude) != 6 || len(back.Sets[0].Srcs[1].Exclude) != 0 {
		t.Fatalf("round trip:\n%s", back.Render())
	}
	// The exclusions apply to the rule-set only, never to the set's own
	// names: "own.example.net" stays although nothing excludes it, and an
	// exclusion of it would not touch it either.
	set2 := ManifestSet{Name: "r0"}
	set2.AddRuleSet("rs-a", []Entry{sfx("example.net")})
	set2.Add(SrcSuffix, "own.example.net")
	d, err := Derive(Manifest{Sets: []ManifestSet{set2}}, MemReader{RuleSets: map[string][]Entry{"rs-a": {sfx("example.net"), sfx("other.example")}}})
	if err != nil {
		t.Fatal(err)
	}
	if fmt.Sprint(d.Files["r0"]) != "[other.example own.example.net]" {
		t.Fatalf("derived %v", d.Files["r0"])
	}
	for _, b := range []string{
		ManifestHeader + "\nset r0\nexclude-suffix example.com\n",
		ManifestHeader + "\nset r0\nsuffix x.example\nexclude-suffix example.com\n",
		ManifestHeader + "\nexclude-suffix example.com\n",
		ManifestHeader + "\nset r0\nruleset rs-a\nexclude-suffix Example.com\n",
		ManifestHeader + "\nset r0\nruleset rs-a\nexclude-suffix ../etc\n",
		ManifestHeader + "\nset r0\nruleset rs-a\nexclude-cidr 198.51.100.1/24\n",
		ManifestHeader + "\nset r0\nruleset rs-a\nexclude-geosite cn\n",
		ManifestHeader + "\nset r0\nruleset rs-a\nexclude-keyword a b\n",
	} {
		if _, err := ParseManifest([]byte(b)); err == nil {
			t.Errorf("accepted %q", b)
		}
	}
}

// Without exclusions the snapshot and manifest texts are what they were.
func TestNoExclusionsSameText(t *testing.T) {
	b, _ := json.Marshal(Source{Kind: SrcRuleSet, Value: "rs-a"})
	if string(b) != `{"kind":"ruleset","value":"rs-a"}` {
		t.Fatal(string(b))
	}
	var s Source
	if err := json.Unmarshal([]byte(`{"kind":"geosite","value":"cn","exclude":"suffix x.example\n"}`), &s); err == nil {
		t.Fatal("exclusions accepted on a geosite source")
	}
	if err := json.Unmarshal([]byte(`{"kind":"ruleset","value":"rs-a","exclude":"suffix X..example\n"}`), &s); err == nil {
		t.Fatal("bad exclusion accepted")
	}
}
