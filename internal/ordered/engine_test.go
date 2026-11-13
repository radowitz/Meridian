package ordered

import (
	"encoding/json"
	"fmt"
	"math/rand"
	"net/netip"
	"sync"
	"testing"
)

// Decide (indexed) equals Reference (linear spec) on generated lists with
// every entry kind, keywords, sub-domain entries, device rules and GEOIP.
func TestDecideMatchesReference(t *testing.T) {
	rng := rand.New(rand.NewSource(3))
	uni := universe()
	kws := []string{"a.b", "exa", "test", "b.c", "zz"}
	srcs := []netip.Prefix{netip.MustParsePrefix("192.168.1.0/24"), netip.MustParsePrefix("192.168.1.7/32")}
	n := 0
	for iter := 0; iter < 2000; iter++ {
		var rules []Rule
		for i := 0; i < 1+rng.Intn(10); i++ {
			r := Rule{ID: fmt.Sprint(i), Target: fmt.Sprintf("T%d", rng.Intn(5)), GeoIPCN: rng.Intn(10) == 0}
			if rng.Intn(8) == 0 {
				r.Sources = []netip.Prefix{srcs[rng.Intn(2)]}
			}
			for k := 0; k < 1+rng.Intn(4); k++ {
				switch rng.Intn(6) {
				case 0:
					r.Entries = append(r.Entries, sfx(uni[rng.Intn(len(uni))]))
				case 1:
					r.Entries = append(r.Entries, exact(uni[rng.Intn(len(uni))]))
				case 2:
					r.Entries = append(r.Entries, Entry{Kind: Sub, Value: uni[rng.Intn(len(uni))]})
				case 3:
					r.Entries = append(r.Entries, kw(kws[rng.Intn(len(kws))]))
				default:
					r.Entries = append(r.Entries, cidr(cidrPool[rng.Intn(len(cidrPool))]))
				}
			}
			rules = append(rules, r)
		}
		tail := testTail
		c := Compile(rules, tail, -1)
		for _, name := range append(uni, "zz.a.example", "q.c.b.test", "") {
			for _, a := range []string{"198.51.100.7", "192.0.2.9", "2001:db8:1:2::5", "203.0.113.4"} {
				for _, s := range []string{"", "192.168.1.7", "192.168.1.9"} {
					q := Query{Name: name, Addr: netip.MustParseAddr(a)}
					if s != "" {
						q.Source = netip.MustParseAddr(s)
					}
					want := Reference(rules, tail, q)
					got := c.Decide(Request{Name: q.Name, Addr: q.Addr, Source: q.Source})
					if got.Index != want.Index || got.Target != want.Target {
						for i, r := range rules {
							t.Logf("%d %s src=%v geo=%v %v", i, r.Target, r.Sources, r.GeoIPCN, r.Entries)
						}
						t.Fatalf("%+v: decide %d %s, reference %d %s (%s)", q, got.Index, got.Target, want.Index, want.Target, want.Reason)
					}
					n++
				}
			}
		}
	}
	t.Logf("%d decisions: Decide == Reference", n)
}

func TestDecideQUIC(t *testing.T) {
	rules := []Rule{
		{ID: "ai", Target: "us", Entries: []Entry{sfx("ai.example")}},
		{ID: "home", Target: "direct", Action: "direct", Entries: []Entry{sfx("home.example")}},
		{ID: "vid", Target: "hk", Entries: []Entry{sfx("video.example")}},
	}
	c := Compile(rules, testTail, 2) // the switch row is between home and vid
	udp := func(n string) Decision {
		return c.Decide(Request{Name: n, Addr: netip.MustParseAddr("100.64.0.1"), Proto: "udp", Port: 443})
	}
	if udp("ai.example").QUICRejected || udp("home.example").QUICRejected || !udp("video.example").QUICRejected || !udp("other.example").QUICRejected {
		t.Fatal("QUIC switch positions")
	}
	if udp("x.cn.example").QUICRejected { // domestic tail: direct
		t.Fatal("domestic traffic rejected")
	}
}

func TestSnapshotRoundTrip(t *testing.T) {
	s := Snapshot{Version: SnapshotVersion, QUICAt: -1, Rules: []SnapshotRule{
		{ID: "a", Target: "group:us", Mark: 0x10a, Entries: string(MarshalEntries([]Entry{sfx("a.example")})), Sources: []Source{{Kind: SrcRuleSet, Value: "rs1"}}},
		{ID: "b", Target: "direct", Action: "direct", Mark: 0x64, GeoIPCN: true},
	}, Tail: SnapshotTail{DomesticGeosite: "cn", DirectMark: 0x64, Default: "group:hk", DefaultMark: 0x101}}
	b, _ := json.Marshal(s)
	c, err := LoadSnapshot(b, MemReader{RuleSets: map[string][]Entry{"rs1": {sfx("rs.example")}}, Geo: map[string][]string{"cn": {"cn.example"}}}, []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24")})
	if err != nil {
		t.Fatal(err)
	}
	var e Engine
	if _, ok := e.Decide(Request{}); ok {
		t.Fatal("decision before load")
	}
	e.Swap(c)
	for name, want := range map[string]uint32{"x.rs.example": 0x10a, "a.example": 0x10a, "y.cn.example": 0x64, "other.example": 0x101} {
		d, _ := e.Decide(Request{Name: name, Addr: netip.MustParseAddr("100.64.0.1")})
		if d.Mark != want {
			t.Errorf("%s: mark %#x want %#x (%s)", name, d.Mark, want, d.Reason)
		}
	}
	if d, _ := e.Decide(Request{Addr: netip.MustParseAddr("192.0.2.5")}); d.ID != "b" {
		t.Errorf("GEOIP,CN rule: %+v", d)
	}
	// Concurrent use while swapping.
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 1000; j++ {
				e.Decide(Request{Name: "a.example"})
			}
		}()
	}
	for j := 0; j < 50; j++ {
		e.Swap(c)
	}
	wg.Wait()
}

func bigCompiled(b *testing.B) *Compiled {
	var rules []Rule
	for r := 0; r < 60; r++ {
		var es []Entry
		for i := 0; i < 1000; i++ {
			es = append(es, sfx(fmt.Sprintf("h%d.s%d.example", r*1000+i, i%97)))
		}
		for i := 0; i < 160; i++ {
			es = append(es, kw(fmt.Sprintf("kw%dx%d", r, i)))
		}
		for i := 0; i < 300; i++ {
			es = append(es, cidr(fmt.Sprintf("10.%d.%d.0/24", r, i%256)))
		}
		rules = append(rules, Rule{ID: fmt.Sprint(r), Target: fmt.Sprint(r), Entries: es})
	}
	return Compile(rules, testTail, -1)
}

// BenchmarkDecide: 60 rules with 60 000 suffix, 9 600 keyword and 18 000
// CIDR entries in total.
func BenchmarkDecide(b *testing.B) {
	c := bigCompiled(b)
	names := []string{"h59999.s7.example", "deep.sub.h1234.s21.example", "nomatch.example.org", "www.kw33x99y.example"}
	addr := netip.MustParseAddr("10.40.7.9")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		c.Decide(Request{Name: names[i%len(names)], Addr: addr})
	}
}

func BenchmarkCompile(b *testing.B) {
	for i := 0; i < b.N; i++ {
		bigCompiled(b)
	}
}
