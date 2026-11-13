package dnssplit

import (
	"encoding/binary"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// Stub upstream: per name and type, a list of records (CNAME first if
// set), a delay, or silence. China is 198.51.100.0/24 and 2001:db8:c::/48.

type rec struct {
	cname string
	a     []string
	delay time.Duration
	drop  bool
	tc    bool // answer UDP with TC set and no records
	rcode byte
	// then: a second UDP reply to the same query (injection first,
	// genuine answer second), its delay counted from the query.
	then *rec
}

type stub struct {
	mu    sync.Mutex
	names map[string]rec
	asked map[string]int
	addr  string
}

func encodeName(n string) []byte {
	var b []byte
	for _, l := range strings.Split(strings.TrimSuffix(n, "."), ".") {
		b = append(b, byte(len(l)))
		b = append(b, l...)
	}
	return append(b, 0)
}

func rr(owner []byte, typ uint16, rd []byte) []byte {
	out := []byte{0xc0, 12}
	if owner != nil {
		out = append([]byte(nil), owner...)
	}
	out = binary.BigEndian.AppendUint16(out, typ)
	out = binary.BigEndian.AppendUint16(out, 1)
	out = binary.BigEndian.AppendUint32(out, 300)
	out = binary.BigEndian.AppendUint16(out, uint16(len(rd)))
	return append(out, rd...)
}

func answer(q []byte, r rec, tcp bool) []byte {
	m, _ := parseQuery(q)
	out := append([]byte(nil), q[:m.end]...)
	out[2], out[3] = 0x81, 0x80|r.rcode
	binary.BigEndian.PutUint16(out[6:], 0)
	binary.BigEndian.PutUint16(out[8:], 0)
	binary.BigEndian.PutUint16(out[10:], 0)
	if r.tc && !tcp {
		out[2] |= 0x02
		return out
	}
	var rrs [][]byte
	var owner []byte
	if r.cname != "" {
		owner = encodeName(r.cname)
		rrs = append(rrs, rr(nil, typeCNAME, owner))
	}
	for _, s := range r.a {
		a := netip.MustParseAddr(s)
		if (a.Is4() && m.qtype == typeA) || (a.Is6() && m.qtype == typeAAAA) {
			rrs = append(rrs, rr(owner, m.qtype, a.AsSlice()))
		}
	}
	binary.BigEndian.PutUint16(out[6:], uint16(len(rrs)))
	for _, x := range rrs {
		out = append(out, x...)
	}
	return out
}

func startStub(t *testing.T) *stub {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", pc.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { pc.Close(); ln.Close() })
	s := &stub{names: map[string]rec{}, asked: map[string]int{}, addr: pc.LocalAddr().String()}
	get := func(q []byte) (rec, bool) {
		m, err := parseQuery(q)
		if err != nil {
			return rec{}, false
		}
		s.mu.Lock()
		defer s.mu.Unlock()
		s.asked[m.qname]++
		r, ok := s.names[m.qname]
		return r, ok && !r.drop
	}
	go func() {
		buf := make([]byte, 4096)
		for {
			n, from, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			q := append([]byte(nil), buf[:n]...)
			r, ok := get(q)
			if !ok {
				continue
			}
			go func() { time.Sleep(r.delay); _, _ = pc.WriteTo(answer(q, r, false), from) }()
			if r.then != nil {
				r2 := *r.then
				go func() { time.Sleep(r2.delay); _, _ = pc.WriteTo(answer(q, r2, false), from) }()
			}
		}
	}()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				q, err := readTCP(c)
				if err != nil {
					return
				}
				if r, ok := get(q); ok {
					_ = writeTCP(c, answer(q, r, true))
				}
			}()
		}
	}()
	return s
}

func (s *stub) set(n string, r rec) { s.mu.Lock(); s.names[n] = r; s.mu.Unlock() }
func (s *stub) count(n string) int  { s.mu.Lock(); defer s.mu.Unlock(); return s.asked[n] }

func mkQuery(name string, qtype uint16) []byte {
	q := []byte{0x12, 0x34, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0}
	q = append(q, encodeName(name)...)
	q = binary.BigEndian.AppendUint16(q, qtype)
	return binary.BigEndian.AppendUint16(q, 1)
}

func TestResolveAcceptsOnlyAllChinaDomesticAnswers(t *testing.T) {
	udp, dot := startStub(t), startStub(t) // two domestic resolvers
	exit := startStub(t)
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "4"), []byte("198.51.100.0/24\n"), 0o644)
	os.WriteFile(filepath.Join(dir, "6"), []byte("2001:db8:c::/48\n"), 0o644)
	cfg := Config{Listen: "127.0.0.1:0", Domestic: []string{udp.addr, dot.addr}, Exit: exit.addr,
		China4: filepath.Join(dir, "4"), China6: filepath.Join(dir, "6"),
		DomesticTimeout: 300 * time.Millisecond, Settle: DefaultSettle, ExitTimeout: time.Second}
	s := New(cfg)
	if v4, v6 := s.Lists(); v4 != 1 || v6 != 1 {
		t.Fatalf("lists %d %d", v4, v6)
	}
	both := func(n string, r rec) { udp.set(n, r); dot.set(n, r) }
	exitA := rec{cname: "edge.exit.example.org", a: []string{"203.0.113.1", "2001:db8:e::1"}, delay: 30 * time.Millisecond}
	cases := []struct {
		name       string
		domestic   rec
		dot        *rec // second domestic resolver differs
		exit       rec
		qtype      uint16
		want       []string
		wantRcode  int
		domesticOK bool
	}{
		{name: "cname-foreign", domestic: rec{cname: "dyna.example.org", a: []string{"203.0.113.9"}}, exit: exitA, want: []string{"203.0.113.1"}},
		{name: "cname-china", domestic: rec{cname: "edge.example.cn", a: []string{"198.51.100.9"}}, exit: exitA, want: []string{"198.51.100.9"}},
		{name: "cname-mixed", domestic: rec{cname: "edge.example.cn", a: []string{"198.51.100.9", "203.0.113.9"}}, exit: exitA, want: []string{"203.0.113.1"}},
		{name: "poison", domestic: rec{a: []string{"192.0.2.66"}}, exit: exitA, want: []string{"203.0.113.1"}},
		{name: "china", domestic: rec{a: []string{"198.51.100.10"}}, exit: exitA, want: []string{"198.51.100.10"}},
		{name: "nodata", domestic: rec{}, exit: exitA, want: []string{"203.0.113.1"}},
		{name: "nxdomain", domestic: rec{rcode: 3}, exit: exitA, want: []string{"203.0.113.1"}},
		{name: "china-slow-domestic", domestic: rec{a: []string{"198.51.100.11"}, delay: 150 * time.Millisecond}, exit: rec{a: []string{"203.0.113.1"}}, want: []string{"198.51.100.11"}},
		{name: "one-poisoned-one-china", domestic: rec{a: []string{"192.0.2.66"}}, dot: &rec{a: []string{"198.51.100.12"}, delay: 15 * time.Millisecond}, exit: exitA, want: []string{"198.51.100.12"}},
		// The China answer of the second resolver comes after the first
		// resolver settled (0 + 30 ms) and the exit answered (30 ms): the
		// documented safe direction, tunnelled instead of direct.
		{name: "china-after-decision", domestic: rec{a: []string{"192.0.2.66"}}, dot: &rec{a: []string{"198.51.100.14"}, delay: 120 * time.Millisecond}, exit: exitA, want: []string{"203.0.113.1"}},
		{name: "domestic-silent", domestic: rec{drop: true}, exit: exitA, want: []string{"203.0.113.1"}},
		{name: "exit-down-foreign", domestic: rec{cname: "dyna.example.org", a: []string{"203.0.113.9"}}, exit: rec{drop: true}, wantRcode: 2},
		{name: "exit-down-china", domestic: rec{a: []string{"198.51.100.13"}}, exit: rec{drop: true}, want: []string{"198.51.100.13"}},
		{name: "aaaa-china", domestic: rec{cname: "edge.example.cn", a: []string{"2001:db8:c::5"}}, exit: exitA, qtype: typeAAAA, want: []string{"2001:db8:c::5"}},
		{name: "aaaa-foreign", domestic: rec{cname: "edge.example.org", a: []string{"2001:db8:bad::5"}}, exit: exitA, qtype: typeAAAA, want: []string{"2001:db8:e::1"}},
		{name: "exit-truncated", domestic: rec{a: []string{"192.0.2.66"}}, exit: rec{a: []string{"203.0.113.2"}, tc: true}, want: []string{"203.0.113.2"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			n := c.name + ".example.net"
			both(n, c.domestic)
			if c.dot != nil {
				dot.set(n, *c.dot)
			}
			exit.set(n, c.exit)
			qt := c.qtype
			if qt == 0 {
				qt = typeA
			}
			r := s.Resolve(mkQuery(n, qt), false)
			if r == nil || binary.BigEndian.Uint16(r) != 0x1234 {
				t.Fatalf("no reply or wrong id: %x", r)
			}
			addrs, ok := answerAddrs(r)
			if !ok {
				t.Fatal("unparsable reply")
			}
			var got []string
			for _, a := range addrs {
				got = append(got, a.String())
			}
			if int(r[3]&0x0f) != c.wantRcode || strings.Join(got, ",") != strings.Join(c.want, ",") {
				t.Fatalf("rcode %d %v, want %d %v", r[3]&0x0f, got, c.wantRcode, c.want)
			}
			if c.wantRcode == 0 && len(got) == 0 {
				t.Fatal("no address")
			}
		})
	}
	// Other query types: the exit only.
	exit.set("https.example.net", rec{a: []string{"203.0.113.3"}})
	both("https.example.net", rec{a: []string{"198.51.100.3"}})
	_ = s.Resolve(mkQuery("https.example.net", 65), false)
	if udp.count("https.example.net") != 0 || exit.count("https.example.net") != 1 {
		t.Fatalf("HTTPS asked domestic %d, exit %d", udp.count("https.example.net"), exit.count("https.example.net"))
	}
}

func TestResolveOverTheWire(t *testing.T) {
	dom, exit := startStub(t), startStub(t)
	dom.set("x.example.net", rec{cname: "dyna.example.org", a: []string{"203.0.113.9"}})
	exit.set("x.example.net", rec{a: []string{"203.0.113.1"}})
	s := New(Config{Listen: "127.0.0.1:0", Domestic: []string{dom.addr}, Exit: exit.addr, DomesticTimeout: 200 * time.Millisecond, Settle: DefaultSettle, ExitTimeout: time.Second})
	if err := s.Start(); err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	for _, network := range []string{"udp", "tcp"} {
		c, err := net.Dial(network, s.Addr())
		if err != nil {
			t.Fatal(err)
		}
		var r []byte
		if network == "udp" {
			c.Write(mkQuery("x.example.net", typeA))
			c.SetReadDeadline(time.Now().Add(3 * time.Second))
			buf := make([]byte, 4096)
			n, err := c.Read(buf)
			if err != nil {
				t.Fatal(err)
			}
			r = buf[:n]
		} else {
			writeTCP(c, mkQuery("x.example.net", typeA))
			c.SetReadDeadline(time.Now().Add(3 * time.Second))
			if r, err = readTCP(c); err != nil {
				t.Fatal(err)
			}
		}
		c.Close()
		addrs, _ := answerAddrs(r)
		if len(addrs) != 1 || addrs[0].String() != "203.0.113.1" {
			t.Fatalf("%s: %v", network, addrs)
		}
	}
}

func TestParseArgs(t *testing.T) {
	c, err := ParseArgs(strings.Fields("--listen 127.0.0.1:5356 --domestic 223.5.5.5:53,1.12.12.12:53 --exit [fd66::53:d]:53 --exit-mark 269 --china4 /a --china6 /b"))
	if err != nil || c.Exit != "[fd66::53:d]:53" || c.ExitMark != 269 || len(c.Domestic) != 2 {
		t.Fatalf("%+v %v", c, err)
	}
	if c.DomesticTimeout != DefaultDomesticTimeout || c.Settle != DefaultSettle || c.ExitTimeout != DefaultExitTimeout || c.StatsInterval != DefaultStatsInterval {
		t.Fatalf("defaults %+v", c)
	}
	base := "--listen 127.0.0.1:1 --exit 127.0.0.1:2 --domestic 1.1.1.1:53 "
	for _, bad := range []string{base + "--settle 500ms", base + "--domestic-timeout 0s", base + "--settle -1ms", base + "--stats-interval -1s", "--listen x", "--listen 127.0.0.1:1 --exit 127.0.0.1:2", "--listen 127.0.0.1:1 --exit host:53 --domestic 1.1.1.1:53", "--listen 127.0.0.1:1 --exit 127.0.0.1:2 --domestic 1.1.1.1:53 extra"} {
		if _, err := ParseArgs(strings.Fields(bad)); err == nil {
			t.Fatalf("accepted %q", bad)
		}
	}
}

// Decision times with the default timings (DomesticTimeout 400 ms, Settle
// 30 ms): the exit's answer is used as soon as the exit answered and the
// domestic resolvers are done, not after the whole 400 ms.
func TestDecisionTimes(t *testing.T) {
	d1, d2, exit := startStub(t), startStub(t), startStub(t)
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "4"), []byte("198.51.100.0/24\n"), 0o644)
	s := New(Config{Listen: "127.0.0.1:0", Domestic: []string{d1.addr, d2.addr}, Exit: exit.addr,
		China4: filepath.Join(dir, "4"), DomesticTimeout: DefaultDomesticTimeout, Settle: DefaultSettle, ExitTimeout: DefaultExitTimeout})
	ms := time.Millisecond
	cases := []struct {
		name       string
		d1, d2, ex rec
		want       string
		min, max   time.Duration
	}{
		// Both domestic non-China at 10 ms, exit at 50 ms: ≈ exit time.
		{"both-foreign-exit-50", rec{a: []string{"203.0.113.9"}, delay: 10 * ms}, rec{a: []string{"203.0.113.9"}, delay: 10 * ms}, rec{a: []string{"203.0.113.1"}, delay: 50 * ms}, "203.0.113.1", 45 * ms, 90 * ms},
		// Exit faster than domestic settle: ≈ 10 + 30 ms.
		{"both-foreign-exit-5", rec{a: []string{"203.0.113.9"}, delay: 10 * ms}, rec{a: []string{"203.0.113.9"}, delay: 10 * ms}, rec{a: []string{"203.0.113.1"}, delay: 5 * ms}, "203.0.113.1", 38 * ms, 80 * ms},
		// Exit slower than domestic: ≈ exit time.
		{"exit-slow-150", rec{cname: "dyna.example.org", a: []string{"203.0.113.9"}, delay: 10 * ms}, rec{a: []string{"192.0.2.66"}, delay: 3 * ms}, rec{a: []string{"203.0.113.1"}, delay: 150 * ms}, "203.0.113.1", 145 * ms, 200 * ms},
		// One domestic silent, the other non-China at 10 ms, exit 20 ms:
		// ≈ 10 + 30 ms, not the 400 ms cap.
		{"one-silent", rec{drop: true}, rec{a: []string{"203.0.113.9"}, delay: 10 * ms}, rec{a: []string{"203.0.113.1"}, delay: 20 * ms}, "203.0.113.1", 38 * ms, 90 * ms},
		// Forged (non-China) at 5 ms, genuine China at 20 ms on the same
		// query, other resolver non-China, exit at 10 ms: domestic.
		{"forged-then-genuine", rec{a: []string{"192.0.2.66"}, delay: 5 * ms, then: &rec{a: []string{"198.51.100.40"}, delay: 20 * ms}}, rec{a: []string{"203.0.113.9"}, delay: 5 * ms}, rec{a: []string{"203.0.113.1"}, delay: 10 * ms}, "198.51.100.40", 18 * ms, 60 * ms},
		// The genuine reply after the settle time: the exit's (safe).
		{"forged-then-late-genuine", rec{a: []string{"192.0.2.66"}, delay: 5 * ms, then: &rec{a: []string{"198.51.100.41"}, delay: 100 * ms}}, rec{drop: true}, rec{a: []string{"203.0.113.1"}, delay: 10 * ms}, "203.0.113.1", 33 * ms, 80 * ms},
		// China answer: immediately, whatever the exit does.
		{"china-fast", rec{a: []string{"198.51.100.42"}, delay: 8 * ms}, rec{a: []string{"203.0.113.9"}, delay: 3 * ms}, rec{a: []string{"203.0.113.1"}, delay: 2 * ms}, "198.51.100.42", 7 * ms, 40 * ms},
		// No domestic answer at all: the 400 ms cap.
		{"all-silent", rec{drop: true}, rec{drop: true}, rec{a: []string{"203.0.113.1"}, delay: 20 * ms}, "203.0.113.1", 395 * ms, 460 * ms},
		// Exit silent: all domestic waited for, China answer still used.
		{"exit-silent-china", rec{a: []string{"203.0.113.9"}, delay: 5 * ms}, rec{a: []string{"198.51.100.43"}, delay: 60 * ms}, rec{drop: true}, "198.51.100.43", 55 * ms, 110 * ms},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			n := c.name + ".example.net"
			d1.set(n, c.d1)
			d2.set(n, c.d2)
			exit.set(n, c.ex)
			t0 := time.Now()
			r := s.Resolve(mkQuery(n, typeA), false)
			el := time.Since(t0)
			addrs, _ := answerAddrs(r)
			got := ""
			if len(addrs) == 1 {
				got = addrs[0].String()
			}
			t.Logf("%-26s -> %-15s in %v", c.name, got, el.Round(time.Millisecond))
			if got != c.want {
				t.Fatalf("got %v, want %s", addrs, c.want)
			}
			if el < c.min || el > c.max {
				t.Fatalf("decided after %v, want %v..%v", el, c.min, c.max)
			}
		})
	}
	if line := s.stats.summary(time.Minute); !strings.Contains(line, "queries") || strings.Contains(line, "example") {
		t.Fatalf("summary %q (must hold counts only, no names)", line)
	}
}

// The default exit's resolver as an external TCP-only exit presents it to
// the gateway (its carrier's resolver group, reached over plain UDP and
// answering A only, docs/architecture.md「外部 SOCKS 出口」): an A query gets
// the exit's A; an AAAA query (only asked when the gateway allows AAAA at
// all) gets the exit's empty answer, never a domestic non-China AAAA; a
// refused exit port (nothing listening: ICMP port unreachable) gives
// SERVFAIL at once, never a domestic non-China answer.
func TestExitLikeExternalResolver(t *testing.T) {
	dom, exit := startStub(t), startStub(t)
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "4"), []byte("198.51.100.0/24\n"), 0o644)
	os.WriteFile(filepath.Join(dir, "6"), []byte("2001:db8:c::/48\n"), 0o644)
	dom.set("ext.example.net", rec{a: []string{"192.0.2.70", "2001:db8:bad::70"}})
	exit.set("ext.example.net", rec{a: []string{"203.0.113.70"}})
	cfg := Config{Listen: "127.0.0.1:0", Domestic: []string{dom.addr}, Exit: exit.addr,
		China4: filepath.Join(dir, "4"), China6: filepath.Join(dir, "6"),
		DomesticTimeout: DefaultDomesticTimeout, Settle: DefaultSettle, ExitTimeout: DefaultExitTimeout}
	s := New(cfg)
	if addrs, _ := answerAddrs(s.Resolve(mkQuery("ext.example.net", typeA), false)); len(addrs) != 1 || addrs[0].String() != "203.0.113.70" {
		t.Fatalf("A: %v", addrs)
	}
	r := s.Resolve(mkQuery("ext.example.net", typeAAAA), false)
	if addrs, ok := answerAddrs(r); !ok || len(addrs) != 0 || r[3]&0x0f != 0 {
		t.Fatalf("AAAA: %v rcode %d (want the exit's empty NOERROR)", addrs, r[3]&0x0f)
	}

	// A closed port on loopback: the exit refuses.
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	closed := pc.LocalAddr().String()
	pc.Close()
	cfg.Exit = closed
	s = New(cfg)
	t0 := time.Now()
	r = s.Resolve(mkQuery("ext.example.net", typeA), false)
	if r[3]&0x0f != 2 {
		t.Fatalf("refused exit: rcode %d, want SERVFAIL", r[3]&0x0f)
	}
	if addrs, _ := answerAddrs(r); len(addrs) != 0 {
		t.Fatalf("refused exit returned %v", addrs)
	}
	if el := time.Since(t0); el > DefaultDomesticTimeout+200*time.Millisecond {
		t.Fatalf("refused exit decided after %v", el)
	}
}
