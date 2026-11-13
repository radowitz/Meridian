package sniff

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/radowitz/meridian/internal/ordered"
)

// ------------------------------------------------------------ fixture ---

// Marks and resolver addresses in the shape of the gateway's (synthetic).
const (
	mDirect = 0x64
	mReject = 0x65
	mJP     = 0x102
	mHK     = 0x10a
	mUS     = 0x113
	rsDom   = "192.0.2.53:53"
	rsJP    = "[fd66::54:2]:53"
	rsHK    = "[fd66::53:a]:53"
	rsUS    = "[fd66::53:13]:53"
	testMAC = "02:00:00:00:00:01"
)

func sfx(v string) ordered.Entry { return ordered.Entry{Kind: ordered.Suffix, Value: v} }

func fixtureRules() ([]ordered.Rule, ordered.Tail) {
	rules := []ordered.Rule{
		{ID: "video", Target: "group:hk", Mark: mHK, Entries: []ordered.Entry{sfx("video.example.net")}},
		{ID: "kw", Target: "group:us", Mark: mUS, Entries: []ordered.Entry{{Kind: ordered.Keyword, Value: "stream"}}},
		{ID: "ai", Target: "group:us", Mark: mUS, Entries: []ordered.Entry{sfx("ai.example.org")}},
		{ID: "net", Target: "exit:jp", Mark: mJP, Entries: []ordered.Entry{{Kind: ordered.CIDR, Prefix: netip.MustParsePrefix("203.0.113.128/25")}}},
		{ID: "ads", Target: "reject", Mark: mReject, Action: "reject", Entries: []ordered.Entry{sfx("ads.example.com")}},
		{ID: "home", Target: "direct", Mark: mDirect, Action: "direct", Entries: []ordered.Entry{sfx("home.example.org")}},
		{ID: "devmac", Target: "exit:jp", Mark: mJP, SourceMAC: testMAC, Entries: []ordered.Entry{sfx("dev.example.org")}},
		{ID: "dev", Target: "group:us", Mark: mUS, Entries: []ordered.Entry{sfx("dev.example.org")}},
	}
	tail := ordered.Tail{Domestic: []string{"example.cn"}, China: []netip.Prefix{netip.MustParsePrefix("192.0.2.128/25")},
		DirectTarget: "direct", DirectMark: mDirect, Default: "group:hk", DefaultMark: mHK}
	return rules, tail
}

func fixtureTargets() []Target {
	return []Target{
		{Name: "direct", Mark: mDirect, Resolvers: []string{rsDom}, IPv6: true},
		{Name: "exit:jp", Mark: mJP, Resolvers: []string{rsJP}},
		{Name: "group:hk", Mark: mHK, Resolvers: []string{rsHK}},
		{Name: "group:us", Mark: mUS, Resolvers: []string{rsUS}},
		{Name: "reject", Mark: mReject, Reject: true},
	}
}

func fixtureDNS() *dnsNet {
	a := func(s ...string) []netip.Addr {
		var out []netip.Addr
		for _, x := range s {
			out = append(out, netip.MustParseAddr(x))
		}
		return out
	}
	return &dnsNet{stubs: map[string]*dnsStub{
		rsHK: {answers: map[string][]netip.Addr{"a.video.example.net": a("198.51.100.10"), "other.example.org": a("198.51.100.11"),
			"public.example.net": a("198.51.100.12"), "v6only.video.example.net": a("2001:db8::10")}, rcode: 3, ttl: 60},
		rsUS: {answers: map[string][]netip.Addr{"b.ai.example.org": a("198.51.100.20"), "x.stream-cdn.example.com": a("198.51.100.21"),
			"dev.example.org": a("198.51.100.22")}, rcode: 2, ttl: 60},
		rsJP:  {answers: map[string][]netip.Addr{"dev.example.org": a("198.51.100.30")}, rcode: 3, ttl: 60},
		rsDom: {answers: map[string][]netip.Addr{"www.home.example.org": a("192.0.2.140"), "a.example.cn": a("192.0.2.141")}, rcode: 3, ttl: 60},
	}}
}

type harness struct {
	t     *testing.T
	s     *Server
	dn    *dnsNet
	echo  string // real echo upstream
	mu    sync.Mutex
	orig  map[uint16]netip.AddrPort
	real  map[string]string // virtual addr:port -> real listener ("" = echo)
	dials []string
}

func newHarness(t *testing.T, cfg Config, rules []ordered.Rule, tail ordered.Tail, targets []Target) *harness {
	t.Helper()
	return newHarnessWith(t, cfg, rules, tail, targets, nil)
}

func newHarnessWith(t *testing.T, cfg Config, rules []ordered.Rule, tail ordered.Tail, targets []Target, setup func(*Server)) *harness {
	t.Helper()
	h := &harness{t: t, dn: fixtureDNS(), orig: map[uint16]netip.AddrPort{}, real: map[string]string{}}
	h.echo = h.serve(func(c net.Conn) { io.Copy(c, c) })
	if cfg.Listen == "" {
		cfg.Listen = "127.0.0.1:0"
	}
	s := New(cfg)
	s.Resolver.Exchange = h.dn.exchange
	s.Resolver.Timeout = 100 * time.Millisecond
	s.OrigDst = h.origDst
	s.Dial = h.dial
	if setup != nil {
		setup(s)
	}
	if err := s.Install(ordered.Compile(rules, tail, -1), targets); err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", cfg.Listen)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Start(ln); err != nil {
		t.Fatal(err)
	}
	h.s = s
	t.Cleanup(s.Close)
	return h
}

// serve runs handler for every connection on a loopback listener.
func (h *harness) serve(handler func(net.Conn)) string {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		h.t.Fatal(err)
	}
	h.t.Cleanup(func() { l.Close() })
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				handler(c)
			}()
		}
	}()
	return l.Addr().String()
}

func (h *harness) origDst(c net.Conn) (netip.AddrPort, error) {
	p := addrPortOf(c.RemoteAddr()).Port()
	for i := 0; i < 400; i++ {
		h.mu.Lock()
		o, ok := h.orig[p]
		h.mu.Unlock()
		if ok {
			return o, nil
		}
		time.Sleep(5 * time.Millisecond)
	}
	return netip.AddrPort{}, errors.New("no original destination")
}

func (h *harness) dial(ctx context.Context, network, addr string, mark uint32) (net.Conn, error) {
	h.mu.Lock()
	h.dials = append(h.dials, fmt.Sprintf("%s %#x", addr, mark))
	r, ok := h.real[addr]
	h.mu.Unlock()
	if !ok {
		r = h.echo // every virtual upstream is an echo server unless set
	}
	var d net.Dialer
	return d.DialContext(ctx, network, r)
}

func (h *harness) setReal(virtual, real string) {
	h.mu.Lock()
	h.real[virtual] = real
	h.mu.Unlock()
}

func (h *harness) dialLog() []string {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]string(nil), h.dials...)
}

// connect opens a client connection whose original destination is orig.
func (h *harness) connect(orig string) net.Conn {
	h.t.Helper()
	c, err := net.Dial("tcp", h.s.Addr().String())
	if err != nil {
		h.t.Fatal(err)
	}
	h.mu.Lock()
	h.orig[addrPortOf(c.LocalAddr()).Port()] = netip.MustParseAddrPort(orig)
	h.mu.Unlock()
	h.t.Cleanup(func() { c.Close() })
	_ = c.SetDeadline(time.Now().Add(10 * time.Second))
	return c
}

// roundTrip writes the pieces (with a pause between them), then reads the
// echo of all of them.
func (h *harness) roundTrip(c net.Conn, pause time.Duration, pieces ...[]byte) {
	h.t.Helper()
	var all []byte
	for i, p := range pieces {
		if i > 0 && pause > 0 {
			time.Sleep(pause)
		}
		if _, err := c.Write(p); err != nil {
			h.t.Fatal(err)
		}
		all = append(all, p...)
	}
	got := make([]byte, len(all))
	if _, err := io.ReadFull(c, got); err != nil {
		h.t.Fatalf("echo: %v", err)
	}
	if !bytes.Equal(got, all) {
		h.t.Fatal("echo differs from what was sent: bytes lost or reordered")
	}
}

// expectReset: the forwarder closes the connection without relaying.
func expectReset(t *testing.T, c net.Conn) {
	t.Helper()
	b := make([]byte, 1)
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := c.Read(b); err == nil {
		t.Fatal("connection relayed, want it closed")
	} else if ne, ok := err.(net.Error); ok && ne.Timeout() {
		t.Fatal("connection left open, want it closed")
	}
}

// last waits for the newest record with n records in total.
func (h *harness) last(n int) ConnRecord {
	h.t.Helper()
	for i := 0; i < 500; i++ {
		if r := h.s.Recent(); len(r) >= n {
			return r[0]
		}
		time.Sleep(5 * time.Millisecond)
	}
	h.t.Fatalf("no record %d", n)
	return ConnRecord{}
}

func split3(b []byte) [][]byte {
	return [][]byte{b[:3], b[3 : len(b)/2], b[len(b)/2:]}
}

func defaultHarness(t *testing.T, cfg Config) *harness {
	rules, tail := fixtureRules()
	return newHarness(t, cfg, rules, tail, fixtureTargets())
}

// -------------------------------------------------------------- tests ---

// A ClientHello split over TLS records and TCP segments is decided by its
// name; the name is resolved by the target's resolver with the target's
// mark and the connection goes to that answer, not to the address the
// client used; every sniffed byte reaches the upstream.
func TestForwardTLSByName(t *testing.T) {
	h := defaultHarness(t, Config{})
	c := h.connect("203.0.113.5:443")
	hello := records(helloMsg(helloOpts{sni: []string{"a.video.example.net"}, pad: 300}), 100)
	h.roundTrip(c, 20*time.Millisecond, split3(hello)...)
	h.roundTrip(c, 0, []byte("after the handshake"))
	if d := h.dialLog(); len(d) != 1 || d[0] != "198.51.100.10:443 0x10a" {
		t.Fatalf("dials %q", d)
	}
	if q := h.dn.queries(); len(q) != 1 || q[0] != rsHK+" 0x10a a.video.example.net 1" {
		t.Fatalf("queries %q", q)
	}
	r := h.last(1)
	if !r.Sniffed || r.Name != "" || r.Target != "group:hk" || r.By != ordered.ByName || r.Result != "ok" || r.Proto != "tls" || r.RuleID != "video" {
		t.Fatalf("record %+v", r)
	}
}

// Two names on one shared address go to their own targets (what the
// address path cannot do).
func TestSharedAddressTwoNames(t *testing.T) {
	h := defaultHarness(t, Config{})
	for _, n := range []string{"a.video.example.net", "b.ai.example.org"} {
		c := h.connect("203.0.113.5:443")
		h.roundTrip(c, 0, clientHello(n))
	}
	d := h.dialLog()
	if len(d) != 2 || d[0] != "198.51.100.10:443 0x10a" || d[1] != "198.51.100.20:443 0x113" {
		t.Fatalf("dials %q", d)
	}
}

// A keyword rule (which SmartDNS and the address path cannot execute).
func TestKeywordRule(t *testing.T) {
	h := defaultHarness(t, Config{})
	h.roundTrip(h.connect("203.0.113.6:443"), 0, clientHello("x.stream-cdn.example.com"))
	if d := h.dialLog(); len(d) != 1 || d[0] != "198.51.100.21:443 0x113" {
		t.Fatalf("dials %q", d)
	}
	if r := h.last(1); r.RuleID != "kw" {
		t.Fatalf("%+v", r)
	}
}

func TestHTTPHostForward(t *testing.T) {
	h := defaultHarness(t, Config{})
	req := []byte("GET /path HTTP/1.1\r\nHost: b.ai.example.org\r\nUser-Agent: test\r\n\r\n")
	h.roundTrip(h.connect("203.0.113.7:80"), 10*time.Millisecond, req[:5], req[5:30], req[30:])
	if d := h.dialLog(); len(d) != 1 || d[0] != "198.51.100.20:80 0x113" {
		t.Fatalf("dials %q", d)
	}
	if r := h.last(1); r.Proto != "http" || !r.Sniffed {
		t.Fatalf("%+v", r)
	}
}

// Connections without a name are decided by the original destination
// address and connected to it, with the bytes replayed.
func TestFallbackByAddress(t *testing.T) {
	h := defaultHarness(t, Config{})
	cases := []struct {
		name string
		data []byte
		orig string
		dial string
		why  string
	}{
		{"no SNI", records(helloMsg(helloOpts{}), 1<<14), "203.0.113.200:443", "203.0.113.200:443 0x102", WhyNoSNI},
		{"ECH", records(helloMsg(helloOpts{sni: []string{"public.example.net"}, ech: true}), 1<<14), "203.0.113.201:443", "203.0.113.201:443 0x102", WhyECH},
		{"malformed", records(helloMsg(helloOpts{sni: []string{"a.example.org", "b.example.org"}}), 1<<14), "198.51.100.99:443", "198.51.100.99:443 0x10a", WhyMalformed},
		{"not TLS/HTTP", []byte("SSH-2.0-test\r\n"), "192.0.2.150:22", "192.0.2.150:22 0x64", WhyOther},
		{"IP Host", []byte("GET / HTTP/1.1\r\nHost: 198.51.100.98\r\n\r\n"), "198.51.100.98:80", "198.51.100.98:80 0x10a", WhyIPHost},
	}
	for i, c := range cases {
		h.roundTrip(h.connect(c.orig), 0, c.data)
		d := h.dialLog()
		if len(d) != i+1 || d[i] != c.dial {
			t.Fatalf("%s: dials %q, want %s", c.name, d, c.dial)
		}
		if r := h.last(i + 1); r.Sniffed || r.Why != c.why {
			t.Fatalf("%s: %+v", c.name, r)
		}
	}
	if q := h.dn.queries(); len(q) != 0 {
		t.Fatalf("address decisions resolved names: %q", q)
	}
}

// With --ech-outer the cleartext outer name decides (documented as the
// provider's public name for real ECH).
func TestECHOuter(t *testing.T) {
	h := defaultHarness(t, Config{ECHOuter: true})
	h.roundTrip(h.connect("198.51.100.95:443"), 0, records(helloMsg(helloOpts{sni: []string{"public.example.net"}, ech: true}), 1<<14))
	if d := h.dialLog(); len(d) != 1 || d[0] != "198.51.100.12:443 0x10a" {
		t.Fatalf("dials %q", d)
	}
}

// A name decided rule by address (an earlier CIDR rule matches the
// original destination) connects to that destination, no resolution.
func TestAddressRuleBeforeNameRule(t *testing.T) {
	h := defaultHarness(t, Config{})
	h.roundTrip(h.connect("203.0.113.200:443"), 0, clientHello("www.home.example.org"))
	if d := h.dialLog(); len(d) != 1 || d[0] != "203.0.113.200:443 0x102" {
		t.Fatalf("dials %q", d)
	}
	if r := h.last(1); r.By != ordered.ByAddr || !r.Sniffed || r.RuleID != "net" {
		t.Fatalf("%+v", r)
	}
	if len(h.dn.queries()) != 0 {
		t.Fatal("resolved")
	}
}

// Direct targets resolve with the domestic resolvers and the domestic
// mark, also for the built-in domestic list after the rules.
func TestDirectUsesDomestic(t *testing.T) {
	h := defaultHarness(t, Config{})
	h.roundTrip(h.connect("203.0.113.8:443"), 0, clientHello("www.home.example.org"))
	h.roundTrip(h.connect("203.0.113.8:443"), 0, clientHello("a.example.cn"))
	d := h.dialLog()
	if len(d) != 2 || d[0] != "192.0.2.140:443 0x64" || d[1] != "192.0.2.141:443 0x64" {
		t.Fatalf("dials %q", d)
	}
	for _, q := range h.dn.queries() {
		if !strings.HasPrefix(q, rsDom+" 0x64 ") {
			t.Fatalf("query %q", q)
		}
	}
}

// A failed resolution fails the connection: no other resolver, no
// domestic resolver, no dial to the client's address.
func TestResolveFailureNoFallback(t *testing.T) {
	h := defaultHarness(t, Config{})
	expectReset(t, h.connectWrite("203.0.113.9:443", clientHello("fail.ai.example.org")))      // SERVFAIL
	expectReset(t, h.connectWrite("203.0.113.9:443", clientHello("missing.example.org")))      // default group NXDOMAIN
	expectReset(t, h.connectWrite("203.0.113.9:443", clientHello("v6only.video.example.net"))) // no A
	if d := h.dialLog(); len(d) != 0 {
		t.Fatalf("dials %q", d)
	}
	q := h.dn.queries()
	if len(q) != 3 || !strings.HasPrefix(q[0], rsUS+" ") || !strings.HasPrefix(q[1], rsHK+" ") || !strings.HasPrefix(q[2], rsHK+" ") {
		t.Fatalf("queries %q", q)
	}
	if r := h.last(3); r.Result != "resolve_failed" {
		t.Fatalf("%+v", r)
	}
}

func (h *harness) connectWrite(orig string, b []byte) net.Conn {
	c := h.connect(orig)
	if _, err := c.Write(b); err != nil {
		h.t.Fatal(err)
	}
	return c
}

func TestRejectRule(t *testing.T) {
	h := defaultHarness(t, Config{})
	expectReset(t, h.connectWrite("203.0.113.10:443", clientHello("x.ads.example.com")))
	if len(h.dialLog()) != 0 || len(h.dn.queries()) != 0 {
		t.Fatal("rejected connection went out")
	}
	if r := h.last(1); r.Result != "rejected" {
		t.Fatalf("%+v", r)
	}
}

// Device rule by MAC: the client's MAC from the neighbour table selects
// the MAC rule; without it the later rule applies.
func TestMACRule(t *testing.T) {
	rules, tail := fixtureRules()
	var mu sync.Mutex
	known := ""
	h := newHarnessWith(t, Config{}, rules, tail, fixtureTargets(), func(s *Server) {
		s.Neighbors = func(a netip.Addr) string {
			mu.Lock()
			defer mu.Unlock()
			if a == netip.MustParseAddr("127.0.0.1") {
				return known
			}
			return ""
		}
	})
	h.roundTrip(h.connect("203.0.113.11:443"), 0, clientHello("dev.example.org"))
	mu.Lock()
	known = strings.ToUpper(testMAC)
	mu.Unlock()
	h.roundTrip(h.connect("203.0.113.11:443"), 0, clientHello("dev.example.org"))
	d := h.dialLog()
	if len(d) != 2 || d[0] != "198.51.100.22:443 0x113" || d[1] != "198.51.100.30:443 0x102" {
		t.Fatalf("dials %q", d)
	}
}

// A client that sends nothing (server-first protocol) is connected by
// address after the sniff deadline and sees the server's banner.
func TestNoDataServerFirst(t *testing.T) {
	h := defaultHarness(t, Config{SniffTimeout: 150 * time.Millisecond})
	banner := h.serve(func(c net.Conn) {
		c.Write([]byte("220 ready\r\n"))
		io.Copy(c, c)
	})
	h.setReal("203.0.113.212:25", banner)
	c := h.connect("203.0.113.212:25")
	start := time.Now()
	got := make([]byte, 11)
	if _, err := io.ReadFull(c, got); err != nil || string(got) != "220 ready\r\n" {
		t.Fatalf("banner %q %v", got, err)
	}
	if el := time.Since(start); el < 140*time.Millisecond {
		t.Fatalf("connected after %v, before the sniff deadline", el)
	}
	h.roundTrip(c, 0, []byte("EHLO x\r\n"))
	if r := h.last(1); r.Why != WhyNoData || r.Sniffed || r.Target != "exit:jp" {
		t.Fatalf("%+v", r)
	}
}

// A slow client: part of a ClientHello, then nothing past the deadline.
// Decided by address; the partial bytes and the rest arrive in order.
func TestSlowClient(t *testing.T) {
	h := defaultHarness(t, Config{SniffTimeout: 150 * time.Millisecond})
	hello := clientHello("a.video.example.net")
	h.roundTrip(h.connect("198.51.100.97:443"), 400*time.Millisecond, hello[:7], hello[7:])
	if d := h.dialLog(); len(d) != 1 || d[0] != "198.51.100.97:443 0x10a" {
		t.Fatalf("dials %q", d)
	}
	if r := h.last(1); r.Why != WhyTimeout || r.Proto != "tls" || r.Sniffed {
		t.Fatalf("%+v", r)
	}
}

// Oversized first bytes: decided by address, everything relayed.
func TestOversizedFallback(t *testing.T) {
	h := defaultHarness(t, Config{MaxSniffBytes: 4096})
	hello := records(helloMsg(helloOpts{sni: []string{"a.video.example.net"}, pad: 9000}), 1<<14)
	h.roundTrip(h.connect("203.0.113.202:443"), 0, hello)
	if r := h.last(1); r.Why != WhyOversized || r.Target != "exit:jp" {
		t.Fatalf("%+v", r)
	}
	big := []byte("GET / HTTP/1.1\r\nX: " + strings.Repeat("y", 6000) + "\r\nHost: b.ai.example.org\r\n\r\n")
	h.roundTrip(h.connect("203.0.113.203:80"), 0, big)
	if r := h.last(2); r.Why != WhyOversized {
		t.Fatalf("%+v", r)
	}
}

// Ports outside --sniff-ports are decided at once.
func TestSkippedPort(t *testing.T) {
	h := defaultHarness(t, Config{SniffPorts: []uint16{443}, SniffTimeout: 2 * time.Second})
	h.setReal("203.0.113.13:25", h.serve(func(c net.Conn) { c.Write([]byte("hi")) }))
	c := h.connect("203.0.113.13:25")
	start := time.Now()
	b := make([]byte, 2)
	if _, err := io.ReadFull(c, b); err != nil || time.Since(start) > time.Second {
		t.Fatalf("%v after %v", err, time.Since(start))
	}
	if r := h.last(1); r.Why != WhySkipped {
		t.Fatalf("%+v", r)
	}
}

func TestLimitsAndLoop(t *testing.T) {
	h := defaultHarness(t, Config{MaxPerSource: 1, SniffTimeout: 3 * time.Second})
	first := h.connect("203.0.113.14:443") // holds the slot while sniffing
	time.Sleep(50 * time.Millisecond)
	second, err := net.Dial("tcp", h.s.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	expectReset(t, second)
	if n := h.s.Health().Counters["refused_per_source"]; n != 1 {
		t.Fatalf("refused_per_source %d", n)
	}
	first.Close()
	time.Sleep(50 * time.Millisecond)
	// Connecting to the listener itself (would loop).
	loop := h.connect(h.s.Addr().String())
	expectReset(t, loop)
	if r := h.last(2); r.Result != "loop" {
		t.Fatalf("%+v", r)
	}
}

func TestEOFAfterPartialData(t *testing.T) {
	h := defaultHarness(t, Config{})
	c := h.connect("198.51.100.96:443")
	c.Write([]byte("abc"))
	c.(*net.TCPConn).CloseWrite()
	got, err := io.ReadAll(c)
	if err != nil || string(got) != "abc" {
		t.Fatalf("%q %v", got, err)
	}
	if r := h.last(1); r.Why != WhyEOF {
		t.Fatalf("%+v", r)
	}
}

// Recent record: bounded, names only when asked.
func TestRecentAndHealth(t *testing.T) {
	for _, names := range []bool{false, true} {
		h := defaultHarness(t, Config{RecentSize: 3, RecordNames: names})
		for i := 0; i < 5; i++ {
			h.roundTrip(h.connect("203.0.113.15:443"), 0, clientHello("b.ai.example.org"))
		}
		time.Sleep(20 * time.Millisecond)
		rec := h.s.Recent()
		if len(rec) != 3 {
			t.Fatalf("%d records", len(rec))
		}
		srv := httptest.NewServer(h.s.StatusHandler())
		var bodies []string
		for _, p := range []string{"/v1/recent", "/v1/health"} {
			resp, err := http.Get(srv.URL + p)
			if err != nil {
				t.Fatal(err)
			}
			b, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			if resp.StatusCode != 200 {
				t.Fatalf("%s: %d %s", p, resp.StatusCode, b)
			}
			bodies = append(bodies, string(b))
		}
		srv.Close()
		if strings.Contains(bodies[0], "ai.example.org") != names || strings.Contains(bodies[1], "ai.example.org") {
			t.Fatalf("record_names=%v: %s / %s", names, bodies[0], bodies[1])
		}
		var hh Health
		if err := json.Unmarshal([]byte(bodies[1]), &hh); err != nil || !hh.Ready || hh.Rules != 8 || hh.Counters["decided_by_name"] != 5 || !hh.MACRules {
			t.Fatalf("health %+v %v", hh, err)
		}
	}
}

// Install refuses inconsistent targets and keeps the current rules.
func TestInstallChecks(t *testing.T) {
	rules, tail := fixtureRules()
	s := New(Config{})
	c := ordered.Compile(rules, tail, -1)
	ts := fixtureTargets()
	if err := s.Install(c, ts); err != nil {
		t.Fatal(err)
	}
	gen := s.Health().Generation
	bad := map[string]func([]Target) []Target{
		"missing target":       func(t []Target) []Target { return t[1:] },
		"wrong mark":           func(t []Target) []Target { t[1].Mark = 0x199; return t },
		"reject with resolver": func(t []Target) []Target { t[4].Resolvers = []string{rsHK}; return t },
		"bad resolver":         func(t []Target) []Target { t[2].Resolvers = []string{"resolver.example"}; return t },
		"shared mark":          func(t []Target) []Target { t[3].Mark = t[2].Mark; return t },
		"reject mismatch": func(t []Target) []Target {
			t[4].Reject = false
			t[4].Resolvers = []string{rsHK}
			return t
		},
	}
	for name, f := range bad {
		if err := s.Install(c, f(fixtureTargets())); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if s.Health().Generation != gen {
		t.Fatal("a refused install changed the rules")
	}
	// A target without resolvers is accepted since R3 (an exit reached only
	// over the Mesh has no tunnel resolver): names decided to it fail with
	// ErrNoResolvers instead of using another resolver (TestNoResolverTarget).
	nr := fixtureTargets()
	nr[2].Resolvers = nil
	if err := s.Install(c, nr); err != nil {
		t.Fatalf("target without resolvers refused: %v", err)
	}
}

// Swapping rules while decisions run: every decision is the reference
// decision of one of the two lists, never a mixture or "no rules".
func TestAtomicSwap(t *testing.T) {
	rules, tail := fixtureRules()
	alt := append([]ordered.Rule{{ID: "all", Target: "group:us", Mark: mUS, Entries: []ordered.Entry{sfx("example.net")}}}, rules...)
	s := New(Config{})
	ca, cb := ordered.Compile(rules, tail, -1), ordered.Compile(alt, tail, -1)
	if err := s.Install(ca, fixtureTargets()); err != nil {
		t.Fatal(err)
	}
	conn := Conn{Source: netip.MustParseAddrPort("192.0.2.200:5000"), OrigDst: netip.MustParseAddrPort("203.0.113.5:443"), Sniff: Result{Name: "a.video.example.net"}}
	wantA := ordered.Reference(rules, tail, ordered.Query{Name: "a.video.example.net", Addr: conn.OrigDst.Addr(), Source: conn.Source.Addr()})
	wantB := ordered.Reference(alt, tail, ordered.Query{Name: "a.video.example.net", Addr: conn.OrigDst.Addr(), Source: conn.Source.Addr()})
	if wantA.Target == wantB.Target {
		t.Fatal("fixture: lists must differ")
	}
	var wg sync.WaitGroup
	stop := make(chan struct{})
	errs := make(chan string, 1)
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				d, _, ok := s.Decide(conn)
				if !ok || (d.Target != wantA.Target && d.Target != wantB.Target) {
					select {
					case errs <- fmt.Sprintf("%+v ok=%v", d, ok):
					default:
					}
				}
			}
		}()
	}
	for i := 0; i < 200; i++ {
		c := ca
		if i%2 == 0 {
			c = cb
		}
		if err := s.Install(c, fixtureTargets()); err != nil {
			t.Fatal(err)
		}
	}
	close(stop)
	wg.Wait()
	select {
	case e := <-errs:
		t.Fatal(e)
	default:
	}
}

// --------------------------------------------------------- equivalence ---

// The forwarder's decision on sniffed bytes equals the reference
// interpreter (ordered.Reference) on generated lists with every entry
// kind, keyword rules, device rules by address and by MAC, GEOIP,CN and
// the tail; a share of the cases also go end to end through the
// listener.
func TestDecisionsMatchReference(t *testing.T) {
	rng := rand.New(rand.NewSource(11))
	uni := []string{"example.com", "a.example.com", "b.a.example.com", "example.net", "x.example.net", "cdn.example.org", "stream.example.org", "teststream.example.cn", "example.cn"}
	kws := []string{"stream", "cdn", "a.ex", "test"}
	cidrs := []string{"198.51.100.0/24", "198.51.100.128/25", "203.0.113.0/24", "2001:db8::/32"}
	srcs := []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8"), netip.MustParsePrefix("192.0.2.200/32")}
	macs := []string{testMAC, "02:00:00:00:00:02"}
	addrs := []string{"198.51.100.7", "198.51.100.200", "203.0.113.4", "192.0.2.130", "2001:db8::5"}
	tail := ordered.Tail{Domestic: []string{"example.cn"}, China: []netip.Prefix{netip.MustParsePrefix("192.0.2.128/25")},
		DirectTarget: "direct", DirectMark: mDirect, Default: "T0", DefaultMark: 0x101}
	var targets []Target
	for k := 0; k < 4; k++ {
		targets = append(targets, Target{Name: fmt.Sprintf("T%d", k), Mark: uint32(0x101 + k), Resolvers: []string{fmt.Sprintf("[fd66::53:%d]:53", k+1)}, IPv6: true})
	}
	targets = append(targets, Target{Name: "direct", Mark: mDirect, Resolvers: []string{rsDom}, IPv6: true})
	n, e2e := 0, 0
	for iter := 0; iter < 300; iter++ {
		var rules []ordered.Rule
		for i := 0; i < 1+rng.Intn(8); i++ {
			k := rng.Intn(5)
			r := ordered.Rule{ID: fmt.Sprint(i), Target: fmt.Sprintf("T%d", k), Mark: uint32(0x101 + k), GeoIPCN: rng.Intn(12) == 0}
			if k == 4 {
				r.Target, r.Mark, r.Action = "direct", mDirect, "direct"
			}
			if rng.Intn(6) == 0 {
				r.Sources = []netip.Prefix{srcs[rng.Intn(2)]}
			}
			if rng.Intn(6) == 0 {
				r.SourceMAC = macs[rng.Intn(2)]
			}
			for j := 0; j < 1+rng.Intn(3); j++ {
				switch rng.Intn(5) {
				case 0:
					r.Entries = append(r.Entries, sfx(uni[rng.Intn(len(uni))]))
				case 1:
					r.Entries = append(r.Entries, ordered.Entry{Kind: ordered.Exact, Value: uni[rng.Intn(len(uni))]})
				case 2:
					r.Entries = append(r.Entries, ordered.Entry{Kind: ordered.Sub, Value: uni[rng.Intn(len(uni))]})
				case 3:
					r.Entries = append(r.Entries, ordered.Entry{Kind: ordered.Keyword, Value: kws[rng.Intn(len(kws))]})
				default:
					r.Entries = append(r.Entries, ordered.Entry{Kind: ordered.CIDR, Prefix: netip.MustParsePrefix(cidrs[rng.Intn(len(cidrs))])})
				}
			}
			rules = append(rules, r)
		}
		s := New(Config{})
		if err := s.Install(ordered.Compile(rules, tail, -1), targets); err != nil {
			t.Fatal(err)
		}
		for _, name := range append(uni, "zz.example.org", "") {
			var first []byte
			switch {
			case name == "":
				first = records(helloMsg(helloOpts{}), 1<<14)
			case rng.Intn(2) == 0:
				first = records(helloMsg(helloOpts{sni: []string{name}}), 1+rng.Intn(200))
			default:
				first = []byte("GET / HTTP/1.1\r\nHost: " + name + "\r\n\r\n")
			}
			sn, _ := Sniff(first, DefaultMaxSniffBytes)
			for _, a := range addrs {
				for _, src := range []string{"127.0.0.1", "192.0.2.200", "192.0.2.201"} {
					for _, mac := range []string{"", testMAC, "02:00:00:00:00:02"} {
						conn := Conn{Source: netip.AddrPortFrom(netip.MustParseAddr(src), 40000), MAC: mac, OrigDst: netip.AddrPortFrom(netip.MustParseAddr(a), 443), Sniff: sn}
						got, used, _ := s.Decide(conn)
						want := ordered.Reference(rules, tail, ordered.Query{Name: name, Addr: conn.OrigDst.Addr(), Source: conn.Source.Addr(), SourceMAC: mac})
						if used != name || got.Index != want.Index || got.Target != want.Target {
							for i, r := range rules {
								t.Logf("%d %s src=%v mac=%q geo=%v %v", i, r.Target, r.Sources, r.SourceMAC, r.GeoIPCN, r.Entries)
							}
							t.Fatalf("name %q addr %s src %s mac %q: forwarder %d %s (name %q), reference %d %s (%s)", name, a, src, mac, got.Index, got.Target, used, want.Index, want.Target, want.Reason)
						}
						n++
					}
				}
			}
		}
		// End to end for some lists: the decision recorded by the running
		// forwarder for a real connection equals the reference.
		if iter%30 == 0 {
			h := newHarness(t, Config{}, rules, tail, targets)
			h.dn.mu.Lock()
			for k := range targets[:4] {
				h.dn.stubs[fmt.Sprintf("[fd66::53:%d]:53", k+1)] = &dnsStub{any: []netip.Addr{netip.MustParseAddr("198.51.100.77")}, ttl: 30}
			}
			h.dn.stubs[rsDom] = &dnsStub{any: []netip.Addr{netip.MustParseAddr("192.0.2.77")}, ttl: 30}
			h.dn.mu.Unlock()
			for i, name := range uni {
				a := addrs[i%(len(addrs)-1)] // IPv4 destinations
				h.roundTrip(h.connect(a+":443"), 0, clientHello(name))
				r := h.last(i + 1)
				want := ordered.Reference(rules, tail, ordered.Query{Name: name, Addr: netip.MustParseAddr(a), Source: netip.MustParseAddr("127.0.0.1")})
				if r.RuleIndex != want.Index || r.Target != want.Target {
					t.Fatalf("end to end %s @%s: %+v, reference %d %s", name, a, r, want.Index, want.Target)
				}
				e2e++
			}
		}
	}
	t.Logf("%d decisions and %d forwarded connections equal the reference interpreter", n, e2e)
}

// ------------------------------------------------------- files, reload ---

func TestLoadFilesAndReload(t *testing.T) {
	dir := t.TempDir()
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	for _, d := range []string{"lists", "geosite", "keywords"} {
		must(os.MkdirAll(filepath.Join(dir, d), 0o755))
	}
	must(os.WriteFile(filepath.Join(dir, "lists", "china.txt"), []byte("192.0.2.128/25\n"), 0o644))
	must(os.WriteFile(filepath.Join(dir, "geosite", "cn.txt"), []byte("example.cn\n"), 0o644))
	snap := ordered.Snapshot{Version: ordered.SnapshotVersion, QUICAt: -1, Rules: []ordered.SnapshotRule{
		{ID: "mac", Target: "exit:jp", Mark: mJP, Entries: string(ordered.MarshalEntries([]ordered.Entry{sfx("dev.example.org")})), SourceMAC: strings.ToUpper(testMAC)},
		{ID: "kw", Target: "group:us", Mark: mUS, Entries: string(ordered.MarshalEntries([]ordered.Entry{{Kind: ordered.Keyword, Value: "stream"}}))},
		{ID: "dev", Target: "group:us", Mark: mUS, Entries: string(ordered.MarshalEntries([]ordered.Entry{sfx("dev.example.org")})), SourceAddrs: []string{"127.0.0.1"}},
	}, Tail: ordered.SnapshotTail{DomesticGeosite: "cn", DirectMark: mDirect, Default: "group:hk", DefaultMark: mHK}}
	sb, _ := json.Marshal(snap)
	must(os.WriteFile(filepath.Join(dir, "decide.json"), sb, 0o644))
	tb, _ := json.Marshal(TargetsFile{Version: TargetsVersion, Targets: fixtureTargets()})
	must(os.WriteFile(filepath.Join(dir, "targets.json"), tb, 0o644))
	cfg := Config{SnapshotPath: filepath.Join(dir, "decide.json"), TargetsPath: filepath.Join(dir, "targets.json"), ListsDir: dir}
	s := New(cfg)
	must(s.Reload())
	dec := func(name, mac string) string {
		d, _, _ := s.Decide(Conn{Source: netip.MustParseAddrPort("127.0.0.1:1"), MAC: mac, OrigDst: netip.MustParseAddrPort("192.0.2.130:443"), Sniff: Result{Name: name}})
		return d.Target + "/" + d.By
	}
	for _, c := range [][3]string{
		{"dev.example.org", testMAC, "exit:jp/name"}, // the MAC rule is not skipped any more
		{"dev.example.org", "", "group:us/name"},
		{"live-stream.example.org", "", "group:us/name"}, // keyword
		{"a.example.cn", "", "direct/name"},              // domestic list
		{"other.example.org", "", "direct/addr"},         // China address
	} {
		if got := dec(c[0], c[1]); got != c[2] {
			t.Errorf("%s mac %q: %s, want %s", c[0], c[1], got, c[2])
		}
	}
	gen := s.Health().Generation
	// A broken target file: the reload fails, the rules stay.
	must(os.WriteFile(filepath.Join(dir, "targets.json"), []byte(`{"version":1,"targets":[{"target":"group:hk","mark":1,"resolvers":["x"]}]}`), 0o644))
	if err := s.Reload(); err == nil {
		t.Fatal("broken target file accepted")
	}
	h := s.Health()
	if h.Generation != gen || h.LastReloadError == "" || dec("dev.example.org", "") != "group:us/name" {
		t.Fatalf("after failed reload: %+v", h)
	}
	must(os.WriteFile(filepath.Join(dir, "targets.json"), []byte(`{"version":1,"targets":[],"extra":1}`), 0o644))
	if err := s.Reload(); err == nil {
		t.Fatal("unknown field accepted")
	}
}

func TestParseArgs(t *testing.T) {
	c, err := ParseArgs([]string{"--listen", "127.0.0.1:7890", "--mode", "redirect", "--snapshot", "/a", "--targets", "/b", "--sniff-ports", "80,443", "--neigh-if", "lan0"})
	if err != nil || c.Mode != "redirect" || len(c.SniffPorts) != 2 || c.NeighIfaces[0] != "lan0" || c.RecordNames || c.ECHOuter {
		t.Fatalf("%+v %v", c, err)
	}
	for _, bad := range [][]string{
		{"--listen", "x", "--snapshot", "/a", "--targets", "/b"},
		{"--listen", "127.0.0.1:1", "--snapshot", "/a"},
		{"--listen", "127.0.0.1:1", "--snapshot", "/a", "--targets", "/b", "--mode", "socks"},
		{"--listen", "127.0.0.1:1", "--snapshot", "/a", "--targets", "/b", "--sniff-ports", "0"},
		{"--listen", "127.0.0.1:1", "--snapshot", "/a", "--targets", "/b", "--max-sniff-bytes", "10"},
		{"--listen", "127.0.0.1:1", "--snapshot", "/a", "--targets", "/b", "--addr-mark-bit", "0x3"},
		{"--listen", "127.0.0.1:1", "--snapshot", "/a", "--targets", "/b", "--ech-public-names", "not a name"},
	} {
		if _, err := ParseArgs(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestParseArgsR3(t *testing.T) {
	c, err := ParseArgs([]string{"--listen", "[::]:5358", "--snapshot", "/a", "--targets", "/b", "--ech-outer", "--ech-public-names", "Cloudflare-ECH.com,ech.example.net", "--addr-mark-bit", "0x1000000"})
	if err != nil || !c.ECHOuter || strings.Join(c.ECHPublicNames, ",") != "cloudflare-ech.com,ech.example.net" || c.AddrMarkBit != 0x1000000 {
		t.Fatalf("%+v %v", c, err)
	}
}

func TestNeighborParse(t *testing.T) {
	msg := func(ifindex int32, state uint16, addr []byte, ll []byte) []byte {
		b := make([]byte, 12)
		b[0] = 2
		putNE32(b[4:], uint32(ifindex))
		putNE16(b[8:], state)
		attr := func(typ uint16, v []byte) {
			a := make([]byte, 4, 4+len(v)+3)
			putNE16(a, uint16(4+len(v)))
			putNE16(a[2:], typ)
			a = append(a, v...)
			for len(a)%4 != 0 {
				a = append(a, 0)
			}
			b = append(b, a...)
		}
		attr(ndaDst, addr)
		if ll != nil {
			attr(ndaLLAddr, ll)
		}
		return b
	}
	mac := []byte{2, 0, 0, 0, 0, 1}
	n, ok := parseNeighMsg(msg(3, nudReachable, []byte{192, 0, 2, 9}, mac))
	if !ok || n.Addr != netip.MustParseAddr("192.0.2.9") || n.MAC != testMAC || n.Ifindex != 3 {
		t.Fatalf("%+v %v", n, ok)
	}
	if _, ok := parseNeighMsg(msg(3, nudFailed, []byte{192, 0, 2, 9}, mac)); ok {
		t.Fatal("failed entry used")
	}
	if _, ok := parseNeighMsg(msg(3, nudReachable, []byte{192, 0, 2, 9}, nil)); ok {
		t.Fatal("entry without lladdr used")
	}
	v6 := netip.MustParseAddr("2001:db8::9").AsSlice()
	if n, ok := parseNeighMsg(msg(4, nudStale, v6, mac)); !ok || n.Addr.String() != "2001:db8::9" {
		t.Fatalf("v6 %+v", n)
	}
	for k := 0; k < 40; k++ {
		parseNeighMsg(msg(3, nudReachable, []byte{192, 0, 2, 9}, mac)[:k]) // no panic
	}
	now := time.Unix(0, 0)
	calls := 0
	tab := &NeighborTable{Ifindexes: []int{3}, MaxAge: time.Second, Now: func() time.Time { return now }, Dump: func() ([]Neighbor, error) {
		calls++
		return []Neighbor{{Addr: netip.MustParseAddr("192.0.2.9"), MAC: testMAC, Ifindex: 3}, {Addr: netip.MustParseAddr("192.0.2.10"), MAC: testMAC, Ifindex: 9}}, nil
	}}
	if tab.Lookup(netip.MustParseAddr("192.0.2.9")) != testMAC || tab.Lookup(netip.MustParseAddr("192.0.2.10")) != "" || calls != 1 {
		t.Fatalf("lookup (calls %d)", calls)
	}
	now = now.Add(2 * time.Second)
	tab.Lookup(netip.MustParseAddr("::ffff:192.0.2.9"))
	if calls != 2 {
		t.Fatal("not refreshed")
	}
}

func putNE16(b []byte, v uint16) { binary.NativeEndian.PutUint16(b, v) }
func putNE32(b []byte, v uint32) { binary.NativeEndian.PutUint32(b, v) }

// AddrMark: a connection without a name takes the address classifier's
// mark; an unknown mark fails the connection.
func TestAddrMark(t *testing.T) {
	rules, tail := fixtureRules()
	var mu sync.Mutex
	mark := uint32(mUS)
	h := newHarnessWith(t, Config{}, rules, tail, fixtureTargets(), func(s *Server) {
		s.AddrMark = func(net.Conn) (uint32, bool) {
			mu.Lock()
			defer mu.Unlock()
			return mark, true
		}
	})
	h.roundTrip(h.connect("203.0.113.200:443"), 0, []byte("SSH-2.0-test\r\n"))
	if d := h.dialLog(); len(d) != 1 || d[0] != "203.0.113.200:443 0x113" {
		t.Fatalf("dials %q", d)
	}
	// A name still decides by name.
	h.roundTrip(h.connect("203.0.113.5:443"), 0, clientHello("a.video.example.net"))
	mu.Lock()
	mark = 0x777
	mu.Unlock()
	expectReset(t, h.connectWrite("203.0.113.200:443", []byte("SSH-2.0-test\r\n")))
	if r := h.last(3); r.Result != "unknown_mark" {
		t.Fatalf("%+v", r)
	}
	if d := h.dialLog(); len(d) != 2 || d[1] != "198.51.100.10:443 0x10a" {
		t.Fatalf("dials %q", d)
	}
}

// R3: a target without resolvers (an exit reached only over the Mesh, no
// tunnel resolver) is installed; a name decided to it fails without asking
// any other resolver, and a connection without a name still goes to its
// original address with that target's mark.
func TestNoResolverTarget(t *testing.T) {
	rules, tail := fixtureRules()
	ts := fixtureTargets()
	ts[1].Resolvers = nil // exit:jp
	rules = append([]ordered.Rule{{ID: "jpname", Target: "exit:jp", Mark: mJP, Entries: []ordered.Entry{sfx("jp.example.org")}}}, rules...)
	h := newHarness(t, Config{}, rules, tail, ts)
	expectReset(t, h.connectWrite("203.0.113.9:443", clientHello("www.jp.example.org")))
	if r := h.last(1); r.Result != "resolve_failed" || r.Target != "exit:jp" {
		t.Fatalf("%+v", r)
	}
	h.roundTrip(h.connect("203.0.113.200:443"), 0, []byte("SSH-2.0-test\r\n"))
	if d := h.dialLog(); len(d) != 1 || d[0] != "203.0.113.200:443 0x102" {
		t.Fatalf("dials %q", d)
	}
	if q := h.dn.queries(); len(q) != 0 {
		t.Fatalf("queries %q", q)
	}
}

// R3: targets are matched by mark. A static region group's rules carry its
// member exit's mark: "group:static" and "exit:jp" share one target entry
// (its label is the exit's), and the decision record keeps the rule's own
// target name.
func TestTargetsByMark(t *testing.T) {
	rules, tail := fixtureRules()
	rules = append([]ordered.Rule{{ID: "static", Target: "group:static", Mark: mJP, Entries: []ordered.Entry{sfx("dev.example.org")}}}, rules...)
	h := newHarness(t, Config{}, rules, tail, fixtureTargets())
	h.roundTrip(h.connect("203.0.113.5:443"), 0, clientHello("dev.example.org"))
	if d := h.dialLog(); len(d) != 1 || d[0] != "198.51.100.30:443 0x102" {
		t.Fatalf("dials %q", d)
	}
	if q := h.dn.queries(); len(q) != 1 || !strings.HasPrefix(q[0], rsJP+" ") {
		t.Fatalf("queries %q", q)
	}
	if r := h.last(1); r.Target != "group:static" || r.Mark != mJP {
		t.Fatalf("%+v", r)
	}
	// A mark the target file does not list is refused at install.
	bad := append([]ordered.Rule{{ID: "x", Target: "group:static", Mark: 0x1ff, Entries: []ordered.Entry{sfx("x.example.org")}}}, rules...)
	if err := New(Config{}).Install(ordered.Compile(bad, tail, -1), fixtureTargets()); err == nil {
		t.Fatal("a rule mark without a target entry was installed")
	}
}

// R3 ECH: with ECHOuter the cleartext name decides (the real name of a
// GREASE ECH ClientHello), except for a configured ECH public name (and
// names under it), which is decided by address; the record says which.
func TestECHPublicNames(t *testing.T) {
	h := defaultHarness(t, Config{ECHOuter: true, ECHPublicNames: []string{"example.net"}})
	ech := func(n string) []byte { return records(helloMsg(helloOpts{sni: []string{n}, ech: true}), 1<<14) }
	h.roundTrip(h.connect("203.0.113.201:443"), 0, ech("public.example.net"))
	if r := h.last(1); r.Sniffed || r.Why != WhyECHPublic || r.By != ordered.ByAddr {
		t.Fatalf("public name: %+v", r)
	}
	h.roundTrip(h.connect("203.0.113.5:443"), 0, ech("b.ai.example.org"))
	if r := h.last(2); !r.Sniffed || r.Why != WhyECHOuter || r.RuleID != "ai" {
		t.Fatalf("GREASE name: %+v", r)
	}
	d := h.dialLog()
	if len(d) != 2 || d[0] != "203.0.113.201:443 0x102" || d[1] != "198.51.100.20:443 0x113" {
		t.Fatalf("dials %q", d)
	}
}

// R3: the target file can name the snapshot it belongs to; a pair from two
// generations is refused (startup fails, a reload keeps the current pair).
func TestSnapshotPair(t *testing.T) {
	dir := t.TempDir()
	snap := []byte(`{"version":1,"rules":[],"quic_at":-1,"tail":{"domestic_geosite":"","direct_mark":100,"default":"group:hk","default_mark":266}}`)
	other := []byte(`{"version":1,"rules":[],"quic_at":-1,"tail":{"domestic_geosite":"","direct_mark":100,"default":"group:hk","default_mark":266} }`)
	sum := sha256.Sum256(snap)
	tf := fmt.Sprintf(`{"version":1,"snapshot_sha256":%q,"targets":[{"target":"direct","mark":100,"resolvers":["192.0.2.53:53"]},{"target":"group:hk","mark":266,"resolvers":["[fd66::53:a]:53"]}]}`, hex.EncodeToString(sum[:]))
	cfg := Config{SnapshotPath: filepath.Join(dir, "decide.json"), TargetsPath: filepath.Join(dir, "targets.json"), ListsDir: dir}
	if err := os.WriteFile(cfg.TargetsPath, []byte(tf), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cfg.SnapshotPath, snap, 0o644); err != nil {
		t.Fatal(err)
	}
	s := New(cfg)
	if err := s.Reload(); err != nil {
		t.Fatal(err)
	}
	gen := s.Health().Generation
	if err := os.WriteFile(cfg.SnapshotPath, other, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := s.Reload(); err == nil || !strings.Contains(err.Error(), "two generations") {
		t.Fatalf("mismatched pair loaded: %v", err)
	}
	if h := s.Health(); h.Generation != gen || h.LastReloadError == "" {
		t.Fatalf("%+v", h)
	}
}

// MarkFromSocket off Linux (and on a socket without the bit) reports mark
// 0, which no target has: the connection is reset, never decided by the
// forwarder's own address view.
func TestMarkFromSocketNoBit(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	go func() {
		if c, err := l.Accept(); err == nil {
			c.Close()
		}
	}()
	c, err := net.Dial("tcp", l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if m, ok := MarkFromSocket(0x01000000)(c); m != 0 || !ok {
		t.Fatalf("mark %#x ok %v", m, ok)
	}
}
