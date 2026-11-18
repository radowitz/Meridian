package sniff

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"
)

// dnsStub is one synthetic resolver.
type dnsStub struct {
	answers map[string][]netip.Addr // name -> addresses (both families)
	rcode   int                     // for names without answers: 0 NODATA, 3 NXDOMAIN, 2 SERVFAIL
	down    bool                    // no answer at all
	ttl     uint32
	cname   bool         // answer through a CNAME first
	any     []netip.Addr // answer for every name not in answers
}

// dnsNet routes exchanges to stubs by server address and logs every
// query as "server mark name type".
type dnsNet struct {
	mu    sync.Mutex
	stubs map[string]*dnsStub
	log   []string
}

func (d *dnsNet) exchange(ctx context.Context, server string, mark uint32, q []byte) ([]byte, error) {
	name, i, err := readQName(q, 12)
	if err != nil {
		return nil, err
	}
	qt := binary.BigEndian.Uint16(q[i:])
	d.mu.Lock()
	d.log = append(d.log, fmt.Sprintf("%s %#x %s %d", server, mark, name, qt))
	st := d.stubs[server]
	d.mu.Unlock()
	if st == nil || st.down {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	var as []netip.Addr
	all, listed := st.answers[name]
	if !listed && st.any != nil {
		all, listed = st.any, true
	}
	for _, a := range all {
		if a.Is4() == (qt == typeA) {
			as = append(as, a)
		}
	}
	rcode := 0
	if !listed {
		rcode = st.rcode
	}
	return reply(q, i+4, as, rcode, st.ttl, st.cname), nil
}

func (d *dnsNet) queries() []string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return append([]string(nil), d.log...)
}

// reply answers query q (question ends at qend).
func reply(q []byte, qend int, as []netip.Addr, rcode int, ttl uint32, cname bool) []byte {
	out := append([]byte(nil), q[:qend]...)
	out[2] = 0x81
	out[3] = 0x80 | byte(rcode)
	n := len(as)
	if cname && n > 0 {
		n++
	}
	binary.BigEndian.PutUint16(out[6:], uint16(n))
	binary.BigEndian.PutUint16(out[8:], 0)
	binary.BigEndian.PutUint16(out[10:], 0)
	rr := func(owner []byte, typ uint16, rd []byte) {
		out = append(out, owner...)
		var h [10]byte
		binary.BigEndian.PutUint16(h[0:], typ)
		binary.BigEndian.PutUint16(h[2:], 1)
		binary.BigEndian.PutUint32(h[4:], ttl)
		binary.BigEndian.PutUint16(h[8:], uint16(len(rd)))
		out = append(out, h[:]...)
		out = append(out, rd...)
	}
	owner := []byte{0xc0, 12}
	if cname && len(as) > 0 {
		at := len(out) + 12
		rr(owner, 5, []byte{3, 'c', 'd', 'n', 0xc0, 12})
		owner = []byte{0xc0 | byte(at>>8), byte(at)}
	}
	for _, a := range as {
		typ := typeA
		if a.Is6() {
			typ = typeAAAA
		}
		rr(owner, typ, a.AsSlice())
	}
	return out
}

func tgt(name string, mark uint32, servers ...string) Target {
	return Target{Name: name, Mark: mark, Resolvers: servers}
}

var (
	addrA = netip.MustParseAddr("198.51.100.10")
	addrB = netip.MustParseAddr("198.51.100.20")
	addr6 = netip.MustParseAddr("2001:db8::20")
)

func TestResolverTargetIsolation(t *testing.T) {
	dn := &dnsNet{stubs: map[string]*dnsStub{
		"[fd66::54:1]:53": {answers: map[string][]netip.Addr{"shared.example.org": {addrA}}, ttl: 60},
		"[fd66::53:2]:53": {answers: map[string][]netip.Addr{"shared.example.org": {addrB}}, ttl: 60, cname: true},
		"[fd66::53:3]:53": {down: true},
	}}
	r := NewResolver()
	r.Exchange, r.Timeout = dn.exchange, 50*time.Millisecond
	ex := tgt("exit:a", 0x102, "[fd66::54:1]:53")
	gr := tgt("group:b", 0x113, "[fd66::53:2]:53")
	dead := tgt("group:c", 0x114, "[fd66::53:3]:53")
	ctx := context.Background()
	for i := 0; i < 3; i++ {
		a, err := r.Lookup(ctx, ex, "shared.example.org", false)
		if err != nil || len(a) != 1 || a[0] != addrA {
			t.Fatalf("exit: %v %v", a, err)
		}
		b, err := r.Lookup(ctx, gr, "shared.example.org", false)
		if err != nil || len(b) != 1 || b[0] != addrB {
			t.Fatalf("group (CNAME): %v %v", b, err)
		}
	}
	// One query per target (then cached), each to its own server with
	// its own mark.
	q := dn.queries()
	if len(q) != 2 || q[0] != "[fd66::54:1]:53 0x102 shared.example.org 1" || q[1] != "[fd66::53:2]:53 0x113 shared.example.org 1" {
		t.Fatalf("queries %q", q)
	}
	// A target whose resolver does not answer fails; nothing cached for
	// another target is used and no other server is asked.
	if _, err := r.Lookup(ctx, dead, "shared.example.org", false); !errors.Is(err, ErrResolve) {
		t.Fatalf("dead target: %v", err)
	}
	if q := dn.queries(); len(q) != 3 || q[2][:15] != "[fd66::53:3]:53" {
		t.Fatalf("queries after failure %q", q)
	}
	if r.CacheLen(dead) != 0 {
		t.Fatal("failure cached")
	}
	// DNSMark overrides the query mark (and so the cache key).
	zero := uint32(0)
	ex0 := ex
	ex0.DNSMark = &zero
	if _, err := r.Lookup(ctx, ex0, "shared.example.org", false); err != nil {
		t.Fatal(err)
	}
	if q := dn.queries(); q[len(q)-1] != "[fd66::54:1]:53 0x0 shared.example.org 1" {
		t.Fatalf("dns mark: %q", q[len(q)-1])
	}
	// Purge keeps only the listed targets.
	r.Purge([]Target{gr})
	if r.CacheLen(ex) != 0 || r.CacheLen(gr) != 1 {
		t.Fatalf("purge: %d %d", r.CacheLen(ex), r.CacheLen(gr))
	}
}

func TestResolverAnswers(t *testing.T) {
	dn := &dnsNet{stubs: map[string]*dnsStub{
		"192.0.2.53:53": {answers: map[string][]netip.Addr{"v6.example.org": {addr6}}, rcode: 3, ttl: 1},
		"192.0.2.54:53": {rcode: 2},
	}}
	now := time.Unix(1000, 0)
	r := NewResolver()
	r.Exchange, r.Timeout, r.Now = dn.exchange, 50*time.Millisecond, func() time.Time { return now }
	ctx := context.Background()
	d := tgt("direct", 0x64, "192.0.2.53:53")
	if a, err := r.Lookup(ctx, d, "v6.example.org", true); err != nil || len(a) != 1 || a[0] != addr6 {
		t.Fatalf("AAAA: %v %v", a, err)
	}
	if a, err := r.Lookup(ctx, d, "v6.example.org", false); err != nil || len(a) != 0 {
		t.Fatalf("NODATA: %v %v", a, err)
	}
	if _, err := r.Lookup(ctx, d, "nx.example.org", false); !errors.Is(err, ErrNXDomain) {
		t.Fatalf("NXDOMAIN: %v", err)
	}
	n := len(dn.queries())
	r.Lookup(ctx, d, "nx.example.org", false) // negative cache
	if len(dn.queries()) != n {
		t.Fatal("NXDOMAIN not cached")
	}
	// TTL 1 s is raised to MinTTL; after it the name is asked again.
	now = now.Add(DefaultMinTTL + time.Second)
	r.Lookup(ctx, d, "v6.example.org", true)
	if len(dn.queries()) != n+1 {
		t.Fatal("expired entry not refreshed")
	}
	// SERVFAIL from the first resolver: the next resolver of the SAME
	// target is asked; SERVFAIL everywhere is an error, not cached.
	two := tgt("direct", 0x64, "192.0.2.54:53", "192.0.2.53:53")
	if a, err := r.Lookup(ctx, two, "v6.example.org", true); err != nil || len(a) != 1 {
		t.Fatalf("second resolver: %v %v", a, err)
	}
	only := tgt("direct", 0x64, "192.0.2.54:53")
	if _, err := r.Lookup(ctx, only, "v6.example.org", true); !errors.Is(err, ErrResolve) {
		t.Fatalf("SERVFAIL: %v", err)
	}
	if _, err := r.Lookup(ctx, Target{Name: "x", Mark: 1}, "a.example", false); !errors.Is(err, ErrNoResolvers) {
		t.Fatalf("no resolvers: %v", err)
	}
}

func TestResolverCacheBound(t *testing.T) {
	dn := &dnsNet{stubs: map[string]*dnsStub{"192.0.2.53:53": {rcode: 3}}}
	r := NewResolver()
	r.Exchange, r.CacheSize = dn.exchange, 64
	d := tgt("direct", 0x64, "192.0.2.53:53")
	for i := 0; i < 1000; i++ {
		r.Lookup(context.Background(), d, fmt.Sprintf("n%d.example.org", i), false)
	}
	if n := r.CacheLen(d); n > 64 {
		t.Fatalf("cache %d entries", n)
	}
}

func TestParseAnswerChecks(t *testing.T) {
	q, id, _ := buildQuery("a.example.org", typeA)
	_, i, _ := readQName(q, 12)
	good := reply(q[:i+4], i+4, []netip.Addr{addrA}, 0, 30, false)
	if a, ttl, rc, err := parseAnswer(good, id, "a.example.org", typeA); err != nil || rc != 0 || len(a) != 1 || ttl != 30*time.Second {
		t.Fatalf("%v %v %v %v", a, ttl, rc, err)
	}
	if _, _, _, err := parseAnswer(good, id+1, "a.example.org", typeA); err == nil {
		t.Fatal("wrong id accepted")
	}
	if _, _, _, err := parseAnswer(good, id, "b.example.org", typeA); err == nil {
		t.Fatal("wrong question accepted")
	}
	for k := 0; k < len(good); k++ {
		parseAnswer(good[:k], id, "a.example.org", typeA) // no panic
	}
}

// ExchangeNet against a loopback UDP/TCP server, including a truncated
// UDP reply that moves the query to TCP (mark 0: works without Linux).
func TestExchangeNetTruncation(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	tl, err := net.Listen("tcp", pc.LocalAddr().String())
	if err != nil {
		t.Skipf("tcp on the same port: %v", err)
	}
	defer tl.Close()
	go func() {
		b := make([]byte, 512)
		for {
			n, a, err := pc.ReadFrom(b)
			if err != nil {
				return
			}
			_, i, _ := readQName(b[:n], 12)
			r := reply(b[:i+4], i+4, nil, 0, 0, false)
			r[2] |= 0x02 // TC
			pc.WriteTo(r, a)
		}
	}()
	go func() {
		c, err := tl.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		var lb [2]byte
		if _, err := c.Read(lb[:]); err != nil {
			return
		}
		q := make([]byte, binary.BigEndian.Uint16(lb[:]))
		if _, err := c.Read(q); err != nil {
			return
		}
		_, i, _ := readQName(q, 12)
		r := reply(q[:i+4], i+4, []netip.Addr{addrB}, 0, 60, false)
		c.Write(append([]byte{byte(len(r) >> 8), byte(len(r))}, r...))
	}()
	r := NewResolver()
	a, err := r.Lookup(context.Background(), Target{Name: "t", Resolvers: []string{pc.LocalAddr().String()}}, "tcp.example.org", false)
	if err != nil || len(a) != 1 || a[0] != addrB {
		t.Fatalf("%v %v", a, err)
	}
}

// A lookup whose caller's budget runs out during a query says so
// (context.DeadlineExceeded inside ErrResolve), also to a caller waiting on
// the same in-flight lookup, and nothing is cached: the next lookup asks
// again. A query that only hit its own Timeout is a resolver failure.
func TestResolverBudget(t *testing.T) {
	dn := &dnsNet{stubs: map[string]*dnsStub{}}
	r := NewResolver()
	r.Exchange = dn.exchange
	r.Timeout = 5 * time.Second
	tg := Target{Name: "group:x", Mark: 0x120, Resolvers: []string{"[fd66::53:91]:53"}}
	ctx, cancel := context.WithTimeout(context.Background(), 80*time.Millisecond)
	defer cancel()
	start := time.Now()
	var wg sync.WaitGroup
	errs := make([]error, 2)
	for i := range errs {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, errs[i] = r.Lookup(ctx, tg, "slow.example.net", false)
		}(i)
	}
	wg.Wait()
	if el := time.Since(start); el > time.Second {
		t.Fatalf("took %v", el)
	}
	for _, err := range errs {
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("%v", err)
		}
	}
	if r.CacheLen(tg) != 0 {
		t.Fatal("a timed-out lookup was cached")
	}
	// A second resolver: the first one's detached exchanges still read its
	// Timeout until they end (changing it here would race them).
	r2 := NewResolver()
	r2.Exchange = dn.exchange
	r2.Timeout = 30 * time.Millisecond
	_, err := r2.Lookup(context.Background(), tg, "slow.example.net", false)
	if !errors.Is(err, ErrResolve) || errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("%v", err)
	}
}

// hedgeClock drives the hedge timer and the health clock by hand.
type hedgeClock struct {
	mu     sync.Mutex
	now    time.Time
	timers []chan time.Time
}

func (c *hedgeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *hedgeClock) After(time.Duration) <-chan time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	ch := make(chan time.Time, 1)
	c.timers = append(c.timers, ch)
	return ch
}

// fire fires every pending hedge timer.
func (c *hedgeClock) fire() {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, ch := range c.timers {
		ch <- c.now
	}
	c.timers = nil
}

func (c *hedgeClock) pending() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.timers)
}

func (c *hedgeClock) advance(d time.Duration) {
	c.mu.Lock()
	c.now = c.now.Add(d)
	c.mu.Unlock()
}

func waitFor(t *testing.T, what string, ok func() bool) {
	t.Helper()
	for i := 0; i < 400; i++ {
		if ok() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

// A silent first resolver is not waited for in series: the next one is
// asked when the hedge timer fires (fake clock), the answer comes from it
// long before the silent one's own Timeout, the silent one is then
// demoted and later lookups do not wait on it at all; after
// HealthDemoteFor it is asked first again; an answer ends the demotion.
func TestResolverHedgeAndHealth(t *testing.T) {
	dn := &dnsNet{stubs: map[string]*dnsStub{
		"192.0.2.1:53": {down: true},
		"192.0.2.2:53": {any: []netip.Addr{addrA}, ttl: 60},
	}}
	clk := &hedgeClock{now: time.Unix(5000, 0)}
	r := NewResolver()
	r.Exchange, r.Now, r.After = dn.exchange, clk.Now, clk.After
	r.Timeout = 300 * time.Millisecond
	d := tgt("direct", 0x64, "192.0.2.1:53", "192.0.2.2:53")
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second) // DefaultLookupBudget
	defer cancel()
	start := time.Now()
	done := make(chan error, 1)
	go func() {
		a, err := r.Lookup(ctx, d, "one.example.org", false)
		if err == nil && (len(a) != 1 || a[0] != addrA) {
			err = fmt.Errorf("answer %v", a)
		}
		done <- err
	}()
	waitFor(t, "first query and hedge timer", func() bool { return len(dn.queries()) == 1 && clk.pending() == 1 })
	if q := dn.queries(); q[0] != "192.0.2.1:53 0x64 one.example.org 1" {
		t.Fatalf("first asked %q", q)
	}
	select {
	case err := <-done:
		t.Fatalf("answered before the hedge: %v", err)
	case <-time.After(20 * time.Millisecond):
	}
	clk.fire()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if el := time.Since(start); el >= r.Timeout {
		t.Fatalf("waited %v for the silent resolver (Timeout %v)", el, r.Timeout)
	}
	// The silent resolver's exchange ends by its own Timeout and is recorded.
	waitFor(t, "health of the silent resolver", func() bool { return r.demoted("192.0.2.1:53", 0x64) })
	byServer := map[string]ResolverHealth{}
	for _, h := range r.Health() {
		byServer[h.Server] = h
	}
	if h := byServer["192.0.2.1:53"]; h.LastOutcome != OutcomeTimeout || h.ConsecutiveFailures != 1 || h.Failed != 1 || h.Source != "lookup" || h.Transport != "udp" {
		t.Fatalf("silent: %+v", h)
	}
	if h := byServer["192.0.2.2:53"]; h.LastOutcome != OutcomeAnswer || h.Answered != 1 || !h.DemotedUntil.IsZero() {
		t.Fatalf("answering: %+v", h)
	}
	// Demoted: the healthy one is asked first and answers; no hedge wait.
	n := len(dn.queries())
	if _, err := r.Lookup(ctx, d, "two.example.org", false); err != nil {
		t.Fatal(err)
	}
	if q := dn.queries(); len(q) != n+1 || q[n] != "192.0.2.2:53 0x64 two.example.org 1" {
		t.Fatalf("demoted resolver asked first: %q", q[n:])
	}
	clk.fire() // the unused hedge timer of that lookup
	// After HealthDemoteFor the configured order is back.
	clk.advance(HealthDemoteFor + time.Second)
	if got := r.order(d); got[0] != "192.0.2.1:53" {
		t.Fatalf("order after demotion: %v", got)
	}
	// An answer ends a demotion at once.
	r.observe("192.0.2.1:53", 0x64, OutcomeTimeout, time.Second, "selfcheck")
	r.observe("192.0.2.1:53", 0x64, OutcomeNXDomain, 9*time.Millisecond, "selfcheck")
	if r.demoted("192.0.2.1:53", 0x64) {
		t.Fatal("still demoted after an answer")
	}
	// PurgeHealth keeps only the resolvers of the given targets.
	r.PurgeHealth([]Target{tgt("direct", 0x64, "192.0.2.2:53")})
	if h := r.Health(); len(h) != 1 || h[0].Server != "192.0.2.2:53" {
		t.Fatalf("purge: %+v", h)
	}
}

// Every resolver silent: the lookup ends with ErrResolve after about one
// Timeout plus the hedge delays (in parallel, not one Timeout per
// resolver), well within the lookup budget; a failure (SERVFAIL, refused)
// starts the next resolver at once without waiting for the hedge timer.
func TestResolverTimeBounds(t *testing.T) {
	dn := &dnsNet{stubs: map[string]*dnsStub{
		"192.0.2.1:53": {down: true}, "192.0.2.2:53": {down: true}, "192.0.2.3:53": {down: true},
		"192.0.2.4:53": {rcode: 2}, "192.0.2.5:53": {any: []netip.Addr{addrB}, ttl: 60},
	}}
	r := NewResolver()
	r.Exchange, r.Timeout, r.HedgeDelay = dn.exchange, 200*time.Millisecond, 20*time.Millisecond
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	start := time.Now()
	_, err := r.Lookup(ctx, tgt("direct", 0x64, "192.0.2.1:53", "192.0.2.2:53", "192.0.2.3:53"), "dead.example.org", false)
	el := time.Since(start)
	if !errors.Is(err, ErrResolve) || errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("%v", err)
	}
	if el > 2*r.Timeout {
		t.Fatalf("three silent resolvers took %v (serial would be %v)", el, 3*r.Timeout)
	}
	// SERVFAIL first: the next one at once (the hedge timer never fires).
	clk := &hedgeClock{now: time.Unix(1, 0)}
	r2 := NewResolver()
	r2.Exchange, r2.Timeout, r2.After, r2.Now = dn.exchange, time.Second, clk.After, clk.Now
	a, err := r2.Lookup(ctx, tgt("direct", 0x64, "192.0.2.4:53", "192.0.2.5:53"), "sf.example.org", false)
	if err != nil || len(a) != 1 || a[0] != addrB {
		t.Fatalf("%v %v", a, err)
	}
	for _, h := range r2.Health() {
		if h.Server == "192.0.2.4:53" && (h.LastOutcome != OutcomeRcode || h.ConsecutiveFailures != 0) {
			t.Fatalf("SERVFAIL is an answer for health (the resolver is reachable): %+v", h)
		}
	}
}
