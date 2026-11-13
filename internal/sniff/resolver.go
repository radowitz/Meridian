package sniff

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"
)

// Target is one decision target as the forwarder reaches it: the mark its
// connections carry and the resolvers that answer for it. The gateway
// install compiles one per target of the rule snapshot (TargetsFile).
type Target struct {
	// Name is the snapshot's target string ("group:hk", "exit:jp",
	// "direct", ...).
	Name string `json:"target"`
	// Mark is the fwmark of the forwarder's connections for this target;
	// it must equal the mark the snapshot gives the target.
	Mark uint32 `json:"mark"`
	// Resolvers answer for this target only, host:port, asked in order
	// (the next one only after a failure or SERVFAIL): the exit's resolver
	// address (fd66::54:<i>), the group's (fd66::53:<k>) or, for the direct
	// target, the domestic resolvers.
	Resolvers []string `json:"resolvers,omitempty"`
	// DNSMark is the fwmark of the queries; nil means Mark. The group
	// resolver addresses need the group mark (transit_snat), the domestic
	// resolvers the domestic mark.
	DNSMark *uint32 `json:"dns_mark,omitempty"`
	// IPv6 allows connecting to this target over IPv6 (AAAA answers). When
	// false only A records are asked and an IPv6 client is connected over
	// IPv4 (the target cannot carry IPv6; the gateway returns no AAAA for
	// it either).
	IPv6 bool `json:"ipv6,omitempty"`
	// Reject: connections to this target are refused (no resolver).
	Reject bool `json:"reject,omitempty"`
}

func (t Target) dnsMark() uint32 {
	if t.DNSMark != nil {
		return *t.DNSMark
	}
	return t.Mark
}

// cacheKey isolates caches: a target name, the resolvers and the mark.
// Two targets never share entries, and a target whose resolvers change
// with a reload starts empty.
func (t Target) cacheKey() string {
	return fmt.Sprintf("%s|%d|%s", t.Name, t.dnsMark(), strings.Join(t.Resolvers, ","))
}

// Errors of Lookup. None of them is ever answered with another target's
// resolver, the domestic resolvers or the client's own destination.
var (
	ErrNXDomain    = errors.New("name does not exist")
	ErrNoAddress   = errors.New("no address of a usable family")
	ErrResolve     = errors.New("resolvers failed")
	ErrNoResolvers = errors.New("target has no resolvers")
)

// Exchange sends one DNS query to server with mark on the socket and
// returns the reply (UDP, then TCP when the reply is truncated).
type Exchange func(ctx context.Context, server string, mark uint32, q []byte) ([]byte, error)

// Resolver resolves names per target with per-target caches.
type Resolver struct {
	// Timeout bounds one query to one server.
	Timeout time.Duration
	// CacheSize is the most names cached per target (and query type).
	CacheSize int
	// MinTTL / MaxTTL clamp answer TTLs; NegTTL is how long NXDOMAIN and
	// empty answers are cached. Failures are never cached.
	MinTTL, MaxTTL, NegTTL time.Duration
	// Exchange (nil: ExchangeNet).
	Exchange Exchange
	// Now (nil: time.Now).
	Now func() time.Time

	mu       sync.Mutex
	caches   map[string]*cache
	inflight map[string]*flight
}

// Defaults of the resolver.
const (
	DefaultResolveTimeout = 2 * time.Second
	DefaultCacheSize      = 4096
	DefaultMinTTL         = 5 * time.Second
	DefaultMaxTTL         = 10 * time.Minute
	DefaultNegTTL         = 10 * time.Second
)

// NewResolver has the defaults.
func NewResolver() *Resolver {
	return &Resolver{Timeout: DefaultResolveTimeout, CacheSize: DefaultCacheSize, MinTTL: DefaultMinTTL, MaxTTL: DefaultMaxTTL, NegTTL: DefaultNegTTL}
}

type entry struct {
	addrs []netip.Addr
	err   error // ErrNXDomain or nil
	exp   time.Time
}

type cache struct{ m map[string]entry }

type flight struct {
	done  chan struct{}
	addrs []netip.Addr
	err   error
}

func (r *Resolver) now() time.Time {
	if r.Now != nil {
		return r.Now()
	}
	return time.Now()
}

// Purge drops every cache whose key is not in keep (called after a reload:
// targets that disappeared or changed resolvers lose their entries).
func (r *Resolver) Purge(keep []Target) {
	ks := map[string]bool{}
	for _, t := range keep {
		ks[t.cacheKey()] = true
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	for k := range r.caches {
		if !ks[k] {
			delete(r.caches, k)
		}
	}
}

// CacheLen is the number of cached names for t (tests, status).
func (r *Resolver) CacheLen(t Target) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	if c := r.caches[t.cacheKey()]; c != nil {
		return len(c.m)
	}
	return 0
}

// Lookup returns the addresses of name for target t: AAAA when v6, else A.
// The answer comes from t's resolvers (or t's cache) only.
func (r *Resolver) Lookup(ctx context.Context, t Target, name string, v6 bool) ([]netip.Addr, error) {
	if len(t.Resolvers) == 0 {
		return nil, ErrNoResolvers
	}
	qt := typeA
	if v6 {
		qt = typeAAAA
	}
	ck := t.cacheKey()
	nk := fmt.Sprintf("%s/%d", name, qt)
	r.mu.Lock()
	if r.caches == nil {
		r.caches, r.inflight = map[string]*cache{}, map[string]*flight{}
	}
	c := r.caches[ck]
	if c == nil {
		c = &cache{m: map[string]entry{}}
		r.caches[ck] = c
	}
	now := r.now()
	if e, ok := c.m[nk]; ok && now.Before(e.exp) {
		r.mu.Unlock()
		return e.addrs, e.err
	}
	fk := ck + "#" + nk
	if f := r.inflight[fk]; f != nil {
		r.mu.Unlock()
		select {
		case <-f.done:
			return f.addrs, f.err
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	f := &flight{done: make(chan struct{})}
	r.inflight[fk] = f
	r.mu.Unlock()

	addrs, ttl, err := r.query(ctx, t, name, qt)

	r.mu.Lock()
	delete(r.inflight, fk)
	if err == nil || errors.Is(err, ErrNXDomain) {
		if err != nil || len(addrs) == 0 {
			ttl = r.NegTTL
		} else {
			if ttl < r.MinTTL {
				ttl = r.MinTTL
			}
			if r.MaxTTL > 0 && ttl > r.MaxTTL {
				ttl = r.MaxTTL
			}
		}
		if ttl > 0 && r.CacheSize > 0 {
			if len(c.m) >= r.CacheSize {
				evict(c, now)
			}
			c.m[nk] = entry{addrs: addrs, err: err, exp: now.Add(ttl)}
		}
	}
	r.mu.Unlock()
	f.addrs, f.err = addrs, err
	close(f.done)
	return addrs, err
}

// evict drops expired entries, then, if still full, about a quarter of the
// rest (map order: arbitrary).
func evict(c *cache, now time.Time) {
	for k, e := range c.m {
		if !now.Before(e.exp) {
			delete(c.m, k)
		}
	}
	n := len(c.m) / 4
	for k := range c.m {
		if n <= 0 {
			break
		}
		delete(c.m, k)
		n--
	}
}

func (r *Resolver) query(ctx context.Context, t Target, name string, qt uint16) ([]netip.Addr, time.Duration, error) {
	ex := r.Exchange
	if ex == nil {
		ex = ExchangeNet
	}
	q, id, err := buildQuery(name, qt)
	if err != nil {
		return nil, 0, err
	}
	var last error = ErrResolve
	for _, srv := range t.Resolvers {
		if ctx.Err() != nil {
			return nil, 0, ctx.Err()
		}
		qctx, cancel := context.WithTimeout(ctx, r.Timeout)
		resp, err := ex(qctx, srv, t.dnsMark(), q)
		cancel()
		if err != nil {
			last = fmt.Errorf("%w: %v", ErrResolve, err)
			continue
		}
		addrs, ttl, rcode, err := parseAnswer(resp, id, name, qt)
		if err != nil {
			last = fmt.Errorf("%w: %v", ErrResolve, err)
			continue
		}
		switch rcode {
		case 0:
			return addrs, ttl, nil
		case 3:
			return nil, 0, ErrNXDomain
		default:
			last = fmt.Errorf("%w: rcode %d", ErrResolve, rcode)
		}
	}
	return nil, 0, last
}

// --------------------------------------------------------- wire format ---

const (
	typeA    uint16 = 1
	typeAAAA uint16 = 28
	typeOPT  uint16 = 41
)

// buildQuery makes a recursive query with an EDNS0 OPT record (1232-byte
// UDP payload, the size commonly recommended against fragmentation).
func buildQuery(name string, qt uint16) ([]byte, uint16, error) {
	var idb [2]byte
	if _, err := io.ReadFull(rand.Reader, idb[:]); err != nil {
		return nil, 0, err
	}
	id := binary.BigEndian.Uint16(idb[:])
	b := make([]byte, 12, 12+len(name)+2+4+11)
	binary.BigEndian.PutUint16(b[0:], id)
	b[2] = 0x01                           // RD
	binary.BigEndian.PutUint16(b[4:], 1)  // QDCOUNT
	binary.BigEndian.PutUint16(b[10:], 1) // ARCOUNT (OPT)
	for _, l := range strings.Split(name, ".") {
		if l == "" || len(l) > 63 {
			return nil, 0, errors.New("bad name")
		}
		b = append(b, byte(len(l)))
		b = append(b, l...)
	}
	b = append(b, 0, byte(qt>>8), byte(qt), 0, 1)
	// OPT: root name, type 41, class = UDP size, TTL 0, RDLEN 0.
	b = append(b, 0, 0, byte(typeOPT), 0x04, 0xd0, 0, 0, 0, 0, 0, 0)
	return b, id, nil
}

func skipName(b []byte, i int) (int, error) {
	for n := 0; n < 128; n++ {
		if i >= len(b) {
			return 0, errShort
		}
		l := int(b[i])
		switch {
		case l == 0:
			return i + 1, nil
		case l&0xc0 == 0xc0:
			if i+2 > len(b) {
				return 0, errShort
			}
			return i + 2, nil
		case l&0xc0 != 0:
			return 0, errShort
		}
		i += 1 + l
	}
	return 0, errShort
}

var errShort = errors.New("malformed DNS message")

// readQName reads an uncompressed question name.
func readQName(b []byte, i int) (string, int, error) {
	var labels []string
	for n := 0; n < 128; n++ {
		if i >= len(b) {
			return "", 0, errShort
		}
		l := int(b[i])
		i++
		if l == 0 {
			return strings.ToLower(strings.Join(labels, ".")), i, nil
		}
		if l&0xc0 != 0 || i+l > len(b) {
			return "", 0, errShort
		}
		labels = append(labels, string(b[i:i+l]))
		i += l
	}
	return "", 0, errShort
}

// parseAnswer checks the reply belongs to the query and returns the
// addresses of type qt in the answer section (the owner may be the end of
// a CNAME chain), the smallest TTL of the answer records and the rcode.
func parseAnswer(b []byte, id uint16, name string, qt uint16) ([]netip.Addr, time.Duration, int, error) {
	if len(b) < 12 || binary.BigEndian.Uint16(b) != id || b[2]&0x80 == 0 || binary.BigEndian.Uint16(b[4:]) != 1 {
		return nil, 0, 0, errors.New("reply does not match the query")
	}
	rcode := int(b[3] & 0x0f)
	qn, i, err := readQName(b, 12)
	if err != nil || i+4 > len(b) {
		return nil, 0, 0, errShort
	}
	if qn != name || binary.BigEndian.Uint16(b[i:]) != qt {
		return nil, 0, 0, errors.New("reply question does not match")
	}
	i += 4
	an := int(binary.BigEndian.Uint16(b[6:]))
	var out []netip.Addr
	minTTL := uint32(0xffffffff)
	for k := 0; k < an; k++ {
		j, err := skipName(b, i)
		if err != nil || j+10 > len(b) {
			return nil, 0, 0, errShort
		}
		typ := binary.BigEndian.Uint16(b[j:])
		ttl := binary.BigEndian.Uint32(b[j+4:])
		rdl := int(binary.BigEndian.Uint16(b[j+8:]))
		if j+10+rdl > len(b) {
			return nil, 0, 0, errShort
		}
		rd := b[j+10 : j+10+rdl]
		if ttl < minTTL {
			minTTL = ttl
		}
		switch {
		case typ == qt && qt == typeA && rdl == 4:
			out = append(out, netip.AddrFrom4([4]byte(rd)))
		case typ == qt && qt == typeAAAA && rdl == 16:
			a := netip.AddrFrom16([16]byte(rd))
			if !a.Is4In6() {
				out = append(out, a)
			}
		case typ == qt:
			return nil, 0, 0, errShort
		}
		i = j + 10 + rdl
	}
	if an == 0 {
		minTTL = 0
	}
	return out, time.Duration(minTTL) * time.Second, rcode, nil
}

// ExchangeNet is the network exchange: UDP from a socket carrying mark,
// TCP (same mark) when the reply is truncated.
func ExchangeNet(ctx context.Context, server string, mark uint32, q []byte) ([]byte, error) {
	d := net.Dialer{Control: markControl(mark)}
	c, err := d.DialContext(ctx, "udp", server)
	if err != nil {
		return nil, err
	}
	defer c.Close()
	if dl, ok := ctx.Deadline(); ok {
		_ = c.SetDeadline(dl)
	}
	if _, err := c.Write(q); err != nil {
		return nil, err
	}
	buf := make([]byte, 65535)
	for {
		n, err := c.Read(buf)
		if err != nil {
			return nil, err
		}
		r := buf[:n]
		if n < 12 || r[0] != q[0] || r[1] != q[1] || r[2]&0x80 == 0 {
			continue // not ours: keep waiting (until the deadline)
		}
		if r[2]&0x02 == 0 { // TC clear
			return append([]byte(nil), r...), nil
		}
		break
	}
	tc, err := d.DialContext(ctx, "tcp", server)
	if err != nil {
		return nil, err
	}
	defer tc.Close()
	if dl, ok := ctx.Deadline(); ok {
		_ = tc.SetDeadline(dl)
	}
	msg := make([]byte, 2+len(q))
	binary.BigEndian.PutUint16(msg, uint16(len(q)))
	copy(msg[2:], q)
	if _, err := tc.Write(msg); err != nil {
		return nil, err
	}
	var lb [2]byte
	if _, err := io.ReadFull(tc, lb[:]); err != nil {
		return nil, err
	}
	resp := make([]byte, binary.BigEndian.Uint16(lb[:]))
	if _, err := io.ReadFull(tc, resp); err != nil {
		return nil, err
	}
	return resp, nil
}
