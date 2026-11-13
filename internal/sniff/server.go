// Package sniff is the gateway's name-sniffing TCP forwarder.
//
// The kernel hands it TCP connections (TPROXY or REDIRECT, installed by the
// gateway bundle). For each one it reads the first bytes the client sends
// (TLS ClientHello server_name, HTTP/1 Host; parser.go), decides the target
// with the same ordered first-match engine the panel's tester and the rule
// compiler use (internal/ordered, loaded from decide.json), resolves the
// name again through that target's own resolver (resolver.go; the direct
// target uses the domestic resolvers), connects with the target's fwmark
// and relays both directions, the sniffed bytes first. Tunnels, relay
// sharing, hub failover and exit switching stay in the kernel data plane:
// the forwarder only chooses the mark.
//
// Connections that yield no name (no SNI, ECH, neither TLS nor HTTP/1,
// nothing sent before the sniff deadline, oversized or malformed first
// bytes, a port that is not sniffed) are decided by their original
// destination address and connected to it, with every byte already read
// replayed.
package sniff

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/radowitz/meridian/internal/lists"
	"github.com/radowitz/meridian/internal/ordered"
)

// Config is the forwarder's configuration (flags of "meridian sniff").
type Config struct {
	// Listen is the TCP address the kernel delivers connections to.
	Listen string
	// Mode is "tproxy" (IP_TRANSPARENT listener, original destination =
	// local address) or "redirect" (SO_ORIGINAL_DST).
	Mode string
	// SnapshotPath is the ordered rule snapshot (compile.DecidePath),
	// TargetsPath the target file (TargetsFile), ListsDir the lists
	// directory whose geosite/keyword/rule-set files and China lists the
	// snapshot refers to.
	SnapshotPath, TargetsPath, ListsDir string
	// StatusSocket is a Unix socket for /v1/health and /v1/recent ("" none).
	StatusSocket string
	// NeighIfaces are the interfaces whose neighbour entries give client
	// MACs (device rules by MAC); empty: no MAC lookup.
	NeighIfaces []string

	// SniffTimeout bounds the wait for the first bytes (all of a
	// fragmented ClientHello or HTTP head); DialTimeout the upstream
	// connect (all addresses); ResolveTimeout one query to one resolver;
	// IdleTimeout closes a connection with no data either way (0: never).
	SniffTimeout, DialTimeout, ResolveTimeout, IdleTimeout time.Duration
	// MaxSniffBytes caps the bytes read before a decision (per connection);
	// MaxConns the concurrent connections; MaxPerSource those of one client
	// address; RecentSize the in-memory record of recent decisions (0:
	// the default, negative: none).
	MaxSniffBytes, MaxConns, MaxPerSource, RecentSize int
	// RecordNames keeps the sniffed name in the recent record (off by
	// default: names are sensitive). Names are never logged.
	RecordNames bool
	// ECHOuter decides ECH connections by the cleartext outer server_name
	// (the ECH provider's public name for real ECH; the true name for a
	// GREASE ECH extension). Off (default): ECH connections are decided by
	// address, as the user's plan states.
	ECHOuter bool
	// ECHPublicNames are known ECH public names (normalized): with
	// ECHOuter, an ECH ClientHello whose cleartext name is one of them or
	// under one of them is decided by address after all (that name is a
	// provider's front, not the site).
	ECHPublicNames []string
	// AddrMarkBit, when non-zero, makes connections without a usable name
	// take the target of the address classifier's own mark: the install
	// sets this bit (with the classification mark) on the SYNs it redirects
	// here and turns on net.ipv4.tcp_fwmark_accept, so an accepted socket
	// carries the SYN's fwmark (MarkFromSocket). A socket without the bit,
	// or whose mark is not a target of the current target file, is reset.
	AddrMarkBit uint32
	// SniffPorts restricts sniffing to these destination ports (empty:
	// every port); other connections are decided by address at once,
	// without waiting for client data (server-first protocols).
	SniffPorts []uint16
	// StatsInterval is the period of the counter log line (0: none).
	StatsInterval time.Duration
}

// Defaults.
const (
	DefaultSniffTimeout  = time.Second
	DefaultDialTimeout   = 10 * time.Second
	DefaultIdleTimeout   = 2 * time.Hour
	DefaultMaxSniffBytes = 16 << 10
	DefaultMaxConns      = 2048
	DefaultMaxPerSource  = 512
	DefaultRecentSize    = 256
	DefaultStatsInterval = 10 * time.Minute
	// ReadyMarker is the first word of the readiness log line.
	ReadyMarker = "meridian-sniff-ready"
	// TargetsVersion is the version of TargetsFile.
	TargetsVersion = 1
)

// DefaultConfig has every default.
func DefaultConfig() Config {
	return Config{Mode: "tproxy", ListsDir: "/var/lib/meridian", SniffTimeout: DefaultSniffTimeout, DialTimeout: DefaultDialTimeout,
		ResolveTimeout: DefaultResolveTimeout, IdleTimeout: DefaultIdleTimeout, MaxSniffBytes: DefaultMaxSniffBytes,
		MaxConns: DefaultMaxConns, MaxPerSource: DefaultMaxPerSource, RecentSize: DefaultRecentSize, StatsInterval: DefaultStatsInterval}
}

// TargetsFile is the target file the gateway install writes next to the
// snapshot: every target the snapshot can decide, with its mark and
// resolvers.
type TargetsFile struct {
	Version int `json:"version"`
	// SnapshotSHA256 pairs the file with one snapshot: when set, the
	// snapshot's bytes must hash to it, otherwise the pair is not loaded
	// (the install writes both files before it signals a reload; a reload
	// or a restart that catches one file new and the other old keeps the
	// rules it has, or does not start, instead of mixing generations).
	SnapshotSHA256 string   `json:"snapshot_sha256,omitempty"`
	Targets        []Target `json:"targets"`
}

// ruleState is one atomically installed rule list with its targets.
type ruleState struct {
	c       *ordered.Compiled
	targets map[string]Target
	byMark  map[uint32]Target
	gen     uint64
	at      time.Time
}

// Server is the forwarder.
type Server struct {
	cfg Config

	// OrigDst returns a connection's original destination (OrigDstLocal for
	// TPROXY, OrigDstRedirect for REDIRECT; tests inject their own).
	OrigDst func(net.Conn) (netip.AddrPort, error)
	// Neighbors returns the client's MAC ("" unknown); nil: no MAC lookup.
	Neighbors func(netip.Addr) string
	// Dial connects upstream with mark on the socket (nil: DialMarked).
	Dial func(ctx context.Context, network, addr string, mark uint32) (net.Conn, error)
	// AddrMark, when set, supplies the address classifier's own mark for
	// a connection without a name (for instance the SYN's fwmark through
	// SocketMark and tcp_fwmark_accept); the forwarder then uses the target
	// with that mark instead of deciding by address itself. ok false falls
	// back to its own address decision.
	AddrMark func(net.Conn) (mark uint32, ok bool)
	// Resolver answers per target.
	Resolver *Resolver
	// Logf (nil: discard). Never given a name.
	Logf func(format string, args ...any)
	// Now (nil: time.Now).
	Now func() time.Time

	state   atomic.Pointer[ruleState]
	gen     atomic.Uint64
	reload  sync.Mutex
	lastErr atomic.Pointer[string]
	lastAt  atomic.Pointer[time.Time]

	sem    chan struct{}
	mu     sync.Mutex
	perSrc map[netip.Addr]int
	conns  map[net.Conn]struct{}

	recent  *ring
	counter counters

	ln         net.Listener
	listenPort uint16
	wg         sync.WaitGroup
	closed     atomic.Bool

	localMu sync.Mutex
	localAt time.Time
	local   map[netip.Addr]bool
}

// New makes a server for cfg (zero values take the defaults).
func New(cfg Config) *Server {
	d := DefaultConfig()
	if cfg.SniffTimeout <= 0 {
		cfg.SniffTimeout = d.SniffTimeout
	}
	if cfg.DialTimeout <= 0 {
		cfg.DialTimeout = d.DialTimeout
	}
	if cfg.ResolveTimeout <= 0 {
		cfg.ResolveTimeout = d.ResolveTimeout
	}
	if cfg.IdleTimeout < 0 {
		cfg.IdleTimeout = 0
	}
	if cfg.MaxSniffBytes <= 0 {
		cfg.MaxSniffBytes = d.MaxSniffBytes
	}
	if cfg.MaxConns <= 0 {
		cfg.MaxConns = d.MaxConns
	}
	if cfg.MaxPerSource <= 0 {
		cfg.MaxPerSource = d.MaxPerSource
	}
	switch {
	case cfg.RecentSize < 0:
		cfg.RecentSize = 0 // no record
	case cfg.RecentSize == 0:
		cfg.RecentSize = d.RecentSize
	}
	r := NewResolver()
	r.Timeout = cfg.ResolveTimeout
	return &Server{cfg: cfg, Resolver: r, sem: make(chan struct{}, cfg.MaxConns), perSrc: map[netip.Addr]int{},
		conns: map[net.Conn]struct{}{}, recent: newRing(cfg.RecentSize)}
}

func (s *Server) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

func (s *Server) logf(format string, args ...any) {
	if s.Logf != nil {
		s.Logf(format, args...)
	}
}

// --------------------------------------------------------------- rules ---

// Install checks c against targets and makes the pair current atomically:
// a connection being decided keeps the pair it started with, the next one
// gets the new pair, and there is never a moment without rules.
//
// Targets are matched by mark: the mark is what the kernel data plane
// routes, so it alone decides where a connection goes and which resolver
// answers for it. Every (target, mark) c can decide must have an entry with
// that mark (reject decisions need none); an entry's name is only a label.
// Two rule targets with the same mark (a static region group and its
// member exit, or a group rule moved to a member by the unlock map) share
// the entry. An entry without resolvers is allowed: names decided to it
// fail (ErrNoResolvers), as the gateway resolver answers such names with
// nothing (an exit reached only over the Mesh has no tunnel resolver);
// connections without a name still go to their original address.
// Otherwise nothing changes.
func (s *Server) Install(c *ordered.Compiled, targets []Target) error {
	if c == nil {
		return errors.New("no rules")
	}
	st := &ruleState{c: c, targets: map[string]Target{}, byMark: map[uint32]Target{}}
	for _, t := range targets {
		if t.Name == "" {
			return errors.New("target without a name")
		}
		if _, dup := st.targets[t.Name]; dup {
			return fmt.Errorf("target %s listed twice", t.Name)
		}
		if o, dup := st.byMark[t.Mark]; dup {
			return fmt.Errorf("targets %s and %s share mark %#x", o.Name, t.Name, t.Mark)
		}
		if t.Mark == 0 {
			return fmt.Errorf("target %s: no mark (every forwarded connection carries a target mark)", t.Name)
		}
		for _, r := range t.Resolvers {
			if _, err := netip.ParseAddrPort(r); err != nil {
				return fmt.Errorf("target %s: resolver %q is not address:port", t.Name, r)
			}
		}
		if t.Reject && len(t.Resolvers) > 0 {
			return fmt.Errorf("target %s: a reject target has no resolver", t.Name)
		}
		st.targets[t.Name] = t
		st.byMark[t.Mark] = t
	}
	for _, tm := range c.Targets() {
		t, ok := st.byMark[tm.Mark]
		if tm.Action == "reject" {
			if ok && !t.Reject {
				return fmt.Errorf("rule target %s (mark %#x) rejects, the target file's %s does not", tm.Target, tm.Mark, t.Name)
			}
			continue
		}
		if !ok {
			return fmt.Errorf("rules decide target %s with mark %#x, which the target file does not list", tm.Target, tm.Mark)
		}
		if t.Reject {
			return fmt.Errorf("target %s (mark %#x) rejects in the target file but not in the rules", tm.Target, tm.Mark)
		}
	}
	st.gen = s.gen.Add(1)
	st.at = s.now()
	s.state.Store(st)
	s.Resolver.Purge(targets)
	return nil
}

// LoadFiles reads the snapshot, its sources and the China lists under
// cfg.ListsDir, and the target file.
func LoadFiles(cfg Config) (*ordered.Compiled, []Target, error) {
	b, err := os.ReadFile(cfg.SnapshotPath)
	if err != nil {
		return nil, nil, err
	}
	var china []netip.Prefix
	for _, f := range []string{"china.txt", "china6.txt"} {
		data, err := os.ReadFile(filepath.Join(cfg.ListsDir, "lists", f))
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return nil, nil, err
		}
		ps, err := lists.ParsePrefixes(f == "china.txt", data, 0)
		if err != nil {
			return nil, nil, fmt.Errorf("%s: %w", f, err)
		}
		china = append(china, ps...)
	}
	c, err := ordered.LoadSnapshot(b, lists.FileReader(cfg.ListsDir), china)
	if err != nil {
		return nil, nil, fmt.Errorf("snapshot: %w", err)
	}
	tb, err := os.ReadFile(cfg.TargetsPath)
	if err != nil {
		return nil, nil, err
	}
	var tf TargetsFile
	dec := json.NewDecoder(strings.NewReader(string(tb)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&tf); err != nil {
		return nil, nil, fmt.Errorf("targets: %w", err)
	}
	if tf.Version != TargetsVersion {
		return nil, nil, fmt.Errorf("targets: version %d", tf.Version)
	}
	if tf.SnapshotSHA256 != "" {
		sum := sha256.Sum256(b)
		if got := hex.EncodeToString(sum[:]); got != strings.ToLower(tf.SnapshotSHA256) {
			return nil, nil, fmt.Errorf("targets belong to snapshot %.12s…, the snapshot on disk is %.12s… (a pair from two generations)", tf.SnapshotSHA256, got)
		}
	}
	return c, tf.Targets, nil
}

// Reload loads the files and installs them; on any failure the current
// rules stay (and the failure is reported by Health).
func (s *Server) Reload() error {
	s.reload.Lock()
	defer s.reload.Unlock()
	now := s.now()
	s.lastAt.Store(&now)
	c, ts, err := LoadFiles(s.cfg)
	if err == nil {
		err = s.Install(c, ts)
	}
	msg := ""
	if err != nil {
		msg = err.Error()
	}
	s.lastErr.Store(&msg)
	return err
}

// ------------------------------------------------------------ listener ---

// Listen opens cfg.Listen for cfg.Mode (tproxy: IP_TRANSPARENT; Linux).
func Listen(ctx context.Context, cfg Config) (net.Listener, error) {
	lc := net.ListenConfig{}
	if cfg.Mode == "tproxy" {
		lc.Control = transparentControl
	}
	return lc.Listen(ctx, "tcp", cfg.Listen)
}

// OrigDstLocal is the original destination under TPROXY: the connection's
// local address (the listener is IP_TRANSPARENT).
func OrigDstLocal(c net.Conn) (netip.AddrPort, error) {
	ap, err := netip.ParseAddrPort(c.LocalAddr().String())
	if err != nil {
		return ap, err
	}
	return netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port()), nil
}

// DialMarked connects with mark on the socket (SO_MARK, Linux).
func DialMarked(ctx context.Context, network, addr string, mark uint32) (net.Conn, error) {
	d := net.Dialer{Control: markControl(mark)}
	return d.DialContext(ctx, network, addr)
}

// Start serves ln until Close. Rules must be installed first.
func (s *Server) Start(ln net.Listener) error {
	if s.state.Load() == nil {
		return errors.New("no rules installed")
	}
	if s.OrigDst == nil {
		return errors.New("no original-destination function")
	}
	s.ln = ln
	if ap, err := netip.ParseAddrPort(ln.Addr().String()); err == nil {
		s.listenPort = ap.Port()
	}
	s.wg.Add(1)
	go s.serve()
	return nil
}

// Addr is the listener's address.
func (s *Server) Addr() net.Addr { return s.ln.Addr() }

// Close stops accepting and closes every relayed connection.
func (s *Server) Close() {
	s.closed.Store(true)
	if s.ln != nil {
		s.ln.Close()
	}
	s.mu.Lock()
	for c := range s.conns {
		c.Close()
	}
	s.mu.Unlock()
	s.wg.Wait()
}

func (s *Server) serve() {
	defer s.wg.Done()
	backoff := 5 * time.Millisecond
	for {
		c, err := s.ln.Accept()
		if err != nil {
			if s.closed.Load() {
				return
			}
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() || errors.Is(err, syscall.EMFILE) {
				time.Sleep(backoff)
				if backoff < time.Second {
					backoff *= 2
				}
				continue
			}
			if errors.Is(err, net.ErrClosed) {
				return
			}
			s.logf("meridian-sniff: accept: %v", err)
			time.Sleep(backoff)
			continue
		}
		backoff = 5 * time.Millisecond
		src := addrPortOf(c.RemoteAddr()).Addr()
		if !s.admit(c, src) {
			reset(c)
			continue
		}
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			defer s.release(c, src)
			s.handle(c)
		}()
	}
}

// admit applies the global and per-client limits.
func (s *Server) admit(c net.Conn, src netip.Addr) bool {
	select {
	case s.sem <- struct{}{}:
	default:
		s.counter.add("refused_overload")
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.perSrc[src] >= s.cfg.MaxPerSource {
		<-s.sem
		s.counter.add("refused_per_source")
		return false
	}
	s.perSrc[src]++
	s.conns[c] = struct{}{}
	return true
}

func (s *Server) release(c net.Conn, src netip.Addr) {
	s.mu.Lock()
	if s.perSrc[src]--; s.perSrc[src] <= 0 {
		delete(s.perSrc, src)
	}
	delete(s.conns, c)
	s.mu.Unlock()
	<-s.sem
}

func (s *Server) track(c net.Conn, on bool) {
	s.mu.Lock()
	if on {
		s.conns[c] = struct{}{}
	} else {
		delete(s.conns, c)
	}
	s.mu.Unlock()
}

// --------------------------------------------------------- connection ---

// Conn describes one connection for a decision.
type Conn struct {
	Source  netip.AddrPort
	MAC     string
	OrigDst netip.AddrPort
	Sniff   Result
}

// Decide is the forwarder's decision for one connection, exactly the
// ordered engine's (ordered.Compiled.Decide, equal to ordered.Reference)
// on the sniffed name (if any), the original destination address and the
// client. name is the name used ("" for an address decision).
func (s *Server) Decide(c Conn) (d ordered.Decision, name string, ok bool) {
	st := s.state.Load()
	if st == nil {
		return d, "", false
	}
	d, name = s.decide(st, c)
	return d, name, true
}

func (s *Server) decide(st *ruleState, c Conn) (ordered.Decision, string) {
	name := c.Sniff.Name
	if name == "" && c.Sniff.ECH && s.cfg.ECHOuter && !s.echPublic(c.Sniff.OuterName) {
		name = c.Sniff.OuterName
	}
	req := ordered.Request{Name: name, Addr: c.OrigDst.Addr(), Proto: "tcp", Port: int(c.OrigDst.Port()), Source: c.Source.Addr(), SourceMAC: c.MAC}
	return st.c.Decide(req), name
}

func (s *Server) handle(c net.Conn) {
	defer c.Close()
	start := s.now()
	rec := ConnRecord{Start: start, RuleIndex: -1}
	src := addrPortOf(c.RemoteAddr())
	rec.Source = src.Addr().String()
	orig, err := s.OrigDst(c)
	if err != nil || !orig.IsValid() || !orig.Addr().IsValid() || orig.Port() == 0 {
		s.finish(&rec, "orig_dst_failed")
		reset(c)
		return
	}
	rec.Dest = orig.String()
	if bad := s.badDest(orig); bad != "" {
		s.finish(&rec, bad)
		reset(c)
		return
	}
	st := s.state.Load()
	rec.Generation = st.gen
	conn := Conn{Source: src, OrigDst: orig}
	var buf []byte
	if s.sniffPort(orig.Port()) {
		buf, conn.Sniff = s.sniff(c)
	} else {
		conn.Sniff = Result{Why: WhySkipped}
	}
	rec.Proto, rec.Why, rec.ECH = string(conn.Sniff.Proto), conn.Sniff.Why, conn.Sniff.ECH
	if (conn.Sniff.Why == WhyEOF && len(buf) == 0) || conn.Sniff.Why == WhyReadFailed {
		s.finish(&rec, "client_closed")
		return
	}
	if s.Neighbors != nil {
		conn.MAC = s.Neighbors(src.Addr())
	}
	d, name := s.decide(st, conn)
	if conn.Sniff.ECH {
		// The record says which ECH case applied: the cleartext name was
		// used, or it is a known ECH public name and the address decided.
		if name != "" {
			rec.Why = WhyECHOuter
		} else if s.cfg.ECHOuter {
			rec.Why = WhyECHPublic
		}
	}
	if name == "" && s.AddrMark != nil {
		if m, ok := s.AddrMark(c); ok {
			t, known := st.byMark[m]
			if !known {
				s.finish(&rec, "unknown_mark")
				reset(c)
				return
			}
			d = ordered.Decision{Index: -1, Target: t.Name, Mark: m, By: ordered.ByAddr, Reason: "address classifier mark"}
			if t.Reject {
				d.Action = "reject"
			}
		}
	}
	rec.RuleIndex, rec.RuleID, rec.Target, rec.Mark, rec.By = d.Index, d.ID, d.Target, d.Mark, d.By
	rec.Sniffed = name != ""
	if s.cfg.RecordNames {
		rec.Name = name
	}
	t, known := st.byMark[d.Mark]
	if d.Action == "reject" || (known && t.Reject) {
		s.finish(&rec, "rejected")
		reset(c)
		return
	}
	if !known {
		s.finish(&rec, "unknown_target")
		reset(c)
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), s.cfg.DialTimeout+2*s.cfg.ResolveTimeout*time.Duration(1+len(t.Resolvers)))
	defer cancel()
	var addrs []netip.Addr
	if name != "" && d.By != ordered.ByAddr {
		addrs, err = s.lookup(ctx, t, name, orig.Addr().Is6())
		if err != nil {
			rec.Error = errClass(err)
			s.finish(&rec, "resolve_failed")
			reset(c)
			return
		}
	} else {
		addrs = []netip.Addr{orig.Addr()}
	}
	up, err := s.dial(ctx, addrs, orig.Port(), d.Mark)
	if err != nil {
		s.finish(&rec, "dial_failed")
		reset(c)
		return
	}
	defer up.Close()
	rec.Upstream = addrPortOf(up.RemoteAddr()).String()
	s.track(up, true)
	defer s.track(up, false)
	if len(buf) > 0 {
		if _, err := up.Write(buf); err != nil {
			s.finish(&rec, "upstream_write_failed")
			reset(c)
			return
		}
	}
	if conn.Sniff.Why == WhyEOF {
		closeWrite(up) // the client already half-closed
	}
	s.finish(&rec, "ok")
	s.pipe(c, up, conn.Sniff.Why == WhyEOF)
}

// lookup asks t's resolvers: the client's address family first (AAAA only
// when t carries IPv6), then the other family the target allows when the
// first one has no address. Errors are final: no other target's resolver,
// no domestic resolver, no client-supplied address.
func (s *Server) lookup(ctx context.Context, t Target, name string, v6 bool) ([]netip.Addr, error) {
	fams := []bool{false}
	switch {
	case v6 && t.IPv6:
		fams = []bool{true, false}
	case t.IPv6:
		fams = []bool{false, true}
	}
	for _, f := range fams {
		a, err := s.Resolver.Lookup(ctx, t, name, f)
		if err != nil {
			return nil, err
		}
		if len(a) > 0 {
			return a, nil
		}
	}
	return nil, ErrNoAddress
}

// dial tries up to four addresses in order within ctx.
func (s *Server) dial(ctx context.Context, addrs []netip.Addr, port uint16, mark uint32) (net.Conn, error) {
	dial := s.Dial
	if dial == nil {
		dial = DialMarked
	}
	if len(addrs) > 4 {
		addrs = addrs[:4]
	}
	var last error = errors.New("no address")
	for i, a := range addrs {
		dctx := ctx
		if len(addrs) > 1 && i < len(addrs)-1 {
			var cancel context.CancelFunc
			dctx, cancel = context.WithTimeout(ctx, s.cfg.DialTimeout/time.Duration(len(addrs)))
			defer cancel()
		}
		c, err := dial(dctx, "tcp", netip.AddrPortFrom(a, port).String(), mark)
		if err == nil {
			return c, nil
		}
		last = err
	}
	return nil, last
}

// sniff reads until the parser decides, the byte limit or the deadline.
func (s *Server) sniff(c net.Conn) ([]byte, Result) {
	max := s.cfg.MaxSniffBytes
	buf := make([]byte, 0, minInt(2048, max))
	_ = c.SetReadDeadline(s.now().Add(s.cfg.SniffTimeout))
	defer c.SetReadDeadline(time.Time{})
	for {
		if len(buf) == cap(buf) {
			nb := make([]byte, len(buf), minInt(2*cap(buf), max))
			copy(nb, buf)
			buf = nb
		}
		n, err := c.Read(buf[len(buf):cap(buf)])
		buf = buf[:len(buf)+n]
		if n > 0 {
			r, more := Sniff(buf, max)
			if !more {
				return buf, r
			}
			if len(buf) >= max {
				return buf, Result{Proto: r.Proto, Why: WhyOversized}
			}
		}
		if err != nil {
			r := Result{}
			if len(buf) > 0 {
				r, _ = Sniff(buf, max)
				r = Result{Proto: r.Proto}
			}
			var ne net.Error
			switch {
			case errors.As(err, &ne) && ne.Timeout():
				r.Why = WhyTimeout
				if len(buf) == 0 {
					r.Why = WhyNoData
				}
			case errors.Is(err, io.EOF):
				r.Why = WhyEOF
			default:
				r.Why = WhyReadFailed
			}
			return buf, r
		}
	}
}

var bufPool = sync.Pool{New: func() any { b := make([]byte, 16<<10); return &b }}

// pipe relays both directions with half-close; idle (no data either way
// for IdleTimeout) or an error closes both.
func (s *Server) pipe(client, up net.Conn, clientDone bool) {
	idle := s.cfg.IdleTimeout
	var last atomic.Int64
	last.Store(time.Now().UnixNano())
	var wg sync.WaitGroup
	cp := func(dst, src net.Conn) {
		defer wg.Done()
		bp := bufPool.Get().(*[]byte)
		defer bufPool.Put(bp)
		b := *bp
		for {
			if idle > 0 {
				_ = src.SetReadDeadline(time.Now().Add(idle))
			}
			n, err := src.Read(b)
			if n > 0 {
				last.Store(time.Now().UnixNano())
				if idle > 0 {
					_ = dst.SetWriteDeadline(time.Now().Add(idle))
				}
				if _, werr := dst.Write(b[:n]); werr != nil {
					client.Close()
					up.Close()
					return
				}
			}
			if err != nil {
				var ne net.Error
				if errors.As(err, &ne) && ne.Timeout() && idle > 0 && time.Since(time.Unix(0, last.Load())) < idle {
					continue // the other direction is active
				}
				if errors.Is(err, io.EOF) {
					closeWrite(dst)
					return
				}
				client.Close()
				up.Close()
				return
			}
		}
	}
	if clientDone {
		wg.Add(1)
		cp(client, up)
		return
	}
	wg.Add(2)
	go cp(up, client)
	cp(client, up)
	wg.Wait()
}

// echPublic: name is a configured ECH public name or under one.
func (s *Server) echPublic(name string) bool {
	for _, p := range s.cfg.ECHPublicNames {
		if ordered.Under(name, p) {
			return true
		}
	}
	return false
}

// MarkFromSocket is Server.AddrMark for an install that marks redirected
// SYNs with bit and the classification mark (Config.AddrMarkBit): the
// accepted socket's SO_MARK (net.ipv4.tcp_fwmark_accept) with bit cleared.
// A mark without bit, or one that cannot be read, is reported as mark 0,
// which no target has, so the connection is reset rather than decided by
// the forwarder's own (weaker) address view.
func MarkFromSocket(bit uint32) func(net.Conn) (uint32, bool) {
	return func(c net.Conn) (uint32, bool) {
		m, err := SocketMark(c)
		if err != nil || bit == 0 || m&bit == 0 {
			return 0, true
		}
		return m &^ bit, true
	}
}

func (s *Server) sniffPort(p uint16) bool {
	if len(s.cfg.SniffPorts) == 0 {
		return true
	}
	for _, x := range s.cfg.SniffPorts {
		if x == p {
			return true
		}
	}
	return false
}

// badDest refuses destinations that cannot be a forwarded connection:
// unspecified, multicast, broadcast, and the forwarder itself (a client
// connecting to the listener directly, which would loop).
func (s *Server) badDest(ap netip.AddrPort) string {
	a := ap.Addr()
	switch {
	case a.IsUnspecified() || a.IsMulticast() || a == netip.AddrFrom4([4]byte{255, 255, 255, 255}):
		return "bad_destination"
	case ap.Port() == s.listenPort && (a.IsLoopback() || s.isLocal(a)):
		return "loop"
	}
	return ""
}

func (s *Server) isLocal(a netip.Addr) bool {
	s.localMu.Lock()
	defer s.localMu.Unlock()
	if s.local == nil || time.Since(s.localAt) > 10*time.Second {
		s.local = map[netip.Addr]bool{}
		s.localAt = time.Now()
		if as, err := net.InterfaceAddrs(); err == nil {
			for _, x := range as {
				if p, err := netip.ParsePrefix(x.String()); err == nil {
					s.local[p.Addr().Unmap()] = true
				}
			}
		}
	}
	return s.local[a.Unmap()]
}

// ------------------------------------------------------------ helpers ---

func addrPortOf(a net.Addr) netip.AddrPort {
	if a == nil {
		return netip.AddrPort{}
	}
	ap, err := netip.ParseAddrPort(a.String())
	if err != nil {
		return netip.AddrPort{}
	}
	return netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port())
}

// reset closes c with an RST (SO_LINGER 0) so the client fails at once.
func reset(c net.Conn) {
	if l, ok := c.(interface{ SetLinger(int) error }); ok {
		_ = l.SetLinger(0)
	}
	c.Close()
}

func closeWrite(c net.Conn) {
	if cw, ok := c.(interface{ CloseWrite() error }); ok {
		_ = cw.CloseWrite()
		return
	}
	c.Close()
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func errClass(err error) string {
	switch {
	case errors.Is(err, ErrNXDomain):
		return "nxdomain"
	case errors.Is(err, ErrNoAddress):
		return "no_address"
	case errors.Is(err, context.DeadlineExceeded):
		return "timeout"
	default:
		return "resolver_failed"
	}
}

// ------------------------------------------------------ health, record ---

// ConnRecord is one recent decision (in memory only).
type ConnRecord struct {
	Start  time.Time `json:"start"`
	Source string    `json:"source"`
	Dest   string    `json:"dest,omitempty"`
	Proto  string    `json:"proto,omitempty"`
	Name   string    `json:"name,omitempty"` // only with Config.RecordNames
	ECH    bool      `json:"ech,omitempty"`
	Why    string    `json:"why,omitempty"` // why no name
	// Sniffed: the decision used a name read from the connection (false:
	// decided by the original destination address).
	Sniffed    bool   `json:"sniffed"`
	By         string `json:"by,omitempty"` // name, addr, default
	RuleIndex  int    `json:"rule_index"`
	RuleID     string `json:"rule_id,omitempty"`
	Target     string `json:"target,omitempty"`
	Mark       uint32 `json:"mark,omitempty"`
	Upstream   string `json:"upstream,omitempty"`
	Result     string `json:"result"`
	Error      string `json:"error,omitempty"`
	DecideMS   int64  `json:"decide_ms"`
	Generation uint64 `json:"generation"`
}

func (s *Server) finish(r *ConnRecord, result string) {
	r.Result = result
	r.DecideMS = s.now().Sub(r.Start).Milliseconds()
	s.counter.add("result_" + result)
	if r.Target != "" {
		if r.Sniffed {
			s.counter.add("decided_by_name")
		} else {
			s.counter.add("decided_by_address_" + r.Why)
		}
	}
	s.recent.put(*r)
}

type ring struct {
	mu   sync.Mutex
	buf  []ConnRecord
	next int
	full bool
}

func newRing(n int) *ring { return &ring{buf: make([]ConnRecord, n)} }

func (r *ring) put(c ConnRecord) {
	if len(r.buf) == 0 {
		return
	}
	r.mu.Lock()
	r.buf[r.next] = c
	r.next = (r.next + 1) % len(r.buf)
	if r.next == 0 {
		r.full = true
	}
	r.mu.Unlock()
}

// all returns the records, newest first.
func (r *ring) all() []ConnRecord {
	r.mu.Lock()
	defer r.mu.Unlock()
	n := r.next
	if r.full {
		n = len(r.buf)
	}
	out := make([]ConnRecord, 0, n)
	for i := 1; i <= n; i++ {
		out = append(out, r.buf[(r.next-i+len(r.buf))%len(r.buf)])
	}
	return out
}

type counters struct {
	mu sync.Mutex
	m  map[string]uint64
}

func (c *counters) add(k string) {
	c.mu.Lock()
	if c.m == nil {
		c.m = map[string]uint64{}
	}
	c.m[k]++
	c.mu.Unlock()
}

func (c *counters) snapshot() map[string]uint64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make(map[string]uint64, len(c.m))
	for k, v := range c.m {
		out[k] = v
	}
	return out
}

// Recent returns the recent decisions, newest first.
func (s *Server) Recent() []ConnRecord { return s.recent.all() }

// Health is the forwarder's state.
type Health struct {
	Ready           bool              `json:"ready"`
	Mode            string            `json:"mode"`
	Listen          string            `json:"listen"`
	Generation      uint64            `json:"generation"`
	LoadedAt        time.Time         `json:"loaded_at,omitempty"`
	Rules           int               `json:"rules"`
	Targets         []string          `json:"targets"`
	MACRules        bool              `json:"mac_rules"`
	MACLookup       bool              `json:"mac_lookup"`
	LastReloadAt    *time.Time        `json:"last_reload_at,omitempty"`
	LastReloadError string            `json:"last_reload_error,omitempty"`
	Active          int               `json:"active"`
	MaxConns        int               `json:"max_conns"`
	RecordNames     bool              `json:"record_names"`
	ECHOuter        bool              `json:"ech_outer"`
	Counters        map[string]uint64 `json:"counters"`
}

// Health reports readiness and counters.
func (s *Server) Health() Health {
	h := Health{Mode: s.cfg.Mode, Listen: s.cfg.Listen, MaxConns: s.cfg.MaxConns, RecordNames: s.cfg.RecordNames,
		ECHOuter: s.cfg.ECHOuter, MACLookup: s.Neighbors != nil, Counters: s.counter.snapshot(), Active: len(s.sem)}
	if st := s.state.Load(); st != nil {
		h.Ready = s.ln != nil && !s.closed.Load()
		h.Generation, h.LoadedAt, h.Rules, h.MACRules = st.gen, st.at, st.c.Len(), st.c.HasMACRules()
		for n := range st.targets {
			h.Targets = append(h.Targets, n)
		}
		sort.Strings(h.Targets)
	}
	if p := s.lastAt.Load(); p != nil {
		h.LastReloadAt = p
	}
	if p := s.lastErr.Load(); p != nil {
		h.LastReloadError = *p
	}
	return h
}
