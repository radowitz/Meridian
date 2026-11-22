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
// replayed. So are connections whose name the target's resolvers cannot
// resolve (NXDOMAIN, no address, every resolver failed, LookupBudget spent):
// by address, never with the name rule's target (WhyUnresolved).
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
	// JournalDir holds the connection journal (journal.go; "" none). The
	// gateway passes the unit's StateDirectory.
	JournalDir string
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
	// RecordNames keeps the sniffed name in the recent record and the
	// connection journal (off by default: names are sensitive). Names are
	// never logged. Off, a journal opened at start loses every name it
	// still holds (journal.go).
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
	// carries the SYN's fwmark (MarkFromSocket). A mark with the bit that is
	// not a target of the current target file is reset (unknown_mark); a
	// socket without the bit or whose mark cannot be read is handled by
	// addrDecision's conservative rule (see there).
	AddrMarkBit uint32
	// LookupBudget bounds the whole name lookup of one connection (every
	// resolver of the target, both address families). When it runs out
	// the lookup is abandoned and the connection is handled by address,
	// like an NXDOMAIN (WhyUnresolved). ResolveTimeout still bounds each
	// single query inside it.
	LookupBudget time.Duration
	// SniffPorts restricts sniffing to these destination ports (empty:
	// every port); other connections are decided by address at once,
	// without waiting for client data (server-first protocols).
	SniffPorts []uint16
	// StatsInterval is the period of the counter log line (0: none).
	StatsInterval time.Duration
	// SelfCheckInterval repeats the self-check (selfcheck.go) while running
	// (0: only at start, after a reload and on request).
	SelfCheckInterval time.Duration
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
	// DefaultLookupBudget: one resolver that times out (DefaultResolveTimeout,
	// 2 s) plus one more second for the next resolver or the other family.
	// The resolvers of a target are raced with hedging (Resolver.query), so
	// a silent resolver costs at most HedgeDelay, none once it is demoted.
	// A client waits at most this long (plus the upstream connect) before
	// its connection is handled by address instead.
	DefaultLookupBudget = 3 * time.Second
	// ReadyMarker is the first word of the readiness log line.
	ReadyMarker = "meridian-sniff-ready"
	// TargetsVersion is the version of TargetsFile.
	TargetsVersion = 1
)

// DefaultConfig has every default.
func DefaultConfig() Config {
	return Config{Mode: "tproxy", ListsDir: "/var/lib/meridian", SniffTimeout: DefaultSniffTimeout, DialTimeout: DefaultDialTimeout,
		ResolveTimeout: DefaultResolveTimeout, IdleTimeout: DefaultIdleTimeout, MaxSniffBytes: DefaultMaxSniffBytes,
		MaxConns: DefaultMaxConns, MaxPerSource: DefaultMaxPerSource, RecentSize: DefaultRecentSize, StatsInterval: DefaultStatsInterval,
		SelfCheckInterval: DefaultSelfCheckInterval, LookupBudget: DefaultLookupBudget}
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
	// direct holds the marks the rules decide with action "direct" (the
	// domestic mark): addrDecision's counters say what the forwarder's own
	// address view would have chosen for a refused connection.
	direct map[uint32]bool
	gen    uint64
	at     time.Time
	// sha is the hex SHA-256 of the target file the pair was loaded from
	// ("" when installed directly): the install's identity of the pair.
	sha string
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
	// a connection handled by address (for instance the SYN's fwmark
	// through SocketMark and tcp_fwmark_accept, MarkFromSocket); the
	// forwarder then uses the target with that mark instead of deciding by
	// address itself. A MarkInfo whose Status is not MarkOK is not
	// trusted (addrDecision). nil: the forwarder's own address decision.
	AddrMark func(net.Conn) MarkInfo
	// Resolver answers per target.
	Resolver *Resolver
	// Logf (nil: discard). Never given a name.
	Logf func(format string, args ...any)
	// Now (nil: time.Now).
	Now func() time.Time
	// Journal, when set, receives every finished record (journal.go): a
	// non-blocking hand-off, never in the way of a connection.
	Journal *Journal

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
	tstats  targetStats
	sc      *selfChecker

	// connSeq numbers the connections of this process (ConnRecord.Conn);
	// active holds the connections being relayed (activeConn), at most
	// MaxConns: the bounded "open connections" view (Active).
	connSeq  atomic.Uint64
	activeMu sync.Mutex
	active   map[uint64]*activeConn

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
	if cfg.LookupBudget <= 0 {
		cfg.LookupBudget = d.LookupBudget
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
		conns: map[net.Conn]struct{}{}, recent: newRing(cfg.RecentSize), sc: newSelfChecker(), active: map[uint64]*activeConn{}}
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
	return s.install(c, targets, "")
}

func (s *Server) install(c *ordered.Compiled, targets []Target, sha string) error {
	if c == nil {
		return errors.New("no rules")
	}
	st := &ruleState{c: c, targets: map[string]Target{}, byMark: map[uint32]Target{}, direct: map[uint32]bool{}}
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
		if tm.Action == "direct" {
			st.direct[tm.Mark] = true
		}
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
	st.sha = sha
	s.state.Store(st)
	s.Resolver.Purge(targets)
	s.Resolver.PurgeHealth(targets)
	names := map[string]bool{}
	for n := range st.targets {
		names[n] = true
	}
	s.tstats.keep(names)
	return nil
}

// LoadFiles reads the snapshot, its sources and the China lists under
// cfg.ListsDir, and the target file.
func LoadFiles(cfg Config) (*ordered.Compiled, []Target, error) {
	c, ts, _, err := loadFiles(cfg)
	return c, ts, err
}

// loadFiles is LoadFiles with the hex SHA-256 of the target file's bytes
// (the identity of the pair the install wrote; SelfCheck.TargetsSHA256).
func loadFiles(cfg Config) (*ordered.Compiled, []Target, string, error) {
	fail := func(err error) (*ordered.Compiled, []Target, string, error) { return nil, nil, "", err }
	b, err := os.ReadFile(cfg.SnapshotPath)
	if err != nil {
		return fail(err)
	}
	var china []netip.Prefix
	for _, f := range []string{"china.txt", "china6.txt"} {
		data, err := os.ReadFile(filepath.Join(cfg.ListsDir, "lists", f))
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return fail(err)
		}
		ps, err := lists.ParsePrefixes(f == "china.txt", data, 0)
		if err != nil {
			return fail(fmt.Errorf("%s: %w", f, err))
		}
		china = append(china, ps...)
	}
	c, err := ordered.LoadSnapshot(b, lists.FileReader(cfg.ListsDir), china)
	if err != nil {
		return fail(fmt.Errorf("snapshot: %w", err))
	}
	tb, err := os.ReadFile(cfg.TargetsPath)
	if err != nil {
		return fail(err)
	}
	var tf TargetsFile
	dec := json.NewDecoder(strings.NewReader(string(tb)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&tf); err != nil {
		return fail(fmt.Errorf("targets: %w", err))
	}
	if tf.Version != TargetsVersion {
		return fail(fmt.Errorf("targets: version %d", tf.Version))
	}
	if tf.SnapshotSHA256 != "" {
		sum := sha256.Sum256(b)
		if got := hex.EncodeToString(sum[:]); got != strings.ToLower(tf.SnapshotSHA256) {
			return fail(fmt.Errorf("targets belong to snapshot %.12s…, the snapshot on disk is %.12s… (a pair from two generations)", tf.SnapshotSHA256, got))
		}
	}
	tsum := sha256.Sum256(tb)
	return c, tf.Targets, hex.EncodeToString(tsum[:]), nil
}

// Reload loads the files and installs them; on any failure the current
// rules stay (and the failure is reported by Health).
func (s *Server) Reload() error {
	s.reload.Lock()
	defer s.reload.Unlock()
	now := s.now()
	s.lastAt.Store(&now)
	c, ts, sha, err := loadFiles(s.cfg)
	if err == nil {
		err = s.install(c, ts, sha)
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

// Close stops accepting and closes every relayed connection. Each of them
// is finished with result and end "shutdown" (its record reaches the ring
// and the journal hand-off) before Close returns.
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
	s.sc.stop()
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
	rec := ConnRecord{Start: start, RuleIndex: -1, Conn: s.connSeq.Add(1)}
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
		rec.MAC = conn.MAC
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
	if s.cfg.RecordNames {
		rec.Name = name
	}
	// setDecision records decision d. Every branch records the decision it
	// acted on before it finishes, refusals included (unknown_mark: the
	// classifier's mark; mark_missing: the own view's rule that would have
	// sent the connection direct).
	setDecision := func(d ordered.Decision, sniffed bool) {
		rec.RuleIndex, rec.RuleID, rec.Target, rec.Mark, rec.By = d.Index, d.ID, d.Target, d.Mark, d.By
		rec.Sniffed = sniffed
	}
	if name == "" {
		var fail string
		d, fail = s.addrDecision(st, c, d, &rec)
		setDecision(d, false)
		if fail != "" {
			s.finish(&rec, fail)
			reset(c)
			return
		}
	}
	setDecision(d, name != "")
	// route: the target of decision d, or the result that ends the
	// connection (a reject is decided here, before any lookup: a name rule
	// that rejects an existing or a made-up name stays rejected).
	route := func(d ordered.Decision) (Target, string) {
		t, known := st.byMark[d.Mark]
		switch {
		case d.Action == "reject" || (known && t.Reject):
			return t, "rejected"
		case !known:
			return t, "unknown_target"
		}
		return t, ""
	}
	t, fail := route(d)
	if fail != "" {
		s.finish(&rec, fail)
		reset(c)
		return
	}
	// The lookup has its own budget (LookupBudget), the upstream connect
	// its own (DialTimeout).
	ctx, cancel := context.WithTimeout(context.Background(), s.cfg.LookupBudget+s.cfg.DialTimeout)
	defer cancel()
	addrs := []netip.Addr{orig.Addr()}
	if name != "" && d.By != ordered.ByAddr {
		lctx, lcancel := context.WithTimeout(ctx, s.cfg.LookupBudget)
		addrs, err = s.lookup(lctx, t, name, orig.Addr().Is6())
		over := lctx.Err() != nil
		lcancel()
		if err != nil {
			class := errClass(err)
			if over {
				class = "timeout"
			}
			rec.Error = class
			if errors.Is(err, ErrNoResolvers) {
				// The target has no resolver at all (an exit reached only
				// over the Mesh): every name of its rules would leave by
				// address, which turns the rule off. Not a lookup failure
				// of this name; refused as before.
				s.finish(&rec, "resolve_failed")
				reset(c)
				return
			}
			// Name lookup failed: handled exactly like a connection without
			// a name (the address classifier's mark and the original
			// destination), never with the name rule's target, which is kept
			// in the record for diagnosis.
			s.counter.add("name_unresolved_" + class)
			if class == "timeout" || class == "resolver_failed" {
				// A path problem of the name's target (an NXDOMAIN or an empty
				// answer is a working resolver answering): it stays visible in
				// that target's counters.
				s.tstats.add(d.Target, statResolve, start, "resolve_failed "+class+" (handled by address)")
			}
			rec.NameRule = &NameRule{Index: d.Index, ID: d.ID, Target: d.Target, Mark: d.Mark, By: d.By, Error: class}
			rec.Why = WhyUnresolved
			if d, fail = s.addrDecision(st, c, s.decideAddr(st, conn), &rec); fail == "" {
				t, fail = route(d)
			}
			setDecision(d, false)
			if fail != "" {
				s.finish(&rec, fail)
				reset(c)
				return
			}
			addrs = []netip.Addr{orig.Addr()}
		}
	}
	up, tried, err := s.dial(ctx, addrs, orig.Port(), d.Mark)
	if err != nil {
		// The bounded class of the last attempt's error and the address it
		// went to (an address the record already carries as dest or as the
		// target resolver's answer; nothing new).
		rec.Reason, rec.Upstream = NetErrClass(err), tried
		s.finish(&rec, "dial_failed")
		reset(c)
		return
	}
	defer up.Close()
	rec.Upstream = addrPortOf(up.RemoteAddr()).String()
	s.track(up, true)
	defer s.track(up, false)
	// From here the connection is relayed: it is in the active view until
	// its one final record is written (finishRelay).
	rec.DecideMS = s.now().Sub(start).Milliseconds()
	ac := s.addActive(rec, c, up)
	if len(buf) > 0 {
		if _, err := up.Write(buf); err != nil {
			s.finishRelay(&rec, ac, writeEnd(EndUpstreamReset, EndUpstreamError, err))
			reset(c)
			return
		}
		ac.up.Add(int64(len(buf)))
	}
	if conn.Sniff.Why == WhyEOF {
		closeWrite(up) // the client already half-closed
	}
	s.finishRelay(&rec, ac, s.pipe(c, up, conn.Sniff.Why == WhyEOF, ac))
}

// ------------------------------------------------------- relay results ---

// The record model (docs/architecture.md「设备连接日志」「连接结果」): one
// final record per connection, written when the connection ends — refused,
// failed before a relay, or relayed and then closed. It goes to the ring,
// the journal, the counters and the per-target statistics in one place
// (finish), so all of them count a connection exactly once and agree on
// its result. Connections still being relayed are not in any of them; they
// are in the bounded active view (Active, at most MaxConns, read through
// the status socket's /v1/recent and the journal's first page). This was
// chosen over an "established" record followed by a final one because the
// journal's bounds (records, age, bytes) and every reader (paging, the
// per-device summary) then never have to merge two lines of one
// connection, and no record ever says "ok" for a connection whose end is
// not known. The cost: a connection is in the journal only once it ended.
// Close (SIGTERM, a restart by an install) finishes every open connection
// with EndShutdown first; a hard kill (SIGKILL, OOM, a crash, power loss)
// loses the records of the connections open at that moment, and the
// journal reports that such a stop happened with the number of
// connections open at its last check (JournalStats.UncleanStop).

// End reasons of a relayed connection (ConnRecord.End): who ended the
// relay and how. The first abnormal event wins (an error caused by the
// forwarder's own close of the other side is not an event); without one,
// the side whose FIN came first.
const (
	EndClientClosed   = "client_closed"   // the client closed (FIN) first, normal
	EndUpstreamClosed = "upstream_closed" // the upstream closed (FIN) first, normal
	EndClientReset    = "client_reset"    // the client reset (RST) the connection
	EndUpstreamReset  = "upstream_reset"  // the upstream reset it
	EndClientError    = "client_error"    // reading from / writing to the client failed otherwise (Reason)
	EndUpstreamError  = "upstream_error"  // reading from / writing to the upstream failed otherwise (Reason)
	EndIdleTimeout    = "idle_timeout"    // no data either way for IdleTimeout (or a write stalled that long)
	EndOperatorClosed = "operator_closed" // the panel disconnected an active relay
	EndShutdown       = "shutdown"        // the forwarder stopped (Close) while the connection was open
)

// Results of a relayed connection (ConnRecord.Result; relayResult). The
// results of connections that never reached a relay (rejected,
// dial_failed, …) are unchanged.
const (
	// ResultOK: the upstream answered: at least one byte from the upstream
	// reached the client (however it ended afterwards, except shutdown).
	ResultOK = "ok"
	// ResultNoResponse: the upstream was connected and the client had sent
	// data, but not one byte came back before the client closed, the
	// upstream closed or the idle timeout (a path that connects but does
	// not carry the answer, an upstream that refuses the request silently).
	ResultNoResponse = "no_response"
	// ResultRelayFailed: the upstream reset the connection or failed before
	// any byte came back.
	ResultRelayFailed = "relay_failed"
	// ResultClientClosed: the client left without sending anything and
	// nothing came back (an unused pre-connection); also a client that
	// closed before a decision (unchanged). Not a failure.
	ResultClientClosed = "client_closed"
	// ResultShutdown: the forwarder stopped while the connection was open.
	ResultShutdown = "shutdown"
)

// relayEnd is how a relay ended: the end reason, its bounded error class
// (Reason: "<read|write>_<NetErrClass>", "" for a normal end) and the
// bytes relayed each way (client to upstream including the sniffed bytes;
// upstream to client).
type relayEnd struct {
	End, Reason string
	Up, Down    int64
}

// relayResult is the result of a relayed connection (the ok definition).
func relayResult(e relayEnd) string {
	switch {
	case e.End == EndOperatorClosed:
		return ResultClientClosed
	case e.End == EndShutdown:
		return ResultShutdown
	case e.Down > 0:
		return ResultOK
	case e.End == EndUpstreamReset || e.End == EndUpstreamError:
		return ResultRelayFailed
	case e.Up == 0 && e.End != EndUpstreamClosed:
		return ResultClientClosed
	}
	return ResultNoResponse
}

// NetErrClass is the bounded class of a connect, read or write error:
// timeout, refused, unreachable (network unreachable), no_route (no route
// to host), reset (reset, broken pipe, aborted), af_unavailable (address
// family or local address not available), denied (the local firewall or a
// permission refused the send) or other.
func NetErrClass(err error) string {
	switch {
	case err == nil:
		return ""
	case errors.Is(err, syscall.ECONNREFUSED):
		return "refused"
	case errors.Is(err, syscall.ECONNRESET) || errors.Is(err, syscall.EPIPE) || errors.Is(err, syscall.ECONNABORTED):
		return "reset"
	case errors.Is(err, syscall.ENETUNREACH):
		return "unreachable"
	case errors.Is(err, syscall.EHOSTUNREACH):
		return "no_route"
	case errors.Is(err, syscall.EAFNOSUPPORT) || errors.Is(err, syscall.EADDRNOTAVAIL):
		return "af_unavailable"
	case errors.Is(err, syscall.EPERM) || errors.Is(err, syscall.EACCES):
		return "denied"
	case errors.Is(err, syscall.ETIMEDOUT) || errors.Is(err, context.DeadlineExceeded) || errors.Is(err, os.ErrDeadlineExceeded):
		return "timeout"
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return "timeout"
	}
	return "other"
}

// writeEnd is the end of a relay whose write to a side failed.
func writeEnd(resetEnd, errEnd string, err error) relayEnd {
	if errors.Is(err, os.ErrDeadlineExceeded) {
		return relayEnd{End: EndIdleTimeout, Reason: "write_stalled"}
	}
	c := NetErrClass(err)
	if c == "reset" {
		return relayEnd{End: resetEnd, Reason: "write_reset"}
	}
	return relayEnd{End: errEnd, Reason: "write_" + c}
}

// activeConn is a connection being relayed: its record as of the relay's
// start and the bytes relayed so far.
type activeConn struct {
	rec              ConnRecord
	client, upstream net.Conn
	disconnected     atomic.Bool
	up, down         atomic.Int64
}

func (s *Server) addActive(r ConnRecord, client, upstream net.Conn) *activeConn {
	ac := &activeConn{rec: r, client: client, upstream: upstream}
	s.activeMu.Lock()
	s.active[r.Conn] = ac
	s.activeMu.Unlock()
	s.Journal.notifyChange()
	return ac
}

// DisconnectActive closes the relay sockets that were active at the time
// of the request. New connections are still accepted.
func (s *Server) DisconnectActive() int {
	s.activeMu.Lock()
	current := make([]*activeConn, 0, len(s.active))
	for _, ac := range s.active {
		if ac.disconnected.CompareAndSwap(false, true) {
			current = append(current, ac)
		}
	}
	s.activeMu.Unlock()
	for _, ac := range current {
		_ = ac.client.Close()
		_ = ac.upstream.Close()
	}
	return len(current)
}

// ActiveResult is ConnRecord.Result of a connection in the active view.
const ActiveResult = "active"

// Active returns the connections being relayed that match (nil: all),
// newest first, at most max of them, and how many match: each a copy of its
// record with Result ActiveResult, the bytes so far and the time since its
// start. Bounded by MaxConns.
func (s *Server) Active(match func(*ConnRecord) bool, max int) ([]ConnRecord, int) {
	now := s.now()
	s.activeMu.Lock()
	all := make([]ConnRecord, 0, len(s.active))
	for _, ac := range s.active {
		r := ac.rec
		if match != nil && !match(&r) {
			continue
		}
		r.Result = ActiveResult
		r.BytesUp, r.BytesDown = ac.up.Load(), ac.down.Load()
		r.DurationMS = now.Sub(r.Start).Milliseconds()
		all = append(all, r)
	}
	s.activeMu.Unlock()
	sort.Slice(all, func(i, j int) bool { return all[i].Conn > all[j].Conn })
	n := len(all)
	if max >= 0 && len(all) > max {
		all = all[:max]
	}
	return all, n
}

// relaying is the number of connections being relayed.
func (s *Server) relaying() int {
	s.activeMu.Lock()
	defer s.activeMu.Unlock()
	return len(s.active)
}

// finishRelay writes the one final record of a relayed connection.
func (s *Server) finishRelay(r *ConnRecord, ac *activeConn, e relayEnd) {
	if ac.disconnected.Load() {
		e.End, e.Reason = EndOperatorClosed, ""
	}
	e.Up, e.Down = ac.up.Load(), ac.down.Load()
	r.End, r.Reason, r.BytesUp, r.BytesDown = e.End, e.Reason, e.Up, e.Down
	s.finish(r, relayResult(e))
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

// dial tries up to four addresses in order within ctx. It also returns the
// last address tried.
func (s *Server) dial(ctx context.Context, addrs []netip.Addr, port uint16, mark uint32) (net.Conn, string, error) {
	dial := s.Dial
	if dial == nil {
		dial = DialMarked
	}
	if len(addrs) > 4 {
		addrs = addrs[:4]
	}
	var last error = errors.New("no address")
	tried := ""
	for i, a := range addrs {
		dctx := ctx
		if len(addrs) > 1 && i < len(addrs)-1 {
			var cancel context.CancelFunc
			dctx, cancel = context.WithTimeout(ctx, s.cfg.DialTimeout/time.Duration(len(addrs)))
			defer cancel()
		}
		tried = netip.AddrPortFrom(a, port).String()
		c, err := dial(dctx, "tcp", tried, mark)
		if err == nil {
			return c, tried, nil
		}
		last = err
	}
	return nil, tried, last
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
// for IdleTimeout) or an error closes both. It returns how the relay ended
// (relayEnd; the bytes are counted in ac). There is no maximum lifetime: a
// connection with traffic lives until one side ends it or the forwarder
// stops.
func (s *Server) pipe(client, up net.Conn, clientDone bool, ac *activeConn) relayEnd {
	idle := s.cfg.IdleTimeout
	var last atomic.Int64
	last.Store(time.Now().UnixNano())
	var (
		mu       sync.Mutex
		abnormal relayEnd // the first abnormal end
		fin      string   // the side whose FIN came first
		once     sync.Once
	)
	closeBoth := func() {
		once.Do(func() {
			client.Close()
			up.Close()
		})
	}
	// fail records an abnormal end (the first wins) and closes both sides.
	// An error that is the forwarder's own close is no event of its own: it
	// follows another direction's end, or Close (shutdown).
	fail := func(e relayEnd, err error) {
		mu.Lock()
		if abnormal.End == "" {
			switch {
			case err != nil && errors.Is(err, net.ErrClosed) && s.closed.Load():
				abnormal = relayEnd{End: EndShutdown}
			case err != nil && errors.Is(err, net.ErrClosed):
				// closed by the other direction's end: recorded there
			default:
				abnormal = e
			}
		}
		mu.Unlock()
		closeBoth()
	}
	var wg sync.WaitGroup
	cp := func(dst, src net.Conn, srcClient bool, n *atomic.Int64) {
		defer wg.Done()
		bp := bufPool.Get().(*[]byte)
		defer bufPool.Put(bp)
		b := *bp
		srcReset, srcErr, srcFIN, dstReset, dstErr := EndUpstreamReset, EndUpstreamError, EndUpstreamClosed, EndClientReset, EndClientError
		if srcClient {
			srcReset, srcErr, srcFIN, dstReset, dstErr = EndClientReset, EndClientError, EndClientClosed, EndUpstreamReset, EndUpstreamError
		}
		for {
			if idle > 0 {
				_ = src.SetReadDeadline(time.Now().Add(idle))
			}
			k, err := src.Read(b)
			if k > 0 {
				last.Store(time.Now().UnixNano())
				if idle > 0 {
					_ = dst.SetWriteDeadline(time.Now().Add(idle))
				}
				if _, werr := dst.Write(b[:k]); werr != nil {
					fail(writeEnd(dstReset, dstErr, werr), werr)
					return
				}
				n.Add(int64(k))
			}
			if err != nil {
				switch {
				case errors.Is(err, os.ErrDeadlineExceeded) && idle > 0:
					if time.Since(time.Unix(0, last.Load())) < idle {
						continue // the other direction is active
					}
					fail(relayEnd{End: EndIdleTimeout}, err)
				case errors.Is(err, io.EOF):
					mu.Lock()
					if fin == "" {
						fin = srcFIN
					}
					mu.Unlock()
					closeWrite(dst)
				default:
					c := NetErrClass(err)
					if c == "reset" {
						fail(relayEnd{End: srcReset, Reason: "read_reset"}, err)
					} else {
						fail(relayEnd{End: srcErr, Reason: "read_" + c}, err)
					}
				}
				return
			}
		}
	}
	if clientDone {
		fin = EndClientClosed
		wg.Add(1)
		cp(client, up, false, &ac.down)
	} else {
		wg.Add(2)
		go cp(up, client, true, &ac.up)
		cp(client, up, false, &ac.down)
		wg.Wait()
	}
	mu.Lock()
	defer mu.Unlock()
	switch {
	case abnormal.End != "":
		return abnormal
	case fin != "":
		return relayEnd{End: fin}
	case s.closed.Load():
		return relayEnd{End: EndShutdown}
	}
	return relayEnd{End: EndClientError, Reason: "read_other"}
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

// The states of an accepted socket's mark (MarkInfo.Status,
// ConnRecord.MarkStatus, counters "mark_<state>").
const (
	// MarkOK: the mark carries the takeover bit; the rest is the address
	// classifier's mark of this connection.
	MarkOK = "ok"
	// MarkWithoutBit: SO_MARK was read but lacks the takeover bit (the SYN
	// that created the socket was not marked by sniff_mark, or
	// tcp_fwmark_accept is off).
	MarkWithoutBit = "without_bit"
	// MarkReadFailed: SO_MARK could not be read.
	MarkReadFailed = "read_failed"
	// MarkUnknownTarget: the mark carries the bit but no target of the
	// loaded target file has it (result unknown_mark).
	MarkUnknownTarget = "unknown_target"
)

// ViewOwnAddress (ConnRecord.View): the socket mark was not trustworthy, the
// connection was refused (result mark_missing), and the record's rule,
// target, by and mark fields are the forwarder's own address decision,
// kept for diagnosis only: it was not acted on.
const ViewOwnAddress = "own_address_view"

// ErrClassificationUnconfirmed (ConnRecord.Error of result mark_missing):
// the kernel's address classification of the connection could not be
// confirmed from the socket mark, so the connection was refused.
const ErrClassificationUnconfirmed = "classification_unconfirmed"

// WhyUnresolved (ConnRecord.Why): a name was read and decided a target, but
// that target's resolvers gave no address for it (NXDOMAIN, no address of
// a usable family, every resolver failed, or the lookup budget ran out;
// ConnRecord.Error says which), so the connection was handled exactly like
// one without a name: by its original destination address
// (docs/architecture.md「名字解析不到时按地址处理」).
const WhyUnresolved = "name_unresolved"

// MarkInfo is what Server.AddrMark read from an accepted connection.
type MarkInfo struct {
	// Raw is SO_MARK as read (0 when it could not be read).
	Raw uint32
	// Mark is Raw without the takeover bit; meaningful with MarkOK only.
	Mark uint32
	// Status is MarkOK, MarkWithoutBit or MarkReadFailed.
	Status string
}

// MarkFromSocket is Server.AddrMark for an install that marks redirected
// SYNs with bit and the classification mark (Config.AddrMarkBit): the
// accepted socket's SO_MARK (net.ipv4.tcp_fwmark_accept) with bit cleared.
// A mark without bit or one that cannot be read is reported as such and
// never as a classification.
func MarkFromSocket(bit uint32) func(net.Conn) MarkInfo {
	return func(c net.Conn) MarkInfo {
		m, err := SocketMark(c)
		switch {
		case err != nil:
			return MarkInfo{Status: MarkReadFailed}
		case bit == 0 || m&bit == 0:
			return MarkInfo{Raw: m, Status: MarkWithoutBit}
		}
		return MarkInfo{Raw: m, Mark: m &^ bit, Status: MarkOK}
	}
}

// decideAddr is the forwarder's own address decision for c: the ordered
// engine without a name (CIDR entries, GEOIP,CN, the China addresses, the
// default). It cannot see the addresses the gateway's resolver learned into
// the rules' sets at run time.
func (s *Server) decideAddr(st *ruleState, c Conn) ordered.Decision {
	c.Sniff = Result{}
	d, _ := s.decide(st, c)
	return d
}

// addrDecision is the decision for a connection handled by its address
// (no usable name, or a name that could not be resolved). own is the
// forwarder's own address decision. It returns the decision to record and,
// when the connection must end, the result.
//
// Without AddrMark the own decision is used (no kernel classification is
// available in that mode). With AddrMark:
//
//   - MarkOK: the target with the address classifier's mark (exactly what
//     the connection would get with sniffing off, including addresses the
//     resolver learned into a rule's set). A mark no target has ends the
//     connection (unknown_mark): a rule pair from another generation, never
//     guessed.
//   - MarkWithoutBit / MarkReadFailed: there is no trustworthy kernel
//     classification, and the connection is refused (result mark_missing,
//     Error ErrClassificationUnconfirmed) whatever the own decision says.
//     The own decision cannot see the addresses the gateway's resolver
//     learned into the rules' sets at run time (a name rule's answers,
//     including a reject rule's, and the domestic list's answers): an
//     address the kernel would reject, send direct or send to another
//     tunnel through such a set can look like a plain default-group or
//     CIDR address to it. Forwarding on it, even only to a tunnel, could
//     bypass a reject rule, so only a reset is safe. The own decision is
//     recorded for diagnosis (View ViewOwnAddress, with MarkStatus and
//     RawMark). sniff_input puts the takeover bit back on every redirected
//     SYN that lost it, so this remains for tcp_fwmark_accept switched off
//     and an unreadable SO_MARK.
func (s *Server) addrDecision(st *ruleState, c net.Conn, own ordered.Decision, rec *ConnRecord) (ordered.Decision, string) {
	if s.AddrMark == nil {
		return own, ""
	}
	mi := s.AddrMark(c)
	rec.MarkStatus = mi.Status
	if mi.Status != MarkReadFailed {
		rec.RawMark = fmt.Sprintf("%#x", mi.Raw)
	}
	if mi.Status == MarkOK {
		t, known := st.byMark[mi.Mark]
		if !known {
			rec.MarkStatus = MarkUnknownTarget
			s.counter.add("mark_" + MarkUnknownTarget)
			return ordered.Decision{Index: -1, Mark: mi.Mark, By: ordered.ByAddr, Reason: "address classifier mark"}, "unknown_mark"
		}
		s.counter.add("mark_" + MarkOK)
		d := ordered.Decision{Index: -1, Target: t.Name, Mark: mi.Mark, By: ordered.ByAddr, Reason: "address classifier mark"}
		if t.Reject {
			d.Action = "reject"
		}
		return d, ""
	}
	s.counter.add("mark_" + mi.Status)
	// Refused; the counter says what the own view would have chosen.
	kind := "tunnel"
	switch {
	case own.Action == "reject":
		kind = "reject"
	case own.Action == "direct" || st.direct[own.Mark]:
		kind = "direct"
	}
	s.counter.add("mark_missing_own_view_" + kind)
	rec.View = ViewOwnAddress
	rec.Error = ErrClassificationUnconfirmed
	return own, "mark_missing"
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

// ConnRecord is one decision: in the in-memory recent record and, with a
// journal, in the connection journal (journal.go).
type ConnRecord struct {
	Start  time.Time `json:"start"`
	Source string    `json:"source"`
	// MAC is the client's MAC from the neighbour table (--neigh-if), when
	// it was known.
	MAC   string `json:"mac,omitempty"`
	Dest  string `json:"dest,omitempty"`
	Proto string `json:"proto,omitempty"`
	Name  string `json:"name,omitempty"` // only with Config.RecordNames
	ECH   bool   `json:"ech,omitempty"`
	Why   string `json:"why,omitempty"` // why no name
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
	// Conn numbers the connection within this forwarder process (the
	// active view's key; it restarts at 1 with the process).
	Conn uint64 `json:"conn,omitempty"`
	// End is how a relayed connection ended (EndClientClosed …; empty for a
	// connection that was not relayed). Reason is the bounded class of the
	// failure behind the result: for dial_failed the last attempt's
	// NetErrClass (Upstream is the address it went to), for a relay
	// "<read|write>_<NetErrClass>" or write_stalled.
	End    string `json:"end,omitempty"`
	Reason string `json:"reason,omitempty"`
	// DurationMS is the connection's whole life (accept to final record);
	// BytesUp the bytes relayed from the client to the upstream (the
	// sniffed first bytes included), BytesDown from the upstream to the
	// client. Counts only, never content.
	DurationMS int64 `json:"duration_ms,omitempty"`
	BytesUp    int64 `json:"bytes_up,omitempty"`
	BytesDown  int64 `json:"bytes_down,omitempty"`
	// NameRule is the decision the name made when its lookup failed and
	// the connection was handled by address instead (Why WhyUnresolved);
	// the fields above then describe the address decision.
	NameRule *NameRule `json:"name_rule,omitempty"`
	// MarkStatus is the state of the accepted socket's mark when it was
	// consulted (MarkOK, MarkWithoutBit, MarkReadFailed,
	// MarkUnknownTarget), RawMark the mark as read in hex (absent when it
	// could not be read). View is ViewOwnAddress when the mark was not
	// trustworthy: the connection was refused and the rule, target, by and
	// mark fields are the forwarder's own address decision (diagnosis only).
	MarkStatus string `json:"mark_status,omitempty"`
	RawMark    string `json:"raw_mark,omitempty"`
	View       string `json:"view,omitempty"`
}

// EndTime is when the connection's record was finished (Start plus
// DurationMS): the journal's time for retention and ordering.
func (r *ConnRecord) EndTime() time.Time {
	return r.Start.Add(time.Duration(r.DurationMS) * time.Millisecond)
}

// NameRule is the name's decision of a connection whose name could not be
// resolved (ConnRecord.NameRule). Error is why the lookup gave no address:
// nxdomain, no_address, resolver_failed or timeout (the lookup budget).
type NameRule struct {
	Index  int    `json:"rule_index"`
	ID     string `json:"rule_id,omitempty"`
	Target string `json:"target,omitempty"`
	Mark   uint32 `json:"mark,omitempty"`
	By     string `json:"by,omitempty"`
	Error  string `json:"error,omitempty"`
}

// finish writes a connection's one final record: the counters, the
// per-target statistics, the ring and the journal hand-off, in that order,
// then takes the connection out of the active view. Every connection passes
// here exactly once (handle's returns; a relayed one through finishRelay).
func (s *Server) finish(r *ConnRecord, result string) {
	r.Result = result
	now := s.now()
	r.DurationMS = now.Sub(r.Start).Milliseconds()
	if r.End == "" {
		// Not relayed: the decision took the whole time.
		r.DecideMS = r.DurationMS
	}
	s.counter.add("result_" + result)
	if r.End != "" {
		s.counter.add("end_" + r.End)
	}
	if r.Target != "" {
		// At the end time: a long connection counts in the window it ended.
		switch result {
		case ResultOK:
			s.tstats.add(r.Target, statOK, now, "")
		case "resolve_failed":
			s.tstats.add(r.Target, statResolve, now, strings.TrimSpace("resolve_failed "+r.Error))
		case "dial_failed":
			s.tstats.add(r.Target, statDial, now, strings.TrimSpace("dial_failed "+r.Reason))
		case ResultRelayFailed, ResultNoResponse:
			s.tstats.add(r.Target, statRelay, now, strings.TrimSpace(result+" "+r.End+" "+r.Reason))
		}

		if r.Sniffed {
			s.counter.add("decided_by_name")
		} else {
			s.counter.add("decided_by_address_" + r.Why)
		}
	}
	s.recent.put(*r)
	s.Journal.Add(*r)
	if r.End != "" {
		s.activeMu.Lock()
		delete(s.active, r.Conn)
		s.activeMu.Unlock()
		s.Journal.notifyChange()
	}
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

// clear drops every record.
func (r *ring) clear() {
	r.mu.Lock()
	clear(r.buf)
	r.next, r.full = 0, false
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
	Ready           bool       `json:"ready"`
	Mode            string     `json:"mode"`
	Listen          string     `json:"listen"`
	Generation      uint64     `json:"generation"`
	LoadedAt        time.Time  `json:"loaded_at,omitempty"`
	Rules           int        `json:"rules"`
	Targets         []string   `json:"targets"`
	MACRules        bool       `json:"mac_rules"`
	MACLookup       bool       `json:"mac_lookup"`
	LastReloadAt    *time.Time `json:"last_reload_at,omitempty"`
	LastReloadError string     `json:"last_reload_error,omitempty"`
	Active          int        `json:"active"`
	// Relaying: of Active, the connections past their decision and being
	// relayed (the active view); the rest are still being decided.
	Relaying    int               `json:"relaying"`
	MaxConns    int               `json:"max_conns"`
	RecordNames bool              `json:"record_names"`
	ECHOuter    bool              `json:"ech_outer"`
	Counters    map[string]uint64 `json:"counters"`
	// TargetsSHA256 identifies the loaded rule pair (SelfCheck.TargetsSHA256).
	TargetsSHA256 string `json:"targets_sha256,omitempty"`
	// TargetStats: per target, how connections ended, since start and over
	// the last StatsWindowS seconds.
	TargetStats  []TargetStat `json:"target_stats,omitempty"`
	StatsWindowS int          `json:"stats_window_s,omitempty"`
	// SelfCheck is the most recent self-check (selfcheck.go).
	SelfCheck *SelfCheck `json:"self_check,omitempty"`
	// Journal describes the connection journal (nil: none).
	Journal *JournalStats `json:"journal,omitempty"`
}

// Health reports readiness and counters.
func (s *Server) Health() Health {
	h := Health{Mode: s.cfg.Mode, Listen: s.cfg.Listen, MaxConns: s.cfg.MaxConns, RecordNames: s.cfg.RecordNames,
		ECHOuter: s.cfg.ECHOuter, MACLookup: s.Neighbors != nil, Counters: s.counter.snapshot(), Active: len(s.sem)}
	if st := s.state.Load(); st != nil {
		h.Ready = s.ln != nil && !s.closed.Load()
		h.Generation, h.LoadedAt, h.Rules, h.MACRules, h.TargetsSHA256 = st.gen, st.at, st.c.Len(), st.c.HasMACRules(), st.sha
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
	s.activeMu.Lock()
	h.Relaying = len(s.active)
	s.activeMu.Unlock()
	h.TargetStats, h.StatsWindowS = s.tstats.snapshot(s.now()), int(StatsWindow/time.Second)
	h.SelfCheck = s.LastSelfCheck()
	if s.Journal != nil {
		js := s.Journal.Stats()
		h.Journal = &js
	}
	return h
}
