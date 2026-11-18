// Package dnssplit is the gateway's check for names no list and no rule
// matches (settings unlisted_domestic_dns): the gateway SmartDNS sends such
// names here instead of to the default exit's resolver, and this decides,
// per answer, which resolver's answer the client gets:
//
//   - A and AAAA queries go to every domestic resolver (plain UDP) and to
//     the default exit's resolver at the same time;
//   - a domestic answer is used only when its rcode is NOERROR, it is not
//     truncated, it has at least one address record of the queried type in
//     the answer section, and EVERY A/AAAA record in the answer section is
//     inside the China lists (chnroute). The whole answer is accepted or
//     rejected: a CNAME chain ending in a foreign address, a mixed answer,
//     NODATA and a poisoned address are all rejected;
//   - otherwise the exit's answer is returned as it came, or SERVFAIL when
//     the exit does not answer. A domestic answer is never returned unless
//     it passed the check;
//   - every other query type goes to the exit only.
//
// When it decides (Resolve):
//
//   - a qualifying domestic answer is returned the moment it arrives, as
//     long as no decision was made yet;
//   - a domestic resolver is "done" when it gave a non-qualifying reply and
//     Settle passed after that first reply with no qualifying second reply
//     to the same query (see below), or when DomesticTimeout passed with no
//     reply at all (silent);
//   - the exit's answer is returned as soon as the exit has answered AND
//     either every domestic resolver is done or at least one of them is
//     done after answering. A silent resolver therefore holds nothing up
//     once another one has answered and settled; DomesticTimeout only caps
//     the wait when no domestic resolver answers at all;
//   - with the exit silent or failed, every domestic resolver is waited for
//     (a China answer is still usable), then SERVFAIL.
//
// Settle exists for on-path injection: on plain UDP a forged reply can
// arrive before the resolver's genuine one, with the same ID. After a
// resolver's first non-qualifying reply its socket is read for Settle more,
// and a qualifying reply in that time is accepted. Getting this wrong in
// either timing direction is safe: a genuine China answer that arrives too
// late (or a qualifying answer from a slower second resolver) only means
// the name gets the exit's answer and is tunnelled instead of going direct.
// The other direction, returning a domestic answer with a non-China
// address, cannot happen at any timing, because only qualifying answers are
// ever returned from a domestic resolver.
//
// SmartDNS 1.2026.08.05 cannot express this itself: with -whitelist-ip a
// domestic answer "CNAME + foreign A" keeps the CNAME, the CNAME sets the
// request's rcode to NOERROR, so the "all addresses skipped, retry" branch
// of _dns_server_process_answer (it requires rcode SERVFAIL) never runs, the
// -fallback exit server is never asked, and the client gets (and SmartDNS
// caches) the address-less CNAME. See docs/architecture.md「未列名单域名的国内解析」.
package dnssplit

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/netip"
	"os"
	"strings"
	"sync"
	"time"
)

// Config is the whole configuration; the gateway unit passes it as flags
// (ParseArgs).
type Config struct {
	// Listen is the UDP and TCP address SmartDNS asks (loopback).
	Listen string
	// Domestic are the domestic resolvers, host:port.
	Domestic []string
	// Exit is the default exit's (or default group's) resolver, host:port,
	// and ExitMark the fwmark its queries carry (0: none), exactly as the
	// SmartDNS upstream line for it.
	Exit     string
	ExitMark int
	// China4, China6 are the China IP lists the list update saves. A
	// missing or unreadable list accepts nothing.
	China4, China6 string
	// DomesticTimeout caps the wait for a domestic resolver that does not
	// answer at all; Settle is how long a resolver's socket is still read
	// after its first non-qualifying reply; ExitTimeout bounds one exit
	// query. StatsInterval is the period of the summary log line (0: none).
	DomesticTimeout, Settle, ExitTimeout, StatsInterval time.Duration
}

// Defaults of the timing flags (the gateway unit writes them out).
const (
	DefaultDomesticTimeout = 400 * time.Millisecond
	DefaultSettle          = 30 * time.Millisecond
	DefaultExitTimeout     = 2 * time.Second
	DefaultStatsInterval   = 10 * time.Minute
)

// ParseArgs reads the flags of "meridian dns-split".
func ParseArgs(args []string) (Config, error) {
	fs := flag.NewFlagSet("dns-split", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	var c Config
	var domestic string
	fs.StringVar(&c.Listen, "listen", "", "loopback host:port")
	fs.StringVar(&domestic, "domestic", "", "domestic resolvers, comma separated host:port")
	fs.StringVar(&c.Exit, "exit", "", "default exit resolver host:port")
	fs.IntVar(&c.ExitMark, "exit-mark", 0, "fwmark for exit queries")
	fs.StringVar(&c.China4, "china4", "", "China IPv4 list")
	fs.StringVar(&c.China6, "china6", "", "China IPv6 list")
	fs.DurationVar(&c.DomesticTimeout, "domestic-timeout", DefaultDomesticTimeout, "cap for a silent domestic resolver")
	fs.DurationVar(&c.Settle, "settle", DefaultSettle, "extra read after a domestic resolver's first non-qualifying reply")
	fs.DurationVar(&c.ExitTimeout, "exit-timeout", DefaultExitTimeout, "one exit query")
	fs.DurationVar(&c.StatsInterval, "stats-interval", DefaultStatsInterval, "summary log period, 0 for none")
	if err := fs.Parse(args); err != nil {
		return c, err
	}
	if fs.NArg() != 0 {
		return c, fmt.Errorf("unexpected argument %q", fs.Arg(0))
	}
	for _, d := range strings.Split(domestic, ",") {
		if d = strings.TrimSpace(d); d != "" {
			c.Domestic = append(c.Domestic, d)
		}
	}
	for _, hp := range append([]string{c.Listen, c.Exit}, c.Domestic...) {
		if _, err := netip.ParseAddrPort(hp); err != nil {
			return c, fmt.Errorf("not an address:port: %q", hp)
		}
	}
	if len(c.Domestic) == 0 {
		return c, errors.New("no domestic resolver")
	}
	if c.ExitMark < 0 {
		return c, errors.New("negative mark")
	}
	if c.DomesticTimeout <= 0 || c.ExitTimeout <= 0 || c.Settle < 0 || c.Settle > c.DomesticTimeout || c.StatsInterval < 0 {
		return c, errors.New("timings: domestic-timeout and exit-timeout > 0, 0 <= settle <= domestic-timeout, stats-interval >= 0")
	}
	return c, nil
}

// Server answers on Config.Listen.
type Server struct {
	cfg     Config
	china4  []netip.Prefix
	china6  []netip.Prefix
	udp     net.PacketConn
	tcp     net.Listener
	wg      sync.WaitGroup
	closing chan struct{}
	// Logf reports upstream failures (nil: discard).
	Logf  func(format string, args ...any)
	stats stats
}

// New loads the China lists; it does not listen yet.
func New(cfg Config) *Server {
	s := &Server{cfg: cfg, closing: make(chan struct{})}
	s.china4 = loadList(cfg.China4, true)
	s.china6 = loadList(cfg.China6, false)
	return s
}

// loadList reads a China list as the list update saved it (it validated
// the file strictly before publishing it, internal/lists.ParsePrefixes):
// one prefix or address per line, "#" comments. Lines of the other family
// or that do not parse are skipped.
func loadList(path string, v4 bool) []netip.Prefix {
	if path == "" {
		return nil
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var out []netip.Prefix
	for _, line := range strings.Split(string(b), "\n") {
		if i := strings.IndexByte(line, '#'); i >= 0 {
			line = line[:i]
		}
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		p, err := netip.ParsePrefix(line)
		if err != nil {
			a, err := netip.ParseAddr(line)
			if err != nil {
				continue
			}
			p = netip.PrefixFrom(a, a.BitLen())
		}
		if p.Addr().Is4() != v4 || p.Addr().Is4In6() {
			continue
		}
		out = append(out, p.Masked())
	}
	return out
}

// Lists reports how many China prefixes were loaded.
func (s *Server) Lists() (v4, v6 int) { return len(s.china4), len(s.china6) }

func (s *Server) logf(format string, args ...any) {
	if s.Logf != nil {
		s.Logf(format, args...)
	}
}

// Start listens on UDP and TCP.
func (s *Server) Start() error {
	pc, err := net.ListenPacket("udp", s.cfg.Listen)
	if err != nil {
		return err
	}
	ln, err := net.Listen("tcp", pc.LocalAddr().String())
	if err != nil {
		pc.Close()
		return err
	}
	s.udp, s.tcp = pc, ln
	s.wg.Add(2)
	go s.serveUDP()
	go s.serveTCP()
	return nil
}

// Addr is the bound address (useful with port 0).
func (s *Server) Addr() string { return s.udp.LocalAddr().String() }

// Close stops listening and waits for the listeners.
func (s *Server) Close() {
	close(s.closing)
	s.udp.Close()
	s.tcp.Close()
	s.wg.Wait()
}

func (s *Server) serveUDP() {
	defer s.wg.Done()
	buf := make([]byte, 65535)
	for {
		n, from, err := s.udp.ReadFrom(buf)
		if err != nil {
			return
		}
		q := append([]byte(nil), buf[:n]...)
		go func() {
			if r := s.Resolve(q, false); r != nil {
				_, _ = s.udp.WriteTo(r, from)
			}
		}()
	}
}

func (s *Server) serveTCP() {
	defer s.wg.Done()
	for {
		c, err := s.tcp.Accept()
		if err != nil {
			return
		}
		go func() {
			defer c.Close()
			for {
				_ = c.SetDeadline(time.Now().Add(10 * time.Second))
				q, err := readTCP(c)
				if err != nil {
					return
				}
				r := s.Resolve(q, true)
				if r == nil {
					return
				}
				if err := writeTCP(c, r); err != nil {
					return
				}
			}
		}()
	}
}

func readTCP(c net.Conn) ([]byte, error) {
	var l [2]byte
	if _, err := io.ReadFull(c, l[:]); err != nil {
		return nil, err
	}
	b := make([]byte, binary.BigEndian.Uint16(l[:]))
	_, err := io.ReadFull(c, b)
	return b, err
}

func writeTCP(c net.Conn, b []byte) error {
	out := binary.BigEndian.AppendUint16(nil, uint16(len(b)))
	_, err := c.Write(append(out, b...))
	return err
}

// Resolve answers one query (nil: not a query, drop it). See the package
// comment for when it decides.
func (s *Server) Resolve(q []byte, tcp bool) []byte {
	msg, err := parseQuery(q)
	if err != nil {
		return nil
	}
	start := time.Now()
	ctx, cancel := context.WithTimeout(context.Background(), s.cfg.DomesticTimeout+s.cfg.ExitTimeout+time.Second)
	defer cancel()
	exitCh := make(chan []byte, 1)
	go func() { exitCh <- s.askExit(ctx, q, tcp) }()
	if msg.qtype != typeA && msg.qtype != typeAAAA {
		r := <-exitCh
		s.stats.record(outcomeOther, time.Since(start))
		if r != nil {
			return withID(r, msg.id)
		}
		return servfail(q, msg)
	}
	n := len(s.cfg.Domestic)
	events := make(chan domEvent, n)
	for _, d := range s.cfg.Domestic {
		go s.watchDomestic(ctx, d, q, msg, start, events)
	}
	var exitR []byte
	exitDone := false
	done, answeredDone := 0, 0
	for {
		if exitDone && exitR != nil && (done == n || answeredDone > 0) {
			s.stats.record(outcomeExit, time.Since(start))
			return withID(exitR, msg.id)
		}
		if exitDone && exitR == nil && done == n {
			s.stats.record(outcomeServfail, time.Since(start))
			return servfail(q, msg)
		}
		select {
		case ev := <-events:
			if ev.accept != nil {
				if ev.second {
					s.stats.secondReply.Add(1)
				}
				s.stats.record(outcomeDomestic, time.Since(start))
				return withID(ev.accept, msg.id)
			}
			done++
			if ev.answered {
				answeredDone++
			} else {
				s.stats.silent.Add(1)
			}
		case r := <-exitCh:
			exitDone, exitR, exitCh = true, r, nil
		}
	}
}

// domEvent is one domestic resolver's verdict: a qualifying answer, or
// done (answered: it replied, nothing qualified within Settle; otherwise
// it stayed silent until DomesticTimeout).
type domEvent struct {
	accept   []byte
	second   bool // the qualifying reply followed a non-qualifying one
	answered bool
}

// watchDomestic asks one domestic resolver over UDP and reports exactly one
// event.
func (s *Server) watchDomestic(ctx context.Context, server string, q []byte, msg query, start time.Time, out chan<- domEvent) {
	deadline := start.Add(s.cfg.DomesticTimeout)
	var d net.Dialer
	c, err := d.DialContext(ctx, "udp", server)
	if err != nil {
		out <- domEvent{}
		return
	}
	defer c.Close()
	stop := context.AfterFunc(ctx, func() { _ = c.SetReadDeadline(time.Now()) })
	defer stop()
	id := newID()
	if _, err := c.Write(withID(q, id)); err != nil {
		out <- domEvent{}
		return
	}
	answered := false
	buf := make([]byte, 65535)
	for {
		if ctx.Err() != nil {
			out <- domEvent{answered: answered}
			return
		}
		_ = c.SetReadDeadline(deadline)
		nr, err := c.Read(buf)
		if err != nil {
			out <- domEvent{answered: answered}
			return
		}
		r := buf[:nr]
		if len(r) < 12 || binary.BigEndian.Uint16(r) != id || r[2]&0x80 == 0 {
			continue
		}
		if rm, err := parseQuery(r); err != nil || rm.qname != msg.qname || rm.qtype != msg.qtype {
			continue
		}
		if s.qualifies(r, msg) {
			out <- domEvent{accept: append([]byte(nil), r...), second: answered}
			return
		}
		if !answered {
			answered = true
			if t := time.Now().Add(s.cfg.Settle); t.Before(deadline) {
				deadline = t
			}
		}
	}
}

// qualifies: NOERROR, not truncated, at least one address of the queried
// type, and every A/AAAA in the answer section is a China address.
func (s *Server) qualifies(r []byte, msg query) bool {
	if len(r) < 12 || r[2]&0x02 != 0 || r[3]&0x0f != 0 {
		return false
	}
	addrs, ok := answerAddrs(r)
	if !ok {
		return false
	}
	found := false
	for _, a := range addrs {
		if (a.Is4() && msg.qtype == typeA) || (a.Is6() && msg.qtype == typeAAAA) {
			found = true
		}
		set := s.china6
		if a.Is4() {
			set = s.china4
		}
		in := false
		for _, p := range set {
			if p.Contains(a) {
				in = true
				break
			}
		}
		if !in {
			return false
		}
	}
	return found
}

func (s *Server) askExit(ctx context.Context, q []byte, tcp bool) []byte {
	ctx, cancel := context.WithTimeout(ctx, s.cfg.ExitTimeout)
	defer cancel()
	msg, _ := parseQuery(q)
	if !tcp {
		r := exchangeUDP(ctx, s.cfg.Exit, s.cfg.ExitMark, q, msg)
		if r == nil {
			s.logf("dns-split: exit %s did not answer", s.cfg.Exit)
			return nil
		}
		if r[2]&0x02 == 0 {
			return r
		}
		// Truncated over UDP: ask the same resolver over TCP.
	}
	r := exchangeTCP(ctx, s.cfg.Exit, s.cfg.ExitMark, q)
	if r == nil {
		s.logf("dns-split: exit %s did not answer over TCP", s.cfg.Exit)
	}
	return r
}

func newID() uint16 {
	var b [2]byte
	_, _ = rand.Read(b[:])
	return binary.BigEndian.Uint16(b[:])
}

func withID(r []byte, id uint16) []byte {
	out := append([]byte(nil), r...)
	binary.BigEndian.PutUint16(out, id)
	return out
}

// exchangeUDP sends q (with its own ID) and returns the first reply whose
// ID and question match.
func exchangeUDP(ctx context.Context, server string, mark int, q []byte, msg query) []byte {
	d := net.Dialer{Control: markControl(mark)}
	c, err := d.DialContext(ctx, "udp", server)
	if err != nil {
		return nil
	}
	defer c.Close()
	if dl, ok := ctx.Deadline(); ok {
		_ = c.SetDeadline(dl)
	}
	id := newID()
	out := withID(q, id)
	if _, err := c.Write(out); err != nil {
		return nil
	}
	buf := make([]byte, 65535)
	for {
		n, err := c.Read(buf)
		if err != nil {
			return nil
		}
		r := buf[:n]
		if len(r) < 12 || binary.BigEndian.Uint16(r) != id || r[2]&0x80 == 0 {
			continue
		}
		rm, err := parseQuery(r)
		if err != nil || rm.qname != msg.qname || rm.qtype != msg.qtype {
			continue
		}
		return append([]byte(nil), r...)
	}
}

func exchangeTCP(ctx context.Context, server string, mark int, q []byte) []byte {
	d := net.Dialer{Control: markControl(mark)}
	c, err := d.DialContext(ctx, "tcp", server)
	if err != nil {
		return nil
	}
	defer c.Close()
	if dl, ok := ctx.Deadline(); ok {
		_ = c.SetDeadline(dl)
	}
	if err := writeTCP(c, q); err != nil {
		return nil
	}
	r, err := readTCP(c)
	if err != nil || len(r) < 12 || binary.BigEndian.Uint16(r) != binary.BigEndian.Uint16(q) {
		return nil
	}
	return r
}

// ---------------------------------------------------------- wire format ---

const (
	typeA     uint16 = 1
	typeCNAME uint16 = 5
	typeAAAA  uint16 = 28
)

type query struct {
	id    uint16
	qname string
	qtype uint16
	end   int // offset after the question
}

var errFormat = errors.New("malformed message")

// skipName returns the offset after the (possibly compressed) name at i.
func skipName(b []byte, i int) (int, error) {
	for n := 0; n < 128; n++ {
		if i >= len(b) {
			return 0, errFormat
		}
		l := int(b[i])
		switch {
		case l == 0:
			return i + 1, nil
		case l&0xc0 == 0xc0:
			if i+2 > len(b) {
				return 0, errFormat
			}
			return i + 2, nil
		case l&0xc0 != 0:
			return 0, errFormat
		}
		i += 1 + l
	}
	return 0, errFormat
}

// parseQuery reads the header and the single question.
func parseQuery(b []byte) (query, error) {
	var q query
	if len(b) < 12 || binary.BigEndian.Uint16(b[4:]) != 1 {
		return q, errFormat
	}
	q.id = binary.BigEndian.Uint16(b)
	i := 12
	var labels []string
	for {
		if i >= len(b) {
			return q, errFormat
		}
		l := int(b[i])
		i++
		if l == 0 {
			break
		}
		if l&0xc0 != 0 || i+l > len(b) || len(labels) > 127 {
			return q, errFormat
		}
		labels = append(labels, strings.ToLower(string(b[i:i+l])))
		i += l
	}
	if i+4 > len(b) {
		return q, errFormat
	}
	q.qname = strings.Join(labels, ".")
	q.qtype = binary.BigEndian.Uint16(b[i:])
	q.end = i + 4
	return q, nil
}

// answerAddrs lists every A/AAAA record of the answer section, whatever its
// owner (a CNAME chain's target owns the addresses).
func answerAddrs(b []byte) ([]netip.Addr, bool) {
	q, err := parseQuery(b)
	if err != nil {
		return nil, false
	}
	an := int(binary.BigEndian.Uint16(b[6:]))
	i := q.end
	var out []netip.Addr
	for k := 0; k < an; k++ {
		j, err := skipName(b, i)
		if err != nil || j+10 > len(b) {
			return nil, false
		}
		typ := binary.BigEndian.Uint16(b[j:])
		rdl := int(binary.BigEndian.Uint16(b[j+8:]))
		if j+10+rdl > len(b) {
			return nil, false
		}
		rd := b[j+10 : j+10+rdl]
		switch {
		case typ == typeA && rdl == 4:
			out = append(out, netip.AddrFrom4([4]byte(rd)))
		case typ == typeAAAA && rdl == 16:
			out = append(out, netip.AddrFrom16([16]byte(rd)))
		case typ == typeA || typ == typeAAAA:
			return nil, false
		}
		i = j + 10 + rdl
	}
	return out, true
}

// servfail answers q with SERVFAIL and no records.
func servfail(q []byte, msg query) []byte {
	out := append([]byte(nil), q[:msg.end]...)
	out[2] = 0x80 | (q[2] & 0x01) // QR, keep RD
	out[3] = 0x80 | 2             // RA, SERVFAIL
	binary.BigEndian.PutUint16(out[6:], 0)
	binary.BigEndian.PutUint16(out[8:], 0)
	binary.BigEndian.PutUint16(out[10:], 0)
	return out
}

// Main runs "meridian dns-split" until the process is stopped.
func Main(args []string) int {
	cfg, err := ParseArgs(args)
	if err != nil {
		fmt.Fprintln(os.Stderr, "meridian dns-split:", err)
		return 2
	}
	s := New(cfg)
	s.Logf = log.Printf
	if err := s.Start(); err != nil {
		fmt.Fprintln(os.Stderr, "meridian dns-split:", err)
		return 1
	}
	v4, v6 := s.Lists()
	log.Printf("meridian-dns-split-ready: listen %s, domestic %s, exit %s mark %d, China lists %d IPv4 / %d IPv6 prefixes, domestic-timeout %v settle %v exit-timeout %v", cfg.Listen, strings.Join(cfg.Domestic, ","), cfg.Exit, cfg.ExitMark, v4, v6, cfg.DomesticTimeout, cfg.Settle, cfg.ExitTimeout)
	if v4+v6 == 0 {
		log.Printf("meridian-dns-split: the China lists are empty or unreadable; no domestic answer will be accepted until a list update")
	}
	if cfg.StatsInterval <= 0 {
		select {}
	}
	for range time.Tick(cfg.StatsInterval) {
		if line := s.stats.summary(cfg.StatsInterval); line != "" {
			log.Print(line)
		}
	}
	return 0
}
