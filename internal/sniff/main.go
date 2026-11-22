package sniff

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/radowitz/meridian/internal/ordered"
)

// ParseArgs reads the flags of "meridian sniff".
func ParseArgs(args []string) (Config, error) {
	c := DefaultConfig()
	fs := flag.NewFlagSet("sniff", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	var neigh, ports, echPublic, markBit string
	fs.StringVar(&c.Listen, "listen", "", "TCP address:port the kernel delivers connections to")
	fs.StringVar(&c.Mode, "mode", c.Mode, "tproxy (IP_TRANSPARENT listener) or redirect (SO_ORIGINAL_DST)")
	fs.StringVar(&c.SnapshotPath, "snapshot", "", "ordered rule snapshot (decide.json)")
	fs.StringVar(&c.TargetsPath, "targets", "", "target file (marks and resolvers)")
	fs.StringVar(&c.ListsDir, "lists-dir", c.ListsDir, "lists directory the snapshot refers to")
	fs.StringVar(&c.StatusSocket, "status-socket", "", "Unix socket for /v1/health and /v1/recent (empty: none)")
	fs.StringVar(&c.JournalDir, "journal-dir", "", "directory of the bounded connection journal (empty: none)")
	fs.StringVar(&neigh, "neigh-if", "", "interfaces whose neighbour entries give client MACs, comma separated")
	fs.StringVar(&ports, "sniff-ports", "", "destination ports to sniff, comma separated (empty: all)")
	fs.DurationVar(&c.SniffTimeout, "sniff-timeout", c.SniffTimeout, "wait for the client's first bytes")
	fs.DurationVar(&c.DialTimeout, "dial-timeout", c.DialTimeout, "upstream connect")
	fs.DurationVar(&c.ResolveTimeout, "resolve-timeout", c.ResolveTimeout, "one query to one resolver")
	fs.DurationVar(&c.IdleTimeout, "idle-timeout", c.IdleTimeout, "close after no data either way (0: never)")
	fs.IntVar(&c.MaxSniffBytes, "max-sniff-bytes", c.MaxSniffBytes, "bytes read before a decision, per connection")
	fs.IntVar(&c.MaxConns, "max-conns", c.MaxConns, "concurrent connections")
	fs.IntVar(&c.MaxPerSource, "max-per-source", c.MaxPerSource, "concurrent connections of one client address")
	fs.IntVar(&c.RecentSize, "recent", c.RecentSize, "recent decisions kept in memory")
	fs.BoolVar(&c.RecordNames, "record-names", false, "keep sniffed names in the recent record and the connection journal (off: names already in the journal are removed at start)")
	fs.BoolVar(&c.ECHOuter, "ech-outer", false, "decide ECH connections by the outer (public) server name instead of the address")
	fs.StringVar(&echPublic, "ech-public-names", "", "with --ech-outer: ECH public names (and names under them) still decided by address, comma separated")
	fs.StringVar(&markBit, "addr-mark-bit", "", "take unnamed connections' target from the accepted socket's mark carrying this bit (hex; tcp_fwmark_accept)")
	fs.DurationVar(&c.StatsInterval, "stats-interval", c.StatsInterval, "counter log period (0: none)")
	fs.DurationVar(&c.SelfCheckInterval, "selfcheck-interval", c.SelfCheckInterval, "repeat the path self-check while running (0: only at start, after a reload and on request)")
	if err := fs.Parse(args); err != nil {
		return c, err
	}
	if fs.NArg() != 0 {
		return c, fmt.Errorf("unexpected argument %q", fs.Arg(0))
	}
	if _, err := netip.ParseAddrPort(c.Listen); err != nil {
		return c, fmt.Errorf("listen: not an address:port: %q", c.Listen)
	}
	if c.Mode != "tproxy" && c.Mode != "redirect" {
		return c, fmt.Errorf("mode: tproxy or redirect, not %q", c.Mode)
	}
	if c.SnapshotPath == "" || c.TargetsPath == "" {
		return c, errors.New("snapshot and targets are required")
	}
	if c.JournalDir != "" && (!filepath.IsAbs(c.JournalDir) || filepath.Clean(c.JournalDir) != c.JournalDir) {
		return c, fmt.Errorf("journal-dir: not a plain absolute path: %q", c.JournalDir)
	}
	c.NeighIfaces = splitList(neigh)
	for _, n := range splitList(echPublic) {
		d, ok := ordered.NormDomain(n)
		if !ok {
			return c, fmt.Errorf("ech-public-names: %q is not a domain name", n)
		}
		c.ECHPublicNames = append(c.ECHPublicNames, d)
	}
	if markBit != "" {
		v, err := strconv.ParseUint(strings.TrimPrefix(strings.ToLower(markBit), "0x"), 16, 32)
		if err != nil || v == 0 || v&(v-1) != 0 {
			return c, fmt.Errorf("addr-mark-bit: one bit in hex, not %q", markBit)
		}
		c.AddrMarkBit = uint32(v)
	}
	if c.RecentSize == 0 {
		c.RecentSize = -1 // "--recent 0": no record
	}
	for _, p := range splitList(ports) {
		n, err := strconv.Atoi(p)
		if err != nil || n <= 0 || n > 65535 {
			return c, fmt.Errorf("sniff-ports: bad port %q", p)
		}
		c.SniffPorts = append(c.SniffPorts, uint16(n))
	}
	switch {
	case c.SniffTimeout <= 0 || c.DialTimeout <= 0 || c.ResolveTimeout <= 0 || c.IdleTimeout < 0 || c.StatsInterval < 0:
		return c, errors.New("timeouts must be positive (idle-timeout, stats-interval >= 0)")
	case c.SelfCheckInterval != 0 && c.SelfCheckInterval < time.Minute:
		return c, errors.New("selfcheck-interval: 0 or at least 1m")
	case c.MaxSniffBytes < 512 || c.MaxSniffBytes > 1<<20:
		return c, errors.New("max-sniff-bytes: 512..1048576")
	case c.MaxConns <= 0 || c.MaxPerSource <= 0 || c.RecentSize < 0:
		return c, errors.New("max-conns, max-per-source > 0, recent >= 0")
	}
	return c, nil
}

func splitList(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// RecentActiveMax bounds the active connections in /v1/recent.
const RecentActiveMax = 100

// StatusHandler serves GET /v1/health, GET /v1/recent (the ring of final
// records and, as "active", the connections being relayed: at most
// RecentActiveMax, newest first, with "active_total"), POST /v1/selfcheck
// (no parameters: runs the self-check now, after any run in progress, and
// answers its result; bounded by SelfCheckBudget plus the wait for a run in
// progress) and the connection journal's fixed reads and clear:
// GET /v1/journal (JournalQuery as query parameters, validated; one page),
// GET /v1/journal/summary (from, to) and POST /v1/journal/clear (no
// parameters). Without a journal those answer 404. Every answer stays below
// MaxStatusAnswer (a page holds at most JournalPageMax lines of at most
// JournalMaxLine bytes; a summary at most JournalSummaryDevices devices).
func (s *Server) StatusHandler() http.Handler {
	mux := http.NewServeMux()
	write := func(w http.ResponseWriter, v any) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(v)
	}
	mux.HandleFunc("/v1/health", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "GET only", http.StatusMethodNotAllowed)
			return
		}
		h := s.Health()
		if !h.Ready {
			w.WriteHeader(http.StatusServiceUnavailable)
		}
		write(w, h)
	})
	mux.HandleFunc("/v1/recent", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "GET only", http.StatusMethodNotAllowed)
			return
		}
		active, total := s.Active(nil, RecentActiveMax)
		write(w, map[string]any{"record_names": s.cfg.RecordNames, "connections": s.Recent(), "active": active, "active_total": total})
	})
	noJournal := func(w http.ResponseWriter) bool {
		if s.Journal == nil {
			http.Error(w, "no connection journal", http.StatusNotFound)
			return true
		}
		return false
	}
	mux.HandleFunc("/v1/journal", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "GET only", http.StatusMethodNotAllowed)
			return
		}
		if noJournal(w) {
			return
		}
		q, err := JournalQueryFrom(r.URL.Query())
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		page, err := s.journalPage(q)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		write(w, page)
	})
	mux.HandleFunc("/v1/journal/summary", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "GET only", http.StatusMethodNotAllowed)
			return
		}
		if noJournal(w) {
			return
		}
		var q JournalSummaryQuery
		for k, vs := range r.URL.Query() {
			if len(vs) != 1 || (k != "from" && k != "to") {
				http.Error(w, "parameters: from, to", http.StatusBadRequest)
				return
			}
		}
		q.From, q.To = r.URL.Query().Get("from"), r.URL.Query().Get("to")
		sum, err := s.journalSummary(q)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		write(w, sum)
	})
	mux.HandleFunc("/v1/journal/clear", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "POST only", http.StatusMethodNotAllowed)
			return
		}
		if r.ContentLength > 0 || r.URL.RawQuery != "" {
			http.Error(w, "no parameters", http.StatusBadRequest)
			return
		}
		if noJournal(w) {
			return
		}
		n := s.Journal.Clear()
		// The in-memory ring holds the same kind of records (names
		// included when recorded): "clear" empties it too. Connections
		// still open are live state, not records; each gets its record
		// when it ends.
		s.recent.clear()
		write(w, map[string]any{"cleared": n, "stats": s.Journal.Stats()})
	})
	mux.HandleFunc("POST /v1/connections/disconnect", func(w http.ResponseWriter, r *http.Request) {
		if r.ContentLength != 0 || r.URL.RawQuery != "" {
			http.Error(w, "no parameters", http.StatusBadRequest)
			return
		}
		write(w, map[string]int{"disconnected": s.DisconnectActive()})
	})
	mux.HandleFunc("/v1/selfcheck", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "POST only", http.StatusMethodNotAllowed)
			return
		}
		if r.ContentLength > 0 || r.URL.RawQuery != "" {
			http.Error(w, "no parameters", http.StatusBadRequest)
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 2*SelfCheckBudget)
		defer cancel()
		res, err := s.RunSelfCheck(ctx, TriggerRequest)
		if err != nil {
			http.Error(w, "self-check not run: "+err.Error(), http.StatusServiceUnavailable)
			return
		}
		write(w, res)
	})
	return mux
}

// Main runs "meridian sniff" until SIGTERM / SIGINT; SIGHUP reloads the
// snapshot and the target file (a failed reload keeps the current rules).
// Exit 2 usage, 1 failure to start.
func Main(args []string) int {
	cfg, err := ParseArgs(args)
	if err != nil {
		fmt.Fprintln(os.Stderr, "meridian sniff:", err)
		return 2
	}
	s := New(cfg)
	s.Logf = log.Printf
	if err := s.Reload(); err != nil {
		fmt.Fprintln(os.Stderr, "meridian-sniff-failed: rules:", err)
		return 1
	}
	switch cfg.Mode {
	case "tproxy":
		s.OrigDst = OrigDstLocal
	default:
		s.OrigDst = OrigDstRedirect
	}
	if cfg.AddrMarkBit != 0 {
		s.AddrMark = MarkFromSocket(cfg.AddrMarkBit)
	}
	if len(cfg.NeighIfaces) > 0 {
		nt, err := NewNeighborTable(cfg.NeighIfaces)
		if err != nil {
			fmt.Fprintln(os.Stderr, "meridian-sniff-failed: neighbour table:", err)
			return 1
		}
		s.Neighbors = nt.Lookup
	}
	if cfg.JournalDir != "" {
		// A journal that cannot be opened is not a reason to refuse
		// connections: the forwarder runs without one (Health.Journal nil).
		j, err := OpenJournal(JournalConfig{Dir: cfg.JournalDir, RecordNames: cfg.RecordNames, Active: s.relaying})
		if err != nil {
			log.Printf("meridian-sniff: warning: connection journal not available: %v", err)
		} else {
			s.Journal = j
			defer j.Close()
			if st := j.Stats(); st.PurgedNames > 0 || st.TornBytes > 0 {
				log.Printf("meridian-sniff: journal opened: %d records, names removed from %d (recording off), %d torn bytes cut", st.Records, st.PurgedNames, st.TornBytes)
			}
			if u := j.Stats().UncleanStop; u != nil {
				log.Printf("meridian-sniff: warning: the previous forwarder stopped without closing the journal (last alive %s, %d connections open then): those connections have no record", u.LastAlive.UTC().Format(time.RFC3339), u.Active)
			}
		}
	}
	h := s.Health()
	if h.MACRules && s.Neighbors == nil {
		log.Printf("meridian-sniff: warning: the rules restrict some rules by MAC and no --neigh-if is set; those rules match no connection here")
	}
	ln, err := Listen(context.Background(), cfg)
	if err != nil {
		fmt.Fprintln(os.Stderr, "meridian-sniff-failed: listen:", err)
		return 1
	}
	if err := s.Start(ln); err != nil {
		fmt.Fprintln(os.Stderr, "meridian-sniff-failed:", err)
		return 1
	}
	if cfg.StatusSocket != "" {
		// Answered only to uid 0 (the host agent; see status.go).
		sl, err := ListenStatus(cfg.StatusSocket, StatusRootOnly)
		if err != nil {
			fmt.Fprintln(os.Stderr, "meridian-sniff-failed: status socket:", err)
			s.Close()
			return 1
		}
		go func() { _ = (&http.Server{Handler: s.StatusHandler(), ReadHeaderTimeout: 5 * time.Second}).Serve(sl) }()
	}
	// The first self-check of these rules, in the background: forwarding
	// does not wait for it.
	s.TriggerSelfCheck(TriggerStart)
	h = s.Health()
	log.Printf("%s: listen %s mode %s, %d rules, %d targets, generation %d, sniff-timeout %v, max-sniff-bytes %d, max-conns %d/%d per source, MAC lookup %v, ECH by outer name %v (%d public names by address), address mark bit %#x, names recorded %v",
		ReadyMarker, cfg.Listen, cfg.Mode, h.Rules, len(h.Targets), h.Generation, cfg.SniffTimeout, cfg.MaxSniffBytes, cfg.MaxConns, cfg.MaxPerSource, h.MACLookup, cfg.ECHOuter, len(cfg.ECHPublicNames), cfg.AddrMarkBit, cfg.RecordNames)

	sig := make(chan os.Signal, 4)
	signal.Notify(sig, syscall.SIGHUP, syscall.SIGTERM, syscall.SIGINT)
	var tick, check <-chan time.Time
	if cfg.StatsInterval > 0 {
		t := time.NewTicker(cfg.StatsInterval)
		defer t.Stop()
		tick = t.C
	}
	if cfg.SelfCheckInterval > 0 {
		t := time.NewTicker(cfg.SelfCheckInterval)
		defer t.Stop()
		check = t.C
	}
	for {
		select {
		case x := <-sig:
			if x == syscall.SIGHUP {
				if err := s.Reload(); err != nil {
					log.Printf("meridian-sniff: reload failed, keeping generation %d: %v", s.Health().Generation, err)
				} else {
					log.Printf("meridian-sniff: reloaded, generation %d", s.Health().Generation)
					s.TriggerSelfCheck(TriggerReload)
				}
				continue
			}
			s.Close()
			if cfg.StatusSocket != "" {
				_ = os.Remove(cfg.StatusSocket)
			}
			return 0
		case <-tick:
			log.Printf("meridian-sniff-stats: %s", formatCounters(s.Health().Counters))
		case <-check:
			s.TriggerSelfCheck(TriggerPeriodic)
		}
	}
}

// journalPage is the journal's page with, on the first page of a query
// without a result filter, the matching connections still being relayed
// (JournalPage.Active).
func (s *Server) journalPage(q JournalQuery) (JournalPage, error) {
	page, err := s.Journal.Query(q)
	if err != nil || q.Before != 0 || q.Result != "" {
		return page, err
	}
	p, err := q.parse()
	if err != nil {
		return page, err
	}
	page.Active, page.ActiveMatched = s.Active(p.matchConn, JournalActiveMax)
	return page, nil
}

// journalSummary is the journal's summary with each device's connections
// still being relayed (DeviceSummary.Active); a device with open
// connections and no record yet is listed too.
func (s *Server) journalSummary(q JournalSummaryQuery) (JournalSummary, error) {
	sum, err := s.Journal.Summary(q)
	if err != nil {
		return sum, err
	}
	p, err := JournalQuery{From: q.From, To: q.To}.parse()
	if err != nil {
		return sum, err
	}
	active, _ := s.Active(p.matchConn, -1)
	idx := map[string]int{}
	for i, d := range sum.Devices {
		idx[d.Device] = i
	}
	for _, r := range active {
		i, ok := idx[r.Source]
		if !ok {
			if len(sum.Devices) >= JournalSummaryDevices {
				sum.Truncated = true
				continue
			}
			sum.Devices = append(sum.Devices, DeviceSummary{Device: r.Source, MAC: r.MAC, FirstSeen: r.Start, LastSeen: s.now(),
				ByClass: map[string]int{}, ByTarget: map[string]int{}})
			i = len(sum.Devices) - 1
			idx[r.Source] = i
		}
		sum.Devices[i].Active++
	}
	return sum, nil
}

func formatCounters(m map[string]uint64) string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	for i, k := range keys {
		if i > 0 {
			b.WriteByte(' ')
		}
		fmt.Fprintf(&b, "%s=%d", k, m[k])
	}
	return b.String()
}
