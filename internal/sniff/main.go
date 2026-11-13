package sniff

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// ParseArgs reads the flags of "meridian sniff".
func ParseArgs(args []string) (Config, error) {
	c := DefaultConfig()
	fs := flag.NewFlagSet("sniff", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	var neigh, ports string
	fs.StringVar(&c.Listen, "listen", "", "TCP address:port the kernel delivers connections to")
	fs.StringVar(&c.Mode, "mode", c.Mode, "tproxy (IP_TRANSPARENT listener) or redirect (SO_ORIGINAL_DST)")
	fs.StringVar(&c.SnapshotPath, "snapshot", "", "ordered rule snapshot (decide.json)")
	fs.StringVar(&c.TargetsPath, "targets", "", "target file (marks and resolvers)")
	fs.StringVar(&c.ListsDir, "lists-dir", c.ListsDir, "lists directory the snapshot refers to")
	fs.StringVar(&c.StatusSocket, "status-socket", "", "Unix socket for /v1/health and /v1/recent (empty: none)")
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
	fs.BoolVar(&c.RecordNames, "record-names", false, "keep sniffed names in the in-memory recent record")
	fs.BoolVar(&c.ECHOuter, "ech-outer", false, "decide ECH connections by the outer (public) server name instead of the address")
	fs.DurationVar(&c.StatsInterval, "stats-interval", c.StatsInterval, "counter log period (0: none)")
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
	c.NeighIfaces = splitList(neigh)
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

// StatusHandler serves GET /v1/health and GET /v1/recent.
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
		write(w, map[string]any{"record_names": s.cfg.RecordNames, "connections": s.Recent()})
	})
	return mux
}

// ListenStatus opens the status socket (0600, replacing a stale file).
func ListenStatus(path string) (net.Listener, error) {
	if fi, err := os.Lstat(path); err == nil {
		if fi.Mode()&os.ModeSocket == 0 {
			return nil, fmt.Errorf("%s exists and is not a socket", path)
		}
		_ = os.Remove(path)
	}
	old := syscall.Umask(0o177)
	l, err := net.Listen("unix", path)
	syscall.Umask(old)
	if err != nil {
		return nil, err
	}
	_ = os.Chmod(path, 0o600)
	return l, nil
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
	if len(cfg.NeighIfaces) > 0 {
		nt, err := NewNeighborTable(cfg.NeighIfaces)
		if err != nil {
			fmt.Fprintln(os.Stderr, "meridian-sniff-failed: neighbour table:", err)
			return 1
		}
		s.Neighbors = nt.Lookup
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
		sl, err := ListenStatus(cfg.StatusSocket)
		if err != nil {
			fmt.Fprintln(os.Stderr, "meridian-sniff-failed: status socket:", err)
			s.Close()
			return 1
		}
		go func() { _ = (&http.Server{Handler: s.StatusHandler(), ReadHeaderTimeout: 5 * time.Second}).Serve(sl) }()
	}
	h = s.Health()
	log.Printf("%s: listen %s mode %s, %d rules, %d targets, generation %d, sniff-timeout %v, max-sniff-bytes %d, max-conns %d/%d per source, MAC lookup %v, ECH by outer name %v, names recorded %v",
		ReadyMarker, cfg.Listen, cfg.Mode, h.Rules, len(h.Targets), h.Generation, cfg.SniffTimeout, cfg.MaxSniffBytes, cfg.MaxConns, cfg.MaxPerSource, h.MACLookup, cfg.ECHOuter, cfg.RecordNames)

	sig := make(chan os.Signal, 4)
	signal.Notify(sig, syscall.SIGHUP, syscall.SIGTERM, syscall.SIGINT)
	var tick <-chan time.Time
	if cfg.StatsInterval > 0 {
		t := time.NewTicker(cfg.StatsInterval)
		defer t.Stop()
		tick = t.C
	}
	for {
		select {
		case x := <-sig:
			if x == syscall.SIGHUP {
				if err := s.Reload(); err != nil {
					log.Printf("meridian-sniff: reload failed, keeping generation %d: %v", s.Health().Generation, err)
				} else {
					log.Printf("meridian-sniff: reloaded, generation %d", s.Health().Generation)
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
		}
	}
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
