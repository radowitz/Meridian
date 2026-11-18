package sniff

import (
	"bytes"
	"context"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

// Relay results: every connection gets exactly one final record when it
// ends, with how it ended, and the ring, the journal, the counters, the
// per-target statistics and the per-device summary agree on it. Synthetic
// loopback connections and in-process fakes only.

// faults makes chosen upstream addresses fail to connect, or wraps their
// connection, before the harness's own dial (which maps addresses to
// loopback listeners).
type faults struct {
	mu   sync.Mutex
	err  map[string]error
	wrap map[string]func(net.Conn) net.Conn
	h    atomic.Pointer[harness]
}

func (f *faults) setErr(addr string, err error) {
	f.mu.Lock()
	f.err[addr] = err
	f.mu.Unlock()
}

func (f *faults) setWrap(addr string, w func(net.Conn) net.Conn) {
	f.mu.Lock()
	f.wrap[addr] = w
	f.mu.Unlock()
}

func (f *faults) dial(ctx context.Context, network, addr string, mark uint32) (net.Conn, error) {
	f.mu.Lock()
	e, w := f.err[addr], f.wrap[addr]
	f.mu.Unlock()
	if e != nil {
		return nil, e
	}
	c, err := f.h.Load().dial(ctx, network, addr, mark)
	if err != nil || w == nil {
		return c, err
	}
	return w(c), nil
}

// relayHarness is the default harness with a journal, a large ring and the
// faults in front of its dial.
func relayHarness(t *testing.T, cfg Config, names bool) (*harness, *faults, string) {
	t.Helper()
	dir := t.TempDir()
	f := &faults{err: map[string]error{}, wrap: map[string]func(net.Conn) net.Conn{}}
	cfg.RecentSize, cfg.RecordNames = 1000, names
	rules, tail := fixtureRules()
	h := newHarnessWith(t, cfg, rules, tail, fixtureTargets(), func(s *Server) {
		j, err := OpenJournal(JournalConfig{Dir: dir, RecordNames: names, Active: s.relaying})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(j.Close) // after s.Close (cleanups run last first)
		s.Journal = j
		s.Dial = f.dial
	})
	f.h.Store(h)
	return h, f, dir
}

// recordFor waits for the final record of the connection to dest.
func (h *harness) recordFor(dest string) ConnRecord {
	h.t.Helper()
	for i := 0; i < 1000; i++ {
		for _, r := range h.s.Recent() {
			if r.Dest == dest {
				return r
			}
		}
		time.Sleep(5 * time.Millisecond)
	}
	h.t.Fatalf("no record for %s", dest)
	return ConnRecord{}
}

// errConn fails its reads and/or writes with a syscall error.
type errConn struct {
	net.Conn
	readErr, writeErr error
}

func (c errConn) Read(b []byte) (int, error) {
	if c.readErr != nil {
		return 0, c.readErr
	}
	return c.Conn.Read(b)
}

func (c errConn) Write(b []byte) (int, error) {
	if c.writeErr != nil {
		return 0, c.writeErr
	}
	return c.Conn.Write(b)
}

func opErr(op string, e syscall.Errno) error {
	return &net.OpError{Op: op, Net: "tcp", Err: os.NewSyscallError(op, e)}
}

func rst(c net.Conn) {
	if tc, ok := c.(*net.TCPConn); ok {
		_ = tc.SetLinger(0)
	}
	c.Close()
}

var raw = []byte("SSH-2.0-test\r\n") // no name: decided by address

// TestRelayResults covers each way a relayed connection ends and checks
// that every view counts it once with the same result.
func TestRelayResults(t *testing.T) {
	h, f, dir := relayHarness(t, Config{}, false)
	type want struct {
		result, end, reason string
		down                bool // bytes came back
	}
	cases := []struct {
		name     string
		dest     string
		upstream func(net.Conn) // nil: the echo server
		wrap     func(net.Conn) net.Conn
		client   func(t *testing.T, c net.Conn)
		want     want
	}{
		{
			name:     "upstream reset before any response",
			dest:     "192.0.2.150:1001",
			upstream: func(c net.Conn) { b := make([]byte, 64); _, _ = c.Read(b); rst(c) },
			client: func(t *testing.T, c net.Conn) {
				_, _ = c.Write(raw)
				_, _ = io.ReadAll(c)
			},
			want: want{ResultRelayFailed, EndUpstreamReset, "read_reset", false},
		},
		{
			name: "upstream reset after data",
			dest: "192.0.2.150:1002",
			upstream: func(c net.Conn) {
				b := make([]byte, 64)
				_, _ = c.Read(b)
				_, _ = c.Write([]byte("hello\n"))
				time.Sleep(50 * time.Millisecond)
				rst(c)
			},
			client: func(t *testing.T, c net.Conn) {
				_, _ = c.Write(raw)
				_, _ = io.ReadAll(c)
			},
			want: want{ResultOK, EndUpstreamReset, "read_reset", true},
		},
		{
			name: "client reset after data",
			dest: "192.0.2.150:1003",
			client: func(t *testing.T, c net.Conn) {
				h.roundTrip(c, 0, raw)
				rst(c)
			},
			want: want{ResultOK, EndClientReset, "read_reset", true},
		},
		{
			name:     "client reset before any response",
			dest:     "192.0.2.150:1004",
			upstream: func(c net.Conn) { _, _ = io.Copy(io.Discard, c) },
			client: func(t *testing.T, c net.Conn) {
				_, _ = c.Write(raw)
				time.Sleep(50 * time.Millisecond)
				rst(c)
			},
			want: want{ResultNoResponse, EndClientReset, "read_reset", false},
		},
		{
			name: "client normal close",
			dest: "192.0.2.150:1005",
			client: func(t *testing.T, c net.Conn) {
				h.roundTrip(c, 0, raw)
				c.Close()
			},
			want: want{ResultOK, EndClientClosed, "", true},
		},
		{
			name: "upstream normal close",
			dest: "203.0.113.200:1006",
			upstream: func(c net.Conn) {
				b := make([]byte, 64)
				_, _ = c.Read(b)
				_, _ = c.Write([]byte("bye\n"))
			},
			client: func(t *testing.T, c net.Conn) {
				_, _ = c.Write(raw)
				if b, _ := io.ReadAll(c); string(b) != "bye\n" {
					t.Errorf("got %q", b)
				}
				c.Close()
			},
			want: want{ResultOK, EndUpstreamClosed, "", true},
		},
		{
			name:     "upstream closes without answering",
			dest:     "203.0.113.200:1007",
			upstream: func(c net.Conn) { b := make([]byte, 64); _, _ = c.Read(b) },
			client: func(t *testing.T, c net.Conn) {
				_, _ = c.Write(raw)
				_, _ = io.ReadAll(c)
				c.Close()
			},
			want: want{ResultNoResponse, EndUpstreamClosed, "", false},
		},
		{
			name: "client leaves without sending",
			dest: "192.0.2.150:1008",
			client: func(t *testing.T, c net.Conn) {
				time.Sleep(1200 * time.Millisecond) // past the sniff timeout: decided as server-first
				c.Close()
			},
			want: want{ResultClientClosed, EndClientClosed, "", false},
		},
		{
			name: "upstream read error",
			dest: "203.0.113.200:1009",
			wrap: func(c net.Conn) net.Conn { return errConn{Conn: c, readErr: opErr("read", syscall.EHOSTUNREACH)} },
			client: func(t *testing.T, c net.Conn) {
				_, _ = c.Write(raw)
				_, _ = io.ReadAll(c)
			},
			want: want{ResultRelayFailed, EndUpstreamError, "read_no_route", false},
		},
		{
			name: "upstream write error on the first bytes",
			dest: "203.0.113.200:1010",
			wrap: func(c net.Conn) net.Conn { return errConn{Conn: c, writeErr: opErr("write", syscall.EACCES)} },
			client: func(t *testing.T, c net.Conn) {
				_, _ = c.Write(raw)
				_, _ = io.ReadAll(c)
			},
			want: want{ResultRelayFailed, EndUpstreamError, "write_denied", false},
		},
	}
	for _, c := range cases {
		if c.upstream != nil {
			h.setReal(c.dest, h.serve(c.upstream))
		}
		if c.wrap != nil {
			f.setWrap(c.dest, c.wrap)
		}
		conn := h.connect(c.dest)
		c.client(t, conn)
		r := h.recordFor(c.dest)
		if r.Result != c.want.result || r.End != c.want.end || r.Reason != c.want.reason || (r.BytesDown > 0) != c.want.down ||
			r.Upstream == "" || r.DurationMS < r.DecideMS || r.Conn == 0 {
			t.Errorf("%s: record %+v, want %+v", c.name, r, c.want)
		}
		if c.name != "client leaves without sending" && r.BytesUp < int64(len(raw)) && c.wrap == nil {
			t.Errorf("%s: %d bytes up", c.name, r.BytesUp)
		}
	}
	checkAgree(t, h.s, len(cases))
	if st := h.s.Journal.Stats(); st.Records != len(cases) || allLinesParse(t, dir) != len(cases) {
		t.Fatalf("journal holds %d records (%d lines), want one per connection: %d", st.Records, allLinesParse(t, dir), len(cases))
	}
}

// Idle timeout: nothing from the upstream is no_response; after an
// answer it is an ok connection that went quiet.
func TestRelayIdleTimeout(t *testing.T) {
	h, _, _ := relayHarness(t, Config{IdleTimeout: 300 * time.Millisecond}, false)
	silent := h.serve(func(c net.Conn) { _, _ = io.Copy(io.Discard, c) })
	once := h.serve(func(c net.Conn) {
		b := make([]byte, 64)
		_, _ = c.Read(b)
		_, _ = c.Write([]byte("hi\n"))
		_, _ = io.Copy(io.Discard, c)
	})
	h.setReal("203.0.113.200:2001", silent)
	h.setReal("203.0.113.200:2002", once)
	c := h.connect("203.0.113.200:2001")
	_, _ = c.Write(raw)
	r := h.recordFor("203.0.113.200:2001")
	if r.Result != ResultNoResponse || r.End != EndIdleTimeout || r.BytesDown != 0 || r.Target != "exit:jp" {
		t.Fatalf("silent: %+v", r)
	}
	c = h.connect("203.0.113.200:2002")
	_, _ = c.Write(raw)
	r = h.recordFor("203.0.113.200:2002")
	if r.Result != ResultOK || r.End != EndIdleTimeout || r.BytesDown != 3 {
		t.Fatalf("answered, then quiet: %+v", r)
	}
	checkAgree(t, h.s, 2)
	if ts := statOf(h.s, "exit:jp"); ts.RecentRelayFailed != 1 || ts.RecentOK != 1 || !strings.HasPrefix(ts.LastFailure, "no_response idle_timeout") {
		t.Fatalf("target stats %+v", ts)
	}
}

// Dial failures keep the class of the last attempt's error and the
// address it went to.
func TestDialFailureClasses(t *testing.T) {
	h, f, _ := relayHarness(t, Config{}, false)
	cases := []struct {
		err   error
		class string
	}{
		{opErr("connect", syscall.ECONNREFUSED), "refused"},
		{opErr("connect", syscall.ETIMEDOUT), "timeout"},
		{context.DeadlineExceeded, "timeout"},
		{opErr("connect", syscall.ENETUNREACH), "unreachable"},
		{opErr("connect", syscall.EHOSTUNREACH), "no_route"},
		{opErr("connect", syscall.ECONNRESET), "reset"},
		{opErr("connect", syscall.EAFNOSUPPORT), "af_unavailable"},
		{opErr("connect", syscall.EADDRNOTAVAIL), "af_unavailable"},
		{opErr("connect", syscall.EPERM), "denied"},
		{opErr("connect", syscall.EINVAL), "other"},
	}
	for i, c := range cases {
		dest := "203.0.113.200:" + itoa(3000+i)
		f.setErr(dest, c.err)
		conn := h.connect(dest)
		_, _ = conn.Write(raw)
		expectReset(t, conn)
		r := h.recordFor(dest)
		if r.Result != "dial_failed" || r.Reason != c.class || r.Upstream != dest || r.End != "" || r.BytesUp != 0 {
			t.Errorf("%v: %+v", c.err, r)
		}
	}
	checkAgree(t, h.s, len(cases))
	if ts := statOf(h.s, "exit:jp"); ts.RecentDialFailed != uint64(len(cases)) || ts.LastFailure != "dial_failed other" {
		t.Fatalf("target stats %+v", ts)
	}
}

func itoa(n int) string {
	var b [12]byte
	i := len(b)
	for n > 0 || i == len(b) {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}

// Open connections are in the active view, not in any count; stopping the
// forwarder finishes each with shutdown, in every view.
func TestRelayShutdownAndActiveView(t *testing.T) {
	h, _, _ := relayHarness(t, Config{}, false)
	c1, c2 := h.connect("192.0.2.150:4001"), h.connect("203.0.113.200:4002")
	h.roundTrip(c1, 0, raw)
	h.roundTrip(c2, 0, raw)
	h.waitFor(func() bool { _, n := h.s.Active(nil, -1); return n == 2 })
	act, n := h.s.Active(nil, 1)
	if n != 2 || len(act) != 1 || act[0].Result != ActiveResult || act[0].Dest != "203.0.113.200:4002" || act[0].BytesDown != int64(len(raw)) {
		t.Fatalf("active %d %+v", n, act)
	}
	if len(h.s.Recent()) != 0 || h.s.Health().Relaying != 2 {
		t.Fatalf("an open connection was counted: %+v", h.s.Recent())
	}
	// The status socket's views: /v1/recent and the journal's first page
	// and summary carry the open connections.
	page, err := h.s.journalPage(JournalQuery{Device: "127.0.0.1"})
	if err != nil || page.ActiveMatched != 2 || len(page.Active) != 2 || page.Matched != 0 {
		t.Fatalf("page %+v %v", page, err)
	}
	if page, _ := h.s.journalPage(JournalQuery{Result: ClassOK}); len(page.Active) != 0 {
		t.Fatal("open connections listed under a result filter")
	}
	sum, _ := h.s.journalSummary(JournalSummaryQuery{})
	if len(sum.Devices) != 1 || sum.Devices[0].Active != 2 || sum.Devices[0].Total != 0 {
		t.Fatalf("summary %+v", sum)
	}
	h.s.Close()
	for _, d := range []string{"192.0.2.150:4001", "203.0.113.200:4002"} {
		if r := h.recordFor(d); r.Result != ResultShutdown || r.End != EndShutdown || r.BytesDown != int64(len(raw)) {
			t.Fatalf("%s: %+v", d, r)
		}
	}
	if _, n := h.s.Active(nil, -1); n != 0 {
		t.Fatalf("%d still active", n)
	}
	checkAgree(t, h.s, 2)
}

// A hard kill: the journal as the killed forwarder left it (marker still
// there) is opened again. The connection that was open has no record and
// nothing claims it succeeded; the stop is reported with the number of
// connections that were open.
func TestJournalUncleanStop(t *testing.T) {
	h, _, dir := relayHarness(t, Config{}, false)
	done := h.connect("192.0.2.150:5001")
	h.roundTrip(done, 0, raw)
	done.Close()
	h.recordFor("192.0.2.150:5001")
	open := h.connect("192.0.2.150:5002")
	h.roundTrip(open, 0, raw)
	h.waitFor(func() bool { return h.s.relaying() == 1 })
	h.s.Journal.Flush()
	h.s.Journal.writeMarker() // the minute's marker write
	// The disk as a SIGKILL now leaves it.
	killed := t.TempDir()
	ents, _ := os.ReadDir(dir)
	for _, e := range ents {
		b, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(killed, e.Name()), b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	j, err := OpenJournal(JournalConfig{Dir: killed})
	if err != nil {
		t.Fatal(err)
	}
	st := j.Stats()
	if st.UncleanStop == nil || st.UncleanStop.Active != 1 || st.Records != 1 {
		t.Fatalf("stats %+v", st)
	}
	p, _ := j.Query(JournalQuery{})
	if len(p.Records) != 1 || p.Records[0].Dest != "192.0.2.150:5001" {
		t.Fatalf("records %+v", p.Records)
	}
	if p, _ := j.Query(JournalQuery{Result: ClassOK}); p.Matched != 1 {
		t.Fatal("the unfinished connection was counted as a success")
	}
	j.Close() // a clean stop removes the marker
	if _, err := os.Stat(filepath.Join(killed, journalMarker)); !os.IsNotExist(err) {
		t.Fatal("marker left after Close")
	}
	j, _ = OpenJournal(JournalConfig{Dir: killed})
	if j.Stats().UncleanStop != nil {
		t.Fatal("a clean stop reported as unclean")
	}
	j.Close()
	// Clear forgets the report.
	if err := os.WriteFile(filepath.Join(killed, journalMarker), []byte(`{"at":"2026-11-14T08:00:00Z","active":3}`), 0o600); err != nil {
		t.Fatal(err)
	}
	j, _ = OpenJournal(JournalConfig{Dir: killed})
	defer j.Close()
	if u := j.Stats().UncleanStop; u == nil || u.Active != 3 || !u.LastAlive.Equal(jT0) {
		t.Fatalf("report %+v", u)
	}
	j.Clear()
	if j.Stats().UncleanStop != nil {
		t.Fatal("report kept after clear")
	}
}

// Records of an older forwarder that wrote "ok" when the upstream
// connected are "ended unknown", never a success or a failure.
func TestLegacyOKIsEndedUnknown(t *testing.T) {
	clk := &fakeClock{t: jT0}
	j := openJ(t, t.TempDir(), clk, nil)
	j.Add(ConnRecord{Start: clk.Now(), Source: "192.0.2.10", Result: "ok", Target: "direct"})
	j.Add(ConnRecord{Start: clk.Now(), Source: "192.0.2.10", Result: "upstream_write_failed", Target: "direct"})
	j.Flush()
	sum, _ := j.Summary(JournalSummaryQuery{})
	d := sum.Devices[0]
	if d.ByClass[ClassEndedUnknown] != 1 || d.ByClass[ClassOK] != 0 || d.ByClass[ClassRelayFailed] != 1 || d.Failed != 1 {
		t.Fatalf("%+v", d)
	}
	if p, _ := j.Query(JournalQuery{Result: ClassFailed}); p.Matched != 1 {
		t.Fatalf("failed %d", p.Matched)
	}
}

// With names off, no view carries the sniffed name: ring, journal file,
// active view, /v1/recent.
func TestRelayNamesOff(t *testing.T) {
	h, _, dir := relayHarness(t, Config{}, false)
	c := h.connect("203.0.113.5:443")
	h.roundTrip(c, 0, clientHello("a.video.example.net"))
	act, _ := h.s.Active(nil, -1)
	if len(act) != 1 || act[0].Name != "" || !act[0].Sniffed {
		t.Fatalf("active %+v", act)
	}
	c.Close()
	r := h.recordFor("203.0.113.5:443")
	if r.Name != "" || r.Result != ResultOK {
		t.Fatalf("%+v", r)
	}
	h.s.Journal.Flush()
	assertNoBytes(t, dir, "video.example")
	// With names on, the active view and the records carry it.
	h2, _, _ := relayHarness(t, Config{}, true)
	c = h2.connect("203.0.113.5:443")
	h2.roundTrip(c, 0, clientHello("a.video.example.net"))
	if act, _ := h2.s.Active(nil, -1); len(act) != 1 || act[0].Name != "a.video.example.net" {
		t.Fatalf("active %+v", act)
	}
}

// A connection counts once against the journal's record bound however
// long it lived: ten connections, ten records, and a record bound of 8
// keeps the newest.
func TestRelayCountedOnceInBounds(t *testing.T) {
	dir := t.TempDir()
	f := &faults{err: map[string]error{}, wrap: map[string]func(net.Conn) net.Conn{}}
	rules, tail := fixtureRules()
	h := newHarnessWith(t, Config{RecentSize: 100}, rules, tail, fixtureTargets(), func(s *Server) {
		j, err := OpenJournal(JournalConfig{Dir: dir, MaxRecords: 8})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(j.Close)
		s.Journal = j
		s.Dial = f.dial
	})
	f.h.Store(h)
	for i := 0; i < 10; i++ {
		c := h.connect("192.0.2.150:" + itoa(6000+i))
		h.roundTrip(c, 0, raw)
		h.roundTrip(c, 0, bytes.Repeat([]byte("x"), 100))
		c.Close()
		h.recordFor("192.0.2.150:" + itoa(6000+i))
	}
	h.s.Journal.Flush()
	p, _ := h.s.Journal.Query(JournalQuery{Limit: 200})
	if p.Matched > 8 || p.Matched < 7 || allLinesParse(t, dir) > 8 {
		t.Fatalf("%d records", p.Matched)
	}
	seen := map[uint64]bool{}
	for _, r := range p.Records {
		if seen[r.Conn] {
			t.Fatalf("connection %d twice", r.Conn)
		}
		seen[r.Conn] = true
		if r.BytesUp != int64(len(raw)+100) {
			t.Fatalf("%+v", r)
		}
	}
}

func statOf(s *Server, name string) TargetStat {
	for _, x := range s.Health().TargetStats {
		if x.Target == name {
			return x
		}
	}
	return TargetStat{}
}

// checkAgree: the ring, the journal, the counters, the per-target
// statistics and the per-device summary describe the same n connections
// with the same results.
func checkAgree(t *testing.T, s *Server, n int) {
	t.Helper()
	s.Journal.Flush()
	ring := s.Recent()
	page, err := s.Journal.Query(JournalQuery{Limit: JournalPageMax})
	if err != nil || len(ring) != n || page.Matched != n {
		t.Fatalf("ring %d, journal %d (%v), want %d", len(ring), page.Matched, err, n)
	}
	byConn := map[uint64]ConnRecord{}
	results, ends := map[string]uint64{}, map[string]uint64{}
	classes, failed := map[string]int{}, 0
	type tcount struct{ ok, dial, relay, resolve uint64 }
	tc := map[string]*tcount{}
	for _, r := range ring {
		if _, dup := byConn[r.Conn]; dup {
			t.Fatalf("connection %d twice in the ring", r.Conn)
		}
		byConn[r.Conn] = r
		results[r.Result]++
		if r.End != "" {
			ends[r.End]++
		}
		cl := RecordClass(&r)
		classes[cl]++
		if IsFailureClass(cl) {
			failed++
		}
		x := tc[r.Target]
		if x == nil {
			x = &tcount{}
			tc[r.Target] = x
		}
		switch r.Result {
		case ResultOK:
			x.ok++
		case "dial_failed":
			x.dial++
		case ResultRelayFailed, ResultNoResponse:
			x.relay++
		case "resolve_failed":
			x.resolve++
		}
	}
	for _, jr := range page.Records {
		r, ok := byConn[jr.Conn]
		if !ok || r.Result != jr.Result || r.End != jr.End || r.Reason != jr.Reason || r.BytesUp != jr.BytesUp || r.BytesDown != jr.BytesDown ||
			r.Target != jr.Target || r.Upstream != jr.Upstream || r.DurationMS != jr.DurationMS {
			t.Fatalf("journal %+v, ring %+v", jr.ConnRecord, r)
		}
	}
	cs := s.Health().Counters
	for k, v := range results {
		if cs["result_"+k] != v {
			t.Fatalf("counter result_%s = %d, ring %d", k, cs["result_"+k], v)
		}
	}
	for k, v := range ends {
		if cs["end_"+k] != v {
			t.Fatalf("counter end_%s = %d, ring %d", k, cs["end_"+k], v)
		}
	}
	for name, x := range tc {
		ts := statOf(s, name)
		if ts.RecentOK != x.ok || ts.RecentDialFailed != x.dial || ts.RecentRelayFailed != x.relay || ts.RecentResolveFailed != x.resolve ||
			ts.OK != x.ok || ts.DialFailed != x.dial || ts.RelayFailed != x.relay {
			t.Fatalf("target %s: stats %+v, ring %+v", name, ts, *x)
		}
	}
	sum, _ := s.Journal.Summary(JournalSummaryQuery{})
	gotClasses, gotFailed, total := map[string]int{}, 0, 0
	for _, d := range sum.Devices {
		for k, v := range d.ByClass {
			gotClasses[k] += v
		}
		gotFailed += d.Failed
		total += d.Total
	}
	if total != n || gotFailed != failed || len(gotClasses) != len(classes) {
		t.Fatalf("summary total %d failed %d classes %v; ring failed %d classes %v", total, gotFailed, gotClasses, failed, classes)
	}
	for k, v := range classes {
		if gotClasses[k] != v {
			t.Fatalf("summary class %s = %d, ring %d", k, gotClasses[k], v)
		}
	}
	if fp, _ := s.Journal.Query(JournalQuery{Result: ClassFailed, Limit: JournalPageMax}); fp.Matched != failed {
		t.Fatalf("failed filter %d, ring %d", fp.Matched, failed)
	}
}
