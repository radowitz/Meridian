package api

// Fixtures of the panel's demo preview (web/src/demo; web/README.md
// 「演示预览」, docs/ui-layout.md "Demo preview"), generated from the real
// handlers.
//
// buildDemo builds a synthetic gateway of real size (14 nodes with two
// relays, a primary and a backup hub, a nested exit and an external SOCKS
// exit; 7 region groups; 160+ ordered rules; 50+ rule-sets; a dozen-plus
// service groups; unlock results of the whole catalogue on 9 exits …) on
// the test seams only: an in-process host agent that answers healthy
// (demoHost), the fake host preflight, the fake rule-set downloader, the
// fake prober, fake upstream / sniff / remote-access / lists runtimes, the
// in-memory Cloudflare and Mesh remote, and for the deployment guide the
// SSH stand-ins of the deployment tests (sshtest servers on the loopback
// interface, reached only through the SSHDial seam). Nothing leaves the
// process's machine and no remote host is contacted. Names are "example"
// names, addresses are documentation ranges (RFC 5737, RFC 3849) or
// private LAN ranges.
//
// The three logs (demo_logs: demoDNS, demoLink, demoJournal) are the real
// services on synthetic input, each in a temporary directory: the query
// journal's reader follows a synthetic resolver audit file (the parser,
// the zone estimate, the MAC lookup and the bounded journal are the real
// ones), the link journal's collector reads synthetic sources (the
// failover record in its grammar, "wg" and "systemctl" answers, the
// forwarder's self-check) on a clock the fixture advances, and the
// connection journal holds synthetic connection records. The scenarios
// show them normal (healthy), with observation gaps (degraded: a
// collection gap, changes found after it, a flapping tunnel, a source that
// cannot be read, a reader that was down, records without a zone or a MAC,
// a forwarder that was killed), unavailable (no host agent), switched off
// or not installed (logs-off) and installed without any data yet
// (logs-empty).
//
// It then calls every GET endpoint the panel uses (and the read-only POSTs
// it calls to show state) and stores the JSON bodies per scenario
// (demoScenarioBase): healthy and unavailable are full sets; degraded, the
// deployment guide states (run in progress, rate-limit wait, failed and
// compensated, unknown outcome, finished with installed and adopted
// steps), the preflight with blocking findings and the refused save hold
// only the responses that differ from healthy. Every state is reached
// through the handlers on the seams; where a seam stands for a host the
// panel would read (the hubs' group reports, remote nodes recorded as
// installed, servers' connection tests, the gateway's upstream record,
// the forwarder's status, WireGuard peers, the lists status) the stored or
// returned state is built with the same functions and parsers the real
// path uses (saveGroupHub with hubstate.Parse, saveOutcome,
// RecordConnectionTest, hostexec.ParseUpstream, sniff.Health …). Nothing
// is hand-written into the fixture files.
//
// The run is made deterministic afterwards (normalizeRun, tokenMap):
// times become offsets from a fixed anchor (the demo shifts them back to
// "now" in the browser), every random token (IDs, keys, fingerprints,
// digests) is replaced by a stable value of the same shape — found by
// building everything twice and comparing — certificate bodies (random
// length) become one placeholder line, and the unlock history, whose order
// within one ingest follows map iteration, is sorted.
//
// Regenerate (one command, from the repository root; also
// `npm --prefix web run demo:fixtures`):
//
//	MERIDIAN_DEMO_FIXTURES=write go test ./internal/api -run 'TestDemoFixtures$' -count=1
//
// Without the variable the test builds the fixtures once in memory and
// checks that the committed files still have the shape (fields and kinds)
// the handlers produce now.

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/radowitz/meridian/internal/compile"
	"github.com/radowitz/meridian/internal/credentials"
	"github.com/radowitz/meridian/internal/dnsjournal"
	"github.com/radowitz/meridian/internal/hostexec"
	"github.com/radowitz/meridian/internal/hubstate"
	"github.com/radowitz/meridian/internal/linkjournal"
	"github.com/radowitz/meridian/internal/lists"
	"github.com/radowitz/meridian/internal/mesh"
	"github.com/radowitz/meridian/internal/model"
	"github.com/radowitz/meridian/internal/ordered"
	"github.com/radowitz/meridian/internal/probe"
	"github.com/radowitz/meridian/internal/provision"
	"github.com/radowitz/meridian/internal/sniff"
	"github.com/radowitz/meridian/internal/sshexec/sshtest"
)

// demoFixtureDir is web/src/demo/generated, relative to this package.
const demoFixtureDir = "../../web/src/demo/generated"

// demoAnchor is the "now" of every generated fixture.
var demoAnchor = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

// ------------------------------------------------------------ runtimes ---

// demoHost is the host agent of a healthy gateway: every action succeeds;
// an activation of the
// forwarder reports its self-check of the target file on the host: every
// target reached.
type demoHost struct{ root string }

func (d demoHost) Do(_ context.Context, req hostexec.Request) (hostexec.Result, error) {
	res := hostexec.Result{RequestID: req.RequestID, Action: req.Action, OK: true}
	if req.Action == hostexec.ActionActivate && slices.Contains(req.Resources.Units, hostexec.SniffUnit) {
		b, err := os.ReadFile(filepath.Join(d.root, compile.SniffTargetsPath))
		if err != nil {
			return res, err
		}
		snap, err := os.ReadFile(filepath.Join(d.root, compile.DecidePath))
		if err != nil {
			return res, err
		}
		now := time.Now().UTC()
		sc := demoSelfCheck(string(b), string(snap), now, "")
		res.SniffCheck = &hostexec.SniffCheckReport{RequestedAt: now.Add(-5 * time.Second), ReadAt: now, TargetsSHA256: sc.TargetsSHA256, Result: sc}
	}
	return res, nil
}

// demoSelfCheck is a self-check of the target file body: every target with
// a resolver reached in a fixed time; failing names a non-default target
// that timed out instead.
func demoSelfCheck(body, snapshot string, at time.Time, failing string) *sniff.SelfCheck {
	var tf sniff.TargetsFile
	var snap struct {
		Tail ordered.SnapshotTail `json:"tail"`
	}
	if json.Unmarshal([]byte(body), &tf) != nil || json.Unmarshal([]byte(snapshot), &snap) != nil {
		return nil
	}
	sum := sha256.Sum256([]byte(body))
	at = at.Truncate(time.Second) // whole seconds: the ages derived from it are the same in every build
	c := &sniff.SelfCheck{Version: sniff.SelfCheckVersion, Trigger: sniff.TriggerReload, StartedAt: at.Add(-3 * time.Second), FinishedAt: at.Add(-3*time.Second + 412*time.Millisecond),
		DurationMS: 412, Generation: 42, TargetsSHA256: hex.EncodeToString(sum[:]), QName: sniff.SelfCheckQName, QType: sniff.SelfCheckQType, OK: true}
	def := ""
	for _, t := range tf.Targets {
		if t.Mark == snap.Tail.DefaultMark && !t.Reject {
			def = t.Name
		}
	}
	c.Default = def
	for i, t := range tf.Targets {
		if t.Reject {
			continue
		}
		dm := t.Mark
		if t.DNSMark != nil {
			dm = *t.DNSMark
		}
		e := sniff.SelfCheckTarget{Target: t.Name, Mark: t.Mark, DNSMark: dm, Default: t.Name == def, Status: sniff.TargetOK}
		if len(t.Resolvers) == 0 {
			e.Status, e.Reason = sniff.TargetUnchecked, "这个目标没有解析器：按名字判断到它的连接会失败，自检无从检查"
		}
		for j, r := range t.Resolvers {
			if j >= sniff.SelfCheckMaxResolvers {
				break
			}
			p := sniff.SelfCheckProbe{Server: r, Outcome: sniff.OutcomeAnswer, Reached: true, DurationMS: int64(18 + (i*7+j*3)%40), Transport: "udp", TimeoutMS: 2000}
			switch {
			case t.Name == failing:
				p = sniff.SelfCheckProbe{Server: r, Outcome: sniff.OutcomeTimeout, DurationMS: 2000, Error: "i/o timeout", Transport: "udp", TimeoutMS: 2000}
			case t.Name == "direct" && j == 1:
				// The second domestic resolver does not answer on plain 53:
				// known silent, re-checked with the short timeout.
				p = sniff.SelfCheckProbe{Server: r, Outcome: sniff.OutcomeTimeout, DurationMS: 500, Error: "i/o timeout", Transport: "udp",
					TimeoutMS: sniff.SelfCheckRecheckTimeout.Milliseconds(), KnownSilent: true}
			}
			e.Resolvers = append(e.Resolvers, p)
			h := sniff.ResolverHealth{Server: r, Mark: dm, Transport: "udp", LastOutcome: p.Outcome, LastAt: at.Add(-3 * time.Second), LastLatencyMS: p.DurationMS, Source: "selfcheck"}
			if p.Reached {
				h.Answered, h.LastAnswerAt = 120, h.LastAt
			} else {
				h.Failed, h.ConsecutiveFailures, h.DemotedUntil = 9, 9, at.Add(57*time.Second)
			}
			c.ResolverHealth = append(c.ResolverHealth, h)
		}
		if t.Name == failing {
			e.Status, e.Reason = sniff.TargetFailed, "解析器 "+t.Resolvers[0]+" "+sniff.OutcomeText(sniff.OutcomeTimeout)
		}
		if e.Default && len(t.Resolvers) > 0 {
			e.Connect = &sniff.SelfCheckProbe{Server: t.Resolvers[0], Outcome: sniff.OutcomeConnected, Reached: true, DurationMS: 31}
		}
		c.Targets = append(c.Targets, e)
	}
	// The default first, then by name, as the forwarder orders them.
	sort.SliceStable(c.Targets, func(i, j int) bool {
		if c.Targets[i].Default != c.Targets[j].Default {
			return c.Targets[i].Default
		}
		return c.Targets[i].Target < c.Targets[j].Target
	})
	return c
}

// demoSniff is the forwarder's status read and its connection journal: a
// real sniff.Journal in a temporary directory holding the synthetic
// records of demoJournal, answered the way the host agent passes the
// forwarder's answers on.
type demoSniff struct {
	st hostexec.SniffStatus
	j  *sniff.Journal
	// active: synthetic connections still being relayed (the forwarder
	// adds the matching ones to a journal's first page and the summary).
	active []sniff.ConnRecord
}

func (d *demoSniff) SniffStatus(context.Context) (hostexec.SniffStatus, error) { return d.st, nil }

func (d *demoSniff) journalAnswer(v any, err error) (hostexec.SniffJournalAnswer, error) {
	switch {
	case d.j == nil:
		return hostexec.SniffJournalAnswer{Code: "no_socket", Error: "嗅探服务没有运行（没有状态套接字）"}, nil
	case err != nil:
		return hostexec.SniffJournalAnswer{Present: true, Code: "bad_request", Error: err.Error()}, nil
	}
	b, _ := json.Marshal(v)
	return hostexec.SniffJournalAnswer{Present: true, Body: b}, nil
}

func (d *demoSniff) SniffJournal(_ context.Context, q sniff.JournalQuery) (hostexec.SniffJournalAnswer, error) {
	if d.j == nil {
		return d.journalAnswer(nil, nil)
	}
	page, err := d.j.Query(q)
	if err == nil && q.Before == 0 && q.Result == "" {
		for _, r := range d.active {
			if q.Device == "" || q.Device == r.Source {
				page.Active = append(page.Active, r)
			}
		}
		page.ActiveMatched = len(page.Active)
	}
	return d.journalAnswer(page, err)
}

func (d *demoSniff) SniffJournalSummary(_ context.Context, q sniff.JournalSummaryQuery) (hostexec.SniffJournalAnswer, error) {
	if d.j == nil {
		return d.journalAnswer(nil, nil)
	}
	sum, err := d.j.Summary(q)
	for i := range sum.Devices {
		for _, r := range d.active {
			if r.Source == sum.Devices[i].Device {
				sum.Devices[i].Active++
			}
		}
	}
	return d.journalAnswer(sum, err)
}

func (d *demoSniff) SniffJournalClear(context.Context) (hostexec.SniffJournalAnswer, error) {
	return hostexec.SniffJournalAnswer{Code: "read_failed", Error: "演示数据不清空"}, nil
}

// demoJournal fills a synthetic connection journal: four invented devices
// of the demo LAN (192.168.77.0/24, 2001:db8:77::/64), documentation MACs
// (00:00:5e:00:53:xx, RFC 7042), destinations in documentation ranges,
// example names; every way a connection is decided and ends. Each record
// is a connection's final one (it ended Duration after Start).
func demoJournal(t *testing.T, now time.Time, targets []string) *sniff.Journal {
	t.Helper()
	now = now.Truncate(time.Minute)
	j, err := sniff.OpenJournal(sniff.JournalConfig{Dir: t.TempDir(), RecordNames: true, Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(j.Close)
	var fwd []string
	for _, x := range targets {
		if x != "reject" {
			fwd = append(fwd, x)
		}
	}
	for i := 0; i < demoConns; i++ {
		j.Add(demoConn(now, i, fwd))
	}
	j.Flush()
	return j
}

// The demo LAN's devices (192.168.77.0/24, 2001:db8:77::/64; MACs of the
// documentation range 00:00:5e:00:53:xx, RFC 7042 — the IPv6 device has no
// neighbour entry) and the names they ask for and connect to.
type demoDevice struct{ addr, mac string }

var (
	demoDevices = []demoDevice{{"192.168.77.20", "00:00:5e:00:53:20"}, {"192.168.77.21", "00:00:5e:00:53:21"}, {"192.168.77.35", "00:00:5e:00:53:35"}, {"2001:db8:77::50", ""}}
	demoNames   = []string{"www.example.com", "api.example.net", "media.example.org", "cdn-07.example.com", "updates.example.net", "chat.example.org"}
)

// demoConns is the number of synthetic connections: one every nine minutes
// back from now, the devices in turn.
const demoConns = 160

// demoConnKind is how connection i is decided and ends (the cases of demoConn).
func demoConnKind(i int) int { return (i/4 + 3*(i%4)) % 16 }

// demoConnStart is when connection i began.
func demoConnStart(now time.Time, i int) time.Time {
	return now.Add(-time.Duration(i*9)*time.Minute - time.Duration(1+i%7)*1700*time.Millisecond)
}

// demoConn is synthetic connection i (its final record), to one of the
// forwarding targets fwd.
func demoConn(now time.Time, i int, fwd []string) sniff.ConnRecord {
	tg := func(i int) string { return fwd[i%len(fwd)] }
	devs, names := demoDevices, demoNames
	d := devs[i%len(devs)]
	dest := fmt.Sprintf("198.51.100.%d:443", 10+i%40)
	if strings.Contains(d.addr, ":") {
		dest = fmt.Sprintf("[2001:db8:5::%x]:443", 16+i%40)
	}
	dur := time.Duration(1+i%7) * 1700 * time.Millisecond
	r := sniff.ConnRecord{Start: demoConnStart(now, i), Source: d.addr, MAC: d.mac, Dest: dest, Proto: "tls",
		Name: names[i%len(names)], Sniffed: true, By: "name", RuleIndex: 3 + i%5, RuleID: fmt.Sprintf("m%02d", 1+i%5), Target: tg(i),
		Upstream: dest, Result: sniff.ResultOK, DecideMS: int64(2 + i%9), Generation: 42, Conn: uint64(5000 - i),
		End:        []string{sniff.EndClientClosed, sniff.EndUpstreamClosed, sniff.EndClientReset, sniff.EndIdleTimeout}[i%4],
		DurationMS: dur.Milliseconds(), BytesUp: int64(517 + i*31), BytesDown: int64(4096 + i*997)}
	if r.End == sniff.EndClientReset {
		r.Reason = "read_reset"
	}
	switch demoConnKind(i) {
	case 1:
		r.Result, r.End, r.Reason, r.BytesDown = sniff.ResultRelayFailed, sniff.EndUpstreamReset, "read_reset", 0
	case 2:
		r.Result, r.End, r.Reason, r.BytesDown = sniff.ResultNoResponse, sniff.EndClientClosed, "", 0
	case 6:
		r.Result, r.End, r.Reason = sniff.ResultShutdown, sniff.EndShutdown, ""
	case 3:
		r.Name, r.Sniffed, r.By, r.Why, r.ECH, r.RuleID, r.RuleIndex = "", false, "addr", sniff.WhyECH, true, "", -1
	case 5:
		r.Proto, r.Name, r.Sniffed, r.By, r.Why, r.RuleID, r.RuleIndex = "", "", false, "addr", "no_data", "", -1
	case 7:
		r.Result, r.Error, r.Reason, r.End, r.BytesUp, r.BytesDown = "dial_failed", "", "timeout", "", 0, 0
	case 9:
		r.Why, r.Sniffed, r.By, r.Error, r.RuleID, r.RuleIndex = sniff.WhyUnresolved, false, "addr", "nxdomain", "", -1
		r.Name = "internal-only.example.net"
		r.NameRule = &sniff.NameRule{Index: 2, ID: "m02", Target: "direct", By: "name", Error: "nxdomain"}
		r.MarkStatus, r.RawMark = sniff.MarkOK, "0x1000105"
	case 11:
		r.Name, r.Sniffed, r.By, r.Why, r.RuleID, r.RuleIndex, r.Proto = "", false, "addr", "other", "", -1, ""
		r.Result, r.Error, r.MarkStatus, r.RawMark, r.View, r.Target = "mark_missing", sniff.ErrClassificationUnconfirmed, sniff.MarkWithoutBit, "0x0", sniff.ViewOwnAddress, "direct"
		r.End, r.Reason, r.BytesUp, r.BytesDown, r.Upstream = "", "", 0, 0, ""
	case 13:
		r.Result, r.Target, r.Upstream = "rejected", "reject", ""
		r.Name = "ads.example.com"
		r.End, r.Reason, r.BytesUp, r.BytesDown = "", "", 0, 0
	case 15:
		r.Result, r.Target, r.Upstream, r.Name, r.Proto, r.Sniffed, r.By, r.Why = "client_closed", "", "", "", "", false, "", "eof"
		r.End, r.Reason, r.BytesUp, r.BytesDown = "", "", 0, 0
	}
	return r
}

// ------------------------------------------------------ the three logs ---

// demoClock is the clock of a synthetic service: the fixture sets it.
type demoClock struct{ ns atomic.Int64 }

func (c *demoClock) set(t time.Time) { c.ns.Store(t.UnixNano()) }
func (c *demoClock) now() time.Time  { return time.Unix(0, c.ns.Load()).UTC() }

// demoJournalKilled is the connection journal of a forwarder that was
// killed 34 minutes ago while three connections were open: the directory a
// process that never closed its journal leaves (its marker included) is
// opened again, as the restarted forwarder does, and the connections that
// ended since then are added. The journal reports the unclean stop.
func demoJournalKilled(t *testing.T, now time.Time, targets []string) *sniff.Journal {
	t.Helper()
	now = now.Truncate(time.Minute)
	killedAt := now.Add(-34 * time.Minute)
	var fwd []string
	for _, x := range targets {
		if x != "reject" {
			fwd = append(fwd, x)
		}
	}
	src := t.TempDir()
	first, err := sniff.OpenJournal(sniff.JournalConfig{Dir: src, RecordNames: true, Now: func() time.Time { return killedAt }, Active: func() int { return 3 }})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(first.Close)
	var later []sniff.ConnRecord
	for i := demoConns - 1; i >= 0; i-- {
		if rec := demoConn(now, i, fwd); rec.EndTime().After(killedAt) {
			later = append(later, rec)
		} else {
			first.Add(rec)
		}
	}
	first.Flush()
	// The disk as the kill leaves it: every file, the marker too.
	dir := t.TempDir()
	ents, err := os.ReadDir(src)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range ents {
		b, err := os.ReadFile(filepath.Join(src, e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, e.Name()), b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	j, err := sniff.OpenJournal(sniff.JournalConfig{Dir: dir, RecordNames: true, Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(j.Close)
	if j.Stats().UncleanStop == nil || len(later) == 0 {
		t.Fatalf("the reopened journal reports no unclean stop (%d connections after it)", len(later))
	}
	for _, rec := range later {
		j.Add(rec)
	}
	j.Flush()
	return j
}

// demoResolverZone is the time zone of the resolver's container: its audit
// timestamps are local time without a zone, which the reader works out from
// the audit file's modification time.
const demoResolverZone = 8 * time.Hour

// demoResolverVersion is what the healthy gateway's resolver reports (a
// version in dnsjournal.VerifiedVersions); demoResolverUnverified an
// invented later one nobody verified.
const (
	demoResolverVersion    = "1.2026.11.09-1240"
	demoResolverUnverified = "1.2026.12.20-0815"
)

// demoResolverStatus is the host agent's status answer for a gateway whose
// resolver container reports version and has the writable audit mount,
// without a reader (the query journal is not installed).
func demoResolverStatus(version string) hostexec.DNSJournalStatus {
	img := sha256.Sum256([]byte("meridian demo resolver image " + version))
	f := dnsjournal.Facts{Provider: "container", Running: true, Version: version, ImageID: "sha256:" + hex.EncodeToString(img[:]), MountFound: true, MountRW: true}
	return hostexec.DNSJournalStatus{ReadAt: time.Now().UTC().Format(time.RFC3339), Facts: f, Capability: dnsjournal.Evaluate(f)}
}

// demoDNS is the query journal of the synthetic gateway: the real reader
// (dnsjournal.Daemon: the tailer with its parser, zone estimate and MAC
// lookup, and the bounded journal) following a synthetic audit file in a
// temporary directory, on a clock the fixture sets. resolve appends audit
// lines the way the resolver does; read is one poll of the reader.
type demoDNS struct {
	t        *testing.T
	raw, dir string
	clock    demoClock
	d        *dnsjournal.Daemon
	// neigh is the gateway's neighbour table: address → MAC.
	neigh map[string]string
}

func newDemoDNS(t *testing.T, at time.Time) *demoDNS {
	t.Helper()
	root := t.TempDir()
	g := &demoDNS{t: t, raw: filepath.Join(root, "raw"), dir: filepath.Join(root, "journal"), neigh: map[string]string{}}
	for _, d := range demoDevices {
		if d.mac != "" {
			g.neigh[d.addr] = d.mac
		}
	}
	if err := dnsjournal.PrepareSink(g.raw); err != nil {
		t.Fatal(err)
	}
	g.start(at)
	t.Cleanup(g.stop)
	return g
}

// start starts the reader at at (a restart finds the saved position).
func (g *demoDNS) start(at time.Time) {
	g.clock.set(at)
	d, err := dnsjournal.NewDaemon(dnsjournal.DaemonConfig{RawDir: g.raw, JournalDir: g.dir, MaxRecords: dnsjournal.DefaultMaxRecords, MaxAge: dnsjournal.DefaultMaxAge, MaxBytes: dnsjournal.DefaultMaxBytes},
		func(a netip.Addr) string { return g.neigh[a.String()] }, g.clock.now)
	if err != nil {
		g.t.Fatal(err)
	}
	g.d = d
}

func (g *demoDNS) stop() {
	if g.d != nil {
		g.d.Close()
		g.d = nil
	}
}

// resolve appends lines to the audit file, last written at at.
func (g *demoDNS) resolve(at time.Time, lines ...string) {
	p := filepath.Join(g.raw, dnsjournal.AuditBase)
	f, err := os.OpenFile(p, os.O_WRONLY|os.O_APPEND, 0)
	if err != nil {
		g.t.Fatal(err)
	}
	for _, l := range lines {
		if _, err := f.WriteString(l + "\n"); err != nil {
			g.t.Fatal(err)
		}
	}
	if err := f.Close(); err != nil {
		g.t.Fatal(err)
	}
	if err := os.Chtimes(p, at, at); err != nil {
		g.t.Fatal(err)
	}
}

// read is one poll of the reader at at.
func (g *demoDNS) read(at time.Time) {
	g.clock.set(at)
	g.d.Tail.Step()
	g.d.Journal.Flush()
}

// demoAuditLine is one audit line as the observed resolver writes it
// (docs/architecture.md「网关解析日志」): local time with milliseconds and no
// zone, the client, the name, the numeric type, the time it took, the group
// and the answers ("" for none).
func demoAuditLine(at time.Time, client, name string, qtype int, ms int64, group string, answers ...string) string {
	local := at.UTC().Add(demoResolverZone)
	return fmt.Sprintf("[%s,%03d] %s query %s, type %d, time %dms, speed: -0.1ms, group %s, result %s",
		local.Format("2006-01-02 15:04:05"), local.Nanosecond()/int(time.Millisecond), client, name, qtype, ms, group, strings.Join(answers, ", "))
}

// status is the host agent's status answer for this reader next to a
// resolver that reports version.
func (g *demoDNS) status(version string) hostexec.DNSJournalStatus {
	st := demoResolverStatus(version)
	st.AuditInstalled, st.UnitActive, st.Present = true, "active", true
	st.Health, _ = json.Marshal(g.d.Health())
	st.Sink = dnsjournal.CheckSink(g.raw, uint32(os.Getuid()))
	if !st.Sink.OK {
		g.t.Fatalf("the synthetic audit sink is not what the agent accepts: %+v", st.Sink)
	}
	// The reader's saved position names the temporary file's inode (a
	// number of varying length): it is left out of the byte count.
	_ = os.Remove(filepath.Join(g.dir, "position.json"))
	st.DataFiles, st.DataBytes = dnsjournal.DataUsage(g.raw, g.dir)
	return st
}

// demoGroups are the resolver groups the synthetic queries are answered
// by, as the gateway's compiled SmartDNS config names them.
type demoGroups struct{ domestic, def, region, region2, exit string }

func demoGroupsOf(t *testing.T, topo model.Topology) demoGroups {
	t.Helper()
	gs, err := compile.DNSLogGroups(topo)
	if err != nil {
		t.Fatal(err)
	}
	var g demoGroups
	for _, x := range gs {
		switch {
		case x.Kind == "domestic":
			g.domestic = x.Group
		case x.Group == "default":
			g.def = x.Group
		case x.Kind == "region_group" && x.ID == "jp":
			g.region = x.Group
		case x.Kind == "region_group" && x.ID == "us":
			g.region2 = x.Group
		case x.Kind == "exit" && x.ID == "us1":
			g.exit = x.Group
		}
	}
	if g.domestic == "" || g.def == "" || g.region == "" || g.region2 == "" || g.exit == "" {
		t.Fatalf("resolver groups of the demo topology: %+v", g)
	}
	return g
}

// of is the group that answers synthetic name n.
func (g demoGroups) of(n int) string {
	return []string{g.def, g.region, g.region2, g.def, g.domestic, g.exit}[n%len(demoNames)]
}

// demoQueries fills the query journal of the healthy gateway from the
// synthetic connections: two seconds before each one its device asks for
// the name it then connects to (so a query and its connection find each
// other), sometimes for the other address family too (an empty answer
// within a millisecond: the name has no record of that type), sometimes
// for an HTTPS record; a few queries through an exit's resolver wait two
// seconds and come back empty (the upstream did not answer). The reader
// polls one second after each batch, so the device's MAC is still fresh.
func demoQueries(t *testing.T, now time.Time, gr demoGroups) *demoDNS {
	t.Helper()
	now = now.Truncate(time.Minute)
	g := newDemoDNS(t, demoConnStart(now, demoConns-1).Add(-time.Minute))
	for i := demoConns - 1; i >= 0; i-- {
		d := demoDevices[i%len(demoDevices)]
		at := demoConnStart(now, i).Add(-2 * time.Second)
		v6 := strings.Contains(d.addr, ":")
		name, group := demoNames[i%len(demoNames)], gr.of(i)
		a4, a6 := fmt.Sprintf("198.51.100.%d", 10+i%40), fmt.Sprintf("2001:db8:5::%x", 16+i%40)
		qtype, answers := 1, []string{a4}
		if v6 {
			qtype, answers = 28, []string{a6}
		}
		if i%3 == 0 && !v6 {
			answers = append(answers, fmt.Sprintf("198.51.100.%d", 60+i%40))
		}
		ms := int64((i * 7) % 38)
		switch demoConnKind(i) {
		case 9:
			// The name the connection journal shows as "could not be
			// resolved": no such name, an empty answer in a few milliseconds.
			name, group, answers, ms = "internal-only.example.net", gr.domestic, nil, 3
		case 13:
			name = "ads.example.com"
		}
		lines := []string{demoAuditLine(at, d.addr, name, qtype, ms, group, answers...)}
		if i%8 == 3 {
			other := 28
			if v6 {
				other = 1
			}
			lines = append(lines, demoAuditLine(at.Add(7*time.Millisecond), d.addr, name, other, 1, group))
		}
		if i%16 == 5 {
			lines = append(lines, demoAuditLine(at.Add(11*time.Millisecond), d.addr, name, 65, 2, group))
		}
		if i%40 == 11 {
			lines = append(lines, demoAuditLine(at.Add(900*time.Millisecond), d.addr, "updates.example.net", qtype, 2004, gr.exit))
		}
		g.resolve(at.Add(900*time.Millisecond), lines...)
		g.read(at.Add(time.Second))
	}
	g.read(now)
	return g
}

// demoQueriesWithGaps is the query journal of the degraded gateway, with
// what a reader that could not observe everything leaves:
//
//   - the reader starts fresh 40 minutes ago (the log was cleared before)
//     on an audit file whose last query is seven minutes older than its
//     last write — the resolver was restarted in between and left half a
//     line. The zone cannot be established: these records carry the time
//     they were read and are marked time_approx; the half line is counted
//     as a bad line and not stored;
//   - from 30 to 21 minutes ago the reader was stopped: the lines written
//     meanwhile are read late, so they have their time but no MAC (the
//     neighbour table is only asked for fresh lines);
//   - while the main path was going down the queries through an exit's
//     resolver waited two seconds and came back empty;
//   - 12 minutes ago 192.168.77.35 was given to another device: one
//     address, two MACs.
func demoQueriesWithGaps(t *testing.T, now time.Time, gr demoGroups) *demoDNS {
	t.Helper()
	now = now.Truncate(time.Minute)
	ago := func(m int, extra time.Duration) time.Time { return now.Add(-time.Duration(m)*time.Minute + extra) }
	n := 0
	line := func(at time.Time, slow bool) string {
		n++
		d := demoDevices[n%len(demoDevices)]
		qtype, answer := 1, fmt.Sprintf("198.51.100.%d", 10+n%40)
		if strings.Contains(d.addr, ":") {
			qtype, answer = 28, fmt.Sprintf("2001:db8:5::%x", 16+n%40)
		}
		if slow {
			return demoAuditLine(at, d.addr, demoNames[n%len(demoNames)], qtype, 2004+int64(n%5), gr.exit)
		}
		return demoAuditLine(at, d.addr, demoNames[n%len(demoNames)], qtype, int64((n*7)%38), gr.of(n), answer)
	}
	g := newDemoDNS(t, ago(40, 0))
	// 47 minutes ago three queries; 40 minutes ago the restarted resolver
	// left half a line behind.
	g.resolve(ago(40, -2*time.Second), line(ago(47, 0), false), line(ago(47, 400*time.Millisecond), false), line(ago(47, 900*time.Millisecond), false),
		"["+ago(40, -2*time.Second).Add(demoResolverZone).Format("2006-01-02 15:04:05")+",118] 192.168.77.21 query cdn-07.exam")
	g.read(ago(40, 0))
	for m := 39; m >= 31; m-- {
		at := ago(m, -5*time.Second)
		g.resolve(at.Add(300*time.Millisecond), line(at, false), line(at.Add(200*time.Millisecond), false))
		g.read(at.Add(time.Second))
	}
	if h := g.d.Health().Reader; h.Bad != 1 || h.TimeApprox != 3 || h.ZoneOffsetS == nil || *h.ZoneOffsetS != int(demoResolverZone/time.Second) {
		t.Fatalf("the degraded query journal's first reader: %+v", h)
	}
	g.stop()
	for m := 29; m >= 21; m-- {
		at := ago(m, -5*time.Second)
		g.resolve(at.Add(300*time.Millisecond), line(at, m <= 23), line(at.Add(200*time.Millisecond), false))
	}
	g.start(ago(21, 0))
	g.read(ago(21, 0))
	for m := 20; m >= 1; m-- {
		if m == 12 {
			g.neigh["192.168.77.35"] = "00:00:5e:00:53:36"
		}
		at := ago(m, -5*time.Second)
		g.resolve(at.Add(300*time.Millisecond), line(at, m >= 18), line(at.Add(200*time.Millisecond), false))
		g.read(at.Add(time.Second))
	}
	g.read(now)
	// The restarted reader read the backlog late: no MAC for those lines.
	if h := g.d.Health().Reader; h.NoMAC < 10 || h.TimeApprox != 0 {
		t.Fatalf("the degraded query journal's second reader: %+v", h)
	}
	return g
}

// demoIfaces are the gateway's interfaces of the paths its failover record
// names, from the compiled object list of the link journal.
type demoIfaces struct{ access, aliWSS, access2, backup string }

func demoIfacesOf(t *testing.T, cfg linkjournal.Config) demoIfaces {
	t.Helper()
	var ifs demoIfaces
	for _, p := range cfg.Paths {
		switch {
		case p.Name == "relay" && p.Peer == "access" && p.Mode == "udp":
			ifs.access = p.Iface
		case p.Name == "relay" && p.Peer == "access" && p.Mode == "wss":
			ifs.aliWSS = p.Iface
		case p.Name == "relay" && p.Peer == "access2":
			ifs.access2 = p.Iface
		case p.Name == "backup":
			ifs.backup = p.Iface
		}
	}
	if ifs.access == "" || ifs.aliWSS == "" || ifs.access2 == "" || ifs.backup == "" || cfg.Mode != linkjournal.ModeShare || cfg.Sniff == nil {
		t.Fatalf("the demo gateway's object list: mode %s, interfaces %+v", cfg.Mode, ifs)
	}
	return ifs
}

// demoLink is the link journal of the synthetic gateway: the real collector
// (linkjournal.Collector) with the object list compiled for the demo
// topology, reading synthetic sources — the failover service's record in
// its grammar (demoUpstreamRecord), "wg show … latest-handshakes" and
// "systemctl is-active" answers, the forwarder's self-check (demoSelfCheck)
// — on a clock the fixture advances 20 seconds a pass over the two hours
// before end. What it holds afterwards is what the collector recorded.
type demoLink struct {
	t     *testing.T
	dir   string
	cfg   linkjournal.Config
	ifs   demoIfaces
	clock demoClock
	end   time.Time
	j     *linkjournal.Journal
	c     *linkjournal.Collector
	// The forwarder's rule pair (its self-check is built from it).
	targets, snapshot string
	// What the sources answer at the current pass.
	record  string
	shake   map[string]int64 // interface → newest handshake (unix seconds)
	unitsOK bool
	health  []byte
	checked int // the offset of the self-check health holds
}

func newDemoLink(t *testing.T, cfg linkjournal.Config, end time.Time, targets, snapshot string) *demoLink {
	t.Helper()
	l := &demoLink{t: t, dir: filepath.Join(t.TempDir(), "linklog"), cfg: cfg, ifs: demoIfacesOf(t, cfg), end: end.Truncate(time.Minute), targets: targets, snapshot: snapshot, checked: 1}
	t.Cleanup(func() {
		if l.j != nil {
			l.j.Close()
		}
	})
	return l
}

// Run answers the collector's programs (linkjournal.Runner).
func (l *demoLink) Run(_ context.Context, prog string, args ...string) (string, error) {
	switch {
	case prog == "wg" && len(args) == 3:
		ts, ok := l.shake[args[1]]
		if !ok {
			return "Unable to access interface: No such device\n", fmt.Errorf("exit status 1")
		}
		key := sha256.Sum256([]byte("meridian demo peer of " + args[1]))
		return base64.StdEncoding.EncodeToString(key[:]) + "\t" + fmt.Sprint(ts) + "\n", nil
	case prog == "systemctl" && len(args) == 2:
		if !l.unitsOK {
			return "Failed to connect to bus: Connection refused\n", fmt.Errorf("exit status 1")
		}
		return "active\n", nil
	}
	return "", fmt.Errorf("demo: no answer for %s %v", prog, args)
}

// open starts the collector on the journal directory (a restart finds the
// checkpoint and the events of the run before).
func (l *demoLink) open() {
	j, err := linkjournal.Open(linkjournal.Options{Dir: l.dir, Now: l.clock.now})
	if err != nil {
		l.t.Fatal(err)
	}
	l.j = j
	l.c = linkjournal.NewCollector(l.cfg, j, linkjournal.Reader{Runner: l,
		ReadFile: func(string, int64) ([]byte, error) { return []byte(l.record), nil },
		Status: func(context.Context, string, string) ([]byte, int, error) {
			return l.health, http.StatusOK, nil
		}})
}

// Offsets (seconds before the end) of what happens on the synthetic
// gateway. Healthy: the UDP leg to the first relay stalls for 18 minutes
// (its handshake goes stale, the relay is carried by its WSS leg); the
// gateway's self-check of the external exit fails from its 90-minute to
// its 60-minute run. Degraded, on top: the collector is down for nine
// minutes, and the UDP leg stalls for good during that gap; the tunnel to
// the second relay flaps every minute; the first relay is evicted, then
// the second, and the backup hub carries; the WSS leg's tunnel goes stale;
// the unit states cannot be read any more; the external exit's check fails
// again.
const (
	demoLinkSpan     = 2 * 3600 // the collector's first pass (its baseline)
	demoLinkStep     = 20
	demoLegStall     = 112 * 60 // healthy: the UDP leg stalls…
	demoLegBack      = 94 * 60  // …and handshakes again
	demoLegRouteBack = 92 * 60  // the relay is back on its UDP leg
	demoExtFailFrom  = 90 * 60  // self-check runs that fail for the external exit
	demoExtFailTo    = 60 * 60
	demoGapFrom      = 58 * 60 // degraded: the collector is down…
	demoGapTo        = 49 * 60 // …and back
	demoLegGone      = 55 * 60 // the UDP leg's last handshake (inside the gap)
	demoFlapFrom     = 40      // minutes: the tunnel to the second relay flaps…
	demoFlapTo       = 3       // …until
	demoRelayDown    = 1300    // the first relay is evicted
	demoOnBackup     = 1260    // the second one too: the backup hub carries
	demoWSSGone      = 1320    // the WSS leg's last handshake
	demoUnitsGone    = 6 * 60  // systemctl stops answering
	demoExtFailAgain = 120     // a self-check after a reload fails for the external exit
)

// set puts the sources into their state off seconds before the end.
func (l *demoLink) set(off int, degraded bool) {
	now := l.end.Add(-time.Duration(off) * time.Second)
	end := l.end.Unix()
	// A healthy tunnel shook hands a minute ago (whole minutes: the
	// fixture's times are rounded to them).
	fresh := now.Unix() - 60
	l.shake = map[string]int64{}
	for _, tun := range l.cfg.Tunnels {
		l.shake[tun.Iface] = fresh
	}
	ifs := l.ifs
	stage := 0
	switch {
	case degraded && off <= demoLegGone:
		l.shake[ifs.access], ifs.access = end-demoLegGone, ifs.aliWSS
	case off <= demoLegStall && off > demoLegBack:
		l.shake[ifs.access], ifs.access = end-demoLegStall, ifs.aliWSS
	case off <= demoLegBack && off > demoLegRouteBack:
		ifs.access = ifs.aliWSS
	}
	l.unitsOK = true
	if degraded {
		// Stale on the even minutes, fine on the odd ones (and afterwards).
		if m := off / 60; m <= demoFlapFrom && m >= demoFlapTo && m%2 == 0 {
			l.shake[l.ifs.access2] = now.Unix() - 240
		}
		switch {
		case off <= demoOnBackup:
			stage = 2
		case off <= demoRelayDown:
			stage = 1
		}
		if off <= demoWSSGone {
			l.shake[l.ifs.aliWSS] = end - demoWSSGone
		}
		l.unitsOK = off > demoUnitsGone
	}
	l.record = demoUpstreamRecord(now.Unix(), end, stage, ifs)
	// The forwarder's last self-check: every 15 minutes, and (degraded) one
	// after a reload two minutes before the end.
	run := (off / 900) * 900
	if off%900 != 0 {
		run += 900
	}
	if degraded && off <= demoExtFailAgain {
		run = demoExtFailAgain
		if off == 0 {
			run = 0
		}
	}
	if run != l.checked {
		failing := ""
		if run <= demoExtFailFrom && run >= demoExtFailTo || degraded && run <= demoExtFailAgain {
			failing = "exit:myext"
		}
		sc := demoSelfCheck(l.targets, l.snapshot, l.end.Add(-time.Duration(run)*time.Second), failing)
		if sc == nil {
			l.t.Fatal("no self-check from the forwarder's rule pair")
		}
		l.health, _ = json.Marshal(map[string]any{"ready": true, "self_check": sc})
		l.checked = run
	}
}

// pass is one pass of the collector off seconds before the end.
func (l *demoLink) pass(off int, degraded bool) {
	l.set(off, degraded)
	now := l.end.Add(-time.Duration(off) * time.Second)
	l.clock.set(now)
	l.c.Step(context.Background(), now)
}

// run records the two hours before the end.
func (l *demoLink) run(degraded bool) *demoLink {
	l.clock.set(l.end.Add(-demoLinkSpan * time.Second))
	l.open()
	for off := demoLinkSpan; off >= 0; off -= demoLinkStep {
		if degraded && off < demoGapFrom && off > demoGapTo {
			continue
		}
		if degraded && off == demoGapTo {
			// The collector was stopped after its last pass and starts again.
			l.j.Close()
			l.clock.set(l.end.Add(-time.Duration(off) * time.Second))
			l.open()
		}
		l.pass(off, degraded)
	}
	return l
}

// idle is a collector installed a few minutes ago on a gateway where
// nothing has changed since: its first pass is the baseline, there is no
// event yet.
func (l *demoLink) idle() *demoLink {
	l.clock.set(l.end.Add(-4 * time.Minute))
	l.open()
	for off := 240; off >= 0; off -= demoLinkStep {
		l.pass(off, false)
	}
	return l
}

// status is the host agent's status answer for this collector.
func (l *demoLink) status() hostexec.LinkJournalStatus {
	h := l.c.Health()
	// The stand-in sources answer at once; a fixed value keeps the fixture
	// the same from one build to the next.
	h.LastPassMS = 3
	b, _ := json.Marshal(h)
	return hostexec.LinkJournalStatus{ReadAt: time.Now().UTC().Format(time.RFC3339), UnitActive: "active", Present: true, ConfigInstalled: true, Health: b}
}

type demoRemote struct {
	mu sync.Mutex
	st hostexec.WGStatus
}

func (d *demoRemote) RemoteAccessStatus(context.Context) (hostexec.WGStatus, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.st, nil
}

// demoFetch serves synthetic rule-set contents; a URL in fail answers an
// error (the previous version stays active).
type demoFetch struct {
	mu   sync.Mutex
	body map[string]string
	fail map[string]string
}

func (f *demoFetch) Get(_ context.Context, url string) ([]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if msg, ok := f.fail[url]; ok {
		return nil, fmt.Errorf("%s", msg)
	}
	b, ok := f.body[url]
	if !ok {
		return nil, fmt.Errorf("HTTP 404")
	}
	return []byte(b), nil
}

// ------------------------------------------------------------ topology ---

var demoRegions = []string{"hk", "tw", "my", "jp", "sg", "us", "gb"}

func demoTopology() model.Topology {
	t := model.Topology{
		Settings: model.Settings{
			LANInterface:    "eth0",
			GatewayLANIP:    "192.168.77.2/24",
			ROSIPv4:         "192.168.77.1",
			ROSv6LLA:        "fe80::5054:ff:fe12:3456",
			LANIPv6Prefix:   "2001:db8:77::/64",
			ULAPrefix:       "fd66::/48",
			PanelBind:       "192.168.77.2:8787",
			DomesticDoT:     []string{"192.0.2.53", "198.51.100.53"},
			TransitV4Prefix: "10.77.200.0/24",
			TransitV6Prefix: "fd66:0:0:ff::/64",
			NAT64:           model.NAT64{Reserved: true},
			DefaultGroup:    "hk",
		},
		RulesOrdered: true,
	}
	exit := func(id, name, region, v4 string, x, y float64) model.Node {
		return model.Node{ID: id, Name: name, Role: model.RoleExit, Region: region, Managed: true, X: x, Y: y,
			EndpointV4: v4, WANInterface: "eth0", PathV4: true, EgressV4: true}
	}
	t.Nodes = []model.Node{
		{ID: "gw", Name: "网关（客厅机柜）", Role: model.RoleGateway, Region: "cn", Managed: true, X: 0, Y: 260,
			LANInterface: "eth0", LANIPv4: "192.168.77.2/24", LANIPv6Prefix: "2001:db8:77::/64",
			UnderlayNextHop: "192.168.77.1", PathV4: true, PathV6: true},
		{ID: "access", Name: "国内中继 · 华东一区（共享带宽，示例里名字特意写得很长）", Role: model.RoleRelay, Region: "cn", Managed: true, X: 220, Y: 200,
			WANInterface: "eth0", EndpointV4: "203.0.113.10", PathV4: true, WSSListenPort: 8443},
		{ID: "access2", Name: "国内中继 2 · 华南", Role: model.RoleRelay, Region: "cn", Managed: true, X: 220, Y: 340,
			WANInterface: "eth0", EndpointV4: "203.0.113.11", PathV4: true},
		{ID: "ix", Name: "IX 专线（主枢纽）", Role: model.RoleHub, Region: "hk", Managed: true, X: 440, Y: 200,
			HubTier: model.HubPrimary, IXLine: true, IngressV4: "198.51.100.10", EndpointV4: "203.0.113.20", WANInterface: "eth0", PathV4: true},
		{ID: "hkb", Name: "备用枢纽 · 香港机房五号", Role: model.RoleHub, Region: "hk", Managed: true, X: 440, Y: 380,
			HubTier: model.HubBackup, EndpointV4: "203.0.113.30", WANInterface: "eth0", WSSListenPort: 8443, PathV4: true},
		exit("dc1", "香港机房 1（中继出口，带台湾 NAT）", "hk", "203.0.113.41", 680, 80),
		exit("dc2", "香港机房 2（承载马来西亚 SOCKS）", "hk", "203.0.113.42", 680, 170),
		exit("jp-a", "日本东京 · 一个很长很长的出口名字用来测试换行", "jp", "203.0.113.51", 680, 260),
		exit("sg1", "新加坡", "sg", "203.0.113.52", 680, 350),
		exit("us1", "美国西岸（双栈）", "us", "203.0.113.53", 680, 440),
		exit("us2", "美国东岸（家宽）", "us", "203.0.113.54", 680, 530),
		exit("gb1", "英国伦敦", "gb", "203.0.113.55", 680, 620),
		{ID: "twnat", Name: "台湾 NAT（只能拨出）", Role: model.RoleExit, Region: "tw", Managed: true, X: 900, Y: 80,
			WANInterface: "eth0", PathV4: true, EgressV4: true, NatDialOut: true, ViaExit: "dc1"},
		{ID: "myext", Name: "马来西亚路由器（外部 SOCKS）", Role: model.RoleExit, Region: "my", Managed: false, X: 900, Y: 170,
			PathV4: true, EgressV4: true,
			External: &model.ExternalExit{Carrier: "dc2", SOCKSAddress: "198.51.100.66", SOCKSPort: 1080, Interface: "wg9", CredentialID: "socks-placeholder"}},
	}
	for i := range t.Nodes {
		switch t.Nodes[i].ID {
		case "us1":
			t.Nodes[i].EndpointV6, t.Nodes[i].PathV6, t.Nodes[i].EgressV6 = "2001:db8:4000:1234:5678:9abc:def0:51", true, true
		case "us2":
			t.Nodes[i].Residential = true
		case "dc1":
			t.Nodes[i].IXBound = true
		}
	}
	link := func(id, name, from, to string, tr model.Transport) model.Link {
		return model.Link{ID: id, Name: name, From: from, To: to, Transport: tr, Enabled: true}
	}
	t.Links = []model.Link{
		link("gw-access", "网关 → 国内中继（UDP，WSS 兜底）", "gw", "access", model.TransportUDPWSSFailover),
		link("gw-access2", "网关 → 国内中继 2", "gw", "access2", model.TransportDirectWG),
		link("access-ix", "国内中继 → IX（专线）", "access", "ix", model.TransportDirectWG),
		link("access2-ix", "国内中继 2 → IX（专线）", "access2", "ix", model.TransportDirectWG),
		link("twnat-dc1", "台湾 NAT → 香港机房 1（中继出口）", "twnat", "dc1", model.TransportDirectWG),
	}
	backup := link("gw-hkb", "网关 → 备用枢纽（WSS）", "gw", "hkb", model.TransportIXReplacementWSS)
	backup.Standby = true
	t.Links = append(t.Links, backup)
	for _, hub := range []string{"ix", "hkb"} {
		for _, ex := range []string{"dc1", "dc2", "jp-a", "sg1", "us1", "us2", "gb1"} {
			t.Links = append(t.Links, link(hub+"-"+ex, "", hub, ex, model.TransportDirectWG))
		}
	}
	mesh := link("ix-jp-a-mesh", "IX → 日本东京 Mesh 备路", "ix", "jp-a", model.TransportCFMesh)
	mesh.Standby = true
	t.Links = append(t.Links, mesh)

	t.Groups = []model.RegionGroup{
		{ID: "hk", Name: "香港机房", Region: "hk", Members: []string{"dc1", "dc2"}, Mode: model.GroupAuto, ExcludeResidential: true},
		{ID: "tw", Name: "台湾", Region: "tw", Members: []string{"twnat"}, Mode: model.GroupAuto},
		{ID: "my", Name: "马来西亚", Region: "my", Members: []string{"myext"}, Mode: model.GroupAuto},
		{ID: "jp", Name: "日本", Region: "jp", Members: []string{"jp-a"}, Mode: model.GroupAuto},
		{ID: "sg", Name: "新加坡", Region: "sg", Members: []string{"sg1"}, Mode: model.GroupAuto},
		{ID: "us", Name: "美国（手动指定西岸，失败时回落）", Region: "us", Members: []string{"us1", "us2"}, Mode: model.GroupManual,
			Chosen: "us1", OnFailure: model.OnFailureFallback},
		{ID: "gb", Name: "英国", Region: "gb", Members: []string{"gb1"}, Mode: model.GroupAuto},
	}

	// Imported mihomo policy groups: rules point at the region group (or
	// action) each one selected and keep its name as a label.
	svcNames := []string{"AI 服务", "国际流媒体", "港澳台流媒体", "日本流媒体", "即时通讯", "游戏平台", "开发者工具", "云存储与同步",
		"新闻与资讯", "社交网络", "广告拦截", "国内直连服务", "下载与更新", "音乐平台"}
	svcTargets := []string{"us", "sg", "hk", "jp", "hk", "jp", "us", "us", "gb", "sg", model.ActionReject, model.ActionDirect, "hk", "tw"}
	viaPolicy := func(r *model.Rule, i int) {
		r.MihomoGroup = svcNames[i]
		if tg := svcTargets[i]; tg == model.ActionReject || tg == model.ActionDirect {
			r.TargetAction = tg
		} else {
			r.TargetGroup = tg
		}
	}
	// 56 rule-sets.
	for i := 1; i <= 56; i++ {
		rs := model.RuleSet{ID: fmt.Sprintf("rs%02d", i), Name: fmt.Sprintf("Service%02d", i), Origin: "mihomo",
			URL: fmt.Sprintf("https://rules.example.org/subscriptions/provider-%02d/a-rather-long-path/Service%02d.list", i, i)}
		if i == 3 {
			rs.Name = "StreamingWithExclusions"
			rs.Exclude = []string{"DOMAIN-SUFFIX,wide-cdn-03.example", "DOMAIN-SUFFIX,removed-upstream.example"}
		}
		if i%10 == 0 {
			rs.Behavior = "domain"
			rs.URL = fmt.Sprintf("https://rules.example.org/subscriptions/provider-%02d/Service%02d.yaml", i, i)
		}
		t.RuleSets = append(t.RuleSets, rs)
	}
	// 162 rules: manual rules first, then the imported list, then a few
	// non-manual rows.
	var rules []model.Rule
	add := func(r model.Rule) {
		r.Enabled = true
		r.Priority = (len(rules) + 1) * 10
		rules = append(rules, r)
	}
	add(model.Rule{ID: "m-quic", Name: "拒绝走隧道的 QUIC（UDP 443）", Manual: true, MatchType: model.MatchQUICReject})
	for i := 1; i <= 24; i++ {
		r := model.Rule{ID: fmt.Sprintf("m%02d", i), Manual: true}
		switch i % 6 {
		case 0:
			r.Name, r.MatchType, r.MatchValue, r.TargetGroup = fmt.Sprintf("手动 %02d · 整段地址", i), model.MatchCIDR, fmt.Sprintf("198.51.100.%d/32", i), demoRegions[i%7]
		case 1:
			r.Name, r.MatchType, r.MatchValue, r.TargetGroup = fmt.Sprintf("手动 %02d · api-%02d.example.com", i, i), model.MatchDomain, fmt.Sprintf("api-%02d.example.com", i), demoRegions[i%7]
			r.Domains = []string{r.MatchValue}
		case 2:
			r.Name, r.MatchType, r.MatchValue, r.TargetExit = fmt.Sprintf("手动 %02d · 钉死到美国西岸", i), model.MatchSuffix, fmt.Sprintf("pinned-%02d.example.net", i), "us1"
		case 3:
			r.Name, r.MatchType, r.MatchValue = fmt.Sprintf("手动 %02d · 来自策略组", i), model.MatchSuffix, fmt.Sprintf("svc-%02d.a-very-long-subdomain-for-layout.example.org", i)
			viaPolicy(&r, i%10)
		case 4:
			r.Name, r.MatchType, r.MatchValue, r.TargetAction = fmt.Sprintf("手动 %02d · 直连", i), model.MatchSuffix, fmt.Sprintf("direct-%02d.example.cn", i), model.ActionDirect
		case 5:
			r.Name, r.MatchType, r.MatchValue, r.TargetGroup = fmt.Sprintf("手动 %02d · 书房电脑", i), model.MatchSuffix, fmt.Sprintf("study-%02d.example.net", i), "jp"
			r.SourceMAC = fmt.Sprintf("02:00:5e:00:53:%02x", i)
		}
		if i == 7 {
			r.Notes = "这条说明写得比较长：用于检查规则抽屉和表格里的长说明是否会把列撑开，或者被固定的操作列压住。"
		}
		add(r)
	}
	// A rule pinned to the external SOCKS exit: the forwarder's self-check
	// then has a target of its own for it (what the link journal records of
	// an external exit).
	add(model.Rule{ID: "m-my", Name: "手动 · 钉死到马来西亚出口（外部 SOCKS）", Manual: true, MatchType: model.MatchSuffix, MatchValue: "pinned-my.example.net", TargetExit: "myext"})
	// AI rules go to the US group; the unlock page neither probes nor
	// moves them.
	add(model.Rule{ID: "m-openai", Name: "OpenAI", Manual: true, MatchType: model.MatchSuffix, MatchValue: "openai.com", TargetGroup: "us", MihomoGroup: "AI"})
	add(model.Rule{ID: "m-claude", Name: "Claude", Manual: true, MatchType: model.MatchSuffix, MatchValue: "claude.com", TargetGroup: "us", MihomoGroup: "AI"})
	// Rules of probed services (the unlock page's 确认 / 手动 retarget
	// them). m-prime and m-dazn share one mihomo label: ownership ignores
	// it, so a save for Prime Video never moves the DAZN rule.
	add(model.Rule{ID: "m-prime", Name: "Prime Video", Manual: true, MatchType: model.MatchSuffix, MatchValue: "primevideo.com", TargetGroup: "us", MihomoGroup: "Streaming"})
	add(model.Rule{ID: "m-dazn", Name: "DAZN", Manual: true, MatchType: model.MatchSuffix, MatchValue: "dazn.com", TargetGroup: "us", MihomoGroup: "Streaming"})
	// Viu is its own Hong Kong service, apart from MyTV SUPER.
	add(model.Rule{ID: "m-viu", Name: "Viu", Manual: true, MatchType: model.MatchSuffix, MatchValue: "viu.com", TargetGroup: "hk"})
	add(model.Rule{ID: "m-youtube", Name: "YouTube", Manual: true, MatchType: model.MatchSuffix, MatchValue: "youtube.com", TargetGroup: "tw"})
	add(model.Rule{ID: "m-kktv", Name: "KKTV", Manual: true, MatchType: model.MatchSuffix, MatchValue: "kktv.me", TargetGroup: "tw"})
	add(model.Rule{ID: "m-abema", Name: "ABEMA", Manual: true, MatchType: model.MatchSuffix, MatchValue: "abema.io", TargetGroup: "jp"})
	for i := 1; i <= 132; i++ {
		line := 200 + i
		r := model.Rule{ID: fmt.Sprintf("imp-%03d", i), Origin: "mihomo", SourceLine: line, Manual: true}
		viaPolicy(&r, i%14)
		switch {
		case i <= 56:
			rs := fmt.Sprintf("rs%02d", i)
			r.Name, r.MatchType, r.RuleSet = "RULE-SET "+t.RuleSets[i-1].Name, model.MatchRuleSet, rs
			r.SourceText = fmt.Sprintf("RULE-SET,%s,%s", t.RuleSets[i-1].Name, svcNames[(i%14)])
		case i%3 == 0:
			v := fmt.Sprintf("imported-%03d.example.com", i)
			r.Name, r.MatchType, r.MatchValue = "DOMAIN-SUFFIX "+v, model.MatchSuffix, v
			r.SourceText = fmt.Sprintf("DOMAIN-SUFFIX,%s,%s", v, svcNames[(i%14)])
		case i%3 == 1:
			v := fmt.Sprintf("www.imported-%03d.example.org", i)
			r.Name, r.MatchType, r.MatchValue = "DOMAIN "+v, model.MatchDomain, v
			r.Domains = []string{v}
			r.SourceText = fmt.Sprintf("DOMAIN,%s,%s", v, svcNames[(i%14)])
		default:
			v := fmt.Sprintf("203.0.113.%d/32", i%250)
			r.Name, r.MatchType, r.MatchValue = "IP-CIDR "+v, model.MatchCIDR, v
			r.SourceText = fmt.Sprintf("IP-CIDR,%s,%s,no-resolve", v, svcNames[(i%14)])
		}
		add(r)
	}
	for i, reg := range []string{"hk", "tw", "jp", "us"} {
		v := fmt.Sprintf("streaming-%d.example", i+1)
		add(model.Rule{ID: "auto-" + reg, Name: "自动：" + v + " 按解锁结果", Manual: false, MatchType: model.MatchSuffix,
			MatchValue: v, TargetGroup: reg, Domains: []string{v}})
	}
	t.Rules = rules
	return t
}

// demoRuleSetBody is the synthetic content of rule-set i.
func demoRuleSetBody(i int, url string) string {
	var b strings.Builder
	if strings.HasSuffix(url, ".yaml") {
		b.WriteString("payload:\n")
		for k := 0; k < 30+i; k++ {
			fmt.Fprintf(&b, "  - '+.svc%02d-%03d.example'\n", i, k)
		}
		return b.String()
	}
	fmt.Fprintf(&b, "# Service%02d (synthetic)\n", i)
	for k := 0; k < 20+i*3; k++ {
		fmt.Fprintf(&b, "DOMAIN-SUFFIX,svc%02d-%03d.example\n", i, k)
	}
	fmt.Fprintf(&b, "DOMAIN,api.svc%02d.example\nIP-CIDR,198.51.100.%d/32,no-resolve\n", i, i)
	if i%9 == 0 {
		b.WriteString("PROCESS-NAME,example-client.exe\nUSER-AGENT,ExampleAgent*\n")
	}
	if i == 3 {
		b.WriteString("DOMAIN-SUFFIX,wide-cdn-03.example\n")
	}
	return b.String()
}

// ------------------------------------------------------------- the rig ---

type demoRig struct {
	t       *testing.T
	s       *Server
	cs      *credentials.Store
	fetch   *demoFetch
	up      *fakeUpstream
	sn      *demoSniff
	ra      *demoRemote
	lists   *fakeLists
	prober  *fakeProber
	cf      *memCF
	rem     *okRemote
	hp      *fakeHostPreflight
	ids     map[string]string // random id -> stable id
	servers map[string]string // node -> server id
	pw      string            // password of cred-ops (the SSH stand-ins accept it)
	// SSH stand-ins (sshtest, in-process, reached only through SSHDial)
	// for the nodes the deployment guide scenarios install.
	ssh  map[string]*sshtest.Server
	host *deployFix // answers the stand-ins like the deployment tests
	// sniffTargets and sniffSnapshot are the installed forwarder's rule pair.
	sniffTargets, sniffSnapshot string
	// at is when each scenario was collected: its times are normalized
	// against that moment (see normalizeRun).
	at map[string]time.Time
	// The query journal and the link journal behind the host agent's
	// requests (the stand-ins of their own tests, in front of the real
	// journals demoQueries and demoLink fill), the gateway's interfaces
	// and the resolver groups of the installed bundle.
	dl      *fakeDNSLog
	ll      *fakeLinkLog
	ifs     demoIfaces
	groups  demoGroups
	linkCfg linkjournal.Config
}

// snap records the moment scenario sc is collected.
func (r *demoRig) snap(sc string) { r.at[sc] = time.Now().UTC() }

// demoSSHNodes are the remote nodes the guide scenarios install.
var demoSSHNodes = []string{"jp-a", "sg1", "us2", "gb1", "ix", "hkb"}

func (r *demoRig) call(method, path string, body any, want int) []byte {
	r.t.Helper()
	var raw []byte
	if body != nil {
		raw = mustJSON(body)
	}
	rr := do(r.s, method, path, raw)
	if want != 0 && rr.Code != want {
		r.t.Fatalf("%s %s: %d %s", method, path, rr.Code, rr.Body.String())
	}
	return rr.Body.Bytes()
}

func (r *demoRig) id(random, stable string) { r.ids[random] = stable }

// post is one read-only POST's response as it is (any status).
func (r *demoRig) post(path, body string) demoResponse {
	rr := do(r.s, http.MethodPost, path, []byte(body))
	return demoResponse{Status: rr.Code, Body: json.RawMessage(bytes.TrimSpace(rr.Body.Bytes()))}
}

func newDemoRig(t *testing.T, healthy bool) *demoRig {
	t.Helper()
	s := newTest(t)
	s.HostRoot = t.TempDir()
	s.RuleSetDir = filepath.Join(t.TempDir(), "rulesets")
	s.ListsDir = t.TempDir()
	r := &demoRig{t: t, s: s, ids: map[string]string{}, servers: map[string]string{}, at: map[string]time.Time{},
		fetch: &demoFetch{body: map[string]string{}, fail: map[string]string{}}}
	s.RuleSetFetch = func(RuleSetFetchOptions) RuleSetFetcher { return r.fetch }
	topo := demoTopology()
	for i, rs := range topo.RuleSets {
		r.fetch.body[rs.URL] = demoRuleSetBody(i+1, rs.URL)
	}
	if healthy {
		r.hp = &fakeHostPreflight{}
		r.up = &fakeUpstream{}
		r.sn = &demoSniff{}
		r.ra = &demoRemote{}
		r.lists = &fakeLists{}
		r.prober = &fakeProber{}
		s.Host, s.HostPreflight, s.Upstream, s.Sniff, s.RemoteStatus, s.Lists, s.Prober = demoHost{root: s.HostRoot}, r.hp, r.up, r.sn, r.ra, r.lists, agedProber{fakeProber: r.prober}
		// The gateway's resolver is a verified version with the writable
		// audit mount; neither journal is installed yet.
		r.dl, r.ll = &fakeDNSLog{st: demoResolverStatus(demoResolverVersion)}, &fakeLinkLog{st: hostexec.LinkJournalStatus{ReadAt: time.Now().UTC().Format(time.RFC3339), UnitActive: "inactive"}}
		s.DNSLog, s.LinkLog = r.dl, r.ll
		r.cf = &memCF{nodes: map[string]mesh.CFNode{}, routes: map[string]mesh.CFRoute{}, nodeToken: "eyJnode" + strings.Repeat("q", 30)}
		r.rem = &okRemote{keys: map[string]string{}}
		s.MeshCF = func(mesh.Credentials) (mesh.Cloudflare, error) { return r.cf, nil }
		s.MeshRemote = func() mesh.Remote { return r.rem }
		topo.Settings.UnlockProbe = &model.UnlockProbeSettings{ExitConcurrency: 1} // results in a fixed order
		r.ssh = map[string]*sshtest.Server{}
		r.host = &deployFix{s: s, extra: map[string]string{}, script: map[string]func(string) (string, uint32){}, host: map[string]string{}, runs: map[string]int{}, state: map[string]string{}}
		byAddr := map[string]*sshtest.Server{}
		for _, n := range topo.Nodes {
			if !slices.Contains(demoSSHNodes, n.ID) {
				continue
			}
			srv := startSSH(t)
			node := n.ID
			srv.SetHandler(func(cmd, stdin string) (string, uint32) { return r.host.answer(node, cmd, stdin) })
			r.ssh[n.ID] = srv
			addr := net.JoinHostPort(n.EndpointV4, "22")
			if n.ID == "ix" { // through a port-forward on the relay
				addr = "203.0.113.10:2222"
			}
			byAddr[addr] = srv
		}
		s.SSHDial = func(ctx context.Context, network, addr string) (net.Conn, error) {
			srv, ok := byAddr[addr]
			if !ok {
				return nil, fmt.Errorf("demo: no route to %s", addr)
			}
			var d net.Dialer
			return d.DialContext(ctx, network, net.JoinHostPort(srv.Host, fmt.Sprint(srv.Port)))
		}
	}
	if err := s.Store.Save(topo); err != nil {
		t.Fatal(err)
	}
	cs, err := s.credStore()
	if err != nil {
		t.Fatal(err)
	}
	r.cs = cs
	return r
}

// resources: SSH credentials, SOCKS credential, one server per managed
// remote node (trusted host keys), the Cloudflare account.
func (r *demoRig) resources() {
	t := r.t
	type credOut struct {
		Credential struct {
			ID string `json:"id"`
		} `json:"credential"`
	}
	var c1, c2, c3, sc credOut
	mk := func(out *credOut, body map[string]any, stable string) {
		if err := json.Unmarshal(r.call(http.MethodPost, "/api/ssh-credentials", body, http.StatusCreated), out); err != nil {
			t.Fatal(err)
		}
		r.id(out.Credential.ID, stable)
	}
	r.pw = "pw-" + rnd(t, 10)
	for _, srv := range r.ssh {
		srv.SetPassword(r.pw)
	}
	mk(&c1, map[string]any{"name": "运维密码（所有机房）", "kind": "password", "password": r.pw, "notes": "合成数据：演示用"}, "cred-ops")
	mk(&c2, map[string]any{"name": "部署密钥 · ed25519 · 一个比较长的名字", "kind": "password", "password": "pw-" + rnd(t, 10)}, "cred-deploy")
	mk(&c3, map[string]any{"name": "备用枢纽专用", "kind": "password", "password": r.pw}, "cred-hub")
	if err := json.Unmarshal(r.call(http.MethodPost, "/api/socks-credentials", map[string]any{"name": "马来西亚 SOCKS", "username": demoSOCKSUser, "password": demoSOCKSPass}, http.StatusCreated), &sc); err != nil {
		t.Fatal(err)
	}
	r.id(sc.Credential.ID, "socks-my")

	topo, _, _ := r.s.Store.Load()
	for i := range topo.Nodes {
		n := &topo.Nodes[i]
		if n.ID == "myext" {
			n.External.CredentialID = sc.Credential.ID
		}
		if !n.Managed || n.Role == model.RoleGateway {
			continue
		}
		cred, user, addr := c1.Credential.ID, "root", n.EndpointV4
		switch n.ID {
		case "hkb":
			cred = c3.Credential.ID
		case "access", "access2":
			cred, user = c2.Credential.ID, "deploy"
		case "twnat":
			addr = "nat-exit-taiwan.home-broadband.subscriber-line.example.net"
		case "us1":
			addr = "2001:db8:4000:1234:5678:9abc:def0:51"
		case "ix":
			addr = "203.0.113.10"
		}
		in := credentials.ServerInput{Name: "机器 " + n.Name, Address: addr, Port: 22, User: user, Auth: model.AuthPassword, CredentialID: cred,
			Tags: []string{n.Region, string(n.Role)}}
		if n.ID == "us1" {
			// Managed through its tunnel address on the main path: the first
			// usable candidate the derivation offers.
			reach, err := compile.ManagementCandidates(topo, n.ID)
			if err != nil {
				t.Fatal(err)
			}
			for _, c := range reach.Candidates {
				if c.Status == compile.MgmtUsable && c.Depends == compile.MgmtDependsMain {
					in.Channel = &model.ManagementChannel{Mode: model.ChannelTunnel, Address: c.Address}
					break
				}
			}
			if in.Channel == nil {
				t.Fatal("us1 has no usable tunnel candidate on the main path")
			}
		}
		if n.ID == "ix" {
			in.Port = 2222
			in.Notes = "经国内中继的端口转发登录"
		}
		sv, err := r.cs.CreateServer(in)
		if err != nil {
			t.Fatalf("server %s: %v", n.ID, err)
		}
		sum := sha256.Sum256([]byte("demo host key " + n.ID))
		fp := "SHA256:" + base64.RawStdEncoding.EncodeToString(sum[:])
		if srv := r.ssh[n.ID]; srv != nil {
			fp = srv.Fingerprint()
		}
		if _, err := r.cs.ObserveHostKey(sv.ID, "ssh-ed25519", fp); err != nil {
			t.Fatal(err)
		}
		if _, err := r.cs.TrustHostKey(sv.ID, fp); err != nil {
			t.Fatal(err)
		}
		at := time.Now().UTC().Add(-26 * time.Hour).Format(time.RFC3339)
		if _, err := r.cs.RecordConnectionTest(sv.ID, model.ConnectionTest{At: at, OK: true, AuthMethod: model.AuthPassword}); err != nil {
			t.Fatal(err)
		}
		r.id(sv.ID, "srv-"+n.ID)
		r.servers[n.ID] = sv.ID
		n.ServerID = sv.ID
	}
	// One server not bound to any node.
	sv, err := r.cs.CreateServer(credentials.ServerInput{Name: "闲置机器（还没有绑定节点）", Address: "198.51.100.200", Port: 22, User: "root", Auth: model.AuthPassword, CredentialID: c1.Credential.ID})
	if err != nil {
		t.Fatal(err)
	}
	r.id(sv.ID, "srv-spare")
	// … whose host key waits for the operator's confirmation.
	sum := sha256.Sum256([]byte("demo host key spare"))
	if _, err := r.cs.ObserveHostKey(sv.ID, "ssh-ed25519", "SHA256:"+base64.RawStdEncoding.EncodeToString(sum[:])); err != nil {
		t.Fatal(err)
	}
	if err := r.s.Store.Save(topo); err != nil {
		t.Fatal(err)
	}

	var acct struct {
		Account struct {
			ID string `json:"id"`
		} `json:"account"`
	}
	if err := json.Unmarshal(r.call(http.MethodPost, "/api/cloudflare/accounts", map[string]any{"name": "Cloudflare 主账户", "account_id": strings.Repeat("0123456789abcdef", 2), "api_token": "cfapitoken_" + rnd(t, 24)}, http.StatusCreated), &acct); err != nil {
		t.Fatal(err)
	}
	r.id(acct.Account.ID, "cf-main")
	r.call(http.MethodPut, "/api/cloudflare/mesh-account", map[string]string{"account": acct.Account.ID}, http.StatusOK)
	r.call(http.MethodPut, "/api/sniff", map[string]any{"enabled": true, "record_names": true}, http.StatusOK)

	// The exits' encrypted DNS upstream: an invented provider under
	// example.net whose account label is a DNS account credential
	// (demoDNSAccount never appears in a fixture: TestDemoFixturesNoDNSAccount).
	var da struct {
		Account struct {
			ID string `json:"id"`
		} `json:"account"`
	}
	if err := json.Unmarshal(r.call(http.MethodPost, "/api/dns-accounts", map[string]any{"name": "示例加密解析服务", "account": demoDNSAccount, "notes": "合成数据：演示用"}, http.StatusCreated), &da); err != nil {
		t.Fatal(err)
	}
	r.id(da.Account.ID, "dnsacct-demo")
	r.call(http.MethodPut, "/api/dns/upstream", map[string]any{"global": map[string]any{"protocol": "dot", "addresses": []string{"192.0.2.153", "2001:db8:53::153"},
		"tls_host_name": "{account}.dns.example.net", "account_credential": da.Account.ID}}, http.StatusOK)
	// One exit with its own upstream (saved alone: the global setting is
	// kept): an invented DoH provider under example.org, documentation
	// addresses, no account label.
	r.call(http.MethodPut, "/api/dns/upstream", map[string]any{"exits": map[string]any{"sg1": map[string]any{"protocol": "doh",
		"addresses": []string{"203.0.113.153", "2001:db8:53::253"}, "tls_host_name": "doh.example.org", "path": "/dns-query"}}}, http.StatusOK)
}

// enableDNSLog turns the query journal on through its handler (the gate
// passes: the resolver stand-in reports a verified version with the audit
// mount); the gateway install that follows puts the reader on the host.
func (r *demoRig) enableDNSLog() {
	r.call(http.MethodPut, "/api/dns-log", map[string]any{"enabled": true, "acknowledge": true}, http.StatusOK)
}

// demoDNSAccount is the demo's synthetic DNS account value.
const demoDNSAccount = "demoacct7f3k"

// demoSOCKSUser / demoSOCKSPass are the demo's synthetic SOCKS username
// and password (they never appear in a fixture:
// TestDemoFixturesNoSOCKSMaterial).
const (
	demoSOCKSUser = "demo-socks-user-7f3k"
	demoSOCKSPass = "demo-socks-pass-9q2w"
)

// fetchRuleSets downloads every rule-set through the handler.
func (r *demoRig) fetchRuleSets() {
	topo, _, _ := r.s.Store.Load()
	for _, rs := range topo.RuleSets {
		r.call(http.MethodPost, "/api/rule-sets/"+rs.ID+"/update", map[string]any{}, 0)
		waitRS(r.t, r.s, rs.ID, func(st *RuleSetStatus) bool { return st.State == "ok" || st.State == "failed" || st.State == "held" })
	}
}

// remote access: enabled with three devices.
func (r *demoRig) remoteAccess() {
	r.call(http.MethodPut, "/api/remote-access", map[string]any{"enabled": true, "endpoint": "vpn.home-gateway.example.net", "listen_port": 51820}, 0)
	for i, d := range []struct{ name, mode string }{{"手机 · 日常", "home"}, {"笔记本（出差用，名字比较长的一台设备）", "full"}, {"平板", "home"}} {
		var out struct {
			Device struct {
				ID string `json:"id"`
			} `json:"device"`
		}
		b := r.call(http.MethodPost, "/api/remote-access/devices", map[string]any{"name": d.name, "mode": d.mode}, 0)
		if err := json.Unmarshal(b, &out); err != nil || out.Device.ID == "" {
			r.t.Fatalf("device: %v %s", err, b)
		}
		r.id(out.Device.ID, fmt.Sprintf("dev-%d", i+1))
	}
}

// install: node keys, the gateway's preflight and install, every remote
// node recorded as installed with exactly its current content.
func (r *demoRig) install() {
	t := r.t
	if _, _, err := r.s.ensureNodeKeys(); err != nil {
		t.Fatal(err)
	}
	var pf struct {
		Preflight struct {
			ID string `json:"id"`
		} `json:"preflight"`
	}
	if err := json.Unmarshal(r.call(http.MethodPost, "/api/host/preflight", map[string]any{}, http.StatusOK), &pf); err != nil {
		t.Fatal(err)
	}
	r.call(http.MethodPost, "/api/apply", map[string]any{"install": true, "preflight_id": pf.Preflight.ID}, http.StatusOK)
	r.markInSync(func(string) bool { return true })
}

func (r *demoRig) markInSync(sel func(string) bool) {
	l, err := r.s.liveDeploy()
	if err != nil {
		r.t.Fatal(err)
	}
	for _, n := range l.t.Nodes {
		if !n.Managed || n.Role == model.RoleGateway || !sel(n.ID) {
			continue
		}
		id := l.idents[n.ID]
		now := time.Now().UTC().Add(-26 * time.Hour)
		r.s.saveOutcome(provisionOutcome{NodeID: n.ID, ServerID: id.ServerID, Address: id.Address, Port: id.Port, Fingerprint: id.Fingerprint,
			User: id.User, CredentialID: id.CredentialID, Bundle: l.bundles[n.ID], At: now, OK: true, Outcome: "installed", Run: "run-seed",
			Verify:      &nodeVerify{At: now, State: verifyOK, Source: "post_install", HostBundle: l.bundles[n.ID]},
			DNSAccounts: dnsAccountVersionsOf(provision.FilesFor(l.b.Files, n.ID)), SOCKSVersions: socksVersionsOf(provision.FilesFor(l.b.Files, n.ID))})
	}
}

// runtimes: what a healthy gateway reports right now.
func (r *demoRig) runtimes() {
	now := time.Now().UTC()
	beat := now.Unix() - 4

	// The forwarder runs the compiled target file of the installed bundle.
	topo, _, _ := r.s.Store.Load()
	b, err := r.s.compileTopo(topo)
	if err != nil {
		r.t.Fatal(err)
	}
	// The link journal's collector runs the bundle's object list; the
	// failover record names the gateway's interfaces of that list.
	if r.linkCfg, err = linkjournal.ParseConfig([]byte(b.Files["nodes/gw"+compile.LinkJournalConfigPath])); err != nil {
		r.t.Fatalf("the bundle's link journal object list: %v", err)
	}
	r.ifs, r.groups = demoIfacesOf(r.t, r.linkCfg), demoGroupsOf(r.t, topo)
	r.setUpstream(demoUpstreamRecord(beat, beat, 0, r.ifs))
	var tf sniff.TargetsFile
	if err := json.Unmarshal([]byte(b.Files["nodes/gw"+compile.SniffTargetsPath]), &tf); err != nil || len(tf.Targets) == 0 {
		r.t.Fatalf("sniff targets of the bundle: %v (%d)", err, len(tf.Targets))
	}
	var targets []string
	for _, x := range tf.Targets {
		targets = append(targets, x.Name)
	}
	r.sniffTargets, r.sniffSnapshot = b.Files["nodes/gw"+compile.SniffTargetsPath], b.Files["nodes/gw"+compile.DecidePath]
	sc := demoSelfCheck(r.sniffTargets, r.sniffSnapshot, now.Add(-4*time.Minute), "")
	health, _ := json.Marshal(sniff.Health{Ready: true, Mode: "redirect", Listen: "[::]:5358", Generation: 42, LoadedAt: now.Add(-3 * time.Hour),
		Rules: len(topo.Rules), Targets: targets, MACRules: true, MACLookup: true, Active: 37, Relaying: 35, MaxConns: 4096,
		RecordNames: true, Counters: map[string]uint64{"decided_by_name": 171002, "decided_by_address_ech": 6011, "decided_by_address_no_sni": 4200,
			"decided_by_address_other": 1131, "result_ok": 179930, "result_no_response": 140, "result_relay_failed": 40, "result_dial_failed": 21,
			"result_rejected": 902, "refused_overload": 0, "end_client_closed": 121004, "end_upstream_closed": 50211, "end_client_reset": 6100,
			"end_upstream_reset": 2210, "end_idle_timeout": 585},
		TargetsSHA256: sc.TargetsSHA256, TargetStats: demoTargetStats(sc, now, ""), StatsWindowS: int(sniff.StatsWindow / time.Second), SelfCheck: sc})
	var recs []sniff.ConnRecord
	names := []string{"api-01.example.com", "www.imported-004.example.org", "svc03-010.example", "streaming-1.example", "", "pinned-02.example.net", "svc-03.a-very-long-subdomain-for-layout.example.org"}
	for i, nm := range names {
		rec := sniff.ConnRecord{Start: now.Add(-time.Duration(i*7) * time.Second), Source: fmt.Sprintf("192.168.77.%d:%d", 20+i, 50000+i), Dest: fmt.Sprintf("198.51.100.%d:443", 10+i),
			Proto: "tls", Name: nm, Sniffed: nm != "", By: "name", RuleIndex: 3 + i*11, RuleID: fmt.Sprintf("m%02d", i+1), Target: tf.Targets[i%len(tf.Targets)].Name, Mark: tf.Targets[i%len(tf.Targets)].Mark,
			Upstream: fmt.Sprintf("198.51.100.%d:443", 10+i), Result: sniff.ResultOK, DecideMS: int64(2 + i), Generation: 42, Conn: uint64(9000 - i),
			End: sniff.EndClientClosed, DurationMS: int64(2400 + i*1300), BytesUp: int64(900 + i*40), BytesDown: int64(18000 + i*5000)}
		if i == 2 {
			rec.Result, rec.End, rec.Reason, rec.BytesDown = sniff.ResultRelayFailed, sniff.EndUpstreamReset, "read_reset", 0
		}
		if nm == "" {
			rec.Why, rec.By, rec.ECH, rec.RuleID, rec.RuleIndex = sniff.WhyECH, "addr", true, "", 0
		}
		recs = append(recs, rec)
	}
	active := []sniff.ConnRecord{
		{Start: now.Add(-41 * time.Minute), Source: "192.168.77.20", MAC: "00:00:5e:00:53:20", Dest: "198.51.100.61:443", Proto: "tls", Name: "chat.example.org",
			Sniffed: true, By: "name", RuleIndex: 4, RuleID: "m02", Target: tf.Targets[0].Name, Upstream: "198.51.100.61:443", Result: sniff.ActiveResult,
			DecideMS: 3, Generation: 42, Conn: 9101, DurationMS: (41 * time.Minute).Milliseconds(), BytesUp: 48211, BytesDown: 912004},
		{Start: now.Add(-90 * time.Second), Source: "192.168.77.20", MAC: "00:00:5e:00:53:20", Dest: "[2001:db8:5::30]:443", Proto: "tls", Name: "media.example.org",
			Sniffed: true, By: "name", RuleIndex: 5, RuleID: "m03", Target: tf.Targets[len(tf.Targets)-1].Name, Upstream: "[2001:db8:5::30]:443", Result: sniff.ActiveResult,
			DecideMS: 4, Generation: 42, Conn: 9102, DurationMS: 90000, BytesUp: 2210, BytesDown: 5242880},
	}
	recent, _ := json.Marshal(map[string]any{"record_names": true, "connections": recs, "active": active, "active_total": len(active)})
	r.sn.j = demoJournal(r.t, now, targets)
	r.sn.active = active
	// The query journal (installed and on: enableDNSLog) and the link
	// journal, as their services recorded the synthetic day.
	dns := demoQueries(r.t, now, r.groups)
	r.dl.j, r.dl.st = dns.d.Journal, dns.status(demoResolverVersion)
	link := newDemoLink(r.t, r.linkCfg, now, r.sniffTargets, r.sniffSnapshot).run(false)
	r.ll.j, r.ll.st = link.j, link.status()
	for addr, label := range map[string]string{"192.168.77.20": "示例手机", "192.168.77.21": "客厅电视（示例）", "2001:db8:77::50": "示例平板"} {
		r.call(http.MethodPut, "/api/sniff/devices/"+addr+"/label", map[string]string{"label": label}, http.StatusOK)
	}
	r.sn.st = hostexec.SniffStatus{Present: true, Active: "active", Health: health, Recent: recent, ReadAt: now.Format(time.RFC3339),
		TargetsSHA256: sc.TargetsSHA256, DeniedSince: &hostexec.CounterSample{At: now.Add(-5 * time.Minute), Packets: 3},
		Counters: map[string]hostexec.NFTCounter{"sniff_denied": {Present: true, Packets: 3, Bytes: 468}, "sniff_wg_outer": {Present: true, Packets: 2318804, Bytes: 1907351220}}}

	var ra struct {
		Devices []struct {
			PublicKey string `json:"public_key"`
		} `json:"devices"`
	}
	_ = json.Unmarshal(r.call(http.MethodGet, "/api/remote-access/devices", nil, http.StatusOK), &ra)
	var peers []hostexec.WGPeer
	for i, d := range ra.Devices {
		hs := now.Unix() - int64(40+i*900)
		if i == 2 {
			hs = 0
		}
		peers = append(peers, hostexec.WGPeer{PublicKey: d.PublicKey, LatestHandshake: hs, RxBytes: int64(i+1) * 73 << 20, TxBytes: int64(i+1) * 9 << 20})
	}
	r.ra.mu.Lock()
	r.ra.st = hostexec.WGStatus{Interface: "mra", Present: true, Peers: peers, ReadAt: now.Format(time.RFC3339)}
	r.ra.mu.Unlock()

	pub := lists.Published{Source: "github", URL: "https://lists.example.org/geosite/cn.txt", UpdatedAt: now.Add(-5 * time.Hour), Count: 118204, Files: 1}
	r.lists.status = lists.Status{Published: map[string]lists.Published{
		"geosite:cn": pub,
		"chnroute4":  {Source: "github", URL: "https://lists.example.org/chnroute/v4.txt", UpdatedAt: now.Add(-5 * time.Hour), Count: 8840},
		"chnroute6":  {Source: "github", URL: "https://lists.example.org/chnroute/v6.txt", UpdatedAt: now.Add(-5 * time.Hour), Count: 1932},
	}}
}

// unlock: every service on the exits it is probed on (IPv4, and IPv6 on
// the US exits that have it), with a mix of results.
func (r *demoRig) unlock() {
	r.prober.answer = func(req hostexec.ProbeRequest, svc string) probe.Category {
		a, _ := probe.Lookup(svc)
		if a.Capability == probe.CapReachability {
			return probe.CatNetworkOK
		}
		h := sha256.Sum256([]byte(req.ExitID + "/" + svc + "/" + req.Family))
		switch v := binary.BigEndian.Uint16(h[:2]) % 20; {
		case v < 13:
			return probe.CatUnlocked
		case v < 17:
			return probe.CatNotUnlocked
		case v < 18:
			return probe.CatFailed
		default:
			return probe.CatUnknown
		}
	}
	// By region, as the page does: global services on every exit,
	// regional ones only on exits of their region.
	runJob(r.t, r.s, `{"scope":"all","families":["ipv4"]}`)
	runJob(r.t, r.s, `{"scope":"us","families":["ipv6"]}`)
}

// unlockSaves records the unlock page's three saves on the healthy matrix:
// 确认 of the first recommendation not in use, 手动 to a region group (出口组)
// and 手动 pinning an exit that is not unlocked (具体节点), each with its
// preview, and their automatic-apply outcome. The demo answers a save only
// for exactly these targets.
func (r *demoRig) unlockSaves() map[string]demoResponse {
	out := map[string]demoResponse{}
	var m struct {
		Regions []matrixRegion `json:"regions"`
	}
	if err := json.Unmarshal(r.call(http.MethodGet, "/api/unlock/matrix", nil, http.StatusOK), &m); err != nil {
		r.t.Fatal(err)
	}
	var confirm, group, manual map[string]any
	for _, reg := range m.Regions {
		ident := map[string]string{}
		for _, e := range reg.Exits {
			ident[e.ID] = e.Identity
		}
		for _, svc := range reg.Services {
			if len(svc.Rules) == 0 {
				continue
			}
			if confirm == nil && svc.Recommend != nil && !svc.Recommend.Adopted {
				confirm = map[string]any{"service": svc.ID, "exit": svc.Recommend.ExitID}
				continue
			}
			if group == nil && (confirm == nil || confirm["service"] != svc.ID) {
				for _, g := range svc.Groups {
					if g.Identity != "" && (svc.Current == nil || svc.Current.Group != g.ID) {
						group = map[string]any{"service": svc.ID, "group": g.ID, "manual": true, "identity": g.Identity}
						break
					}
				}
				if group != nil {
					continue
				}
			}
			if manual == nil && (confirm == nil || confirm["service"] != svc.ID) && (group == nil || group["service"] != svc.ID) {
				for _, c := range svc.Cells {
					if c.State != cellUnlocked && ident[c.ExitID] != "" {
						manual = map[string]any{"service": svc.ID, "exit": c.ExitID, "manual": true, "identity": ident[c.ExitID]}
						break
					}
				}
			}
		}
	}
	if confirm == nil || group == nil || manual == nil {
		r.t.Fatalf("demo matrix has no save to show: %v %v %v", confirm, group, manual)
	}
	for _, name := range []string{"group", "manual", "confirm"} {
		b := map[string]map[string]any{"confirm": confirm, "group": group, "manual": manual}[name]
		pv := map[string]any{"preview": true}
		for k, v := range b {
			pv[k] = v
		}
		out["POST /api/unlock/adopt?preview="+name] = r.post("/api/unlock/adopt", string(mustJSON(pv)))
		// Each save is its own automatic run (not coalesced with the last).
		r.s.rulesAuto.mu.Lock()
		r.s.rulesAuto.lastRun = time.Time{}
		r.s.rulesAuto.mu.Unlock()
		out["POST /api/unlock/adopt?save="+name] = r.post("/api/unlock/adopt", string(mustJSON(b)))
	}
	return out
}

// hubRead stores a fresh read of the primary hub reporting every group
// on its target member.
func (r *demoRig) hubRead(tier model.HubTier, age time.Duration, hop map[string]string) {
	topo, _, _ := r.s.Store.Load()
	hub, _ := hubByTier(topo, tier)
	plans, err := compile.PlanGroupsForHub(topo, hub.ID)
	if err != nil {
		r.t.Fatal(err)
	}
	plan := compile.GroupPlanID(plans)
	now := time.Now().Add(-age).Unix()
	var blocks []string
	for _, g := range topo.Groups {
		h := hop[g.ID]
		if h == "" {
			h = g.Members[0]
			if g.Chosen != "" {
				h = g.Chosen
			}
		}
		blocks = append(blocks, hubReport(g.ID, plan, now-3, "hop "+h, "active "+h, "reason preferred", fmt.Sprintf("switched %d", now-7200)))
	}
	snap, err := hubstate.Parse(hubOutput(plan, now, blocks...))
	if err != nil {
		r.t.Fatal(err)
	}
	rd := hubstate.Read{ReadAt: time.Now().UTC().Add(-age), Identity: r.s.hubReachabilityTier(topo, tier).identity, Snapshot: &snap}
	if err := r.s.saveGroupHub(tier, rd); err != nil {
		r.t.Fatal(err)
	}
}

func (r *demoRig) meshDeploy() {
	for node, id := range r.servers {
		if sv, err := r.cs.Server(id); err == nil {
			r.rem.keys[node] = sv.HostKey.Fingerprint
		}
	}
	// ix ↔ jp-a like the first real check: jp-a already is a host-level Mesh
	// node (reused), ix has none and gets the host-level Linux connector.
	// Synthetic detection output only; the signing key fingerprint is a
	// placeholder, not Cloudflare's.
	r.t.Setenv(mesh.RepoKeyFingerprintEnv, "0123456789ABCDEF0123456789ABCDEF01234567")
	r.rem.account = strings.Repeat("0123456789abcdef", 2)
	r.rem.detect = map[string]string{
		"jp-a": "MESHHOST svc running\nMESHHOST cli present\nMESHHOST mode Mode: WarpConnector\nMESHHOST reg Account ID: " + strings.Repeat("0123456789abcdef", 2) + "\nMESHHOST addr CloudflareWARP 100.96.0.21/32\nMESHHOST rule 4 5209: not from all fwmark 0x100cf lookup 65743\nMESHHOST memavail 66560\nMESHHOST done 1\n",
		"ix":   "MESHHOST svc stopped\nMESHHOST cli absent\nMESHHOST memavail 1572864\nMESHHOST os debian bookworm\nMESHHOST arch x86_64\nMESHHOST apt present\nMESHHOST systemd present\nMESHHOST repo 200\nMESHHOST done 1\n",
	}
	r.call(http.MethodPost, "/api/mesh/detect", map[string]any{}, http.StatusOK)
	r.call(http.MethodPost, "/api/mesh/deploy", map[string]any{"confirm_install": true}, 0)
	deadline := time.Now().Add(10 * time.Second)
	for {
		j, err := (&mesh.Deployer{Dir: r.s.meshDir()}).Load()
		if err == nil && j != nil && j.State != mesh.StateRunning && j.State != mesh.StateCompensating {
			if j.State != "published" && j.State != "done" {
				r.t.Logf("mesh state %s: %s", j.State, j.Error)
			}
			return
		}
		if time.Now().After(deadline) {
			r.t.Fatal("mesh deploy did not finish")
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// ------------------------------------------------------------- collect ---

// demoGets are the read endpoints the panel calls, answered as they are.
var demoGets = []string{
	"/api/health", "/api/meta", "/api/status", "/api/host", "/api/topology", "/api/upstream", "/api/sniff",
	"/api/servers", "/api/ssh-credentials", "/api/socks-credentials", "/api/cloudflare/accounts", "/api/cloudflare/requirements",
	"/api/mesh", "/api/lists", "/api/lists/job", "/api/lists/status", "/api/region-groups", "/api/remote-access",
	"/api/remote-access/devices", "/api/unlock", "/api/unlock/catalog", "/api/unlock/jobs", "/api/unlock/results", "/api/unlock/matrix",
	"/api/deployments", "/api/wss", "/api/leakcheck", "/api/rule-sets", "/api/rules/analysis",
	"/api/deploy", "/api/artifacts", "/api/sniff/journal", "/api/sniff/devices", "/api/dns-accounts",
	"/api/acceptance", "/api/acceptance/summary",
}

// demoPosts are the read-only POSTs the panel calls to show state, with
// the body it sends.
var demoPosts = []struct{ path, body string }{
	{"/api/diff", "{}"}, {"/api/validate", "{}"}, {"/api/topology/allocations", "{}"},
}

type demoResponse struct {
	Status int             `json:"status"`
	Body   json.RawMessage `json:"body"`
}

func (r *demoRig) collect() map[string]demoResponse {
	out := map[string]demoResponse{}
	get := func(key, method, path string, body []byte) []byte {
		rr := do(r.s, method, path, body)
		out[key] = demoResponse{Status: rr.Code, Body: json.RawMessage(bytes.TrimSpace(rr.Body.Bytes()))}
		return rr.Body.Bytes()
	}
	for _, p := range demoGets {
		get("GET "+p, http.MethodGet, p, nil)
	}
	for _, p := range demoPosts {
		get("POST "+p.path, http.MethodPost, p.path, []byte(p.body))
	}
	// Detail reads of every listed object.
	var ids struct {
		Servers []struct {
			ID string `json:"id"`
		} `json:"servers"`
		Credentials []struct {
			ID string `json:"id"`
		} `json:"credentials"`
		Accounts []struct {
			ID string `json:"id"`
		} `json:"accounts"`
		Groups []struct {
			ID string `json:"id"`
		} `json:"groups"`
		Devices []struct {
			ID string `json:"id"`
		} `json:"devices"`
		Jobs []struct {
			ID string `json:"id"`
		} `json:"jobs"`
	}
	for _, p := range []string{"/api/servers", "/api/ssh-credentials", "/api/cloudflare/accounts", "/api/region-groups", "/api/remote-access/devices", "/api/unlock/jobs"} {
		_ = json.Unmarshal(out["GET "+p].Body, &ids)
	}
	for _, x := range ids.Servers {
		get("GET /api/servers/"+x.ID, http.MethodGet, "/api/servers/"+x.ID, nil)
		get("GET /api/servers/"+x.ID+"/tunnel-candidates", http.MethodGet, "/api/servers/"+x.ID+"/tunnel-candidates", nil)
	}
	for _, x := range ids.Credentials {
		get("GET /api/ssh-credentials/"+x.ID, http.MethodGet, "/api/ssh-credentials/"+x.ID, nil)
	}
	for _, x := range ids.Accounts {
		get("GET /api/cloudflare/accounts/"+x.ID, http.MethodGet, "/api/cloudflare/accounts/"+x.ID, nil)
	}
	for _, x := range ids.Groups {
		get("GET /api/region-groups/"+x.ID, http.MethodGet, "/api/region-groups/"+x.ID, nil)
	}
	for _, x := range ids.Devices {
		get("GET /api/remote-access/devices/"+x.ID, http.MethodGet, "/api/remote-access/devices/"+x.ID, nil)
	}
	for _, x := range ids.Jobs {
		get("GET /api/unlock/jobs/"+x.ID, http.MethodGet, "/api/unlock/jobs/"+x.ID, nil)
	}
	// The connection journal of each device the summary lists.
	var sum struct {
		Summary struct {
			Devices []struct {
				Device string `json:"device"`
			} `json:"devices"`
		} `json:"summary"`
	}
	_ = json.Unmarshal(out["GET /api/sniff/devices"].Body, &sum)
	for _, d := range sum.Summary.Devices {
		p := "/api/sniff/journal?device=" + d.Device
		get("GET "+p, http.MethodGet, p, nil)
	}
	// The rule tester on a few example names.
	for _, n := range []string{"api-01.example.com", "svc03-010.example", "wide-cdn-03.example", "unknown-name.example.net"} {
		get("POST /api/rules/test?name="+n, http.MethodPost, "/api/rules/test", mustJSON(map[string]string{"name": n}))
	}
	// The resolution view: one fixed check of the first checkable exit,
	// then the view and the generated configs of the gateway and that exit.
	var dv struct {
		Exits []struct {
			ID        string `json:"id"`
			Checkable bool   `json:"checkable"`
		} `json:"exits"`
		Configs []struct {
			Node string `json:"node"`
		} `json:"configs"`
	}
	_ = json.Unmarshal(do(r.s, http.MethodGet, "/api/dns", nil).Body.Bytes(), &dv)
	for _, e := range dv.Exits {
		if e.Checkable {
			do(r.s, http.MethodPost, "/api/dns/check", mustJSON(map[string]string{"exit_id": e.ID}))
			break
		}
	}
	get("GET /api/dns", http.MethodGet, "/api/dns", nil)
	for _, c := range dv.Configs {
		p := "/api/dns/config?node=" + c.Node
		get("GET "+p, http.MethodGet, p, nil)
	}
	r.collectLogs(get, out)
	// The topology page's uplink MTU view (read last, so the random
	// tokens it shares with earlier answers keep their placeholders).
	get("GET /api/mtu/uplinks", http.MethodGet, "/api/mtu/uplinks", nil)
	return out
}

// demoLogKeys are the responses the three log pages read (the connection
// journal's per-device pages are added per device).
var demoLogKeys = []string{"GET /api/sniff", "GET /api/sniff/devices", "GET /api/sniff/journal", "GET /api/sniff/journal/related",
	"GET /api/dns-log", "GET /api/dns-log/devices", "GET /api/dns-log/journal", "GET /api/dns-log/related",
	"GET /api/link-log", "GET /api/link-log/current", "GET /api/link-log/events"}

// collectLogs reads the query journal and the link journal the way their
// pages do, each with its largest page: the synthetic journals fit into one
// (the demo filters and pages that list in the browser), and one related
// lookup in each direction, around the newest record that has a MAC (the
// demo answers any other lookup from the two lists; demo.test.tsx compares
// its answer with these).
func (r *demoRig) collectLogs(get func(key, method, path string, body []byte) []byte, out map[string]demoResponse) {
	for _, p := range []string{"/api/dns-log", "/api/dns-log/devices", "/api/link-log", "/api/link-log/current"} {
		get("GET "+p, http.MethodGet, p, nil)
	}
	get("GET /api/dns-log/journal", http.MethodGet, fmt.Sprintf("/api/dns-log/journal?limit=%d", dnsjournal.PageMax), nil)
	get("GET /api/link-log/events", http.MethodGet, fmt.Sprintf("/api/link-log/events?limit=%d", linkjournal.PageMax), nil)
	related := func(key, path, device, mac string, at time.Time) {
		q := "?device=" + device + "&at=" + at.UTC().Format(time.RFC3339)
		if mac != "" {
			q += "&mac=" + mac
		}
		get(key, http.MethodGet, path+q, nil)
	}
	var dns struct {
		Page struct {
			Records    []dnsjournal.Record `json:"records"`
			NextBefore uint64              `json:"next_before"`
		} `json:"page"`
	}
	var conns struct {
		Page struct {
			Records []sniff.JournalRecord `json:"records"`
		} `json:"page"`
	}
	var link struct {
		Page struct {
			NextBefore string `json:"next_before"`
		} `json:"page"`
	}
	_ = json.Unmarshal(out["GET /api/dns-log/journal"].Body, &dns)
	_ = json.Unmarshal(out["GET /api/sniff/journal"].Body, &conns)
	_ = json.Unmarshal(out["GET /api/link-log/events"].Body, &link)
	if dns.Page.NextBefore != 0 || link.Page.NextBefore != "" {
		r.t.Fatalf("a synthetic journal does not fit into one page (%d queries)", len(dns.Page.Records))
	}
	// Without records the lookups still show what the page gets then.
	device, mac, at := demoDevices[0].addr, demoDevices[0].mac, time.Now()
	for _, rec := range dns.Page.Records {
		if rec.MAC != "" && !rec.TimeApprox {
			device, mac, at = rec.Client, rec.MAC, rec.Time
			break
		}
	}
	related("GET /api/dns-log/related", "/api/dns-log/related", device, mac, at)
	device, mac, at = demoDevices[0].addr, demoDevices[0].mac, time.Now()
	for _, rec := range conns.Page.Records {
		if rec.MAC != "" {
			device, mac, at = rec.Source, rec.MAC, rec.Start
			break
		}
	}
	related("GET /api/sniff/journal/related", "/api/sniff/journal/related", device, mac, at)
}

// logStates are the two states of the three logs that the main scenarios
// do not show, on a gateway of their own (the same topology): first every
// log off — the forwarder not enabled, the query journal at its default
// (off; the resolver could take it), the link journal's collector not
// installed because the gateway is not installed yet — then, after the
// forwarder and the query journal were enabled and the gateway installed,
// every log running without a single record: no connection ended, no query
// was read, and the collector has only its baseline.
func (r *demoRig) logStates() map[string]map[string]demoResponse {
	out := map[string]map[string]demoResponse{}
	keys := func() map[string]demoResponse {
		all := map[string]demoResponse{}
		get := func(key, method, path string, body []byte) []byte {
			rr := do(r.s, method, path, body)
			all[key] = demoResponse{Status: rr.Code, Body: json.RawMessage(bytes.TrimSpace(rr.Body.Bytes()))}
			return rr.Body.Bytes()
		}
		for _, p := range []string{"/api/sniff", "/api/sniff/devices", "/api/sniff/journal"} {
			get("GET "+p, http.MethodGet, p, nil)
		}
		r.collectLogs(get, all)
		for _, k := range demoLogKeys {
			if _, ok := all[k]; !ok {
				r.t.Fatalf("log state without %s", k)
			}
		}
		return all
	}
	now := time.Now().UTC()
	r.call(http.MethodPut, "/api/sniff", map[string]any{"enabled": false}, http.StatusOK)
	r.sn.st = hostexec.SniffStatus{Active: "inactive", ReadAt: now.Format(time.RFC3339)}
	r.snap("logs-off")
	out["logs-off"] = keys()

	r.call(http.MethodPut, "/api/sniff", map[string]any{"enabled": true}, http.StatusOK)
	r.enableDNSLog()
	r.install()
	topo, _, _ := r.s.Store.Load()
	b, err := r.s.compileTopo(topo)
	if err != nil {
		r.t.Fatal(err)
	}
	cfg, err := linkjournal.ParseConfig([]byte(b.Files["nodes/gw"+compile.LinkJournalConfigPath]))
	if err != nil {
		r.t.Fatal(err)
	}
	targets, snapshot := b.Files["nodes/gw"+compile.SniffTargetsPath], b.Files["nodes/gw"+compile.DecidePath]
	now = time.Now().UTC()
	sc := demoSelfCheck(targets, snapshot, now.Add(-3*time.Minute), "")
	var names []string
	for _, x := range sc.Targets {
		names = append(names, x.Target)
	}
	j, err := sniff.OpenJournal(sniff.JournalConfig{Dir: r.t.TempDir(), Now: func() time.Time { return now.Truncate(time.Minute) }})
	if err != nil {
		r.t.Fatal(err)
	}
	r.t.Cleanup(j.Close)
	health, _ := json.Marshal(sniff.Health{Ready: true, Mode: "redirect", Listen: "[::]:5358", Generation: 1, LoadedAt: now.Add(-4 * time.Minute), Rules: len(topo.Rules), Targets: names,
		MACRules: true, MACLookup: true, MaxConns: 4096, Counters: map[string]uint64{}, TargetsSHA256: sc.TargetsSHA256, StatsWindowS: int(sniff.StatsWindow / time.Second), SelfCheck: sc})
	recent, _ := json.Marshal(map[string]any{"record_names": false, "connections": []sniff.ConnRecord{}, "active": []sniff.ConnRecord{}, "active_total": 0})
	r.sn.j = j
	r.sn.st = hostexec.SniffStatus{Present: true, Active: "active", Health: health, Recent: recent, ReadAt: now.Format(time.RFC3339), TargetsSHA256: sc.TargetsSHA256,
		Counters: map[string]hostexec.NFTCounter{"sniff_denied": {Present: true}, "sniff_wg_outer": {Present: true}}}
	dns := newDemoDNS(r.t, now.Truncate(time.Minute).Add(-4*time.Minute))
	dns.read(now.Truncate(time.Minute))
	r.dl.j, r.dl.st = dns.d.Journal, dns.status(demoResolverVersion)
	link := newDemoLink(r.t, cfg, now, targets, snapshot).idle()
	r.ll.j, r.ll.st = link.j, link.status()
	r.snap("logs-empty")
	out["logs-empty"] = keys()
	return out
}

// demoUpstreamRecord is the gateway's upstream record in its own grammar
// (pathquality.FormatStatus), parsed below by the agent's parser and read
// by the link journal's collector: written at beat, with the times of its
// states counted back from ref. Stage 0: two relays share the main path;
// stage 1: the first relay is down and evicted, the second carries alone;
// stage 2 (the degraded gateway): the second is evicted for loss too and
// the backup hub carries. ifs are the gateway's interfaces of these paths
// (ifs.access is the leg the first relay is carried by).
func demoUpstreamRecord(beat, ref int64, stage int, ifs demoIfaces) string {
	b := &strings.Builder{}
	fmt.Fprintf(b, "meridian-upstream 2\nbeat %d\n", beat)
	relay := func(id, iface, status string, weight int, drain int, reason string, since int64, grade, rtt, loss, lastRTT, lastLoss string, rx, tx, rxBps, txBps, conns int64, probeKbps, probeLoss, probeOK string) {
		// The speed tests' verdict (R2/R3): the last valid test 15 minutes ago.
		fmt.Fprintf(b, "relay %s %s %s %d %d %s %d %s %s %s %s %s %d %d %d %d %d %d - %d %s %s %s %d ok 168400 %d 182000 p90\n",
			id, iface, status, weight, drain, reason, since, grade, rtt, loss, lastRTT, lastLoss, beat-2, rx, tx, rxBps, txBps, conns, beat-600, probeKbps, probeLoss, probeOK, 3<<20, beat-900)
	}
	switch stage {
	case 0:
		fmt.Fprintf(b, "path main\niface %s\nhub ix\ntier primary\nsince %d\nstate ok\ncontroller go\nalert -\nswitched %d\ndesignated access\n", ifs.access, ref-86400, ref-86400)
		relay("access", ifs.access, "active", 600, 0, "-", ref-86400, "good", "21400", "2", "22300", "0", 38<<30, 4<<30, 11<<20, 1<<20, 412, "48000", "0", "1")
		relay("access2", ifs.access2, "active", 400, 0, "-", ref-86400, "good", "27800", "5", "28700", "0", 25<<30, 3<<30, 7<<20, 1<<20, 291, "41000", "0", "1")
		fmt.Fprintf(b, "backup hkb %s good 36500 3 36100 0 %d %d %d 0\nend\n", ifs.backup, beat-30, 1<<20, 1<<20)
	case 1:
		fmt.Fprintf(b, "path main\niface %s\nhub ix\ntier primary\nsince %d\nstate ok\ncontroller go\nalert -\nswitched %d\ndesignated access2\n", ifs.access2, ref-86400, ref-86400)
		relay("access", ifs.access, "evicted", 0, 1, "down", ref-1300, "down", "-", "1000", "-", "1000", 38<<30, 4<<30, 0, 0, 0, "-", "-", "0")
		relay("access2", ifs.access2, "active", 1000, 0, "-", ref-86400, "mild", "44100", "38", "47900", "52", 25<<30, 3<<30, 9<<20, 1<<20, 388, "22000", "41", "1")
		fmt.Fprintf(b, "backup hkb %s good 37800 3 38400 0 %d %d %d 0\nend\n", ifs.backup, beat-30, 1<<20, 1<<20)
	default:
		fmt.Fprintf(b, "path backup\niface %s\nhub hkb\ntier backup\nsince %d\nstate ok\ncontroller go\nalert on_backup\nswitched %d\ndesignated backup\n", ifs.backup, ref-1260, ref-1260)
		relay("access", ifs.access, "evicted", 0, 1, "down", ref-1300, "down", "-", "1000", "-", "1000", 38<<30, 4<<30, 0, 0, 0, "-", "-", "0")
		relay("access2", ifs.access2, "evicted", 0, 1, "poor_loss", ref-1260, "poor", "61200", "186", "64800", "240", 25<<30, 3<<30, 12<<10, 3<<10, 0, "3100", "210", "0")
		fmt.Fprintf(b, "backup hkb %s good 38900 4 39200 0 %d %d %d 0\nend\n", ifs.backup, beat-3, 9<<30, 1<<30)
	}
	return b.String()
}

// setUpstream answers the upstream read with rec, parsed like the agent does.
func (r *demoRig) setUpstream(rec string) {
	st, err := hostexec.ParseUpstream(rec)
	if err != nil {
		r.t.Fatalf("upstream record: %v\n%s", err, rec)
	}
	r.up.mu.Lock()
	r.up.st = hostexec.UpstreamStatus{Present: true, Record: &st, ReadAt: time.Now().UTC().Format(time.RFC3339)}
	r.up.mu.Unlock()
}

// ------------------------------------------------- guide scenarios ---

// demoDeployKeys are the responses a deployment-guide scenario replaces.
var demoDeployKeys = []string{"GET /api/deploy", "GET /api/status", "GET /api/deployments", "GET /api/host", "POST /api/diff", "GET /api/topology", "GET /api/rules/analysis", "POST /api/validate"}

func (r *demoRig) collectKeys(keys []string) map[string]demoResponse {
	all := r.collect()
	out := map[string]demoResponse{}
	for _, k := range keys {
		out[k] = all[k]
	}
	return out
}

type demoRun struct {
	Run *struct {
		ID    string `json:"id"`
		State string `json:"state"`
		Steps []struct {
			NodeID      string `json:"node_id"`
			Phase       string `json:"phase"`
			PreflightID string `json:"preflight_id"`
		} `json:"steps"`
	} `json:"run"`
}

func (r *demoRig) deployState() demoRun {
	var v demoRun
	if err := json.Unmarshal(r.call(http.MethodGet, "/api/deploy", nil, http.StatusOK), &v); err != nil {
		r.t.Fatal(err)
	}
	return v
}

func (r *demoRig) step(node string) (phase, preflight string) {
	v := r.deployState()
	for i := 0; v.Run == nil && i < 50; i++ { // read while a step is being written
		time.Sleep(10 * time.Millisecond)
		v = r.deployState()
	}
	if v.Run == nil {
		r.t.Fatal("no run")
	}
	for _, st := range v.Run.Steps {
		if st.NodeID == node {
			return st.Phase, st.PreflightID
		}
	}
	r.t.Fatalf("no step %s", node)
	return "", ""
}

func (r *demoRig) preflightStep(run, node string) {
	r.call(http.MethodPost, "/api/deploy/runs/"+run+"/preflight", map[string]any{"node_id": node}, http.StatusOK)
}

func (r *demoRig) installStep(run, node string) {
	_, pf := r.step(node)
	r.call(http.MethodPost, "/api/deploy/runs/"+run+"/install", map[string]any{"node_id": node, "preflight_id": pf}, http.StatusOK)
}

func (r *demoRig) startRun(stable string) string {
	var v demoRun
	if err := json.Unmarshal(r.call(http.MethodPost, "/api/deploy/runs", map[string]any{}, http.StatusOK), &v); err != nil || v.Run == nil {
		r.t.Fatalf("start run: %v", err)
	}
	r.id(v.Run.ID, stable)
	return v.Run.ID
}

// touch changes the content of the given exits' bundles (the MTU of
// their hub links, so both hubs change too) and, with gateway, of the
// gateway (a manual rule), so they are pending.
func (r *demoRig) touch(mtu int, gateway bool, exits ...string) {
	topo, _, _ := r.s.Store.Load()
	for i := range topo.Links {
		if slices.Contains(exits, topo.Links[i].To) && (topo.Links[i].From == "ix" || topo.Links[i].From == "hkb") && topo.Links[i].Transport == model.TransportDirectWG {
			topo.Links[i].MTU = mtu
		}
	}
	if gateway {
		for i := range topo.Rules {
			if topo.Rules[i].ID == "m01" {
				topo.Rules[i].MatchValue = fmt.Sprintf("api-01-v%d.example.com", mtu)
				topo.Rules[i].Domains = []string{topo.Rules[i].MatchValue}
			}
		}
	}
	if err := r.s.Store.Save(topo); err != nil {
		r.t.Fatal(err)
	}
}

// guide runs the deployment guide through its states on the SSH
// stand-ins and the in-process gateway, collecting each one.
func (r *demoRig) guide() map[string]map[string]demoResponse {
	out := map[string]map[string]demoResponse{}
	r.touch(1380, true, "jp-a", "sg1", "us2", "gb1")

	// The plan's order of the remote steps.
	run := r.startRun("run-demo-1")
	var order []string
	for _, st := range r.deployState().Run.Steps {
		if st.NodeID != localNodeID {
			order = append(order, st.NodeID)
		}
	}
	if len(order) != len(demoSSHNodes) {
		r.t.Fatalf("plan %v", order)
	}
	a, b, c := order[0], order[1], order[2]

	// A run in progress: a installed, b installing right now.
	r.preflightStep(run, a)
	r.installStep(run, a)
	r.preflightStep(run, b)
	release, entered := make(chan struct{}), make(chan struct{})
	var once sync.Once
	r.host.setScript(b, func(string) (string, uint32) {
		once.Do(func() { close(entered) })
		<-release
		return "MERIDIAN_PROVISION_OK\n", 0
	})
	done := make(chan struct{})
	_, pf := r.step(b)
	go func() {
		defer close(done)
		do(r.s, http.MethodPost, "/api/deploy/runs/"+run+"/install", mustJSON(map[string]any{"node_id": b, "preflight_id": pf}))
	}()
	// The install script is running on the stand-in (and waits there):
	// the stored run says "installing" and nothing else moves.
	select {
	case <-entered:
	case <-time.After(30 * time.Second):
		close(release)
		r.t.Fatalf("%s never reached its install script", b)
	}
	if ph, _ := r.step(b); ph != phaseInstalling {
		close(release)
		r.t.Fatalf("%s is %s while its script runs", b, ph)
	}
	r.snap("deploy-running")
	out["deploy-running"] = r.collectKeys(demoDeployKeys)
	close(release)
	<-done
	r.host.setScript(b, nil)

	// c refuses the panel's address before the banner: wait for retry_after.
	r.ssh[c].RefuseBeforeBanner("Not allowed at this time")
	r.preflightStep(run, c)
	r.snap("deploy-rate-limited")
	out["deploy-rate-limited"] = r.collectKeys(demoDeployKeys)
	r.ssh[c].RefuseBeforeBanner("")
	r.call(http.MethodPost, "/api/deploy/runs/"+run+"/cancel", map[string]any{}, http.StatusOK)
	r.s.sshPoolMu.Lock()
	r.s.SSHPool = nil // forget the remembered refusal
	r.s.sshPoolMu.Unlock()

	// c's install fails and is compensated: the run stops.
	run = r.startRun("run-demo-2")
	r.host.setScript(c, func(string) (string, uint32) { return "MERIDIAN_COMPENSATING exit=1\nMERIDIAN_COMPENSATED\n", 1 })
	r.preflightStep(run, c)
	r.installStep(run, c)
	r.snap("deploy-compensated")
	out["deploy-compensated"] = r.collectKeys(demoDeployKeys)
	r.call(http.MethodPost, "/api/deploy/runs/"+run+"/cancel", map[string]any{}, http.StatusOK)

	// c's answer is unreadable: the outcome is unknown and the run stops.
	run = r.startRun("run-demo-3")
	r.host.setScript(c, func(string) (string, uint32) { return "garbled\n", 1 })
	r.preflightStep(run, c)
	r.installStep(run, c)
	r.snap("deploy-unknown")
	out["deploy-unknown"] = r.collectKeys(demoDeployKeys)

	// The re-check finds the content on the host and adopts it; d and the
	// gateway install: the run finishes with installed and adopted steps.
	l, err := r.s.liveDeploy()
	if err != nil {
		r.t.Fatal(err)
	}
	r.host.mu.Lock()
	r.host.extra[c] = "manifest-begin\nmanifest node " + c + "\nmanifest deployment " + mustDeployment(r.t, r.s) + "\nmanifest server " + r.servers[c] +
		"\nmanifest bundle " + l.bundles[c] + "\nmanifest-end\njournal-begin\njournal state done\njournal run run-x\njournal-end\n"
	r.host.mu.Unlock()
	r.host.setScript(c, nil)
	r.preflightStep(run, c)
	r.host.mu.Lock()
	r.host.extra[c] = ""
	r.host.mu.Unlock()
	for _, n := range append(order[3:], localNodeID) {
		r.preflightStep(run, n)
		r.installStep(run, n)
	}
	r.snap("deploy-done")
	out["deploy-done"] = r.collectKeys(demoDeployKeys)
	return out
}

// verifyGuide: on the degraded gateway (the backup hub carries), a run
// with install steps and three verify-only steps: one verified, one whose
// server cannot be reached (it has no stand-in: the dial fails), one in its
// rate-limit wait.
func (r *demoRig) verifyGuide() map[string]demoResponse {
	l, err := r.s.liveDeploy()
	if err != nil {
		r.t.Fatal(err)
	}
	for _, node := range []string{"jp-a", "sg1", "dc1"} {
		id, bundle := l.idents[node], l.bundles[node]
		at := time.Now().UTC().Add(-26 * time.Hour)
		r.s.updateOutcome(node, func(o *provisionOutcome) {
			*o = provisionOutcome{NodeID: node, ServerID: id.ServerID, Address: id.Address, Port: id.Port, Fingerprint: id.Fingerprint,
				User: id.User, CredentialID: id.CredentialID, Bundle: bundle, At: at, OK: true, Outcome: "installed", Run: "run-seed",
				Installed: true, InstalledBundle: bundle, InstalledAt: &at, InstalledRun: "run-seed",
				DNSAccounts: dnsAccountVersionsOf(provision.FilesFor(l.b.Files, node)), InstalledDNSAccounts: dnsAccountVersionsOf(provision.FilesFor(l.b.Files, node)),
				SOCKSVersions: socksVersionsOf(provision.FilesFor(l.b.Files, node)), InstalledSOCKSVersions: socksVersionsOf(provision.FilesFor(l.b.Files, node)),
				InstalledTarget: &targetIdentity{ServerID: id.ServerID, Address: id.Address, Port: id.Port, User: id.User, Fingerprint: id.Fingerprint, CredentialID: id.CredentialID}}
		})
	}
	r.host.mu.Lock()
	r.host.extra["jp-a"] = "manifest-begin\nmanifest node jp-a\nmanifest deployment " + mustDeployment(r.t, r.s) + "\nmanifest server " + r.servers["jp-a"] +
		"\nmanifest bundle " + l.bundles["jp-a"] + "\nmanifest-end\njournal-begin\njournal state done\njournal run run-seed\njournal-end\n"
	r.host.mu.Unlock()
	r.s.sshPoolMu.Lock()
	r.s.SSHPool = nil
	r.s.sshPoolMu.Unlock()
	run := r.startRun("run-demo-4")
	r.call(http.MethodPost, "/api/deploy/runs/"+run+"/verify", map[string]any{"node_id": "jp-a"}, http.StatusOK)
	r.ssh["sg1"].RefuseBeforeBanner("Not allowed at this time")
	r.call(http.MethodPost, "/api/deploy/runs/"+run+"/verify", map[string]any{"all": true}, http.StatusOK)
	r.snap("deploy-verify")
	out := r.collectKeys(demoDeployKeys)
	r.ssh["sg1"].RefuseBeforeBanner("")
	return out
}

// skipGuide: after the verify run, a run on the same gateway where the
// first exit the guide reaches is blocked by its preflight and skipped
// (a server without a stand-in cannot be reached and is skipped too), the
// next independent exit is installed, and the exit after it is blocked
// right now (its skip action names what would wait); the hubs and the
// gateway wait for the skipped node.
func (r *demoRig) skipGuide() map[string]demoResponse {
	if v := r.deployState(); v.Run != nil && (v.Run.State == runActive || v.Run.State == runStopped) {
		r.call(http.MethodPost, "/api/deploy/runs/"+v.Run.ID+"/cancel", map[string]any{}, http.StatusOK)
	}
	r.s.sshPoolMu.Lock()
	r.s.SSHPool = nil
	r.s.sshPoolMu.Unlock()
	r.touch(1340, true, "jp-a", "sg1", "us2", "gb1")
	run := r.startRun("run-demo-5")
	current := func() (string, int) {
		r.s.deployMu.Lock()
		defer r.s.deployMu.Unlock()
		rn := r.s.loadRunLocked()
		if i := rn.current(); i >= 0 {
			return rn.Steps[i].NodeID, rn.Steps[i].Tier
		}
		return "", -1
	}
	skip := func(node string) {
		r.call(http.MethodPost, "/api/deploy/runs/"+run+"/skip", map[string]any{"node_id": node}, http.StatusOK)
	}
	var blocked []string
	installed := false
	for i := 0; i < 20; i++ {
		cur, tier := current()
		if cur == "" || tier > tierExit {
			r.t.Fatalf("skip scenario: current %q (tier %d)", cur, tier)
		}
		r.host.mu.Lock()
		if slices.Contains(demoSSHNodes, cur) && (len(blocked) == 0 || installed) {
			r.host.extra[cur] = otherManifest
			blocked = append(blocked, cur)
		}
		r.host.mu.Unlock()
		r.preflightStep(run, cur)
		switch {
		case !slices.Contains(demoSSHNodes, cur) || len(blocked) == 1 && blocked[0] == cur:
			skip(cur) // unreachable, or the first blocked one
			continue
		case !installed:
			r.installStep(run, cur)
			installed = true
			continue
		}
		break // the second blocked exit stays current
	}
	if len(blocked) != 2 || !installed {
		r.t.Fatalf("skip scenario: blocked %v installed %v", blocked, installed)
	}
	r.snap("deploy-skipped")
	// The gateway's file diff stays the base scenario's: after the touch it
	// is long and its alignment around the random peer keys is not stable
	// from one build to the next.
	var keys []string
	for _, k := range demoDeployKeys {
		if k != "POST /api/diff" {
			keys = append(keys, k)
		}
	}
	out := r.collectKeys(keys)
	r.host.mu.Lock()
	for _, n := range blocked {
		r.host.extra[n] = ""
	}
	r.host.mu.Unlock()
	return out
}

// ----------------------------------------------------------- degraded ---

// agedProber answers like fakeProber, with results from age ago, one
// millisecond apart (no two results share a time, so nothing depends on
// how ties are broken).
type agedProber struct {
	*fakeProber
	age time.Duration
}

func (a agedProber) Probe(ctx context.Context, req hostexec.ProbeRequest) (probe.Report, error) {
	rep, err := a.fakeProber.Probe(ctx, req)
	rep.StartedAt = rep.StartedAt.Add(-a.age)
	for i := range rep.Results {
		at := rep.StartedAt.Add(time.Duration(i+1) * time.Millisecond)
		rep.Results[i].StartedAt, rep.Results[i].FinishedAt = at, at.Add(time.Millisecond/2)
	}
	rep.FinishedAt = rep.StartedAt.Add(time.Duration(len(rep.Results)+1) * time.Millisecond)
	return rep, err
}

// DNSCheck answers the fixed exit resolver check: the exit's resolver
// answered with one address.
func (a agedProber) DNSCheck(_ context.Context, req hostexec.DNSCheckRequest) (hostexec.DNSCheckResult, error) {
	return hostexec.DNSCheckResult{ExitID: req.ExitID, Resolver: req.Resolver, Name: hostexec.DNSCheckName, QType: "A", Outcome: "answer",
		Answers: 1, DurationMS: 48, CheckedAt: time.Now().UTC().Truncate(time.Second)}, nil
}

// degrade: the same gateway after things went wrong.
func (r *demoRig) degrade() {
	now := time.Now().UTC()
	r.setUpstream(demoUpstreamRecord(now.Unix()-6, now.Unix()-6, 2, r.ifs))

	// An exit fails its health checks: the hk group moves to dc2.
	for i := 0; i < 3; i++ {
		r.call(http.MethodPost, "/api/region-groups/health", map[string]any{"observations": []map[string]any{{"id": "dc1", "up": false}}}, http.StatusOK)
	}

	// A rule-set's download fails: the previous version stays active.
	topo, _, _ := r.s.Store.Load()
	rs := topo.RuleSets[6]
	r.fetch.mu.Lock()
	r.fetch.fail[rs.URL] = "HTTP 503 Service Unavailable"
	r.fetch.mu.Unlock()
	r.call(http.MethodPost, "/api/rule-sets/"+rs.ID+"/update", map[string]any{}, 0)
	waitRS(r.t, r.s, rs.ID, func(st *RuleSetStatus) bool { return st.LastError != "" })

	// Results of gb1 from three days ago: expired.
	var all []string
	for _, a := range probe.Catalog {
		if probe.Probeable(a.Service) {
			all = append(all, a.Service)
		}
	}
	r.s.Prober = agedProber{fakeProber: r.prober, age: 72 * time.Hour}
	runJob(r.t, r.s, string(mustJSON(map[string]any{"services": all, "exits": []string{"gb1"}, "families": []string{"ipv4"}})))
	r.s.Prober = agedProber{fakeProber: r.prober}

	// myext's SOCKS target was replaced after its results: they are about
	// another exit now and show as 未测, with no recommendation.
	topo, _, _ = r.s.Store.Load()
	for i := range topo.Nodes {
		if topo.Nodes[i].ID == "myext" && topo.Nodes[i].External != nil {
			topo.Nodes[i].External.SOCKSPort = 1081
		}
	}
	if err := r.s.Store.Save(topo); err != nil {
		r.t.Fatal(err)
	}

	// Pending changes on two nodes (hkb and dc2).
	topo, _, _ = r.s.Store.Load()
	for i := range topo.Links {
		if topo.Links[i].ID == "hkb-dc2" {
			topo.Links[i].MTU = 1360
		}
	}
	if err := r.s.Store.Save(topo); err != nil {
		r.t.Fatal(err)
	}

	// The hub reports are old: the primary's from 25 minutes ago, the
	// backup's (which carries now) from 12 minutes ago.
	r.hubRead(model.HubPrimary, 25*time.Minute, nil)
	r.hubRead(model.HubBackup, 12*time.Minute, map[string]string{"hk": "dc2"})

	// A server stopped answering the connection test.
	if _, err := r.cs.RecordConnectionTest(r.servers["access2"], model.ConnectionTest{At: now.Add(-9 * time.Minute).Format(time.RFC3339), OK: false, AuthMethod: model.AuthPassword,
		Code: "timeout", Error: "连接 203.0.113.11:22 超时（10 秒内没有完成 TCP 握手）", NotExecuted: true, SafeToRetry: true}); err != nil {
		r.t.Fatal(err)
	}

	// One remote device has not answered for three days.
	r.ra.mu.Lock()
	if len(r.ra.st.Peers) > 0 {
		r.ra.st.Peers[0].LatestHandshake = now.Unix() - 3*86400
	}
	r.ra.mu.Unlock()

	// The forwarder's self-check after the last reload: one exit's resolver
	// did not answer (the default region group and the others did); its
	// by-name connections fail.
	var h sniff.Health
	if err := json.Unmarshal(r.sn.st.Health, &h); err != nil {
		r.t.Fatal(err)
	}
	failing := ""
	for _, x := range demoSelfCheck(r.sniffTargets, r.sniffSnapshot, now, "").Targets {
		if !x.Default && strings.HasPrefix(x.Target, "exit:") && len(x.Resolvers) > 0 && failing == "" {
			failing = x.Target
		}
	}
	h.SelfCheck = demoSelfCheck(r.sniffTargets, r.sniffSnapshot, now.Add(-2*time.Minute), failing)
	h.TargetStats = demoTargetStats(h.SelfCheck, now, failing)
	health, _ := json.Marshal(h)
	r.sn.st.Health, r.sn.st.ReadAt = health, now.Format(time.RFC3339)
	r.sn.st.DeniedSince = &hostexec.CounterSample{At: now.Add(-5 * time.Minute), Packets: 3}

	// The three logs with observation gaps. The forwarder was killed 34
	// minutes ago; the query journal was cleared and its reader could not
	// observe everything since (demoQueriesWithGaps), next to a resolver
	// whose image was replaced by a version nobody verified (the journal
	// keeps recording, the next install is refused); the link journal's
	// collector was down for nine minutes and then recorded the way to the
	// backup hub (demoLink.run).
	r.sn.j = demoJournalKilled(r.t, now, h.Targets)
	dns := demoQueriesWithGaps(r.t, now, r.groups)
	r.dl.j, r.dl.st = dns.d.Journal, dns.status(demoResolverUnverified)
	link := newDemoLink(r.t, r.linkCfg, now, r.sniffTargets, r.sniffSnapshot).run(true)
	r.ll.j, r.ll.st = link.j, link.status()
}

// demoTargetStats: recent connection outcomes per target of the
// self-check; failing's resolutions fail.
func demoTargetStats(c *sniff.SelfCheck, now time.Time, failing string) []sniff.TargetStat {
	var out []sniff.TargetStat
	for i, t := range c.Targets {
		s := sniff.TargetStat{Target: t.Target, OK: uint64(4000 + i*977), RecentOK: uint64(40 + i*13), DialFailed: uint64(i % 3), ResolveFailed: uint64(i % 2),
			RelayFailed: uint64(3 + i%4), RecentRelayFailed: uint64(i % 2)}
		if t.Target == failing {
			at := now.Add(-2 * time.Minute) // whole minutes: stable under the normalization's rounding
			s.RecentOK, s.RecentResolveFailed, s.ResolveFailed, s.LastFailureAt, s.LastFailure = 0, 17, s.ResolveFailed+17, &at, "resolve_failed timeout"
		}
		out = append(out, s)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Target < out[j].Target })
	return out
}

// ---------------------------------------------------- single states ---

// extras are states of one request: the gateway preflight with blocking
// findings, a whole-topology save refused for a changed independent block.
func (r *demoRig) extras() map[string]map[string]demoResponse {
	out := map[string]map[string]demoResponse{}
	resp := func(method, path string, body []byte) demoResponse {
		rr := do(r.s, method, path, body)
		return demoResponse{Status: rr.Code, Body: json.RawMessage(bytes.TrimSpace(rr.Body.Bytes()))}
	}
	r.hp.mu.Lock()
	r.hp.extra = "ipt ipv4 -P FORWARD DROP\nunit docker.service active enabled 7\nss udp UNCONN 0 0 0.0.0.0:53 0.0.0.0:* users:((\"dnsmasq\",pid=9,fd=4))\n"
	r.hp.mu.Unlock()
	r.snap("preflight-blocked")
	out["preflight-blocked"] = map[string]demoResponse{"POST /api/host/preflight": resp(http.MethodPost, "/api/host/preflight", []byte("{}"))}
	r.hp.mu.Lock()
	r.hp.extra = ""
	r.hp.mu.Unlock()

	var topo map[string]any
	if err := json.Unmarshal(r.call(http.MethodGet, "/api/topology", nil, http.StatusOK), &topo); err != nil {
		r.t.Fatal(err)
	}
	if rs, ok := topo["rule_sets"].([]any); ok && len(rs) > 0 {
		rs[0].(map[string]any)["name"] = "Changed"
	}
	r.snap("save-refused")
	out["save-refused"] = map[string]demoResponse{"PUT /api/topology": resp(http.MethodPut, "/api/topology", mustJSON(topo))}
	return out
}

// acceptance carries out a few acceptance items on the healthy gateway, so
// the 验收 page shows every kind of result: the configuration audit, a
// read-only check, a drill that was restored and verified (the fake agent
// of the acceptance tests; nothing is executed) and a human sign-off. The
// clock is fixed for these calls, so their times and durations do not
// depend on how long the build took.
func (r *demoRig) acceptance() {
	r.t.Helper()
	now := time.Now().UTC().Truncate(time.Second)
	drill := &fakeDrill{finish: func(rec *hostexec.DrillRecord) {
		start, end := now.Add(-4*time.Minute), now.Add(-30*time.Second)
		rec.StartedAt, rec.FinishedAt = start, &end
		rec.Deadline, rec.RestoreDeadline = start.Add(45*time.Second), start.Add(345*time.Second)
	}}
	r.s.Drill, r.s.AccPoll = drill, 2*time.Millisecond
	r.s.clock = func() time.Time { return now }
	defer func() { r.s.clock = nil }()
	wait := func() {
		r.t.Helper()
		deadline := time.Now().Add(30 * time.Second)
		for r.s.currentAccJob() != nil {
			if time.Now().After(deadline) {
				r.t.Fatal("demo: an acceptance item did not finish")
			}
			time.Sleep(2 * time.Millisecond)
		}
	}
	r.call(http.MethodPost, "/api/acceptance/items/config-audit/run", nil, http.StatusAccepted)
	wait()
	r.call(http.MethodPost, "/api/acceptance/items/gateway-health/run", nil, http.StatusAccepted)
	wait()
	var view accBody
	if err := json.Unmarshal(r.call(http.MethodGet, "/api/acceptance", nil, http.StatusOK), &view); err != nil {
		r.t.Fatal(err)
	}
	for _, it := range view.Items {
		if it.ID != "relay-removal" || !it.Applicable || !it.Runnable || len(it.Targets) == 0 || !it.Targets[0].Selectable {
			continue
		}
		var prep struct {
			Confirmation struct {
				Token string `json:"token"`
			} `json:"confirmation"`
		}
		body := map[string]any{"target": it.Targets[0].ID}
		if err := json.Unmarshal(r.call(http.MethodPost, "/api/acceptance/items/relay-removal/prepare", body, http.StatusOK), &prep); err != nil {
			r.t.Fatal(err)
		}
		body["confirm_token"] = prep.Confirmation.Token
		r.call(http.MethodPost, "/api/acceptance/items/relay-removal/run", body, http.StatusAccepted)
		wait()
	}
	r.call(http.MethodPost, "/api/acceptance/items/webrtc/signoff", map[string]any{"outcome": "pass", "note": "演示数据：测试机浏览器截图已存档（evidence/webrtc-demo.png）"}, http.StatusOK)
}

// buildDemo builds every scenario once. The base scenarios (healthy,
// unavailable) have every response; the others only the responses that
// differ from their base (demoScenarioBase).
func buildDemo(t *testing.T) (raw map[string]map[string]demoResponse, ids map[string]string, at map[string]time.Time) {
	raw = map[string]map[string]demoResponse{}

	h := newDemoRig(t, true)
	h.resources()
	h.fetchRuleSets()
	h.remoteAccess()
	h.enableDNSLog()
	h.install()
	h.runtimes()
	h.call(http.MethodPost, "/api/lists/update", map[string]any{}, http.StatusAccepted)
	waitJob(t, h.s)
	h.unlock()
	h.hubRead(model.HubPrimary, 20*time.Second, nil)
	h.meshDeploy()
	h.acceptance()
	h.jobIDs()
	h.snap("healthy")
	raw["healthy"] = h.collect()
	raw["healthy"]["POST /api/host/preflight"] = h.post("/api/host/preflight", "{}")
	for k, v := range h.unlockSaves() {
		raw["healthy"][k] = v
	}
	for k, v := range h.extras() {
		raw[k] = v
	}
	for k, v := range h.guide() {
		raw[k] = v
	}
	h.degrade()
	h.jobIDs()
	h.snap("degraded")
	raw["degraded"] = h.collect()
	raw["deploy-verify"] = h.verifyGuide()
	raw["deploy-skipped"] = h.skipGuide()

	u := newDemoRig(t, false)
	u.snap("unavailable")
	raw["unavailable"] = u.collect()
	raw["unavailable"]["POST /api/host/preflight"] = u.post("/api/host/preflight", "{}")

	// The log states the main scenarios do not show, on a gateway of their own.
	l := newDemoRig(t, true)
	l.resources()
	for k, v := range l.logStates() {
		raw[k] = v
	}
	for _, o := range []*demoRig{u, l} {
		for k, v := range o.ids {
			h.ids[k] = v
		}
		for k, v := range o.at {
			h.at[k] = v
		}
	}
	return raw, h.ids, h.at
}

// jobIDs gives the probe jobs stable names in the order they ran.
func (r *demoRig) jobIDs() {
	var jobs struct {
		Jobs []struct {
			ID string `json:"id"`
		} `json:"jobs"`
	}
	_ = json.Unmarshal(r.call(http.MethodGet, "/api/unlock/jobs", nil, http.StatusOK), &jobs)
	n := 0
	for _, j := range jobs.Jobs {
		if _, ok := r.ids[j.ID]; ok {
			n++
		}
	}
	for i := len(jobs.Jobs) - 1; i >= 0; i-- {
		if _, ok := r.ids[jobs.Jobs[i].ID]; !ok {
			n++
			r.id(jobs.Jobs[i].ID, fmt.Sprintf("job-demo-%02d", n))
		}
	}
}

// demoScenarioBase is the full scenario each partial one is applied to.
var demoScenarioBase = map[string]string{
	"healthy": "", "unavailable": "", "degraded": "healthy",
	"deploy-running": "healthy", "deploy-rate-limited": "healthy", "deploy-compensated": "healthy", "deploy-unknown": "healthy", "deploy-done": "healthy",
	"deploy-verify": "healthy", "deploy-skipped": "healthy",
	"preflight-blocked": "healthy", "save-refused": "healthy",
	"logs-off": "healthy", "logs-empty": "healthy",
}

// ---------------------------------------------------------- normalize ---

var (
	// RFC 3339 times, and the "2006-01-02 15:04:05Z" times the link journal
	// writes into the evidence of its events (demoStampLayout).
	demoTimeRe = regexp.MustCompile(`\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})|\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}Z`)
	// Certificates are random material whose length varies from run to
	// run: their body is replaced by a fixed line (the BEGIN/END lines and
	// the diff prefix stay).
	demoPEMRe   = regexp.MustCompile(`(-----BEGIN CERTIFICATE-----)(\n)([+ -]?)[\s\S]*?(-----END CERTIFICATE-----)`)
	demoTokenRe = regexp.MustCompile(`(?:[0-9A-Fa-f]{2}:){7,}[0-9A-Fa-f]{2}|[A-Za-z0-9+/=_-]+`)
)

// demoStampLayout is how the link journal writes a time into a text.
const demoStampLayout = "2006-01-02 15:04:05Z"

// demoNormal is a run with the explicit IDs replaced and the times moved
// to the anchor: scenario → "METHOD /path" → {status, body}.
type demoNormal map[string]map[string]any

// Every scenario's times are moved relative to the moment it was collected
// (at[scenario]; start when not recorded): a time the handlers derived from
// "now" ("26 hours ago", "in 60 seconds") lands on the same whole minute in
// every build however long the build took before that scenario. Against
// one start for all, such a time near a half minute rounded differently
// from build to build, and the token mapping (tokenMap) then renumbered
// every fake token after it: whole files changed on every regeneration.
func normalizeRun(t *testing.T, raw map[string]map[string]demoResponse, ids map[string]string, at map[string]time.Time, start time.Time) demoNormal {
	t.Helper()
	keys := make([]string, 0, len(ids))
	for k := range ids {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		return len(keys[i]) > len(keys[j]) || len(keys[i]) == len(keys[j]) && keys[i] < keys[j]
	})
	pairs := make([]string, 0, 2*len(keys))
	for _, k := range keys {
		pairs = append(pairs, k, ids[k])
	}
	rep := strings.NewReplacer(pairs...)
	shiftFrom := func(ref time.Time) func(string) string {
		return func(s string) string {
			s = demoPEMRe.ReplaceAllString(s, "${1}${2}${3}DEMO-CERTIFICATE-OMITTED${2}${3}${4}")
			return demoTimeRe.ReplaceAllStringFunc(s, func(m string) string {
				layout := time.RFC3339
				tm, err := time.Parse(time.RFC3339Nano, m)
				if err != nil {
					if tm, err = time.Parse(demoStampLayout, m); err != nil {
						return m
					}
					layout = demoStampLayout
				}
				return demoAnchor.Add(tm.Sub(ref).Round(time.Minute)).Format(layout)
			})
		}
	}
	out := demoNormal{}
	for sc, m := range raw {
		ref := start
		if a, ok := at[sc]; ok {
			ref = a
		}
		shift := shiftFrom(ref)
		out[sc] = map[string]any{}
		for k, r := range m {
			dec := json.NewDecoder(strings.NewReader(rep.Replace(string(r.Body))))
			dec.UseNumber()
			var v any
			if err := dec.Decode(&v); err != nil {
				t.Fatalf("%s %s: %v", sc, k, err)
			}
			if fix := demoFixups[k]; fix != nil {
				fix(v)
			}
			out[sc][rep.Replace(k)] = map[string]any{"status": json.Number(fmt.Sprint(r.Status)), "body": mapStrings(v, shift)}
		}
	}
	return out
}

// demoFixups make orders the handlers leave to chance (map iteration)
// fixed, before the times are moved.
var demoFixups = map[string]func(any){
	// History entries of one ingest share a stamp order that follows map
	// iteration: order them by report, exit, service and family.
	"GET /api/unlock": func(v any) {
		m, _ := v.(map[string]any)
		h, _ := m["history"].([]any)
		key := func(x any) string {
			e, _ := x.(map[string]any)
			return fmt.Sprint(e["exit_id"], "|", e["service"], "|", e["family"], "|", e["kind"], "|", e["observed_at"])
		}
		sort.SliceStable(h, func(i, j int) bool { return key(h[i]) < key(h[j]) })
	},
}

// mapStrings applies f to every string (object keys included).
func mapStrings(v any, f func(string) string) any {
	switch x := v.(type) {
	case string:
		return f(x)
	case []any:
		for i := range x {
			x[i] = mapStrings(x[i], f)
		}
		return x
	case map[string]any:
		out := make(map[string]any, len(x))
		for k, e := range x {
			out[f(k)] = mapStrings(e, f)
		}
		return out
	}
	return v
}

func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// tokenMap compares two runs of the same build and maps every token
// (letters, digits and + / = _ -) that differs between them — random
// IDs, keys, fingerprints, digests derived from them — to a stable
// replacement of the same shape. Anything else that differs fails.
func tokenMap(t *testing.T, a, b demoNormal) map[string]string {
	t.Helper()
	mapping := map[string]string{}
	seen := map[string]string{} // b token -> replacement
	n := 0
	var fails []string
	fail := func(path, format string, args ...any) {
		if len(fails) < 20 {
			fails = append(fails, path+": "+fmt.Sprintf(format, args...))
		}
	}
	var walk func(path string, x, y any)
	walk = func(path string, x, y any) {
		switch xa := x.(type) {
		case map[string]any:
			ya, ok := y.(map[string]any)
			if !ok {
				fail(path, "type differs")
				return
			}
			kx, ky := sortedKeys(xa), sortedKeys(ya)
			if len(kx) != len(ky) {
				fail(path, "keys %v vs %v", kx, ky)
				return
			}
			for i := range kx {
				if kx[i] != ky[i] {
					walk(path+".<key>", kx[i], ky[i])
				}
				walk(path+"."+kx[i], xa[kx[i]], ya[ky[i]])
			}
		case []any:
			ya, ok := y.([]any)
			if !ok || len(ya) != len(xa) {
				fail(path, "array differs")
				return
			}
			for i := range xa {
				walk(fmt.Sprintf("%s[%d]", path, i), xa[i], ya[i])
			}
		case string:
			ys, ok := y.(string)
			if !ok {
				fail(path, "type differs")
				return
			}
			if xa == ys {
				return
			}
			// A normalized time that still differs by a minute between the
			// builds is not a random token: the first build's value stands,
			// and nothing else is renumbered for it.
			if tx, ty := demoTimeRe.FindAllString(xa, -1), demoTimeRe.FindAllString(ys, -1); len(tx) > 0 && len(tx) == len(ty) {
				i := 0
				ys = demoTimeRe.ReplaceAllStringFunc(ys, func(string) string { i++; return tx[i-1] })
				if xa == ys {
					return
				}
			}
			ix, iy := demoTokenRe.FindAllStringIndex(xa, -1), demoTokenRe.FindAllStringIndex(ys, -1)
			if len(ix) != len(iy) {
				fail(path, "%q vs %q", clipText(xa, 120), clipText(ys, 120))
				return
			}
			px, py := 0, 0
			for i := range ix {
				if xa[px:ix[i][0]] != ys[py:iy[i][0]] {
					fail(path, "%q vs %q", clipText(xa, 120), clipText(ys, 120))
					return
				}
				tx, ty := xa[ix[i][0]:ix[i][1]], ys[iy[i][0]:iy[i][1]]
				px, py = ix[i][1], iy[i][1]
				if tx == ty {
					continue
				}
				r, okx := mapping[tx]
				r2, oky := seen[ty]
				switch {
				case okx && oky && r != r2, okx != oky:
					fail(path, "token %q/%q mapped inconsistently", tx, ty)
					return
				case !okx:
					n++
					r = demoFake(tx, n)
					mapping[tx], seen[ty] = r, r
				}
			}
			if xa[px:] != ys[py:] {
				fail(path, "%q vs %q", clipText(xa, 120), clipText(ys, 120))
			}
		default:
			if fmt.Sprint(x) != fmt.Sprint(y) {
				fail(path, "%v vs %v", x, y)
			}
		}
	}
	for _, sc := range sortedKeys(a) {
		bs, ok := b[sc]
		if !ok {
			t.Fatalf("scenario %s missing in the second run", sc)
		}
		walk(sc, a[sc], bs)
	}
	if len(fails) > 0 {
		t.Fatalf("the two builds differ in more than random tokens:\n%s", strings.Join(fails, "\n"))
	}
	return mapping
}

// demoFake is a stable stand-in for a random token: the same length and
// the same alphabet (colon-separated hex, hex, or letters and digits with
// + and /), so the output depends only on n, never on which characters
// the random value happened to have. Short all-letter words between
// dashes (prefixes such as "pf", "dep", "boot") are kept.
func demoFake(tok string, n int) string {
	seed := sha256.Sum256([]byte(fmt.Sprintf("meridian-demo-token-%d", n)))
	stream := seed[:]
	next := func() byte {
		if len(stream) == 0 {
			s := sha256.Sum256(seed[:])
			seed = s
			stream = seed[:]
		}
		b := stream[0]
		stream = stream[1:]
		return b
	}
	const (
		hexLower = "0123456789abcdef"
		hexUpper = "0123456789ABCDEF"
		b64      = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	)
	var b strings.Builder
	switch {
	case strings.Contains(tok, ":"):
		for _, c := range []byte(tok) {
			if c == ':' {
				b.WriteByte(c)
			} else {
				b.WriteByte(hexUpper[next()%16])
			}
		}
		return b.String()
	case strings.Trim(tok, hexLower) == "":
		for range tok {
			b.WriteByte(hexLower[next()%16])
		}
		return b.String()
	}
	for _, seg := range strings.SplitAfter(tok, "-") {
		word := strings.TrimSuffix(seg, "-")
		if strings.Contains(tok, "-") && word != "" && len(word) <= 8 && strings.Trim(word, "abcdefghijklmnopqrstuvwxyz") == "" {
			b.WriteString(seg)
			continue
		}
		alpha := b64
		if strings.Trim(word, hexLower) == "" {
			alpha = hexLower
		} else if strings.Contains(tok, "-") || strings.Contains(tok, "_") {
			alpha = b64[:62]
		}
		for _, c := range []byte(seg) {
			switch c {
			case '=', '-', '_':
				b.WriteByte(c)
			default:
				b.WriteByte(alpha[int(next())%len(alpha)])
			}
		}
	}
	return b.String()
}

// finalize applies the token map and keeps, for every partial scenario,
// only the responses that differ from its base.
func finalize(n demoNormal, tokens map[string]string) demoNormal {
	sub := func(s string) string {
		return demoTokenRe.ReplaceAllStringFunc(s, func(m string) string {
			if r, ok := tokens[m]; ok {
				return r
			}
			return m
		})
	}
	out := demoNormal{}
	for sc, m := range n {
		out[sc] = mapStrings(m, sub).(map[string]any)
	}
	for sc, base := range demoScenarioBase {
		if base == "" {
			continue
		}
		for k, v := range out[sc] {
			if bv, ok := out[base][k]; ok && demoJSON(bv) == demoJSON(v) {
				delete(out[sc], k)
			}
		}
	}
	return out
}

func demoJSON(v any) string {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", " ")
	_ = enc.Encode(v)
	return b.String()
}

// demoFile is one scenario's file.
func demoFile(sc string, responses map[string]any) string {
	return demoJSON(map[string]any{
		"scenario":  sc,
		"base":      demoScenarioBase[sc],
		"anchor":    demoAnchor.Format(time.RFC3339),
		"generator": "internal/api/demo_fixtures_test.go (MERIDIAN_DEMO_FIXTURES=write go test ./internal/api -run 'TestDemoFixtures$' -count=1)",
		"responses": responses,
	})
}

// shapeOf is the structure of a value: object keys with their shapes,
// array elements merged, primitive kinds. Null matches anything.
func shapeOf(v any) any {
	switch x := v.(type) {
	case map[string]any:
		out := map[string]any{}
		for k, e := range x {
			out[k] = shapeOf(e)
		}
		return out
	case []any:
		var el any
		for _, e := range x {
			el = mergeShape(el, shapeOf(e))
		}
		return []any{el}
	case string:
		return "string"
	case json.Number, float64:
		return "number"
	case bool:
		return "bool"
	}
	return nil
}

func mergeShape(a, b any) any {
	am, ok1 := a.(map[string]any)
	bm, ok2 := b.(map[string]any)
	if ok1 && ok2 {
		out := map[string]any{}
		for k, v := range am {
			out[k] = v
		}
		for k, v := range bm {
			out[k] = mergeShape(out[k], v)
		}
		return out
	}
	if a == nil {
		return b
	}
	return a
}

// shapeDiff lists the paths where the shapes differ.
func shapeDiff(path string, a, b any, out *[]string) {
	if a == nil || b == nil || len(*out) > 30 {
		return
	}
	switch x := a.(type) {
	case map[string]any:
		y, ok := b.(map[string]any)
		if !ok {
			*out = append(*out, path+": object vs "+fmt.Sprint(b))
			return
		}
		for _, k := range sortedKeys(x) {
			if _, ok := y[k]; !ok {
				*out = append(*out, path+"."+k+": only in the committed file")
				continue
			}
			shapeDiff(path+"."+k, x[k], y[k], out)
		}
		for _, k := range sortedKeys(y) {
			if _, ok := x[k]; !ok {
				*out = append(*out, path+"."+k+": only in the handlers' answer")
			}
		}
	case []any:
		y, ok := b.([]any)
		if !ok {
			*out = append(*out, path+": array vs "+fmt.Sprint(b))
			return
		}
		shapeDiff(path+"[]", x[0], y[0], out)
	default:
		if fmt.Sprint(a) != fmt.Sprint(b) {
			*out = append(*out, path+": "+fmt.Sprint(a)+" vs "+fmt.Sprint(b))
		}
	}
}

// TestDemoFixtures builds the demo's fixtures from the handlers. With
// MERIDIAN_DEMO_FIXTURES=write it builds them twice (to find the random
// tokens) and writes web/src/demo/generated/*.json; otherwise it builds
// them once and checks that every committed response still has the shape
// (fields, kinds) the handlers produce now, so the demo cannot drift from
// the backend unnoticed.
func TestDemoFixtures(t *testing.T) {
	write := os.Getenv("MERIDIAN_DEMO_FIXTURES") == "write"
	start := time.Now().UTC()
	rawA, idsA, atA := buildDemo(t)
	a := normalizeRun(t, rawA, idsA, atA, start)
	if !write {
		files, err := filepath.Glob(filepath.Join(demoFixtureDir, "*.json"))
		if err != nil || len(files) == 0 {
			t.Fatalf("no committed demo fixtures in %s (generate them: MERIDIAN_DEMO_FIXTURES=write go test ./internal/api -run 'TestDemoFixtures$' -count=1)", demoFixtureDir)
		}
		if len(files) != len(demoScenarioBase) {
			t.Fatalf("%d fixture files, %d scenarios", len(files), len(demoScenarioBase))
		}
		fresh := finalize(a, nil)
		var diffs []string
		for _, f := range files {
			b, err := os.ReadFile(f)
			if err != nil {
				t.Fatal(err)
			}
			var doc struct {
				Scenario  string         `json:"scenario"`
				Responses map[string]any `json:"responses"`
			}
			if err := json.Unmarshal(b, &doc); err != nil {
				t.Fatalf("%s: %v", f, err)
			}
			got, ok := fresh[doc.Scenario]
			if !ok {
				t.Fatalf("%s: unknown scenario %q", f, doc.Scenario)
			}
			for _, k := range sortedKeys(doc.Responses) {
				gk := k
				if _, ok := got[gk]; !ok {
					// Partial scenarios keep only what differs from their base.
					if base := demoScenarioBase[doc.Scenario]; base != "" {
						if _, ok := fresh[base][k]; ok {
							got[gk] = fresh[base][k]
						}
					}
				}
				if _, ok := got[gk]; !ok {
					diffs = append(diffs, doc.Scenario+" "+k+": the handlers no longer answer it")
					continue
				}
				shapeDiff(doc.Scenario+" "+k, shapeOf(doc.Responses[k]), shapeOf(got[gk]), &diffs)
			}
		}
		if len(diffs) > 0 {
			t.Fatalf("the committed demo fixtures no longer match the handlers (regenerate: MERIDIAN_DEMO_FIXTURES=write go test ./internal/api -run 'TestDemoFixtures$' -count=1):\n%s", strings.Join(diffs, "\n"))
		}
		return
	}
	start = time.Now().UTC()
	rawB, idsB, atB := buildDemo(t)
	b := normalizeRun(t, rawB, idsB, atB, start)
	out := finalize(a, tokenMap(t, a, b))
	if err := os.MkdirAll(demoFixtureDir, 0o755); err != nil {
		t.Fatal(err)
	}
	old, _ := filepath.Glob(filepath.Join(demoFixtureDir, "*.json"))
	for _, f := range old {
		if err := os.Remove(f); err != nil {
			t.Fatal(err)
		}
	}
	for _, sc := range sortedKeys(out) {
		if err := os.WriteFile(filepath.Join(demoFixtureDir, sc+".json"), []byte(demoFile(sc, out[sc])), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

// The committed demo fixtures keep the three logs' content where it
// belongs. The synthetic devices (addresses, MACs), the names they ask for
// and connect to, and the texts of the link journal's events are in the
// answers of the logs' own endpoints only — never in a topology, a diff, a
// deployment or status view, a preflight or any other response. The data
// itself is synthetic: demo LAN and documentation addresses, documentation
// MACs, example names. And the five states are all there: recording,
// recording with gaps, unreadable, off, and without data.
func TestDemoFixturesLogContentStaysInLogResponses(t *testing.T) {
	entries, err := os.ReadDir(demoFixtureDir)
	if err != nil {
		t.Fatal(err)
	}
	own := func(key string) bool {
		for _, p := range []string{"GET /api/sniff", "GET /api/dns-log", "GET /api/link-log"} {
			if key == p || strings.HasPrefix(key, p+"/") || strings.HasPrefix(key, p+"?") {
				return true
			}
		}
		return false
	}
	// tornName is the half line the degraded resolver left: counted as a bad
	// line by the reader, never a record.
	const tornName = `"cdn-07.exam"`
	content := []string{"00:00:5e:00:53:", "internal-only.example.net", "ads.example.com", tornName,
		"最近一次握手在", "抖动合并", "分担控制器：状态", "网关嗅探转发服务的自检（", "没有采集，这段时间里的状态未知", `"elapsed_ms":`, `"prev_for_s":`}
	for _, d := range demoDevices {
		content = append(content, d.addr)
	}
	content = append(content, demoNames...)
	seen := map[string]bool{}
	states := map[string]bool{}
	clientRe := regexp.MustCompile(`"client":"([^"]*)"`)
	nameRe := regexp.MustCompile(`"name":"([^"]*)"`)
	okClient := regexp.MustCompile(`^(192\.168\.77\.\d+|2001:db8:77::[0-9a-f]+)$`)
	okName := regexp.MustCompile(`(^|\.)example\.(com|net|org)$`)
	for _, e := range entries {
		b, err := os.ReadFile(filepath.Join(demoFixtureDir, e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		var doc struct {
			Scenario  string                     `json:"scenario"`
			Responses map[string]json.RawMessage `json:"responses"`
		}
		if err := json.Unmarshal(b, &doc); err != nil {
			t.Fatalf("%s: %v", e.Name(), err)
		}
		for key, raw := range doc.Responses {
			var compact bytes.Buffer
			if err := json.Compact(&compact, raw); err != nil {
				t.Fatal(err)
			}
			body := compact.String()
			for _, c := range content {
				if !strings.Contains(body, c) {
					continue
				}
				if !own(key) {
					t.Errorf("%s: %s carries log content (%q)", doc.Scenario, key, c)
				}
				seen[c] = true
			}
			if !strings.HasPrefix(key, "GET /api/dns-log/journal") {
				continue
			}
			for _, m := range clientRe.FindAllStringSubmatch(body, -1) {
				if !okClient.MatchString(m[1]) {
					t.Errorf("%s: %s: client %q is not an address of the demo LAN", doc.Scenario, key, m[1])
				}
			}
			for _, m := range nameRe.FindAllStringSubmatch(body, -1) {
				if !okName.MatchString(m[1]) {
					t.Errorf("%s: %s: name %q is not an example name", doc.Scenario, key, m[1])
				}
			}
		}
		// Which state of the logs this scenario shows.
		var dns struct {
			Body struct {
				Installed  struct{ Enabled bool }
				Capability struct {
					Available bool
					Code      string
				}
			}
		}
		var journal struct {
			Body struct {
				Page struct {
					Records []json.RawMessage
					Events  []json.RawMessage
				}
			}
		}
		if raw, ok := doc.Responses["GET /api/dns-log"]; ok {
			_ = json.Unmarshal(raw, &dns)
			_ = json.Unmarshal(doc.Responses["GET /api/dns-log/journal"], &journal)
			switch {
			case dns.Body.Capability.Code == codeDNSLogAgentUnavailable:
				states["unreadable"] = true
			case !dns.Body.Installed.Enabled:
				states["off"] = true
			case len(journal.Body.Page.Records) == 0:
				states["no data"] = true
			case !dns.Body.Capability.Available:
				states["recording with gaps"] = true
			default:
				states["recording"] = true
			}
		}
	}
	for _, c := range content {
		if !seen[c] && c != tornName {
			t.Errorf("no fixture shows %q: the check looks for content the demo no longer has", c)
		}
	}
	if seen[tornName] {
		t.Error("the half line of the degraded resolver was stored as a record")
	}
	for _, st := range []string{"recording", "recording with gaps", "unreadable", "off", "no data"} {
		if !states[st] {
			t.Errorf("no scenario shows the logs %s", st)
		}
	}
}
