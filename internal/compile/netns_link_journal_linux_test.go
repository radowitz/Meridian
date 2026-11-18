//go:build linux

package compile

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/radowitz/meridian/internal/linkjournal"
)

// The link journal against real kernel state (docs/architecture.md
// 「链路日志」, docs/verification.md).
//
// Both tests are root only, Linux only and opt-in: MERIDIAN_NETNS_TEST=1
// MERIDIAN_NFT_TEST=1. Without them, without root, without the tools or on
// a kernel that cannot create what they need they are skipped with "NOT
// RUN" — a skip is not a pass. Everything they create lives in network
// namespaces of their own (names "mlj…" and the dual-hub lab's "mrd…") and
// in the test's temporary directory: no interface, route, rule set, sysctl,
// unit or file of the host is created, changed or read, and no fixed socket
// or state path is used. The collector under test is the real one
// (linkjournal.Collector with its real parsers and its real journal on
// disk); only its programs are run inside the namespace instead of on the
// host, and its time thresholds are shortened where a test could not wait
// for the real ones.

// linkJournalNetnsPrereqs skips with "NOT RUN" unless the test can run.
func linkJournalNetnsPrereqs(t *testing.T, bins ...string) {
	t.Helper()
	if os.Getenv("MERIDIAN_NETNS_TEST") != "1" || os.Getenv("MERIDIAN_NFT_TEST") != "1" {
		t.Skip("NOT RUN: runtime netns test; run as root with MERIDIAN_NETNS_TEST=1 MERIDIAN_NFT_TEST=1 (docs/verification.md)")
	}
	if os.Geteuid() != 0 {
		t.Skip("NOT RUN: needs root for network namespaces")
	}
	for _, bin := range append([]string{"ip"}, bins...) {
		if _, err := exec.LookPath(bin); err != nil {
			t.Skipf("NOT RUN: %s is not installed", bin)
		}
	}
}

// nsRunner runs the collector's programs inside one network namespace. It
// accepts exactly the two programs a namespace can answer for (wg, ip);
// systemctl is not a namespaced question and is refused.
type nsRunner struct {
	ns    string
	calls []string
}

func (r *nsRunner) Run(ctx context.Context, prog string, args ...string) (string, error) {
	r.calls = append(r.calls, prog+" "+strings.Join(args, " "))
	if prog != "wg" && prog != "ip" {
		return "", errors.New("the namespace lab does not run " + prog)
	}
	out, err := exec.CommandContext(ctx, "ip", append([]string{"netns", "exec", r.ns, prog}, args...)...).CombinedOutput()
	return string(out), err
}

// noRunner fails the test when the collector runs any program.
type noRunner struct{ t *testing.T }

func (r noRunner) Run(_ context.Context, prog string, args ...string) (string, error) {
	r.t.Errorf("the collector ran %s %s; this lab's object list names no program source", prog, strings.Join(args, " "))
	return "", errors.New("not in this lab")
}

func linkEvents(t *testing.T, j *linkjournal.Journal, q linkjournal.Query) []linkjournal.Event {
	t.Helper()
	q.Limit = linkjournal.PageMax
	p, err := j.Query(q)
	if err != nil {
		t.Fatal(err)
	}
	// Oldest first: the order things happened in.
	out := make([]linkjournal.Event, 0, len(p.Events))
	for i := len(p.Events) - 1; i >= 0; i-- {
		out = append(out, p.Events[i])
	}
	return out
}

func linkState(t *testing.T, j *linkjournal.Journal, kind, id string) linkjournal.CurrentObject {
	t.Helper()
	for _, o := range j.Current().Objects {
		if o.Kind == kind && o.ID == id {
			return o
		}
	}
	t.Fatalf("no object %s/%s in the journal's current view: %+v", kind, id, j.Current().Objects)
	return linkjournal.CurrentObject{}
}

// TestNetnsLinkJournalHandshake: a kernel WireGuard tunnel named like a
// gateway tunnel ("m00") between two namespaces over a veth underlay, read
// by the collector exactly as on a gateway ("wg show m00 latest-handshakes",
// "ip -4 -o route show table 102", both inside the namespace).
//
//	H1 the tunnel has handshaken: the first pass is a baseline (no event),
//	   the tunnel is "ok", the carrying path is the leg table 102 points at;
//	H2 the underlay is cut: once the last handshake is older than the
//	   threshold, one event "ok → stale" (handshake_timeout) with the
//	   kernel's handshake time as evidence;
//	H3 the peer is re-created while the underlay is still cut: no handshake
//	   can complete, the kernel reports none, one event "stale → never";
//	   the tunnel stays abnormal;
//	H4 the underlay is restored and traffic flows: a new handshake, one
//	   event "never → ok" with the time the tunnel was down;
//	H5 a collector restart (journal closed and reopened from disk, a new
//	   collector) with nothing changed: no event;
//	H6 the interface is deleted: one event "ok → absent".
//
// The stale threshold is 10 s here (180 s on a gateway). What this does NOT
// show: that 180 s is right for a healthy tunnel (WireGuard renews a
// session about every 120 s; a healthy tunnel is not watched for that long
// here), a WSS carrier (no unit in a namespace), and a real peer's outage.
func TestNetnsLinkJournalHandshake(t *testing.T) {
	linkJournalNetnsPrereqs(t, "wg", "ping")
	sfx := strconv.Itoa(os.Getpid() % 100000)
	gw, far := "mljgw"+sfx, "mljfar"+sfx
	sh := func(args ...string) (string, error) {
		out, err := exec.Command(args[0], args[1:]...).CombinedOutput()
		return string(out), err
	}
	must := func(args ...string) string {
		t.Helper()
		out, err := sh(args...)
		if err != nil {
			t.Fatalf("%s: %v\n%s", strings.Join(args, " "), err, out)
		}
		return out
	}
	in := func(ns string, args ...string) []string { return append([]string{"ip", "netns", "exec", ns}, args...) }
	t.Cleanup(func() {
		_ = exec.Command("ip", "netns", "del", gw).Run()
		_ = exec.Command("ip", "netns", "del", far).Run()
	})
	must("ip", "netns", "add", gw)
	must("ip", "netns", "add", far)
	if out, err := sh("ip", "-n", gw, "link", "add", "m00", "type", "wireguard"); err != nil {
		t.Skipf("NOT RUN: this kernel cannot create a WireGuard interface (%v: %s)", err, strings.TrimSpace(out))
	}
	// The underlay: a veth created inside the two namespaces (never in the
	// host's), documentation-range addresses.
	must("ip", "-n", gw, "link", "add", "ua", "type", "veth", "peer", "name", "ub", "netns", far)
	for _, c := range [][]string{
		in(gw, "ip", "link", "set", "lo", "up"), in(far, "ip", "link", "set", "lo", "up"),
		in(gw, "ip", "addr", "add", "198.18.0.1/30", "dev", "ua"), in(far, "ip", "addr", "add", "198.18.0.2/30", "dev", "ub"),
		in(gw, "ip", "link", "set", "ua", "up"), in(far, "ip", "link", "set", "ub", "up"),
		in(far, "ip", "link", "add", "wgfar", "type", "wireguard"),
	} {
		must(c...)
	}
	dir := t.TempDir()
	key := func(name string) (path, pub string) {
		priv := strings.TrimSpace(must("wg", "genkey"))
		path = filepath.Join(dir, name+".key")
		mustWrite(t, path, priv+"\n")
		if err := os.Chmod(path, 0o600); err != nil {
			t.Fatal(err)
		}
		cmd := exec.Command("wg", "pubkey")
		cmd.Stdin = strings.NewReader(priv + "\n")
		out, err := cmd.Output()
		if err != nil {
			t.Fatalf("wg pubkey: %v", err)
		}
		return path, strings.TrimSpace(string(out))
	}
	gwKey, gwPub := key("gw")
	farKey, farPub := key("far")
	addPeer := func() {
		must(in(gw, "wg", "set", "m00", "peer", farPub, "endpoint", "198.18.0.2:51820", "allowed-ips", "10.99.0.2/32", "persistent-keepalive", "1")...)
	}
	// The far side first, so the gateway side's first handshake finds a
	// listener.
	must(in(far, "wg", "set", "wgfar", "private-key", farKey, "listen-port", "51820", "peer", gwPub, "allowed-ips", "10.99.0.1/32")...)
	must(in(far, "ip", "addr", "add", "10.99.0.2/30", "dev", "wgfar")...)
	must(in(far, "ip", "link", "set", "wgfar", "up")...)
	must(in(gw, "wg", "set", "m00", "private-key", gwKey, "listen-port", "51821")...)
	addPeer()
	for _, c := range [][]string{
		in(gw, "ip", "addr", "add", "10.99.0.1/30", "dev", "m00"),
		in(gw, "ip", "link", "set", "m00", "up"),
		// Table 102 on the tunnel over the blackhole floor, as the gateway's
		// routes script leaves it.
		in(gw, "ip", "route", "add", "default", "dev", "m00", "table", "102"),
		in(gw, "ip", "route", "add", "blackhole", "default", "metric", "32767", "table", "102"),
	} {
		must(c...)
	}
	ping := func() bool {
		_, err := sh(in(gw, "ping", "-c", "1", "-W", "2", "-n", "10.99.0.2")...)
		return err == nil
	}
	up := false
	for i := 0; i < 8 && !up; i++ { // a lost first handshake is retried after 5 s
		up = ping()
	}
	if !up {
		t.Fatalf("setup: no ping through the tunnel:\n%s\n%s", must(in(gw, "wg", "show")...), must(in(far, "wg", "show")...))
	}

	const staleS = 10
	cfg := linkjournal.Config{Version: 1, Gateway: "gw", IntervalS: 2, SlowEvery: 1, HandshakeStaleS: staleS, UpstreamStaleS: 60, Mode: linkjournal.ModeSingle,
		Paths:   []linkjournal.PathConfig{{Name: "udp", Iface: "m00", Link: "gw-far", Peer: "far", Hub: "hub", Tier: "primary", Mode: "udp"}},
		Tunnels: []linkjournal.TunnelConfig{{Iface: "m00", Link: "gw-far", Mode: "udp", Peer: "far", PeerRole: "relay", KeepaliveS: 1}}}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	jdir := filepath.Join(dir, "journal")
	open := func() (*linkjournal.Journal, *linkjournal.Collector, *nsRunner) {
		j, err := linkjournal.Open(linkjournal.Options{Dir: jdir, FlapAfter: 16})
		if err != nil {
			t.Fatal(err)
		}
		r := &nsRunner{ns: gw}
		return j, linkjournal.NewCollector(cfg, j, linkjournal.Reader{Runner: r}), r
	}
	j, c, runner := open()
	defer func() { j.Close() }()
	step := func() { c.Step(context.Background(), time.Now()) }
	tunnelEvents := func() []linkjournal.Event {
		return linkEvents(t, j, linkjournal.Query{Kind: linkjournal.KindTunnel, ID: "m00"})
	}
	// until steps once a second until the tunnel's events are n, at most
	// for wait.
	until := func(what string, n int, wait time.Duration) []linkjournal.Event {
		t.Helper()
		deadline := time.Now().Add(wait)
		for {
			step()
			evs := tunnelEvents()
			if len(evs) >= n {
				if len(evs) != n {
					t.Fatalf("%s: %d tunnel events, want %d: %+v", what, len(evs), n, evs)
				}
				return evs
			}
			if time.Now().After(deadline) {
				t.Fatalf("%s: still %d tunnel events after %s (want %d); wg says:\n%s\ncurrent: %+v", what, len(evs), wait, n, must(in(gw, "wg", "show", "m00", "latest-handshakes")...), j.Current().Objects)
			}
			time.Sleep(time.Second)
		}
	}

	// H1: baseline.
	step()
	if evs := linkEvents(t, j, linkjournal.Query{}); len(evs) != 0 {
		t.Fatalf("H1: the first pass produced events: %+v", evs)
	}
	if o := linkState(t, j, linkjournal.KindTunnel, "m00"); o.State != linkjournal.TunnelOK || !o.SinceOpen || o.SourceAt == nil {
		t.Fatalf("H1: tunnel: %+v", o)
	}
	if o := linkState(t, j, linkjournal.KindUpstream, linkjournal.GatewayID); o.State != "udp" || o.Source != linkjournal.SourceRoute {
		t.Fatalf("H1: carrying path: %+v", o)
	}
	t.Logf("EVIDENCE H1 baseline: tunnel m00 ok (%s), carrying path udp, no event", linkState(t, j, linkjournal.KindTunnel, "m00").Evidence)

	// H2: cut the underlay; the handshake ages past the threshold.
	must(in(far, "ip", "link", "set", "ub", "down")...)
	cutAt := time.Now()
	evs := until("H2", 1, 40*time.Second)
	e := evs[0]
	if e.From != linkjournal.TunnelOK || e.To != linkjournal.TunnelStale || e.Reason != "handshake_timeout" || e.Source != linkjournal.SourceHandshake || e.Class != linkjournal.ClassTunnel ||
		e.SourceAt == nil || !e.PrevOpen || e.PrevForS == nil || e.AfterGap != nil || !strings.Contains(e.Evidence, "最近一次握手在") {
		t.Fatalf("H2: %+v", e)
	}
	// Recorded only once the kernel's handshake time is older than the
	// threshold, and soon after.
	if age := e.At.Sub(*e.SourceAt); age <= staleS*time.Second || age > (staleS+6)*time.Second {
		t.Fatalf("H2: recorded %s after the last handshake (threshold %d s)", age, staleS)
	}
	if ping() {
		t.Fatal("H2: the tunnel still passes traffic with the underlay cut")
	}
	t.Logf("EVIDENCE H2 stale: %s → %s at %s, %s after the cut; %s", e.From, e.To, e.At.Format(time.RFC3339), e.At.Sub(cutAt).Round(time.Second), e.Evidence)

	// H3: a fresh peer cannot handshake while the underlay is cut.
	must(in(gw, "wg", "set", "m00", "peer", farPub, "remove")...)
	addPeer()
	_ = ping()
	evs = until("H3", 2, 20*time.Second)
	if e := evs[1]; e.From != linkjournal.TunnelStale || e.To != linkjournal.TunnelNever || e.Reason != "no_handshake" {
		t.Fatalf("H3: %+v", e)
	}
	if o := linkState(t, j, linkjournal.KindTunnel, "m00"); o.Level != linkjournal.LevelAbnormal {
		t.Fatalf("H3: %+v", o)
	}
	t.Logf("EVIDENCE H3 no handshake over a cut underlay: %s → %s", evs[1].From, evs[1].To)

	// H4: the underlay is back; traffic brings a new handshake.
	must(in(far, "ip", "link", "set", "ub", "up")...)
	ok := false
	for i := 0; i < 15 && !ok; i++ {
		ok = ping()
	}
	if !ok {
		t.Fatalf("H4: no ping after the underlay came back:\n%s", must(in(gw, "wg", "show")...))
	}
	evs = until("H4", 3, 20*time.Second)
	if e := evs[2]; e.From != linkjournal.TunnelNever || e.To != linkjournal.TunnelOK || e.PrevForS == nil || e.PrevOpen || e.SourceAt == nil || e.SourceAt.Before(cutAt) {
		t.Fatalf("H4: %+v", e)
	}
	// From the first "stale" to the recovery: what the timeline shows as
	// the outage. It never includes time before the tunnel was seen stale.
	down := evs[2].At.Sub(evs[0].At)
	if down <= 0 || down > 90*time.Second || evs[2].At.Before(cutAt) {
		t.Fatalf("H4: outage of %s", down)
	}
	t.Logf("EVIDENCE H4 recovered: %s → %s; abnormal for %s in the timeline", evs[2].From, evs[2].To, down.Round(time.Second))

	// H5: restart with nothing changed.
	j.Close()
	j, c, _ = open()
	if st := j.Stats(); !st.Restored || st.Events < 3 {
		t.Fatalf("H5: the journal did not come back from disk: %+v", st)
	}
	step()
	step()
	if evs := linkEvents(t, j, linkjournal.Query{}); len(evs) != 3 {
		t.Fatalf("H5: a restart produced events: %+v", evs)
	}
	t.Logf("EVIDENCE H5 restart: %d events before and after, none added", 3)

	// H6: the interface goes away.
	must(in(gw, "ip", "link", "del", "m00")...)
	evs = until("H6", 4, 15*time.Second)
	if e := evs[3]; e.From != linkjournal.TunnelOK || e.To != linkjournal.TunnelAbsent || e.Reason != "no_interface" {
		t.Fatalf("H6: %+v", e)
	}
	// The carrying path lost its route with the interface.
	if o := linkState(t, j, linkjournal.KindUpstream, linkjournal.GatewayID); o.State != linkjournal.PathNone || o.Level != linkjournal.LevelAbnormal {
		t.Fatalf("H6: carrying path: %+v", o)
	}
	// Only the fixed read-only commands were run, inside the namespace.
	for _, call := range runner.calls {
		if call != "wg show m00 latest-handshakes" && call != "ip -4 -o route show table 102" {
			t.Fatalf("unexpected command: %q", call)
		}
	}
	// The journal's files: a root-only directory, 0600 files.
	if fi, err := os.Stat(jdir); err != nil || fi.Mode().Perm() != 0o700 {
		t.Fatalf("journal directory: %v %v", fi, err)
	}
	ents, _ := os.ReadDir(jdir)
	for _, ent := range ents {
		if fi, err := ent.Info(); err != nil || fi.Mode().Perm() != 0o600 {
			t.Fatalf("%s: %v %v", ent.Name(), fi, err)
		}
	}
	fmt.Println("meridian-netns-link-journal-handshake-test-ok")
}

// TestNetnsLinkJournalBackupSwitch runs the dual-hub lab of TestNetnsDualHub
// (the gateway's COMPILED failover script deciding with real pings in
// namespaces; see its comment for the lab and what it does not emulate) and
// reads the upstream record that script writes with the link journal's
// collector, configured from the gateway's COMPILED object list:
//
//	main       the first pass is a baseline: no event; carrying path "udp";
//	ix cut     the failover moved to the backup hub: one event
//	           "udp → backup" naming the backup hub; a collector restart
//	           right after it adds nothing;
//	all down   nothing answers: the path stays, the probe result changes:
//	           one event "ok → down";
//	main back  two events: "backup → udp" and "down → ok".
//
// The lab's tunnels are veth pairs, not WireGuard, and it has no units: the
// compiled list's tunnels and WSS carriers are left out here (the handshake
// test covers a real tunnel), so the collector runs no program at all. The
// gap and heartbeat thresholds are raised: the lab's phases take as long as
// its traffic checks do.
func TestNetnsLinkJournalBackupSwitch(t *testing.T) {
	linkJournalNetnsPrereqs(t, "nft", "ping", "bash", "python3")
	jdir := filepath.Join(t.TempDir(), "journal")
	var j *linkjournal.Journal
	var c *linkjournal.Collector
	defer func() {
		if j != nil {
			j.Close()
		}
	}()
	open := func(upstream string, b *Bundle) {
		cfg, err := linkjournal.ParseConfig([]byte(b.File("nodes/gw/" + strings.TrimPrefix(LinkJournalConfigPath, "/"))))
		if err != nil {
			t.Fatalf("the compiled object list: %v", err)
		}
		if cfg.Mode != linkjournal.ModeDual || len(cfg.Paths) < 2 {
			t.Fatalf("the compiled object list is not the dual-hub one: %+v", cfg)
		}
		cfg.Tunnels, cfg.WSS, cfg.Sniff, cfg.UpstreamStaleS = nil, nil, nil, 600
		j, err = linkjournal.Open(linkjournal.Options{Dir: jdir, GapAfter: 30 * time.Minute})
		if err != nil {
			t.Fatal(err)
		}
		c = linkjournal.NewCollector(cfg, j, linkjournal.Reader{UpstreamFile: upstream, Runner: noRunner{t}})
	}
	pathEvents := func() []linkjournal.Event { return linkEvents(t, j, linkjournal.Query{Class: linkjournal.ClassPath}) }
	phases := 0
	runNetnsDualHub(t, func(phase, upstream string, b *Bundle) {
		phases++
		if j == nil {
			open(upstream, b)
		}
		c.Step(context.Background(), time.Now())
		evs := pathEvents()
		carrying := linkState(t, j, linkjournal.KindUpstream, linkjournal.GatewayID)
		switch phase {
		case "main":
			if len(evs) != 0 || carrying.State != "udp" || carrying.Level != linkjournal.LevelOK || !carrying.SinceOpen || !strings.Contains(carrying.Evidence, "枢纽 ix（主枢纽）") {
				t.Fatalf("main: events %+v, carrying %+v", evs, carrying)
			}
			if h := linkState(t, j, linkjournal.KindHealth, linkjournal.GatewayID); h.State != linkjournal.HealthOK {
				t.Fatalf("main: probe result %+v", h)
			}
		case "ix cut":
			if len(evs) != 1 {
				t.Fatalf("ix cut: %d events: %+v", len(evs), evs)
			}
			e := evs[0]
			if e.Kind != linkjournal.KindUpstream || e.From != "udp" || e.To != "backup" || e.Reason != "on_backup" || e.Source != linkjournal.SourceUpstream ||
				!strings.Contains(e.Evidence, "枢纽 hkb（备用枢纽）") || e.SourceAt == nil || e.PrevForS == nil || !e.PrevOpen || e.AfterGap != nil {
				t.Fatalf("ix cut: %+v", e)
			}
			if carrying.Level != linkjournal.LevelAbnormal {
				t.Fatalf("ix cut: carrying %+v", carrying)
			}
			// A collector restart here: the checkpoint holds "backup", the
			// record says "backup": no event.
			j.Close()
			open(upstream, b)
			if st := j.Stats(); !st.Restored {
				t.Fatalf("ix cut: no checkpoint after a restart: %+v", st)
			}
			c.Step(context.Background(), time.Now())
			if got := pathEvents(); len(got) != 1 {
				t.Fatalf("ix cut: the restart produced events: %+v", got)
			}
		case "all down":
			if len(evs) != 2 || evs[1].Kind != linkjournal.KindHealth || evs[1].From != linkjournal.HealthOK || evs[1].To != linkjournal.HealthDown || carrying.State != "backup" {
				t.Fatalf("all down: events %+v, carrying %+v", evs, carrying)
			}
		case "main back":
			if len(evs) != 4 {
				t.Fatalf("main back: %d events: %+v", len(evs), evs)
			}
			var up, health *linkjournal.Event
			for i := 2; i < 4; i++ {
				switch evs[i].Kind {
				case linkjournal.KindUpstream:
					up = &evs[i]
				case linkjournal.KindHealth:
					health = &evs[i]
				}
			}
			if up == nil || up.From != "backup" || up.To != "udp" || up.PrevForS == nil || up.PrevOpen || health == nil || health.From != linkjournal.HealthDown || health.To != linkjournal.HealthOK ||
				carrying.State != "udp" || carrying.Level != linkjournal.LevelOK || carrying.SinceOpen {
				t.Fatalf("main back: events %+v, carrying %+v", evs, carrying)
			}
			// The time on the backup hub in the timeline is the time between
			// the two switches, as observed.
			if on := up.At.Sub(evs[0].At); on <= 0 || int64(on/time.Second) != *up.PrevForS {
				t.Fatalf("main back: on the backup hub for %s, the event says %d s", on, *up.PrevForS)
			}
		default:
			t.Fatalf("unknown phase %q", phase)
		}
		for _, e := range evs {
			t.Logf("EVIDENCE %s: %s %s: %s → %s (%s)", phase, e.At.Format("15:04:05"), e.Kind, e.From, e.To, e.Evidence)
		}
	})
	if phases != 4 {
		t.Fatalf("the lab reported %d phases, want 4", phases)
	}
	if got := linkEvents(t, j, linkjournal.Query{}); len(got) != 4 {
		t.Fatalf("the whole journal holds %d events, want the four path events: %+v", len(got), got)
	}
	fmt.Println("meridian-netns-link-journal-backup-test-ok")
}
