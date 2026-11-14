//go:build linux

package compile

import (
	"bufio"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/radowitz/meridian/internal/model"
	"github.com/radowitz/meridian/internal/sniff"
)

// TestNetnsSniff is the runtime proof of the name-sniffing forwarder
// (settings.sniff, render_sniff.go) on the compiled gateway ruleset and
// routes, with the forwarder itself (internal/sniff) running as its own uid
// (SniffUID, CAP_NET_ADMIN only) in the gateway namespace:
//
//	cli ──┐                               ┌── far: every exit, hub and resolver
//	ros ──┼── br (LAN "enp3s0") ── gw ──── tunnel ifaces (veth, arp off)
//	      └ (ROS: domestic resolver and server)   dev ── mra (remote device)
//
// The tunnel interfaces are veth pairs into one namespace "far" that owns
// the test servers, the exit and region-group resolver addresses and
// routes the transit prefixes back. Which exit a connection used is read at
// "far" from its source address: the transit address of the mark (the hub
// selects the exit by it). The LAN interface is not called eth0.
//
// Phases (each logged as EVIDENCE):
//
//	A  a flow established before the forwarder is enabled keeps its path
//	   across the ruleset change (only new SYNs are redirected);
//	B  two names on one shared address leave through their own targets (IPv4
//	   by HTTP Host and TLS SNI, IPv6), the client never asked the gateway's
//	   DNS (it connects to an address), and a keyword rule works;
//	C  no usable name: the connection gets exactly the classifier's target,
//	   including an address the resolver had learned into a rule's set
//	   (which the forwarder's own address view cannot see); with
//	   tcp_fwmark_accept off (no mark on the socket) it is refused;
//	D  each name is resolved only at its target's resolver: tunnelled names
//	   never reach the domestic resolver; a direct name is resolved there
//	   and leaves on the LAN NIC to ROS; a reject name is refused;
//	E  a remote-access device (mra) is intercepted the same way;
//	F  the forwarder's own output: unmarked, wrong-port, special-destination
//	   and wrongly marked DNS attempts are dropped (counter sniff_denied),
//	   a legal one passes; root's sockets are not affected;
//	G  hot rule update (nft load + pair rewrite + SIGHUP) under continuous
//	   connections: every connection lands on the old or the new target,
//	   none fails, none reaches ROS;
//	H  the forwarder killed: redirected connections are refused at once,
//	   nothing reaches far or ROS (no fallback to the address path).
//
// Throughout, ROS counts any packet to a foreign test destination (must
// stay 0).
//
// Root only, Linux only, opt-in: MERIDIAN_NETNS_TEST=1 (docs/verification.md).
func TestNetnsSniff(t *testing.T) {
	// Like netnsPrereqs, without ping (this test sends no ICMP).
	if os.Getenv("MERIDIAN_NETNS_TEST") != "1" {
		t.Skip("runtime netns test: run as root with MERIDIAN_NETNS_TEST=1 (docs/verification.md)")
	}
	if os.Geteuid() != 0 {
		t.Skip("needs root for network namespaces")
	}
	for _, bin := range []string{"ip", "nft", "bash", "setpriv"} {
		if _, err := exec.LookPath(bin); err != nil {
			t.Skipf("%s not installed", bin)
		}
	}
	l := newSniffLab(t, sniffLabTopo(t, "us"))
	l.run(t)
	fmt.Fprintln(os.Stderr, "meridian-netns-sniff-test-ok")
}

// sniffLabTopo: the remote-access example with the forwarder on, a LAN
// interface that is not eth0, documentation-range domestic resolver, and
// rules for two names on one shared address.
func sniffLabTopo(t *testing.T, bTarget string) model.Topology {
	topo, _ := raExample(t)
	topo = sniffLabBase(topo)
	topo = sniffRules(topo, "jp")
	topo.Rules = append([]model.Rule{
		{ID: "sn-a", Name: "a", Enabled: true, MatchType: model.MatchSuffix, MatchValue: "a.example.net", TargetGroup: "hk", Priority: -2},
		{ID: "sn-b", Name: "b", Enabled: true, MatchType: model.MatchSuffix, MatchValue: "b.example.net", TargetGroup: bTarget, Priority: -1},
	}, topo.Rules...)
	return sniffOn(topo)
}

// sniffLabBase: a LAN interface that is not eth0 and a domestic resolver
// in a documentation range.
func sniffLabBase(topo model.Topology) model.Topology {
	topo.Settings.LANInterface = "enp3s0"
	for i := range topo.Nodes {
		if topo.Nodes[i].Role == model.RoleGateway {
			topo.Nodes[i].LANInterface = "enp3s0"
		}
	}
	topo.Settings.DomesticDoT = []string{"198.18.0.53"}
	return topo
}

type sniffLab struct {
	t        *testing.T
	topo     model.Topology
	b        *Bundle
	dir, exe string
	lan, sfx string
	ns       map[string]string
	tunnels  []string
	west     string
	sniffCmd *exec.Cmd
	sniffLog string
	farDNS   *helperProc
	rosDNS   *helperProc
	farSrv   *helperProc
	rosSrv   *helperProc
	exits    []ExitPlan
	groups   []GroupPlan
	files    map[string]string // compiled sniff files written for the forwarder
}

func (l *sniffLab) sh(args ...string) (string, error) {
	out, err := exec.Command(args[0], args[1:]...).CombinedOutput()
	return string(out), err
}

func (l *sniffLab) must(args ...string) string {
	l.t.Helper()
	out, err := l.sh(args...)
	if err != nil {
		l.t.Fatalf("%s: %v\n%s", strings.Join(args, " "), err, out)
	}
	return out
}

func (l *sniffLab) in(n string, args ...string) []string {
	return append([]string{"ip", "netns", "exec", l.ns[n]}, args...)
}

func (l *sniffLab) write(name, body string) string {
	p := filepath.Join(l.dir, name)
	mustWrite(l.t, p, body)
	return p
}

// helperProc is a long-running helper (this test binary) in a namespace.
type helperProc struct {
	cmd *exec.Cmd
	mu  sync.Mutex
	out []string
}

func (h *helperProc) lines() []string {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]string(nil), h.out...)
}

func (l *sniffLab) helper(n, mode string, args []string, asSniff bool) *helperProc {
	l.t.Helper()
	cmdline := l.in(n)
	if asSniff {
		cmdline = append(cmdline, "setpriv", fmt.Sprintf("--reuid=%d", SniffUID), fmt.Sprintf("--regid=%d", SniffUID), "--clear-groups",
			"--inh-caps=+net_admin", "--ambient-caps=+net_admin", "--")
	}
	cmdline = append(cmdline, "env", "MERIDIAN_SNIFF_HELPER="+mode, "MERIDIAN_SNIFF_HELPER_ARGS="+strings.Join(args, "\x1f"), l.exe, "-test.run=^TestNetnsSniffHelper$")
	cmd := exec.Command(cmdline[0], cmdline[1:]...)
	pr, pw := io.Pipe()
	cmd.Stdout, cmd.Stderr = pw, pw
	h := &helperProc{cmd: cmd}
	if err := cmd.Start(); err != nil {
		l.t.Fatal(err)
	}
	go func() {
		sc := bufio.NewScanner(pr)
		for sc.Scan() {
			h.mu.Lock()
			h.out = append(h.out, sc.Text())
			h.mu.Unlock()
		}
	}()
	l.t.Cleanup(func() { _ = cmd.Process.Kill(); _, _ = cmd.Process.Wait(); pw.Close() })
	return h
}

// client runs one client connection in namespace n and returns its line.
func (l *sniffLab) client(n string, asSniff bool, args ...string) string {
	cmdline := l.in(n)
	if asSniff {
		cmdline = append(cmdline, "setpriv", fmt.Sprintf("--reuid=%d", SniffUID), fmt.Sprintf("--regid=%d", SniffUID), "--clear-groups",
			"--inh-caps=+net_admin", "--ambient-caps=+net_admin", "--")
	}
	cmdline = append(cmdline, "env", "MERIDIAN_SNIFF_HELPER=client", "MERIDIAN_SNIFF_HELPER_ARGS="+strings.Join(args, "\x1f"), l.exe, "-test.run=^TestNetnsSniffHelper$")
	out, _ := exec.Command(cmdline[0], cmdline[1:]...).CombinedOutput()
	for _, line := range strings.Split(string(out), "\n") {
		if strings.HasPrefix(line, "OK ") || strings.HasPrefix(line, "ERR ") {
			return line
		}
	}
	return "ERR no output: " + string(out)
}

func newSniffLab(t *testing.T, topo model.Topology) *sniffLab {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	b := mustCompile(t, topo)
	l := &sniffLab{t: t, topo: topo, b: b, exe: exe, lan: topo.Settings.LANInterface, dir: t.TempDir()}
	// The forwarder runs as SniffUID: it must reach its files.
	for _, d := range []string{filepath.Dir(l.dir), l.dir} {
		if err := os.Chmod(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	tunnels := mustTunnels(t, topo)
	l.exits = planExits(topo, tunnels)
	l.groups = planGroups(topo, l.exits)
	l.sfx = strconv.Itoa(os.Getpid() % 100000)
	l.ns = map[string]string{}
	for _, n := range []string{"sw", "gw", "ros", "cli", "dev", "far"} {
		l.ns[n] = "msn" + n + l.sfx
	}
	t.Cleanup(func() {
		for _, n := range l.ns {
			_ = exec.Command("ip", "netns", "del", n).Run()
		}
	})
	for _, n := range []string{"sw", "gw", "ros", "cli", "dev", "far"} {
		l.must("ip", "netns", "add", l.ns[n])
		l.must(l.in(n, "ip", "link", "set", "lo", "up")...)
	}
	in, must := l.in, l.must
	lan := l.lan
	must(in("sw", "ip", "link", "add", "br0", "type", "bridge", "mcast_snooping", "0")...)
	must(in("sw", "ip", "link", "set", "br0", "up")...)
	for _, h := range []string{"gw", "ros", "cli"} {
		a, p := "t"+h+l.sfx, "p"+h+l.sfx
		must("ip", "link", "add", a, "type", "veth", "peer", "name", p)
		must("ip", "link", "set", a, "netns", l.ns[h])
		must("ip", "link", "set", p, "netns", l.ns["sw"])
		must(in(h, "ip", "link", "set", a, "name", lan)...)
		must(in("sw", "ip", "link", "set", p, "master", "br0", "up")...)
		must(in(h, "sysctl", "-qw", "net.ipv6.conf."+lan+".accept_ra=0")...)
		must(in(h, "ip", "link", "set", lan, "up")...)
	}
	// ROS: the LAN's router, the domestic resolver (198.18.0.53) and a
	// domestic server (198.18.0.2); counts any packet to a foreign test
	// destination.
	must(in("ros", "ip", "addr", "add", "192.168.100.1/24", "dev", lan)...)
	must(in("ros", "ip", "addr", "add", "fe80::1/64", "dev", lan, "nodad")...)
	must(in("ros", "ip", "link", "add", "inet0", "type", "dummy")...)
	must(in("ros", "ip", "link", "set", "inet0", "up")...)
	for _, a := range []string{"198.18.0.53/32", "198.18.0.2/32"} {
		must(in("ros", "ip", "addr", "add", a, "dev", "inet0")...)
	}
	must(in("ros", "ip", "-6", "route", "add", "2001:db8:100::/64", "dev", lan)...)
	must(in("ros", "nft", "-f", l.write("ros.nft", `table inet sink {
  counter foreign {}
  chain pre {
    type filter hook prerouting priority -300; policy accept;
    ip daddr { 203.0.113.0/24, 198.51.100.0/24 } counter name "foreign"
    ip6 daddr 2001:db8:f::/48 counter name "foreign"
  }
}
`))...)
	// Client.
	must(in("cli", "ip", "addr", "add", "192.168.100.50/24", "dev", lan)...)
	must(in("cli", "ip", "addr", "add", "2001:db8:100::50/64", "dev", lan, "nodad")...)
	must(in("cli", "ip", "route", "add", "default", "via", "192.168.100.88")...)
	must(in("cli", "ip", "-6", "route", "add", "default", "via", "fe80::88", "dev", lan)...)
	// Gateway LAN.
	must(in("gw", "ip", "addr", "add", "192.168.100.88/24", "dev", lan)...)
	must(in("gw", "ip", "addr", "add", "fe80::88/64", "dev", lan, "nodad")...)
	must(in("gw", "ip", "addr", "add", "2001:db8:100::88/64", "dev", lan, "nodad")...)
	// Remote device behind mra.
	must("ip", "link", "add", "ra"+l.sfx, "type", "veth", "peer", "name", "rd"+l.sfx)
	must("ip", "link", "set", "ra"+l.sfx, "netns", l.ns["gw"])
	must("ip", "link", "set", "rd"+l.sfx, "netns", l.ns["dev"])
	must(in("gw", "ip", "link", "set", "ra"+l.sfx, "name", "mra")...)
	must(in("gw", "bash", l.write("ra-up.sh", "set -euo pipefail\n"+remoteUpCommands(planRemote(topo))))...)
	must(in("dev", "ip", "link", "set", "rd"+l.sfx, "up")...)
	must(in("dev", "ip", "addr", "add", "10.67.0.2/24", "dev", "rd"+l.sfx)...)
	must(in("dev", "ip", "addr", "add", "fd67::2/64", "dev", "rd"+l.sfx, "nodad")...)
	must(in("dev", "ip", "route", "add", "default", "via", "10.67.0.1")...)
	must(in("dev", "ip", "-6", "route", "add", "default", "via", "fd67::1")...)
	// Tunnels: veth pairs into far, both ends one MAC with ARP off (an L3
	// link like WireGuard: no neighbour discovery for the destinations).
	addrLine := regexp.MustCompile(`(?m)^Address\s*=\s*(.+)$`)
	for path := range b.Files {
		if strings.HasPrefix(path, "nodes/gw/etc/wireguard/") && filepath.Base(path) != "mra.conf" {
			l.tunnels = append(l.tunnels, strings.TrimSuffix(filepath.Base(path), ".conf"))
		}
	}
	sortStrings(l.tunnels)
	for i, tun := range l.tunnels {
		x, y := fmt.Sprintf("sx%d%s", i, l.sfx), fmt.Sprintf("sy%d%s", i, l.sfx)
		mac := fmt.Sprintf("02:6e:00:00:%02x:01", i+1)
		must("ip", "link", "add", x, "type", "veth", "peer", "name", y)
		must("ip", "link", "set", x, "netns", l.ns["gw"])
		must("ip", "link", "set", y, "netns", l.ns["far"])
		for _, e := range []struct{ n, name string }{{"gw", x}, {"far", y}} {
			must(in(e.n, "ip", "link", "set", e.name, "name", tun)...)
			must(in(e.n, "ip", "link", "set", "dev", tun, "address", mac, "arp", "off")...)
			_, _ = l.sh(in(e.n, "ip", "link", "set", "dev", tun, "addrgenmode", "none")...)
		}
		m := addrLine.FindStringSubmatch(b.File("nodes/gw/etc/wireguard/" + tun + ".conf"))
		if m == nil {
			t.Fatalf("%s.conf has no Address", tun)
		}
		for _, a := range strings.Split(m[1], ",") {
			if a = strings.TrimSpace(a); a != "" {
				args := []string{"ip", "addr", "add", a, "dev", tun}
				if strings.Contains(a, ":") {
					args = append(args, "nodad")
				}
				must(in("gw", args...)...)
			}
		}
		must(in("gw", "ip", "link", "set", tun, "up")...)
		must(in("far", "ip", "link", "set", tun, "up")...)
	}
	routes := strings.ReplaceAll(b.File("nodes/gw/usr/local/sbin/meridian-routes.sh"), "/run/meridian", filepath.Join(l.dir, "gwrun"))
	if m := regexp.MustCompile(`(?m)^# meridian-west-preferred: \S+ (\S+)$`).FindStringSubmatch(routes); m != nil {
		l.west = m[1]
	} else {
		t.Fatal("no preferred west interface in the routes script")
	}
	must(in("gw", "ip", "route", "add", "default", "via", "192.168.100.1", "dev", lan)...)
	must(in("gw", "ip", "-6", "route", "add", "default", "via", "fe80::1", "dev", lan)...)
	must(in("gw", "bash", l.write("routes.sh", routes))...)
	must(in("gw", "sysctl", "-qw", "net.ipv4.ip_forward=1")...)
	must(in("gw", "sysctl", "-qw", "net.ipv6.conf.all.forwarding=1")...)
	// far: the test servers and every resolver of the target file on lo,
	// the way home through the preferred tunnel.
	// far stands for the relays, the hubs and the exits together and sends
	// everything home through one tunnel, so a connection the gateway
	// shares onto another leg reaches far on an interface its reverse
	// route does not use. The far interfaces carry no IPv4 address, and
	// on such an interface any rp_filter but 0 drops that packet (even
	// loose mode); a new namespace copies the host's values, which are 2
	// on a host Meridian is installed on. Real relays answer on the leg a
	// connection came in on, so this is the test's far end only.
	must(in("far", "sysctl", "-qw", "net.ipv4.conf.all.rp_filter=0")...)
	must(in("far", "sysctl", "-qw", "net.ipv4.conf.default.rp_filter=0")...)
	for _, tun := range l.tunnels {
		must(in("far", "sysctl", "-qw", "net.ipv4.conf."+tun+".rp_filter=0")...)
	}
	for _, a := range []string{"203.0.113.110/32", "203.0.113.111/32", "203.0.113.115/32", "203.0.113.200/32", "198.51.100.30/32"} {
		must(in("far", "ip", "addr", "add", a, "dev", "lo")...)
	}
	must(in("far", "ip", "addr", "add", "2001:db8:f::10/128", "dev", "lo", "nodad")...)
	for _, r := range l.farResolvers() {
		must(in("far", "ip", "addr", "add", r+"/128", "dev", "lo", "nodad")...)
	}
	for _, p := range []string{"10.66.0.0/16", "192.168.100.0/24", "10.67.0.0/24"} {
		must(in("far", "ip", "route", "add", p, "dev", l.west)...)
	}
	for _, p := range []string{"fd66::/48", "2001:db8:100::/64", "fd67::/64"} {
		must(in("far", "ip", "-6", "route", "add", p, "dev", l.west)...)
	}
	return l
}

// targetsFile is the compiled target file.
func (l *sniffLab) targetsFile() sniff.TargetsFile {
	var tf sniff.TargetsFile
	if err := json.Unmarshal([]byte(l.b.File("nodes/gw/"+strings.TrimPrefix(SniffTargetsPath, "/"))), &tf); err != nil {
		l.t.Fatal(err)
	}
	return tf
}

// farResolvers: the exit and group resolver addresses (not the domestic).
func (l *sniffLab) farResolvers() []string {
	var out []string
	for _, tg := range l.targetsFile().Targets {
		if tg.Name == "direct" {
			continue
		}
		for _, r := range tg.Resolvers {
			out = append(out, netip.MustParseAddrPort(r).Addr().String())
		}
	}
	return out
}

// target is where a rule to group g goes: (transit v4, transit v6,
// resolver address).
func (l *sniffLab) target(g string) (string, string, string) {
	gp, ok := groupByID(l.groups, g)
	if !ok {
		l.t.Fatalf("no group %s", g)
	}
	tg, ok := groupTarget(gp)
	if !ok {
		l.t.Fatalf("group %s has no target", g)
	}
	if tg.Group != nil {
		return tg.Group.TransitV4, tg.Group.TransitV6, tg.Group.Resolver
	}
	return tg.Exit.TransitV4, tg.Exit.TransitV6, tg.Exit.DNSULA
}

func (l *sniffLab) rosForeign() int {
	out := l.must(l.in("ros", "nft", "list", "counter", "inet", "sink", "foreign")...)
	m := regexp.MustCompile(`packets (\d+)`).FindStringSubmatch(out)
	v, _ := strconv.Atoi(m[1])
	return v
}

func (l *sniffLab) gwCounter(name string) int {
	out := l.must(l.in("gw", "nft", "list", "counter", "inet", "meridian", name)...)
	m := regexp.MustCompile(`packets (\d+)`).FindStringSubmatch(out)
	v, _ := strconv.Atoi(m[1])
	return v
}

func (l *sniffLab) diag() {
	for _, c := range [][]string{
		{"nft", "list", "ruleset"}, {"ip", "-4", "rule"}, {"ip", "-6", "rule"}, {"ip", "route", "show", "table", "102"},
		{"ip", "route"}, {"ip", "-6", "route"}, {"ss", "-tanpe"}, {"sysctl", "net.ipv4.tcp_fwmark_accept"},
	} {
		out, err := l.sh(l.in("gw", c...)...)
		l.t.Logf("DIAG gw$ %s (err=%v)\n%s", strings.Join(c, " "), err, out)
	}
	if l.sniffLog != "" {
		b, _ := os.ReadFile(l.sniffLog)
		l.t.Logf("DIAG forwarder log:\n%s", b)
	}
	for _, h := range []*helperProc{l.farDNS, l.rosDNS, l.farSrv, l.rosSrv} {
		if h != nil {
			l.t.Logf("DIAG helper %v:\n%s", h.cmd.Args[len(h.cmd.Args)-3:], strings.Join(h.lines(), "\n"))
		}
	}
}

// writeSniffFiles writes the forwarder's pair from bundle b into the lab
// directory (temp file + rename, like the install) and returns the args.
func (l *sniffLab) writeSniffFiles(b *Bundle) []string {
	l.t.Helper()
	gw := "nodes/gw/"
	for _, f := range []struct{ src, dst string }{{DecidePath, "decide.json"}, {SniffTargetsPath, "targets.json"}} {
		tmp := filepath.Join(l.dir, "."+f.dst)
		mustWrite(l.t, tmp, b.File(gw+strings.TrimPrefix(f.src, "/")))
		if err := os.Rename(tmp, filepath.Join(l.dir, f.dst)); err != nil {
			l.t.Fatal(err)
		}
	}
	unit := b.File(gw + "etc/systemd/system/" + SniffUnit)
	m := regexp.MustCompile(`(?m)^ExecStart=/usr/local/bin/meridian sniff (.+)$`).FindStringSubmatch(unit)
	if m == nil {
		l.t.Fatal("no ExecStart in the unit")
	}
	args := strings.Fields(m[1])
	repl := map[string]string{
		DecidePath: filepath.Join(l.dir, "decide.json"), SniffTargetsPath: filepath.Join(l.dir, "targets.json"),
		"/var/lib/meridian": filepath.Join(l.dir, "lists"), SniffStatusSocket: filepath.Join(l.dir, "run", "status.sock"),
	}
	for i, a := range args {
		if v, ok := repl[a]; ok {
			args[i] = v
		}
	}
	return args
}

func (l *sniffLab) startSniff(args []string) {
	l.t.Helper()
	l.sniffLog = filepath.Join(l.dir, "sniff.log")
	logf, err := os.Create(l.sniffLog)
	if err != nil {
		l.t.Fatal(err)
	}
	cmdline := l.in("gw", "setpriv", fmt.Sprintf("--reuid=%d", SniffUID), fmt.Sprintf("--regid=%d", SniffUID), "--clear-groups",
		"--inh-caps=+net_admin", "--ambient-caps=+net_admin", "--",
		"env", "MERIDIAN_SNIFF_HELPER=sniff", "MERIDIAN_SNIFF_HELPER_ARGS="+strings.Join(args, "\x1f"), l.exe, "-test.run=^TestNetnsSniffHelper$")
	cmd := exec.Command(cmdline[0], cmdline[1:]...)
	cmd.Stdout, cmd.Stderr = logf, logf
	if err := cmd.Start(); err != nil {
		l.t.Fatal(err)
	}
	l.sniffCmd = cmd
	l.t.Cleanup(func() { _ = cmd.Process.Kill(); _, _ = cmd.Process.Wait(); logf.Close() })
	for i := 0; i < 200; i++ {
		b, _ := os.ReadFile(l.sniffLog)
		if strings.Contains(string(b), sniff.ReadyMarker) {
			return
		}
		if strings.Contains(string(b), "meridian-sniff-failed") {
			l.t.Fatalf("forwarder failed to start:\n%s", b)
		}
		time.Sleep(50 * time.Millisecond)
	}
	b, _ := os.ReadFile(l.sniffLog)
	l.t.Fatalf("forwarder not ready:\n%s", b)
}

// sniffPID is the forwarder's own pid (setpriv and env exec into it).
func (l *sniffLab) sniffPID() int { return l.sniffCmd.Process.Pid }

// TestNetnsSniffRelaySharing: with two relays sharing the main path, the
// forwarder's own exit-marked connections get a relay from relay_assign
// exactly like forwarded ones (chain sniff_route): they leave on more than
// one relay leg, each with the mark's transit source; after the failover
// shell's share_apply moves every new connection to the backup hub, new
// forwarder connections leave on the backup leg only. The tunnels are veth
// pairs into one namespace that counts SYNs per interface.
//
// Root only, Linux only, opt-in: MERIDIAN_NETNS_TEST=1.
func TestNetnsSniffRelaySharing(t *testing.T) {
	if os.Getenv("MERIDIAN_NETNS_TEST") != "1" {
		t.Skip("runtime netns test: run as root with MERIDIAN_NETNS_TEST=1 (docs/verification.md)")
	}
	if os.Geteuid() != 0 {
		t.Skip("needs root for network namespaces")
	}
	for _, bin := range []string{"ip", "nft", "bash", "setpriv"} {
		if _, err := exec.LookPath(bin); err != nil {
			t.Skipf("%s not installed", bin)
		}
	}
	topo := sniffOn(sniffLabBase(sharedRAExample(t)))
	if !topo.RelaySharing() {
		t.Fatal("the example must share relays")
	}
	l := newSniffLab(t, topo)
	failed := true
	defer func() {
		if failed {
			l.diag()
		}
	}()
	in, must := l.in, l.must
	sp := planShare(topo, mustTunnels(t, topo))
	if sp == nil || sp.Backup == nil {
		t.Fatal("no relay-sharing plan with a backup hub")
	}
	var obs strings.Builder
	obs.WriteString("table inet legs {\n")
	for _, tun := range l.tunnels {
		fmt.Fprintf(&obs, "  counter %s {}\n", tun)
	}
	obs.WriteString("  chain pre {\n    type filter hook prerouting priority -300; policy accept;\n")
	for _, tun := range l.tunnels {
		fmt.Fprintf(&obs, "    iifname %q ip daddr 203.0.113.110 tcp flags syn counter name %q\n", tun, tun)
	}
	obs.WriteString("  }\n}\n")
	must(in("far", "nft", "-f", l.write("legs.nft", obs.String()))...)
	legs := func() map[string]int {
		out := map[string]int{}
		for _, tun := range l.tunnels {
			o := must(in("far", "nft", "list", "counter", "inet", "legs", tun)...)
			m := regexp.MustCompile(`packets (\d+)`).FindStringSubmatch(o)
			v, _ := strconv.Atoi(m[1])
			out[tun] = v
		}
		return out
	}
	def, _ := defaultExit(topo, l.groups)
	want := def.Exit.TransitV4
	if def.Group != nil {
		want = def.Group.TransitV4
	}
	var res []string
	for _, r := range l.farResolvers() {
		res = append(res, "["+r+"]:53")
	}
	l.farDNS = l.helper("far", "dns", []string{strings.Join(res, ","), "z.example.net=203.0.113.110"}, false)
	l.farSrv = l.helper("far", "server", []string{":80"}, false)
	nftOn := l.write("on.nft", l.b.File("nodes/gw/etc/nftables.d/meridian.nft"))
	must(in("gw", "nft", "-f", nftOn)...)
	must(in("gw", "sysctl", "-qw", "net.ipv4.tcp_fwmark_accept=1")...)
	for _, d := range []string{"lists", "run"} {
		if err := os.MkdirAll(filepath.Join(l.dir, d), 0o777); err != nil {
			t.Fatal(err)
		}
		_ = os.Chmod(filepath.Join(l.dir, d), 0o777)
	}
	l.startSniff(l.writeSniffFiles(l.b))
	time.Sleep(500 * time.Millisecond)
	before := legs()
	for i := 0; i < 24; i++ {
		got := l.client("cli", false, "203.0.113.110:80", "http", "z.example.net")
		if peerOf(got) != want {
			t.Fatalf("connection %d: %q, want peer %s", i, got, want)
		}
	}
	after := legs()
	used := 0
	for _, r := range sp.Relays {
		for _, lg := range r.Legs {
			if after[lg.Iface()] > before[lg.Iface()] {
				used++
			}
		}
	}
	t.Logf("EVIDENCE relay sharing: forwarder SYNs per tunnel %v -> %v (transit source %s)", before, after, want)
	if used < 2 {
		t.Fatalf("the forwarder's connections used %d relay legs, want both relays", used)
	}
	if after[sp.Backup.Tun.Iface()] != before[sp.Backup.Tun.Iface()] {
		t.Fatal("a forwarder connection used the backup hub while the relays carry")
	}
	// Hub failover: every new connection to the backup hub (share_apply,
	// as the failover loop does).
	var args []string
	for _, r := range sp.Relays {
		args = append(args, shQuote(r.Legs[0].Iface()), "0", "0")
	}
	script := "set -u\n" + sharePrelude(sp) + "share_apply backup backup " + strings.Join(args, " ") + " 0\n"
	script = strings.ReplaceAll(script, "/run/meridian", filepath.Join(l.dir, "gwrun"))
	must(in("gw", "bash", l.write("backup.sh", script))...)
	before = legs()
	for i := 0; i < 8; i++ {
		if got := l.client("cli", false, "203.0.113.110:80", "http", "z.example.net"); peerOf(got) != want {
			t.Fatalf("backup: %q", got)
		}
	}
	after = legs()
	t.Logf("EVIDENCE backup hub: forwarder SYNs per tunnel %v -> %v", before, after)
	for tun := range after {
		if tun != sp.Backup.Tun.Iface() && after[tun] != before[tun] {
			t.Fatalf("after the switch to the backup hub a forwarder connection left on %s", tun)
		}
	}
	if after[sp.Backup.Tun.Iface()]-before[sp.Backup.Tun.Iface()] < 8 {
		t.Fatal("the forwarder's connections did not follow the switch to the backup hub")
	}
	failed = false
	fmt.Fprintln(os.Stderr, "meridian-netns-sniff-sharing-test-ok")
}

func peerOf(line string) string {
	m := regexp.MustCompile(`peer=(\S+)`).FindStringSubmatch(line)
	if m == nil {
		return ""
	}
	return m[1]
}

func (l *sniffLab) run(t *testing.T) {
	failed := true
	defer func() {
		if failed {
			l.diag()
			if os.Getenv("MERIDIAN_SNIFF_PAUSE") != "" {
				fmt.Fprintln(os.Stderr, "PAUSED", l.ns)
				time.Sleep(10 * time.Minute)
			}
		}
	}()
	in, must := l.in, l.must
	hk4, hk6, hkRes := l.target("hk")
	us4, _, usRes := l.target("us")
	jp4, _, jpRes := l.target("jp")
	t.Logf("EVIDENCE targets: hk transit %s/%s resolver %s; us transit %s resolver %s; jp transit %s resolver %s", hk4, hk6, hkRes, us4, usRes, jp4, jpRes)
	if hk4 == us4 || us4 == jp4 || hk4 == jp4 {
		t.Fatal("the lab needs three distinct targets")
	}

	// Servers and resolvers.
	answers := "a.example.net=203.0.113.110,2001:db8:f::10;b.example.net=203.0.113.110;x.stream-cdn.example.com=203.0.113.111;www.home.example.org=198.18.0.2"
	var farListen []string
	for _, r := range l.farResolvers() {
		farListen = append(farListen, "["+r+"]:53")
	}
	l.farDNS = l.helper("far", "dns", []string{strings.Join(farListen, ","), answers}, false)
	l.rosDNS = l.helper("ros", "dns", []string{"198.18.0.53:53", answers}, false)
	l.farSrv = l.helper("far", "server", []string{":80,:443"}, false)
	l.rosSrv = l.helper("ros", "server", []string{"198.18.0.2:80,198.18.0.2:443"}, false)
	time.Sleep(500 * time.Millisecond)

	// A. A flow established before the forwarder: the ruleset without it.
	off := l.topo
	s := *off.Settings.Sniff
	s.Enabled = false
	off.Settings.Sniff = &s
	bOff := mustCompile(t, off)
	must(in("gw", "nft", "-f", l.write("off.nft", bOff.File("nodes/gw/etc/nftables.d/meridian.nft")))...)
	long := l.helper("cli", "long", []string{"203.0.113.111:80", "c.example.org"}, false)
	waitLine(t, long, "STARTED", 5*time.Second)
	nftOn := l.write("on.nft", l.b.File("nodes/gw/etc/nftables.d/meridian.nft"))
	must(in("gw", "nft", "-c", "-f", nftOn)...)
	must(in("gw", "nft", "-f", nftOn)...)
	must(in("gw", "sysctl", "-qw", "net.ipv4.tcp_fwmark_accept=1")...)
	if err := os.MkdirAll(filepath.Join(l.dir, "lists"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(l.dir, "run"), 0o777); err != nil {
		t.Fatal(err)
	}
	_ = os.Chmod(filepath.Join(l.dir, "run"), 0o777)
	l.startSniff(l.writeSniffFiles(l.b))
	time.Sleep(time.Second)
	if line := waitLine(t, long, "ECHO", 5*time.Second); !strings.Contains(line, "after=") {
		t.Fatalf("A: the flow established before the install broke: %s", line)
	}
	t.Logf("EVIDENCE A established flow kept across enabling the forwarder: %v", long.lines())
	_ = long.cmd.Process.Kill()

	ros0 := l.rosForeign()
	expect := func(phase, got, want string) {
		t.Helper()
		if !strings.HasPrefix(got, "OK ") || peerOf(got) != want {
			t.Fatalf("%s: got %q, want peer %s", phase, got, want)
		}
		t.Logf("EVIDENCE %s: %s", phase, got)
	}

	// B. Shared address, two names, two targets; TLS and IPv6; keyword.
	expect("B http a.example.net @203.0.113.110 -> hk", l.client("cli", false, "203.0.113.110:80", "http", "a.example.net"), hk4)
	expect("B http b.example.net @203.0.113.110 -> us", l.client("cli", false, "203.0.113.110:80", "http", "b.example.net"), us4)
	expect("B tls a.example.net @203.0.113.110 -> hk", l.client("cli", false, "203.0.113.110:443", "tls", "a.example.net"), hk4)
	expect("B tls b.example.net @203.0.113.110 -> us", l.client("cli", false, "203.0.113.110:443", "tls", "b.example.net"), us4)
	// An IPv6 client: over IPv6 when the target carries IPv6, else the
	// forwarder connects over IPv4 (the target file's ipv6 flag).
	want6 := hk4
	for _, tg := range l.targetsFile().Targets {
		if tg.Mark == l.markOf("hk") && tg.IPv6 {
			want6 = hk6
		}
	}
	expect("B ipv6 client a.example.net @[2001:db8:f::10] -> hk", l.client("cli", false, "[2001:db8:f::10]:80", "http", "a.example.net"), want6)
	expect("B keyword x.stream-cdn.example.com -> jp", l.client("cli", false, "203.0.113.111:443", "tls", "x.stream-cdn.example.com"), jp4)

	// C. No usable name: the classifier's target, exactly.
	expect("C no name, CIDR rule 203.0.113.200 -> jp", l.client("cli", false, "203.0.113.200:443", "raw", "SSH-2.0-test"), jp4)
	set := regexp.MustCompile(`(?m)^\s*ip daddr @(r\d+) meta mark set 0x0*` + strconv.FormatUint(uint64(l.markOf("hk")), 16) + ` return`).FindStringSubmatch(l.b.File("nodes/gw/etc/nftables.d/meridian.nft"))
	if set == nil {
		t.Fatal("no classify set of the hk rule")
	}
	must(in("gw", "nft", "add", "element", "inet", "meridian", set[1], "{ 203.0.113.115 }")...)
	expect("C no name, address learned into the hk rule's set -> hk (parity with classify)", l.client("cli", false, "203.0.113.115:443", "raw", "SSH-2.0-test"), hk4)
	expect("C no name, unknown address -> default group", l.client("cli", false, "203.0.113.111:443", "raw", "SSH-2.0-test"), hk4)
	must(in("gw", "sysctl", "-qw", "net.ipv4.tcp_fwmark_accept=0")...)
	if got := l.client("cli", false, "203.0.113.115:443", "raw", "SSH-2.0-test"); strings.HasPrefix(got, "OK ") {
		t.Fatalf("C: without the SYN's mark a nameless connection was forwarded: %s", got)
	} else {
		t.Logf("EVIDENCE C without tcp_fwmark_accept (no mark on the socket) the nameless connection is refused: %s", got)
	}
	expect("C named connections still work without the socket mark", l.client("cli", false, "203.0.113.110:80", "http", "b.example.net"), us4)
	must(in("gw", "sysctl", "-qw", "net.ipv4.tcp_fwmark_accept=1")...)

	// D. DNS isolation, direct, reject.
	expect("D direct www.home.example.org -> ROS from the gateway's LAN address", l.client("cli", false, "203.0.113.110:80", "http", "www.home.example.org"), "192.168.100.88")
	if got := l.client("cli", false, "203.0.113.110:443", "tls", "x.ads.example.com"); strings.HasPrefix(got, "OK ") {
		t.Fatalf("D: reject rule forwarded: %s", got)
	}
	for _, q := range l.rosDNS.lines() {
		if strings.HasPrefix(q, "Q ") && !strings.Contains(q, "name=www.home.example.org") {
			t.Fatalf("D: a tunnelled name reached the domestic resolver: %s", q)
		}
	}
	saw := map[string]string{}
	for _, q := range l.farDNS.lines() {
		if m := regexp.MustCompile(`server=\[?([^\]\s]+?)\]?:53 from=\S+ name=(\S+)`).FindStringSubmatch(q); m != nil {
			if prev, ok := saw[m[2]]; ok && prev != m[1] {
				t.Fatalf("D: %s asked at two resolvers (%s, %s)", m[2], prev, m[1])
			}
			saw[m[2]] = m[1]
		}
	}
	if saw["a.example.net"] != hkRes || saw["b.example.net"] != usRes || saw["x.stream-cdn.example.com"] != jpRes || saw["www.home.example.org"] != "" {
		t.Fatalf("D: names asked at the wrong resolvers: %v", saw)
	}
	t.Logf("EVIDENCE D resolvers asked: %v; domestic resolver saw only the direct name: %v", saw, l.rosDNS.lines())

	// E. Remote access.
	expect("E remote device b.example.net -> us", l.client("dev", false, "203.0.113.110:80", "http", "b.example.net"), us4)

	// F. The forwarder's own output.
	d0 := l.gwCounter("sniff_denied")
	for _, c := range []struct{ what, mark, addr string }{
		{"unmarked", "0", "203.0.113.110:80"},
		{"legal mark, port not sniffed", fmt.Sprint(l.markOf("hk")), "203.0.113.110:8080"},
		{"legal mark, private destination", fmt.Sprint(l.markOf("hk")), "192.168.100.1:80"},
		{"mark outside every target", "0x1ff", "203.0.113.110:80"},
		{"DNS to the domestic resolver unmarked", "0", "dns:198.18.0.53:53"},
		{"DNS to a group resolver with the wrong mark", "0x64", "dns:[" + hkRes + "]:53"},
	} {
		got := l.client("gw", true, c.addr, "mark", c.mark)
		if strings.HasPrefix(got, "OK ") {
			t.Fatalf("F: forwarder output %s passed: %s", c.what, got)
		}
		t.Logf("EVIDENCE F forwarder output refused (%s): %s", c.what, got)
	}
	if d := l.gwCounter("sniff_denied") - d0; d < 6 {
		t.Fatalf("F: sniff_denied counted %d drops, want >= 6", d)
	}
	expect("F legal forwarder output (hk mark, sniffed port)", l.client("gw", true, "203.0.113.110:80", "mark", fmt.Sprint(l.markOf("hk"))), hk4)
	if got := l.client("gw", false, "198.18.0.2:80", "http", "root.example.org"); !strings.HasPrefix(got, "OK ") {
		t.Fatalf("F: root's own unmarked connection was affected: %s", got)
	}

	// G. Hot update under traffic: b.example.net moves from us to jp.
	topo2 := sniffLabTopo(t, "jp")
	b2 := mustCompile(t, topo2)
	var mu sync.Mutex
	var results []string
	stop := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
			}
			r := l.client("cli", false, "203.0.113.110:80", "http", "b.example.net")
			mu.Lock()
			results = append(results, r)
			mu.Unlock()
		}
	}()
	time.Sleep(time.Second)
	nft2 := l.write("on2.nft", b2.File("nodes/gw/etc/nftables.d/meridian.nft"))
	must(in("gw", "nft", "-c", "-f", nft2)...)
	must(in("gw", "nft", "-f", nft2)...)
	l.writeSniffFiles(b2)
	if err := syscall.Kill(l.sniffPID(), syscall.SIGHUP); err != nil {
		t.Fatal(err)
	}
	time.Sleep(2 * time.Second)
	close(stop)
	wg.Wait()
	nOld, nNew := 0, 0
	for _, r := range results {
		switch peerOf(r) {
		case us4:
			if nNew > 0 {
				t.Fatalf("G: a connection went to the old target after the new one was in use: %v", results)
			}
			nOld++
		case jp4:
			nNew++
		default:
			t.Fatalf("G: a connection during the update failed or went elsewhere: %q (all %v)", r, results)
		}
	}
	if nOld == 0 || nNew == 0 {
		t.Fatalf("G: want connections on both sides of the update, old=%d new=%d", nOld, nNew)
	}
	t.Logf("EVIDENCE G hot update under traffic: %d connections on the old target, then %d on the new, none failed", nOld, nNew)

	// H. The forwarder killed: refused, nothing leaves.
	far0 := len(l.farSrv.lines())
	_ = l.sniffCmd.Process.Kill()
	_, _ = l.sniffCmd.Process.Wait()
	for _, c := range [][]string{{"203.0.113.110:80", "http", "a.example.net"}, {"203.0.113.111:443", "raw", "SSH-2.0-test"}, {"[2001:db8:f::10]:80", "http", "a.example.net"}} {
		start := time.Now()
		got := l.client("cli", false, c...)
		if strings.HasPrefix(got, "OK ") {
			t.Fatalf("H: a connection succeeded with the forwarder stopped: %s", got)
		}
		t.Logf("EVIDENCE H forwarder stopped, %s refused in %v: %s", c[0], time.Since(start).Round(time.Millisecond), got)
	}
	if n := len(l.farSrv.lines()); n != far0 {
		t.Fatalf("H: far saw connections with the forwarder stopped: %v", l.farSrv.lines()[far0:])
	}
	if d := l.rosForeign() - ros0; d != 0 {
		t.Fatalf("ROS saw %d packets to foreign destinations", d)
	}
	t.Logf("EVIDENCE no packet to a foreign destination reached ROS in any phase")
	failed = false
}

// markOf is the mark of a rule to group g.
func (l *sniffLab) markOf(g string) uint32 {
	gp, _ := groupByID(l.groups, g)
	tg, _ := groupTarget(gp)
	return tg.Mark
}

func waitLine(t *testing.T, h *helperProc, prefix string, d time.Duration) string {
	t.Helper()
	end := time.Now().Add(d)
	for time.Now().Before(end) {
		for _, l := range h.lines() {
			if strings.HasPrefix(l, prefix) {
				return l
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("no %q line: %v", prefix, h.lines())
	return ""
}

// TestNetnsSniffHelper is not a test: TestNetnsSniff runs this binary as a
// helper process (MERIDIAN_SNIFF_HELPER, arguments separated by 0x1f):
//
//   - sniff ARGS…: meridian sniff (internal/sniff.Main);
//   - dns LISTEN,… NAME=ADDR,…;…: a resolver on each address (UDP) that
//     answers A/AAAA from the table and logs every query;
//   - server ADDR,…: a TCP server that reads the client's first bytes and
//     answers "peer=<source> local=<destination>", then echoes;
//   - long ADDR HOST: one connection that sends a request, then a line
//     every 2 s, printing STARTED and ECHO lines;
//   - client ADDR KIND VALUE: one connection; KIND http (Host VALUE), tls
//     (ClientHello with server_name VALUE), raw (VALUE as bytes) or mark
//     (an HTTP request on a socket with SO_MARK VALUE; ADDR "dns:A:P" sends
//     one DNS query instead). Prints "OK <answer>" or "ERR <error>".
func TestNetnsSniffHelper(t *testing.T) {
	mode := os.Getenv("MERIDIAN_SNIFF_HELPER")
	if mode == "" {
		t.Skip("helper process for TestNetnsSniff")
	}
	args := strings.Split(os.Getenv("MERIDIAN_SNIFF_HELPER_ARGS"), "\x1f")
	switch mode {
	case "sniff":
		os.Exit(sniff.Main(args))
	case "dns":
		helperDNS(args[0], args[1])
	case "server":
		helperServer(args[0])
	case "long":
		helperLong(args[0], args[1])
	case "client":
		fmt.Println(helperClient(args[0], args[1], args[2]))
		os.Exit(0)
	}
	os.Exit(2)
}

func helperDNS(listen, table string) {
	ans := map[string][]string{}
	for _, e := range strings.Split(table, ";") {
		k, v, _ := strings.Cut(e, "=")
		ans[k] = strings.Split(v, ",")
	}
	var mu sync.Mutex
	for _, a := range strings.Split(listen, ",") {
		pc, err := net.ListenPacket("udp", a)
		if err != nil {
			fmt.Println("LISTEN-FAILED", a, err)
			os.Exit(1)
		}
		go func(pc net.PacketConn, a string) {
			buf := make([]byte, 4096)
			for {
				n, from, err := pc.ReadFrom(buf)
				if err != nil {
					return
				}
				q := append([]byte(nil), buf[:n]...)
				name, qt, end, ok := dnsQuestion(q)
				if !ok {
					continue
				}
				mu.Lock()
				fmt.Printf("Q server=%s from=%s name=%s type=%d\n", a, from, name, qt)
				mu.Unlock()
				var sa stubAnswer
				for _, x := range ans[name] {
					if strings.Contains(x, ":") {
						sa.AAAA = append(sa.AAAA, x)
					} else {
						sa.A = append(sa.A, x)
					}
				}
				_, _ = pc.WriteTo(dnsReply(q, end, qt, sa), from)
			}
		}(pc, a)
	}
	fmt.Println("READY")
	select {}
}

func helperServer(listen string) {
	var mu sync.Mutex
	for _, a := range strings.Split(listen, ",") {
		ln, err := net.Listen("tcp", a)
		if err != nil {
			fmt.Println("LISTEN-FAILED", a, err)
			os.Exit(1)
		}
		go func(ln net.Listener) {
			for {
				c, err := ln.Accept()
				if err != nil {
					return
				}
				go func(c net.Conn) {
					defer c.Close()
					buf := make([]byte, 16384)
					_ = c.SetReadDeadline(time.Now().Add(3 * time.Second))
					n, _ := c.Read(buf)
					peer := netip.MustParseAddrPort(c.RemoteAddr().String()).Addr().Unmap()
					mu.Lock()
					fmt.Printf("C peer=%s local=%s bytes=%d\n", peer, c.LocalAddr(), n)
					mu.Unlock()
					_ = c.SetReadDeadline(time.Time{})
					fmt.Fprintf(c, "peer=%s local=%s\n", peer, c.LocalAddr())
					_, _ = io.Copy(c, c)
				}(c)
			}
		}(ln)
	}
	fmt.Println("READY")
	select {}
}

func helperLong(addr, host string) {
	c, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		fmt.Println("ERR", err)
		os.Exit(1)
	}
	fmt.Fprintf(c, "GET / HTTP/1.1\r\nHost: %s\r\n\r\n", host)
	r := bufio.NewReader(c)
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	line, err := r.ReadString('\n')
	if err != nil {
		fmt.Println("ERR", err)
		os.Exit(1)
	}
	fmt.Println("STARTED", strings.TrimSpace(line))
	for i := 0; ; i++ {
		time.Sleep(2 * time.Second)
		msg := fmt.Sprintf("after=%d\n", i)
		_ = c.SetDeadline(time.Now().Add(5 * time.Second))
		if _, err := c.Write([]byte(msg)); err != nil {
			fmt.Println("BROKEN", err)
			os.Exit(1)
		}
		got, err := r.ReadString('\n')
		if err != nil {
			fmt.Println("BROKEN", err)
			os.Exit(1)
		}
		fmt.Println("ECHO", strings.TrimSpace(got))
	}
}

func clientHelloBytes(sni string) []byte {
	a, b := net.Pipe()
	go func() { _ = tls.Client(a, &tls.Config{ServerName: sni, InsecureSkipVerify: true}).Handshake() }()
	buf := make([]byte, 16384)
	_ = b.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, _ := b.Read(buf)
	a.Close()
	b.Close()
	return buf[:n]
}

func helperClient(addr, kind, value string) string {
	var payload []byte
	var mark int
	switch kind {
	case "http":
		payload = []byte("GET / HTTP/1.1\r\nHost: " + value + "\r\n\r\n")
	case "tls":
		payload = clientHelloBytes(value)
	case "raw":
		payload = []byte(value + "\r\n")
	case "mark":
		m, err := strconv.ParseUint(value, 0, 32)
		if err != nil {
			return "ERR bad mark"
		}
		mark = int(m)
		payload = []byte("GET / HTTP/1.1\r\nHost: forwarder.example.net\r\n\r\n")
	}
	d := net.Dialer{Timeout: 3 * time.Second}
	if mark != 0 {
		d.Control = func(_, _ string, c syscall.RawConn) error {
			var serr error
			if err := c.Control(func(fd uintptr) { serr = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_MARK, mark) }); err != nil {
				return err
			}
			return serr
		}
	}
	if strings.HasPrefix(addr, "dns:") {
		c, err := d.Dial("udp", strings.TrimPrefix(addr, "dns:"))
		if err != nil {
			return "ERR " + err.Error()
		}
		defer c.Close()
		q := []byte{0x12, 0x34, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0}
		q = append(q, encodeName("a.example.net")...)
		q = append(q, 0, 1, 0, 1)
		_ = c.SetDeadline(time.Now().Add(2 * time.Second))
		if _, err := c.Write(q); err != nil {
			return "ERR " + err.Error()
		}
		buf := make([]byte, 1500)
		if _, err := c.Read(buf); err != nil {
			return "ERR " + err.Error()
		}
		return "OK dns answered"
	}
	c, err := d.Dial("tcp", addr)
	if err != nil {
		return "ERR " + err.Error()
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(6 * time.Second))
	if _, err := c.Write(payload); err != nil {
		return "ERR " + err.Error()
	}
	line, err := bufio.NewReader(c).ReadString('\n')
	if err != nil {
		return "ERR " + err.Error()
	}
	return "OK " + strings.TrimSpace(line)
}

// TestSniffNFTLoadAll checks (nft -c, then nft -f in a fresh namespace)
// the gateway ruleset with the forwarder on for every topology shape of
// sniffTopologies: IPv4-only and dual-stack targets, a backup hub, relay
// sharing, remote access, a nested and a TCP-only external exit.
//
// Opt-in: root, MERIDIAN_NFT_TEST=1 (like TestRuleSetNFTLoadLarge).
func TestSniffNFTLoadAll(t *testing.T) {
	if os.Getenv("MERIDIAN_NFT_TEST") != "1" {
		t.Skip("MERIDIAN_NFT_TEST not set")
	}
	for name, topo := range sniffTopologies(t) {
		_, f := sniffCompile(t, topo)
		p := filepath.Join(t.TempDir(), name+".nft")
		mustWrite(t, p, f.nft)
		ns := "msnload" + strconv.Itoa(os.Getpid()%100000)
		if out, err := exec.Command("ip", "netns", "add", ns).CombinedOutput(); err != nil {
			t.Fatalf("%v %s", err, out)
		}
		for _, args := range [][]string{{"-c", "-f", p}, {"-f", p}} {
			if out, err := exec.Command("ip", append([]string{"netns", "exec", ns, "nft"}, args...)...).CombinedOutput(); err != nil {
				_ = exec.Command("ip", "netns", "del", ns).Run()
				t.Fatalf("%s: nft %v: %v\n%s", name, args, err, out)
			}
		}
		_ = exec.Command("ip", "netns", "del", ns).Run()
		t.Logf("EVIDENCE %s: the gateway ruleset with the forwarder loads", name)
	}
}
