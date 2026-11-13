//go:build linux

package compile

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/radowitz/meridian/internal/defaults"
	"github.com/radowitz/meridian/internal/model"
)

// p2Lab is the namespace harness of the nested-exit and external-exit
// netns tests. It starts at the hubs: a "home" namespace stands for
// everything west of them (the gateway's SNAT has already happened: home
// owns the transit addresses and originates connections from them) and
// holds the two west tunnels (the relay's to the primary hub, the
// gateway's to the backup hub). Every managed node from the hubs on runs
// its COMPILED nft and routes script. Tunnels are veth pairs carrying the
// compiled addresses (ARP/ND off, one MAC on both ends, so "dev <tunnel>"
// routes behave as on a WireGuard device); other tunnel interfaces of a
// node are dummies with their addresses. "net" is the Internet behind the
// exits (server 192.0.2.80:8080 answers each connection with the source
// address it saw: the exit's WAN address names the exit that carried it).
type p2Lab struct {
	t     *testing.T
	b     *Bundle
	dir   string
	sfx   string
	ns    map[string]string
	node  map[string]string // namespace name → node id
	vethN int
	wans  map[string]string // namespace → WAN address
}

func newP2Lab(t *testing.T, b *Bundle) *p2Lab {
	t.Helper()
	l := &p2Lab{t: t, b: b, dir: t.TempDir(), sfx: strconv.Itoa(os.Getpid() % 100000), ns: map[string]string{}, node: map[string]string{}, wans: map[string]string{}}
	return l
}

func (l *p2Lab) in(n string, args ...string) []string {
	return append([]string{"ip", "netns", "exec", l.ns[n]}, args...)
}

func (l *p2Lab) sh(args ...string) (string, error) {
	out, err := exec.Command(args[0], args[1:]...).CombinedOutput()
	return string(out), err
}

func (l *p2Lab) must(args ...string) string {
	l.t.Helper()
	out, err := l.sh(args...)
	if err != nil {
		l.t.Fatalf("%s: %v\n%s", strings.Join(args, " "), err, out)
	}
	return out
}

func (l *p2Lab) write(name, body string) string {
	p := filepath.Join(l.dir, name)
	mustWrite(l.t, p, body)
	return p
}

// add creates namespaces; node maps a namespace to the topology node whose
// files it runs ("" for home / net / helpers).
func (l *p2Lab) add(names map[string]string) {
	for n, node := range names {
		l.ns[n] = "mrp" + n + l.sfx
		l.node[n] = node
		l.must("ip", "netns", "add", l.ns[n])
		name := l.ns[n]
		l.t.Cleanup(func() { _ = exec.Command("ip", "netns", "del", name).Run() })
		l.must(l.in(n, "ip", "link", "set", "lo", "up")...)
	}
}

var p2AddrLine = regexp.MustCompile(`(?m)^Address\s*=\s*(.+)$`)

// addAddrs puts node's compiled addresses of iface on iface in namespace n.
func (l *p2Lab) addAddrs(n, node, iface string) {
	l.t.Helper()
	m := p2AddrLine.FindStringSubmatch(l.b.File("nodes/" + node + "/etc/wireguard/" + iface + ".conf"))
	if m == nil {
		l.t.Fatalf("nodes/%s %s.conf has no Address line", node, iface)
	}
	for _, a := range strings.Split(m[1], ",") {
		if a = strings.TrimSpace(a); a == "" {
			continue
		}
		args := []string{"ip", "addr", "add", a, "dev", iface}
		if strings.Contains(a, ":") {
			args = append(args, "nodad")
		}
		l.must(l.in(n, args...)...)
	}
}

// p2p joins namespaces a and b with the tunnel iface (both ends named
// iface, each with its node's compiled addresses; nodeA/nodeB name whose
// files to read, which for home is the west node of that link).
func (l *p2Lab) p2p(a, nodeA, b, nodeB, iface string) {
	l.t.Helper()
	l.vethN++
	x, y := fmt.Sprintf("pa%d%s", l.vethN, l.sfx), fmt.Sprintf("pb%d%s", l.vethN, l.sfx)
	mac := fmt.Sprintf("02:6f:00:00:%02x:01", l.vethN)
	l.must("ip", "link", "add", x, "type", "veth", "peer", "name", y)
	l.must("ip", "link", "set", x, "netns", l.ns[a])
	l.must("ip", "link", "set", y, "netns", l.ns[b])
	for _, e := range []struct{ n, node, name string }{{a, nodeA, x}, {b, nodeB, y}} {
		l.must(l.in(e.n, "ip", "link", "set", e.name, "name", iface)...)
		l.must(l.in(e.n, "ip", "link", "set", "dev", iface, "address", mac, "arp", "off")...)
		_, _ = l.sh(l.in(e.n, "ip", "link", "set", "dev", iface, "addrgenmode", "none")...)
		l.addAddrs(e.n, e.node, iface)
		l.must(l.in(e.n, "ip", "link", "set", iface, "up")...)
	}
}

// dummies adds every other tunnel interface of the node in namespace n as
// a dummy with its addresses.
func (l *p2Lab) dummies(n string, have map[string]bool) {
	node := l.node[n]
	pre := "nodes/" + node + "/etc/wireguard/"
	for path := range l.b.Files {
		if !strings.HasPrefix(path, pre) {
			continue
		}
		iface := strings.TrimSuffix(strings.TrimPrefix(path, pre), ".conf")
		if have[iface] {
			continue
		}
		l.must(l.in(n, "ip", "link", "add", iface, "type", "dummy")...)
		l.addAddrs(n, node, iface)
		l.must(l.in(n, "ip", "link", "set", iface, "up")...)
	}
}

// wan gives namespace n an eth0 to "net" (100.64.<i>.2/30, net .1).
func (l *p2Lab) wan(n string, i int) {
	l.vethN++
	x, y := fmt.Sprintf("pw%d%s", l.vethN, l.sfx), fmt.Sprintf("pn%d%s", l.vethN, l.sfx)
	l.must("ip", "link", "add", x, "type", "veth", "peer", "name", y)
	l.must("ip", "link", "set", x, "netns", l.ns[n])
	l.must("ip", "link", "set", y, "netns", l.ns["net"])
	l.must(l.in(n, "ip", "link", "set", x, "name", "eth0")...)
	l.must(l.in(n, "ip", "addr", "add", fmt.Sprintf("100.64.%d.2/30", i), "dev", "eth0")...)
	l.must(l.in(n, "ip", "link", "set", "eth0", "up")...)
	l.must(l.in(n, "ip", "route", "add", "default", "via", fmt.Sprintf("100.64.%d.1", i))...)
	l.must(l.in("net", "ip", "addr", "add", fmt.Sprintf("100.64.%d.1/30", i), "dev", y)...)
	l.must(l.in("net", "ip", "link", "set", y, "up")...)
	l.wans[n] = fmt.Sprintf("100.64.%d.2", i)
}

// apply runs the node's compiled routes script and loads its nft.
func (l *p2Lab) apply(n string) string {
	l.t.Helper()
	node := l.node[n]
	run := filepath.Join(l.dir, n+"run")
	routes := strings.ReplaceAll(l.b.File("nodes/"+node+"/usr/local/sbin/meridian-routes.sh"), "/run/meridian", run)
	if out, err := l.sh(l.in(n, "bash", l.write(n+"-routes.sh", routes))...); err != nil {
		l.t.Fatalf("setup: %s routes script: %v\n%s", n, err, out)
	}
	nftP := l.write(n+".nft", l.b.File("nodes/"+node+"/etc/nftables.d/meridian.nft"))
	l.must(l.in(n, "nft", "-c", "-f", nftP)...)
	l.must(l.in(n, "nft", "-f", nftP)...)
	l.must(l.in(n, "sysctl", "-qw", "net.ipv4.ip_forward=1")...)
	l.must(l.in(n, "sysctl", "-qw", "net.ipv6.conf.all.forwarding=1")...)
	return run
}

func (l *p2Lab) start(n string, args ...string) *exec.Cmd {
	cmd := exec.Command("ip", append([]string{"netns", "exec", l.ns[n]}, args...)...)
	name := n + "-" + filepath.Base(args[len(args)-1])
	if len(args) > 1 {
		name = n + "-" + filepath.Base(args[1]) + "-" + strings.ReplaceAll(strings.Join(args[2:], "_"), "/", "_")
	}
	logf, _ := os.Create(filepath.Join(l.dir, name+".log"))
	cmd.Stdout, cmd.Stderr = logf, logf
	if err := cmd.Start(); err != nil {
		l.t.Fatal(err)
	}
	l.t.Cleanup(func() { _ = cmd.Process.Kill(); _, _ = cmd.Process.Wait(); _ = logf.Close() })
	return cmd
}

func (l *p2Lab) obs(n, body string) {
	l.must(l.in(n, "nft", "-f", l.write(n+"-obs.nft", "table inet p2obs {\n"+body+"}\n"))...)
}

func (l *p2Lab) counter(n, name string) int {
	out, err := l.sh(l.in(n, "nft", "list", "counter", "inet", "p2obs", name)...)
	if err != nil {
		l.t.Fatalf("counter %s/%s: %v\n%s", n, name, err, out)
	}
	m := regexp.MustCompile(`packets (\d+)`).FindStringSubmatch(out)
	if m == nil {
		l.t.Fatalf("counter %s/%s unreadable:\n%s", n, name, out)
	}
	v, _ := strconv.Atoi(m[1])
	return v
}

func (l *p2Lab) diag(cmds [][]string) {
	for _, c := range cmds {
		out, err := l.sh(l.in(c[0], c[1:]...)...)
		l.t.Logf("DIAG %s$ %s (err=%v)\n%s", c[0], strings.Join(c[1:], " "), err, out)
	}
	ents, _ := os.ReadDir(l.dir)
	for _, e := range ents {
		if strings.HasSuffix(e.Name(), ".log") {
			body, _ := os.ReadFile(filepath.Join(l.dir, e.Name()))
			l.t.Logf("DIAG %s:\n%s", e.Name(), body)
		}
	}
}

// hubDriver runs the compiled hub failover's group logic (everything
// before its main loop) in namespace n: reset_groups once, then
// check_groups for a given number of passes.
func (l *p2Lab) hubDriver(n, run string) func(passes int) {
	fo := l.b.File("nodes/" + l.node[n] + "/usr/local/sbin/meridian-failover.sh")
	cut := strings.Index(fo, "# --- main loop ---")
	if cut < 0 {
		l.t.Fatal("no main-loop marker in the hub failover script")
	}
	text := strings.ReplaceAll(fo[:cut], "/run/meridian", run)
	p := l.write(n+"-groups.sh", text+"\nreset_groups\n")
	l.must(l.in(n, "bash", p)...)
	return func(passes int) {
		l.t.Helper()
		p := l.write(n+"-step.sh", text+"\nfor i in $(seq "+strconv.Itoa(passes)+"); do check_groups; done\n")
		if out, err := l.sh(l.in(n, "bash", p)...); err != nil {
			l.t.Fatalf("hub %s group step: %v\n%s", n, err, out)
		}
	}
}

// groupReport reads one line ("hop", "active", …) of a group's report.
func groupReport(run, gid, key string) string {
	v, _ := os.ReadFile(filepath.Join(run, "group", gid, "report"))
	for _, ln := range strings.Split(string(v), "\n") {
		if k, val, ok := strings.Cut(ln, " "); ok && k == key {
			return val
		}
	}
	return ""
}

// p2ConnectPy SRC ADDR PORT: connect from SRC, print the server's line, or
// TIMEOUT / REFUSED / RESET / ERROR <x>.
const p2ConnectPy = `import socket, sys, errno
try:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(5)
    s.bind((sys.argv[1], 0))
    s.connect((sys.argv[2], int(sys.argv[3])))
    d = s.recv(100).decode().strip()
    print(d if d else "CLOSED")
except socket.timeout:
    print("TIMEOUT")
except ConnectionRefusedError:
    print("REFUSED")
except ConnectionResetError:
    print("RESET")
except OSError as e:
    print("ERROR", e.errno)
`

// p2UDPPy SRC ADDR PORT: one datagram from SRC; REFUSED when an ICMP port
// unreachable comes back, REPLY when anything answers, TIMEOUT otherwise.
const p2UDPPy = `import socket, sys
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.settimeout(3)
s.bind((sys.argv[1], 0))
s.connect((sys.argv[2], int(sys.argv[3])))
try:
    s.send(b"quic-like datagram")
    s.recv(100)
    print("REPLY")
except ConnectionRefusedError:
    print("REFUSED")
except socket.timeout:
    print("TIMEOUT")
except OSError as e:
    print("ERROR", e.errno)
`

// p2QueryPy SRC SERVER NAME: an A query over UDP from SRC (IPv6), print
// the first address or TIMEOUT.
const p2QueryPy = `import socket, struct, sys, random
src, server, name = sys.argv[1], sys.argv[2], sys.argv[3]
q = struct.pack(">HHHHHH", random.randint(0, 65535), 0x0100, 1, 0, 0, 0)
for label in name.split("."):
    q += bytes([len(label)]) + label.encode()
q += b"\x00" + struct.pack(">HH", 1, 1)
try:
    s = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
    s.settimeout(4)
    s.bind((src, 0))
    s.sendto(q, (server, 53))
    r = s.recv(4096)
    if (r[3] & 0x0f) != 0 or struct.unpack(">H", r[6:8])[0] == 0:
        print("NOANSWER")
    else:
        print(socket.inet_ntoa(r[-4:]))
except Exception:
    print("TIMEOUT")
`

// TestNetnsNestedExit is the runtime check of an exit behind a relay exit
// (docs/architecture.md「挂在中继出口后面的出口」) on defaults.NestedExample:
// hubs ix (primary) and hk5 (backup), exits dc1 (the relay exit, also a
// member of group hk) and dc2, and tw2 behind dc1 (group tw = tw2, then
// dc2). Namespaces: home (west of the hubs, see p2Lab), ix, hk5, dc1, dc2,
// tw2, net. Every node from the hubs on runs its compiled nft and routes;
// the hubs' group switching is the compiled meridian-failover.sh
// (check_groups with the real ping). Resolver stand-ins answer 198.18.1.1
// (dc1), 198.18.1.2 (dc2), 198.18.1.3 (tw2) on their tunnel resolvers.
//
// Phases:
//  1. primary hub: group tw (switched to tw2 through dc1), tw2's own mark,
//     group hk (dc1 itself) and the three resolvers (group tw, tw2's
//     hub-independent address, group hk) reach the right exit; tw2's
//     replies come back through dc1's tunnel to the primary hub only;
//     nothing of tw2's traffic leaves dc1's WAN.
//  2. backup hub takes over (home sends everything to hk5): the same flows
//     go through hk5 and dc1 answers them on its hk5 tunnel, never on its
//     ix tunnel.
//  3. relay exit down (dc1's hub tunnels cut): the primary hub's group
//     logic marks tw2 (and dc1) down and moves groups tw and hk to dc2
//     (report "hop dc2"); tw2's own mark times out; nothing leaves dc1.
//  4. nested tunnel gone (dc1 back, its tunnel to tw2 deleted): tw2's mark
//     fails closed on dc1 (blackhole), zero packets out of dc1's WAN.
//
// Root only, Linux only, opt-in (MERIDIAN_NETNS_TEST=1); needs ip, nft,
// ping, bash and python3. A pass prints "EVIDENCE <phase>: …" lines and
// ends with PASS. Not executed on a real host: until a passing log is
// archived these properties are NOT verified at runtime there.
func TestNetnsNestedExit(t *testing.T) {
	netnsPrereqs(t)
	if _, err := exec.LookPath("python3"); err != nil {
		t.Skip("python3 not installed")
	}
	topo := defaults.NestedExample()
	model.MigrateRegionGroups(&topo)
	b := mustCompile(t, topo)
	tunnels := mustTunnels(t, topo)
	exits, groups := plans(t, topo)
	tw := mustGroup(t, groups, "tw")
	hk := mustGroup(t, groups, "hk")
	if !tw.Dynamic || tw.Target.Node.ID != "tw2" || !hk.Dynamic {
		t.Fatalf("groups: tw %+v hk %+v", tw.Policy(), hk.Policy())
	}
	link := func(id string) Tunnel {
		for _, tun := range tunnels {
			if tun.LinkID == id && tun.Mode == "udp" || tun.LinkID == id && tun.Mode == "wss" && tun.Transport == model.TransportIXReplacementWSS {
				return tun
			}
		}
		t.Fatalf("no tunnel for link %s", id)
		return Tunnel{}
	}
	aliIX, gwHk5 := link("ali-ix"), link("gw-hk5")
	ixDC1, ixDC2, hk5DC1, hk5DC2, nest := link("ix-dc1"), link("ix-dc2"), link("hk5-dc1"), link("hk5-dc2"), link("tw2-dc1")
	dc1, _ := exitByID(exits, "dc1")
	dc2, _ := exitByID(exits, "dc2")
	tw2, _ := exitByID(exits, "tw2")
	t.Logf("tw2 behind dc1 via %s (peer %s); hubs: ix→dc1 %s, hk5→dc1 %s; group tw mark %#x transit %s, tw2 transit %s",
		nest.Iface(), tw2.PeerV4, ixDC1.Iface(), hk5DC1.Iface(), tw.Mark, tw.TransitV4, tw2.TransitV4)

	l := newP2Lab(t, b)
	l.add(map[string]string{"home": "", "ix": "ix", "hk5": "hk5", "dc1": "dc1", "dc2": "dc2", "tw2": "tw2", "net": ""})
	l.p2p("home", "ali", "ix", "ix", aliIX.Iface())
	l.p2p("home", "gw", "hk5", "hk5", gwHk5.Iface())
	l.p2p("ix", "ix", "dc1", "dc1", ixDC1.Iface())
	l.p2p("ix", "ix", "dc2", "dc2", ixDC2.Iface())
	l.p2p("hk5", "hk5", "dc1", "dc1", hk5DC1.Iface())
	l.p2p("hk5", "hk5", "dc2", "dc2", hk5DC2.Iface())
	l.p2p("dc1", "dc1", "tw2", "tw2", nest.Iface())
	have := map[string]bool{}
	for _, tun := range []Tunnel{aliIX, gwHk5, ixDC1, ixDC2, hk5DC1, hk5DC2, nest} {
		have[tun.Iface()] = true
	}
	for _, n := range []string{"ix", "hk5", "dc1", "dc2", "tw2"} {
		l.dummies(n, have)
	}
	for _, n := range []string{"ix", "hk5"} {
		l.must(l.in(n, "ip", "link", "add", "eth0", "type", "dummy")...)
		l.must(l.in(n, "ip", "link", "set", "eth0", "up")...)
		l.must(l.in(n, "ip", "route", "add", "default", "dev", "eth0")...)
	}
	l.wan("dc1", 1)
	l.wan("dc2", 2)
	l.wan("tw2", 3)
	l.must(l.in("net", "ip", "link", "add", "srv", "type", "dummy")...)
	l.must(l.in("net", "ip", "addr", "add", "192.0.2.80/32", "dev", "srv")...)
	l.must(l.in("net", "ip", "link", "set", "srv", "up")...)
	run := map[string]string{}
	for _, n := range []string{"ix", "hk5", "dc1", "dc2", "tw2"} {
		run[n] = l.apply(n)
	}
	// home: the transit sources, and the path toward the active hub.
	for _, a := range []string{tw.TransitV4, hk.TransitV4, tw2.TransitV4, dc1.TransitV4} {
		l.must(l.in("home", "ip", "addr", "add", a+"/32", "dev", "lo")...)
	}
	for _, a := range []string{tw.TransitV6, hk.TransitV6} {
		l.must(l.in("home", "ip", "-6", "addr", "add", a+"/128", "dev", "lo", "nodad")...)
	}
	via := func(dev string) {
		l.must(l.in("home", "ip", "route", "replace", "192.0.2.80/32", "dev", dev)...)
		l.must(l.in("home", "ip", "-6", "route", "replace", "fd66::53:0/112", "dev", dev)...)
		l.must(l.in("home", "ip", "-6", "route", "replace", "fd66::54:0/112", "dev", dev)...)
	}
	via(aliIX.Iface())
	homeULA := aliIX.WestULA

	l.obs("dc1", fmt.Sprintf(`  counter r_p {}
  counter r_b {}
  counter wan_tw2 {}
  counter wan_any {}
  chain fwdobs {
    type filter hook forward priority -400; policy accept;
    ip saddr %[3]s oifname "eth0" counter name "wan_tw2"
  }
  chain post {
    type filter hook postrouting priority 400; policy accept;
    oifname %[1]q ct direction reply counter name "r_p"
    oifname %[2]q ct direction reply counter name "r_b"
    oifname "eth0" tcp dport 8080 counter name "wan_any"
  }
`, ixDC1.Iface(), hk5DC1.Iface(), tw2.TransitV4))
	l.obs("tw2", "  counter wan {}\n  chain post {\n    type filter hook postrouting priority 400; policy accept;\n    oifname \"eth0\" tcp dport 8080 counter name \"wan\"\n  }\n")

	resolverPy := l.write("resolver.py", netnsResolverPy)
	l.start("dc1", "python3", resolverPy, dc1.DNSULA, "198.18.1.1")
	l.start("dc2", "python3", resolverPy, dc2.DNSULA, "198.18.1.2")
	l.start("tw2", "python3", resolverPy, tw2.DNSULA, "198.18.1.3")
	l.start("net", "python3", l.write("server.py", netnsServerPy), "192.0.2.80", "8080")
	connectPy, queryPy := l.write("connect.py", p2ConnectPy), l.write("query.py", p2QueryPy)
	time.Sleep(time.Second)
	connect := func(src string) string {
		out, _ := l.sh(l.in("home", "python3", connectPy, src, "192.0.2.80", "8080")...)
		return strings.TrimSpace(out)
	}
	query := func(src, server string) string {
		out, _ := l.sh(l.in("home", "python3", queryPy, src, server, "probe.example.net")...)
		return strings.TrimSpace(out)
	}
	steps := l.hubDriver("ix", run["ix"])

	fails := 0
	check := func(phase, what, got, want string) {
		t.Helper()
		if got != want {
			fails++
			t.Errorf("%s: %s: got %q, want %q", phase, what, got, want)
		} else {
			t.Logf("EVIDENCE %s: %s: %s", phase, what, got)
		}
	}
	finish := func(phase string) {
		t.Helper()
		if fails > 0 {
			l.diag([][]string{
				{"ix", "ip", "rule"}, {"ix", "ip", "route"}, {"ix", "ip", "route", "show", "table", strconv.Itoa(tw.Table)}, {"ix", "ip", "-6", "route", "show", "table", strconv.Itoa(tw.Table)},
				{"ix", "nft", "list", "ruleset"}, {"hk5", "ip", "route", "show", "table", strconv.Itoa(tw.Table)},
				{"dc1", "ip", "rule"}, {"dc1", "ip", "route"}, {"dc1", "ip", "route", "show", "table", strconv.Itoa(tw2.Table)}, {"dc1", "nft", "list", "ruleset"},
				{"tw2", "ip", "route"}, {"tw2", "ip", "-6", "route"}, {"tw2", "nft", "list", "ruleset"},
			})
			t.Fatalf("%s: %d checks failed", phase, fails)
		}
	}
	snap := func() [4]int {
		return [4]int{l.counter("dc1", "r_p"), l.counter("dc1", "r_b"), l.counter("dc1", "wan_tw2"), l.counter("tw2", "wan")}
	}
	flows := func(phase string) {
		check(phase, "group tw connection (switched to tw2 through dc1)", connect(tw.TransitV4), l.wans["tw2"])
		check(phase, "tw2's own mark", connect(tw2.TransitV4), l.wans["tw2"])
		check(phase, "group hk connection (dc1 itself)", connect(hk.TransitV4), l.wans["dc1"])
		check(phase, "group tw resolver (resolved at tw2, not at dc1)", query(tw.TransitV6, tw.Resolver), "198.18.1.3")
		check(phase, "tw2's hub-independent resolver address", query(homeULA, tw2.Resolver), "198.18.1.3")
		check(phase, "group hk resolver (dc1 answers its own)", query(hk.TransitV6, hk.Resolver), "198.18.1.1")
	}

	// 1. Primary hub.
	steps(2)
	check("primary", "hub report: group tw hop", groupReport(run["ix"], "tw", "hop"), "tw2")
	check("primary", "hub report: group hk hop", groupReport(run["ix"], "hk", "hop"), "dc1")
	before := snap()
	flows("primary")
	after := snap()
	if after[0] == before[0] || after[1] != before[1] {
		fails++
		t.Errorf("primary: dc1 replies not on its ix tunnel only (before %v after %v)", before, after)
	}
	if after[2] != 0 || after[3] == before[3] {
		fails++
		t.Errorf("primary: tw2 traffic left dc1's WAN (%d) or not tw2's (before %v after %v)", after[2], before, after)
	}
	finish("primary")

	// 2. Backup hub carries.
	via(gwHk5.Iface())
	before = snap()
	flows("backup")
	after = snap()
	if after[1] == before[1] || after[0] != before[0] {
		fails++
		t.Errorf("backup: dc1 did not answer on its hk5 tunnel only (before %v after %v)", before, after)
	}
	if after[2] != 0 {
		fails++
		t.Errorf("backup: tw2 traffic left dc1's WAN (%d)", after[2])
	}
	finish("backup")

	// 3. The relay exit goes down: the primary hub moves both groups away.
	via(aliIX.Iface())
	l.must(l.in("dc1", "nft", "-f", l.write("dc1-cut.nft", fmt.Sprintf(`table inet p2cut {
  chain i { type filter hook prerouting priority -500; policy accept; iifname { %[1]q, %[2]q } drop; }
  chain o { type filter hook postrouting priority -500; policy accept; oifname { %[1]q, %[2]q } drop; }
}
`, ixDC1.Iface(), hk5DC1.Iface())))...)
	steps(2)
	check("relay down", "two passes: group tw still on tw2 (FAILS_NEED is 3)", groupReport(run["ix"], "tw", "hop"), "tw2")
	steps(2)
	check("relay down", "hub report: group tw hop", groupReport(run["ix"], "tw", "hop"), "dc2")
	check("relay down", "hub report: group hk hop", groupReport(run["ix"], "hk", "hop"), "dc2")
	wan0 := l.counter("dc1", "wan_any")
	check("relay down", "group tw connection (failed over to dc2)", connect(tw.TransitV4), l.wans["dc2"])
	check("relay down", "group hk connection (failed over to dc2)", connect(hk.TransitV4), l.wans["dc2"])
	check("relay down", "tw2's own mark (no other path)", connect(tw2.TransitV4), "TIMEOUT")
	check("relay down", "group tw resolver follows the group", query(tw.TransitV6, tw.Resolver), "198.18.1.2")
	if v := l.counter("dc1", "wan_any"); v != wan0 {
		fails++
		t.Errorf("relay down: %d connections left dc1's WAN", v-wan0)
	}
	finish("relay down")

	// 4. dc1 back, its tunnel to tw2 gone: tw2's mark fails closed on dc1.
	l.must(l.in("dc1", "nft", "delete", "table", "inet", "p2cut")...)
	l.must(l.in("dc1", "ip", "link", "del", nest.Iface())...)
	wan0, tw0 := l.counter("dc1", "wan_any"), l.counter("dc1", "wan_tw2")
	check("nested gone", "tw2's own mark", connect(tw2.TransitV4), "TIMEOUT")
	if v := l.counter("dc1", "wan_any"); v != wan0 || l.counter("dc1", "wan_tw2") != tw0 {
		fails++
		t.Errorf("nested gone: tw2 traffic left dc1's WAN (%d / %d)", v-wan0, l.counter("dc1", "wan_tw2")-tw0)
	}
	steps(6)
	check("nested gone", "hub report: group tw stays off tw2", groupReport(run["ix"], "tw", "hop"), "dc2")
	finish("nested gone")
}
