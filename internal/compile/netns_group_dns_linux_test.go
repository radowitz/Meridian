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

	"github.com/radowitz/meridian/internal/model"
	"github.com/radowitz/meridian/internal/validate"
)

// TestNetnsGroupDNSFailover is the runtime check of region-group DNS
// (docs/architecture.md「地区组的解析」): with the preferred member of a
// switchable group and its resolver completely down, the hub's own
// failover logic moves the group, and the backup member then resolves new
// names and carries the connection; no group query ever reaches a domestic
// resolver or ROS, or leaves the gateway unmarked.
//
// Namespaces: the TestNetnsReloadNoLeak lab (gateway, ROS, LAN client,
// remote device; newNetnsLab) plus the relay "ali", the hub, the two
// members of group "us" (exits "us" and "us-2") and "net", a stand-in for
// the Internet behind both exits' WAN. Every host runs its COMPILED files
// from the example topology with remote access on (raExample): nft, routes
// script, and on the hub the group_step logic of the compiled
// meridian-failover.sh, driven with the compiled check line for group us.
// The tunnels on the path (gateway-ali, ali-hub, hub-us, hub-us-2) are veth
// pairs carrying the compiled tunnel addresses, with ARP/ND off and the
// same MAC on both ends, so "dev <tunnel>" routes behave as on a
// point-to-point WireGuard device; every other tunnel interface is a dummy
// with its compiled addresses. No WireGuard is involved: the AllowedIPs of
// the compiled configs are checked by unit tests only.
//
// Resolver stand-ins: a small python3 UDP+TCP responder bound to each
// exit's tunnel resolver address (what the exit's SmartDNS binds) answers
// every A query with an address that names the member (198.18.1.1 for us,
// 198.18.1.2 for us-2). SmartDNS is not run: the gateway query is sent by
// python3 with SO_MARK set to the group mark, which is what SmartDNS's
// -set-mark does. ROS owns the domestic resolver addresses and counts any
// packet to them on 53/853 and any packet to the group resolver range.
//
// Mesh backup (phases 7 to 9): the hub and exit us run their COMPILED
// meridian-mesh-up.sh against stand-in sidecars, the namespaces "hsc" and
// "esc" (a sleeping process in each stands in for the container, a "docker"
// shim reports its pid; the script's own nsenter seals the namespace). The
// Cloudflare Mesh between the two sidecars is emulated by a pair of tun
// devices ("cfw0", link/none like the real warp device) joined by a python3
// relay; what Cloudflare would install on the warp devices is added by hand:
// the hub sidecar gets the resolver /128 that us's compiled mesh-up names
// for publication and the data server's /32 (an operator Mesh route), both
// sidecars get the other side's Mesh address. The emulation assumes the
// connector source-NATs traffic it carries (hub sidecar into the Mesh, exit
// sidecar out of its docker bridge); the real connector's behaviour is NOT
// known from this test. The hub sidecar also has a docker-bridge stand-in
// "eth0" with a default route, which must never carry a packet.
//
// Root only, Linux only, opt-in (MERIDIAN_NETNS_TEST=1); needs ip, nft,
// ping, bash, python3, nsenter and /dev/net/tun. Phases 1 to 6 passed once
// on 2026-11-13 (docs/evidence/2026-11-13-debian13/netns-group-dns.log);
// phases 7 to 9 (Mesh) have NOT been executed yet: until a passing log is
// archived the Mesh property is NOT verified.
func TestNetnsGroupDNSFailover(t *testing.T) {
	netnsPrereqs(t)
	if _, err := exec.LookPath("python3"); err != nil {
		t.Skip("python3 not installed")
	}
	if _, err := exec.LookPath("nsenter"); err != nil {
		t.Skip("nsenter not installed (the compiled meridian-mesh-up.sh seals through it)")
	}
	if _, err := os.Stat("/dev/net/tun"); err != nil {
		t.Skip("/dev/net/tun not available (the Mesh emulation needs tun devices)")
	}
	topo, _ := raExample(t)
	lab := newNetnsLab(t, topo, labV6{prefix: "2001:db8:100::/64", gw: "2001:db8:100::88", cli: "2001:db8:100::50"})
	b, dir, sh, must, in := lab.b, lab.dir, lab.sh, lab.must, lab.in
	tunnels := mustTunnels(t, topo)
	exits, groups := plans(t, topo)
	us := mustGroup(t, groups, "us")
	if !us.Dynamic || len(us.Try) < 2 || us.Try[0].Node.ID != "us" || us.Try[1].Node.ID != "us-2" {
		t.Fatalf("group us must be switchable with us then us-2: %+v", us.Policy())
	}
	usExit, us2Exit := us.Try[0], us.Try[1]

	// Tunnels on the path.
	var gwWest, aliHub Tunnel
	for _, tun := range tunnels {
		if tun.West.ID == "gw" && tun.Transport == model.TransportUDPWSSFailover && tun.Mode == "udp" {
			gwWest = tun
		}
		if tun.West.ID == "ali" && tun.East.ID == "hk-hub" && tun.Transport == model.TransportDirectWG {
			aliHub = tun
		}
	}
	hubUS, hubUS2 := hubDirect(tunnels, "us", "hk-hub"), hubDirect(tunnels, "us-2", "hk-hub")
	for _, tun := range []Tunnel{gwWest, aliHub, hubUS, hubUS2} {
		if tun.LinkID == "" {
			t.Fatal("example path tunnels not found")
		}
	}
	t.Logf("path: gw %s ali %s hub %s us / %s us-2; group us mark %#x transit %s resolver %s table %d",
		gwWest.Iface(), aliHub.Iface(), hubUS.Iface(), hubUS2.Iface(), us.Mark, us.TransitV6, us.Resolver, us.Table)

	sfx := strconv.Itoa(os.Getpid() % 100000)
	for _, n := range []string{"ali", "hub", "us", "us2", "net"} {
		lab.ns[n] = "mrd" + n + sfx
		must("ip", "netns", "add", lab.ns[n])
		must(in(n, "ip", "link", "set", "lo", "up")...)
	}
	ns := lab.ns
	nodeNS := map[string]string{"gw": "gw", "ali": "ali", "hk-hub": "hub", "us": "us", "us-2": "us2"}

	addrLine := regexp.MustCompile(`(?m)^Address\s*=\s*(.+)$`)
	addAddrs := func(node, iface string) {
		t.Helper()
		m := addrLine.FindStringSubmatch(b.File("nodes/" + node + "/etc/wireguard/" + iface + ".conf"))
		if m == nil {
			t.Fatalf("nodes/%s %s.conf has no Address line", node, iface)
		}
		for _, a := range strings.Split(m[1], ",") {
			if a = strings.TrimSpace(a); a == "" {
				continue
			}
			args := []string{"ip", "addr", "add", a, "dev", iface}
			if strings.Contains(a, ":") {
				args = append(args, "nodad")
			}
			must(in(nodeNS[node], args...)...)
		}
	}
	// p2p joins two nodes with a veth pair named iface on both ends, with
	// ARP/ND off and one MAC on both ends: a frame is addressed to the
	// sender's own MAC (NOARP), which is then also the receiver's.
	vethN := 0
	p2p := func(a, bNode, iface string) {
		t.Helper()
		vethN++
		x, y := fmt.Sprintf("xa%d%s", vethN, sfx), fmt.Sprintf("xb%d%s", vethN, sfx)
		mac := fmt.Sprintf("02:6d:00:00:%02x:01", vethN)
		must("ip", "link", "add", x, "type", "veth", "peer", "name", y)
		must("ip", "link", "set", x, "netns", ns[nodeNS[a]])
		must("ip", "link", "set", y, "netns", ns[nodeNS[bNode]])
		for _, e := range []struct{ node, name string }{{a, x}, {bNode, y}} {
			n := nodeNS[e.node]
			must(in(n, "ip", "link", "set", e.name, "name", iface)...)
			must(in(n, "ip", "link", "set", "dev", iface, "address", mac, "arp", "off")...)
			_, _ = sh(in(n, "ip", "link", "set", "dev", iface, "addrgenmode", "none")...)
			addAddrs(e.node, iface)
			must(in(n, "ip", "link", "set", iface, "up")...)
		}
	}
	// The gateway's west tunnel was a dummy in the lab: replace it.
	must(in("gw", "ip", "link", "del", gwWest.Iface())...)
	p2p("gw", "ali", gwWest.Iface())
	p2p("ali", "hk-hub", aliHub.Iface())
	p2p("hk-hub", "us", hubUS.Iface())
	p2p("hk-hub", "us-2", hubUS2.Iface())
	veths := map[string]bool{gwWest.Iface(): true, aliHub.Iface(): true, hubUS.Iface(): true, hubUS2.Iface(): true}
	// Every other WireGuard interface of these nodes: a dummy with its
	// compiled addresses, so the compiled routes scripts find them.
	for _, node := range []string{"ali", "hk-hub", "us", "us-2"} {
		for path := range b.Files {
			pre := "nodes/" + node + "/etc/wireguard/"
			if !strings.HasPrefix(path, pre) {
				continue
			}
			iface := strings.TrimSuffix(strings.TrimPrefix(path, pre), ".conf")
			if veths[iface] {
				continue
			}
			must(in(nodeNS[node], "ip", "link", "add", iface, "type", "dummy")...)
			addAddrs(node, iface)
			must(in(nodeNS[node], "ip", "link", "set", iface, "up")...)
		}
	}
	// WANs. ali and the hub: a dummy "eth0" default, so loose source
	// validation finds a route to Internet sources. The exits: a real link
	// "eth0" to "net", which owns the data server 192.0.2.80.
	for _, n := range []string{"ali", "hub"} {
		must(in(n, "ip", "link", "add", "eth0", "type", "dummy")...)
		must(in(n, "ip", "link", "set", "eth0", "up")...)
		must(in(n, "ip", "route", "add", "default", "dev", "eth0")...)
		must(in(n, "ip", "-6", "route", "add", "default", "dev", "eth0")...)
	}
	for i, n := range []string{"us", "us2"} {
		x, y := fmt.Sprintf("xw%d%s", i, sfx), fmt.Sprintf("xn%d%s", i, sfx)
		must("ip", "link", "add", x, "type", "veth", "peer", "name", y)
		must("ip", "link", "set", x, "netns", ns[n])
		must("ip", "link", "set", y, "netns", ns["net"])
		must(in(n, "ip", "link", "set", x, "name", "eth0")...)
		must(in(n, "ip", "addr", "add", fmt.Sprintf("100.64.%d.2/30", i+1), "dev", "eth0")...)
		must(in(n, "ip", "link", "set", "eth0", "up")...)
		must(in(n, "ip", "route", "add", "default", "via", fmt.Sprintf("100.64.%d.1", i+1))...)
		must(in("net", "ip", "addr", "add", fmt.Sprintf("100.64.%d.1/30", i+1), "dev", y)...)
		must(in("net", "ip", "link", "set", y, "up")...)
	}
	must(in("net", "ip", "link", "add", "srv", "type", "dummy")...)
	must(in("net", "ip", "addr", "add", "192.0.2.80/32", "dev", "srv")...)
	must(in("net", "ip", "link", "set", "srv", "up")...)

	// Compiled routes and nft on every node. The hub's state directory is
	// redirected away from the host's /run/meridian (this may run on a
	// real gateway).
	run := filepath.Join(dir, "hubrun")
	write := func(name, body string) string {
		p := filepath.Join(dir, name)
		mustWrite(t, p, body)
		return p
	}
	for _, node := range []string{"ali", "hk-hub", "us", "us-2"} {
		n := nodeNS[node]
		routes := strings.ReplaceAll(b.File("nodes/"+node+"/usr/local/sbin/meridian-routes.sh"), "/run/meridian", run)
		must(in(n, "bash", write(n+"-routes.sh", routes))...)
		nftP := write(n+".nft", b.File("nodes/"+node+"/etc/nftables.d/meridian.nft"))
		must(in(n, "nft", "-c", "-f", nftP)...)
		must(in(n, "nft", "-f", nftP)...)
		must(in(n, "sysctl", "-qw", "net.ipv4.ip_forward=1")...)
		must(in(n, "sysctl", "-qw", "net.ipv6.conf.all.forwarding=1")...)
	}
	// Gateway: the west tunnel changed, so the compiled routes run again;
	// then the compiled nft (nothing has been sent yet: every flow below
	// starts after the ruleset is loaded).
	must(in("gw", "bash", lab.routesPath)...)
	must(in("gw", "nft", "-c", "-f", lab.nftPath)...)
	must(in("gw", "nft", "-f", lab.nftPath)...)

	// Observation tables (separate tables, never replaced by a reload).
	res := us.Resolver
	gwObs := fmt.Sprintf(`table inet grpobs {
  counter marked {}
  counter unmarked {}
  counter snatted {}
  counter lan {}
  counter domestic {}
  chain out {
    type filter hook output priority -400; policy accept;
    ip6 daddr %[1]s meta mark 0 counter name "unmarked"
    ip6 daddr %[1]s meta mark %#[2]x counter name "marked"
  }
  chain post {
    type filter hook postrouting priority 400; policy accept;
    ip6 daddr %[3]s oifname "%[4]s" counter name "lan"
    ip6 daddr %[1]s ip6 saddr %[5]s oifname "%[6]s" counter name "snatted"
    ip daddr { %[7]s } meta l4proto { tcp, udp } th dport { 53, 853 } counter name "domestic"
  }
}
`, res, us.Mark, validate.GroupResolverNet, lab.lan, us.TransitV6, gwWest.Iface(), strings.Join(topo.Settings.DomesticDoT, ", "))
	must(in("gw", "nft", "-f", write("gwobs.nft", gwObs))...)
	for _, d := range topo.Settings.DomesticDoT {
		must(in("ros", "ip", "addr", "add", d+"/32", "dev", "inet0")...)
	}
	rosObs := fmt.Sprintf(`table inet grpobs {
  counter domestic {}
  counter group {}
  chain pre {
    type filter hook prerouting priority -400; policy accept;
    ip daddr { %s } meta l4proto { tcp, udp } th dport { 53, 853 } counter name "domestic"
    ip6 daddr %s counter name "group"
  }
}
`, strings.Join(topo.Settings.DomesticDoT, ", "), validate.GroupResolverNet)
	must(in("ros", "nft", "-f", write("rosobs.nft", rosObs))...)
	for _, n := range []string{"us", "us2"} {
		must(in(n, "nft", "-f", write(n+"obs.nft", fmt.Sprintf("table inet grpobs {\n  counter q {}\n  chain pre {\n    type filter hook prerouting priority -400; policy accept;\n    ip6 daddr %s counter name \"q\"\n  }\n}\n", validate.GroupResolverNet)))...)
	}
	cnt := func(n, name string) int { return lab.counter(n, "grpobs", name) }

	// Resolver stand-ins on the exits' tunnel resolver addresses, and the
	// data server.
	resolverPy := write("resolver.py", netnsResolverPy)
	serverPy := write("server.py", netnsServerPy)
	queryPy := write("query.py", netnsQueryPy)
	connectPy := write("connect.py", netnsConnectPy)
	start := func(n string, args ...string) func() {
		cmd := exec.Command("ip", append([]string{"netns", "exec", ns[n]}, args...)...)
		logf, _ := os.Create(filepath.Join(dir, n+"-"+filepath.Base(args[1])+".log"))
		cmd.Stdout, cmd.Stderr = logf, logf
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
		stop := func() { _ = cmd.Process.Kill(); _, _ = cmd.Process.Wait(); _ = logf.Close() }
		t.Cleanup(stop)
		return stop
	}
	stopUS := start("us", "python3", resolverPy, usExit.DNSULA, "198.18.1.1")
	start("us2", "python3", resolverPy, us2Exit.DNSULA, "198.18.1.2")
	start("net", "python3", serverPy, "192.0.2.80", "8080")
	time.Sleep(time.Second)

	// The data path of a group-us rule: its set holds the server address,
	// as SmartDNS's nftset would after resolving a name of the rule.
	var set4 string
	for _, rp := range planRules(topo, exits, groups, nil) {
		if rp.ViaGroup != nil && rp.ViaGroup.Group.ID == "us" && rp.Mark == us.Mark {
			set4 = rp.Set4
			break
		}
	}
	if set4 == "" {
		t.Fatal("no rule on group us")
	}
	must(in("gw", "nft", "add", "element", "inet", "meridian", set4, "{ 192.0.2.80 }")...)

	logs := func() {
		for _, f := range []string{"us-resolver.py.log", "us2-resolver.py.log", "net-server.py.log"} {
			body, _ := os.ReadFile(filepath.Join(dir, f))
			t.Logf("DIAG %s:\n%s", f, body)
		}
	}
	diag := func() {
		for _, c := range []struct {
			n    string
			args []string
		}{
			{"gw", []string{"ip", "-6", "rule"}}, {"gw", []string{"ip", "-6", "route", "show", "table", "102"}},
			{"gw", []string{"ip", "-6", "route", "show", "table", "main"}}, {"gw", []string{"ip", "-6", "addr"}},
			{"gw", []string{"ip", "-6", "route", "get", res, "mark", fmt.Sprintf("%#x", us.Mark)}},
			{"gw", []string{"nft", "list", "chain", "inet", "meridian", "transit_snat"}},
			{"gw", []string{"nft", "list", "table", "inet", "grpobs"}},
			{"gw", []string{"conntrack", "-L", "-f", "ipv6"}},
			{"ali", []string{"ip", "-6", "rule"}}, {"ali", []string{"ip", "-6", "route", "show", "table", "150"}}, {"ali", []string{"ip", "-6", "route"}},
			{"hub", []string{"ip", "-6", "rule"}}, {"hub", []string{"ip", "-4", "rule"}},
			{"hub", []string{"ip", "-6", "route", "show", "table", strconv.Itoa(us.Table)}},
			{"hub", []string{"ip", "-4", "route", "show", "table", strconv.Itoa(us.Table)}},
			{"hub", []string{"ip", "-6", "route"}}, {"hub", []string{"ip", "link"}},
			{"hub", []string{"bash", "-c", "for f in " + run + "/group/us/*; do echo \"$f: $(cat $f)\"; done"}},
			{"us", []string{"nft", "list", "ruleset"}}, {"us", []string{"ip", "-6", "addr"}}, {"us", []string{"ip", "-6", "route"}},
			{"us2", []string{"nft", "list", "ruleset"}}, {"us2", []string{"ip", "-6", "addr"}}, {"us2", []string{"ip", "-6", "route"}},
			{"ros", []string{"nft", "list", "table", "inet", "grpobs"}},
		} {
			out, err := sh(in(c.n, c.args...)...)
			t.Logf("DIAG %s$ %s (err=%v)\n%s", c.n, strings.Join(c.args, " "), err, out)
		}
		logs()
	}
	query := func(mark uint32, proto string) string {
		out, _ := sh(in("gw", "python3", queryPy, res, strconv.FormatUint(uint64(mark), 10), proto, "probe.example.com")...)
		return strings.TrimSpace(out)
	}
	connect := func() string {
		out, _ := sh(in("cli", "python3", connectPy, "192.0.2.80", "8080")...)
		return strings.TrimSpace(out)
	}
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
	// noLeak: no group query reached ROS or a domestic resolver, none left
	// on the LAN port, none left the gateway unmarked.
	// unmarkedBase is the one query the control phase sends without a mark on
	// purpose; the phases after it count from there.
	unmarkedBase := 0
	noLeak := func(phase string) {
		t.Helper()
		c := map[string]int{"gw unmarked": cnt("gw", "unmarked") - unmarkedBase, "gw lan": cnt("gw", "lan"), "gw domestic": cnt("gw", "domestic"),
			"ros domestic": cnt("ros", "domestic"), "ros group": cnt("ros", "group")}
		t.Logf("EVIDENCE %s counters: %v marked=%d snatted=%d at_us=%d at_us2=%d", phase, c, cnt("gw", "marked"), cnt("gw", "snatted"), cnt("us", "q"), cnt("us2", "q"))
		for k, v := range c {
			if v != 0 {
				fails++
				t.Errorf("%s: %s = %d, want 0", phase, k, v)
			}
		}
	}
	finish := func(phase string) {
		t.Helper()
		if fails > 0 {
			diag()
			t.Fatalf("%s: %d checks failed", phase, fails)
		}
	}

	// 1. Before failover: the preferred member answers and carries data.
	check("before", "UDP query via group us", query(us.Mark, "udp"), "198.18.1.1")
	check("before", "TCP query via group us", query(us.Mark, "tcp"), "198.18.1.1")
	check("before", "LAN client connection via group us (source seen by the server)", connect(), "100.64.1.2")
	if cnt("gw", "marked") == 0 || cnt("gw", "snatted") == 0 || cnt("us", "q") == 0 || cnt("us2", "q") != 0 {
		fails++
		t.Errorf("before: marked=%d snatted=%d at_us=%d at_us2=%d (want marked, SNATed, at us only)", cnt("gw", "marked"), cnt("gw", "snatted"), cnt("us", "q"), cnt("us2", "q"))
	}
	noLeak("before")
	finish("before")

	// 2. The preferred member goes down completely: resolver, tunnel, WAN.
	stopUS()
	must(in("us", "ip", "link", "set", hubUS.Iface(), "down")...)
	must(in("us", "ip", "link", "set", "eth0", "down")...)
	check("us down, hub not yet switched", "UDP query via group us", query(us.Mark, "udp"), "TIMEOUT")

	// 3. The hub's compiled group logic switches the group (the compiled
	// check line for group us, as check_groups runs it every 5 s).
	failover := b.File("nodes/hk-hub/usr/local/sbin/meridian-failover.sh")
	cut := strings.Index(failover, "# --- main loop ---")
	if cut < 0 {
		t.Fatal("no main-loop marker in the hub failover script")
	}
	var stepLine string
	for _, l := range strings.Split(failover, "\n") {
		if strings.HasPrefix(strings.TrimSpace(l), "group_step 'us' ") {
			stepLine = strings.TrimSpace(l)
		}
	}
	if stepLine == "" {
		t.Fatal("no group_step line for group us")
	}
	stepPath := write("hub-step.sh", strings.ReplaceAll(failover[:cut], "/run/meridian", run)+"\n"+stepLine+"\n")
	step := func(n int) {
		for i := 0; i < n; i++ {
			if out, err := sh(in("hub", "bash", stepPath)...); err != nil {
				diag()
				t.Fatalf("group_step: %v\n%s", err, out)
			}
		}
	}
	state := func(f string) string {
		v, _ := os.ReadFile(filepath.Join(run, "group", "us", f))
		return strings.TrimSpace(string(v))
	}
	// The hub's report reads the kernel's table: what the panel reads back
	// with sshexec.GroupStateCommand.
	report := func(key string) string {
		v, _ := os.ReadFile(filepath.Join(run, "group", "us", "report"))
		for _, l := range strings.Split(string(v), "\n") {
			if k, val, ok := strings.Cut(l, " "); ok && k == key {
				return val
			}
		}
		return ""
	}
	step(4)
	check("failover", "hub active member of group us", state("active"), "us-2")
	check("failover", "hub report: hop in table us", report("hop"), "us-2")
	check("failover", "hub report: result", report("result"), "ok")
	tbl := must(in("hub", "ip", "-6", "route", "show", "table", strconv.Itoa(us.Table))...)
	if !regexp.MustCompile(`(?m)^default dev ` + regexp.QuoteMeta(hubUS2.Iface()) + `( |$)`).MatchString(tbl) {
		fails++
		t.Errorf("failover: hub table %d does not point at us-2 (%s):\n%s", us.Table, hubUS2.Iface(), tbl)
	}
	finish("failover")

	// 4. After failover: the backup member answers new queries and carries
	// a new connection; nothing leaked at any point.
	q2 := cnt("us2", "q")
	check("after failover", "UDP query via group us", query(us.Mark, "udp"), "198.18.1.2")
	check("after failover", "TCP query via group us", query(us.Mark, "tcp"), "198.18.1.2")
	check("after failover", "LAN client connection via group us", connect(), "100.64.2.2")
	if cnt("us2", "q") == q2 {
		fails++
		t.Error("after failover: no group query reached us-2")
	}
	noLeak("after failover")
	finish("after failover")

	// 5. Both members down: the group has no member (its Mesh hop is not
	// sealed here, so the table is blackholed). Group DNS fails, and still
	// nothing goes to a domestic resolver or the LAN port.
	must(in("us2", "ip", "link", "set", hubUS2.Iface(), "down")...)
	step(4)
	check("all members down", "hub active hop of group us", state("active"), "mmesh")
	check("all members down", "hub report: hop in table us (Mesh unsealed)", report("hop"), "blackhole")
	check("all members down", "UDP query via group us", query(us.Mark, "udp"), "TIMEOUT")
	noLeak("all members down")
	finish("all members down")

	// 6. Control: the same query without the mark is not SNATed, so the
	// hub cannot put it into any group table; it gets no answer and never
	// reaches ROS. (This is the one unmarked group query of the test.)
	must(in("us2", "ip", "link", "set", hubUS2.Iface(), "up")...)
	time.Sleep(500 * time.Millisecond)
	q2 = cnt("us2", "q")
	check("control", "unmarked query", query(0, "udp"), "TIMEOUT")
	if cnt("us2", "q") != q2 || cnt("ros", "group") != 0 || cnt("ros", "domestic") != 0 || cnt("gw", "lan") != 0 {
		fails++
		t.Errorf("control: an unmarked query reached a member (%d), ROS (%d/%d) or the LAN port (%d)", cnt("us2", "q")-q2, cnt("ros", "group"), cnt("ros", "domestic"), cnt("gw", "lan"))
	}
	finish("control")
	unmarkedBase = cnt("gw", "unmarked")
	if unmarkedBase != 1 {
		fails++
		t.Errorf("control: the gateway counted %d unmarked group queries, want exactly the 1 the control sent", unmarkedBase)
	}

	// 7. Mesh backup, encapsulated and working. Exit us is alive but its
	// WireGuard path from the hub is dead: the hub drops everything on its
	// end of the tunnel (both ends stay up with carrier, as a WireGuard
	// device whose peer is unreachable does; an IPv6 address added on a
	// device without carrier would get no local route). us keeps its
	// tunnel route to the transit prefix, so a reply that ignored the Mesh
	// return path would go there and be counted (r_tun). us-2 stays dead.
	runUS := filepath.Join(dir, "usrun")
	if err := os.MkdirAll(runUS, 0o755); err != nil {
		t.Fatal(err)
	}
	must(in("hub", "nft", "-f", write("hub-cut.nft", fmt.Sprintf(`table inet wgcut {
  chain cut_in {
    type filter hook prerouting priority -500; policy accept;
    iifname "%[1]s" drop
  }
  chain cut_out {
    type filter hook output priority -500; policy accept;
    oifname "%[1]s" drop
  }
  chain cut_through {
    type filter hook forward priority -500; policy accept;
    oifname "%[1]s" drop
  }
}
`, hubUS.Iface())))...)
	must(in("us", "ip", "link", "set", hubUS.Iface(), "up")...)
	m := addrLine.FindStringSubmatch(b.File("nodes/us/etc/wireguard/" + hubUS.Iface() + ".conf"))
	for _, a := range strings.Split(m[1], ",") {
		if a = strings.TrimSpace(a); a != "" {
			args := []string{"ip", "addr", "replace", a, "dev", hubUS.Iface()}
			if strings.Contains(a, ":") {
				args = append(args, "nodad")
			}
			must(in("us", args...)...)
		}
	}
	must(in("us", "ip", "link", "set", "eth0", "up")...)
	must(in("us", "ip", "route", "replace", "default", "via", "100.64.1.1")...)
	start("us", "python3", resolverPy, usExit.DNSULA, "198.18.1.1")

	// Sidecar namespaces, the docker-bridge stand-ins and the Mesh overlay.
	for _, n := range []string{"hsc", "esc"} {
		lab.ns[n] = "mrd" + n + sfx
		must("ip", "netns", "add", lab.ns[n])
		must(in(n, "ip", "link", "set", "lo", "up")...)
		must(in(n, "sysctl", "-qw", "net.ipv4.ip_forward=1")...)
		must(in(n, "sysctl", "-qw", "net.ipv6.conf.all.forwarding=1")...)
		must(in(n, "sysctl", "-qw", "net.ipv4.conf.all.rp_filter=2")...)
		must(in(n, "sysctl", "-qw", "net.ipv4.conf.default.rp_filter=2")...)
	}
	must(in("hsc", "ip", "link", "add", "eth0", "type", "dummy")...)
	must(in("hsc", "ip", "link", "set", "eth0", "up")...)
	must(in("hsc", "ip", "addr", "add", "172.31.66.2/24", "dev", "eth0")...)
	must(in("hsc", "ip", "route", "add", "default", "dev", "eth0")...)
	must(in("hsc", "ip", "-6", "route", "add", "default", "dev", "eth0")...)
	xd, xe := "xd"+sfx, "xe"+sfx
	must("ip", "link", "add", xd, "type", "veth", "peer", "name", xe)
	must("ip", "link", "set", xd, "netns", ns["us"])
	must("ip", "link", "set", xe, "netns", ns["esc"])
	must(in("us", "ip", "link", "set", xd, "name", "dk0")...)
	must(in("us", "ip", "link", "set", "dk0", "up")...)
	must(in("us", "ip", "addr", "add", "172.30.66.1/30", "dev", "dk0")...)
	must(in("esc", "ip", "link", "set", xe, "name", "eth0")...)
	must(in("esc", "ip", "link", "set", "eth0", "up")...)
	must(in("esc", "ip", "addr", "add", "172.30.66.2/30", "dev", "eth0")...)
	must(in("esc", "ip", "route", "add", "default", "via", "172.30.66.1")...)
	cfa, cfb := "cfa"+sfx, "cfb"+sfx
	stopRelay := start("hsc", "python3", write("relay.py", netnsTunRelayPy), cfa, cfb)
	// linkDiag dumps links, addresses, routes and rules of namespaces.
	linkDiag := func(nss ...string) {
		for _, n := range nss {
			for _, args := range [][]string{
				{"ip", "-d", "link"}, {"ip", "addr"}, {"ip", "route"}, {"ip", "-6", "route"}, {"ip", "rule"}, {"ip", "-6", "rule"},
			} {
				out, err := sh(in(n, args...)...)
				t.Logf("DIAG %s$ %s (err=%v)\n%s", n, strings.Join(args, " "), err, out)
			}
		}
		body, _ := os.ReadFile(filepath.Join(dir, "hsc-relay.py.log"))
		t.Logf("DIAG relay log:\n%s", body)
	}
	deadline := time.Now().Add(10 * time.Second)
	for {
		if _, err := sh(in("hsc", "ip", "link", "show", cfb)...); err == nil {
			break
		}
		if time.Now().After(deadline) {
			linkDiag("hsc")
			t.Fatal("mesh setup: the tun relay did not create its devices in hsc")
		}
		time.Sleep(100 * time.Millisecond)
	}
	// Moving a device to another namespace sets it down and drops its
	// addresses: rename, bring up and address it only in its final
	// namespace, the far end (esc) first, so the relay never writes into a
	// device that is down (EIO).
	must(in("hsc", "ip", "link", "set", cfb, "netns", ns["esc"])...)
	must(in("hsc", "ip", "link", "set", cfa, "name", "cfw0")...)
	must(in("esc", "ip", "link", "set", cfb, "name", "cfw0")...)
	// Published resolver route: read from us's compiled mesh-up.
	usMeshUp := b.File("nodes/us/usr/local/sbin/meridian-mesh-up.sh")
	pub := regexp.MustCompile(`(?m)^# meridian-mesh-publish (\S+) group=us$`).FindStringSubmatch(usMeshUp)
	if pub == nil || pub[1] != res+"/128" {
		t.Fatalf("exit us does not publish group us's resolver %s:\n%s", res, usMeshUp)
	}
	for _, c := range []struct {
		n, self4, self6 string
		routes          [][]string
	}{
		{"esc", "100.96.0.2/32", "2001:db8:ff::2/128", nil},
		{"hsc", "100.96.0.1/32", "2001:db8:ff::1/128", [][]string{{"192.0.2.80/32"}, {"-6", pub[1]}}},
	} {
		must(in(c.n, "ip", "link", "set", "cfw0", "up")...)
		if l := must(in(c.n, "ip", "-o", "link", "show", "cfw0")...); !regexp.MustCompile(`[<,]UP[,>]`).MatchString(l) || strings.Contains(l, "NO-CARRIER") {
			linkDiag(c.n)
			t.Fatalf("mesh setup: %s cfw0 is not up with carrier after \"ip link set cfw0 up\" (relay not attached?):\n%s", c.n, l)
		}
		must(in(c.n, "ip", "addr", "add", c.self4, "dev", "cfw0")...)
		must(in(c.n, "ip", "-6", "addr", "add", c.self6, "dev", "cfw0", "nodad")...)
		must(in(c.n, "ip", "route", "add", "100.96.0.0/12", "dev", "cfw0")...)
		must(in(c.n, "ip", "-6", "route", "add", "2001:db8:ff::/64", "dev", "cfw0")...)
		for _, r := range c.routes {
			args := []string{"ip", "route", "add", r[0], "dev", "cfw0"}
			if len(r) == 2 {
				args = []string{"ip", "-6", "route", "add", r[1], "dev", "cfw0"}
			}
			must(in(c.n, args...)...)
		}
	}
	// Postcondition: the emulated Mesh carries IPv4 and IPv6 both ways.
	for _, args := range [][]string{
		{"ping", "-c", "2", "-W", "2", "-n", "100.96.0.2"},
		{"ping", "-6", "-c", "2", "-W", "2", "-n", "2001:db8:ff::2"},
	} {
		if out, err := sh(in("hsc", args...)...); err != nil {
			linkDiag("hsc", "esc")
			t.Fatalf("mesh setup: the emulated Mesh does not forward (hsc$ %s): %v\n%s", strings.Join(args, " "), err, out)
		}
	}
	t.Logf("EVIDENCE mesh setup: emulated Mesh hsc <-> esc forwards IPv4 and IPv6")
	// Source NAT of the connectors (assumed, see above) and docker's
	// masquerade on the exit host.
	must(in("hsc", "nft", "-f", write("hsc-nat.nft", "table inet mrdemu {\n  chain post {\n    type nat hook postrouting priority srcnat; policy accept;\n    oifname \"cfw0\" masquerade\n  }\n}\n"))...)
	must(in("esc", "nft", "-f", write("esc-nat.nft", "table ip mrdemu {\n  chain post {\n    type nat hook postrouting priority srcnat; policy accept;\n    oifname \"eth0\" masquerade\n  }\n}\n"))...)
	must(in("us", "nft", "-f", write("us-docker.nft", "table ip mrdemu {\n  chain post {\n    type nat hook postrouting priority srcnat; policy accept;\n    ip saddr 172.30.66.0/30 oifname \"eth0\" masquerade\n  }\n}\n"))...)
	must(in("hsc", "nft", "-f", write("hsc-obs.nft", "table inet meshobs {\n  counter leak {}\n  chain post {\n    type filter hook postrouting priority 400; policy accept;\n    oifname \"eth0\" counter name \"leak\"\n  }\n}\n"))...)
	must(in("us", "nft", "-f", write("us-meshobs.nft", fmt.Sprintf(`table inet meshobs {
  counter q_mesh {}
  counter q_tun {}
  counter r_mesh {}
  counter r_tun {}
  counter r_wan {}
  chain pre {
    type filter hook prerouting priority -400; policy accept;
    iifname "mmesh" ip6 daddr %[1]s counter name "q_mesh"
    iifname "%[2]s" ip6 daddr %[1]s counter name "q_tun"
  }
  chain post {
    type filter hook postrouting priority 400; policy accept;
    oifname "mmesh" ip6 saddr %[1]s counter name "r_mesh"
    oifname "%[2]s" ip6 saddr %[1]s counter name "r_tun"
    oifname "eth0" ip6 saddr %[1]s counter name "r_wan"
  }
}
`, validate.GroupResolverNet, hubUS.Iface())))...)
	mcnt := func(n, name string) int { return lab.counter(n, "meshobs", name) }

	// The compiled meridian-mesh-up.sh of the hub and of us, each against
	// its stand-in sidecar. Its combined stdout/stderr and exit code are
	// always logged.
	meshOut := map[string]string{}
	meshUp := func(node, n, runDir string, pid int, token string, args ...string) string {
		t.Helper()
		etc := filepath.Join(dir, n+"-etc")
		bin := filepath.Join(dir, n+"-bin")
		for _, d := range []string{etc, bin} {
			if err := os.MkdirAll(d, 0o755); err != nil {
				t.Fatal(err)
			}
		}
		mustWrite(t, filepath.Join(etc, "mesh.env"), "MESH_NODE_TOKEN="+token+"\n")
		mustWrite(t, filepath.Join(etc, "mesh-sidecar.compose.yml"), "# netns stand-in\n")
		// A shim, never the real docker daemon.
		shim := fmt.Sprintf("#!/bin/bash\ncase \"$1 $2\" in\n  \"compose -f\") shift 3; case \"$*\" in \"up -d\") exit 0 ;; \"ps -q mesh\") echo meridian-netns-sidecar; exit 0 ;; esac ;;\n  \"inspect -f\") echo %d; exit 0 ;;\nesac\nexit 1\n", pid)
		if err := os.WriteFile(filepath.Join(bin, "docker"), []byte(shim), 0o755); err != nil {
			t.Fatal(err)
		}
		body := b.File("nodes/" + node + "/usr/local/sbin/meridian-mesh-up.sh")
		body = strings.ReplaceAll(body, "/run/meridian", runDir)
		body = strings.ReplaceAll(body, "/etc/meridian/", etc+"/")
		p := write(n+"-mesh-up.sh", body)
		out, err := sh(in(n, append([]string{"env", "PATH=" + bin + ":" + os.Getenv("PATH"), "bash", p}, args...)...)...)
		code := 0
		if ee, ok := err.(*exec.ExitError); ok {
			code = ee.ExitCode()
		} else if err != nil {
			code = -1
		}
		meshOut[node] = fmt.Sprintf("args=%v exit=%d err=%v\n%s", args, code, err, out)
		t.Logf("EVIDENCE %s meridian-mesh-up.sh %v: exit=%d\n%s", node, args, code, out)
		if err != nil {
			linkDiag(n)
			t.Fatalf("%s meridian-mesh-up.sh %v: exit=%d %v\n%s", node, args, code, err, out)
		}
		return out
	}
	sleeper := func(n string) int {
		cmd := exec.Command("ip", "netns", "exec", ns[n], "sleep", "100000")
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = cmd.Process.Kill(); _, _ = cmd.Process.Wait() })
		return cmd.Process.Pid
	}
	hscPID, escPID := sleeper("hsc"), sleeper("esc")
	time.Sleep(300 * time.Millisecond)
	meshDiag := func() {
		linkDiag("hub", "hsc", "esc", "us")
		for _, c := range []struct {
			n    string
			args []string
		}{
			{"hub", []string{"ip", "neigh", "show", "dev", "mmesh"}}, {"hub", []string{"ip", "-6", "neigh", "show", "dev", "mmesh"}},
			{"hub", []string{"ip", "-6", "route", "show", "table", strconv.Itoa(us.Table)}},
			{"hsc", []string{"ip", "route", "show", "table", "170"}}, {"hsc", []string{"ip", "-6", "route", "show", "table", "170"}}, {"hsc", []string{"nft", "list", "ruleset"}},
			{"esc", []string{"ip", "route", "show", "table", "170"}}, {"esc", []string{"ip", "-6", "route", "show", "table", "170"}}, {"esc", []string{"nft", "list", "ruleset"}},
			{"us", []string{"ip", "-6", "neigh", "show", "dev", "mmesh"}}, {"us", []string{"ip", "-6", "route", "show", "table", strconv.Itoa(tableMeshDNS)}},
			{"us", []string{"nft", "list", "table", "inet", "meshobs"}}, {"us", []string{"nft", "list", "table", "inet", "meridian"}},
		} {
			out, err := sh(in(c.n, c.args...)...)
			t.Logf("DIAG %s$ %s (err=%v)\n%s", c.n, strings.Join(c.args, " "), err, out)
		}
		for _, d := range []string{run, runUS} {
			ents, _ := os.ReadDir(d)
			var names []string
			for _, e := range ents {
				names = append(names, e.Name())
			}
			t.Logf("DIAG %s: %v", d, names)
		}
		for node, o := range meshOut {
			t.Logf("DIAG last %s meridian-mesh-up.sh: %s", node, o)
		}
	}
	finishMesh := func(phase string) {
		t.Helper()
		if fails > 0 {
			meshDiag()
		}
		finish(phase)
	}
	// sealed checks every postcondition of a successful compiled seal on
	// host namespace n with sidecar namespace side; want lists table-170
	// routes the sidecar must have copied from cfw0.
	sealed := func(node, n, side, runDir string, want ...string) {
		t.Helper()
		var bad []string
		if _, err := os.Stat(filepath.Join(runDir, "mesh-sealed")); err != nil {
			bad = append(bad, "no seal file "+filepath.Join(runDir, "mesh-sealed"))
		}
		if !strings.Contains(meshOut[node], "mesh sidecar sealed") {
			bad = append(bad, "the script did not report \"mesh sidecar sealed\"")
		}
		for _, fam := range []string{"-4", "-6"} {
			if out, _ := sh(in(side, "ip", fam, "rule")...); !strings.Contains(out, "iif mmesh-c lookup 170") {
				bad = append(bad, side+": no "+fam+" rule \"iif mmesh-c lookup 170\"")
			}
		}
		if out, _ := sh(in(side, "nft", "list", "table", "inet", "meridian_mesh")...); !strings.Contains(out, `iifname "mmesh-c" oifname != "cfw0" drop`) {
			bad = append(bad, side+": inet meridian_mesh does not drop mmesh-c -> anything but cfw0")
		}
		t170, _ := sh(in(side, "ip", "-4", "route", "show", "table", "170")...)
		o6, _ := sh(in(side, "ip", "-6", "route", "show", "table", "170")...)
		t170 += o6
		if !strings.Contains(t170, "unreachable default") {
			bad = append(bad, side+": table 170 has no unreachable default")
		}
		for _, w := range want {
			if !strings.Contains(t170, w) {
				bad = append(bad, side+": table 170 lacks \""+w+"\"")
			}
		}
		n4, _ := sh(in(n, "ip", "-4", "neigh", "show", "dev", "mmesh")...)
		n6, _ := sh(in(n, "ip", "-6", "neigh", "show", "dev", "mmesh")...)
		if !strings.Contains(n4, "169.254.66.2") || !strings.Contains(n4, "PERMANENT") || !strings.Contains(n6, "fe80::66:2") || !strings.Contains(n6, "PERMANENT") {
			bad = append(bad, n+": no permanent neighbours for the sidecar next-hops on mmesh")
		}
		if len(bad) > 0 {
			meshDiag()
			t.Fatalf("mesh setup: %s seal postconditions failed:\n  %s", node, strings.Join(bad, "\n  "))
		}
		t.Logf("EVIDENCE mesh setup: %s sealed; %s table 170:\n%s", node, side, t170)
	}
	meshUp("hk-hub", "hub", run, hscPID, "netns-placeholder")
	sealed("hk-hub", "hub", "hsc", run, res+" dev cfw0", "192.0.2.80 dev cfw0")
	meshUp("us", "us", runUS, escPID, "netns-placeholder")
	sealed("us", "us", "esc", runUS, "100.96.0.0/12 dev cfw0", "2001:db8:ff::/64 dev cfw0")
	// The static install agrees with the seal: the compiled routes script
	// of us, run again now, keeps table 171 on the sidecar.
	must(in("us", "bash", write("us-routes-mesh.sh", strings.ReplaceAll(b.File("nodes/us/usr/local/sbin/meridian-routes.sh"), "/run/meridian", runUS)))...)
	t171 := must(in("us", "ip", "-6", "route", "show", "table", strconv.Itoa(tableMeshDNS))...)
	if !regexp.MustCompile(`(?m)^default via fe80::66:2 dev mmesh( |$)`).MatchString(t171) || !strings.Contains(t171, "blackhole default") {
		fails++
		t.Errorf("mesh: us table %d is not on its sidecar next-hop with the blackhole floor:\n%s", tableMeshDNS, t171)
	} else {
		t.Logf("EVIDENCE mesh: us table %d:\n%s", tableMeshDNS, t171)
	}
	finishMesh("mesh setup")

	step(1)
	check("mesh", "hub active hop of group us", state("active"), "mmesh")
	check("mesh", "hub report: hop in table us (Mesh sealed)", report("hop"), "mmesh")
	check("mesh", "hub report: result", report("result"), "ok")
	tbl = must(in("hub", "ip", "-6", "route", "show", "table", strconv.Itoa(us.Table))...)
	if !regexp.MustCompile(`(?m)^default via fe80::66:2 dev mmesh( |$)`).MatchString(tbl) {
		fails++
		t.Errorf("mesh: hub table %d is not on the sidecar next-hop:\n%s", us.Table, tbl)
	}
	finishMesh("mesh switch")
	qm, rm := mcnt("us", "q_mesh"), mcnt("us", "r_mesh")
	check("mesh", "UDP query via group us (answered by exit us over the Mesh)", query(us.Mark, "udp"), "198.18.1.1")
	check("mesh", "TCP query via group us (answered by exit us over the Mesh)", query(us.Mark, "tcp"), "198.18.1.1")
	check("mesh", "LAN client connection via group us over the Mesh (source seen by the server)", connect(), "100.64.1.2")
	meshCounters := func(phase string) {
		t.Helper()
		c := map[string]int{"us q_tun": mcnt("us", "q_tun"), "us r_tun": mcnt("us", "r_tun"), "us r_wan": mcnt("us", "r_wan"), "hub sidecar docker bridge": mcnt("hsc", "leak")}
		t.Logf("EVIDENCE %s Mesh counters: %v q_mesh=%d r_mesh=%d", phase, c, mcnt("us", "q_mesh"), mcnt("us", "r_mesh"))
		for k, v := range c {
			if v != 0 {
				fails++
				t.Errorf("%s: %s = %d, want 0", phase, k, v)
			}
		}
	}
	if mcnt("us", "q_mesh") <= qm || mcnt("us", "r_mesh") <= rm {
		fails++
		t.Errorf("mesh: queries on mmesh %d -> %d, replies on mmesh %d -> %d (want both to grow)", qm, mcnt("us", "q_mesh"), rm, mcnt("us", "r_mesh"))
	}
	meshCounters("mesh")
	noLeak("mesh")
	finishMesh("mesh")

	// 8. The Mesh overlay goes away (the tun relay stops; Cloudflare's
	// routes vanish with the warp devices). The hub keeps the group on the
	// sealed sidecar; nothing answers, nothing leaves elsewhere.
	stopRelay()
	time.Sleep(500 * time.Millisecond)
	step(1)
	check("mesh down", "hub report: hop in table us", report("hop"), "mmesh")
	check("mesh down", "UDP query via group us", query(us.Mark, "udp"), "TIMEOUT")
	check("mesh down", "TCP query via group us", query(us.Mark, "tcp"), "TIMEOUT")
	check("mesh down", "LAN client connection via group us", connect(), "TIMEOUT")
	meshCounters("mesh down")
	noLeak("mesh down")
	finishMesh("mesh down")

	// 9. The seal goes away (empty token: the compiled mesh-up unseals).
	// The hub blackholes the group table on its next round and us's table
	// 171 loses its route to the sidecar.
	meshUp("hk-hub", "hub", run, hscPID, "", "--seal-only")
	meshUp("us", "us", runUS, escPID, "", "--seal-only")
	step(1)
	check("unsealed", "hub active hop of group us", state("active"), "mmesh")
	check("unsealed", "hub report: hop in table us", report("hop"), "blackhole")
	check("unsealed", "UDP query via group us", query(us.Mark, "udp"), "TIMEOUT")
	t171 = must(in("us", "ip", "-6", "route", "show", "table", strconv.Itoa(tableMeshDNS))...)
	if strings.Contains(t171, "via") || !strings.Contains(t171, "blackhole default") {
		fails++
		t.Errorf("unsealed: us table 171 still routes to the sidecar:\n%s", t171)
	}
	meshCounters("unsealed")
	noLeak("unsealed")
	finishMesh("unsealed")
	logs()
	fmt.Fprintln(os.Stderr, "meridian-netns-group-dns-test-ok")
}

// netnsTunRelayPy A B: creates the tun devices A and B in the current
// namespace (the test then moves B) and copies every packet between them,
// standing in for the Cloudflare Mesh between two connectors.
const netnsTunRelayPy = `import fcntl, os, select, struct, sys
TUNSETIFF, IFF_TUN, IFF_NO_PI = 0x400454ca, 0x0001, 0x1000
def tun(name):
    fd = os.open("/dev/net/tun", os.O_RDWR)
    fcntl.ioctl(fd, TUNSETIFF, struct.pack("16sH", name.encode(), IFF_TUN | IFF_NO_PI))
    return fd
a, b = tun(sys.argv[1]), tun(sys.argv[2])
print("relay up", flush=True)
peer = {a: b, b: a}
while True:
    r, _, _ = select.select([a, b], [], [])
    for fd in r:
        try:
            os.write(peer[fd], os.read(fd, 65535))
        except OSError as e:
            print("relay", e, flush=True)
`

// netnsResolverPy ADDR ANSWER: a DNS responder on [ADDR]:53, UDP and TCP,
// that answers every query with one A record ANSWER (TTL 0) and logs the
// source of each query.
const netnsResolverPy = `import socket, struct, sys, threading
addr, answer = sys.argv[1], socket.inet_aton(sys.argv[2])

def reply(q):
    i = 12
    while q[i] != 0:
        i += q[i] + 1
    qend = i + 5
    hdr = q[:2] + struct.pack(">HHHHH", 0x8180, 1, 1, 0, 0)
    return hdr + q[12:qend] + struct.pack(">HHHIH", 0xC00C, 1, 1, 0, 4) + answer

def udp():
    s = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
    s.bind((addr, 53))
    while True:
        q, peer = s.recvfrom(4096)
        print("udp query from", peer[0], flush=True)
        s.sendto(reply(q), peer)

def tcp():
    s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((addr, 53))
    s.listen(8)
    while True:
        c, peer = s.accept()
        try:
            c.settimeout(3)
            n = struct.unpack(">H", c.recv(2))[0]
            q = b""
            while len(q) < n:
                q += c.recv(n - len(q))
            print("tcp query from", peer[0], flush=True)
            r = reply(q)
            c.sendall(struct.pack(">H", len(r)) + r)
        except Exception as e:
            print("tcp error", e, flush=True)
        finally:
            c.close()

threading.Thread(target=udp, daemon=True).start()
tcp()
`

// netnsQueryPy SERVER MARK PROTO NAME: one A query for NAME to [SERVER]:53
// over PROTO with SO_MARK=MARK (0 = no mark), as SmartDNS's -set-mark does.
// Prints the first A answer or TIMEOUT.
const netnsQueryPy = `import socket, struct, sys, random
server, mark, proto, name = sys.argv[1], int(sys.argv[2]), sys.argv[3], sys.argv[4]
q = struct.pack(">HHHHHH", random.randint(0, 65535), 0x0100, 1, 0, 0, 0)
for label in name.split("."):
    q += bytes([len(label)]) + label.encode()
q += b"\x00" + struct.pack(">HH", 1, 1)
try:
    if proto == "udp":
        s = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
    else:
        s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
    if mark:
        s.setsockopt(socket.SOL_SOCKET, 36, mark)  # SO_MARK
    s.settimeout(3)
    if proto == "udp":
        s.sendto(q, (server, 53))
        r = s.recv(4096)
    else:
        s.connect((server, 53))
        s.sendall(struct.pack(">H", len(q)) + q)
        n = struct.unpack(">H", s.recv(2))[0]
        r = b""
        while len(r) < n:
            r += s.recv(n - len(r))
    print(socket.inet_ntoa(r[-4:]))
except Exception:
    print("TIMEOUT")
`

// netnsServerPy ADDR PORT: a TCP server that answers each connection with
// the peer's address (the exit's masquerade address names the member).
const netnsServerPy = `import socket, sys
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind((sys.argv[1], int(sys.argv[2])))
s.listen(8)
while True:
    c, peer = s.accept()
    print("connection from", peer[0], flush=True)
    c.sendall((peer[0] + "\n").encode())
    c.close()
`

// netnsConnectPy ADDR PORT: connect, print the server's line or TIMEOUT.
const netnsConnectPy = `import socket, sys
try:
    s = socket.create_connection((sys.argv[1], int(sys.argv[2])), timeout=5)
    print(s.recv(100).decode().strip())
except Exception:
    print("TIMEOUT")
`
