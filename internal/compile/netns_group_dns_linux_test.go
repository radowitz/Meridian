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
// Root only, Linux only, opt-in (MERIDIAN_NETNS_TEST=1); needs ip, nft,
// ping, bash and python3. Not executed as of 2026-11-13: until a passing
// log is archived the property is NOT verified.
func TestNetnsGroupDNSFailover(t *testing.T) {
	netnsPrereqs(t)
	if _, err := exec.LookPath("python3"); err != nil {
		t.Skip("python3 not installed")
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
	hubUS, hubUS2 := hubDirect(tunnels, "us"), hubDirect(tunnels, "us-2")
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
	noLeak := func(phase string) {
		t.Helper()
		c := map[string]int{"gw unmarked": cnt("gw", "unmarked"), "gw lan": cnt("gw", "lan"), "gw domestic": cnt("gw", "domestic"),
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
	logs()
	fmt.Fprintln(os.Stderr, "meridian-netns-group-dns-test-ok")
}

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
