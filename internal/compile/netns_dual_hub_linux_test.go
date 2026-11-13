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
	"github.com/radowitz/meridian/internal/remoteaccess"
)

// TestNetnsDualHub is the runtime check of the primary/backup hub data
// plane (docs/architecture.md「主枢纽与备用枢纽」) on defaults.DualHubExample
// (gateway → relay ali → IX primary hub "ix" → exits dc1, dc2; backup hub
// "hk5" reached from the gateway over its WSS link) with remote access on.
//
// Namespaces: the TestNetnsReloadNoLeak lab (gateway, ROS, LAN client,
// remote device; newNetnsLab) plus ali, ix, hk5, dc1, dc2 and "net" (the
// Internet behind both exits: data servers 192.0.2.80, a group-hk target,
// and 192.0.2.81, the target of the rule pinned to dc2). Every host runs
// its COMPILED nft and routes script. The tunnels gw-ali (UDP leg), gw-hk5
// (the backup's WSS link; the WSS transport itself is not emulated), ali-ix,
// ix-dc1, ix-dc2, hk5-dc1 and hk5-dc2 are veth pairs carrying the compiled
// tunnel addresses (ARP/ND off, one MAC on both ends, so "dev <tunnel>"
// routes behave as on a point-to-point WireGuard device); every other
// tunnel interface is a dummy with its compiled addresses. No WireGuard is
// involved. The gateway's path choice is the COMPILED meridian-failover.sh
// (its upstream_step, run a fixed number of passes per phase with the real
// ping), so the end-to-end main path probe is exercised for real. Resolver
// stand-ins (python3) sit on each exit's tunnel resolver address and answer
// 198.18.1.1 (dc1) or 198.18.1.2 (dc2).
//
// Phases:
//  1. main path: group-hk and pinned-dc2 connections, the group resolver
//     (marked) and dc2's hub-independent resolver address (unmarked) all go
//     gateway → ali → ix; nothing touches hk5; replies leave the exits on
//     their ix tunnel.
//  2. relay → IX cut (ali drops everything on its ix tunnel, carrier up):
//     the gateway's end-to-end probe fails on the main path and the
//     compiled failover moves table 102 to the backup hub after FAILS_NEED
//     passes; the same flows then go through hk5, the exits answer them on
//     their hk5 tunnel and never on their ix tunnel (reply symmetry), group
//     DNS and the exit resolver follow the backup hub.
//  3. all down (hk5 also cut): the failover stays where it is; new
//     connections time out; zero packets of them leave the gateway's LAN
//     port or reach ROS.
//  4. main path back: after RECOVERS_NEED passes the failover returns to the
//     main path and traffic goes through ix again.
//
// Not covered here: the Mesh hop (Mesh edges join the primary hub only;
// TestNetnsGroupDNSFailover covers the Mesh phase on the single-hub
// example), WireGuard and wstunnel themselves, the switch-back cooldown
// (each phase starts the failover with no previous switch; the unit test
// TestDualHubGatewayFailoverTakeoverAndReturn covers it).
//
// Root only, Linux only, opt-in (MERIDIAN_NETNS_TEST=1); needs ip, nft,
// ping, bash and python3. It has NOT been executed on a real host yet:
// until a passing log is archived these properties are NOT verified at
// runtime.
func TestNetnsDualHub(t *testing.T) {
	netnsPrereqs(t)
	if _, err := exec.LookPath("python3"); err != nil {
		t.Skip("python3 not installed")
	}
	topo := dualRAExample(t)
	lab := newNetnsLab(t, topo, labV6{prefix: "2001:db8:100::/64", gw: "2001:db8:100::88", cli: "2001:db8:100::50"})
	b, dir, sh, must, in := lab.b, lab.dir, lab.sh, lab.must, lab.in
	tunnels := mustTunnels(t, topo)
	exits, groups := plans(t, topo)
	hk := mustGroup(t, groups, "hk")
	if !hk.Dynamic || hk.Target.Node.ID != "dc1" {
		t.Fatalf("group hk must be switchable with target dc1: %+v", hk.Policy())
	}
	link := func(id, mode string) Tunnel {
		for _, tun := range tunnels {
			if tun.LinkID == id && (mode == "" || tun.Mode == mode) {
				return tun
			}
		}
		t.Fatalf("no tunnel for link %s", id)
		return Tunnel{}
	}
	gwAli, gwHk5, aliIX := link("gw-ali", "udp"), link("gw-hk5", ""), link("ali-ix", "")
	ixDC1, ixDC2, hk5DC1, hk5DC2 := link("ix-dc1", ""), link("ix-dc2", ""), link("hk5-dc1", ""), link("hk5-dc2", "")
	dc1, _ := exitByID(exits, "dc1")
	dc2, _ := exitByID(exits, "dc2")
	t.Logf("path: gw %s ali %s ix %s/%s; backup gw %s hk5 %s/%s; hk mark %#x transit %s resolver %s; dc2 resolver %s",
		gwAli.Iface(), aliIX.Iface(), ixDC1.Iface(), ixDC2.Iface(), gwHk5.Iface(), hk5DC1.Iface(), hk5DC2.Iface(), hk.Mark, hk.TransitV4, hk.Resolver, dc2.Resolver)

	sfx := strconv.Itoa(os.Getpid() % 100000)
	nodeNS := map[string]string{"gw": "gw", "ali": "ali", "ix": "ix", "hk5": "hk5", "dc1": "dc1", "dc2": "dc2"}
	for _, n := range []string{"ali", "ix", "hk5", "dc1", "dc2", "net"} {
		lab.ns[n] = "mrd" + n + sfx
		must("ip", "netns", "add", lab.ns[n])
		must(in(n, "ip", "link", "set", "lo", "up")...)
	}
	ns := lab.ns
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
	vethN := 0
	p2p := func(a, bNode, iface string) {
		t.Helper()
		vethN++
		x, y := fmt.Sprintf("ya%d%s", vethN, sfx), fmt.Sprintf("yb%d%s", vethN, sfx)
		mac := fmt.Sprintf("02:6e:00:00:%02x:01", vethN)
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
	// The gateway's tunnels on the two paths were dummies in the lab.
	must(in("gw", "ip", "link", "del", gwAli.Iface())...)
	must(in("gw", "ip", "link", "del", gwHk5.Iface())...)
	p2p("gw", "ali", gwAli.Iface())
	p2p("gw", "hk5", gwHk5.Iface())
	p2p("ali", "ix", aliIX.Iface())
	p2p("ix", "dc1", ixDC1.Iface())
	p2p("ix", "dc2", ixDC2.Iface())
	p2p("hk5", "dc1", hk5DC1.Iface())
	p2p("hk5", "dc2", hk5DC2.Iface())
	veths := map[string]bool{}
	for _, tun := range []Tunnel{gwAli, gwHk5, aliIX, ixDC1, ixDC2, hk5DC1, hk5DC2} {
		veths[tun.Iface()] = true
	}
	for _, node := range []string{"ali", "ix", "hk5", "dc1", "dc2"} {
		pre := "nodes/" + node + "/etc/wireguard/"
		for path := range b.Files {
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
	for _, n := range []string{"ali", "ix", "hk5"} {
		must(in(n, "ip", "link", "add", "eth0", "type", "dummy")...)
		must(in(n, "ip", "link", "set", "eth0", "up")...)
		must(in(n, "ip", "route", "add", "default", "dev", "eth0")...)
		must(in(n, "ip", "-6", "route", "add", "default", "dev", "eth0")...)
	}
	for i, n := range []string{"dc1", "dc2"} {
		x, y := fmt.Sprintf("yw%d%s", i, sfx), fmt.Sprintf("yn%d%s", i, sfx)
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
	must(in("net", "ip", "addr", "add", "192.0.2.81/32", "dev", "srv")...)
	must(in("net", "ip", "link", "set", "srv", "up")...)
	// Postcondition: the exits reach the data servers over their WAN.
	for _, n := range []string{"dc1", "dc2"} {
		if out, err := sh(in(n, "ping", "-c", "1", "-W", "2", "192.0.2.80")...); err != nil {
			t.Fatalf("setup: %s cannot reach the data server over its WAN:\n%s", n, out)
		}
	}

	write := func(name, body string) string {
		p := filepath.Join(dir, name)
		mustWrite(t, p, body)
		return p
	}
	runDir := map[string]string{}
	for _, node := range []string{"ali", "ix", "hk5", "dc1", "dc2"} {
		runDir[node] = filepath.Join(dir, node+"run")
		routes := strings.ReplaceAll(b.File("nodes/"+node+"/usr/local/sbin/meridian-routes.sh"), "/run/meridian", runDir[node])
		if out, err := sh(in(node, "bash", write(node+"-routes.sh", routes))...); err != nil {
			t.Fatalf("setup: %s routes script: %v\n%s", node, err, out)
		}
		nftP := write(node+".nft", b.File("nodes/"+node+"/etc/nftables.d/meridian.nft"))
		must(in(node, "nft", "-c", "-f", nftP)...)
		must(in(node, "nft", "-f", nftP)...)
		must(in(node, "sysctl", "-qw", "net.ipv4.ip_forward=1")...)
		must(in(node, "sysctl", "-qw", "net.ipv6.conf.all.forwarding=1")...)
	}
	// Postcondition: each exit has its two hub return tables and rules.
	for _, n := range []string{"dc1", "dc2"} {
		rules := must(in(n, "ip", "-4", "rule")...)
		if !strings.Contains(rules, "fwmark 0x4d50 lookup 172") || !strings.Contains(rules, "fwmark 0x4d51 lookup 173") {
			t.Fatalf("setup: %s lacks the hub return rules:\n%s", n, rules)
		}
	}
	gwRun := filepath.Join(dir, "gwrun")
	must(in("gw", "bash", lab.routesPath)...)
	must(in("gw", "nft", "-c", "-f", lab.nftPath)...)
	must(in("gw", "nft", "-f", lab.nftPath)...)
	// Postcondition: table 102 starts on the main path; the probe routes exist.
	if tbl := must(in("gw", "ip", "route", "show", "table", "102")...); !regexp.MustCompile(`(?m)^default dev ` + gwAli.Iface() + `\b`).MatchString(tbl) {
		t.Fatalf("setup: table 102 does not start on %s:\n%s", gwAli.Iface(), tbl)
	}
	probe := aliIX.EastV4
	if out := must(in("gw", "ip", "route", "show", probe)...); !strings.Contains(out, "src "+upstreamProbeSrc) {
		t.Fatalf("setup: no probe route to %s:\n%s", probe, out)
	}

	// Observation tables (separate tables, never replaced).
	obs := func(n, body string) {
		must(in(n, "nft", "-f", write(n+"-obs.nft", "table inet dualobs {\n"+body+"}\n"))...)
	}
	obs("gw", fmt.Sprintf(`  counter lanleak {}
  counter lanleak6 {}
  chain post {
    type filter hook postrouting priority 400; policy accept;
    oifname "%[1]s" ip daddr { 192.0.2.80, 192.0.2.81 } counter name "lanleak"
    oifname "%[1]s" ip6 daddr { fd66::53:0/112, fd66::54:0/112 } counter name "lanleak6"
  }
`, lab.lan))
	must(in("ros", "nft", "-f", write("ros-obs.nft", `table inet dualobs {
  counter foreign {}
  counter dns {}
  chain pre {
    type filter hook prerouting priority -400; policy accept;
    ip daddr { 192.0.2.80, 192.0.2.81 } counter name "foreign"
    ip6 daddr { fd66::53:0/112, fd66::54:0/112 } counter name "dns"
  }
}
`))...)
	obs("ix", fmt.Sprintf("  counter in {}\n  chain pre {\n    type filter hook prerouting priority -400; policy accept;\n    iifname %q counter name \"in\"\n  }\n", aliIX.Iface()))
	obs("hk5", fmt.Sprintf("  counter in {}\n  chain pre {\n    type filter hook prerouting priority -400; policy accept;\n    iifname %q counter name \"in\"\n  }\n", gwHk5.Iface()))
	for _, e := range []struct {
		n        string
		pri, bak Tunnel
	}{{"dc1", ixDC1, hk5DC1}, {"dc2", ixDC2, hk5DC2}} {
		obs(e.n, fmt.Sprintf(`  counter r_p {}
  counter r_b {}
  chain post {
    type filter hook postrouting priority 400; policy accept;
    oifname %q ct direction reply counter name "r_p"
    oifname %q ct direction reply counter name "r_b"
  }
`, e.pri.Iface(), e.bak.Iface()))
	}
	cnt := func(n, name string) int { return lab.counter(n, "dualobs", name) }

	resolverPy := write("resolver.py", netnsResolverPy)
	serverPy := write("server.py", netnsServerPy)
	queryPy := write("query.py", netnsQueryPy)
	connectPy := write("connect.py", netnsConnectPy)
	start := func(n string, args ...string) {
		cmd := exec.Command("ip", append([]string{"netns", "exec", ns[n]}, args...)...)
		logf, _ := os.Create(filepath.Join(dir, n+"-"+filepath.Base(args[1])+"-"+args[2]+".log"))
		cmd.Stdout, cmd.Stderr = logf, logf
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = cmd.Process.Kill(); _, _ = cmd.Process.Wait(); _ = logf.Close() })
	}
	start("dc1", "python3", resolverPy, dc1.DNSULA, "198.18.1.1")
	start("dc2", "python3", resolverPy, dc2.DNSULA, "198.18.1.2")
	start("net", "python3", serverPy, "192.0.2.80", "8080")
	start("net", "python3", serverPy, "192.0.2.81", "8080")
	time.Sleep(time.Second)
	// The rule pinned to dc2: its set holds 192.0.2.81, as SmartDNS's nftset
	// would after resolving its name.
	var pinSet string
	for _, rp := range planRules(topo, exits, groups, nil) {
		if rp.Rule.ID == "pin-dc2" {
			pinSet = rp.Set4
		}
	}
	if pinSet == "" {
		t.Fatal("no plan for rule pin-dc2")
	}
	must(in("gw", "nft", "add", "element", "inet", "meridian", pinSet, "{ 192.0.2.81 }")...)

	// The compiled gateway failover, run for n passes from path cur.
	fo := b.File("nodes/gw/usr/local/sbin/meridian-failover.sh")
	cut := strings.Index(fo, "# --- main loop ---")
	if cut < 0 {
		t.Fatal("no main-loop marker in the gateway failover script")
	}
	foText := strings.ReplaceAll(fo[:cut], "/run/meridian", gwRun)
	drive := func(cur string, n int) string {
		t.Helper()
		p := write("gw-drive.sh", foText+"\ncur="+shQuote(cur)+"\nlast_switch=0\nfor i in $(seq "+strconv.Itoa(n)+"); do upstream_step; done\necho \"CUR=$cur\"\n")
		out, err := sh(in("gw", "bash", p)...)
		m := regexp.MustCompile(`CUR=(\S+)`).FindStringSubmatch(out)
		if err != nil || m == nil {
			t.Fatalf("gateway failover: %v\n%s", err, out)
		}
		return m[1]
	}
	record := func(key string) string {
		v, _ := os.ReadFile(filepath.Join(gwRun, "upstream"))
		for _, l := range strings.Split(string(v), "\n") {
			if k, val, ok := strings.Cut(l, " "); ok && k == key {
				return val
			}
		}
		return ""
	}
	query := func(server string, mark uint32) string {
		out, _ := sh(in("gw", "python3", queryPy, server, strconv.FormatUint(uint64(mark), 10), "udp", "probe.example.com")...)
		return strings.TrimSpace(out)
	}
	connect := func(addr string) string {
		out, _ := sh(in("cli", "python3", connectPy, addr, "8080")...)
		return strings.TrimSpace(out)
	}
	diag := func() {
		for _, c := range []struct {
			n    string
			args []string
		}{
			{"gw", []string{"ip", "rule"}}, {"gw", []string{"ip", "route", "show", "table", "102"}}, {"gw", []string{"ip", "route"}},
			{"gw", []string{"ip", "-6", "route"}}, {"gw", []string{"cat", filepath.Join(gwRun, "upstream")}},
			{"gw", []string{"nft", "list", "table", "inet", "dualobs"}}, {"gw", []string{"nft", "list", "table", "inet", "meridian_guard"}},
			{"ali", []string{"ip", "rule"}}, {"ali", []string{"ip", "route"}}, {"ali", []string{"ip", "route", "show", "table", "150"}},
			{"ix", []string{"ip", "rule"}}, {"ix", []string{"ip", "route"}}, {"ix", []string{"ip", "-6", "route"}}, {"ix", []string{"ip", "route", "show", "table", strconv.Itoa(hk.Table)}},
			{"hk5", []string{"ip", "rule"}}, {"hk5", []string{"ip", "route"}}, {"hk5", []string{"ip", "-6", "route"}}, {"hk5", []string{"ip", "route", "show", "table", strconv.Itoa(hk.Table)}},
			{"dc1", []string{"nft", "list", "ruleset"}}, {"dc1", []string{"ip", "rule"}}, {"dc1", []string{"ip", "route", "show", "table", "172"}}, {"dc1", []string{"ip", "route", "show", "table", "173"}},
			{"dc2", []string{"nft", "list", "ruleset"}}, {"dc2", []string{"ip", "-6", "route", "show", "table", "172"}}, {"dc2", []string{"ip", "-6", "route", "show", "table", "173"}},
			{"ros", []string{"nft", "list", "table", "inet", "dualobs"}},
		} {
			out, err := sh(in(c.n, c.args...)...)
			t.Logf("DIAG %s$ %s (err=%v)\n%s", c.n, strings.Join(c.args, " "), err, out)
		}
		for _, f := range []string{"dc1-resolver.py-" + dc1.DNSULA + ".log", "dc2-resolver.py-" + dc2.DNSULA + ".log", "net-server.py-192.0.2.80.log", "net-server.py-192.0.2.81.log"} {
			body, _ := os.ReadFile(filepath.Join(dir, f))
			t.Logf("DIAG %s:\n%s", f, body)
		}
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
	zero := func(phase string, names map[string][2]string) {
		t.Helper()
		for label, nc := range names {
			if v := cnt(nc[0], nc[1]); v != 0 {
				fails++
				t.Errorf("%s: %s = %d, want 0", phase, label, v)
			}
		}
	}
	noLeak := func(phase string) {
		zero(phase, map[string][2]string{"gw LAN port: data": {"gw", "lanleak"}, "gw LAN port: resolver": {"gw", "lanleak6"},
			"ROS: data": {"ros", "foreign"}, "ROS: resolver queries": {"ros", "dns"}})
	}
	finish := func(phase string) {
		t.Helper()
		if fails > 0 {
			diag()
			t.Fatalf("%s: %d checks failed", phase, fails)
		}
	}
	snapshot := func() map[string]int {
		return map[string]int{"ix": cnt("ix", "in"), "hk5": cnt("hk5", "in"), "dc1p": cnt("dc1", "r_p"), "dc1b": cnt("dc1", "r_b"), "dc2p": cnt("dc2", "r_p"), "dc2b": cnt("dc2", "r_b")}
	}
	flows := func(phase string) {
		check(phase, "group hk connection (source seen by the server)", connect("192.0.2.80"), "100.64.1.2")
		check(phase, "connection pinned to dc2", connect("192.0.2.81"), "100.64.2.2")
		check(phase, "group hk resolver (marked query)", query(hk.Resolver, hk.Mark), "198.18.1.1")
		check(phase, "dc2's hub-independent resolver address", query(dc2.Resolver, 0), "198.18.1.2")
	}

	// 1. Main path.
	check("main", "failover keeps the main path", drive("udp", 2), "udp")
	check("main", "upstream record: hub", record("hub"), "ix")
	check("main", "upstream record: state", record("state"), "ok")
	before := snapshot()
	flows("main")
	after := snapshot()
	if after["ix"] == before["ix"] || after["hk5"] != before["hk5"] || after["dc1p"] == before["dc1p"] || after["dc1b"] != before["dc1b"] || after["dc2b"] != before["dc2b"] {
		fails++
		t.Errorf("main: traffic did not stay on ix (before %v after %v)", before, after)
	}
	noLeak("main")
	finish("main")

	// 2. relay → IX cut: the main path is down end to end, the gateway
	// moves to the backup hub, replies return through hk5.
	must(in("ali", "nft", "-f", write("ali-cut.nft", fmt.Sprintf(`table inet wgcut {
  chain cut_in { type filter hook prerouting priority -500; policy accept; iifname %[1]q drop; }
  chain cut_out { type filter hook output priority -500; policy accept; oifname %[1]q drop; }
  chain cut_fwd { type filter hook forward priority -500; policy accept; oifname %[1]q drop; }
}
`, aliIX.Iface())))...)
	check("ix cut", "two passes: still on the main path (FAILS_NEED is 3)", drive("udp", 2), "udp")
	check("ix cut", "third pass: backup hub", drive("udp", 3), "backup")
	check("ix cut", "upstream record: hub", record("hub"), "hk5")
	check("ix cut", "upstream record: tier", record("tier"), "backup")
	if tbl := must(in("gw", "ip", "route", "show", "table", "102")...); !regexp.MustCompile(`(?m)^default dev ` + gwHk5.Iface() + `\b`).MatchString(tbl) {
		fails++
		t.Errorf("ix cut: table 102 not on %s:\n%s", gwHk5.Iface(), tbl)
	}
	before = snapshot()
	flows("ix cut")
	after = snapshot()
	if after["hk5"] == before["hk5"] || after["dc1b"] == before["dc1b"] || after["dc2b"] == before["dc2b"] {
		fails++
		t.Errorf("ix cut: traffic did not take the backup hub (before %v after %v)", before, after)
	}
	if after["dc1p"] != before["dc1p"] || after["dc2p"] != before["dc2p"] {
		fails++
		t.Errorf("ix cut: an exit replied into its ix tunnel to a connection that came from hk5 (before %v after %v)", before, after)
	}
	noLeak("ix cut")
	finish("ix cut")

	// 3. Everything down: stay, drop, nothing out of the LAN port.
	must(in("hk5", "nft", "-f", write("hk5-cut.nft", fmt.Sprintf(`table inet wgcut {
  chain cut_in { type filter hook prerouting priority -500; policy accept; iifname %[1]q drop; }
  chain cut_out { type filter hook output priority -500; policy accept; oifname %[1]q drop; }
}
`, gwHk5.Iface())))...)
	check("all down", "failover stays on the backup path", drive("backup", 3), "backup")
	check("all down", "upstream record: state", record("state"), "down")
	check("all down", "group hk connection", connect("192.0.2.80"), "TIMEOUT")
	check("all down", "pinned connection", connect("192.0.2.81"), "TIMEOUT")
	check("all down", "group resolver", query(hk.Resolver, hk.Mark), "TIMEOUT")
	check("all down", "dc2 resolver address", query(dc2.Resolver, 0), "TIMEOUT")
	noLeak("all down")
	finish("all down")

	// 4. The main path comes back.
	must(in("ali", "nft", "delete", "table", "inet", "wgcut")...)
	must(in("hk5", "nft", "delete", "table", "inet", "wgcut")...)
	check("main back", "four passes: still on the backup (RECOVERS_NEED is 5)", drive("backup", 4), "backup")
	check("main back", "five passes: main path again", drive("backup", 5), "udp")
	check("main back", "upstream record: hub", record("hub"), "ix")
	before = snapshot()
	flows("main back")
	after = snapshot()
	if after["ix"] == before["ix"] || after["dc1p"] == before["dc1p"] || after["dc1b"] != before["dc1b"] {
		fails++
		t.Errorf("main back: traffic did not return to ix (before %v after %v)", before, after)
	}
	noLeak("main back")
	finish("main back")
}

// dualRAExample is defaults.DualHubExample with remote access on (the
// netns lab brings up the remote device).
func dualRAExample(t *testing.T) model.Topology {
	t.Helper()
	topo := defaults.DualHubExample()
	gen := func() remoteaccess.Keypair {
		kp, err := remoteaccess.GenerateKeypair()
		if err != nil {
			t.Fatal(err)
		}
		return kp
	}
	gw := gen()
	ra := &model.RemoteAccess{Enabled: true, Endpoint: "home.example.net", ListenPort: 51900, PublicKey: gw.Public, KeyID: "ra-key-test"}
	kp := gen()
	ra.Devices = append(ra.Devices, model.RemoteDevice{ID: "dev-aaaa", Name: "dev-aaaa", Mode: model.RemoteModeFull, Enabled: true, PublicKey: kp.Public, IPv4: "10.67.0.2", IPv6: "fd67::2"})
	topo.RemoteAccess = ra
	model.MigrateRegionGroups(&topo)
	return topo
}
