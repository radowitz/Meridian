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
	"github.com/radowitz/meridian/internal/hostexec"
	"github.com/radowitz/meridian/internal/model"
	"github.com/radowitz/meridian/internal/pathquality"
	"github.com/radowitz/meridian/internal/remoteaccess"
)

// The test binary doubles as "meridian path-step" for the compiled
// gateway failover script (MERIDIAN_BIN points at it).
func init() {
	if os.Getenv("MERIDIAN_PATHSTEP_HELPER") == "1" && len(os.Args) > 1 && os.Args[1] == "path-step" {
		os.Exit(pathquality.RunStep(os.Args[2:], os.Stdout, os.Stderr))
	}
}

// TestNetnsRelaySharing is the runtime check of relay sharing
// (docs/architecture.md「多中继同时分担」) on defaults.SharedRelaysExample
// (gateway → relays ali and ali2 → IX primary hub "ix" → exits dc1, dc2;
// backup hub hk5 over the gateway's WSS link) with remote access on and
// short controller timers (sharedLabSettings).
//
// Namespaces: the TestNetnsReloadNoLeak lab (gateway, ROS, LAN client,
// remote device) plus ali, ali2, ix, hk5, dc1, dc2 and "net" (the Internet
// behind the exits: 192.0.2.80:8080 answers with the peer address,
// 192.0.2.80:8081 echoes). Every host runs its COMPILED nft and routes
// script. gw-ali (UDP leg), gw-ali2, gw-hk5, ali-ix, ali2-ix and the four
// hub-exit tunnels are veth pairs with the compiled addresses (ARP off),
// every other tunnel interface a dummy. No WireGuard. The controller is the
// COMPILED meridian-failover.sh (its share_step, passes driven with a
// synthetic clock 5 s apart: PQ_NOW) calling this test binary as
// "meridian path-step", which measures for real (ping bursts through each
// leg to the hub, interface counters, the compiled nft counters).
//
// Phases:
//  1. distribution: 200 new connections from the LAN split between the
//     relays within 35–65 % each (p = 0.5, n = 200: ±15 points is over 4
//     standard deviations); no reply ever arrives on a relay other than
//     the one the connection was assigned to (gateway), and the hub never
//     sends a reply into another relay's tunnel than the one it came from.
//  2. affinity: a long echo connection keeps its relay in both directions
//     while all new connections are steered to the other relay
//     (share_apply), and never breaks.
//  3. "pings fine, no throughput" on ali2 (its forward drops everything
//     but ICMP): under load the controller sees TCP leave with no reply,
//     evicts ali2 (reason no_delivery), its drain rule appears, and new
//     connections avoid it.
//  4. recovery: ali2 is not re-admitted at once (hysteresis), then comes
//     back at a quarter of its weight and ramps to equal.
//  5. loss on ali2 (tc netem 50 %), only when tc and netem are available:
//     evicted with reason poor_loss. Skipped otherwise (logged).
//  6. all relays down (relay → hub cut): the backup hub takes over (table
//     102 and new connections), the exits answer on their hk5 tunnel.
//  7. everything down: the controller stays, records "down"; zero packets
//     of the test flows leave the LAN port or reach ROS.
//  8. main path back after ReturnAfter; the remote device's connections
//     and the group resolver (this host's marked query) take the relays.
//
// Root only, Linux only, opt-in (MERIDIAN_NETNS_TEST=1); needs ip, nft,
// ping, bash, timeout and python3 (tc only for phase 5). It has NOT been
// executed on a real host; a pass in a container is not evidence about real
// relays or real throttling.
func TestNetnsRelaySharing(t *testing.T) {
	netnsPrereqs(t)
	for _, bin := range []string{"python3", "timeout"} {
		if _, err := exec.LookPath(bin); err != nil {
			t.Skipf("%s not installed", bin)
		}
	}
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	topo := sharedRAExample(t)
	lab := newNetnsLab(t, topo, labV6{prefix: "2001:db8:100::/64", gw: "2001:db8:100::88", cli: "2001:db8:100::50"})
	b, dir, sh, must, in := lab.b, lab.dir, lab.sh, lab.must, lab.in
	tunnels := mustTunnels(t, topo)
	exits, groups := plans(t, topo)
	hk := mustGroup(t, groups, "hk")
	link := func(id, mode string) Tunnel {
		for _, tun := range tunnels {
			if tun.LinkID == id && (mode == "" || tun.Mode == mode) {
				return tun
			}
		}
		t.Fatalf("no tunnel for link %s", id)
		return Tunnel{}
	}
	gwAli, gwAli2, gwHk5 := link("gw-ali", "udp"), link("gw-ali2", ""), link("gw-hk5", "")
	aliIX, ali2IX := link("ali-ix", ""), link("ali2-ix", "")
	ixDC1, ixDC2, hk5DC1, hk5DC2 := link("ix-dc1", ""), link("ix-dc2", ""), link("hk5-dc1", ""), link("hk5-dc2", "")
	dc1, _ := exitByID(exits, "dc1")
	dc2, _ := exitByID(exits, "dc2")
	t.Logf("relays: ali %s→%s, ali2 %s→%s; backup %s; hk mark %#x resolver %s", gwAli.Iface(), aliIX.Iface(), gwAli2.Iface(), ali2IX.Iface(), gwHk5.Iface(), hk.Mark, hk.Resolver)

	sfx := strconv.Itoa(os.Getpid() % 100000)
	nodeNS := map[string]string{"gw": "gw", "ali": "ali", "ali2": "ali2", "ix": "ix", "hk5": "hk5", "dc1": "dc1", "dc2": "dc2"}
	for _, n := range []string{"ali", "ali2", "ix", "hk5", "dc1", "dc2", "net"} {
		lab.ns[n] = "mrq" + n + sfx
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
		x, y := fmt.Sprintf("qa%d%s", vethN, sfx), fmt.Sprintf("qb%d%s", vethN, sfx)
		mac := fmt.Sprintf("02:6f:00:00:%02x:01", vethN)
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
	for _, tun := range []Tunnel{gwAli, gwAli2, gwHk5} {
		must(in("gw", "ip", "link", "del", tun.Iface())...)
	}
	p2p("gw", "ali", gwAli.Iface())
	p2p("gw", "ali2", gwAli2.Iface())
	p2p("gw", "hk5", gwHk5.Iface())
	p2p("ali", "ix", aliIX.Iface())
	p2p("ali2", "ix", ali2IX.Iface())
	p2p("ix", "dc1", ixDC1.Iface())
	p2p("ix", "dc2", ixDC2.Iface())
	p2p("hk5", "dc1", hk5DC1.Iface())
	p2p("hk5", "dc2", hk5DC2.Iface())
	veths := map[string]bool{}
	for _, tun := range []Tunnel{gwAli, gwAli2, gwHk5, aliIX, ali2IX, ixDC1, ixDC2, hk5DC1, hk5DC2} {
		veths[tun.Iface()] = true
	}
	for _, node := range []string{"ali", "ali2", "ix", "hk5", "dc1", "dc2"} {
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
	for _, n := range []string{"ali", "ali2", "ix", "hk5"} {
		must(in(n, "ip", "link", "add", "eth0", "type", "dummy")...)
		must(in(n, "ip", "link", "set", "eth0", "up")...)
		must(in(n, "ip", "route", "add", "default", "dev", "eth0")...)
		must(in(n, "ip", "-6", "route", "add", "default", "dev", "eth0")...)
	}
	for i, n := range []string{"dc1", "dc2"} {
		x, y := fmt.Sprintf("qw%d%s", i, sfx), fmt.Sprintf("qn%d%s", i, sfx)
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

	write := func(name, body string) string {
		p := filepath.Join(dir, name)
		mustWrite(t, p, body)
		return p
	}
	for _, node := range []string{"ali", "ali2", "ix", "hk5", "dc1", "dc2"} {
		routes := strings.ReplaceAll(b.File("nodes/"+node+"/usr/local/sbin/meridian-routes.sh"), "/run/meridian", filepath.Join(dir, node+"run"))
		if out, err := sh(in(node, "bash", write(node+"-routes.sh", routes))...); err != nil {
			t.Fatalf("setup: %s routes script: %v\n%s", node, err, out)
		}
		nftP := write(node+".nft", b.File("nodes/"+node+"/etc/nftables.d/meridian.nft"))
		must(in(node, "nft", "-c", "-f", nftP)...)
		must(in(node, "nft", "-f", nftP)...)
		must(in(node, "sysctl", "-qw", "net.ipv4.ip_forward=1")...)
		must(in(node, "sysctl", "-qw", "net.ipv6.conf.all.forwarding=1")...)
	}
	gwRun := filepath.Join(dir, "gwrun")
	must(in("gw", "bash", lab.routesPath)...)
	must(in("gw", "nft", "-c", "-f", lab.nftPath)...)
	must(in("gw", "nft", "-f", lab.nftPath)...)
	// Postconditions: one table per relay on its leg, the fwmark rules,
	// table 102 on the first relay, the hub's per-relay reply rules.
	for _, c := range []struct{ table, dev string }{{"111", gwAli.Iface()}, {"112", gwAli2.Iface()}, {"109", gwHk5.Iface()}, {"102", gwAli.Iface()}} {
		if tbl := must(in("gw", "ip", "route", "show", "table", c.table)...); !regexp.MustCompile(`(?m)^default dev ` + c.dev + `\b`).MatchString(tbl) {
			t.Fatalf("setup: table %s not on %s:\n%s", c.table, c.dev, tbl)
		}
	}
	if rules := must(in("gw", "ip", "rule")...); !strings.Contains(rules, "fwmark 0x10000/0xff0000 lookup 111") || !strings.Contains(rules, "fwmark 0x20000/0xff0000 lookup 112") {
		t.Fatalf("setup: relay rules missing:\n%s", rules)
	}
	if rules := must(in("ix", "ip", "rule")...); !strings.Contains(rules, "fwmark 0x4e00 lookup 174") || !strings.Contains(rules, "fwmark 0x4e01 lookup 175") {
		t.Fatalf("setup: ix reply rules missing:\n%s", rules)
	}

	// Observation tables (never replaced by the compiled files).
	obs := func(n, body string) {
		must(in(n, "nft", "-f", write(n+"-obs.nft", "table inet qobs {\n"+body+"}\n"))...)
	}
	obs("gw", fmt.Sprintf(`  counter lanleak {}
  counter lanleak6 {}
  counter wrongin {}
  chain post {
    type filter hook postrouting priority 400; policy accept;
    oifname "%[1]s" ip daddr 192.0.2.80 counter name "lanleak"
    oifname "%[1]s" ip6 daddr { fd66::53:0/112, fd66::54:0/112 } counter name "lanleak6"
  }
  chain pre {
    type filter hook prerouting priority -100; policy accept;
    iifname "%[2]s" ct direction reply ct mark 0x00020000 counter name "wrongin"
    iifname "%[3]s" ct direction reply ct mark 0x00010000 counter name "wrongin"
  }
`, lab.lan, gwAli.Iface(), gwAli2.Iface()))
	must(in("ros", "nft", "-f", write("ros-obs.nft", `table inet qobs {
  counter foreign {}
  counter dns {}
  chain pre {
    type filter hook prerouting priority -400; policy accept;
    ip daddr 192.0.2.80 counter name "foreign"
    ip6 daddr { fd66::53:0/112, fd66::54:0/112 } counter name "dns"
  }
}
`))...)
	for _, r := range []struct{ n, west string }{{"ali", gwAli.Iface()}, {"ali2", gwAli2.Iface()}} {
		obs(r.n, fmt.Sprintf(`  counter syn {}
  counter long_in {}
  counter long_out {}
  chain pre {
    type filter hook prerouting priority -400; policy accept;
    iifname %[1]q tcp flags syn / syn,ack counter name "syn"
    iifname %[1]q tcp dport 8081 counter name "long_in"
  }
  chain post {
    type filter hook postrouting priority 400; policy accept;
    oifname %[1]q tcp sport 8081 counter name "long_out"
  }
`, r.west))
	}
	obs("ix", fmt.Sprintf(`  counter wrongout {}
  counter dns_r1 {}
  counter dns_r2 {}
  chain pre {
    type filter hook prerouting priority -400; policy accept;
    iifname %[1]q meta l4proto udp th dport 53 counter name "dns_r1"
    iifname %[2]q meta l4proto udp th dport 53 counter name "dns_r2"
  }
  chain post {
    type filter hook postrouting priority 400; policy accept;
    oifname %[1]q ct direction reply ct mark 0x4e01 counter name "wrongout"
    oifname %[2]q ct direction reply ct mark 0x4e00 counter name "wrongout"
  }
`, aliIX.Iface(), ali2IX.Iface()))
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
	cnt := func(n, name string) int { return lab.counter(n, "qobs", name) }

	resolverPy := write("resolver.py", netnsResolverPy)
	serverPy := write("server.py", netnsServerPy)
	echoPy := write("echo.py", netnsEchoPy)
	queryPy := write("query.py", netnsQueryPy)
	connectPy := write("connect.py", netnsConnectPy)
	manyPy := write("many.py", netnsManyPy)
	longPy := write("long.py", netnsLongPy)
	loadPy := write("load.py", netnsLoadPy)
	start := func(n string, args ...string) *exec.Cmd {
		cmd := exec.Command("ip", append([]string{"netns", "exec", ns[n]}, args...)...)
		logf, _ := os.Create(filepath.Join(dir, n+"-"+filepath.Base(args[1])+"-"+strconv.Itoa(len(args))+".log"))
		cmd.Stdout, cmd.Stderr = logf, logf
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = cmd.Process.Kill(); _, _ = cmd.Process.Wait(); _ = logf.Close() })
		return cmd
	}
	start("dc1", "python3", resolverPy, dc1.DNSULA, "198.18.1.1")
	start("dc2", "python3", resolverPy, dc2.DNSULA, "198.18.1.2")
	start("net", "python3", serverPy, "192.0.2.80", "8080")
	start("net", "python3", echoPy, "192.0.2.80", "8081")
	time.Sleep(time.Second)

	// The compiled failover script up to its main loop, driven pass by pass.
	fo := b.File("nodes/gw/usr/local/sbin/meridian-failover.sh")
	cut := strings.Index(fo, "# --- main loop ---")
	if cut < 0 {
		t.Fatal("no main-loop marker in the gateway failover script")
	}
	cfgPath := write("path-quality.json", b.File("nodes/gw/etc/meridian/path-quality.json"))
	foText := strings.ReplaceAll(fo[:cut], "/run/meridian", gwRun)
	foText = strings.ReplaceAll(foText, SharePathConfig, cfgPath)
	foText = strings.ReplaceAll(foText, "MERIDIAN_BIN=/usr/local/bin/meridian", "MERIDIAN_BIN="+shQuote(self))
	clock := int64(1_800_000_000)
	drive := func(n int) {
		t.Helper()
		var s strings.Builder
		s.WriteString(foText + "\nexport MERIDIAN_PATHSTEP_HELPER=1\nmkdir -p " + gwRun + "/pathq\n")
		for i := 0; i < n; i++ {
			clock += pathquality.PassInterval
			fmt.Fprintf(&s, "PQ_NOW=%d share_step\n", clock)
		}
		if out, err := sh(in("gw", "bash", write("gw-drive.sh", s.String()))...); err != nil {
			t.Fatalf("gateway failover: %v\n%s", err, out)
		}
	}
	record := func() hostexec.UpstreamState {
		t.Helper()
		v, err := os.ReadFile(filepath.Join(gwRun, "upstream"))
		if err != nil {
			t.Fatal(err)
		}
		st, err := hostexec.ParseUpstream(string(v))
		if err != nil {
			t.Fatalf("record refused: %v\n%s", err, v)
		}
		return st
	}
	relay := func(st hostexec.UpstreamState, id string) hostexec.UpstreamRelay {
		for _, r := range st.Relays {
			if r.ID == id {
				return r
			}
		}
		t.Fatalf("no relay %s in the record", id)
		return hostexec.UpstreamRelay{}
	}
	shareApply := func(args string) {
		t.Helper()
		// Behind the controller's back: forget its "already applied" mark,
		// so its next pass puts its own decision back.
		if out, err := sh(in("gw", "bash", write("gw-apply.sh", foText+"\nshare_apply "+args+" && rm -f \"$SH_APPLIED\"\n"))...); err != nil {
			t.Fatalf("share_apply %s: %v\n%s", args, err, out)
		}
	}
	connect := func(from, addr string) string {
		out, _ := sh(in(from, "python3", connectPy, addr, "8080")...)
		return strings.TrimSpace(out)
	}
	many := func(from string, n int) (ok, fail int) {
		out, _ := sh(in(from, "python3", manyPy, "192.0.2.80", "8080", strconv.Itoa(n))...)
		m := regexp.MustCompile(`ok=(\d+) fail=(\d+)`).FindStringSubmatch(out)
		if m == nil {
			t.Fatalf("many.py: %s", out)
		}
		ok, _ = strconv.Atoi(m[1])
		fail, _ = strconv.Atoi(m[2])
		return ok, fail
	}
	query := func(server string, mark uint32) string {
		out, _ := sh(in("gw", "python3", queryPy, server, strconv.FormatUint(uint64(mark), 10), "udp", "probe.example.com")...)
		return strings.TrimSpace(out)
	}
	diag := func() {
		for _, c := range []struct {
			n    string
			args []string
		}{
			{"gw", []string{"ip", "rule"}}, {"gw", []string{"ip", "route", "show", "table", "102"}}, {"gw", []string{"ip", "route", "show", "table", "111"}},
			{"gw", []string{"ip", "route", "show", "table", "112"}}, {"gw", []string{"ip", "route", "show", "table", "109"}},
			{"gw", []string{"cat", filepath.Join(gwRun, "upstream")}}, {"gw", []string{"cat", filepath.Join(gwRun, "pathq", "state.json")}},
			{"gw", []string{"nft", "list", "table", "inet", "qobs"}}, {"gw", []string{"nft", "list", "chain", "inet", "meridian", "relay_assign"}},
			{"gw", []string{"nft", "list", "chain", "inet", "meridian", "relay_drain"}}, {"gw", []string{"nft", "list", "counters", "table", "inet", "meridian"}},
			{"gw", []string{"nft", "list", "table", "inet", "meridian_guard"}},
			{"ali", []string{"nft", "list", "ruleset"}}, {"ali", []string{"ip", "rule"}}, {"ali", []string{"ip", "route"}},
			{"ali2", []string{"nft", "list", "ruleset"}}, {"ali2", []string{"ip", "rule"}}, {"ali2", []string{"ip", "route"}},
			{"ix", []string{"nft", "list", "ruleset"}}, {"ix", []string{"ip", "rule"}}, {"ix", []string{"ip", "route"}}, {"ix", []string{"ip", "route", "show", "table", "174"}},
			{"hk5", []string{"nft", "list", "table", "inet", "qobs"}}, {"dc1", []string{"nft", "list", "table", "inet", "qobs"}},
			{"ros", []string{"nft", "list", "table", "inet", "qobs"}},
		} {
			out, err := sh(in(c.n, c.args...)...)
			t.Logf("DIAG %s$ %s (err=%v)\n%s", c.n, strings.Join(c.args, " "), err, out)
		}
		for _, f := range []string{"net-server.py-4.log", "net-echo.py-4.log"} {
			body, _ := os.ReadFile(filepath.Join(dir, f))
			t.Logf("DIAG %s:\n%s", f, body)
		}
	}
	fails := 0
	check := func(phase, what string, ok bool, got any) {
		t.Helper()
		if !ok {
			fails++
			t.Errorf("%s: %s: got %v", phase, what, got)
		} else {
			t.Logf("EVIDENCE %s: %s: %v", phase, what, got)
		}
	}
	finish := func(phase string) {
		t.Helper()
		if fails > 0 {
			diag()
			t.Fatalf("%s: %d checks failed", phase, fails)
		}
	}
	noLeak := func(phase string) {
		t.Helper()
		for label, nc := range map[string][2]string{"gw LAN port: data": {"gw", "lanleak"}, "gw LAN port: resolver": {"gw", "lanleak6"},
			"ROS: data": {"ros", "foreign"}, "ROS: resolver": {"ros", "dns"}} {
			v := cnt(nc[0], nc[1])
			check(phase, label+" packets (want 0)", v == 0, v)
		}
	}
	symmetric := func(phase string) {
		t.Helper()
		w1, w2 := cnt("gw", "wrongin"), cnt("ix", "wrongout")
		check(phase, "replies on another relay than assigned, at the gateway (want 0)", w1 == 0, w1)
		check(phase, "hub replies into another relay's tunnel (want 0)", w2 == 0, w2)
	}
	untilStatus := func(phase string, max int, ok func(hostexec.UpstreamState) bool, what string) (hostexec.UpstreamState, int) {
		t.Helper()
		for i := 1; i <= max; i++ {
			drive(1)
			if st := record(); ok(st) {
				return st, i
			}
		}
		st := record()
		fails++
		t.Errorf("%s: %s not reached in %d passes; record %+v", phase, what, max, st)
		finish(phase)
		return st, max
	}

	// 1. Both relays good: equal weights; 200 connections split.
	drive(3)
	st := record()
	check("distribution", "controller and path", st.Controller == "go" && st.Path == "main" && st.Hub == "ix", fmt.Sprintf("%s %s %s", st.Controller, st.Path, st.Hub))
	check("distribution", "weights 500/500", relay(st, "ali").Weight == 500 && relay(st, "ali2").Weight == 500, fmt.Sprintf("%d/%d", relay(st, "ali").Weight, relay(st, "ali2").Weight))
	s1, s2 := cnt("ali", "syn"), cnt("ali2", "syn")
	ok, failed := many("cli", 200)
	d1, d2 := cnt("ali", "syn")-s1, cnt("ali2", "syn")-s2
	check("distribution", "200 connections answered", ok == 200 && failed == 0, fmt.Sprintf("ok=%d fail=%d", ok, failed))
	check("distribution", "ali share within 35–65 % (n=200, p=0.5)", d1 >= 70 && d1 <= 130 && d1+d2 >= 200, fmt.Sprintf("ali %d ali2 %d", d1, d2))
	symmetric("distribution")
	noLeak("distribution")
	finish("distribution")

	// 2. Affinity: a long connection stays on its relay, both directions,
	// while every new connection is steered to the other relay.
	long := start("cli", "python3", longPy, "192.0.2.80", "8081", "6")
	time.Sleep(1500 * time.Millisecond)
	li1, li2 := cnt("ali", "long_in"), cnt("ali2", "long_in")
	if (li1 == 0) == (li2 == 0) {
		fails++
		t.Errorf("affinity: the long connection is on both or neither relay (ali %d, ali2 %d)", li1, li2)
		finish("affinity")
	}
	on, other, otherIface := "ali", "ali2", gwAli2.Iface()
	if li2 > 0 {
		on, other, otherIface = "ali2", "ali", gwAli.Iface()
	}
	if other == "ali" {
		shareApply(fmt.Sprintf("main ali %s 1000 0 %s 0 0 0", gwAli.Iface(), gwAli2.Iface()))
	} else {
		shareApply(fmt.Sprintf("main ali2 %s 0 0 %s 1000 0 0", gwAli.Iface(), gwAli2.Iface()))
	}
	so := cnt(other, "syn")
	sOn := cnt(on, "syn")
	ok, _ = many("cli", 20)
	check("affinity", "new connections all on "+other+" ("+otherIface+")", ok == 20 && cnt(other, "syn")-so >= 20 && cnt(on, "syn") == sOn, fmt.Sprintf("ok=%d %s+%d %s+%d", ok, other, cnt(other, "syn")-so, on, cnt(on, "syn")-sOn))
	_ = long.Wait()
	out, _ := os.ReadFile(filepath.Join(dir, "cli-long.py-5.log"))
	check("affinity", "long connection never broke", strings.Contains(string(out), "ok=") && !strings.Contains(string(out), "broken"), strings.TrimSpace(string(out)))
	check("affinity", "long connection only on "+on+" (in and out)", cnt(other, "long_in") == 0 && cnt(other, "long_out") == 0 && cnt(on, "long_in") > li1+li2 && cnt(on, "long_out") > 0,
		fmt.Sprintf("%s in/out %d/%d, %s in/out %d/%d", on, cnt(on, "long_in"), cnt(on, "long_out"), other, cnt(other, "long_in"), cnt(other, "long_out")))
	symmetric("affinity")
	noLeak("affinity")
	finish("affinity")
	drive(2) // back to the controller's weights
	st = record()
	check("affinity", "controller weights back after the manual change", relay(st, "ali").Weight == 500 && relay(st, "ali2").Weight == 500, fmt.Sprintf("%d/%d", relay(st, "ali").Weight, relay(st, "ali2").Weight))
	if assign := must(in("gw", "nft", "list", "chain", "inet", "meridian", "relay_assign")...); !strings.Contains(assign, "0-499 : 0x00010000, 500-999 : 0x00020000") {
		fails++
		t.Errorf("affinity: the controller did not restore its map:\n%s", assign)
	}
	finish("affinity")

	// 3. "Pings fine, no throughput" on ali2: only ICMP passes its forward.
	must(in("ali2", "nft", "-f", write("ali2-blk.nft", fmt.Sprintf("table inet qblk {\n  chain f {\n    type filter hook forward priority -500; policy accept;\n    iifname %q meta l4proto != icmp drop\n  }\n}\n", gwAli2.Iface())))...)
	if out, err := sh(in("gw", "ping", "-n", "-q", "-I", gwAli2.Iface(), "-c", "2", "-W", "1", relayProbe(t, b, "ali2"))...); err != nil {
		t.Fatalf("setup: ali2's echo path should still answer: %v\n%s", err, out)
	}
	load := start("cli", "python3", loadPy, "192.0.2.80", "8080", "60", "24")
	st, n := untilStatus("no throughput", 14, func(s hostexec.UpstreamState) bool { return relay(s, "ali2").Status == "evicted" }, "ali2 evicted")
	_ = load.Process.Kill()
	_, _ = load.Process.Wait()
	r2 := relay(st, "ali2")
	loss := int64(-1)
	if r2.LossPermille != nil {
		loss = *r2.LossPermille
	}
	check("no throughput", fmt.Sprintf("ali2 evicted after %d passes, reason no_delivery, pings still answered", n), r2.Reason == "no_delivery" && loss >= 0 && loss < 150, fmt.Sprintf("%s/%s loss %d‰", r2.Status, r2.Reason, loss))
	check("no throughput", "weights 1000/0, drain on", relay(st, "ali").Weight == 1000 && r2.Weight == 0 && r2.Drain, fmt.Sprintf("%d/%d drain=%v", relay(st, "ali").Weight, r2.Weight, r2.Drain))
	drainChain := must(in("gw", "nft", "list", "chain", "inet", "meridian", "relay_drain")...)
	check("no throughput", "reset rule for ali2's connections", strings.Contains(drainChain, "ct mark 0x00020000") && strings.Contains(drainChain, "reject with tcp reset"), strings.TrimSpace(drainChain))
	time.Sleep(time.Second)
	s2 = cnt("ali2", "syn")
	ok, failed = many("cli", 40)
	check("no throughput", "new connections avoid ali2", ok == 40 && cnt("ali2", "syn") == s2, fmt.Sprintf("ok=%d fail=%d ali2 syn +%d", ok, failed, cnt("ali2", "syn")-s2))
	noLeak("no throughput")
	finish("no throughput")

	// 4. Recovery with hysteresis and gradual re-admission.
	must(in("ali2", "nft", "delete", "table", "inet", "qblk")...)
	drive(2)
	st = record()
	check("recovery", "not re-admitted at once", relay(st, "ali2").Weight == 0, relay(st, "ali2").Status)
	st, n = untilStatus("recovery", 20, func(s hostexec.UpstreamState) bool { return relay(s, "ali2").Weight > 0 }, "ali2 re-admitted")
	check("recovery", fmt.Sprintf("re-admitted after %d more passes at a quarter of its weight", n), relay(st, "ali2").Status == "recovering" && relay(st, "ali2").Weight == 200, fmt.Sprintf("%s %d", relay(st, "ali2").Status, relay(st, "ali2").Weight))
	st, _ = untilStatus("recovery", 10, func(s hostexec.UpstreamState) bool { return relay(s, "ali2").Weight == 500 }, "equal weights again")
	check("recovery", "active at equal weight", relay(st, "ali2").Status == "active", relay(st, "ali2").Status)
	finish("recovery")

	// 5. Induced loss (tc netem), when available.
	if _, err := exec.LookPath("tc"); err != nil {
		t.Log("SKIP phase loss: tc not installed (the no-throughput phase above covers eviction)")
	} else if out, err := sh(in("ali2", "tc", "qdisc", "add", "dev", gwAli2.Iface(), "root", "netem", "loss", "50%")...); err != nil {
		t.Logf("SKIP phase loss: netem not available: %v %s", err, strings.TrimSpace(out))
	} else {
		st, n = untilStatus("loss", 10, func(s hostexec.UpstreamState) bool { return relay(s, "ali2").Status == "evicted" }, "ali2 evicted for loss")
		check("loss", fmt.Sprintf("evicted after %d passes, reason poor_loss", n), relay(st, "ali2").Reason == "poor_loss", relay(st, "ali2").Reason)
		must(in("ali2", "tc", "qdisc", "del", "dev", gwAli2.Iface(), "root")...)
		finish("loss")
	}

	// 6. All relays down (relay → hub cut on both relays): backup hub.
	cutRelay := func(node, iface string) {
		must(in(node, "nft", "-f", write(node+"-cut.nft", fmt.Sprintf(`table inet qcut {
  chain cut_in { type filter hook prerouting priority -500; policy accept; iifname %[1]q drop; }
  chain cut_out { type filter hook output priority -500; policy accept; oifname %[1]q drop; }
  chain cut_fwd { type filter hook forward priority -500; policy accept; oifname %[1]q drop; }
}
`, iface)))...)
	}
	cutRelay("ali", aliIX.Iface())
	cutRelay("ali2", ali2IX.Iface())
	st, n = untilStatus("all relays down", 8, func(s hostexec.UpstreamState) bool { return s.Path == "backup" }, "backup hub")
	check("all relays down", fmt.Sprintf("backup after %d passes, hub hk5", n), st.Hub == "hk5" && st.Tier == "backup" && st.Designated == "backup", fmt.Sprintf("%s %s %s", st.Hub, st.Tier, st.Designated))
	if tbl := must(in("gw", "ip", "route", "show", "table", "102")...); !regexp.MustCompile(`(?m)^default dev ` + gwHk5.Iface() + `\b`).MatchString(tbl) {
		fails++
		t.Errorf("all relays down: table 102 not on %s:\n%s", gwHk5.Iface(), tbl)
	}
	h, rb, rp := cnt("hk5", "in"), cnt("dc1", "r_b"), cnt("dc1", "r_p")
	got := connect("cli", "192.0.2.80")
	check("all relays down", "group hk connection through the backup hub", got == "100.64.1.2" && cnt("hk5", "in") > h && cnt("dc1", "r_b") > rb && cnt("dc1", "r_p") == rp, fmt.Sprintf("%s hk5+%d r_b+%d r_p+%d", got, cnt("hk5", "in")-h, cnt("dc1", "r_b")-rb, cnt("dc1", "r_p")-rp))
	noLeak("all relays down")
	finish("all relays down")

	// 7. Everything down: stay, record "down", nothing leaks.
	must(in("hk5", "nft", "-f", write("hk5-cut.nft", fmt.Sprintf(`table inet qcut {
  chain cut_in { type filter hook prerouting priority -500; policy accept; iifname %[1]q drop; }
  chain cut_out { type filter hook output priority -500; policy accept; oifname %[1]q drop; }
}
`, gwHk5.Iface())))...)
	st, _ = untilStatus("all down", 6, func(s hostexec.UpstreamState) bool { return s.State == "down" }, "state down")
	check("all down", "alert nothing_reachable", st.Alert == "nothing_reachable", st.Alert)
	check("all down", "group hk connection times out", connect("cli", "192.0.2.80") == "TIMEOUT", "")
	check("all down", "remote device connection times out", connect("dev", "192.0.2.80") == "TIMEOUT", "")
	check("all down", "group resolver times out", query(hk.Resolver, hk.Mark) == "TIMEOUT", "")
	noLeak("all down")
	finish("all down")

	// 8. Main path back; remote access and group DNS under sharing.
	must(in("ali", "nft", "delete", "table", "inet", "qcut")...)
	must(in("ali2", "nft", "delete", "table", "inet", "qcut")...)
	must(in("hk5", "nft", "delete", "table", "inet", "qcut")...)
	drive(2)
	check("main back", "not back at once (ReturnAfter)", record().Path == "backup", record().Path)
	st, n = untilStatus("main back", 20, func(s hostexec.UpstreamState) bool { return s.Path == "main" }, "main path")
	check("main back", fmt.Sprintf("main path after %d more passes", n), st.Hub == "ix", st.Hub)
	untilStatus("main back", 20, func(s hostexec.UpstreamState) bool { return relay(s, "ali").Weight > 0 && relay(s, "ali2").Weight > 0 }, "both relays in the set")
	s1, s2 = cnt("ali", "syn"), cnt("ali2", "syn")
	got = connect("dev", "192.0.2.80")
	check("main back", "remote device connection through a relay", got == "100.64.1.2" && cnt("ali", "syn")+cnt("ali2", "syn") > s1+s2, fmt.Sprintf("%s ali+%d ali2+%d", got, cnt("ali", "syn")-s1, cnt("ali2", "syn")-s2))
	st = record()
	q1, q2 := cnt("ix", "dns_r1"), cnt("ix", "dns_r2")
	ans := query(hk.Resolver, hk.Mark)
	via := "dns_r1"
	if st.Designated == "ali2" {
		via = "dns_r2"
	}
	check("main back", "group resolver answered through the designated relay "+st.Designated, ans == "198.18.1.1" && cnt("ix", via) > map[string]int{"dns_r1": q1, "dns_r2": q2}[via],
		fmt.Sprintf("%s r1+%d r2+%d", ans, cnt("ix", "dns_r1")-q1, cnt("ix", "dns_r2")-q2))
	symmetric("main back")
	noLeak("main back")
	finish("main back")
}

// relayProbe is the relay's probe address from the compiled config.
func relayProbe(t *testing.T, b *Bundle, id string) string {
	t.Helper()
	cfg, err := pathquality.ParseConfig([]byte(b.File("nodes/gw/etc/meridian/path-quality.json")))
	if err != nil {
		t.Fatal(err)
	}
	r, ok := cfg.RelayByID(id)
	if !ok {
		t.Fatalf("no relay %s", id)
	}
	return r.Probe
}

// sharedLabSettings shortens the controller's timers for the lab.
func sharedLabSettings() *model.PathQuality {
	return &model.PathQuality{
		// RTT thresholds far above what CPU jitter in a lab (or an
		// emulated container) produces: this test is about the logic.
		MildRTTMS: 2000, PoorRTTMS: 5000,
		ReduceAfterSec: 10, StandbyAfterSec: 20, EvictAfterSec: 10, DownAfterSec: 10,
		RecoverAfterSec: 20, RampStepSec: 10, BackupAfterSec: 10, ReturnAfterSec: 20, MinDwellSec: 20,
		ProbeMinIntervalSec: 60, ProbeBytes: 64 * 1024, ProbeRateKbps: 2000, ProbeFloorKbps: 500,
	}
}

// sharedRAExample is defaults.SharedRelaysExample with remote access on
// and the lab timers.
func sharedRAExample(t *testing.T) model.Topology {
	t.Helper()
	topo := defaults.SharedRelaysExample()
	topo.Settings.PathQuality = sharedLabSettings()
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

// netnsEchoPy ADDR PORT: a threaded line echo server.
const netnsEchoPy = `import socket, sys, threading
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind((sys.argv[1], int(sys.argv[2])))
s.listen(16)
def serve(c):
    try:
        while True:
            d = c.recv(4096)
            if not d:
                break
            c.sendall(d)
    except Exception:
        pass
    finally:
        c.close()
while True:
    c, peer = s.accept()
    threading.Thread(target=serve, args=(c,), daemon=True).start()
`

// netnsManyPy ADDR PORT N: N sequential connections (each a new source
// port), each reading the server's line. Prints ok=… fail=….
const netnsManyPy = `import socket, sys
ok = fail = 0
for i in range(int(sys.argv[3])):
    try:
        s = socket.create_connection((sys.argv[1], int(sys.argv[2])), timeout=3)
        if s.recv(100):
            ok += 1
        else:
            fail += 1
        s.close()
    except Exception:
        fail += 1
print("ok=%d fail=%d" % (ok, fail))
`

// netnsLongPy ADDR PORT SECONDS: one connection, a line every 0.1 s, each
// echoed back. Prints ok=N, or "broken after N".
const netnsLongPy = `import socket, sys, time
s = socket.create_connection((sys.argv[1], int(sys.argv[2])), timeout=3)
end = time.time() + float(sys.argv[3])
n = 0
try:
    while time.time() < end:
        s.sendall(b"ping %d\n" % n)
        got = b""
        while not got.endswith(b"\n"):
            d = s.recv(100)
            if not d:
                raise Exception("closed")
            got += d
        n += 1
        time.sleep(0.1)
    print("ok=%d" % n, flush=True)
except Exception as e:
    print("broken after %d: %s" % (n, e), flush=True)
`

// netnsLoadPy ADDR PORT SECONDS PARALLEL: PARALLEL threads opening
// connections (0.5 s timeout) until SECONDS pass: business demand.
const netnsLoadPy = `import socket, sys, threading, time
end = time.time() + float(sys.argv[3])
def run():
    while time.time() < end:
        try:
            s = socket.create_connection((sys.argv[1], int(sys.argv[2])), timeout=0.5)
            s.recv(100)
            s.close()
        except Exception:
            pass
ts = [threading.Thread(target=run, daemon=True) for _ in range(int(sys.argv[4]))]
for t in ts:
    t.start()
for t in ts:
    t.join()
`
