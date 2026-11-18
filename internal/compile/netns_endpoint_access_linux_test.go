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

// TestNetnsEndpointAccess is the packet-level check of the gateway's policy
// for LAN traffic to a tunnel endpoint (internal/validate/endpoint_access.go,
// sets endpoint_direct4/6, endpoint_tunnel4/6, endpoint_block4/6 in the
// classify chain; docs/architecture.md「局域网到隧道端点」).
//
// Topology: defaults.DualHubExample with remote access on (dualRAExample),
// plus two synthetic IPv6 endpoints: the relay access gets 2001:db8:a1::10
// (domestic: endpoint_direct6) and the exit dc2 gets 2001:db8:42::42 (the
// default group hk does not carry IPv6: endpoint_block6).
//
// Namespaces: the TestNetnsReloadNoLeak lab (gateway, ROS = the home uplink,
// LAN client, remote device) plus access, ix, hkb, dc1, dc2 and "net", the
// Internet. Unlike TestNetnsDualHub, every node has a WAN (eth0, a veth into
// net) that owns its public endpoint addresses, and ROS has a WAN into net
// too, so an endpoint is reachable both through the home uplink and through
// the tunnels: a leak to the home uplink would SUCCEED and show the client's
// LAN address at the server, which the checks forbid. A TCP server on :8080
// at every endpoint address answers with the peer address it sees. The
// tunnels on the paths are veth pairs carrying the compiled tunnel addresses
// (as in TestNetnsDualHub); every node runs its COMPILED nft and routes
// script, and the gateway's path choice is the COMPILED meridian-failover.sh.
//
// Phases:
//  1. main path (gateway → access → ix → dc1): client → relay 203.0.113.10 and
//     IX ingress 198.51.100.10 leave the gateway's LAN port toward ROS
//     (table 100) and never enter a tunnel; client → dc2 203.0.113.42, dc1
//     203.0.113.41, the IX egress 203.0.113.20 and the backup hub
//     203.0.113.30 enter the default group's tunnel and zero client packets
//     to them leave on the LAN port or reach ROS. IPv6: client → relay
//     2001:db8:a1::10 goes direct; client → 2001:db8:42::42 (family not
//     carried by the default group) is dropped at the gateway: TIMEOUT, LAN
//     port 0, ROS 0, tunnels 0.
//  2. backup hub active (relay → IX cut, the compiled failover moves table
//     102 to the gw-hkb tunnel): client → 203.0.113.30 is carried by that
//     tunnel and answered by hkb itself; the gateway's own outer packets to
//     hkb (ICMP with the underlay fwmark 0x4d72 standing in for WireGuard,
//     an unmarked TCP connect to :8443 standing in for wstunnel) leave on the
//     LAN port via the main table, never on the tunnel; per-packet counters
//     show N client packets give N packets on the tunnel and nothing more
//     (no growth loop).
//  3. fail-closed: the gateway nft rendered for a default group with no
//     exit target (validation refuses such a topology; this is the
//     renderer's defence) puts every foreign endpoint in endpoint_block4;
//     client → those addresses time out and nothing reaches the LAN port or
//     ROS, while the relay stays reachable directly.
//
// Not covered: a default group that carries IPv6 through a tunnel (the
// dual-hub example is IPv4-only), WireGuard and wstunnel themselves (the
// outer packets are stand-ins with the same mark/route class), the Mesh.
//
// Root only, Linux only, opt-in (MERIDIAN_NETNS_TEST=1); needs ip, nft,
// ping, bash and python3.
func TestNetnsEndpointAccess(t *testing.T) {
	netnsPrereqs(t)
	if _, err := exec.LookPath("python3"); err != nil {
		t.Skip("python3 not installed")
	}
	const (
		relay4, ixIn4, ixOut4, hk5v4, dc1v4, dc2v4 = "203.0.113.10", "198.51.100.10", "203.0.113.20", "203.0.113.30", "203.0.113.41", "203.0.113.42"
		relay6, dc2v6                              = "2001:db8:a1::10", "2001:db8:42::42"
		cli4, cli6, gw4                            = "192.0.2.50", "2001:db8:100::50", "192.0.2.88"
	)
	topo := dualRAExample(t)
	for i := range topo.Nodes {
		switch topo.Nodes[i].ID {
		case "access":
			topo.Nodes[i].EndpointV6 = relay6
		case "dc2":
			topo.Nodes[i].EndpointV6 = dc2v6
		}
	}
	lab := newNetnsLab(t, topo, labV6{prefix: "2001:db8:100::/64", gw: "2001:db8:100::88", cli: cli6})
	b, dir, sh, must, in := lab.b, lab.dir, lab.sh, lab.must, lab.in
	tunnels := mustTunnels(t, topo)
	exits, groups := plans(t, topo)
	hk := mustGroup(t, groups, "hk")

	// The compiled classes are what this test then exercises with packets.
	wantClass := map[string]string{
		relay4: validate.EndpointDirect, ixIn4: validate.EndpointDirect, relay6: validate.EndpointDirect,
		ixOut4: validate.EndpointTunnel, hk5v4: validate.EndpointTunnel, dc1v4: validate.EndpointTunnel, dc2v4: validate.EndpointTunnel,
		dc2v6: validate.EndpointBlocked,
	}
	for _, e := range b.EndpointAccess {
		if w, ok := wantClass[e.Addr]; !ok || w != e.Class {
			t.Fatalf("setup: compiled endpoint %s (%s) class %s, want %q", e.Addr, e.NodeID, e.Class, w)
		}
		t.Logf("compiled endpoint %s node %s class %s: %s", e.Addr, e.NodeID, e.Class, e.Reason)
	}
	if len(b.EndpointAccess) != len(wantClass) {
		t.Fatalf("setup: %d compiled endpoints, want %d", len(b.EndpointAccess), len(wantClass))
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
	gwAli, gwHk5, aliIX := link("gw-access", "udp"), link("gw-hkb", ""), link("access-ix", "")
	ixDC1, ixDC2, hk5DC1, hk5DC2 := link("ix-dc1", ""), link("ix-dc2", ""), link("hkb-dc1", ""), link("hkb-dc2", "")
	t.Logf("gw tunnels: main %s, backup %s; group hk mark %#x table %d", gwAli.Iface(), gwHk5.Iface(), hk.Mark, hk.Table)

	sfx := strconv.Itoa(os.Getpid() % 100000)
	for _, n := range []string{"access", "ix", "hkb", "dc1", "dc2", "net"} {
		lab.ns[n] = "mre" + n + sfx
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
			must(in(node, args...)...)
		}
	}
	vethN := 0
	p2p := func(a, bNode, iface string) {
		t.Helper()
		vethN++
		x, y := fmt.Sprintf("ea%d%s", vethN, sfx), fmt.Sprintf("eb%d%s", vethN, sfx)
		mac := fmt.Sprintf("02:6f:00:00:%02x:01", vethN)
		must("ip", "link", "add", x, "type", "veth", "peer", "name", y)
		must("ip", "link", "set", x, "netns", ns[a])
		must("ip", "link", "set", y, "netns", ns[bNode])
		for _, e := range []struct{ node, name string }{{a, x}, {bNode, y}} {
			must(in(e.node, "ip", "link", "set", e.name, "name", iface)...)
			must(in(e.node, "ip", "link", "set", "dev", iface, "address", mac, "arp", "off")...)
			_, _ = sh(in(e.node, "ip", "link", "set", "dev", iface, "addrgenmode", "none")...)
			addAddrs(e.node, iface)
			must(in(e.node, "ip", "link", "set", iface, "up")...)
		}
	}
	must(in("gw", "ip", "link", "del", gwAli.Iface())...)
	must(in("gw", "ip", "link", "del", gwHk5.Iface())...)
	p2p("gw", "access", gwAli.Iface())
	p2p("gw", "hkb", gwHk5.Iface())
	p2p("access", "ix", aliIX.Iface())
	p2p("ix", "dc1", ixDC1.Iface())
	p2p("ix", "dc2", ixDC2.Iface())
	p2p("hkb", "dc1", hk5DC1.Iface())
	p2p("hkb", "dc2", hk5DC2.Iface())
	veths := map[string]bool{}
	for _, tun := range []Tunnel{gwAli, gwHk5, aliIX, ixDC1, ixDC2, hk5DC1, hk5DC2} {
		veths[tun.Iface()] = true
	}
	for _, node := range []string{"access", "ix", "hkb", "dc1", "dc2"} {
		pre := "nodes/" + node + "/etc/wireguard/"
		for path := range b.Files {
			if !strings.HasPrefix(path, pre) {
				continue
			}
			iface := strings.TrimSuffix(strings.TrimPrefix(path, pre), ".conf")
			if veths[iface] {
				continue
			}
			must(in(node, "ip", "link", "add", iface, "type", "dummy")...)
			addAddrs(node, iface)
			must(in(node, "ip", "link", "set", iface, "up")...)
		}
	}

	// The Internet: every node (and ROS) has a WAN veth into "net"; the
	// node's public endpoint addresses sit on its WAN.
	must(in("net", "sysctl", "-qw", "net.ipv4.ip_forward=1")...)
	must(in("net", "sysctl", "-qw", "net.ipv6.conf.all.forwarding=1")...)
	wan := func(i int, node, ifname string, pub ...string) {
		t.Helper()
		x, y := fmt.Sprintf("ew%d%s", i, sfx), fmt.Sprintf("en%d%s", i, sfx)
		must("ip", "link", "add", x, "type", "veth", "peer", "name", y)
		must("ip", "link", "set", x, "netns", ns[node])
		must("ip", "link", "set", y, "netns", ns["net"])
		must(in(node, "ip", "link", "set", x, "name", ifname)...)
		must(in(node, "ip", "addr", "add", fmt.Sprintf("100.64.%d.2/30", i), "dev", ifname)...)
		must(in(node, "ip", "addr", "add", fmt.Sprintf("2001:db8:64:%d::2/64", i), "dev", ifname, "nodad")...)
		for _, p := range pub {
			args := []string{"ip", "addr", "add", p, "dev", ifname}
			if strings.Contains(p, ":") {
				args = append(args, "nodad")
			}
			must(in(node, args...)...)
		}
		must(in(node, "ip", "link", "set", ifname, "up")...)
		must(in("net", "ip", "addr", "add", fmt.Sprintf("100.64.%d.1/30", i), "dev", y)...)
		must(in("net", "ip", "addr", "add", fmt.Sprintf("2001:db8:64:%d::1/64", i), "dev", y, "nodad")...)
		must(in("net", "ip", "link", "set", y, "up")...)
		must(in(node, "ip", "route", "add", "default", "via", fmt.Sprintf("100.64.%d.1", i))...)
		must(in(node, "ip", "-6", "route", "add", "default", "via", fmt.Sprintf("2001:db8:64:%d::1", i))...)
		for _, p := range pub {
			host := strings.Split(p, "/")[0]
			if strings.Contains(host, ":") {
				must(in("net", "ip", "-6", "route", "add", host, "via", fmt.Sprintf("2001:db8:64:%d::2", i))...)
			} else {
				must(in("net", "ip", "route", "add", host, "via", fmt.Sprintf("100.64.%d.2", i))...)
			}
		}
	}
	wan(1, "dc1", "eth0", dc1v4+"/32")
	wan(2, "dc2", "eth0", dc2v4+"/32", dc2v6+"/128")
	wan(3, "access", "eth0", relay4+"/32", relay6+"/128")
	wan(4, "ix", "eth0", ixOut4+"/32", ixIn4+"/32")
	wan(5, "hkb", "eth0", hk5v4+"/32")
	wan(9, "ros", "wan0")
	must(in("ros", "sysctl", "-qw", "net.ipv4.ip_forward=1")...)
	must(in("ros", "sysctl", "-qw", "net.ipv6.conf.all.forwarding=1")...)
	// The home network behind ROS (no NAT: the server sees the client's own
	// LAN address, which is how a home-uplink path shows up).
	must(in("net", "ip", "route", "add", "192.0.2.0/24", "via", "100.64.9.2")...)
	must(in("net", "ip", "-6", "route", "add", "2001:db8:100::/64", "via", "2001:db8:64:9::2")...)

	write := func(name, body string) string {
		p := filepath.Join(dir, name)
		mustWrite(t, p, body)
		return p
	}
	for _, node := range []string{"access", "ix", "hkb", "dc1", "dc2"} {
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
	if tbl := must(in("gw", "ip", "route", "show", "table", "102")...); !regexp.MustCompile(`(?m)^default dev ` + gwAli.Iface() + `\b`).MatchString(tbl) {
		t.Fatalf("setup: table 102 does not start on %s:\n%s", gwAli.Iface(), tbl)
	}
	// The loaded sets hold what the compiler classified.
	for set, want := range map[string][]string{
		"endpoint_direct4": {relay4, ixIn4}, "endpoint_direct6": {relay6},
		"endpoint_tunnel4": {ixOut4, hk5v4, dc1v4, dc2v4}, "endpoint_block6": {dc2v6},
	} {
		out := must(in("gw", "nft", "list", "set", "inet", "meridian", set)...)
		for _, a := range want {
			if !strings.Contains(out, a) {
				t.Fatalf("setup: loaded set %s lacks %s:\n%s", set, a, out)
			}
		}
		t.Logf("EVIDENCE loaded set %s holds %s", set, strings.Join(want, ", "))
	}

	// Observation counters (separate tables, never replaced by a reload).
	type ep struct{ name, addr string }
	eps := []ep{{"relay4", relay4}, {"ixin4", ixIn4}, {"ixout4", ixOut4}, {"hk54", hk5v4}, {"dc14", dc1v4}, {"dc24", dc2v4}, {"relay6", relay6}, {"dc26", dc2v6}}
	tunIfs := fmt.Sprintf("{ %q, %q }", gwAli.Iface(), gwHk5.Iface())
	var gwObs, rosObs strings.Builder
	gwObs.WriteString("table inet epobs {\n")
	rosObs.WriteString("table inet epobs {\n")
	for _, e := range eps {
		for _, c := range []string{"pre_", "lan_", "tun_", "bak_"} {
			fmt.Fprintf(&gwObs, "  counter %s%s {}\n", c, e.name)
		}
		fmt.Fprintf(&rosObs, "  counter ros_%s {}\n", e.name)
	}
	gwObs.WriteString("  counter outer_wg {}\n  counter outer_wss {}\n  counter outer_tun {}\n")
	gwObs.WriteString("  chain pre {\n    type filter hook prerouting priority -400; policy accept;\n")
	rosObs.WriteString("  chain pre {\n    type filter hook prerouting priority -400; policy accept;\n")
	fam := func(a string) (string, string) {
		if strings.Contains(a, ":") {
			return "ip6", cli6
		}
		return "ip", cli4
	}
	for _, e := range eps {
		f, c := fam(e.addr)
		fmt.Fprintf(&gwObs, "    iifname %q %s saddr %s %s daddr %s counter name \"pre_%s\"\n", lab.lan, f, c, f, e.addr, e.name)
		fmt.Fprintf(&rosObs, "    %s saddr %s %s daddr %s counter name \"ros_%s\"\n", f, c, f, e.addr, e.name)
	}
	gwObs.WriteString("  }\n  chain post {\n    type filter hook postrouting priority 400; policy accept;\n")
	for _, e := range eps {
		f, c := fam(e.addr)
		fmt.Fprintf(&gwObs, "    oifname %q ct original %s saddr %s %s daddr %s counter name \"lan_%s\"\n", lab.lan, f, c, f, e.addr, e.name)
		fmt.Fprintf(&gwObs, "    oifname %s ct original %s saddr %s %s daddr %s counter name \"tun_%s\"\n", tunIfs, f, c, f, e.addr, e.name)
		fmt.Fprintf(&gwObs, "    oifname %q ct original %s saddr %s %s daddr %s counter name \"bak_%s\"\n", gwHk5.Iface(), f, c, f, e.addr, e.name)
	}
	fmt.Fprintf(&gwObs, "    oifname %q ip saddr %s ip daddr %s meta mark 0x%x counter name \"outer_wg\"\n", lab.lan, gw4, hk5v4, markUnderlay)
	fmt.Fprintf(&gwObs, "    oifname %q ip saddr %s ip daddr %s tcp dport 8443 counter name \"outer_wss\"\n", lab.lan, gw4, hk5v4)
	fmt.Fprintf(&gwObs, "    oifname %s ct original ip saddr != %s ip daddr %s counter name \"outer_tun\"\n", tunIfs, cli4, hk5v4)
	gwObs.WriteString("  }\n}\n")
	rosObs.WriteString("  }\n}\n")
	must(in("gw", "nft", "-f", write("gw-epobs.nft", gwObs.String()))...)
	must(in("ros", "nft", "-f", write("ros-epobs.nft", rosObs.String()))...)
	cnt := func(n, name string) int { return lab.counter(n, "epobs", name) }

	serverPy := write("epserver.py", netnsEPServerPy)
	connectPy := write("connect.py", netnsConnectPy)
	start := func(n, addr, port string) {
		cmd := exec.Command("ip", "netns", "exec", ns[n], "python3", serverPy, addr, port)
		logf, _ := os.Create(filepath.Join(dir, n+"-server-"+addr+"-"+port+".log"))
		cmd.Stdout, cmd.Stderr = logf, logf
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = cmd.Process.Kill(); _, _ = cmd.Process.Wait(); _ = logf.Close() })
	}
	start("access", relay4, "8080")
	start("access", relay6, "8080")
	start("ix", ixIn4, "8080")
	start("ix", ixOut4, "8080")
	start("hkb", hk5v4, "8080")
	start("hkb", hk5v4, "8443")
	start("dc1", dc1v4, "8080")
	start("dc2", dc2v4, "8080")
	start("dc2", dc2v6, "8080")
	time.Sleep(time.Second)
	// Postcondition: the Internet works from ROS (so a leak would succeed).
	for _, a := range []string{relay4, dc2v4, hk5v4, relay6, dc2v6} {
		if out, err := sh(in("ros", "python3", connectPy, a, "8080")...); err != nil || strings.TrimSpace(out) == "TIMEOUT" {
			t.Fatalf("setup: ROS cannot reach %s over the Internet: %v %s", a, err, out)
		}
	}

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
	connect := func(from, addr, port string) string {
		out, _ := sh(in(from, "python3", connectPy, addr, port)...)
		return strings.TrimSpace(out)
	}
	diag := func() {
		for _, c := range []struct {
			n    string
			args []string
		}{
			{"gw", []string{"ip", "rule"}}, {"gw", []string{"ip", "-6", "rule"}}, {"gw", []string{"ip", "route", "show", "table", "100"}},
			{"gw", []string{"ip", "route", "show", "table", "102"}}, {"gw", []string{"ip", "route"}}, {"gw", []string{"ip", "-6", "route", "show", "table", "100"}},
			{"gw", []string{"nft", "list", "chain", "inet", "meridian", "classify"}}, {"gw", []string{"nft", "list", "table", "inet", "epobs"}},
			{"gw", []string{"nft", "list", "table", "inet", "meridian_guard"}}, {"ros", []string{"nft", "list", "table", "inet", "epobs"}},
			{"ros", []string{"ip", "route"}}, {"ros", []string{"ip", "-6", "route"}},
			{"access", []string{"ip", "rule"}}, {"access", []string{"ip", "route"}}, {"ix", []string{"ip", "rule"}}, {"ix", []string{"ip", "route", "show", "table", strconv.Itoa(hk.Table)}},
			{"hkb", []string{"ip", "rule"}}, {"hkb", []string{"ip", "route"}}, {"hkb", []string{"ip", "route", "show", "table", strconv.Itoa(hk.Table)}},
			{"dc1", []string{"ip", "rule"}}, {"dc1", []string{"ip", "route"}}, {"dc1", []string{"nft", "list", "ruleset"}},
		} {
			out, err := sh(in(c.n, c.args...)...)
			t.Logf("DIAG %s$ %s (err=%v)\n%s", c.n, strings.Join(c.args, " "), err, out)
		}
		logs, _ := filepath.Glob(filepath.Join(dir, "*-server-*.log"))
		for _, f := range logs {
			body, _ := os.ReadFile(f)
			t.Logf("DIAG %s:\n%s", filepath.Base(f), body)
		}
	}
	fails := 0
	fail := func(format string, a ...any) {
		t.Helper()
		fails++
		t.Errorf(format, a...)
	}
	finish := func(phase string) {
		t.Helper()
		if fails > 0 {
			diag()
			t.Fatalf("%s: %d checks failed", phase, fails)
		}
	}
	type delta struct{ pre, lan, tun, bak, ros int }
	snap := func(name string) delta {
		return delta{cnt("gw", "pre_"+name), cnt("gw", "lan_"+name), cnt("gw", "tun_"+name), cnt("gw", "bak_"+name), cnt("ros", "ros_"+name)}
	}
	sub := func(a, b delta) delta {
		return delta{a.pre - b.pre, a.lan - b.lan, a.tun - b.tun, a.bak - b.bak, a.ros - b.ros}
	}
	homeSrc := map[bool]string{false: cli4, true: cli6}
	// direct: the server sees the client's own LAN address (home uplink, no
	// tunnel SNAT), the LAN port and ROS carried it, no tunnel did.
	direct := func(phase string, e ep) {
		t.Helper()
		s0 := snap(e.name)
		got := connect("cli", e.addr, "8080")
		d := sub(snap(e.name), s0)
		want := homeSrc[strings.Contains(e.addr, ":")]
		if got != want || d.lan == 0 || d.ros == 0 || d.tun != 0 {
			fail("%s: client → %s (domestic): server saw %q (want %q), counters %+v (want lan>0 ros>0 tun=0)", phase, e.addr, got, want, d)
			return
		}
		t.Logf("EVIDENCE %s: client → %s (domestic endpoint): server saw %s; packets gw LAN port %d, at ROS %d, into tunnels %d", phase, e.addr, got, d.lan, d.ros, d.tun)
	}
	// viaTunnel: the connection succeeds, the server does not see the home
	// address, the tunnel (bak: the backup tunnel specifically) carried it and
	// zero client packets left on the LAN port or reached ROS.
	viaTunnel := func(phase string, e ep, wantSrc string, backup bool) {
		t.Helper()
		s0 := snap(e.name)
		got := connect("cli", e.addr, "8080")
		d := sub(snap(e.name), s0)
		ok := got != "TIMEOUT" && got != cli4 && got != cli6 && (wantSrc == "" || got == wantSrc) && d.tun > 0 && d.lan == 0 && d.ros == 0
		if backup {
			ok = ok && d.bak == d.tun
		} else {
			ok = ok && d.bak == 0
		}
		if !ok {
			fail("%s: client → %s (foreign): server saw %q (want %q), counters %+v (want tun>0, lan=0, ros=0, backup=%v)", phase, e.addr, got, wantSrc, d, backup)
			return
		}
		t.Logf("EVIDENCE %s: client → %s (foreign endpoint): server saw %s; packets into tunnel %d (backup tunnel %d), gw LAN port 0, at ROS 0", phase, e.addr, got, d.tun, d.bak)
	}
	dropped := func(phase string, e ep) {
		t.Helper()
		s0 := snap(e.name)
		got := connect("cli", e.addr, "8080")
		_, _ = sh(in("cli", "ping", "-n", "-c", "2", "-i", "0.2", "-W", "1", e.addr)...)
		d := sub(snap(e.name), s0)
		if got != "TIMEOUT" || d.pre == 0 || d.lan != 0 || d.ros != 0 || d.tun != 0 {
			fail("%s: client → %s must be dropped: got %q, counters %+v (want arrived>0, lan=0, ros=0, tun=0)", phase, e.addr, got, d)
			return
		}
		t.Logf("EVIDENCE %s: client → %s dropped (fail-closed): %s; arrived at gw %d, gw LAN port 0, at ROS 0, into tunnels 0", phase, e.addr, got, d.pre)
	}
	byName := map[string]ep{}
	for _, e := range eps {
		byName[e.name] = e
	}
	exitSrc := "100.64.1.2" // dc1's WAN: the default group's carrier exit

	// 1. Main path.
	if got := drive("udp", 2); got != "udp" {
		t.Fatalf("main: failover left the main path: %s", got)
	}
	direct("main", byName["relay4"])
	direct("main", byName["ixin4"])
	direct("main", byName["relay6"])
	viaTunnel("main", byName["dc24"], exitSrc, false)
	viaTunnel("main", byName["hk54"], exitSrc, false)
	viaTunnel("main", byName["dc14"], "", false)
	viaTunnel("main", byName["ixout4"], "", false)
	dropped("main", byName["dc26"])
	finish("main")

	// 2. The backup hub carries the default group.
	must(in("access", "nft", "-f", write("access-cut.nft", fmt.Sprintf(`table inet wgcut {
  chain cut_in { type filter hook prerouting priority -500; policy accept; iifname %[1]q drop; }
  chain cut_out { type filter hook output priority -500; policy accept; oifname %[1]q drop; }
  chain cut_fwd { type filter hook forward priority -500; policy accept; oifname %[1]q drop; }
}
`, aliIX.Iface())))...)
	if got := drive("udp", 3); got != "backup" {
		t.Fatalf("backup: failover did not move to the backup hub: %s", got)
	}
	if tbl := must(in("gw", "ip", "route", "show", "table", "102")...); !regexp.MustCompile(`(?m)^default dev ` + gwHk5.Iface() + `\b`).MatchString(tbl) {
		t.Fatalf("backup: table 102 not on %s:\n%s", gwHk5.Iface(), tbl)
	}
	t.Logf("EVIDENCE backup: compiled failover moved table 102 to %s (the backup hub hkb carries group hk)", gwHk5.Iface())
	viaTunnel("backup", byName["hk54"], "", true)
	viaTunnel("backup", byName["dc24"], exitSrc, true)
	direct("backup", byName["relay4"])
	// Route lookups: the client's marked packet to hkb enters the tunnel;
	// the gateway's outer packet (underlay fwmark) takes the main table.
	if out := must(in("gw", "ip", "route", "get", hk5v4, "from", cli4, "iif", lab.lan, "mark", fmt.Sprintf("%#x", hk.Mark))...); !strings.Contains(out, "dev "+gwHk5.Iface()) {
		fail("backup: client route to %s (mark %#x) not via %s:\n%s", hk5v4, hk.Mark, gwHk5.Iface(), out)
	} else {
		t.Logf("EVIDENCE backup: route get %s from client mark %#x: %s", hk5v4, hk.Mark, strings.TrimSpace(out))
	}
	if out := must(in("gw", "ip", "route", "get", hk5v4, "mark", fmt.Sprintf("%#x", markUnderlay))...); !strings.Contains(out, "via 192.0.2.1 dev "+lab.lan) {
		fail("backup: outer route to %s (mark %#x) not the main table's uplink:\n%s", hk5v4, markUnderlay, out)
	} else {
		t.Logf("EVIDENCE backup: route get %s mark %#x (gateway's WireGuard): %s", hk5v4, markUnderlay, strings.TrimSpace(out))
	}
	if out := must(in("gw", "ip", "route", "get", hk5v4)...); !strings.Contains(out, "via 192.0.2.1 dev "+lab.lan) {
		fail("backup: unmarked local route to %s (wstunnel) not the uplink:\n%s", hk5v4, out)
	} else {
		t.Logf("EVIDENCE backup: route get %s unmarked (gateway's wstunnel TCP): %s", hk5v4, strings.TrimSpace(out))
	}
	// Real outer packets, interleaved with real client packets.
	wg0, wss0, otun0, h0 := cnt("gw", "outer_wg"), cnt("gw", "outer_wss"), cnt("gw", "outer_tun"), snap("hk54")
	const n = 10
	if out, err := sh(in("gw", "ping", "-n", "-c", strconv.Itoa(n), "-i", "0.1", "-W", "2", "-m", strconv.Itoa(int(markUnderlay)), hk5v4)...); err != nil {
		fail("backup: gateway's own marked ICMP to %s failed: %v\n%s", hk5v4, err, out)
	}
	if got := connect("gw", hk5v4, "8443"); got != gw4 {
		fail("backup: gateway's own TCP to %s:8443 (wstunnel stand-in): server saw %q, want %q", hk5v4, got, gw4)
	} else {
		t.Logf("EVIDENCE backup: gateway's own TCP to %s:8443 (wstunnel stand-in): server saw %s (home uplink)", hk5v4, got)
	}
	if out, err := sh(in("cli", "ping", "-n", "-c", strconv.Itoa(n), "-i", "0.1", "-W", "2", hk5v4)...); err != nil {
		fail("backup: client ICMP to %s through the backup tunnel failed: %v\n%s", hk5v4, err, out)
	}
	time.Sleep(500 * time.Millisecond)
	dwg, dwss, dotun, dh := cnt("gw", "outer_wg")-wg0, cnt("gw", "outer_wss")-wss0, cnt("gw", "outer_tun")-otun0, sub(snap("hk54"), h0)
	t.Logf("EVIDENCE backup: %d marked outer ICMP + 1 TCP connect from the gateway and %d client ICMP to %s: outer on LAN port %d (wg) + %d (wss), outer into tunnels %d; client into backup tunnel %d, client on LAN port %d, at ROS %d",
		n, n, hk5v4, dwg, dwss, dotun, dh.bak, dh.lan, dh.ros)
	if dwg != n || dwss == 0 || dotun != 0 {
		fail("backup: gateway outer packets did not keep the main-table path: wg %d (want %d), wss %d (want >0), into tunnels %d (want 0)", dwg, n, dwss, dotun)
	}
	if dh.bak != n || dh.tun != n || dh.lan != 0 || dh.ros != 0 {
		fail("backup: client packets to %s: into backup tunnel %d (want exactly %d: no growth loop), all tunnels %d, LAN port %d, ROS %d", hk5v4, dh.bak, n, dh.tun, dh.lan, dh.ros)
	}
	finish("backup")

	// 3. Fail-closed: the default group has no exit target.
	noDef := append([]GroupPlan(nil), groups...)
	for i := range noDef {
		if noDef[i].Group.ID == topo.Settings.DefaultGroup {
			noDef[i].HasTarget = false
		}
	}
	m := regexp.MustCompile(`(?m)^# mss-clamp v4 (\d+) v6 (\d+)$`).FindStringSubmatch(lab.nftText)
	if m == nil {
		t.Fatal("no mss-clamp header in the compiled gateway nft")
	}
	mss4, _ := strconv.Atoi(m[1])
	mss6, _ := strconv.Atoi(m[2])
	var eaNoDef []string
	for _, e := range endpointAccess(topo, tunnels, noDef) {
		eaNoDef = append(eaNoDef, e.Addr+"="+e.Class)
		if !validate.EndpointDomestic(nodeOf(t, topo, e.NodeID), e.Addr) && e.Class != validate.EndpointBlocked {
			t.Fatalf("fail-closed: %s classified %s with no default target", e.Addr, e.Class)
		}
	}
	t.Logf("EVIDENCE fail-closed: endpoint classes with no default exit target: %s", strings.Join(eaNoDef, " "))
	failNFT := write("gw-nodefault.nft", renderGatewayNFT(topo, tunnels, exits, noDef, mss4, mss6, nil, nil))
	must(in("gw", "nft", "-c", "-f", failNFT)...)
	must(in("gw", "nft", "-f", failNFT)...)
	blk := must(in("gw", "nft", "list", "set", "inet", "meridian", "endpoint_block4")...)
	for _, a := range []string{ixOut4, hk5v4, dc1v4, dc2v4} {
		if !strings.Contains(blk, a) {
			t.Fatalf("fail-closed: loaded endpoint_block4 lacks %s:\n%s", a, blk)
		}
	}
	for _, name := range []string{"dc24", "dc14", "hk54", "ixout4", "dc26"} {
		dropped("fail-closed", byName[name])
	}
	direct("fail-closed", byName["relay4"])
	finish("fail-closed")
	fmt.Fprintln(os.Stderr, "meridian-netns-endpoint-access-test-ok")
}

func nodeOf(t *testing.T, topo model.Topology, id string) model.Node {
	t.Helper()
	n, ok := topo.NodeByID(id)
	if !ok {
		t.Fatalf("no node %s", id)
	}
	return n
}

// netnsEPServerPy ADDR PORT: netnsServerPy for either address family.
const netnsEPServerPy = `import socket, sys
fam = socket.AF_INET6 if ":" in sys.argv[1] else socket.AF_INET
s = socket.socket(fam, socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind((sys.argv[1], int(sys.argv[2])))
s.listen(8)
while True:
    c, peer = s.accept()
    print("connection from", peer[0], flush=True)
    c.sendall((peer[0] + "\n").encode())
    c.close()
`
