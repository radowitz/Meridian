//go:build linux

package compile

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/radowitz/meridian/internal/defaults"
	"github.com/radowitz/meridian/internal/remoteaccess"
	"github.com/radowitz/meridian/internal/validate"
)

// TestNetnsMeshLeg is the runtime check of a WireGuard leg carried over the
// Mesh (docs/architecture.md「Cloudflare Mesh：WireGuard 的底层承载」), with
// the COMPILED files of the example topology for the hub and exit "us":
// their WireGuard configs (the direct leg and the Mesh leg, real WireGuard
// interfaces with generated keys), routes scripts, nft rulesets and
// meridian-mesh-up.sh.
//
// Namespaces:
//
//	hub ──eth0── net ──eth0── us          the Internet stand-in: the direct
//	 │                         │          leg's underlay, and the data server
//	mmesh                     mmesh       192.0.2.80 behind the exit's WAN
//	 │                         │
//	hsc ══cfw0═══════════cfw0══ esc       the two sidecars and the Mesh
//
// "hsc" and "esc" stand in for the sidecar containers (a sleeping process
// in each is the container, a "docker" shim reports its pid; the compiled
// script's own nsenter seals the namespace). The Cloudflare Mesh between
// them is a pair of tun devices ("cfw0", link/none like the WARP device,
// MTU 1280) joined by a python3 relay; each end has a Mesh address in
// 100.96.0.0/12 and the on-link route to that range. Nothing else is added
// by hand in the sidecars: the routes to the published address, table 170,
// the forward chain and the source NAT all come from the compiled seal. The
// hub sidecar also has a docker-bridge stand-in "eth0" with a default
// route, which must never carry a packet.
//
// What it shows, with packets:
//
//   - the hub's Mesh leg handshakes with the exit through both sidecars, and
//     its outer packets never touch the hub's WAN;
//   - client traffic (the exit's transit source, as the hub receives it
//     from the gateway) put on the Mesh leg leaves from the exit's own WAN
//     address, exactly as over the direct leg, and its replies come back
//     over the Mesh leg, also with the direct leg cut;
//   - a region-group resolver query (IPv6) over the Mesh leg is answered by
//     the exit's resolver address;
//   - an inner packet of the leg's payload MTU crosses the 1280 Mesh
//     unfragmented, one byte more is carried by fragments of the outer
//     packet, up to the interface MTU;
//   - the seal: from the hub nothing but the leg's WireGuard UDP to the
//     exit's Mesh address crosses the sidecar (another port, ICMP, another
//     destination routed onto the veth by hand are all dropped), nothing
//     leaves the sidecar's docker bridge, and the exit forwards nothing that
//     arrives from its sidecar;
//   - with the Mesh down the leg carries nothing and nothing leaks; unsealed,
//     the hub's route to the exit's Mesh address is the blackhole.
//
// What it does not show: that the real Cloudflare Mesh routes a published
// /32 between two nodes, lets WireGuard's UDP through, or passes the
// fragments. The emulation only forwards IP packets between two tun
// devices.
//
// Root only, Linux only, opt-in (MERIDIAN_NETNS_TEST=1); needs ip, nft,
// ping, bash, python3, nsenter, wg and /dev/net/tun.
func TestNetnsMeshLeg(t *testing.T) {
	netnsPrereqs(t)
	for _, bin := range []string{"python3", "nsenter", "wg"} {
		if _, err := exec.LookPath(bin); err != nil {
			t.Skipf("%s not installed", bin)
		}
	}
	if _, err := os.Stat("/dev/net/tun"); err != nil {
		t.Skip("/dev/net/tun not available (the Mesh emulation needs tun devices)")
	}
	topo := defaults.Example()
	keys := map[string]remoteaccess.Keypair{}
	for i := range topo.Nodes {
		if id := topo.Nodes[i].ID; id == "hk-hub" || id == "us" {
			kp, err := remoteaccess.GenerateKeypair()
			if err != nil {
				t.Fatal(err)
			}
			keys[id] = kp
			topo.Nodes[i].PublicKey = kp.Public
		}
	}
	b, err := Compile(topo)
	if err != nil {
		t.Fatal(err)
	}
	lab := &netnsLab{t: t, b: b, dir: t.TempDir(), ns: map[string]string{}}
	dir, sh, must, in := lab.dir, lab.sh, lab.must, lab.in
	tunnels := mustTunnels(t, topo)
	exits, groups := plans(t, topo)
	direct, leg := hubDirect(tunnels, "us", "hk-hub"), hubMeshLeg(tunnels, "us", "hk-hub")
	usExit, _ := exitByID(exits, "us")
	usGroup := mustGroup(t, groups, "us")
	if direct.LinkID == "" || leg.LinkID == "" || !leg.Standby || usExit.HubIface != direct.Iface() || usExit.MeshIface != leg.Iface() {
		t.Fatalf("exit us must have a direct leg and a standby Mesh leg: %+v / %+v", direct, leg)
	}
	payload, device := validate.MeshLegMTU(meshLinkOf(topo, leg))
	if leg.MTU != device || device != 1280 || payload != 1216 {
		t.Fatalf("Mesh leg MTU %d (payload %d, device %d)", leg.MTU, payload, device)
	}
	t.Logf("exit us: direct leg %s, Mesh leg %s (Mesh address %s port %d, MTU %d, payload %d), transit %s, table %d; group us table %d resolver %s",
		direct.Iface(), leg.Iface(), leg.MeshAddr, leg.WGPort, leg.MTU, payload, usExit.TransitV4, usExit.Table, usGroup.Table, usGroup.Resolver)

	sfx := strconv.Itoa(os.Getpid() % 100000)
	for _, n := range []string{"hub", "us", "hsc", "esc", "net"} {
		lab.ns[n] = "mml" + n + sfx
		must("ip", "netns", "add", lab.ns[n])
		name := lab.ns[n]
		t.Cleanup(func() { _, _ = sh("ip", "netns", "del", name) })
		must(in(n, "ip", "link", "set", "lo", "up")...)
		must(in(n, "sysctl", "-qw", "net.ipv4.ip_forward=1")...)
		must(in(n, "sysctl", "-qw", "net.ipv6.conf.all.forwarding=1")...)
		must(in(n, "sysctl", "-qw", "net.ipv4.conf.all.rp_filter=2")...)
		must(in(n, "sysctl", "-qw", "net.ipv4.conf.default.rp_filter=2")...)
	}
	ns := lab.ns
	nodeNS := map[string]string{"hk-hub": "hub", "us": "us"}
	write := func(name, body string) string {
		p := filepath.Join(dir, name)
		mustWrite(t, p, body)
		return p
	}
	fails := 0
	check := func(what, got, want string) {
		t.Helper()
		if got != want {
			fails++
			t.Errorf("%s: got %q, want %q", what, got, want)
			return
		}
		t.Logf("EVIDENCE %s: %s", what, got)
	}

	// The Internet stand-in: hub and us each on their public address.
	wan := map[string]string{"hub": "203.0.113.20", "us": "198.51.100.20"}
	for i, n := range []string{"hub", "us"} {
		x, y := fmt.Sprintf("mw%d%s", i, sfx), fmt.Sprintf("mn%d%s", i, sfx)
		gwAddr := strings.TrimSuffix(wan[n], ".20") + ".1"
		must("ip", "link", "add", x, "type", "veth", "peer", "name", y)
		must("ip", "link", "set", x, "netns", ns[n])
		must("ip", "link", "set", y, "netns", ns["net"])
		must(in(n, "ip", "link", "set", x, "name", "eth0")...)
		must(in(n, "ip", "addr", "add", wan[n]+"/24", "dev", "eth0")...)
		must(in(n, "ip", "link", "set", "eth0", "up")...)
		must(in(n, "ip", "route", "add", "default", "via", gwAddr)...)
		must(in("net", "ip", "addr", "add", gwAddr+"/24", "dev", y)...)
		must(in("net", "ip", "link", "set", y, "up")...)
	}
	must(in("net", "ip", "link", "add", "srv", "type", "dummy")...)
	must(in("net", "ip", "addr", "add", "192.0.2.80/32", "dev", "srv")...)
	must(in("net", "ip", "link", "set", "srv", "up")...)
	// What the Internet sees: WireGuard to the Mesh leg's port (must stay 0),
	// anything with a Meridian source (must stay 0), and the client traffic
	// by the address it arrives from.
	must(in("net", "nft", "-f", write("net-obs.nft", fmt.Sprintf(`table inet meshobs {
  counter mesh_port {}
  counter private_src {}
  counter to_mesh_addr {}
  chain pre {
    type filter hook prerouting priority -400; policy accept;
    udp dport %[1]d counter name "mesh_port"
    ip saddr { 10.66.0.0/16, 10.68.0.0/24, 169.254.0.0/16, 100.96.0.0/12 } counter name "private_src"
    ip daddr 10.68.0.0/24 counter name "to_mesh_addr"
  }
}
`, leg.WGPort)))...)

	// What the hub's compiled meridian-up.sh does before it brings up any
	// WireGuard interface: the blackholes of the exits' Mesh addresses. The
	// Mesh leg starts its handshake the moment it is up, and not one of
	// those packets may leave by the hub's default route (counted on "net").
	guard := meshUnderlayGuard(mustNode(t, topo, "hk-hub"), tunnels)
	up := b.File("nodes/hk-hub/usr/local/sbin/meridian-up.sh")
	if guard == "" || !strings.Contains(up, guard) || strings.Index(up, guard) > strings.Index(up, "wg-quick up") {
		t.Fatalf("the hub's meridian-up.sh does not blackhole the Mesh addresses before WireGuard comes up:\n%s", guard)
	}
	must(in("hub", "bash", write("hub-guard.sh", "set -e\n"+guard))...)

	// WireGuard: the two legs between the hub and us are real, from the
	// compiled configs with the generated keys; every other tunnel of the
	// two hosts is a dummy with its compiled addresses, so the compiled
	// routes scripts find it.
	addrLine := regexp.MustCompile(`(?m)^Address\s*=\s*(.+)$`)
	mtuLine := regexp.MustCompile(`(?m)^MTU\s*=\s*(\d+)$`)
	for _, node := range []string{"hk-hub", "us"} {
		n := nodeNS[node]
		pre := "nodes/" + node + "/etc/wireguard/"
		for path, conf := range b.Files {
			if !strings.HasPrefix(path, pre) {
				continue
			}
			iface := strings.TrimSuffix(strings.TrimPrefix(path, pre), ".conf")
			real := iface == direct.Iface() || iface == leg.Iface()
			if real {
				must(in(n, "ip", "link", "add", iface, "type", "wireguard")...)
				conf = strings.ReplaceAll(conf, PrivateKeyPlaceholder, keys[node].Private)
				var strip []string
				for _, l := range strings.Split(conf, "\n") {
					if k := strings.TrimSpace(strings.SplitN(l, "=", 2)[0]); k == "Address" || k == "MTU" || k == "Table" {
						continue
					}
					strip = append(strip, l)
				}
				p := write(n+"-"+iface+".conf", strings.Join(strip, "\n"))
				if err := os.Chmod(p, 0o600); err != nil {
					t.Fatal(err)
				}
				must(in(n, "wg", "setconf", iface, p)...)
				if m := mtuLine.FindStringSubmatch(conf); m != nil {
					must(in(n, "ip", "link", "set", "dev", iface, "mtu", m[1])...)
				}
			} else {
				must(in(n, "ip", "link", "add", iface, "type", "dummy")...)
			}
			m := addrLine.FindStringSubmatch(conf)
			if m == nil {
				t.Fatalf("%s has no Address line", path)
			}
			for _, a := range strings.Split(m[1], ",") {
				if a = strings.TrimSpace(a); a == "" {
					continue
				}
				args := []string{"ip", "addr", "add", a, "dev", iface}
				if strings.Contains(a, ":") {
					args = append(args, "nodad")
				}
				must(in(n, args...)...)
			}
			must(in(n, "ip", "link", "set", iface, "up")...)
		}
	}
	// The interface really is what the compiler wrote: 1280 with IPv6 on it.
	for _, n := range []string{"hub", "us"} {
		l := must(in(n, "ip", "-o", "link", "show", leg.Iface())...)
		a6 := must(in(n, "ip", "-6", "-o", "addr", "show", "dev", leg.Iface())...)
		if !strings.Contains(l, "mtu 1280 ") || !strings.Contains(a6, "fd66:") {
			t.Fatalf("%s: Mesh leg %s is not a 1280 interface with its ULA:\n%s\n%s", n, leg.Iface(), l, a6)
		}
	}

	// Compiled routes and nft on both hosts. State directories are
	// redirected away from this host's /run/meridian.
	runDir := map[string]string{"hub": filepath.Join(dir, "hubrun"), "us": filepath.Join(dir, "usrun")}
	for _, node := range []string{"hk-hub", "us"} {
		n := nodeNS[node]
		if err := os.MkdirAll(runDir[n], 0o755); err != nil {
			t.Fatal(err)
		}
		routes := strings.ReplaceAll(b.File("nodes/"+node+"/usr/local/sbin/meridian-routes.sh"), "/run/meridian", runDir[n])
		must(in(n, "bash", write(n+"-routes.sh", routes))...)
		nftP := write(n+".nft", b.File("nodes/"+node+"/etc/nftables.d/meridian.nft"))
		must(in(n, "nft", "-c", "-f", nftP)...)
		must(in(n, "nft", "-f", nftP)...)
	}
	// Before any sidecar exists the hub's route to the exit's Mesh address
	// is the blackhole: the leg's outer packets go nowhere.
	if out, _ := sh(in("hub", "ip", "route", "get", leg.MeshAddr)...); !strings.Contains(out, "blackhole") && !strings.Contains(out, "Invalid argument") && !strings.Contains(out, "unreachable") {
		t.Fatalf("no sidecar yet, but the hub routes %s: %s", leg.MeshAddr, out)
	}

	// Client traffic as the hub sees it: the exit's and the group's transit
	// sources (on the hub's lo, so its "from <transit> lookup <table>" rules
	// apply and replies are delivered here).
	must(in("hub", "ip", "addr", "add", usExit.TransitV4+"/32", "dev", "lo")...)
	must(in("hub", "ip", "-6", "addr", "add", usGroup.TransitV6+"/128", "dev", "lo")...)
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
	start("net", "python3", write("server.py", netnsServerPy), "192.0.2.80", "8080")
	start("us", "python3", write("resolver.py", netnsResolverPy), usExit.DNSULA, "198.18.1.1")
	connectPy := write("connect-from.py", netnsConnectFromPy)
	queryPy := write("query-from.py", netnsQueryFromPy)
	sendPy := write("send.py", "import socket, sys\ns = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)\ns.sendto(b'x' * 32, (sys.argv[1], int(sys.argv[2])))\n")
	time.Sleep(time.Second)
	connect := func() string {
		out, _ := sh(in("hub", "python3", connectPy, usExit.TransitV4, "192.0.2.80", "8080")...)
		return strings.TrimSpace(out)
	}
	query := func() string {
		out, _ := sh(in("hub", "python3", queryPy, usGroup.TransitV6, usGroup.Resolver, "mesh.example.com")...)
		return strings.TrimSpace(out)
	}

	// SmartDNS-style socket: no SO_MARK and no bind, especially no
	// TransitV6. Kernel main-table lookup chooses both leg and source.
	smartQueryPy := write("query-unbound.py", strings.Replace(netnsQueryFromPy, "    s.bind((src, 0))\n", "", 1))
	smartQuery := func() string {
		out, _ := sh(in("hub", "python3", smartQueryPy, "unused", usExit.DNSULA, "pinned.example.com")...)
		return strings.TrimSpace(out)
	}
	smartLookup := func(dev, src string) {
		out := must(in("hub", "ip", "-6", "route", "get", usExit.DNSULA)...)
		if !strings.Contains(out, "dev "+dev) || !strings.Contains(out, "src "+src) || strings.Contains(out, "table ") {
			t.Errorf("unmarked/unbound main lookup: %s; want dev %s src %s", out, dev, src)
		}
	}

	// us: what arrives on and leaves through each leg with the transit
	// address, and what leaves the WAN with it (never, after the NAT).
	must(in("us", "nft", "-f", write("us-obs.nft", fmt.Sprintf(`table inet meshobs {
  counter in_direct {}
  counter in_mesh {}
  counter back_direct {}
  counter back_mesh {}
  counter wan_transit {}
  counter fwd_from_veth {}
  chain pre {
    type filter hook prerouting priority -400; policy accept;
    iifname "%[1]s" ip saddr %[3]s counter name "in_direct"
    iifname "%[2]s" ip saddr %[3]s counter name "in_mesh"
    iifname "mmesh" ip daddr 192.0.2.81 counter name "fwd_from_veth"
  }
  chain post {
    type filter hook postrouting priority 400; policy accept;
    oifname "%[1]s" ip daddr %[3]s counter name "back_direct"
    oifname "%[2]s" ip daddr %[3]s counter name "back_mesh"
    oifname "eth0" ip saddr %[3]s counter name "wan_transit"
  }
}
`, direct.Iface(), leg.Iface(), usExit.TransitV4)))...)
	cnt := func(n, name string) int { return lab.counter(n, "meshobs", name) }

	// 1. The direct leg, as before any Mesh: the exit's own WAN address.
	check("direct leg: the server sees the client from", connect(), wan["us"])
	if cnt("us", "in_direct") == 0 || cnt("us", "in_mesh") != 0 {
		t.Fatalf("direct leg: us counters in_direct=%d in_mesh=%d", cnt("us", "in_direct"), cnt("us", "in_mesh"))
	}

	// 2. The sidecars and the Mesh between them.
	must(in("hsc", "ip", "link", "add", "eth0", "type", "dummy")...)
	must(in("hsc", "ip", "link", "set", "eth0", "up")...)
	must(in("hsc", "ip", "addr", "add", "172.31.66.2/24", "dev", "eth0")...)
	must(in("hsc", "ip", "route", "add", "default", "dev", "eth0")...)
	must(in("hsc", "ip", "-6", "route", "add", "default", "dev", "eth0")...)
	xd, xe := "md"+sfx, "me"+sfx
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
	cfa, cfb := "mca"+sfx, "mcb"+sfx
	stopRelay := start("hsc", "python3", write("relay.py", netnsTunRelayPy), cfa, cfb)
	deadline := time.Now().Add(10 * time.Second)
	for {
		if _, err := sh(in("hsc", "ip", "link", "show", cfb)...); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("mesh setup: the tun relay did not create its devices in hsc")
		}
		time.Sleep(100 * time.Millisecond)
	}
	must(in("hsc", "ip", "link", "set", cfb, "netns", ns["esc"])...)
	must(in("hsc", "ip", "link", "set", cfa, "name", "cfw0")...)
	must(in("esc", "ip", "link", "set", cfb, "name", "cfw0")...)
	for _, c := range []struct{ n, self string }{{"esc", "100.96.0.2/32"}, {"hsc", "100.96.0.1/32"}} {
		must(in(c.n, "ip", "link", "set", "cfw0", "mtu", "1280")...)
		must(in(c.n, "ip", "link", "set", "cfw0", "up")...)
		must(in(c.n, "ip", "addr", "add", c.self, "dev", "cfw0")...)
		must(in(c.n, "ip", "route", "add", "100.96.0.0/12", "dev", "cfw0")...)
	}
	if out, err := sh(in("hsc", "ping", "-c", "2", "-W", "2", "-n", "100.96.0.2")...); err != nil {
		t.Fatalf("mesh setup: the emulated Mesh does not forward: %v\n%s", err, out)
	}
	// Observation in the sidecars: anything leaving the hub sidecar's docker
	// bridge, what enters the exit's sidecar from the Mesh by port, and
	// fragments on the Mesh (counted before reassembly).
	must(in("hsc", "nft", "-f", write("hsc-obs.nft", "table inet meshobs {\n  counter leak {}\n  counter to_mesh_other {}\n  chain post {\n    type filter hook postrouting priority 400; policy accept;\n    oifname \"eth0\" counter name \"leak\"\n    oifname \"cfw0\" ip daddr 192.0.2.0/24 counter name \"to_mesh_other\"\n  }\n}\n"))...)
	must(in("esc", "nft", "-f", write("esc-obs.nft", fmt.Sprintf("table inet meshobs {\n  counter c_wg {}\n  counter c_other {}\n  counter c_icmp {}\n  counter c_frags {}\n  chain pre {\n    type filter hook prerouting priority -450; policy accept;\n    iifname \"cfw0\" ip frag-off & 0x3fff != 0 counter name \"c_frags\"\n    iifname \"cfw0\" udp dport %d counter name \"c_wg\"\n    iifname \"cfw0\" udp dport 9999 counter name \"c_other\"\n    iifname \"cfw0\" meta l4proto icmp ip daddr %s counter name \"c_icmp\"\n  }\n}\n", leg.WGPort, leg.MeshAddr)))...)

	// The compiled meridian-mesh-up.sh of the hub and of us, each against
	// its stand-in sidecar.
	sleeper := func(n string) int {
		cmd := exec.Command("ip", "netns", "exec", ns[n], "sleep", "100000")
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = cmd.Process.Kill(); _, _ = cmd.Process.Wait() })
		return cmd.Process.Pid
	}
	pids := map[string]int{"hub": sleeper("hsc"), "us": sleeper("esc")}
	time.Sleep(300 * time.Millisecond)
	meshUp := func(node, token string, args ...string) string {
		t.Helper()
		n := nodeNS[node]
		etc, bin := filepath.Join(dir, n+"-etc"), filepath.Join(dir, n+"-bin")
		for _, d := range []string{etc, bin} {
			if err := os.MkdirAll(d, 0o755); err != nil {
				t.Fatal(err)
			}
		}
		mustWrite(t, filepath.Join(etc, "mesh.env"), "MESH_NODE_TOKEN="+token+"\n")
		mustWrite(t, filepath.Join(etc, "mesh-sidecar.compose.yml"), "# netns stand-in\n")
		// A shim, never the real docker daemon.
		shim := fmt.Sprintf("#!/bin/bash\ncase \"$1 $2\" in\n  \"compose -f\") shift 3; case \"$*\" in \"up -d\") exit 0 ;; \"ps -q mesh\") echo meridian-netns-sidecar; exit 0 ;; esac ;;\n  \"inspect -f\") echo %d; exit 0 ;;\nesac\nexit 1\n", pids[n])
		if err := os.WriteFile(filepath.Join(bin, "docker"), []byte(shim), 0o755); err != nil {
			t.Fatal(err)
		}
		body := b.File("nodes/" + node + "/usr/local/sbin/meridian-mesh-up.sh")
		body = strings.ReplaceAll(body, "/run/meridian", runDir[n])
		body = strings.ReplaceAll(body, "/etc/meridian/", etc+"/")
		out, err := sh(in(n, append([]string{"env", "PATH=" + bin + ":" + os.Getenv("PATH"), "bash", write(n+"-mesh-up.sh", body)}, args...)...)...)
		t.Logf("EVIDENCE %s meridian-mesh-up.sh %v: err=%v\n%s", node, args, err, out)
		if err != nil {
			t.Fatalf("%s meridian-mesh-up.sh %v: %v\n%s", node, args, err, out)
		}
		return out
	}
	diag := func() {
		for _, c := range []struct {
			n    string
			args []string
		}{
			{"hub", []string{"ip", "route"}}, {"hub", []string{"ip", "rule"}}, {"hub", []string{"ip", "route", "show", "table", strconv.Itoa(usExit.Table)}}, {"hub", []string{"wg", "show"}},
			{"hub", []string{"ip", "neigh", "show", "dev", "mmesh"}}, {"hub", []string{"ip", "addr", "show", "dev", "mmesh"}},
			{"hsc", []string{"ip", "addr"}}, {"hsc", []string{"ip", "route"}}, {"hsc", []string{"ip", "rule"}}, {"hsc", []string{"ip", "route", "show", "table", "170"}}, {"hsc", []string{"nft", "list", "ruleset"}},
			{"esc", []string{"ip", "addr"}}, {"esc", []string{"ip", "route"}}, {"esc", []string{"ip", "rule"}}, {"esc", []string{"ip", "route", "show", "table", "170"}}, {"esc", []string{"nft", "list", "ruleset"}},
			{"us", []string{"ip", "route"}}, {"us", []string{"ip", "rule"}}, {"us", []string{"ip", "addr", "show", "dev", "mmesh"}}, {"us", []string{"wg", "show"}},
			{"us", []string{"ip", "route", "show", "table", strconv.Itoa(tableHubReturnMesh)}}, {"us", []string{"nft", "list", "ruleset"}},
			{"net", []string{"nft", "list", "table", "inet", "meshobs"}},
		} {
			out, err := sh(in(c.n, c.args...)...)
			t.Logf("DIAG %s$ %s (err=%v)\n%s", c.n, strings.Join(c.args, " "), err, out)
		}
	}
	finish := func(phase string) {
		t.Helper()
		if fails > 0 {
			diag()
			t.Fatalf("%s: %d check(s) failed", phase, fails)
		}
	}
	for _, node := range []string{"hk-hub", "us"} {
		if out := meshUp(node, "netns-placeholder"); !strings.Contains(out, "mesh sidecar sealed") {
			diag()
			t.Fatalf("%s: the compiled meridian-mesh-up.sh did not seal", node)
		}
		if _, err := os.Stat(filepath.Join(runDir[nodeNS[node]], "mesh-sealed")); err != nil {
			t.Fatalf("%s: no seal file", node)
		}
	}
	// The seal as installed: table 170 holds only the Mesh peers, the
	// forward chain only the leg's WireGuard.
	t170 := func(n string) []string {
		var out []string
		for _, l := range strings.Split(strings.TrimSpace(must(in(n, "ip", "route", "show", "table", "170")...)), "\n") {
			if f := strings.Fields(l); len(f) > 1 {
				out = append(out, f[0]+" "+f[1])
			}
		}
		sort.Strings(out)
		return out
	}
	hubLegs := meshLegsOn(tunnels, "hk-hub")
	wantHub := []string{}
	for _, a := range meshUnderlayAddrs(mustNode(t, topo, "hk-hub"), tunnels) {
		wantHub = append(wantHub, a+" dev")
	}
	wantHub = append(wantHub, "unreachable default")
	check("hub sidecar table 170", strings.Join(t170("hsc"), ", "), strings.Join(wantHub, ", "))
	check("exit sidecar table 170", strings.Join(t170("esc"), ", "), "100.96.0.0/12 dev, unreachable default")
	for _, n := range []string{"hsc", "esc"} {
		for _, fam := range []string{"-4", "-6"} {
			if out := must(in(n, "ip", fam, "rule")...); !strings.Contains(out, "iif mmesh-c lookup 170") {
				fails++
				t.Errorf("%s: no %s rule iif mmesh-c lookup 170:\n%s", n, fam, out)
			}
		}
	}
	hscNft := must(in("hsc", "nft", "list", "table", "inet", "meridian_mesh")...)
	for _, tun := range hubLegs {
		if !strings.Contains(hscNft, fmt.Sprintf(`iifname "mmesh-c" oifname "cfw0" ip daddr %s udp dport %d accept`, tun.MeshAddr, tun.WGPort)) {
			fails++
			t.Errorf("hub sidecar does not pass leg %s:\n%s", tun.LinkID, hscNft)
		}
	}
	escNft := must(in("esc", "nft", "list", "table", "inet", "meridian_mesh")...)
	if !strings.Contains(escNft, `iifname "mmesh-c" drop`) || !strings.Contains(hscNft, `iifname "mmesh-c" drop`) || !strings.Contains(escNft, "masquerade") || !strings.Contains(hscNft, "masquerade") {
		fails++
		t.Errorf("sidecar seal incomplete:\n%s\n%s", hscNft, escNft)
	}
	hubRoute := must(in("hub", "ip", "route", "get", leg.MeshAddr)...)
	if !strings.Contains(hubRoute, "via 169.254.66.2 dev mmesh") {
		fails++
		t.Errorf("sealed: the hub does not route %s through the sidecar: %s", leg.MeshAddr, hubRoute)
	}
	if out := must(in("us", "ip", "-o", "-4", "addr", "show", "dev", "mmesh")...); !strings.Contains(out, leg.MeshAddr+"/32") {
		fails++
		t.Errorf("us does not own its Mesh address on mmesh:\n%s", out)
	}
	// No default route onto the veth anywhere on either host.
	for _, n := range []string{"hub", "us"} {
		all := must(in(n, "ip", "route", "show", "table", "all")...) + must(in(n, "ip", "-6", "route", "show", "table", "all")...)
		for _, l := range strings.Split(all, "\n") {
			if strings.HasPrefix(l, "default") && strings.Contains(l, "mmesh") {
				fails++
				t.Errorf("%s: a default route onto the Mesh veth: %s", n, l)
			}
		}
	}
	finish("seal")

	// 3. The Mesh leg handshakes through the sidecars and answers.
	pingLeg := func() error {
		_, err := sh(in("hub", "ping", "-c", "3", "-W", "2", "-n", "-I", leg.Iface(), leg.EastV4)...)
		return err
	}
	var perr error
	for i := 0; i < 5; i++ {
		if perr = pingLeg(); perr == nil {
			break
		}
		time.Sleep(time.Second)
	}
	if perr != nil {
		fails++
		t.Errorf("the hub cannot reach the exit over the Mesh leg: %v", perr)
	}
	hs := must(in("hub", "wg", "show", leg.Iface(), "latest-handshakes")...)
	if f := strings.Fields(hs); len(f) != 2 || f[1] == "0" {
		fails++
		t.Errorf("no handshake on the hub's Mesh leg: %q", hs)
	}
	ep := strings.TrimSpace(must(in("us", "wg", "show", leg.Iface(), "endpoints")...))
	if f := strings.Fields(ep); len(f) != 2 || !strings.HasPrefix(f[1], "169.254.66.2:") {
		fails++
		t.Errorf("the exit's Mesh-leg peer is not its sidecar: %q", ep)
	} else {
		t.Logf("EVIDENCE the exit sees the hub's Mesh leg from %s (its own sidecar)", f[1])
	}
	if cnt("esc", "c_wg") == 0 || cnt("net", "mesh_port") != 0 || cnt("net", "to_mesh_addr") != 0 {
		fails++
		t.Errorf("the Mesh leg's outer packets: through the Mesh %d, on the Internet %d / %d (want >0, 0, 0)", cnt("esc", "c_wg"), cnt("net", "mesh_port"), cnt("net", "to_mesh_addr"))
	}
	finish("handshake")

	// 4. Client traffic on the Mesh leg: what the quality switch will do is
	// point the exit's table at the other leg. The exit's public address is
	// the same, and the replies come back over the Mesh leg.
	hop := func(iface string) {
		for _, table := range []int{usExit.Table, usGroup.Table} {
			must(in("hub", "ip", "route", "replace", "default", "dev", iface, "table", strconv.Itoa(table))...)
			must(in("hub", "ip", "-6", "route", "replace", "default", "dev", iface, "table", strconv.Itoa(table))...)
		}
	}
	quality := renderMeshQuality(topo, []ExitPlan{usExit})
	quality = quality[:strings.Index(quality, "mesh_managed()")]
	quality = strings.ReplaceAll(quality, "/run/meridian", runDir["hub"])
	target, ds, ms := meshDNSRoute(topo, usExit)
	quality += fmt.Sprintf("\nmesh_leg_step us %d %s %s %s %s %s %s %s\n", usExit.Table, shQuote(direct.Iface()), shQuote(usExit.PeerV4), shQuote(leg.Iface()), shQuote(usExit.MeshPeerV4), shQuote(target), shQuote(ds), shQuote(ms))
	qualityScript := write("hub-quality.sh", quality)
	hop(leg.Iface())
	inMesh, backMesh, backDirect := cnt("us", "in_mesh"), cnt("us", "back_mesh"), cnt("us", "back_direct")
	check("Mesh leg: the server sees the client from", connect(), wan["us"])
	if cnt("us", "in_mesh") <= inMesh || cnt("us", "back_mesh") <= backMesh || cnt("us", "back_direct") != backDirect {
		fails++
		t.Errorf("Mesh leg: us counters in_mesh %d→%d back_mesh %d→%d back_direct %d→%d (replies must follow the Mesh leg)", inMesh, cnt("us", "in_mesh"), backMesh, cnt("us", "back_mesh"), backDirect, cnt("us", "back_direct"))
	}
	// The direct leg cut entirely: the Mesh leg alone carries the exit.
	must(in("net", "nft", "-f", write("net-cut.nft", fmt.Sprintf("table inet wgcut {\n  chain cut_through {\n    type filter hook forward priority -300; policy accept;\n    udp dport %d drop\n    udp sport %d drop\n  }\n}\n", direct.WGPort, direct.WGPort)))...)
	// Start from the direct exit hop: the real measured controller must
	// select Mesh immediately, without selecting a different exit.
	for _, fam := range []string{"-4", "-6"} {
		must(in("hub", "ip", fam, "route", "replace", "default", "dev", direct.Iface(), "table", strconv.Itoa(usExit.Table))...)
	}
	must(in("hub", "bash", qualityScript)...)
	selected, _ := os.ReadFile(filepath.Join(runDir["hub"], "exit-legs/us/iface"))
	if strings.TrimSpace(string(selected)) != leg.Iface() {
		t.Fatalf("direct cut: controller selected %s", selected)
	}
	check("Mesh leg, direct leg cut: the server sees the client from", connect(), wan["us"])
	smartLookup(leg.Iface(), ms)
	check("unmarked unbound DNS, direct cut", smartQuery(), "198.18.1.1")
	// A region-group resolver query (IPv6, the group's transit source) over
	// the Mesh leg: answered by the exit's resolver.
	check("Mesh leg: group resolver query answered by", query(), "198.18.1.1")
	// A re-seal (the hub's failover loop runs one every 5 seconds, an exit's
	// timer every minute) changes nothing that is already right: the leg
	// keeps carrying, on the same WireGuard session.
	hsBefore := must(in("hub", "wg", "show", leg.Iface(), "latest-handshakes")...)
	for i := 0; i < 3; i++ {
		for _, node := range []string{"hk-hub", "us"} {
			if out := meshUp(node, "netns-placeholder", "--seal-only"); !strings.Contains(out, "mesh sidecar sealed") {
				fails++
				t.Errorf("%s: re-seal %d did not seal:\n%s", node, i, out)
			}
		}
		check(fmt.Sprintf("Mesh leg after re-seal %d: the server sees the client from", i+1), connect(), wan["us"])
	}
	if hsAfter := must(in("hub", "wg", "show", leg.Iface(), "latest-handshakes")...); hsAfter != hsBefore {
		t.Logf("NOTE the Mesh leg re-handshook during the re-seals (%q → %q)", strings.TrimSpace(hsBefore), strings.TrimSpace(hsAfter))
	}
	check("hub sidecar table 170 after re-seals", strings.Join(t170("hsc"), ", "), strings.Join(wantHub, ", "))
	finish("traffic over the Mesh leg")

	// 5. MTU: the payload size crosses the 1280 Mesh unfragmented; one byte
	// more, and up to the interface MTU, is carried by outer fragments.
	ping := func(size int) error {
		_, err := sh(in("hub", "ping", "-c", "2", "-W", "2", "-n", "-M", "dont", "-s", strconv.Itoa(size-28), "-I", usExit.TransitV4, "192.0.2.80")...)
		return err
	}
	frags := cnt("esc", "c_frags")
	if err := ping(payload); err != nil || cnt("esc", "c_frags") != frags {
		fails++
		t.Errorf("a %d-byte inner packet: err %v, outer fragments %d (want none)", payload, err, cnt("esc", "c_frags")-frags)
	} else {
		t.Logf("EVIDENCE a %d-byte inner packet crosses the 1280 Mesh without a fragment", payload)
	}
	for _, size := range []int{payload + 1, device} {
		frags = cnt("esc", "c_frags")
		if err := ping(size); err != nil || cnt("esc", "c_frags") == frags {
			fails++
			t.Errorf("a %d-byte inner packet: err %v, outer fragments %d (want some, and an answer)", size, err, cnt("esc", "c_frags")-frags)
		} else {
			t.Logf("EVIDENCE a %d-byte inner packet is carried by %d fragments of the outer packet", size, cnt("esc", "c_frags")-frags)
		}
	}
	finish("MTU")

	// 6. The seal, with packets. From the hub host, onto the veth:
	// WireGuard's port passes (above); another port, ICMP and another
	// destination do not.
	_, _ = sh(in("hub", "python3", sendPy, leg.MeshAddr, "9999")...)
	if _, err := sh(in("hub", "ping", "-c", "1", "-W", "1", "-n", leg.MeshAddr)...); err == nil {
		fails++
		t.Error("seal: ICMP from the hub reaches the exit's Mesh address")
	}
	must(in("hub", "ip", "route", "add", "192.0.2.80/32", "via", "169.254.66.2", "dev", "mmesh")...)
	if _, err := sh(in("hub", "ping", "-c", "1", "-W", "1", "-n", "192.0.2.80")...); err == nil {
		fails++
		t.Error("seal: a destination routed onto the veth by hand is reachable through the sidecar")
	}
	must(in("hub", "ip", "route", "del", "192.0.2.80/32", "via", "169.254.66.2", "dev", "mmesh")...)
	// From the exit's sidecar toward the exit host: nothing is forwarded.
	must(in("esc", "ip", "route", "add", "192.0.2.81/32", "via", "169.254.66.1", "dev", "mmesh-c")...)
	must(in("net", "ip", "addr", "add", "192.0.2.81/32", "dev", "srv")...)
	fwd := cnt("us", "fwd_from_veth")
	if _, err := sh(in("esc", "ping", "-c", "1", "-W", "1", "-n", "192.0.2.81")...); err == nil {
		fails++
		t.Error("seal: the exit forwards what arrives from its sidecar")
	}
	if cnt("us", "fwd_from_veth") == fwd {
		t.Log("NOTE the exit sidecar's own forward chain already stopped the packet before the host's")
	}
	if cnt("esc", "c_other") != 0 || cnt("esc", "c_icmp") != 0 || cnt("hsc", "to_mesh_other") != 0 || cnt("hsc", "leak") != 0 || cnt("net", "private_src") != 0 {
		fails++
		t.Errorf("seal: through the Mesh another port %d, ICMP %d, another destination %d; out of the hub sidecar's bridge %d; Meridian sources on the Internet %d (want all 0)",
			cnt("esc", "c_other"), cnt("esc", "c_icmp"), cnt("hsc", "to_mesh_other"), cnt("hsc", "leak"), cnt("net", "private_src"))
	} else {
		t.Log("EVIDENCE seal: another port, ICMP and another destination did not cross the sidecar; nothing left its docker bridge; no Meridian source on the Internet")
	}
	if cnt("us", "wan_transit") != 0 {
		fails++
		t.Errorf("the exit sent %d packets out of its WAN with a transit source", cnt("us", "wan_transit"))
	}
	finish("seal with packets")

	// 7. The Mesh goes away: the leg carries nothing, nothing leaks, and
	// the exit's table does not fall anywhere else.
	stopRelay()
	time.Sleep(300 * time.Millisecond)
	check("Mesh down: connection over the Mesh leg", connect(), "TIMEOUT")
	check("Mesh down: group resolver query", query(), "TIMEOUT")
	if cnt("hsc", "leak") != 0 || cnt("net", "private_src") != 0 || cnt("net", "mesh_port") != 0 {
		fails++
		t.Errorf("Mesh down: leak %d, Meridian sources on the Internet %d, Mesh-leg WireGuard on the Internet %d", cnt("hsc", "leak"), cnt("net", "private_src"), cnt("net", "mesh_port"))
	}
	finish("Mesh down")

	// 8. Unsealed (no token): the hub's route to the exit's Mesh address is
	// the blackhole again, whatever the exit's table says.
	meshUp("hk-hub", "", "--seal-only")
	if _, err := os.Stat(filepath.Join(runDir["hub"], "mesh-sealed")); err == nil {
		fails++
		t.Error("unsealed: the seal file is still there")
	}
	if out, _ := sh(in("hub", "ip", "route", "get", leg.MeshAddr)...); strings.Contains(out, "mmesh") || strings.Contains(out, "eth0") {
		fails++
		t.Errorf("unsealed: the hub still routes %s somewhere: %s", leg.MeshAddr, out)
	} else {
		t.Logf("EVIDENCE unsealed: ip route get %s: %s", leg.MeshAddr, strings.TrimSpace(out))
	}
	check("unsealed: connection over the Mesh leg", connect(), "TIMEOUT")
	if cnt("net", "mesh_port") != 0 || cnt("net", "to_mesh_addr") != 0 || cnt("net", "private_src") != 0 {
		fails++
		t.Errorf("unsealed: the leg's outer packets left the hub's WAN (%d / %d / %d)", cnt("net", "mesh_port"), cnt("net", "to_mesh_addr"), cnt("net", "private_src"))
	}
	// Back on the direct leg (its cut removed): the exit works as before.
	must(in("net", "nft", "delete", "table", "inet", "wgcut")...)
	hop(direct.Iface())
	var got string
	for i := 0; i < 6; i++ {
		if got = connect(); got == wan["us"] {
			break
		}
		time.Sleep(time.Second)
	}
	check("back on the direct leg: the server sees the client from", got, wan["us"])
	// R3: actual measured selection after the Mesh relay has stopped.
	// The namespace's real ping sees the direct leg, then both legs down;
	// the controller must install v4/v6 blackholes in this exit table.
	must(in("hub", "bash", qualityScript)...)
	check("quality controller keeps reachable direct leg", connect(), wan["us"])
	smartLookup(direct.Iface(), ds)
	check("unmarked unbound DNS switchback", smartQuery(), "198.18.1.1")
	must(in("hub", "ip", "link", "set", direct.Iface(), "down")...)
	must(in("hub", "bash", qualityScript)...)
	for _, fam := range []string{"-4", "-6"} {
		routes := must(in("hub", "ip", fam, "route", "show", "table", strconv.Itoa(usExit.Table))...)
		if !strings.Contains(routes, "blackhole default") || strings.Contains(routes, "default dev") {
			t.Errorf("dual-leg outage did not blackhole %s table: %s", fam, routes)
		}
	}
	check("quality controller dual-down", connect(), "TIMEOUT")
	if out, err := sh(in("hub", "ip", "-6", "route", "get", usExit.DNSULA)...); err == nil {
		t.Errorf("both down DNS lookup escaped blackhole: %s", out)
	}
	check("unmarked unbound DNS both down", smartQuery(), "TIMEOUT")
	if cnt("net", "private_src") != 0 || cnt("net", "mesh_port") != 0 {
		t.Error("quality controller leaked onto WAN")
	}
	must(in("hub", "ip", "link", "set", direct.Iface(), "up")...)
	must(in("hub", "bash", qualityScript)...)
	check("quality controller direct restored", connect(), wan["us"])
	finish("unsealed")
	fmt.Fprintln(os.Stderr, "meridian-netns-mesh-leg-test-ok")
}

// netnsConnectFromPy SRC ADDR PORT: connect from SRC, print the server's
// line or TIMEOUT.
const netnsConnectFromPy = `import socket, sys
try:
    s = socket.create_connection((sys.argv[2], int(sys.argv[3])), timeout=5, source_address=(sys.argv[1], 0))
    print(s.recv(100).decode().strip())
except Exception:
    print("TIMEOUT")
`

// netnsQueryFromPy SRC SERVER NAME: one UDP A query for NAME from [SRC] to
// [SERVER]:53. Prints the first A answer or TIMEOUT.
const netnsQueryFromPy = `import socket, struct, sys, random
src, server, name = sys.argv[1], sys.argv[2], sys.argv[3]
q = struct.pack(">HHHHHH", random.randint(0, 65535), 0x0100, 1, 0, 0, 0)
for label in name.split("."):
    q += bytes([len(label)]) + label.encode()
q += b"\x00" + struct.pack(">HH", 1, 1)
try:
    s = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
    s.bind((src, 0))
    s.settimeout(3)
    s.sendto(q, (server, 53))
    r = s.recv(4096)
    print(socket.inet_ntoa(r[-4:]))
except Exception:
    print("TIMEOUT")
`
