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
)

// TestNetnsReloadNoLeak is the runtime check for the atomic nft reload and
// the LAN guard. It builds an isolated L2 segment out of network
// namespaces (client, gateway, ROS, joined by a bridge in a fourth
// namespace), installs the compiled gateway routes and nft file into the
// gateway namespace, gives the gateway an IPv6 main-table default via ROS
// (the leak path from the review), and keeps IPv4 and IPv6 traffic
// running from the client while it:
//
//   - shows the leak path is real when no Meridian table is loaded (control);
//   - loads the file on a namespace with no tables (first install);
//   - reloads it many times under traffic;
//   - injects load failures (bad rule at the end of the batch, and between
//     the guard and the main table) and checks both tables are unchanged;
//   - switches the default region group back and forth (nft and routes
//     script of a second compile) and re-runs the routes script under
//     traffic (phase G, added with region groups; not yet executed);
//   - deletes table inet meridian outright and checks the guard alone
//     drops everything forwarded from the LAN;
//   - loads only the early-boot guard file (meridian-guard.nft) and checks
//     the same.
//
// Remote access is on: a fifth namespace is a remote device behind "mra"
// (a veth standing in for the WireGuard interface: the gateway's rules only
// see the interface name, the addresses and the marks). The device keeps
// foreign and domestic v4/v6 traffic running too. Its foreign traffic must
// never reach ROS (and ROS must never see a device-pool source address);
// once loaded, its foreign path must enter the tunnels and its domestic
// path must reach ROS translated to the gateway's LAN address. LAN-to-
// device and device-to-LAN reachability is checked once.
//
// ROS counts packets for a "foreign" v4/v6 destination (must stay 0 once
// the firewall is loaded) and a "domestic" v6 destination added to direct6
// (must arrive, proving the guard keeps the intended direct path).
//
// Root only, Linux only, and opt-in: MERIDIAN_NETNS_TEST=1. It creates and
// removes its own namespaces and touches nothing in the host namespace.
// A passing log from 2026-11-12 is archived under
// docs/evidence/2026-11-12-debian13/; it predates remote access and region
// groups (the "mra" namespace and phase G did not exist then), so it does
// not cover this version. Rerun and re-archive after changing the nft or
// routes rendering. Without a current log the reload is NOT
// verified, and a netns pass is never evidence about a real client.
func TestNetnsReloadNoLeak(t *testing.T) {
	if os.Getenv("MERIDIAN_NETNS_TEST") != "1" {
		t.Skip("runtime netns test: run as root with MERIDIAN_NETNS_TEST=1 (docs/verification.md)")
	}
	if os.Geteuid() != 0 {
		t.Skip("needs root for network namespaces")
	}
	for _, bin := range []string{"ip", "nft", "ping", "bash"} {
		if _, err := exec.LookPath(bin); err != nil {
			t.Skipf("%s not installed", bin)
		}
	}

	topo, _ := raExample(t)
	b, err := Compile(topo)
	if err != nil {
		t.Fatal(err)
	}
	lan := topo.Settings.LANInterface
	nftText := b.File("nodes/gw/etc/nftables.d/meridian.nft")
	dir := t.TempDir()
	nftPath := filepath.Join(dir, "meridian.nft")
	routesPath := filepath.Join(dir, "meridian-routes.sh")
	mustWrite(t, nftPath, nftText)
	mustWrite(t, routesPath, b.File("nodes/gw/usr/local/sbin/meridian-routes.sh"))
	var tunnels []string
	for path := range b.Files {
		if strings.HasPrefix(path, "nodes/gw/etc/wireguard/") && filepath.Base(path) != "mra.conf" {
			tunnels = append(tunnels, strings.TrimSuffix(filepath.Base(path), ".conf"))
		}
	}
	guardPath := filepath.Join(dir, "meridian-guard.nft")
	mustWrite(t, guardPath, b.File("nodes/gw/etc/nftables.d/meridian-guard.nft"))
	raUpPath := filepath.Join(dir, "ra-up.sh")
	mustWrite(t, raUpPath, "set -euo pipefail\n"+remoteUpCommands(planRemote(topo)))

	sfx := strconv.Itoa(os.Getpid() % 100000)
	ns := map[string]string{"sw": "mrdsw" + sfx, "gw": "mrdgw" + sfx, "ros": "mrdros" + sfx, "cli": "mrdcli" + sfx, "dev": "mrddev" + sfx}
	t.Cleanup(func() {
		for _, n := range ns {
			_ = exec.Command("ip", "netns", "del", n).Run()
		}
	})
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
	in := func(n string, args ...string) []string {
		return append([]string{"ip", "netns", "exec", ns[n]}, args...)
	}

	for _, n := range []string{"sw", "gw", "ros", "cli", "dev"} {
		must("ip", "netns", "add", ns[n])
		must(in(n, "ip", "link", "set", "lo", "up")...)
	}
	must(in("sw", "ip", "link", "add", "br0", "type", "bridge", "mcast_snooping", "0")...)
	must(in("sw", "ip", "link", "set", "br0", "up")...)
	for _, h := range []string{"gw", "ros", "cli"} {
		a, p := "t"+h+sfx, "p"+h+sfx
		must("ip", "link", "add", a, "type", "veth", "peer", "name", p)
		must("ip", "link", "set", a, "netns", ns[h])
		must("ip", "link", "set", p, "netns", ns["sw"])
		must(in(h, "ip", "link", "set", a, "name", lan)...)
		must(in("sw", "ip", "link", "set", p, "master", "br0", "up")...)
		must(in(h, "sysctl", "-qw", "net.ipv6.conf."+lan+".accept_ra=0")...)
		must(in(h, "ip", "link", "set", lan, "up")...)
	}

	// ROS: owns the LAN default, and sinks foreign and domestic test addresses.
	must(in("ros", "ip", "addr", "add", "192.168.100.1/24", "dev", lan)...)
	must(in("ros", "ip", "addr", "add", "fe80::1/64", "dev", lan, "nodad")...)
	must(in("ros", "ip", "link", "add", "inet0", "type", "dummy")...)
	must(in("ros", "ip", "link", "set", "inet0", "up")...)
	must(in("ros", "ip", "addr", "add", "198.18.0.1/32", "dev", "inet0")...)
	must(in("ros", "ip", "addr", "add", "198.18.0.2/32", "dev", "inet0")...)
	for _, a := range []string{"2001:db8:ffff::1/128", "2001:db8:cccc::1/128"} {
		must(in("ros", "ip", "addr", "add", a, "dev", "inet0", "nodad")...)
	}
	sink := `table inet sink {
  counter foreign4 {}
  counter foreign6 {}
  counter domestic6 {}
  counter devdom4 {}
  counter devdom6 {}
  counter devraw {}
  chain pre {
    type filter hook prerouting priority -300; policy accept;
    ip saddr 10.67.0.0/24 counter name "devraw"
    ip6 saddr fd67::/64 counter name "devraw"
    ip daddr 198.18.0.1 counter name "foreign4"
    ip6 daddr 2001:db8:ffff::1 counter name "foreign6"
    ip6 daddr 2001:db8:cccc::1 counter name "domestic6"
    ip saddr 192.168.100.88 ip daddr 198.18.0.2 counter name "devdom4"
    ip6 saddr 2001:db8:100::88 ip6 daddr 2001:db8:cccc::1 counter name "devdom6"
  }
}
`
	sinkPath := filepath.Join(dir, "sink.nft")
	mustWrite(t, sinkPath, sink)
	must(in("ros", "nft", "-f", sinkPath)...)

	// Client.
	must(in("cli", "ip", "addr", "add", "192.168.100.50/24", "dev", lan)...)
	must(in("cli", "ip", "addr", "add", "2001:db8:100::50/64", "dev", lan, "nodad")...)
	must(in("cli", "ip", "route", "add", "default", "via", "192.168.100.88")...)
	must(in("cli", "ip", "-6", "route", "add", "default", "via", "fe80::88", "dev", lan)...)

	// Gateway: tunnels are dummies, so whatever is routed into them never
	// reaches ROS; their tx counters show the foreign path is in use.
	must(in("gw", "ip", "addr", "add", "192.168.100.88/24", "dev", lan)...)
	must(in("gw", "ip", "addr", "add", "fe80::88/64", "dev", lan, "nodad")...)
	// A global address for the masquerade of the devices' domestic IPv6.
	must(in("gw", "ip", "addr", "add", "2001:db8:100::88/64", "dev", lan, "nodad")...)
	// Remote device behind "mra".
	must("ip", "link", "add", "ra"+sfx, "type", "veth", "peer", "name", "rd"+sfx)
	must("ip", "link", "set", "ra"+sfx, "netns", ns["gw"])
	must("ip", "link", "set", "rd"+sfx, "netns", ns["dev"])
	must(in("gw", "ip", "link", "set", "ra"+sfx, "name", "mra")...)
	must(in("gw", "bash", raUpPath)...)
	must(in("dev", "ip", "link", "set", "rd"+sfx, "up")...)
	must(in("dev", "ip", "addr", "add", "10.67.0.2/24", "dev", "rd"+sfx)...)
	must(in("dev", "ip", "addr", "add", "fd67::2/64", "dev", "rd"+sfx, "nodad")...)
	must(in("dev", "ip", "route", "add", "default", "via", "10.67.0.1")...)
	must(in("dev", "ip", "-6", "route", "add", "default", "via", "fd67::1")...)
	// Counts device traffic that entered a tunnel (original source kept by
	// conntrack across the transit SNAT). Separate table, never replaced.
	devtunText := "table inet devtun {\n  counter tun {}\n  chain post {\n    type filter hook postrouting priority 300; policy accept;\n"
	for _, tun := range tunnels {
		devtunText += fmt.Sprintf("    oifname %q ct original ip saddr 10.67.0.2 counter name \"tun\"\n    oifname %q ct original ip6 saddr fd67::2 counter name \"tun\"\n", tun, tun)
	}
	devtunText += "  }\n}\n"
	devtunPath := filepath.Join(dir, "devtun.nft")
	mustWrite(t, devtunPath, devtunText)
	must(in("gw", "nft", "-f", devtunPath)...)
	for _, tun := range tunnels {
		must(in("gw", "ip", "link", "add", tun, "type", "dummy")...)
		must(in("gw", "ip", "link", "set", tun, "up")...)
	}
	must(in("gw", "ip", "route", "add", "default", "via", "192.168.100.1", "dev", lan)...)
	must(in("gw", "ip", "-6", "route", "add", "default", "via", "fe80::1", "dev", lan)...)
	must(in("gw", "bash", routesPath)...)
	must(in("gw", "sysctl", "-qw", "net.ipv4.ip_forward=1")...)
	must(in("gw", "sysctl", "-qw", "net.ipv6.conf.all.forwarding=1")...)
	time.Sleep(2 * time.Second)

	counter := func(name string) int {
		t.Helper()
		out := must(in("ros", "nft", "list", "counter", "inet", "sink", name)...)
		m := regexp.MustCompile(`packets (\d+)`).FindStringSubmatch(out)
		if m == nil {
			t.Fatalf("no counter in %s", out)
		}
		v, _ := strconv.Atoi(m[1])
		return v
	}
	tunnelTx := func() int {
		total := 0
		for _, tun := range tunnels {
			out := must(in("gw", "cat", "/sys/class/net/"+tun+"/statistics/tx_packets")...)
			v, _ := strconv.Atoi(strings.TrimSpace(out))
			total += v
		}
		return total
	}
	devTun := func() int {
		t.Helper()
		out := must(in("gw", "nft", "list", "counter", "inet", "devtun", "tun")...)
		m := regexp.MustCompile(`packets (\d+)`).FindStringSubmatch(out)
		if m == nil {
			t.Fatalf("no counter in %s", out)
		}
		v, _ := strconv.Atoi(m[1])
		return v
	}
	// raw: device-pool sources at ROS (never allowed once loaded);
	// dd4/dd6: device domestic traffic at ROS, translated; dt: device
	// traffic into the tunnels.
	type snap struct{ f4, f6, d6, tx, raw, dd4, dd6, dt int }
	read := func() snap {
		return snap{counter("foreign4"), counter("foreign6"), counter("domestic6"), tunnelTx(),
			counter("devraw"), counter("devdom4"), counter("devdom6"), devTun()}
	}
	delta := func(a, b snap) snap {
		return snap{b.f4 - a.f4, b.f6 - a.f6, b.d6 - a.d6, b.tx - a.tx, b.raw - a.raw, b.dd4 - a.dd4, b.dd6 - a.dd6, b.dt - a.dt}
	}
	devOK := func(phase string, d snap, wantFlow bool) {
		t.Helper()
		t.Logf("EVIDENCE %s remote device: raw_at_ros=%d domestic4=%d domestic6=%d into_tunnels=%d", phase, d.raw, d.dd4, d.dd6, d.dt)
		if d.raw != 0 {
			t.Fatalf("%s: a remote device's untranslated traffic reached ROS: %+v", phase, d)
		}
		if wantFlow && (d.dd4 == 0 || d.dd6 == 0 || d.dt == 0) {
			t.Fatalf("%s: remote device domestic (v4/v6) or tunnel path is not working: %+v", phase, d)
		}
		if !wantFlow && (d.dd4 != 0 || d.dd6 != 0 || d.dt != 0) {
			t.Fatalf("%s: remote device traffic forwarded without classification: %+v", phase, d)
		}
	}

	pinger := func(n, dst string) {
		cmd := exec.Command("ip", "netns", "exec", ns[n], "ping", "-n", "-q", "-i", "0.01", dst)
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = cmd.Process.Kill(); _, _ = cmd.Process.Wait() })
	}
	for _, dst := range []string{"198.18.0.1", "2001:db8:ffff::1", "2001:db8:cccc::1"} {
		pinger("cli", dst)
	}
	for _, dst := range []string{"198.18.0.1", "2001:db8:ffff::1", "198.18.0.2", "2001:db8:cccc::1"} {
		pinger("dev", dst)
	}

	// A. Control: no Meridian tables. The IPv6 main default via ROS must
	// leak, or this harness cannot see the failure it is meant to catch.
	s0 := read()
	time.Sleep(time.Second)
	d := delta(s0, read())
	t.Logf("EVIDENCE control(no tables): foreign4=%d foreign6=%d domestic6=%d tunnel_tx=%d", d.f4, d.f6, d.d6, d.tx)
	if d.f6 == 0 {
		t.Fatal("control saw no IPv6 leak via the main-table default; the harness is not exercising the leak path")
	}
	t.Logf("EVIDENCE control(no tables) remote device: raw_at_ros=%d (IPv6 via the main default; IPv4 stops at iif mra unreachable)", d.raw)

	// B. First install on a namespace with no Meridian tables.
	must(in("gw", "nft", "-c", "-f", nftPath)...)
	must(in("gw", "nft", "-f", nftPath)...)
	must(in("gw", "nft", "list", "table", "inet", "meridian_guard")...)
	must(in("gw", "nft", "list", "table", "inet", "meridian")...)
	addDomestic := func() {
		must(in("gw", "nft", "add", "element", "inet", "meridian", "direct6", "{ 2001:db8:cccc::1 }")...)
		must(in("gw", "nft", "add", "element", "inet", "meridian", "direct4", "{ 198.18.0.2 }")...)
	}
	addDomestic()
	s1 := read()
	time.Sleep(time.Second)
	d = delta(s1, read())
	t.Logf("EVIDENCE first-install: foreign4=%d foreign6=%d domestic6=%d tunnel_tx=%d", d.f4, d.f6, d.d6, d.tx)
	if d.f4 != 0 || d.f6 != 0 {
		t.Fatalf("foreign traffic reached ROS after load: %+v", d)
	}
	if d.d6 == 0 {
		t.Fatal("domestic IPv6 via ROS was blocked: the guard breaks the intended direct path")
	}
	if d.tx == 0 {
		t.Fatal("no traffic entered the tunnel interfaces; classification did not run")
	}
	devOK("first-install", d, true)
	// LAN to device and device to LAN (the point of home-only mode).
	must(in("cli", "ping", "-n", "-c", "2", "-W", "2", "10.67.0.2")...)
	must(in("dev", "ping", "-n", "-c", "2", "-W", "2", "192.168.100.50")...)
	must(in("cli", "ping", "-n", "-c", "2", "-W", "2", "fd67::2")...)

	// C. Reload under continuous traffic.
	const reloads = 200
	s2 := read()
	for i := 0; i < reloads; i++ {
		must(in("gw", "nft", "-f", nftPath)...)
	}
	time.Sleep(200 * time.Millisecond)
	d = delta(s2, read())
	t.Logf("EVIDENCE %d reloads under traffic: foreign4=%d foreign6=%d tunnel_tx=%d", reloads, d.f4, d.f6, d.tx)
	if d.f4 != 0 || d.f6 != 0 {
		t.Fatalf("foreign traffic reached ROS during reload: %+v", d)
	}
	devOK(fmt.Sprintf("%d reloads", reloads), d, true)

	// D. Fault injection. Both tables must be byte-for-byte what they were
	// (ignoring counter values), and the up-script loader must stop.
	addDomestic()
	stripCounters := regexp.MustCompile(`counter packets \d+ bytes \d+`)
	listing := func() string {
		g := must(in("gw", "nft", "list", "table", "inet", "meridian_guard")...)
		m := must(in("gw", "nft", "list", "table", "inet", "meridian")...)
		return stripCounters.ReplaceAllString(g+m, "counter")
	}
	before := listing()
	bad := "add rule inet meridian_guard forward ip daddr @meridian_no_such_set drop\n"
	split := strings.Index(nftText, "table inet meridian\ndelete table inet meridian\n")
	if split < 0 {
		t.Fatal("main table idiom not found")
	}
	variants := map[string]string{
		"end":    nftText + "add rule inet meridian classify ip daddr @meridian_no_such_set drop\n",
		"middle": nftText[:split] + bad + nftText[split:],
	}
	s3 := read()
	for name, body := range variants {
		p := filepath.Join(dir, "broken-"+name+".nft")
		mustWrite(t, p, body)
		if out, err := sh(in("gw", "nft", "-c", "-f", p)...); err == nil {
			t.Fatalf("%s: nft -c accepted a broken batch\n%s", name, out)
		}
		if out, err := sh(in("gw", "nft", "-f", p)...); err == nil {
			t.Fatalf("%s: nft -f accepted a broken batch\n%s", name, out)
		}
		if after := listing(); after != before {
			t.Fatalf("%s: failed load changed the ruleset\nbefore:\n%s\nafter:\n%s", name, before, after)
		}
		loader := strings.ReplaceAll(nftLoadCommands(true), "/etc/nftables.d/meridian.nft", p)
		out, err := sh(in("gw", "bash", "-c", "set -euo pipefail\n"+loader+"echo loader-continued\n")...)
		if err == nil || strings.Contains(out, "loader-continued") || !strings.Contains(out, "meridian-nft-check-failed") {
			t.Fatalf("%s: up-script loader did not stop: err=%v\n%s", name, err, out)
		}
	}
	time.Sleep(time.Second)
	d = delta(s3, read())
	t.Logf("EVIDENCE injected load failures: foreign4=%d foreign6=%d domestic6=%d (old ruleset kept)", d.f4, d.f6, d.d6)
	if d.f4 != 0 || d.f6 != 0 {
		t.Fatalf("foreign traffic reached ROS around failed loads: %+v", d)
	}
	if d.d6 == 0 {
		t.Fatal("domestic path stopped after a failed load: old table not intact")
	}
	devOK("injected load failures", d, true)

	// G. Region-group switch under traffic: install the same topology with
	// another default group (new classifier mark for unmatched foreign
	// traffic, the routes script re-run with its delete-and-re-add of every
	// fwmark rule), re-run the routes script repeatedly, then switch back.
	// Neither LAN nor device traffic may reach ROS at any point, and the
	// foreign path must resume through the tunnels afterwards.
	switched := topo
	switched.Settings.DefaultGroup = "jp"
	if switched.Settings.DefaultGroup == topo.Settings.DefaultGroup {
		t.Fatal("example default group is already jp")
	}
	b2, err := Compile(switched)
	if err != nil {
		t.Fatal(err)
	}
	groups2, err := PlanGroups(switched)
	if err != nil {
		t.Fatal(err)
	}
	var jpMark uint32
	for _, g := range groups2 {
		if g.Group.ID == "jp" {
			jpMark = g.Mark
		}
	}
	if jpMark == 0 {
		t.Fatal("no jp group mark")
	}
	nft2Path := filepath.Join(dir, "meridian-switched.nft")
	routes2Path := filepath.Join(dir, "meridian-routes-switched.sh")
	mustWrite(t, nft2Path, b2.File("nodes/gw/etc/nftables.d/meridian.nft"))
	mustWrite(t, routes2Path, b2.File("nodes/gw/usr/local/sbin/meridian-routes.sh"))
	s6 := read()
	for i := 0; i < 20; i++ {
		nftP, routesP := nft2Path, routes2Path
		if i%2 == 1 {
			nftP, routesP = nftPath, routesPath
		}
		must(in("gw", "nft", "-c", "-f", nftP)...)
		must(in("gw", "nft", "-f", nftP)...)
		must(in("gw", "bash", routesP)...)
	}
	time.Sleep(200 * time.Millisecond)
	d = delta(s6, read())
	t.Logf("EVIDENCE 20 group switches (nft + routes) under traffic: foreign4=%d foreign6=%d", d.f4, d.f6)
	if d.f4 != 0 || d.f6 != 0 {
		t.Fatalf("foreign traffic reached ROS during a group switch: %+v", d)
	}
	if d.raw != 0 {
		t.Fatalf("a remote device's untranslated traffic reached ROS during a group switch: %+v", d)
	}
	// End on the switched topology and check its default mark is live.
	must(in("gw", "nft", "-f", nft2Path)...)
	must(in("gw", "bash", routes2Path)...)
	classify := must(in("gw", "nft", "list", "chain", "inet", "meridian", "classify")...)
	if !regexp.MustCompile(fmt.Sprintf(`meta nfproto ipv4 meta mark set 0x0*%x`, jpMark)).MatchString(classify) {
		t.Fatalf("switched default group mark %#x not loaded:\n%s", jpMark, classify)
	}
	for i := 0; i < 20; i++ {
		must(in("gw", "bash", routes2Path)...)
	}
	addDomestic()
	s7 := read()
	time.Sleep(time.Second)
	d = delta(s7, read())
	t.Logf("EVIDENCE after group switch and 20 routes reloads: foreign4=%d foreign6=%d domestic6=%d tunnel_tx=%d", d.f4, d.f6, d.d6, d.tx)
	if d.f4 != 0 || d.f6 != 0 {
		t.Fatalf("foreign traffic reached ROS after a group switch: %+v", d)
	}
	if d.d6 == 0 || d.tx == 0 {
		t.Fatalf("domestic or tunnel path not working after a group switch: %+v", d)
	}
	devOK("after group switch", d, true)

	// E. Guard independence: drop the classification table entirely (what
	// the old delete-then-load sequence did between its two processes).
	must(in("gw", "nft", "delete", "table", "inet", "meridian")...)
	s4 := read()
	time.Sleep(time.Second)
	d = delta(s4, read())
	t.Logf("EVIDENCE guard only (inet meridian deleted): foreign4=%d foreign6=%d domestic6=%d", d.f4, d.f6, d.d6)
	if d.f4 != 0 || d.f6 != 0 || d.d6 != 0 {
		t.Fatalf("guard did not fail closed without classification: %+v", d)
	}
	devOK("guard only", d, false)

	// F. Boot order: only the early-boot guard file is loaded (what
	// meridian-guard.service does before meridian.service), forwarding and
	// routes already in place. Everything from the LAN and from mra drops.
	must(in("gw", "nft", "delete", "table", "inet", "meridian_guard")...)
	must(in("gw", "nft", "-f", guardPath)...)
	if _, err := sh(in("gw", "nft", "list", "table", "inet", "meridian")...); err == nil {
		t.Fatal("the early-boot file must not create the classification table")
	}
	s5 := read()
	time.Sleep(time.Second)
	d = delta(s5, read())
	t.Logf("EVIDENCE early-boot guard file only: foreign4=%d foreign6=%d domestic6=%d", d.f4, d.f6, d.d6)
	if d.f4 != 0 || d.f6 != 0 || d.d6 != 0 {
		t.Fatalf("early-boot guard did not fail closed: %+v", d)
	}
	devOK("early-boot guard only", d, false)
	fmt.Fprintln(os.Stderr, "meridian-netns-reload-test-ok")
}

func mustWrite(t *testing.T, path, body string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}
