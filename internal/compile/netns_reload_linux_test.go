//go:build linux

package compile

import (
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/radowitz/meridian/internal/model"
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
// device and device-to-LAN reachability is part of e2e() below.
//
// ROS counts packets for a "foreign" v4/v6 destination (must stay 0 once
// the firewall is loaded) and "domestic" v4/v6 destinations added to
// direct4/direct6 (must arrive, proving the guard keeps the intended direct
// path). ROS owns those addresses on a dummy interface, has an on-link route
// for the LAN (v4 and v6) so it can answer the client and the gateway's
// masquerade address, and has NO route to the device pool (that is why the
// gateway NATs the devices' domestic traffic; the test asserts it).
//
// Counting packets that leave is not enough: an IPv4 "iif <LAN> unreachable"
// policy rule once made the kernel's source validation (rp_filter=2, reverse
// lookup with iif = the output interface and mark 0) drop every IPv4 packet
// forwarded OUT of the LAN NIC or mra, and no counter here noticed. So in
// every phase where traffic must flow (first install, after the reload
// storm, after the group switch) e2e() also requires real ping REPLIES —
// LAN client to domestic v4/v6, device to domestic v4/v6 (the reply comes
// back through the gateway's NAT and out of mra), LAN client to device and
// device to LAN client, v4 and v6 — and asks the kernel with
// "ip route get … iif <tunnel>" whether a reply from each tunnel interface
// to the LAN client and to the device resolves out of the LAN NIC and mra
// (the dummy tunnels cannot answer, so this is the only check of that
// path), and that no "iif … unreachable" rule is loaded.
//
// Root only, Linux only, and opt-in: MERIDIAN_NETNS_TEST=1. It creates and
// removes its own namespaces and touches nothing in the host namespace.
// A passing log of this version from 2026-11-13 (Debian 13, kernel 6.12,
// nftables 1.1.3) is archived under docs/evidence/2026-11-13-debian13/. The
// older log under docs/evidence/2026-11-12-debian13/ predates remote access
// and region groups (the "mra" namespace and phase G did not exist then),
// was produced with the "iif … unreachable" rule in place and did not
// exercise IPv4 domestic traffic or any reply path, so it does not cover
// this version. Rerun and re-archive after changing the nft or routes
// rendering. Without a current log the reload is NOT verified, and a netns
// pass is never evidence about a real client.
//
// The namespaces are built by newNetnsLab (shared with
// TestNetnsULALANHomeAccess, which repeats the setup with a ULA LAN
// prefix); moving the setup there changed no command, address or order of
// this test, only added the unused "ulaout" counter to ROS's sink.
func TestNetnsReloadNoLeak(t *testing.T) {
	netnsPrereqs(t)
	topo, _ := raExample(t)
	lab := newNetnsLab(t, topo, labV6{prefix: "2001:db8:100::/64", gw: "2001:db8:100::88", cli: "2001:db8:100::50"})
	lan, nftText, dir, ns, tunnels := lab.lan, lab.nftText, lab.dir, lab.ns, lab.tunnels
	nftPath, routesPath, guardPath := lab.nftPath, lab.routesPath, lab.guardPath
	sh, must, in := lab.sh, lab.must, lab.in

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
	// d4: the LAN client's domestic IPv4 at ROS; raw4: the IPv4 part of raw.
	type snap struct{ f4, f6, d4, d6, tx, raw, raw4, dd4, dd6, dt int }
	read := func() snap {
		return snap{counter("foreign4"), counter("foreign6"), counter("domestic4"), counter("domestic6"), tunnelTx(),
			counter("devraw"), counter("devraw4"), counter("devdom4"), counter("devdom6"), devTun()}
	}
	delta := func(a, b snap) snap {
		return snap{b.f4 - a.f4, b.f6 - a.f6, b.d4 - a.d4, b.d6 - a.d6, b.tx - a.tx, b.raw - a.raw, b.raw4 - a.raw4, b.dd4 - a.dd4, b.dd6 - a.dd6, b.dt - a.dt}
	}
	// diag logs the gateway namespace's live state when a device check
	// fails, so a failure on a real kernel can be read from the log alone.
	diag := func() {
		for _, c := range [][]string{
			{"ip", "-4", "rule"}, {"ip", "-6", "rule"},
			{"ip", "-4", "route", "show", "table", "100"}, {"ip", "-6", "route", "show", "table", "100"},
			{"ip", "-4", "route", "show", "table", "main"}, {"ip", "-4", "addr", "show", "dev", "mra"},
			{"ip", "-4", "route", "get", "10.67.0.2"},
			{"sysctl", "net.ipv4.conf.all.src_valid_mark", "net.ipv4.conf.mra.src_valid_mark", "net.ipv4.conf.all.forwarding", "net.ipv4.conf.mra.forwarding"},
			{"ip", "-4", "route", "get", "198.18.0.2", "from", "10.67.0.2", "iif", "mra", "mark", "0x64"},
			{"ip", "-4", "route", "get", "198.18.0.2", "from", "192.168.100.50", "iif", lan, "mark", "0x64"},
			{"ip", "-6", "route", "get", "2001:db8:cccc::1", "from", "fd67::2", "iif", "mra", "mark", "0x64"},
			{"ip", "-4", "route", "get", "10.67.0.2", "from", "198.18.0.2", "iif", lan, "mark", "0x64"},
			{"ip", "-4", "route", "get", "192.168.100.50", "from", "198.18.0.1", "iif", tunnels[0]},
			{"ip", "-4", "route", "get", "10.67.0.2", "from", "198.18.0.1", "iif", tunnels[0]},
			{"ip", "-4", "route", "get", "192.168.100.50", "from", "10.67.0.2", "iif", "mra"},
			{"nft", "list", "chain", "inet", "meridian", "transit_snat"},
			{"nft", "list", "chain", "inet", "meridian", "classify"},
			{"nft", "list", "table", "inet", "meridian_guard"},
			{"sysctl", "net.ipv4.conf.all.rp_filter", "net.ipv4.conf.mra.rp_filter", "net.ipv4.conf." + lan + ".rp_filter"},
		} {
			out, err := exec.Command("ip", append([]string{"netns", "exec", ns["gw"]}, c...)...).CombinedOutput()
			t.Logf("DIAG gw$ %s (err=%v)\n%s", strings.Join(c, " "), err, out)
		}
		for _, c := range [][]string{{"ip", "-4", "route"}, {"ip", "-6", "route"}, {"ip", "-6", "neigh"}} {
			out, err := exec.Command("ip", append([]string{"netns", "exec", ns["ros"]}, c...)...).CombinedOutput()
			t.Logf("DIAG ros$ %s (err=%v)\n%s", strings.Join(c, " "), err, out)
		}
	}
	// e2e: in a phase where traffic must flow, real replies and the kernel's
	// forwarding decision for the reply paths the dummy tunnels cannot answer.
	e2e := func(phase string) {
		t.Helper()
		fails := 0
		for _, p := range []struct{ from, dst, what string }{
			{"cli", "198.18.0.2", "LAN client to domestic IPv4 (hairpin out of the LAN NIC)"},
			{"cli", "2001:db8:cccc::1", "LAN client to domestic IPv6"},
			{"dev", "198.18.0.2", "device to domestic IPv4 (NAT on the LAN NIC, reply out of mra)"},
			{"dev", "2001:db8:cccc::1", "device to domestic IPv6 (NAT on the LAN NIC, reply out of mra)"},
			{"cli", "10.67.0.2", "LAN client to device IPv4"},
			{"cli", "fd67::2", "LAN client to device IPv6"},
			{"dev", "192.168.100.50", "device to LAN client IPv4"},
			{"dev", "2001:db8:100::50", "device to LAN client IPv6"},
		} {
			out, err := sh(in(p.from, "ping", "-n", "-c", "3", "-i", "0.2", "-W", "2", p.dst)...)
			if err != nil {
				fails++
				t.Errorf("%s: no reply: %s (%s -> %s): %v\n%s", phase, p.what, p.from, p.dst, err, out)
			} else {
				t.Logf("EVIDENCE %s e2e ok: %s (%s -> %s)", phase, p.what, p.from, p.dst)
			}
		}
		// Each lookup must resolve out of the named interface.
		type probe struct {
			want string
			args []string
		}
		var checks []probe
		add := func(want string, args ...string) { checks = append(checks, probe{want, args}) }
		add(lan, "-4", "route", "get", "198.18.0.2", "from", "192.168.100.50", "iif", lan, "mark", "0x64")
		add(lan, "-4", "route", "get", "198.18.0.2", "from", "10.67.0.2", "iif", "mra", "mark", "0x64")
		add("mra", "-4", "route", "get", "10.67.0.2", "from", "198.18.0.2", "iif", lan, "mark", "0x64")
		for _, tun := range tunnels {
			add(lan, "-4", "route", "get", "192.168.100.50", "from", "198.18.0.1", "iif", tun)
			add(lan, "-6", "route", "get", "2001:db8:100::50", "from", "2001:db8:ffff::1", "iif", tun)
			add("mra", "-4", "route", "get", "10.67.0.2", "from", "198.18.0.1", "iif", tun)
			add("mra", "-6", "route", "get", "fd67::2", "from", "2001:db8:ffff::1", "iif", tun)
		}
		devRe := func(dev string) *regexp.Regexp { return regexp.MustCompile(` dev ` + regexp.QuoteMeta(dev) + `( |$)`) }
		for _, c := range checks {
			out, err := sh(in("gw", append([]string{"ip"}, c.args...)...)...)
			first, _, _ := strings.Cut(out, "\n")
			if err != nil || !devRe(c.want).MatchString(first) || strings.HasPrefix(first, "unreachable") || strings.HasPrefix(first, "blackhole") {
				fails++
				t.Errorf("%s: ip %s must resolve out of %s (kernel source validation included), got err=%v:\n%s", phase, strings.Join(c.args, " "), c.want, err, out)
			}
		}
		if rules := must(in("gw", "ip", "-4", "rule", "show")...); regexp.MustCompile(`iif \S+( \[detached\])? unreachable`).MatchString(rules) {
			fails++
			t.Errorf("%s: an iif unreachable rule is loaded:\n%s", phase, rules)
		}
		if fails > 0 {
			diag()
			t.Fatalf("%s: %d end-to-end or route-validation checks failed", phase, fails)
		}
		t.Logf("EVIDENCE %s: %d route-validation checks ok (replies from %d tunnels to the LAN client and the device, LAN/device domestic and reply)", phase, len(checks), len(tunnels))
	}
	devOK := func(phase string, d snap, wantFlow bool) {
		t.Helper()
		t.Logf("EVIDENCE %s remote device: raw_at_ros=%d domestic4=%d domestic6=%d into_tunnels=%d", phase, d.raw, d.dd4, d.dd6, d.dt)
		if d.raw != 0 {
			diag()
			t.Fatalf("%s: a remote device's untranslated traffic reached ROS: %+v", phase, d)
		}
		if wantFlow && (d.dd4 == 0 || d.dd6 == 0 || d.dt == 0) {
			diag()
			t.Fatalf("%s: remote device domestic (v4/v6) or tunnel path is not working: %+v", phase, d)
		}
		if !wantFlow && (d.dd4 != 0 || d.dd6 != 0 || d.dt != 0) {
			diag()
			t.Fatalf("%s: remote device traffic forwarded without classification: %+v", phase, d)
		}
	}

	pinger := func(n, dst string) (stop func()) {
		cmd := exec.Command("ip", "netns", "exec", ns[n], "ping", "-n", "-q", "-i", "0.01", dst)
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
		var once sync.Once
		stop = func() { once.Do(func() { _ = cmd.Process.Kill(); _, _ = cmd.Process.Wait() }) }
		t.Cleanup(stop)
		return stop
	}
	for _, dst := range []string{"198.18.0.1", "2001:db8:ffff::1", "198.18.0.2", "2001:db8:cccc::1"} {
		pinger("cli", dst)
	}
	devDsts := []string{"198.18.0.1", "2001:db8:ffff::1", "198.18.0.2", "2001:db8:cccc::1"}
	var devStops []func()
	startDev := func() {
		for _, dst := range devDsts {
			devStops = append(devStops, pinger("dev", dst))
		}
	}
	stopDev := func() {
		for _, s := range devStops {
			s()
		}
		devStops = nil
	}
	startDev()

	// A. Control: no Meridian tables (the routes are installed, forwarding
	// is on). Unclassified traffic, v4 and v6, from the LAN client and from
	// the device must leak via the main-table default to ROS: this is the
	// baseline the tables prevent, and it shows the harness exercises the
	// leak path. (IPv4 too: there is no "iif … unreachable" routing
	// backstop; with both Meridian nft tables gone IPv4 leaks like IPv6.)
	s0 := read()
	time.Sleep(time.Second)
	d := delta(s0, read())
	t.Logf("EVIDENCE control(no tables): foreign4=%d foreign6=%d domestic4=%d domestic6=%d tunnel_tx=%d (expected: foreign v4 and v6 leak, nothing enters a tunnel)", d.f4, d.f6, d.d4, d.d6, d.tx)
	t.Logf("EVIDENCE control(no tables) remote device: raw_at_ros=%d raw4_at_ros=%d (expected: untranslated v4 and v6 leak)", d.raw, d.raw4)
	if d.f4 == 0 || d.f6 == 0 {
		diag()
		t.Fatalf("control saw no IPv4 or IPv6 leak via the main-table default; the harness is not exercising the leak path: %+v", d)
	}
	if d.raw4 == 0 || d.raw == d.raw4 {
		diag()
		t.Fatalf("control saw no untranslated device IPv4 or IPv6 at ROS; the harness is not exercising the device leak path: %+v", d)
	}

	// B. First install on a namespace with no Meridian tables.
	//
	// The control phase forwarded the device's flows with connection
	// tracking already active (the devtun counter table) and no NAT rule,
	// so those flows hold untranslated conntrack entries that a later
	// ruleset cannot rewrite. A real gateway never has such flows: mra is
	// created by meridian-up.sh only after the ruleset is loaded. The
	// device's pings are therefore stopped here and started again after the
	// load, as new flows; the LAN client's pings keep running throughout.
	stopDev()
	must(in("gw", "nft", "-c", "-f", nftPath)...)
	must(in("gw", "nft", "-f", nftPath)...)
	must(in("gw", "nft", "list", "table", "inet", "meridian_guard")...)
	must(in("gw", "nft", "list", "table", "inet", "meridian")...)
	addDomestic := func() {
		must(in("gw", "nft", "add", "element", "inet", "meridian", "direct6", "{ 2001:db8:cccc::1 }")...)
		must(in("gw", "nft", "add", "element", "inet", "meridian", "direct4", "{ 198.18.0.2 }")...)
	}
	addDomestic()
	startDev()
	time.Sleep(300 * time.Millisecond)
	s1 := read()
	time.Sleep(time.Second)
	d = delta(s1, read())
	t.Logf("EVIDENCE first-install: foreign4=%d foreign6=%d domestic4=%d domestic6=%d tunnel_tx=%d", d.f4, d.f6, d.d4, d.d6, d.tx)
	if d.f4 != 0 || d.f6 != 0 {
		t.Fatalf("foreign traffic reached ROS after load: %+v", d)
	}
	if d.d4 == 0 || d.d6 == 0 {
		diag()
		t.Fatalf("domestic IPv4 or IPv6 via ROS was blocked: the intended direct path is broken: %+v", d)
	}
	if d.tx == 0 {
		t.Fatal("no traffic entered the tunnel interfaces; classification did not run")
	}
	devOK("first-install", d, true)
	e2e("first-install")

	// C. Reload under continuous traffic.
	const reloads = 200
	s2 := read()
	for i := 0; i < reloads; i++ {
		must(in("gw", "nft", "-f", nftPath)...)
	}
	time.Sleep(200 * time.Millisecond)
	d = delta(s2, read())
	t.Logf("EVIDENCE %d reloads under traffic: foreign4=%d foreign6=%d domestic4=%d tunnel_tx=%d", reloads, d.f4, d.f6, d.d4, d.tx)
	if d.f4 != 0 || d.f6 != 0 {
		t.Fatalf("foreign traffic reached ROS during reload: %+v", d)
	}
	devOK(fmt.Sprintf("%d reloads", reloads), d, true)
	// Every reload recreates inet meridian, which empties the sets the
	// resolver fills at runtime (direct4/direct6 here). Until a name is
	// resolved again its address is classified as foreign and goes into a
	// tunnel: a detour, not a leak, and a documented limitation. The
	// "domestic" test addresses live in those sets, so they are put back
	// before the end-to-end checks, as the resolver would on the next query.
	addDomestic()
	// Classification is per packet, NAT is per connection. The device's
	// long-running pings were classified as foreign while the sets were
	// empty, so their conntrack entries are bound to a transit SNAT; once
	// the addresses are domestic again those same flows leave the LAN NIC
	// with the stale translation and get no reply until the entry expires.
	// That is a known reliability limit of reclassifying a live flow (not a
	// leak: the destination is domestic). New connections are unaffected,
	// so the device's flows are restarted here, as a real client's would be
	// after its connection timed out.
	restartDev := func() {
		stopDev()
		startDev()
		time.Sleep(300 * time.Millisecond)
	}
	restartDev()
	e2e(fmt.Sprintf("after %d reloads", reloads))

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
	restartDev()
	s7 := read()
	time.Sleep(time.Second)
	d = delta(s7, read())
	t.Logf("EVIDENCE after group switch and 20 routes reloads: foreign4=%d foreign6=%d domestic4=%d domestic6=%d tunnel_tx=%d", d.f4, d.f6, d.d4, d.d6, d.tx)
	if d.f4 != 0 || d.f6 != 0 {
		t.Fatalf("foreign traffic reached ROS after a group switch: %+v", d)
	}
	if d.d4 == 0 || d.d6 == 0 || d.tx == 0 {
		diag()
		t.Fatalf("domestic or tunnel path not working after a group switch: %+v", d)
	}
	devOK("after group switch", d, true)
	e2e("after group switch")

	// E. Guard independence: drop the classification table entirely (what
	// the old delete-then-load sequence did between its two processes).
	must(in("gw", "nft", "delete", "table", "inet", "meridian")...)
	s4 := read()
	time.Sleep(time.Second)
	d = delta(s4, read())
	t.Logf("EVIDENCE guard only (inet meridian deleted): foreign4=%d foreign6=%d domestic4=%d domestic6=%d", d.f4, d.f6, d.d4, d.d6)
	if d.f4 != 0 || d.f6 != 0 || d.d4 != 0 || d.d6 != 0 {
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
	t.Logf("EVIDENCE early-boot guard file only: foreign4=%d foreign6=%d domestic4=%d domestic6=%d", d.f4, d.f6, d.d4, d.d6)
	if d.f4 != 0 || d.f6 != 0 || d.d4 != 0 || d.d6 != 0 {
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

// netnsPrereqs skips unless the opt-in runtime netns tests can run here.
func netnsPrereqs(t *testing.T) {
	t.Helper()
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
}

// labV6 is the LAN IPv6 side of a netns lab: the prefix (as in the
// topology's settings) and the gateway's and the LAN client's addresses in
// it, without a length.
type labV6 struct{ prefix, gw, cli string }

// netnsLab is the namespace harness of the netns tests: a bridge ("sw")
// joining the gateway, ROS and a LAN client on the LAN NIC, and a remote
// device behind "mra" (a veth standing in for the WireGuard interface).
// The compiled routes script is installed on the gateway; the nft file is
// written to nftPath but NOT loaded, and no traffic is started.
type netnsLab struct {
	t                              *testing.T
	b                              *Bundle
	lan, dir, nftText              string
	nftPath, routesPath, guardPath string
	ns                             map[string]string
	tunnels                        []string
}

func (l *netnsLab) sh(args ...string) (string, error) {
	out, err := exec.Command(args[0], args[1:]...).CombinedOutput()
	return string(out), err
}

func (l *netnsLab) must(args ...string) string {
	l.t.Helper()
	out, err := l.sh(args...)
	if err != nil {
		l.t.Fatalf("%s: %v\n%s", strings.Join(args, " "), err, out)
	}
	return out
}

func (l *netnsLab) in(n string, args ...string) []string {
	return append([]string{"ip", "netns", "exec", l.ns[n]}, args...)
}

// counter reads a named nft counter of table inet <table> in namespace n.
func (l *netnsLab) counter(n, table, name string) int {
	l.t.Helper()
	out := l.must(l.in(n, "nft", "list", "counter", "inet", table, name)...)
	m := regexp.MustCompile(`packets (\d+)`).FindStringSubmatch(out)
	if m == nil {
		l.t.Fatalf("no counter in %s", out)
	}
	v, _ := strconv.Atoi(m[1])
	return v
}

func newNetnsLab(t *testing.T, topo model.Topology, v6 labV6) *netnsLab {
	t.Helper()
	b, err := Compile(topo)
	if err != nil {
		t.Fatal(err)
	}
	l := &netnsLab{t: t, b: b, lan: topo.Settings.LANInterface, dir: t.TempDir()}
	lan, dir := l.lan, l.dir
	sh, must, in := l.sh, l.must, l.in
	l.nftText = b.File("nodes/gw/etc/nftables.d/meridian.nft")
	l.nftPath = filepath.Join(dir, "meridian.nft")
	l.routesPath = filepath.Join(dir, "meridian-routes.sh")
	mustWrite(t, l.nftPath, l.nftText)
	// State files the routes script writes (the dual-hub upstream record)
	// go to the test directory, never to this host's /run/meridian.
	mustWrite(t, l.routesPath, strings.ReplaceAll(b.File("nodes/gw/usr/local/sbin/meridian-routes.sh"), "/run/meridian", filepath.Join(dir, "gwrun")))
	for path := range b.Files {
		if strings.HasPrefix(path, "nodes/gw/etc/wireguard/") && filepath.Base(path) != "mra.conf" {
			l.tunnels = append(l.tunnels, strings.TrimSuffix(filepath.Base(path), ".conf"))
		}
	}
	tunnels := l.tunnels
	l.guardPath = filepath.Join(dir, "meridian-guard.nft")
	mustWrite(t, l.guardPath, b.File("nodes/gw/etc/nftables.d/meridian-guard.nft"))
	raUpPath := filepath.Join(dir, "ra-up.sh")
	mustWrite(t, raUpPath, "set -euo pipefail\n"+remoteUpCommands(planRemote(topo)))

	sfx := strconv.Itoa(os.Getpid() % 100000)
	l.ns = map[string]string{"sw": "mrdsw" + sfx, "gw": "mrdgw" + sfx, "ros": "mrdros" + sfx, "cli": "mrdcli" + sfx, "dev": "mrddev" + sfx}
	ns := l.ns
	t.Cleanup(func() {
		for _, n := range ns {
			_ = exec.Command("ip", "netns", "del", n).Run()
		}
	})

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
	// Return path to the LAN: v4 is the connected /24; v6 is on-link like the
	// prefix ROS advertises. Nothing for the device pool (checked below).
	must(in("ros", "ip", "-6", "route", "add", v6.prefix, "dev", lan)...)
	// ulaout counts the ULA test destinations outside the LAN prefix that
	// the ULA-LAN test sends (never allowed to arrive here).
	sink := fmt.Sprintf(`table inet sink {
  counter foreign4 {}
  counter foreign6 {}
  counter domestic4 {}
  counter domestic6 {}
  counter devdom4 {}
  counter devdom6 {}
  counter devraw {}
  counter devraw4 {}
  counter ulaout {}
  chain pre {
    type filter hook prerouting priority -300; policy accept;
    ip saddr 10.67.0.0/24 counter name "devraw4"
    ip saddr 10.67.0.0/24 counter name "devraw"
    ip6 saddr fd67::/64 counter name "devraw"
    ip daddr 198.18.0.1 counter name "foreign4"
    ip6 daddr 2001:db8:ffff::1 counter name "foreign6"
    ip saddr 192.168.100.50 ip daddr 198.18.0.2 counter name "domestic4"
    ip6 daddr 2001:db8:cccc::1 counter name "domestic6"
    ip saddr 192.168.100.88 ip daddr 198.18.0.2 counter name "devdom4"
    ip6 saddr %s ip6 daddr 2001:db8:cccc::1 counter name "devdom6"
    ip6 daddr { %s } counter name "ulaout"
  }
}
`, v6.gw, strings.Join(netnsULAOutside, ", "))
	sinkPath := filepath.Join(dir, "sink.nft")
	mustWrite(t, sinkPath, sink)
	must(in("ros", "nft", "-f", sinkPath)...)
	for _, c := range [][]string{{"ip", "-4", "route", "get", "10.67.0.2"}, {"ip", "-6", "route", "get", "fd67::2"}} {
		if out, err := sh(in("ros", c...)...); err == nil && !strings.HasPrefix(out, "unreachable") && !strings.HasPrefix(out, "prohibit") && !strings.HasPrefix(out, "blackhole") {
			t.Fatalf("ROS must have no route to the device pool (the gateway NATs it): %s\n%s", strings.Join(c, " "), out)
		}
	}

	// Client.
	must(in("cli", "ip", "addr", "add", "192.168.100.50/24", "dev", lan)...)
	must(in("cli", "ip", "addr", "add", v6.cli+"/"+prefixLen(t, v6.prefix), "dev", lan, "nodad")...)
	must(in("cli", "ip", "route", "add", "default", "via", "192.168.100.88")...)
	must(in("cli", "ip", "-6", "route", "add", "default", "via", "fe80::88", "dev", lan)...)

	// Gateway: tunnels are dummies, so whatever is routed into them never
	// reaches ROS; their tx counters show the foreign path is in use.
	must(in("gw", "ip", "addr", "add", "192.168.100.88/24", "dev", lan)...)
	must(in("gw", "ip", "addr", "add", "fe80::88/64", "dev", lan, "nodad")...)
	// An address of the LAN prefix for the masquerade of the devices'
	// domestic and LAN IPv6.
	must(in("gw", "ip", "addr", "add", v6.gw+"/"+prefixLen(t, v6.prefix), "dev", lan, "nodad")...)
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
	// The dummies stand in for the gateway's WireGuard interfaces, so they
	// carry the addresses the compiled configs give those interfaces. This
	// matters for more than realism: for a packet arriving on an interface
	// that has no IPv4 address at all, the kernel's source validation skips
	// the loose-mode second lookup and fails with EXDEV whenever rp_filter
	// is on, so the reply-path lookups below would fail on an address-less
	// dummy while passing on a real tunnel.
	addrLine := regexp.MustCompile(`(?m)^Address\s*=\s*(.+)$`)
	for _, tun := range tunnels {
		must(in("gw", "ip", "link", "add", tun, "type", "dummy")...)
		m := addrLine.FindStringSubmatch(b.File("nodes/gw/etc/wireguard/" + tun + ".conf"))
		if m == nil {
			t.Fatalf("compiled %s.conf has no Address line; the dummy cannot mirror it", tun)
		}
		for _, a := range strings.Split(m[1], ",") {
			a = strings.TrimSpace(a)
			if a == "" {
				continue
			}
			args := []string{"ip", "addr", "add", a, "dev", tun}
			if strings.Contains(a, ":") {
				args = append(args, "nodad")
			}
			must(in("gw", args...)...)
		}
		must(in("gw", "ip", "link", "set", tun, "up")...)
	}
	must(in("gw", "ip", "route", "add", "default", "via", "192.168.100.1", "dev", lan)...)
	must(in("gw", "ip", "-6", "route", "add", "default", "via", "fe80::1", "dev", lan)...)
	// The rules older versions installed: the routes script must delete
	// them (an upgrade heals without a reboot).
	must(in("gw", "ip", "-4", "rule", "add", "iif", lan, "unreachable", "priority", "17850")...)
	must(in("gw", "ip", "-4", "rule", "add", "iif", "mra", "unreachable", "priority", "17851")...)
	must(in("gw", "bash", l.routesPath)...)
	if rules := must(in("gw", "ip", "-4", "rule", "show")...); strings.Contains(rules, "iif") {
		t.Fatalf("the routes script left an iif rule in place:\n%s", rules)
	}
	must(in("gw", "sysctl", "-qw", "net.ipv4.ip_forward=1")...)
	must(in("gw", "sysctl", "-qw", "net.ipv6.conf.all.forwarding=1")...)
	time.Sleep(2 * time.Second)
	return l
}

func prefixLen(t *testing.T, prefix string) string {
	t.Helper()
	p, err := netip.ParsePrefix(prefix)
	if err != nil {
		t.Fatal(err)
	}
	return strconv.Itoa(p.Bits())
}

// netnsULAOutside are ULA destinations outside the ULA LAN prefix that
// TestNetnsULALANHomeAccess sends from the device and the LAN client: an
// unrelated ULA, the /64 next to the LAN prefix, the tunnel ULA (a link
// address and the /48) and the transit /64. All must be dropped by the
// gateway's classifier and never reach ROS.
var netnsULAOutside = []string{"fd99::1", "fd12:3456:789a:2::1", "fd66::1", "fd66:0:0:2::9", "fd66:0:0:ff::9"}

// TestNetnsULALANHomeAccess is the runtime regression check for a ULA LAN
// IPv6 prefix (fd12:3456:789a:1::/64, see ulaLANExample): the gateway's
// classifier drops fc00::/7, and the ULA LAN prefix must be let through
// ahead of that drop, exactly. On the same namespaces as
// TestNetnsReloadNoLeak, after one install of the compiled nft file (the
// device sends nothing before it is loaded), it requires ping REPLIES for
// device -> LAN host and LAN host -> device over IPv6 (the first through the
// device-pool masquerade on the LAN NIC and back out of mra), and for each
// ULA destination outside the LAN prefix (netnsULAOutside), sent from the
// device and from the LAN client, that the gateway saw it arrive, never
// forwarded it (a forward-hook counter ahead of the guard stays 0: the
// classifier dropped it) and ROS never saw it.
//
// Root only, Linux only, opt-in (MERIDIAN_NETNS_TEST=1), like
// TestNetnsReloadNoLeak. Not yet executed on a real kernel as of
// 2026-11-13; without an archived passing log this path is not verified.
func TestNetnsULALANHomeAccess(t *testing.T) {
	netnsPrereqs(t)
	topo := ulaLANExample(t)
	lab := newNetnsLab(t, topo, labV6{prefix: ulaLAN, gw: "fd12:3456:789a:1::88", cli: "fd12:3456:789a:1::50"})
	must, in, sh := lab.must, lab.in, lab.sh

	// Arrival (prerouting, before the classifier) and forwarding (forward
	// hook ahead of the guard) of the outside-ULA test destinations on the
	// gateway. A separate table: the Meridian load never replaces it.
	set := strings.Join(netnsULAOutside, ", ")
	probeText := fmt.Sprintf(`table inet ulaprobe {
  counter seen {}
  counter forwarded {}
  chain pre {
    type filter hook prerouting priority -300; policy accept;
    ip6 daddr { %s } counter name "seen"
  }
  chain forwardprobe {
    type filter hook forward priority -400; policy accept;
    ip6 daddr { %s } counter name "forwarded"
  }
}
`, set, set)
	probePath := filepath.Join(lab.dir, "ulaprobe.nft")
	mustWrite(t, probePath, probeText)
	must(in("gw", "nft", "-f", probePath)...)

	// One install, then traffic.
	must(in("gw", "nft", "-c", "-f", lab.nftPath)...)
	must(in("gw", "nft", "-f", lab.nftPath)...)
	classify := must(in("gw", "nft", "list", "chain", "inet", "meridian", "classify")...)
	if !strings.Contains(classify, "ip6 daddr "+ulaLAN+" meta mark set 0x00000064 return") {
		t.Fatalf("the loaded classifier does not mark the ULA LAN prefix:\n%s", classify)
	}
	diag := func() {
		for _, c := range [][]string{
			{"nft", "list", "chain", "inet", "meridian", "classify"},
			{"nft", "list", "table", "inet", "meridian_guard"},
			{"nft", "list", "chain", "inet", "meridian", "transit_snat"},
			{"nft", "list", "table", "inet", "ulaprobe"},
			{"ip", "-6", "rule"}, {"ip", "-6", "route", "show", "table", "100"}, {"ip", "-6", "route", "show", "table", "main"},
			{"ip", "-6", "addr", "show", "dev", lab.lan},
			{"ip", "-6", "route", "get", "fd12:3456:789a:1::50", "from", "fd67::2", "iif", "mra", "mark", "0x64"},
			{"ip", "-6", "route", "get", "fd67::2", "from", "fd12:3456:789a:1::50", "iif", lab.lan, "mark", "0x64"},
		} {
			out, err := sh(in("gw", c...)...)
			t.Logf("DIAG gw$ %s (err=%v)\n%s", strings.Join(c, " "), err, out)
		}
	}

	fails := 0
	for _, p := range []struct{ from, dst, what string }{
		{"dev", "fd12:3456:789a:1::50", "device to a ULA home host (masquerade on the LAN NIC, reply out of mra)"},
		{"cli", "fd67::2", "ULA home host to the device"},
	} {
		out, err := sh(in(p.from, "ping", "-n", "-c", "3", "-i", "0.2", "-W", "2", p.dst)...)
		if err != nil {
			fails++
			t.Errorf("no reply: %s (%s -> %s): %v\n%s", p.what, p.from, p.dst, err, out)
		} else {
			t.Logf("EVIDENCE ula-lan e2e ok: %s (%s -> %s)", p.what, p.from, p.dst)
		}
	}

	seen0, fwd0, ros0 := lab.counter("gw", "ulaprobe", "seen"), lab.counter("gw", "ulaprobe", "forwarded"), lab.counter("ros", "sink", "ulaout")
	for _, from := range []string{"dev", "cli"} {
		for _, dst := range netnsULAOutside {
			// No reply is expected: the exit status is ignored, the counters decide.
			_, _ = sh(in(from, "ping", "-n", "-c", "2", "-i", "0.2", "-W", "1", dst)...)
		}
	}
	seen := lab.counter("gw", "ulaprobe", "seen") - seen0
	fwd := lab.counter("gw", "ulaprobe", "forwarded") - fwd0
	ros := lab.counter("ros", "sink", "ulaout") - ros0
	t.Logf("EVIDENCE ula-lan outside-prefix ULA from device and LAN client: arrived_at_gateway=%d forwarded=%d at_ros=%d (expected: arrived > 0, forwarded 0, at_ros 0)", seen, fwd, ros)
	if want := 2 * 2 * len(netnsULAOutside); seen < want {
		fails++
		t.Errorf("only %d of %d outside-ULA probe packets reached the gateway; the check did not exercise the drop", seen, want)
	}
	if fwd != 0 || ros != 0 {
		fails++
		t.Errorf("a ULA destination outside the LAN prefix was forwarded (%d) or reached ROS (%d)", fwd, ros)
	}
	if fails > 0 {
		diag()
		t.Fatalf("%d ULA-LAN checks failed", fails)
	}
	fmt.Fprintln(os.Stderr, "meridian-netns-ula-lan-test-ok")
}
