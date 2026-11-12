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
//   - deletes table inet meridian outright and checks the guard alone
//     drops everything forwarded from the LAN.
//
// ROS counts packets for a "foreign" v4/v6 destination (must stay 0 once
// the firewall is loaded) and a "domestic" v6 destination added to direct6
// (must arrive, proving the guard keeps the intended direct path).
//
// Root only, Linux only, and opt-in: MERIDIAN_NETNS_TEST=1. It creates and
// removes its own namespaces and touches nothing in the host namespace.
// A passing log from 2026-11-12 is archived under
// docs/evidence/2026-11-12-debian13/; rerun and re-archive after changing
// the nft or routes rendering. Without a current log the reload is NOT
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

	topo := defaults.Example()
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
		if strings.HasPrefix(path, "nodes/gw/etc/wireguard/") {
			tunnels = append(tunnels, strings.TrimSuffix(filepath.Base(path), ".conf"))
		}
	}

	sfx := strconv.Itoa(os.Getpid() % 100000)
	ns := map[string]string{"sw": "mrdsw" + sfx, "gw": "mrdgw" + sfx, "ros": "mrdros" + sfx, "cli": "mrdcli" + sfx}
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

	for _, n := range []string{"sw", "gw", "ros", "cli"} {
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
	for _, a := range []string{"2001:db8:ffff::1/128", "2001:db8:cccc::1/128"} {
		must(in("ros", "ip", "addr", "add", a, "dev", "inet0", "nodad")...)
	}
	sink := `table inet sink {
  counter foreign4 {}
  counter foreign6 {}
  counter domestic6 {}
  chain pre {
    type filter hook prerouting priority -300; policy accept;
    ip daddr 198.18.0.1 counter name "foreign4"
    ip6 daddr 2001:db8:ffff::1 counter name "foreign6"
    ip6 daddr 2001:db8:cccc::1 counter name "domestic6"
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
	type snap struct{ f4, f6, d6, tx int }
	read := func() snap { return snap{counter("foreign4"), counter("foreign6"), counter("domestic6"), tunnelTx()} }
	delta := func(a, b snap) snap { return snap{b.f4 - a.f4, b.f6 - a.f6, b.d6 - a.d6, b.tx - a.tx} }

	for _, dst := range []string{"198.18.0.1", "2001:db8:ffff::1", "2001:db8:cccc::1"} {
		cmd := exec.Command("ip", "netns", "exec", ns["cli"], "ping", "-n", "-q", "-i", "0.01", dst)
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = cmd.Process.Kill(); _, _ = cmd.Process.Wait() })
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

	// B. First install on a namespace with no Meridian tables.
	must(in("gw", "nft", "-c", "-f", nftPath)...)
	must(in("gw", "nft", "-f", nftPath)...)
	must(in("gw", "nft", "list", "table", "inet", "meridian_guard")...)
	must(in("gw", "nft", "list", "table", "inet", "meridian")...)
	addDomestic := func() {
		must(in("gw", "nft", "add", "element", "inet", "meridian", "direct6", "{ 2001:db8:cccc::1 }")...)
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
	fmt.Fprintln(os.Stderr, "meridian-netns-reload-test-ok")
}

func mustWrite(t *testing.T, path, body string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}
