//go:build linux

package compile

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/radowitz/meridian/internal/defaults"
	"github.com/radowitz/meridian/internal/mtu"
	"github.com/radowitz/meridian/internal/preflight"
	"github.com/radowitz/meridian/internal/validate"
)

// TestNetnsUplinkMTU: the uplink MTU check against kernel WireGuard
// (docs/verification.md「上联 MTU」). The shape of the real case: an exit
// whose uplink NIC has MTU 1472 dials the hub with the tunnel MTU the panel
// gives a direct link (1420):
//
//	ex ── ua (MTU 1472) ═══ ub (MTU 1500) ── hub
//	      wg4: WireGuard over IPv4 outer, wg6: over IPv6 outer, both 1420
//
// The hub's 1500-byte uplink sends full-size outer packets; ex's NIC drops
// every frame longer than its MTU (veth: no ICMP), exactly as observed.
//
//	P1 the fixed preflight script, run in ex's namespace with the two route
//	   lookups, and the evaluation report both legs too small, on ua, with
//	   the shortfall (8 / 28) and the suggestion (1408 / 1392); the hub's
//	   end of the same legs fits (1500);
//	B  with 1420 a don't-fragment packet of 1408 bytes passes and one of
//	   1412 does not (the measured boundary), and a full 1420 does not;
//	A  with the suggested MTUs applied to both ends a don't-fragment packet
//	   of the full tunnel MTU passes on both legs, and the evaluation of the
//	   same observation now says "fits".
//
// Root only, Linux only, opt-in: MERIDIAN_NETNS_TEST=1 MERIDIAN_NFT_TEST=1.
// Without root, nft, WireGuard in the kernel, wireguard-tools, ping or bash
// it is skipped and NOT RUN (a skip is never a pass).
func TestNetnsUplinkMTU(t *testing.T) {
	mssNetnsPrereqs(t)
	for _, bin := range []string{"ping", "bash", "timeout"} {
		if _, err := exec.LookPath(bin); err != nil {
			t.Skipf("NOT RUN: %s not installed", bin)
		}
	}
	link, ok := linkByID(defaults.Example(), "hkresi-hub")
	if !ok {
		t.Fatal("the example has no hkresi-hub")
	}
	tunMTU, _, _ := validate.LegMTU(link, mtu.ModeUDP)
	if tunMTU != 1420 {
		t.Fatalf("hkresi-hub MTU %d, want the direct-link default 1420", tunMTU)
	}
	const small, big = 1472, 1500
	dir := t.TempDir()
	sfx := strconv.Itoa(os.Getpid() % 100000)
	ns := map[string]string{"ex": "mupex" + sfx, "hub": "muphub" + sfx}
	t.Cleanup(func() {
		for _, n := range ns {
			_ = exec.Command("ip", "netns", "del", n).Run()
		}
	})
	in := func(n string, args ...string) []string {
		return append([]string{"ip", "netns", "exec", ns[n]}, args...)
	}
	run := func(args ...string) (string, error) {
		out, err := exec.Command(args[0], args[1:]...).CombinedOutput()
		return string(out), err
	}
	must := func(args ...string) string {
		t.Helper()
		out, err := run(args...)
		if err != nil {
			t.Fatalf("%s: %v\n%s", strings.Join(args, " "), err, out)
		}
		return out
	}
	for _, n := range []string{"ex", "hub"} {
		must("ip", "netns", "add", ns[n])
		must(in(n, "ip", "link", "set", "lo", "up")...)
	}
	must(in("ex", "ip", "link", "add", "ua", "type", "veth", "peer", "name", "ub", "netns", ns["hub"])...)
	must(in("ex", "ip", "link", "set", "ua", "mtu", strconv.Itoa(small), "up")...)
	must(in("hub", "ip", "link", "set", "ub", "mtu", strconv.Itoa(big), "up")...)
	must(in("ex", "ip", "addr", "add", "192.0.2.1/30", "dev", "ua")...)
	must(in("hub", "ip", "addr", "add", "192.0.2.2/30", "dev", "ub")...)
	must(in("ex", "ip", "-6", "addr", "add", "2001:db8:5::1/64", "dev", "ua", "nodad")...)
	must(in("hub", "ip", "-6", "addr", "add", "2001:db8:5::2/64", "dev", "ub", "nodad")...)

	exPriv, exPub := wgKeyPair(t)
	hubPriv, hubPub := wgKeyPair(t)
	key := func(name, v string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(v+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	exKey, hubKey := key("ex.key", exPriv), key("hub.key", hubPriv)
	type leg struct {
		ifc, exTun, hubTun, endpoint string
		port, family                 int
	}
	legs := []leg{
		{"wg4", "10.77.4.1", "10.77.4.2", "192.0.2.2", 51820, 4},
		{"wg6", "10.77.6.1", "10.77.6.2", "[2001:db8:5::2]", 51821, 6},
	}
	setMTU := func(ifc string, m int) {
		must(in("ex", "ip", "link", "set", ifc, "mtu", strconv.Itoa(m))...)
		must(in("hub", "ip", "link", "set", ifc, "mtu", strconv.Itoa(m))...)
	}
	for _, l := range legs {
		must(in("hub", "ip", "link", "add", l.ifc, "type", "wireguard")...)
		must(in("hub", "wg", "set", l.ifc, "listen-port", strconv.Itoa(l.port), "private-key", hubKey, "peer", exPub, "allowed-ips", l.exTun+"/32")...)
		must(in("hub", "ip", "addr", "add", l.hubTun+"/30", "dev", l.ifc)...)
		must(in("ex", "ip", "link", "add", l.ifc, "type", "wireguard")...)
		must(in("ex", "wg", "set", l.ifc, "private-key", exKey, "peer", hubPub, "allowed-ips", l.hubTun+"/32",
			"endpoint", fmt.Sprintf("%s:%d", l.endpoint, l.port), "persistent-keepalive", "1")...)
		must(in("ex", "ip", "addr", "add", l.exTun+"/30", "dev", l.ifc)...)
		setMTU(l.ifc, tunMTU)
		must(in("hub", "ip", "link", "set", l.ifc, "up")...)
		must(in("ex", "ip", "link", "set", l.ifc, "up")...)
	}
	deadline := time.Now().Add(15 * time.Second)
	for _, l := range legs {
		for {
			out, _ := run(in("ex", "wg", "show", l.ifc, "latest-handshakes")...)
			if f := strings.Fields(out); len(f) >= 2 && f[1] != "0" {
				break
			}
			if time.Now().After(deadline) {
				t.Fatalf("no WireGuard handshake on %s", l.ifc)
			}
			time.Sleep(200 * time.Millisecond)
		}
	}
	t.Logf("EVIDENCE lab: ex uplink ua MTU %d, hub uplink ub MTU %d; wg4 (outer IPv4) and wg6 (outer IPv6) at tunnel MTU %d, handshakes done", small, big, tunMTU)

	exLegs := []mtu.Carrier{
		{LinkID: "lab-v4", Iface: "wg4", Mode: mtu.ModeUDP, Family: 4, Peer: "192.0.2.2", Dials: true, TunnelMTU: tunMTU, Field: "mtu"},
		{LinkID: "lab-v6", Iface: "wg6", Mode: mtu.ModeUDP, Family: 6, Peer: "2001:db8:5::2", Dials: true, TunnelMTU: tunMTU, Field: "mtu"},
	}
	hubLegs := []mtu.Carrier{
		{LinkID: "lab-v4", Iface: "wg4", Mode: mtu.ModeUDP, Family: 4, Peer: "192.0.2.1", TunnelMTU: tunMTU, Field: "mtu"},
		{LinkID: "lab-v6", Iface: "wg6", Mode: mtu.ModeUDP, Family: 6, Peer: "2001:db8:5::1", TunnelMTU: tunMTU, Field: "mtu"},
	}
	// The fixed preflight script, as the panel sends it, with the route
	// lookups the panel derives from the legs.
	evaluate := func(n string, cs []mtu.Carrier) preflight.Evaluation {
		t.Helper()
		var routes []string
		for _, c := range cs {
			routes = append(routes, c.RouteArg())
		}
		if err := preflight.ValidateRoutes(routes); err != nil {
			t.Fatal(err)
		}
		argv := in(n, append([]string{"bash", "-s", "--"}, routes...)...)
		cmd := exec.Command(argv[0], argv[1:]...)
		cmd.Stdin = strings.NewReader(preflight.Script())
		out, err := cmd.Output()
		if err != nil {
			t.Fatalf("preflight script in %s: %v", n, err)
		}
		rep := preflight.Parse(string(out))
		if !rep.Complete {
			t.Fatalf("preflight report from %s incomplete: %v", n, rep.Notes)
		}
		return preflight.Evaluate(rep, preflight.Footprint{}, preflight.Context{NodeID: n, Deployment: "dep-lab", Uplinks: cs})
	}
	fact := func(ev preflight.Evaluation, ifc string) preflight.UplinkFact {
		t.Helper()
		for _, f := range ev.Uplinks {
			if f.Iface == ifc {
				return f
			}
		}
		t.Fatalf("no uplink fact for %s: %+v", ifc, ev.Uplinks)
		return preflight.UplinkFact{}
	}

	// P1: collection + evaluation.
	ev := evaluate("ex", exLegs)
	suggested := map[string]int{}
	for _, want := range []struct {
		ifc                 string
		fam, short, suggest int
	}{{"wg4", 4, 8, 1408}, {"wg6", 6, 28, 1392}} {
		f := fact(ev, want.ifc)
		t.Logf("EVIDENCE P1 ex %s: status %s via %s (uplink MTU %d), shortfall %d, largest inner %d, suggested %d; %s", want.ifc, f.Status, f.Dev, f.UplinkMTU, f.Shortfall, f.MaxInner, f.Suggested, f.Reason)
		if f.Status != preflight.UplinkTooSmall || f.Dev != "ua" || f.UplinkMTU != small || f.Shortfall != want.short || f.Suggested != want.suggest ||
			f.Suggested != mtu.SuggestUDP(small, want.fam) {
			t.Fatalf("P1 %s: %+v", want.ifc, f)
		}
		suggested[want.ifc] = f.Suggested
	}
	blocking := 0
	for _, f := range ev.Findings {
		if f.Code == preflight.CodeUplinkMTUTooSmall {
			if f.Severity != preflight.Blocking || f.Fix == nil || f.Fix.Field != "mtu" {
				t.Fatalf("P1 finding %+v", f)
			}
			blocking++
		}
	}
	if blocking != 2 {
		t.Fatalf("P1: %d uplink findings, want 2: %+v", blocking, ev.Findings)
	}
	hev := evaluate("hub", hubLegs)
	for _, ifc := range []string{"wg4", "wg6"} {
		if f := fact(hev, ifc); f.Status != preflight.UplinkFits || f.Dev != "ub" || f.UplinkMTU != big {
			t.Fatalf("P1 hub %s: %+v", ifc, f)
		}
	}
	t.Logf("EVIDENCE P1 hub end: both legs fit its %d-byte uplink", big)

	ping := func(dst string, size int) bool {
		// size is the whole inner IPv4 packet: ICMP payload + 8 + 20.
		_, err := run(in("hub", "ping", "-n", "-c", "2", "-W", "1", "-M", "do", "-s", strconv.Itoa(size-28), dst)...)
		return err == nil
	}
	// B: the measured boundary with the configured 1420.
	if !ping("10.77.4.1", 1408) {
		t.Fatal("B: 1408 did not pass with tunnel MTU 1420 (the lab does not reproduce the case)")
	}
	if ping("10.77.4.1", 1412) || ping("10.77.4.1", tunMTU) {
		t.Fatal("B: 1412 / 1420 passed an uplink of 1472 over IPv4: the lab does not reproduce the drop")
	}
	if ping("10.77.6.1", tunMTU) {
		t.Fatal("B: 1420 passed an uplink of 1472 over IPv6")
	}
	t.Logf("EVIDENCE B tunnel MTU %d: don't-fragment 1408 passes, 1412 and %d do not (IPv4 outer); %d does not (IPv6 outer)", tunMTU, tunMTU, tunMTU)

	// A: the suggested MTUs on both ends.
	for _, l := range legs {
		setMTU(l.ifc, suggested[l.ifc])
	}
	for _, l := range legs {
		if !ping(l.exTun, suggested[l.ifc]) {
			t.Fatalf("A: a don't-fragment packet of the full tunnel MTU %d did not pass %s", suggested[l.ifc], l.ifc)
		}
	}
	t.Logf("EVIDENCE A suggested MTUs applied (wg4 %d, wg6 %d): don't-fragment packets of the full tunnel MTU pass both legs", suggested["wg4"], suggested["wg6"])
	for i := range exLegs {
		exLegs[i].TunnelMTU = suggested[exLegs[i].Iface]
	}
	ev = evaluate("ex", exLegs)
	for _, ifc := range []string{"wg4", "wg6"} {
		if f := fact(ev, ifc); f.Status != preflight.UplinkFits || f.MaxInner != suggested[ifc] {
			t.Fatalf("A: evaluation after the change %s: %+v", ifc, f)
		}
	}
	for _, f := range ev.Findings {
		if f.Code == preflight.CodeUplinkMTUTooSmall {
			t.Fatalf("A: still too small: %+v", f)
		}
	}
	fmt.Fprintln(os.Stderr, "meridian-netns-uplink-mtu-test-ok")
}
