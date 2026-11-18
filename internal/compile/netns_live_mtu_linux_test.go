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
	"github.com/radowitz/meridian/internal/mtu"
	"github.com/radowitz/meridian/internal/preflight"
	"github.com/radowitz/meridian/internal/sshexec"
)

// TestNetnsLiveMTU: an adopted tunnel MTU takes effect on a running tunnel
// (render_node.go wgActivateCommands; docs/verification.md「采用的隧道 MTU
// 在运行中的接口上生效」), and what holds while only one end of the link
// has been installed.
//
// The mssLab's kernel WireGuard pair (gateway m02 ↔ the relay's end in
// "far", compiled configuration, test keys) runs over an underlay that
// silently drops IPv4 outer packets longer than L (l.limit, 1446 for the
// example's 1412: like a real uplink whose MTU minus 60 is not a multiple
// of 16, e.g. 1472 → 1412). The tunnel's MTU does not fit L. The topology
// then adopts the suggestion for L (mtu.SuggestUDP: a multiple of 16) on
// that link (Link.MTU, what POST /api/mtu/adopt writes); the test compiles
// it, installs the new m02.conf into a temp directory (never /etc) and runs
// the generated WireGuard step of meridian-up.sh on the gateway's existing
// interface. far keeps the old MTU throughout V and R (the other end not
// yet installed).
//
//	V0 before: a new connection moving 64 KiB each way fails on the
//	   underlay (oversize outer packets dropped); the running MTU is the
//	   old one; the generated verify script's tunnel_mtu check FAILs and
//	   the node read-back (the fixed node-state command's linkmtu lines,
//	   preflight.TunnelMTUDrift) reports the drift;
//	A  the activation step: wg syncconf, then "ip link set … mtu" in place;
//	   it prints the change;
//	V1 after, far still at the old MTU: the running MTU is the configured
//	   one; the interface is the same (ifindex unchanged), the peer's
//	   latest handshake is not reset, a long-lived TCP connection opened
//	   before the change completes; a new connection moves 64 KiB each way
//	   with nothing dropped (far pads a full segment of the new MSS to the
//	   new MTU itself: a multiple of 16 is not padded further); tunnel_mtu
//	   PASSes, the read-back has no drift, a second run changes nothing;
//	R  whether the lowered end accepts a packet larger than its own MTU
//	   from the end that was not installed yet: one DF ping of the old MTU
//	   with the underlay limit lifted, counted at every stage; asserted is
//	   only that the lab delivered it to the gateway, the outcome is
//	   recorded (EVIDENCE R receive-larger: ACCEPTED / NOT DELIVERED);
//	P  the pitfall of a manual MTU that is not a multiple of 16: the
//	   gateway alone at L−60 (which its own packets fit exactly) — its
//	   uploads pass, but far pads the gateway-sized segments to the next
//	   multiple of 16 and its downloads are dropped on the underlay, until
//	   far is lowered to the same value too.
//
// Root only, Linux only, opt-in: MERIDIAN_NETNS_TEST=1 MERIDIAN_NFT_TEST=1
// (the shared lab's prerequisites), plus wg-quick for "wg-quick strip" and
// ping. Everything runs in its own namespaces and a temp directory.
func TestNetnsLiveMTU(t *testing.T) {
	mssNetnsPrereqs(t)
	for _, bin := range []string{"wg-quick", "ping"} {
		if _, err := exec.LookPath(bin); err != nil {
			t.Skipf("NOT RUN: %s not installed", bin)
		}
	}
	l := newMSSLab(t)
	l.handshake()

	// The link of m02 and the values the test relies on.
	tunnels := mustTunnels(t, l.topo)
	var link string
	var oldMTU int
	for _, tun := range tunnels {
		if tun.Iface() == l.ifc && tun.Mode != "wss" && (tun.West.Role == model.RoleGateway || tun.East.Role == model.RoleGateway) {
			link, oldMTU = tun.LinkID, tun.MTU
		}
	}
	if link == "" {
		t.Fatalf("no gateway tunnel %s", l.ifc)
	}
	newMTU := mtu.SuggestUDP(l.limit, 4)
	manual := l.limit - mtu.UDPOverhead(4)
	switch {
	case mtu.FitsUDP(oldMTU, l.limit, 4):
		t.Fatalf("lab: the old MTU %d fits the underlay %d; nothing to fix", oldMTU, l.limit)
	case newMTU%16 != 0 || newMTU >= oldMTU || !mtu.FitsUDP(newMTU, l.limit, 4):
		t.Fatalf("lab: suggestion %d for underlay %d", newMTU, l.limit)
	case mtu.UDPOuterLen(newMTU, oldMTU, 4) > l.limit:
		t.Fatalf("lab: far (MTU %d) would pad a %d-byte packet to %d outer bytes, over %d", oldMTU, newMTU, mtu.UDPOuterLen(newMTU, oldMTU, 4), l.limit)
	case manual%16 == 0 || !mtu.FitsUDP(manual, l.limit, 4) || mtu.UDPOuterLen(manual, oldMTU, 4) <= l.limit || mtu.UDPOuterLen(manual, manual, 4) > l.limit:
		t.Fatalf("lab: the manual value %d does not show the padding pitfall on underlay %d", manual, l.limit)
	}
	t.Logf("EVIDENCE lab: underlay drops outer > %d; old MTU %d (full outer %d), suggestion %d (outer %d, far at %d pads it to outer %d), manual %d (own outer %d, far at %d pads it to outer %d)",
		l.limit, oldMTU, mtu.UDPOuterLen(oldMTU, oldMTU, 4), newMTU, mtu.UDPOuterLen(newMTU, newMTU, 4), oldMTU, mtu.UDPOuterLen(newMTU, oldMTU, 4),
		manual, mtu.UDPOuterLen(manual, manual, 4), oldMTU, mtu.UDPOuterLen(manual, oldMTU, 4))

	etc := filepath.Join(l.dir, "etc-wireguard")
	if err := os.MkdirAll(etc, 0o700); err != nil {
		t.Fatal(err)
	}
	// adopt compiles the topology with m02's link at value, installs its
	// m02.conf (test keys) into etc and returns the bundle and the
	// generated WireGuard step pointed at etc.
	adopt := func(value int) (*Bundle, string) {
		t.Helper()
		next := l.topo
		next.Links = append([]model.Link(nil), l.topo.Links...)
		setLink(t, &next, link, func(lk *model.Link) { lk.MTU = value })
		nb := mustCompile(t, next)
		conf := nb.File("nodes/gw/etc/wireguard/" + l.ifc + ".conf")
		if !strings.Contains(conf, fmt.Sprintf("MTU = %d\n", value)) {
			t.Fatalf("the adopted config has no MTU = %d:\n%s", value, conf)
		}
		up := nb.File("nodes/gw/usr/local/sbin/meridian-up.sh")
		step := wgActivateCommands([]string{l.ifc}, tunnelMTUs(tunnelsFor(mustTunnels(t, next), "gw")))
		for _, want := range []string{fmt.Sprintf("    %s) echo %d ;;\n", l.ifc, value), `      ip link set dev "$iface" mtu "$want_mtu"` + "\n", `    wg syncconf "$iface" <(wg-quick strip "$conf")` + "\n"} {
			if !strings.Contains(up, want) || !strings.Contains(step, want) {
				t.Fatalf("the generated meridian-up.sh and the step under test differ on %q", want)
			}
		}
		var cl []string
		for _, line := range strings.Split(conf, "\n") {
			switch {
			case strings.HasPrefix(line, "PrivateKey ="):
				line = "PrivateKey = " + l.gwPriv
			case strings.HasPrefix(line, "PublicKey ="):
				line = "PublicKey = " + l.farPub
			}
			cl = append(cl, line)
		}
		if err := os.WriteFile(filepath.Join(etc, l.ifc+".conf"), []byte(strings.Join(cl, "\n")), 0o600); err != nil {
			t.Fatal(err)
		}
		return nb, "set -euo pipefail\n" + strings.ReplaceAll(step, "/etc/wireguard/", etc+"/")
	}
	nb, step := adopt(newMTU)

	// The verify script's tunnel_mtu block, with its own run/out_of, for
	// this lab's one interface.
	verify := nb.File("nodes/gw/usr/local/sbin/meridian-verify.sh")
	bs, be := strings.Index(verify, "# --- tunnel interface MTU"), strings.Index(verify, "# --- not executable from this script")
	rs := regexp.MustCompile(`(?s)\nrun\(\) \{\n.*?\n\}\n`).FindString(verify)
	ofs := regexp.MustCompile(`(?m)^out_of\(\) .*$`).FindString(verify)
	if bs < 0 || be < bs || rs == "" || ofs == "" {
		t.Fatal("the verify script has no tunnel_mtu block or no run/out_of")
	}
	if !strings.Contains(verify, fmt.Sprintf("%s:%d", l.ifc, newMTU)) {
		t.Fatalf("the verify script does not expect %s:%d", l.ifc, newMTU)
	}
	evdir := filepath.Join(l.dir, "evidence")
	if err := os.MkdirAll(evdir, 0o755); err != nil {
		t.Fatal(err)
	}
	check := fmt.Sprintf("set -u\nevdir=%s\nfails=0\npass() { echo \"PASS $1: $2\"; }\nfail() { echo \"FAIL $1: $2\"; fails=$((fails + 1)); }\nunknown() { echo \"UNKNOWN $1: $2\"; }\n%s\n%s\ntun_mtus='%s:%d'\n%s\nexit $fails\n",
		shQuote(evdir), ofs, rs, l.ifc, newMTU, verify[bs:be])
	verifyRun := func() string {
		out, _ := l.sh(l.in("gw", "bash", "-c", check)...)
		return strings.TrimSpace(out)
	}
	// The node read-back: the fixed node-state command's linkmtu pipeline.
	ps := strings.Index(sshexec.NodeStateCommand, "ip -o link show")
	pe := strings.Index(sshexec.NodeStateCommand, "sed 's/^/linkmtu /'")
	if ps < 0 || pe < ps {
		t.Fatal("the node-state command has no linkmtu pipeline")
	}
	readBack := func() []string {
		out := l.must(l.in("gw", "bash", "-c", "printf 'meridian-node-state 1\\n'; "+sshexec.NodeStateCommand[ps:pe+len("sed 's/^/linkmtu /'")]+"; echo meridian-node-state-end")...)
		st := preflight.ParseNodeState(out)
		drift, read := preflight.TunnelMTUDrift([]preflight.IfacePlan{{Name: l.ifc, MTU: newMTU}}, st.LinkMTU)
		if !read {
			t.Fatalf("the read-back read no link MTU: %q", out)
		}
		return drift
	}
	linkInfo := func(ns string) (idx string, m int) {
		out := l.must(l.in(ns, "ip", "-o", "link", "show", "dev", l.ifc)...)
		mm := regexp.MustCompile(`^(\d+): .* mtu (\d+) `).FindStringSubmatch(out)
		if mm == nil {
			t.Fatalf("ip link: %q", out)
		}
		m, _ = strconv.Atoi(mm[2])
		return mm[1], m
	}
	handshake := func() int64 {
		out := l.must(l.in("gw", "wg", "show", l.ifc, "latest-handshakes")...)
		f := strings.Fields(out)
		if len(f) < 2 {
			t.Fatalf("latest-handshakes: %q", out)
		}
		v, _ := strconv.ParseInt(f[1], 10, 64)
		return v
	}
	big := 64 << 10
	dst := fmt.Sprintf("%s:7100", l.farTun4)
	// transfer: a new connection gw → far; ok and the oversize drops it
	// caused (failed connections are aborted with a reset, so nothing of
	// theirs is retransmitted later).
	transfer := func(up, down int) (string, int) {
		o0 := l.oversize()
		got := l.client("gw", dst, "", 0, up, down)
		return got, l.oversize() - o0
	}
	far := l.helper("far", "server", "[::]:7100")
	waitLine(t, far, "READY", 5*time.Second)

	// V0.
	idx0, m0 := linkInfo("gw")
	if m0 != oldMTU {
		t.Fatalf("lab: %s runs at %d, want %d", l.ifc, m0, oldMTU)
	}
	if got, d := transfer(big, big); strings.HasPrefix(got, "OK ") || d == 0 {
		t.Fatalf("V0 at MTU %d a 64 KiB connection did not fail on the underlay: %s (%d dropped)", oldMTU, got, d)
	} else {
		t.Logf("EVIDENCE V0 at MTU %d both ends: 64 KiB each way failed (%s), %d oversize outer packets dropped", oldMTU, got, d)
	}
	if out := verifyRun(); !strings.Contains(out, "FAIL tunnel_mtu:") || strings.Contains(out, "PASS tunnel_mtu") {
		t.Fatalf("V0 the verify check did not fail on a running MTU %d against config %d:\n%s", m0, newMTU, out)
	} else {
		t.Logf("EVIDENCE V0 running %d, config %d: %s", m0, newMTU, out)
	}
	if d := readBack(); len(d) != 1 {
		t.Fatalf("V0 the read-back saw no drift: %v", d)
	} else {
		t.Logf("EVIDENCE V0 node read-back drift: %v", d)
	}
	hs0 := handshake()
	release := filepath.Join(l.dir, "release")
	hold := l.helper("gw", "hold", dst, release)
	t.Logf("EVIDENCE long-lived connection before the change: %s", waitLine(t, hold, "HOLDING", 6*time.Second))

	// A: the generated step on the existing interface.
	out, err := l.sh(l.in("gw", "bash", "-c", step)...)
	if err != nil {
		t.Fatalf("A the activation step failed: %v\n%s", err, out)
	}
	if !strings.Contains(out, fmt.Sprintf("meridian-wg-mtu: %s %d -> %d", l.ifc, oldMTU, newMTU)) {
		t.Fatalf("A the activation step did not report the change:\n%s", out)
	}
	t.Logf("EVIDENCE A activation step output: %s", strings.TrimSpace(out))

	// V1: the gateway at the suggestion, far still at the old MTU.
	idx1, m1 := linkInfo("gw")
	if m1 != newMTU || idx1 != idx0 {
		t.Fatalf("V1 %s: ifindex %s → %s, MTU %d (want the same interface at %d)", l.ifc, idx0, idx1, m1, newMTU)
	}
	if _, fm := linkInfo("far"); fm != oldMTU {
		t.Fatalf("V1 lab: far runs at %d, want the old %d", fm, oldMTU)
	}
	if err := os.WriteFile(release, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	held := waitLine(t, hold, "OK", 9*time.Second)
	hs1 := handshake()
	if hs1 == 0 || hs1 < hs0 {
		t.Fatalf("V1 latest handshake %d → %d: the session was reset", hs0, hs1)
	}
	t.Logf("EVIDENCE V1 %s same ifindex %s, MTU %d → %d; latest handshake %d → %d (not reset); long-lived connection: %s", l.ifc, idx0, m0, m1, hs0, hs1, held)
	if got, d := transfer(big, big); !strings.HasPrefix(got, "OK ") || d != 0 {
		l.diag()
		t.Fatalf("V1 gateway at %d, far at %d: a 64 KiB connection each way: %s (%d dropped)", newMTU, oldMTU, got, d)
	} else {
		t.Logf("EVIDENCE V1 gateway at the suggestion %d, far still at %d: 64 KiB each way OK (%s), nothing dropped", newMTU, oldMTU, got)
	}
	if out := verifyRun(); !strings.Contains(out, "PASS tunnel_mtu:") || strings.Contains(out, "FAIL") {
		t.Fatalf("V1 the verify check did not pass:\n%s", out)
	} else {
		t.Logf("EVIDENCE V1 %s", out)
	}
	if d := readBack(); len(d) != 0 {
		t.Fatalf("V1 the read-back still sees a drift: %v", d)
	}
	if out, err := l.sh(l.in("gw", "bash", "-c", step)...); err != nil || strings.Contains(out, "meridian-wg-mtu:") {
		t.Fatalf("V1 a second run of the step was not a no-op: %v\n%s", err, out)
	}

	// R: far (old MTU) sends the lowered gateway a packet larger than the
	// gateway's MTU (one DF ping of the old MTU), with the underlay limit
	// lifted for it. Each stage is counted separately, so the evidence
	// says where it stops: far's m02 egress (request sent), the underlay
	// (outer passed), the gateway's u0 ingress (outer arrived), the
	// gateway's m02 ingress (inner delivered by WireGuard), the gateway's
	// m02 egress (echo reply sent), the ping's own result, and m02's
	// receive error counters. The test asserts only that the lab delivered
	// the outer packet to the gateway; whether the lowered end accepts the
	// inner packet is recorded, not assumed: the rollout guidance
	// (docs/architecture.md「下发顺序」) holds either way.
	counter := func(ns, family, table, name string) int {
		out := l.must(l.in(ns, "nft", "list", "counter", family, table, name)...)
		m := regexp.MustCompile(`packets (\d+)`).FindStringSubmatch(out)
		if m == nil {
			t.Fatalf("counter %s %s %s unreadable: %s", ns, table, name, out)
		}
		v, _ := strconv.Atoi(m[1])
		return v
	}
	setLimit := func(n int, count bool) {
		l.must(l.in("rt", "nft", "flush", "chain", "ip", "mlab", "lab_forward")...)
		if count {
			l.must(l.in("rt", "nft", "add", "rule", "ip", "mlab", "lab_forward", "ip", "length", ">", strconv.Itoa(l.limit), "ip", "length", "<=", strconv.Itoa(n), "counter", "name", "rpass", "accept")...)
		}
		l.must(l.in("rt", "nft", "add", "rule", "ip", "mlab", "lab_forward", "ip", "length", ">", strconv.Itoa(n), "counter", "name", "oversize", "drop")...)
	}
	l.must(l.in("rt", "nft", "add", "counter", "ip", "mlab", "rpass")...)
	l.must(l.in("far", "nft", "-f", l.write("tx.nft", fmt.Sprintf("table inet mlabtx {\n  counter req {\n  }\n  chain lab_tx {\n    type filter hook output priority 0; policy accept;\n    oifname %q icmp type echo-request meta length > %d counter name \"req\"\n  }\n}\n", l.ifc, newMTU)))...)
	l.must(l.in("gw", "nft", "-f", l.write("rx.nft", fmt.Sprintf("table inet mlabrx {\n  counter outer {\n  }\n  counter big {\n  }\n  counter reply {\n  }\n  chain lab_rx {\n    type filter hook prerouting priority -300; policy accept;\n    iifname \"u0\" meta l4proto udp meta length > %d counter name \"outer\"\n    iifname %q meta length > %d counter name \"big\"\n  }\n  chain lab_txr {\n    type filter hook output priority -300; policy accept;\n    oifname %q icmp type echo-reply counter name \"reply\"\n  }\n}\n", l.limit, l.ifc, newMTU, l.ifc)))...)
	route, _ := l.sh(l.in("far", "ip", "route", "get", l.gwTun4)...)
	stats0, _ := l.sh(l.in("gw", "ip", "-s", "-s", "link", "show", "dev", l.ifc)...)
	setLimit(1500, true)
	ping, perr := l.sh(l.in("far", "ping", "-c", "1", "-W", "3", "-M", "do", "-s", strconv.Itoa(oldMTU-28), l.gwTun4)...)
	setLimit(l.limit, false)
	stats1, _ := l.sh(l.in("gw", "ip", "-s", "-s", "link", "show", "dev", l.ifc)...)
	req, pass, outer := counter("far", "inet", "mlabtx", "req"), counter("rt", "ip", "mlab", "rpass"), counter("gw", "inet", "mlabrx", "outer")
	inner, reply := counter("gw", "inet", "mlabrx", "big"), counter("gw", "inet", "mlabrx", "reply")
	t.Logf("EVIDENCE R stages for one %d-byte DF ping from far (MTU %d) to the gateway (MTU %d): far m02 egress %d, underlay passed %d, gateway u0 ingress (outer > %d) %d, gateway m02 ingress (inner > %d) %d, gateway echo replies on m02 %d; ping %v:\n%s\nfar route: %s\ngateway m02 before:\n%s\nafter:\n%s",
		oldMTU, oldMTU, newMTU, req, pass, l.limit, outer, newMTU, inner, reply, perr, strings.TrimSpace(ping), strings.TrimSpace(route), strings.TrimSpace(stats0), strings.TrimSpace(stats1))
	switch {
	case req == 0:
		t.Fatalf("R lab: far did not send the %d-byte request on %s (ping: %v %s; route %s)", oldMTU, l.ifc, perr, ping, route)
	case pass == 0 || outer == 0:
		t.Fatalf("R lab: the outer packet did not reach the gateway (underlay passed %d, u0 ingress %d)", pass, outer)
	case inner > 0:
		t.Logf("EVIDENCE R receive-larger: ACCEPTED — the gateway at MTU %d took far's %d-byte inner packet from WireGuard (replies sent %d, ping %v)", newMTU, oldMTU, reply, perr)
	default:
		t.Logf("EVIDENCE R receive-larger: NOT DELIVERED — the outer packet reached the gateway, but no inner packet longer than its MTU %d came out of %s (see the m02 receive counters above)", newMTU, l.ifc)
	}

	// P: a manual MTU that is not a multiple of 16, on the gateway only.
	_, pstep := adopt(manual)
	if out, err := l.sh(l.in("gw", "bash", "-c", pstep)...); err != nil || !strings.Contains(out, fmt.Sprintf("meridian-wg-mtu: %s %d -> %d", l.ifc, newMTU, manual)) {
		t.Fatalf("P the activation step to %d: %v\n%s", manual, err, out)
	}
	if got, d := transfer(big, 1000); !strings.HasPrefix(got, "OK ") || d != 0 {
		t.Fatalf("P1 gateway at %d: its own 64 KiB upload: %s (%d dropped)", manual, got, d)
	}
	if got, d := transfer(1000, big); strings.HasPrefix(got, "OK ") || d == 0 {
		t.Fatalf("P2 gateway at %d, far at %d: the 64 KiB download did not fail on far's padding: %s (%d dropped)", manual, oldMTU, got, d)
	} else {
		t.Logf("EVIDENCE P2 gateway alone at the manual %d: its uploads pass, far (MTU %d) pads %d-byte packets to %d outer bytes and the download fails (%s), %d dropped", manual, oldMTU, manual, mtu.UDPOuterLen(manual, oldMTU, 4), got, d)
	}
	l.must(l.in("far", "ip", "link", "set", "dev", l.ifc, "mtu", strconv.Itoa(manual))...)
	if got, d := transfer(1000, big); !strings.HasPrefix(got, "OK ") || d != 0 {
		t.Fatalf("P3 both ends at %d: the download: %s (%d dropped)", manual, got, d)
	} else {
		t.Logf("EVIDENCE P3 both ends at %d: the download passes (%s)", manual, got)
	}
	fmt.Fprintln(os.Stderr, "meridian-netns-live-mtu-test-ok")
}
