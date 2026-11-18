//go:build linux

package compile

import (
	"bufio"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/radowitz/meridian/internal/defaults"
	"github.com/radowitz/meridian/internal/model"
	"github.com/radowitz/meridian/internal/mtu"
	"github.com/radowitz/meridian/internal/validate"
)

// The MSS clamp of locally originated TCP through a tunnel whose real path
// MTU is smaller than its interface MTU (render_nft.go writeLocalMSS and
// writeNodeMSS; docs/verification.md「本机发起连接的 MSS 钳制」).
//
// On a real gateway the panel's unlock probe (host agent, root, SO_MARK and
// the exit's transit source) timed out in the TLS handshake on two exits:
// its SYN never passes the forward hook, so it advertised the tunnel
// interface's MSS (MTU 1412 → 1372), the peer's 1412-byte packets did not
// fit the path (real MTU 1408) and were dropped without any ICMP. Here the
// same shape, with kernel WireGuard between namespaces:
//
//	cli ── (LAN NIC, compiled name) ── gw ── u0/u1 ── rt ── u2/u3 ── far
//	                                   gw: m02 (WireGuard, compiled config:
//	                                       MTU, FwMark, Endpoint; test keys)
//	                                   rt: forwards the underlay and drops
//	                                       every outer packet longer than the
//	                                       clamped size allows, silently (no
//	                                       ICMP: a blackhole)
//	                                   far: the tunnel's peer (the relay access
//	                                       of the example), the test servers
//
// The gateway runs the compiled ruleset of the example; its policy routing
// is reduced to what these connections need (every exit and group mark →
// table 102 → m02, the transit addresses on lo).
//
// Root only, Linux only, opt-in: MERIDIAN_NETNS_TEST=1 MERIDIAN_NFT_TEST=1.
// Without root, nft, WireGuard in the kernel or wireguard-tools the tests
// are skipped and NOT RUN (a skip is never a pass).

// TestNetnsLocalMSSGateway:
//
//	L0 the generated ruleset with chains local_mss and local_mss_in
//	   flushed: a marked local connection (mark and transit source of the
//	   default group, like the probe) moving 64 KiB each way fails within
//	   the bounded timeout, IPv4 and IPv6, and the blackhole counts the
//	   dropped outer packets;
//	L1 the generated ruleset: the same connections succeed; far sees the
//	   SYN's MSS at most the forward clamp, and the gateway's own send MSS
//	   (from the clamped SYN-ACK) is at most the clamp too; nothing is
//	   dropped by the blackhole;
//	U  unmarked local connections keep their MSS: to a LAN host (like the
//	   panel or SSH) and through the tunnel to the peer's tunnel address;
//	W  a TCP connection carrying WireGuard's own fwmark over the underlay
//	   (the shape of wstunnel's carrier) keeps its MSS; WireGuard's outer
//	   UDP is never dropped while the clamped connections run;
//	F  forwarded LAN traffic is still clamped by chain mss and works.
func TestNetnsLocalMSSGateway(t *testing.T) {
	l := newMSSLab(t)
	l.loadGateway()
	l.handshake()
	far := l.helper("far", "server", "[::]:7000")
	cli := l.helper("cli", "server", "[::]:7000")
	waitLine(t, far, "READY", 5*time.Second)
	waitLine(t, cli, "READY", 5*time.Second)
	big := 64 << 10

	type marked struct {
		fam, dst, src string
		clamp         int
	}
	cases := []marked{
		{"IPv4", "203.0.113.110:7000", l.transit4, l.mss4},
		{"IPv6", "[2001:db8:f::10]:7000", "[" + l.transit6 + "]:0", l.mss6},
	}
	// L0: the clamp rules removed from the loaded ruleset.
	for _, c := range []string{"local_mss", "local_mss_in"} {
		l.must(l.in("gw", "nft", "flush", "chain", "inet", "meridian", c)...)
	}
	for _, c := range cases {
		d0 := l.oversize()
		start := time.Now()
		got := l.client("gw", c.dst, srcAddr(c.src), l.mark, big, big)
		if strings.HasPrefix(got, "OK ") {
			t.Fatalf("L0 %s: without the local clamp a marked local connection moved %d bytes each way through the blackhole: %s", c.fam, big, got)
		}
		d := l.oversize() - d0
		t.Logf("EVIDENCE L0 %s local_mss/local_mss_in flushed: marked local connection failed in %v (%s); the underlay dropped %d oversize outer packets", c.fam, time.Since(start).Round(time.Millisecond), got, d)
		if d == 0 {
			t.Fatalf("L0 %s: the failure was not the blackhole (no oversize outer packet dropped): %s", c.fam, got)
		}
	}
	// L1: the generated ruleset again.
	l.must(l.in("gw", "nft", "-f", l.nftGW)...)
	for _, c := range cases {
		d0, n0 := l.oversize(), len(far.lines())
		start := time.Now()
		got := l.client("gw", c.dst, srcAddr(c.src), l.mark, big, big)
		if !strings.HasPrefix(got, "OK ") {
			l.diag()
			t.Fatalf("L1 %s: with the generated ruleset the marked local connection failed: %s", c.fam, got)
		}
		peer := lastConn(t, far, n0)
		own := field(got, "mss")
		t.Logf("EVIDENCE L1 %s generated ruleset: marked local connection OK in %v (%s); far saw SYN MSS %d, the gateway's send MSS %d, forward clamp %d",
			c.fam, time.Since(start).Round(time.Millisecond), got, peer, own, c.clamp)
		if peer > c.clamp || own > c.clamp {
			t.Fatalf("L1 %s: MSS not clamped to %d: far saw %d, gateway sends %d", c.fam, c.clamp, peer, own)
		}
		if d := l.oversize() - d0; d != 0 {
			t.Fatalf("L1 %s: %d outer packets were still too large for the path", c.fam, d)
		}
	}
	// U: unmarked local connections keep their MSS.
	n0 := len(cli.lines())
	got := l.client("gw", net.JoinHostPort(l.cliAddr, "7000"), "", 0, 1000, 1000)
	if !strings.HasPrefix(got, "OK ") {
		t.Fatalf("U1 unmarked connection to a LAN host failed: %s", got)
	}
	if mss := lastConn(t, cli, n0); mss <= l.mss4 {
		t.Fatalf("U1 an unmarked local connection on the LAN was clamped to %d", mss)
	} else {
		t.Logf("EVIDENCE U1 unmarked local connection to a LAN host (like the panel or SSH): SYN MSS %d, untouched", mss)
	}
	n0 = len(far.lines())
	got = l.client("gw", net.JoinHostPort(l.farTun4, "7000"), "", 0, 1000, 1000)
	if !strings.HasPrefix(got, "OK ") {
		t.Fatalf("U2 unmarked connection to the peer's tunnel address failed: %s", got)
	}
	if mss := lastConn(t, far, n0); mss <= l.mss4 {
		t.Fatalf("U2 an unmarked local connection through the tunnel was clamped to %d", mss)
	} else {
		t.Logf("EVIDENCE U2 unmarked local connection through %s to %s: SYN MSS %d (the interface's), untouched", l.ifc, l.farTun4, mss)
	}
	// W: WireGuard's fwmark on a TCP connection over the underlay.
	n0 = len(far.lines())
	got = l.client("gw", net.JoinHostPort(l.endpoint.Addr().String(), "7000"), "", markUnderlay, 1000, 1000)
	if !strings.HasPrefix(got, "OK ") {
		t.Fatalf("W1 a connection with the WireGuard fwmark over the underlay failed: %s", got)
	}
	if mss := lastConn(t, far, n0); mss <= l.mss4 {
		t.Fatalf("W1 a connection with the WireGuard fwmark %#x over the underlay was clamped to %d", markUnderlay, mss)
	} else {
		t.Logf("EVIDENCE W1 TCP with the WireGuard fwmark %#x over the underlay (wstunnel's carrier shape): SYN MSS %d, untouched", markUnderlay, mss)
	}
	// F: forwarded LAN traffic.
	d0 := l.oversize()
	n0 = len(far.lines())
	got = l.client("cli", "203.0.113.110:7000", "", 0, big, big)
	if !strings.HasPrefix(got, "OK ") {
		l.diag()
		t.Fatalf("F forwarded LAN connection failed: %s", got)
	}
	peer, own := lastConn(t, far, n0), field(got, "mss")
	t.Logf("EVIDENCE F forwarded LAN connection OK (%s): far saw SYN MSS %d, the client sends %d (chain mss %d)", got, peer, own, l.mss4)
	if peer > l.mss4 || own > l.mss4 {
		t.Fatalf("F forwarded traffic not clamped to %d: %d/%d", l.mss4, peer, own)
	}
	if d := l.oversize() - d0; d != 0 {
		t.Fatalf("F %d outer packets too large", d)
	}
	t.Logf("EVIDENCE W2 WireGuard handshakes and outer packets: every connection above ran through %s; the blackhole dropped outer packets only in L0", l.ifc)
	fmt.Fprintln(os.Stderr, "meridian-netns-local-mss-gateway-test-ok")
}

// TestNetnsLocalMSSNode: the remote side. far is the example's relay (access)
// and loads its compiled ruleset; a connection far opens itself through the
// tunnel to a local socket on the gateway (unmarked there, like the exit's
// unlock report to the panel or a resolver answering the gateway) moving
// 64 KiB each way fails without chains tunnel_mss_out/tunnel_mss_in and
// works with them, IPv4 and IPv6.
func TestNetnsLocalMSSNode(t *testing.T) {
	l := newMSSLab(t)
	l.loadGateway()
	l.handshake()
	gw := l.helper("gw", "server", "[::]:7000")
	waitLine(t, gw, "READY", 5*time.Second)
	big := 64 << 10
	nodeNFT := l.write("access.nft", l.b.File("nodes/access/etc/nftables.d/meridian.nft"))
	if !strings.Contains(l.b.File("nodes/access/etc/nftables.d/meridian.nft"), "chain tunnel_mss_out") {
		t.Fatal("the relay's ruleset has no tunnel_mss_out")
	}
	dsts := []struct{ fam, dst string }{{"IPv4", net.JoinHostPort(l.gwTun4, "7000")}, {"IPv6", net.JoinHostPort(l.gwTun6, "7000")}}
	for _, d := range dsts {
		o0 := l.oversize()
		got := l.client("far", d.dst, "", 0, big, big)
		if strings.HasPrefix(got, "OK ") {
			t.Fatalf("N0 %s: without the node clamp far's own connection moved %d bytes each way through the blackhole: %s", d.fam, big, got)
		}
		t.Logf("EVIDENCE N0 %s no node ruleset: far's own connection to the gateway failed (%s); %d oversize outer packets dropped", d.fam, got, l.oversize()-o0)
	}
	l.must(l.in("far", "nft", "-c", "-f", nodeNFT)...)
	l.must(l.in("far", "nft", "-f", nodeNFT)...)
	for i, d := range dsts {
		clamp := l.mss4
		if i == 1 {
			clamp = l.mss6
		}
		n0, o0 := len(gw.lines()), l.oversize()
		got := l.client("far", d.dst, "", 0, big, big)
		if !strings.HasPrefix(got, "OK ") {
			l.diag()
			t.Fatalf("N1 %s: with the relay's compiled ruleset far's own connection failed: %s", d.fam, got)
		}
		peer, own := lastConn(t, gw, n0), field(got, "mss")
		t.Logf("EVIDENCE N1 %s relay ruleset (tunnel_mss_out/in): OK (%s); the gateway saw SYN MSS %d, far sends %d, clamp %d", d.fam, got, peer, own, clamp)
		if peer > clamp || own > clamp {
			t.Fatalf("N1 %s: not clamped to %d: %d/%d", d.fam, clamp, peer, own)
		}
		if o := l.oversize() - o0; o != 0 {
			t.Fatalf("N1 %s: %d oversize outer packets", d.fam, o)
		}
	}
	fmt.Fprintln(os.Stderr, "meridian-netns-local-mss-node-test-ok")
}

// TestNetnsLocalMSSGroupMesh: a region group switched from the WireGuard
// path to the small-MTU Mesh fallback (compile.groupClamps; docs/
// verification.md「地区组的 Mesh 备路」). The default group of the example
// (hk) can fall back to the primary hub's Mesh hop (MTU 1280); the
// gateway's floor clamp is 1320/1300. far plays the hub: the group's test
// server is first on far itself (the WireGuard path), then in a further
// namespace "mx" reached over a small-MTU hop. A real Cloudflare Mesh
// sidecar cannot run here; the hop is modelled as what it is, a link whose
// MTU is 1280, with no feedback:
//
//	far ── h0 (MTU 1280) ── h1 (MTU 1280) ── mh ── h2 ── h3 ── mx
//
// far and mh forward over the 1280 link; the kernel itself refuses to
// forward a DF packet (or a GSO packet whose segments are) longer than
// the link MTU, and the ICMP fragmentation-needed / ICMPv6 packet-too-big
// it would send back is dropped in far's and mh's output (counted as
// "ptb"): the overlay loses what it cannot carry, silently. mx's own link
// is 1500, so the server advertises its normal MSS (as a real server
// behind the exit would) and only the clamp keeps segments small. A
// length match on the forward hook is not used: GRO (WireGuard's receive
// path, veth TSO) hands the forwarding namespace coalesced packets far
// longer than one segment, which such a match would drop although every
// segment fits.
//
//	G1 WireGuard path, generated ruleset: a marked local connection (group
//	   mark, group transit source) and a forwarded LAN connection move
//	   64 KiB each way; the SYN MSS far sees is the group's clamp;
//	G2 Mesh path, the ruleset without the group's own clamp rules (the
//	   shape before the fix: floor only): the same marked local connection
//	   fails, and the hop refused oversize packets (ptb grew);
//	G3 Mesh path, generated ruleset: marked local (IPv4 and IPv6) and
//	   forwarded connections complete, MSS at most 1240/1220, and the hop
//	   refused nothing (ptb unchanged);
//	O  a group without the fallback (its own mark and transit source)
//	   keeps the floor: its SYN reaches far with an MSS above 1240 and at
//	   most 1320.
func TestNetnsLocalMSSGroupMesh(t *testing.T) {
	l := newMSSLab(t)
	b := l.b
	var mesh, plain *validate.GroupPathReport
	for i, r := range b.GroupPaths {
		switch {
		case r.Mesh && r.MSS4 < l.mss4 && mesh == nil:
			mesh = &b.GroupPaths[i]
		case !r.Mesh && plain == nil:
			plain = &b.GroupPaths[i]
		}
	}
	if mesh == nil || plain == nil {
		t.Fatal("the example has no group with a Mesh fallback below the floor, or none without")
	}
	groups := planGroups(l.topo, planExits(l.topo, mustTunnels(t, l.topo)))
	gm, _ := groupByID(groups, mesh.GroupID)
	gp, _ := groupByID(groups, plain.GroupID)
	if gm.Mark != l.mark {
		t.Fatalf("the lab's default mark %#x is not the Mesh group %s (%#x)", l.mark, gm.Group.ID, gm.Mark)
	}
	// The ruleset without the group's own clamp rules: the floor only.
	var pre []string
	for _, line := range strings.Split(b.File("nodes/gw/etc/nftables.d/meridian.nft"), "\n") {
		if strings.Contains(line, fmt.Sprintf("meta mark %#x ", gm.Mark)) && strings.Contains(line, "maxseg") ||
			strings.Contains(line, "== "+hexMark(gm.Mark)+" ") && strings.Contains(line, "maxseg") ||
			strings.Contains(line, "ip daddr "+gm.TransitV4+" tcp option maxseg") || strings.Contains(line, "ip6 daddr "+gm.TransitV6+" tcp option maxseg") {
			continue
		}
		pre = append(pre, line)
	}
	preNFT := l.write("gw-pre.nft", strings.Join(pre, "\n"))
	l.loadGateway()
	l.handshake()
	// The small hop: far ─h0/h1 (1280)─ mh ─h2/h3 (1500)─ mx.
	in, must := l.in, l.must
	sfx := strconv.Itoa(os.Getpid() % 100000)
	for _, n := range []string{"mh", "mx"} {
		l.ns[n] = "mms" + n + sfx
		must("ip", "netns", "add", l.ns[n])
		must(in(n, "ip", "link", "set", "lo", "up")...)
		for _, s := range []string{"net.ipv4.tcp_mtu_probing=0", "net.ipv4.conf.all.rp_filter=0", "net.ipv4.conf.default.rp_filter=0"} {
			must(in(n, "sysctl", "-qw", s)...)
		}
		_, _ = l.sh(in(n, "sysctl", "-qw", "net.ipv4.tcp_timestamps=0")...)
	}
	for _, n := range []string{"far", "mh"} {
		must(in(n, "sysctl", "-qw", "net.ipv4.ip_forward=1")...)
		must(in(n, "sysctl", "-qw", "net.ipv6.conf.all.forwarding=1")...)
	}
	must(in("far", "ip", "link", "add", "h0", "type", "veth", "peer", "name", "h1", "netns", l.ns["mh"])...)
	must(in("mh", "ip", "link", "add", "h2", "type", "veth", "peer", "name", "h3", "netns", l.ns["mx"])...)
	must(in("far", "ip", "link", "set", "h0", "mtu", "1280", "up")...)
	must(in("mh", "ip", "link", "set", "h1", "mtu", "1280", "up")...)
	must(in("mh", "ip", "link", "set", "h2", "up")...)
	must(in("mx", "ip", "link", "set", "h3", "up")...)
	for _, a := range [][]string{
		{"far", "198.51.100.9/30", "h0"}, {"mh", "198.51.100.10/30", "h1"}, {"mh", "198.51.100.13/30", "h2"}, {"mx", "198.51.100.14/30", "h3"},
	} {
		must(in(a[0], "ip", "addr", "add", a[1], "dev", a[2])...)
	}
	for _, a := range [][]string{
		{"far", "2001:db8:f:1::1/64", "h0"}, {"mh", "2001:db8:f:1::2/64", "h1"}, {"mh", "2001:db8:f:2::1/64", "h2"}, {"mx", "2001:db8:f:2::2/64", "h3"},
	} {
		must(in(a[0], "ip", "-6", "addr", "add", a[1], "dev", a[2], "nodad")...)
	}
	must(in("mh", "ip", "route", "add", "default", "via", "198.51.100.9")...)
	must(in("mh", "ip", "-6", "route", "add", "default", "via", "2001:db8:f:1::1")...)
	must(in("mx", "ip", "route", "add", "default", "via", "198.51.100.13")...)
	must(in("mx", "ip", "-6", "route", "add", "default", "via", "2001:db8:f:2::1")...)
	// No feedback: the ICMP the kernel sends back for a packet too long for
	// the 1280 link is dropped (and counted) where it is generated.
	nofeedback := "table inet mlabmesh {\n  counter ptb {\n  }\n  chain lab_nofeedback {\n    type filter hook output priority 0; policy accept;\n    icmp type destination-unreachable icmp code frag-needed counter name \"ptb\" drop comment \"the small-MTU hop gives no feedback\"\n    icmpv6 type packet-too-big counter name \"ptb\" drop\n  }\n}\n"
	for _, n := range []string{"far", "mh"} {
		must(in(n, "nft", "-f", l.write("nofeedback-"+n+".nft", nofeedback))...)
	}
	ptb := func() int {
		sum := 0
		for _, n := range []string{"far", "mh"} {
			out, _ := l.sh(in(n, "nft", "list", "counter", "inet", "mlabmesh", "ptb")...)
			m := regexp.MustCompile(`packets (\d+)`).FindStringSubmatch(out)
			if m == nil {
				t.Fatalf("ptb counter in %s unreadable: %s", n, out)
			}
			v, _ := strconv.Atoi(m[1])
			sum += v
		}
		return sum
	}
	const dst4, dst6 = "203.0.113.120", "2001:db8:f::20"
	// G1: the WireGuard path, the group's server on far itself.
	must(in("far", "ip", "addr", "add", dst4+"/32", "dev", "lo")...)
	must(in("far", "ip", "-6", "addr", "add", dst6+"/128", "dev", "lo", "nodad")...)
	far := l.helper("far", "server", "[::]:7200")
	waitLine(t, far, "READY", 5*time.Second)
	big := 64 << 10
	n0 := len(far.lines())
	got := l.client("gw", dst4+":7200", srcAddr(l.transit4), gm.Mark, big, big)
	if !strings.HasPrefix(got, "OK ") {
		l.diag()
		t.Fatalf("G1 WireGuard path: marked local connection failed: %s", got)
	}
	if mss := lastConn(t, far, n0); mss > mesh.MSS4 {
		t.Fatalf("G1 the group's SYN reached far with MSS %d, above its clamp %d", mss, mesh.MSS4)
	} else {
		t.Logf("EVIDENCE G1 WireGuard path: group %s (mark %#x) marked local connection OK (%s), far saw SYN MSS %d (group clamp %d, floor %d)", gm.Group.ID, gm.Mark, got, mss, mesh.MSS4, l.mss4)
	}
	if got := l.client("cli", dst4+":7200", "", 0, big, big); !strings.HasPrefix(got, "OK ") {
		t.Fatalf("G1 forwarded LAN connection failed: %s", got)
	} else {
		t.Logf("EVIDENCE G1 forwarded LAN connection on the WireGuard path OK (%s)", got)
	}
	// The switch: the group's server moves behind the small hop.
	must(in("far", "ip", "addr", "del", dst4+"/32", "dev", "lo")...)
	must(in("far", "ip", "-6", "addr", "del", dst6+"/128", "dev", "lo")...)
	must(in("mx", "ip", "addr", "add", dst4+"/32", "dev", "lo")...)
	must(in("mx", "ip", "-6", "addr", "add", dst6+"/128", "dev", "lo", "nodad")...)
	must(in("far", "ip", "route", "add", dst4+"/32", "via", "198.51.100.10")...)
	must(in("far", "ip", "-6", "route", "add", dst6+"/128", "via", "2001:db8:f:1::2")...)
	must(in("mh", "ip", "route", "add", dst4+"/32", "via", "198.51.100.14")...)
	must(in("mh", "ip", "-6", "route", "add", dst6+"/128", "via", "2001:db8:f:2::2")...)
	mx2 := l.helper("mx", "server", "[::]:7202")
	mx3 := l.helper("mx", "server", "[::]:7203")
	waitLine(t, mx2, "READY", 5*time.Second)
	waitLine(t, mx3, "READY", 5*time.Second)
	// G2: the floor only. Failed connections are aborted with a reset
	// (mssClient), so nothing of G2 is retransmitted into G3.
	must(in("gw", "nft", "-f", preNFT)...)
	p0 := ptb()
	if got := l.client("gw", dst4+":7202", srcAddr(l.transit4), gm.Mark, big, big); strings.HasPrefix(got, "OK ") {
		t.Fatalf("G2 without the group's clamp the marked connection crossed the 1280 hop: %s", got)
	} else if d := ptb() - p0; d == 0 {
		t.Fatalf("G2 the failure was not the small hop (it refused no packet): %s", got)
	} else {
		t.Logf("EVIDENCE G2 Mesh path, floor clamp %d only: marked local connection failed (%s); the 1280 hop refused %d packets (their ICMP feedback dropped)", l.mss4, got, d)
	}
	// G3: the generated ruleset. Every G3 connection must complete and the
	// hop must refuse none of its packets.
	must(in("gw", "nft", "-f", l.nftGW)...)
	for _, c := range []struct {
		fam, dst, src string
		clamp         int
	}{{"IPv4", dst4 + ":7203", srcAddr(l.transit4), mesh.MSS4}, {"IPv6", "[" + dst6 + "]:7203", "[" + l.transit6 + "]:0", mesh.MSS6}} {
		n0, p0 := len(mx3.lines()), ptb()
		got := l.client("gw", c.dst, c.src, gm.Mark, big, big)
		d := ptb() - p0
		if !strings.HasPrefix(got, "OK ") {
			l.diag()
			t.Fatalf("G3 %s Mesh path, generated ruleset: marked local connection did not complete: %s (hop refused %d)", c.fam, got, d)
		}
		peer, own := lastConn(t, mx3, n0), field(got, "mss")
		t.Logf("EVIDENCE G3 %s Mesh path, generated ruleset: completed (%s), the server saw SYN MSS %d, the gateway sends %d, group clamp %d; the hop refused %d packets", c.fam, got, peer, own, c.clamp, d)
		if peer > c.clamp || own > c.clamp || d != 0 {
			t.Fatalf("G3 %s: MSS %d/%d (clamp %d), the hop refused %d packets", c.fam, peer, own, c.clamp, d)
		}
	}
	n0 = len(mx3.lines())
	p0 = ptb()
	got = l.client("cli", dst4+":7203", "", 0, big, big)
	if d := ptb() - p0; !strings.HasPrefix(got, "OK ") || d != 0 {
		l.diag()
		t.Fatalf("G3 forwarded LAN connection over the Mesh path: %s (the hop refused %d)", got, d)
	}
	t.Logf("EVIDENCE G3 forwarded LAN connection over the Mesh path completed (%s): the server saw SYN MSS %d, the client sends %d (SYN-ACK clamped by the group's transit address); the hop refused nothing", got, lastConn(t, mx3, n0), field(got, "mss"))
	// O: a group without the fallback keeps the floor (its own mark and
	// transit source, like the probe; far's server on the WireGuard path).
	gpm := markPlan{gp.Mark, gp.Index, gp.TransitV4, gp.TransitV6}
	must(in("gw", "ip", "addr", "add", gpm.TransitV4+"/32", "dev", "lo")...)
	n0 = len(far.lines())
	got = l.client("gw", "203.0.113.110:7200", srcAddr(gpm.TransitV4), gp.Mark, 1000, 1000)
	if !strings.HasPrefix(got, "OK ") {
		l.diag()
		t.Fatalf("O group %s connection failed: %s", gp.Group.ID, got)
	}
	if mss := lastConn(t, far, n0); mss <= mesh.MSS4 || mss > l.mss4 {
		t.Fatalf("O group %s (no Mesh fallback) reached far with MSS %d, want above the Mesh group's %d and at most the floor %d", gp.Group.ID, mss, mesh.MSS4, l.mss4)
	} else {
		t.Logf("EVIDENCE O group %s (mark %#x, no Mesh fallback): SYN MSS %d (floor %d), not the Mesh group's %d", gp.Group.ID, gp.Mark, mss, l.mss4, mesh.MSS4)
	}
	fmt.Fprintln(os.Stderr, "meridian-netns-local-mss-group-mesh-test-ok")
}

// TestNetnsLocalMSSHelper is the server and client the tests above run in
// their namespaces (this binary re-executed). On its own it does nothing.
func TestNetnsLocalMSSHelper(t *testing.T) {
	mode := os.Getenv("MERIDIAN_MSS_HELPER")
	if mode == "" {
		t.Skip("helper process of TestNetnsLocalMSSGateway/Node; not a test on its own")
	}
	args := strings.Split(os.Getenv("MERIDIAN_MSS_HELPER_ARGS"), "\x1f")
	switch mode {
	case "server":
		mssServer(args[0])
	case "client":
		up, _ := strconv.Atoi(args[3])
		down, _ := strconv.Atoi(args[4])
		mark, _ := strconv.ParseUint(args[2], 0, 32)
		fmt.Println(mssClient(args[0], args[1], uint32(mark), up, down))
	case "hold":
		fmt.Println(holdClient(args[0], args[1]))
	}
	os.Exit(0)
}

// holdClient: one long-lived connection to an mssServer. It sends the
// header and half of a 1000-byte upload, prints HOLDING, waits (bounded,
// 8 s) until the file release exists, sends the rest and reads a
// 1000-byte download: "OK …" when the same connection carried both halves.
func holdClient(dst, release string) string {
	c, err := net.DialTimeout("tcp", dst, 4*time.Second)
	if err != nil {
		return "ERR dial " + err.Error()
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(9 * time.Second))
	var h [8]byte
	binary.BigEndian.PutUint32(h[:4], 1000)
	binary.BigEndian.PutUint32(h[4:], 1000)
	if _, err := c.Write(append(h[:], make([]byte, 500)...)); err != nil {
		return "ERR first half: " + err.Error()
	}
	fmt.Println("HOLDING " + c.LocalAddr().String())
	deadline := time.Now().Add(8 * time.Second)
	for {
		if _, err := os.Stat(release); err == nil {
			break
		}
		if time.Now().After(deadline) {
			return "ERR never released"
		}
		time.Sleep(50 * time.Millisecond)
	}
	if _, err := c.Write(make([]byte, 500)); err != nil {
		return "ERR second half: " + err.Error()
	}
	if n, err := io.CopyN(io.Discard, c, 1000); err != nil {
		return fmt.Sprintf("ERR download %d/1000: %v", n, err)
	}
	return "OK held local=" + c.LocalAddr().String()
}

func tcpMaxSeg(c net.Conn) int {
	rc, err := c.(*net.TCPConn).SyscallConn()
	if err != nil {
		return -1
	}
	v := -1
	_ = rc.Control(func(fd uintptr) { v, _ = syscall.GetsockoptInt(int(fd), syscall.IPPROTO_TCP, syscall.TCP_MAXSEG) })
	return v
}

// mssServer: per connection one line "CONN peer=<addr> mss=<TCP_MAXSEG>"
// (with timestamps off, the smaller of the peer's SYN MSS and the route's),
// then it reads the 8-byte header (upload, download sizes), the upload, and
// writes the download.
func mssServer(listen string) {
	ln, err := net.Listen("tcp", listen)
	if err != nil {
		fmt.Println("ERR", err)
		os.Exit(1)
	}
	fmt.Println("READY")
	for {
		c, err := ln.Accept()
		if err != nil {
			continue
		}
		go func(c net.Conn) {
			defer c.Close()
			fmt.Printf("CONN peer=%s mss=%d\n", c.RemoteAddr(), tcpMaxSeg(c))
			_ = c.SetDeadline(time.Now().Add(10 * time.Second))
			var h [8]byte
			if _, err := io.ReadFull(c, h[:]); err != nil {
				return
			}
			if _, err := io.CopyN(io.Discard, c, int64(binary.BigEndian.Uint32(h[:4]))); err != nil {
				return
			}
			_, _ = c.Write(make([]byte, binary.BigEndian.Uint32(h[4:])))
		}(c)
	}
}

// mssClient: one connection (source address and fwmark optional), upload
// and download within 4 s; "OK local=… mss=… up=… down=…" or "ERR …".
func mssClient(dst, src string, mark uint32, up, down int) string {
	d := net.Dialer{Timeout: 4 * time.Second}
	if src != "" {
		ap, err := netip.ParseAddrPort(src)
		if err != nil {
			return "ERR source " + err.Error()
		}
		d.LocalAddr = net.TCPAddrFromAddrPort(ap)
	}
	if mark != 0 {
		d.Control = func(_, _ string, rc syscall.RawConn) error {
			var serr error
			if err := rc.Control(func(fd uintptr) {
				serr = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_MARK, int(mark))
			}); err != nil {
				return err
			}
			return serr
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	c, err := d.DialContext(ctx, "tcp", dst)
	if err != nil {
		return "ERR dial " + err.Error()
	}
	defer c.Close()
	// A failed connection is aborted (RST, nothing left queued): an
	// orphaned socket would keep retransmitting its oversize segments
	// into the next phase's drop counters.
	abort := func(s string) string { _ = c.(*net.TCPConn).SetLinger(0); return s }
	_ = c.SetDeadline(time.Now().Add(4 * time.Second))
	var h [8]byte
	binary.BigEndian.PutUint32(h[:4], uint32(up))
	binary.BigEndian.PutUint32(h[4:], uint32(down))
	if _, err := c.Write(append(h[:], make([]byte, up)...)); err != nil {
		return abort(fmt.Sprintf("ERR local=%s upload: %v", c.LocalAddr(), err))
	}
	n, err := io.CopyN(io.Discard, c, int64(down))
	if err != nil {
		return abort(fmt.Sprintf("ERR local=%s download %d/%d: %v", c.LocalAddr(), n, down, err))
	}
	return fmt.Sprintf("OK local=%s mss=%d up=%d down=%d", c.LocalAddr(), tcpMaxSeg(c), up, down)
}

func srcAddr(s string) string {
	if s == "" || strings.Contains(s, "]:") {
		return s
	}
	return s + ":0"
}

var reMSSField = regexp.MustCompile(`\bmss=(-?\d+)`)

func field(line, _ string) int {
	m := reMSSField.FindStringSubmatch(line)
	if m == nil {
		return -1
	}
	v, _ := strconv.Atoi(m[1])
	return v
}

// lastConn: the MSS of the first connection a server logged after line n0.
func lastConn(t *testing.T, h *helperProc, n0 int) int {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for {
		ls := h.lines()
		for _, l := range ls[min(n0, len(ls)):] {
			if strings.HasPrefix(l, "CONN ") {
				return field(l, "mss")
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("the server logged no connection after line %d: %q", n0, ls)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

type mssLab struct {
	t                  *testing.T
	topo               model.Topology
	b                  *Bundle
	dir, exe           string
	ns                 map[string]string
	ifc, lan           string
	nftGW              string
	mark               uint32
	transit4, transit6 string
	mss4, mss6         int
	endpoint           netip.AddrPort
	gwTun4, gwTun6     string
	farTun4, farTun6   string
	cliAddr, gwLANAddr string
	gwSetconf          string
	// The lab's test keys: the gateway's private key, far's public key.
	gwPriv, farPub string
	// limit: the underlay (rt) drops IPv4 outer packets longer than this.
	limit int
}

func (l *mssLab) in(n string, args ...string) []string {
	return append([]string{"ip", "netns", "exec", l.ns[n]}, args...)
}

func (l *mssLab) sh(args ...string) (string, error) {
	out, err := exec.Command(args[0], args[1:]...).CombinedOutput()
	return string(out), err
}

func (l *mssLab) must(args ...string) string {
	l.t.Helper()
	out, err := l.sh(args...)
	if err != nil {
		l.t.Fatalf("%s: %v\n%s", strings.Join(args, " "), err, out)
	}
	return out
}

func (l *mssLab) write(name, body string) string {
	p := filepath.Join(l.dir, name)
	mustWrite(l.t, p, body)
	return p
}

func (l *mssLab) helper(n string, mode string, args ...string) *helperProc {
	l.t.Helper()
	cmdline := append(l.in(n), "env", "MERIDIAN_MSS_HELPER="+mode, "MERIDIAN_MSS_HELPER_ARGS="+strings.Join(args, "\x1f"), l.exe, "-test.run=^TestNetnsLocalMSSHelper$")
	cmd := exec.Command(cmdline[0], cmdline[1:]...)
	pr, pw := io.Pipe()
	cmd.Stdout, cmd.Stderr = pw, pw
	h := &helperProc{cmd: cmd}
	if err := cmd.Start(); err != nil {
		l.t.Fatal(err)
	}
	go func() {
		sc := bufio.NewScanner(pr)
		for sc.Scan() {
			h.mu.Lock()
			h.out = append(h.out, sc.Text())
			h.mu.Unlock()
		}
	}()
	l.t.Cleanup(func() { _ = cmd.Process.Kill(); _, _ = cmd.Process.Wait(); pw.Close() })
	return h
}

func (l *mssLab) client(n, dst, src string, mark uint32, up, down int) string {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	cmdline := append(l.in(n), "env", "MERIDIAN_MSS_HELPER=client",
		"MERIDIAN_MSS_HELPER_ARGS="+strings.Join([]string{dst, src, fmt.Sprint(mark), fmt.Sprint(up), fmt.Sprint(down)}, "\x1f"), l.exe, "-test.run=^TestNetnsLocalMSSHelper$")
	out, _ := exec.CommandContext(ctx, cmdline[0], cmdline[1:]...).CombinedOutput()
	for _, line := range strings.Split(string(out), "\n") {
		if strings.HasPrefix(line, "OK ") || strings.HasPrefix(line, "ERR ") {
			return line
		}
	}
	return "ERR no output: " + strings.TrimSpace(string(out))
}

// oversize: outer packets the underlay dropped as too long.
func (l *mssLab) oversize() int {
	out, _ := l.sh(l.in("rt", "nft", "list", "counter", "ip", "mlab", "oversize")...)
	m := regexp.MustCompile(`packets (\d+)`).FindStringSubmatch(out)
	if m == nil {
		l.t.Fatalf("blackhole counter unreadable: %s", out)
	}
	v, _ := strconv.Atoi(m[1])
	return v
}

func (l *mssLab) diag() {
	for _, c := range [][]string{
		l.in("gw", "wg", "show"), l.in("far", "wg", "show"),
		l.in("gw", "nft", "list", "chain", "inet", "meridian", "local_mss"),
		l.in("gw", "ip", "rule"), l.in("gw", "ip", "route", "show", "table", "102"),
		l.in("rt", "nft", "list", "ruleset"),
	} {
		out, _ := l.sh(c...)
		l.t.Logf("DIAG %s:\n%s", strings.Join(c[4:], " "), out)
	}
}

// mssNetnsPrereqs skips (NOT RUN) unless root, both opt-in variables, ip,
// nft and wg are there, and the kernel creates a WireGuard interface and
// loads an nft MSS-clamp rule in a namespace.
func mssNetnsPrereqs(t *testing.T) {
	t.Helper()
	if os.Getenv("MERIDIAN_NETNS_TEST") != "1" || os.Getenv("MERIDIAN_NFT_TEST") != "1" {
		t.Skip("NOT RUN: runtime netns test; run as root with MERIDIAN_NETNS_TEST=1 MERIDIAN_NFT_TEST=1 (docs/verification.md)")
	}
	if os.Geteuid() != 0 {
		t.Skip("NOT RUN: needs root for network namespaces")
	}
	for _, bin := range []string{"ip", "nft", "wg"} {
		if _, err := exec.LookPath(bin); err != nil {
			t.Skipf("NOT RUN: %s not installed", bin)
		}
	}
	ns := "mmssprobe" + strconv.Itoa(os.Getpid()%100000)
	if out, err := exec.Command("ip", "netns", "add", ns).CombinedOutput(); err != nil {
		t.Fatalf("ip netns add: %v %s", err, out)
	}
	defer func() { _ = exec.Command("ip", "netns", "del", ns).Run() }()
	if out, err := exec.Command("ip", "netns", "exec", ns, "ip", "link", "add", "wgprobe", "type", "wireguard").CombinedOutput(); err != nil {
		t.Skipf("NOT RUN: this kernel cannot create a WireGuard interface (%v: %s)", err, strings.TrimSpace(string(out)))
	}
	cmd := exec.Command("ip", "netns", "exec", ns, "nft", "-f", "-")
	cmd.Stdin = strings.NewReader("table inet mprobe {\n  chain o {\n    type filter hook output priority -140; policy accept;\n    tcp flags syn tcp option maxseg size > 1300 tcp option maxseg size set 1300\n  }\n}\n")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Skipf("NOT RUN: nft cannot load an MSS clamp in a namespace (%v: %s)", err, strings.TrimSpace(string(out)))
	}
}

var (
	reConfAddr = regexp.MustCompile(`(?m)^Address\s*=\s*(.+)$`)
	reConfMTU  = regexp.MustCompile(`(?m)^MTU\s*=\s*(\d+)$`)
	reConfEP   = regexp.MustCompile(`(?m)^Endpoint\s*=\s*(\S+)$`)
)

// wgOuterLen is an IPv4 WireGuard outer packet carrying an inner packet of
// n bytes on an interface of MTU m (internal/mtu, the one overhead
// computation: IPv4 20 + UDP 8 + data header 16 + tag 16, the plaintext
// padded to 16 but not beyond the MTU).
func wgOuterLen(n, m int) int {
	return mtu.UDPOuterLen(n, m, 4)
}

func newMSSLab(t *testing.T) *mssLab {
	t.Helper()
	mssNetnsPrereqs(t)
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	topo := defaults.Example()
	b := mustCompile(t, topo)
	tunnels := mustTunnels(t, topo)
	exits := planExits(topo, tunnels)
	groups := planGroups(topo, exits)
	def, ok := defaultExit(topo, groups)
	if !ok {
		t.Fatal("the example has no default exit")
	}
	l := &mssLab{t: t, topo: topo, b: b, exe: exe, dir: t.TempDir(), ns: map[string]string{}, ifc: "m02", lan: gatewayLAN(topo), mark: def.Mark}
	for _, m := range markPlans(exits, groups) {
		if m.Mark == def.Mark {
			l.transit4, l.transit6 = m.TransitV4, m.TransitV6
		}
	}
	nft := b.File("nodes/gw/etc/nftables.d/meridian.nft")
	hm := regexp.MustCompile(`# mss-clamp v4 (\d+) v6 (\d+)`).FindStringSubmatch(nft)
	if hm == nil || l.transit4 == "" {
		t.Fatal("no mss-clamp header or no transit address for the default mark")
	}
	l.mss4, _ = strconv.Atoi(hm[1])
	l.mss6, _ = strconv.Atoi(hm[2])
	l.nftGW = l.write("gw.nft", nft)
	gwConf, farConf := b.File("nodes/gw/etc/wireguard/m02.conf"), b.File("nodes/access/etc/wireguard/m02.conf")
	if gwConf == "" || farConf == "" {
		t.Fatal("the example has no m02 between gw and access")
	}
	mtu, _ := strconv.Atoi(reConfMTU.FindStringSubmatch(gwConf)[1])
	l.endpoint = netip.MustParseAddrPort(reConfEP.FindStringSubmatch(gwConf)[1])
	addrs := func(conf string) (string, string) {
		var v4, v6 string
		for _, a := range strings.Split(reConfAddr.FindStringSubmatch(conf)[1], ",") {
			a = strings.TrimSpace(a)
			if strings.Contains(a, ":") {
				v6 = a
			} else {
				v4 = a
			}
		}
		return v4, v6
	}
	g4, g6 := addrs(gwConf)
	f4, f6 := addrs(farConf)
	l.gwTun4, l.gwTun6 = strings.Split(g4, "/")[0], strings.Split(g6, "/")[0]
	l.farTun4, l.farTun6 = strings.Split(f4, "/")[0], strings.Split(f6, "/")[0]
	// The blackhole: outer packets of clamped segments fit, outer packets
	// of segments at the interface's MSS do not.
	fit := wgOuterLen(max(l.mss4+40, l.mss6+60), mtu)
	full := wgOuterLen(mtu, mtu)
	limit := (fit + full) / 2
	l.limit = limit
	if !(fit <= limit && limit < full) {
		t.Fatalf("no blackhole size between %d (clamped) and %d (interface MTU %d)", fit, full, mtu)
	}
	t.Logf("EVIDENCE lab: %s MTU %d (MSS %d unclamped), forward clamp %d/%d; the underlay drops outer packets over %d bytes (clamped segments need %d, full ones %d), without ICMP", l.ifc, mtu, mtu-40, l.mss4, l.mss6, limit, fit, full)

	sfx := strconv.Itoa(os.Getpid() % 100000)
	for _, n := range []string{"gw", "rt", "far", "cli"} {
		l.ns[n] = "mms" + n + sfx
	}
	t.Cleanup(func() {
		for _, n := range l.ns {
			_ = exec.Command("ip", "netns", "del", n).Run()
		}
	})
	in, must := l.in, l.must
	for _, n := range []string{"gw", "rt", "far", "cli"} {
		must("ip", "netns", "add", l.ns[n])
		must(in(n, "ip", "link", "set", "lo", "up")...)
		for _, s := range []string{"net.ipv4.tcp_mtu_probing=0", "net.ipv4.conf.all.rp_filter=0", "net.ipv4.conf.default.rp_filter=0"} {
			must(in(n, "sysctl", "-qw", s)...)
		}
		// Timestamps off: TCP_MAXSEG then reports the MSS itself.
		_, _ = l.sh(in(n, "sysctl", "-qw", "net.ipv4.tcp_timestamps=0")...)
	}
	for _, n := range []string{"gw", "rt"} {
		must(in(n, "sysctl", "-qw", "net.ipv4.ip_forward=1")...)
	}
	must(in("gw", "sysctl", "-qw", "net.ipv6.conf.all.forwarding=1")...)
	veth := func(a, an, b, bn string) {
		must(in(a, "ip", "link", "add", an, "type", "veth", "peer", "name", bn, "netns", l.ns[b])...)
		must(in(a, "ip", "link", "set", an, "up")...)
		must(in(b, "ip", "link", "set", bn, "up")...)
	}
	veth("gw", "u0", "rt", "u1")
	veth("rt", "u2", "far", "u3")
	veth("gw", l.lan, "cli", "c0")
	must(in("gw", "ip", "addr", "add", "198.51.100.1/30", "dev", "u0")...)
	must(in("rt", "ip", "addr", "add", "198.51.100.2/30", "dev", "u1")...)
	must(in("rt", "ip", "addr", "add", "198.51.100.5/30", "dev", "u2")...)
	must(in("far", "ip", "addr", "add", "198.51.100.6/30", "dev", "u3")...)
	ep := l.endpoint.Addr().String()
	must(in("gw", "ip", "route", "add", ep+"/32", "via", "198.51.100.2")...)
	must(in("rt", "ip", "route", "add", ep+"/32", "via", "198.51.100.6")...)
	must(in("far", "ip", "route", "add", "default", "via", "198.51.100.5")...)
	for _, a := range []string{ep + "/32", "203.0.113.110/32"} {
		must(in("far", "ip", "addr", "add", a, "dev", "lo")...)
	}
	must(in("far", "ip", "-6", "addr", "add", "2001:db8:f::10/128", "dev", "lo", "nodad")...)
	must(in("rt", "nft", "-f", l.write("rt.nft", fmt.Sprintf("table ip mlab {\n  counter oversize {\n  }\n  chain lab_forward {\n    type filter hook forward priority 0; policy accept;\n    ip length > %d counter name \"oversize\" drop comment \"blackhole: too long for the path, no ICMP\"\n  }\n}\n", limit)))...)
	// LAN.
	lanP := netip.MustParsePrefix(lanNet(topo))
	l.gwLANAddr = lanHost(topo)
	l.cliAddr = verifyLANClient4(lanNet(topo), l.gwLANAddr, "192.0.2.1")
	must(in("gw", "ip", "addr", "add", fmt.Sprintf("%s/%d", l.gwLANAddr, lanP.Bits()), "dev", l.lan)...)
	must(in("cli", "ip", "addr", "add", fmt.Sprintf("%s/%d", l.cliAddr, lanP.Bits()), "dev", "c0")...)
	must(in("cli", "ip", "route", "add", "default", "via", l.gwLANAddr)...)
	// WireGuard: the gateway with its compiled configuration (test keys),
	// far as the relay's end of the same link.
	gwPriv, gwPub := wgKeyPair(t)
	farPriv, farPub := wgKeyPair(t)
	l.gwPriv, l.farPub = gwPriv, farPub
	farKey := l.write("far.key", farPriv+"\n")
	if err := os.Chmod(farKey, 0o600); err != nil {
		t.Fatal(err)
	}
	must(in("far", "ip", "link", "add", l.ifc, "type", "wireguard")...)
	must(in("far", "wg", "set", l.ifc, "listen-port", fmt.Sprint(l.endpoint.Port()), "private-key", farKey, "peer", gwPub, "allowed-ips", "0.0.0.0/0,::/0")...)
	must(in("far", "ip", "link", "set", l.ifc, "mtu", fmt.Sprint(mtu))...)
	must(in("far", "ip", "addr", "add", f4, "dev", l.ifc)...)
	must(in("far", "ip", "-6", "addr", "add", f6, "dev", l.ifc, "nodad")...)
	must(in("far", "ip", "link", "set", l.ifc, "up")...)
	must(in("far", "ip", "route", "add", transitV4Net(), "dev", l.ifc)...)
	must(in("far", "ip", "-6", "route", "add", transitV6Net(), "dev", l.ifc)...)
	must(in("gw", "ip", "link", "add", l.ifc, "type", "wireguard")...)
	must(in("gw", "ip", "link", "set", l.ifc, "mtu", fmt.Sprint(mtu))...)
	must(in("gw", "ip", "addr", "add", g4, "dev", l.ifc)...)
	must(in("gw", "ip", "-6", "addr", "add", g6, "dev", l.ifc, "nodad")...)
	must(in("gw", "ip", "link", "set", l.ifc, "up")...)
	l.gwSetconf = l.write("gw.setconf", wgSetconfText(t, gwConf, gwPriv, farPub))
	if err := os.Chmod(l.gwSetconf, 0o600); err != nil {
		t.Fatal(err)
	}
	// Policy routing reduced to the marks: table 102 is the tunnel; the
	// default mark's transit addresses on lo (the routes script's job).
	must(in("gw", "ip", "addr", "add", l.transit4+"/32", "dev", "lo")...)
	must(in("gw", "ip", "-6", "addr", "add", l.transit6+"/128", "dev", "lo", "nodad")...)
	for _, m := range markPlans(exits, groups) {
		must(in("gw", "ip", "rule", "add", "fwmark", fmt.Sprintf("%#x", m.Mark), "lookup", "102", "priority", fmt.Sprint(prioExitBase+m.Index))...)
		must(in("gw", "ip", "-6", "rule", "add", "fwmark", fmt.Sprintf("%#x", m.Mark), "lookup", "102", "priority", fmt.Sprint(prioExitBase+m.Index))...)
	}
	must(in("gw", "ip", "route", "add", "default", "dev", l.ifc, "table", "102")...)
	must(in("gw", "ip", "-6", "route", "add", "default", "dev", l.ifc, "table", "102")...)
	return l
}

func (l *mssLab) loadGateway() {
	l.t.Helper()
	l.must(l.in("gw", "nft", "-c", "-f", l.nftGW)...)
	l.must(l.in("gw", "nft", "-f", l.nftGW)...)
	out := l.must(l.in("gw", "nft", "list", "chain", "inet", "meridian", "local_mss")...)
	l.t.Logf("EVIDENCE the compiled gateway ruleset is loaded; local_mss as the kernel lists it:\n%s", out)
}

// handshake applies the gateway's configuration (PersistentKeepalive starts
// a handshake at once) and waits for it, bounded.
func (l *mssLab) handshake() {
	l.t.Helper()
	l.must(l.in("gw", "wg", "setconf", l.ifc, l.gwSetconf)...)
	deadline := time.Now().Add(15 * time.Second)
	for {
		out, _ := l.sh(l.in("gw", "wg", "show", l.ifc, "latest-handshakes")...)
		if f := strings.Fields(out); len(f) >= 2 && f[1] != "0" {
			l.t.Logf("EVIDENCE WireGuard handshake on %s (compiled FwMark %#x, Endpoint %s, test keys)", l.ifc, markUnderlay, l.endpoint)
			return
		}
		if time.Now().After(deadline) {
			l.diag()
			l.t.Fatalf("no WireGuard handshake on %s", l.ifc)
		}
		time.Sleep(200 * time.Millisecond)
	}
}
