//go:build linux

package compile

import (
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/radowitz/meridian/internal/model"
)

// The name-sniffing forwarder over real WireGuard encapsulation.
//
// On a real gateway every tunnelled query and connection of the forwarder
// failed: the kernel's WireGuard outer packet of a packet the forwarder sent
// into a tunnel still carries the forwarder's socket, so "meta skuid" matched
// it in sniff_confine, where it was dropped (render_sniff.go, docs/
// verification.md「嗅探出站限制拦截了 WireGuard 外层包」). The veth lab
// (TestNetnsSniff) has no encapsulation and could not see it. Here the
// gateway's tunnels are kernel WireGuard interfaces:
//
//	cli ── br (LAN "enp3s0") ── gw ── ROS ── underlay (veth) ── far
//	                            gw: m02 m02w m03 … (WireGuard, the compiled
//	                                configs with test keys: FwMark, Endpoint)
//	                            far: one WireGuard interface per gateway
//	                                tunnel, listening at the compiled endpoint
//
// The gateway's configuration is the compiled one (FwMark 0x4d72, Endpoint,
// AllowedIPs, PersistentKeepalive) with keys generated in the test. ROS
// routes the endpoint addresses to far over a veth underlay and masquerades
// like a home router. A WSS carrier's Endpoint is 127.0.0.1:<local port>;
// there a UDP relay (TestNetnsSniffHelper udprelay, running as root like
// wstunnel) stands in for the local wstunnel client and carries each
// datagram over the underlay to far (the real client carries it over TLS to
// the listener's WireGuard port: not covered here, see
// TestWstunnelRealBinary).
//
// Root only, Linux only, opt-in (MERIDIAN_NETNS_TEST=1), and the kernel must
// create WireGuard interfaces and wireguard-tools must be installed;
// otherwise the tests are skipped and NOT RUN.

// TestNetnsSniffWireGuard: on the remote-access example (one relay with a
// direct and a WSS leg, a standby WSS tunnel to the hub), with the forwarder
// running as SniffUID with CAP_NET_ADMIN only:
//
//	W1 direct WireGuard leg: a by-name connection to a region group (the
//	   name resolved at the group's resolver through the tunnel, the
//	   upstream TCP connection through the tunnel), a second group by TLS
//	   name, address fallback, an IPv6 client; sniff_wg_outer grows (the
//	   kernel attributes the outer packets to the forwarder's uid) and
//	   sniff_denied does not;
//	W2 forged datagrams from the forwarder's uid: with the WireGuard fwmark
//	   to a non-endpoint address, to an endpoint address on another port, to
//	   a loopback port that is no wstunnel port, and without the mark to the
//	   endpoint: refused and counted; with the mark to exactly an endpoint
//	   (or the local wstunnel port): accepted, and they reach only that
//	   WireGuard port, where they are discarded; the tunnel keeps working;
//	W3 mutation: with the outer-packet accepts deleted from the loaded
//	   ruleset, the by-name and the address-fallback connection fail and
//	   sniff_denied grows (the incident); with the ruleset reloaded they work;
//	W4 the WSS leg (loopback carrier form): W1's connections again, through
//	   the wstunnel stand-in; then W3 on that leg.
//	S  the forwarder's own path self-check (sniff/selfcheck.go), asked for
//	   through its status socket exactly as the install's host agent asks:
//	   S0 before the domestic resolver runs, direct fails (ROS answers port
//	   unreachable; the verdict stays ok with a warning); on working tunnels
//	   every target with a resolver passes, direct included (the default
//	   also by a TCP connection through its tunnel); with the outer-packet
//	   accepts removed (the incident) every tunnel target fails and the
//	   install's verdict is default_failed, i.e. the install would have been
//	   rolled back; with the ruleset reloaded it passes again.
//
// Throughout, ROS sees no packet to a foreign test destination.
func TestNetnsSniffWireGuard(t *testing.T) {
	sniffNetnsPrereqs(t, true)
	l := newSniffLabMode(t, sniffLabTopo(t, "us"), true)
	failed := true
	defer func() {
		if failed {
			l.diag()
		}
	}()
	in, must := l.in, l.must
	hk4, hk6, hkRes := l.target("hk")
	us4, _, usRes := l.target("us")
	jp4, _, _ := l.target("jp")
	nftText := l.b.File("nodes/gw/etc/nftables.d/meridian.nft")
	for _, line := range strings.Split(nftText, "\n") {
		if strings.Contains(line, "sniff_wg_outer\" accept") {
			t.Logf("EVIDENCE accept in sniff_confine: %s", strings.TrimSpace(line))
		}
	}
	tunnels := mustTunnels(t, l.topo)
	var westTun Tunnel
	for _, tun := range tunnels {
		if tun.Iface() == l.west {
			westTun = tun
		}
	}
	wssLeg := ""
	for _, tun := range tunnels {
		if tun.LinkID == westTun.LinkID && tun.Mode == "wss" {
			wssLeg = tun.Iface()
		}
	}
	if wssLeg == "" || l.wss[wssLeg] == nil {
		t.Fatalf("the west link %s has no WSS leg in this example", westTun.LinkID)
	}
	directEP := regexp.MustCompile(`(?m)^Endpoint\s*=\s*(\S+)$`).FindStringSubmatch(l.b.File("nodes/gw/etc/wireguard/" + l.west + ".conf"))[1]
	wssEP := regexp.MustCompile(`(?m)^Endpoint\s*=\s*(\S+)$`).FindStringSubmatch(l.b.File("nodes/gw/etc/wireguard/" + wssLeg + ".conf"))[1]
	directAP, wssAP := netip.MustParseAddrPort(directEP), netip.MustParseAddrPort(wssEP)

	// Names: one fresh name per check, so the forwarder resolves it (no
	// cache) through the path under test.
	var answers []string
	name := func(phase, suffix string) string {
		n := phase + "." + suffix
		answers = append(answers, n+"=203.0.113.110,2001:db8:f::10")
		return n
	}
	type check struct{ host, tlsHost, v6Host string }
	checks := map[string]check{}
	for _, p := range []string{"w1", "w2", "w3a", "w3b", "w4", "w4a", "w4b"} {
		checks[p] = check{name(p, "a.example.net"), name(p+"t", "b.example.net"), name(p+"6", "a.example.net")}
	}
	var farListen []string
	for _, r := range l.farResolvers() {
		farListen = append(farListen, "["+r+"]:53")
	}
	l.farDNS = l.helper("far", "dns", []string{strings.Join(farListen, ","), strings.Join(answers, ";")}, false)
	l.farSrv = l.helper("far", "server", []string{":80,:443"}, false)
	time.Sleep(500 * time.Millisecond)

	nftOn := l.write("on.nft", nftText)
	must(in("gw", "nft", "-c", "-f", nftOn)...)
	must(in("gw", "nft", "-f", nftOn)...)
	must(in("gw", "sysctl", "-qw", "net.ipv4.tcp_fwmark_accept=1")...)
	for _, d := range []string{"lists", "run"} {
		if err := os.MkdirAll(l.dir+"/"+d, 0o777); err != nil {
			t.Fatal(err)
		}
		_ = os.Chmod(l.dir+"/"+d, 0o777)
	}
	l.startSniff(l.writeSniffFiles(l.b))
	time.Sleep(500 * time.Millisecond)
	ros0 := l.rosForeign()

	want6 := hk4
	for _, tg := range l.targetsFile().Targets {
		if tg.Mark == l.markOf("hk") && tg.IPv6 {
			want6 = hk6
		}
	}
	expect := func(phase, got, want string) {
		t.Helper()
		if !strings.HasPrefix(got, "OK ") || peerOf(got) != want {
			t.Fatalf("%s: got %q, want peer %s", phase, got, want)
		}
		t.Logf("EVIDENCE %s: %s", phase, got)
	}
	askedAt := func(n string) string {
		for _, q := range l.farDNS.lines() {
			if m := regexp.MustCompile(`server=\[?([^\]\s]+?)\]?:53 from=\S+ name=(\S+)`).FindStringSubmatch(q); m != nil && m[2] == n {
				return m[1]
			}
		}
		return ""
	}
	transfer := func(ifc string) string {
		out, _ := l.sh(in("gw", "wg", "show", ifc, "transfer")...)
		if f := strings.Fields(out); len(f) == 3 {
			return f[1] + "/" + f[2]
		}
		return "?"
	}
	// path runs the working-path checks through tunnel ifc (relay: its WSS
	// stand-in, or nil).
	path := func(phase, ifc string, relay *helperProc) {
		t.Helper()
		c := checks[phase]
		d0, o0 := l.gwCounter("sniff_denied"), l.gwCounter("sniff_wg_outer")
		r0 := 0
		if relay != nil {
			r0 = relayedCount(relay)
		}
		x0 := transfer(ifc)
		expect(phase+" by name, group hk ("+ifc+")", l.client("cli", false, "203.0.113.110:80", "http", c.host), hk4)
		if at := askedAt(c.host); at != hkRes {
			t.Fatalf("%s: %s was asked at %q, want the hk resolver %s", phase, c.host, at, hkRes)
		}
		expect(phase+" by TLS name, us ("+ifc+")", l.client("cli", false, "203.0.113.110:443", "tls", c.tlsHost), us4)
		if at := askedAt(c.tlsHost); at != usRes {
			t.Fatalf("%s: %s was asked at %q, want the us resolver %s", phase, c.tlsHost, at, usRes)
		}
		expect(phase+" address fallback, CIDR rule -> jp ("+ifc+")", l.client("cli", false, "203.0.113.200:443", "raw", "SSH-2.0-test"), jp4)
		expect(phase+" IPv6 client by name -> hk ("+ifc+")", l.client("cli", false, "[2001:db8:f::10]:80", "http", c.v6Host), want6)
		d, o := l.gwCounter("sniff_denied")-d0, l.gwCounter("sniff_wg_outer")-o0
		t.Logf("EVIDENCE %s: outer packets of the forwarder accepted %d (sniff_wg_outer), denied %d (sniff_denied); %s transfer rx/tx %s -> %s", phase, o, d, ifc, x0, transfer(ifc))
		if d != 0 {
			t.Fatalf("%s: sniff_denied grew by %d although every connection succeeded", phase, d)
		}
		if o == 0 {
			t.Fatalf("%s: sniff_wg_outer did not grow: the kernel did not attribute the outer packets to the forwarder's uid", phase)
		}
		if relay != nil {
			r := relayedCount(relay) - r0
			t.Logf("EVIDENCE %s: the WSS stand-in on %s relayed %d datagrams", phase, wssAP, r)
			if r == 0 {
				t.Fatalf("%s: nothing went through the local wstunnel port", phase)
			}
		}
	}
	// tunnelTargets: every target that goes through a tunnel (all but
	// direct), which the incident breaks together.
	tunnelTargets := func() []string {
		var out []string
		for _, tg := range l.targetsFile().Targets {
			if tg.Name != "direct" && !tg.Reject && len(tg.Resolvers) > 0 {
				out = append(out, tg.Name)
			}
		}
		return out
	}
	// mutation deletes the outer-packet accepts from the loaded ruleset:
	// the connections of the incident must fail and be counted; then the
	// ruleset is reloaded and they work again.
	mutation := func(phase, ifc string) {
		t.Helper()
		out := must(in("gw", "nft", "-a", "list", "chain", "inet", "meridian", "sniff_confine")...)
		hs := regexp.MustCompile(`WireGuard outer packets of [^"]*" # handle (\d+)`).FindAllStringSubmatch(out, -1)
		if len(hs) == 0 {
			t.Fatalf("%s: no outer-packet accept in the loaded chain:\n%s", phase, out)
		}
		for _, h := range hs {
			must(in("gw", "nft", "delete", "rule", "inet", "meridian", "sniff_confine", "handle", h[1])...)
		}
		d0 := l.gwCounter("sniff_denied")
		c := checks[phase+"a"]
		start := time.Now()
		got := l.client("cli", false, "203.0.113.110:80", "http", c.host)
		if strings.HasPrefix(got, "OK ") {
			t.Fatalf("%s: without the outer-packet accepts a by-name connection succeeded: %s", phase, got)
		}
		t.Logf("EVIDENCE %s accepts removed (%d rules): by-name connection through %s failed in %v: %s", phase, len(hs), ifc, time.Since(start).Round(time.Millisecond), got)
		start = time.Now()
		got = l.client("cli", false, "203.0.113.200:443", "raw", "SSH-2.0-test")
		if strings.HasPrefix(got, "OK ") {
			t.Fatalf("%s: without the outer-packet accepts an address-fallback connection succeeded: %s", phase, got)
		}
		t.Logf("EVIDENCE %s accepts removed: address-fallback connection failed in %v: %s", phase, time.Since(start).Round(time.Millisecond), got)
		d := l.gwCounter("sniff_denied") - d0
		t.Logf("EVIDENCE %s accepts removed: sniff_denied +%d", phase, d)
		if d == 0 {
			t.Fatalf("%s: the dropped outer packets were not counted", phase)
		}
		_, v := l.selfCheck(phase+" S2 accepts removed (the incident)", tunnelTargets()...)
		t.Logf("EVIDENCE %s S2: the install's verdict is %s: the transaction would have compensated (rolled back)", phase, v.Code)
		must(in("gw", "nft", "-f", nftOn)...)
		expect(phase+" ruleset reloaded: by name again", l.client("cli", false, "203.0.113.110:80", "http", checks[phase+"b"].host), hk4)
		l.selfCheck(phase + " S3 ruleset reloaded")
	}

	// S0: the domestic resolver on ROS (198.18.0.53, the direct target's)
	// is not running yet: the self-check's query to it with the domestic
	// mark leaves (sniff_denied unchanged) and ROS answers ICMP port
	// unreachable (its Udp NoPorts grows): direct fails, the verdict is ok
	// with one warning. Then the resolver starts and direct is ok, like
	// every other target (S1).
	n0, d0 := l.udpNoPorts(), l.gwCounter("sniff_denied")
	l.selfCheck("S0 domestic resolver not running", "direct")
	if n, d := l.udpNoPorts()-n0, l.gwCounter("sniff_denied")-d0; n < 1 || d != 0 {
		t.Fatalf("S0: ROS NoPorts +%d, sniff_denied +%d: want the query to leave and ROS to answer port unreachable", n, d)
	} else {
		t.Logf("EVIDENCE S0: direct \"refused\" is ROS's ICMP port unreachable (Udp NoPorts +%d), not a local drop (sniff_denied +%d)", n, d)
	}
	l.rosDNS = l.helper("ros", "dns", []string{"198.18.0.53:53", "www.home.example.org=192.0.2.140"}, false)
	waitLine(t, l.rosDNS, "READY", 5*time.Second)

	// W1: the direct WireGuard leg.
	path("w1", l.west, nil)
	l.selfCheck("S1 working tunnels")

	// W2: forged datagrams from the forwarder's uid.
	wgMark := hexMark(markUnderlay)
	for _, c := range []struct {
		what, addr, mark string
		pass             bool
		relay            *helperProc
	}{
		{"WireGuard mark, a non-endpoint address, the WireGuard port", fmt.Sprintf("udp:198.51.100.30:%d", directAP.Port()), wgMark, false, nil},
		{"WireGuard mark, the endpoint address, another port", fmt.Sprintf("udp:%s:51999", directAP.Addr()), wgMark, false, nil},
		{"WireGuard mark, loopback, not a wstunnel port", "udp:127.0.0.1:52999", wgMark, false, nil},
		{"no mark, the endpoint and its port", "udp:" + directEP, "0", false, nil},
		{"WireGuard mark, the endpoint and its port", "udp:" + directEP, wgMark, true, nil},
		{"WireGuard mark, the local wstunnel port", "udp:" + wssEP, wgMark, true, l.wss[wssLeg]},
	} {
		d0, o0 := l.gwCounter("sniff_denied"), l.gwCounter("sniff_wg_outer")
		far0 := len(l.farSrv.lines()) + len(l.farDNS.lines())
		r0 := 0
		if c.relay != nil {
			r0 = relayedCount(c.relay)
		}
		got := l.client("gw", true, c.addr, "mark", c.mark)
		time.Sleep(300 * time.Millisecond)
		d, o := l.gwCounter("sniff_denied")-d0, l.gwCounter("sniff_wg_outer")-o0
		if c.pass {
			if !strings.HasPrefix(got, "OK ") || o < 1 || d != 0 {
				t.Fatalf("W2 %s: %q accepted %d denied %d, want sent and accepted", c.what, got, o, d)
			}
			if n := len(l.farSrv.lines()) + len(l.farDNS.lines()); n != far0 {
				t.Fatalf("W2 %s: a far service saw something", c.what)
			}
			extra := ""
			if c.relay != nil {
				extra = fmt.Sprintf("; the stand-in relayed %d datagram(s) to the listener's WireGuard port", relayedCount(c.relay)-r0)
			}
			t.Logf("EVIDENCE W2 forged (%s): %s, accepted (sniff_wg_outer +%d); it can only reach that WireGuard port, which discards it, no far service saw anything%s", c.what, got, o, extra)
			continue
		}
		if strings.HasPrefix(got, "OK ") || d < 1 || o != 0 {
			t.Fatalf("W2 %s: %q denied %d accepted %d, want refused and counted", c.what, got, d, o)
		}
		t.Logf("EVIDENCE W2 forged (%s): refused (%s), sniff_denied +%d", c.what, got, d)
	}
	expect("W2 the tunnel still works after the forged datagrams", l.client("cli", false, "203.0.113.110:80", "http", checks["w2"].host), hk4)
	if out, err := l.sh(in("gw", "setpriv", fmt.Sprintf("--reuid=%d", SniffUID), fmt.Sprintf("--regid=%d", SniffUID), "--clear-groups",
		"--inh-caps=+net_admin", "--ambient-caps=+net_admin", "--", "wg", "show", l.west, "private-key")...); err == nil {
		t.Logf("EVIDENCE CAP_NET_ADMIN: uid %d reads the private key of %s over netlink (%d characters): the confinement guards against a misled forwarder, not against code running in it (docs/architecture.md)", SniffUID, l.west, len(strings.TrimSpace(out)))
	} else {
		t.Logf("EVIDENCE CAP_NET_ADMIN: uid %d could not read the private key of %s: %v %s", SniffUID, l.west, err, strings.TrimSpace(out))
	}

	// W3: the incident, on the direct leg.
	mutation("w3", l.west)

	// W4: the WSS leg (Endpoint 127.0.0.1:<port>, out of lo).
	l.gwPath(wssLeg)
	l.farHome(wssLeg)
	path("w4", wssLeg, l.wss[wssLeg])
	mutation("w4", wssLeg)
	l.gwPath(l.west)
	l.farHome(l.west)

	if d := l.rosForeign() - ros0; d != 0 {
		t.Fatalf("ROS saw %d packets to foreign test destinations", d)
	}
	t.Logf("EVIDENCE no packet to a foreign test destination reached ROS")
	failed = false
	fmt.Fprintln(os.Stderr, "meridian-netns-sniff-wg-test-ok")
}

// TestNetnsSniffWireGuardRelaySharing is TestNetnsSniffRelaySharing over
// kernel WireGuard: two relays with a direct leg each and the backup hub
// over its WSS carrier (the loopback form, through the wstunnel stand-in).
// The forwarder's connections spread over both relays, then follow the
// switch to the backup hub; none of its outer packets is denied.
func TestNetnsSniffWireGuardRelaySharing(t *testing.T) {
	sniffNetnsPrereqs(t, true)
	runSniffRelaySharing(t, true)
	fmt.Fprintln(os.Stderr, "meridian-netns-sniff-wg-sharing-test-ok")
}

// gwPath moves the gateway's tunnel routes (table 102 and the tunnel
// prefixes in main, as the failover script does) to tunnel ifc.
func (l *sniffLab) gwPath(ifc string) {
	for _, c := range [][]string{
		{"ip", "route", "replace", "default", "dev", ifc, "table", "102"},
		{"ip", "-6", "route", "replace", "default", "dev", ifc, "table", "102"},
		{"ip", "route", "replace", "10.66.0.0/16", "dev", ifc},
		{"ip", "-6", "route", "replace", "fd66::/48", "dev", ifc},
	} {
		l.must(l.in("gw", c...)...)
	}
}

// wgTunnels creates the gateway's tunnels as kernel WireGuard interfaces
// with the compiled configuration (keys generated here), their peers in far
// (listening at the compiled endpoint's port, or behind a WSS stand-in), and
// the underlay: ROS routes every endpoint address to far and masquerades.
// The configurations are applied by wgHandshakes, once the routes script
// has installed the endpoint routes.
func (l *sniffLab) wgTunnels() {
	t := l.t
	t.Helper()
	in, must := l.in, l.must
	byIf := map[string]Tunnel{}
	for _, tun := range mustTunnels(t, l.topo) {
		if tun.West.Role == model.RoleGateway || tun.East.Role == model.RoleGateway {
			if _, ok := byIf[tun.Iface()]; !ok {
				byIf[tun.Iface()] = tun
			}
		}
	}
	// The underlay, created inside the namespaces (nothing to leak into the
	// host's namespace if the test stops half-way).
	must(in("ros", "ip", "link", "add", "ul0", "type", "veth", "peer", "name", "ul1", "netns", l.ns["far"])...)
	must(in("ros", "ip", "addr", "add", "192.0.2.1/24", "dev", "ul0")...)
	must(in("ros", "ip", "link", "set", "ul0", "up")...)
	must(in("far", "ip", "addr", "add", "192.0.2.2/24", "dev", "ul1")...)
	must(in("far", "ip", "link", "set", "ul1", "up")...)
	must(in("ros", "sysctl", "-qw", "net.ipv4.ip_forward=1")...)
	must(in("ros", "nft", "-f", l.write("ros-masq.nft", "table ip masq {\n  chain post {\n    type nat hook postrouting priority srcnat; policy accept;\n    oifname \"ul0\" masquerade\n  }\n}\n"))...)
	owned := map[string]bool{}
	own := func(a string) {
		if owned[a] {
			return
		}
		owned[a] = true
		must(in("far", "ip", "addr", "add", a+"/32", "dev", "lo")...)
		must(in("ros", "ip", "route", "add", a+"/32", "via", "192.0.2.2")...)
	}
	epRe := regexp.MustCompile(`(?m)^Endpoint\s*=\s*(\S+)$`)
	mtuRe := regexp.MustCompile(`(?m)^MTU\s*=\s*(\d+)$`)
	l.wgSetconf = map[string]string{}
	for i, ifc := range l.tunnels {
		tun, ok := byIf[ifc]
		if !ok {
			t.Fatalf("%s.conf is no gateway tunnel of the plan", ifc)
		}
		conf := l.b.File("nodes/gw/etc/wireguard/" + ifc + ".conf")
		if !strings.Contains(conf, fmt.Sprintf("\nFwMark = %#x\n", markUnderlay)) {
			t.Fatalf("%s.conf does not carry the WireGuard fwmark %#x", ifc, markUnderlay)
		}
		m := epRe.FindStringSubmatch(conf)
		if m == nil {
			t.Fatalf("%s.conf has no Endpoint (the gateway dials every tunnel of this example)", ifc)
		}
		ep, err := netip.ParseAddrPort(m[1])
		if err != nil {
			t.Fatalf("%s.conf: Endpoint %q: %v", ifc, m[1], err)
		}
		farPort := int(ep.Port())
		if tun.Mode == "wss" {
			// The local wstunnel client's port; the stand-in carries each
			// datagram to the listener (far), on a port of its own there.
			if !ep.Addr().IsLoopback() {
				t.Fatalf("%s: WSS Endpoint %s is not on loopback", ifc, ep)
			}
			farPort = 41000 + i
			own(tun.DialV4())
			l.wss[ifc] = l.helper("gw", "udprelay", []string{ep.String(), net.JoinHostPort(tun.DialV4(), strconv.Itoa(farPort))}, false)
			waitLine(t, l.wss[ifc], "READY", 5*time.Second)
		} else {
			own(ep.Addr().String())
		}
		mtu := "1420"
		if mm := mtuRe.FindStringSubmatch(conf); mm != nil {
			mtu = mm[1]
		}
		gwPriv, gwPub := wgKeyPair(t)
		farPriv, farPub := wgKeyPair(t)
		farKey := l.write("far-"+ifc+".key", farPriv+"\n")
		if err := os.Chmod(farKey, 0o600); err != nil {
			t.Fatal(err)
		}
		must(in("far", "ip", "link", "add", ifc, "type", "wireguard")...)
		must(in("far", "wg", "set", ifc, "listen-port", strconv.Itoa(farPort), "private-key", farKey, "peer", gwPub, "allowed-ips", "0.0.0.0/0,::/0")...)
		must(in("far", "ip", "link", "set", ifc, "mtu", mtu, "up")...)
		must(in("gw", "ip", "link", "add", ifc, "type", "wireguard")...)
		must(in("gw", "ip", "link", "set", ifc, "mtu", mtu)...)
		l.gwConfAddrs(ifc)
		must(in("gw", "ip", "link", "set", ifc, "up")...)
		p := l.write("gw-"+ifc+".setconf", wgSetconfText(t, conf, gwPriv, farPub))
		if err := os.Chmod(p, 0o600); err != nil {
			t.Fatal(err)
		}
		l.wgSetconf[ifc] = p
	}
}

// wgHandshakes applies the gateway's configurations (the interfaces are up,
// so the PersistentKeepalive starts a handshake at once) and waits for a
// handshake on every tunnel.
func (l *sniffLab) wgHandshakes() {
	t := l.t
	t.Helper()
	for _, ifc := range l.tunnels {
		l.must(l.in("gw", "wg", "setconf", ifc, l.wgSetconf[ifc])...)
	}
	deadline := time.Now().Add(20 * time.Second)
	for {
		var pending []string
		for _, ifc := range l.tunnels {
			out, _ := l.sh(l.in("gw", "wg", "show", ifc, "latest-handshakes")...)
			if f := strings.Fields(out); len(f) < 2 || f[1] == "0" {
				pending = append(pending, ifc)
			}
		}
		if len(pending) == 0 {
			t.Logf("EVIDENCE WireGuard handshakes on every gateway tunnel %v (compiled FwMark and Endpoint, test keys)", l.tunnels)
			return
		}
		if time.Now().After(deadline) {
			l.diag()
			t.Fatalf("no WireGuard handshake on %v", pending)
		}
		time.Sleep(200 * time.Millisecond)
	}
}

// wgSetconfText is the compiled configuration as wg setconf input: the
// wg-quick keys (Address, MTU, Table) and comments dropped, the key
// placeholders replaced by the test's keys; FwMark, Endpoint, AllowedIPs,
// ListenPort and PersistentKeepalive exactly as compiled.
func wgSetconfText(t *testing.T, conf, priv, peerPub string) string {
	t.Helper()
	keep := map[string]bool{"ListenPort": true, "FwMark": true, "Endpoint": true, "AllowedIPs": true, "PersistentKeepalive": true}
	var sb strings.Builder
	keys := 0
	for _, line := range strings.Split(conf, "\n") {
		s := strings.TrimSpace(line)
		if s == "[Interface]" || s == "[Peer]" {
			sb.WriteString(s + "\n")
			continue
		}
		k, v, ok := strings.Cut(s, "=")
		if !ok || strings.HasPrefix(s, "#") {
			continue
		}
		k, v = strings.TrimSpace(k), strings.TrimSpace(v)
		switch {
		case k == "PrivateKey":
			sb.WriteString("PrivateKey = " + priv + "\n")
			keys++
		case k == "PublicKey":
			sb.WriteString("PublicKey = " + peerPub + "\n")
			keys++
		case keep[k]:
			fmt.Fprintf(&sb, "%s = %s\n", k, v)
		}
	}
	if keys != 2 {
		t.Fatalf("the compiled configuration has %d key lines, want PrivateKey and one PublicKey:\n%s", keys, conf)
	}
	return sb.String()
}

func wgKeyPair(t *testing.T) (priv, pub string) {
	t.Helper()
	out, err := exec.Command("wg", "genkey").Output()
	if err != nil {
		t.Fatalf("wg genkey: %v", err)
	}
	priv = strings.TrimSpace(string(out))
	cmd := exec.Command("wg", "pubkey")
	cmd.Stdin = strings.NewReader(priv + "\n")
	out, err = cmd.Output()
	if err != nil {
		t.Fatalf("wg pubkey: %v", err)
	}
	return priv, strings.TrimSpace(string(out))
}
