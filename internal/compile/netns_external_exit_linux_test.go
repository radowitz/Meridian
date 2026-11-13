//go:build linux

package compile

import (
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/radowitz/meridian/internal/defaults"
	"github.com/radowitz/meridian/internal/model"
)

// p2SOCKSPy USER PASS ADDR PORT: a SOCKS5 server (RFC 1928, CONNECT only,
// username/password RFC 1929 required) that relays to the requested IPv4
// address and prints every CONNECT target.
const p2SOCKSPy = `import socket, struct, sys, threading
user, pw, addr, port = sys.argv[1].encode(), sys.argv[2].encode(), sys.argv[3], int(sys.argv[4])
def rx(c, n):
    b = b""
    while len(b) < n:
        d = c.recv(n - len(b))
        if not d:
            raise EOFError()
        b += d
    return b
def pipe(a, b):
    try:
        while True:
            d = a.recv(4096)
            if not d:
                break
            b.sendall(d)
    except Exception:
        pass
    for s in (a, b):
        try:
            s.shutdown(socket.SHUT_RDWR)
        except Exception:
            pass
def serve(c):
    try:
        v, n = rx(c, 2)
        if v != 5 or 2 not in rx(c, n):
            c.sendall(b"\x05\xff"); return
        c.sendall(b"\x05\x02")
        rx(c, 1)
        u = rx(c, rx(c, 1)[0]); p = rx(c, rx(c, 1)[0])
        if u != user or p != pw:
            print("auth refused", flush=True)
            c.sendall(b"\x01\x01"); return
        c.sendall(b"\x01\x00")
        _, cmd, _, at = rx(c, 4)
        if cmd != 1 or at != 1:
            c.sendall(b"\x05\x07\x00\x01" + b"\x00" * 6); return
        host = socket.inet_ntoa(rx(c, 4)); dport = struct.unpack(">H", rx(c, 2))[0]
        print("connect", host, dport, flush=True)
        up = socket.create_connection((host, dport), timeout=5)
        c.sendall(b"\x05\x00\x00\x01" + b"\x00" * 6)
        threading.Thread(target=pipe, args=(c, up), daemon=True).start()
        pipe(up, c)
    except Exception as e:
        print("error", e, flush=True)
    finally:
        c.close()
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind((addr, port))
s.listen(16)
while True:
    c, _ = s.accept()
    threading.Thread(target=serve, args=(c,), daemon=True).start()
`

// p2DNSTCPPy ADDR: DNS over TCP on ADDR:53 answering every A query with
// 203.0.113.77 (stands in for 1.1.1.1 / 8.8.8.8 behind the proxy).
const p2DNSTCPPy = `import socket, struct, sys, threading
def reply(q):
    i = 12
    while q[i] != 0:
        i += q[i] + 1
    qend = i + 5
    qtype = struct.unpack(">H", q[i+1:i+3])[0]
    if qtype != 1:
        return q[:2] + struct.pack(">HHHHH", 0x8180, 1, 0, 0, 0) + q[12:qend]
    return q[:2] + struct.pack(">HHHHH", 0x8180, 1, 1, 0, 0) + q[12:qend] + struct.pack(">HHHIH", 0xC00C, 1, 1, 60, 4) + socket.inet_aton("203.0.113.77")
def serve(c):
    try:
        while True:
            h = c.recv(2)
            if len(h) < 2:
                return
            n = struct.unpack(">H", h)[0]
            q = b""
            while len(q) < n:
                q += c.recv(n - len(q))
            print("query", flush=True)
            r = reply(q)
            c.sendall(struct.pack(">H", len(r)) + r)
    except Exception:
        pass
    finally:
        c.close()
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind((sys.argv[1], 53))
s.listen(16)
while True:
    c, _ = s.accept()
    threading.Thread(target=serve, args=(c,), daemon=True).start()
`

// TestNetnsExternalExit is the runtime check of an external SOCKS exit
// (docs/architecture.md「外部 SOCKS 出口」) on defaults.ExternalExample: hubs
// ix and hk5, carrier dc2, external exit my1 (group my). Namespaces: home
// (west of the hubs, p2Lab), ix, hk5, dc1, dc2, "router" (the device the
// panel does not manage: its own tunnel to dc2 is a plain veth named wg9
// on dc2 with 192.0.2.65/30 there and 192.0.2.66 on the router, and a
// SOCKS5 stand-in with username/password on 192.0.2.66:1080), net (the
// data server 192.0.2.80:8080 and DNS-over-TCP stand-ins on 1.1.1.1 and
// 8.8.8.8). dc2 runs its compiled nft and routes, the pinned gost with the
// compiled redirector configuration (credential injected as the install
// boundary does), the compiled health probe, and — when
// MERIDIAN_SMARTDNS_BIN is set — the pinned SmartDNS with its compiled
// configuration. The primary hub's group switching is its compiled
// failover logic.
//
// Phases:
//  1. proxy up: TCP from my1's mark and from group my reaches the server
//     through the router (the server sees the router's WAN address); UDP
//     (QUIC-like) is refused at once (ICMP port unreachable from dc2);
//     group my's resolver and my1's hub-independent resolver address answer
//     through the proxy over TCP (SmartDNS); the health address is present
//     and the hub keeps my1 up. Zero packets of my1 on dc2's WAN: no TCP to
//     the server, no UDP, no DNS.
//  2. proxy down: TCP fails, names fail, the health address goes away, the
//     hub marks my1 down (group my alerts, nothing else to switch to).
//     Still zero packets on dc2's WAN.
//  3. the router's tunnel gone (wg9 deleted on dc2, proxy back up): the
//     redirector cannot reach the proxy (dc2 refuses any other interface),
//     TCP fails, nothing to 192.0.2.66 leaves dc2's WAN.
//
// Root only, Linux only, opt-in (MERIDIAN_NETNS_TEST=1 and
// MERIDIAN_GOST_BIN; MERIDIAN_SMARTDNS_BIN adds the DNS checks); needs ip,
// nft, ping, bash and python3. A pass prints "EVIDENCE <phase>: …" lines.
// Not executed on a real host or with the real router.
func TestNetnsExternalExit(t *testing.T) {
	netnsPrereqs(t)
	if _, err := exec.LookPath("python3"); err != nil {
		t.Skip("python3 not installed")
	}
	gost := os.Getenv("MERIDIAN_GOST_BIN")
	if gost == "" {
		t.Skip("MERIDIAN_GOST_BIN not set (path to the pinned gost 3.2.6)")
	}
	smartdns := os.Getenv("MERIDIAN_SMARTDNS_BIN")
	topo := defaults.ExternalExample()
	model.MigrateRegionGroups(&topo)
	b := mustCompile(t, topo)
	tunnels := mustTunnels(t, topo)
	exits, groups := plans(t, topo)
	my := mustGroup(t, groups, "my")
	my1, _ := exitByID(exits, "my1")
	if !my.Dynamic || !my1.External {
		t.Fatalf("group my must be switchable onto the external exit: %+v", my.Policy())
	}
	link := func(id string) Tunnel {
		for _, tun := range tunnels {
			if tun.LinkID == id {
				return tun
			}
		}
		t.Fatalf("no tunnel for link %s", id)
		return Tunnel{}
	}
	aliIX, gwHk5 := link("ali-ix"), link("gw-hk5")
	ixDC1, ixDC2, hk5DC1, hk5DC2 := link("ix-dc1"), link("ix-dc2"), link("hk5-dc1"), link("hk5-dc2")

	l := newP2Lab(t, b)
	l.add(map[string]string{"home": "", "ix": "ix", "hk5": "hk5", "dc1": "dc1", "dc2": "dc2", "router": "", "net": ""})
	l.p2p("home", "ali", "ix", "ix", aliIX.Iface())
	l.p2p("home", "gw", "hk5", "hk5", gwHk5.Iface())
	l.p2p("ix", "ix", "dc1", "dc1", ixDC1.Iface())
	l.p2p("ix", "ix", "dc2", "dc2", ixDC2.Iface())
	l.p2p("hk5", "hk5", "dc1", "dc1", hk5DC1.Iface())
	l.p2p("hk5", "hk5", "dc2", "dc2", hk5DC2.Iface())
	have := map[string]bool{}
	for _, tun := range []Tunnel{aliIX, gwHk5, ixDC1, ixDC2, hk5DC1, hk5DC2} {
		have[tun.Iface()] = true
	}
	for _, n := range []string{"ix", "hk5", "dc1", "dc2"} {
		l.dummies(n, have)
	}
	for _, n := range []string{"ix", "hk5"} {
		l.must(l.in(n, "ip", "link", "add", "eth0", "type", "dummy")...)
		l.must(l.in(n, "ip", "link", "set", "eth0", "up")...)
		l.must(l.in(n, "ip", "route", "add", "default", "dev", "eth0")...)
	}
	l.wan("dc1", 1)
	l.wan("dc2", 2)
	l.wan("router", 9)
	// The router's own tunnel to the carrier: unmanaged (a veth here).
	x, y := "pt0"+l.sfx, "pt1"+l.sfx
	l.must("ip", "link", "add", x, "type", "veth", "peer", "name", y)
	l.must("ip", "link", "set", x, "netns", l.ns["dc2"])
	l.must("ip", "link", "set", y, "netns", l.ns["router"])
	l.must(l.in("dc2", "ip", "link", "set", x, "name", "wg9")...)
	l.must(l.in("dc2", "ip", "addr", "add", "192.0.2.65/30", "dev", "wg9")...)
	l.must(l.in("dc2", "ip", "link", "set", "wg9", "up")...)
	l.must(l.in("router", "ip", "addr", "add", "192.0.2.66/30", "dev", y)...)
	l.must(l.in("router", "ip", "link", "set", y, "up")...)
	l.must(l.in("net", "ip", "link", "add", "srv", "type", "dummy")...)
	for _, a := range []string{"192.0.2.80/32", ExtUpstream1 + "/32", ExtUpstream2 + "/32"} {
		l.must(l.in("net", "ip", "addr", "add", a, "dev", "srv")...)
	}
	l.must(l.in("net", "ip", "link", "set", "srv", "up")...)
	run := map[string]string{}
	for _, n := range []string{"ix", "hk5", "dc1", "dc2"} {
		run[n] = l.apply(n)
	}
	for _, a := range []string{my.TransitV4, my1.TransitV4} {
		l.must(l.in("home", "ip", "addr", "add", a+"/32", "dev", "lo")...)
	}
	l.must(l.in("home", "ip", "-6", "addr", "add", my.TransitV6+"/128", "dev", "lo", "nodad")...)
	for _, d := range []string{"192.0.2.80/32", "192.0.2.81/32"} {
		l.must(l.in("home", "ip", "route", "replace", d, "dev", aliIX.Iface())...)
	}
	l.must(l.in("home", "ip", "-6", "route", "replace", "fd66::53:0/112", "dev", aliIX.Iface())...)
	l.must(l.in("home", "ip", "-6", "route", "replace", "fd66::54:0/112", "dev", aliIX.Iface())...)
	homeULA := aliIX.WestULA

	l.obs("dc2", fmt.Sprintf(`  counter wan_tcp {}
  counter wan_udp {}
  counter wan_dns {}
  counter wan_proxy {}
  chain post {
    type filter hook postrouting priority 400; policy accept;
    oifname "eth0" tcp dport 8080 counter name "wan_tcp"
    oifname "eth0" udp dport 9999 counter name "wan_udp"
    oifname "eth0" meta l4proto { tcp, udp } th dport 53 counter name "wan_dns"
    oifname "eth0" ip daddr %s counter name "wan_proxy"
  }
`, topo.Nodes[len(topo.Nodes)-1].External.SOCKSAddress))
	l.obs("net", "  counter udpin {}\n  chain prein {\n    type filter hook prerouting priority -400; policy accept;\n    udp dport 9999 counter name \"udpin\"\n  }\n")

	const user, pass = "lab-user", "lab-Pa55.w"
	socksPy := l.write("socks.py", p2SOCKSPy)
	socks := l.start("router", "python3", socksPy, user, pass, "192.0.2.66", "1080")
	l.start("net", "python3", l.write("server.py", netnsServerPy), "192.0.2.80", "8080")
	dnsPy := l.write("dnstcp.py", p2DNSTCPPy)
	l.start("net", "python3", dnsPy, ExtUpstream1)
	l.start("net", "python3", dnsPy, ExtUpstream2)
	// The redirector, with the credential injected as at the install
	// boundary (the compiled file carries placeholders only).
	conf := b.File("nodes/dc2" + ExtProxyConfig)
	if strings.Contains(conf, user) || strings.Contains(conf, pass) {
		t.Fatal("compiled redirector configuration carries a credential")
	}
	conf = strings.ReplaceAll(conf, "__MERIDIAN_SECRET_socks-example1-user__", user)
	conf = strings.ReplaceAll(conf, "__MERIDIAN_SECRET_socks-example1-pass__", pass)
	l.start("dc2", gost, "-C", l.write("gost.yaml", conf))
	if smartdns != "" {
		l.start("dc2", smartdns, "-f", "-x", "-p", "-", "-c", l.write("smartdns.conf", b.File("nodes/dc2/etc/smartdns/smartdns.conf")))
	}
	time.Sleep(2 * time.Second)
	hs := b.File("nodes/dc2" + ExtHealthScript)
	cut := strings.Index(hs, "while true; do")
	if cut < 0 {
		t.Fatal("no loop in the health script")
	}
	health := l.write("health-once.sh", strings.ReplaceAll(hs[:cut], "/run/meridian", run["dc2"])+"ext_all\n")
	healthOnce := func() string {
		out, _ := l.sh(l.in("dc2", "bash", health)...)
		return strings.TrimSpace(out)
	}
	healthAddr := func() bool {
		out := l.must(l.in("dc2", "ip", "-o", "addr", "show", "dev", "lo")...)
		return strings.Contains(out, " "+my1.PeerV4+"/32 ")
	}
	connectPy, udpPy, queryPy := l.write("connect.py", p2ConnectPy), l.write("udp.py", p2UDPPy), l.write("query.py", p2QueryPy)
	connect := func(src string) string {
		out, _ := l.sh(l.in("home", "python3", connectPy, src, "192.0.2.80", "8080")...)
		return strings.TrimSpace(out)
	}
	udp := func(src string) string {
		out, _ := l.sh(l.in("home", "python3", udpPy, src, "192.0.2.80", "9999")...)
		return strings.TrimSpace(out)
	}
	query := func(src, server, name string) string {
		out, _ := l.sh(l.in("home", "python3", queryPy, src, server, name)...)
		return strings.TrimSpace(out)
	}
	steps := l.hubDriver("ix", run["ix"])

	fails := 0
	check := func(phase, what, got, want string) {
		t.Helper()
		if got != want {
			fails++
			t.Errorf("%s: %s: got %q, want %q", phase, what, got, want)
		} else {
			t.Logf("EVIDENCE %s: %s: %s", phase, what, got)
		}
	}
	notOK := func(phase, what, got string) {
		t.Helper()
		if strings.HasPrefix(got, "100.64.") || strings.Count(got, ".") == 3 {
			fails++
			t.Errorf("%s: %s: got %q, want a failure", phase, what, got)
		} else {
			t.Logf("EVIDENCE %s: %s: fails (%s)", phase, what, got)
		}
	}
	zeroWAN := func(phase string) {
		t.Helper()
		for _, c := range []string{"wan_tcp", "wan_udp", "wan_dns", "wan_proxy"} {
			if v := l.counter("dc2", c); v != 0 {
				fails++
				t.Errorf("%s: dc2 WAN counter %s = %d, want 0", phase, c, v)
			}
		}
		if v := l.counter("net", "udpin"); v != 0 {
			fails++
			t.Errorf("%s: %d UDP packets of the exit reached the Internet", phase, v)
		}
		if fails == 0 {
			t.Logf("EVIDENCE %s: zero packets of my1 on dc2's WAN (TCP, UDP, DNS, proxy address) and zero UDP on the Internet", phase)
		}
	}
	finish := func(phase string) {
		t.Helper()
		if fails > 0 {
			l.diag([][]string{
				{"ix", "ip", "route", "show", "table", strconv.Itoa(my.Table)}, {"ix", "nft", "list", "ruleset"},
				{"dc2", "ip", "rule"}, {"dc2", "ip", "route"}, {"dc2", "ip", "-o", "addr"}, {"dc2", "nft", "list", "ruleset"}, {"dc2", "ss", "-lntup"},
				{"router", "ip", "route"},
			})
			t.Fatalf("%s: %d checks failed", phase, fails)
		}
	}

	// 1. Proxy up.
	check("proxy up", "health probe", healthOnce(), "meridian-ext-health: my1 up (TCP through its proxy answers); health address "+my1.PeerV4+" present")
	steps(2)
	check("proxy up", "hub report: group my hop", groupReport(run["ix"], "my", "hop"), "my1")
	check("proxy up", "TCP from my1's mark (server sees the router)", connect(my1.TransitV4), l.wans["router"])
	check("proxy up", "TCP from group my", connect(my.TransitV4), l.wans["router"])
	check("proxy up", "UDP (QUIC-like) from my1's mark", udp(my1.TransitV4), "REFUSED")
	check("proxy up", "UDP from group my", udp(my.TransitV4), "REFUSED")
	if smartdns != "" {
		check("proxy up", "group my resolver (through the proxy over TCP)", query(my.TransitV6, my.Resolver, "my.example.net"), "203.0.113.77")
		check("proxy up", "my1's hub-independent resolver address", query(homeULA, my1.Resolver, "my-own.example.net"), "203.0.113.77")
	} else {
		t.Log("MERIDIAN_SMARTDNS_BIN not set: DNS through the proxy not exercised")
	}
	zeroWAN("proxy up")
	finish("proxy up")

	// 2. Proxy down.
	_ = socks.Process.Kill()
	_, _ = socks.Process.Wait()
	notOK("proxy down", "TCP from my1's mark", connect(my1.TransitV4))
	check("proxy down", "health probe", healthOnce(), "meridian-ext-health: my1 down (no TCP answer through its proxy within 8s); health address "+my1.PeerV4+" removed, the hubs stop using it")
	if healthAddr() {
		fails++
		t.Error("proxy down: health address still on dc2")
	}
	steps(4)
	check("proxy down", "hub report: group my alert (nothing to switch to)", groupReport(run["ix"], "my", "alert"), "1")
	notOK("proxy down", "TCP from group my", connect(my.TransitV4))
	check("proxy down", "UDP from my1's mark", udp(my1.TransitV4), "REFUSED")
	if smartdns != "" {
		notOK("proxy down", "group my resolver (a name not cached before)", query(my.TransitV6, my.Resolver, "down.example.net"))
	}
	zeroWAN("proxy down")
	finish("proxy down")

	// 3. The router's tunnel gone, proxy back: dc2 never reaches the proxy
	// another way.
	l.start("router", "python3", socksPy, user, pass, "192.0.2.66", "1080")
	time.Sleep(time.Second)
	l.must(l.in("dc2", "ip", "link", "del", "wg9")...)
	notOK("tunnel gone", "TCP from my1's mark", connect(my1.TransitV4))
	check("tunnel gone", "health probe stays down (no change logged)", healthOnce(), "")
	if healthAddr() {
		fails++
		t.Error("tunnel gone: health address back on dc2")
	}
	zeroWAN("tunnel gone")
	finish("tunnel gone")
}
