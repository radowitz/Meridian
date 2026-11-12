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
	"testing"

	"github.com/radowitz/meridian/internal/defaults"
	"github.com/radowitz/meridian/internal/model"
	"github.com/radowitz/meridian/internal/remoteaccess"
	"github.com/radowitz/meridian/internal/validate"
)

// raExample is the example topology with remote access on: two enabled
// devices (one with a PSK) and one disabled device. Keys are generated per
// run; privs are the device private keys (they must appear nowhere).
func raExample(t *testing.T) (model.Topology, []string) {
	t.Helper()
	topo := defaults.Example()
	gen := func() remoteaccess.Keypair {
		kp, err := remoteaccess.GenerateKeypair()
		if err != nil {
			t.Fatal(err)
		}
		return kp
	}
	gw := gen()
	ra := &model.RemoteAccess{Enabled: true, Endpoint: "home.example.net", ListenPort: 51900, PublicKey: gw.Public, KeyID: "ra-key-test"}
	privs := []string{gw.Private}
	for i, id := range []string{"dev-aaaa", "dev-bbbb", "dev-cccc"} {
		kp := gen()
		privs = append(privs, kp.Private)
		d := model.RemoteDevice{ID: id, Name: id, Mode: model.RemoteModeFull, Enabled: i != 2, PublicKey: kp.Public,
			IPv4: fmt.Sprintf("10.67.0.%d", i+2), IPv6: fmt.Sprintf("fd67::%d", i+2)}
		if i == 0 {
			d.PSKID = "ra-psk-aaaa"
		}
		ra.Devices = append(ra.Devices, d)
	}
	topo.RemoteAccess = ra
	return topo, privs
}

func mustCompile(t *testing.T, topo model.Topology) *Bundle {
	t.Helper()
	b, err := Compile(topo)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// Remote access off (absent, disabled with devices, disabled and
// half-configured) compiles every node byte for byte like a topology that
// never had it. (The renderers were also compared once against the code
// before this feature: identical; see the task report.)
func TestRemoteDisabledIsByteIdentical(t *testing.T) {
	base := mustCompile(t, defaults.Example()).Canonical()
	on, _ := raExample(t)
	off := on
	off.RemoteAccess = on.RemoteAccess.Clone()
	off.RemoteAccess.Enabled = false
	half := defaults.Example()
	half.RemoteAccess = &model.RemoteAccess{Endpoint: "not a host", ListenPort: 53}
	for name, topo := range map[string]model.Topology{"disabled": off, "half": half} {
		if got := mustCompile(t, topo).Canonical(); got != base {
			t.Errorf("%s: compiled output differs from a topology without remote access", name)
		}
	}
	if mustCompile(t, on).Canonical() == base {
		t.Fatal("enabled remote access changed nothing")
	}
}

// guardRule is one parsed rule of the guard's forward chain.
type guardRule struct {
	iif, oif []string
	markLo   uint32
	markHi   uint32
	hasMark  bool
	daddr    netip.Prefix
	dns      bool
	verdict  string
	text     string
}

var (
	reIfSet  = regexp.MustCompile(`(iifname|oifname) (\{[^}]*\}|"[^"]*")`)
	reMark   = regexp.MustCompile(`meta mark (0x[0-9a-f]+)(?:-(0x[0-9a-f]+))?`)
	reDaddr  = regexp.MustCompile(`ip6? daddr ([0-9a-f.:/]+)`)
	reQuoted = regexp.MustCompile(`"([^"]*)"`)
)

func parseGuard(t *testing.T, guard string) []guardRule {
	t.Helper()
	var out []guardRule
	for _, line := range strings.Split(guard, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "iifname") {
			continue
		}
		r := guardRule{text: line}
		for _, m := range reIfSet.FindAllStringSubmatch(line, -1) {
			var names []string
			for _, q := range reQuoted.FindAllStringSubmatch(m[2], -1) {
				names = append(names, q[1])
			}
			if m[1] == "iifname" {
				r.iif = names
			} else {
				r.oif = names
			}
		}
		if m := reMark.FindStringSubmatch(line); m != nil {
			lo, _ := strconv.ParseUint(m[1], 0, 32)
			hi := lo
			if m[2] != "" {
				hi, _ = strconv.ParseUint(m[2], 0, 32)
			}
			r.markLo, r.markHi, r.hasMark = uint32(lo), uint32(hi), true
		}
		if m := reDaddr.FindStringSubmatch(line); m != nil {
			r.daddr = netip.MustParsePrefix(m[1])
		}
		r.dns = strings.Contains(line, "th dport { 53, 853 }")
		switch {
		case strings.Contains(line, " return"):
			r.verdict = "accept"
		case strings.Contains(line, " drop"):
			r.verdict = "drop"
		default:
			t.Fatalf("guard rule without verdict: %s", line)
		}
		if rule, _, _ := strings.Cut(line, " comment "); strings.Contains(rule, "saddr") || strings.Contains(rule, " ct ") {
			t.Fatalf("unexpected match in guard: %s", line)
		}
		out = append(out, r)
	}
	return out
}

type pkt struct {
	iif, oif string
	mark     uint32
	daddr    string
	dns      bool
}

func in(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

// verdict evaluates the guard chain for p: the first matching rule decides,
// and a packet no rule matches is accepted (policy accept).
func verdict(rules []guardRule, p pkt) string {
	for _, r := range rules {
		if r.iif != nil && !in(r.iif, p.iif) {
			continue
		}
		if r.oif != nil && !in(r.oif, p.oif) {
			continue
		}
		if r.hasMark && (p.mark < r.markLo || p.mark > r.markHi) {
			continue
		}
		if r.daddr.IsValid() && !r.daddr.Contains(netip.MustParseAddr(p.daddr)) {
			continue
		}
		if r.dns && !p.dns {
			continue
		}
		return r.verdict
	}
	return "accept"
}

func TestRemoteGuardIngress(t *testing.T) {
	topo, _ := raExample(t)
	b := mustCompile(t, topo)
	nft := b.File("nodes/gw/etc/nftables.d/meridian.nft")
	guard := nftBlock(t, nft, "meridian_guard")
	boot := b.File("nodes/gw/etc/nftables.d/meridian-guard.nft")
	if nftBlock(t, boot, "meridian_guard") != guard {
		t.Fatal("the early-boot guard differs from the one in meridian.nft")
	}
	if !strings.Contains(guard, `iifname { "eth0", "mra" } counter drop`) {
		t.Fatalf("the remote interface is not in the fail-closed ingress set:\n%s", guard)
	}
	tunnels, err := buildTunnels(topo)
	if err != nil {
		t.Fatal(err)
	}
	for _, i := range gatewayTunnelIfaces(tunnels) {
		if i == model.RemoteAccessIface {
			t.Fatal("mra must not count as a gateway tunnel interface")
		}
	}
	rules := parseGuard(t, guard)
	for _, r := range rules {
		if in(r.oif, "mra") && (r.hasMark || !r.daddr.IsValid() || len(r.iif) != 1 || r.iif[0] != "eth0") {
			t.Fatalf("mra may only be an egress for LAN-to-device by destination: %s", r.text)
		}
	}
	tun := gatewayTunnelIfaces(tunnels)[0]
	const dom, exit, grp = markDomestic, markExitBase, markExitBase + 40
	cases := []struct {
		p    pkt
		want string
		why  string
	}{
		{pkt{"mra", tun, exit, "198.18.0.1", false}, "accept", "device foreign traffic into a tunnel"},
		{pkt{"mra", tun, grp, "2001:db8::1", false}, "accept", "device group mark into a tunnel"},
		{pkt{"mra", "eth0", exit, "198.18.0.1", false}, "drop", "exit-marked device traffic to ROS"},
		{pkt{"mra", "mra", exit, "198.18.0.1", false}, "drop", "exit mark out of mra"},
		{pkt{"mra", "eth0", dom, "114.114.114.114", false}, "accept", "device domestic via ROS"},
		{pkt{"mra", "eth0", dom, "192.168.100.50", false}, "accept", "device to a LAN host"},
		{pkt{"mra", tun, dom, "114.114.114.114", false}, "drop", "domestic mark into a tunnel"},
		{pkt{"mra", "mra", dom, "10.67.0.3", false}, "drop", "device to device"},
		{pkt{"mra", "eth0", 0, "198.18.0.1", false}, "drop", "unclassified device traffic"},
		{pkt{"mra", tun, 0, "198.18.0.1", false}, "drop", "unmarked into a tunnel"},
		{pkt{"mra", "eth0", dom, "114.114.114.114", true}, "drop", "forwarded DNS from a device"},
		{pkt{"eth0", "mra", dom, "10.67.0.2", false}, "accept", "LAN (or a direct reply) to a device"},
		{pkt{"eth0", "mra", dom, "fd67::2", false}, "accept", "LAN to a device over v6"},
		{pkt{"eth0", "mra", dom, "198.18.0.1", false}, "drop", "LAN traffic to a non-device address on mra"},
		{pkt{"eth0", "mra", dom, "10.67.0.2", true}, "drop", "DNS from the LAN towards a device"},
		{pkt{"eth0", "eth0", 0, "198.18.0.1", false}, "drop", "unclassified LAN traffic (unchanged)"},
		{pkt{"eth0", tun, exit, "198.18.0.1", false}, "accept", "LAN foreign traffic (unchanged)"},
		{pkt{tun, "mra", 0, "10.67.0.2", false}, "accept", "tunnel reply to a device (not an ingress)"},
	}
	for _, c := range cases {
		if got := verdict(rules, c.p); got != c.want {
			t.Errorf("%s: %+v got %s want %s", c.why, c.p, got, c.want)
		}
	}
}

func TestRemoteClassifyDNSInputNAT(t *testing.T) {
	topo, _ := raExample(t)
	b := mustCompile(t, topo)
	nft := b.File("nodes/gw/etc/nftables.d/meridian.nft")
	main := nftBlock(t, nft, "meridian")
	chain := func(name string) string {
		i := strings.Index(main, "  chain "+name+" {\n")
		if i < 0 {
			t.Fatalf("no chain %s", name)
		}
		j := strings.Index(main[i:], "\n  }\n")
		return main[i : i+j]
	}
	for _, need := range []string{`iifname { "eth0", "mra" } jump classify`} {
		if !strings.Contains(chain("prerouting"), need) {
			t.Errorf("prerouting missing %q", need)
		}
	}
	classify := strings.Split(chain("classify"), "\n")
	if !strings.HasPrefix(strings.TrimSpace(classify[1]), "ip daddr 10.67.0.0/24 meta mark set 0x64 return") ||
		!strings.HasPrefix(strings.TrimSpace(classify[2]), "ip6 daddr fd67::/64 meta mark set 0x64 return") {
		t.Fatalf("device-bound traffic must be marked first:\n%s", chain("classify"))
	}
	hijack := chain("dns_hijack")
	for _, need := range []string{
		`iifname "mra" meta nfproto ipv4 udp dport { 53, 853 } redirect to :53`,
		`iifname "mra" meta nfproto ipv4 tcp dport 853 redirect to :853`,
		`iifname "mra" meta nfproto ipv6 udp dport { 53, 853 } redirect to :53`,
		`iifname "mra" meta nfproto ipv6 tcp dport 53 redirect to :53`,
	} {
		if !strings.Contains(hijack, need) {
			t.Errorf("dns_hijack missing %q", need)
		}
	}
	input := chain("input")
	for _, need := range []string{
		`iifname "eth0" udp dport 51900 accept`,
		`udp dport 51900 drop`,
		`udp dport { 53, 853 } ip saddr != { 192.168.100.0/24, 10.67.0.0/24 } drop`,
		`fd67::/64 } drop`,
		`tcp dport 8787 ip saddr != 192.168.100.0/24 drop`,
	} {
		if !strings.Contains(input, need) {
			t.Errorf("input missing %q:\n%s", need, input)
		}
	}
	if strings.Index(input, `iifname "eth0" udp dport 51900 accept`) > strings.Index(input, "udp dport 51900 drop") {
		t.Fatal("the LAN accept must precede the drop for other interfaces")
	}
	doh := chain("doh")
	if !strings.Contains(doh, `iifname "mra" ip daddr @doh4 tcp dport 443 reject`) {
		t.Error("DoH addresses not rejected for devices")
	}
	mss := chain("mss")
	for _, need := range []string{`oifname "mra" tcp flags syn meta nfproto ipv4 tcp option maxseg size > 1340`, `iifname "mra" tcp flags syn meta nfproto ipv6 tcp option maxseg size > 1320`} {
		if !strings.Contains(mss, need) {
			t.Errorf("mss missing %q", need)
		}
	}
	snat := chain("transit_snat")
	exits, groups := plans(t, topo)
	for _, m := range markPlans(exits, groups) {
		for _, need := range []string{
			fmt.Sprintf("ip saddr 10.67.0.0/24 meta mark %#x snat to %s", m.Mark, m.TransitV4),
			fmt.Sprintf("ip6 saddr fd67::/64 meta mark %#x snat to %s", m.Mark, m.TransitV6),
		} {
			if !strings.Contains(snat, need) {
				t.Errorf("transit_snat missing %q", need)
			}
		}
	}
	for _, need := range []string{`oifname "eth0" ip saddr 10.67.0.0/24 masquerade`, `oifname "eth0" ip6 saddr fd67::/64 masquerade`} {
		if !strings.Contains(snat, need) {
			t.Errorf("transit_snat missing %q", need)
		}
	}
	if strings.Contains(snat, "192.168.100.0/24 masquerade") || strings.Contains(snat, "ip saddr 192.168.100.0/24 oifname") {
		t.Fatal("LAN clients must stay untranslated on the direct path")
	}
	if nftBin, err := exec.LookPath("nft"); err == nil {
		cmd := exec.Command(nftBin, "-c", "-f", "-")
		cmd.Stdin = strings.NewReader(nft)
		if out, err := cmd.CombinedOutput(); err != nil && !strings.Contains(string(out), "Operation not permitted") {
			t.Fatalf("nft -c: %v\n%s", err, out)
		}
	}
}

func TestRemoteRoutesAndUpOrder(t *testing.T) {
	topo, _ := raExample(t)
	b := mustCompile(t, topo)
	routes := b.File("nodes/gw/usr/local/sbin/meridian-routes.sh")
	for _, need := range []string{
		"ip route replace 10.67.0.0/24 dev 'mra'\n",
		"ip route replace blackhole 10.67.0.0/24 metric 32767\n",
		"ip route replace 10.67.0.0/24 dev 'mra' table 100\n",
		"ip route replace blackhole 10.67.0.0/24 metric 32767 table 100\n",
		"ip -6 route replace fd67::/64 dev 'mra' table 100\n",
		"ip -6 route replace blackhole fd67::/64 metric 32767\n",
		"ip rule add iif 'mra' unreachable priority 17851\n",
		"ip rule add iif 'eth0' unreachable priority 17850\n",
	} {
		if !strings.Contains(routes, need) {
			t.Errorf("routes missing %q", need)
		}
	}
	if strings.Contains(routes, "table 102") && strings.Contains(routes, "10.67.0.0/24 dev 'mra' table 102") {
		t.Fatal("the device pool must not be in the foreign table")
	}
	up := b.File("nodes/gw/usr/local/sbin/meridian-up.sh")
	order := []string{
		"nft -c -f \"$MERIDIAN_NFT\"",
		"meridian-guard-missing",
		"until lan_ready",
		"MERIDIAN_FWD=/etc/meridian/forwarding.conf",
		"for iface in mra m",
		"wg syncconf \"$iface\"",
		"ip address replace 10.67.0.1/24 dev mra",
		"sysctl -w net.ipv6.conf.mra.forwarding=1",
		"/usr/local/sbin/meridian-routes.sh",
	}
	last := -1
	for _, s := range order {
		i := strings.Index(up, s)
		if i < 0 || i < last {
			t.Fatalf("up script order: %q missing or out of order\n%s", s, up)
		}
		last = i
	}
	wg := b.File("nodes/gw/etc/wireguard/mra.conf")
	for _, need := range []string{
		"PrivateKey = __MERIDIAN_SECRET_ra-key-test__",
		"Address = 10.67.0.1/24, fd67::1/64",
		"ListenPort = 51900", "Table = off", "MTU = 1380",
		"PresharedKey = __MERIDIAN_SECRET_ra-psk-aaaa__",
		"AllowedIPs = 10.67.0.2/32, fd67::2/128",
		"AllowedIPs = 10.67.0.3/32, fd67::3/128",
	} {
		if !strings.Contains(wg, need) {
			t.Errorf("mra.conf missing %q", need)
		}
	}
	if strings.Contains(wg, "10.67.0.4/32") || strings.Contains(wg, topo.RemoteAccess.Devices[2].PublicKey) {
		t.Fatal("a disabled device must not be a peer")
	}
	for _, p := range b.PeerKeyProblems("gw") {
		if p.Iface == "mra" {
			t.Fatalf("device peer key problem: %+v", p)
		}
	}
	for path := range b.Files {
		if strings.Contains(path, "mra") && !strings.HasPrefix(path, "nodes/gw/") {
			t.Fatalf("remote access leaked onto another node: %s", path)
		}
	}
	if len(remoteRuntimeFilesOutsideGW(b)) != 0 {
		t.Fatal("other nodes changed with remote access on")
	}
}

// remoteRuntimeFilesOutsideGW lists non-gateway files that mention the pools.
func remoteRuntimeFilesOutsideGW(b *Bundle) []string {
	var out []string
	for p, body := range b.Files {
		if !strings.HasPrefix(p, "nodes/gw/") && (strings.Contains(body, "10.67.0.") || strings.Contains(body, "fd67::")) {
			out = append(out, p)
		}
	}
	return out
}

// No secret value (device private keys, the gateway's remote-access key)
// appears anywhere in the compiled bundle; only placeholders do.
func TestRemoteBundleCarriesNoSecrets(t *testing.T) {
	topo, privs := raExample(t)
	canon := mustCompile(t, topo).Canonical()
	for _, p := range privs {
		if strings.Contains(canon, p) {
			t.Fatal("a private key reached the bundle")
		}
	}
	if !strings.Contains(canon, model.SecretPlaceholder("ra-key-test")) {
		t.Fatal("no placeholder for the remote-access key")
	}
}

// Every port the compiled gateway binds is one validation knows about, so
// the listen-port conflict check cannot miss a compiler allocation.
func TestGatewayPortsCoverCompiledPorts(t *testing.T) {
	topo := defaults.Example()
	b := mustCompile(t, topo)
	known := validate.GatewayPorts(topo)
	listen := regexp.MustCompile(`(?m)^ListenPort = (\d+)$`)
	local := regexp.MustCompile(`udp://127\.0\.0\.1:(\d+):`)
	seen := 0
	for p, body := range b.Files {
		if !strings.HasPrefix(p, "nodes/gw/") {
			continue
		}
		for _, re := range []*regexp.Regexp{listen, local} {
			for _, m := range re.FindAllStringSubmatch(body, -1) {
				n, _ := strconv.Atoi(m[1])
				seen++
				if _, ok := known[n]; !ok {
					t.Errorf("%s binds %d, unknown to validate.GatewayPorts", p, n)
				}
			}
		}
	}
	tunnels, _ := buildTunnels(topo)
	for _, tun := range tunnels {
		if tun.West.Role != model.RoleGateway && tun.East.Role != model.RoleGateway {
			continue
		}
		seen++
		if _, ok := known[tun.WGPort]; !ok {
			t.Errorf("tunnel %s port %d unknown to validation", tun.LinkID, tun.WGPort)
		}
		if tun.ClientUDP != 0 {
			if _, ok := known[tun.ClientUDP]; !ok {
				t.Errorf("tunnel %s local port %d unknown to validation", tun.LinkID, tun.ClientUDP)
			}
		}
	}
	if seen == 0 {
		t.Fatal("no gateway ports found; the test is not looking at the right files")
	}
	if _, ok := known[panelPort(topo)]; !ok {
		t.Fatal("panel port unknown to validation")
	}
}

// The remote block of the up script aligns mra's addresses: a stale
// address from an old pool is removed, the configured ones are kept.
func TestRemoteUpAlignsAddresses(t *testing.T) {
	if !bashOK() {
		t.Skip("bash not available")
	}
	topo, _ := raExample(t)
	dir := t.TempDir()
	log := filepath.Join(dir, "log")
	stub := `#!/bin/bash
echo "$0 $*" >> ` + log + `
case "$*" in
  "-o address show dev mra scope global")
    echo "5: mra    inet 10.67.0.1/24 scope global mra"
    echo "5: mra    inet 10.99.0.1/24 scope global mra"
    echo "5: mra    inet6 fd67::1/64 scope global"
    echo "5: mra    inet6 fd99::1/64 scope global" ;;
esac
`
	for _, bin := range []string{"ip", "sysctl"} {
		if err := os.WriteFile(filepath.Join(dir, bin), []byte(stub), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	cmd := exec.Command("bash", "-c", "set -euo pipefail\n"+remoteUpCommands(planRemote(topo)))
	cmd.Env = append(os.Environ(), "PATH="+dir+":"+os.Getenv("PATH"))
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	got, _ := os.ReadFile(log)
	for _, need := range []string{"address del 10.99.0.1/24 dev mra", "address del fd99::1/64 dev mra", "ip address replace 10.67.0.1/24 dev mra", "net.ipv6.conf.mra.forwarding=1"} {
		if !strings.Contains(string(got), need) {
			t.Errorf("missing %q in\n%s", need, got)
		}
	}
	for _, keep := range []string{"del 10.67.0.1/24", "del fd67::1/64"} {
		if strings.Contains(string(got), keep) {
			t.Errorf("configured address removed: %s", keep)
		}
	}
}
