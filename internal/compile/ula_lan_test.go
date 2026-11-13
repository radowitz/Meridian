package compile

import (
	"fmt"
	"net/netip"
	"regexp"
	"strings"
	"testing"

	"github.com/radowitz/meridian/internal/model"
	"github.com/radowitz/meridian/internal/remoteaccess"
)

// ulaLAN is a ULA home-LAN prefix (RFC 4193 style, not a real network).
const ulaLAN = "fd12:3456:789a:1::/64"

// ulaLANExample is raExample with the LAN IPv6 prefix moved into fc00::/7.
func ulaLANExample(t *testing.T) model.Topology {
	t.Helper()
	topo, _ := raExample(t)
	topo.Settings.LANIPv6Prefix = ulaLAN
	for i := range topo.Nodes {
		if topo.Nodes[i].Role == model.RoleGateway {
			topo.Nodes[i].LANIPv6Prefix = ulaLAN
		}
	}
	return topo
}

// classifyChain returns the rule lines of chain classify in inet meridian.
func classifyChain(t *testing.T, nft string) []string {
	t.Helper()
	main := nftBlock(t, nft, "meridian")
	i := strings.Index(main, "  chain classify {\n")
	if i < 0 {
		t.Fatal("no chain classify")
	}
	j := strings.Index(main[i:], "\n  }\n")
	var out []string
	for _, l := range strings.Split(main[i:i+j], "\n")[1:] {
		out = append(out, strings.TrimSpace(l))
	}
	return out
}

var (
	reClsDaddr6 = regexp.MustCompile(`^ip6 daddr (\{ [^}]* \}|\S+) `)
	reClsMark   = regexp.MustCompile(`meta mark set (0x[0-9a-f]+) return`)
)

// classify6 evaluates the classify chain for an IPv6 destination: "drop",
// "unmarked" (a bare return) or the mark set. Named sets (@…) are taken to
// be empty, which is what a fresh install has before any list update.
func classify6(t *testing.T, chain []string, daddr string) string {
	t.Helper()
	a := netip.MustParseAddr(daddr)
	for _, l := range chain {
		rule, _, _ := strings.Cut(l, " comment ")
		match := false
		switch {
		case strings.HasPrefix(rule, "meta nfproto ipv6 "):
			match = true
		case strings.HasPrefix(rule, "ip6 daddr "):
			m := reClsDaddr6.FindStringSubmatch(rule)
			if m == nil {
				t.Fatalf("unparsed classify rule: %s", l)
			}
			if strings.HasPrefix(m[1], "@") {
				continue
			}
			for _, e := range strings.Split(strings.Trim(m[1], "{} "), ",") {
				e = strings.TrimSpace(e)
				p, err := netip.ParsePrefix(e)
				if err != nil {
					p = netip.PrefixFrom(netip.MustParseAddr(e), 128)
				}
				match = match || p.Contains(a)
			}
		default:
			// IPv4 rules, and rules with a source or MAC predicate (none
			// in these topologies match an IPv6 destination by prefix).
			continue
		}
		if !match {
			continue
		}
		switch {
		case strings.HasSuffix(rule, " drop"):
			return "drop"
		case reClsMark.MatchString(rule):
			return reClsMark.FindStringSubmatch(rule)[1]
		case strings.HasSuffix(rule, " return"):
			return "unmarked"
		}
		t.Fatalf("classify rule without verdict: %s", l)
	}
	return "unmarked"
}

// TestULALANClassify: with a ULA LAN prefix, home hosts are classified
// domestic ahead of the ULA drop, in both directions of device <-> LAN
// host, while tunnel, transit and every other ULA destination is still
// dropped; the rule is exactly as wide as the configured prefix.
func TestULALANClassify(t *testing.T) {
	topo := ulaLANExample(t)
	b := mustCompile(t, topo)
	nft := b.File("nodes/gw/etc/nftables.d/meridian.nft")
	chain := classifyChain(t, nft)
	dom := fmt.Sprintf("%#x", markDomestic)

	want := fmt.Sprintf(`ip6 daddr %s meta mark set %s return comment "ULA LAN prefix: home hosts only"`, ulaLAN, dom)
	at, drop, n := -1, -1, 0
	for i, l := range chain {
		if strings.Contains(l, "fd12:3456:789a:") {
			n++
		}
		if l == want {
			at = i
		}
		if strings.HasPrefix(l, "ip6 daddr fc00::/7 drop") {
			drop = i
		}
	}
	if at < 0 || drop < 0 || at != drop-1 || n != 1 {
		t.Fatalf("want exactly one LAN rule %q right ahead of the ULA drop:\n%s", want, strings.Join(chain, "\n"))
	}
	// Only the device pool and the LAN prefix come before the drop for v6.
	for _, l := range chain[:drop] {
		if strings.Contains(l, "ip6") && !strings.HasPrefix(l, "ip6 daddr fd67::/64 meta mark set 0x64 return") && l != want {
			t.Fatalf("unexpected IPv6 rule ahead of the ULA drop: %s", l)
		}
	}

	cases := []struct{ daddr, want, why string }{
		{"fd12:3456:789a:1::50", dom, "device (or LAN client) to a home host"},
		{"fd12:3456:789a:1::88", dom, "LAN host's reply to the gateway's address (before de-NAT)"},
		{"fd12:3456:789a:1:ffff:ffff:ffff:ffff", dom, "last address of the LAN prefix"},
		{"fd67::2", dom, "LAN host to a device"},
		{"fd12:3456:789a:2::1", "drop", "next /64 after the LAN prefix"},
		{"fd12:3456:789a:0:ffff:ffff:ffff:ffff", "drop", "address just below the LAN prefix"},
		{"fd12:3456:789b::1", "drop", "same /40, other ULA"},
		{"fd66::1", "drop", "tunnel ULA (ula_prefix fd66::/48)"},
		{"fd66:0:0:2::2", "drop", "a link's tunnel address"},
		{"fd66:0:0:ff::1", "drop", "transit /64"},
		{"fd67:0:0:1::2", "drop", "outside the device pool"},
		{"fd00::1", "drop", "unrelated ULA"},
		{"fc00::1", "drop", "unrelated fc00::/8 ULA"},
		{"2001:db8:ffff::1", fmt.Sprintf("%#x", defaultMark(t, nft)), "foreign v6 takes the default exit"},
	}
	for _, c := range cases {
		if got := classify6(t, chain, c.daddr); got != c.want {
			t.Errorf("%s (%s): classify gives %s, want %s", c.why, c.daddr, got, c.want)
		}
	}

	// The guard admits both directions and a LAN-to-LAN hairpin, nothing else.
	rules := parseGuard(t, nftBlock(t, nft, "meridian_guard"))
	tunnels, err := buildTunnels(topo)
	if err != nil {
		t.Fatal(err)
	}
	tun := gatewayTunnelIfaces(tunnels)[0]
	for _, c := range []struct {
		p    pkt
		want string
		why  string
	}{
		{pkt{"mra", "eth0", markDomestic, "fd12:3456:789a:1::50", false}, "accept", "device to a ULA home host"},
		{pkt{"eth0", "mra", markDomestic, "fd67::2", false}, "accept", "home host (reply or new) to a device"},
		{pkt{"eth0", "eth0", markDomestic, "fd12:3456:789a:1::50", false}, "accept", "LAN client to a LAN ULA host through the gateway"},
		{pkt{"mra", tun, markDomestic, "fd12:3456:789a:1::50", false}, "drop", "domestic LAN destination into a tunnel"},
		{pkt{"mra", "mra", markDomestic, "fd67::3", false}, "drop", "device to device"},
		{pkt{"mra", "eth0", 0, "fd12:3456:789a:2::1", false}, "drop", "an unmarked ULA (were classify missing)"},
	} {
		if got := verdict(rules, c.p); got != c.want {
			t.Errorf("guard, %s: got %s want %s", c.why, got, c.want)
		}
	}

	// The rest of the path: the prefix is on-link on the LAN NIC in the
	// domestic table, devices are masqueraded onto the LAN, LAN hosts may
	// use the gateway's resolver.
	routes := b.File("nodes/gw/usr/local/sbin/meridian-routes.sh")
	if !strings.Contains(routes, "ip -6 route replace '"+ulaLAN+"' dev 'eth0' table 100") {
		t.Errorf("table 100 has no on-link route for the ULA LAN prefix")
	}
	main := nftBlock(t, nft, "meridian")
	for _, need := range []string{
		`oifname "eth0" ip6 saddr fd67::/64 masquerade`,
		"udp dport { 53, 853 } ip6 saddr != { fe80::/10, " + ulaLAN + ", fd67::/64 } drop",
	} {
		if !strings.Contains(main, need) {
			t.Errorf("inet meridian missing %q", need)
		}
	}
	// The device's home-only AllowedIPs carry the LAN prefix.
	if !strings.Contains(strings.Join(remoteaccess.AllowedIPs(topo, model.RemoteModeHome), ","), ulaLAN) {
		t.Error("remote-access home routes do not include the ULA LAN prefix")
	}
}

// defaultMark reads the default-exit mark from the nft header.
func defaultMark(t *testing.T, nft string) uint32 {
	t.Helper()
	m := regexp.MustCompile(`(?m)^# default-exit \S+ group \S+ mark (0x[0-9a-f]+)$`).FindStringSubmatch(nft)
	if m == nil {
		t.Fatal("no default-exit header")
	}
	var v uint32
	fmt.Sscanf(m[1], "0x%x", &v)
	return v
}

// TestGlobalLANClassifyUnchanged: with a global LAN prefix nothing new is
// rendered; the LAN rule stays after the private IPv4 ranges and the ULA
// drop is preceded only by the device pool.
func TestGlobalLANClassifyUnchanged(t *testing.T) {
	topo, _ := raExample(t)
	nft := mustCompile(t, topo).File("nodes/gw/etc/nftables.d/meridian.nft")
	if strings.Contains(nft, "ULA LAN prefix") {
		t.Fatal("a global LAN prefix rendered the ULA LAN rule")
	}
	chain := classifyChain(t, nft)
	idx := func(prefix string) int {
		for i, l := range chain {
			if strings.HasPrefix(l, prefix) {
				return i
			}
		}
		t.Fatalf("no classify rule %q:\n%s", prefix, strings.Join(chain, "\n"))
		return -1
	}
	want := []string{
		"ip daddr 10.67.0.0/24 meta mark set 0x64 return",
		"ip6 daddr fd67::/64 meta mark set 0x64 return",
		"ip daddr @underlay4 drop",
		"ip daddr 10.66.0.0/16 drop",
		"ip6 daddr fc00::/7 drop",
		"ip6 daddr { fe80::/10, ff00::/8, ::1 } return",
	}
	for i, w := range want {
		if !strings.HasPrefix(chain[i], w) {
			t.Fatalf("classify rule %d is %q, want %q", i, chain[i], w)
		}
	}
	lan := idx("ip6 daddr 2001:db8:100::/64 meta mark set 0x64 return")
	if lan != idx("ip daddr { 0.0.0.0/8, 10.0.0.0/8")+1 || lan+1 != idx("ip daddr @default4") {
		t.Fatalf("the global LAN rule moved:\n%s", strings.Join(chain, "\n"))
	}
	if got := classify6(t, chain, "fd12:3456:789a:1::50"); got != "drop" {
		t.Fatalf("with a global LAN prefix a ULA destination must be dropped, got %s", got)
	}
}
