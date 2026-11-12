package compile

import (
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"

	"github.com/radowitz/meridian/internal/model"
)

type mssClamp struct {
	Mark uint32
	MSS4 int
	MSS6 int
}

func renderNFT(t model.Topology, n model.Node, tunnels []Tunnel, exits []ExitPlan, mss4, mss6 int, decisions map[string]string, clamps []mssClamp) string {
	switch n.Role {
	case model.RoleGateway:
		return renderGatewayNFT(t, tunnels, exits, mss4, mss6, decisions, clamps)
	case model.RoleExit:
		return renderExitNFT(t, n)
	default:
		return renderTransitNFT(n, tunnels)
	}
}

func renderGatewayNFT(t model.Topology, tunnels []Tunnel, exits []ExitPlan, mss4, mss6 int, decisions map[string]string, clamps []mssClamp) string {
	lan := t.Settings.LANInterface
	if lan == "" {
		lan = "eth0"
	}
	def, _ := defaultExit(t, exits)
	rules := planRules(t, exits, decisions)
	var sb strings.Builder
	sb.WriteString("#!/usr/sbin/nft -f\n")
	sb.WriteString("# Meridian gateway policy. Reloading this file deletes only table inet meridian.\n")
	fmt.Fprintf(&sb, "# default-exit %s mark %#x\n", def.Node.ID, def.Mark)
	fmt.Fprintf(&sb, "# mss-clamp v4 %d v6 %d\n", mss4, mss6)
	sb.WriteString("table inet meridian {\n")

	writeSet(&sb, "chnroute", "ipv4_addr", false, nil)
	writeSet(&sb, "chnroute6", "ipv6_addr", false, nil)
	writeSet(&sb, "direct4", "ipv4_addr", true, nil)
	writeSet(&sb, "direct6", "ipv6_addr", true, nil)
	writeSet(&sb, "default4", "ipv4_addr", true, nil)
	writeSet(&sb, "default6", "ipv6_addr", true, nil)
	writeSet(&sb, "doh4", "ipv4_addr", false, []string{
		"1.1.1.1", "1.0.0.1", "8.8.8.8", "8.8.4.4", "9.9.9.9", "149.112.112.112",
	})
	writeSet(&sb, "doh6", "ipv6_addr", false, []string{
		"2606:4700:4700::1111", "2606:4700:4700::1001",
		"2001:4860:4860::8888", "2001:4860:4860::8844",
	})
	var underlay []string
	seen := map[string]bool{}
	for _, tun := range tunnels {
		for _, ip := range []string{tun.West.EndpointV4, tun.East.EndpointV4} {
			if ip == "" || seen[ip] {
				continue
			}
			seen[ip] = true
			underlay = append(underlay, ip)
		}
	}
	writeSet(&sb, "underlay4", "ipv4_addr", false, underlay)

	for _, rp := range rules {
		var v4, v6 []string
		if rp.Rule.MatchType == model.MatchCIDR {
			if addr, err := netip.ParsePrefix(rp.Rule.MatchValue); err == nil {
				if addr.Addr().Is4() {
					v4 = []string{addr.String()}
				} else {
					v6 = []string{addr.String()}
				}
			} else if addr, err := netip.ParseAddr(rp.Rule.MatchValue); err == nil {
				if addr.Is4() {
					v4 = []string{addr.String()}
				} else {
					v6 = []string{addr.String()}
				}
			}
		}
		timeout := rp.Rule.MatchType != model.MatchCIDR
		writeSet(&sb, rp.Set4, "ipv4_addr", timeout, v4)
		if !rp.FilterAAAA {
			writeSet(&sb, rp.Set6, "ipv6_addr", timeout, v6)
		}
	}

	sb.WriteString("  chain classify {\n")
	sb.WriteString("    ip daddr @underlay4 drop comment \"clients cannot bypass the tunnel by talking to an endpoint\"\n")
	sb.WriteString("    ip daddr 10.66.0.0/16 drop comment \"tunnel v4 is not a LAN destination\"\n")
	sb.WriteString("    ip6 daddr fc00::/7 drop comment \"ULA, including fd66, never goes to ROS\"\n")
	// Link-local and multicast must not be dropped here: RA and ND arrive
	// on this interface and are delivered locally. Forwarded copies are
	// unmarked so they follow the main table instead of an exit.
	sb.WriteString("    ip6 daddr { fe80::/10, ff00::/8, ::1 } return\n")
	sb.WriteString("    ip daddr { 224.0.0.0/4, 255.255.255.255 } return\n")
	for _, rp := range rules {
		for _, pred := range sourcePreds(rp.Rule) {
			fmt.Fprintf(&sb, "    %sip daddr @%s meta mark set %#x return\n", pred, rp.Set4, rp.Exit.Mark)
			if !rp.FilterAAAA {
				fmt.Fprintf(&sb, "    %sip6 daddr @%s meta mark set %#x return\n", pred, rp.Set6, rp.Exit.Mark)
			}
		}
	}
	fmt.Fprintf(&sb, "    ip daddr @direct4 meta mark set %#x return\n", markDomestic)
	fmt.Fprintf(&sb, "    ip6 daddr @direct6 meta mark set %#x return\n", markDomestic)
	fmt.Fprintf(&sb, "    ip daddr @chnroute meta mark set %#x return\n", markDomestic)
	fmt.Fprintf(&sb, "    ip6 daddr @chnroute6 meta mark set %#x return\n", markDomestic)
	// Private ranges are domestic. Leaving them unmarked made them follow
	// the main default, and the catch-all below would otherwise stuff them
	// into the foreign tunnel.
	fmt.Fprintf(&sb, "    ip daddr { 0.0.0.0/8, 10.0.0.0/8, 127.0.0.0/8, 169.254.0.0/16, 172.16.0.0/12, 192.168.0.0/16 } meta mark set %#x return\n", markDomestic)
	if t.Settings.LANIPv6Prefix != "" {
		fmt.Fprintf(&sb, "    ip6 daddr %s meta mark set %#x return\n", t.Settings.LANIPv6Prefix, markDomestic)
	}
	sb.WriteString("    ip daddr @default4 meta mark set " + fmt.Sprintf("%#x", def.Mark) + " return\n")
	sb.WriteString("    ip6 daddr @default6 meta mark set " + fmt.Sprintf("%#x", def.Mark) + " return\n")
	fmt.Fprintf(&sb, "    meta nfproto ipv4 meta mark set %#x return\n", def.Mark)
	fmt.Fprintf(&sb, "    meta nfproto ipv6 meta mark set %#x return\n", def.Mark)
	sb.WriteString("  }\n\n")

	fmt.Fprintf(&sb, "  chain prerouting {\n    type filter hook prerouting priority mangle; policy accept;\n    iifname \"%s\" jump classify\n  }\n\n", lan)

	// Only lower an advertised MSS. Raising a small MSS black-holes TCP.
	sb.WriteString("  chain mss {\n    type filter hook forward priority mangle; policy accept;\n")
	for _, c := range clamps {
		if c.MSS4 > 0 {
			fmt.Fprintf(&sb, "    tcp flags syn meta mark %#x meta nfproto ipv4 tcp option maxseg size > %d tcp option maxseg size set %d\n", c.Mark, c.MSS4, c.MSS4)
		}
		if c.MSS6 > 0 {
			fmt.Fprintf(&sb, "    tcp flags syn meta mark %#x meta nfproto ipv6 tcp option maxseg size > %d tcp option maxseg size set %d\n", c.Mark, c.MSS6, c.MSS6)
		}
	}
	fmt.Fprintf(&sb, "    tcp flags syn meta nfproto ipv4 tcp option maxseg size > %d tcp option maxseg size set %d\n    tcp flags syn meta nfproto ipv6 tcp option maxseg size > %d tcp option maxseg size set %d\n  }\n\n", mss4, mss4, mss6, mss6)

	fmt.Fprintf(&sb, `  chain doh {
    type filter hook forward priority filter; policy accept;
    iifname "%s" ip daddr @doh4 tcp dport 443 reject comment "known DoH list, not exhaustive"
    iifname "%s" ip6 daddr @doh6 tcp dport 443 reject
  }

`, lan, lan)

	v6src := "fe80::/10"
	if t.Settings.LANIPv6Prefix != "" {
		v6src = "fe80::/10, " + t.Settings.LANIPv6Prefix
	}
	fmt.Fprintf(&sb, `  chain dns_hijack {
    type nat hook prerouting priority dstnat; policy accept;
    iifname "%s" meta nfproto ipv4 udp dport { 53, 853 } redirect to :53
    iifname "%s" meta nfproto ipv4 tcp dport 53 redirect to :53
    iifname "%s" meta nfproto ipv4 tcp dport 853 redirect to :853
    iifname "%s" meta nfproto ipv6 udp dport { 53, 853 } redirect to :53
    iifname "%s" meta nfproto ipv6 tcp dport 53 redirect to :53
    iifname "%s" meta nfproto ipv6 tcp dport 853 redirect to :853
  }

`, lan, lan, lan, lan, lan, lan)
	// UDP/853 (DoQ) is redirected at port 53 above: nothing here speaks DoQ,
	// and leaving it forwarded would bypass SmartDNS.
	fmt.Fprintf(&sb, `  chain input {
    type filter hook input priority filter; policy accept;
    tcp dport { 53, 853 } ip saddr != %s drop comment "DNS only from the LAN"
    udp dport { 53, 853 } ip saddr != %s drop
    tcp dport { 53, 853 } ip6 saddr != { %s } drop
    udp dport { 53, 853 } ip6 saddr != { %s } drop
    tcp dport %d ip saddr != %s drop comment "panel stays on the LAN"
    tcp dport %d meta nfproto ipv6 drop
  }

`, lanNet(t), lanNet(t), v6src, v6src, panelPort(t), lanNet(t), panelPort(t))

	sb.WriteString("  chain transit_snat {\n    type nat hook postrouting priority srcnat; policy accept;\n")
	for _, e := range exits {
		fmt.Fprintf(&sb, "    ip saddr %s meta mark %#x snat to %s\n", lanNet(t), e.Mark, e.TransitV4)
		if t.Settings.LANIPv6Prefix != "" {
			fmt.Fprintf(&sb, "    ip6 saddr %s meta mark %#x snat to %s\n", t.Settings.LANIPv6Prefix, e.Mark, e.TransitV6)
		}
	}
	sb.WriteString("  }\n}\n")
	return sb.String()
}

func renderExitNFT(t model.Topology, n model.Node) string {
	wan := n.WANInterface
	if wan == "" {
		wan = "eth0"
	}
	var sb strings.Builder
	sb.WriteString("#!/usr/sbin/nft -f\n")
	fmt.Fprintf(&sb, "# exit %s public NAT. Tunnel ULA and the LAN prefix are translated here, not on the home gateway.\n", n.ID)
	sb.WriteString("table inet meridian {\n")
	sb.WriteString("  chain srcnat {\n    type nat hook postrouting priority srcnat; policy accept;\n")
	if n.EgressV4 {
		fmt.Fprintf(&sb, "    oifname \"%s\" ip saddr { %s, %s } masquerade\n", wan, lanNet(t), transitV4Net())
	}
	if n.EgressV6 {
		v6 := []string{transitV6Net()}
		if t.Settings.LANIPv6Prefix != "" {
			v6 = append([]string{t.Settings.LANIPv6Prefix}, v6...)
		}
		fmt.Fprintf(&sb, "    oifname \"%s\" ip6 saddr { %s } masquerade comment \"NAT66\"\n", wan, strings.Join(v6, ", "))
	}
	sb.WriteString("  }\n")
	if !n.EgressV6 {
		fmt.Fprintf(&sb, "  chain drop_v6 {\n    type filter hook forward priority filter; policy accept;\n    oifname \"%s\" meta nfproto ipv6 drop comment \"no egress_v6; AAAA is filtered at DNS\"\n  }\n", wan)
	}
	sb.WriteString("}\n")
	return sb.String()
}

func renderTransitNFT(n model.Node, tunnels []Tunnel) string {
	wan := n.WANInterface
	if wan == "" {
		wan = "eth0"
	}
	var ports []int
	for _, tun := range tunnels {
		if tun.Mode == "wss" && tun.Listener().ID == n.ID {
			ports = append(ports, tun.WGPort)
		}
	}
	var sb strings.Builder
	sb.WriteString("#!/usr/sbin/nft -f\n")
	sb.WriteString("# Transit node. Does not NAT client traffic and does not own the default route.\n")
	sb.WriteString("table inet meridian {\n")
	if len(ports) > 0 {
		parts := make([]string, len(ports))
		for i, p := range ports {
			parts[i] = fmt.Sprintf("%d", p)
		}
		fmt.Fprintf(&sb, "  chain input {\n    type filter hook input priority filter; policy accept;\n    iifname \"%s\" udp dport { %s } drop comment \"wss wireguard port is reached only via local wstunnel\"\n  }\n", wan, strings.Join(parts, ", "))
	} else {
		sb.WriteString("  chain forward {\n    type filter hook forward priority filter; policy accept;\n  }\n")
	}
	sb.WriteString("}\n")
	return sb.String()
}

func writeSet(sb *strings.Builder, name, typ string, timeout bool, elements []string) {
	flags := "interval"
	if timeout {
		flags = "interval, timeout"
	}
	fmt.Fprintf(sb, "  set %s {\n    type %s\n    flags %s\n", name, typ, flags)
	if len(elements) > 0 {
		fmt.Fprintf(sb, "    elements = { %s }\n", strings.Join(elements, ", "))
	}
	sb.WriteString("  }\n")
}

// sourcePreds builds nft match prefixes. A packet is one address family, so
// a v4 source and a v6 source are alternatives, while a MAC is combined
// with each of them.
func sourcePreds(r model.Rule) []string {
	mac := ""
	if r.SourceMAC != "" {
		mac = "ether saddr " + r.SourceMAC + " "
	}
	var v4, v6 string
	if r.SourceIPv4 != "" {
		v4 = "ip saddr " + r.SourceIPv4 + " "
	}
	if r.SourceIPv6 != "" {
		v6 = "ip6 saddr " + r.SourceIPv6 + " "
	}
	switch {
	case v4 != "" && v6 != "":
		return []string{mac + v4, mac + v6}
	case v4 != "" || v6 != "":
		return []string{mac + v4 + v6}
	default:
		return []string{mac}
	}
}

func panelPort(t model.Topology) int {
	const fallback = 8787
	if t.Settings.PanelBind == "" {
		return fallback
	}
	_, p, err := net.SplitHostPort(t.Settings.PanelBind)
	if err != nil {
		return fallback
	}
	n, err := strconv.Atoi(p)
	if err != nil || n <= 0 || n > 65535 || n == 22 {
		return fallback
	}
	return n
}
