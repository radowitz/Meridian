package compile

import (
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"

	"github.com/radowitz/meridian/internal/model"
	"github.com/radowitz/meridian/internal/validate"
)

type mssClamp struct {
	Mark uint32
	MSS4 int
	MSS6 int
}

func renderNFT(t model.Topology, n model.Node, tunnels []Tunnel, exits []ExitPlan, groups []GroupPlan, mss4, mss6 int, decisions map[string]string, clamps []mssClamp) string {
	switch n.Role {
	case model.RoleGateway:
		return renderGatewayNFT(t, tunnels, exits, groups, mss4, mss6, decisions, clamps)
	case model.RoleExit:
		return renderExitNFT(t, n, tunnels, exits, groups, nodeMSSFor(n, exits, mss4, mss6, clamps))
	default:
		return renderTransitNFT(t, n, tunnels, groups, nodeMSSFor(n, exits, mss4, mss6, clamps))
	}
}

// writeLocalMSS clamps the MSS of TCP connections this gateway opens itself
// with an exit or region-group mark into a tunnel: the panel's unlock probe
// (host agent, root, SO_MARK and the exit's transit source), SmartDNS's
// marked TCP queries to a group resolver, any other local socket carrying
// such a mark. They never pass the forward hook, so chain mss never saw
// them and their SYN carried the tunnel interface's MSS (MTU 1412 → 1372):
// on a path whose real MTU is smaller the peer's full-size segments were
// silently dropped and the TLS handshake timed out. The values are chain
// mss's, from the same full-path computation (compile.mssFloor and the
// per-exit clamps): never a second number, and only ever lowered.
//
//   - local_mss (output, filter, priority -140 = mangle + 10): the SYN.
//     Route-type output chains at mangle (sniff_route → relay_share with
//     relay sharing) may change the mark, and the kernel re-routes after
//     them, so at -140 the packet carries its final mark and output
//     interface, as in sniff_mss. Relay bits are masked off before the
//     mark is compared (relay_strip does that for chain mss on forward).
//     Matched: a mark in the exit/region-group range (markExitBase … the
//     guard's top) leaving on a gateway WireGuard interface (failover
//     companions included, so a moved table 102 or a backup hub is
//     covered). Not matched: unmarked sockets (panel, SSH, DNS, the host
//     agent's other work), domestic and reject marks, WireGuard's own
//     outer UDP (mark 0x4d72, not TCP, leaves on the LAN NIC or lo), and
//     wstunnel's TCP carriers (no exit mark, leave on the LAN NIC).
//   - local_mss_in (input, filter, priority mangle): the SYN-ACK of such
//     a connection, so this host also sends no segment larger than the
//     clamp (the forward chain clamps both directions the same way). An
//     arriving packet has no socket mark; the connection is recognised by
//     its reply tuple: replies go to an exit's or group's transit address
//     (transitV4Net/transitV6Net), which only marked connections use (the
//     probe binds it; SNAT gives it to the forwarder's and SmartDNS's
//     group connections). Input sees only this host's connections; LAN
//     traffic to the same transit addresses is forwarded and clamped in
//     chain mss as before.
//
// This is a sibling of sniff_mss, not a generalisation of it: sniff_mss is
// rendered only with settings.sniff on (off, the files must stay byte for
// byte what they were) and clamps every SYN of the forwarder's uid, its
// domestic connections on the LAN NIC included. A forwarder SYN into a
// tunnel is matched by both chains; both only lower to the same value, so
// the result is the same. The forwarder's confinement (sniff_out,
// sniff_confine) is not touched.
func writeLocalMSS(sb *strings.Builder, tunnels []string, marks []markPlan, last uint32, mss4, mss6 int, clamps []mssClamp) {
	if len(tunnels) == 0 {
		return
	}
	quoted := make([]string, len(tunnels))
	for i, n := range tunnels {
		quoted[i] = "\"" + n + "\""
	}
	oifs := "{ " + strings.Join(quoted, ", ") + " }"
	sb.WriteString("  chain local_mss {\n    type filter hook output priority -140; policy accept;\n")
	for _, c := range clamps {
		if c.MSS4 > 0 {
			fmt.Fprintf(sb, "    tcp flags syn meta mark & %s == %s oifname %s meta nfproto ipv4 tcp option maxseg size > %d tcp option maxseg size set %d\n", hexMark(markNoShare), hexMark(c.Mark), oifs, c.MSS4, c.MSS4)
		}
		if c.MSS6 > 0 {
			fmt.Fprintf(sb, "    tcp flags syn meta mark & %s == %s oifname %s meta nfproto ipv6 tcp option maxseg size > %d tcp option maxseg size set %d\n", hexMark(markNoShare), hexMark(c.Mark), oifs, c.MSS6, c.MSS6)
		}
	}
	fmt.Fprintf(sb, "    tcp flags syn meta mark & %s %#x-%#x oifname %s meta nfproto ipv4 tcp option maxseg size > %d tcp option maxseg size set %d comment \"this host's exit- and group-marked TCP into a tunnel: chain mss's clamp\"\n", hexMark(markNoShare), markExitBase, last, oifs, mss4, mss4)
	fmt.Fprintf(sb, "    tcp flags syn meta mark & %s %#x-%#x oifname %s meta nfproto ipv6 tcp option maxseg size > %d tcp option maxseg size set %d\n", hexMark(markNoShare), markExitBase, last, oifs, mss6, mss6)
	sb.WriteString("  }\n")
	transit := map[uint32]markPlan{}
	for _, m := range marks {
		transit[m.Mark] = m
	}
	sb.WriteString("  chain local_mss_in {\n    type filter hook input priority mangle; policy accept;\n")
	for _, c := range clamps {
		m, ok := transit[c.Mark]
		if !ok {
			continue
		}
		if c.MSS4 > 0 && m.TransitV4 != "" {
			fmt.Fprintf(sb, "    iifname %s ct direction reply tcp flags syn meta nfproto ipv4 ct reply ip daddr %s tcp option maxseg size > %d tcp option maxseg size set %d\n", oifs, m.TransitV4, c.MSS4, c.MSS4)
		}
		if c.MSS6 > 0 && m.TransitV6 != "" {
			fmt.Fprintf(sb, "    iifname %s ct direction reply tcp flags syn meta nfproto ipv6 ct reply ip6 daddr %s tcp option maxseg size > %d tcp option maxseg size set %d\n", oifs, m.TransitV6, c.MSS6, c.MSS6)
		}
	}
	fmt.Fprintf(sb, "    iifname %s ct direction reply tcp flags syn meta nfproto ipv4 ct reply ip daddr %s tcp option maxseg size > %d tcp option maxseg size set %d comment \"SYN-ACK of this host's marked connections (transit source)\"\n", oifs, transitV4Net(), mss4, mss4)
	fmt.Fprintf(sb, "    iifname %s ct direction reply tcp flags syn meta nfproto ipv6 ct reply ip6 daddr %s tcp option maxseg size > %d tcp option maxseg size set %d\n", oifs, transitV6Net(), mss6, mss6)
	sb.WriteString("  }\n\n")
}

// nodeMSS is the clamp a remote node applies to its own TCP through its
// Meridian tunnels (writeNodeMSS).
type nodeMSS struct{ MSS4, MSS6 int }

// nodeMSSFor: the gateway's forward clamp (the full-path floor), lowered
// to the per-exit clamp when n is an exit that has one (an exit with a Mesh
// leg). Never
// a second computation and never above what forwarded traffic gets.
func nodeMSSFor(n model.Node, exits []ExitPlan, mss4, mss6 int, clamps []mssClamp) nodeMSS {
	out := nodeMSS{mss4, mss6}
	e, ok := exitByID(exits, n.ID)
	if !ok {
		return out
	}
	for _, c := range clamps {
		if c.Mark != e.Mark {
			continue
		}
		if c.MSS4 > 0 && c.MSS4 < out.MSS4 {
			out.MSS4 = c.MSS4
		}
		if c.MSS6 > 0 && c.MSS6 < out.MSS6 {
			out.MSS6 = c.MSS6
		}
	}
	return out
}

// nodeTunnelIfaces are node n's Meridian WireGuard interfaces (standby and
// WSS legs included), sorted.
func nodeTunnelIfaces(n model.Node, tunnels []Tunnel) []string {
	seen := map[string]bool{}
	var out []string
	for _, tun := range tunnelsFor(tunnels, n.ID) {
		name := tun.Iface()
		if name == "" || seen[name] {
			continue
		}
		seen[name] = true
		out = append(out, name)
	}
	sortStrings(out)
	return out
}

// writeNodeMSS clamps TCP that a remote node itself terminates or opens
// through its Meridian tunnels: the unlock timer's report to the panel
// (exit → gateway LAN, through the tunnels), the exit resolver's TCP
// answers to the gateway, an external-exit carrier's redirector and
// resolver group answering the hub tunnel, anything else local. Forwarded
// traffic is clamped on the gateway (chain mss, both directions); these
// connections are not forwarded anywhere on the gateway side either when
// the gateway end is a local socket (the panel, SmartDNS's unmarked
// queries), so nothing clamped them. A node has no exit marks: the match
// is the interface. tunnel_mss_out (output, priority -140, after the
// route-type output chains at mangle that re-route local replies to a hub
// or relay tunnel) lowers the SYN and SYN-ACK this host sends into a
// tunnel; tunnel_mss_in (input) lowers the SYN and SYN-ACK arriving from
// one, so this host also sends no larger segment. WireGuard's outer UDP,
// wstunnel's TCP carriers, the WAN and the Mesh veth are other interfaces
// or not TCP and are not matched; forwarded packets never pass input or
// output. Same values as the gateway's forward clamp (nodeMSSFor), only
// ever lowered. legs: on a hub, each of its Mesh legs with the smaller MSS
// the Mesh path leaves (meshLegMSS); the hub's own TCP into such a leg is
// clamped to it. An exit's own clamp already counts its Mesh leg.
func writeNodeMSS(sb *strings.Builder, ifaces []string, m nodeMSS, legs ...legMSS) {
	if len(ifaces) == 0 {
		return
	}
	quoted := make([]string, len(ifaces))
	for i, n := range ifaces {
		quoted[i] = "\"" + n + "\""
	}
	ifs := "{ " + strings.Join(quoted, ", ") + " }"
	fmt.Fprintf(sb, "  chain tunnel_mss_out {\n    type filter hook output priority -140; policy accept;\n")
	for _, l := range legs {
		fmt.Fprintf(sb, "    oifname \"%s\" tcp flags syn meta nfproto ipv4 tcp option maxseg size > %d tcp option maxseg size set %d comment \"Mesh leg: what the Mesh path carries unfragmented\"\n", l.Iface, l.MSS4, l.MSS4)
		fmt.Fprintf(sb, "    oifname \"%s\" tcp flags syn meta nfproto ipv6 tcp option maxseg size > %d tcp option maxseg size set %d\n", l.Iface, l.MSS6, l.MSS6)
	}
	fmt.Fprintf(sb, "    oifname %s tcp flags syn meta nfproto ipv4 tcp option maxseg size > %d tcp option maxseg size set %d comment \"this host's own TCP into a tunnel: the gateway's forward clamp\"\n", ifs, m.MSS4, m.MSS4)
	fmt.Fprintf(sb, "    oifname %s tcp flags syn meta nfproto ipv6 tcp option maxseg size > %d tcp option maxseg size set %d\n", ifs, m.MSS6, m.MSS6)
	sb.WriteString("  }\n")
	fmt.Fprintf(sb, "  chain tunnel_mss_in {\n    type filter hook input priority mangle; policy accept;\n")
	for _, l := range legs {
		fmt.Fprintf(sb, "    iifname \"%s\" tcp flags syn meta nfproto ipv4 tcp option maxseg size > %d tcp option maxseg size set %d comment \"Mesh leg: what the Mesh path carries unfragmented\"\n", l.Iface, l.MSS4, l.MSS4)
		fmt.Fprintf(sb, "    iifname \"%s\" tcp flags syn meta nfproto ipv6 tcp option maxseg size > %d tcp option maxseg size set %d\n", l.Iface, l.MSS6, l.MSS6)
	}
	fmt.Fprintf(sb, "    iifname %s tcp flags syn meta nfproto ipv4 tcp option maxseg size > %d tcp option maxseg size set %d comment \"this host's own TCP from a tunnel: the gateway's forward clamp\"\n", ifs, m.MSS4, m.MSS4)
	fmt.Fprintf(sb, "    iifname %s tcp flags syn meta nfproto ipv6 tcp option maxseg size > %d tcp option maxseg size set %d\n", ifs, m.MSS6, m.MSS6)
	sb.WriteString("  }\n")
}

func renderGatewayNFT(t model.Topology, tunnels []Tunnel, exits []ExitPlan, groups []GroupPlan, mss4, mss6 int, decisions map[string]string, clamps []mssClamp) string {
	lan := gatewayLAN(t)
	def, _ := defaultExit(t, groups)
	rules := planRules(t, exits, groups, decisions)
	rp := planRemote(t)
	// in is the managed ingress match: the LAN NIC, plus mra when remote
	// access is on. Disabled renders byte for byte what it did before.
	in := fmt.Sprintf("\"%s\"", lan)
	if rp != nil {
		in = fmt.Sprintf("{ \"%s\", \"%s\" }", lan, rp.Iface)
	}
	var sb strings.Builder
	sb.WriteString("#!/usr/sbin/nft -f\n")
	sb.WriteString("# Meridian gateway policy. This whole file is one nft transaction: it\n")
	sb.WriteString("# replaces only tables inet meridian_guard and inet meridian, never the\n")
	sb.WriteString("# rest of the ruleset. Load it with nft -c -f first, then nft -f.\n")
	fmt.Fprintf(&sb, "# default-exit %s group %s mark %#x\n", def.Exit.Node.ID, t.Settings.DefaultGroup, def.Mark)
	for _, g := range groups {
		kind := "static"
		if g.Dynamic {
			kind = "dynamic"
		}
		fmt.Fprintf(&sb, "# group %s mark %#x transit %s target %s %s\n", g.Group.ID, g.Mark, g.TransitV4, g.Target.Node.ID, kind)
	}
	fmt.Fprintf(&sb, "# mss-clamp v4 %d v6 %d\n", mss4, mss6)
	writeGuardTable(&sb, lan, gatewayTunnelIfaces(tunnels), guardLastExitMark(exits, groups...), rp, usesReject(t))
	writeAtomicReplace(&sb, tableMain)
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
	eps := endpointAccess(t, tunnels, groups)
	for _, set := range []struct{ name, class string }{
		{"endpoint_block", validate.EndpointBlocked},
		{"endpoint_direct", validate.EndpointDirect},
		{"endpoint_tunnel", validate.EndpointTunnel},
	} {
		var v4, v6 []string
		for _, e := range eps {
			if e.Class != set.class {
				continue
			}
			if e.Family == 6 {
				v6 = append(v6, e.Addr)
			} else {
				v4 = append(v4, e.Addr)
			}
		}
		writeSet(&sb, set.name+"4", "ipv4_addr", false, v4)
		writeSet(&sb, set.name+"6", "ipv6_addr", false, v6)
	}

	for _, rp := range rules {
		if rp.QUIC {
			continue
		}
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
		// A rule-set's address entries: filled by the host's derive step
		// (lists.DeriveOrdered), never by the resolver, never expiring.
		if rp.CIDR4 != "" {
			writeSet(&sb, rp.CIDR4, "ipv4_addr", false, nil)
			if rp.CIDR6 != "" {
				writeSet(&sb, rp.CIDR6, "ipv6_addr", false, nil)
			}
		}
	}

	sb.WriteString("  chain classify {\n")
	if rp != nil {
		// Device-bound packets (from the LAN, or direct replies from ROS
		// after de-NAT) take table 100, where the pools are on mra. The
		// guard lets them out on mra only when they came in on the LAN NIC.
		fmt.Fprintf(&sb, "    ip daddr %s meta mark set %#x return comment \"remote-access devices, delivered on %s\"\n", rp.V4, markDomestic, rp.Iface)
		fmt.Fprintf(&sb, "    ip6 daddr %s meta mark set %#x return\n", rp.V6, markDomestic)
	}
	sb.WriteString("    ip daddr 10.66.0.0/16 drop comment \"tunnel v4 is not a LAN destination\"\n")
	// A LAN IPv6 prefix inside fc00::/7 is classified domestic right ahead
	// of the ULA drop, exactly as wide as configured (validation keeps it
	// clear of fd66::/48, the transit prefix, the device pool and the tunnel
	// ULA). Table 100 holds it on-link on the LAN NIC, and the guard admits
	// the domestic mark only there, so it reaches home hosts, never ROS's
	// default route. A global LAN prefix keeps its place further down.
	lanULA, isULA := lanULAPrefix(t)
	if isULA {
		fmt.Fprintf(&sb, "    ip6 daddr %s meta mark set %#x return comment \"ULA LAN prefix: home hosts only\"\n", lanULA, markDomestic)
	}
	sb.WriteString("    ip6 daddr fc00::/7 drop comment \"ULA, including fd66, never goes to ROS\"\n")
	// Tunnel endpoints (endpointAccess), right after the
	// tunnel-space and ULA drops (an endpoint inside them stays dropped),
	// ahead of the rules and chnroute:
	// ones the default group cannot carry dropped, domestic ones direct (table 100),
	// foreign ones forced into the default group, never the home uplink.
	sb.WriteString("    ip daddr @endpoint_block4 drop comment \"foreign tunnel endpoint the default group cannot carry: never the home uplink\"\n")
	sb.WriteString("    ip6 daddr @endpoint_block6 drop\n")
	fmt.Fprintf(&sb, "    ip daddr @endpoint_direct4 meta mark set %#x return comment \"domestic tunnel endpoint (relay, IX ingress): home uplink\"\n", markDomestic)
	fmt.Fprintf(&sb, "    ip6 daddr @endpoint_direct6 meta mark set %#x return\n", markDomestic)
	fmt.Fprintf(&sb, "    ip daddr @endpoint_tunnel4 meta mark set %#x return comment \"foreign tunnel endpoint: default group, never the home uplink\"\n", def.Mark)
	fmt.Fprintf(&sb, "    ip6 daddr @endpoint_tunnel6 meta mark set %#x return\n", def.Mark)
	// Link-local and multicast must not be dropped here: RA and ND arrive
	// on this interface and are delivered locally. Forwarded copies are
	// unmarked so they follow the main table instead of an exit.
	sb.WriteString("    ip6 daddr { fe80::/10, ff00::/8, ::1 } return\n")
	sb.WriteString("    ip daddr { 224.0.0.0/4, 255.255.255.255 } return\n")
	// Rules in list order: the first set holding the address decides, so an
	// address rule and a name rule keep their list order (internal/ordered).
	for _, rp := range rules {
		if rp.QUIC {
			continue
		}
		for _, pred := range sourcePreds(rp.Rule) {
			for _, m := range ruleMatches(rp) {
				fmt.Fprintf(&sb, "    %s%s meta mark set %#x return\n", pred, m, rp.Mark)
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
	if t.Settings.LANIPv6Prefix != "" && !isULA {
		fmt.Fprintf(&sb, "    ip6 daddr %s meta mark set %#x return\n", t.Settings.LANIPv6Prefix, markDomestic)
	}
	sb.WriteString("    ip daddr @default4 meta mark set " + fmt.Sprintf("%#x", def.Mark) + " return\n")
	sb.WriteString("    ip6 daddr @default6 meta mark set " + fmt.Sprintf("%#x", def.Mark) + " return\n")
	fmt.Fprintf(&sb, "    meta nfproto ipv4 meta mark set %#x return\n", def.Mark)
	fmt.Fprintf(&sb, "    meta nfproto ipv6 meta mark set %#x return\n", def.Mark)
	sb.WriteString("  }\n\n")

	sp := planShare(t, tunnels)
	if sp != nil {
		writeShareNFT(&sb, t, sp)
	}
	if q := quicChain(rules, in, markExitBase, guardLastExitMark(exits, groups...)); q != "" {
		sb.WriteString(q)
	}
	snp := planSniff(t, exits, groups, decisions)
	if snp != nil {
		outer, none := gatewayWGOuter(t, tunnels)
		writeSniffNFT(&sb, t, snp, in, rp, gatewayTunnelIfaces(tunnels), outer, none, sp != nil, mss4, mss6, clamps)
	}
	fmt.Fprintf(&sb, "  chain prerouting {\n    type filter hook prerouting priority mangle; policy accept;\n    iifname %s jump classify\n", in)
	if snp != nil {
		// Before relay_share: a redirected SYN carries markSniff, so it is
		// outside the exit-mark range and gets no relay assignment.
		fmt.Fprintf(&sb, "    iifname %s meta l4proto tcp jump sniff_mark\n", in)
	}
	if sp != nil {
		// After classification: an exit-marked packet gets its connection's
		// relay (assigned once, when the connection is new).
		fmt.Fprintf(&sb, "    iifname %s meta mark %#x-%#x jump relay_share comment \"relay sharing: per-connection assignment\"\n", in, markExitBase, guardLastExitMark(exits, groups...))
		sb.WriteString("    ct direction reply meta l4proto tcp jump relay_count_in\n")
	}
	sb.WriteString("  }\n\n")
	writeTrafficCounters(&sb, in, lan, gatewayTunnelIfaces(tunnels), guardLastExitMark(exits, groups...), snp != nil)

	// Only lower an advertised MSS. Raising a small MSS black-holes TCP.
	sb.WriteString("  chain mss {\n    type filter hook forward priority mangle; policy accept;\n")
	if rp != nil {
		for _, dir := range []string{"iifname", "oifname"} {
			fmt.Fprintf(&sb, "    %s \"%s\" tcp flags syn meta nfproto ipv4 tcp option maxseg size > %d tcp option maxseg size set %d\n", dir, rp.Iface, rp.mss4(), rp.mss4())
			fmt.Fprintf(&sb, "    %s \"%s\" tcp flags syn meta nfproto ipv6 tcp option maxseg size > %d tcp option maxseg size set %d\n", dir, rp.Iface, rp.mss6(), rp.mss6())
		}
	}
	// Per-mark clamps (an exit with a Mesh leg, a region group that can
	// switch to one):
	// the SYN by its mark; the SYN-ACK coming back from the tunnel carries
	// no mark (only LAN ingress is classified), so it is recognised by its
	// reply tuple, the mark's transit address (transit_snat gives it to
	// every marked LAN connection), as local_mss_in does. Without it the
	// LAN client would learn the floor's MSS and send segments too large
	// for the smaller path.
	transit := map[uint32]markPlan{}
	for _, m := range markPlans(exits, groups) {
		transit[m.Mark] = m
	}
	for _, c := range clamps {
		if c.MSS4 > 0 {
			fmt.Fprintf(&sb, "    tcp flags syn meta mark %#x meta nfproto ipv4 tcp option maxseg size > %d tcp option maxseg size set %d\n", c.Mark, c.MSS4, c.MSS4)
		}
		if c.MSS6 > 0 {
			fmt.Fprintf(&sb, "    tcp flags syn meta mark %#x meta nfproto ipv6 tcp option maxseg size > %d tcp option maxseg size set %d\n", c.Mark, c.MSS6, c.MSS6)
		}
		m, ok := transit[c.Mark]
		if !ok {
			continue
		}
		if c.MSS4 > 0 && m.TransitV4 != "" {
			fmt.Fprintf(&sb, "    ct direction reply tcp flags syn meta nfproto ipv4 ct reply ip daddr %s tcp option maxseg size > %d tcp option maxseg size set %d\n", m.TransitV4, c.MSS4, c.MSS4)
		}
		if c.MSS6 > 0 && m.TransitV6 != "" {
			fmt.Fprintf(&sb, "    ct direction reply tcp flags syn meta nfproto ipv6 ct reply ip6 daddr %s tcp option maxseg size > %d tcp option maxseg size set %d\n", m.TransitV6, c.MSS6, c.MSS6)
		}
	}
	fmt.Fprintf(&sb, "    tcp flags syn meta nfproto ipv4 tcp option maxseg size > %d tcp option maxseg size set %d\n    tcp flags syn meta nfproto ipv6 tcp option maxseg size > %d tcp option maxseg size set %d\n  }\n\n", mss4, mss4, mss6, mss6)
	writeLocalMSS(&sb, gatewayTunnelIfaces(tunnels), markPlans(exits, groups), guardLastExitMark(exits, groups...), mss4, mss6, clamps)

	fmt.Fprintf(&sb, `  chain doh {
    type filter hook forward priority filter; policy accept;
    iifname "%s" ip daddr @doh4 tcp dport 443 reject comment "known DoH list, not exhaustive"
    iifname "%s" ip6 daddr @doh6 tcp dport 443 reject
`, lan, lan)
	if rp != nil {
		fmt.Fprintf(&sb, "    iifname \"%s\" ip daddr @doh4 tcp dport 443 reject\n    iifname \"%s\" ip6 daddr @doh6 tcp dport 443 reject\n", rp.Iface, rp.Iface)
	}
	sb.WriteString("  }\n\n")

	v6src := "fe80::/10"
	if t.Settings.LANIPv6Prefix != "" {
		v6src = "fe80::/10, " + t.Settings.LANIPv6Prefix
	}
	sb.WriteString("  chain dns_hijack {\n    type nat hook prerouting priority dstnat; policy accept;\n")
	hijack := []string{lan}
	if rp != nil {
		hijack = append(hijack, rp.Iface)
	}
	for _, i := range hijack {
		fmt.Fprintf(&sb, `    iifname "%s" meta nfproto ipv4 udp dport { 53, 853 } redirect to :53
    iifname "%s" meta nfproto ipv4 tcp dport 53 redirect to :53
    iifname "%s" meta nfproto ipv4 tcp dport 853 redirect to :853
    iifname "%s" meta nfproto ipv6 udp dport { 53, 853 } redirect to :53
    iifname "%s" meta nfproto ipv6 tcp dport 53 redirect to :53
    iifname "%s" meta nfproto ipv6 tcp dport 853 redirect to :853
`, i, i, i, i, i, i)
	}
	sb.WriteString("  }\n\n")
	// UDP/853 (DoQ) is redirected at port 53 above: nothing here speaks DoQ,
	// and leaving it forwarded would bypass SmartDNS.
	// SmartDNS listens on the wildcard (render_dns.go), so this chain is
	// what keeps it a LAN resolver. Loopback is accepted first: this host's
	// own queries (127.0.0.1, or its LAN address, both arrive on lo) must
	// work with the firewall loaded. iifname "lo" never matches a packet
	// that came in on a NIC, including LAN queries redirected above.
	v4src := lanNet(t)
	if rp != nil {
		v4src = fmt.Sprintf("{ %s, %s }", lanNet(t), rp.V4)
		v6src += ", " + rp.V6.String()
	}
	sb.WriteString(`  chain input {
    type filter hook input priority filter; policy accept;
    iifname "lo" meta l4proto { tcp, udp } th dport { 53, 853 } accept comment "DNS from this host itself"
`)
	if rp != nil {
		fmt.Fprintf(&sb, "    iifname \"%s\" udp dport %d accept comment \"remote-access WireGuard, LAN NIC only\"\n", lan, rp.Port)
		fmt.Fprintf(&sb, "    udp dport %d drop comment \"remote-access port is not reachable on any other interface\"\n", rp.Port)
	}
	fmt.Fprintf(&sb, `    tcp dport { 53, 853 } ip saddr != %s drop comment "DNS only from the LAN"
    udp dport { 53, 853 } ip saddr != %s drop
    tcp dport { 53, 853 } ip6 saddr != { %s } drop
    udp dport { 53, 853 } ip6 saddr != { %s } drop
    tcp dport %d ip saddr != %s drop comment "panel stays on the LAN"
    tcp dport %d meta nfproto ipv6 drop
  }

`, v4src, v4src, v6src, v6src, panelPort(t), v4src, panelPort(t))

	sb.WriteString("  chain transit_snat {\n    type nat hook postrouting priority srcnat; policy accept;\n")
	for _, m := range markPlans(exits, groups) {
		fmt.Fprintf(&sb, "    ip saddr %s meta mark %#x snat to %s\n", lanNet(t), m.Mark, m.TransitV4)
		if t.Settings.LANIPv6Prefix != "" {
			fmt.Fprintf(&sb, "    ip6 saddr %s meta mark %#x snat to %s\n", t.Settings.LANIPv6Prefix, m.Mark, m.TransitV6)
		}
		if rp != nil {
			fmt.Fprintf(&sb, "    ip saddr %s meta mark %#x snat to %s\n", rp.V4, m.Mark, m.TransitV4)
			fmt.Fprintf(&sb, "    ip6 saddr %s meta mark %#x snat to %s\n", rp.V6, m.Mark, m.TransitV6)
		}
	}
	// This host's own queries to a switchable region group's resolver
	// address (SmartDNS upstreams with -set-mark, render_dns.go). They leave
	// with the source address of the tunnel interface; the hub selects the
	// group table by source, so they get the group's transit address, like
	// the group's LAN traffic above. Narrow on purpose: the group mark, the
	// group's own resolver address, UDP/TCP 53. Only this host can produce
	// such a packet: the mark is set either by the classifier, which runs on
	// LAN (and mra) ingress only and drops every fc00::/7 destination before
	// any rule could mark it, or by a local socket. Without the mark nothing
	// is translated and the hub cannot route the query into any member.
	for _, g := range groups {
		if !g.Dynamic {
			continue
		}
		fmt.Fprintf(&sb, "    ip6 daddr %s meta mark %#x meta l4proto { tcp, udp } th dport 53 snat ip6 to %s comment \"group %s resolver: this host's own queries\"\n", g.Resolver, g.Mark, g.TransitV6, verifyLabel(g.Group.ID))
	}
	if snp != nil {
		writeSniffSNAT(&sb, markPlans(exits, groups))
	}
	if rp != nil {
		// ROS has no route back to the pools, and LAN hosts may not route
		// them to this host: domestic-direct and device-to-LAN traffic
		// leaves with the gateway's own LAN address. LAN clients are on
		// ROS's subnet and stay untranslated, as before.
		fmt.Fprintf(&sb, "    oifname \"%s\" ip saddr %s masquerade comment \"remote-access devices: direct and LAN\"\n", lan, rp.V4)
		fmt.Fprintf(&sb, "    oifname \"%s\" ip6 saddr %s masquerade\n", lan, rp.V6)
	}
	sb.WriteString("  }\n}\n")
	return sb.String()
}

func renderExitNFT(t model.Topology, n model.Node, tunnels []Tunnel, exits []ExitPlan, groups []GroupPlan, mss nodeMSS) string {
	wan := n.WANInterface
	if wan == "" {
		wan = "eth0"
	}
	var sb strings.Builder
	sb.WriteString("#!/usr/sbin/nft -f\n")
	fmt.Fprintf(&sb, "# exit %s public NAT. Tunnel ULA and the LAN prefix are translated here, not on the home gateway.\n", n.ID)
	writeAtomicReplace(&sb, tableMain)
	sb.WriteString("table inet meridian {\n")
	writeGroupResolverDNAT(&sb, n, tunnels, exits, groups)
	if rets := exitHubReturns(t, n, tunnels); rets != nil {
		writeExitHubReturnNFT(&sb, rets)
		// The hub-independent resolver address exists with a backup hub
		// only; it is then answered on every hub leg, the Mesh leg included.
		if e, ok := exitByID(exits, n.ID); ok && t.DualHub() {
			writeExitResolverDNAT(&sb, e, rets)
		}
	}
	writeMeshVethNFT(&sb, n, tunnels)
	writeNestedExitResolverDNAT(&sb, t, n, tunnels, exits)
	writeRelayExitNFT(&sb, n, tunnels, exits)
	writeCarrierNFT(&sb, t, n, tunnels, exits)
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
	writeNodeMSS(&sb, nodeTunnelIfaces(n, tunnels), mss)
	sb.WriteString("}\n")
	return sb.String()
}

// writeGroupResolverDNAT answers the region-group resolver addresses on an
// exit, on the managed ingress a group's queries use: the hub's WireGuard
// tunnels to an exit the hub can switch a group to (switchable) — its
// direct tunnel and, when it has one, its Mesh leg (the same exit over the
// Cloudflare Mesh; the hub uses one of the two). The reply goes to the
// group's transit address, which this exit routes back into the tunnel
// the query arrived on (renderExitRoutes, exitHubReturns), the same return
// path as the group's data.
//
// A query to any address of validate.GroupResolverNet on those ingresses is
// DNATed to this exit's own tunnel resolver, the address its SmartDNS binds
// (renderExitDNS). Connection tracking turns the reply's source back into
// the resolver address the gateway asked, so the answer is accepted
// whatever source the resolver picks, and no second listener is needed.
// Every group address is answered, not only those of the groups this exit
// is in today. Queries arriving on any other interface (the WAN, the Mesh
// veth, another tunnel) are not translated. A topology with no switchable
// group renders nothing here.
func writeGroupResolverDNAT(sb *strings.Builder, n model.Node, tunnels []Tunnel, exits []ExitPlan, groups []GroupPlan) {
	any := false
	for _, g := range groups {
		any = any || g.Dynamic
	}
	e, ok := exitByID(exits, n.ID)
	if !any || !ok {
		return
	}
	if !switchable(e) {
		return
	}
	if e.DNSULA == "" {
		fmt.Fprintf(sb, "  # no tunnel resolver on %s: region-group resolver addresses are not answered here\n", n.ID)
		return
	}
	var ifs []string
	seen := map[string]bool{}
	for _, tun := range tunnels {
		// A nested exit's group queries arrive from its relay exit.
		// A direct-exit gateway is the hub for its exits (tunnelsDirect).
		fromHub := tun.West.Role == model.RoleHub || model.IsNested(n) && tun.West.ID == n.ViaExit ||
			tun.West.Role == model.RoleGateway && tunnelsDirect(tunnels)
		// A standby tunnel carries no group; the Mesh leg is the exception:
		// it is the hub's other leg to this same exit.
		if tun.East.ID != n.ID || !fromHub || (tun.Standby && !tun.MeshLeg()) || seen[tun.Iface()] {
			continue
		}
		seen[tun.Iface()] = true
		ifs = append(ifs, "\""+tun.Iface()+"\"")
	}
	if len(ifs) == 0 {
		return
	}
	sortStrings(ifs)
	sb.WriteString("  chain group_dns {\n    type nat hook prerouting priority dstnat; policy accept;\n")
	// One rule per protocol ("udp dport 53", "tcp dport 53"), never
	// "meta l4proto { tcp, udp } th dport 53": exits run on Ubuntu 20.04
	// too, whose nft 0.9.3 is older than the transport-header expression
	// is known to be accepted; the two rules match exactly the same packets.
	if behind := behindSources(exits, n.ID); len(behind) > 0 {
		// Queries of the exits behind this node (the hub rewrote the
		// group's source to theirs) are forwarded to them, never answered
		// here.
		fmt.Fprintf(sb, "    iifname { %s } ip6 saddr { %s } accept comment \"region-group queries of the exits behind this node: not answered here\"\n", strings.Join(ifs, ", "), strings.Join(behind, ", "))
	}
	for _, proto := range []string{"udp", "tcp"} {
		fmt.Fprintf(sb, "    iifname { %s } ip6 daddr %s %s dport 53 dnat ip6 to %s comment \"region-group resolver addresses: this exit's tunnel resolver\"\n",
			strings.Join(ifs, ", "), validate.GroupResolverNet, proto, e.DNSULA)
	}
	sb.WriteString("  }\n")
}

// endpointAccess classifies every tunnel endpoint address for the
// gateway's classify chain (validate.EndpointAccess has the policy): the
// endpoint_v4/endpoint_v6 of both ends of every tunnel and an IX hub's
// ingress, in tunnel order. Foreign endpoints go to the default group only
// when its target is an exit tunnel carrying that family; the gateway's own
// foreign tunnel peers (the backup hub) are tunnel too (no recursion: see
// validate.ClassifyEndpoint).
func endpointAccess(t model.Topology, tunnels []Tunnel, groups []GroupPlan) []validate.EndpointAccess {
	def, ok := defaultExit(t, groups)
	tun4 := ok && def.Mark >= markExitBase && def.Mark != markReject
	tun6 := tun4 && def.V6
	peers := map[string]bool{}
	for _, tun := range tunnels {
		if tun.West.Role == model.RoleGateway {
			peers[tun.East.ID] = true
		}
		if tun.East.Role == model.RoleGateway {
			peers[tun.West.ID] = true
		}
	}
	var out []validate.EndpointAccess
	seen := map[string]bool{}
	for _, tun := range tunnels {
		for _, n := range []model.Node{tun.West, tun.East} {
			for _, raw := range []string{n.EndpointV4, n.EndpointV6, ixIngress(n)} {
				a, err := netip.ParseAddr(strings.TrimSpace(raw))
				if err != nil || a.Is4In6() || seen[a.String()] {
					continue
				}
				seen[a.String()] = true
				out = append(out, validate.ClassifyEndpoint(n, a.String(), peers[n.ID], tun4, tun6))
			}
		}
	}
	return out
}

// ixIngress is an IX hub's domestic ingress address ("" otherwise).
func ixIngress(n model.Node) string {
	if model.IsIXHub(n) {
		return n.IngressV4
	}
	return ""
}

func renderTransitNFT(t model.Topology, n model.Node, tunnels []Tunnel, groups []GroupPlan, mss nodeMSS) string {
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
	writeAtomicReplace(&sb, tableMain)
	sb.WriteString("table inet meridian {\n")
	if rets := ingressReturns(t, n, tunnels); rets != nil {
		writeIngressReturnNFT(&sb, rets)
	}
	if n.Role == model.RoleHub {
		writeHubNestedSNAT(&sb, groups)
	}
	writeMeshVethNFT(&sb, n, tunnels)
	if n.Role == model.RoleRelay {
		writeSpeedTestNFT(&sb, relaySpeedLegs(t, planShare(t, tunnels), n.ID))
	}
	if len(ports) > 0 {
		parts := make([]string, len(ports))
		for i, p := range ports {
			parts[i] = fmt.Sprintf("%d", p)
		}
		fmt.Fprintf(&sb, "  chain input {\n    type filter hook input priority filter; policy accept;\n    iifname \"%s\" udp dport { %s } drop comment \"wss wireguard port is reached only via local wstunnel\"\n  }\n", wan, strings.Join(parts, ", "))
	} else {
		sb.WriteString("  chain forward {\n    type filter hook forward priority filter; policy accept;\n  }\n")
	}
	writeNodeMSS(&sb, nodeTunnelIfaces(n, tunnels), mss, meshLegMSS(t, n, tunnels, mss)...)
	sb.WriteString("}\n")
	return sb.String()
}

const (
	tableMain  = "meridian"
	tableGuard = "meridian_guard"
	// guardPriority puts the guard ahead of every Meridian forward chain
	// (mss at mangle -150, doh at filter 0) and of the usual filter-priority
	// chains of other tables. Order is not what makes it binding: a drop in
	// any base chain is final, while an accept only ends that one chain, so
	// no accept elsewhere can let a packet past this table.
	guardPriority = -200
	// exitMarkLast is the highest exit mark the routes script cleans up
	// (0x101 + 63, the selector loop in render_routes.go).
	exitMarkLast = markExitBase + 63
)

// guardLastExitMark is the top of the exit-mark range the guard lets into
// a tunnel: the routes script's range, widened if a topology has more exit
// and region-group marks. The routes script's selector cleanup uses the
// same bound, so adding or removing groups and members keeps both in step.
func guardLastExitMark(exits []ExitPlan, groups ...GroupPlan) uint32 {
	last := exitMarkLast
	for _, m := range markPlans(exits, groups) {
		if m.Mark > last {
			last = m.Mark
		}
	}
	return last
}

// markPlan is one exit-range fwmark the gateway installs: a per-exit mark
// or a region-group mark.
type markPlan struct {
	Mark      uint32
	Index     int
	TransitV4 string
	TransitV6 string
}

func markPlans(exits []ExitPlan, groups []GroupPlan) []markPlan {
	out := make([]markPlan, 0, len(exits)+len(groups))
	for _, e := range exits {
		out = append(out, markPlan{e.Mark, e.Index, e.TransitV4, e.TransitV6})
	}
	for _, g := range groups {
		out = append(out, markPlan{g.Mark, g.Index, g.TransitV4, g.TransitV6})
	}
	return out
}

// writeAtomicReplace emits the create-then-delete prefix of the nft
// atomic-replacement idiom. "table" is a no-op when the table already
// exists and creates an empty one on first install, so "delete table" never
// fails; the table block that follows recreates it. All three are in the
// same file and so in the same netlink batch: if any later line is
// rejected, the kernel aborts the batch and the old table is untouched.
func writeAtomicReplace(sb *strings.Builder, table string) {
	fmt.Fprintf(sb, "table inet %s\n", table)
	fmt.Fprintf(sb, "delete table inet %s\n", table)
}

// gatewayTunnelIfaces lists every WireGuard interface on the gateway,
// including failover companions, so the guard keeps working when the
// failover script moves table 102 between them.
func gatewayTunnelIfaces(tunnels []Tunnel) []string {
	seen := map[string]bool{}
	var out []string
	for _, tun := range tunnels {
		if tun.West.Role != model.RoleGateway && tun.East.Role != model.RoleGateway {
			continue
		}
		name := tun.Iface()
		if name == "" || seen[name] {
			continue
		}
		seen[name] = true
		out = append(out, name)
	}
	sortStrings(out)
	return out
}

// writeGuardTable renders the LAN fail-closed guard. It lives in its own
// table so that deleting, breaking or replacing table inet meridian (which
// holds classification, DNS hijack and SNAT) cannot remove it, and it never
// references a set or chain of that table. It only looks at what the
// classifier leaves on the packet (the fwmark) and where routing sent it:
//
//   - mark 0x64 (domestic) may only leave on the LAN NIC, i.e. to ROS or a
//     LAN host via table 100. This is the intended direct path for domestic
//     IPv4 and IPv6 (chnroute, direct sets, private/LAN prefixes).
//   - an exit mark may only leave on a gateway WireGuard interface (table
//     102). An exit-marked packet routed to ROS is dropped.
//   - anything else forwarded from the LAN is dropped: unmarked traffic
//     (classification missing, or the IPv6 main-table default via ROS that
//     the routes script deliberately leaves without an iif rule), and
//     DNS/DoT that escaped the hijack.
//
// It hooks forward only, so RA, ND and traffic to the gateway itself
// (input) are not affected, and traffic arriving from a tunnel is not
// matched.
//
// With remote access on (rp != nil) the ingress set is the LAN NIC plus mra
// with the same rules; mra is never in tunnelIfaces, so an exit mark can
// never leave through it. Two narrow accepts let LAN hosts (and direct
// replies from ROS) reach the device pools on mra; nothing else may leave on
// mra from an ingress, so devices cannot reach each other unless the
// operator allows it (remote_access.allow_peers: two more accepts, mra to
// mra, the device pools only). iifname matches by name, so the early-boot
// copy loads before mra exists.
func writeGuardTable(sb *strings.Builder, lan string, tunnelIfaces []string, lastExitMark uint32, rp *remotePlan, reject bool) {
	sb.WriteString("# LAN fail-closed guard. Independent of table inet meridian: it reads only\n")
	sb.WriteString("# the fwmark and the output interface, so if classification is missing\n")
	sb.WriteString("# every forwarded LAN packet is unmarked and dropped here.\n")
	writeAtomicReplace(sb, tableGuard)
	fmt.Fprintf(sb, "table inet %s {\n", tableGuard)
	fmt.Fprintf(sb, "  chain forward {\n    type filter hook forward priority %d; policy accept;\n", guardPriority)
	in := fmt.Sprintf("\"%s\"", lan)
	if rp != nil {
		in = fmt.Sprintf("{ \"%s\", \"%s\" }", lan, rp.Iface)
	}
	fmt.Fprintf(sb, "    iifname %s meta l4proto { tcp, udp } th dport { 53, 853 } drop comment \"DNS is answered locally, never forwarded\"\n", in)
	if rp != nil {
		fmt.Fprintf(sb, "    iifname \"%s\" oifname \"%s\" ip daddr %s return comment \"LAN and direct replies to remote-access devices\"\n", lan, rp.Iface, rp.V4)
		fmt.Fprintf(sb, "    iifname \"%s\" oifname \"%s\" ip6 daddr %s return\n", lan, rp.Iface, rp.V6)
		if rp.AllowPeers {
			// From mra the source is always a device: WireGuard accepts only each peer's own addresses.
			// Classified packets only (the pools get the domestic mark): without the main table the
			// guard still drops device-to-device traffic, like everything else unmarked.
			fmt.Fprintf(sb, "    iifname \"%s\" oifname \"%s\" meta mark %#x ip daddr %s return comment \"remote-access devices reach each other (allow_peers)\"\n", rp.Iface, rp.Iface, markDomestic, rp.V4)
			fmt.Fprintf(sb, "    iifname \"%s\" oifname \"%s\" meta mark %#x ip6 daddr %s return\n", rp.Iface, rp.Iface, markDomestic, rp.V6)
		}
	}
	fmt.Fprintf(sb, "    iifname %s meta mark %#x oifname \"%s\" return comment \"domestic: direct via ROS or LAN only\"\n", in, markDomestic, lan)
	if len(tunnelIfaces) > 0 {
		quoted := make([]string, len(tunnelIfaces))
		for i, name := range tunnelIfaces {
			quoted[i] = "\"" + name + "\""
		}
		fmt.Fprintf(sb, "    iifname %s meta mark %#x-%#x oifname { %s } return comment \"exit marks: WireGuard only\"\n", in, markExitBase, lastExitMark, strings.Join(quoted, ", "))
	}
	if reject {
		// REJECT rules (model.ActionReject): refused at once, never routed.
		fmt.Fprintf(sb, "    iifname %s meta mark %#x meta l4proto tcp reject with tcp reset comment \"reject rules: TCP reset\"\n", in, markReject)
		fmt.Fprintf(sb, "    iifname %s meta mark %#x reject with icmpx port-unreachable comment \"reject rules: ICMP port unreachable\"\n", in, markReject)
	}
	fmt.Fprintf(sb, "    iifname %s counter drop comment \"fail closed: unclassified or misrouted LAN traffic, v4 and v6\"\n", in)
	sb.WriteString("  }\n}\n")
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

// ulaRange is fc00::/7. The gateway classifier drops forwarded traffic to it.
var ulaRange = netip.MustParsePrefix("fc00::/7")

// lanULAPrefix returns the LAN IPv6 prefix, masked, when it is a ULA: an
// IPv6 network inside fc00::/7 of length /48 or longer (what validation
// allows). Anything else, including a global prefix, returns false and
// leaves the classifier as it is, so such traffic is still dropped.
func lanULAPrefix(t model.Topology) (netip.Prefix, bool) {
	p, err := netip.ParsePrefix(strings.TrimSpace(t.Settings.LANIPv6Prefix))
	if err != nil || !p.Addr().Is6() || p.Addr().Is4In6() || p.Bits() < 48 || !ulaRange.Contains(p.Addr()) {
		return netip.Prefix{}, false
	}
	return p.Masked(), true
}

// ruleMatches are the classify matches of one rule, in order: its own
// sets, its rule-set's address sets, and the China lists for GEOIP,CN.
func ruleMatches(rp rulePlan) []string {
	out := []string{"ip daddr @" + rp.Set4}
	if !rp.FilterAAAA {
		out = append(out, "ip6 daddr @"+rp.Set6)
	}
	if rp.CIDR4 != "" {
		out = append(out, "ip daddr @"+rp.CIDR4)
		if rp.CIDR6 != "" {
			out = append(out, "ip6 daddr @"+rp.CIDR6)
		}
	}
	if isGeoIPCN(rp.Rule) {
		out = append(out, "ip daddr @chnroute")
		if !rp.FilterAAAA {
			out = append(out, "ip6 daddr @chnroute6")
		}
	}
	return out
}

func isGeoIPCN(r model.Rule) bool {
	return r.MatchType == model.MatchGeoIP && strings.EqualFold(strings.TrimSpace(r.MatchValue), "cn")
}

// usesReject: some enabled rule's target (directly or through its service
// group) is reject.
func usesReject(t model.Topology) bool {
	for _, r := range t.Rules {
		if r.Enabled && r.MatchType != model.MatchQUICReject && t.ResolveTarget(r).Kind == model.ActionReject {
			return true
		}
	}
	return false
}

// quicChain is the QUIC switch (model.MatchQUICReject): UDP to port 443 of
// tunnelled traffic (exit and group marks) from the LAN or remote access is
// refused with ICMP port unreachable, so clients fall back to TCP at once.
// Addresses of the rules ABOVE the switch row are exempt, in list order as
// classified (an address in an exempt set was classified by that rule or an
// earlier one, all above the row). Direct traffic (domestic mark) is never
// touched. "" when the list has no switch row.
func quicChain(rules []rulePlan, in string, first, last uint32) string {
	at := -1
	for i, rp := range rules {
		if rp.QUIC {
			at = i
			break
		}
	}
	if at < 0 {
		return ""
	}
	var sb strings.Builder
	sb.WriteString("  chain quic {\n    type filter hook forward priority filter; policy accept;\n")
	for _, rp := range rules[:at] {
		for _, m := range ruleMatches(rp) {
			fmt.Fprintf(&sb, "    iifname %s udp dport 443 %s return comment \"above the QUIC switch: exempt\"\n", in, m)
		}
	}
	fmt.Fprintf(&sb, "    iifname %s meta mark %#x-%#x udp dport 443 reject with icmpx port-unreachable comment \"QUIC switch: tunnelled UDP 443 refused\"\n", in, first, last)
	sb.WriteString("  }\n\n")
	return sb.String()
}

// Traffic counter names, read by hostexec (GET /v1/traffic). The order is
// the API's order; renaming one is a protocol change.
var TrafficCounterNames = []string{"traffic_up_domestic", "traffic_up_foreign", "traffic_down_domestic", "traffic_down_foreign"}

// writeTrafficCounters adds named byte/packet counters for forwarded
// throughput. The chain only counts: no verdict, no mark or ct change, so
// classification and routing are untouched. It hooks forward at priority
// filter + 10, after the guard (-200) and the quic chain (filter) have
// dropped or rejected what they refuse, and forward only, so the gateway's
// own tunnel outer packets (output/input) are never counted.
//
//   - up: arriving on the ingress (LAN NIC, plus mra when remote access is
//     on); domestic is mark 0x64, foreign the exit-mark range.
//   - down: reply-direction packets leaving on the ingress. Replies are not
//     classified (no meta mark), so the path decides: from a WireGuard
//     tunnel is foreign, from the LAN NIC (ROS's direct replies) domestic.
//     ct direction reply keeps LAN-to-LAN or LAN-to-mra originals out.
//
// With settings.sniff on, managed TCP to the sniffed ports is redirected
// to the local forwarder: the LAN<->forwarder leg is local delivery
// (input/output), never forward, so chain traffic does not see it. The
// forwarder<->Internet leg is counted instead, where its mark is known:
//
//   - traffic_sniff_out (output, after sniff_out's confinement): the
//     forwarder's (meta skuid SniffUID) original-direction TCP, port 53
//     excluded. Domestic is mark 0x64 out of the LAN NIC, foreign the
//     exit-mark range (relay bits masked) into a WireGuard tunnel. Its
//     replies to the LAN clients are ct direction reply and not counted;
//     WireGuard outer packets carry the forwarder's socket but are UDP with
//     the underlay mark and leave the LAN NIC (or lo for WSS), so they match
//     neither rule. The gateway's own sockets (DNS, probes, wstunnel) are
//     not SniffUID.
//   - traffic_sniff_in (input): reply-direction TCP to a SniffUID socket
//     (early demux), domestic from the LAN NIC, foreign from a tunnel.
//
// Both chains only count. They are part of the counter block, so sniff off
// renders exactly what it did before.
func writeTrafficCounters(sb *strings.Builder, in, lan string, tunnelIfaces []string, lastExitMark uint32, sniff bool) {
	for _, n := range TrafficCounterNames {
		fmt.Fprintf(sb, "  counter %s {\n  }\n", n)
	}
	sb.WriteString("  chain traffic {\n    type filter hook forward priority filter + 10; policy accept;\n")
	fmt.Fprintf(sb, "    iifname %s meta mark %#x counter name \"traffic_up_domestic\"\n", in, markDomestic)
	fmt.Fprintf(sb, "    iifname %s meta mark %#x-%#x counter name \"traffic_up_foreign\"\n", in, markExitBase, lastExitMark)
	fmt.Fprintf(sb, "    ct direction reply iifname \"%s\" oifname %s counter name \"traffic_down_domestic\"\n", lan, in)
	if len(tunnelIfaces) > 0 {
		quoted := make([]string, len(tunnelIfaces))
		for i, name := range tunnelIfaces {
			quoted[i] = "\"" + name + "\""
		}
		fmt.Fprintf(sb, "    ct direction reply iifname { %s } oifname %s counter name \"traffic_down_foreign\"\n", strings.Join(quoted, ", "), in)
	}
	if !sniff {
		sb.WriteString("  }\n\n")
		return
	}
	// Single blank line only after the last chain: the block ends at the
	// first "  }\n\n" after chain traffic.
	sb.WriteString("  }\n")
	tun := ""
	if len(tunnelIfaces) > 0 {
		quoted := make([]string, len(tunnelIfaces))
		for i, name := range tunnelIfaces {
			quoted[i] = "\"" + name + "\""
		}
		tun = "{ " + strings.Join(quoted, ", ") + " }"
	}
	sb.WriteString("  chain traffic_sniff_out {\n    type filter hook output priority filter + 20; policy accept;\n")
	fmt.Fprintf(sb, "    meta skuid %d ct direction original meta l4proto tcp tcp dport != 53 meta mark & %s == %#x oifname \"%s\" counter name \"traffic_up_domestic\" comment \"the forwarder's direct connections\"\n", SniffUID, hexMark(markNoShare), markDomestic, lan)
	if tun != "" {
		fmt.Fprintf(sb, "    meta skuid %d ct direction original meta l4proto tcp tcp dport != 53 meta mark & %s %#x-%#x oifname %s counter name \"traffic_up_foreign\" comment \"the forwarder's tunnelled connections\"\n", SniffUID, hexMark(markNoShare), markExitBase, lastExitMark, tun)
	}
	sb.WriteString("  }\n")
	sb.WriteString("  chain traffic_sniff_in {\n    type filter hook input priority filter + 10; policy accept;\n")
	fmt.Fprintf(sb, "    ct direction reply meta l4proto tcp tcp sport != 53 meta skuid %d iifname \"%s\" counter name \"traffic_down_domestic\"\n", SniffUID, lan)
	if tun != "" {
		fmt.Fprintf(sb, "    ct direction reply meta l4proto tcp tcp sport != 53 meta skuid %d iifname %s counter name \"traffic_down_foreign\"\n", SniffUID, tun)
	}
	sb.WriteString("  }\n\n")
}

// tunnelsDirect: the tunnels of a direct-exit topology (no relay, hub or
// IX at either end of any tunnel; model.Topology.DirectExits).
func tunnelsDirect(tunnels []Tunnel) bool {
	gw := false
	for _, tun := range tunnels {
		for _, n := range []model.Node{tun.West, tun.East} {
			switch n.Role {
			case model.RoleRelay, model.RoleHub, model.RoleIX:
				return false
			case model.RoleGateway:
				gw = true
			}
		}
	}
	return gw
}
