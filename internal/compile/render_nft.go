package compile

import (
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"

	"github.com/radowitz/meridian/internal/mesh"
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
		return renderExitNFT(t, n, tunnels, exits, groups)
	default:
		return renderTransitNFT(t, n, tunnels, groups)
	}
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
	var underlay []string
	seen := map[string]bool{}
	for _, tun := range tunnels {
		for _, ip := range []string{tun.West.EndpointV4, tun.East.EndpointV4, ixIngress(tun.West), ixIngress(tun.East)} {
			if ip == "" || seen[ip] {
				continue
			}
			seen[ip] = true
			underlay = append(underlay, ip)
		}
	}
	writeSet(&sb, "underlay4", "ipv4_addr", false, underlay)

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
	sb.WriteString("    ip daddr @underlay4 drop comment \"clients cannot bypass the tunnel by talking to an endpoint\"\n")
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
		writeShareNFT(&sb, sp)
	}
	if q := quicChain(rules, in, markExitBase, guardLastExitMark(exits, groups...)); q != "" {
		sb.WriteString(q)
	}
	snp := planSniff(t, exits, groups, decisions)
	if snp != nil {
		writeSniffNFT(&sb, t, snp, in, rp, gatewayTunnelIfaces(tunnels), sp != nil, mss4, mss6, clamps)
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

	// Only lower an advertised MSS. Raising a small MSS black-holes TCP.
	sb.WriteString("  chain mss {\n    type filter hook forward priority mangle; policy accept;\n")
	if rp != nil {
		for _, dir := range []string{"iifname", "oifname"} {
			fmt.Fprintf(&sb, "    %s \"%s\" tcp flags syn meta nfproto ipv4 tcp option maxseg size > %d tcp option maxseg size set %d\n", dir, rp.Iface, rp.mss4(), rp.mss4())
			fmt.Fprintf(&sb, "    %s \"%s\" tcp flags syn meta nfproto ipv6 tcp option maxseg size > %d tcp option maxseg size set %d\n", dir, rp.Iface, rp.mss6(), rp.mss6())
		}
	}
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

`, v4src, v4src, v6src, v6src, panelPort(t), lanNet(t), panelPort(t))

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

func renderExitNFT(t model.Topology, n model.Node, tunnels []Tunnel, exits []ExitPlan, groups []GroupPlan) string {
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
		if e, ok := exitByID(exits, n.ID); ok {
			writeExitResolverDNAT(&sb, e, rets)
		}
	}
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
	sb.WriteString("}\n")
	return sb.String()
}

// writeGroupResolverDNAT answers the region-group resolver addresses on an
// exit, on exactly the two managed ingresses a group's queries can use:
//
//   - the hub's direct WireGuard tunnel, on an exit the hub can switch a
//     group to (switchable). The reply goes to the group's transit
//     address, which this exit routes back into the tunnel
//     (renderExitRoutes), the same return path as the group's data.
//   - the Mesh veth mmesh, on an exit that is some group's Mesh resolver
//     (GroupPlan.MeshResolver): while the hub has the group on the Mesh
//     hop, the query reaches this exit through the Cloudflare Mesh (its
//     Mesh node publishes the group's resolver/128) and its sidecar. The
//     connection gets ct mark markMeshDNS and its source is rewritten on
//     input to meshDNSAnchor; every reply packet is marked and routed by
//     table tableMeshDNS back onto mmesh (meshDNSReturnShell), never into
//     the hub tunnel (the WireGuard path is the one that failed) and never
//     out of the WAN. Whatever source the query carries (the transit
//     address or a Mesh address after the sidecar's source NAT), the
//     reply follows the connection back into the sidecar.
//
// A query to any address of validate.GroupResolverNet on those ingresses is
// DNATed to this exit's own tunnel resolver, the address its SmartDNS binds
// (renderExitDNS). Connection tracking turns the reply's source back into
// the resolver address the gateway asked, so the answer is accepted
// whatever source the resolver picks, and no second listener is needed.
// Every group address is answered, not only those of the groups this exit
// is in today. Queries arriving on any other interface (the WAN, another
// tunnel) are not translated. A topology with no switchable group renders
// nothing here.
func writeGroupResolverDNAT(sb *strings.Builder, n model.Node, tunnels []Tunnel, exits []ExitPlan, groups []GroupPlan) {
	any := false
	for _, g := range groups {
		any = any || g.Dynamic
	}
	e, ok := exitByID(exits, n.ID)
	if !any || !ok {
		return
	}
	meshGroups := meshDNSGroups(groups, n.ID)
	if !switchable(e) && len(meshGroups) == 0 {
		return
	}
	if e.DNSULA == "" {
		fmt.Fprintf(sb, "  # no tunnel resolver on %s: region-group resolver addresses are not answered here\n", n.ID)
		return
	}
	var ifs []string
	seen := map[string]bool{}
	if switchable(e) {
		for _, tun := range tunnels {
			// A nested exit's group queries arrive from its relay exit.
			fromHub := tun.West.Role == model.RoleHub || model.IsNested(n) && tun.West.ID == n.ViaExit
			if tun.East.ID != n.ID || !fromHub || tun.Standby || seen[tun.Iface()] {
				continue
			}
			seen[tun.Iface()] = true
			ifs = append(ifs, "\""+tun.Iface()+"\"")
		}
	}
	if len(ifs) == 0 && len(meshGroups) == 0 {
		return
	}
	sortStrings(ifs)
	sb.WriteString("  chain group_dns {\n    type nat hook prerouting priority dstnat; policy accept;\n")
	// One rule per protocol ("udp dport 53", "tcp dport 53"), never
	// "meta l4proto { tcp, udp } th dport 53": exits run on Ubuntu 20.04
	// too, whose nft 0.9.3 is older than the transport-header expression
	// is known to be accepted; the two rules match exactly the same packets.
	if behind := behindSources(exits, n.ID); len(behind) > 0 && len(ifs) > 0 {
		// Queries of the exits behind this node (the hub rewrote the
		// group's source to theirs) are forwarded to them, never answered
		// here.
		fmt.Fprintf(sb, "    iifname { %s } ip6 saddr { %s } accept comment \"region-group queries of the exits behind this node: not answered here\"\n", strings.Join(ifs, ", "), strings.Join(behind, ", "))
	}
	if len(ifs) > 0 {
		for _, proto := range []string{"udp", "tcp"} {
			fmt.Fprintf(sb, "    iifname { %s } ip6 daddr %s %s dport 53 dnat ip6 to %s comment \"region-group resolver addresses: this exit's tunnel resolver\"\n",
				strings.Join(ifs, ", "), validate.GroupResolverNet, proto, e.DNSULA)
		}
	}
	if len(meshGroups) > 0 {
		var ids []string
		for _, g := range meshGroups {
			ids = append(ids, verifyLabel(g.Group.ID))
		}
		for _, proto := range []string{"udp", "tcp"} {
			fmt.Fprintf(sb, "    iifname \"%s\" ip6 daddr %s %s dport 53 dnat ip6 to %s comment \"region-group resolver addresses over the Mesh backup (groups %s)\"\n",
				mesh.HostIface, validate.GroupResolverNet, proto, e.DNSULA, strings.Join(ids, " "))
		}
	}
	sb.WriteString("  }\n")
	if len(meshGroups) == 0 {
		return
	}
	fmt.Fprintf(sb, `  chain group_dns_mesh_in {
    type filter hook prerouting priority mangle; policy accept;
    iifname "%[1]s" ip6 daddr %[2]s udp dport 53 ct mark set %#[3]x comment "Mesh ingress of region-group queries: reply on mmesh"
    iifname "%[1]s" ip6 daddr %[2]s tcp dport 53 ct mark set %#[3]x comment "Mesh ingress of region-group queries: reply on mmesh"
  }
  chain group_dns_mesh_anchor {
    type nat hook input priority 100; policy accept;
    iifname "%[1]s" ct mark %#[3]x ip6 daddr %[4]s udp dport 53 snat ip6 to %[5]s comment "the reply has a route at the socket: table %[6]d"
    iifname "%[1]s" ct mark %#[3]x ip6 daddr %[4]s tcp dport 53 snat ip6 to %[5]s comment "the reply has a route at the socket: table %[6]d"
  }
  chain group_dns_mesh_reply {
    type route hook output priority mangle; policy accept;
    ct direction reply ct mark %#[3]x meta mark set %#[3]x comment "every reply packet: table %[6]d, mmesh or blackhole"
  }
`, mesh.HostIface, validate.GroupResolverNet, markMeshDNS, e.DNSULA, meshDNSAnchor, tableMeshDNS)
}

// ixIngress is an IX hub's domestic ingress address ("" otherwise).
func ixIngress(n model.Node) string {
	if model.IsIXHub(n) {
		return n.IngressV4
	}
	return ""
}

func renderTransitNFT(t model.Topology, n model.Node, tunnels []Tunnel, groups []GroupPlan) string {
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
// mra from an ingress, so devices cannot reach each other. iifname matches
// by name, so the early-boot copy loads before mra exists.
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
