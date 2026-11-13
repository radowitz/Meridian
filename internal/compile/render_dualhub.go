package compile

import (
	"fmt"
	"strings"

	"github.com/radowitz/meridian/internal/model"
)

// hubReturn is one hub's return path on an exit.
type hubReturn struct {
	Hub   string
	Tier  model.HubTier
	Iface string
	Mark  uint32
	Table int
}

// exitHubReturns lists the exit's ingress tunnel from each hub, primary
// first, when the topology has a backup hub and the exit has a tunnel from
// both (validation requires that of every exit then). Nil otherwise: a
// single-hub exit compiles as before.
func exitHubReturns(t model.Topology, n model.Node, tunnels []Tunnel) []hubReturn {
	if !t.DualHub() || n.Role != model.RoleExit {
		return nil
	}
	p, _ := t.PrimaryHub()
	b, _ := t.BackupHub()
	pt := exitIngress(n, tunnels, p.ID)
	bt := exitIngress(n, tunnels, b.ID)
	if pt.LinkID == "" || bt.LinkID == "" || pt.West.ID != p.ID || bt.West.ID != b.ID {
		return nil
	}
	return []hubReturn{
		{Hub: p.ID, Tier: model.HubPrimary, Iface: pt.Iface(), Mark: markHubReturnPrimary, Table: tableHubReturnPrimary},
		{Hub: b.ID, Tier: model.HubBackup, Iface: bt.Iface(), Mark: markHubReturnBackup, Table: tableHubReturnBackup},
	}
}

// renderExitHubReturnRoutes installs one table per hub: the home prefixes
// (the LAN, 10.66.0.0/16 with the transit addresses and the hubs' tunnel
// addresses, fd66::/48 with the transit, tunnel and resolver addresses) on
// that hub's tunnel, over a blackhole default, and the fwmark rule that
// selects it.
func renderExitHubReturnRoutes(sb *strings.Builder, t model.Topology, rets []hubReturn) {
	sb.WriteString("# hub return paths: a reply leaves through the hub tunnel its connection arrived on\n")
	for i, r := range rets {
		prio := prioHubReturn + i
		fmt.Fprintf(sb, "# %s hub %s: mark %#x table %d dev %s\n", r.Tier, r.Hub, r.Mark, r.Table, r.Iface)
		fmt.Fprintf(sb, "ip route replace %s dev %s table %d\n", lanNet(t), r.Iface, r.Table)
		fmt.Fprintf(sb, "ip route replace 10.66.0.0/16 dev %s table %d\n", r.Iface, r.Table)
		fmt.Fprintf(sb, "ip -6 route replace fd66::/48 dev %s table %d\n", r.Iface, r.Table)
		if t.Settings.LANIPv6Prefix != "" {
			fmt.Fprintf(sb, "ip -6 route replace %s dev %s table %d\n", t.Settings.LANIPv6Prefix, r.Iface, r.Table)
		}
		fmt.Fprintf(sb, "ip route replace blackhole default metric 32767 table %d\n", r.Table)
		fmt.Fprintf(sb, "ip -6 route replace blackhole default metric 32767 table %d\n", r.Table)
		fmt.Fprintf(sb, "del_rule ip rule del fwmark %#x lookup %d\n", r.Mark, r.Table)
		fmt.Fprintf(sb, "ip rule add fwmark %#x lookup %d priority %d\n", r.Mark, r.Table, prio)
		fmt.Fprintf(sb, "del_rule ip -6 rule del fwmark %#x lookup %d\n", r.Mark, r.Table)
		fmt.Fprintf(sb, "ip -6 rule add fwmark %#x lookup %d priority %d\n", r.Mark, r.Table, prio)
	}
}

// writeExitHubReturnNFT: the connection mark by ingress hub tunnel and its
// restoration onto every reply packet, forwarded (prerouting) and local
// (output, rerouted by the route hook). The original direction is never
// marked, so forwarded traffic toward the internet keeps using the main
// table (the WAN).
func writeExitHubReturnNFT(sb *strings.Builder, rets []hubReturn) {
	sb.WriteString("  chain hub_return_in {\n    type filter hook prerouting priority mangle; policy accept;\n")
	for _, r := range rets {
		fmt.Fprintf(sb, "    iifname \"%s\" ct direction original ct mark set %#x comment \"arrived from the %s hub %s\"\n", r.Iface, r.Mark, r.Tier, r.Hub)
	}
	for _, r := range rets {
		fmt.Fprintf(sb, "    ct direction reply ct mark %#x meta mark set %#x comment \"reply: back through the %s hub\"\n", r.Mark, r.Mark, r.Tier)
	}
	sb.WriteString("  }\n  chain hub_return_out {\n    type route hook output priority mangle; policy accept;\n")
	for _, r := range rets {
		fmt.Fprintf(sb, "    ct direction reply ct mark %#x meta mark set %#x comment \"local reply (resolver, ping): back through the %s hub\"\n", r.Mark, r.Mark, r.Tier)
	}
	sb.WriteString("  }\n")
}

// writeExitResolverDNAT answers the exit's hub-independent resolver address
// (ExitPlan.Resolver) on its tunnels from both hubs, with its own tunnel
// resolver. One rule per protocol (nft 0.9.3 on Ubuntu 20.04).
func writeExitResolverDNAT(sb *strings.Builder, e ExitPlan, rets []hubReturn) {
	if e.DNSULA == "" || len(rets) == 0 {
		return
	}
	var ifs []string
	for _, r := range rets {
		ifs = append(ifs, "\""+r.Iface+"\"")
	}
	sb.WriteString("  chain exit_dns {\n    type nat hook prerouting priority dstnat; policy accept;\n")
	for _, proto := range []string{"udp", "tcp"} {
		fmt.Fprintf(sb, "    iifname { %s } ip6 daddr %s %s dport 53 dnat ip6 to %s comment \"this exit's resolver address, from either hub\"\n", strings.Join(ifs, ", "), e.Resolver, proto, e.DNSULA)
	}
	sb.WriteString("  }\n")
}

// ixHubMarker is the line an IX hub's meridian-up.sh carries for the
// preflight: "# meridian-ix-hub: ingress=<a> iface=<i|-> egress=<b|->".
func ixHubMarker(n model.Node) string {
	if !model.IsIXHub(n) {
		return ""
	}
	iface, egress := n.IngressInterface, n.EndpointV4
	if iface == "" {
		iface = "-"
	}
	if egress == "" {
		egress = "-"
	}
	return fmt.Sprintf("# meridian-ix-hub: ingress=%s iface=%s egress=%s\n", n.IngressV4, iface, egress)
}
