package compile

import (
	"fmt"
	"strings"

	"github.com/radowitz/meridian/internal/model"
)

// hubReturn is one hub leg's return path on an exit.
type hubReturn struct {
	Hub   string
	Tier  model.HubTier
	Iface string
	Mark  uint32
	Table int
	Prio  int
	// Mesh: the leg is that hub's Mesh leg (a WireGuard leg carried
	// over the Cloudflare Mesh), not its direct tunnel.
	Mesh bool
}

// exitMeshReturn: exit n has a Mesh leg from the primary hub next to that
// hub's direct tunnel, so its replies must follow the leg a connection
// arrived on (exitHubReturns).
func exitMeshReturn(t model.Topology, n model.Node) bool {
	m, ok := t.MeshLegOf(primaryHubID(t), n.ID)
	return ok && !m.Sole
}

// exitBackupMeshReturn: exit n has a Mesh leg from the backup hub next to
// that hub's direct tunnel (a dual-hub topology only).
func exitBackupMeshReturn(t model.Topology, n model.Node) bool {
	b, ok := t.BackupHub()
	if !ok {
		return false
	}
	m, ok := t.MeshLegOf(b.ID, n.ID)
	return ok && !m.Sole
}

// exitHubReturns lists the exit's ingress tunnels from the hubs when there
// is more than one way in: the primary hub's direct tunnel first; the
// backup hub's, when the topology has a backup hub and the exit has a
// tunnel from both (validation requires that of every exit then); the
// primary hub's Mesh leg when the exit has one; and the backup hub's Mesh
// leg when the exit has one (each leg its own mark, table and priority, so
// a reply always leaves on the leg — and toward the hub — its connection
// arrived from). Nil otherwise: an exit with one hub tunnel compiles as
// before.
func exitHubReturns(t model.Topology, n model.Node, tunnels []Tunnel) []hubReturn {
	if n.Role != model.RoleExit {
		return nil
	}
	p, _ := t.PrimaryHub()
	pt := exitIngress(n, tunnels, p.ID)
	var rets []hubReturn
	var bleg Tunnel
	if t.DualHub() {
		b, _ := t.BackupHub()
		bt := exitIngress(n, tunnels, b.ID)
		if pt.LinkID == "" || bt.LinkID == "" || pt.West.ID != p.ID || bt.West.ID != b.ID {
			return nil
		}
		rets = []hubReturn{
			{Hub: p.ID, Tier: model.HubPrimary, Iface: pt.Iface(), Mark: markHubReturnPrimary, Table: tableHubReturnPrimary, Prio: prioHubReturn},
			{Hub: b.ID, Tier: model.HubBackup, Iface: bt.Iface(), Mark: markHubReturnBackup, Table: tableHubReturnBackup, Prio: prioHubReturn + 1},
		}
		if l := hubMeshLeg(tunnels, n.ID, b.ID); l.LinkID != "" && l.Standby {
			bleg = l
		}
	}
	leg := hubMeshLeg(tunnels, n.ID, p.ID)
	if leg.LinkID != "" && leg.Standby {
		if rets == nil {
			if pt.LinkID == "" || pt.West.ID != p.ID {
				return nil
			}
			rets = []hubReturn{{Hub: p.ID, Tier: model.HubPrimary, Iface: pt.Iface(), Mark: markHubReturnPrimary, Table: tableHubReturnPrimary, Prio: prioHubReturn}}
		}
		rets = append(rets, hubReturn{Hub: p.ID, Tier: model.HubPrimary, Iface: leg.Iface(), Mark: markHubReturnMesh, Table: tableHubReturnMesh, Prio: prioHubReturn + 2, Mesh: true})
	}
	// No Mesh leg, or the Mesh leg is the exit's one tunnel (exitIngress).
	if bleg.LinkID != "" {
		rets = append(rets, hubReturn{Hub: bleg.West.ID, Tier: model.HubBackup, Iface: bleg.Iface(), Mark: markHubReturnMeshBackup, Table: tableHubReturnMeshBackup, Prio: prioHubReturn + 3, Mesh: true})
	}
	return rets
}

// label names a return path in comments.
func (r hubReturn) label() string {
	if r.Mesh {
		return fmt.Sprintf("Mesh leg of the %s hub", r.Tier)
	}
	return fmt.Sprintf("%s hub", r.Tier)
}

// renderExitHubReturnRoutes installs one table per hub leg: the home
// prefixes (the LAN, 10.66.0.0/16 with the transit addresses and the hubs'
// tunnel addresses, fd66::/48 with the transit, tunnel and resolver
// addresses) on that leg's tunnel, over a blackhole default, and the fwmark
// rule that selects it.
func renderExitHubReturnRoutes(sb *strings.Builder, t model.Topology, rets []hubReturn) {
	sb.WriteString("# hub return paths: a reply leaves through the hub tunnel its connection arrived on\n")
	for _, r := range rets {
		fmt.Fprintf(sb, "# %s %s: mark %#x table %d dev %s\n", r.label(), r.Hub, r.Mark, r.Table, r.Iface)
		fmt.Fprintf(sb, "ip route replace %s dev %s table %d\n", lanNet(t), r.Iface, r.Table)
		fmt.Fprintf(sb, "ip route replace 10.66.0.0/16 dev %s table %d\n", r.Iface, r.Table)
		fmt.Fprintf(sb, "ip -6 route replace fd66::/48 dev %s table %d\n", r.Iface, r.Table)
		if t.Settings.LANIPv6Prefix != "" {
			fmt.Fprintf(sb, "ip -6 route replace %s dev %s table %d\n", t.Settings.LANIPv6Prefix, r.Iface, r.Table)
		}
		fmt.Fprintf(sb, "ip route replace blackhole default metric 32767 table %d\n", r.Table)
		fmt.Fprintf(sb, "ip -6 route replace blackhole default metric 32767 table %d\n", r.Table)
		fmt.Fprintf(sb, "del_rule ip rule del fwmark %#x lookup %d\n", r.Mark, r.Table)
		fmt.Fprintf(sb, "ip rule add fwmark %#x lookup %d priority %d\n", r.Mark, r.Table, r.Prio)
		fmt.Fprintf(sb, "del_rule ip -6 rule del fwmark %#x lookup %d\n", r.Mark, r.Table)
		fmt.Fprintf(sb, "ip -6 rule add fwmark %#x lookup %d priority %d\n", r.Mark, r.Table, r.Prio)
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
		fmt.Fprintf(sb, "    iifname \"%s\" ct direction original ct mark set %#x comment \"arrived from the %s %s\"\n", r.Iface, r.Mark, r.label(), r.Hub)
	}
	for _, r := range rets {
		fmt.Fprintf(sb, "    ct direction reply ct mark %#x meta mark set %#x comment \"reply: back through the %s\"\n", r.Mark, r.Mark, r.label())
	}
	sb.WriteString("  }\n  chain hub_return_out {\n    type route hook output priority mangle; policy accept;\n")
	for _, r := range rets {
		fmt.Fprintf(sb, "    ct direction reply ct mark %#x meta mark set %#x comment \"local reply (resolver, ping): back through the %s\"\n", r.Mark, r.Mark, r.label())
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
