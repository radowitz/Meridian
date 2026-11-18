package compile

import (
	"fmt"
	"strings"
	"time"

	"github.com/radowitz/meridian/internal/mesh"
	"github.com/radowitz/meridian/internal/model"
	"github.com/radowitz/meridian/internal/pool"
)

func renderRoutes(t model.Topology, n model.Node, tunnels []Tunnel, exits []ExitPlan, groups []GroupPlan) string {
	var sb strings.Builder
	sb.WriteString("#!/bin/bash\n")
	sb.WriteString("# Policy routes for one Meridian node. Safe to re-run.\n")
	sb.WriteString("# fd66::/48 is never given a next hop of the ROS gateway.\n")
	sb.WriteString("set -euo pipefail\n")
	if n.Role == model.RoleGateway {
		if sp := planShare(t, tunnels); sp != nil {
			sb.WriteString(shareInstallBegin(sp))
		}
	}
	sb.WriteString("del_rule() {\n")
	sb.WriteString("  while \"$@\" >/dev/null 2>&1; do :; done || true\n")
	sb.WriteString("}\n")
	writeHarden(&sb, sysctlIfaces(t, n, tunnelsFor(tunnels, n.ID)))

	switch n.Role {
	case model.RoleGateway:
		renderGatewayRoutes(&sb, t, tunnels, exits, groups)
	case model.RoleRelay:
		renderRelayRoutes(&sb, t, n, tunnels)
	case model.RoleHub:
		renderHubRoutes(&sb, t, n, tunnels, exits, groups)
	case model.RoleExit:
		renderExitRoutes(&sb, t, n, tunnels)
		renderRelayExitRoutes(&sb, t, n, tunnels, exits)
		renderCarrierRoutes(&sb, n, exits)
		renderMeshUnderlayRoutes(&sb, n, tunnels)
		if n.DualstackRelay {
			renderDualstackForward(&sb, t, n, tunnels, exits)
		}
	default:
		sb.WriteString("echo \"no routes for role " + string(n.Role) + "\"\n")
	}
	if n.Role == model.RoleGateway {
		if sp := planShare(t, tunnels); sp != nil {
			sb.WriteString(shareInstallFinish(sp))
		}
	}
	return dropEmptyOperandIPLines(sb.String())
}

func renderGatewayRoutes(sb *strings.Builder, t model.Topology, tunnels []Tunnel, exits []ExitPlan, groups []GroupPlan) {
	lan := gatewayLAN(t)
	ros := t.Settings.ROSIPv4
	lla := t.Settings.ROSv6LLA
	if lla == "" {
		lla = "fe80::1"
	}
	udp, wss, direct := gatewayIfaces(tunnels)
	if udp.LinkID == "" {
		udp = wss
	}
	lanQ, rosQ, llaQ := shQuote(lan), shQuote(ros), shQuote(lla)
	westQ := shQuote(udp.Iface())
	if t.DirectExits() {
		sb.WriteString("# meridian-west-preferred: none (direct exits)\n")
	} else {
		fmt.Fprintf(sb, "# meridian-west-preferred: udp %s\n", udp.Iface())
	}
	// Ciphertext is marked and pinned to the main table, ahead of every
	// exit rule, so the outer packet cannot re-enter the tunnel.
	fmt.Fprintf(sb, "del_rule ip rule del fwmark %#x lookup main\n", markUnderlay)
	fmt.Fprintf(sb, "ip rule add fwmark %#x lookup main priority %d\n", markUnderlay, prioUnderlay)
	fmt.Fprintf(sb, "del_rule ip -6 rule del fwmark %#x lookup main\n", markUnderlay)
	fmt.Fprintf(sb, "ip -6 rule add fwmark %#x lookup main priority %d\n", markUnderlay, prioUnderlay)
	seen := map[string]bool{}
	for _, tun := range tunnels {
		if tun.West.Role != model.RoleGateway {
			continue
		}
		ep := tun.Listener().EndpointV4
		if ep == "" || seen[ep] {
			continue
		}
		seen[ep] = true
		fmt.Fprintf(sb, "ip route replace %s via %s dev %s\n", shQuote(ep+"/32"), rosQ, lanQ)
	}
	lanNetQ := shQuote(lanNet(t))
	fmt.Fprintf(sb, "ip route replace %s dev %s table 100\n", lanNetQ, lanQ)
	fmt.Fprintf(sb, "ip route replace default via %s dev %s table 100\n", rosQ, lanQ)
	sb.WriteString("ip route replace blackhole default metric 32767 table 100\n")
	if t.Settings.LANIPv6Prefix != "" {
		lan6 := shQuote(t.Settings.LANIPv6Prefix)
		fmt.Fprintf(sb, "ip -6 route replace %s dev %s table 100\n", lan6, lanQ)
		fmt.Fprintf(sb, "ip -6 route replace default via %s dev %s table 100\n", llaQ, lanQ)
		sb.WriteString("ip -6 route replace blackhole default metric 32767 table 100\n")
		fmt.Fprintf(sb, "ip -6 route replace %s dev %s table 102\n", lan6, lanQ)
	}
	// Table 102 is the foreign path. LAN destinations stay on the LAN NIC.
	// The blackhole default is what remains if the WireGuard device route
	// disappears, so the lookup cannot fall through to ROS.
	fmt.Fprintf(sb, "ip route replace %s dev %s table 102\n", lanNetQ, lanQ)
	if sp := planShare(t, tunnels); sp != nil {
		// Two or more relays carry the main path at once (share.go): one
		// table per relay, table 102 on the designated relay, the same
		// shell the failover loop applies its decisions with.
		renderShareRoutes(sb, t, sp)
	} else if t.DualHub() {
		// Main path or backup hub: decided in one place (planUpstream),
		// applied by the same shell the failover loop uses.
		renderUpstreamRoutes(sb, planUpstream(t, tunnels))
	} else if t.DirectExits() {
		// No relay, hub or IX: every exit is the gateway's own tunnel.
		// Table 102 has nothing to carry (each mark has its own table
		// below); it and the tunnel prefixes keep only their blackholes.
		renderDirectGatewayRoutes(sb, t, lan, exits, groups)
	} else {
		fmt.Fprintf(sb, "ip route replace default dev %s table 102\n", westQ)
		sb.WriteString("ip route replace blackhole default metric 32767 table 102\n")
		fmt.Fprintf(sb, "ip -6 route replace default dev %s table 102\n", westQ)
		sb.WriteString("ip -6 route replace blackhole default metric 32767 table 102\n")
		fmt.Fprintf(sb, "ip route replace 10.66.0.0/16 dev %s\n", westQ)
		sb.WriteString("ip route replace blackhole 10.66.0.0/16 metric 32767\n")
		fmt.Fprintf(sb, "ip -6 route replace fd66::/48 dev %s\n", westQ)
		sb.WriteString("ip -6 route replace blackhole fd66::/48 metric 32767\n")
	}

	// Selectors only. This does not delete another program's rules, but it
	// does drop marks for exits and region groups that were removed from
	// the topology. The bound is the guard's (guardLastExitMark).
	fmt.Fprintf(sb, "for n in $(seq 0 %d); do\n", guardLastExitMark(exits, groups...)-markExitBase)
	sb.WriteString("  m=$(printf '0x%x' $((0x101 + n)))\n")
	sb.WriteString("  del_rule ip rule del fwmark \"$m\" lookup 102\n")
	if t.DirectExits() {
		// A direct-exit gateway's marks look up their own table.
		sb.WriteString("  del_rule ip rule del fwmark \"$m\" lookup $((201 + n))\n")
		sb.WriteString("  del_rule ip -6 rule del fwmark \"$m\" lookup $((201 + n))\n")
	}
	sb.WriteString("  del_rule ip rule del fwmark \"$m\" unreachable\n")
	sb.WriteString("  del_rule ip -6 rule del fwmark \"$m\" lookup 102\n")
	sb.WriteString("  del_rule ip -6 rule del fwmark \"$m\" unreachable\n")
	sb.WriteString("done\n")
	// Exit marks and region-group marks alike go to table 102 (the IX west
	// path) and are SNATed to their own transit address; the hub picks the
	// exit or group table by that source.
	// Transit addresses of exits and groups that left the topology are still
	// on lo from the previous install: remove the ones this plan no longer
	// uses (only inside Meridian's own transit prefixes; the marker line
	// tells the preflight which prefixes those are, so it attributes such
	// leftovers to this install instead of reporting a foreign overlap).
	{
		keep := []string{upstreamProbeSrc}
		for _, e := range markPlans(exits, groups) {
			keep = append(keep, e.TransitV4, e.TransitV6)
		}
		fmt.Fprintf(sb, "# meridian-transit: %s %s\n", transitV4Net(), transitV6Net())
		fmt.Fprintf(sb, "keep_transit=' %s '\n", strings.Join(keep, " "))
		fmt.Fprintf(sb, "for a in $(ip -o -4 addr show dev lo to %s 2>/dev/null | awk '{print $4}'); do case \"$keep_transit\" in *\" ${a%%/*} \"*) ;; *) ip addr del \"$a\" dev lo 2>/dev/null || true ;; esac; done\n", transitV4Net())
		fmt.Fprintf(sb, "for a in $(ip -o -6 addr show dev lo to %s 2>/dev/null | awk '{print $4}'); do case \"$keep_transit\" in *\" ${a%%/*} \"*) ;; *) ip -6 addr del \"$a\" dev lo 2>/dev/null || true ;; esac; done\n", transitV6Net())
	}
	directExits := t.DirectExits()
	for _, e := range markPlans(exits, groups) {
		// Through a hub every mark leaves by table 102 (the west path);
		// a direct-exit gateway looks up the mark's own table.
		table := "102"
		if directExits {
			table = fmt.Sprint(markTable(e.Index))
		}
		fmt.Fprintf(sb, "ip addr replace %s/32 dev lo\n", e.TransitV4)
		fmt.Fprintf(sb, "ip -6 addr replace %s/128 dev lo\n", e.TransitV6)
		fmt.Fprintf(sb, "ip rule add fwmark %#x lookup %s priority %d\n", e.Mark, table, prioExitBase+e.Index)
		fmt.Fprintf(sb, "ip rule add fwmark %#x unreachable priority %d\n", e.Mark, prioExitDrop+e.Index)
		fmt.Fprintf(sb, "ip -6 rule add fwmark %#x lookup %s priority %d\n", e.Mark, table, prioExitBase+e.Index)
		fmt.Fprintf(sb, "ip -6 rule add fwmark %#x unreachable priority %d\n", e.Mark, prioExitDrop+e.Index)
	}
	fmt.Fprintf(sb, "del_rule ip rule del fwmark %#x lookup 100\n", markDomestic)
	fmt.Fprintf(sb, "ip rule add fwmark %#x lookup 100 priority %d\n", markDomestic, prioDomestic)
	fmt.Fprintf(sb, "del_rule ip -6 rule del fwmark %#x lookup 100\n", markDomestic)
	fmt.Fprintf(sb, "ip -6 rule add fwmark %#x lookup 100 priority %d\n", markDomestic, prioDomestic)
	// No "iif <LAN> unreachable" rule, v4 or v6. The kernel validates the
	// source of a forwarded packet (rp_filter is 2) with a reverse lookup
	// whose iif is the packet's OUTPUT interface and whose mark is 0, so
	// such a rule failed that lookup for every IPv4 packet forwarded OUT of
	// the LAN NIC (domestic hairpin to ROS, tunnel replies to LAN clients)
	// and the kernel dropped it with EXDEV. Unclassified forwarded traffic
	// is dropped instead by the forward-hook guard in table inet
	// meridian_guard (render_nft.go), for v4 and v6 alike, and the per-mark
	// "fwmark X unreachable" rules above stop classified foreign traffic
	// from falling through to main (reverse lookups carry mark 0, so those
	// are not affected). Installs from before this change carry the rules
	// at 17850/17851: remove them so an upgrade heals without a reboot.
	removeStaleIIFRules(sb, lanQ)
	if rp := planRemote(t); rp != nil {
		remoteRouteCommands(sb, rp)
	}
	fmt.Fprintf(sb, "# failover companions: udp=%s wss=%s direct_wss=%s\n", ifaceOrDash(udp), ifaceOrDash(wss), ifaceOrDash(direct))
}

// writeHarden sets rp_filter=2 and turns ICMP redirects off on exactly the
// interfaces this node manages or the topology names (sysctlIfaces), after
// the WireGuard interfaces exist. Per-interface values are what matter:
// the kernel uses max(all, interface) for rp_filter, so an interface set to
// 2 is loose whatever "all" is (2 is the maximum); for send_redirects it ORs
// all and the interface, so the interface needs 0 and so does "all"
// (99-meridian.conf); IPv4 accept_redirects is ANDed while forwarding, so
// the interface value alone decides. Every other interface on the host
// (Docker bridges and veths, WARP, an operator's own) is left as it is.
// Earlier versions looped over every interface; values they set on other
// interfaces stay until reboot (see docs/architecture.md「内核参数的范围」).
func writeHarden(sb *strings.Builder, ifaces []string) {
	sb.WriteString(`# rp_filter=2 and no ICMP redirects on Meridian's interfaces only (the
# managed tunnels, the interface the topology names, mra/mmesh). The kernel
# uses max(all, iface) for rp_filter and ORs send_redirects, so the
# interface value is what matters here. Other interfaces are not touched.
harden_sysctl() {
  local i
  for i in "$@"; do
    sysctl -w "net.ipv4.conf.${i}.rp_filter=2" >/dev/null 2>&1 || true
    sysctl -w "net.ipv4.conf.${i}.send_redirects=0" >/dev/null 2>&1 || true
    sysctl -w "net.ipv4.conf.${i}.accept_redirects=0" >/dev/null 2>&1 || true
    sysctl -w "net.ipv6.conf.${i}.accept_redirects=0" >/dev/null 2>&1 || true
  done
}
`)
	sb.WriteString("harden_sysctl " + strings.Join(ifaces, " ") + "\n")
}

func renderRelayRoutes(sb *strings.Builder, t model.Topology, n model.Node, tunnels []Tunnel) {
	westUDP, westWSS, eastIX, eastWSS := relayIfaces(tunnelsFor(tunnels, n.ID))
	preferred := eastIX
	kind := "ix"
	if !t.HasIX() {
		kind = "hub"
	}
	if t.Settings.IXReplacementMode && eastWSS.Iface() != "" {
		preferred = eastWSS
		kind = "ix-replacement"
	}
	fmt.Fprintf(sb, "# meridian-east-preferred: %s %s\n", kind, preferred.Iface())
	// Return path toward the gateway uses the preferred west leg.
	west := westUDP
	if west.Iface() == "" {
		west = westWSS
	}
	if legs := relayWestLegs(tunnels, n.ID); t.RelaySharing() && west.Iface() == "" && len(legs) > 0 {
		// A plain WireGuard (or WSS-only) leg from the gateway: replies
		// follow the ingress mark (ingressReturns); this is the default.
		west = legs[0]
	}
	fmt.Fprintf(sb, "ip route replace %s dev %s\n", lanNet(t), west.Iface())
	fmt.Fprintf(sb, "ip route replace %s dev %s\n", transitV4Net(), west.Iface())
	if t.Settings.LANIPv6Prefix != "" {
		fmt.Fprintf(sb, "ip -6 route replace %s dev %s\n", t.Settings.LANIPv6Prefix, west.Iface())
	}
	fmt.Fprintf(sb, "ip -6 route replace %s dev %s\n", transitV6Net(), west.Iface())
	fmt.Fprintf(sb, "ip -6 route replace fd66::/48 dev %s\n", preferred.Iface())
	writePrefixBlackholes(sb, t)

	fmt.Fprintf(sb, "ip route replace default dev %s table 150\n", preferred.Iface())
	fmt.Fprintf(sb, "ip route replace %s dev %s table 150\n", lanNet(t), west.Iface())
	fmt.Fprintf(sb, "ip route replace %s dev %s table 150\n", transitV4Net(), west.Iface())
	fmt.Fprintf(sb, "ip -6 route replace default dev %s table 150\n", preferred.Iface())
	if t.Settings.LANIPv6Prefix != "" {
		fmt.Fprintf(sb, "ip -6 route replace %s dev %s table 150\n", t.Settings.LANIPv6Prefix, west.Iface())
	}
	fmt.Fprintf(sb, "ip -6 route replace %s dev %s table 150\n", transitV6Net(), west.Iface())
	sb.WriteString("ip route replace blackhole default metric 32767 table 150\n")
	sb.WriteString("ip -6 route replace blackhole default metric 32767 table 150\n")

	sb.WriteString("del_rule ip rule del from " + lanNet(t) + " lookup 150\n")
	fmt.Fprintf(sb, "ip rule add from %s lookup 150 priority %d\n", lanNet(t), prioRelayFrom)
	sb.WriteString("del_rule ip rule del from " + transitV4Net() + " lookup 150\n")
	fmt.Fprintf(sb, "ip rule add from %s lookup 150 priority %d\n", transitV4Net(), prioRelayFrom+1)
	if t.Settings.LANIPv6Prefix != "" {
		fmt.Fprintf(sb, "del_rule ip -6 rule del from %s lookup 150\n", t.Settings.LANIPv6Prefix)
		fmt.Fprintf(sb, "ip -6 rule add from %s lookup 150 priority %d\n", t.Settings.LANIPv6Prefix, prioRelayFrom)
	}
	fmt.Fprintf(sb, "del_rule ip -6 rule del from %s lookup 150\n", transitV6Net())
	fmt.Fprintf(sb, "ip -6 rule add from %s lookup 150 priority %d\n", transitV6Net(), prioRelayFrom+1)
	fmt.Fprintf(sb, "# companions west_udp=%s west_wss=%s east_ix=%s east_wss=%s\n",
		ifaceOrDash(westUDP), ifaceOrDash(westWSS), ifaceOrDash(eastIX), ifaceOrDash(eastWSS))
	if rets := ingressReturns(t, n, tunnels); rets != nil {
		renderIngressReturnRoutes(sb, t, rets)
	}
}

func renderHubRoutes(sb *strings.Builder, t model.Topology, n model.Node, tunnels []Tunnel, exits []ExitPlan, groups []GroupPlan) {
	westTun := hubWestTunnel(tunnels, n.ID, t.Settings.IXReplacementMode)
	west := westTun.Iface()
	kind := "ix"
	if !t.HasIX() {
		kind = "relay"
	}
	if t.Settings.IXReplacementMode {
		kind = "ix-replacement"
	}
	if t.EffectiveHubTier(n) == model.HubBackup {
		kind = "backup-wss"
		if t.RelayBackup() {
			kind = "backup-relay"
		}
	}
	fmt.Fprintf(sb, "# meridian-west-preferred: %s %s\n", kind, west)
	fmt.Fprintf(sb, "ip route replace %s dev %s\n", lanNet(t), west)
	fmt.Fprintf(sb, "ip route replace %s dev %s\n", transitV4Net(), west)
	if t.Settings.LANIPv6Prefix != "" {
		fmt.Fprintf(sb, "ip -6 route replace %s dev %s\n", t.Settings.LANIPv6Prefix, west)
	}
	fmt.Fprintf(sb, "ip -6 route replace %s dev %s\n", transitV6Net(), west)
	fmt.Fprintf(sb, "ip route replace 10.66.0.0/16 dev %s\n", west)
	fmt.Fprintf(sb, "ip -6 route replace fd66::/48 dev %s\n", west)
	writePrefixBlackholes(sb, t)
	for _, e := range exits {
		if e.HubIface == "" {
			fmt.Fprintf(sb, "# exit %s has no hub iface\n", e.Node.ID)
			continue
		}
		if e.ViaRelay != "" {
			fmt.Fprintf(sb, "# pure-v6 %s via dualstack %s dev %s\n", e.Node.ID, e.ViaRelay, e.HubIface)
			if e.PeerV4 != "" {
				fmt.Fprintf(sb, "ip route replace %s/32 dev %s\n", e.PeerV4, e.HubIface)
				fmt.Fprintf(sb, "ip route replace blackhole %s/32 metric 32767\n", e.PeerV4)
			}
			if e.PeerULA != "" {
				fmt.Fprintf(sb, "ip -6 route replace %s/128 dev %s\n", e.PeerULA, e.HubIface)
				fmt.Fprintf(sb, "ip -6 route replace blackhole %s/128 metric 32767\n", e.PeerULA)
			}
		}
		if e.sharedHop() {
			if e.External {
				fmt.Fprintf(sb, "# external exit %s on carrier %s dev %s: health %s, resolver %s (both on the carrier)\n", e.Node.ID, model.HubSideOf(e.Node), e.HubIface, e.PeerV4, e.PeerULA)
			} else {
				fmt.Fprintf(sb, "# nested exit %s behind relay exit %s dev %s\n", e.Node.ID, e.Nested, e.HubIface)
			}
			if e.PeerV4 != "" {
				fmt.Fprintf(sb, "ip route replace %s/32 dev %s\n", e.PeerV4, e.HubIface)
				fmt.Fprintf(sb, "ip route replace blackhole %s/32 metric 32767\n", e.PeerV4)
			}
			if e.PeerULA != "" {
				fmt.Fprintf(sb, "ip -6 route replace %s/128 dev %s\n", e.PeerULA, e.HubIface)
				fmt.Fprintf(sb, "ip -6 route replace blackhole %s/128 metric 32767\n", e.PeerULA)
			}
		}
		if e.MeshIface != "" && e.MeshSole {
			fmt.Fprintf(sb, "# pure-v6 %s: its one leg is the WireGuard leg carried over the Mesh (dev %s); never the IX west path\n", e.Node.ID, e.MeshIface)
		} else if e.MeshIface != "" {
			fmt.Fprintf(sb, "# exit %s also has a Mesh leg (dev %s, peer %s): the same exit over the Cloudflare Mesh.\n", e.Node.ID, e.MeshIface, e.MeshPeerV4)
			fmt.Fprintf(sb, "# The compiled hop below is the direct leg; the table only ever points at one of the two legs.\n")
		}
		fmt.Fprintf(sb, "# exit %s mark %#x transit %s dev %s\n", e.Node.ID, e.Mark, e.TransitV4, e.HubIface)
		if !t.DualHub() && e.MeshIface != "" && e.DNSULA != "" {
			target, src, _ := meshDNSRoute(t, e)
			fmt.Fprintf(sb, "ip -6 route replace blackhole %s/128 metric 32767\n", target)
			fmt.Fprintf(sb, "ip -6 route replace %s/128 dev %s src %s\n", target, e.HubIface, src)
		}
		if t.DualHub() && e.ViaRelay == "" {
			// The exit's hub-independent resolver address: the gateway asks
			// it through whichever hub carries the traffic; this hub hands it
			// to its own tunnel to the exit (which DNATs it to its resolver).
			fmt.Fprintf(sb, "ip -6 route replace %s/128 dev %s\n", e.Resolver, e.HubIface)
			fmt.Fprintf(sb, "ip -6 route replace blackhole %s/128 metric 32767\n", e.Resolver)
		}
		fmt.Fprintf(sb, "ip route replace default dev %s table %d\n", e.HubIface, e.Table)
		fmt.Fprintf(sb, "ip route replace %s dev %s table %d\n", lanNet(t), west, e.Table)
		fmt.Fprintf(sb, "ip route replace %s dev %s table %d\n", transitV4Net(), west, e.Table)
		fmt.Fprintf(sb, "ip -6 route replace default dev %s table %d\n", e.HubIface, e.Table)
		if t.Settings.LANIPv6Prefix != "" {
			fmt.Fprintf(sb, "ip -6 route replace %s dev %s table %d\n", t.Settings.LANIPv6Prefix, west, e.Table)
		}
		fmt.Fprintf(sb, "ip -6 route replace %s dev %s table %d\n", transitV6Net(), west, e.Table)
		fmt.Fprintf(sb, "ip route replace blackhole default metric 32767 table %d\n", e.Table)
		fmt.Fprintf(sb, "ip -6 route replace blackhole default metric 32767 table %d\n", e.Table)
		fmt.Fprintf(sb, "del_rule ip rule del from %s/32 lookup %d\n", e.TransitV4, e.Table)
		fmt.Fprintf(sb, "ip rule add from %s/32 lookup %d priority %d\n", e.TransitV4, e.Table, prioHubExitFrom+e.Index)
		fmt.Fprintf(sb, "del_rule ip -6 rule del from %s/128 lookup %d\n", e.TransitV6, e.Table)
		fmt.Fprintf(sb, "ip -6 rule add from %s/128 lookup %d priority %d\n", e.TransitV6, e.Table, prioHubExitFrom+e.Index)
	}
	renderMeshUnderlayRoutes(sb, n, tunnels)
	renderHubGroupRoutes(sb, t, west, groups, t.HasMeshLegs())
	if rets := ingressReturns(t, n, tunnels); rets != nil {
		renderIngressReturnRoutes(sb, t, rets)
	}
}

func renderExitRoutes(sb *strings.Builder, t model.Topology, n model.Node, tunnels []Tunnel) {
	tun := exitIngress(n, tunnels, primaryHubID(t))
	if tun.Iface() == "" {
		sb.WriteString("echo \"exit has no hub tunnel\" >&2\nexit 1\n")
		return
	}
	if tun.MeshLeg() {
		sb.WriteString("# The hub reaches this exit by a WireGuard leg carried over the Cloudflare Mesh;\n")
		sb.WriteString("# it is this exit's one tunnel home. Do not point fd66 at ROS.\n")
	}
	fmt.Fprintf(sb, "ip route replace %s dev %s\n", lanNet(t), tun.Iface())
	fmt.Fprintf(sb, "ip route replace %s dev %s\n", transitV4Net(), tun.Iface())
	if t.Settings.LANIPv6Prefix != "" {
		fmt.Fprintf(sb, "ip -6 route replace %s dev %s\n", t.Settings.LANIPv6Prefix, tun.Iface())
	}
	fmt.Fprintf(sb, "ip -6 route replace %s dev %s\n", transitV6Net(), tun.Iface())
	fmt.Fprintf(sb, "ip -6 route replace fd66::/48 dev %s\n", tun.Iface())
	if model.IsNested(n) {
		// The hubs' tunnel addresses (their health probes) are behind the
		// relay exit too: this exit's one tunnel is its only way home.
		fmt.Fprintf(sb, "# nested exit behind relay exit %s: everything toward home goes into its one tunnel\n", n.ViaExit)
		fmt.Fprintf(sb, "ip route replace 10.66.0.0/16 dev %s\n", tun.Iface())
	}
	writePrefixBlackholes(sb, t)
	if rets := exitHubReturns(t, n, tunnels); rets != nil {
		renderExitHubReturnRoutes(sb, t, rets)
	}
	if n.NatDialOut {
		sb.WriteString("# NAT dial-out: keep the mapping warm. Updates must use wg syncconf, not wg-quick down.\n")
	}
}

// renderDirectGatewayRoutes: the gateway of a direct-exit topology does
// for its exits what a hub does (renderHubRoutes): one table per exit with
// the default into that exit's tunnel and a blackhole under it (an exit
// whose tunnel is down drops, it never falls back to ROS), the region
// groups' tables switched by group_hop, and the from-transit rules that
// steer this host's own queries. Home prefixes are local: LAN routes in
// those tables point at the LAN NIC.
func renderDirectGatewayRoutes(sb *strings.Builder, t model.Topology, lan string, exits []ExitPlan, groups []GroupPlan) {
	sb.WriteString("# meridian-direct-exits: the gateway reaches every exit through its own tunnel\n")
	sb.WriteString("ip route replace blackhole default metric 32767 table 102\n")
	sb.WriteString("ip -6 route replace blackhole default metric 32767 table 102\n")
	sb.WriteString("ip route replace blackhole 10.66.0.0/16 metric 32767\n")
	sb.WriteString("ip -6 route replace blackhole fd66::/48 metric 32767\n")
	for _, e := range exits {
		if e.HubIface == "" {
			fmt.Fprintf(sb, "# exit %s has no tunnel from the gateway\n", e.Node.ID)
			continue
		}
		fmt.Fprintf(sb, "# exit %s mark %#x transit %s dev %s\n", e.Node.ID, e.Mark, e.TransitV4, e.HubIface)
		fmt.Fprintf(sb, "ip route replace default dev %s table %d\n", e.HubIface, e.Table)
		fmt.Fprintf(sb, "ip route replace %s dev %s table %d\n", lanNet(t), lan, e.Table)
		fmt.Fprintf(sb, "ip -6 route replace default dev %s table %d\n", e.HubIface, e.Table)
		if t.Settings.LANIPv6Prefix != "" {
			fmt.Fprintf(sb, "ip -6 route replace %s dev %s table %d\n", t.Settings.LANIPv6Prefix, lan, e.Table)
		}
		fmt.Fprintf(sb, "ip route replace blackhole default metric 32767 table %d\n", e.Table)
		fmt.Fprintf(sb, "ip -6 route replace blackhole default metric 32767 table %d\n", e.Table)
		fmt.Fprintf(sb, "del_rule ip rule del from %s/32 lookup %d\n", e.TransitV4, e.Table)
		fmt.Fprintf(sb, "ip rule add from %s/32 lookup %d priority %d\n", e.TransitV4, e.Table, prioHubExitFrom+e.Index)
		fmt.Fprintf(sb, "del_rule ip -6 rule del from %s/128 lookup %d\n", e.TransitV6, e.Table)
		fmt.Fprintf(sb, "ip -6 rule add from %s/128 lookup %d priority %d\n", e.TransitV6, e.Table, prioHubExitFrom+e.Index)
	}
	renderHubGroupRoutes(sb, t, lan, groups, false)
}

func renderFailover(t model.Topology, n model.Node, tunnels []Tunnel, exits []ExitPlan, groups []GroupPlan) string {
	switch n.Role {
	case model.RoleGateway:
		if t.DirectExits() {
			return renderDirectGatewayFailover(t, groups)
		}
		return renderGatewayFailover(t, tunnels)
	case model.RoleHub:
		return renderHubFailover(t, n, tunnels, exits, groups)
	default:
		return renderRelayFailover(t, n, tunnels)
	}
}

// renderDirectGatewayFailover: a direct-exit gateway has no west path to
// fail over; it runs the hub's group switch (renderGroupChecks) over its
// own tunnels to the exits: a group whose current member stops answering
// moves to the next member of its order, with the same hysteresis.
func renderDirectGatewayFailover(t model.Topology, groups []GroupPlan) string {
	var sb strings.Builder
	sb.WriteString("#!/bin/bash\n")
	sb.WriteString("# Direct exits: no relay or hub to fail over. Region groups switch between their members here.\n")
	sb.WriteString("set -u\n")
	fmt.Fprintf(&sb, "FAILS_NEED=%d\nRECOVERS_NEED=%d\nCOOLDOWN=%d\n", pool.FailsNeed, pool.RecoversNeed, int(pool.Cooldown/time.Second))
	fmt.Fprintf(&sb, "GROUP_PLAN=%s\n", GroupPlanID(groups))
	sb.WriteString(renderGroupChecks(groups, false))
	sb.WriteString(failoverLoopDirect)
	_ = t
	return sb.String()
}

const failoverLoopDirect = `
alive() {
  local iface="$1" peer="$2"
  [ -n "$iface" ] || return 1
  ping -I "$iface" -c 1 -W 2 -n "$peer" >/dev/null 2>&1
}
# --- main loop ---
reset_groups
while true; do
  check_groups || true
  sleep 5
done
`

func renderGatewayFailover(t model.Topology, tunnels []Tunnel) string {
	if sp := planShare(t, tunnels); sp != nil {
		return renderGatewayFailoverShare(t, sp)
	}
	if t.DualHub() {
		return renderGatewayFailoverDual(planUpstream(t, tunnels))
	}
	udp, wss, direct := gatewayIfaces(tunnels)
	var sb strings.Builder
	sb.WriteString("#!/bin/bash\n")
	sb.WriteString("# Prefer UDP toward the relay. Fall back to WSS, then to the pre-provisioned gateway-to-hub WSS.\n")
	sb.WriteString("# Hysteresis avoids flapping. Mesh is not a candidate.\n")
	sb.WriteString("set -u\n")
	fmt.Fprintf(&sb, "UDP=%q\nWSS=%q\nDIRECT=%q\n", udp.Iface(), wss.Iface(), direct.Iface())
	fmt.Fprintf(&sb, "UDP_PEER=%q\nWSS_PEER=%q\nDIRECT_PEER=%q\n", udp.EastV4, wss.EastV4, direct.EastV4)
	sb.WriteString("FAILS_NEED=3\nRECOVERS_NEED=5\nCOOLDOWN=120\n")
	sb.WriteString("state=/run/meridian/gw-failover\nmkdir -p /run/meridian\n")
	sb.WriteString(failoverLoopGateway)
	_ = t
	return sb.String()
}

func renderRelayFailover(t model.Topology, n model.Node, tunnels []Tunnel) string {
	westUDP, westWSS, eastIX, eastWSS := relayIfaces(tunnelsFor(tunnels, n.ID))
	if legs := relayWestLegs(tunnels, n.ID); t.RelaySharing() && westUDP.Iface() == "" && westWSS.Iface() == "" && len(legs) > 0 {
		westUDP = legs[0]
	}
	mode := "0"
	if t.Settings.IXReplacementMode {
		mode = "1"
	}
	var sb strings.Builder
	sb.WriteString("#!/bin/bash\n")
	sb.WriteString("# IX replacement is pre-provisioned. It takes traffic only after health failure or when IX_MODE=1.\n")
	sb.WriteString("set -u\n")
	fmt.Fprintf(&sb, "IX_MODE=%s\n", mode)
	fmt.Fprintf(&sb, "WEST_UDP=%q\nWEST_WSS=%q\nEAST_IX=%q\nEAST_WSS=%q\n", westUDP.Iface(), westWSS.Iface(), eastIX.Iface(), eastWSS.Iface())
	fmt.Fprintf(&sb, "WEST_PEER_UDP=%q\nWEST_PEER_WSS=%q\nEAST_PEER_IX=%q\nEAST_PEER_WSS=%q\n",
		westUDP.WestV4, westWSS.WestV4, eastIX.EastV4, eastWSS.EastV4)
	fmt.Fprintf(&sb, "LAN=%q\nTRANSIT4=%q\nTRANSIT6=%q\nLAN6=%q\n",
		lanNet(t), transitV4Net(), transitV6Net(), t.Settings.LANIPv6Prefix)
	sb.WriteString("FAILS_NEED=3\nRECOVERS_NEED=5\nCOOLDOWN=120\n")
	sb.WriteString("state=/run/meridian/relay-failover\nmkdir -p /run/meridian\n")
	sb.WriteString(failoverLoopRelay)
	return sb.String()
}

const failoverLoopGateway = `
alive() {
  local iface="$1" peer="$2"
  [ -n "$iface" ] || return 1
  ping -I "$iface" -c 1 -W 2 -n "$peer" >/dev/null 2>&1
}
pick() {
  if alive "$UDP" "$UDP_PEER"; then echo udp; return; fi
  if alive "$WSS" "$WSS_PEER"; then echo wss; return; fi
  if alive "$DIRECT" "$DIRECT_PEER"; then echo direct; return; fi
  echo udp
}
apply_choice() {
  local iface peer
  case "$1" in
    wss) iface="$WSS" ;;
    direct) iface="$DIRECT" ;;
    *) iface="$UDP" ;;
  esac
  [ -n "$iface" ] || return 0
  ip route replace default dev "$iface" table 102
  ip route replace blackhole default metric 32767 table 102
  ip -6 route replace default dev "$iface" table 102
  ip -6 route replace blackhole default metric 32767 table 102
  ip route replace 10.66.0.0/16 dev "$iface"
  ip route replace blackhole 10.66.0.0/16 metric 32767
  ip -6 route replace fd66::/48 dev "$iface"
  ip -6 route replace blackhole fd66::/48 metric 32767
}
cur=udp
bad=0
good=0
last_switch=0
while true; do
  want=$(pick)
  now=$(date +%s)
  if [ "$want" != "$cur" ]; then
    bad=$((bad+1))
    good=0
    if [ "$bad" -ge "$FAILS_NEED" ] && [ $((now-last_switch)) -ge "$COOLDOWN" -o "$last_switch" -eq 0 ]; then
      apply_choice "$want"
      cur="$want"
      bad=0
      last_switch=$now
    fi
  else
    good=$((good+1))
    bad=0
  fi
  sleep 5
done
`

const failoverLoopRelay = `
alive() {
  local iface="$1" peer="$2"
  [ -n "$iface" ] || return 1
  ping -I "$iface" -c 1 -W 2 -n "$peer" >/dev/null 2>&1
}
apply_east() {
  local iface="$1"
  [ -n "$iface" ] || return 0
  ip route replace default dev "$iface" table 150
  ip route replace blackhole default metric 32767 table 150
  ip -6 route replace default dev "$iface" table 150
  ip -6 route replace blackhole default metric 32767 table 150
  ip -6 route replace fd66::/48 dev "$iface"
  ip -6 route replace blackhole fd66::/48 metric 32767
}
apply_west() {
  local iface="$1"
  [ -n "$iface" ] || return 0
  ip route replace "$LAN" dev "$iface"
  ip route replace "$TRANSIT4" dev "$iface"
  ip route replace "$LAN" dev "$iface" table 150
  ip route replace "$TRANSIT4" dev "$iface" table 150
  if [ -n "$LAN6" ]; then
    ip -6 route replace "$LAN6" dev "$iface"
    ip -6 route replace "$LAN6" dev "$iface" table 150
  fi
  ip -6 route replace "$TRANSIT6" dev "$iface"
  ip -6 route replace "$TRANSIT6" dev "$iface" table 150
  ip route replace blackhole "$LAN" metric 32767
  ip route replace blackhole "$TRANSIT4" metric 32767
  ip route replace blackhole 10.66.0.0/16 metric 32767
  ip -6 route replace blackhole "$TRANSIT6" metric 32767
  ip -6 route replace blackhole fd66::/48 metric 32767
  if [ -n "$LAN6" ]; then
    ip -6 route replace blackhole "$LAN6" metric 32767
  fi
}
east_pref="$EAST_IX"
[ "$IX_MODE" = "1" ] && east_pref="$EAST_WSS"
west_pref="$WEST_UDP"
[ -n "$west_pref" ] || west_pref="$WEST_WSS"
cur_east="$east_pref"
cur_west="$west_pref"
east_bad=0
west_bad=0
last_switch=0
while true; do
  now=$(date +%s)
  want_east="$EAST_IX"
  if [ "$IX_MODE" = "1" ]; then
    if alive "$EAST_WSS" "$EAST_PEER_WSS"; then want_east="$EAST_WSS"
    elif alive "$EAST_IX" "$EAST_PEER_IX"; then want_east="$EAST_IX"
    else want_east="$EAST_WSS"; fi
  else
    if alive "$EAST_IX" "$EAST_PEER_IX"; then want_east="$EAST_IX"
    elif alive "$EAST_WSS" "$EAST_PEER_WSS"; then want_east="$EAST_WSS"
    else want_east="$EAST_IX"; fi
  fi
  want_west="$WEST_UDP"
  if alive "$WEST_UDP" "$WEST_PEER_UDP"; then want_west="$WEST_UDP"
  elif alive "$WEST_WSS" "$WEST_PEER_WSS"; then want_west="$WEST_WSS"
  fi
  if [ "$want_east" != "$cur_east" ]; then
    east_bad=$((east_bad+1))
    if [ "$east_bad" -ge "$FAILS_NEED" ] && [ $((now-last_switch)) -ge "$COOLDOWN" -o "$last_switch" -eq 0 ]; then
      apply_east "$want_east"
      cur_east="$want_east"
      east_bad=0
      last_switch=$now
    fi
  else
    east_bad=0
  fi
  if [ "$want_west" != "$cur_west" ]; then
    west_bad=$((west_bad+1))
    if [ "$west_bad" -ge "$FAILS_NEED" ]; then
      apply_west "$want_west"
      cur_west="$want_west"
      west_bad=0
    fi
  else
    west_bad=0
  fi
  sleep 5
done
`

func gatewayIfaces(tunnels []Tunnel) (udp, wss, direct Tunnel) {
	for _, tun := range tunnels {
		if tun.West.Role != model.RoleGateway {
			continue
		}
		switch {
		case tun.Transport == model.TransportUDPWSSFailover && tun.Mode == "udp":
			udp = tun
		case tun.Transport == model.TransportUDPWSSFailover && tun.Mode == "wss":
			wss = tun
		case tun.Transport == model.TransportIXReplacementWSS && tun.East.Role == model.RoleHub:
			direct = tun
		}
	}
	if udp.LinkID == "" && wss.LinkID == "" {
		// No relay (a hub reached straight from the gateway, the
		// single-relay template): its plain WireGuard is the west path.
		udp = gatewayHubMain(tunnels)
	}
	return udp, wss, direct
}

// gatewayHubMain is the gateway's enabled, non-standby direct_wg tunnel to
// a hub (zero: none). Only a topology without relays has one on its main
// path (validate: gateway → primary hub → exit).
func gatewayHubMain(tunnels []Tunnel) Tunnel {
	for _, tun := range tunnels {
		if tun.West.Role == model.RoleGateway && tun.East.Role == model.RoleHub &&
			tun.Transport == model.TransportDirectWG && !tun.Standby {
			return tun
		}
	}
	return Tunnel{}
}

// relayWestLegs are the relay's non-standby tunnels from the gateway, UDP
// legs first.
func relayWestLegs(tunnels []Tunnel, relay string) []Tunnel {
	var udp, wss []Tunnel
	for _, tun := range tunnels {
		if tun.East.ID != relay || tun.West.Role != model.RoleGateway || tun.Standby {
			continue
		}
		if tun.Mode == "udp" {
			udp = append(udp, tun)
		} else {
			wss = append(wss, tun)
		}
	}
	return append(udp, wss...)
}

func relayIfaces(tunnels []Tunnel) (westUDP, westWSS, eastIX, eastWSS Tunnel) {
	var eastCompanion Tunnel
	for _, tun := range tunnels {
		if tun.West.Role != model.RoleRelay && tun.East.Role != model.RoleRelay {
			continue
		}
		switch {
		case tun.Transport == model.TransportUDPWSSFailover && tun.Mode == "udp" && tun.West.Role == model.RoleGateway:
			westUDP = tun
		case tun.Transport == model.TransportUDPWSSFailover && tun.Mode == "wss" && tun.West.Role == model.RoleGateway:
			westWSS = tun
		case tun.Transport == model.TransportDirectWG && tun.West.Role == model.RoleRelay && tun.East.Role == model.RoleHub:
			eastIX = tun
		case tun.Transport == model.TransportIXReplacementWSS && tun.West.Role == model.RoleRelay:
			eastWSS = tun
		case relayHubCarrier(tun):
			eastIX = tun
		case relayHubCompanion(tun):
			eastCompanion = tun
		}
	}
	if eastWSS.LinkID == "" {
		// The relay's own UDP → WSS failover on its tunnel to the hub.
		eastWSS = eastCompanion
	}
	return westUDP, westWSS, eastIX, eastWSS
}

// relayHubCarrier: tun is the leg of a relay → hub udp_wss_failover or
// wg_over_wss link that carries the main path while it is healthy (the UDP
// leg; a WSS-only link's one leg). A relay → hub direct_wg link is matched
// by its own case.
func relayHubCarrier(tun Tunnel) bool {
	if tun.Standby || tun.West.Role != model.RoleRelay || tun.East.Role != model.RoleHub {
		return false
	}
	switch tun.Transport {
	case model.TransportUDPWSSFailover:
		return tun.Mode == "udp"
	case model.TransportWGOverWSS:
		return true
	}
	return false
}

// relayHubCompanion: the WSS leg of a relay → hub udp_wss_failover link.
func relayHubCompanion(tun Tunnel) bool {
	return !tun.Standby && tun.West.Role == model.RoleRelay && tun.East.Role == model.RoleHub &&
		tun.Transport == model.TransportUDPWSSFailover && tun.Mode == "wss"
}

// hubWestTunnel is hub's tunnel toward home: the relay's direct WireGuard
// (on the IX line), the relay's WSS replacement, or, for a backup hub that
// only the gateway dials, the gateway's WSS.
func hubWestTunnel(tunnels []Tunnel, hub string, replacement bool) Tunnel {
	var ix, wss, home, companion Tunnel
	for _, tun := range tunnels {
		if tun.East.Role != model.RoleHub || tun.East.ID != hub {
			continue
		}
		switch {
		case tun.West.Role == model.RoleRelay && tun.Transport == model.TransportDirectWG:
			ix = tun
		case tun.West.Role == model.RoleRelay && tun.Transport == model.TransportIXReplacementWSS:
			wss = tun
		case relayHubCarrier(tun):
			ix = tun
		case relayHubCompanion(tun):
			companion = tun
		case tun.West.Role == model.RoleGateway && tun.Transport == model.TransportIXReplacementWSS:
			home = tun
		}
	}
	if replacement && wss.LinkID != "" {
		return wss
	}
	if ix.LinkID != "" {
		return ix
	}
	if wss.LinkID != "" {
		return wss
	}
	if companion.LinkID != "" {
		return companion
	}
	if gw := gatewayHubMain(tunnelsTo(tunnels, hub)); gw.LinkID != "" {
		// No relay: the gateway's own tunnel is this hub's way home.
		return gw
	}
	return home
}

// tunnelsTo: the tunnels whose east end is node id.
func tunnelsTo(tunnels []Tunnel, id string) []Tunnel {
	var out []Tunnel
	for _, tun := range tunnels {
		if tun.East.ID == id {
			out = append(out, tun)
		}
	}
	return out
}

func renderDualstackForward(sb *strings.Builder, t model.Topology, n model.Node, tunnels []Tunnel, exits []ExitPlan) {
	var west Tunnel
	for _, tun := range tunnels {
		if tun.East.ID == n.ID && tun.West.Role == model.RoleHub && !tun.Standby && tun.Mode != "wss" {
			west = tun
			break
		}
	}
	sb.WriteString("# dualstack relay: v4 from the hub, v6 toward a pure-v6 exit. This is still after the IX.\n")
	if west.Iface() == "" {
		sb.WriteString("# dualstack relay has no v4 tunnel back to the hub\n")
		return
	}
	fmt.Fprintf(sb, "# relay west %s\n", west.Iface())
	for _, e := range exits {
		if e.ViaRelay != n.ID {
			continue
		}
		down := exitIngress(e.Node, tunnels, primaryHubID(t))
		if down.Iface() == "" {
			fmt.Fprintf(sb, "# pure-v6 %s has no relay tunnel\n", e.Node.ID)
			continue
		}
		fmt.Fprintf(sb, "ip route replace default dev %s table %d\n", down.Iface(), e.Table)
		fmt.Fprintf(sb, "ip route replace %s dev %s table %d\n", lanNet(t), west.Iface(), e.Table)
		fmt.Fprintf(sb, "ip route replace %s dev %s table %d\n", transitV4Net(), west.Iface(), e.Table)
		fmt.Fprintf(sb, "ip -6 route replace default dev %s table %d\n", down.Iface(), e.Table)
		fmt.Fprintf(sb, "ip -6 route replace %s dev %s table %d\n", transitV6Net(), west.Iface(), e.Table)
		fmt.Fprintf(sb, "ip route replace blackhole default metric 32767 table %d\n", e.Table)
		fmt.Fprintf(sb, "ip -6 route replace blackhole default metric 32767 table %d\n", e.Table)
		fmt.Fprintf(sb, "del_rule ip rule del from %s/32 lookup %d\n", e.TransitV4, e.Table)
		fmt.Fprintf(sb, "ip rule add from %s/32 lookup %d priority %d\n", e.TransitV4, e.Table, prioHubExitFrom+e.Index)
		fmt.Fprintf(sb, "del_rule ip -6 rule del from %s/128 lookup %d\n", e.TransitV6, e.Table)
		fmt.Fprintf(sb, "ip -6 rule add from %s/128 lookup %d priority %d\n", e.TransitV6, e.Table, prioHubExitFrom+e.Index)
	}
	_ = t
}

func renderHubFailover(t model.Topology, n model.Node, tunnels []Tunnel, exits []ExitPlan, groups []GroupPlan) string {
	var ix, aliWSS, home Tunnel
	for _, tun := range tunnels {
		if tun.East.Role != model.RoleHub || tun.East.ID != n.ID {
			continue
		}
		switch {
		case tun.West.Role == model.RoleRelay && tun.Transport == model.TransportDirectWG:
			ix = tun
		case tun.West.Role == model.RoleRelay && tun.Transport == model.TransportIXReplacementWSS:
			aliWSS = tun
		case tun.West.Role == model.RoleGateway && tun.Transport == model.TransportIXReplacementWSS:
			home = tun
		}
	}
	if ix.LinkID == "" && aliWSS.LinkID == "" {
		// No relay: the gateway's plain WireGuard is the west path.
		ix = gatewayHubMain(tunnelsTo(tunnels, n.ID))
	}
	mode := "0"
	if t.Settings.IXReplacementMode {
		mode = "1"
	}
	var sb strings.Builder
	sb.WriteString("#!/bin/bash\n")
	sb.WriteString("# Return path follows whichever west tunnel is actually up: IX, relay WSS, then gateway WSS.\n")
	sb.WriteString("set -u\n")
	fmt.Fprintf(&sb, "IX_MODE=%s\n", mode)
	fmt.Fprintf(&sb, "IX=%q\nALI_WSS=%q\nHOME_WSS=%q\n", ix.Iface(), aliWSS.Iface(), home.Iface())
	fmt.Fprintf(&sb, "IX_PEER=%q\nALI_PEER=%q\nHOME_PEER=%q\n", ix.WestV4, aliWSS.WestV4, home.WestV4)
	fmt.Fprintf(&sb, "LAN=%q\nTRANSIT4=%q\nTRANSIT6=%q\nLAN6=%q\n", lanNet(t), transitV4Net(), transitV6Net(), t.Settings.LANIPv6Prefix)
	fmt.Fprintf(&sb, "FAILS_NEED=%d\nRECOVERS_NEED=%d\nCOOLDOWN=%d\n", pool.FailsNeed, pool.RecoversNeed, int(pool.Cooldown/time.Second))
	// GROUP_PLAN identifies the group plan this script runs (see
	// GroupPlanID); it is written to the hub's state reports.
	fmt.Fprintf(&sb, "GROUP_PLAN=%s\n", GroupPlanID(groups))
	checks := renderGroupChecks(groups, t.HasMeshLegs())
	loop := failoverLoopHub
	if n.Role == model.RoleHub && len(meshLegsOn(tunnels, n.ID)) > 0 {
		checks = strings.Replace(checks, `  [ -n "$dev" ] || return 1`, `  dev=$(mesh_selected "$dev")
  [ -n "$dev" ] || return 1
  if [ "$dev" = blackhole ]; then mesh_route "$table" blackhole; return; fi`, 1)
		checks = strings.Replace(checks, `    if alive "$iface" "$peer"; then`, `    if mesh_member_alive "$id" "$iface" "$peer" "$gid" "$target"; then`, 1)
		// Reapply even when the member did not change: its leg may have.
		checks = strings.Replace(checks, `  group_record "$dir"`, `  if mesh_managed "$active"; then
    dev=$(cat "/run/meridian/group-iface/$active" 2>/dev/null)
    group_hop "$table" "$dev" || hfail="$active"
  fi
  group_record "$dir"`, 1)
		// The report maps either leg back to the same selected member.
		checks = strings.Replace(checks, `    pairs="$pairs $id=$iface"`, `    pairs="$pairs $id=$(mesh_selected "$iface")"`, 1)
		sb.WriteString(renderMeshQuality(t, exits))
		loop = strings.Replace(loop, "  check_groups || true", "  check_mesh_legs || true\n  check_groups || true", 1)
		loop = strings.Replace(loop, "reset_groups\n", "check_mesh_legs || true\nreset_groups\n", 1)
		if n.MeshHost != nil {
			// No sidecar re-seal here: follow the host WARP interface.
			sb.WriteString(meshUnderlayShell(n, tunnels))
			loop = strings.Replace(loop, "  check_mesh_legs || true\n", "  mesh_underlay\n  check_mesh_legs || true\n", 1)
		}
	}
	sb.WriteString(checks)
	sb.WriteString(loop)
	return sb.String()
}

// groupHopPrelude is shared, byte for byte, by the hub's static routes
// script and its failover script: the Mesh veth's name and next-hops, the
// list of group tables, and group_hop, the only function that points a
// group table at a member. Static install and dynamic switching therefore
// agree on the route. meshLegs: the topology has Mesh legs, so a hub may
// have the veth, and group_hop refuses it on every hub (meshGroupHopShell):
// a group table only ever points at a member's WireGuard interface.
func groupHopPrelude(groups []GroupPlan, meshLegs bool) string {
	var sb strings.Builder
	ma := mesh.DefaultAddressing()
	fmt.Fprintf(&sb, "MESH_DEV=%s\nMESH_NH4=%s\nMESH_NH6=%s\n", mesh.HostIface, ma.NextHopV4(), ma.NextHopV6())
	var tables []string
	for _, g := range groups {
		tables = append(tables, fmt.Sprintf("%d", g.Table))
	}
	fmt.Fprintf(&sb, "GROUP_TABLES=%q\n", strings.Join(tables, " "))
	hop := hopShell(sharedHops(groups))
	if meshLegs {
		hop = meshGroupHopShell(hop)
	}
	sb.WriteString(hop)
	return sb.String()
}

// renderHubGroupRoutes installs every region group's table on the hub. A
// dynamic group's default goes to its compiled target through group_hop;
// the hub's runtime state for the group is cleared, so the failover script
// starts from the same member. A group the hub cannot switch keeps only
// the blackhole: its rules use the target's own mark, and a stray packet
// with the group's transit source is dropped, not routed out of the hub.
func renderHubGroupRoutes(sb *strings.Builder, t model.Topology, west string, groups []GroupPlan, meshLegs bool) {
	if len(groups) == 0 {
		return
	}
	sb.WriteString("# region groups: one table per group; only group_hop points it at a member\n")
	sb.WriteString(groupHopPrelude(groups, meshLegs))
	for _, g := range groups {
		fmt.Fprintf(sb, "# group %s mark %#x transit %s table %d\n", g.Group.ID, g.Mark, g.TransitV4, g.Table)
		fmt.Fprintf(sb, "rm -rf -- %s\n", shQuote("/run/meridian/group/"+g.Group.ID))
		fmt.Fprintf(sb, "ip route replace blackhole default metric 32767 table %d\n", g.Table)
		fmt.Fprintf(sb, "ip -6 route replace blackhole default metric 32767 table %d\n", g.Table)
		if g.Dynamic {
			fmt.Fprintf(sb, "group_hop %d %s\n", g.Table, shQuote(hopDev(g.Target)))
		} else {
			fmt.Fprintf(sb, "# group %s target %s is not switchable from the hub: blackhole only\n", g.Group.ID, g.Target.Node.ID)
		}
		fmt.Fprintf(sb, "ip route replace %s dev %s table %d\n", lanNet(t), west, g.Table)
		fmt.Fprintf(sb, "ip route replace %s dev %s table %d\n", transitV4Net(), west, g.Table)
		if t.Settings.LANIPv6Prefix != "" {
			fmt.Fprintf(sb, "ip -6 route replace %s dev %s table %d\n", t.Settings.LANIPv6Prefix, west, g.Table)
		}
		fmt.Fprintf(sb, "ip -6 route replace %s dev %s table %d\n", transitV6Net(), west, g.Table)
		fmt.Fprintf(sb, "del_rule ip rule del from %s/32 lookup %d\n", g.TransitV4, g.Table)
		fmt.Fprintf(sb, "ip rule add from %s/32 lookup %d priority %d\n", g.TransitV4, g.Table, prioHubExitFrom+g.Index)
		fmt.Fprintf(sb, "del_rule ip -6 rule del from %s/128 lookup %d\n", g.TransitV6, g.Table)
		fmt.Fprintf(sb, "ip -6 rule add from %s/128 lookup %d priority %d\n", g.TransitV6, g.Table, prioHubExitFrom+g.Index)
	}
}

// renderGroupChecks writes the hub-side group switch: group_hop (shared
// with the routes script), the state machine group_step, reset_groups (run
// once when the service starts: clears state and re-installs every
// compiled target) and check_groups (one step per dynamic group). Each
// group only ever changes its own table, among its own switchable members.
// The state machine's Mesh fallback (its fourth argument) is never asked
// for: it is always 0.
func renderGroupChecks(groups []GroupPlan, meshLegs bool) string {
	var sb strings.Builder
	sb.WriteString(groupHopPrelude(groups, meshLegs))
	sb.WriteString(stepShell(sharedHops(groups)))
	sb.WriteString(reportShell(sharedHops(groups)))
	sb.WriteString("reset_groups() {\n")
	for _, g := range groups {
		if !g.Dynamic {
			continue
		}
		fmt.Fprintf(&sb, "  rm -rf -- %s\n", shQuote("/run/meridian/group/"+g.Group.ID))
		fmt.Fprintf(&sb, "  group_hop %d %s || true\n", g.Table, shQuote(hopDev(g.Target)))
	}
	sb.WriteString("  group_plan_record || true\n")
	sb.WriteString("  :\n}\n")
	sb.WriteString("check_groups() {\n")
	for _, g := range groups {
		if !g.Dynamic {
			continue
		}
		p := g.Policy()
		fmt.Fprintf(&sb, "  group_step %s %d %s %d %d %d %s", shQuote(g.Group.ID), g.Table, shQuote(g.Target.Node.ID),
			boolNum(p.Mesh), boolNum(p.Hold), boolNum(p.Manual), shQuote(p.TargetReason))
		for _, e := range g.Try {
			fmt.Fprintf(&sb, " %s %s %s", shQuote(e.Node.ID), shQuote(hopDev(e)), shQuote(e.PeerV4))
		}
		sb.WriteString("\n")
	}
	sb.WriteString("  :\n}\n")
	return sb.String()
}

func boolNum(v bool) int {
	if v {
		return 1
	}
	return 0
}

// groupHopShell points one group table at a member interface or at the
// Mesh veth. It refuses every table that is not a compiled group table
// (100, 102, 150, main and the per-exit tables included).
const groupHopShell = `
group_hop() {
  local table="$1" dev="$2"
  case "$table" in
    ""|main|100|102|150)
      echo "group hop refused on table $table" >&2
      return 1
      ;;
  esac
  case " $GROUP_TABLES " in
    *" $table "*) ;;
    *)
      echo "group hop refused on table $table: not a region-group table" >&2
      return 1
      ;;
  esac
  [ -n "$dev" ] || return 1
  if [ "$dev" = "$MESH_DEV" ]; then
    if ! ip link show "$MESH_DEV" >/dev/null 2>&1 || [ ! -f /run/meridian/mesh-sealed ]; then
      ip route replace blackhole default table "$table"
      ip -6 route replace blackhole default table "$table"
      echo "mmesh is not sealed; table $table stays blackholed" >&2
      return 0
    fi
    # Ethernet veth: route via the sidecar's addresses, never "dev mmesh"
    # alone (that would ARP/ND for every public destination).
    ip route replace default via "$MESH_NH4" dev "$MESH_DEV" table "$table"
    ip -6 route replace default via "$MESH_NH6" dev "$MESH_DEV" table "$table"
  else
    ip route replace default dev "$dev" table "$table"
    ip -6 route replace default dev "$dev" table "$table"
  fi
  ip route replace blackhole default metric 32767 table "$table"
  ip -6 route replace blackhole default metric 32767 table "$table"
}
`

// groupStepShell mirrors pool.StepGroup (internal/pool): FailsNeed /
// RecoversNeed hysteresis per member, a success streak (okst, cleared by
// any failure) and the last sample (lastok). Leaving a member that is
// marked down is immediate; returning to the target needs it up, its
// latest sample a success, COOLDOWN seconds of unbroken success and
// COOLDOWN seconds since the last switch. hold=1 never moves.
const groupStepShell = `
group_can_return() {
  local dir="$1" target="$2" now="$3" last="$4" st lo ok
  st=$(cat "$dir/$target.state" 2>/dev/null || echo up)
  lo=$(cat "$dir/$target.lastok" 2>/dev/null || echo 0)
  ok=$(cat "$dir/$target.okst" 2>/dev/null || true)
  case "$ok" in ''|*[!0-9]*) return 1 ;; esac
  [ "$st" = "up" ] && [ "$lo" = "1" ] || return 1
  [ $((now-ok)) -ge "$COOLDOWN" ] || return 1
  [ "$last" -eq 0 ] || [ $((now-last)) -ge "$COOLDOWN" ]
}
group_step() {
  local gid="$1" table="$2" target="$3" mesh="$4" hold="$5" manual="$6" treason="$7"
  shift 7
  local dir="/run/meridian/group/${gid}"
  mkdir -p "$dir" /run/meridian/group-iface
  local now id iface peer fails goods state okst lastok ids="" t_up=0 alt_id="" pairs=""
  now=$(date +%s)
  while [ $# -ge 3 ]; do
    id="$1"; iface="$2"; peer="$3"; shift 3
    ids="$ids $id"
    pairs="$pairs $id=$iface"
    echo "$iface" > "/run/meridian/group-iface/${id}"
    fails=$(cat "$dir/$id.fails" 2>/dev/null || echo 0)
    goods=$(cat "$dir/$id.goods" 2>/dev/null || echo 0)
    state=$(cat "$dir/$id.state" 2>/dev/null || echo up)
    okst=$(cat "$dir/$id.okst" 2>/dev/null || true)
    case "$fails" in ''|*[!0-9]*) fails=0 ;; esac
    case "$goods" in ''|*[!0-9]*) goods=0 ;; esac
    [ "$state" = "down" ] || state=up
    if alive "$iface" "$peer"; then
      lastok=1
      [ -n "$okst" ] || okst="$now"
      fails=0
      if [ "$state" = "down" ]; then
        goods=$((goods+1))
        if [ "$goods" -ge "$RECOVERS_NEED" ]; then state=up; goods=0; fi
      else
        goods=0
      fi
    else
      lastok=0; okst=""; goods=0
      if [ "$state" = "up" ]; then
        fails=$((fails+1))
        if [ "$fails" -ge "$FAILS_NEED" ]; then state=down; fails=0; fi
      fi
    fi
    echo "$fails" > "$dir/$id.fails"
    echo "$goods" > "$dir/$id.goods"
    echo "$state" > "$dir/$id.state"
    echo "$okst" > "$dir/$id.okst"
    echo "$lastok" > "$dir/$id.lastok"
    if [ "$id" = "$target" ] && [ "$state" = "up" ]; then t_up=1; fi
    if [ "$id" != "$target" ] && [ "$state" = "up" ] && [ -z "$alt_id" ]; then alt_id="$id"; fi
  done
  local active want last ast dev reason hfail=""
  active=$(cat "$dir/active" 2>/dev/null || true)
  [ -n "$active" ] || active="$target"
  if [ "$active" != "mmesh" ]; then
    case " $ids " in *" $active "*) ;; *) active="$target" ;; esac
  fi
  last=$(cat "$dir/switched" 2>/dev/null || echo 0)
  case "$last" in ''|*[!0-9]*) last=0 ;; esac
  want="$active"
  if [ "$hold" = "1" ]; then
    want="$target"
  elif [ "$active" = "$target" ]; then
    if [ "$t_up" -eq 0 ]; then
      if [ -n "$alt_id" ]; then want="$alt_id"; elif [ "$mesh" = "1" ]; then want="mmesh"; fi
    fi
  elif group_can_return "$dir" "$target" "$now" "$last"; then
    want="$target"
  elif [ "$active" = "mmesh" ]; then
    if [ -n "$alt_id" ]; then want="$alt_id"; fi
  else
    ast=$(cat "$dir/$active.state" 2>/dev/null || echo down)
    if [ "$ast" != "up" ]; then
      if [ -n "$alt_id" ]; then want="$alt_id"; elif [ "$mesh" = "1" ]; then want="mmesh"; fi
    fi
  fi
  if [ "$want" != "$active" ]; then
    if [ "$want" = "mmesh" ]; then dev="$MESH_DEV"; else dev=$(cat "/run/meridian/group-iface/$want" 2>/dev/null || true); fi
    if group_hop "$table" "$dev"; then
      active="$want"
      echo "$active" > "$dir/active"
      echo "$now" > "$dir/switched"
    else
      hfail="$want"
    fi
  elif [ "$active" = "mmesh" ]; then
    # Staying on Mesh: re-apply every round, so the table follows the seal
    # (via the sidecar while sealed, blackhole otherwise) and survives a
    # re-created veth. Not a switch: active and switched stay as they are;
    # the report reads the table (hop mmesh or blackhole).
    group_hop "$table" "$MESH_DEV" 2>/dev/null || true
  fi
  if [ "$active" = "$target" ]; then
    reason="$treason"
    if [ "$t_up" -eq 0 ]; then
      if [ "$hold" = "1" ]; then reason=held; fi
      echo 1 > "$dir/alert"
    else
      echo 0 > "$dir/alert"
    fi
  elif [ "$active" = "mmesh" ]; then
    reason=mesh; echo 1 > "$dir/alert"
  elif [ "$manual" = "1" ]; then
    reason=fallback; echo 1 > "$dir/alert"
  else
    reason=failover; echo 0 > "$dir/alert"
  fi
  [ -f "$dir/active" ] || echo "$active" > "$dir/active"
  echo "$reason" > "$dir/reason"
  group_record "$dir" "$gid" "$table" "$now" "$active" "$reason" "$hfail" "$pairs"
}
`

const failoverLoopHub = `
alive() {
  local iface="$1" peer="$2"
  [ -n "$iface" ] || return 1
  ping -I "$iface" -c 1 -W 2 -n "$peer" >/dev/null 2>&1
}
apply_west() {
  local iface="$1"
  [ -n "$iface" ] || return 0
  ip route replace "$LAN" dev "$iface"
  ip route replace "$TRANSIT4" dev "$iface"
  ip route replace blackhole "$LAN" metric 32767
  ip route replace blackhole "$TRANSIT4" metric 32767
  ip route replace 10.66.0.0/16 dev "$iface"
  ip route replace blackhole 10.66.0.0/16 metric 32767
  ip -6 route replace "$TRANSIT6" dev "$iface"
  ip -6 route replace blackhole "$TRANSIT6" metric 32767
  ip -6 route replace fd66::/48 dev "$iface"
  ip -6 route replace blackhole fd66::/48 metric 32767
  if [ -n "$LAN6" ]; then
    ip -6 route replace "$LAN6" dev "$iface"
    ip -6 route replace blackhole "$LAN6" metric 32767
  fi
}
choose() {
  if [ "$IX_MODE" = "1" ]; then
    if alive "$ALI_WSS" "$ALI_PEER"; then echo "$ALI_WSS"; return; fi
    if alive "$IX" "$IX_PEER"; then echo "$IX"; return; fi
    echo "$HOME_WSS"; return
  fi
  if alive "$IX" "$IX_PEER"; then echo "$IX"; return; fi
  if alive "$ALI_WSS" "$ALI_PEER"; then echo "$ALI_WSS"; return; fi
  echo "$HOME_WSS"
}
# --- main loop ---
reset_groups
cur=""
bad=0
while true; do
  if [ -x /usr/local/sbin/meridian-mesh-up.sh ]; then
    /usr/local/sbin/meridian-mesh-up.sh --seal-only || rm -f /run/meridian/mesh-sealed
  fi
  want=$(choose)
  if [ "$want" != "$cur" ]; then
    bad=$((bad+1))
    if [ "$bad" -ge "$FAILS_NEED" ] || [ -z "$cur" ]; then
      apply_west "$want"
      cur="$want"
      bad=0
    fi
  else
    bad=0
  fi
  check_groups || true
  sleep 5
done
`

// writePrefixBlackholes keeps tunnel and LAN prefixes from following a VPS
// default route when the WireGuard device route is deleted. The live route
// uses metric 0; this one stays at 32767.
func writePrefixBlackholes(sb *strings.Builder, t model.Topology) {
	fmt.Fprintf(sb, "ip route replace blackhole %s metric 32767\n", lanNet(t))
	fmt.Fprintf(sb, "ip route replace blackhole %s metric 32767\n", transitV4Net())
	sb.WriteString("ip route replace blackhole 10.66.0.0/16 metric 32767\n")
	sb.WriteString("ip -6 route replace blackhole fd66::/48 metric 32767\n")
	fmt.Fprintf(sb, "ip -6 route replace blackhole %s metric 32767\n", transitV6Net())
	if t.Settings.LANIPv6Prefix != "" {
		fmt.Fprintf(sb, "ip -6 route replace blackhole %s metric 32767\n", t.Settings.LANIPv6Prefix)
	}
}

func ifaceOrDash(t Tunnel) string {
	if t.Iface() == "" || t.LinkID == "" {
		return "-"
	}
	return t.Iface()
}
