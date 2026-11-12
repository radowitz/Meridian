package compile

import (
	"fmt"
	"strings"
	"time"

	"github.com/radowitz/meridian/internal/mesh"
	"github.com/radowitz/meridian/internal/model"
	"github.com/radowitz/meridian/internal/pool"
)

func renderRoutes(t model.Topology, n model.Node, tunnels []Tunnel, exits []ExitPlan) string {
	var sb strings.Builder
	sb.WriteString("#!/bin/bash\n")
	sb.WriteString("# Policy routes for one Meridian node. Safe to re-run.\n")
	sb.WriteString("# fd66::/48 is never given a next hop of the ROS gateway.\n")
	sb.WriteString("set -euo pipefail\n")
	sb.WriteString("del_rule() {\n")
	sb.WriteString("  while \"$@\" >/dev/null 2>&1; do :; done || true\n")
	sb.WriteString("}\n")
	writeHarden(&sb)

	switch n.Role {
	case model.RoleGateway:
		renderGatewayRoutes(&sb, t, tunnels, exits)
	case model.RoleRelay:
		renderRelayRoutes(&sb, t, tunnels)
	case model.RoleHub:
		renderHubRoutes(&sb, t, tunnels, exits)
	case model.RoleExit:
		renderExitRoutes(&sb, t, n, tunnels)
		if n.DualstackRelay {
			renderDualstackForward(&sb, t, n, tunnels, exits)
		}
	default:
		sb.WriteString("echo \"no routes for role " + string(n.Role) + "\"\n")
	}
	return sb.String()
}

func renderGatewayRoutes(sb *strings.Builder, t model.Topology, tunnels []Tunnel, exits []ExitPlan) {
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
	fmt.Fprintf(sb, "# meridian-west-preferred: udp %s\n", udp.Iface())
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
	fmt.Fprintf(sb, "ip route replace default dev %s table 102\n", westQ)
	sb.WriteString("ip route replace blackhole default metric 32767 table 102\n")
	fmt.Fprintf(sb, "ip -6 route replace default dev %s table 102\n", westQ)
	sb.WriteString("ip -6 route replace blackhole default metric 32767 table 102\n")
	fmt.Fprintf(sb, "ip route replace 10.66.0.0/16 dev %s\n", westQ)
	sb.WriteString("ip route replace blackhole 10.66.0.0/16 metric 32767\n")
	fmt.Fprintf(sb, "ip -6 route replace fd66::/48 dev %s\n", westQ)
	sb.WriteString("ip -6 route replace blackhole fd66::/48 metric 32767\n")

	// Selectors only. This does not delete another program's rules, but it
	// does drop marks for exits that were removed from the topology.
	sb.WriteString("for n in $(seq 0 63); do\n")
	sb.WriteString("  m=$(printf '0x%x' $((0x101 + n)))\n")
	sb.WriteString("  del_rule ip rule del fwmark \"$m\" lookup 102\n")
	sb.WriteString("  del_rule ip rule del fwmark \"$m\" unreachable\n")
	sb.WriteString("  del_rule ip -6 rule del fwmark \"$m\" lookup 102\n")
	sb.WriteString("  del_rule ip -6 rule del fwmark \"$m\" unreachable\n")
	sb.WriteString("done\n")
	for _, e := range exits {
		fmt.Fprintf(sb, "ip addr replace %s/32 dev lo\n", e.TransitV4)
		fmt.Fprintf(sb, "ip -6 addr replace %s/128 dev lo\n", e.TransitV6)
		fmt.Fprintf(sb, "ip rule add fwmark %#x lookup 102 priority %d\n", e.Mark, prioExitBase+e.Index)
		fmt.Fprintf(sb, "ip rule add fwmark %#x unreachable priority %d\n", e.Mark, prioExitDrop+e.Index)
		fmt.Fprintf(sb, "ip -6 rule add fwmark %#x lookup 102 priority %d\n", e.Mark, prioExitBase+e.Index)
		fmt.Fprintf(sb, "ip -6 rule add fwmark %#x unreachable priority %d\n", e.Mark, prioExitDrop+e.Index)
	}
	fmt.Fprintf(sb, "del_rule ip rule del fwmark %#x lookup 100\n", markDomestic)
	fmt.Fprintf(sb, "ip rule add fwmark %#x lookup 100 priority %d\n", markDomestic, prioDomestic)
	fmt.Fprintf(sb, "del_rule ip -6 rule del fwmark %#x lookup 100\n", markDomestic)
	fmt.Fprintf(sb, "ip -6 rule add fwmark %#x lookup 100 priority %d\n", markDomestic, prioDomestic)
	// IPv4 only. An IPv6 interface blackhole would also have to be proven
	// not to eat RA or ND, so there is no IPv6 counterpart here: unmarked
	// IPv6 from the LAN can still match the main-table default via ROS. That
	// path is closed by the forward-hook guard in table inet meridian_guard
	// (render_nft.go), which drops every forwarded LAN packet, v4 and v6,
	// that does not carry the domestic mark on the LAN NIC or an exit mark
	// on a WireGuard interface. This IPv4 rule stays as a second, routing
	// level layer. SSH to this host is in the local table (priority 0) and
	// is not matched by this rule.
	fmt.Fprintf(sb, "del_rule ip rule del iif %s unreachable\n", lanQ)
	fmt.Fprintf(sb, "ip rule add iif %s unreachable priority %d\n", lanQ, prioLANDrop)
	fmt.Fprintf(sb, "# failover companions: udp=%s wss=%s direct_wss=%s\n", ifaceOrDash(udp), ifaceOrDash(wss), ifaceOrDash(direct))
}

func writeHarden(sb *strings.Builder) {
	sb.WriteString(`# Per-interface values win over "all" for redirects (the kernel ORs them)
# and rp_filter uses the max of all and the device. Set every device.
harden_sysctl() {
  local d i
  for d in /proc/sys/net/ipv4/conf/*; do
    i=$(basename "$d")
    sysctl -w "net.ipv4.conf.${i}.rp_filter=2" >/dev/null 2>&1 || true
    sysctl -w "net.ipv4.conf.${i}.send_redirects=0" >/dev/null 2>&1 || true
    sysctl -w "net.ipv4.conf.${i}.accept_redirects=0" >/dev/null 2>&1 || true
  done
  for d in /proc/sys/net/ipv6/conf/*; do
    i=$(basename "$d")
    sysctl -w "net.ipv6.conf.${i}.send_redirects=0" >/dev/null 2>&1 || true
    sysctl -w "net.ipv6.conf.${i}.accept_redirects=0" >/dev/null 2>&1 || true
  done
}
harden_sysctl
`)
}

func renderRelayRoutes(sb *strings.Builder, t model.Topology, tunnels []Tunnel) {
	westUDP, westWSS, eastIX, eastWSS := relayIfaces(tunnels)
	preferred := eastIX
	kind := "ix"
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
}

func renderHubRoutes(sb *strings.Builder, t model.Topology, tunnels []Tunnel, exits []ExitPlan) {
	westTun := hubWestTunnel(tunnels, t.Settings.IXReplacementMode)
	west := westTun.Iface()
	kind := "ix"
	if t.Settings.IXReplacementMode {
		kind = "ix-replacement"
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
	ma := mesh.DefaultAddressing()
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
		if e.Mesh {
			fmt.Fprintf(sb, "# pure-v6 %s mesh hop only; never the IX west path\n", e.Node.ID)
			fmt.Fprintf(sb, "# mmesh is used only after meridian-mesh-up.sh has sealed the sidecar.\n")
			fmt.Fprintf(sb, "# Without that seal, packets would follow the container default route onto this host's WAN.\n")
			// mmesh is an Ethernet veth: an explicit next-hop the sidecar owns
			// (never "default dev mmesh", which would ARP/ND for every
			// destination). IPv6 uses the link-local next-hop scoped to mmesh.
			fmt.Fprintf(sb, "# veth next-hops: %s (v4) and %s%%%s (v6)\n", ma.NextHopV4(), ma.NextHopV6(), mesh.HostIface)
			fmt.Fprintf(sb, "if ip link show mmesh >/dev/null 2>&1 && [ -f /run/meridian/mesh-sealed ]; then\n")
			fmt.Fprintf(sb, "  ip route replace default via %s dev %s table %d\n", ma.NextHopV4(), mesh.HostIface, e.Table)
			fmt.Fprintf(sb, "  ip -6 route replace default via %s dev %s table %d\n", ma.NextHopV6(), mesh.HostIface, e.Table)
			fmt.Fprintf(sb, "else\n")
			fmt.Fprintf(sb, "  ip route replace blackhole default table %d\n", e.Table)
			fmt.Fprintf(sb, "  ip -6 route replace blackhole default table %d\n", e.Table)
			fmt.Fprintf(sb, "  echo \"mmesh is not sealed; exit %s stays blackholed\" >&2\n", e.Node.ID)
			fmt.Fprintf(sb, "fi\n")
		}
		fmt.Fprintf(sb, "# exit %s mark %#x transit %s dev %s\n", e.Node.ID, e.Mark, e.TransitV4, e.HubIface)
		if e.Mesh {
			fmt.Fprintf(sb, "# default via the mmesh next-hop is installed above when the sidecar is sealed\n")
		} else {
			fmt.Fprintf(sb, "ip route replace default dev %s table %d\n", e.HubIface, e.Table)
		}
		fmt.Fprintf(sb, "ip route replace %s dev %s table %d\n", lanNet(t), west, e.Table)
		fmt.Fprintf(sb, "ip route replace %s dev %s table %d\n", transitV4Net(), west, e.Table)
		if !e.Mesh {
			fmt.Fprintf(sb, "ip -6 route replace default dev %s table %d\n", e.HubIface, e.Table)
		}
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
}

func renderExitRoutes(sb *strings.Builder, t model.Topology, n model.Node, tunnels []Tunnel) {
	tun := exitIngress(n, tunnels)
	if tun.Iface() == "" {
		if !n.PathV4 && n.PathV6 && n.V6Workaround == model.WorkaroundMesh {
			sb.WriteString("# reached via the Mesh sidecar after the hub. No direct WireGuard from the hub.\n")
			sb.WriteString("# Return traffic follows the Mesh session. Do not point fd66 at ROS.\n")
			writePrefixBlackholes(sb, t)
			return
		}
		sb.WriteString("echo \"exit has no hub tunnel\" >&2\nexit 1\n")
		return
	}
	fmt.Fprintf(sb, "ip route replace %s dev %s\n", lanNet(t), tun.Iface())
	fmt.Fprintf(sb, "ip route replace %s dev %s\n", transitV4Net(), tun.Iface())
	if t.Settings.LANIPv6Prefix != "" {
		fmt.Fprintf(sb, "ip -6 route replace %s dev %s\n", t.Settings.LANIPv6Prefix, tun.Iface())
	}
	fmt.Fprintf(sb, "ip -6 route replace %s dev %s\n", transitV6Net(), tun.Iface())
	fmt.Fprintf(sb, "ip -6 route replace fd66::/48 dev %s\n", tun.Iface())
	writePrefixBlackholes(sb, t)
	if n.NatDialOut {
		sb.WriteString("# NAT dial-out: keep the mapping warm. Updates must use wg syncconf, not wg-quick down.\n")
	}
}

func renderFailover(t model.Topology, n model.Node, tunnels []Tunnel, exits []ExitPlan) string {
	switch n.Role {
	case model.RoleGateway:
		return renderGatewayFailover(t, tunnels)
	case model.RoleHub:
		return renderHubFailover(t, tunnels, exits)
	default:
		return renderRelayFailover(t, tunnels)
	}
}

func renderGatewayFailover(t model.Topology, tunnels []Tunnel) string {
	udp, wss, direct := gatewayIfaces(tunnels)
	var sb strings.Builder
	sb.WriteString("#!/bin/bash\n")
	sb.WriteString("# Prefer UDP toward Aliyun. Fall back to WSS, then to the pre-provisioned home-to-hub WSS.\n")
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

func renderRelayFailover(t model.Topology, tunnels []Tunnel) string {
	westUDP, westWSS, eastIX, eastWSS := relayIfaces(tunnels)
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
	return udp, wss, direct
}

func relayIfaces(tunnels []Tunnel) (westUDP, westWSS, eastIX, eastWSS Tunnel) {
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
		}
	}
	return westUDP, westWSS, eastIX, eastWSS
}

func hubWestTunnel(tunnels []Tunnel, replacement bool) Tunnel {
	var ix, wss Tunnel
	for _, tun := range tunnels {
		if tun.East.Role != model.RoleHub || tun.West.Role != model.RoleRelay {
			continue
		}
		if tun.Transport == model.TransportDirectWG {
			ix = tun
		}
		if tun.Transport == model.TransportIXReplacementWSS {
			wss = tun
		}
	}
	if replacement && wss.LinkID != "" {
		return wss
	}
	if ix.LinkID != "" {
		return ix
	}
	return wss
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
		down := exitIngress(e.Node, tunnels)
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

func renderHubFailover(t model.Topology, tunnels []Tunnel, exits []ExitPlan) string {
	var ix, aliWSS, home Tunnel
	for _, tun := range tunnels {
		if tun.East.Role != model.RoleHub {
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
	mode := "0"
	if t.Settings.IXReplacementMode {
		mode = "1"
	}
	var sb strings.Builder
	sb.WriteString("#!/bin/bash\n")
	sb.WriteString("# Return path follows whichever west tunnel is actually up: IX, Aliyun WSS, then home WSS.\n")
	sb.WriteString("set -u\n")
	fmt.Fprintf(&sb, "IX_MODE=%s\n", mode)
	fmt.Fprintf(&sb, "IX=%q\nALI_WSS=%q\nHOME_WSS=%q\n", ix.Iface(), aliWSS.Iface(), home.Iface())
	fmt.Fprintf(&sb, "IX_PEER=%q\nALI_PEER=%q\nHOME_PEER=%q\n", ix.WestV4, aliWSS.WestV4, home.WestV4)
	fmt.Fprintf(&sb, "LAN=%q\nTRANSIT4=%q\nTRANSIT6=%q\nLAN6=%q\n", lanNet(t), transitV4Net(), transitV6Net(), t.Settings.LANIPv6Prefix)
	fmt.Fprintf(&sb, "FAILS_NEED=%d\nRECOVERS_NEED=%d\nCOOLDOWN=%d\n", pool.FailsNeed, pool.RecoversNeed, int(pool.Cooldown/time.Second))
	sb.WriteString(renderPoolChecks(t, exits))
	sb.WriteString(failoverLoopHub)
	return sb.String()
}

// renderPoolChecks writes the hub-side pool next-hop switch. It only changes
// the preferred member's table. Mesh is used after every WireGuard member
// of that pool is down, and the helper refuses tables 100, 102 and 150.
func renderPoolChecks(t model.Topology, exits []ExitPlan) string {
	byPool := map[string][]ExitPlan{}
	var names []string
	seen := map[string]bool{}
	for _, e := range exits {
		poolName := e.Node.Pool
		if poolName == "" || e.Mesh {
			continue
		}
		if e.HubIface == "" || e.HubIface == "mmesh" || e.PeerV4 == "" {
			continue
		}
		if e.ViaRelay != "" {
			continue
		}
		byPool[poolName] = append(byPool[poolName], e)
		if !seen[poolName] {
			seen[poolName] = true
			names = append(names, poolName)
		}
	}
	sortStrings(names)
	var sb strings.Builder
	ma := mesh.DefaultAddressing()
	// The dynamic switch uses the same explicit veth next-hops as the
	// static routes (mesh.Addressing).
	fmt.Fprintf(&sb, "MESH_DEV=%s\nMESH_NH4=%s\nMESH_NH6=%s\n", mesh.HostIface, ma.NextHopV4(), ma.NextHopV6())
	sb.WriteString(poolStepShell)
	sb.WriteString("check_pools() {\n")
	for _, name := range names {
		members := pool.Members(t, name)
		if len(members) == 0 {
			continue
		}
		pref, _ := pool.Preferred(members)
		prefPlan, ok := exitByID(exits, pref.ID)
		if !ok || prefPlan.Mesh || prefPlan.HubIface == "" || prefPlan.HubIface == "mmesh" {
			continue
		}
		mesh := poolHasMesh(t, name)
		fmt.Fprintf(&sb, "  pool_step %s %d %s %d", shQuote(name), prefPlan.Table, shQuote(pref.ID), boolNum(mesh))
		for _, m := range members {
			ep, ok := exitByID(exits, m.ID)
			if !ok || ep.Mesh || ep.HubIface == "" || ep.HubIface == "mmesh" || ep.PeerV4 == "" || ep.ViaRelay != "" {
				continue
			}
			fmt.Fprintf(&sb, " %s %s %s", shQuote(m.ID), shQuote(ep.HubIface), shQuote(ep.PeerV4))
		}
		sb.WriteString("\n")
	}
	sb.WriteString("}\n")
	return sb.String()
}

func poolHasMesh(t model.Topology, poolName string) bool {
	members := map[string]bool{}
	for _, n := range pool.Members(t, poolName) {
		members[n.ID] = true
	}
	hub := ""
	for _, n := range t.Nodes {
		if n.Role == model.RoleHub {
			hub = n.ID
			break
		}
	}
	for _, l := range t.Links {
		if l.Transport != model.TransportCFMesh || !l.Enabled || !l.Standby {
			continue
		}
		if l.From == hub && members[l.To] || l.To == hub && members[l.From] {
			return true
		}
	}
	return false
}

func boolNum(v bool) int {
	if v {
		return 1
	}
	return 0
}

const poolStepShell = `
# Pool next-hop hysteresis. Thresholds match internal/pool (FailsNeed,
# RecoversNeed, Cooldown). A single failure does not move the route.
# Mesh is refused on the IX west tables (100, 102, 150, main).
pool_step() {
  local pool="$1" table="$2" pref="$3" mesh="$4"
  shift 4
  local dir="/run/meridian/pool/${pool}"
  mkdir -p "$dir" /run/meridian/pool-iface
  local id iface peer fails goods state
  local up_pref=0 alt_iface="" alt_id="" pref_iface=""
  while [ $# -ge 3 ]; do
    id="$1"; iface="$2"; peer="$3"; shift 3
    echo "$iface" > "/run/meridian/pool-iface/${id}"
    fails=0; goods=0; state=up
    [ -f "$dir/$id.fails" ] && fails=$(cat "$dir/$id.fails")
    [ -f "$dir/$id.goods" ] && goods=$(cat "$dir/$id.goods")
    [ -f "$dir/$id.state" ] && state=$(cat "$dir/$id.state")
    [ -n "$state" ] || state=up
    if alive "$iface" "$peer"; then
      fails=0
      if [ "$state" = "down" ]; then
        goods=$((goods+1))
        if [ "$goods" -ge "$RECOVERS_NEED" ]; then state=up; goods=0; fi
      else
        goods=0; state=up
      fi
    else
      goods=0
      if [ "$state" = "up" ]; then
        fails=$((fails+1))
        if [ "$fails" -ge "$FAILS_NEED" ]; then state=down; fails=0; fi
      fi
    fi
    echo "$fails" > "$dir/$id.fails"
    echo "$goods" > "$dir/$id.goods"
    echo "$state" > "$dir/$id.state"
    if [ "$id" = "$pref" ]; then pref_iface="$iface"; fi
    if [ "$id" = "$pref" ] && [ "$state" = "up" ]; then up_pref=1; fi
    if [ "$id" != "$pref" ] && [ "$state" = "up" ] && [ -z "$alt_iface" ]; then
      alt_iface="$iface"; alt_id="$id"
    fi
  done
  local active="" want last=0 now
  [ -f "$dir/active" ] && active=$(cat "$dir/active")
  [ -n "$active" ] || active="$pref"
  want="$active"
  if [ "$active" = "$pref" ]; then
    if [ "$up_pref" -eq 0 ]; then
      if [ -n "$alt_id" ]; then want="$alt_id"
      elif [ "$mesh" = "1" ]; then want="mmesh"; fi
    fi
  elif [ "$up_pref" -eq 1 ]; then
    want="$pref"
  elif [ "$active" = "mmesh" ]; then
    if [ -n "$alt_id" ]; then want="$alt_id"; fi
  else
    local ast
    ast=$(cat "$dir/$active.state" 2>/dev/null || echo down)
    if [ "$ast" != "up" ]; then
      if [ -n "$alt_id" ]; then want="$alt_id"
      elif [ "$mesh" = "1" ]; then want="mmesh"; fi
    fi
  fi
  now=$(date +%s)
  last=0
  if [ -f "$dir/switched" ]; then
    last=$(cat "$dir/switched" 2>/dev/null || echo 0)
  fi
  case "$last" in
    ''|*[!0-9]*) last=0 ;;
  esac
  if [ "$want" != "$active" ]; then
    # 120s only delays the return to a preferred member that is up again.
    # A member already marked down must be left immediately, or this table
    # keeps handing packets to a dead tunnel.
    if [ "$want" = "$pref" ] && [ "$up_pref" -eq 1 ] && [ "$last" -ne 0 ] && [ $((now-last)) -lt "$COOLDOWN" ]; then
      return 0
    fi
    apply_pool_hop "$table" "$want" || return 0
    echo "$want" > "$dir/active"
    echo "$now" > "$dir/switched"
  fi
}
apply_pool_hop() {
  local table="$1" want="$2" dev
  case "$table" in
    ""|main|100|102|150)
      echo "mesh/pool refused on table $table" >&2
      return 1
      ;;
  esac
  if [ "$want" = "mmesh" ]; then
    dev="$MESH_DEV"
    if ! ip link show mmesh >/dev/null 2>&1 || [ ! -f /run/meridian/mesh-sealed ]; then
      ip route replace blackhole default table "$table"
      ip -6 route replace blackhole default table "$table"
      echo "mmesh is not sealed; pool $pool stays blackholed" >&2
      return 0
    fi
  else
    dev=$(cat "/run/meridian/pool-iface/$want" 2>/dev/null || true)
  fi
  [ -n "$dev" ] || return 0
  if [ "$dev" = "$MESH_DEV" ]; then
    # Ethernet veth: route via the sidecar's addresses, never "dev mmesh"
    # alone (that would ARP/ND for every public destination).
    ip route replace default via "$MESH_NH4" dev "$MESH_DEV" table "$table"
    ip route replace blackhole default metric 32767 table "$table"
    ip -6 route replace default via "$MESH_NH6" dev "$MESH_DEV" table "$table"
    ip -6 route replace blackhole default metric 32767 table "$table"
    return 0
  fi
  ip route replace default dev "$dev" table "$table"
  ip route replace blackhole default metric 32767 table "$table"
  ip -6 route replace default dev "$dev" table "$table"
  ip -6 route replace blackhole default metric 32767 table "$table"
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
  check_pools || true
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
