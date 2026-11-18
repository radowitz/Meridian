package compile

import (
	"fmt"
	"sort"
	"strings"

	"github.com/radowitz/meridian/internal/mesh"
	"github.com/radowitz/meridian/internal/model"
	"github.com/radowitz/meridian/internal/validate"
)

// Cloudflare Mesh as the underlay of a WireGuard leg (docs/architecture.md
// 「Cloudflare Mesh：WireGuard 的底层承载」).
//
// A cf_mesh link compiles to an ordinary WireGuard tunnel between the
// primary (or backup) hub and an exit (buildTunnels: its own interface, port and tunnel
// subnet from its link slot). Only the outer packets differ: the hub's
// Endpoint is the exit's Mesh underlay address (Tunnel.MeshAddr), one /32
// the exit's Mesh node publishes and nothing else does.
//
//	hub WireGuard ──UDP──▶ mmesh ──▶ hub sidecar ──▶ Cloudflare Mesh
//	    ──▶ exit sidecar ──▶ mmesh ──▶ exit WireGuard (listening)
//
// What is inside the tunnel is what is inside the direct leg: the client's
// packets with their transit source. They are decapsulated on the exit and
// leave through the exit's own uplink, so the public address, the region,
// the unlock results and the resolver are the exit's whichever leg carried
// them. Cloudflare only ever sees WireGuard ciphertext between two
// addresses of its own Mesh.
//
// What this file guarantees, on every host with a Mesh leg:
//
//   - one sidecar per host (one container, one veth pair) serves all of the
//     host's Mesh legs;
//   - no routing table ever gets a default route onto mmesh, and none of an
//     exit's or region group's routes points at it: the only routes onto
//     mmesh are the hub's /32 host routes to its exits' Mesh addresses
//     (mesh_underlay), installed only while the sidecar is sealed, each
//     over a blackhole of the same /32 so the outer packets are dropped
//     rather than sent out of the host's WAN when the sidecar is away;
//   - the host forwards nothing to or from mmesh (mesh_veth chains in the
//     node's nft table) and accepts nothing from it but the WireGuard
//     packets of its Mesh legs;
//   - inside the sidecar, table 170 (what the host injects on mmesh-c) holds
//     only the routes to the peers' Mesh addresses on the WARP device over
//     an unreachable default, and the forward chain passes only the Mesh
//     legs' WireGuard UDP between mmesh-c and the WARP device
//     (meshSealScript).
//
// The compiled default hop of an exit with both legs is its direct leg; the
// Mesh leg is up and idle. Moving the hub's hop between the two legs is the
// quality switch's job, which only ever changes that one hop.

// Return path of connections that arrived on an exit's Mesh leg
// (render_dualhub.go): like the per-hub return paths, by connection mark.
const (
	markHubReturnMesh  uint32 = 0x4d52
	tableHubReturnMesh        = 169
	// The backup hub's Mesh leg (dual hub): its own mark and table, so
	// both hubs' Mesh legs on one exit never share a return path.
	markHubReturnMeshBackup  uint32 = 0x4d53
	tableHubReturnMeshBackup        = 168
)

// meshLinkOf is the cf_mesh link a Mesh-leg tunnel was made from.
func meshLinkOf(t model.Topology, tun Tunnel) model.Link {
	l, _ := t.LinkByID(tun.LinkID)
	return l
}

// meshLegsOn are node id's Mesh-leg tunnels, in tunnel (slot) order.
func meshLegsOn(tunnels []Tunnel, id string) []Tunnel {
	var out []Tunnel
	for _, tun := range tunnels {
		if tun.MeshLeg() && (tun.West.ID == id || tun.East.ID == id) {
			out = append(out, tun)
		}
	}
	return out
}

// legMSS is the MSS a node applies to its own TCP on one Mesh-leg interface.
type legMSS struct {
	Iface      string
	MSS4, MSS6 int
}

// meshLegMSS lists node n's Mesh legs whose MSS (the leg's payload MTU
// minus 40 / 60) is below the node's general clamp m, in interface order.
func meshLegMSS(t model.Topology, n model.Node, tunnels []Tunnel, m nodeMSS) []legMSS {
	var out []legMSS
	for _, tun := range meshLegsOn(tunnels, n.ID) {
		payload, _ := validate.MeshLegMTU(meshLinkOf(t, tun))
		l := legMSS{Iface: tun.Iface(), MSS4: payload - 40, MSS6: payload - 60}
		if l.MSS4 < m.MSS4 || l.MSS6 < m.MSS6 {
			out = append(out, l)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Iface < out[j].Iface })
	return out
}

// meshLegExits are the exits that have a Mesh leg from either hub: that
// hub may carry them over it, so their path MTU counts it (PathReport) and
// their marks are clamped on their own instead of lowering everyone's
// floor.
func meshLegExits(t model.Topology) map[string]bool {
	out := map[string]bool{}
	for _, m := range t.MeshLegs() {
		out[m.Exit] = true
	}
	return out
}

// withPendingMeshHosts returns t with every end of an enabled cf_mesh link
// that is not (yet) a host-level Mesh node marked as a pending one
// (model.NodeMeshHost.Pending): no sidecar is rendered for any host any
// more. An exit's pending address is its allocated placeholder, never
// reachable; every leg with a pending end is blackholed on the hub and its
// WireGuard port closed on the exit until the node exists and the hub and
// exit are re-provisioned with its real Mesh address. A topology without
// Mesh edges is returned unchanged.
func withPendingMeshHosts(t model.Topology) model.Topology {
	if !t.HasMeshLegs() {
		return t
	}
	addr := map[string]string{}
	ends := map[string]bool{}
	for _, m := range t.MeshLegs() {
		ends[m.Hub], ends[m.Exit] = true, true
		if m.Addr.IsValid() {
			addr[m.Exit] = m.Addr.String()
		}
	}
	nodes := append([]model.Node(nil), t.Nodes...)
	for i := range nodes {
		n := &nodes[i]
		if !ends[n.ID] || n.MeshHost != nil || n.Role == model.RoleGateway {
			continue
		}
		n.MeshHost = &model.NodeMeshHost{Addr: addr[n.ID], Iface: model.MeshPendingIface, Pending: true}
	}
	t.Nodes = nodes
	return t
}

// meshPeer: node id runs a Mesh sidecar (it is an end of an enabled cf_mesh
// link). Never the gateway.
func meshPeer(t model.Topology, id string) bool {
	n, ok := t.NodeByID(id)
	if !ok || n.Role == model.RoleGateway {
		return false
	}
	if n.MeshHost != nil {
		// A host-level Mesh node (or a pending one): no sidecar.
		return false
	}
	for _, m := range t.MeshLegs() {
		if m.Hub == id || m.Exit == id {
			return true
		}
	}
	return false
}

// meshSealTimer: the node needs the periodic re-seal unit. A hub re-seals
// from its failover loop every few seconds; an exit has no such loop, and
// its sidecar's WARP device (and so the routes of table 170) may only
// appear some time after boot.
func meshSealTimer(t model.Topology, n model.Node) bool {
	return n.Role == model.RoleExit && meshPeer(t, n.ID)
}

// meshUnderlayAddrs are the Mesh underlay addresses node n's host deals
// with: on a hub the addresses of the exits its Mesh legs dial (sorted,
// unique), on an exit its own.
func meshUnderlayAddrs(n model.Node, tunnels []Tunnel) []string {
	seen := map[string]bool{}
	var out []string
	for _, tun := range meshLegsOn(tunnels, n.ID) {
		if tun.MeshAddr != "" && !seen[tun.MeshAddr] {
			seen[tun.MeshAddr] = true
			out = append(out, tun.MeshAddr)
		}
	}
	sort.Strings(out)
	return out
}

// meshUnderlayShell defines mesh_underlay, shared byte for byte by the
// node's routes script and its meridian-mesh-up.sh (which runs it on every
// exit path, sealed or not), so the static install and every re-seal agree.
//
// On a hub: every exit Mesh address always has a blackhole /32 (metric
// 32767) in the main table, and the live route "via <sidecar> dev mmesh"
// only while mmesh exists and /run/meridian/mesh-sealed is present. A
// route via the sidecar to an address that is no longer a Mesh peer is
// removed. Nothing but these /32 routes is ever installed onto mmesh.
//
// On an exit: its own Mesh address lives on mmesh (the WireGuard listener
// is reached at it from the sidecar), again over a blackhole /32 so a
// packet for the address is dropped, not forwarded, while the veth is away.
func meshUnderlayShell(n model.Node, tunnels []Tunnel) string {
	addrs := meshUnderlayAddrs(n, tunnels)
	if n.MeshHost != nil {
		return meshHostUnderlayShell(n, tunnels, addrs)
	}
	ma := mesh.DefaultAddressing()
	if n.Role == model.RoleExit {
		var sb strings.Builder
		sb.WriteString("mesh_underlay() {\n")
		for _, a := range addrs {
			fmt.Fprintf(&sb, "  ip route replace blackhole %s/32 metric 32767 >/dev/null 2>&1 || true\n", a)
			fmt.Fprintf(&sb, "  if ip link show %s >/dev/null 2>&1; then\n", mesh.HostIface)
			fmt.Fprintf(&sb, "    ip addr replace %s/32 dev %s || echo \"Mesh address %s not set on %s; the Mesh leg stays down\" >&2\n", a, mesh.HostIface, a, mesh.HostIface)
			sb.WriteString("  fi\n")
		}
		sb.WriteString("  return 0\n}\n")
		return sb.String()
	}
	return fmt.Sprintf(`mesh_underlay() {
  local a keep=%[1]s
  for a in $keep; do
    ip route replace blackhole "$a/32" metric 32767 >/dev/null 2>&1 || true
    if ip link show %[2]s >/dev/null 2>&1 && [ -f /run/meridian/mesh-sealed ]; then
      ip route replace "$a/32" via %[3]s dev %[2]s || echo "Mesh underlay route to $a not installed; that Mesh leg stays down" >&2
    else
      ip route del "$a/32" via %[3]s dev %[2]s >/dev/null 2>&1 || true
    fi
  done
  for a in $(ip -4 route show dev %[2]s 2>/dev/null | awk '$2 == "via" { print $1 }'); do
    case " $keep " in
      *" ${a%%/32} "*) ;;
      *) ip route del "$a" via %[3]s dev %[2]s >/dev/null 2>&1 || true ;;
    esac
  done
  return 0
}
`, shQuote(strings.Join(addrs, " ")), mesh.HostIface, ma.NextHopV4())
}

// meshUnderlayGuard is what a hub's meridian-up.sh does before it brings up
// its WireGuard interfaces: the blackhole of every exit Mesh address its
// Mesh legs dial. A leg sends its first handshake as soon as the interface
// is up (PersistentKeepalive); without this the packet would follow the
// host's default route out of its WAN until the routes script ran. "" for a
// node that dials no Mesh leg (an exit only listens on its own).
func meshUnderlayGuard(n model.Node, tunnels []Tunnel) string {
	if n.Role == model.RoleExit {
		// A host-level exit answers the hub at its Mesh address: blackholed
		// before its WireGuard comes up, routed by mesh_underlay.
		if n.MeshHost == nil {
			return ""
		}
		all, _ := meshHostPeers(n, tunnels)
		var sb strings.Builder
		for _, a := range all {
			fmt.Fprintf(&sb, "ip route replace blackhole %s/32 metric 32767\n", a)
		}
		if sb.Len() == 0 {
			return ""
		}
		return "# Mesh legs: outer packets to the hub's Mesh address leave only through this host's\n# Mesh interface. Blackholed before the WireGuard interfaces come up.\n" + sb.String()
	}
	addrs := meshUnderlayAddrs(n, tunnels)
	if len(addrs) == 0 {
		return ""
	}
	var sb strings.Builder
	sb.WriteString("# Mesh legs: their outer packets reach the exits' Mesh addresses through the sealed\n")
	sb.WriteString("# sidecar or not at all. Blackholed before the WireGuard interfaces come up.\n")
	for _, a := range addrs {
		fmt.Fprintf(&sb, "ip route replace blackhole %s/32 metric 32767\n", a)
	}
	return sb.String()
}

// renderMeshUnderlayRoutes is the Mesh part of a node's routes script.
func renderMeshUnderlayRoutes(sb *strings.Builder, n model.Node, tunnels []Tunnel) {
	legs := meshLegsOn(tunnels, n.ID)
	if len(legs) == 0 {
		return
	}
	if n.MeshHost != nil && n.MeshHost.Pending {
		sb.WriteString("# Mesh legs: this host has no Mesh node yet (the panel installs the host-level\n")
		sb.WriteString("# connector). Until it exists and this host is re-provisioned, the legs stay closed.\n")
	} else if n.MeshHost != nil {
		fmt.Fprintf(sb, "# Mesh legs over this host's own Mesh node on %s: no sidecar, no published\n", n.MeshHost.Iface)
		sb.WriteString("# route. Outer packets go only through that interface to the peer's Mesh address.\n")
	} else if n.Role == model.RoleExit {
		sb.WriteString("# Mesh leg: this exit's WireGuard is reached at its Mesh address through the local\n")
		sb.WriteString("# sidecar (mmesh). The address is the one route this exit's Mesh node publishes.\n")
	} else {
		sb.WriteString("# Mesh legs: WireGuard's outer packets reach the exits' Mesh addresses through the\n")
		sb.WriteString("# local sidecar (mmesh), only while it is sealed; otherwise they are blackholed, never\n")
		sb.WriteString("# sent out of this host's WAN. No exit or group table ever points at mmesh.\n")
	}
	for _, tun := range legs {
		fmt.Fprintf(sb, "# mesh leg %s dev %s exit %s address %s port %d\n", tun.LinkID, tun.Iface(), tun.East.ID, tun.MeshAddr, tun.WGPort)
	}
	sb.WriteString(meshUnderlayShell(n, tunnels))
	sb.WriteString("mesh_underlay\n")
	if n.Role == model.RoleExit {
		// What an exit carried while region-group queries were answered on
		// the Mesh veth itself (fwmark 0x4d6d, anchor fd66::4d:1, table 171):
		// nothing uses it any more.
		sb.WriteString("# leftovers of the structure before the Mesh became an underlay\n")
		sb.WriteString("del_rule ip -6 rule del fwmark 0x4d6d lookup 171\n")
		sb.WriteString("del_rule ip -6 rule del to fd66::4d:1/128 lookup 171\n")
		sb.WriteString("ip -6 route flush table 171 >/dev/null 2>&1 || true\n")
	}
}

// meshGroupHopShell is groupHopShell on the hubs of a topology with Mesh
// legs: group_hop refuses the Mesh veth outright. The plain variant (kept byte for byte for
// every topology without a Mesh edge) still carries the hop onto the veth
// that region groups used before the Mesh became an underlay; no compiled
// plan asks for it any more, and on a host that actually has the veth the
// function itself must not be able to do it.
func meshGroupHopShell(base string) string {
	return mustReplace(base, `  if [ "$dev" = "$MESH_DEV" ]; then
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
`, `  if [ "${dev%%|*}" = "$MESH_DEV" ]; then
    # The Mesh veth carries only WireGuard's outer packets to the exits' Mesh
    # addresses (mesh_underlay). It is never the next hop of a table.
    echo "group hop refused on table $table: $MESH_DEV is never a next hop" >&2
    return 1
`)
}

// writeMeshVethNFT closes the host side of the Mesh veth on node n (a hub
// or an exit with Mesh legs): the host never forwards a packet to or from
// mmesh, and takes nothing from it but the WireGuard packets of its Mesh
// legs (on an exit: UDP to its own Mesh address and the legs' ports; on a
// hub: only replies to what its own WireGuard sent), plus ICMP for the
// seal's reachability check. On an exit the legs' WireGuard ports are also
// closed on every other interface: a Mesh leg is reached through the Mesh
// only. One rule per protocol where exits' older nft (0.9.3) needs it.
func writeMeshVethNFT(sb *strings.Builder, n model.Node, tunnels []Tunnel) {
	legs := meshLegsOn(tunnels, n.ID)
	if len(legs) == 0 {
		return
	}
	if n.MeshHost != nil {
		writeMeshHostNFT(sb, n, legs)
		return
	}
	dev := mesh.HostIface
	sb.WriteString("  chain mesh_veth_forward {\n    type filter hook forward priority filter; policy accept;\n")
	fmt.Fprintf(sb, "    iifname \"%s\" drop comment \"nothing from the Mesh sidecar is forwarded by this host\"\n", dev)
	fmt.Fprintf(sb, "    oifname \"%s\" drop comment \"nothing is forwarded into the Mesh sidecar: only this host's WireGuard uses it\"\n", dev)
	sb.WriteString("  }\n")
	sb.WriteString("  chain mesh_veth_input {\n    type filter hook input priority filter; policy accept;\n")
	if n.Role == model.RoleExit {
		ports := meshLegPorts(legs)
		for _, a := range meshUnderlayAddrs(n, tunnels) {
			fmt.Fprintf(sb, "    iifname \"%s\" ip daddr %s udp dport { %s } accept comment \"Mesh legs: WireGuard from the hub, through the Mesh\"\n", dev, a, ports)
		}
		fmt.Fprintf(sb, "    iifname != \"%s\" udp dport { %s } drop comment \"a Mesh leg's WireGuard port is reached through the Mesh sidecar only\"\n", dev, ports)
	}
	fmt.Fprintf(sb, "    iifname \"%s\" ct state established,related accept\n", dev)
	fmt.Fprintf(sb, "    iifname \"%s\" meta l4proto icmp accept\n", dev)
	fmt.Fprintf(sb, "    iifname \"%s\" meta l4proto ipv6-icmp accept\n", dev)
	fmt.Fprintf(sb, "    iifname \"%s\" drop comment \"nothing else enters this host from the Mesh sidecar\"\n", dev)
	sb.WriteString("  }\n")
}

// meshLegPorts are the listening ports of legs as an nft set body.
func meshLegPorts(legs []Tunnel) string {
	seen := map[int]bool{}
	var ports []int
	for _, tun := range legs {
		if !seen[tun.WGPort] {
			seen[tun.WGPort] = true
			ports = append(ports, tun.WGPort)
		}
	}
	sort.Ints(ports)
	parts := make([]string, len(ports))
	for i, p := range ports {
		parts[i] = fmt.Sprint(p)
	}
	return strings.Join(parts, ", ")
}

// renderMeshUp is meridian-mesh-up.sh for node n: it attaches the veth to
// the node's one Mesh sidecar and seals it for the node's Mesh legs. The
// veth is an Ethernet device, so both ends get fixed MACs, IPv4 and IPv6
// link addresses and permanent neighbour entries for each other (see
// mesh.Addressing). The seal file is only written after both next-hops
// answered a ping, and mesh_underlay runs on every way out of the script.
//
// An exit's script names the one route its Mesh node publishes on a
// "meridian-mesh-publish" line: its Mesh underlay address as a /32. The
// panel's Mesh deployment publishes exactly that (mesh.BuildPlan compares
// the line with the topology's allocation).
func renderMeshUp(t model.Topology, n model.Node, tunnels []Tunnel) string {
	a := mesh.DefaultAddressing()
	ret4, ret6 := mesh.ReturnPrefixes(t)
	legs := meshLegsOn(tunnels, n.ID)
	exit := n.Role == model.RoleExit

	var head strings.Builder
	var routes, nsRoutes, fwd, nat strings.Builder
	keep := []string{}
	if exit {
		head.WriteString("# The one route this exit's Mesh node publishes (the panel's Mesh deployment\n")
		head.WriteString("# publishes it as a Cloudflare route of this node; nothing else, never a default):\n")
		for _, addr := range meshUnderlayAddrs(n, tunnels) {
			var ids []string
			for _, tun := range legs {
				if tun.MeshAddr == addr {
					ids = append(ids, tun.LinkID)
				}
			}
			fmt.Fprintf(&head, "%s %s/32 leg=%s\n", mesh.PublishMarker, addr, strings.Join(ids, ","))
			// Delivered to the host's WireGuard listener; replies leave to
			// the hub's Mesh address, which is somewhere in the Mesh range.
			fmt.Fprintf(&nsRoutes, "ip route replace %s/32 via %s dev %s\n", addr, a.HostV4, mesh.SidecarIface)
			fmt.Fprintf(&fwd, "    iifname \"$warp\" oifname \"%s\" ip daddr %s udp dport { %s } accept\n", mesh.SidecarIface, addr, meshLegPorts(legs))
			fmt.Fprintf(&fwd, "    iifname \"%s\" oifname \"$warp\" ip saddr %s udp sport { %s } ct state established accept\n", mesh.SidecarIface, addr, meshLegPorts(legs))
		}
		fmt.Fprintf(&routes, "  ip route replace %s dev \"$warp\" table %d\n", mesh.MeshIPRange, mesh.SidecarTable)
		keep = append(keep, mesh.MeshIPRange.String())
		fmt.Fprintf(&nat, "    iifname \"$warp\" oifname \"%s\" masquerade\n", mesh.SidecarIface)
	} else {
		head.WriteString("# Mesh legs of this hub (WireGuard to each exit's Mesh address, through this sidecar):\n")
		for _, tun := range legs {
			fmt.Fprintf(&head, "# meridian-mesh-peer %s port=%d leg=%s exit=%s\n", tun.MeshAddr, tun.WGPort, tun.LinkID, tun.East.ID)
			fmt.Fprintf(&routes, "  ip route replace %s/32 dev \"$warp\" table %d\n", tun.MeshAddr, mesh.SidecarTable)
			keep = append(keep, tun.MeshAddr)
			fmt.Fprintf(&fwd, "    iifname \"%s\" oifname \"$warp\" ip daddr %s udp dport %d accept\n", mesh.SidecarIface, tun.MeshAddr, tun.WGPort)
		}
		fmt.Fprintf(&fwd, "    iifname \"$warp\" oifname \"%s\" ct state established,related accept\n", mesh.SidecarIface)
		fmt.Fprintf(&nat, "    iifname \"%s\" oifname \"$warp\" masquerade\n", mesh.SidecarIface)
	}
	role, tableDesc := "this hub's WireGuard legs to its exits' Mesh addresses", "the routes to the exits' Mesh addresses on the WARP device"
	if exit {
		role, tableDesc = "the hub's WireGuard leg to this exit's Mesh address", "the Mesh address range on the WARP device (replies to the hub)"
	}
	return strings.NewReplacer(
		"@HEAD@\n", head.String(),
		"@GWLAN@", lanHost(t),
		"@UNDERLAY@\n", meshUnderlayShell(n, tunnels),
		"@ROLE@", role,
		"@TABLEDESC@", tableDesc,
		"@SEALROUTES@\n", routes.String(),
		"@KEEP@", shQuote(strings.Join(keep, " ")),
		"@NSROUTES@\n", nsRoutes.String(),
		"@FWD@\n", fwd.String(),
		"@NAT@\n", nat.String(),
		"@HOST4@", a.HostV4CIDR(),
		"@SIDE4@", a.SidecarV4CIDR(),
		"@NH4@", a.NextHopV4(),
		"@HOSTIP4@", a.HostV4.String(),
		"@HOST6@", a.HostV6CIDR(),
		"@SIDE6@", a.SidecarV6CIDR(),
		"@NH6@", a.NextHopV6(),
		"@HOSTIP6@", a.HostV6.String(),
		"@HOSTMAC@", a.HostMAC,
		"@SIDEMAC@", a.SidecarMAC,
		"@TABLE@", fmt.Sprint(mesh.SidecarTable),
		"@RET4@", strings.Join(ret4, " "),
		"@RET6@", strings.Join(ret6, " "),
	).Replace(meshUpBody)
}

// 169.254.66.0/30 and fe80::66:1/2 exist on the veth only. The IPv4 link is
// outside 10.66.0.0/16 (tunnel aggregate, routed west) and outside the LAN,
// so a missing connected route cannot send this hop toward the relay or the home router.
const meshUpBody = `#!/bin/bash
# Attach a veth to this host's one Mesh sidecar and seal it.
#
# The Mesh carries one thing for Meridian: the outer UDP packets of
# @ROLE@.
# Client traffic never enters the sidecar unencrypted and never leaves through
# Cloudflare: it is decapsulated on the exit and leaves from the exit's own
# uplink. No exit table, group table or default route points at mmesh.
#
# The seal: what this host injects on mmesh is looked up in table @TABLE@ of the
# sidecar netns only (priority 17000). That table holds
# @TABLEDESC@
# over an unreachable default; never the container's default route (the docker
# bridge, which NATs onto this machine's WAN). The sidecar's forward chain
# (table inet meridian_mesh) passes nothing but the Mesh legs' WireGuard UDP
# between mmesh-c and the WARP device and drops everything else on mmesh-c, in
# both directions. It never installs a route in table 100, 102, 150, or main
# of this host.
#
# mmesh is an Ethernet veth, not a point-to-point tunnel. Routes onto it
# must name a next-hop: via @NH4@ dev mmesh (IPv6: @NH6@ dev mmesh).
# Both ends have fixed MACs and permanent neighbour entries, so no ARP/ND
# is sent for other destinations and no proxy ARP/ND is needed.
# The seal (/run/meridian/mesh-sealed) is only written when both next-hops
# answer from the host.
# This script refuses to run on the home gateway (@GWLAN@).
@HEAD@
set -u
# The host side of the underlay follows the seal on every exit path of this
# script (the same function the routes script installs it with).
@UNDERLAY@
trap mesh_underlay EXIT
seal_only=0
if [ "${1:-}" = "--seal-only" ]; then
  seal_only=1
fi
unseal() {
  rm -f /run/meridian/mesh-sealed
}
if ip -4 addr show 2>/dev/null | grep -q 'inet @GWLAN@/'; then
  echo "refusing to start mesh on the home gateway" >&2
  unseal
  exit 0
fi
if [ ! -s /etc/meridian/mesh.env ]; then
  echo "mesh sidecar skipped: /etc/meridian/mesh.env is missing" >&2
  unseal
  exit 0
fi
if ! grep -q '^MESH_NODE_TOKEN=.\+' /etc/meridian/mesh.env; then
  echo "mesh sidecar skipped: MESH_NODE_TOKEN is empty" >&2
  unseal
  exit 0
fi
compose=/etc/meridian/mesh-sidecar.compose.yml
if [ ! -f "$compose" ]; then
  echo "mesh compose missing" >&2
  unseal
  exit 0
fi
if ! command -v docker >/dev/null 2>&1; then
  echo "docker is not installed; mesh sidecar not started" >&2
  unseal
  exit 0
fi
if [ "$seal_only" -eq 0 ]; then
  docker compose -f "$compose" up -d || {
    echo "mesh sidecar failed to start" >&2
    unseal
    exit 0
  }
fi
cid=$(docker compose -f "$compose" ps -q mesh 2>/dev/null || true)
pid=$(docker inspect -f '{{.State.Pid}}' "$cid" 2>/dev/null || true)
if [ -z "$pid" ] || [ "$pid" = "0" ]; then
  echo "mesh sidecar is not running" >&2
  unseal
  exit 0
fi
if ip link show mmesh >/dev/null 2>&1; then
  if ! nsenter -t "$pid" -n ip link show mmesh-c >/dev/null 2>&1; then
    ip link del mmesh >/dev/null 2>&1 || true
  fi
fi
if ! ip link show mmesh >/dev/null 2>&1; then
  ip link add mmesh address @HOSTMAC@ type veth peer name mmesh-c address @SIDEMAC@ || {
    echo "mesh veth failed" >&2
    unseal
    exit 0
  }
fi
ip link set mmesh address @HOSTMAC@ || true
ip link set mmesh addrgenmode none >/dev/null 2>&1 || true
sysctl -qw net.ipv6.conf.mmesh.disable_ipv6=0 >/dev/null 2>&1 || true
sysctl -qw net.ipv6.conf.mmesh.accept_ra=0 >/dev/null 2>&1 || true
ip link set mmesh up || true
ip addr replace @HOST4@ dev mmesh || true
ip -6 addr replace @HOST6@ dev mmesh nodad || true
if ip link show mmesh-c >/dev/null 2>&1; then
  ip link set mmesh-c netns "$pid" || true
fi
# rp_filter lives in the container's netns. Loose mode matches the host.
for key in net.ipv4.conf.all.rp_filter net.ipv4.conf.default.rp_filter net.ipv4.conf.mmesh-c.rp_filter; do
  path="/proc/$pid/root/proc/sys/${key//./\/}"
  if [ -e "$path" ]; then
    echo 2 > "$path" || true
  fi
done
# The seal block below must succeed as a whole (set -eu) before the host
# writes the seal; any failure inside the sidecar netns leaves it unsealed.
if nsenter -t "$pid" -n bash -s <<'EOS'
set -eu
command -v nft >/dev/null 2>&1 || { echo "nft is missing: the sidecar cannot be sealed" >&2; exit 1; }
ip link set mmesh-c address @SIDEMAC@
ip link set mmesh-c addrgenmode none >/dev/null 2>&1 || true
# Seal before the link comes up: table @TABLE@, its rule and the forward chain.
# A re-seal changes nothing that is already right (no flush, no rule gap).
ip route replace unreachable default metric 32767 table @TABLE@
ip -6 route replace unreachable default metric 32767 table @TABLE@
ip rule show | grep -q 'iif mmesh-c lookup @TABLE@' || ip rule add iif mmesh-c lookup @TABLE@ priority 17000
ip -6 rule show | grep -q 'iif mmesh-c lookup @TABLE@' || ip -6 rule add iif mmesh-c lookup @TABLE@ priority 17000
warp=""
for d in $(ip -o link show | awk -F': ' '{print $2}' | cut -d@ -f1); do
  case "$d" in
    lo|eth*|mmesh-c|docker*|br-*|veth*) continue ;;
  esac
  if ip -d link show "$d" 2>/dev/null | grep -q 'link/none'; then
    warp=$d
    break
  fi
done
keep=@KEEP@
if [ -n "$warp" ]; then
@SEALROUTES@
  :
else
  keep=""
fi
# Table @TABLE@ holds nothing else: drop every other route (what an earlier
# version copied from the WARP device, a peer that is gone).
ip route show table @TABLE@ 2>/dev/null | while read -r dst rest; do
  case "$dst" in unreachable|"") continue ;; esac
  case " $keep " in *" $dst "*) continue ;; esac
  ip route del "$dst" table @TABLE@ 2>/dev/null || true
done
ip -6 route show table @TABLE@ 2>/dev/null | while read -r dst rest; do
  case "$dst" in unreachable|"") continue ;; esac
  ip -6 route del "$dst" table @TABLE@ 2>/dev/null || true
done
# One nft transaction: create-if-missing, delete, recreate. Either the
# whole batch commits or the previous table stays.
if [ -n "$warp" ]; then
  nft -f - <<NFT
table inet meridian_mesh
delete table inet meridian_mesh
table inet meridian_mesh {
  chain forward {
    type filter hook forward priority filter; policy accept;
@FWD@
    iifname "mmesh-c" drop
    oifname "mmesh-c" drop
  }
  chain postrouting {
    type nat hook postrouting priority srcnat; policy accept;
@NAT@
  }
}
NFT
else
  # No WARP device yet: nothing passes at all.
  nft -f - <<NFT
table inet meridian_mesh
delete table inet meridian_mesh
table inet meridian_mesh {
  chain forward {
    type filter hook forward priority filter; policy accept;
    iifname "mmesh-c" drop
    oifname "mmesh-c" drop
  }
}
NFT
fi
ip link set mmesh-c up
ip addr replace @SIDE4@ dev mmesh-c
ip -6 addr replace @SIDE6@ dev mmesh-c nodad
ip neigh replace @HOSTIP4@ lladdr @HOSTMAC@ dev mmesh-c nud permanent
ip -6 neigh replace @HOSTIP6@ lladdr @HOSTMAC@ dev mmesh-c nud permanent
# Earlier versions sent Meridian's own prefixes back through the veth; no
# Meridian prefix is routed through the sidecar any more.
for p in @RET4@; do
  ip route del "$p" via @HOSTIP4@ dev mmesh-c 2>/dev/null || true
done
for p in @RET6@; do
  ip -6 route del "$p" via @HOSTIP6@ dev mmesh-c 2>/dev/null || true
done
@NSROUTES@
EOS
then
  ip neigh replace @NH4@ lladdr @SIDEMAC@ dev mmesh nud permanent || true
  ip -6 neigh replace @NH6@ lladdr @SIDEMAC@ dev mmesh nud permanent || true
  if ping -c 1 -W 2 -n -I mmesh @NH4@ >/dev/null 2>&1 && ping -6 -c 1 -W 2 -n @NH6@%mmesh >/dev/null 2>&1; then
    mkdir -p /run/meridian
    : > /run/meridian/mesh-sealed
    echo "mesh sidecar sealed; next-hops @NH4@ and @NH6@%mmesh answer; only the Mesh legs' WireGuard packets pass"
  else
    echo "mesh next-hop @NH4@ or @NH6@%mmesh does not answer; the Mesh legs stay down" >&2
    unseal
  fi
else
  echo "mesh seal failed; the Mesh legs stay down" >&2
  unseal
fi
exit 0
`

// Reused host-level Mesh nodes (model.Node.MeshHost; docs/architecture.md
// 「沿用主机上已有的 Mesh 节点」). The host's WARP client owns its interface,
// address and policy routing; Meridian adds only what keeps its own outer
// packets on that interface:
//
//   - on a hub, every peer Mesh address keeps its blackhole /32 (metric
//     32767) and gets "dev <iface>" only while the interface is up, so the
//     outer packets never follow the host's default route;
//   - an nft output rule drops the Mesh legs' WireGuard UDP to a peer Mesh
//     address on any other interface (route conflict or a WARP table that
//     hands the address elsewhere);
//   - on an exit, the legs' WireGuard ports are accepted only from that
//     interface to the node's own Mesh address, and the hub's Mesh address
//     gets the same blackhole / "dev <iface>" pair and output drop as on a
//     hub (keyed on the leg's listen port as UDP source), refreshed by
//     meridian-mesh-underlay.timer since an exit has no failover loop.
//
// Nothing is forwarded into or out of the interface by these rules, and the
// WARP client's own settings and rules are never touched.

// meshLegLive: both ends of a Mesh leg are host-level nodes with real Mesh
// addresses (neither is pending).
func meshLegLive(tun Tunnel) bool {
	for _, n := range []model.Node{tun.West, tun.East} {
		if n.MeshHost == nil || n.MeshHost.Pending {
			return false
		}
	}
	return true
}

// meshHostPeers are the peer Mesh addresses a host-level node's outer
// packets go to (sorted, unique): on a hub the exits' addresses its legs
// dial, on an exit the hubs' addresses its legs answer (a hub still
// waiting for its Mesh node has none yet). live lists those of legs whose
// ends both are real Mesh nodes.
func meshHostPeers(n model.Node, tunnels []Tunnel) (all, live []string) {
	seen, seenLive := map[string]bool{}, map[string]bool{}
	for _, tun := range meshLegsOn(tunnels, n.ID) {
		a := tun.MeshAddr
		if n.Role == model.RoleExit {
			a = ""
			if tun.West.MeshHost != nil {
				a = tun.West.MeshHost.Addr
			}
		}
		if a == "" {
			continue
		}
		if !seen[a] {
			seen[a] = true
			all = append(all, a)
		}
		if meshLegLive(tun) && !seenLive[a] {
			seenLive[a] = true
			live = append(live, a)
		}
	}
	sort.Strings(all)
	sort.Strings(live)
	return all, live
}

// meshHostUnderlayShell is mesh_underlay for a host-level Mesh node, hub or
// exit alike. Only live legs' peer addresses ever get a route onto the WARP
// interface, and only while it is up; every peer address keeps its
// blackhole, so an exit's handshakes, keepalives and replies to the hub's
// Mesh address never leave by the host's default route either.
func meshHostUnderlayShell(n model.Node, tunnels []Tunnel, addrs []string) string {
	all, live := meshHostPeers(n, tunnels)
	if n.Role != model.RoleExit {
		all = addrs
	} else if len(all) == 0 {
		return "mesh_underlay() {\n  # this exit's Mesh address belongs to its host-level WARP client\n  return 0\n}\n"
	}
	return fmt.Sprintf(`mesh_underlay() {
  local a keep=%[1]s live=%[3]s
  for a in $keep; do
    ip route replace blackhole "$a/32" metric 32767 >/dev/null 2>&1 || true
    case " $live " in
      *" $a "*) up=1 ;;
      *) up=0 ;;
    esac
    if [ "$up" = 1 ] && [ -n "$(ip link show %[2]s up 2>/dev/null)" ]; then
      ip route replace "$a/32" dev %[2]s || echo "Mesh underlay route to $a not installed; that Mesh leg stays down" >&2
    else
      ip route del "$a/32" dev %[2]s >/dev/null 2>&1 || true
    fi
  done
  return 0
}
`, shQuote(strings.Join(all, " ")), shQuote(n.MeshHost.Iface), shQuote(strings.Join(live, " ")))
}

// meshHostExitRefresh: an exit that is (or waits to be) a host-level Mesh
// node with Mesh legs. It has no failover loop, so a timer re-runs
// mesh_underlay (meridian-mesh-underlay.sh) the way the hub's loop does.
func meshHostExitRefresh(n model.Node, tunnels []Tunnel) bool {
	if n.Role != model.RoleExit || n.MeshHost == nil {
		return false
	}
	all, _ := meshHostPeers(n, tunnels)
	return len(all) > 0
}

// renderMeshUnderlayScript is the exit's periodic mesh_underlay.
func renderMeshUnderlayScript(n model.Node, tunnels []Tunnel) string {
	return "#!/bin/bash\n# Meridian: keep this exit's outer WireGuard packets to the hub's Mesh address on\n# the host's Mesh interface or blackholed (meridian-mesh-underlay.timer).\nset -u\n" +
		meshUnderlayShell(n, tunnels) + "mesh_underlay\n"
}

func renderMeshUnderlayService() string {
	return `[Unit]
Description=Meridian Mesh underlay routes of this exit (follow the host Mesh interface)
After=network-online.target

[Service]
Type=oneshot
StandardInput=null
ExecStart=/bin/sh -c 'if [ -x /usr/local/sbin/meridian-mesh-underlay.sh ]; then exec /usr/local/sbin/meridian-mesh-underlay.sh; fi'
`
}

func renderMeshUnderlayTimer() string {
	return `# Follow the host Mesh interface every 10 seconds: the route to the hub's Mesh
# address exists only while the interface is up; the blackhole stays.
[Unit]
Description=Meridian Mesh underlay refresh every 10 seconds

[Timer]
OnBootSec=10
OnUnitActiveSec=10
AccuracySec=2

[Install]
WantedBy=timers.target
`
}

// writeMeshHostNFT seals the Mesh legs of a host-level node: outer packets
// only through the WARP interface to the peer's Mesh address; a leg with a
// pending end is closed outright.
func writeMeshHostNFT(sb *strings.Builder, n model.Node, legs []Tunnel) {
	dev := n.MeshHost.Iface
	if n.Role == model.RoleExit {
		ports := meshLegPorts(legs)
		sb.WriteString("  chain mesh_host_input {\n    type filter hook input priority filter; policy accept;\n")
		if n.MeshHost.Pending {
			fmt.Fprintf(sb, "    udp dport { %s } drop comment \"no Mesh node on this host yet: the Mesh leg stays closed\"\n", ports)
		} else {
			fmt.Fprintf(sb, "    iifname \"%s\" ip daddr %s udp dport { %s } accept comment \"Mesh legs: WireGuard from the hub, through this host's Mesh node\"\n", dev, n.MeshHost.Addr, ports)
			fmt.Fprintf(sb, "    iifname != \"%s\" udp dport { %s } drop comment \"a Mesh leg's WireGuard port is reached through the Mesh only\"\n", dev, ports)
		}
		sb.WriteString("  }\n")
		var out strings.Builder
		for _, tun := range legs {
			if tun.West.MeshHost == nil || tun.West.MeshHost.Addr == "" {
				continue
			}
			hub := tun.West.MeshHost.Addr
			if !meshLegLive(tun) {
				fmt.Fprintf(&out, "    ip daddr %s udp sport %d drop comment \"Mesh leg %s: an end has no Mesh node yet\"\n", hub, tun.WGPort, tun.LinkID)
				continue
			}
			fmt.Fprintf(&out, "    oifname != \"%s\" ip daddr %s udp sport %d drop comment \"Mesh leg %s: outer packets to the hub only through the Mesh interface\"\n", dev, hub, tun.WGPort, tun.LinkID)
		}
		if out.Len() > 0 {
			sb.WriteString("  chain mesh_host_output {\n    type filter hook output priority filter; policy accept;\n")
			sb.WriteString(out.String())
			sb.WriteString("  }\n")
		}
		return
	}
	sb.WriteString("  chain mesh_host_output {\n    type filter hook output priority filter; policy accept;\n")
	for _, tun := range legs {
		if !meshLegLive(tun) {
			fmt.Fprintf(sb, "    ip daddr %s udp dport %d drop comment \"Mesh leg %s: an end has no Mesh node yet\"\n", tun.MeshAddr, tun.WGPort, tun.LinkID)
			continue
		}
		fmt.Fprintf(sb, "    oifname != \"%s\" ip daddr %s udp dport %d drop comment \"Mesh leg %s: outer packets only through the Mesh interface\"\n", dev, tun.MeshAddr, tun.WGPort, tun.LinkID)
	}
	sb.WriteString("  }\n")
}
