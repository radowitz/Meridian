package compile

import (
	"fmt"
	"net/netip"
	"strings"

	"github.com/radowitz/meridian/internal/artifacts"
	"github.com/radowitz/meridian/internal/model"
	"github.com/radowitz/meridian/internal/validate"
)

// Hub side of nested and external exits (docs/architecture.md「挂在中继出口后面
// 的出口」「外部 SOCKS 出口」).
//
// A nested exit is reached through the hub's tunnel to its relay exit, an
// external exit through the hub's tunnel to its carrier: the same device as
// another exit's. The exit's own mark needs nothing new (its transit source
// tells the relay exit or the carrier what to do). A region group pointed at
// such a member is told apart by next hop: group_hop installs
// "default via <PeerV4> dev <iface> onlink" (and the ULA for IPv6) — the
// next hop never leaves the hub, WireGuard routes by destination — and the
// hub's nested_snat chain rewrites the group's transit source to the
// member's own transit address for exactly that device and next hop. A
// group pointed at the relay exit or the carrier itself keeps the plain
// device route and its transit source, so it leaves through their WAN as
// before. Topologies without such a member render byte for byte what they
// did before: the shell variants below are only used when a dynamic group
// has one.

// hopDev is the group_hop argument for a member: its hub interface, or for
// a member behind another exit's tunnel "iface|PeerV4|PeerULA" (canonical
// addresses: the report compares them with what ip prints).
func hopDev(e ExitPlan) string {
	if !e.sharedHop() {
		return e.HubIface
	}
	return e.HubIface + "|" + canonAddr(e.PeerV4) + "|" + canonAddr(e.PeerULA)
}

func canonAddr(s string) string {
	if a, err := netip.ParseAddr(strings.TrimSpace(s)); err == nil {
		return a.String()
	}
	return s
}

// sharedHops reports whether some dynamic group can switch to a member
// behind another exit's tunnel.
func sharedHops(groups []GroupPlan) bool {
	for _, g := range groups {
		if !g.Dynamic {
			continue
		}
		for _, e := range g.Try {
			if e.sharedHop() {
				return true
			}
		}
		if g.Target.sharedHop() {
			return true
		}
	}
	return false
}

func mustReplace(s, old, repl string) string {
	if !strings.Contains(s, old) {
		panic("compile: shell variant anchor not found: " + old)
	}
	return strings.Replace(s, old, repl, 1)
}

// hopShell is groupHopShell, or with shared hops the variant that accepts
// "iface|nh4|nh6" and installs the next-hop form.
func hopShell(shared bool) string {
	if !shared {
		return groupHopShell
	}
	s := mustReplace(groupHopShell, `  [ -n "$dev" ] || return 1
`, `  [ -n "$dev" ] || return 1
  local nh4="" nh6=""
  case "$dev" in
    *"|"*) nh4="${dev#*|}"; nh6="${nh4#*|}"; nh4="${nh4%%|*}"; dev="${dev%%|*}" ;;
  esac
`)
	s = mustReplace(s, `  else
    ip route replace default dev "$dev" table "$table"
    ip -6 route replace default dev "$dev" table "$table"
  fi
`, `  elif [ -n "$nh4" ] && [ -n "$nh6" ]; then
    # A member behind another exit's tunnel (nested or external exit): the
    # same device, told apart by next hop; the hub's nested_snat chain gives
    # the group's packets that member's own transit source.
    ip route replace default via "$nh4" dev "$dev" onlink table "$table"
    ip -6 route replace default via "$nh6" dev "$dev" onlink table "$table"
  else
    ip route replace default dev "$dev" table "$table"
    ip -6 route replace default dev "$dev" table "$table"
  fi
`)
	return s
}

// stepShell is groupStepShell; with shared hops the health probe uses the
// device part of the hop.
func stepShell(shared bool) string {
	if !shared {
		return groupStepShell
	}
	return mustReplace(groupStepShell, `    if alive "$iface" "$peer"; then`, `    if alive "${iface%%|*}" "$peer"; then`)
}

// reportShell is groupReportShell; with shared hops a next-hop default is
// reported as "dev:<iface>@<nh4>@<nh6>" and matched against the members'
// hops, so the report names the nested member, not the relay exit.
func reportShell(shared bool) string {
	if !shared {
		return groupReportShell
	}
	s := mustReplace(groupReportShell, `  local fam="$1" table="$2" out line floor=0 i
`, `  local fam="$1" table="$2" out line floor=0 i via
`)
	s = mustReplace(s, `    if [ "${w[0]}" = default ]; then
      for ((i=1; i<${#w[@]}-1; i++)); do
        if [ "${w[$i]}" = dev ]; then echo "dev:${w[$((i+1))]}"; return 0; fi
      done
`, `    if [ "${w[0]}" = default ]; then
      via=""
      for ((i=1; i<${#w[@]}-1; i++)); do
        if [ "${w[$i]}" = via ]; then via="${w[$((i+1))]}"; fi
      done
      for ((i=1; i<${#w[@]}-1; i++)); do
        if [ "${w[$i]}" = dev ]; then
          if [ -n "$via" ]; then echo "dev:${w[$((i+1))]}@$via"; else echo "dev:${w[$((i+1))]}"; fi
          return 0
        fi
      done
`)
	s = mustReplace(s, `  if [ "$a" = "$b" ]; then echo "$a"; else echo split; fi
`, `  case "$a|$b" in
    dev:*@*"|"dev:*@*)
      if [ "${a%%@*}" = "${b%%@*}" ]; then echo "$a@${b#*@}"; return 0; fi
      ;;
  esac
  if [ "$a" = "$b" ]; then echo "$a"; else echo split; fi
`)
	s = mustReplace(s, `  local tbl hop p result=ok`, `  local tbl hop p h result=ok`)
	s = mustReplace(s, `        if [ "dev:${p#*=}" = "$tbl" ]; then hop="${p%%=*}"; break; fi
`, `        h="${p#*=}"
        if [ "dev:${h//|/@}" = "$tbl" ]; then hop="${p%%=*}"; break; fi
`)
	return s
}

// writeHubNestedSNAT renders the hub's nested_snat chain: for every dynamic
// group and every member of its switch order behind another exit's tunnel,
// the group's transit source becomes the member's own transit source when
// the packet leaves on that tunnel with that member's next hop. Nothing is
// rendered without such a member.
func writeHubNestedSNAT(sb *strings.Builder, groups []GroupPlan) {
	type rule struct {
		g GroupPlan
		e ExitPlan
	}
	var rules []rule
	seen := map[string]bool{}
	for _, g := range groups {
		if !g.Dynamic {
			continue
		}
		members := append([]ExitPlan{g.Target}, g.Try...)
		for _, e := range members {
			if !e.sharedHop() || e.HubIface == "" || e.PeerV4 == "" || e.PeerULA == "" {
				continue
			}
			k := g.Group.ID + "/" + e.Node.ID
			if seen[k] {
				continue
			}
			seen[k] = true
			rules = append(rules, rule{g, e})
		}
	}
	if len(rules) == 0 {
		return
	}
	sb.WriteString("  chain nested_snat {\n    type nat hook postrouting priority srcnat; policy accept;\n")
	for _, r := range rules {
		kind := "nested exit behind " + r.e.Nested
		if r.e.External {
			kind = "external exit on carrier " + model.HubSideOf(r.e.Node)
		}
		fmt.Fprintf(sb, "    oifname \"%s\" ip saddr %s rt ip nexthop %s snat ip to %s comment \"group %s on %s (%s)\"\n",
			r.e.HubIface, r.g.TransitV4, canonAddr(r.e.PeerV4), r.e.TransitV4, verifyLabel(r.g.Group.ID), verifyLabel(r.e.Node.ID), kind)
		fmt.Fprintf(sb, "    oifname \"%s\" ip6 saddr %s rt ip6 nexthop %s snat ip6 to %s\n",
			r.e.HubIface, r.g.TransitV6, canonAddr(r.e.PeerULA), r.e.TransitV6)
	}
	sb.WriteString("  }\n")
}

// ---------------------------------------------------------------------------
// Relay exit and nested exit.

// nestedPlans are the exit plans of the nested exits behind relay exit id.
func nestedPlans(exits []ExitPlan, id string) []ExitPlan {
	var out []ExitPlan
	for _, e := range exits {
		if e.Nested == id && id != "" {
			out = append(out, e)
		}
	}
	return out
}

// externalPlans are the exit plans of the external exits carried by id.
func externalPlans(exits []ExitPlan, id string) []ExitPlan {
	var out []ExitPlan
	for _, e := range exits {
		if e.External && model.HubSideOf(e.Node) == id && id != "" {
			out = append(out, e)
		}
	}
	return out
}

// renderRelayExitRoutes: on a relay exit, each nested exit's transit
// sources select a table whose only route is the tunnel to that exit, over
// a blackhole: its traffic can never leave through this host's WAN. With a
// backup hub the nested exit's hub-independent resolver address is routed
// into the same tunnel (the nested exit answers it itself). Replies coming
// back from the nested exit follow this host's ordinary return path toward
// home, and with a backup hub the connection mark of the hub tunnel the
// connection arrived on (hub_return_in), so they leave through the hub they
// came from.
func renderRelayExitRoutes(sb *strings.Builder, t model.Topology, n model.Node, tunnels []Tunnel, exits []ExitPlan) {
	nested := nestedPlans(exits, n.ID)
	if len(nested) == 0 {
		return
	}
	sb.WriteString("# relay exit: exits behind this node, selected by their transit source; never this host's WAN\n")
	for _, e := range nested {
		down := nestedTunnel(e.Node, tunnels)
		if down.Iface() == "" {
			fmt.Fprintf(sb, "# nested exit %s has no tunnel to this node: its table stays blackholed\n", e.Node.ID)
		}
		fmt.Fprintf(sb, "# nested exit %s mark %#x transit %s table %d dev %s\n", e.Node.ID, e.Mark, e.TransitV4, e.Table, ifaceOr(down.Iface()))
		sb.WriteString(fmt.Sprintf("ip route replace blackhole default metric 32767 table %d\n", e.Table))
		sb.WriteString(fmt.Sprintf("ip -6 route replace blackhole default metric 32767 table %d\n", e.Table))
		if down.Iface() != "" {
			fmt.Fprintf(sb, "ip route replace default dev %s table %d\n", down.Iface(), e.Table)
			fmt.Fprintf(sb, "ip -6 route replace default dev %s table %d\n", down.Iface(), e.Table)
			if t.DualHub() {
				fmt.Fprintf(sb, "ip -6 route replace %s/128 dev %s\n", e.Resolver, down.Iface())
				fmt.Fprintf(sb, "ip -6 route replace blackhole %s/128 metric 32767\n", e.Resolver)
			}
		}
		fmt.Fprintf(sb, "del_rule ip rule del from %s/32 lookup %d\n", e.TransitV4, e.Table)
		fmt.Fprintf(sb, "ip rule add from %s/32 lookup %d priority %d\n", e.TransitV4, e.Table, prioHubExitFrom+e.Index)
		fmt.Fprintf(sb, "del_rule ip -6 rule del from %s/128 lookup %d\n", e.TransitV6, e.Table)
		fmt.Fprintf(sb, "ip -6 rule add from %s/128 lookup %d priority %d\n", e.TransitV6, e.Table, prioHubExitFrom+e.Index)
	}
}

func ifaceOr(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

// writeRelayExitNFT: on a relay exit, a nested exit's transit sources may
// only leave into that exit's tunnel (dropped anywhere else, the WAN
// included), whatever the routing tables say.
func writeRelayExitNFT(sb *strings.Builder, n model.Node, tunnels []Tunnel, exits []ExitPlan) {
	nested := nestedPlans(exits, n.ID)
	if len(nested) == 0 {
		return
	}
	sb.WriteString("  chain nested_guard {\n    type filter hook forward priority filter; policy accept;\n")
	for _, e := range nested {
		dev := nestedTunnel(e.Node, tunnels).Iface()
		if dev == "" {
			fmt.Fprintf(sb, "    ip saddr %s counter drop comment \"nested exit %s has no tunnel here\"\n", e.TransitV4, verifyLabel(e.Node.ID))
			fmt.Fprintf(sb, "    ip6 saddr %s counter drop\n", e.TransitV6)
			continue
		}
		fmt.Fprintf(sb, "    ip saddr %s oifname != \"%s\" counter drop comment \"nested exit %s: only into its tunnel, never this host's WAN\"\n", e.TransitV4, dev, verifyLabel(e.Node.ID))
		fmt.Fprintf(sb, "    ip6 saddr %s oifname != \"%s\" counter drop\n", e.TransitV6, dev)
	}
	sb.WriteString("  }\n")
}

// behindSources are the IPv6 transit sources of the exits reached through
// node id (nested exits of a relay exit, external exits of a carrier):
// group-resolver queries from them are theirs, never answered by id.
func behindSources(exits []ExitPlan, id string) []string {
	var out []string
	for _, e := range exits {
		if (e.Nested == id || e.External && model.HubSideOf(e.Node) == id) && id != "" {
			out = append(out, e.TransitV6)
		}
	}
	return out
}

// writeNestedExitResolverDNAT: with a backup hub, a nested exit answers its
// hub-independent resolver address on its tunnel from the relay exit (both
// hubs route it there through the relay exit).
func writeNestedExitResolverDNAT(sb *strings.Builder, t model.Topology, n model.Node, tunnels []Tunnel, exits []ExitPlan) {
	if !t.DualHub() || !model.IsNested(n) {
		return
	}
	e, ok := exitByID(exits, n.ID)
	tun := nestedTunnel(n, tunnels)
	if !ok || e.DNSULA == "" || tun.Iface() == "" {
		return
	}
	sb.WriteString("  chain exit_dns {\n    type nat hook prerouting priority dstnat; policy accept;\n")
	for _, proto := range []string{"udp", "tcp"} {
		fmt.Fprintf(sb, "    iifname \"%s\" ip6 daddr %s %s dport 53 dnat ip6 to %s comment \"this exit's resolver address, from either hub through relay exit %s\"\n", tun.Iface(), e.Resolver, proto, e.DNSULA, verifyLabel(n.ViaExit))
	}
	sb.WriteString("  }\n")
}

// ---------------------------------------------------------------------------
// Carrier of external SOCKS exits.

// Files and units on a carrier.
const (
	ExtDir          = "/etc/meridian/ext"
	ExtProxyConfig  = ExtDir + "/gost.yaml"
	ExtProxyUnit    = "meridian-ext-proxy.service"
	ExtHealthUnit   = "meridian-ext-health.service"
	ExtHealthScript = "/usr/local/sbin/meridian-ext-health.sh"
	// ExtRedirPort is the redirector's port on each external exit's service
	// address; ExtDNSPort1/2 the DNS forwarders (to ExtUpstream1/2 port 53
	// through the proxy).
	ExtRedirPort = 12301
	// ExtRefusePort: where the exit's UDP and IPv6 are DNATed to be refused
	// by the kernel (nothing listens there).
	ExtRefusePort = 9
	ExtDNSPort1   = 5301
	ExtDNSPort2   = 5302
	ExtUpstream1  = "1.1.1.1"
	ExtUpstream2  = "8.8.8.8"
	// ExtHealthInterval / ExtHealthTimeout: the carrier probes every
	// external exit this often, each probe bounded by the timeout.
	ExtHealthInterval = 10
	ExtHealthTimeout  = 8
)

// ExtSecretFile reports whether a host path is an external-exit file that
// carries a secret (the redirector's configuration names the proxy
// credential): installed 0600 in a 0700 directory.
func ExtSecretFile(p string) bool {
	p = "/" + strings.TrimPrefix(p, "/")
	return strings.HasPrefix(p, ExtDir+"/") && strings.HasSuffix(p, ".yaml")
}

// SOCKSUserSecret / SOCKSPassSecret are the credential-store ids of a SOCKS
// credential's two halves as the carrier's files name them.
func SOCKSUserSecret(credID string) string { return credID + "-user" }
func SOCKSPassSecret(credID string) string { return credID + "-pass" }

// extMarker is the line the carrier's meridian-up.sh carries per external
// exit for the preflight: the proxy address and the interface that must
// route it.
func extMarker(e ExitPlan) string {
	x := e.Node.External
	return fmt.Sprintf("# meridian-ext: %s socks=%s:%d iface=%s\n", e.Node.ID, x.SOCKSAddress, x.SOCKSPort, x.Interface)
}

// renderCarrierRoutes: the external exits' service and resolver addresses
// on lo (the health address is the health service's), and a blackhole
// table selected by each exit's transit sources: whatever the nft DNAT does
// not take to the local redirector or resolver is dropped here, never
// routed out of the WAN or into another exit. Addresses of external exits
// that left the topology are removed (only inside Meridian's own ranges).
func renderCarrierRoutes(sb *strings.Builder, n model.Node, exits []ExitPlan) {
	ext := externalPlans(exits, n.ID)
	if len(ext) == 0 {
		return
	}
	sb.WriteString("# carrier of external SOCKS exits: TCP to the local redirector, DNS to the local resolver group, everything else blackholed\n")
	var keep []string
	for _, e := range ext {
		keep = append(keep, e.ExtService, e.PeerULA)
	}
	fmt.Fprintf(sb, "# meridian-transit: %s %s %s\n", validate.ExternalServiceNet, validate.ExternalHealthNet, validate.ExternalResolverNet)
	fmt.Fprintf(sb, "keep_ext=' %s '\n", strings.Join(keep, " "))
	fmt.Fprintf(sb, "for a in $(ip -o -4 addr show dev lo to %s 2>/dev/null | awk '{print $4}'); do case \"$keep_ext\" in *\" ${a%%%%/*} \"*) ;; *) ip addr del \"$a\" dev lo 2>/dev/null || true ;; esac; done\n", validate.ExternalServiceNet)
	fmt.Fprintf(sb, "for a in $(ip -o -6 addr show dev lo to %s 2>/dev/null | awk '{print $4}'); do case \"$keep_ext\" in *\" ${a%%%%/*} \"*) ;; *) ip -6 addr del \"$a\" dev lo 2>/dev/null || true ;; esac; done\n", validate.ExternalResolverNet)
	for _, e := range ext {
		x := e.Node.External
		fmt.Fprintf(sb, "# external exit %s mark %#x transit %s: proxy %s:%d via %s\n", e.Node.ID, e.Mark, e.TransitV4, x.SOCKSAddress, x.SOCKSPort, x.Interface)
		fmt.Fprintf(sb, "ip addr replace %s/32 dev lo\n", e.ExtService)
		fmt.Fprintf(sb, "ip -6 addr replace %s/128 dev lo\n", e.PeerULA)
		fmt.Fprintf(sb, "ip route replace blackhole default table %d\n", e.Table)
		fmt.Fprintf(sb, "ip -6 route replace blackhole default table %d\n", e.Table)
		fmt.Fprintf(sb, "del_rule ip rule del from %s/32 lookup %d\n", e.TransitV4, e.Table)
		fmt.Fprintf(sb, "ip rule add from %s/32 lookup %d priority %d\n", e.TransitV4, e.Table, prioHubExitFrom+e.Index)
		fmt.Fprintf(sb, "del_rule ip -6 rule del from %s/128 lookup %d\n", e.TransitV6, e.Table)
		fmt.Fprintf(sb, "ip -6 rule add from %s/128 lookup %d priority %d\n", e.TransitV6, e.Table, prioHubExitFrom+e.Index)
	}
}

// carrierHubIfaces are the carrier's tunnels from the hubs (sorted, quoted).
func carrierHubIfaces(n model.Node, tunnels []Tunnel) []string {
	seen := map[string]bool{}
	var ifs []string
	for _, tun := range tunnels {
		if tun.East.ID != n.ID || tun.West.Role != model.RoleHub || tun.Standby || seen[tun.Iface()] {
			continue
		}
		seen[tun.Iface()] = true
		ifs = append(ifs, "\""+tun.Iface()+"\"")
	}
	sortStrings(ifs)
	return ifs
}

// writeCarrierNFT: for each external exit carried here,
//
//   - ext_dnat (just ahead of every other dstnat chain): its group-resolver
//     queries (the hub rewrote the group's source to its transit address)
//     and, with a backup hub, its hub-independent resolver address go to its
//     resolver group on this host; its IPv4 TCP goes to the redirector on
//     its service address; everything else of UDP and TCP (UDP of either
//     family, QUIC included; IPv6 TCP) goes to ExtRefusePort on its own
//     service or resolver address, where nothing listens: the kernel answers
//     at once with ICMP port unreachable (UDP) or a reset (TCP), with the
//     original destination as source, so clients fall back immediately.
//     Nothing of it is forwarded; other protocols find only the blackhole
//     table its transit sources select (renderCarrierRoutes);
//   - ext_reject: a second line behind that: whatever of its transit
//     sources would still be forwarded is refused here;
//   - ext_local: its service address is reachable only through that DNAT
//     (and from this host), its resolver address only from the hubs;
//   - ext_proxy_out: this host reaches the proxy only through the
//     configured interface (the unmanaged tunnel): if that interface or its
//     route is gone, the connection is reset instead of following the
//     default route out of the WAN.
func writeCarrierNFT(sb *strings.Builder, t model.Topology, n model.Node, tunnels []Tunnel, exits []ExitPlan) {
	ext := externalPlans(exits, n.ID)
	if len(ext) == 0 {
		return
	}
	ifs := strings.Join(carrierHubIfaces(n, tunnels), ", ")
	if ifs == "" {
		ifs = "\"-\""
	}
	sb.WriteString("  chain ext_dnat {\n    type nat hook prerouting priority -101; policy accept;\n")
	for _, e := range ext {
		id := verifyLabel(e.Node.ID)
		for _, proto := range []string{"udp", "tcp"} {
			fmt.Fprintf(sb, "    iifname { %s } ip6 saddr %s ip6 daddr %s %s dport 53 dnat ip6 to [%s]:53 comment \"external exit %s: region-group queries, answered by its resolver group here\"\n", ifs, e.TransitV6, validate.GroupResolverNet, proto, e.PeerULA, id)
		}
		if t.DualHub() {
			for _, proto := range []string{"udp", "tcp"} {
				fmt.Fprintf(sb, "    iifname { %s } ip6 daddr %s %s dport 53 dnat ip6 to [%s]:53 comment \"external exit %s: its resolver address, from either hub\"\n", ifs, e.Resolver, proto, e.PeerULA, id)
			}
		}
		fmt.Fprintf(sb, "    iifname { %s } ip saddr %s meta l4proto tcp dnat ip to %s:%d comment \"external exit %s: TCP to the redirector (SOCKS5 %s:%d)\"\n", ifs, e.TransitV4, e.ExtService, ExtRedirPort, id, e.Node.External.SOCKSAddress, e.Node.External.SOCKSPort)
		fmt.Fprintf(sb, "    iifname { %s } ip saddr %s meta l4proto udp dnat ip to %s:%d comment \"external exit %s is TCP only: UDP (QUIC included) refused here (port unreachable)\"\n", ifs, e.TransitV4, e.ExtService, ExtRefusePort, id)
		fmt.Fprintf(sb, "    iifname { %s } ip6 saddr %s meta l4proto { tcp, udp } dnat ip6 to [%s]:%d comment \"external exit %s carries no IPv6: refused here (reset / port unreachable)\"\n", ifs, e.TransitV6, e.PeerULA, ExtRefusePort, id)
	}
	sb.WriteString("  }\n")
	sb.WriteString("  chain ext_reject {\n    type filter hook forward priority filter; policy accept;\n")
	for _, e := range ext {
		id := verifyLabel(e.Node.ID)
		fmt.Fprintf(sb, "    ip saddr %s meta l4proto udp counter reject with icmp type port-unreachable comment \"external exit %s is TCP only: nothing of it is forwarded\"\n", e.TransitV4, id)
		fmt.Fprintf(sb, "    ip saddr %s counter reject with icmp type admin-prohibited\n", e.TransitV4)
		fmt.Fprintf(sb, "    ip6 saddr %s meta l4proto tcp counter reject with tcp reset\n", e.TransitV6)
		fmt.Fprintf(sb, "    ip6 saddr %s counter reject with icmpv6 type admin-prohibited\n", e.TransitV6)
	}
	sb.WriteString("  }\n")
	sb.WriteString("  chain ext_local {\n    type filter hook input priority filter; policy accept;\n")
	for _, e := range ext {
		id := verifyLabel(e.Node.ID)
		fmt.Fprintf(sb, "    iifname != \"lo\" ip daddr %s ct status dnat accept comment \"external exit %s: its own DNAT\"\n", e.ExtService, id)
		fmt.Fprintf(sb, "    iifname != \"lo\" ip daddr %s counter drop comment \"external exit %s: service address only through its DNAT\"\n", e.ExtService, id)
		fmt.Fprintf(sb, "    iifname != { \"lo\", %s } ip6 daddr %s counter drop comment \"external exit %s: resolver address only from the hubs\"\n", ifs, e.PeerULA, id)
	}
	sb.WriteString("  }\n")
	sb.WriteString("  chain ext_proxy_out {\n    type filter hook output priority filter; policy accept;\n")
	for _, e := range ext {
		x := e.Node.External
		fmt.Fprintf(sb, "    ip daddr %s tcp dport %d oifname != \"%s\" counter reject with tcp reset comment \"external exit %s: the proxy only through %s, never the default route\"\n", x.SOCKSAddress, x.SOCKSPort, x.Interface, verifyLabel(e.Node.ID), x.Interface)
	}
	sb.WriteString("  }\n")
}

// renderExtProxyConfig is the redirector's configuration (gost v3 YAML):
// per external exit a transparent TCP service on its service address
// (the original destination from the DNAT, SO_ORIGINAL_DST) and two DNS
// forwarders to fixed public resolvers, all through a chain whose one hop
// is the exit's SOCKS5 proxy with username and password (placeholders: the
// credential is injected at the install boundary only). No sniffing, no
// name resolution, no UDP, no API, no metrics.
func renderExtProxyConfig(exits []ExitPlan, carrier string) string {
	ext := externalPlans(exits, carrier)
	var sb strings.Builder
	sb.WriteString("# Meridian external SOCKS exits: transparent TCP redirector (gost " + artifacts.Version(artifacts.Gost) + ").\n")
	sb.WriteString("# Secret-bearing (0600): the proxy credentials are injected at install.\n")
	sb.WriteString("services:\n")
	for _, e := range ext {
		id := strings.ReplaceAll(e.Node.ID, "_", "-")
		fmt.Fprintf(&sb, "- name: ext-%s-redir\n  addr: \"%s:%d\"\n  handler:\n    type: red\n    chain: ext-%s\n    metadata:\n      sniffing: false\n  listener:\n    type: red\n    metadata:\n      tproxy: false\n", id, e.ExtService, ExtRedirPort, id)
		for i, up := range []string{ExtUpstream1, ExtUpstream2} {
			port := ExtDNSPort1 + i
			fmt.Fprintf(&sb, "- name: ext-%s-dns%d\n  addr: \"%s:%d\"\n  handler:\n    type: tcp\n    chain: ext-%s\n  listener:\n    type: tcp\n  forwarder:\n    nodes:\n    - name: ext-%s-dns%d-target\n      addr: \"%s:53\"\n", id, i+1, e.ExtService, port, id, id, i+1, up)
		}
	}
	sb.WriteString("chains:\n")
	for _, e := range ext {
		id := strings.ReplaceAll(e.Node.ID, "_", "-")
		x := e.Node.External
		fmt.Fprintf(&sb, "- name: ext-%s\n  hops:\n  - name: ext-%s-hop\n    nodes:\n    - name: ext-%s-socks\n      addr: \"%s:%d\"\n      connector:\n        type: socks5\n        auth:\n          username: \"%s\"\n          password: \"%s\"\n      dialer:\n        type: tcp\n",
			id, id, id, x.SOCKSAddress, x.SOCKSPort, model.SecretPlaceholder(SOCKSUserSecret(x.CredentialID)), model.SecretPlaceholder(SOCKSPassSecret(x.CredentialID)))
	}
	sb.WriteString("log:\n  level: warn\n  format: text\n  output: stderr\n")
	return sb.String()
}

func renderExtProxyUnit() string {
	return fmt.Sprintf(`# Meridian external SOCKS exits: transparent TCP redirector (panel-delivered gost %s).
[Unit]
Description=Meridian external SOCKS exits (TCP redirector to the proxies; no UDP)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=%s -C %s
Restart=always
RestartSec=3
NoNewPrivileges=yes
ProtectHome=yes
PrivateTmp=yes

[Install]
WantedBy=multi-user.target
`, artifacts.Version(artifacts.Gost), artifacts.HostPath(artifacts.Gost), ExtProxyConfig)
}

func renderExtHealthUnit() string {
	return `# Meridian external SOCKS exits: health (TCP through each proxy).
[Unit]
Description=Meridian external SOCKS exits health probe
After=network-online.target ` + ExtProxyUnit + `
Wants=network-online.target

[Service]
Type=simple
ExecStart=` + ExtHealthScript + `
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
`
}

// renderExtHealthScript probes every external exit carried here: a DNS
// query over TCP (the root NS) to the exit's forwarders, which the
// redirector relays through the proxy to the fixed public resolvers. While
// either answers within the timeout, the exit's health address is on lo
// (the hubs ping it); otherwise it is removed, so the hubs' groups leave
// the exit. Every change is logged to the journal. No credential is used
// by the script (the redirector holds it).
func renderExtHealthScript(exits []ExitPlan, carrier string) string {
	ext := externalPlans(exits, carrier)
	var sb strings.Builder
	sb.WriteString("#!/bin/bash\n")
	sb.WriteString("# Meridian external SOCKS exits health. Managed by Meridian (node manifest).\n")
	sb.WriteString("# Health = a DNS query over TCP relayed by the redirector through the proxy\n")
	sb.WriteString("# (TCP reachability through the proxy; no ICMP to the proxy, no credential here).\n")
	sb.WriteString("set -u\n")
	fmt.Fprintf(&sb, "INTERVAL=%d\nTIMEOUT=%d\n", ExtHealthInterval, ExtHealthTimeout)
	sb.WriteString("mkdir -p /run/meridian/ext\n")
	sb.WriteString(`ext_probe() {
  local addr="$1" port="$2" out
  # 17-byte query: header (id 0x4d52, RD, one question), root name, NS, IN.
  out=$(timeout "$TIMEOUT" bash -c 'exec 3<>"/dev/tcp/$0/$1" || exit 1; printf "\x00\x11\x4d\x52\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00\x01" >&3; head -c 4 <&3' "$addr" "$port" 2>/dev/null | od -An -tx1 | tr -d ' \n')
  [ "${out:4:4}" = "4d52" ]
}
ext_check() {
  local id="$1" svc="$2" health="$3" was now
  was=$(cat "/run/meridian/ext/$id" 2>/dev/null || echo unknown)
  if ext_probe "$svc" ` + fmt.Sprint(ExtDNSPort1) + ` || ext_probe "$svc" ` + fmt.Sprint(ExtDNSPort2) + `; then
    now=up
    ip addr replace "$health/32" dev lo
  else
    now=down
    ip addr del "$health/32" dev lo 2>/dev/null || true
  fi
  if [ "$now" != "$was" ]; then
    echo "$now" > "/run/meridian/ext/$id"
    if [ "$now" = up ]; then
      echo "meridian-ext-health: $id up (TCP through its proxy answers); health address $health present"
    else
      echo "meridian-ext-health: $id down (no TCP answer through its proxy within ${TIMEOUT}s); health address $health removed, the hubs stop using it" >&2
    fi
  fi
}
`)
	sb.WriteString("ext_all() {\n")
	for _, e := range ext {
		fmt.Fprintf(&sb, "  ext_check %s %s %s\n", shQuote(e.Node.ID), e.ExtService, e.PeerV4)
	}
	sb.WriteString("  :\n}\n")
	// Health addresses of exits that left the topology.
	var keep []string
	for _, e := range ext {
		keep = append(keep, e.PeerV4)
	}
	fmt.Fprintf(&sb, "keep_health=' %s '\n", strings.Join(keep, " "))
	fmt.Fprintf(&sb, "for a in $(ip -o -4 addr show dev lo to %s 2>/dev/null | awk '{print $4}'); do case \"$keep_health\" in *\" ${a%%%%/*} \"*) ;; *) ip addr del \"$a\" dev lo 2>/dev/null || true ;; esac; done\n", validate.ExternalHealthNet)
	sb.WriteString("while true; do\n  ext_all\n  sleep \"$INTERVAL\"\ndone\n")
	return sb.String()
}

// renderCarrierDNS adds each external exit's resolver group to the
// carrier's resolver: a listener on the exit's resolver address bound to
// group ext_<id>, whose only servers are the exit's DNS forwarders (DNS over
// TCP through the proxy). The group is excluded from the default group, the
// listener never asks another group: when the proxy gives no answer the
// name fails. No AAAA (the exit is IPv4 only).
func renderCarrierDNS(sb *strings.Builder, exits []ExitPlan, carrier string) {
	for _, e := range externalPlans(exits, carrier) {
		g := "ext_" + strings.ReplaceAll(e.Node.ID, "-", "_")
		fmt.Fprintf(sb, "# external SOCKS exit %s: names are resolved on this carrier, upstream queries over TCP through its proxy\n", e.Node.ID)
		fmt.Fprintf(sb, "# (%s:53, %s:53); no other upstream, no fallback to this host's own servers, no AAAA.\n", ExtUpstream1, ExtUpstream2)
		for _, b := range []string{"bind", "bind-tcp"} {
			fmt.Fprintf(sb, "%s [%s]:53 -group %s -no-speed-check -no-dualstack-selection -force-aaaa-soa\n", b, e.PeerULA, g)
		}
		fmt.Fprintf(sb, "server-tcp %s:%d -group %s -exclude-default-group\n", e.ExtService, ExtDNSPort1, g)
		fmt.Fprintf(sb, "server-tcp %s:%d -group %s -exclude-default-group\n", e.ExtService, ExtDNSPort2, g)
	}
}

// ---------------------------------------------------------------------------
// Dynamic-DNS endpoint refresh (every dialing node with a name endpoint).

// Files of the endpoint refresh.
const (
	EndpointRefreshScript = "/usr/local/sbin/meridian-endpoint-refresh.sh"
	EndpointRefreshUnit   = "meridian-endpoint-refresh.service"
	EndpointRefreshTimer  = "meridian-endpoint-refresh.timer"
	// EndpointStaleSec: a peer whose latest handshake is older than this
	// (or never happened) gets its name endpoint re-applied. WireGuard
	// re-handshakes every 2 minutes while traffic or keepalives flow.
	EndpointStaleSec = 150
)

// refreshTunnels are the UDP tunnels n dials whose listener has a DNS-name
// endpoint.
func refreshTunnels(n model.Node, tunnels []Tunnel) []Tunnel {
	var out []Tunnel
	for _, tun := range tunnels {
		if tun.Mode != "udp" || tun.Dialer().ID != n.ID || tun.OuterV6 {
			continue
		}
		if dialHost(tun) != "" {
			out = append(out, tun)
		}
	}
	return out
}

// dialHost is the DNS name the dialer of tun targets ("" for an address).
func dialHost(tun Tunnel) string {
	lis := tun.Listener()
	if lis.Role == model.RoleExit && lis.EndpointHost != "" {
		return lis.EndpointHost
	}
	return ""
}

func renderEndpointRefresh(n model.Node, tunnels []Tunnel) string {
	var sb strings.Builder
	sb.WriteString("#!/bin/bash\n")
	sb.WriteString("# Meridian endpoint refresh. Managed by Meridian (node manifest).\n")
	sb.WriteString("# WireGuard resolves a name endpoint once, when the interface is configured.\n")
	sb.WriteString("# For every peer this node dials by a DNS name (dynamic DNS), the endpoint is\n")
	sb.WriteString("# re-applied (and so re-resolved) when the latest handshake is older than\n")
	fmt.Fprintf(&sb, "# %d seconds or never happened. One attempt per peer per timer run.\n", EndpointStaleSec)
	sb.WriteString("set -u\n")
	fmt.Fprintf(&sb, "STALE=%d\n", EndpointStaleSec)
	sb.WriteString(`refresh() {
  local iface="$1" pub="$2" ep="$3" hs now age
  ip link show "$iface" >/dev/null 2>&1 || return 0
  hs=$(wg show "$iface" latest-handshakes 2>/dev/null | awk -v k="$pub" '$1==k {print $2}')
  case "$hs" in ''|*[!0-9]*) hs=0 ;; esac
  now=$(date +%s)
  if [ "$hs" -ne 0 ] && [ $((now-hs)) -le "$STALE" ]; then return 0; fi
  if [ "$hs" -eq 0 ]; then age=never; else age="$((now-hs))s ago"; fi
  if timeout 20 wg set "$iface" peer "$pub" endpoint "$ep"; then
    echo "meridian-endpoint-refresh: $iface last handshake $age; endpoint $ep re-resolved and re-applied"
  else
    echo "meridian-endpoint-refresh: $iface last handshake $age; $ep could not be resolved or applied, previous endpoint kept" >&2
  fi
}
`)
	for _, tun := range refreshTunnels(n, tunnels) {
		fmt.Fprintf(&sb, "refresh %s %s %s\n", shQuote(tun.Iface()), shQuote(pubkey(tun.Listener())), shQuote(fmt.Sprintf("%s:%d", dialHost(tun), tun.WGPort)))
	}
	sb.WriteString("exit 0\n")
	return sb.String()
}

func renderEndpointRefreshUnit() string {
	return `# Meridian endpoint refresh (dynamic-DNS endpoints).
[Unit]
Description=Meridian: re-resolve DNS-name WireGuard endpoints after stale handshakes
After=network-online.target

[Service]
Type=oneshot
ExecStart=` + EndpointRefreshScript + `
TimeoutStartSec=90
`
}

func renderEndpointRefreshTimer() string {
	return `# Meridian endpoint refresh (dynamic-DNS endpoints).
[Unit]
Description=Meridian: check DNS-name WireGuard endpoints every minute

[Timer]
OnBootSec=2min
OnUnitActiveSec=1min
AccuracySec=10s

[Install]
WantedBy=timers.target
`
}
