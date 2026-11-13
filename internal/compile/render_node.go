package compile

import (
	"fmt"
	"strings"

	"github.com/radowitz/meridian/internal/artifacts"
	"github.com/radowitz/meridian/internal/model"
)

func renderBundleReadme(t model.Topology) string {
	return strings.TrimSpace(`
Meridian 生成的数据面配置。
地址若仍是 203.0.113.0/24、198.51.100.0/24、2001:db8::/32，说明这是示例，不能直接上线。
私钥占位符 __MERIDIAN_PRIVATE_KEY__ 只在装机写入主机时替换为该节点的私钥（首次装机生成并保存，之后复用），编译产物、快照、预览和差异始终保留占位符，不要写入 git。
ULA fd66::/48 只在隧道内转发，不要指向 ROS。
IX 替换用的 WSS 会随配置一起下发并做健康探测，但在替换模式关闭时不作为默认下一跳。
`) + "\nROS=" + t.Settings.ROSIPv4 + " 网关=" + t.Settings.GatewayLANIP + "\n"
}

func renderSysctl(t model.Topology, n model.Node) string {
	ifName := sysctlIface(t, n)
	var sb strings.Builder
	sb.WriteString("# Meridian host sysctls. Does not flush other sysctls.\n")
	sb.WriteString("# Forwarding is NOT turned on here: systemd-sysctl applies this file at\n")
	sb.WriteString("# boot, before meridian.service has loaded the nft guard. meridian-up.sh\n")
	sb.WriteString("# enables forwarding from /etc/meridian/forwarding.conf after the firewall\n")
	sb.WriteString("# (and on the gateway the inet meridian_guard table) is loaded.\n")
	if n.Role == model.RoleGateway {
		// Explicitly off at boot, also overriding an earlier sysctl file,
		// so the LAN is never forwarded before the guard exists. The up
		// script skips these two lines.
		sb.WriteString("net.ipv4.ip_forward=0\n")
		sb.WriteString("net.ipv6.conf.all.forwarding=0\n")
	}
	if n.Role != model.RoleGateway {
		// A remote node shares its host with other services (Docker,
		// WARP, the operator's own). Only what Meridian needs: the
		// interface the topology names, plus all.send_redirects=0, which
		// the kernel ORs with each interface's value (without it no
		// interface can be kept from sending redirects). rp_filter is
		// max(all, interface): the interface value 2 is loose whatever
		// "all" is, so "all" and "default" are not changed here. The
		// WireGuard interfaces do not exist at boot; meridian-routes.sh
		// sets the same keys on them (and on this interface) once they are
		// up. Older versions wrote all/default keys into this file: the
		// file is rewritten whole on every install, so they are gone from
		// the next boot on.
		sb.WriteString("# Remote node: only the topology's interface and the one global that is\n")
		sb.WriteString("# required (send_redirects is ORed with all). all/default rp_filter and\n")
		sb.WriteString("# accept_redirects are left to the host.\n")
		sb.WriteString("net.ipv4.conf.all.send_redirects=0\n")
		fmt.Fprintf(&sb, "net.ipv4.conf.%s.rp_filter=2\n", ifName)
		fmt.Fprintf(&sb, "net.ipv4.conf.%s.send_redirects=0\n", ifName)
		fmt.Fprintf(&sb, "net.ipv4.conf.%s.accept_redirects=0\n", ifName)
		fmt.Fprintf(&sb, "net.ipv6.conf.%s.accept_redirects=0\n", ifName)
		return sb.String()
	}
	sb.WriteString("net.ipv4.conf.all.rp_filter=2\n")
	sb.WriteString("net.ipv4.conf.default.rp_filter=2\n")
	fmt.Fprintf(&sb, "net.ipv4.conf.%s.rp_filter=2\n", ifName)
	sb.WriteString("net.ipv4.conf.all.send_redirects=0\n")
	sb.WriteString("net.ipv4.conf.default.send_redirects=0\n")
	fmt.Fprintf(&sb, "net.ipv4.conf.%s.send_redirects=0\n", ifName)
	// Linux has no net.ipv6.conf.*.send_redirects: IPv6 redirects are sent
	// by the forwarding path without a sysctl switch, so none is written.
	fmt.Fprintf(&sb, "net.ipv6.conf.%s.accept_redirects=0\n", ifName)
	sb.WriteString("net.ipv4.conf.all.accept_redirects=0\n")
	sb.WriteString("net.ipv6.conf.all.accept_redirects=0\n")
	sb.WriteString("net.ipv6.conf.default.accept_redirects=0\n")
	if n.Role == model.RoleGateway {
		// forwarding=1 ignores accept_ra unless it is 2. This host is a
		// SLAAC client of ROS and must not advertise its own prefix.
		fmt.Fprintf(&sb, "net.ipv6.conf.%s.accept_ra=2\n", ifName)
		sb.WriteString("# Do not run radvd or a DHCP server on this LAN.\n")
	}
	return sb.String()
}

// renderForwarding is applied by meridian-up.sh only after the firewall is
// loaded, never by systemd-sysctl at boot (see renderSysctl).
func renderForwarding(t model.Topology, n model.Node) string {
	var sb strings.Builder
	sb.WriteString("# Meridian forwarding. Applied by meridian-up.sh after the nft batch (and\n")
	sb.WriteString("# on the gateway the LAN guard) is loaded. Not in /etc/sysctl.d on purpose.\n")
	sb.WriteString("net.ipv4.ip_forward=1\n")
	if forwards6(n) {
		sb.WriteString("net.ipv6.conf.all.forwarding=1\n")
	} else {
		// An exit without IPv6 egress and without IPv6 transit forwards no
		// IPv6 at all: the switch stays as the host has it, so the host's
		// own router-advertisement handling is never affected.
		sb.WriteString("# No IPv6 forwarding: this exit has no IPv6 egress and relays no IPv6.\n")
	}
	if n.Role == model.RoleGateway {
		fmt.Fprintf(&sb, "net.ipv6.conf.%s.forwarding=1\n", sysctlIface(t, n))
	}
	return sb.String()
}

// sysctlIface is the interface the per-interface sysctls name. On the
// gateway that is always settings.lan_interface, the one source of truth the
// nft guard, the routes, the LAN wait and the verify script use too
// (validation refuses a gateway node whose own lan_interface differs).
func sysctlIface(t model.Topology, n model.Node) string {
	if n.Role == model.RoleGateway {
		return gatewayLAN(t)
	}
	// A remote node's interface is its WAN, the same name its nft NAT, its
	// IPv6 drop and its DOCKER-USER rules use (nodeWAN); the preflight checks
	// that it exists and carries the default route.
	return nodeWAN(n)
}

// forwards6 says whether the node forwards IPv6: the gateway, hubs and
// relays (ULA transit and the LAN prefix), and exits with IPv6 egress or
// acting as the dual-stack relay. Every other exit only terminates IPv6
// (group-resolver queries are DNATed to a local socket) or drops it.
func forwards6(n model.Node) bool {
	if n.Role != model.RoleExit {
		return true
	}
	return n.EgressV6 || n.DualstackRelay
}

// renderGuardNFT is the gateway LAN guard alone, loaded at early boot by
// deploy/debian/meridian-guard.service (before systemd-sysctl, Docker and
// meridian.service). It is the same table meridian.nft also carries, so the
// later full load replaces it atomically with identical rules.
// gatewayLAN is settings.lan_interface, or eth0 when unset.
func gatewayLAN(t model.Topology) string {
	if t.Settings.LANInterface != "" {
		return t.Settings.LANInterface
	}
	return "eth0"
}

func renderGuardNFT(t model.Topology, tunnels []Tunnel, exits []ExitPlan, groups []GroupPlan) string {
	lan := gatewayLAN(t)
	var sb strings.Builder
	sb.WriteString("#!/usr/sbin/nft -f\n")
	sb.WriteString("# Meridian early-boot LAN guard. Loaded by meridian-guard.service before\n")
	sb.WriteString("# forwarding can be enabled. Replaces only table inet meridian_guard.\n")
	writeGuardTable(&sb, lan, gatewayTunnelIfaces(tunnels), guardLastExitMark(exits, groups...), planRemote(t))
	return sb.String()
}

func renderRTTables(t model.Topology, n model.Node, exits []ExitPlan, groups []GroupPlan) string {
	var sb strings.Builder
	sb.WriteString("100\tmeridian_domestic\n")
	sb.WriteString("102\tmeridian_foreign\n")
	sb.WriteString("150\tmeridian_east\n")
	if n.Role == model.RoleExit && len(meshDNSGroups(groups, n.ID)) > 0 {
		fmt.Fprintf(&sb, "%d\tmeridian_mesh_dns\n", tableMeshDNS)
	}
	if n.Role == model.RoleExit && t.DualHub() {
		fmt.Fprintf(&sb, "%d\tmeridian_return_primary\n", tableHubReturnPrimary)
		fmt.Fprintf(&sb, "%d\tmeridian_return_backup\n", tableHubReturnBackup)
	}
	if n.Role == model.RoleGateway && t.RelaySharing() {
		writeShareRTTables(&sb, t)
	}
	for _, r := range ingressReturnsFor(t, n) {
		fmt.Fprintf(&sb, "%d\tmeridian_in_%s\n", r.Table, r.Iface)
	}
	if n.Role == model.RoleHub {
		for _, e := range exits {
			fmt.Fprintf(&sb, "%d\tmeridian_%s\n", e.Table, strings.ReplaceAll(e.Node.ID, "-", "_"))
		}
		for _, g := range groups {
			fmt.Fprintf(&sb, "%d\t%s\n", g.Table, g.tableName())
		}
	}
	_ = t
	return sb.String()
}

func renderWG(t model.Topology, tun Tunnel, self model.Node) string {
	var peer model.Node
	var selfV4, selfULA, peerV4, peerULA string
	west := self.ID == tun.West.ID
	if west {
		peer = tun.East
		selfV4, selfULA = tun.WestV4, tun.WestULA
		peerV4, peerULA = tun.EastV4, tun.EastULA
	} else {
		peer = tun.West
		selfV4, selfULA = tun.EastV4, tun.EastULA
		peerV4, peerULA = tun.WestV4, tun.WestULA
	}
	localCIDR, _ := v4PairPrefix(selfV4, peerV4)
	var sb strings.Builder
	fmt.Fprintf(&sb, "# meridian link %s mode %s iface %s\n", tun.LinkID, tun.Mode, tun.Iface())
	fmt.Fprintf(&sb, "# peer %s (%s). Table=off so this never replaces the host default route.\n", peer.ID, peer.Name)
	if tun.Standby {
		sb.WriteString("# STANDBY: bring the interface up, but do not install it as the default route.\n")
	}
	if tun.OuterV6 {
		sb.WriteString("# outer v6: the Hong Kong hub has no IPv6. This leg is past the dual-stack relay.\n")
	}
	if self.V6Workaround == model.WorkaroundV4Front && self.Role == model.RoleExit {
		sb.WriteString("# v4 front: Endpoint is a v4 address in front of this v6-only host, not the hub.\n")
	}
	if tun.DialOut && peer.Role == model.RoleHub && !west {
		sb.WriteString("# NAT dial-out: this node dials the hub. The hub has no Endpoint for us.\n")
	}
	sb.WriteString("[Interface]\n")
	fmt.Fprintf(&sb, "PrivateKey = %s\n", privateKeyPlaceholder)
	fmt.Fprintf(&sb, "Address = %s, %s/64\n", localCIDR, selfULA)
	fmt.Fprintf(&sb, "MTU = %d\n", tun.MTU)
	sb.WriteString("Table = off\n")
	if self.Role == model.RoleGateway {
		// Outer packets are looked up with this mark. The gateway's policy
		// rules send it to the main table before any exit mark is considered.
		fmt.Fprintf(&sb, "FwMark = %#x\n", markUnderlay)
	}
	listens := (!tun.DialOut && !west) || (tun.DialOut && west)
	if listens {
		fmt.Fprintf(&sb, "ListenPort = %d\n", tun.WGPort)
	}
	sb.WriteString("\n[Peer]\n")
	fmt.Fprintf(&sb, "# peer-node %s\n", peer.ID)
	fmt.Fprintf(&sb, "PublicKey = %s\n", pubkey(peer))
	if endpoint := peerEndpoint(tun, self); endpoint != "" {
		fmt.Fprintf(&sb, "Endpoint = %s\n", endpoint)
	} else {
		sb.WriteString("# Endpoint omitted: the peer dials us (NAT dial-out or we are the listener).\n")
	}
	fmt.Fprintf(&sb, "AllowedIPs = %s\n", allowedIPs(t, tun, west))
	if tun.Keepalive > 0 && !listens {
		fmt.Fprintf(&sb, "PersistentKeepalive = %d\n", tun.Keepalive)
	}
	_ = peerV4
	_ = peerULA
	return sb.String()
}

func peerEndpoint(tun Tunnel, self model.Node) string {
	if tun.Mode == "wss" {
		if tun.Dialer().ID == self.ID {
			return fmt.Sprintf("127.0.0.1:%d", tun.ClientUDP)
		}
		return ""
	}
	if tun.Dialer().ID != self.ID {
		return ""
	}
	srv := tun.Listener()
	if tun.OuterV6 {
		if srv.EndpointV6 == "" {
			return ""
		}
		return fmt.Sprintf("[%s]:%d", srv.EndpointV6, tun.WGPort)
	}
	if tun.DialV4() == "" {
		return ""
	}
	return fmt.Sprintf("%s:%d", tun.DialV4(), tun.WGPort)
}

func allowedIPs(t model.Topology, tun Tunnel, west bool) string {
	// The west side sends arbitrary internet destinations toward the east.
	// The east side only sends LAN, transit, and ULA back toward home.
	if west {
		return "0.0.0.0/0, ::/0"
	}
	parts := []string{
		lanNet(t),
		transitV4Net(),
		tun.WestV4 + "/32",
		"fd66::/48",
	}
	if t.Settings.LANIPv6Prefix != "" {
		parts = append(parts, t.Settings.LANIPv6Prefix)
	}
	return strings.Join(parts, ", ")
}

func renderUp(t model.Topology, n model.Node, tunnels []Tunnel, meshDNS bool) string {
	var sb strings.Builder
	sb.WriteString("#!/bin/bash\n")
	sb.WriteString("# Bring up Meridian on this host without flushing the rest of nftables.\n")
	sb.WriteString("# A bad line in sysctl is skipped so a wrong interface name cannot abort SSH.\n")
	sb.WriteString("# Normally run by meridian.service (boot, and activation via meridian-host).\n")
	sb.WriteString("set -euo pipefail\n")
	if n.Role != model.RoleGateway {
		sb.WriteString(wanMarker(n))
		sb.WriteString(ixHubMarker(n))
	}
	sb.WriteString(nftLoadCommands(n.Role == model.RoleGateway))
	if n.Role == model.RoleGateway {
		// Firewall and guard are loaded; nothing has been forwarded or
		// routed yet. At boot the LAN address may still be on its way.
		sb.WriteString(lanWaitCommands(t))
	}
	// No "sysctl --system": it would re-apply the boot-time forwarding=0 of
	// 99-meridian.conf and flap forwarding on every reload. Only Meridian's
	// own keys are applied, forwarding last and only after the firewall.
	// Every install rewrites the whole file, so what is applied here is
	// exactly the compiled set; the panel reads each key back afterwards
	// (apply.SysctlReport) and shows what is not in effect. The summary
	// line makes the same visible in journalctl -u meridian.service.
	sb.WriteString("if [ -f /etc/sysctl.d/99-meridian.conf ]; then\n")
	sb.WriteString("  sysctl_ok=0; sysctl_skip=0\n")
	sb.WriteString("  while IFS= read -r line; do\n")
	sb.WriteString("    case \"$line\" in ''|'#'*|*ip_forward=*|*.forwarding=*) continue ;; esac\n")
	sb.WriteString("    if sysctl -w \"$line\" >/dev/null 2>&1; then sysctl_ok=$((sysctl_ok + 1)); else sysctl_skip=$((sysctl_skip + 1)); echo \"skip sysctl: $line\" >&2; fi\n")
	sb.WriteString("  done < /etc/sysctl.d/99-meridian.conf\n")
	sb.WriteString("  echo \"meridian-sysctl: applied $sysctl_ok, skipped $sysctl_skip from /etc/sysctl.d/99-meridian.conf\"\n")
	sb.WriteString("else\n")
	sb.WriteString("  echo \"meridian-sysctl: /etc/sysctl.d/99-meridian.conf missing; host sysctls not applied\" >&2\n")
	sb.WriteString("fi\n")
	if n.Role != model.RoleGateway {
		// Docker's FORWARD DROP: the coexistence rules go in before
		// forwarding is turned on and before any tunnel exists. A host whose
		// DROP cannot be worked around fails here, visibly, with the
		// interfaces still down (the preflight refuses such a host before
		// the first install).
		sb.WriteString(fwCompatCommands)
		if forwards6(n) {
			// Before the IPv6 forwarding switch: interfaces whose IPv6
			// comes from router advertisements keep accepting them.
			sb.WriteString(raKeepCommands)
		}
	}
	sb.WriteString(forwardingCommands())
	if n.Role == model.RoleGateway {
		sb.WriteString(dnsSeedCommands(t))
		sb.WriteString(`if [ ! -s /etc/meridian/dns/cert.pem ] && command -v openssl >/dev/null 2>&1; then
  openssl req -x509 -newkey rsa:2048 -nodes \
    -keyout /etc/meridian/dns/key.pem \
    -out /etc/meridian/dns/cert.pem \
    -days 3650 -subj "/CN=meridian.lan" >/dev/null 2>&1
  chmod 600 /etc/meridian/dns/key.pem /etc/meridian/dns/cert.pem || true
fi
`)
	}
	// Only the interfaces this manifest owns, never a glob: a config left
	// behind by another (failed or rolled-back) apply is not brought up.
	// mra goes first so it holds its listen port before any tunnel without
	// a ListenPort is given a random one. wg syncconf replaces the running
	// peer set with the file's: a disabled or deleted device is gone here.
	ifaces := tunnelIfaces(tunnels)
	var rp *remotePlan
	if n.Role == model.RoleGateway {
		rp = planRemote(t)
	}
	if rp != nil {
		ifaces = append([]string{rp.Iface}, ifaces...)
	}
	if len(ifaces) > 0 {
		fmt.Fprintf(&sb, "for iface in %s; do\n", strings.Join(ifaces, " "))
		sb.WriteString("  conf=\"/etc/wireguard/$iface.conf\"\n")
		sb.WriteString("  if [ ! -f \"$conf\" ]; then\n")
		sb.WriteString("    echo \"meridian-wg-missing: $conf is listed in this manifest but not installed\" >&2\n")
		sb.WriteString("    exit 1\n")
		sb.WriteString("  fi\n")
		sb.WriteString("  if ip link show \"$iface\" >/dev/null 2>&1; then\n")
		sb.WriteString("    wg syncconf \"$iface\" <(wg-quick strip \"$conf\")\n")
		sb.WriteString("  else\n")
		sb.WriteString("    wg-quick up \"$conf\"\n")
		sb.WriteString("  fi\n")
		sb.WriteString("done\n")
	}
	if rp != nil {
		sb.WriteString(remoteUpCommands(rp))
	}
	// Seal the Mesh sidecar before policy routes, so a mesh exit table can
	// point at mmesh on the first boot. A mesh failure must not skip routes:
	// the foreign path still has to install its blackhole.
	if n.Role != model.RoleGateway {
		sb.WriteString("if [ -x /usr/local/sbin/meridian-mesh-up.sh ]; then\n")
		sb.WriteString("  /usr/local/sbin/meridian-mesh-up.sh || echo \"mesh sidecar skipped\" >&2\n")
		sb.WriteString("fi\n")
	}
	sb.WriteString("/usr/local/sbin/meridian-routes.sh\n")
	// No silent skip: without systemd the WSS and failover services would
	// not run while the install still looked successful.
	sb.WriteString("enable_unit() {\n")
	sb.WriteString("  if [ ! -d /run/systemd/system ] || ! command -v systemctl >/dev/null 2>&1; then\n")
	sb.WriteString("    echo \"meridian-systemd-missing: cannot start $1 here; activate through meridian-host on the host\" >&2\n")
	sb.WriteString("    exit 1\n")
	sb.WriteString("  fi\n")
	sb.WriteString("  systemctl enable --now \"$1\"\n")
	sb.WriteString("}\n")
	seen := map[string]bool{}
	for _, tun := range tunnels {
		if tun.Mode != "wss" {
			continue
		}
		var unit string
		if tun.Dialer().ID == n.ID {
			unit = "wstunnel-client-" + tun.LinkID + ".service"
		} else {
			unit = "wstunnel-meridian.service"
		}
		if seen[unit] {
			continue
		}
		seen[unit] = true
		fmt.Fprintf(&sb, "enable_unit %s\n", shQuote(unit))
	}
	if n.Role == model.RoleGateway || n.Role == model.RoleRelay || n.Role == model.RoleHub {
		sb.WriteString("enable_unit meridian-failover.service\n")
		// enable --now does not restart a running service. The failover
		// script carries the compiled group policy (targets, switch order)
		// and resets the group tables to the compiled targets when it
		// starts, so it must restart with the routes it belongs to.
		sb.WriteString("systemctl restart meridian-failover.service\n")
	}
	if n.Role == model.RoleExit && meshDNS {
		// This exit answers region-group queries over the Mesh: its
		// sidecar's table 170 must learn the Mesh routes Cloudflare installs
		// after boot, and table 171 must follow the seal (no failover loop
		// re-seals an exit).
		sb.WriteString("enable_unit meridian-mesh-seal.timer\n")
	}
	if n.Role == model.RoleExit {
		sb.WriteString("enable_unit meridian-unlock.timer\n")
		// The exit resolver binds to tunnel addresses, which only exist once
		// the WireGuard interfaces above are up. A boot-time start before
		// that fails to bind, so restart it here. Provision installs it.
		// The resolver is the panel-delivered binary under its own unit
		// (SmartDNSUnit), never the distribution's smartdns.service.
		sb.WriteString(`if [ -f /etc/smartdns/smartdns.conf ] && [ -d /run/systemd/system ] && command -v systemctl >/dev/null 2>&1; then
  if systemctl cat ` + SmartDNSUnit + ` >/dev/null 2>&1; then
    systemctl enable ` + SmartDNSUnit + ` >/dev/null 2>&1 || true
    systemctl restart ` + SmartDNSUnit + ` || echo "` + SmartDNSUnit + ` restart failed; exit resolver is down" >&2
  else
    echo "` + SmartDNSUnit + ` is not installed; exit resolver is down" >&2
  fi
fi
`)
	}
	sb.WriteString("echo meridian-up-complete\n")
	return sb.String()
}

// tunnelIfaces lists a node's WireGuard interfaces, sorted and unique.
func tunnelIfaces(tunnels []Tunnel) []string {
	seen := map[string]bool{}
	var out []string
	for _, tun := range tunnels {
		if name := tun.Iface(); name != "" && !seen[name] {
			seen[name] = true
			out = append(out, name)
		}
	}
	sortStrings(out)
	return out
}

// LANNotReadyExit is meridian-up.sh's exit status when the LAN never became
// ready (meridian-lan-not-ready). deploy/debian/meridian.service lists it in
// RestartForceExitStatus, so only this case is retried by systemd: nothing
// but the nft batch and the guard has been applied when it is returned.
const LANNotReadyExit = 75

// LANWaitDefaultSec bounds the LAN wait. It must stay well inside the
// unit's TimeoutStartSec (checked by a test against meridian.service).
const LANWaitDefaultSec = 60

// lanWaitCommands blocks (bounded) until the gateway LAN can carry the
// routes step: settings.lan_interface exists and is up, it holds the
// configured gateway LAN IPv4 address, and the ROS IPv4 next-hop resolves
// on-link on that interface. Without this, a late DHCP lease at boot makes
// "ip route replace default via <ROS> dev <lan> table 100" fail ("Nexthop
// has invalid gateway") after forwarding was already on.
//
// IPv6 is deliberately not waited for. The routes step only uses the ROS
// link-local next-hop with an explicit device, which the kernel accepts once
// the interface exists and is up; the gateway's own RA-learned default and
// GUA are not used by the routes step, so a late RA neither blocks boot nor
// aborts the IPv4 data plane.
//
// The output is parsed in shell variables, never with a pipe into grep -q:
// under pipefail an early-exiting grep would turn a match into a failure.
func lanWaitCommands(t model.Topology) string {
	return strings.NewReplacer(
		"@LAN@", shQuote(gatewayLAN(t)),
		"@ADDR@", shQuote(lanHost(t)),
		"@ROS@", shQuote(t.Settings.ROSIPv4),
		"@WAIT@", fmt.Sprint(LANWaitDefaultSec),
		"@EXIT@", fmt.Sprint(LANNotReadyExit),
	).Replace(`lan_if=@LAN@
lan_addr=@ADDR@
ros4=@ROS@
lan_wait=${MERIDIAN_LAN_WAIT_SEC:-@WAIT@}
case "$lan_wait" in ''|*[!0-9]*) lan_wait=@WAIT@ ;; esac
lan_why=""
lan_ready() {
  local out
  out=$(ip -o link show dev "$lan_if" 2>/dev/null) || { lan_why="interface $lan_if does not exist"; return 1; }
  case "$out" in
    *'<UP,'*|*',UP,'*|*',UP>'*|*'<UP>'*) ;;
    *) lan_why="interface $lan_if is down"; return 1 ;;
  esac
  out=$(ip -4 -o addr show dev "$lan_if" 2>/dev/null) || out=""
  case "$out" in
    *" $lan_addr/"*) ;;
    *) lan_why="$lan_if does not carry $lan_addr yet"; return 1 ;;
  esac
  if [ -n "$ros4" ]; then
    out=$(ip -4 route get "$ros4" 2>/dev/null) || { lan_why="no route to ROS $ros4"; return 1; }
    case "$out" in
      *" via "*) lan_why="ROS $ros4 is not on-link"; return 1 ;;
    esac
    case "$out " in
      *" dev $lan_if "*) ;;
      *) lan_why="ROS $ros4 is not reached on $lan_if"; return 1 ;;
    esac
  fi
  return 0
}
lan_waited=0
until lan_ready; do
  if [ "$lan_waited" -ge "$lan_wait" ]; then
    echo "meridian-lan-not-ready: $lan_why after ${lan_waited}s; forwarding not enabled, routes not installed (systemd retries meridian.service)" >&2
    exit @EXIT@
  fi
  sleep 1
  lan_waited=$((lan_waited + 1))
done
`)
}

// raKeepCommands keeps router advertisements working on the host's own
// interfaces once IPv6 forwarding is on. With net.ipv6.conf.all.forwarding=1
// the kernel ignores RAs on an interface whose accept_ra is 1, so an
// RA-learned default route expires and the host silently loses IPv6. Before
// the switch, every interface that has an RA-learned route in the main
// table now (ip -6 route … proto ra), or that an earlier run recorded in
// RAState (so a late RA at boot is covered too), gets accept_ra=2 when it
// is 1. An interface with RA routes and accept_ra 0 is served by a
// userspace RA client (systemd-networkd, NetworkManager) whose behaviour
// with forwarding on is not known here: the script stops before forwarding
// (fail closed: the host keeps its IPv6), as the preflight already refuses.
// Values are written with the slash form so interface names with dots work.
const raKeepCommands = `MERIDIAN_RA_STATE=` + RAState + `
ra_now=$(ip -6 route show table main proto ra 2>/dev/null | awk '{for (i=1;i<NF;i++) if ($i=="dev") print $(i+1)}' | sort -u) || ra_now=""
ra_old=""
if [ -f "$MERIDIAN_RA_STATE" ]; then ra_old=$(cat "$MERIDIAN_RA_STATE"); fi
for ra_if in $(printf '%s\n%s\n' "$ra_now" "$ra_old" | sort -u); do
  case "$ra_if" in ''|*[!A-Za-z0-9_.@-]*) continue ;; esac
  ra_f=/proc/sys/net/ipv6/conf/$ra_if/accept_ra
  [ -r "$ra_f" ] || continue
  ra_cur=$(head -c 8 "$ra_f")
  case "$ra_cur" in
    2) ;;
    1)
      if ! sysctl -w "net/ipv6/conf/$ra_if/accept_ra=2" >/dev/null; then
        echo "meridian-ra-failed: could not set accept_ra=2 on $ra_if; IPv6 forwarding not enabled" >&2
        exit 1
      fi
      echo "meridian-ra: $ra_if accept_ra 1 -> 2 (keeps its router advertisements with IPv6 forwarding on)" ;;
    *)
      case " $(printf '%s ' $ra_now) " in
        *" $ra_if "*)
          echo "meridian-ra-unmanaged: $ra_if has RA-learned IPv6 routes but accept_ra=$ra_cur (a userspace RA client); IPv6 forwarding could break it, so forwarding is not enabled" >&2
          exit 1 ;;
      esac
      continue ;;
  esac
  install -d -m 700 "${MERIDIAN_RA_STATE%/*}"
  grep -qx -- "$ra_if" "$MERIDIAN_RA_STATE" 2>/dev/null || printf '%s\n' "$ra_if" >> "$MERIDIAN_RA_STATE"
done
`

// RAState lists the interfaces whose accept_ra meridian-up.sh set to 2
// (host state, not a bundle file; removed by withdraw and by a failed first
// install's compensation).
const RAState = "/var/lib/meridian/node/ra-accept"

// fwCompatCommands runs meridian-fwcompat.sh apply when the bundle has it.
const fwCompatCommands = `if [ -x ` + FWCompatPath + ` ]; then
  if ! ` + FWCompatPath + ` apply; then
    echo "meridian-fwcompat-failed: the host's FORWARD policy drops tunnel traffic and Meridian's DOCKER-USER rules could not be ensured; forwarding not enabled, tunnels not brought up" >&2
    exit 1
  fi
fi
`

// forwardingCommands turns forwarding on from /etc/meridian/forwarding.conf.
// It runs after nftLoadCommands, so on the gateway the guard is already
// verified. The global keys must succeed; a per-interface key may be skipped
// (a wrong interface name must not abort the rest).
func forwardingCommands() string {
	return `MERIDIAN_FWD=/etc/meridian/forwarding.conf
if [ ! -f "$MERIDIAN_FWD" ]; then
  echo "meridian-forwarding-missing: $MERIDIAN_FWD not found; forwarding left as is" >&2
  exit 1
fi
while IFS= read -r line; do
  case "$line" in ''|'#'*) continue ;; esac
  case "$line" in
    net.ipv4.ip_forward=*|net.ipv6.conf.all.forwarding=*)
      if ! sysctl -w "$line" >/dev/null; then
        echo "meridian-forwarding-failed: $line" >&2
        exit 1
      fi ;;
    *) sysctl -w "$line" >/dev/null 2>&1 || echo "skip sysctl: $line" >&2 ;;
  esac
done < "$MERIDIAN_FWD"
`
}

// nftLoadCommands loads the firewall first, before sysctl turns forwarding
// on and before policy routes exist. The rendered meridian.nft is a single
// atomic batch (see writeAtomicReplace), so there is no separate delete:
// either the kernel commits every table in the file or it keeps the old
// ones. The batch is checked with nft -c first. Any failure stops the
// script here, so routes and forwarding are not touched on top of a
// ruleset that did not load. On the gateway a missing file or a missing
// guard table after the load is also a failure: forwarding must not be
// turned on without the LAN guard.
//
// On the gateway the last chnroute batch the list update loaded
// (lists.SavedBatchPath) is appended to the ruleset before the check, so a
// reload does not leave chnroute empty until the next update. The saved
// file may only hold "flush set" / "add element" lines for the two
// chnroute sets; a file with anything else, or a combination nft -c
// rejects, is ignored and the compiled ruleset alone is checked and loaded.
func nftLoadCommands(gateway bool) string {
	var sb strings.Builder
	sb.WriteString("MERIDIAN_NFT=/etc/nftables.d/meridian.nft\n")
	if gateway {
		sb.WriteString(chnrouteReaddCommands)
	}
	sb.WriteString("if [ -f \"$MERIDIAN_NFT\" ]; then\n")
	sb.WriteString("  if ! nft -c -f \"$MERIDIAN_NFT\"; then\n")
	sb.WriteString("    echo \"meridian-nft-check-failed: running ruleset left unchanged; routes and forwarding not touched\" >&2\n")
	sb.WriteString("    exit 1\n")
	sb.WriteString("  fi\n")
	sb.WriteString("  if ! nft -f \"$MERIDIAN_NFT\"; then\n")
	sb.WriteString("    echo \"meridian-nft-load-failed: the batch was aborted as a whole; previous Meridian tables kept; routes and forwarding not touched\" >&2\n")
	sb.WriteString("    exit 1\n")
	sb.WriteString("  fi\n")
	if gateway {
		fmt.Fprintf(&sb, "  if ! nft list table inet %s >/dev/null 2>&1; then\n", tableGuard)
		fmt.Fprintf(&sb, "    echo \"meridian-guard-missing: inet %s is not loaded; refusing to enable forwarding\" >&2\n", tableGuard)
		sb.WriteString("    exit 1\n")
		sb.WriteString("  fi\n")
		sb.WriteString("else\n")
		sb.WriteString("  echo \"meridian-nft-missing: $MERIDIAN_NFT not found; refusing to enable forwarding without the LAN guard\" >&2\n")
		sb.WriteString("  exit 1\n")
	}
	sb.WriteString("fi\n")
	return sb.String()
}

func renderFailoverUnit() string {
	return `[Unit]
Description=Meridian tunnel failover
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/sbin/meridian-failover.sh
Restart=always
RestartSec=2

[Install]
WantedBy=multi-user.target
`
}

// SmartDNSUnit runs an exit's resolver: the panel-delivered SmartDNS
// binary (artifacts.HostPath) with the bundle's /etc/smartdns/smartdns.conf.
// It is a Meridian unit of the bundle (manifest-owned, removed by a
// withdraw); the distribution's smartdns package and smartdns.service are
// not used on remote nodes. The config binds only tunnel addresses, which
// exist once the WireGuard interfaces are up: before that the bind fails
// and systemd retries; meridian-up.sh restarts it after the interfaces.
// No pid file (-p -), log to the journal (-x, foreground -f).
const SmartDNSUnit = "meridian-smartdns.service"

func renderSmartDNSUnit() string {
	return fmt.Sprintf(`# Meridian exit resolver (panel-delivered SmartDNS %s).
[Unit]
Description=Meridian exit resolver (SmartDNS bound to tunnel addresses only)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=%s -f -x -p - -c /etc/smartdns/smartdns.conf
Restart=always
RestartSec=5
NoNewPrivileges=yes

[Install]
WantedBy=multi-user.target
`, artifacts.Version(artifacts.SmartDNS), artifacts.HostPath(artifacts.SmartDNS))
}

func systemdUnit(desc, exec string) string {
	return fmt.Sprintf(`[Unit]
Description=%s
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=%s
Restart=always
RestartSec=2

[Install]
WantedBy=multi-user.target
`, desc, exec)
}

// chnrouteReaddCommands builds the ruleset with the saved chnroute
// elements (see nftLoadCommands). It only changes which file
// MERIDIAN_NFT names; the check and the load stay the single nft -c / nft -f
// pair below it.
const chnrouteReaddCommands = `MERIDIAN_NFT_BASE="$MERIDIAN_NFT"
MERIDIAN_CHNROUTE_SAVED=/var/lib/meridian/lists/chnroute.nft
if [ -f "$MERIDIAN_NFT_BASE" ] && [ -s "$MERIDIAN_CHNROUTE_SAVED" ]; then
  if grep -qvE '^(flush set inet meridian chnroute6?|add element inet meridian chnroute6? \{ [0-9A-Fa-f.:/]+(, [0-9A-Fa-f.:/]+)* \})$' "$MERIDIAN_CHNROUTE_SAVED"; then
    echo "meridian-chnroute-saved-ignored: $MERIDIAN_CHNROUTE_SAVED has unexpected lines; chnroute stays empty until the next list update" >&2
  elif cat "$MERIDIAN_NFT_BASE" "$MERIDIAN_CHNROUTE_SAVED" > /var/lib/meridian/lists/.boot.nft; then
    MERIDIAN_NFT=/var/lib/meridian/lists/.boot.nft
    if ! nft -c -f "$MERIDIAN_NFT"; then
      echo "meridian-chnroute-saved-ignored: the saved chnroute elements do not load with this ruleset; loading the compiled ruleset alone" >&2
      MERIDIAN_NFT="$MERIDIAN_NFT_BASE"
    fi
  fi
fi
`
