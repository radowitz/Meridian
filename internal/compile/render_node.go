package compile

import (
	"fmt"
	"strings"

	"github.com/radowitz/meridian/internal/model"
)

func renderBundleReadme(t model.Topology) string {
	return strings.TrimSpace(`
Meridian 生成的数据面配置。
地址若仍是 203.0.113.0/24、198.51.100.0/24、2001:db8::/32，说明这是示例，不能直接上线。
私钥占位符 __MERIDIAN_PRIVATE_KEY__ 会在装机时生成，不要写入 git。
ULA fd66::/48 只在隧道内转发，不要指向 ROS。
IX 替换用的 WSS 会随配置一起下发并做健康探测，但在替换模式关闭时不作为默认下一跳。
`) + "\nROS=" + t.Settings.ROSIPv4 + " 网关=" + t.Settings.GatewayLANIP + "\n"
}

func renderSysctl(t model.Topology, n model.Node) string {
	ifName := n.LANInterface
	if ifName == "" {
		ifName = n.WANInterface
	}
	if ifName == "" {
		ifName = t.Settings.LANInterface
	}
	if ifName == "" {
		ifName = "eth0"
	}
	var sb strings.Builder
	sb.WriteString("# Meridian forwarding. Does not flush other sysctls.\n")
	sb.WriteString("net.ipv4.ip_forward=1\n")
	sb.WriteString("net.ipv6.conf.all.forwarding=1\n")
	sb.WriteString("net.ipv4.conf.all.rp_filter=2\n")
	sb.WriteString("net.ipv4.conf.default.rp_filter=2\n")
	fmt.Fprintf(&sb, "net.ipv4.conf.%s.rp_filter=2\n", ifName)
	sb.WriteString("net.ipv4.conf.all.send_redirects=0\n")
	sb.WriteString("net.ipv4.conf.default.send_redirects=0\n")
	fmt.Fprintf(&sb, "net.ipv4.conf.%s.send_redirects=0\n", ifName)
	sb.WriteString("net.ipv6.conf.all.send_redirects=0\n")
	sb.WriteString("net.ipv6.conf.default.send_redirects=0\n")
	fmt.Fprintf(&sb, "net.ipv6.conf.%s.send_redirects=0\n", ifName)
	fmt.Fprintf(&sb, "net.ipv6.conf.%s.accept_redirects=0\n", ifName)
	sb.WriteString("net.ipv4.conf.all.accept_redirects=0\n")
	sb.WriteString("net.ipv6.conf.all.accept_redirects=0\n")
	sb.WriteString("net.ipv6.conf.default.accept_redirects=0\n")
	if n.Role == model.RoleGateway {
		// forwarding=1 ignores accept_ra unless it is 2. This host is a
		// SLAAC client of ROS and must not advertise its own prefix.
		fmt.Fprintf(&sb, "net.ipv6.conf.%s.accept_ra=2\n", ifName)
		fmt.Fprintf(&sb, "net.ipv6.conf.%s.forwarding=1\n", ifName)
		sb.WriteString("# Do not run radvd or a DHCP server on this LAN.\n")
	}
	return sb.String()
}

func renderRTTables(t model.Topology, n model.Node, exits []ExitPlan) string {
	var sb strings.Builder
	sb.WriteString("100\tmeridian_domestic\n")
	sb.WriteString("102\tmeridian_foreign\n")
	sb.WriteString("150\tmeridian_east\n")
	if n.Role == model.RoleHub {
		for _, e := range exits {
			fmt.Fprintf(&sb, "%d\tmeridian_%s\n", e.Table, strings.ReplaceAll(e.Node.ID, "-", "_"))
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
	if srv.EndpointV4 == "" {
		return ""
	}
	return fmt.Sprintf("%s:%d", srv.EndpointV4, tun.WGPort)
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

func renderUp(t model.Topology, n model.Node, tunnels []Tunnel) string {
	var sb strings.Builder
	sb.WriteString("#!/bin/bash\n")
	sb.WriteString("# Bring up Meridian on this host without flushing the rest of nftables.\n")
	sb.WriteString("# A bad line in sysctl is skipped so a wrong interface name cannot abort SSH.\n")
	sb.WriteString("set -euo pipefail\n")
	sb.WriteString("sysctl --system >/dev/null 2>&1 || true\n")
	sb.WriteString("if [ -f /etc/sysctl.d/99-meridian.conf ]; then\n")
	sb.WriteString("  while IFS= read -r line; do\n")
	sb.WriteString("    case \"$line\" in ''|'#'*) continue ;; esac\n")
	sb.WriteString("    sysctl -w \"$line\" >/dev/null 2>&1 || echo \"skip sysctl: $line\" >&2\n")
	sb.WriteString("  done < /etc/sysctl.d/99-meridian.conf\n")
	sb.WriteString("fi\n")
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
	sb.WriteString("shopt -s nullglob\n")
	sb.WriteString("for conf in /etc/wireguard/m*.conf; do\n")
	sb.WriteString("  iface=$(basename \"$conf\" .conf)\n")
	sb.WriteString("  if ip link show \"$iface\" >/dev/null 2>&1; then\n")
	sb.WriteString("    wg syncconf \"$iface\" <(wg-quick strip \"$conf\")\n")
	sb.WriteString("  else\n")
	sb.WriteString("    wg-quick up \"$conf\"\n")
	sb.WriteString("  fi\n")
	sb.WriteString("done\n")
	sb.WriteString("if [ -f /etc/nftables.d/meridian.nft ]; then\n")
	sb.WriteString("  nft -c -f /etc/nftables.d/meridian.nft\n")
	sb.WriteString("fi\n")
	sb.WriteString("/usr/local/sbin/meridian-routes.sh\n")
	sb.WriteString("if [ -f /etc/nftables.d/meridian.nft ]; then\n")
	sb.WriteString("  nft delete table inet meridian >/dev/null 2>&1 || true\n")
	sb.WriteString("  nft -f /etc/nftables.d/meridian.nft\n")
	sb.WriteString("fi\n")
	sb.WriteString("enable_unit() {\n")
	sb.WriteString("  if [ -d /run/systemd/system ] && command -v systemctl >/dev/null 2>&1; then\n")
	sb.WriteString("    systemctl enable --now \"$1\"\n")
	sb.WriteString("  fi\n")
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
	}
	if n.Role == model.RoleExit {
		sb.WriteString("enable_unit meridian-unlock.timer\n")
	}
	if n.Role != model.RoleGateway {
		sb.WriteString("if [ -x /usr/local/sbin/meridian-mesh-up.sh ]; then\n")
		sb.WriteString("  /usr/local/sbin/meridian-mesh-up.sh || echo \"mesh sidecar skipped\" >&2\n")
		sb.WriteString("fi\n")
	}
	sb.WriteString("echo meridian-up-complete\n")
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

func renderWstunnelServer(n model.Node, tunnels []Tunnel) string {
	var ports []int
	for _, tun := range tunnels {
		if tun.Mode != "wss" || tun.Listener().ID != n.ID {
			continue
		}
		ports = append(ports, tun.WGPort)
	}
	if len(ports) == 0 {
		return ""
	}
	listen := n.WSSListenPort
	if listen == 0 {
		listen = 443
	}
	prefix := n.WSSPathPrefix
	if prefix == "" {
		prefix = "example-wss-path-prefix"
	}
	cert := n.TLSCertPath
	key := n.TLSKeyPath
	if cert == "" {
		cert = "/etc/meridian/tls/fullchain.pem"
	}
	if key == "" {
		key = "/etc/meridian/tls/privkey.pem"
	}
	var args []string
	args = append(args, "server")
	for _, p := range ports {
		args = append(args, fmt.Sprintf("--restrict-to 127.0.0.1:%d", p))
	}
	args = append(args,
		"--restrict-http-upgrade-path-prefix "+prefix,
		"--tls-certificate "+cert,
		"--tls-private-key "+key,
		fmt.Sprintf("wss://0.0.0.0:%d", listen),
	)
	return systemdUnit(
		"Meridian wstunnel server (restrict-to local WireGuard, real certificate)",
		"/usr/local/bin/wstunnel "+strings.Join(args, " "),
	)
}

func renderWstunnelClient(tun Tunnel) string {
	srv := tun.Listener()
	prefix := srv.WSSPathPrefix
	if prefix == "" {
		prefix = "example-wss-path-prefix"
	}
	host := srv.EndpointV4
	if host == "" {
		host = "203.0.113.10"
	}
	port := srv.WSSListenPort
	if port == 0 {
		port = 443
	}
	exec := fmt.Sprintf(
		"/usr/local/bin/wstunnel client -L 'udp://127.0.0.1:%d:127.0.0.1:%d?timeout_sec=0' --http-upgrade-path-prefix %s --tls-verify-certificate wss://%s:%d",
		tun.ClientUDP, tun.WGPort, prefix, host, port,
	)
	return systemdUnit("Meridian wstunnel client for "+tun.LinkID+" ("+tun.Mode+")", exec)
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
