package validate

import (
	"encoding/base64"
	"fmt"
	"net"
	"net/netip"
	"regexp"
	"strconv"
	"strings"

	"github.com/radowitz/meridian/internal/model"
)

// Remote access (docs/architecture.md「远程接入」). The device pools must be
// provably disjoint from every prefix the gateway already routes or
// classifies, and the listen port from every port the compiler makes the
// gateway bind.

// Fixed ports the remote-access listen port may never take: SSH, DNS, DoT,
// DHCP (v4 and v6 client/server), NTP and mDNS.
var remoteFixedPorts = map[int]string{
	22: "SSH", 53: "DNS", 67: "DHCP", 68: "DHCP", 123: "NTP",
	546: "DHCPv6", 547: "DHCPv6", 853: "DoT", 5353: "mDNS",
}

// Planned address blocks the pools must not touch, whatever the topology says.
var (
	remoteTunnelV4 = netip.MustParsePrefix("10.66.0.0/16")
	remoteTransit4 = netip.MustParsePrefix("10.66.200.0/24")
	remoteMeshV4   = netip.MustParsePrefix("169.254.66.0/30")
	remoteCFV4     = netip.MustParsePrefix("100.96.0.0/12")
	remoteTunnelV6 = netip.MustParsePrefix("fd66::/48")
	remoteTransit6 = netip.MustParsePrefix("fd66:0:0:ff::/64")
	rfc1918        = []netip.Prefix{
		netip.MustParsePrefix("10.0.0.0/8"),
		netip.MustParsePrefix("172.16.0.0/12"),
		netip.MustParsePrefix("192.168.0.0/16"),
	}
	ulaRange = netip.MustParsePrefix("fc00::/7")
	hostRe   = regexp.MustCompile(`^([A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)*[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?$`)
	deviceRe = regexp.MustCompile(`^[a-z][a-z0-9-]{1,40}$`)
	storeRe  = regexp.MustCompile(`^[a-z][a-z0-9-]{1,63}$`)
)

// GatewayPorts lists every UDP/TCP port the compiler makes the gateway bind
// or reserve, with the reason: the ports TunnelPorts gives the links the
// gateway is an end of (compile.buildTunnels takes them from there) plus
// the gateway's WSS listen port and the panel port. A compile test checks
// that every port in the compiled gateway files is in this map.
func GatewayPorts(t model.Topology) map[int]string {
	out := map[int]string{}
	gw := firstRole(t, model.RoleGateway)
	for _, lp := range TunnelPorts(t) {
		if gw.ID == "" || (lp.Listener != gw.ID && lp.Dialer != gw.ID) {
			continue
		}
		out[lp.WG] = "隧道 " + lp.LinkID + " 的 WireGuard 端口"
		if lp.WSSLeg != 0 {
			out[lp.WSSLeg] = "隧道 " + lp.LinkID + " 的 WSS 腿端口"
		}
		if lp.Local != 0 {
			out[lp.Local] = "隧道 " + lp.LinkID + " 的 wstunnel 本地端口"
		}
	}
	if gw.WSSListenPort > 0 {
		out[gw.WSSListenPort] = "网关的 WSS 监听端口"
	}
	out[PanelPort(t)] = "面板端口"
	return out
}

// PanelPort is the panel's TCP port (settings.panel_bind, default 8787),
// the same value compile uses for the input chain.
func PanelPort(t model.Topology) int {
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

// CheckRemoteAccess validates the remote-access block when it is enabled.
// A disabled block is not compiled and is only checked by the API (through
// CheckRemoteAccessConfig) when it is edited.
func CheckRemoteAccess(t model.Topology) []Issue {
	if !t.RemoteAccess.Active() {
		return nil
	}
	return CheckRemoteAccessConfig(t)
}

// CheckRemoteAccessConfig checks the whole block as if it were enabled
// (key presence only when it is). Every issue carries a field, and device
// issues the device ID.
func CheckRemoteAccessConfig(t model.Topology) []Issue {
	ra := t.RemoteAccess
	if ra == nil {
		return nil
	}
	var out []Issue
	add := func(code, field, dev, format string, a ...any) {
		out = append(out, Issue{Code: code, Severity: SeverityError, Field: field, DeviceID: dev, Message: fmt.Sprintf(format, a...)})
	}
	if or(t.Settings.LANInterface, "eth0") == model.RemoteAccessIface {
		add("remote_lan_interface", "lan_interface", "", "局域网接口不能叫 %s：这个名字留给远程接入接口。", model.RemoteAccessIface)
	}
	// Endpoint.
	ep := strings.TrimSpace(ra.Endpoint)
	switch {
	case ep == "":
		add("remote_endpoint", "endpoint", "", "需要填写设备在外面拨的 Endpoint（DDNS 域名或公网地址）；面板不猜测公网地址。")
	case !ValidEndpointHost(ep):
		add("remote_endpoint", "endpoint", "", "Endpoint 只能是域名、IPv4 或 IPv6 地址，不带端口和空格。")
	default:
		if a, err := netip.ParseAddr(ep); err == nil && (a.IsPrivate() || a.IsLoopback() || a.IsLinkLocalUnicast() || a.IsUnspecified()) {
			out = append(out, Issue{Code: "remote_endpoint_private", Severity: SeverityWarning, Field: "endpoint",
				Message: "Endpoint 是私有或本机地址，设备在家外面拨不到它；只适合在局域网里试连。"})
		}
	}
	// Port.
	switch p := ra.ListenPort; {
	case p == 0:
		add("remote_port", "listen_port", "", "需要填写监听端口（UDP），路由器把同一个端口转发到网关。")
	case p < 1 || p > 65535:
		add("remote_port", "listen_port", "", "监听端口必须在 1–65535 之间。")
	default:
		if why, ok := remoteFixedPorts[p]; ok {
			add("remote_port_conflict", "listen_port", "", "端口 %d 已被 %s 使用。", p, why)
		} else if why, ok := GatewayPorts(t)[p]; ok {
			add("remote_port_conflict", "listen_port", "", "端口 %d 与%s冲突。", p, why)
		}
	}
	if m := ra.MTU; m != 0 && (m < 1280 || m > 1420) {
		add("remote_mtu", "mtu", "", "MTU 必须在 1280–1420 之间（默认 %d）。", model.DefaultRemoteMTU)
	}
	if k := ra.Keepalive; k < 0 || k > 600 {
		add("remote_keepalive", "keepalive", "", "保活间隔必须在 0–600 秒之间（0 表示默认 %d）。", model.DefaultRemoteKeepalive)
	}
	// Gateway key.
	if ra.PublicKey != "" && !validKey(ra.PublicKey) {
		add("remote_key", "public_key", "", "网关远程接入公钥格式不正确。")
	}
	if ra.KeyID != "" && !storeRe.MatchString(ra.KeyID) {
		add("remote_key", "key_id", "", "网关远程接入私钥的存储 ID 不合法。")
	}
	if ra.Enabled && (ra.PublicKey == "" || ra.KeyID == "") {
		add("remote_key", "public_key", "", "远程接入还没有网关密钥；经 /api/remote-access 保存设置时会生成。")
	}
	// Pools.
	p4, ok4 := checkRemoteV4(t, ra, add)
	p6, ok6 := checkRemoteV6(t, ra, add)
	// Devices.
	if len(ra.Devices) > model.MaxRemoteDevices {
		add("remote_device_limit", "devices", "", "最多 %d 台设备。", model.MaxRemoteDevices)
	}
	ids, keys, a4s, a6s := map[string]bool{}, map[string]string{}, map[netip.Addr]string{}, map[netip.Addr]string{}
	gw4, _, _ := ra.GatewayV4()
	gw6, _, _ := ra.GatewayV6()
	for _, d := range ra.Devices {
		if !deviceRe.MatchString(d.ID) || ids[d.ID] {
			add("remote_device", "id", d.ID, "设备 ID 为空、不合法或重复：%q", d.ID)
		}
		ids[d.ID] = true
		if n := strings.TrimSpace(d.Name); n == "" || len([]rune(n)) > 64 || strings.ContainsAny(n, "\r\n") {
			add("remote_device", "name", d.ID, "设备名称不能为空、不能换行，最长 64 个字符。")
		}
		if d.Mode != model.RemoteModeFull && d.Mode != model.RemoteModeHome {
			add("remote_device", "mode", d.ID, "模式只能是 full（全隧道）或 home（仅家网）。")
		}
		switch {
		case !validKey(d.PublicKey):
			add("remote_device", "public_key", d.ID, "设备 %s 的公钥格式不正确。", d.ID)
		case d.PublicKey == ra.PublicKey:
			add("remote_device", "public_key", d.ID, "设备公钥不能和网关公钥相同。")
		case keys[d.PublicKey] != "":
			add("remote_device", "public_key", d.ID, "设备 %s 与 %s 的公钥相同。", d.ID, keys[d.PublicKey])
		default:
			keys[d.PublicKey] = d.ID
		}
		if d.PSKID != "" && !storeRe.MatchString(d.PSKID) {
			add("remote_device", "psk_id", d.ID, "预共享密钥的存储 ID 不合法。")
		}
		if a, err := netip.ParseAddr(d.IPv4); err != nil || !a.Is4() {
			add("remote_device", "ipv4", d.ID, "设备 IPv4 地址无法解析：%q", d.IPv4)
		} else if ok4 {
			last := lastAddr(p4)
			switch {
			case !p4.Contains(a) || a == p4.Addr() || a == last || a == gw4:
				add("remote_device", "ipv4", d.ID, "设备地址 %s 不在 %s 的可用主机地址里（网络地址、广播地址和网关 %s 除外）。", a, p4, gw4)
			case a4s[a] != "":
				add("remote_device", "ipv4", d.ID, "设备地址 %s 已分给 %s。", a, a4s[a])
			default:
				a4s[a] = d.ID
			}
		}
		if a, err := netip.ParseAddr(d.IPv6); err != nil || !a.Is6() || a.Is4In6() {
			add("remote_device", "ipv6", d.ID, "设备 IPv6 地址无法解析：%q", d.IPv6)
		} else if ok6 {
			switch {
			case !p6.Contains(a) || a == p6.Addr() || a == gw6:
				add("remote_device", "ipv6", d.ID, "设备地址 %s 不在 %s 里（网络地址和网关 %s 除外）。", a, p6, gw6)
			case a6s[a] != "":
				add("remote_device", "ipv6", d.ID, "设备地址 %s 已分给 %s。", a, a6s[a])
			default:
				a6s[a] = d.ID
			}
		}
	}
	return out
}

type addFn func(code, field, dev, format string, a ...any)

func checkRemoteV4(t model.Topology, ra *model.RemoteAccess, add addFn) (netip.Prefix, bool) {
	raw := ra.V4Prefix()
	p, err := netip.ParsePrefix(raw)
	if err != nil || !p.Addr().Is4() {
		add("remote_prefix", "ipv4_prefix", "", "设备 IPv4 地址池无法解析：%q", raw)
		return netip.Prefix{}, false
	}
	if p != p.Masked() {
		add("remote_prefix", "ipv4_prefix", "", "设备 IPv4 地址池要写成网络地址，例如 %s。", p.Masked())
		return netip.Prefix{}, false
	}
	if p.Bits() < 16 || p.Bits() > 29 {
		add("remote_prefix", "ipv4_prefix", "", "设备 IPv4 地址池长度必须在 /16 到 /29 之间。")
		return netip.Prefix{}, false
	}
	private := false
	for _, r := range rfc1918 {
		private = private || (r.Bits() <= p.Bits() && r.Contains(p.Addr()))
	}
	if !private {
		add("remote_prefix", "ipv4_prefix", "", "设备 IPv4 地址池必须在 10.0.0.0/8、172.16.0.0/12 或 192.168.0.0/16 里。")
		return netip.Prefix{}, false
	}
	type named struct {
		p    netip.Prefix
		what string
	}
	var others []named
	if lan, err := netip.ParsePrefix(lanPrefix(t)); err == nil {
		others = append(others, named{lan.Masked(), "局域网 " + lan.Masked().String()})
	}
	others = append(others,
		named{remoteTunnelV4, "隧道地址规划 10.66.0.0/16"},
		named{remoteTransit4, "中转前缀 10.66.200.0/24"},
		named{remoteMeshV4, "Mesh 169.254.66.0/30"},
		named{remoteCFV4, "Cloudflare 100.96.0.0/12"},
	)
	if t.Settings.TransitV4Prefix != "" {
		if tp, err := netip.ParsePrefix(t.Settings.TransitV4Prefix); err == nil {
			others = append(others, named{tp.Masked(), "中转前缀 " + tp.Masked().String()})
		}
	}
	host := func(s, what string) {
		if a, err := netip.ParseAddr(hostOf(s)); err == nil && a.Is4() {
			others = append(others, named{netip.PrefixFrom(a, 32), what + " " + a.String()})
		}
	}
	host(t.Settings.ROSIPv4, "ROS 地址")
	host(t.Settings.GatewayLANIP, "网关局域网地址")
	for _, n := range t.Nodes {
		host(n.EndpointV4, "节点 "+n.ID+" 的端点")
		host(n.LANIPv4, "节点 "+n.ID+" 的局域网地址")
	}
	for _, l := range t.Links {
		host(l.FromV4, "链路 "+l.ID+" 的隧道地址")
		host(l.ToV4, "链路 "+l.ID+" 的隧道地址")
		for _, r := range l.MeshRoutes {
			if mp, err := netip.ParsePrefix(r); err == nil && mp.Addr().Is4() {
				others = append(others, named{mp.Masked(), "链路 " + l.ID + " 的 Mesh 路由 " + mp.Masked().String()})
			}
		}
	}
	others = append(others, ruleCIDRs(t, true, func(p netip.Prefix, what string) named { return named{p, what} })...)
	for _, o := range others {
		if o.p.IsValid() && o.p.Overlaps(p) {
			add("remote_prefix_conflict", "ipv4_prefix", "", "设备 IPv4 地址池 %s 与%s重叠。", p, o.what)
			return p, false
		}
	}
	return p, true
}

func checkRemoteV6(t model.Topology, ra *model.RemoteAccess, add addFn) (netip.Prefix, bool) {
	raw := ra.V6Prefix()
	p, err := netip.ParsePrefix(raw)
	if err != nil || !p.Addr().Is6() || p.Addr().Is4In6() {
		add("remote_prefix", "ipv6_prefix", "", "设备 IPv6 地址池无法解析：%q", raw)
		return netip.Prefix{}, false
	}
	if p != p.Masked() {
		add("remote_prefix", "ipv6_prefix", "", "设备 IPv6 地址池要写成网络地址，例如 %s。", p.Masked())
		return netip.Prefix{}, false
	}
	if p.Bits() < 48 || p.Bits() > 120 {
		add("remote_prefix", "ipv6_prefix", "", "设备 IPv6 地址池长度必须在 /48 到 /120 之间（建议 /64）。")
		return netip.Prefix{}, false
	}
	if !ulaRange.Contains(p.Addr()) {
		add("remote_prefix", "ipv6_prefix", "", "设备 IPv6 地址池必须是 ULA（fc00::/7）；网关对它做地址改写，不占用运营商前缀。")
		return netip.Prefix{}, false
	}
	type named struct {
		p    netip.Prefix
		what string
	}
	others := []named{{remoteTunnelV6, "隧道 ULA fd66::/48"}, {remoteTransit6, "中转前缀 fd66:0:0:ff::/64"}}
	for _, v := range []struct{ s, what string }{
		{t.Settings.ULAPrefix, "隧道 ULA"},
		{t.Settings.LANIPv6Prefix, "局域网 IPv6 前缀"},
		{t.Settings.TransitV6Prefix, "中转前缀"},
		{t.Settings.NAT64.Prefix, "NAT64 前缀"},
	} {
		if v.s == "" {
			continue
		}
		if q, err := netip.ParsePrefix(v.s); err == nil {
			others = append(others, named{q.Masked(), v.what + " " + q.Masked().String()})
		}
	}
	host := func(s, what string) {
		if a, err := netip.ParseAddr(hostOf(s)); err == nil && a.Is6() {
			others = append(others, named{netip.PrefixFrom(a, 128), what + " " + a.String()})
		}
	}
	host(t.Settings.ROSv6LLA, "ROS 链路本地地址")
	for _, n := range t.Nodes {
		host(n.EndpointV6, "节点 "+n.ID+" 的端点")
	}
	for _, l := range t.Links {
		host(l.FromULA, "链路 "+l.ID+" 的隧道地址")
		host(l.ToULA, "链路 "+l.ID+" 的隧道地址")
		for _, r := range l.MeshRoutes {
			if mp, err := netip.ParsePrefix(r); err == nil && mp.Addr().Is6() {
				others = append(others, named{mp.Masked(), "链路 " + l.ID + " 的 Mesh 路由 " + mp.Masked().String()})
			}
		}
	}
	others = append(others, ruleCIDRs(t, false, func(p netip.Prefix, what string) named { return named{p, what} })...)
	for _, o := range others {
		if o.p.IsValid() && o.p.Overlaps(p) {
			add("remote_prefix_conflict", "ipv6_prefix", "", "设备 IPv6 地址池 %s 与%s重叠。", p, o.what)
			return p, false
		}
	}
	return p, true
}

// ruleCIDRs lists the CIDR rules of one family: a pool inside a rule's
// destination would be steered by it.
func ruleCIDRs[T any](t model.Topology, v4 bool, mk func(netip.Prefix, string) T) []T {
	var out []T
	for _, r := range t.Rules {
		if r.MatchType != model.MatchCIDR {
			continue
		}
		var p netip.Prefix
		if q, err := netip.ParsePrefix(r.MatchValue); err == nil {
			p = q.Masked()
		} else if a, err := netip.ParseAddr(r.MatchValue); err == nil {
			p = netip.PrefixFrom(a, a.BitLen())
		} else {
			continue
		}
		if p.Addr().Is4() == v4 {
			out = append(out, mk(p, "规则 "+r.ID+" 的 CIDR "+p.String()))
		}
	}
	return out
}

func lastAddr(p netip.Prefix) netip.Addr {
	a := p.Masked().Addr().As4()
	host := uint32(1)<<(32-p.Bits()) - 1
	v := uint32(a[0])<<24 | uint32(a[1])<<16 | uint32(a[2])<<8 | uint32(a[3])
	v |= host
	return netip.AddrFrom4([4]byte{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)})
}

// ValidEndpointHost reports whether s is a DNS name or an IP literal
// (no port, no brackets, no spaces).
func ValidEndpointHost(s string) bool {
	if s == "" || len(s) > 253 {
		return false
	}
	if a, err := netip.ParseAddr(s); err == nil {
		return a.Zone() == "" && !a.Is4In6()
	}
	if strings.Contains(s, ":") {
		return false
	}
	return hostRe.MatchString(s)
}

func validKey(s string) bool {
	if len(s) != 44 {
		return false
	}
	raw, err := base64.StdEncoding.DecodeString(s)
	return err == nil && len(raw) == 32
}
