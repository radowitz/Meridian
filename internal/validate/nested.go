package validate

import (
	"fmt"
	"net/netip"
	"regexp"
	"strings"

	"github.com/radowitz/meridian/internal/model"
)

// Nested exits (behind a relay exit) and external SOCKS exits
// (model.ExternalExit). What this version compiles is checked here; every
// shape it cannot compile soundly is refused by name.
//
// Nested exit N with relay exit R:
//   - N dials out (nat_dial_out), has IPv4 on the path (the transit and
//     tunnel addresses it is reached on are IPv4/ULA inside the tunnels),
//     and exactly one enabled, non-standby tunnel link: direct_wg N → R.
//     It has no tunnel to a hub, no Mesh edge, no v6 workaround and is not
//     itself a dual-stack relay or a relay exit (one level only).
//   - R is a managed exit that is neither nested nor external, listens for
//     N at its endpoint (endpoint_v4, or endpoint_host for a dynamic name),
//     and reaches every hub through its own tunnels (with a backup hub:
//     both, checked for R as for any exit).
//
// External exit X with carrier C:
//   - X is an unmanaged exit with no links, no server, no endpoints, no
//     IPv6 egress (the proxy is TCP over IPv4 only), not nat_dial_out,
//     not nested, not a relay and not a carrier.
//   - C is a managed exit that is neither nested nor external.
//   - The proxy address is an IPv4 address outside Meridian's ranges, the
//     port 1–65535, the interface a valid name, the credential a valid id
//     (its existence in the store is checked where the store is known:
//     saving and installing).

var hostnameRe = regexp.MustCompile(`^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]([a-z0-9-]{0,61}[a-z0-9])?$`)

// validDynamicHost reports whether s is a DNS name usable as a WireGuard
// Endpoint host (lower case, at least two labels, no trailing dot, not an
// IP literal: an address belongs in endpoint_v4).
func validDynamicHost(s string) bool { return len(s) <= 253 && hostnameRe.MatchString(s) }

func checkNestedExternal(t model.Topology, nodes map[string]model.Node) []Issue {
	var out []Issue
	add := func(code, nodeID, linkID, field, format string, a ...any) {
		out = append(out, Issue{Code: code, Severity: SeverityError, NodeID: nodeID, ExitID: nodeID, LinkID: linkID, Field: field, Message: fmt.Sprintf(format, a...)})
	}
	carriers := map[string]bool{}
	for _, n := range t.Nodes {
		if model.IsExternal(n) {
			carriers[n.External.Carrier] = true
		}
	}
	for _, n := range t.Nodes {
		if n.EndpointHost != "" {
			switch {
			case n.Role != model.RoleExit || model.IsExternal(n):
				add("endpoint_host_not_exit", n.ID, "", "endpoint_host", "%s 填了动态域名端点（endpoint_host）。这一版只有受管出口可以用域名端点：网关和中继把端点地址写进路由和 nft，不能用域名。", n.Name)
			case !validDynamicHost(n.EndpointHost):
				add("bad_endpoint_host", n.ID, "", "endpoint_host", "%s 的动态域名端点 %q 不是合法的域名（小写字母、数字、短横线，至少两段，不带结尾的点）。", n.Name, n.EndpointHost)
			}
		}
		if n.Role != model.RoleExit {
			if n.ViaExit != "" {
				add("via_exit_not_exit", n.ID, "", "via_exit", "%s 不是出口，不能挂在中继出口后面（via_exit 只用于出口）。", n.Name)
			}
			if n.External != nil {
				add("external_not_exit", n.ID, "", "external", "%s 不是出口，不能设成外部 SOCKS 出口。", n.Name)
			}
			continue
		}
		if n.ViaExit != "" && n.External != nil {
			add("external_nested", n.ID, "", "via_exit", "%s 同时是外部出口和挂在中继出口后面的出口，只能二选一。外部出口经承载节点到达，不建隧道。", n.Name)
			continue
		}
		if n.ViaExit != "" {
			out = append(out, checkNested(t, nodes, n, carriers)...)
		}
		if n.External != nil {
			out = append(out, checkExternal(t, nodes, n)...)
		}
		if n.External == nil && n.ViaExit == "" && carriers[n.ID] && !n.Managed {
			add("external_carrier_unmanaged", n.ID, "", "managed", "%s 承载外部 SOCKS 出口，必须是受管出口：重定向器、解析组和健康探测都装在它上面。", n.Name)
		}
	}
	return out
}

func checkNested(t model.Topology, nodes map[string]model.Node, n model.Node, carriers map[string]bool) []Issue {
	var out []Issue
	add := func(code, linkID, field, format string, a ...any) {
		out = append(out, Issue{Code: code, Severity: SeverityError, NodeID: n.ID, ExitID: n.ID, LinkID: linkID, Field: field, Message: fmt.Sprintf(format, a...)})
	}
	r, ok := nodes[n.ViaExit]
	switch {
	case n.ViaExit == n.ID:
		add("via_exit_loop", "", "via_exit", "%s 的中继出口是它自己。", n.Name)
		return out
	case !ok:
		add("via_exit_not_found", "", "via_exit", "%s 的中继出口 %s 不存在。", n.Name, n.ViaExit)
		return out
	case r.Role != model.RoleExit:
		add("via_exit_not_exit", "", "via_exit", "%s 的中继出口 %s 不是出口。中继出口必须是一台受管出口（它自己也照常做地区组成员）。", n.Name, r.Name)
		return out
	}
	if r.ViaExit != "" {
		code := "via_exit_depth"
		if r.ViaExit == n.ID {
			code = "via_exit_loop"
		}
		add(code, "", "via_exit", "%s 的中继出口 %s 自己也挂在别的出口（%s）后面。这一版只支持一层中继：中继出口必须直接连枢纽。", n.Name, r.Name, r.ViaExit)
		return out
	}
	if model.IsExternal(r) {
		add("via_exit_external", "", "via_exit", "%s 的中继出口 %s 是外部 SOCKS 出口，不能转发隧道。", n.Name, r.Name)
		return out
	}
	if !r.Managed || !n.Managed {
		add("via_exit_unmanaged", "", "managed", "%s 和它的中继出口 %s 都必须是受管节点：两端的隧道、转发和回程规则都由面板下发。", n.Name, r.Name)
	}
	if len(model.NestedExitsOf(t, n.ID)) > 0 {
		add("via_exit_depth", "", "via_exit", "%s 挂在中继出口后面，又被别的出口当作中继出口。这一版只支持一层中继。", n.Name)
	}
	if carriers[n.ID] {
		add("external_carrier_nested", "", "external", "%s 挂在中继出口后面，不能再承载外部 SOCKS 出口（承载节点要直接连枢纽）。", n.Name)
	}
	if !n.NatDialOut {
		add("via_exit_not_dial_out", "", "nat_dial_out", "%s 挂在中继出口后面，必须是主动拨出的出口（nat_dial_out）：由它拨向中继出口，中继出口不去拨它。", n.Name)
	}
	if !n.PathV4 {
		add("via_exit_family", "", "path_v4", "%s 挂在中继出口后面，需要 path_v4：枢纽经中继出口到它的中转和隧道地址是 IPv4（以及隧道内的 ULA），纯 IPv6 的出口请用双栈中继。", n.Name)
	}
	if n.DualstackRelay || n.V6Workaround != model.WorkaroundNone {
		add("via_exit_workaround", "", "v6_workaround", "%s 挂在中继出口后面，不能同时是双栈中继或使用 v6 绕行。", n.Name)
	}
	if strings.TrimSpace(n.EndpointV4) != "" || strings.TrimSpace(n.EndpointV6) != "" || n.EndpointHost != "" {
		add("nat_endpoint_forbidden", "", "endpoint_v4", "%s 挂在中继出口后面，由它主动拨出，不能填写自己的端点。", n.Name)
	}
	if strings.TrimSpace(r.EndpointV4) == "" && r.EndpointHost == "" {
		add("via_exit_no_endpoint", "", "endpoint_v4", "%s 要拨向中继出口 %s，但 %s 没有可拨的端点：给它填 endpoint_v4（或动态域名 endpoint_host），并在它的主机上放行该链路的 WireGuard 端口。", n.Name, r.Name, r.Name)
	}
	// Exactly one tunnel link: direct_wg N → R, enabled and not standby.
	var good, other []model.Link
	for _, l := range t.Links {
		if l.From != n.ID && l.To != n.ID {
			continue
		}
		if !l.Enabled {
			continue
		}
		peer := l.To
		if peer == n.ID {
			peer = l.From
		}
		if l.Transport == model.TransportDirectWG && !l.Standby && peer == r.ID && l.From == n.ID {
			good = append(good, l)
			continue
		}
		other = append(other, l)
	}
	for _, l := range other {
		add("via_exit_link", l.ID, "", "%s 挂在中继出口 %s 后面，只能有一条到它的隧道（direct_wg，由 %s 指向 %s，启用、非待命）。链路 %s 不符合：到枢纽的隧道、Mesh 边、WSS 或别的出口都不能再接。", n.Name, r.Name, n.ID, r.ID, linkName(l))
	}
	switch {
	case len(good) == 0:
		add("via_exit_link", "", "", "%s 挂在中继出口 %s 后面，但还没有一条由 %s 指向 %s 的 direct_wg 链路（启用、非待命）。", n.Name, r.Name, n.ID, r.ID)
	case len(good) > 1:
		add("via_exit_link", good[1].ID, "", "%s 到中继出口 %s 有 %d 条链路，只能有一条。", n.Name, r.Name, len(good))
	}
	for _, l := range good {
		if l.Keepalive != nil && *l.Keepalive <= 0 {
			add("nat_keepalive_required", l.ID, "keepalive", "主动拨出必须开启 PersistentKeepalive（默认 25 秒）。")
		}
	}
	// The relay exit needs a tunnel to the primary hub (and to the backup,
	// which checkDualHub requires of every non-nested exit).
	if p := primaryHub(t); p.ID != "" && !hubTunnelTo(t, p.ID, r.ID) {
		add("via_exit_relay_unreachable", "", "via_exit", "中继出口 %s 没有到主枢纽 %s 的隧道（启用、非待命的 WireGuard）。挂在它后面的 %s 只能经它到达枢纽。", r.Name, p.Name, n.Name)
	}
	return out
}

func checkExternal(t model.Topology, nodes map[string]model.Node, n model.Node) []Issue {
	var out []Issue
	add := func(code, field, format string, a ...any) {
		out = append(out, Issue{Code: code, Severity: SeverityError, NodeID: n.ID, ExitID: n.ID, Field: field, Message: fmt.Sprintf(format, a...)})
	}
	x := n.External
	if n.Managed {
		add("external_managed", "managed", "%s 是外部 SOCKS 出口，不能标成受管：面板不登录这台设备，也不给它生成安装包。", n.Name)
	}
	if n.ServerID != "" || n.SSHHost != "" {
		add("external_has_server", "server_id", "%s 是外部 SOCKS 出口，不能关联服务器：面板从不登录它。", n.Name)
	}
	if n.NatDialOut || n.DualstackRelay || n.V6Workaround != model.WorkaroundNone || n.IXBound {
		add("external_flags", "nat_dial_out", "%s 是外部 SOCKS 出口：它不建隧道，nat_dial_out、双栈中继、v6 绕行和 ix_bound 都不适用。", n.Name)
	}
	if strings.TrimSpace(n.EndpointV4) != "" || strings.TrimSpace(n.EndpointV6) != "" || n.EndpointHost != "" || n.ListenPort != 0 || n.PublicKey != "" {
		add("external_endpoint", "endpoint_v4", "%s 是外部 SOCKS 出口，不能填写端点、监听端口或公钥：它只经承载节点上的 SOCKS 到达。", n.Name)
	}
	if n.EgressV6 {
		add("external_v6", "egress_v6", "%s 是外部 SOCKS 出口，这一版只承载 IPv4 的 TCP：egress_v6 必须关闭（发往它的域名不返回 AAAA，IPv6 流量被拒绝）。", n.Name)
	}
	if !n.EgressV4 {
		add("external_v4", "egress_v4", "%s 是外部 SOCKS 出口，需要 egress_v4：它承载的是 IPv4 的 TCP。", n.Name)
	}
	for _, l := range t.Links {
		if l.From == n.ID || l.To == n.ID {
			add("external_link", "", "%s 是外部 SOCKS 出口，不能有链路（%s）：它经承载节点上的 SOCKS 到达，面板不给它建隧道。", n.Name, linkName(l))
			break
		}
	}
	if len(model.NestedExitsOf(t, n.ID)) > 0 {
		add("via_exit_external", "via_exit", "%s 是外部 SOCKS 出口，不能当中继出口。", n.Name)
	}
	c, ok := nodes[x.Carrier]
	switch {
	case x.Carrier == "":
		add("external_carrier_missing", "external.carrier", "外部 SOCKS 出口 %s 没有承载节点：选一台能到达这个 SOCKS 的受管出口。", n.Name)
	case !ok:
		add("external_carrier_missing", "external.carrier", "外部 SOCKS 出口 %s 的承载节点 %s 不存在。", n.Name, x.Carrier)
	case x.Carrier == n.ID:
		add("external_carrier_not_exit", "external.carrier", "外部 SOCKS 出口 %s 不能承载它自己。", n.Name)
	case c.Role != model.RoleExit || model.IsExternal(c):
		add("external_carrier_not_exit", "external.carrier", "外部 SOCKS 出口 %s 的承载节点 %s 必须是一台受管出口（不是外部出口）。", n.Name, c.Name)
	case c.ViaExit != "":
		add("external_carrier_nested", "external.carrier", "外部 SOCKS 出口 %s 的承载节点 %s 挂在中继出口后面。承载节点必须直接连枢纽。", n.Name, c.Name)
	case !c.Managed:
		add("external_carrier_unmanaged", "external.carrier", "外部 SOCKS 出口 %s 的承载节点 %s 不是受管节点。", n.Name, c.Name)
	}
	a, err := netip.ParseAddr(strings.TrimSpace(x.SOCKSAddress))
	switch {
	case err != nil || !a.Is4():
		add("external_socks_address", "external.socks_address", "外部 SOCKS 出口 %s 的 SOCKS 地址必须是 IPv4 地址（承载节点看到的地址，通常在它已有的隧道上）。", n.Name)
	case a.IsLoopback() || a.IsUnspecified() || a.IsMulticast() || a.IsLinkLocalUnicast() || remoteTunnelV4.Contains(a):
		add("external_socks_address", "external.socks_address", "外部 SOCKS 出口 %s 的 SOCKS 地址 %s 不能是环回、未指定、组播、链路本地地址，也不能在 Meridian 的 10.66.0.0/16 里。", n.Name, a)
	default:
		if lan, err := netip.ParsePrefix(lanPrefix(t)); err == nil && lan.Contains(a) {
			add("external_socks_address", "external.socks_address", "外部 SOCKS 出口 %s 的 SOCKS 地址 %s 在家里的局域网 %s 里。", n.Name, a, lan.Masked())
		}
	}
	if x.SOCKSPort < 1 || x.SOCKSPort > 65535 {
		add("external_socks_port", "external.socks_port", "外部 SOCKS 出口 %s 的 SOCKS 端口 %d 不在 1–65535 之间。", n.Name, x.SOCKSPort)
	}
	if strings.TrimSpace(x.Interface) == "" {
		add("external_interface", "external.interface", "外部 SOCKS 出口 %s 需要填写承载节点上通往 SOCKS 的接口名（那条不由面板管理的隧道，例如 wg0）：承载节点只经这个接口连 SOCKS，接口没了就失败关闭，不会走它的默认路由。", n.Name)
	} else if iss := checkIface(x.Interface, "外部出口 "+n.Name+" 的承载接口"); iss != nil {
		iss.NodeID, iss.Field = n.ID, "external.interface"
		out = append(out, *iss)
	} else if ok && (x.Interface == nodeWANName(c) || strings.HasPrefix(x.Interface, "m") && tunnelIfaceName(x.Interface)) {
		add("external_interface", "external.interface", "外部 SOCKS 出口 %s 的承载接口 %s 是承载节点的 WAN 或 Meridian 自己的隧道接口。这里填那条不由面板管理、SOCKS 地址所在的隧道。", n.Name, x.Interface)
	}
	if !socksCredRe.MatchString(x.CredentialID) {
		add("external_credential_missing", "external.credential_id", "外部 SOCKS 出口 %s 没有选 SOCKS 凭据（用户名和密码只保存在受限的凭据存储里）。", n.Name)
	}
	return out
}

// socksCredRe is the id shape of a SOCKS credential (credentials.SOCKSIDPrefix).
var socksCredRe = regexp.MustCompile(`^socks-[a-z0-9]{4,40}$`)

// ValidSOCKSCredentialID reports whether id has the shape of a SOCKS
// credential id.
func ValidSOCKSCredentialID(id string) bool { return socksCredRe.MatchString(id) }

func nodeWANName(n model.Node) string {
	if n.WANInterface != "" {
		return n.WANInterface
	}
	return "eth0"
}

var meridianTunnelRe = regexp.MustCompile(`^m[0-9]{2,3}w?$`)

func tunnelIfaceName(s string) bool { return meridianTunnelRe.MatchString(s) }
