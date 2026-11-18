// Package validate enforces the design's path, transport, NAT, MTU, and rule checks.
package validate

import (
	"fmt"
	"net/netip"
	"regexp"
	"sort"
	"strings"

	"github.com/radowitz/meridian/internal/lists"
	"github.com/radowitz/meridian/internal/model"
	"github.com/radowitz/meridian/internal/mtu"
	rulesorder "github.com/radowitz/meridian/internal/ordered"
	"github.com/radowitz/meridian/internal/pool"
)

const (
	SeverityError   = "error"
	SeverityWarning = "warning"
)

type Issue struct {
	Code     string `json:"code"`
	Severity string `json:"severity"`
	Message  string `json:"message"`
	NodeID   string `json:"node_id,omitempty"`
	LinkID   string `json:"link_id,omitempty"`
	RuleID   string `json:"rule_id,omitempty"`
	ExitID   string `json:"exit_id,omitempty"`
	GroupID  string `json:"group_id,omitempty"`
	DeviceID string `json:"device_id,omitempty"`
	// Field names the offending group field (members, chosen, mode…).
	Field string `json:"field,omitempty"`
}

type PathReport struct {
	ExitID string   `json:"exit_id"`
	Nodes  []string `json:"nodes"`
	Links  []string `json:"links"`
	MTU    int      `json:"mtu"`
	MSS4   int      `json:"mss4"`
	MSS6   int      `json:"mss6"`
	// MeshLinks are the exit's Mesh legs (cf_mesh links from either hub)
	// that MTU counts besides Links: the hub may carry the exit over
	// one of them instead of its direct leg. Empty without a Mesh leg.
	MeshLinks []string `json:"mesh_links,omitempty"`
}

// GroupPathReport is the path MTU of one region group the hub switches
// (compile.GroupPlan.Dynamic): the smallest tunnel MTU over every path that
// can carry the group's mark, i.e. the paths of the members it may switch
// to (Members, their PathReport MTUs, each of which already counts the
// member's Mesh leg). Mesh says that some member has a Mesh leg (a
// WireGuard leg carried over the Cloudflare Mesh), MeshLinks which links
// those are and MeshMTU the smallest of their MTUs (GroupMeshHopMTU).
// MSS4/MSS6 are MTU-40/-60. Compile renders a per-mark clamp for the group
// from it when it is below the global clamp (only a member with a Mesh leg
// can make it so: such members are not part of the global floor); the
// adoption preview diffs it.
type GroupPathReport struct {
	GroupID   string   `json:"group_id"`
	Members   []string `json:"members"`
	Mesh      bool     `json:"mesh"`
	MeshLinks []string `json:"mesh_links,omitempty"`
	MeshMTU   int      `json:"mesh_mtu,omitempty"`
	MTU       int      `json:"mtu"`
	MSS4      int      `json:"mss4"`
	MSS6      int      `json:"mss6"`
}

// GroupMeshHopMTU is the smallest MTU of the Mesh legs between hub and the
// given members (hopMTU of a cf_mesh link: the Mesh path MTU minus the
// WireGuard overhead, MeshLegMTU), and the IDs of those links. 0 when there
// is none. The way from the gateway into hub is not part of it: it is the
// members' own path (their PathReport), which the group's MTU already
// takes the minimum over.
func GroupMeshHopMTU(t model.Topology, hub string, members []string) (int, []string) {
	in := map[string]bool{}
	for _, id := range members {
		in[id] = true
	}
	var links []model.Link
	var ids []string
	for _, l := range t.Links {
		if hub == "" || l.Transport != model.TransportCFMesh || !l.Enabled {
			continue
		}
		if p := peerOf(l, hub); p != "" && in[p] {
			links = append(links, l)
			ids = append(ids, l.ID)
		}
	}
	if len(links) == 0 {
		return 0, nil
	}
	return pathMTU(links), ids
}

type Result struct {
	Issues []Issue      `json:"issues"`
	Paths  []PathReport `json:"paths"`
}

func (r Result) HasErrors() bool {
	for _, iss := range r.Issues {
		if iss.Severity == SeverityError {
			return true
		}
	}
	return false
}

func Run(t model.Topology) Result {
	var out Result
	nodes := indexNodes(t)
	out.Issues = append(out.Issues, checkIDs(t)...)
	out.Issues = append(out.Issues, checkSettings(t)...)
	out.Issues = append(out.Issues, checkClientDNS(t)...)
	out.Issues = append(out.Issues, checkGroupResolver(t)...)
	out.Issues = append(out.Issues, checkLinks(t, nodes)...)
	out.Issues = append(out.Issues, checkNestedExternal(t, nodes)...)

	exits := exitsOf(t)
	if len(exits) == 0 {
		out.Issues = append(out.Issues, Issue{
			Code: SeverityCode("no_exit"), Severity: SeverityError,
			Message: "至少需要一个出口节点。",
		})
	}
	gw := firstRole(t, model.RoleGateway)
	for _, exit := range exits {
		if gw.ID == "" {
			break
		}
		if model.IsExternal(exit) {
			// An external exit has no links: its path is its carrier's,
			// reported with the exit appended (checkExternal refuses a
			// missing or unsuitable carrier).
			c, ok := nodes[exit.External.Carrier]
			if !ok || c.Role != model.RoleExit || model.IsExternal(c) {
				continue
			}
			path, links, ok := findExitPath(t, nodes, gw.ID, c)
			if !ok {
				continue
			}
			mtu := exitPathMTU(t, nodes, gw.ID, exit, links)
			report := PathReport{ExitID: exit.ID, Nodes: append(append([]string(nil), path...), exit.ID), MTU: mtu, MSS4: mtu - 40, MSS6: mtu - 60}
			for _, l := range links {
				report.Links = append(report.Links, l.ID)
			}
			out.Paths = append(out.Paths, report)
			continue
		}
		path, links, ok := findExitPath(t, nodes, gw.ID, exit)
		if !ok {
			any, _, anyOK := findAnyPath(t, gw.ID, exit.ID)
			if !anyOK {
				out.Issues = append(out.Issues, Issue{
					Code: "path_not_found", Severity: SeverityError, ExitID: exit.ID,
					Message: fmt.Sprintf("出口 %s 没有从网关出发的主路径。", exit.Name),
				})
			} else {
				out.Issues = append(out.Issues, checkPathRoles(t, nodes, any, exit)...)
			}
			out.Issues = append(out.Issues, checkPureV6(t, nodes, exit)...)
			continue
		}
		out.Issues = append(out.Issues, checkPathRoles(t, nodes, path, exit)...)
		out.Issues = append(out.Issues, checkPureV6(t, nodes, exit)...)
		carrying := exitPathLinks(t, nodes, gw.ID, exit, links)
		mtu := pathMTU(carrying)
		// A Mesh leg's own hop MTU (what the Mesh path leaves a WireGuard
		// leg) is below 1280 over the default Mesh path; checkMeshLegs
		// reports that (mesh_leg_fragments). Everything else on the path
		// must carry 1280.
		if rest := pathMTU(withoutMesh(carrying)); rest > 0 && rest < 1280 {
			out.Issues = append(out.Issues, Issue{
				Code: "mtu_too_low", Severity: SeverityError, ExitID: exit.ID,
				Message: fmt.Sprintf("到 %s 的路径 MTU 为 %d，低于 IPv6 最小 MTU 1280。", exit.Name, rest),
			})
		}
		report := PathReport{ExitID: exit.ID, MTU: mtu, MSS4: mtu - 40, MSS6: mtu - 60}
		for _, id := range path {
			report.Nodes = append(report.Nodes, id)
		}
		for _, l := range links {
			report.Links = append(report.Links, l.ID)
		}
		report.MeshLinks = meshLinkIDs(carrying, report.Links)
		out.Paths = append(out.Paths, report)
	}

	out.Issues = append(out.Issues, checkIXReplacement(t, nodes)...)
	out.Issues = append(out.Issues, checkHubs(t, nodes)...)
	out.Issues = append(out.Issues, checkDirect(t)...)
	out.Issues = append(out.Issues, checkRelayless(t)...)
	out.Issues = append(out.Issues, checkSharing(t, nodes)...)
	out.Issues = append(out.Issues, checkAllocations(t)...)
	out.Issues = append(out.Issues, checkMeshLegs(t, nodes)...)
	out.Issues = append(out.Issues, checkSubnets(t)...)
	out.Issues = append(out.Issues, checkLinkAddrReserved(t)...)
	out.Issues = append(out.Issues, checkIfaceNames(t)...)
	out.Issues = append(out.Issues, checkPorts(t)...)
	out.Issues = append(out.Issues, checkRules(t, nodes)...)
	out.Issues = append(out.Issues, checkRuleReachable(t)...)
	out.Issues = append(out.Issues, checkRuleSetsAndServices(t)...)
	out.Issues = append(out.Issues, checkSafe(t)...)
	out.Issues = append(out.Issues, CheckGroups(t)...)
	out.Issues = append(out.Issues, CheckRemoteAccess(t)...)
	out.Issues = append(out.Issues, checkSniff(t)...)
	out.Issues = append(out.Issues, checkDNSLog(t)...)
	out.Issues = append(out.Issues, checkExitDNS(t)...)
	if t.Settings.DefaultGroup == "" {
		out.Issues = append(out.Issues, Issue{
			Code: "no_default_exit", Severity: SeverityError, Field: "default_group",
			Message: "没有设置默认境外组（settings.default_group）。需要一个非住宅出口组（有 IX 时最好是 IX 绑定的出口组）。",
		})
	} else if g, ok := t.GroupByID(t.Settings.DefaultGroup); !ok {
		out.Issues = append(out.Issues, Issue{
			Code: "no_default_exit", Severity: SeverityError, GroupID: t.Settings.DefaultGroup, Field: "default_group",
			Message: fmt.Sprintf("默认境外组 %s 不存在。", t.Settings.DefaultGroup),
		})
	} else if _, ok := GroupTarget(t, g.ID); !ok {
		out.Issues = append(out.Issues, Issue{
			Code: "no_default_exit", Severity: SeverityError, GroupID: g.ID, Field: "default_group",
			Message: fmt.Sprintf("默认境外组 %s 里没有可选出口。", g.Name),
		})
	} else if !g.ExcludeResidential && !g.RequireResidential {
		for _, m := range pool.Select(t, g, nil).Members {
			if m.Eligible && m.Residential {
				out.Issues = append(out.Issues, Issue{
					Code: "residential_in_default_pool", Severity: SeverityWarning, GroupID: g.ID, NodeID: m.ID,
					Message: fmt.Sprintf("%s 是家宽，不应进默认境外组 %s。给组打开 exclude_residential，或把家宽放进单独的组。", m.Name, g.Name),
				})
			}
		}
	}
	sort.SliceStable(out.Issues, func(i, j int) bool {
		if out.Issues[i].Severity != out.Issues[j].Severity {
			return out.Issues[i].Severity == SeverityError
		}
		return out.Issues[i].Code < out.Issues[j].Code
	})
	return out
}

func SeverityCode(s string) string { return s }

func indexNodes(t model.Topology) map[string]model.Node {
	m := make(map[string]model.Node, len(t.Nodes))
	for _, n := range t.Nodes {
		m[n.ID] = n
	}
	return m
}

func checkIDs(t model.Topology) []Issue {
	var out []Issue
	seen := map[string]bool{}
	for _, n := range t.Nodes {
		if n.ID == "" || seen["n:"+n.ID] {
			out = append(out, Issue{Code: "duplicate_id", Severity: SeverityError, NodeID: n.ID, Message: "节点 ID 为空或重复。"})
		}
		seen["n:"+n.ID] = true
		if n.Role == model.RoleGateway && n.LANIPv4 != "" && t.Settings.ROSIPv4 != "" && hostOf(n.LANIPv4) == t.Settings.ROSIPv4 {
			out = append(out, Issue{
				Code: "gateway_is_ros", Severity: SeverityError, NodeID: n.ID,
				Message: "网关地址不能和 ROS（局域网路由器）的地址相同。",
			})
		}
	}
	for _, l := range t.Links {
		if l.ID == "" || seen["l:"+l.ID] {
			out = append(out, Issue{Code: "duplicate_id", Severity: SeverityError, LinkID: l.ID, Message: "链路 ID 为空或重复。"})
		}
		seen["l:"+l.ID] = true
	}
	return out
}

func checkSettings(t model.Topology) []Issue {
	var out []Issue
	if t.Settings.ULAPrefix == "" {
		t.Settings.ULAPrefix = "fd66::/48"
	}
	ula, err := netip.ParsePrefix(t.Settings.ULAPrefix)
	if err != nil || !ula.Addr().Is6() {
		return append(out, Issue{Code: "prefix_conflict", Severity: SeverityError, Message: "ULA 前缀无法解析，应为 fd66::/48。"})
	}
	if !strings.HasPrefix(strings.ToLower(t.Settings.ULAPrefix), "fd66:") {
		out = append(out, Issue{Code: "prefix_conflict", Severity: SeverityError, Message: "隧道 ULA 必须位于 fd66::/48，避免和运营商前缀或 ROS 黑洞策略混用。"})
	}
	if t.Settings.LANIPv6Prefix != "" {
		lan, err := netip.ParsePrefix(t.Settings.LANIPv6Prefix)
		if err != nil {
			out = append(out, Issue{Code: "prefix_conflict", Severity: SeverityError, Message: "局域网 IPv6 前缀无法解析。"})
		} else if ula.Overlaps(lan) {
			out = append(out, Issue{Code: "prefix_conflict", Severity: SeverityError, Message: "局域网 IPv6 前缀与 fd66 ULA 重叠。"})
		} else {
			out = append(out, checkLANIPv6(t, lan)...)
		}
	}
	out = append(out, checkLANIPv4(t)...)
	// The gateway LAN comes from the operator (first-run input or confirmed
	// detection); nothing falls back to a built-in network.
	if p, err := netip.ParsePrefix(strings.TrimSpace(t.Settings.GatewayLANIP)); err != nil || !p.Addr().Is4() {
		out = append(out, Issue{Code: "missing_gateway_lan", Severity: SeverityError, Field: "gateway_lan_ipv4",
			Message: "需要网关的局域网 IPv4 地址和前缀长度（例如 192.0.2.10/24），由首次配置填写或确认。"})
	}
	if t.Settings.ROSIPv4 == "" {
		out = append(out, Issue{Code: "missing_ros", Severity: SeverityError, Message: "需要 ROS（局域网路由器）的 IPv4 地址，国内流量下一跳指向它。"})
	} else if _, err := netip.ParseAddr(t.Settings.ROSIPv4); err != nil {
		out = append(out, Issue{Code: "bad_address", Severity: SeverityError, Message: "ROS IPv4 地址无法解析。"})
	}
	if t.Settings.LANIPv6Prefix != "" && (t.Settings.ROSv6LLA == "" || t.Settings.ROSv6LLA == "fe80::1") {
		out = append(out, Issue{
			Code: "ros_lla_placeholder", Severity: SeverityWarning,
			Message: "ROS 的 IPv6 链路本地地址还是占位 fe80::1。国内 IPv6 下一跳会走错，请改成 bridge 上的真实 fe80::。",
		})
	}
	if t.Settings.ROSv6LLA != "" {
		if ip, err := netip.ParseAddr(t.Settings.ROSv6LLA); err != nil || !ip.Is6() || !ip.IsLinkLocalUnicast() {
			out = append(out, Issue{Code: "bad_address", Severity: SeverityError, Message: "ROS 的 IPv6 下一跳必须是 fe80:: 链路本地地址。"})
		}
	}
	if iss := checkIface(t.Settings.LANInterface, "局域网接口"); iss != nil {
		out = append(out, *iss)
	}
	// settings.lan_interface is the only source for the gateway LAN NIC (nft
	// guard, routes, sysctls, LAN wait, verify script). A gateway node that
	// names a different NIC of its own would silently split them.
	lanIf := or(t.Settings.LANInterface, "eth0")
	for _, n := range t.Nodes {
		if n.Role == model.RoleGateway && n.LANInterface != "" && n.LANInterface != lanIf {
			out = append(out, Issue{
				Code: "lan_interface_mismatch", Severity: SeverityError, NodeID: n.ID,
				Message: fmt.Sprintf("网关节点 %s 的 lan_interface 是 %q，而 settings.lan_interface 是 %q。网关局域网口只以 settings.lan_interface 为准：把节点上的改成相同或留空。", n.Name, n.LANInterface, lanIf),
			})
		}
	}
	if t.Settings.UnlockIntervalSec > 0 && t.Settings.UnlockIntervalSec < 3600 {
		out = append(out, Issue{
			Code: "unlock_interval_short", Severity: SeverityWarning,
			Message: "解锁测试间隔小于 1 小时。定时失败要连续两次才换同池备选，间隔太短会把滞回提前用完。",
		})
	}
	if t.Settings.NAT64.Prefix != "" {
		p, err := netip.ParsePrefix(t.Settings.NAT64.Prefix)
		if err != nil || !p.Addr().Is6() || strings.ContainsAny(t.Settings.NAT64.Prefix, " \t\r\n'\"\\") {
			out = append(out, Issue{Code: "nat64_prefix", Severity: SeverityError, Message: "NAT64 前缀必须是一行合法的 IPv6 前缀，不能夹带别的路由命令。"})
		} else {
			ula, _ := netip.ParsePrefix(or(t.Settings.ULAPrefix, "fd66::/48"))
			if ula.IsValid() && p.Overlaps(ula) {
				out = append(out, Issue{Code: "nat64_prefix", Severity: SeverityError, Message: "NAT64 前缀不能和 fd66 ULA 重叠。"})
			}
			if t.Settings.LANIPv6Prefix != "" {
				if lan, err := netip.ParsePrefix(t.Settings.LANIPv6Prefix); err == nil && p.Overlaps(lan) {
					out = append(out, Issue{Code: "nat64_prefix", Severity: SeverityError, Message: "NAT64 前缀不能和局域网 IPv6 重叠。"})
				}
			}
		}
	}
	if t.Settings.NAT64.Enabled {
		if strings.TrimSpace(t.Settings.NAT64.Prefix) == "" {
			out = append(out, Issue{Code: "nat64_prefix", Severity: SeverityError, Message: "NAT64 已启用，但前缀不是合法的 IPv6 前缀。"})
		}
		out = append(out, Issue{
			Code: "nat64_not_installed", Severity: SeverityWarning,
			Message: "NAT64 只是预留。即使标成启用，这一期也不会把前缀装进路由表，现有 IPv4 路径保持原样。",
		})
	}
	if iss := checkImageRef(t.Settings.MeshImage, "mesh_image"); iss != nil {
		out = append(out, *iss)
	}
	if iss := checkImageRef(t.Settings.RegioncheckImage, "regioncheck_image"); iss != nil {
		out = append(out, *iss)
	}
	out = append(out, checkListSource(t)...)
	for _, n := range t.Nodes {
		if n.DualstackRelay && (!n.PathV4 || !n.PathV6) {
			out = append(out, Issue{
				Code: "relay_not_dualstack", Severity: SeverityError, NodeID: n.ID,
				Message: fmt.Sprintf("%s 标成了双栈中继，但 path_v4 或 path_v6 没有打开。枢纽用 v4 连它，纯 v6 出口用 v6 连它。", n.Name),
			})
		}
	}
	return out
}

func checkLinks(t model.Topology, nodes map[string]model.Node) []Issue {
	var out []Issue
	for _, l := range t.Links {
		a, aok := nodes[l.From]
		b, bok := nodes[l.To]
		if !aok || !bok {
			out = append(out, Issue{Code: "dangling_link", Severity: SeverityError, LinkID: l.ID, Message: "链路的一端不存在。"})
			continue
		}
		if l.MTU != 0 && l.MTU < 1280 {
			out = append(out, Issue{Code: "mtu_too_low", Severity: SeverityError, LinkID: l.ID, Message: fmt.Sprintf("链路 %s 的 MTU %d 低于 1280。", l.Name, l.MTU)})
		}
		if l.WSSMTU != 0 && l.WSSMTU < 1280 {
			out = append(out, Issue{Code: "mtu_too_low", Severity: SeverityError, LinkID: l.ID, Message: fmt.Sprintf("链路 %s 的 WSS MTU %d 低于 1280。", l.Name, l.WSSMTU)})
		}
		switch l.Transport {
		case model.TransportCFMesh:
			out = append(out, checkMesh(l, a, b, t.HasIX())...)
		case model.TransportIXReplacementWSS:
			out = append(out, checkReplacementLink(l, a, b)...)
		}
		out = append(out, checkNATLink(t, l, a, b)...)
		out = append(out, checkAddrConflicts(t, l)...)
	}
	return out
}

func checkMesh(l model.Link, a, b model.Node, hasIX bool) []Issue {
	var out []Issue
	if !l.Standby {
		out = append(out, Issue{
			Code: "mesh_not_standby", Severity: SeverityError, LinkID: l.ID, Field: "standby",
			Message: "Cloudflare Mesh 边是枢纽到出口的备用 WireGuard 腿（直连腿优先），要标为待命；它不能当主路，也不能当作 IX 的备路。纯 IPv6 出口选了 Mesh 绕行时它是唯一的一腿，同样标为待命。",
		})
	}
	if involves(a, b, model.RoleGateway) || involves(a, b, model.RoleRelay) {
		out = append(out, Issue{
			Code: "mesh_bypasses_ix", Severity: SeverityError, LinkID: l.ID,
			Message: "Mesh 不能从网关或中继直连境外，也不能绕过 IX。",
		})
		if !hasIX {
			out[len(out)-1].Message = "Mesh 只连枢纽和出口，不能从网关或中继直连境外，也不能绕过中继和主枢纽组成的主路径。"
		}
	}
	roles := map[model.Role]bool{a.Role: true, b.Role: true}
	if !(roles[model.RoleHub] && roles[model.RoleExit]) {
		out = append(out, Issue{
			Code: "mesh_not_hub_exit", Severity: SeverityError, LinkID: l.ID,
			Message: "Mesh 边只能连接枢纽和某个出口。",
		})
	}
	return out
}

func checkReplacementLink(l model.Link, a, b model.Node) []Issue {
	var out []Issue
	if !l.Standby {
		out = append(out, Issue{
			Code: "ix_replacement_not_standby", Severity: SeverityError, LinkID: l.ID,
			Message: "IX 替换 WSS 必须预先待命，默认不进路由表。",
		})
	}
	ids := map[model.Role]bool{a.Role: true, b.Role: true}
	okPair := ids[model.RoleHub] && (ids[model.RoleRelay] || ids[model.RoleGateway])
	if !okPair {
		out = append(out, Issue{
			Code: "ix_replacement_wrong_ends", Severity: SeverityError, LinkID: l.ID,
			Message: "IX 替换 WSS 只能是「中继 → 枢纽」或「网关 → 枢纽」。",
		})
	}
	return out
}

func checkNATLink(t model.Topology, l model.Link, a, b model.Node) []Issue {
	_ = t
	// A Mesh leg is not dialled at a public address: both sides connect out
	// to Cloudflare, and the hub's WireGuard leg dials the exit's Mesh
	// underlay address. It is always written hub → exit (checked
	// elsewhere), so a dial-out exit must not turn that direction into an
	// error here.
	if l.Transport == model.TransportCFMesh {
		return nil
	}
	var nat *model.Node
	var other model.Node
	switch {
	case a.NatDialOut && !b.NatDialOut:
		nat, other = &a, b
	case b.NatDialOut && !a.NatDialOut:
		nat, other = &b, a
	default:
		return nil
	}
	var out []Issue
	// A nested exit's link to its relay exit is checked by checkNested.
	if nat.ViaExit != "" && other.ID == nat.ViaExit {
		return nil
	}
	if a.ViaExit == b.ID || b.ViaExit == a.ID {
		return nil
	}
	// A dial-out relay exit dials the hubs but listens for its nested
	// exits: it keeps an endpoint for them (the hubs still get none, as
	// they are its listeners).
	if strings.TrimSpace(nat.EndpointV4) != "" && !model.IsRelayExit(t, *nat) {
		out = append(out, Issue{
			Code: "nat_endpoint_forbidden", Severity: SeverityError, NodeID: nat.ID, LinkID: l.ID,
			Message: fmt.Sprintf("%s 在 NAT 后面，不能把 Endpoint 写成它的公网地址。枢纽只保存对端公钥和 AllowedIPs。", nat.Name),
		})
	}
	if l.From != nat.ID || other.Role != model.RoleHub {
		out = append(out, Issue{
			Code: "nat_dial_direction", Severity: SeverityError, NodeID: nat.ID, LinkID: l.ID,
			Message: fmt.Sprintf("%s 必须由该节点拨向枢纽（链路方向：出口 → 枢纽）。不要由枢纽去拨它的公网地址。", nat.Name),
		})
	}
	if l.Keepalive != nil && *l.Keepalive <= 0 {
		out = append(out, Issue{
			Code: "nat_keepalive_required", Severity: SeverityError, NodeID: nat.ID, LinkID: l.ID,
			Message: "NAT 拨出必须开启 PersistentKeepalive（默认 25 秒）。",
		})
	}
	return out
}

func checkAddrConflicts(t model.Topology, l model.Link) []Issue {
	var out []Issue
	ros := t.Settings.ROSIPv4
	for _, f := range []struct{ field, addr string }{{"from_v4", l.FromV4}, {"to_v4", l.ToV4}} {
		addr := f.addr
		if addr == "" {
			continue
		}
		ip, err := netip.ParseAddr(addr)
		if err != nil || !ip.Is4() {
			out = append(out, Issue{Code: "bad_address", Severity: SeverityError, LinkID: l.ID, Field: f.field, Message: "隧道 IPv4 地址无法解析：" + addr})
			continue
		}
		if ros != "" && ip.String() == ros {
			out = append(out, Issue{Code: "ula_via_ros", Severity: SeverityError, LinkID: l.ID, Field: f.field, Message: "隧道地址不能是 ROS " + ros + "。"})
		}
		if lan, err := netip.ParsePrefix(lanPrefix(t)); err == nil && lan.Contains(ip) {
			out = append(out, Issue{Code: "prefix_conflict", Severity: SeverityError, LinkID: l.ID, Field: f.field, Message: "隧道 IPv4 落在局域网 " + lan.String() + " 里。"})
		}
	}
	ula, _ := netip.ParsePrefix(or(t.Settings.ULAPrefix, "fd66::/48"))
	for _, f := range []struct{ field, addr string }{{"from_ula", l.FromULA}, {"to_ula", l.ToULA}} {
		addr := f.addr
		if addr == "" {
			continue
		}
		ip, err := netip.ParseAddr(addr)
		if err != nil || !ula.Contains(ip) {
			out = append(out, Issue{Code: "prefix_conflict", Severity: SeverityError, LinkID: l.ID, Field: f.field, Message: "隧道 ULA 必须位于 " + ula.String() + "：" + addr})
		}
	}
	return out
}

func checkPathRoles(t model.Topology, nodes map[string]model.Node, path []string, exit model.Node) []Issue {
	if !t.HasIX() {
		return checkNoIXPathRoles(t, nodes, path, exit)
	}
	var out []Issue
	roles := pathRoles(nodes, path)
	want := []model.Role{model.RoleGateway, model.RoleRelay, model.RoleIX, model.RoleHub, model.RoleExit}
	if !subsequence(roles, want) {
		missing := "IX"
		code := "path_missing_ix"
		if !containsRole(roles, model.RoleRelay) {
			missing = "国内中继"
			code = "path_missing_relay"
		} else if !containsRole(roles, model.RoleIX) {
			missing = "IX 专线"
			code = "path_missing_ix"
		} else if !containsRole(roles, model.RoleHub) {
			missing = "主枢纽"
			code = "path_missing_hub"
		}
		out = append(out, Issue{
			Code: code, Severity: SeverityError, ExitID: exit.ID,
			Message: fmt.Sprintf("到 %s 的主路径必须依序经过国内中继、IX 专线、主枢纽。缺少%s。Mesh 不能用来绕过 IX。", exit.Name, missing),
		})
	}
	// Order: relay before ix before hub.
	if !ordered(roles, model.RoleRelay, model.RoleIX) || !ordered(roles, model.RoleIX, model.RoleHub) || !ordered(roles, model.RoleHub, model.RoleExit) {
		out = append(out, Issue{
			Code: "path_missing_ix", Severity: SeverityError, ExitID: exit.ID,
			Message: fmt.Sprintf("到 %s 的主路径顺序错误。正确顺序是网关 → 国内中继 → IX → 主枢纽 → 出口。", exit.Name),
		})
	}
	_ = t
	return out
}

func pureV6(exit model.Node) bool { return !exit.PathV4 && exit.PathV6 }

func checkPureV6(t model.Topology, nodes map[string]model.Node, exit model.Node) []Issue {
	if !pureV6(exit) {
		return nil
	}
	hub := primaryHub(t)
	if exit.V6Workaround == model.WorkaroundNone {
		return []Issue{{
			Code: "pure_v6_unreachable", Severity: SeverityError, NodeID: exit.ID, ExitID: exit.ID,
			Message: fmt.Sprintf("%s 是纯 IPv6 出口，而主枢纽 path_v6=%v。枢纽没有 IPv6，必须先选择绕行（双栈中继、Mesh 或 v4 可达前置），否则拒绝保存。", exit.Name, hub.PathV6),
		}}
	}
	var out []Issue
	switch exit.V6Workaround {
	case model.WorkaroundDualstackRelay:
		if !wiredDualstack(t, exit) {
			out = append(out, Issue{
				Code: "workaround_not_wired", Severity: SeverityError, NodeID: exit.ID, ExitID: exit.ID,
				Message: fmt.Sprintf("%s 选择了双栈中继，但还没有接上。需要一台 IX 之后的双栈节点（path_v4 与 path_v6），枢纽用 v4 WireGuard 连它，它再用 v6 WireGuard 连这个出口。出口要有文档用的 EndpointV6。", exit.Name),
			})
		}
	case model.WorkaroundMesh:
		if !wiredMesh(t, exit) {
			out = append(out, Issue{
				Code: "workaround_not_wired", Severity: SeverityError, NodeID: exit.ID, ExitID: exit.ID,
				Message: fmt.Sprintf("%s 选择了 Mesh 绕行，但没有一条待命的枢纽 → 该出口 Mesh 边。枢纽经 Mesh 承载的 WireGuard 腿到达它；Mesh 只承载这一跳，不能绕过 IX。", exit.Name),
			})
		}
	case model.WorkaroundV4Front:
		if !wiredV4Front(t, exit) {
			out = append(out, Issue{
				Code: "workaround_not_wired", Severity: SeverityError, NodeID: exit.ID, ExitID: exit.ID,
				Message: fmt.Sprintf("%s 选择了 v4 前置，但没有前置的 IPv4 端点，或没有一条枢纽到它的直连 WireGuard。前置地址用文档前缀，不要写成枢纽的地址。", exit.Name),
			})
		}
	default:
		out = append(out, Issue{
			Code: "workaround_not_wired", Severity: SeverityError, NodeID: exit.ID, ExitID: exit.ID,
			Message: "未知的 v6 绕行方式。",
		})
	}
	if hasDirectHubWG(t, exit) && exit.V6Workaround != model.WorkaroundV4Front {
		out = append(out, Issue{
			Code: "pure_v6_direct_ignored", Severity: SeverityWarning, NodeID: exit.ID, ExitID: exit.ID,
			Message: fmt.Sprintf("枢纽没有 IPv6，到 %s 的直连 WireGuard 不会当主路径。流量走已选的绕行。", exit.Name),
		})
	}
	_ = nodes
	return out
}

func wiredDualstack(t model.Topology, exit model.Node) bool {
	if ip, err := netip.ParseAddr(exit.EndpointV6); err != nil || !ip.Is6() {
		return false
	}
	hub := primaryHub(t)
	var relay model.Node
	found := false
	for _, n := range t.Nodes {
		if n.DualstackRelay && n.PathV4 && n.PathV6 && n.ID != exit.ID {
			if linkedPrimary(t, hub.ID, n.ID) && linkedPrimary(t, n.ID, exit.ID) {
				relay = n
				found = true
				break
			}
		}
	}
	return found && relay.ID != ""
}

func wiredMesh(t model.Topology, exit model.Node) bool {
	hub := primaryHub(t)
	for _, l := range t.Links {
		if l.Transport != model.TransportCFMesh || !l.Enabled || !l.Standby {
			continue
		}
		if (l.From == hub.ID && l.To == exit.ID) || (l.To == hub.ID && l.From == exit.ID) {
			return true
		}
	}
	return false
}

func wiredV4Front(t model.Topology, exit model.Node) bool {
	ip, err := netip.ParseAddr(exit.EndpointV4)
	if err != nil || !ip.Is4() {
		return false
	}
	hub := primaryHub(t)
	return linkedPrimary(t, hub.ID, exit.ID)
}

func linkedPrimary(t model.Topology, a, b string) bool {
	if a == "" || b == "" {
		return false
	}
	for _, l := range t.Links {
		if !l.Enabled || l.Standby {
			continue
		}
		if l.Transport == model.TransportCFMesh || l.Transport == model.TransportIXReplacementWSS {
			continue
		}
		if (l.From == a && l.To == b) || (l.From == b && l.To == a) {
			return true
		}
	}
	return false
}

func hasDirectHubWG(t model.Topology, exit model.Node) bool {
	hub := primaryHub(t)
	for _, l := range t.Links {
		if !l.Enabled || l.Transport != model.TransportDirectWG {
			continue
		}
		if (l.From == hub.ID && l.To == exit.ID) || (l.To == hub.ID && l.From == exit.ID) {
			return true
		}
	}
	return false
}

func findExitPath(t model.Topology, nodes map[string]model.Node, gw string, exit model.Node) ([]string, []model.Link, bool) {
	if pureV6(exit) && exit.V6Workaround == model.WorkaroundMesh {
		if path, links, ok := meshPath(t, nodes, gw, exit.ID); ok {
			return path, links, true
		}
	}
	if pureV6(exit) && exit.V6Workaround == model.WorkaroundDualstackRelay {
		if path, links, ok := pathViaRelay(t, nodes, gw, exit.ID); ok {
			return path, links, true
		}
	}
	return findPrimaryPath(t, nodes, gw, exit.ID)
}

func meshPath(t model.Topology, nodes map[string]model.Node, gw, exit string) ([]string, []model.Link, bool) {
	hub := primaryHub(t)
	path, links, ok := findAnyPath(t, gw, hub.ID)
	if !ok {
		return nil, nil, false
	}
	if !hubPrefixSatisfies(nodes, path) {
		return nil, nil, false
	}
	var mesh model.Link
	for _, l := range t.Links {
		if l.Transport != model.TransportCFMesh || !l.Enabled || !l.Standby {
			continue
		}
		if (l.From == hub.ID && l.To == exit) || (l.To == hub.ID && l.From == exit) {
			mesh = l
			break
		}
	}
	if mesh.ID == "" {
		return nil, nil, false
	}
	return append(path, exit), append(links, mesh), true
}

func pathViaRelay(t model.Topology, nodes map[string]model.Node, from, to string) ([]string, []model.Link, bool) {
	type edge struct {
		to   string
		link model.Link
	}
	adj := map[string][]edge{}
	for _, l := range t.Links {
		if !primaryLink(l) {
			continue
		}
		adj[l.From] = append(adj[l.From], edge{l.To, l})
		adj[l.To] = append(adj[l.To], edge{l.From, l})
	}
	type state struct {
		id    string
		path  []string
		links []model.Link
	}
	var best []string
	var bestLinks []model.Link
	stack := []state{{id: from, path: []string{from}}}
	for len(stack) > 0 {
		cur := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		if cur.id == to && pathHasRelay(t, cur.path) && pathSatisfies(nodes, cur.path) {
			if best == nil || len(cur.path) < len(best) {
				best = append([]string(nil), cur.path...)
				bestLinks = append([]model.Link(nil), cur.links...)
			}
			continue
		}
		if len(cur.path) > 8 {
			continue
		}
		for _, e := range adj[cur.id] {
			if containsStr(cur.path, e.to) {
				continue
			}
			stack = append(stack, state{
				id:    e.to,
				path:  append(append([]string(nil), cur.path...), e.to),
				links: append(append([]model.Link(nil), cur.links...), e.link),
			})
		}
	}
	return best, bestLinks, best != nil
}

func pathHasRelay(t model.Topology, path []string) bool {
	for _, id := range path {
		n, ok := t.NodeByID(id)
		if ok && n.DualstackRelay {
			return true
		}
	}
	return false
}

func checkIXReplacement(t model.Topology, nodes map[string]model.Node) []Issue {
	if t.DualHub() {
		// The backup path is checked by checkHubs: gateway → backup hub.
		return nil
	}
	if !t.HasIX() && !t.Settings.IXReplacementMode {
		// No IX to replace: the standby WSS links are optional.
		return nil
	}
	var relay, home bool
	for _, l := range t.Links {
		if l.Transport != model.TransportIXReplacementWSS || !l.Enabled {
			continue
		}
		a, b := nodes[l.From], nodes[l.To]
		roles := map[model.Role]bool{a.Role: true, b.Role: true}
		if roles[model.RoleRelay] && roles[model.RoleHub] && l.Standby {
			relay = true
		}
		if roles[model.RoleGateway] && roles[model.RoleHub] && l.Standby {
			home = true
		}
	}
	if relay && home {
		return nil
	}
	msg := "IX 替换 WSS 还没配齐。需要预先待命两条：中继 → 枢纽，以及网关 → 枢纽。不要等 IX 故障再临时创建。"
	sev := SeverityWarning
	if t.Settings.IXReplacementMode {
		sev = SeverityError
		msg = "已经打开 IX 替换模式，但待命 WSS 没有预先部署。请先画好并启用待命隧道。"
	}
	return []Issue{{Code: "ix_replacement_not_provisioned", Severity: sev, Message: msg}}
}

func checkRules(t model.Topology, nodes map[string]model.Node) []Issue {
	var out []Issue
	autoNames := map[string]string{}
	for _, r := range t.Rules {
		if !r.Manual {
			autoNames[strings.ToLower(r.Name)] = r.ID
			autoNames[strings.ToLower(r.MatchValue)] = r.ID
		}
	}
	for _, r := range t.Rules {
		if !r.Enabled {
			continue
		}
		out = append(out, checkRuleShape(r)...)
		if r.MatchType == model.MatchQUICReject {
			if r.TargetGroup != "" || r.TargetExit != "" || r.TargetAction != "" {
				out = append(out, Issue{Code: "quic_row_target", Severity: SeverityError, RuleID: r.ID, Field: "target",
					Message: "QUIC 开关行没有目标：它只决定哪些规则的 UDP 443 被拒绝（它下面的规则和默认组）。"})
			}
			continue
		}
		if r.MatchType == model.MatchRuleSet {
			if _, ok := t.RuleSetByID(r.RuleSet); !ok {
				out = append(out, Issue{Code: "ruleset_not_found", Severity: SeverityError, RuleID: r.ID, Field: "rule_set",
					Message: fmt.Sprintf("规则「%s」使用的规则集 %s 不存在。", r.Name, r.RuleSet)})
			}
		}
		if r.MatchType == model.MatchGeoIP && strings.EqualFold(strings.TrimSpace(r.MatchValue), "cn") {
			// GEOIP,CN is executed with the China lists (chnroute).
		} else if r.MatchType == model.MatchGeoIP || r.MatchType == model.MatchASN {
			out = append(out, Issue{
				Code: "match_not_enforced", Severity: SeverityWarning, RuleID: r.ID,
				Message: fmt.Sprintf("规则「%s」的 %s 匹配在这一期不会写入数据面。它不会按归属地分流，流量会落到后面的策略。", r.Name, r.MatchType),
			})
		}
		exit, group, errIss := resolveRuleTarget(t, r)
		if errIss != nil {
			out = append(out, *errIss)
			continue
		}
		if act := t.ResolveTarget(r).Kind; act == model.ActionDirect || act == model.ActionReject {
			if model.ResidentialRequired(r) || r.RequireV6 {
				out = append(out, Issue{Code: "constraint_conflict", Severity: SeverityError, RuleID: r.ID, Field: "target",
					Message: fmt.Sprintf("规则「%s」要求家宽或 IPv6，但目标是%s，不经过任何出口。", r.Name, actionLabel(act))})
			}
			continue
		}
		if exit != nil && model.IsExternal(*exit) {
			out = append(out, Issue{Code: "tcp_only_target", Severity: SeverityWarning, RuleID: r.ID, ExitID: exit.ID,
				Message: fmt.Sprintf("规则「%s」落到仅 TCP 的外部出口 %s：UDP（包括 QUIC）在那里被拒绝。", r.Name, exit.Name)})
		}
		if model.ResidentialRequired(r) {
			if r.TargetExit != "" && (exit == nil || !exit.Residential) {
				out = append(out, Issue{
					Code: "residential_required", Severity: SeverityError, RuleID: r.ID,
					Message: fmt.Sprintf("规则「%s」必须落到家宽（residential）出口，不能使用机房出口。", r.Name),
				})
			}
			if group != nil && !group.RequireResidential {
				out = append(out, Issue{
					Code: "residential_required", Severity: SeverityError, RuleID: r.ID, GroupID: group.ID, Field: "require_residential",
					Message: fmt.Sprintf("规则「%s」要求家宽，但组 %s 没有 require_residential，组可能选中或切到机房出口。Netflix / Disney+ 一类只能走家宽出口。", r.Name, group.Name),
				})
			}
		}
		if r.RequireV6 {
			if r.TargetExit != "" && (exit == nil || !exit.EgressV6) {
				out = append(out, Issue{
					Code: "constraint_conflict", Severity: SeverityError, RuleID: r.ID,
					Message: fmt.Sprintf("规则「%s」要求 IPv6，但钉死的出口没有 egress_v6。", r.Name),
				})
			}
			if group != nil && !group.RequireV6 {
				out = append(out, Issue{
					Code: "constraint_conflict", Severity: SeverityError, RuleID: r.ID, GroupID: group.ID, Field: "require_v6",
					Message: fmt.Sprintf("规则「%s」要求 IPv6，但组 %s 没有 require_v6。约束放在组上，规则只做断言。", r.Name, group.Name),
				})
			}
		}
		// With clients_ipv6_via_gateway off every tunnelled rule is
		// IPv4-only; checkClientDNS reports that once for the topology.
		if t.Settings.ClientsIPv6ViaGateway && exit != nil && !exit.EgressV6 {
			out = append(out, Issue{
				Code: "aaaa_filtered", Severity: SeverityWarning, RuleID: r.ID, ExitID: exit.ID,
				Message: fmt.Sprintf("规则「%s」的出口 %s 没有 egress_v6。不返回 AAAA，在同一出口回落 v4，不会改送到别的国家。", r.Name, exit.Name),
			})
		}
		if r.SourceMAC != "" || r.SourceIPv4 != "" || r.SourceIPv6 != "" {
			if r.MatchType == model.MatchDomain || r.MatchType == model.MatchSuffix || r.MatchType == model.MatchKeyword || r.MatchType == model.MatchGeosite {
				out = append(out, Issue{
					Code: "device_scope_shared_ip", Severity: SeverityWarning, RuleID: r.ID,
					Message: "按设备匹配会和目的 IP 同时生效。若其他设备访问同一个解析结果，不会套用这条设备规则，而是落到它们自己的策略。",
				})
			}
		}
		if r.Manual {
			for _, key := range []string{strings.ToLower(r.MatchValue), strings.ToLower(r.Name)} {
				if id, ok := autoNames[key]; ok {
					out = append(out, Issue{
						Code: "manual_overrides_auto", Severity: SeverityWarning, RuleID: r.ID,
						Message: fmt.Sprintf("手动规则优先，将覆盖自动规则 %s。", id),
					})
					break
				}
			}
		}
	}
	_ = nodes
	return out
}

func actionLabel(a string) string {
	if a == model.ActionReject {
		return "拒绝（REJECT）"
	}
	return "直连（DIRECT）"
}

// resolveRuleTarget checks a rule's target; direct and reject return no
// exit and no group.
func resolveRuleTarget(t model.Topology, r model.Rule) (*model.Node, *model.RegionGroup, *Issue) {
	if r.TargetAction != "" {
		if r.TargetGroup != "" || r.TargetExit != "" {
			return nil, nil, &Issue{Code: "rule_target_conflict", Severity: SeverityError, RuleID: r.ID, Field: "target_group",
				Message: fmt.Sprintf("规则「%s」有多个目标，只能是地区组、出口、直连或拒绝之一。", r.Name)}
		}
		if r.TargetAction != model.ActionDirect && r.TargetAction != model.ActionReject {
			return nil, nil, &Issue{Code: "bad_action", Severity: SeverityError, RuleID: r.ID, Field: "target_action",
				Message: fmt.Sprintf("规则「%s」的动作只能是 direct 或 reject。", r.Name)}
		}
		return nil, nil, nil
	}
	return resolveRuleTargetDirect(t, r)
}

func resolveRuleTargetDirect(t model.Topology, r model.Rule) (*model.Node, *model.RegionGroup, *Issue) {
	if r.TargetPool != "" {
		return nil, nil, &Issue{Code: "legacy_pool_target", Severity: SeverityError, RuleID: r.ID, Field: "target_pool",
			Message: fmt.Sprintf("规则「%s」仍指向旧的出口池 %s。保存或重新载入拓扑会把它迁移到地区组。", r.Name, r.TargetPool)}
	}
	if r.Mode != "" {
		return nil, nil, &Issue{Code: "rule_mode_removed", Severity: SeverityError, RuleID: r.ID, Field: "mode",
			Message: fmt.Sprintf("规则「%s」带了 mode。手动/自动只在地区组上设置，规则只引用组或钉死一个出口。", r.Name)}
	}
	if r.TargetExit != "" && r.TargetGroup != "" {
		return nil, nil, &Issue{Code: "rule_target_conflict", Severity: SeverityError, RuleID: r.ID, Field: "target_group",
			Message: fmt.Sprintf("规则「%s」同时指向组和出口，只能二选一。", r.Name)}
	}
	if r.TargetExit != "" {
		n, ok := t.NodeByID(r.TargetExit)
		if !ok || n.Role != model.RoleExit {
			return nil, nil, &Issue{Code: "exit_not_found", Severity: SeverityError, RuleID: r.ID, Message: "规则指向的出口不存在。"}
		}
		return &n, nil, nil
	}
	if r.TargetGroup == "" {
		return nil, nil, &Issue{Code: "exit_not_found", Severity: SeverityError, RuleID: r.ID, Message: "规则没有出口或地区组。"}
	}
	g, ok := t.GroupByID(r.TargetGroup)
	if !ok {
		return nil, nil, &Issue{Code: "group_not_found", Severity: SeverityError, RuleID: r.ID, GroupID: r.TargetGroup, Message: fmt.Sprintf("规则「%s」指向的地区组 %s 不存在。", r.Name, r.TargetGroup)}
	}
	chosen, ok := GroupTarget(t, g.ID)
	if !ok {
		return nil, nil, &Issue{Code: "exit_not_found", Severity: SeverityError, RuleID: r.ID, GroupID: g.ID, Message: fmt.Sprintf("地区组 %s 里没有可选出口。", g.Name)}
	}
	return &chosen, &g, nil
}

// GroupTarget is the member a group installs until health says otherwise:
// the chosen member (manual) or the first of the effective order (IX-bound
// first, then the operator's order), after hard constraints.
func GroupTarget(t model.Topology, groupID string) (model.Node, bool) {
	g, ok := t.GroupByID(groupID)
	if !ok {
		return model.Node{}, false
	}
	sel := pool.Select(t, g, nil)
	if sel.Target == "" {
		return model.Node{}, false
	}
	return t.NodeByID(sel.Target)
}

// CheckGroups validates the region groups themselves.
func CheckGroups(t model.Topology) []Issue {
	var out []Issue
	// Every exit and every group owns one fwmark, transit address
	// (10.66.200.10+i) and hub table (201+i): 240 in all.
	if n := len(exitsOf(t)) + len(t.Groups); n > maxMarks {
		out = append(out, Issue{Code: "too_many_marks", Severity: SeverityError, Field: "region_groups",
			Message: fmt.Sprintf("出口和地区组一共 %d 个，超过 %d 个可分配的标记、中转地址和路由表。", n, maxMarks)})
	}
	ids := map[string]bool{}
	for _, g := range t.Groups {
		bad := func(code, field, msg string) {
			out = append(out, Issue{Code: code, Severity: SeverityError, GroupID: g.ID, Field: field, Message: msg})
		}
		if g.ID == "" || ids[g.ID] {
			bad("duplicate_id", "id", "地区组 ID 为空或重复。")
		}
		ids[g.ID] = true
		if g.ID != "" && !idRe.MatchString(g.ID) {
			bad("bad_id", "id", "地区组 ID 只能是小写字母、数字和短横线。")
		}
		switch g.Mode {
		case model.GroupAuto:
			if g.Chosen != "" {
				bad("chosen_in_auto", "chosen", fmt.Sprintf("地区组 %s 是自动模式，不能同时指定成员。", g.Name))
			}
			if g.OnFailure != "" {
				bad("on_failure_in_auto", "on_failure", fmt.Sprintf("地区组 %s 是自动模式，on_failure 只用于手动模式。", g.Name))
			}
		case model.GroupManual:
			switch g.OnFailure {
			case "", model.OnFailureHold, model.OnFailureFallback:
			default:
				bad("invalid_field", "on_failure", "on_failure 只能是 hold 或 fallback。")
			}
		default:
			bad("invalid_field", "mode", "mode 只能是 auto 或 manual。")
		}
		if g.RequireResidential && g.ExcludeResidential {
			bad("constraint_conflict", "exclude_residential", fmt.Sprintf("地区组 %s 不能同时要求和排除家宽。", g.Name))
		}
		sel := pool.Select(t, g, nil)
		for _, m := range sel.Members {
			for _, why := range m.Reasons {
				switch why.Code {
				case pool.WhyMissing, pool.WhyDuplicate:
					out = append(out, Issue{Code: "group_member_invalid", Severity: SeverityError, GroupID: g.ID, NodeID: m.ID, Field: "members",
						Message: fmt.Sprintf("地区组 %s 的成员 %s：%s", g.Name, m.ID, why.Message)})
				case pool.WhyResiRequired, pool.WhyResiExcluded, pool.WhyV6Required:
					out = append(out, Issue{Code: "group_member_excluded", Severity: SeverityWarning, GroupID: g.ID, NodeID: m.ID, Field: "members",
						Message: fmt.Sprintf("地区组 %s 的成员 %s 被约束排除：%s", g.Name, m.Name, why.Message)})
				}
			}
			if m.Eligible && g.Region != "" && m.Region != "" && unlockRegion(m.Region) != unlockRegion(g.Region) {
				out = append(out, Issue{Code: "member_region_mismatch", Severity: SeverityWarning, GroupID: g.ID, NodeID: m.ID, Field: "members",
					Message: fmt.Sprintf("地区组 %s（%s）的成员 %s 在 %s。", g.Name, g.Region, m.Name, m.Region)})
			}
		}
		if g.Mode == model.GroupManual && sel.Reason != pool.ReasonChosen {
			if g.Chosen == "" {
				bad("chosen_not_eligible", "chosen", fmt.Sprintf("地区组 %s 是手动模式，需要指定一个成员。", g.Name))
			} else {
				bad("chosen_not_eligible", "chosen", fmt.Sprintf("地区组 %s 指定的 %s 不是组里可用的成员（不存在或被约束排除）。", g.Name, g.Chosen))
			}
		}
		if len(sel.Order) == 0 {
			out = append(out, Issue{Code: "group_empty", Severity: SeverityWarning, GroupID: g.ID, Field: "members",
				Message: fmt.Sprintf("地区组 %s 里没有可用的出口；引用它的规则不会生效。", g.Name)})
		}
	}
	return out
}

const maxMarks = 240

// unlockRegion folds region spellings (HK, Hong Kong) for comparison.
func unlockRegion(s string) string {
	s = strings.ToLower(strings.ReplaceAll(strings.ReplaceAll(strings.TrimSpace(s), " ", ""), "-", ""))
	switch s {
	case "hongkong":
		return "hk"
	case "taiwan":
		return "tw"
	case "japan":
		return "jp"
	case "singapore":
		return "sg"
	case "unitedstates", "usa":
		return "us"
	}
	return s
}

func findAnyPath(t model.Topology, from, to string) ([]string, []model.Link, bool) {
	return searchPaths(t, nil, from, to, false)
}

func findPrimaryPath(t model.Topology, nodes map[string]model.Node, from, to string) ([]string, []model.Link, bool) {
	return searchPaths(t, nodes, from, to, true)
}

func searchPaths(t model.Topology, nodes map[string]model.Node, from, to string, requireIX bool) ([]string, []model.Link, bool) {
	type edge struct {
		to   string
		link model.Link
	}
	adj := map[string][]edge{}
	for _, l := range t.Links {
		if !primaryLink(l) {
			continue
		}
		adj[l.From] = append(adj[l.From], edge{l.To, l})
		adj[l.To] = append(adj[l.To], edge{l.From, l})
	}
	type state struct {
		id    string
		path  []string
		links []model.Link
	}
	var best []string
	var bestLinks []model.Link
	stack := []state{{id: from, path: []string{from}}}
	for len(stack) > 0 {
		cur := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		if cur.id == to {
			if betterPath(nodes, cur.path, best, requireIX) {
				best = append([]string(nil), cur.path...)
				bestLinks = append([]model.Link(nil), cur.links...)
			}
			continue
		}
		if len(cur.path) > 8 {
			continue
		}
		for _, e := range adj[cur.id] {
			if containsStr(cur.path, e.to) {
				continue
			}
			next := state{
				id:    e.to,
				path:  append(append([]string(nil), cur.path...), e.to),
				links: append(append([]model.Link(nil), cur.links...), e.link),
			}
			stack = append(stack, next)
		}
	}
	return best, bestLinks, best != nil
}

func betterPath(nodes map[string]model.Node, path, best []string, requireIX bool) bool {
	ok := !requireIX || pathSatisfies(nodes, path)
	if !ok {
		return false
	}
	if best == nil {
		return true
	}
	return len(path) < len(best)
}

func pathSatisfies(nodes map[string]model.Node, path []string) bool {
	if nodesDirect(nodes) {
		return directPathSatisfies(nodes, path)
	}
	if !nodesHaveIX(nodes) {
		return noIXPathSatisfies(nodes, path)
	}
	roles := pathRoles(nodes, path)
	return subsequence(roles, []model.Role{model.RoleGateway, model.RoleRelay, model.RoleIX, model.RoleHub, model.RoleExit}) &&
		ordered(roles, model.RoleRelay, model.RoleIX) &&
		ordered(roles, model.RoleIX, model.RoleHub)
}

func primaryLink(l model.Link) bool {
	if !l.Enabled || l.Standby {
		return false
	}
	switch l.Transport {
	case model.TransportCFMesh, model.TransportIXReplacementWSS:
		return false
	default:
		return true
	}
}

// pathMTU is the smallest hopMTU of links (1360 when none of them
// encapsulates, e.g. only a dedicated line).
func pathMTU(links []model.Link) int {
	mtu := 0
	for _, l := range links {
		h := hopMTU(l)
		if h == 0 {
			continue
		}
		if mtu == 0 || h < mtu {
			mtu = h
		}
	}
	if mtu == 0 {
		mtu = 1360
	}
	return mtu
}

// exitPathMTU is the one path MTU of exit: the smallest tunnel MTU over
// every path that can carry the exit's traffic (the PathReport the panel
// shows, every MSS clamp compile derives from it, and the MTU adoption
// preview all read this value). primary are the links of the reported
// path (findExitPath); they are always included, so the result is never
// above what the primary path alone gives.
//
// "Can carry" follows the carrying states of the gateway's own failover
// and of relay sharing (compile.planUpstream / planShare / mgmtStates) and
// of the relays' own failover (relay → hub IX replacement WSS):
//
//   - upstream into the primary hub: for every sharing relay (model
//     SharingRelays: each relay with an enabled, non-standby tunnel from
//     the gateway; connections are assigned per relay) every such
//     gateway–relay link, and the relay's ways to the primary hub (enabled,
//     non-standby links through IX nodes only, and the relay's enabled IX
//     replacement WSS);
//   - upstream into a hub over the gateway's enabled IX replacement WSS to
//     it (the single hub's home-to-hub fallback, the backup hub);
//   - from each hub reached so: the hub's enabled, non-standby, non-Mesh
//     links to the exit (compile.hubDirect) and, on the primary hub, the
//     exit's Mesh legs (enabled cf_mesh links: the hub may carry the exit
//     over one instead of its direct leg); for a nested exit the hub's
//     links to its relay exit plus the relay exit's links to it; for a
//     pure-IPv6 exit behind a dual-stack relay the hub's direct WireGuard
//     to the relay plus the relay's links to the exit; for a pure-IPv6
//     Mesh exit only the primary hub's Mesh leg (its one way to the hub).
//
// Each link counts with hopMTU, i.e. the smaller of its legs (UDP and WSS
// companion, LegMTU; a Mesh leg with what the Mesh path leaves after the
// WireGuard overhead, MeshLegMTU). Link direction (dial-in or dial-out)
// does not matter. Links that never carry the exit's traffic are not
// counted: a standby gateway–relay link, another hub's or exit's links, a
// hub the gateway has no way into. An exit with a Mesh leg is not part of
// the global MSS floor: compile clamps its mark (and the marks of the
// groups that can switch to it) on its own, so exits and groups without a
// Mesh leg keep their values (docs/architecture.md「Mesh 腿的 MTU」).
func exitPathMTU(t model.Topology, nodes map[string]model.Node, gw string, exit model.Node, primary []model.Link) int {
	return pathMTU(exitPathLinks(t, nodes, gw, exit, primary))
}

// exitPathLinks are the links exitPathMTU takes the minimum over.
func exitPathLinks(t model.Topology, nodes map[string]model.Node, gw string, exit model.Node, primary []model.Link) []model.Link {
	links := append([]model.Link(nil), primary...)
	// Hubs in ID order: the result (and the MeshLinks derived from it) is
	// deterministic.
	ups := upstreamLinks(t, nodes, gw)
	hubs := make([]string, 0, len(ups))
	for hub := range ups {
		hubs = append(hubs, hub)
	}
	sort.Strings(hubs)
	for _, hub := range hubs {
		up := ups[hub]
		down := hubSideLinks(t, nodes, hub, exit)
		if len(up) == 0 || len(down) == 0 {
			continue
		}
		links = append(links, up...)
		links = append(links, down...)
	}
	return links
}

// withoutMesh drops the cf_mesh links.
func withoutMesh(links []model.Link) []model.Link {
	var out []model.Link
	for _, l := range links {
		if l.Transport != model.TransportCFMesh {
			out = append(out, l)
		}
	}
	return out
}

// meshLinkIDs are the IDs of the cf_mesh links in links that are not
// already in reported, sorted and unique.
func meshLinkIDs(links []model.Link, reported []string) []string {
	seen := map[string]bool{}
	for _, id := range reported {
		seen[id] = true
	}
	var out []string
	for _, l := range links {
		if l.Transport == model.TransportCFMesh && !seen[l.ID] {
			seen[l.ID] = true
			out = append(out, l.ID)
		}
	}
	sort.Strings(out)
	return out
}

// upstreamLinks maps each hub the gateway's traffic can reach to the links
// of every carrying state into it (see exitPathMTU).
func upstreamLinks(t model.Topology, nodes map[string]model.Node, gw string) map[string][]model.Link {
	out := map[string][]model.Link{}
	if gw == "" {
		return out
	}
	primary, _ := t.PrimaryHub()
	for _, r := range t.SharingRelays() {
		var west []model.Link
		for _, l := range t.Links {
			if !l.Enabled || l.Standby || !joins(l, gw, r.ID) {
				continue
			}
			switch l.Transport {
			case model.TransportDirectWG, model.TransportWGOverWSS, model.TransportUDPWSSFailover:
				west = append(west, l)
			}
		}
		if len(west) == 0 {
			continue
		}
		if primary.ID != "" {
			if east := relayToHub(t, nodes, r.ID, primary.ID); len(east) > 0 {
				out[primary.ID] = append(out[primary.ID], west...)
				out[primary.ID] = append(out[primary.ID], east...)
			}
		}
		// The relay's own failover onto an IX replacement WSS.
		for _, l := range t.Links {
			if !l.Enabled || l.Transport != model.TransportIXReplacementWSS {
				continue
			}
			hub := peerOf(l, r.ID)
			if hub == "" || nodes[hub].Role != model.RoleHub {
				continue
			}
			out[hub] = append(out[hub], west...)
			out[hub] = append(out[hub], l)
		}
	}
	// The gateway's IX replacement WSS: a single hub's fallback, the
	// backup hub.
	for _, l := range t.Links {
		if !l.Enabled || l.Transport != model.TransportIXReplacementWSS {
			continue
		}
		hub := peerOf(l, gw)
		if hub == "" || nodes[hub].Role != model.RoleHub {
			continue
		}
		out[hub] = append(out[hub], l)
	}
	return out
}

// relayToHub: the links of every way from relay to hub over enabled,
// non-standby links whose intermediate nodes are IX nodes (the dedicated
// line and the IX's tunnel to the hub, or a direct tunnel to an IX hub).
func relayToHub(t model.Topology, nodes map[string]model.Node, relay, hub string) []model.Link {
	var out []model.Link
	var walk func(at string, seen map[string]bool, links []model.Link)
	walk = func(at string, seen map[string]bool, links []model.Link) {
		if len(links) > 4 {
			return
		}
		for _, l := range t.Links {
			if !primaryLink(l) {
				continue
			}
			next := peerOf(l, at)
			if next == "" || seen[next] {
				continue
			}
			path := append(append([]model.Link(nil), links...), l)
			if next == hub {
				out = append(out, path...)
				continue
			}
			if nodes[next].Role != model.RoleIX {
				continue
			}
			seen[next] = true
			walk(next, seen, path)
			delete(seen, next)
		}
	}
	walk(relay, map[string]bool{relay: true}, nil)
	return out
}

// hubSideLinks: the links that carry exit's traffic from hub onward (see
// exitPathMTU); none when hub cannot carry it.
func hubSideLinks(t model.Topology, nodes map[string]model.Node, hub string, exit model.Node) []model.Link {
	if model.IsExternal(exit) {
		c, ok := nodes[exit.External.Carrier]
		if !ok || model.IsExternal(c) {
			return nil
		}
		return hubSideLinks(t, nodes, hub, c)
	}
	if pureV6(exit) && exit.V6Workaround == model.WorkaroundMesh {
		return meshLegLinks(t, hub, exit.ID)
	}
	if model.IsNested(exit) {
		up := hubExitLinks(t, hub, exit.ViaExit)
		down := hubExitLinks(t, exit.ViaExit, exit.ID)
		if len(up) == 0 || len(down) == 0 {
			return nil
		}
		return append(up, down...)
	}
	if pureV6(exit) && exit.V6Workaround == model.WorkaroundDualstackRelay {
		var out []model.Link
		for _, d := range t.Nodes {
			if !d.DualstackRelay || d.ID == exit.ID {
				continue
			}
			down := hubExitLinks(t, d.ID, exit.ID)
			var up []model.Link
			for _, l := range t.Links {
				if l.Enabled && !l.Standby && l.Transport == model.TransportDirectWG && joins(l, hub, d.ID) {
					up = append(up, l)
				}
			}
			if len(up) > 0 && len(down) > 0 {
				out = append(append(out, up...), down...)
			}
		}
		if len(out) > 0 {
			return out
		}
	}
	direct := hubExitLinks(t, hub, exit.ID)
	if len(direct) == 0 {
		return nil
	}
	// The exit's Mesh leg is an alternative of its direct leg from the same
	// hub, never a path of its own.
	return append(direct, meshLegLinks(t, hub, exit.ID)...)
}

// meshLegLinks: the enabled cf_mesh links between hub (primary or backup)
// and exit.
func meshLegLinks(t model.Topology, hub, exit string) []model.Link {
	var out []model.Link
	for _, l := range t.Links {
		if l.Enabled && l.Transport == model.TransportCFMesh && joins(l, hub, exit) {
			out = append(out, l)
		}
	}
	return out
}

// hubExitLinks: the enabled, non-standby links between a and b that are
// not Mesh edges or IX replacements.
func hubExitLinks(t model.Topology, a, b string) []model.Link {
	var out []model.Link
	for _, l := range t.Links {
		if primaryLink(l) && joins(l, a, b) {
			out = append(out, l)
		}
	}
	return out
}

func joins(l model.Link, a, b string) bool {
	return (l.From == a && l.To == b) || (l.From == b && l.To == a)
}

// peerOf is l's other end when l touches id, "" otherwise.
func peerOf(l model.Link, id string) string {
	switch id {
	case l.From:
		return l.To
	case l.To:
		return l.From
	}
	return ""
}

// hopMTU returns the interface MTU that TCP must survive on this hop.
// udp_wss_failover contributes the smaller of the two legs so a switch
// does not black-hole existing sessions. Dedicated line has no extra encap.
// The legs' MTUs are LegMTU's, the same values compile writes into the
// WireGuard configs, so every MSS clamp derives from the interfaces'
// actual MTUs (one computation).
func hopMTU(l model.Link) int {
	switch l.Transport {
	case model.TransportDedicatedLine:
		return 0
	case model.TransportUDPWSSFailover:
		udp, _, _ := LegMTU(l, "udp")
		wss, _, _ := LegMTU(l, "wss")
		if wss < udp {
			return wss
		}
		return udp
	case model.TransportWGOverWSS, model.TransportIXReplacementWSS:
		m, _, _ := LegMTU(l, "wss")
		return m
	case model.TransportCFMesh:
		// What the Mesh path leaves a WireGuard leg carried over it; the
		// interface itself may be larger (MeshLegMTU).
		payload, _ := MeshLegMTU(l)
		return payload
	default:
		m, _, _ := LegMTU(l, "udp")
		return m
	}
}

// MeshLegMTU is the MTU of the WireGuard leg a cf_mesh link carries over
// the Cloudflare Mesh (mtu.MeshLeg over the IPv4 underlay address).
//
// The Mesh path MTU (Link.MTU, default model.MeshPathMTU = 1280) minus
// WireGuard's overhead (60) is 1220, below the 1280 an interface needs to
// carry IPv6 at all (the exits' resolver addresses are IPv6). device, the
// MTU compile writes into the interface, therefore stays at 1280, and
// payload, the hop MTU every MSS clamp follows (hopMTU), is the largest
// inner packet such an interface sends without fragmenting the outer
// packet: 1216 by default (WireGuard's 16-byte padding), MSS 1176 / 1156.
// TCP never needs a fragment; a larger inner packet (up to device) is
// carried by fragmenting WireGuard's outer packet. A Mesh path of 1340 or
// more gives payload = device = path − 60 and no fragment. See
// docs/architecture.md「Mesh 腿的 MTU」.
func MeshLegMTU(l model.Link) (payload, device int) {
	payload, device = mtu.MeshLeg(model.MeshLegPathMTU(l), 4)
	return payload, device
}

// Default tunnel MTUs (Link.MTU / Link.WSSMTU left at zero).
const (
	DefaultMTUUDP         = 1420
	DefaultMTUFailoverUDP = 1412
	DefaultMTUWSS         = 1360
)

// LegMTU is the WireGuard MTU of one leg of a tunnel link ("udp" or "wss"),
// the link field that sets it ("mtu" or "wss_mtu") and that field's value
// (0: the transport default). It is the single source for the interfaces
// compile renders and for the path MTU the MSS clamps follow:
//
//   - udp leg: Link.MTU, default 1420 (1412 on udp_wss_failover);
//   - wss leg of udp_wss_failover: Link.WSSMTU, default 1360 (Link.MTU is
//     the UDP leg's and is not copied: 1412 does not fit a WSS session on
//     PPPoE 1492);
//   - wg_over_wss / ix_replacement_wss: Link.WSSMTU, else Link.MTU, else
//     1360;
//   - cf_mesh (udp leg): the interface MTU of the leg carried over the Mesh
//     (MeshLegMTU's device value); the path MTU and the MSS clamps follow
//     its payload value instead (hopMTU).
func LegMTU(l model.Link, mode string) (mtu int, field string, configured int) {
	if mode == "wss" {
		switch {
		case l.Transport == model.TransportUDPWSSFailover:
			return orInt(l.WSSMTU, DefaultMTUWSS), "wss_mtu", l.WSSMTU
		case l.WSSMTU != 0:
			return l.WSSMTU, "wss_mtu", l.WSSMTU
		default:
			return orInt(l.MTU, DefaultMTUWSS), "mtu", l.MTU
		}
	}
	if l.Transport == model.TransportUDPWSSFailover {
		return orInt(l.MTU, DefaultMTUFailoverUDP), "mtu", l.MTU
	}
	if l.Transport == model.TransportCFMesh {
		// The interface MTU of the leg; Link.MTU is the Mesh path's.
		_, device := MeshLegMTU(l)
		return device, "mtu", l.MTU
	}
	return orInt(l.MTU, DefaultMTUUDP), "mtu", l.MTU
}

func firstRole(t model.Topology, role model.Role) model.Node {
	for _, n := range t.Nodes {
		if n.Role == role {
			return n
		}
	}
	return model.Node{}
}

func exitsOf(t model.Topology) []model.Node {
	var out []model.Node
	for _, n := range t.Nodes {
		if n.Role == model.RoleExit {
			out = append(out, n)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

func subsequence(have, want []model.Role) bool {
	i := 0
	for _, r := range have {
		if i < len(want) && r == want[i] {
			i++
		}
	}
	return i == len(want)
}

func ordered(roles []model.Role, a, b model.Role) bool {
	ia, ib := -1, -1
	for i, r := range roles {
		if r == a && ia < 0 {
			ia = i
		}
		if r == b && ib < 0 {
			ib = i
		}
	}
	return ia >= 0 && ib >= 0 && ia < ib
}

func containsRole(roles []model.Role, want model.Role) bool {
	for _, r := range roles {
		if r == want {
			return true
		}
	}
	return false
}

func containsStr(ss []string, s string) bool {
	for _, v := range ss {
		if v == s {
			return true
		}
	}
	return false
}

func involves(a, b model.Node, role model.Role) bool {
	return a.Role == role || b.Role == role
}

func hostOf(cidr string) string {
	if p, err := netip.ParsePrefix(cidr); err == nil {
		return p.Addr().String()
	}
	if a, err := netip.ParseAddr(cidr); err == nil {
		return a.String()
	}
	return cidr
}

func lanPrefix(t model.Topology) string {
	if t.Settings.GatewayLANIP != "" && strings.Contains(t.Settings.GatewayLANIP, "/") {
		return t.Settings.GatewayLANIP
	}
	return model.UnsetLANPrefix
}

func p2pPrefix(a, b string) (netip.Prefix, error) {
	aa, err := netip.ParseAddr(a)
	if err != nil {
		return netip.Prefix{}, err
	}
	bb, err := netip.ParseAddr(b)
	if err != nil {
		return netip.Prefix{}, err
	}
	bits := 30
	if aa.Is6() {
		bits = 64
	}
	// Compare the /30 (or /64) containing both.
	pa := netip.PrefixFrom(aa, bits).Masked()
	pb := netip.PrefixFrom(bb, bits).Masked()
	if pa != pb {
		// Still treat the two addresses as a block covering both by using the first.
		return pa, nil
	}
	return pa, nil
}

func or(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

func orInt(a, b int) int {
	if a != 0 {
		return a
	}
	return b
}

var (
	idRe     = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,40}$`)
	ifaceRe  = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_.:-]{0,14}$`)
	macRe    = regexp.MustCompile(`(?i)^([0-9a-f]{2}:){5}[0-9a-f]{2}$`)
	wssRe    = regexp.MustCompile(`^[A-Za-z0-9._~/-]{1,64}$`)
	imageRef = regexp.MustCompile(`^[a-z0-9][a-z0-9._/-]{0,180}(?::[A-Za-z0-9_][A-Za-z0-9_.-]{0,127})?(?:@sha256:[a-f0-9]{64})?$`)
)

func checkImageRef(ref, field string) *Issue {
	if ref == "" {
		return nil
	}
	if strings.Contains(ref, "..") || !imageRef.MatchString(ref) {
		return &Issue{
			Code: "bad_image", Severity: SeverityError,
			Message: field + " 不是可用的镜像引用。官方默认是 cloudflare/mesh:latest 和 lmc999/regioncheck:latest，只能改成同样形式的名字、标签或 sha256。",
		}
	}
	return nil
}

func checkSafe(t model.Topology) []Issue {
	var out []Issue
	for _, n := range t.Nodes {
		if n.ID != "" && !idRe.MatchString(n.ID) {
			out = append(out, Issue{Code: "bad_id", Severity: SeverityError, NodeID: n.ID, Message: "节点 ID 只能是小写字母、数字和短横线。"})
		}
		if iss := checkIface(n.LANInterface, "节点 "+n.Name+" 的局域网接口"); iss != nil {
			iss.NodeID = n.ID
			out = append(out, *iss)
		}
		if iss := checkIface(n.WANInterface, "节点 "+n.Name+" 的 WAN 接口"); iss != nil {
			iss.NodeID = n.ID
			out = append(out, *iss)
		}
		if n.EndpointV4 != "" {
			if ip, err := netip.ParseAddr(n.EndpointV4); err != nil || !ip.Is4() {
				out = append(out, Issue{Code: "bad_address", Severity: SeverityError, NodeID: n.ID, Message: "Endpoint 必须是 IPv4 地址。"})
			}
		}
		if n.EndpointV6 != "" {
			if ip, err := netip.ParseAddr(n.EndpointV6); err != nil || !ip.Is6() {
				out = append(out, Issue{Code: "bad_address", Severity: SeverityError, NodeID: n.ID, Message: "EndpointV6 必须是 IPv6 地址。"})
			}
		}
		if n.WSSPathPrefix != "" && (!wssRe.MatchString(n.WSSPathPrefix) || strings.Contains(n.WSSPathPrefix, "..") || strings.Contains(n.WSSPathPrefix, "%")) {
			out = append(out, Issue{Code: "bad_wss_prefix", Severity: SeverityError, NodeID: n.ID, Message: "WSS 路径前缀含有不能写入 systemd 单元的字符。"})
		}
	}
	for _, l := range t.Links {
		if l.ID != "" && !idRe.MatchString(l.ID) {
			out = append(out, Issue{Code: "bad_id", Severity: SeverityError, LinkID: l.ID, Message: "链路 ID 只能是小写字母、数字和短横线。"})
		}
	}
	for _, r := range t.Rules {
		if r.ID != "" && !idRe.MatchString(r.ID) {
			out = append(out, Issue{Code: "bad_id", Severity: SeverityError, RuleID: r.ID, Message: "规则 ID 只能是小写字母、数字和短横线。"})
		}
	}
	return out
}

func checkIface(name, what string) *Issue {
	if name == "" {
		return nil
	}
	if name == "all" || name == "default" || name == "lo" || !ifaceRe.MatchString(name) {
		return &Issue{Code: "bad_interface", Severity: SeverityError, Message: what + " 不能用于生成命令：" + name}
	}
	return nil
}

func checkRuleShape(r model.Rule) []Issue {
	var out []Issue
	checkName := func(s string) {
		if s != "" && !safeDNS(s) {
			out = append(out, Issue{Code: "bad_domain", Severity: SeverityError, RuleID: r.ID, Message: "域名含有不能写入 SmartDNS 的字符：" + s})
		}
	}
	switch r.MatchType {
	case model.MatchDomain, model.MatchSuffix:
		checkName(r.MatchValue)
	case model.MatchKeyword:
		if !regexp.MustCompile(`^[A-Za-z0-9._-]{1,64}$`).MatchString(r.MatchValue) {
			out = append(out, Issue{Code: "bad_keyword", Severity: SeverityError, RuleID: r.ID, Message: "关键词只能是字母、数字、点、下划线和短横线。"})
		}
	case model.MatchGeosite:
		if !regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`).MatchString(r.Geosite) && r.Geosite != "" {
			out = append(out, Issue{Code: "bad_domain", Severity: SeverityError, RuleID: r.ID, Message: "geosite 名称不合法。"})
		}
	case model.MatchRuleSet:
		if !rulesorder.RuleSetIDOK(r.RuleSet) {
			out = append(out, Issue{Code: "bad_rule_set", Severity: SeverityError, RuleID: r.ID, Field: "rule_set", Message: "规则集 ID 不合法。"})
		}
	case model.MatchCIDR:
		if _, err := netip.ParsePrefix(r.MatchValue); err != nil {
			if _, err2 := netip.ParseAddr(r.MatchValue); err2 != nil {
				out = append(out, Issue{Code: "bad_address", Severity: SeverityError, RuleID: r.ID, Message: "CIDR 无法解析：" + r.MatchValue})
			}
		}
	}
	for _, d := range r.Domains {
		checkName(d)
	}
	if r.SourceMAC != "" && !macRe.MatchString(r.SourceMAC) {
		out = append(out, Issue{Code: "bad_address", Severity: SeverityError, RuleID: r.ID, Message: "源 MAC 格式不正确。"})
	}
	if r.SourceIPv4 != "" {
		if ip, err := netip.ParseAddr(r.SourceIPv4); err != nil || !ip.Is4() {
			if _, err2 := netip.ParsePrefix(r.SourceIPv4); err2 != nil {
				out = append(out, Issue{Code: "bad_address", Severity: SeverityError, RuleID: r.ID, Message: "源 IPv4 无法解析。"})
			}
		}
	}
	if r.SourceIPv6 != "" {
		if ip, err := netip.ParseAddr(r.SourceIPv6); err != nil || !ip.Is6() {
			if _, err2 := netip.ParsePrefix(r.SourceIPv6); err2 != nil {
				out = append(out, Issue{Code: "bad_address", Severity: SeverityError, RuleID: r.ID, Message: "源 IPv6 无法解析。"})
			}
		}
	}
	return out
}

func safeDNS(s string) bool {
	s = strings.TrimPrefix(s, ".")
	if s == "" || strings.Contains(s, "..") || strings.ContainsAny(s, " \t\r\n'\"\\/$`;|&") {
		return false
	}
	for _, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '.' || r == '-' || r == '_' {
			continue
		}
		return false
	}
	return true
}

// checkListSource: the list source policy is one of three values, and two
// geosite names must not publish to the same file (lists.FileName).
func checkListSource(t model.Topology) []Issue {
	var out []Issue
	if s := t.Settings.ListSource; s != "" {
		if _, ok := lists.ParsePolicy(s); !ok {
			out = append(out, Issue{
				Code: "bad_list_source", Severity: SeverityError, Field: "list_source",
				Message: "名单源只能是 domestic（国内镜像）、overseas（海外）或 automatic（全自动）。",
			})
		}
	}
	files := map[string]string{}
	for _, r := range t.Rules {
		if r.Geosite == "" {
			continue
		}
		name := strings.ToLower(r.Geosite)
		f := lists.FileName(name)
		if prev, ok := files[f]; ok && prev != name {
			out = append(out, Issue{
				Code: "geosite_name_collision", Severity: SeverityError, RuleID: r.ID,
				Message: fmt.Sprintf("geosite「%s」和「%s」会写到同一个名单文件 %s.txt。", prev, name, f),
			})
			continue
		}
		files[f] = name
	}
	return out
}

// checkLANIPv6 limits settings.lan_ipv6_prefix where the gateway's
// classifier depends on it. A LAN prefix inside fc00::/7 is classified
// domestic (LAN NIC only) ahead of the classifier's ULA drop, so it must be
// one exact network that cannot reach tunnel or transit address space. A
// prefix that contains the whole ULA range (::/0, fc00::/6, ...) is never a
// LAN and is refused outright.
func checkLANIPv6(t model.Topology, lan netip.Prefix) []Issue {
	bad := func(msg string, a ...any) []Issue {
		return []Issue{{Code: "prefix_conflict", Severity: SeverityError, Message: fmt.Sprintf(msg, a...)}}
	}
	if !lan.Addr().Is6() || lan.Addr().Is4In6() {
		return bad("局域网 IPv6 前缀必须是 IPv6 前缀：%s", lan)
	}
	if !lan.Overlaps(ulaRange) {
		return nil
	}
	if lan.Bits() < ulaRange.Bits() {
		return bad("局域网 IPv6 前缀 %s 包含了整个 ULA 段 fc00::/7，不是一个局域网前缀。", lan)
	}
	// From here the LAN prefix is a ULA.
	if lan != lan.Masked() {
		return bad("局域网 IPv6 前缀是 ULA 时要写成网络地址，例如 %s。", lan.Masked())
	}
	if lan.Bits() < 48 {
		return bad("局域网 IPv6 前缀是 ULA 时长度必须在 /48 到 /128 之间（通常是 /64），%s 太宽。", lan)
	}
	if lan.Overlaps(remoteTunnelV6) {
		return bad("局域网 IPv6 前缀 %s 与隧道和中转地址段 fd66::/48 重叠。", lan)
	}
	if tp, err := netip.ParsePrefix(strings.TrimSpace(t.Settings.TransitV6Prefix)); err == nil && tp.Overlaps(lan) {
		return bad("局域网 IPv6 前缀 %s 与中转前缀 %s 重叠。", lan, tp.Masked())
	}
	return nil
}

// checkClientDNS describes what the two resolver settings do to clients
// (docs/architecture.md「客户端 IPv6 与 AAAA」「未列名单域名的国内解析」).
func checkClientDNS(t model.Topology) []Issue {
	var out []Issue
	st := t.Settings
	if !st.ClientsIPv6ViaGateway {
		out = append(out, Issue{
			Code: "aaaa_filtered", Severity: SeverityWarning, Field: "clients_ipv6_via_gateway",
			Message: "网关设置「客户端 IPv6 经本网关」关闭（默认）：除国内域名外，所有域名——没有命中规则的、每条规则的、地区组和钉死出口的——都不返回 AAAA。" +
				"客户端只拿到 IPv4 地址，经本网关进隧道，在同一出口回落 v4，不会改送到别的国家，也不会从家里路由器下发的 IPv6 绕过隧道。国内域名照常返回 AAAA，经家里路由器直连。" +
				"只有客户端的 IPv6 默认路由确实指向本网关（docs/test-device.md）时才打开它。",
		})
	} else {
		if st.LANIPv6Prefix == "" {
			out = append(out, Issue{
				Code: "clients_ipv6_no_prefix", Severity: SeverityWarning, Field: "clients_ipv6_via_gateway",
				Message: "声明了客户端 IPv6 经本网关，但没有填局域网 IPv6 前缀：国内 IPv6 的直连分流（chnroute6）按前缀判断，先填好 lan_ipv6_prefix。",
			})
		}
		if g, ok := t.GroupByID(st.DefaultGroup); ok {
			if gv6, known := groupCarriesV6(t, g); known && !gv6 {
				out = append(out, Issue{
					Code: "aaaa_filtered", Severity: SeverityWarning, GroupID: g.ID,
					Message: fmt.Sprintf("默认地区组 %s 里有成员没有 egress_v6：组选中（或枢纽可能切到）的出口不能端到端承载 IPv6 时，没有命中规则的域名一律不返回 AAAA，在同一出口回落 v4，不会改送到别的国家。", g.Name),
				})
			}
		}
	}
	if st.UnlistedDomesticDNS {
		out = append(out, Issue{
			Code: "unlisted_domestic_dns", Severity: SeverityWarning, Field: "unlisted_domestic_dns",
			Message: "「未列名单域名也问国内 DNS」已打开：不在任何名单、也没有命中规则的域名会同时发给国内解析器（经家宽直接发出），它们能看到这些域名，包括国外的。" +
				"只有国内解析器返回的全是中国地址时才采用并直连，否则用出口解析器的结果。DNS 泄漏测试里会出现国内解析器，这是预期的。",
		})
	}
	return out
}

// groupCarriesV6: every member of g is an exit with egress_v6 (the
// compiler's rule for a switchable group); known is false for an empty
// group (reported elsewhere).
func groupCarriesV6(t model.Topology, g model.RegionGroup) (v6, known bool) {
	if len(g.Members) == 0 {
		return false, false
	}
	for _, id := range g.Members {
		n, ok := t.NodeByID(id)
		if !ok || !n.EgressV6 {
			return false, true
		}
	}
	return true, true
}

// ------------------------------------------------------------ exit DNS ---

// DefaultDomesticResolvers are the domestic resolvers when
// settings.domestic_dot is empty (compile.domesticDoT).
var DefaultDomesticResolvers = []string{"223.5.5.5", "1.12.12.12"}

var (
	exitDNSPathRe = regexp.MustCompile(`^/[A-Za-z0-9._~/-]{0,127}$`)
	exitDNSCredRe = regexp.MustCompile(`^dnsacct-[a-z0-9-]{1,55}$`)
	// exitDNSRefused are the address ranges an exit's upstream may never
	// be in: this host, private and shared networks (the LAN, the tunnels'
	// ULA, CGNAT), link-local, multicast — an upstream there could be
	// reached through a tunnel or the domestic side instead of the exit's
	// own uplink.
	exitDNSRefused = []netip.Prefix{
		netip.MustParsePrefix("0.0.0.0/8"), netip.MustParsePrefix("10.0.0.0/8"), netip.MustParsePrefix("100.64.0.0/10"),
		netip.MustParsePrefix("127.0.0.0/8"), netip.MustParsePrefix("169.254.0.0/16"), netip.MustParsePrefix("172.16.0.0/12"),
		netip.MustParsePrefix("192.168.0.0/16"), netip.MustParsePrefix("224.0.0.0/3"),
		netip.MustParsePrefix("::/127"), netip.MustParsePrefix("fc00::/7"), netip.MustParsePrefix("fe80::/10"), netip.MustParsePrefix("ff00::/8"),
	}
)

// ExitDNSAccountValid is what an account value may be: one DNS label that
// is also a plain URL path segment (letters, digits, inner hyphens; 3–63).
var ExitDNSAccountValid = regexp.MustCompile(`^[A-Za-z0-9](?:[A-Za-z0-9-]{1,61}[A-Za-z0-9])$`)

// CheckExitDNSUpstream checks one upstream; node is "" for the global
// setting. Every message is about the shape only (no account value is
// ever part of an upstream).
func CheckExitDNSUpstream(t model.Topology, u model.ExitDNSUpstream, node string) []string {
	var bad []string
	switch u.Protocol {
	case model.ExitDNSDoT, model.ExitDNSDoH:
	case model.ExitDNSBuiltin:
		if node == "" {
			bad = append(bad, "全局设置不能是 builtin：不设置即为内置公共解析器")
		}
		if len(u.Addresses) > 0 || u.Port != 0 || u.TLSHostName != "" || u.Path != "" || u.AccountCredential != "" {
			bad = append(bad, "builtin 不带任何其它字段")
		}
		return bad
	default:
		return append(bad, fmt.Sprintf("协议只能是 dot 或 doh，不是「%s」", u.Protocol))
	}
	domestic := t.Settings.DomesticDoT
	if len(domestic) == 0 {
		domestic = DefaultDomesticResolvers
	}
	if len(u.Addresses) == 0 || len(u.Addresses) > 2 {
		bad = append(bad, "需要 1 到 2 个上游地址（由操作者给出，出口直接连接，不需要先解析上游自己的名字）")
	}
	seen := map[netip.Addr]bool{}
	for _, a := range u.Addresses {
		ip, err := netip.ParseAddr(a)
		if err != nil || ip.Zone() != "" {
			bad = append(bad, fmt.Sprintf("上游地址「%s」不是 IP 地址", a))
			continue
		}
		ip = ip.Unmap()
		if seen[ip] {
			bad = append(bad, fmt.Sprintf("上游地址 %s 重复", ip))
		}
		seen[ip] = true
		for _, p := range exitDNSRefused {
			if p.Contains(ip) {
				bad = append(bad, fmt.Sprintf("上游地址 %s 在 %s 里：只能是公网地址（不能经隧道、局域网或本机）", ip, p))
				break
			}
		}
		for _, d := range domestic {
			if dd, err := netip.ParseAddr(d); err == nil && dd.Unmap() == ip {
				bad = append(bad, fmt.Sprintf("上游地址 %s 是国内解析器：出口的解析不能交给国内一侧", ip))
			}
		}
	}
	if u.Port < 0 || u.Port > 65535 {
		bad = append(bad, fmt.Sprintf("端口 %d 不在 1–65535 之间", u.Port))
	}
	h := u.TLSHostName
	switch {
	case h == "":
		bad = append(bad, "需要 TLS 主机名：证书按它校验（没有跳过校验的选项）")
	case strings.Count(h, model.ExitDNSAccountToken) > 1 || strings.Contains(h, model.ExitDNSAccountToken) && !strings.HasPrefix(h, model.ExitDNSAccountToken+"."):
		bad = append(bad, "TLS 主机名里的 {account} 只能出现一次，并且必须是第一个标签（{account}.dns.example.net）")
	default:
		probe := strings.ToLower(strings.Replace(h, model.ExitDNSAccountToken, "acct", 1))
		if _, ok := rulesorder.NormDomain(probe); !ok || !strings.Contains(probe, ".") || len(probe) > 253 {
			bad = append(bad, fmt.Sprintf("TLS 主机名「%s」不是域名", h))
		}
	}
	switch {
	case u.Protocol == model.ExitDNSDoT && u.Path != "":
		bad = append(bad, "DoT 没有路径")
	case u.Protocol == model.ExitDNSDoH && u.Path == "":
		bad = append(bad, "DoH 需要 URL 路径（例如 /dns-query）")
	case u.Protocol == model.ExitDNSDoH:
		if strings.Count(u.Path, model.ExitDNSAccountToken) > 1 {
			bad = append(bad, "路径里的 {account} 只能出现一次")
		}
		if !exitDNSPathRe.MatchString(strings.Replace(u.Path, model.ExitDNSAccountToken, "acct", 1)) {
			bad = append(bad, "DoH 路径只能由字母、数字和 . _ ~ / - 组成，以 / 开头，不带查询串")
		}
	}
	switch {
	case u.UsesAccount() && u.AccountCredential == "":
		bad = append(bad, "用了 {account}，需要选择一个 DNS 账户标识凭据")
	case !u.UsesAccount() && u.AccountCredential != "":
		bad = append(bad, "选了 DNS 账户标识凭据，但主机名和路径里都没有 {account}")
	case u.AccountCredential != "" && !exitDNSCredRe.MatchString(u.AccountCredential):
		bad = append(bad, "DNS 账户标识凭据的 id 不合法")
	}
	return bad
}

// checkExitDNS: the global exit upstream and every exit's override.
func checkExitDNS(t model.Topology) []Issue {
	var out []Issue
	if u := t.Settings.ExitDNS; u != nil {
		for _, m := range CheckExitDNSUpstream(t, *u, "") {
			out = append(out, Issue{Code: "exit_dns_invalid", Severity: SeverityError, Field: "exit_dns", Message: "出口解析上游：" + m + "。"})
		}
	}
	for _, n := range t.Nodes {
		if n.ExitDNS == nil {
			continue
		}
		if n.Role != model.RoleExit || model.IsExternal(n) {
			out = append(out, Issue{Code: "exit_dns_invalid", Severity: SeverityError, NodeID: n.ID, Field: "exit_dns",
				Message: "出口解析上游只能设在受管出口上（外部 SOCKS 出口的解析经它的代理走固定的公共解析器）。"})
			continue
		}
		for _, m := range CheckExitDNSUpstream(t, *n.ExitDNS, n.ID) {
			out = append(out, Issue{Code: "exit_dns_invalid", Severity: SeverityError, NodeID: n.ID, Field: "exit_dns", Message: "出口 " + n.ID + " 的解析上游：" + m + "。"})
		}
	}
	return out
}
