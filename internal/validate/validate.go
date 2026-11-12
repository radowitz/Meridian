// Package validate enforces the design's path, transport, NAT, MTU, and rule checks.
package validate

import (
	"fmt"
	"net/netip"
	"sort"
	"strings"

	"github.com/radowitz/meridian/internal/model"
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
}

type PathReport struct {
	ExitID string   `json:"exit_id"`
	Nodes  []string `json:"nodes"`
	Links  []string `json:"links"`
	MTU    int      `json:"mtu"`
	MSS4   int      `json:"mss4"`
	MSS6   int      `json:"mss6"`
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
	out.Issues = append(out.Issues, checkLinks(t, nodes)...)

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
		path, links, ok := findPrimaryPath(t, nodes, gw.ID, exit.ID)
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
			continue
		}
		out.Issues = append(out.Issues, checkPathRoles(t, nodes, path, exit)...)
		mtu := pathMTU(t, links)
		repl := replacementMTU(t)
		if repl > 0 && repl < mtu {
			mtu = repl
		}
		if mtu > 0 && mtu < 1280 {
			out.Issues = append(out.Issues, Issue{
				Code: "mtu_too_low", Severity: SeverityError, ExitID: exit.ID,
				Message: fmt.Sprintf("到 %s 的路径 MTU 为 %d，低于 IPv6 最小 MTU 1280。", exit.Name, mtu),
			})
		}
		report := PathReport{ExitID: exit.ID, MTU: mtu, MSS4: mtu - 40, MSS6: mtu - 60}
		for _, id := range path {
			report.Nodes = append(report.Nodes, id)
		}
		for _, l := range links {
			report.Links = append(report.Links, l.ID)
		}
		out.Paths = append(out.Paths, report)
		out.Issues = append(out.Issues, checkPureV6(t, nodes, exit)...)
	}

	out.Issues = append(out.Issues, checkIXReplacement(t, nodes)...)
	out.Issues = append(out.Issues, checkSubnets(t)...)
	out.Issues = append(out.Issues, checkRules(t, nodes)...)
	if _, ok := SelectExit(t, "hk"); !ok {
		out.Issues = append(out.Issues, Issue{
			Code: "no_default_exit", Severity: SeverityError,
			Message: "默认境外池 hk 里没有可选出口。需要一个非家宽、最好是 IX 绑定的香港出口。",
		})
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
				Message: "网关地址不能是 ROS 192.168.100.1。",
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
		}
	}
	if t.Settings.ROSIPv4 == "" {
		out = append(out, Issue{Code: "missing_ros", Severity: SeverityError, Message: "需要 ROS 的 IPv4 地址（192.168.100.1），国内流量下一跳指向它。"})
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
			out = append(out, checkMesh(l, a, b)...)
		case model.TransportIXReplacementWSS:
			out = append(out, checkReplacementLink(l, a, b)...)
		}
		out = append(out, checkNATLink(t, l, a, b)...)
		out = append(out, checkAddrConflicts(t, l)...)
	}
	return out
}

func checkMesh(l model.Link, a, b model.Node) []Issue {
	var out []Issue
	if !l.Standby {
		out = append(out, Issue{
			Code: "mesh_not_standby", Severity: SeverityError, LinkID: l.ID,
			Message: "Cloudflare Mesh 只能作为枢纽到出口的备路，不能当主路，也不能当作 IX 的备路。",
		})
	}
	if involves(a, b, model.RoleGateway) || involves(a, b, model.RoleRelay) {
		out = append(out, Issue{
			Code: "mesh_bypasses_ix", Severity: SeverityError, LinkID: l.ID,
			Message: "Mesh 不能从家宽或阿里云直连境外，也不能绕过 IX。",
		})
	}
	roles := map[model.Role]bool{a.Role: true, b.Role: true}
	if !(roles[model.RoleHub] && roles[model.RoleExit]) {
		out = append(out, Issue{
			Code: "mesh_not_hub_exit", Severity: SeverityError, LinkID: l.ID,
			Message: "Mesh 边只能连接香港枢纽和某个出口。",
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
			Message: "IX 替换 WSS 只能是「阿里云 → 香港枢纽」或「家宽 → 香港枢纽」。",
		})
	}
	return out
}

func checkNATLink(t model.Topology, l model.Link, a, b model.Node) []Issue {
	_ = t
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
	if strings.TrimSpace(nat.EndpointV4) != "" {
		out = append(out, Issue{
			Code: "nat_endpoint_forbidden", Severity: SeverityError, NodeID: nat.ID, LinkID: l.ID,
			Message: fmt.Sprintf("%s 在 NAT 后面，不能把 Endpoint 写成它的公网地址。枢纽只保存对端公钥和 AllowedIPs。", nat.Name),
		})
	}
	if l.From != nat.ID || other.Role != model.RoleHub {
		out = append(out, Issue{
			Code: "nat_dial_direction", Severity: SeverityError, NodeID: nat.ID, LinkID: l.ID,
			Message: fmt.Sprintf("%s 必须由该节点拨向香港枢纽（链路方向：出口 → 枢纽）。不要由枢纽去拨它的公网地址。", nat.Name),
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
	for _, addr := range []string{l.FromV4, l.ToV4} {
		if addr == "" {
			continue
		}
		ip, err := netip.ParseAddr(addr)
		if err != nil {
			out = append(out, Issue{Code: "bad_address", Severity: SeverityError, LinkID: l.ID, Message: "隧道 IPv4 地址无法解析：" + addr})
			continue
		}
		if ros != "" && ip.String() == ros {
			out = append(out, Issue{Code: "ula_via_ros", Severity: SeverityError, LinkID: l.ID, Message: "隧道地址不能是 ROS " + ros + "。"})
		}
		if lan, err := netip.ParsePrefix(lanPrefix(t)); err == nil && lan.Contains(ip) {
			out = append(out, Issue{Code: "prefix_conflict", Severity: SeverityError, LinkID: l.ID, Message: "隧道 IPv4 落在局域网 " + lan.String() + " 里。"})
		}
	}
	ula, _ := netip.ParsePrefix(or(t.Settings.ULAPrefix, "fd66::/48"))
	for _, addr := range []string{l.FromULA, l.ToULA} {
		if addr == "" {
			continue
		}
		ip, err := netip.ParseAddr(addr)
		if err != nil || !ula.Contains(ip) {
			out = append(out, Issue{Code: "prefix_conflict", Severity: SeverityError, LinkID: l.ID, Message: "隧道 ULA 必须位于 " + ula.String() + "：" + addr})
		}
	}
	return out
}

func checkPathRoles(t model.Topology, nodes map[string]model.Node, path []string, exit model.Node) []Issue {
	var out []Issue
	var roles []model.Role
	for _, id := range path {
		roles = append(roles, nodes[id].Role)
	}
	want := []model.Role{model.RoleGateway, model.RoleRelay, model.RoleIX, model.RoleHub, model.RoleExit}
	if !subsequence(roles, want) {
		missing := "IX"
		code := "path_missing_ix"
		if !containsRole(roles, model.RoleRelay) {
			missing = "阿里云中继"
			code = "path_missing_relay"
		} else if !containsRole(roles, model.RoleIX) {
			missing = "深港 IX"
			code = "path_missing_ix"
		} else if !containsRole(roles, model.RoleHub) {
			missing = "香港枢纽"
			code = "path_missing_hub"
		}
		out = append(out, Issue{
			Code: code, Severity: SeverityError, ExitID: exit.ID,
			Message: fmt.Sprintf("到 %s 的主路径必须依序经过阿里云、深港 IX、香港枢纽。缺少%s。Mesh 不能用来绕过 IX。", exit.Name, missing),
		})
	}
	// Order: relay before ix before hub.
	if !ordered(roles, model.RoleRelay, model.RoleIX) || !ordered(roles, model.RoleIX, model.RoleHub) || !ordered(roles, model.RoleHub, model.RoleExit) {
		out = append(out, Issue{
			Code: "path_missing_ix", Severity: SeverityError, ExitID: exit.ID,
			Message: fmt.Sprintf("到 %s 的主路径顺序错误。正确顺序是网关 → 阿里云 → IX → 香港枢纽 → 出口。", exit.Name),
		})
	}
	_ = t
	return out
}

func checkPureV6(t model.Topology, nodes map[string]model.Node, exit model.Node) []Issue {
	if exit.PathV4 || !exit.PathV6 {
		return nil
	}
	hub := firstRole(t, model.RoleHub)
	if exit.V6Workaround == model.WorkaroundNone {
		return []Issue{{
			Code: "pure_v6_unreachable", Severity: SeverityError, NodeID: exit.ID, ExitID: exit.ID,
			Message: fmt.Sprintf("%s 是纯 IPv6 出口，而香港枢纽 path_v6=%v。枢纽没有 IPv6，必须先选择绕行（双栈中继、Mesh 或 v4 可达前置），否则拒绝保存。", exit.Name, hub.PathV6),
		}}
	}
	return nil
}

func checkIXReplacement(t model.Topology, nodes map[string]model.Node) []Issue {
	var ali, home bool
	for _, l := range t.Links {
		if l.Transport != model.TransportIXReplacementWSS || !l.Enabled {
			continue
		}
		a, b := nodes[l.From], nodes[l.To]
		roles := map[model.Role]bool{a.Role: true, b.Role: true}
		if roles[model.RoleRelay] && roles[model.RoleHub] && l.Standby {
			ali = true
		}
		if roles[model.RoleGateway] && roles[model.RoleHub] && l.Standby {
			home = true
		}
	}
	if ali && home {
		return nil
	}
	msg := "IX 替换 WSS 还没配齐。需要预先待命两条：阿里云 → 香港枢纽，以及家宽 → 香港枢纽。不要等 IX 故障再临时创建。"
	sev := SeverityWarning
	if t.Settings.IXReplacementMode {
		sev = SeverityError
		msg = "已经打开 IX 替换模式，但待命 WSS 没有预先部署。请先画好并启用待命隧道。"
	}
	return []Issue{{Code: "ix_replacement_not_provisioned", Severity: sev, Message: msg}}
}

func checkSubnets(t model.Topology) []Issue {
	var out []Issue
	type block struct {
		prefix netip.Prefix
		id     string
	}
	var blocks []block
	for _, l := range t.Links {
		if l.FromV4 != "" && l.ToV4 != "" {
			p, err := p2pPrefix(l.FromV4, l.ToV4)
			if err == nil {
				blocks = append(blocks, block{p, l.ID})
			}
		}
	}
	for i := 0; i < len(blocks); i++ {
		for j := i + 1; j < len(blocks); j++ {
			if blocks[i].prefix.Overlaps(blocks[j].prefix) && blocks[i].prefix != blocks[j].prefix {
				out = append(out, Issue{
					Code: "subnet_overlap", Severity: SeverityError, LinkID: blocks[i].id,
					Message: fmt.Sprintf("隧道网段 %s 与 %s 重叠。", blocks[i].prefix, blocks[j].prefix),
				})
			}
		}
	}
	return out
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
		exit, poolMembers, errIss := resolveRuleTarget(t, r)
		if errIss != nil {
			out = append(out, *errIss)
			continue
		}
		if residentialRequired(r) {
			if r.TargetExit != "" && (exit == nil || !exit.Residential) {
				out = append(out, Issue{
					Code: "residential_required", Severity: SeverityError, RuleID: r.ID,
					Message: fmt.Sprintf("规则「%s」必须落到 residential 香港家宽，不能使用机房出口。", r.Name),
				})
			}
			if r.TargetExit == "" {
				for _, m := range poolMembers {
					if !m.Residential {
						out = append(out, Issue{
							Code: "residential_required", Severity: SeverityError, RuleID: r.ID,
							Message: fmt.Sprintf("规则「%s」的池 %s 含有非家宽成员 %s。Netflix / Disney+ 一类只能走香港家宽。", r.Name, r.TargetPool, m.Name),
						})
						break
					}
				}
			}
		}
		if exit != nil && !exit.EgressV6 {
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
		if exit != nil && exit.Residential && r.TargetPool == "hk" {
			out = append(out, Issue{
				Code: "residential_in_default_pool", Severity: SeverityWarning, RuleID: r.ID,
				Message: "家宽不进默认境外池。",
			})
		}
	}
	for _, n := range nodes {
		if n.Residential && n.Pool == "hk" {
			out = append(out, Issue{
				Code: "residential_in_default_pool", Severity: SeverityWarning, NodeID: n.ID,
				Message: fmt.Sprintf("%s 标了家宽，不应放进默认境外池 hk。请使用 hk-residential。", n.Name),
			})
		}
	}
	return out
}

func residentialRequired(r model.Rule) bool {
	if r.RequireResidential {
		return true
	}
	blob := strings.ToLower(r.Name + " " + r.MatchValue + " " + r.Geosite)
	return strings.Contains(blob, "netflix") || strings.Contains(blob, "disney")
}

func resolveRuleTarget(t model.Topology, r model.Rule) (*model.Node, []model.Node, *Issue) {
	if r.TargetExit != "" {
		n, ok := t.NodeByID(r.TargetExit)
		if !ok || n.Role != model.RoleExit {
			return nil, nil, &Issue{Code: "exit_not_found", Severity: SeverityError, RuleID: r.ID, Message: "规则指向的出口不存在。"}
		}
		return &n, nil, nil
	}
	if r.TargetPool == "" {
		return nil, nil, &Issue{Code: "exit_not_found", Severity: SeverityError, RuleID: r.ID, Message: "规则没有出口或池。"}
	}
	var members []model.Node
	for _, n := range t.Nodes {
		if n.Role == model.RoleExit && n.Pool == r.TargetPool {
			members = append(members, n)
		}
	}
	if len(members) == 0 {
		return nil, nil, &Issue{Code: "exit_not_found", Severity: SeverityError, RuleID: r.ID, Message: fmt.Sprintf("池 %s 里没有出口。", r.TargetPool)}
	}
	chosen, _ := SelectExit(t, r.TargetPool)
	return &chosen, members, nil
}

// SelectExit picks the Phase-1 member of a pool: IX-bound first, residential
// excluded from the default hk pool, then the lowest ID.
func SelectExit(t model.Topology, pool string) (model.Node, bool) {
	var members []model.Node
	for _, n := range t.Nodes {
		if n.Role != model.RoleExit || n.Pool != pool {
			continue
		}
		if pool == "hk" && n.Residential {
			continue
		}
		members = append(members, n)
	}
	if len(members) == 0 {
		return model.Node{}, false
	}
	sort.Slice(members, func(i, j int) bool {
		if members[i].IXBound != members[j].IXBound {
			return members[i].IXBound
		}
		return members[i].ID < members[j].ID
	})
	return members[0], true
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
	var roles []model.Role
	for _, id := range path {
		roles = append(roles, nodes[id].Role)
	}
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

func pathMTU(t model.Topology, links []model.Link) int {
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
	_ = t
	return mtu
}

func replacementMTU(t model.Topology) int {
	mtu := 0
	for _, l := range t.Links {
		if l.Transport != model.TransportIXReplacementWSS || !l.Enabled {
			continue
		}
		h := hopMTU(l)
		if mtu == 0 || h < mtu {
			mtu = h
		}
	}
	return mtu
}

// hopMTU returns the interface MTU that TCP must survive on this hop.
// udp_wss_failover contributes the smaller of the two legs so a switch
// does not black-hole existing sessions. Dedicated line has no extra encap.
func hopMTU(l model.Link) int {
	switch l.Transport {
	case model.TransportDedicatedLine:
		return 0
	case model.TransportUDPWSSFailover:
		udp := orInt(l.MTU, 1412)
		wss := orInt(l.WSSMTU, 1360)
		if wss < udp {
			return wss
		}
		return udp
	case model.TransportWGOverWSS, model.TransportIXReplacementWSS:
		return orInt(l.MTU, 1360)
	case model.TransportCFMesh:
		return orInt(l.MTU, 1280)
	default:
		return orInt(l.MTU, 1420)
	}
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
	return "192.168.100.0/24"
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
