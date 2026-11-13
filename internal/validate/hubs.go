package validate

import (
	"fmt"
	"net/netip"
	"strings"

	"github.com/radowitz/meridian/internal/model"
)

// Primary hub, backup hub and the IX as a managed hub
// (docs/architecture.md「主枢纽与备用枢纽」).
//
// A topology has one or two hubs. The primary carries the main path
// (gateway → relay → IX → primary → exit); it may be the IX itself
// (ix_line: a loginable server on the dedicated line, with a domestic
// ingress address the relays dial and a Hong Kong egress address toward the
// exits). The backup hub is reached from the gateway by WG over WSS
// (ix_replacement_wss, standby) only while the whole main path is down, and
// reaches the same exits through tunnels of its own. What this version
// cannot compile soundly with a backup hub is refused here, by name, rather
// than compiled half-way: Mesh edges and relay links to the backup hub,
// several relays, pure-IPv6 exits behind a workaround and the manual
// IX-replacement switch.

// primaryHub is model.Topology.PrimaryHub without the ok flag.
func primaryHub(t model.Topology) model.Node {
	n, _ := t.PrimaryHub()
	return n
}

// pathRoles maps a node path to roles; the IX hub stands for both the IX
// and the hub, in that order (it is the IX, and it is where the hub's work
// happens).
func pathRoles(nodes map[string]model.Node, path []string) []model.Role {
	var roles []model.Role
	for _, id := range path {
		n := nodes[id]
		if model.IsIXHub(n) {
			roles = append(roles, model.RoleIX, model.RoleHub)
			continue
		}
		roles = append(roles, n.Role)
	}
	return roles
}

// tunnelTransport: the link becomes a WireGuard interface.
func tunnelTransport(tr model.Transport) bool {
	switch tr {
	case model.TransportDirectWG, model.TransportWGOverWSS, model.TransportUDPWSSFailover, model.TransportIXReplacementWSS:
		return true
	}
	return false
}

func checkHubs(t model.Topology, nodes map[string]model.Node) []Issue {
	var out []Issue
	add := func(code, nodeID, linkID, field, format string, a ...any) {
		out = append(out, Issue{Code: code, Severity: SeverityError, NodeID: nodeID, LinkID: linkID, Field: field, Message: fmt.Sprintf(format, a...)})
	}
	hubs := t.Hubs()
	for _, n := range t.Nodes {
		switch n.HubTier {
		case "", model.HubPrimary, model.HubBackup:
		default:
			add("invalid_field", n.ID, "", "hub_tier", "节点 %s 的 hub_tier 只能是 primary（主枢纽）或 backup（备用枢纽）。", n.Name)
		}
		if n.Role != model.RoleHub {
			if n.HubTier != "" {
				add("hub_tier_not_hub", n.ID, "", "hub_tier", "%s 不是枢纽，不能设置主备（hub_tier）。", n.Name)
			}
			if n.IXLine {
				add("ix_line_not_hub", n.ID, "", "ix_line", "%s 不是枢纽。「IX 即主枢纽」只能设在枢纽节点上；不可登录的专线仍用 ix 角色。", n.Name)
			}
		}
		if !model.IsIXHub(n) && (strings.TrimSpace(n.IngressV4) != "" || strings.TrimSpace(n.IngressInterface) != "") {
			add("ingress_without_ix_line", n.ID, "", "ingress_v4", "%s 填了国内入口地址或接口，但没有标成「IX 即主枢纽」（ix_line）。入口地址只对 IX 枢纽有意义。", n.Name)
		}
		if iss := checkIface(n.IngressInterface, "节点 "+n.Name+" 的国内入口接口"); iss != nil {
			iss.NodeID, iss.Field = n.ID, "ingress_interface"
			out = append(out, *iss)
		}
	}
	switch {
	case len(hubs) > 2:
		add("too_many_hubs", "", "", "hub_tier", "拓扑里有 %d 个枢纽。最多一个主枢纽和一个备用枢纽。", len(hubs))
	case len(hubs) == 2:
		tiers := map[model.HubTier]int{}
		for _, h := range hubs {
			tiers[h.HubTier]++
		}
		if tiers[model.HubPrimary] != 1 || tiers[model.HubBackup] != 1 {
			add("hub_tier_ambiguous", hubs[0].ID, "", "hub_tier", "有两个枢纽时，一个必须是主枢纽（hub_tier: primary），另一个是备用枢纽（hub_tier: backup）。")
		}
	case len(hubs) == 1 && hubs[0].HubTier == model.HubBackup:
		add("backup_without_primary", hubs[0].ID, "", "hub_tier", "只有一个枢纽 %s，却标成了备用枢纽。备用枢纽要和一个主枢纽一起用。", hubs[0].Name)
	}
	ixHub := false
	for _, h := range hubs {
		if !h.IXLine {
			continue
		}
		ixHub = true
		if h.HubTier == model.HubBackup {
			add("ix_line_on_backup", h.ID, "", "ix_line", "备用枢纽 %s 不能是 IX：备用枢纽是主链路整体失败时网关经 WSS 直连的另一台公网机器。", h.Name)
		}
		if !h.Managed {
			add("ix_hub_unmanaged", h.ID, "", "managed", "%s 标成了「IX 即主枢纽」，必须是受管节点（面板要登录它下发配置）。不可登录的专线请用 ix 角色。", h.Name)
		}
		if a, err := netip.ParseAddr(strings.TrimSpace(h.IngressV4)); err != nil || !a.Is4() {
			add("ix_ingress_missing", h.ID, "", "ingress_v4", "IX 枢纽 %s 需要国内入口地址（ingress_v4，中继拨入的 IPv4）。香港出口地址填在 endpoint_v4。", h.Name)
		}
	}
	if ixHub {
		for _, n := range t.Nodes {
			if n.Role == model.RoleIX {
				add("ix_role_with_ix_hub", n.ID, "", "role", "主枢纽已经是 IX（ix_line），拓扑里不能再有不可管的 IX 节点 %s：删掉它，让中继直接连到 IX 枢纽。", n.Name)
			}
		}
		for _, l := range t.Links {
			if l.Transport != model.TransportDedicatedLine {
				continue
			}
			if model.IsIXHub(nodes[l.From]) || model.IsIXHub(nodes[l.To]) {
				add("ix_hub_dedicated_line", "", l.ID, "transport", "链路 %s 是 dedicated_line，但它连着 IX 枢纽。中继到 IX 枢纽用 direct_wg（或 udp_wss_failover），专线本身就是这段 WireGuard 走的线路。", linkName(l))
			}
		}
	}
	if !t.DualHub() {
		return out
	}
	out = append(out, checkDualHub(t, nodes)...)
	return out
}

func linkName(l model.Link) string {
	if l.Name != "" {
		return l.Name
	}
	return l.ID
}

// checkDualHub: the backup hub's wiring, and what is not supported with it.
func checkDualHub(t model.Topology, nodes map[string]model.Node) []Issue {
	var out []Issue
	add := func(code, nodeID, linkID, field, format string, a ...any) {
		out = append(out, Issue{Code: code, Severity: SeverityError, NodeID: nodeID, LinkID: linkID, Field: field, Message: fmt.Sprintf(format, a...)})
	}
	primary, _ := t.PrimaryHub()
	backup, _ := t.BackupHub()
	if t.Settings.IXReplacementMode {
		out = append(out, Issue{Code: "ix_replacement_mode_dual_hub", Severity: SeverityError, Field: "ix_replacement_mode",
			Message: "有备用枢纽时不使用「IX 替换模式」：网关在主链路（网关 → 中继 → IX）整体失败时自动改走备用枢纽，恢复后自动切回。关掉 ix_replacement_mode。"})
	}
	var relays []model.Node
	for _, n := range t.Nodes {
		if n.Role == model.RoleRelay {
			relays = append(relays, n)
		}
	}
	if len(relays) > 1 {
		add("dual_hub_multiple_relays", relays[1].ID, "", "role", "有备用枢纽时这一版只支持一台国内中继（拓扑里有 %d 台）。多中继分担与按质量切换在后续版本提供；在那之前请只保留一台中继。", len(relays))
	}
	backupLinks := 0
	for _, l := range t.Links {
		if !l.Enabled {
			continue
		}
		a, b := nodes[l.From], nodes[l.To]
		touches := func(id string) bool { return l.From == id || l.To == id }
		if a.Role == model.RoleHub && b.Role == model.RoleHub {
			add("hub_to_hub_link", "", l.ID, "", "链路 %s 连接了两个枢纽。主备枢纽之间不建隧道：各自连出口，网关选择走哪一个。", linkName(l))
			continue
		}
		if l.Transport == model.TransportCFMesh && touches(backup.ID) {
			add("mesh_backup_hub_unsupported", "", l.ID, "transport", "Mesh 边 %s 连着备用枢纽 %s。这一版 Mesh 备路只用于主枢纽到出口；备用枢纽到出口请用 WireGuard。", linkName(l), backup.Name)
		}
		if touches(backup.ID) && (a.Role == model.RoleRelay || b.Role == model.RoleRelay) {
			add("backup_hub_relay_link_unsupported", "", l.ID, "", "链路 %s 连接中继和备用枢纽。备用枢纽只由网关经 WG over WSS 直连（ix_replacement_wss），中继经备用枢纽的路径这一版不支持。", linkName(l))
		}
		if l.Transport == model.TransportIXReplacementWSS {
			switch {
			case touches(primary.ID):
				add("replacement_to_primary", "", l.ID, "to", "有备用枢纽时，WSS 备路（ix_replacement_wss）要连到备用枢纽 %s，而不是主枢纽 %s。", backup.Name, primary.Name)
			case touches(backup.ID) && (a.Role == model.RoleGateway || b.Role == model.RoleGateway):
				if !l.Standby {
					add("ix_replacement_not_standby", "", l.ID, "standby", "网关到备用枢纽的 WSS 必须预先待命（standby），默认不进路由表。")
				}
				backupLinks++
			}
		}
		if touches(backup.ID) && (a.Role == model.RoleGateway || b.Role == model.RoleGateway) && l.Transport != model.TransportIXReplacementWSS {
			add("backup_hub_wrong_transport", "", l.ID, "transport", "网关到备用枢纽的链路 %s 只能是 ix_replacement_wss（WG over WSS，待命）。", linkName(l))
		}
	}
	switch {
	case backupLinks == 0:
		add("backup_hub_not_wired", backup.ID, "", "", "备用枢纽 %s 还没有接上网关：画一条网关 → %s 的 ix_replacement_wss（待命）链路。主链路整体失败时网关改走这条 WSS。", backup.Name, backup.Name)
	case backupLinks > 1:
		add("backup_hub_ambiguous", backup.ID, "", "", "网关到备用枢纽 %s 有 %d 条 WSS 链路，只能有一条。", backup.Name, backupLinks)
	}
	exits := exitsOf(t)
	for _, e := range exits {
		if e.DualstackRelay || (pureV6(e) && e.V6Workaround != model.WorkaroundNone) {
			add("dual_hub_unsupported_exit", e.ID, "", "v6_workaround", "出口 %s 经双栈中继、Mesh 或 v4 前置到达（或自己是双栈中继）。有备用枢纽时这一版不支持这类出口：两个枢纽要各有一条到它的 WireGuard。", e.Name)
			continue
		}
		for _, h := range []model.Node{primary, backup} {
			if !hubTunnelTo(t, h.ID, e.ID) {
				add("exit_missing_hub_tunnel", e.ID, "", "", "出口 %s 没有到%s %s 的隧道。有备用枢纽时，每个出口都要和两个枢纽各有一条启用的、非待命的 WireGuard（direct_wg 或 WSS），备用枢纽接管时组和规则才都有路可走。", e.Name, tierName(h.HubTier), h.Name)
			}
		}
	}
	return out
}

func tierName(t model.HubTier) string {
	if t == model.HubBackup {
		return "备用枢纽"
	}
	return "主枢纽"
}

// hubTunnelTo: an enabled, non-standby WireGuard link joins hub and exit.
func hubTunnelTo(t model.Topology, hubID, exitID string) bool {
	for _, l := range t.Links {
		if !l.Enabled || l.Standby || !tunnelTransport(l.Transport) || l.Transport == model.TransportIXReplacementWSS {
			continue
		}
		if (l.From == hubID && l.To == exitID) || (l.To == hubID && l.From == exitID) {
			return true
		}
	}
	return false
}

// HubIDs lists the hubs as (primary, backup) IDs; backup is "" without one.
func HubIDs(t model.Topology) (primary, backup string) {
	p, _ := t.PrimaryHub()
	b, _ := t.BackupHub()
	return p.ID, b.ID
}
