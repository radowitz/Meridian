package validate

import (
	"fmt"

	"github.com/radowitz/meridian/internal/model"
)

// The main path without an IX (docs/architecture.md「主路径」).
//
// A topology with an IX (an ix node or an ix_line hub, enabled links or
// not: model.Topology.HasIX) keeps the rule gateway → relay → IX → primary
// hub → exit and its messages unchanged. Without one the main path is
// gateway → relay → primary hub → exit over enabled, non-standby links
// (primaryLink): the gateway's first hop is a relay, the relay's next hop
// is the designated primary hub. Mesh edges, standby links (the backup
// hub's WG over WSS) and disabled links never make a main path, and the
// backup hub cannot stand in for the primary.

// nodesDirect: no relay, hub or IX at all (model.Topology.DirectExits).
// The main path is then gateway → exit (gateway → relay exit → nested
// exit for a nested one) over enabled, non-standby links.
func nodesDirect(nodes map[string]model.Node) bool {
	gw := false
	for _, n := range nodes {
		switch n.Role {
		case model.RoleRelay, model.RoleHub, model.RoleIX:
			return false
		case model.RoleGateway:
			gw = true
		}
	}
	return gw
}

// directPathSatisfies: gateway → exit, every hop after the gateway an exit.
func directPathSatisfies(nodes map[string]model.Node, path []string) bool {
	if len(path) < 2 || nodes[path[0]].Role != model.RoleGateway {
		return false
	}
	for _, id := range path[1:] {
		if nodes[id].Role != model.RoleExit {
			return false
		}
	}
	return true
}

func nodesHaveIX(nodes map[string]model.Node) bool {
	for _, n := range nodes {
		if n.Role == model.RoleIX || model.IsIXHub(n) {
			return true
		}
	}
	return false
}

func primaryOf(nodes map[string]model.Node) model.Node {
	t := model.Topology{}
	for _, n := range nodes {
		t.Nodes = append(t.Nodes, n)
	}
	n, _ := t.PrimaryHub()
	return n
}

// nodesRelayless: a hub topology without any relay (the single-relay
// template: the one domestic server is the hub). Its main path is gateway
// → primary hub → exit.
func nodesRelayless(nodes map[string]model.Node) bool {
	hub := false
	for _, n := range nodes {
		switch n.Role {
		case model.RoleRelay, model.RoleIX:
			return false
		case model.RoleHub:
			hub = true
		}
	}
	return hub
}

// noIXHubLen: how many nodes the main path has up to the primary hub.
func noIXHubLen(nodes map[string]model.Node) int {
	if nodesRelayless(nodes) {
		return 2
	}
	return 3
}

// noIXHubPrefix: path starts gateway → relay → primary hub (gateway →
// primary hub without relays).
func noIXHubPrefix(nodes map[string]model.Node, path []string) bool {
	k := noIXHubLen(nodes)
	if len(path) < k {
		return false
	}
	primary := primaryOf(nodes)
	return primary.ID != "" &&
		nodes[path[0]].Role == model.RoleGateway &&
		(k == 2 || nodes[path[1]].Role == model.RoleRelay) &&
		path[k-1] == primary.ID
}

// noIXPathSatisfies: gateway → relay → primary hub → … → exit, with no
// other hub after the primary.
func noIXPathSatisfies(nodes map[string]model.Node, path []string) bool {
	k := noIXHubLen(nodes)
	if !noIXHubPrefix(nodes, path) || len(path) < k+1 {
		return false
	}
	for _, id := range path[k:] {
		if r := nodes[id].Role; r == model.RoleHub || r == model.RoleRelay || r == model.RoleGateway {
			return false
		}
	}
	return nodes[path[len(path)-1]].Role == model.RoleExit
}

// hubPrefixSatisfies: path (gateway to the primary hub) is a valid start of
// the main path. With an IX this is the original ordering check.
func hubPrefixSatisfies(nodes map[string]model.Node, path []string) bool {
	if !nodesHaveIX(nodes) {
		return noIXHubPrefix(nodes, path) && len(path) == noIXHubLen(nodes)
	}
	roles := pathRoles(nodes, path)
	return ordered(roles, model.RoleRelay, model.RoleIX) && ordered(roles, model.RoleIX, model.RoleHub)
}

func checkNoIXPathRoles(t model.Topology, nodes map[string]model.Node, path []string, exit model.Node) []Issue {
	if nodesDirect(nodes) {
		if directPathSatisfies(nodes, path) {
			return nil
		}
		return []Issue{{Code: "path_order", Severity: SeverityError, ExitID: exit.ID,
			Message: fmt.Sprintf("到 %s 的主路径要由网关直接连到出口（启用、非待命的链路）。", exit.Name)}}
	}
	if noIXPathSatisfies(nodes, path) {
		return nil
	}
	primary := primaryHub(t)
	hubName := "主枢纽"
	if primary.Name != "" {
		hubName = "主枢纽 " + primary.Name
	}
	roles := pathRoles(nodes, path)
	onPath := func(id string) bool { return id != "" && containsStr(path, id) }
	var code, msg string
	switch {
	case nodesRelayless(nodes) && !onPath(primary.ID):
		code = "path_missing_hub"
		msg = fmt.Sprintf("到 %s 的主路径必须由网关经%s到出口。", exit.Name, hubName)
	case nodesRelayless(nodes):
		code = "path_order"
		msg = fmt.Sprintf("到 %s 的主路径顺序错误。正确顺序是网关 → %s → 出口，各段都要是启用、非待命的链路。", exit.Name, hubName)
	case !containsRole(roles, model.RoleRelay):
		code = "path_missing_relay"
		msg = fmt.Sprintf("到 %s 的主路径必须依序经过中继、%s。缺少中继。Mesh 和待命链路不能代替主路径。", exit.Name, hubName)
	case !onPath(primary.ID):
		code = "path_missing_hub"
		msg = fmt.Sprintf("到 %s 的主路径必须依序经过中继、%s。缺少%s；备用枢纽只在主路径整体失败时接管，不能当主路径。", exit.Name, hubName, hubName)
	default:
		code = "path_order"
		msg = fmt.Sprintf("到 %s 的主路径顺序错误。正确顺序是网关 → 中继 → %s → 出口，各段都要是启用、非待命的链路。", exit.Name, hubName)
	}
	return []Issue{{Code: code, Severity: SeverityError, ExitID: exit.ID, Message: msg}}
}

// checkDirect: what a direct-exit topology (no relay, hub or IX) cannot
// carry yet. The gateway is the hub for its exits there, but the hub-only
// machinery for exits that are not the gateway's own tunnel (a nested exit
// behind a relay exit, an external SOCKS exit on a carrier, a pure-IPv6
// exit's relay or Mesh workaround) is not compiled for the gateway; such
// a topology is refused instead of compiling to something that cannot
// carry those exits. Every other topology is unaffected.
func checkDirect(t model.Topology) []Issue {
	if !t.DirectExits() {
		return nil
	}
	var out []Issue
	for _, n := range t.Nodes {
		if n.Role != model.RoleExit {
			continue
		}
		var why string
		switch {
		case model.IsNested(n):
			why = "经中继出口到达的出口（via_exit）"
		case model.IsExternal(n):
			why = "外部 SOCKS 出口"
		case n.V6Workaround != model.WorkaroundNone:
			why = "纯 IPv6 出口的绕行（双栈中继或 Mesh）"
		case n.DualstackRelay:
			why = "双栈中继"
		}
		if why != "" {
			out = append(out, Issue{Code: "direct_unsupported", Severity: SeverityError, NodeID: n.ID, ExitID: n.ID,
				Message: fmt.Sprintf("%s：网关直连出口的拓扑暂不支持%s。改用经枢纽的拓扑，或去掉这一项。", n.Name, why)})
		}
	}
	for _, l := range t.Links {
		if !l.Enabled {
			continue
		}
		switch l.Transport {
		case model.TransportDirectWG:
			if !l.Standby {
				continue
			}
		}
		out = append(out, Issue{Code: "direct_unsupported", Severity: SeverityError, LinkID: l.ID,
			Message: fmt.Sprintf("链路 %s：网关直连出口时每条链路是一条常开的 WireGuard（direct_wg），暂不支持 WSS、待命链路或 Mesh。", linkLabel(l))})
	}
	return out
}

func linkLabel(l model.Link) string {
	if l.Name != "" {
		return l.Name
	}
	return l.ID
}

// checkRelayless: a hub topology without relays (the single-relay
// template: the gateway's one domestic server is the hub). The gateway's
// way to it is one plain WireGuard (direct_wg); a UDP/WSS pair, WSS or a
// backup hub need the relay machinery and are refused here.
func checkRelayless(t model.Topology) []Issue {
	nodes := map[string]model.Node{}
	for _, n := range t.Nodes {
		nodes[n.ID] = n
	}
	if !nodesRelayless(nodes) {
		return nil
	}
	var out []Issue
	if b, ok := t.BackupHub(); ok {
		out = append(out, Issue{Code: "relayless_unsupported", Severity: SeverityError, NodeID: b.ID,
			Message: fmt.Sprintf("%s：没有中继时不支持备用枢纽。加一台中继（中继 + 枢纽），或去掉备用枢纽。", b.Name)})
	}
	for _, l := range t.Links {
		a, b := nodes[l.From], nodes[l.To]
		if !l.Enabled || !(a.Role == model.RoleGateway && b.Role == model.RoleHub || b.Role == model.RoleGateway && a.Role == model.RoleHub) {
			continue
		}
		if l.Transport != model.TransportDirectWG || l.Standby {
			out = append(out, Issue{Code: "relayless_unsupported", Severity: SeverityError, LinkID: l.ID,
				Message: fmt.Sprintf("链路 %s：没有中继时网关到枢纽是一条常开的 WireGuard（direct_wg）。", linkLabel(l))})
		}
	}
	return out
}
