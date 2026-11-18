package preflight

import "github.com/radowitz/meridian/internal/model"

// CodeNoLink (blocking, panel-side): a managed relay, hub or exit has no
// enabled tunnel link in the topology. Its scripts would have no tunnel
// interface to route through, so it is refused before anything connects
// to the server.
const CodeNoLink = "node_has_no_link"

// NoLinkFinding returns the blocking finding for a managed non-gateway
// node without an enabled link (disabled links do not count), or nil.
func NoLinkFinding(t model.Topology, nodeID string) *Finding {
	n, ok := t.NodeByID(nodeID)
	if !ok || !n.Managed || n.Role == model.RoleGateway || n.Role == model.RoleIX {
		return nil
	}
	if hasTunnel(t, nodeID) {
		return nil
	}
	target := "网关/枢纽"
	switch n.Role {
	case model.RoleRelay:
		target = "网关"
	case model.RoleHub:
		target = "中继或 IX"
		if !t.HasIX() {
			target = "中继"
		}
	case model.RoleExit:
		target = "枢纽"
	}
	return &Finding{Severity: Blocking, Code: CodeNoLink, Resource: nodeID,
		Message: "这个节点还没有链路：先在拓扑页把它连到" + target,
		Action:  "在拓扑页给它加一条启用的链路，保存后重新预检。"}
}

// NoLinkFindings lists NoLinkFinding for every node of t that has one.
func NoLinkFindings(t model.Topology) []Finding {
	out := []Finding{}
	for _, n := range t.Nodes {
		if f := NoLinkFinding(t, n.ID); f != nil {
			out = append(out, *f)
		}
	}
	return out
}

// hasTunnel: the node ends at least one tunnel the compiler materialises.
// An enabled link whose transport carries a tunnel counts (a dedicated line
// alone does not). A hub behind a legacy unmanaged IX (dedicated_line hub ↔
// ix) also counts when that IX has an enabled tunnel link: the relays'
// tunnels to the IX terminate on the hub.
func hasTunnel(t model.Topology, nodeID string) bool {
	for _, l := range t.Links {
		if l.Enabled && (l.From == nodeID || l.To == nodeID) && model.TunnelTransport(l.Transport) {
			return true
		}
	}
	for _, l := range t.Links {
		if !l.Enabled || l.Transport != model.TransportDedicatedLine || (l.From != nodeID && l.To != nodeID) {
			continue
		}
		other := l.To
		if other == nodeID {
			other = l.From
		}
		if o, ok := t.NodeByID(other); !ok || o.Role != model.RoleIX {
			continue
		}
		for _, k := range t.Links {
			if k.Enabled && (k.From == other || k.To == other) && model.TunnelTransport(k.Transport) {
				return true
			}
		}
	}
	return false
}
