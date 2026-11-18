package validate

import (
	"net/netip"
	"strings"

	"github.com/radowitz/meridian/internal/model"
)

// Endpoint access: what the gateway does with LAN traffic addressed to a
// tunnel endpoint (a relay, a hub, an exit, an IX ingress). It used to drop
// every endpoint (set underlay4, "clients cannot bypass the tunnel by
// talking to an endpoint"); now each endpoint address gets one class:
//
//   - direct: a domestic endpoint (a relay's endpoint_v4/endpoint_v6, an IX
//     hub's ingress_v4). The domestic mark, table 100, the home uplink: the
//     same path the gateway's own outer packets to it take, so nothing
//     foreign is exposed. A port forward on a relay (the IX's SSH entry on
//     the Shanghai relay) is reached this way.
//   - tunnel: a foreign endpoint (a hub's or exit's address, an IX hub's
//     Hong Kong egress). The default group's mark, ahead of the rules and
//     chnroute, so it never leaves on the home uplink, whatever list
//     happens to hold the address.
//     A foreign endpoint the gateway itself dials (the backup hub over WSS)
//     is tunnel too: the inner packet is addressed to that peer and
//     delivered there, while the gateway's own outer packets use the main
//     table, so there is no recursion.
//   - blocked: kept dropped, with Reason: a foreign endpoint whose address
//     family the default group does not carry, or every foreign endpoint
//     when the default target is not a tunnel at all.
//
// The gateway's own outer packets (WireGuard with the underlay fwmark,
// wstunnel's TCP) are locally generated and never pass the classify chain:
// they are unchanged by any of this.
const (
	EndpointDirect  = "direct"
	EndpointTunnel  = "tunnel"
	EndpointBlocked = "blocked"
)

// EndpointAccess is one endpoint address and its class.
type EndpointAccess struct {
	Addr     string `json:"addr"`
	Family   int    `json:"family"` // 4 or 6
	NodeID   string `json:"node_id"`
	NodeName string `json:"node_name,omitempty"`
	Class    string `json:"class"`
	Reason   string `json:"reason"`
}

// EndpointDomestic: addr of node n is a domestic endpoint (a relay's own
// address, an IX hub's domestic ingress).
func EndpointDomestic(n model.Node, addr string) bool {
	if n.Role == model.RoleRelay {
		return true
	}
	return model.IsIXHub(n) && addr != "" && strings.TrimSpace(n.IngressV4) == addr
}

// ClassifyEndpoint decides one endpoint address. gwPeer: the gateway itself
// has a tunnel to n. defTunnel4/6: the default group's target is a tunnel
// that carries that family.
func ClassifyEndpoint(n model.Node, addr string, gwPeer, defTunnel4, defTunnel6 bool) EndpointAccess {
	a, err := netip.ParseAddr(addr)
	fam := 4
	if err == nil && a.Is6() && !a.Is4In6() {
		fam = 6
	}
	e := EndpointAccess{Addr: addr, Family: fam, NodeID: n.ID, NodeName: n.Name}
	switch {
	case EndpointDomestic(n, addr):
		e.Class, e.Reason = EndpointDirect, "国内端点（中继或国内入口），按国内直连走家宽"
	case fam == 4 && !defTunnel4, fam == 6 && !defTunnel6:
		e.Class, e.Reason = EndpointBlocked, "境外端点，默认组不能用这个地址族经隧道承载它，不允许走家宽，继续丢弃"
	case gwPeer:
		// The gateway's own outer packets to this peer (WireGuard with its
		// fwmark, or the local wstunnel TCP) are locally generated and
		// routed by the main table; client packets carry the default
		// group's mark and enter the tunnel. Even when this peer carries the
		// default group, the inner packet is addressed to the peer itself
		// and is delivered there: no recursion.
		e.Class, e.Reason = EndpointTunnel, "境外端点（网关也直接连它承载隧道）：客户端流量带默认组标记进隧道，网关自己的外层包不受影响，不会递归"
	default:
		e.Class, e.Reason = EndpointTunnel, "境外端点，按普通境外流量经默认组的隧道出口，不走家宽"
	}
	return e
}

// EndpointGatewayPeers: the nodes at the other end of an enabled tunnel
// link of the gateway.
func EndpointGatewayPeers(t model.Topology) map[string]bool {
	out := map[string]bool{}
	for _, l := range t.Links {
		if !l.Enabled || !model.TunnelTransport(l.Transport) {
			continue
		}
		a, okA := t.NodeByID(l.From)
		b, okB := t.NodeByID(l.To)
		if !okA || !okB {
			continue
		}
		if a.Role == model.RoleGateway {
			out[b.ID] = true
		}
		if b.Role == model.RoleGateway {
			out[a.ID] = true
		}
	}
	return out
}
