package validate

import (
	"fmt"
	"sort"

	"github.com/radowitz/meridian/internal/model"
)

// Ports every node binds, derived from the topology alone. This is the one
// place the tunnel ports are decided: compile.buildTunnels takes WG, WSSLeg
// and Local from TunnelPorts, so the bundle, the preflight footprint (read
// back from the rendered files) and the peers' Endpoint lines always agree
// with what is checked here. See docs/architecture.md「端口从哪里来」.
//
// The WireGuard port of a link (on the side that listens) is, in order:
// the link's wg_port; the listening node's listen_port, when the node
// listens on exactly one link without its own wg_port; 51820 plus the
// link's slot (its persisted allocation, model.EffectiveAllocations — not
// its position, so adding or removing other links never moves it). A
// UDP+WSS failover link uses that port and the one above it. A WSS link's
// wstunnel client binds 127.0.0.1:<wss_local_port> (default 52000 plus the
// slot) on the dialing side; the WSS server listens on the listening
// node's wss_listen_port (default 443).

// LinkPorts is what one tunnel link binds.
type LinkPorts struct {
	LinkID string `json:"link_id"`
	// Index is the link's slot (model.Allocations): interface m%02d, the
	// default ports and tunnel subnets are derived from it.
	Index     int             `json:"index"`
	Transport model.Transport `json:"transport"`
	// Listener and Dialer are the nodes that hold the two ends (a link
	// drawn to an IX ends on the IX's dedicated-line neighbour).
	Listener string `json:"listener"`
	Dialer   string `json:"dialer"`
	// WG is the listener's WireGuard UDP port; WSSLeg the failover leg's
	// (WG+1, udp_wss_failover only); Local the dialer's wstunnel client
	// port on 127.0.0.1 (WSS transports only).
	WG     int `json:"wg"`
	WSSLeg int `json:"wss_leg,omitempty"`
	Local  int `json:"local,omitempty"`
	// WGFrom names where WG came from: link (wg_port), node (listen_port)
	// or default.
	WGFrom string `json:"wg_from"`
}

// WSS reports whether the link carries a WSS leg.
func (lp LinkPorts) WSS() bool { return lp.Local != 0 }

// tunnelLinks are the enabled links that become WireGuard interfaces,
// sorted by ID (compile.buildTunnels uses the same order).
func tunnelLinks(t model.Topology) []model.Link {
	var links []model.Link
	for _, l := range t.Links {
		if l.Enabled && model.TunnelTransport(l.Transport) {
			links = append(links, l)
		}
	}
	sort.Slice(links, func(i, j int) bool { return links[i].ID < links[j].ID })
	return links
}

// TunnelEnds is compile's west/east decision for a link: a link drawn to an
// IX ends on its dedicated-line neighbour, and the node closer to home is
// west. ok is false when a node or the IX neighbour is missing.
func TunnelEnds(t model.Topology, l model.Link) (west, east model.Node, ok bool) {
	from, ok1 := t.NodeByID(l.From)
	to, ok2 := t.NodeByID(l.To)
	if !ok1 || !ok2 {
		return model.Node{}, model.Node{}, false
	}
	if from.Role == model.RoleIX {
		p, ok := dedicatedPeer(t, from.ID, to.ID)
		if !ok {
			return model.Node{}, model.Node{}, false
		}
		from = p
	}
	if to.Role == model.RoleIX {
		p, ok := dedicatedPeer(t, to.ID, from.ID)
		if !ok {
			return model.Node{}, model.Node{}, false
		}
		to = p
	}
	if homeDistance(from) <= homeDistance(to) {
		return from, to, true
	}
	return to, from, true
}

func dedicatedPeer(t model.Topology, ixID, otherID string) (model.Node, bool) {
	for _, l := range t.Links {
		if !l.Enabled || l.Transport != model.TransportDedicatedLine {
			continue
		}
		if l.To == ixID && l.From != otherID {
			if n, ok := t.NodeByID(l.From); ok {
				return n, true
			}
		}
		if l.From == ixID && l.To != otherID {
			if n, ok := t.NodeByID(l.To); ok {
				return n, true
			}
		}
	}
	return model.Node{}, false
}

func homeDistance(n model.Node) int {
	switch n.Role {
	case model.RoleGateway:
		return 0
	case model.RoleRelay:
		return 1
	case model.RoleIX:
		return 2
	case model.RoleHub:
		return 3
	case model.RoleExit:
		return 4
	default:
		return 9
	}
}

// TunnelPorts lists the ports of every tunnel link (links whose ends
// cannot be resolved, or that have no slot, are skipped; other checks
// report them).
func TunnelPorts(t model.Topology) []LinkPorts {
	return tunnelPorts(t, model.EffectiveAllocations(t))
}

func tunnelPorts(t model.Topology, alloc *model.Allocations) []LinkPorts {
	links := tunnelLinks(t)
	type end struct{ west, east model.Node }
	ends := map[string]end{}
	// How many links without wg_port each node listens on: listen_port
	// is that link's default only when there is exactly one.
	defaults := map[string]int{}
	for _, l := range links {
		w, e, ok := TunnelEnds(t, l)
		if !ok {
			continue
		}
		ends[l.ID] = end{w, e}
		lis := e
		if e.NatDialOut {
			lis = w
		}
		if l.WGPort == 0 {
			defaults[lis.ID]++
		}
	}
	var out []LinkPorts
	for _, l := range links {
		en, ok := ends[l.ID]
		if !ok {
			continue
		}
		i, ok := alloc.LinkSlot(l.ID)
		if !ok {
			continue
		}
		lis, dia := en.east, en.west
		if en.east.NatDialOut {
			lis, dia = en.west, en.east
		}
		lp := LinkPorts{LinkID: l.ID, Index: i, Transport: l.Transport, Listener: lis.ID, Dialer: dia.ID}
		switch {
		case l.WGPort != 0:
			lp.WG, lp.WGFrom = l.WGPort, "link"
		case lis.ListenPort != 0 && defaults[lis.ID] == 1:
			lp.WG, lp.WGFrom = lis.ListenPort, "node"
		default:
			lp.WG, lp.WGFrom = model.LinkDefaultWGPort(i), "default"
		}
		switch l.Transport {
		case model.TransportUDPWSSFailover:
			lp.WSSLeg = lp.WG + 1
			lp.Local = orInt(l.WSSLocalPort, model.LinkDefaultLocalPort(i))
		case model.TransportWGOverWSS, model.TransportIXReplacementWSS:
			lp.Local = orInt(l.WSSLocalPort, model.LinkDefaultLocalPort(i))
		}
		out = append(out, lp)
	}
	return out
}

// PortUse is one socket a node binds, with the topology field that sets it.
type PortUse struct {
	Proto string `json:"proto"` // udp | tcp
	Port  int    `json:"port"`
	// Loopback: bound on 127.0.0.1 only (wstunnel client); otherwise on
	// every address (WireGuard, WSS server).
	Loopback bool   `json:"loopback,omitempty"`
	What     string `json:"what"`
	// Kind/ID/Field name what to edit to change the port: kind "link" or
	// "node", the object's ID and its JSON field. Field is empty for a
	// port that cannot be changed.
	Kind  string `json:"kind"`
	ID    string `json:"id"`
	Field string `json:"field,omitempty"`
}

// NodePorts lists the sockets the node's bundle binds for tunnels: its
// WireGuard listen ports, the WSS server port and its wstunnel client
// ports. (SmartDNS binds 53/853 on tunnel addresses only; those ports are
// fixed.)
func NodePorts(t model.Topology, nodeID string) []PortUse {
	var out []PortUse
	wssServer := false
	for _, lp := range TunnelPorts(t) {
		if lp.Listener == nodeID {
			field, kind, id := "wg_port", "link", lp.LinkID
			if lp.WGFrom == "node" {
				field, kind, id = "listen_port", "node", nodeID
			}
			out = append(out, PortUse{Proto: "udp", Port: lp.WG, What: "链路 " + lp.LinkID + " 的 WireGuard 监听端口", Kind: kind, ID: id, Field: field})
			if lp.WSSLeg != 0 {
				out = append(out, PortUse{Proto: "udp", Port: lp.WSSLeg, What: "链路 " + lp.LinkID + " 的 WSS 腿 WireGuard 端口（WireGuard 端口 +1）", Kind: kind, ID: id, Field: field})
			}
			if lp.WSS() {
				wssServer = true
			}
		}
		if lp.Dialer == nodeID && lp.WSS() {
			out = append(out, PortUse{Proto: "udp", Port: lp.Local, Loopback: true, What: "链路 " + lp.LinkID + " 的 wstunnel 客户端本地端口", Kind: "link", ID: lp.LinkID, Field: "wss_local_port"})
		}
	}
	if wssServer {
		n, _ := t.NodeByID(nodeID)
		out = append(out, PortUse{Proto: "tcp", Port: orInt(n.WSSListenPort, 443), What: "节点 " + nodeID + " 的 WSS 监听端口", Kind: "node", ID: nodeID, Field: "wss_listen_port"})
	}
	return out
}

// reservedUDP / reservedTCP are ports a tunnel socket may never take: the
// resolver (53, DoT 853 on TCP), SSH, DHCP, NTP, mDNS.
var (
	reservedUDP = map[int]string{53: "DNS（SmartDNS 绑定隧道地址的 53）", 67: "DHCP", 68: "DHCP", 123: "NTP", 546: "DHCPv6", 547: "DHCPv6", 853: "DoT/DoQ", 5353: "mDNS"}
	reservedTCP = map[int]string{22: "SSH", 53: "DNS（SmartDNS 绑定隧道地址的 53）", 853: "DoT（SmartDNS）"}
)

// checkPorts: a node's own sockets must not collide with each other or
// with reserved ports, every port must be 1–65535, and a node's
// listen_port must be unambiguous.
func checkPorts(t model.Topology) []Issue {
	var out []Issue
	for _, l := range t.Links {
		if p := l.WGPort; p < 0 || p > 65534 {
			out = append(out, Issue{Code: "port_invalid", Severity: SeverityError, LinkID: l.ID, Field: "wg_port",
				Message: fmt.Sprintf("链路 %s 的 WireGuard 端口 %d 不在 1–65534 之间（UDP+WSS 故障切换还要用它的下一个端口）。", l.ID, p)})
		}
		if p := l.WSSLocalPort; p < 0 || p > 65535 {
			out = append(out, Issue{Code: "port_invalid", Severity: SeverityError, LinkID: l.ID, Field: "wss_local_port",
				Message: fmt.Sprintf("链路 %s 的 wstunnel 本地端口 %d 不在 1–65535 之间。", l.ID, p)})
		}
	}
	tps := TunnelPorts(t)
	for _, n := range t.Nodes {
		if p := n.ListenPort; p < 0 || p > 65534 {
			out = append(out, Issue{Code: "port_invalid", Severity: SeverityError, NodeID: n.ID, Field: "listen_port",
				Message: fmt.Sprintf("节点 %s 的 WireGuard 监听端口 %d 不在 1–65534 之间。", n.ID, p)})
		}
		if p := n.WSSListenPort; p < 0 || p > 65535 {
			out = append(out, Issue{Code: "port_invalid", Severity: SeverityError, NodeID: n.ID, Field: "wss_listen_port",
				Message: fmt.Sprintf("节点 %s 的 WSS 监听端口 %d 不在 1–65535 之间。", n.ID, p)})
		}
		if n.ListenPort > 0 {
			var unset []string
			for _, lp := range tps {
				if lp.Listener == n.ID && lp.WGFrom != "link" {
					unset = append(unset, lp.LinkID)
				}
			}
			if len(unset) > 1 {
				out = append(out, Issue{Code: "port_ambiguous", Severity: SeverityError, NodeID: n.ID, Field: "listen_port",
					Message: fmt.Sprintf("节点 %s 设置了 WireGuard 监听端口 %d，但它在 %d 条没有单独设端口的链路（%v）上监听；每个 WireGuard 接口要一个端口：在这些链路上分别填写「WireGuard 端口」，或清空节点的监听端口。", n.ID, n.ListenPort, len(unset), unset)})
			}
		}
		uses := NodePorts(t, n.ID)
		for i, a := range uses {
			res := reservedUDP
			if a.Proto == "tcp" {
				res = reservedTCP
			}
			if why, ok := res[a.Port]; ok {
				out = append(out, portIssue("port_reserved", a, fmt.Sprintf("%s 设为 %s %d，这个端口留给 %s。", a.What, a.Proto, a.Port, why)))
			}
			if n.Role == model.RoleGateway && a.Proto == "tcp" && a.Port == PanelPort(t) {
				out = append(out, portIssue("port_conflict", a, fmt.Sprintf("%s 设为 tcp %d，与面板端口相同。", a.What, a.Port)))
			}
			for _, b := range uses[:i] {
				if a.Proto != b.Proto || a.Port != b.Port {
					continue
				}
				out = append(out, portIssue("port_conflict", a, fmt.Sprintf("节点 %s 上 %s 与 %s 都是 %s %d：同一台主机上两个监听不能用同一个端口。改其中一个。", n.ID, a.What, b.What, a.Proto, a.Port)))
			}
		}
	}
	return out
}

func portIssue(code string, a PortUse, msg string) Issue {
	is := Issue{Code: code, Severity: SeverityError, Field: a.Field, Message: msg}
	if a.Kind == "link" {
		is.LinkID = a.ID
	} else {
		is.NodeID = a.ID
	}
	return is
}
