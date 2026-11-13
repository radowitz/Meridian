package compile

import (
	"fmt"
	"net/netip"
	"sort"

	"github.com/radowitz/meridian/internal/model"
	"github.com/radowitz/meridian/internal/validate"
)

// Tunnel is one WireGuard interface between the west node (closer to home)
// and the east node. Failover links produce two tunnels that share a base name.
type Tunnel struct {
	LinkID    string
	Name      string
	Transport model.Transport
	Mode      string // "udp" or "wss"
	Base      string // iface stem, e.g. m00; wss failover leg uses Base+"w"
	Standby   bool
	DialOut   bool // east node dials west (NAT exit -> hub)
	MTU       int
	WGPort    int // port the listening side binds
	ClientUDP int // localhost port the WSS client forwards
	Keepalive int

	West    model.Node
	East    model.Node
	WestV4  string
	EastV4  string
	WestULA string
	EastULA string
	// OuterV6 means the listener is dialed on IPv6. The hub never does this;
	// only a dual-stack relay, which itself was reached over v4, dials it.
	OuterV6 bool
}

func (t Tunnel) Iface() string {
	if t.Mode == "wss" && t.Transport == model.TransportUDPWSSFailover {
		return t.Base + "w"
	}
	return t.Base
}

func (t Tunnel) Listener() model.Node {
	if t.DialOut {
		return t.West
	}
	return t.East
}

func (t Tunnel) Dialer() model.Node {
	if t.DialOut {
		return t.East
	}
	return t.West
}

// DialV4 is the IPv4 address the dialer targets: the listener's
// EndpointV4, except that a relay dials an IX hub at its domestic ingress
// address (the only one that accepts the relays; EndpointV4 is the IX's
// Hong Kong egress, which exits dial).
func (t Tunnel) DialV4() string {
	lis := t.Listener()
	if model.IsIXHub(lis) && t.Dialer().Role == model.RoleRelay && lis.IngressV4 != "" {
		return lis.IngressV4
	}
	return lis.EndpointV4
}

type side struct {
	node model.Node
	v4   string
	ula  string
}

// buildTunnels makes the tunnels of every enabled tunnel link, in slot
// order. A link's interface name, default ports and default addresses come
// from its slot (model.EffectiveAllocations), never from its position, so
// adding, removing or reordering other links leaves them alone.
//
// The order matters wherever the first matching tunnel wins (the hub's
// direct tunnel to an exit, a relay's probe target) and wherever lists are
// rendered in tunnel order. Slot order is the old link-ID order for a
// migrated topology (its slots are its ID-order positions), and a link
// added later sorts after the links that were there, so it neither takes
// over an existing role nor reorders another node's lists.
func buildTunnels(t model.Topology) ([]Tunnel, error) {
	alloc := model.EffectiveAllocations(t)
	var links []model.Link
	for _, l := range t.Links {
		if l.Enabled && model.TunnelTransport(l.Transport) {
			links = append(links, l)
		}
	}
	slotOf := func(l model.Link) int {
		if s, ok := alloc.LinkSlot(l.ID); ok {
			return s
		}
		return model.MaxLinkSlots
	}
	sort.SliceStable(links, func(i, j int) bool {
		si, sj := slotOf(links[i]), slotOf(links[j])
		if si != sj {
			return si < sj
		}
		return links[i].ID < links[j].ID
	})

	ports := map[string]validate.LinkPorts{}
	for _, lp := range validate.TunnelPorts(t) {
		ports[lp.LinkID] = lp
	}
	var out []Tunnel
	for _, l := range links {
		tuns, err := linkTunnels(t, l, alloc, ports)
		if err != nil {
			return nil, err
		}
		out = append(out, tuns...)
	}
	return out, nil
}

// linkTunnels makes the one or two tunnels of link l.
func linkTunnels(t model.Topology, l model.Link, alloc *model.Allocations, ports map[string]validate.LinkPorts) ([]Tunnel, error) {
	var out []Tunnel
	i, ok := alloc.LinkSlot(l.ID)
	if !ok {
		return nil, fmt.Errorf("link %s: no free interface slot (%d in use)", l.ID, model.MaxLinkSlots)
	}
	west, east, err := materialize(t, l)
	if err != nil {
		return nil, err
	}
	// Ports come from validate.TunnelPorts, the single source the
	// validation and the preflight remedies use as well.
	lp, ok := ports[l.ID]
	lis := east.node
	if east.node.NatDialOut {
		lis = west.node
	}
	if !ok || lp.Index != i || lp.Listener != lis.ID {
		return nil, fmt.Errorf("link %s: port plan does not match the tunnel ends", l.ID)
	}
	base := model.LinkIface(i)
	modes := []string{"udp"}
	switch l.Transport {
	case model.TransportWGOverWSS, model.TransportIXReplacementWSS:
		modes = []string{"wss"}
	case model.TransportUDPWSSFailover:
		modes = []string{"udp", "wss"}
	}
	for _, mode := range modes {
		tun := Tunnel{
			LinkID: l.ID, Name: l.Name, Transport: l.Transport, Mode: mode,
			Base: base, Standby: l.Standby, DialOut: east.node.NatDialOut,
			Keepalive: keepaliveOf(l),
			West:      west.node, East: east.node,
			WestV4: west.v4, EastV4: east.v4, WestULA: west.ula, EastULA: east.ula,
		}
		if mode == "udp" {
			tun.MTU = orInt(l.MTU, 1420)
			if l.Transport == model.TransportUDPWSSFailover {
				tun.MTU = orInt(l.MTU, 1412)
			}
			tun.WGPort = lp.WG
		} else {
			// On udp+wss failover, Link.MTU is the UDP leg. Do not copy it
			// onto the WSS leg: 1412 does not fit a WSS session on PPPoE 1492.
			if l.Transport == model.TransportUDPWSSFailover {
				tun.MTU = orInt(l.WSSMTU, 1360)
				tun.WGPort = lp.WSSLeg
				tun.WestV4, tun.EastV4, tun.WestULA, tun.EastULA = companionAddrs(i)
			} else {
				tun.MTU = orInt(l.WSSMTU, orInt(l.MTU, 1360))
				tun.WGPort = lp.WG
			}
			tun.ClientUDP = lp.Local
		}
		// The Hong Kong hub has no IPv6. A pure-v6 Endpoint is dialed only
		// by a node that itself has v6 and is not the hub (the dual-stack
		// relay, already reached over v4 from the hub).
		if !tun.East.PathV4 && tun.East.PathV6 && tun.East.EndpointV6 != "" &&
			tun.West.Role != model.RoleHub && tun.West.PathV6 {
			tun.OuterV6 = true
		}
		if tun.WestV4 == "" || tun.EastV4 == "" || tun.WestULA == "" || tun.EastULA == "" {
			w4, e4, w6, e6 := allocatedAddrs(i)
			if tun.WestV4 == "" {
				tun.WestV4 = w4
			}
			if tun.EastV4 == "" {
				tun.EastV4 = e4
			}
			if tun.WestULA == "" {
				tun.WestULA = w6
			}
			if tun.EastULA == "" {
				tun.EastULA = e6
			}
		}
		out = append(out, tun)
	}
	return out, nil
}

func materialize(t model.Topology, l model.Link) (west, east side, err error) {
	fromN, ok := t.NodeByID(l.From)
	if !ok {
		return side{}, side{}, fmt.Errorf("link %s: missing node %s", l.ID, l.From)
	}
	toN, ok := t.NodeByID(l.To)
	if !ok {
		return side{}, side{}, fmt.Errorf("link %s: missing node %s", l.ID, l.To)
	}
	from := side{node: fromN, v4: l.FromV4, ula: l.FromULA}
	to := side{node: toN, v4: l.ToV4, ula: l.ToULA}
	if fromN.Role == model.RoleIX {
		peer, ok := peerAcrossDedicated(t, fromN.ID, toN.ID)
		if !ok {
			return side{}, side{}, fmt.Errorf("link %s: IX %s has no dedicated-line neighbor", l.ID, fromN.ID)
		}
		from.node = peer
	}
	if toN.Role == model.RoleIX {
		peer, ok := peerAcrossDedicated(t, toN.ID, fromN.ID)
		if !ok {
			return side{}, side{}, fmt.Errorf("link %s: IX %s has no dedicated-line neighbor", l.ID, toN.ID)
		}
		to.node = peer
	}
	// A nested exit's link: the relay exit is west (closer to home) and
	// listens; the nested exit dials it (validate.TunnelEnds agrees).
	if from.node.Role == model.RoleExit && to.node.Role == model.RoleExit {
		if from.node.ViaExit == to.node.ID {
			return to, from, nil
		}
		if to.node.ViaExit == from.node.ID {
			return from, to, nil
		}
	}
	if distance(from.node) <= distance(to.node) {
		return from, to, nil
	}
	return to, from, nil
}

func peerAcrossDedicated(t model.Topology, ixID, otherID string) (model.Node, bool) {
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

func distance(n model.Node) int {
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

func keepaliveOf(l model.Link) int {
	if l.Keepalive == nil {
		return 25
	}
	return *l.Keepalive
}

// allocatedAddrs are the default tunnel addresses of link slot i.
func allocatedAddrs(i int) (westV4, eastV4, westULA, eastULA string) {
	return model.LinkAutoAddrs(i)
}

// companionAddrs is the second /30 used by the WSS leg of udp+WSS failover
// on link slot i. It stays out of the primary subnets (10.66.1–99) and out
// of the transit prefix 10.66.200.0/24 (model.MaxLinkSlots).
func companionAddrs(i int) (westV4, eastV4, westULA, eastULA string) {
	return model.LinkCompanionAddrs(i)
}

func v4PairPrefix(local, peer string) (localCIDR, peerCIDR string) {
	la, err1 := netip.ParseAddr(local)
	pa, err2 := netip.ParseAddr(peer)
	if err1 != nil || err2 != nil {
		return local + "/32", peer + "/32"
	}
	p := netip.PrefixFrom(la, 30).Masked()
	if p.Contains(pa) {
		return local + "/30", peer + "/32"
	}
	return local + "/32", peer + "/32"
}

func orInt(v, def int) int {
	if v != 0 {
		return v
	}
	return def
}
