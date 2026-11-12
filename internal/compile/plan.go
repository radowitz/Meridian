package compile

import (
	"fmt"
	"sort"
	"strings"

	"github.com/radowitz/meridian/internal/model"
	"github.com/radowitz/meridian/internal/validate"
)

// ExitPlan is one foreign next hop. Mark and transit address are how the
// gateway's choice survives encapsulation.
type ExitPlan struct {
	Node      model.Node
	Index     int
	Mark      uint32
	Table     int
	TransitV4 string
	TransitV6 string
	DNSV4     string
	DNSULA    string
	HubIface  string // iface name on the hub toward this exit, or "mmesh"
	ViaRelay  string // dual-stack relay that carries a pure-v6 exit
	Mesh      bool   // the hub→exit hop is the Mesh sidecar, not a direct WG
	PeerV4    string // exit tunnel address, routed via the relay when ViaRelay is set
	PeerULA   string
	Group     string // smartdns group
}

func planExits(t model.Topology, tunnels []Tunnel) []ExitPlan {
	var exits []model.Node
	for _, n := range t.Nodes {
		if n.Role == model.RoleExit {
			exits = append(exits, n)
		}
	}
	sort.Slice(exits, func(i, j int) bool { return exits[i].ID < exits[j].ID })
	out := make([]ExitPlan, 0, len(exits))
	for i, n := range exits {
		p := ExitPlan{
			Node:      n,
			Index:     i,
			Mark:      exitMark(i),
			Table:     201 + i,
			TransitV4: fmt.Sprintf("10.66.200.%d", 10+i),
			TransitV6: fmt.Sprintf("fd66:0:0:ff::%x", 10+i),
			Group:     "g_" + strings.ReplaceAll(n.ID, "-", "_"),
		}
		p.HubIface, p.ViaRelay, p.Mesh, p.PeerV4, p.PeerULA = locateExit(t, n, tunnels)
		if tun := exitIngress(n, tunnels); tun.LinkID != "" {
			p.DNSV4 = tun.EastV4
			p.DNSULA = tun.EastULA
			if p.HubIface == "" && !p.Mesh {
				p.HubIface = tun.Iface()
			}
		}
		out = append(out, p)
	}
	return out
}

func exitByID(exits []ExitPlan, id string) (ExitPlan, bool) {
	for _, e := range exits {
		if e.Node.ID == id {
			return e, true
		}
	}
	return ExitPlan{}, false
}

func defaultExit(t model.Topology, exits []ExitPlan) (ExitPlan, bool) {
	n, ok := validate.SelectExit(t, "hk")
	if !ok {
		return ExitPlan{}, false
	}
	return exitByID(exits, n.ID)
}

type rulePlan struct {
	Rule       model.Rule
	Exit       ExitPlan
	Set4       string
	Set6       string
	FilterAAAA bool
}

func planRules(t model.Topology, exits []ExitPlan, decisions map[string]string) []rulePlan {
	rules := append([]model.Rule(nil), t.Rules...)
	sort.SliceStable(rules, func(i, j int) bool {
		if rules[i].Manual != rules[j].Manual {
			return rules[i].Manual
		}
		if rules[i].Priority != rules[j].Priority {
			return rules[i].Priority < rules[j].Priority
		}
		return rules[i].ID < rules[j].ID
	})
	var out []rulePlan
	n := 0
	for _, r := range rules {
		if !r.Enabled {
			continue
		}
		target, ok := ruleExit(t, r, exits, decisions)
		if !ok {
			continue
		}
		rp := rulePlan{
			Rule:       r,
			Exit:       target,
			Set4:       fmt.Sprintf("r%d", n),
			Set6:       fmt.Sprintf("r%d6", n),
			FilterAAAA: !target.Node.EgressV6,
		}
		n++
		out = append(out, rp)
	}
	return out
}

func ruleExit(t model.Topology, r model.Rule, exits []ExitPlan, decisions map[string]string) (ExitPlan, bool) {
	// A pinned rule, or a rule aimed at one exit, ignores the unlock map.
	if r.Mode == model.ModePin || r.TargetExit != "" {
		if r.TargetExit != "" {
			return exitByID(exits, r.TargetExit)
		}
		n, ok := validate.SelectExit(t, r.TargetPool)
		if !ok {
			return ExitPlan{}, false
		}
		return exitByID(exits, n.ID)
	}
	if id := decisions[r.ID]; id != "" {
		if e, ok := exitByID(exits, id); ok && e.Node.Pool == r.TargetPool {
			return e, true
		}
	}
	n, ok := validate.SelectExit(t, r.TargetPool)
	if !ok {
		return ExitPlan{}, false
	}
	return exitByID(exits, n.ID)
}

// locateExit decides which interface on the hub carries this exit.
// A pure-v6 exit is never given the hub's own (nonexistent) v6 path.
func locateExit(t model.Topology, n model.Node, tunnels []Tunnel) (iface, via string, mesh bool, peerV4, peerULA string) {
	pure := !n.PathV4 && n.PathV6
	if pure && n.V6Workaround == model.WorkaroundMesh {
		return "mmesh", "", true, "", ""
	}
	if pure && n.V6Workaround == model.WorkaroundDualstackRelay {
		relay, down := relayTunnel(t, n, tunnels)
		if relay.ID != "" {
			hubTun := hubTunnelTo(tunnels, relay.ID)
			return hubTun.Iface(), relay.ID, false, down.EastV4, down.EastULA
		}
	}
	direct := hubDirect(tunnels, n.ID)
	return direct.Iface(), "", false, direct.EastV4, direct.EastULA
}

func hubDirect(tunnels []Tunnel, exitID string) Tunnel {
	var found Tunnel
	for _, tun := range tunnels {
		if tun.Standby || tun.East.ID != exitID || tun.West.Role != model.RoleHub {
			continue
		}
		if tun.Mode == "wss" && found.LinkID != "" {
			continue
		}
		found = tun
		if tun.Mode != "wss" {
			break
		}
	}
	return found
}

func relayTunnel(t model.Topology, exit model.Node, tunnels []Tunnel) (model.Node, Tunnel) {
	for _, tun := range tunnels {
		if tun.Standby || tun.East.ID != exit.ID || !tun.West.DualstackRelay {
			continue
		}
		return tun.West, tun
	}
	return model.Node{}, Tunnel{}
}

func hubTunnelTo(tunnels []Tunnel, relayID string) Tunnel {
	for _, tun := range tunnels {
		if tun.Standby || tun.Mode == "wss" {
			continue
		}
		if tun.East.ID == relayID && tun.West.Role == model.RoleHub && tun.Transport == model.TransportDirectWG {
			return tun
		}
	}
	return Tunnel{}
}

// exitIngress is the tunnel that brings this exit's reply traffic home.
// Pure-v6 exits come from the dual-stack relay, not from the hub.
func exitIngress(n model.Node, tunnels []Tunnel) Tunnel {
	pureMesh := !n.PathV4 && n.PathV6 && n.V6Workaround == model.WorkaroundMesh
	if pureMesh {
		return Tunnel{}
	}
	var hub, other Tunnel
	for _, c := range tunnels {
		if c.East.ID != n.ID || c.Standby || c.Mode == "wss" {
			continue
		}
		if c.West.Role == model.RoleHub {
			hub = c
		} else if other.LinkID == "" {
			other = c
		}
	}
	if !n.PathV4 && n.PathV6 && n.V6Workaround == model.WorkaroundDualstackRelay && other.LinkID != "" {
		return other
	}
	if hub.LinkID != "" {
		return hub
	}
	return other
}

func transitV4Net() string { return "10.66.200.0/24" }
func transitV6Net() string { return "fd66:0:0:ff::/64" }
