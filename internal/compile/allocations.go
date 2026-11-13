package compile

import (
	"fmt"
	"sort"

	"github.com/radowitz/meridian/internal/model"
	"github.com/radowitz/meridian/internal/validate"
)

// LinkLeg is one WireGuard interface of a link as compiled.
type LinkLeg struct {
	Iface   string `json:"iface"`
	Mode    string `json:"mode"` // udp | wss
	WGPort  int    `json:"wg_port"`
	West    string `json:"west"`
	East    string `json:"east"`
	WestV4  string `json:"west_v4"`
	EastV4  string `json:"east_v4"`
	WestULA string `json:"west_ula"`
	EastULA string `json:"east_ula"`
}

// LinkResource is what a link holds on its two hosts: its slot and what
// the slot (or an explicit value) gives it. The panel shows it read-only in
// the link editor.
type LinkResource struct {
	LinkID string `json:"link_id"`
	// Slot is the link's allocation (nil: none, see State).
	Slot *int `json:"slot,omitempty"`
	// State: "allocated"; "unallocated" (no free slot); "not_tunnel" (the
	// transport has no WireGuard interface); "unresolved" (an end is
	// missing; Error says why).
	State   string `json:"state"`
	Enabled bool   `json:"enabled"`
	// Listener binds WGPort (and WSSLegPort); Dialer binds LocalPort on
	// 127.0.0.1 (WSS transports).
	Listener   string    `json:"listener,omitempty"`
	Dialer     string    `json:"dialer,omitempty"`
	WGPort     int       `json:"wg_port,omitempty"`
	WGFrom     string    `json:"wg_from,omitempty"`
	WSSLegPort int       `json:"wss_leg_port,omitempty"`
	LocalPort  int       `json:"local_port,omitempty"`
	Legs       []LinkLeg `json:"legs,omitempty"`
	Error      string    `json:"error,omitempty"`
}

// MarkResource is an exit's or a region group's mark slot and what it
// gives it on the gateway and the hubs.
type MarkResource struct {
	Kind      string `json:"kind"` // exit | group
	ID        string `json:"id"`
	Slot      int    `json:"slot"`
	Mark      string `json:"mark"`
	Table     int    `json:"table"`
	TransitV4 string `json:"transit_v4"`
	TransitV6 string `json:"transit_v6"`
}

// LinkResources lists every link (sorted by ID) with what it holds. A
// disabled tunnel link shows what it would hold when enabled (it keeps its
// slot while disabled). It never fails: a link that cannot be compiled
// carries its State and Error instead.
func LinkResources(t model.Topology) []LinkResource {
	alloc := model.EffectiveAllocations(t)
	links := append([]model.Link(nil), t.Links...)
	sort.SliceStable(links, func(i, j int) bool { return links[i].ID < links[j].ID })
	var out []LinkResource
	for _, l := range links {
		r := LinkResource{LinkID: l.ID, Enabled: l.Enabled}
		if !model.TunnelTransport(l.Transport) {
			r.State = "not_tunnel"
			out = append(out, r)
			continue
		}
		slot, ok := alloc.LinkSlot(l.ID)
		if !ok {
			r.State = "unallocated"
			out = append(out, r)
			continue
		}
		s := slot
		r.Slot = &s
		view := t
		if !l.Enabled {
			view.Links = append([]model.Link(nil), t.Links...)
			for i := range view.Links {
				if view.Links[i].ID == l.ID {
					view.Links[i].Enabled = true
				}
			}
			l.Enabled = true
		}
		view.Allocations = alloc
		ports := map[string]validate.LinkPorts{}
		for _, lp := range validate.TunnelPorts(view) {
			ports[lp.LinkID] = lp
		}
		lp, havePorts := ports[l.ID]
		tuns, err := linkTunnels(view, l, alloc, ports)
		if err != nil || !havePorts {
			r.State = "unresolved"
			if err != nil {
				r.Error = err.Error()
			} else {
				r.Error = fmt.Sprintf("link %s: an end cannot be resolved", l.ID)
			}
			out = append(out, r)
			continue
		}
		r.State = "allocated"
		r.Listener, r.Dialer = lp.Listener, lp.Dialer
		r.WGPort, r.WGFrom, r.WSSLegPort, r.LocalPort = lp.WG, lp.WGFrom, lp.WSSLeg, lp.Local
		for _, tun := range tuns {
			r.Legs = append(r.Legs, LinkLeg{
				Iface: tun.Iface(), Mode: tun.Mode, WGPort: tun.WGPort, West: tun.West.ID, East: tun.East.ID,
				WestV4: tun.WestV4, EastV4: tun.EastV4, WestULA: tun.WestULA, EastULA: tun.EastULA,
			})
		}
		out = append(out, r)
	}
	return out
}

// MarkResources lists the mark slots of the exits and groups (exits first,
// each sorted by ID).
func MarkResources(t model.Topology) []MarkResource {
	alloc := model.EffectiveAllocations(t)
	var out []MarkResource
	add := func(kind, id string, slot int) {
		out = append(out, MarkResource{
			Kind: kind, ID: id, Slot: slot, Mark: fmt.Sprintf("%#x", exitMark(slot)), Table: markTable(slot),
			TransitV4: markTransitV4(slot), TransitV6: markTransitV6(slot),
		})
	}
	var exits []string
	for _, n := range t.Nodes {
		if n.Role == model.RoleExit {
			exits = append(exits, n.ID)
		}
	}
	sort.Strings(exits)
	for _, id := range exits {
		if s, ok := alloc.ExitSlot(id); ok {
			add("exit", id, s)
		}
	}
	var groups []string
	for _, g := range t.Groups {
		groups = append(groups, g.ID)
	}
	sort.Strings(groups)
	for _, id := range groups {
		if s, ok := alloc.GroupSlot(id); ok {
			add("group", id, s)
		}
	}
	return out
}
