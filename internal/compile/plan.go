package compile

import (
	"fmt"
	"sort"
	"strings"

	"github.com/radowitz/meridian/internal/model"
	"github.com/radowitz/meridian/internal/pool"
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
	// Hub is the hub this plan was made for (the primary for the gateway
	// and the exits; each hub's own plan for its routes and failover).
	Hub string
	// Resolver is the exit's hub-independent resolver address
	// (validate.ExitResolverAddr of Index). With a backup hub the gateway
	// asks it instead of DNSULA: both hubs route it to their tunnel to the
	// exit, which DNATs it to its own resolver, so a pinned exit's names
	// resolve through whichever hub carries the traffic. Unused (and not
	// rendered) in a single-hub topology.
	Resolver string
	// Nested is the relay exit a nested exit is reached through (its one
	// tunnel goes there, model.Node.ViaExit): HubIface is the hub's tunnel
	// to that relay exit, PeerV4/PeerULA the nested exit's address on the
	// relay exit's tunnel to it. External is set for an external SOCKS
	// exit: HubIface is the hub's tunnel to its carrier, PeerV4 its health
	// address and PeerULA its resolver address on the carrier
	// (validate.ExternalHealthAddr / ExternalResolverAddr), ExtService the
	// carrier-side service address its redirector listens on.
	//
	// Both share their hub interface with another exit (the relay exit, the
	// carrier), so the hub tells them apart by next hop: a group table
	// pointed at such a member routes "via PeerV4 / PeerULA onlink" (the
	// next hop never leaves the hub: WireGuard routes by destination), and
	// the hub's nested_snat chain rewrites the group's transit source to the
	// member's own transit address for exactly that next hop, so the relay
	// exit or the carrier selects by source as for the member's own mark.
	Nested     string
	External   bool
	ExtService string
}

// sharedHop: the hub reaches this exit through another exit's tunnel, so a
// group hop to it needs the next-hop form and the hub's source rewrite.
func (e ExitPlan) sharedHop() bool { return e.Nested != "" || e.External }

// primaryHubID is the primary hub's node ID ("" without a hub).
func primaryHubID(t model.Topology) string {
	n, _ := t.PrimaryHub()
	return n.ID
}

// planExits plans the exits as the primary hub reaches them: the plan the
// gateway, the exits and the primary hub use.
func planExits(t model.Topology, tunnels []Tunnel) []ExitPlan {
	return planExitsHub(t, tunnels, primaryHubID(t))
}

// planExitsHub plans the exits as hub reaches them. Index, mark, table,
// transit and resolver addresses depend on the exit alone, so they are the
// same on both hubs; only the hub interface and peer addresses differ.
func planExitsHub(t model.Topology, tunnels []Tunnel, hub string) []ExitPlan {
	var exits []model.Node
	for _, n := range t.Nodes {
		if n.Role == model.RoleExit {
			exits = append(exits, n)
		}
	}
	sort.Slice(exits, func(i, j int) bool { return exits[i].ID < exits[j].ID })
	alloc := model.EffectiveAllocations(t)
	out := make([]ExitPlan, 0, len(exits))
	for _, n := range exits {
		// The index is the exit's mark slot (model.Allocations), not its
		// position: adding or removing another exit or group never moves
		// its mark, table, transit or resolver address. Validation refuses
		// an exit without one (mark_alloc_exhausted).
		i, ok := alloc.ExitSlot(n.ID)
		if !ok {
			continue
		}
		p := ExitPlan{
			Node:      n,
			Index:     i,
			Mark:      exitMark(i),
			Table:     markTable(i),
			TransitV4: markTransitV4(i),
			TransitV6: markTransitV6(i),
			Group:     "g_" + strings.ReplaceAll(n.ID, "-", "_"),
			Hub:       hub,
			Resolver:  validate.ExitResolverAddr(i).String(),
		}
		p.HubIface, p.ViaRelay, p.Mesh, p.PeerV4, p.PeerULA = locateExit(t, n, tunnels, hub)
		switch {
		case model.IsNested(n):
			p.Nested = n.ViaExit
		case model.IsExternal(n):
			p.External = true
			p.HubIface = hubDirect(tunnels, n.External.Carrier, hub).Iface()
			p.PeerV4 = validate.ExternalHealthAddr(i).String()
			p.PeerULA = validate.ExternalResolverAddr(i).String()
			p.DNSULA = p.PeerULA
			p.ExtService = validate.ExternalServiceAddr(i).String()
		}
		if tun := exitIngress(n, tunnels, hub); tun.LinkID != "" {
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

// switchable: the hub can point a group table at this exit with a plain
// device route (direct WireGuard from the hub). Exits reached only through
// a dual-stack relay or the Mesh sidecar can be selected statically (their
// own mark) but are not dynamic candidates.
func switchable(e ExitPlan) bool {
	return !e.Mesh && e.HubIface != "" && e.HubIface != "mmesh" && e.PeerV4 != "" && e.ViaRelay == ""
}

func switchableMap(exits []ExitPlan) map[string]bool {
	out := map[string]bool{}
	for _, e := range exits {
		out[e.Node.ID] = switchable(e)
	}
	return out
}

// GroupPlan is one region group as compiled: its own mark, transit address
// and hub table (from its mark slot, model.Allocations), the
// static choice and the members the hub may switch the table to.
type GroupPlan struct {
	Group     model.RegionGroup
	Selection pool.Selection
	Index     int
	Mark      uint32
	Table     int
	TransitV4 string
	TransitV6 string
	// Target is the static choice (manual chosen, or first of the
	// effective order); HasTarget is false when no member is eligible.
	Target    ExitPlan
	HasTarget bool
	// Dynamic: the target is switchable, so rules and default traffic use
	// the group mark and the hub's group table follows health. Otherwise
	// rules use the target's own mark and nothing switches.
	Dynamic bool
	// Try is the switch order on the hub: the target, then the other
	// switchable members of the effective order.
	Try []ExitPlan
	// Mesh: a standby hub→member Mesh edge is the last hop.
	Mesh bool
	// Hold: manual group with on_failure=hold (never moves).
	Hold bool
	// Resolver is the group's resolver address (validate.GroupResolverAddr
	// of Index) and DNSGroup the SmartDNS upstream group that asks it with
	// the group mark. Only a Dynamic group uses them: its queries follow
	// the group's own data path to whichever member the hub selected
	// (docs/architecture.md「地区组的解析」).
	Resolver string
	DNSGroup string
	// MeshResolver is the member that answers Resolver while the hub has
	// the group on the Mesh hop: the first member of the effective order
	// with a standby Mesh edge to the hub and a tunnel resolver
	// (meshDNSCapable). Its Mesh node publishes Resolver/128 (the
	// "meridian-mesh-publish" line of its meridian-mesh-up.sh), and it
	// answers the resolver range on its Mesh ingress (render_nft.go). Empty
	// when the group has no Mesh hop or no such member: the group's names
	// then fail while it is on Mesh, as before.
	MeshResolver string
}

// Policy is the state-machine view of the plan, shared by the panel model
// (pool.StepGroup) and the hub script (group_step).
func (g GroupPlan) Policy() pool.Policy {
	p := pool.Policy{Mesh: g.Mesh, Manual: g.Group.Mode == model.GroupManual, Hold: g.Hold || !g.Dynamic, TargetReason: g.Selection.Reason}
	if g.HasTarget && !g.Dynamic {
		p.Try = []string{g.Target.Node.ID}
		return p
	}
	for _, e := range g.Try {
		p.Try = append(p.Try, e.Node.ID)
	}
	return p
}

func (g GroupPlan) tableName() string {
	return "meridian_grp_" + strings.ReplaceAll(g.Group.ID, "-", "_")
}

// planGroups plans the region groups on the primary hub (the plan the
// gateway compiles its marks, rules and resolvers from).
func planGroups(t model.Topology, exits []ExitPlan) []GroupPlan {
	return planGroupsHub(t, exits, primaryHubID(t))
}

// planGroupsHub plans the groups on hub with exits planned for that hub:
// the same groups in the same order with the same marks, tables, transit
// and resolver addresses, constraints and switch order (validation keeps
// every exit switchable on both hubs or on neither), so either hub can
// carry a group the gateway marked. Only the primary has the Mesh hop.
func planGroupsHub(t model.Topology, exits []ExitPlan, hub string) []GroupPlan {
	groups := append([]model.RegionGroup(nil), t.Groups...)
	sort.Slice(groups, func(i, j int) bool { return groups[i].ID < groups[j].ID })
	sw := switchableMap(exits)
	alloc := model.EffectiveAllocations(t)
	out := make([]GroupPlan, 0, len(groups))
	for _, g := range groups {
		// The group's mark slot, shared with the exits' (a topology from
		// before the table numbered groups after the exits; the migration
		// keeps exactly that).
		idx, ok := alloc.GroupSlot(g.ID)
		if !ok {
			continue
		}
		gp := GroupPlan{
			Group:     g,
			Index:     idx,
			Mark:      exitMark(idx),
			Table:     markTable(idx),
			TransitV4: markTransitV4(idx),
			TransitV6: markTransitV6(idx),
			Hold:      g.EffectiveOnFailure() == model.OnFailureHold,
			Resolver:  validate.GroupResolverAddr(idx).String(),
			DNSGroup:  "rg_" + strings.ReplaceAll(g.ID, "-", "_"),
		}
		gp.Selection = pool.Select(t, g, sw)
		if gp.Selection.Target != "" {
			gp.Target, gp.HasTarget = exitByID(exits, gp.Selection.Target)
		}
		if gp.HasTarget && sw[gp.Target.Node.ID] {
			gp.Dynamic = true
			for _, id := range gp.Selection.Try {
				if e, ok := exitByID(exits, id); ok && sw[id] {
					gp.Try = append(gp.Try, e)
				}
			}
			gp.Mesh = !gp.Hold && hub == primaryHubID(t) && groupHasMesh(t, gp.Selection.Order)
			if gp.Mesh {
				for _, id := range gp.Selection.Order {
					if e, ok := exitByID(exits, id); ok && meshDNSCapable(t, e) {
						gp.MeshResolver = id
						break
					}
				}
			}
		}
		out = append(out, gp)
	}
	return out
}

// PlanGroups compiles the group plans of t (no validation): what the panel
// uses to run the same state machine as the hub.
func PlanGroups(t model.Topology) ([]GroupPlan, error) {
	return PlanGroupsForHub(t, primaryHubID(t))
}

// PlanGroupsForHub compiles the group plans hub runs (no validation): the
// plan its failover script carries, whose GroupPlanID that hub reports.
func PlanGroupsForHub(t model.Topology, hub string) ([]GroupPlan, error) {
	tunnels, err := buildTunnels(t)
	if err != nil {
		return nil, err
	}
	return planGroupsHub(t, planExitsHub(t, tunnels, hub), hub), nil
}

func groupByID(groups []GroupPlan, id string) (GroupPlan, bool) {
	for _, g := range groups {
		if g.Group.ID == id {
			return g, true
		}
	}
	return GroupPlan{}, false
}

// groupHasMesh: an enabled standby cf_mesh link joins the hub to an
// eligible member of the group.
func groupHasMesh(t model.Topology, members []string) bool {
	in := map[string]bool{}
	for _, id := range members {
		in[id] = true
	}
	hub := primaryHubID(t)
	for _, l := range t.Links {
		if l.Transport != model.TransportCFMesh || !l.Enabled || !l.Standby {
			continue
		}
		if l.From == hub && in[l.To] || l.To == hub && in[l.From] {
			return true
		}
	}
	return false
}

// hubMeshStandby: an enabled standby cf_mesh link joins the hub and id.
func hubMeshStandby(t model.Topology, id string) bool {
	hub := primaryHubID(t)
	if hub == "" || id == "" {
		return false
	}
	for _, l := range t.Links {
		if l.Transport != model.TransportCFMesh || !l.Enabled || !l.Standby {
			continue
		}
		if l.From == hub && l.To == id || l.To == hub && l.From == id {
			return true
		}
	}
	return false
}

// meshDNSCapable: the exit can answer a region group's resolver address on
// its Mesh ingress: it has a standby Mesh edge to the hub and a tunnel
// resolver to DNAT to.
func meshDNSCapable(t model.Topology, e ExitPlan) bool {
	return e.Node.Role == model.RoleExit && e.DNSULA != "" && hubMeshStandby(t, e.Node.ID)
}

// meshDNSGroups are the groups whose Mesh resolver is exit id, sorted by
// group ID (the plan order).
func meshDNSGroups(groups []GroupPlan, id string) []GroupPlan {
	var out []GroupPlan
	for _, g := range groups {
		if g.Dynamic && g.Mesh && g.MeshResolver != "" && g.MeshResolver == id {
			out = append(out, g)
		}
	}
	return out
}

// target is where a rule's (or the default traffic's) packets go: the exit
// whose resolver and egress family apply, and the mark the classifier sets.
type target struct {
	Exit ExitPlan
	Mark uint32
	// V6 is false when some member the mark can reach has no egress_v6
	// (AAAA is filtered for the rule).
	V6 bool
	// Group is set when the target is a switchable region group's own
	// mark: names are then resolved through the group's resolver address
	// (Group.DNSGroup), never through one member's resolver.
	Group *GroupPlan
}

// dnsGroup is the SmartDNS upstream group that resolves for this target.
func (tg target) dnsGroup() string {
	if tg.Group != nil {
		return tg.Group.DNSGroup
	}
	return tg.Exit.Group
}

// groupTarget is the static target of a group: the group mark when the hub
// can switch it, otherwise the target member's own mark.
func groupTarget(gp GroupPlan) (target, bool) {
	if !gp.HasTarget {
		return target{}, false
	}
	if !gp.Dynamic {
		return target{Exit: gp.Target, Mark: gp.Target.Mark, V6: carriesV6(gp.Target)}, true
	}
	v6 := true
	for _, e := range gp.Try {
		if !carriesV6(e) {
			v6 = false
		}
	}
	g := gp
	return target{Exit: gp.Target, Mark: gp.Mark, V6: v6, Group: &g}, true
}

// carriesV6: the exit carries IPv6 end to end, so names tunnelled to it may
// get AAAA (with clients_ipv6_via_gateway). An external SOCKS exit never
// does, whatever its egress_v6 says: its carrier refuses every IPv6 packet
// of it (writeCarrierNFT) and its resolver group answers no AAAA.
// Validation already refuses egress_v6 on it (external_v6); this keeps the
// resolver from handing out AAAA for an IPv4-only path even if a topology
// slipped past that check.
func carriesV6(e ExitPlan) bool {
	return e.Node.EgressV6 && !e.External
}

func defaultExit(t model.Topology, groups []GroupPlan) (target, bool) {
	gp, ok := groupByID(groups, t.Settings.DefaultGroup)
	if !ok {
		return target{}, false
	}
	return groupTarget(gp)
}

type rulePlan struct {
	Rule model.Rule
	Exit ExitPlan
	// ViaGroup: the rule uses a switchable group's mark and resolver (nil
	// for a pinned exit, an unlock-moved rule or a group the hub cannot
	// switch).
	ViaGroup   *GroupPlan
	Mark       uint32
	Set4       string
	Set6       string
	FilterAAAA bool
	// Action is model.ActionDirect or model.ActionReject for a rule whose
	// (service group's) target is direct or reject; Exit is then unset.
	Action string
	// CIDR4/CIDR6 are the nft sets of a rule-set rule's address entries
	// (filled by the host's derive step, never by SmartDNS).
	CIDR4, CIDR6 string
	// QUIC marks the MatchQUICReject row (no sets, no target).
	QUIC bool
}

// planRules returns the enabled rules in evaluation order (the list order,
// model.Topology.EvalOrder), each with its sets r<n>/r<n>6 numbered in that
// order. A rule whose target cannot be resolved is left out (validation
// reports it). The QUIC row is kept as a marker.
func planRules(t model.Topology, exits []ExitPlan, groups []GroupPlan, decisions map[string]string) []rulePlan {
	var out []rulePlan
	n := 0
	quic := false
	for _, r := range t.EvalOrder() {
		if !r.Enabled {
			continue
		}
		if r.MatchType == model.MatchQUICReject {
			if !quic {
				out = append(out, rulePlan{Rule: r, QUIC: true})
				quic = true
			}
			continue
		}
		tg, action, ok := ruleExit(t, r, exits, groups, decisions)
		if !ok {
			continue
		}
		rp := rulePlan{
			Rule:       r,
			Exit:       tg.Exit,
			ViaGroup:   tg.Group,
			Mark:       tg.Mark,
			Set4:       fmt.Sprintf("r%d", n),
			Set6:       fmt.Sprintf("r%d6", n),
			FilterAAAA: !tg.V6,
			Action:     action,
		}
		if r.MatchType == model.MatchRuleSet {
			rp.CIDR4, rp.CIDR6 = fmt.Sprintf("r%dc", n), fmt.Sprintf("r%dc6", n)
		}
		n++
		out = append(out, rp)
	}
	return out
}

// ruleExit: a rule aimed at one exit uses that exit's own mark and ignores
// health and the unlock map. A group rule uses the group's target; in an
// automatic group the unlock map may move it to another eligible member,
// which then carries it on that member's own mark. Manual groups ignore the
// unlock map. A service group is followed to its target first; direct and
// reject have no exit (action is set instead).
func ruleExit(t model.Topology, r model.Rule, exits []ExitPlan, groups []GroupPlan, decisions map[string]string) (target, string, bool) {
	rt := t.ResolveTarget(r)
	switch rt.Kind {
	case model.ActionDirect:
		return target{Mark: markDomestic, V6: true}, model.ActionDirect, true
	case model.ActionReject:
		return target{Mark: markReject}, model.ActionReject, true
	case "exit":
		e, ok := exitByID(exits, rt.ID)
		return target{Exit: e, Mark: e.Mark, V6: carriesV6(e)}, "", ok
	case "group":
	default:
		return target{}, "", false
	}
	gp, ok := groupByID(groups, rt.ID)
	if !ok {
		return target{}, "", false
	}
	if gp.Group.Mode == model.GroupAuto {
		if id := decisions[r.ID]; id != "" && id != gp.Selection.Target && containsID(gp.Selection.Order, id) {
			if e, ok := exitByID(exits, id); ok {
				return target{Exit: e, Mark: e.Mark, V6: carriesV6(e)}, "", true
			}
		}
	}
	tg, ok := groupTarget(gp)
	return tg, "", ok
}

func containsID(ids []string, id string) bool {
	for _, v := range ids {
		if v == id {
			return true
		}
	}
	return false
}

// locateExit decides which interface on the hub carries this exit.
// A pure-v6 exit is never given the hub's own (nonexistent) v6 path.
func locateExit(t model.Topology, n model.Node, tunnels []Tunnel, hub string) (iface, via string, mesh bool, peerV4, peerULA string) {
	pure := !n.PathV4 && n.PathV6
	if pure && n.V6Workaround == model.WorkaroundMesh {
		return "mmesh", "", true, "", ""
	}
	if model.IsNested(n) {
		// The hub's own tunnel to the relay exit carries it; its address
		// is on the relay exit's tunnel to it.
		up := hubDirect(tunnels, n.ViaExit, hub)
		down := nestedTunnel(n, tunnels)
		if up.LinkID == "" || down.LinkID == "" {
			return "", "", false, "", ""
		}
		return up.Iface(), "", false, down.EastV4, down.EastULA
	}
	if model.IsExternal(n) {
		return "", "", false, "", ""
	}
	if pure && n.V6Workaround == model.WorkaroundDualstackRelay {
		relay, down := relayTunnel(t, n, tunnels)
		if relay.ID != "" {
			hubTun := hubTunnelTo(tunnels, relay.ID, hub)
			return hubTun.Iface(), relay.ID, false, down.EastV4, down.EastULA
		}
	}
	direct := hubDirect(tunnels, n.ID, hub)
	return direct.Iface(), "", false, direct.EastV4, direct.EastULA
}

// hubDirect is hub's own tunnel to the exit (UDP preferred over WSS).
func hubDirect(tunnels []Tunnel, exitID, hub string) Tunnel {
	var found Tunnel
	for _, tun := range tunnels {
		if tun.Standby || tun.East.ID != exitID || tun.West.Role != model.RoleHub || tun.West.ID != hub {
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

// nestedTunnel is the relay exit's tunnel to nested exit n (west: the relay
// exit, east: n).
func nestedTunnel(n model.Node, tunnels []Tunnel) Tunnel {
	for _, tun := range tunnels {
		if tun.Standby || tun.Mode == "wss" || tun.East.ID != n.ID || tun.West.ID != n.ViaExit {
			continue
		}
		return tun
	}
	return Tunnel{}
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

func hubTunnelTo(tunnels []Tunnel, relayID, hub string) Tunnel {
	for _, tun := range tunnels {
		if tun.Standby || tun.Mode == "wss" {
			continue
		}
		if tun.East.ID == relayID && tun.West.Role == model.RoleHub && tun.West.ID == hub && tun.Transport == model.TransportDirectWG {
			return tun
		}
	}
	return Tunnel{}
}

// exitIngress is the tunnel from hub that brings this exit's reply traffic
// home. Pure-v6 exits come from the dual-stack relay, not from the hub.
func exitIngress(n model.Node, tunnels []Tunnel, hubID string) Tunnel {
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
			if c.West.ID == hubID {
				hub = c
			}
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

// markTable, markTransitV4 and markTransitV6 are the hub table and the
// transit addresses of mark slot i (an exit's or a group's, see
// model.Allocations); exitMark is its fwmark.
func markTable(i int) int        { return 201 + i }
func markTransitV4(i int) string { return fmt.Sprintf("10.66.200.%d", 10+i) }
func markTransitV6(i int) string { return fmt.Sprintf("fd66:0:0:ff::%x", 10+i) }
func transitV4Net() string       { return "10.66.200.0/24" }
func transitV6Net() string       { return "fd66:0:0:ff::/64" }
