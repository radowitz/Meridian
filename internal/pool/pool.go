// Package pool is the region-group selection policy and link-health state
// machine (the package keeps its phase-2 name; the "pool" is now a
// model.RegionGroup).
//
// Effective order: hard constraints (missing node, residential required or
// excluded, IPv6 required) filter first; IX-bound members then come before
// the operator's order, which is kept otherwise. Every member carries the
// reasons it was moved or excluded.
//
// Selection: automatic groups use the first member of the effective order,
// manual groups the chosen member. Link failover only replaces the next hop
// of the group's own routing table, and only with another member of the
// same group (Policy.Try). Mesh is the last hop, after every WireGuard
// member is down, and it is never a candidate for the IX west path.
//
// Return to the target (preferred or chosen) needs: the target marked up by
// hysteresis, its latest sample a success, an unbroken success streak of
// Cooldown since OKSince (any failure clears it), and Cooldown since the
// last switch. A just-failed member is never switched back to.
package pool

import (
	"sort"
	"time"

	"github.com/radowitz/meridian/internal/model"
)

const (
	// FailsNeed consecutive probe failures mark a member down.
	// A single failure must not move the next hop.
	FailsNeed = 3
	// RecoversNeed consecutive successes mark a down member up again.
	RecoversNeed = 5
	// Cooldown is the minimum gap between next-hop changes, and the length
	// of the unbroken success streak the target needs before a return.
	Cooldown = 120 * time.Second
)

// MeshHop is the sentinel stored as the active member when every WireGuard
// member is down and the group has a Mesh sidecar. It is not a node ID.
const MeshHop = "mmesh"

// State reasons (Runtime.Reason, Selection.Reason).
const (
	ReasonPreferred  = "preferred"  // automatic: first member of the effective order
	ReasonChosen     = "chosen"     // manual: the member the operator chose
	ReasonConstraint = "constraint" // the configured choice is excluded; first eligible member used
	ReasonFailover   = "failover"   // automatic: target down, a later member carries the group
	ReasonFallback   = "fallback"   // manual+fallback: chosen down, next eligible member used
	ReasonHeld       = "held"       // manual+hold (or not switchable): target down, kept anyway
	ReasonMesh       = "mesh"       // every WireGuard member down, Mesh last hop
	ReasonNone       = "none"       // no eligible member
)

// Member reasons (MemberStatus.Reasons[].Code).
const (
	WhyMissing       = "missing"
	WhyDuplicate     = "duplicate"
	WhyResiRequired  = "residential_required"
	WhyResiExcluded  = "residential_excluded"
	WhyV6Required    = "v6_required"
	WhyIXFirst       = "ix_first"
	WhyAfterIX       = "after_ix"
	WhyNotSwitchable = "not_switchable"
)

// MemberHealth is one member's hysteresis counters plus the recovery timer.
// Up starts true so a cold start does not black-hole the group before the
// first three failures have been observed.
type MemberHealth struct {
	Up    bool `json:"up"`
	Fails int  `json:"fails"`
	Goods int  `json:"goods"`
	// Seen is set once a sample arrived; LastOK is that latest sample.
	Seen   bool `json:"seen,omitempty"`
	LastOK bool `json:"last_ok,omitempty"`
	// OKSince starts the current unbroken success streak; zero after any
	// failure. It is the recovery timer a return to the target needs.
	OKSince time.Time `json:"ok_since,omitempty"`
	LastAt  time.Time `json:"last_at,omitempty"`
}

func NewHealth() MemberHealth { return MemberHealth{Up: true} }

// Observe applies one probe without a clock (the recovery timer is not
// started). Kept for callers that only need the hysteresis.
func (m MemberHealth) Observe(ok bool) MemberHealth { return m.ObserveAt(ok, time.Time{}) }

// ObserveAt applies one probe at now. The member stays up until FailsNeed
// failures, and stays down until RecoversNeed successes. Any failure clears
// OKSince.
func (m MemberHealth) ObserveAt(ok bool, now time.Time) MemberHealth {
	m.Seen, m.LastOK, m.LastAt = true, ok, now
	if ok {
		if m.OKSince.IsZero() {
			m.OKSince = now
		}
	} else {
		m.OKSince = time.Time{}
	}
	if ok {
		m.Fails = 0
		if m.Up {
			m.Goods = 0
			return m
		}
		m.Goods++
		if m.Goods >= RecoversNeed {
			m.Up = true
			m.Goods = 0
		}
		return m
	}
	m.Goods = 0
	if !m.Up {
		return m
	}
	m.Fails++
	if m.Fails >= FailsNeed {
		m.Up = false
		m.Fails = 0
	}
	return m
}

// Runtime is the last decision for one group.
type Runtime struct {
	// Target is the member the policy wants (Policy.Try[0]); a change of
	// target restarts the group on the new one, as an install does on the hub.
	Target     string                  `json:"target,omitempty"`
	Active     string                  `json:"active"`
	Reason     string                  `json:"reason,omitempty"`
	Alert      bool                    `json:"alert,omitempty"`
	LastSwitch time.Time               `json:"last_switch,omitempty"`
	Members    map[string]MemberHealth `json:"members"`
}

// Policy is what StepGroup needs from a group.
type Policy struct {
	// Try is the switch order: Try[0] is the target (automatic: first of
	// the effective order; manual: the chosen member), then the rest of the
	// effective order. Only members the hub can switch to belong here.
	Try []string
	// Mesh: the group has a standby hub→member Mesh edge (last hop).
	Mesh bool
	// Manual selects the fallback/chosen reason codes.
	Manual bool
	// Hold: never move off the target (manual+hold, or a target the hub
	// cannot switch away from).
	Hold bool
	// TargetReason is reported while the target carries the group
	// (preferred, chosen or constraint). Empty derives it from Manual.
	TargetReason string
}

// Step is StepGroup for an automatic group whose members are in preference
// order. mesh is true when a hub→member Mesh link exists.
func Step(rt Runtime, members []string, up map[string]bool, mesh bool, now time.Time) Runtime {
	return StepGroup(rt, Policy{Try: members, Mesh: mesh}, up, now)
}

// StepGroup updates health from one sample per member and maybe changes
// Active. A zero LastSwitch allows the first change. Leaving a member that
// is marked down is immediate; returning to the target waits for CanReturn.
func StepGroup(rt Runtime, p Policy, up map[string]bool, now time.Time) Runtime {
	if rt.Members == nil {
		rt.Members = map[string]MemberHealth{}
	}
	if len(p.Try) == 0 {
		rt.Target, rt.Active, rt.Reason, rt.Alert = "", "", ReasonNone, true
		return rt
	}
	target := p.Try[0]
	if rt.Target != target {
		rt.Target = target
		rt.Active = target
	}
	if rt.Active == "" || (rt.Active != MeshHop && !contains(p.Try, rt.Active)) {
		rt.Active = target
	}
	for _, id := range p.Try {
		h, ok := rt.Members[id]
		if !ok {
			h = NewHealth()
		}
		if sample, seen := up[id]; seen {
			h = h.ObserveAt(sample, now)
		}
		rt.Members[id] = h
	}
	tUp := rt.Members[target].Up
	if p.Hold {
		rt.Active = target
		rt.Reason = targetReason(p)
		rt.Alert = !tUp
		if !tUp {
			rt.Reason = ReasonHeld
		}
		return rt
	}
	want := rt.Active
	alt := firstUp(p.Try[1:], rt.Members)
	switch {
	case rt.Active == target:
		if !tUp {
			want = backup(alt, p.Mesh, rt.Active)
		}
	case CanReturn(rt, target, now):
		want = target
	case rt.Active == MeshHop:
		if alt != "" {
			want = alt
		}
	case !rt.Members[rt.Active].Up:
		want = backup(alt, p.Mesh, rt.Active)
	}
	if want != rt.Active {
		rt.Active = want
		rt.LastSwitch = now
	}
	switch {
	case rt.Active == target:
		rt.Reason = targetReason(p)
		rt.Alert = !tUp
	case rt.Active == MeshHop:
		rt.Reason, rt.Alert = ReasonMesh, true
	case p.Manual:
		rt.Reason, rt.Alert = ReasonFallback, true
	default:
		rt.Reason, rt.Alert = ReasonFailover, false
	}
	return rt
}

// CanReturn reports whether the group may go back to target at now: target
// up, latest sample a success, an unbroken streak of Cooldown, and Cooldown
// since the last switch.
func CanReturn(rt Runtime, target string, now time.Time) bool {
	h, ok := rt.Members[target]
	if !ok || !h.Up || !h.Seen || !h.LastOK || h.OKSince.IsZero() {
		return false
	}
	if now.Sub(h.OKSince) < Cooldown {
		return false
	}
	return rt.LastSwitch.IsZero() || now.Sub(rt.LastSwitch) >= Cooldown
}

func targetReason(p Policy) string {
	if p.TargetReason != "" {
		return p.TargetReason
	}
	if p.Manual {
		return ReasonChosen
	}
	return ReasonPreferred
}

// backup is the next live member, then Mesh; with neither the group stays
// where it is (a dead target is not "returned to" either).
func backup(alt string, mesh bool, current string) string {
	if alt != "" {
		return alt
	}
	if mesh {
		return MeshHop
	}
	return current
}

func firstUp(ids []string, health map[string]MemberHealth) string {
	for _, id := range ids {
		if health[id].Up {
			return id
		}
	}
	return ""
}

func contains(ss []string, s string) bool {
	for _, v := range ss {
		if v == s {
			return true
		}
	}
	return false
}

// Reason explains a member's place in the effective order.
type Reason struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

// MemberStatus is one configured member of a group.
type MemberStatus struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Region      string `json:"region,omitempty"`
	UserPos     int    `json:"user_position"`
	Pos         int    `json:"position"` // effective position, -1 when excluded
	Eligible    bool   `json:"eligible"`
	IXBound     bool   `json:"ix_bound"`
	Residential bool   `json:"residential"`
	EgressV6    bool   `json:"egress_v6"`
	// Switchable: the hub can move the group's table onto this member.
	// Nil when the caller did not say.
	Switchable *bool    `json:"switchable,omitempty"`
	Reasons    []Reason `json:"reasons"`
}

// Effective returns the group's effective order (eligible members only) and
// the status of every configured member. switchable may be nil.
func Effective(t model.Topology, g model.RegionGroup, switchable map[string]bool) ([]string, []MemberStatus) {
	statuses := make([]MemberStatus, 0, len(g.Members))
	seen := map[string]bool{}
	type cand struct {
		idx  int
		node model.Node
	}
	var eligible []cand
	for i, id := range g.Members {
		st := MemberStatus{ID: id, UserPos: i, Pos: -1, Reasons: []Reason{}}
		n, ok := t.NodeByID(id)
		switch {
		case seen[id]:
			st.Reasons = append(st.Reasons, Reason{WhyDuplicate, "成员重复，只算第一次出现。"})
		case !ok || n.Role != model.RoleExit:
			st.Reasons = append(st.Reasons, Reason{WhyMissing, "节点不存在或不是出口。"})
		}
		if ok {
			st.Name, st.Region = n.Name, n.Region
			st.IXBound, st.Residential, st.EgressV6 = n.IXBound, n.Residential, n.EgressV6
		}
		if len(st.Reasons) == 0 {
			if g.RequireResidential && !n.Residential {
				st.Reasons = append(st.Reasons, Reason{WhyResiRequired, "组要求家宽，这个出口不是家宽。"})
			}
			if g.ExcludeResidential && n.Residential {
				st.Reasons = append(st.Reasons, Reason{WhyResiExcluded, "组排除家宽，这个出口是家宽。"})
			}
			if g.RequireV6 && !n.EgressV6 {
				st.Reasons = append(st.Reasons, Reason{WhyV6Required, "组要求 IPv6 出口，这个出口没有 egress_v6。"})
			}
		}
		seen[id] = true
		if switchable != nil && ok && n.Role == model.RoleExit {
			sw := switchable[id]
			st.Switchable = &sw
		}
		st.Eligible = len(st.Reasons) == 0
		if st.Eligible {
			eligible = append(eligible, cand{idx: len(statuses), node: n})
		}
		statuses = append(statuses, st)
	}
	userRank := map[string]int{}
	for i, c := range eligible {
		userRank[c.node.ID] = i
	}
	sort.SliceStable(eligible, func(i, j int) bool {
		return eligible[i].node.IXBound && !eligible[j].node.IXBound
	})
	order := make([]string, 0, len(eligible))
	for pos, c := range eligible {
		st := &statuses[c.idx]
		st.Pos = pos
		switch {
		case pos < userRank[c.node.ID]:
			st.Reasons = append(st.Reasons, Reason{WhyIXFirst, "IX 绑定的出口排在用户顺序之前。"})
		case pos > userRank[c.node.ID]:
			st.Reasons = append(st.Reasons, Reason{WhyAfterIX, "前面插入了 IX 绑定的出口，位置后移。"})
		}
		if st.Switchable != nil && !*st.Switchable {
			st.Reasons = append(st.Reasons, Reason{WhyNotSwitchable, "只能经双栈中继或纯 Mesh 到达，枢纽不能把组切到它；可以被静态选中。"})
		}
		order = append(order, c.node.ID)
	}
	return order, statuses
}

// Selection is the compiled choice of one group.
type Selection struct {
	Order   []string
	Members []MemberStatus
	// Target is the member installed until health says otherwise.
	Target string
	// Reason: preferred, chosen, constraint or none.
	Reason string
	// Try is Target followed by the rest of Order (the switch order before
	// the hub's reachability filter).
	Try []string
}

// Select computes the effective order and the static choice of g.
func Select(t model.Topology, g model.RegionGroup, switchable map[string]bool) Selection {
	order, members := Effective(t, g, switchable)
	sel := Selection{Order: order, Members: members, Reason: ReasonNone}
	if len(order) == 0 {
		return sel
	}
	sel.Target, sel.Reason = order[0], ReasonPreferred
	if g.Mode == model.GroupManual {
		if contains(order, g.Chosen) {
			sel.Target, sel.Reason = g.Chosen, ReasonChosen
		} else {
			sel.Reason = ReasonConstraint
		}
	}
	sel.Try = append(sel.Try, sel.Target)
	for _, id := range order {
		if id != sel.Target {
			sel.Try = append(sel.Try, id)
		}
	}
	return sel
}

// Names is a list of nodes reduced to IDs, same order.
func Names(members []model.Node) []string {
	out := make([]string, 0, len(members))
	for _, n := range members {
		out = append(out, n.ID)
	}
	return out
}

// View is the legacy /api/pools shape, now one entry per region group.
type View struct {
	ID           string   `json:"id"`
	Preferred    string   `json:"preferred"`
	Residential  bool     `json:"residential"`
	MeshBackup   bool     `json:"mesh_backup"`
	Members      []Member `json:"members"`
	FailsNeed    int      `json:"fails_need"`
	RecoversNeed int      `json:"recovers_need"`
	CooldownSec  int      `json:"cooldown_sec"`
	Active       string   `json:"active,omitempty"`
}

type Member struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	IXBound     bool   `json:"ix_bound"`
	Residential bool   `json:"residential"`
	Priority    int    `json:"priority"`
	Preferred   bool   `json:"preferred"`
	Up          *bool  `json:"up,omitempty"`
}

// Pools is the legacy pool listing built from the region groups: eligible
// members in effective order, priority = position in the operator's order.
func Pools(t model.Topology, meshGroups map[string]bool, health map[string]Runtime) []View {
	groups := append([]model.RegionGroup(nil), t.Groups...)
	sort.Slice(groups, func(i, j int) bool { return groups[i].ID < groups[j].ID })
	out := []View{}
	for _, g := range groups {
		sel := Select(t, g, nil)
		if len(sel.Order) == 0 {
			continue
		}
		v := View{
			ID: g.ID, Preferred: sel.Target, MeshBackup: meshGroups[g.ID],
			FailsNeed: FailsNeed, RecoversNeed: RecoversNeed, CooldownSec: int(Cooldown / time.Second),
			Residential: true,
		}
		rt, hasRT := health[g.ID]
		if hasRT {
			v.Active = rt.Active
		}
		for _, id := range sel.Order {
			var st MemberStatus
			for _, m := range sel.Members {
				if m.ID == id {
					st = m
					break
				}
			}
			if !st.Residential {
				v.Residential = false
			}
			item := Member{ID: id, Name: st.Name, IXBound: st.IXBound, Residential: st.Residential, Priority: st.UserPos, Preferred: id == sel.Target}
			if hasRT {
				if h, ok := rt.Members[id]; ok {
					up := h.Up
					item.Up = &up
				}
			}
			v.Members = append(v.Members, item)
		}
		out = append(out, v)
	}
	return out
}
