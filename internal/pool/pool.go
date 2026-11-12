// Package pool is the phase-2 membership and link-health policy.
//
// A pool's preferred member is the IX-bound exit when there is one, then the
// lowest PoolPriority, then the lowest ID. The default hk pool never includes
// a residential exit. Link failover only replaces the next hop of that
// member's routing table, and only with another member of the same pool.
// Mesh is the last hop, after every WireGuard member of the pool is down,
// and it is never a candidate for the IX west path.
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
	// Cooldown is the minimum gap between next-hop changes.
	Cooldown = 120 * time.Second
)

// MeshHop is the sentinel stored as the active member when every WireGuard
// member is down and the pool has a Mesh sidecar. It is not a node ID.
const MeshHop = "mmesh"

// MemberHealth is one member's hysteresis counters.
// Up starts true so a cold start does not black-hole the pool before the
// first three failures have been observed.
type MemberHealth struct {
	Up    bool `json:"up"`
	Fails int  `json:"fails"`
	Goods int  `json:"goods"`
}

func NewHealth() MemberHealth { return MemberHealth{Up: true} }

// Observe applies one probe. The member stays up until FailsNeed failures,
// and stays down until RecoversNeed successes.
func (m MemberHealth) Observe(ok bool) MemberHealth {
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

// Runtime is the last decision for one pool.
type Runtime struct {
	Active     string                  `json:"active"`
	LastSwitch time.Time               `json:"last_switch,omitempty"`
	Members    map[string]MemberHealth `json:"members"`
}

// Step updates health from one sample per member and maybe changes Active.
// members is in preference order. mesh is true when a hub→member Mesh link
// exists. now is the probe time. A zero LastSwitch allows the first change.
func Step(rt Runtime, members []string, up map[string]bool, mesh bool, now time.Time) Runtime {
	if rt.Members == nil {
		rt.Members = map[string]MemberHealth{}
	}
	if len(members) == 0 {
		return rt
	}
	pref := members[0]
	if rt.Active == "" {
		rt.Active = pref
	}
	for _, id := range members {
		h, ok := rt.Members[id]
		if !ok {
			h = NewHealth()
		}
		sample, seen := up[id]
		if !seen {
			rt.Members[id] = h
			continue
		}
		rt.Members[id] = h.Observe(sample)
	}
	want := rt.Active
	prefUp := rt.Members[pref].Up
	alt := firstUp(members[1:], rt.Members)
	switch {
	case rt.Active == pref && !prefUp:
		want = chooseBackup(alt, mesh, pref)
	case rt.Active != pref && prefUp:
		want = pref
	case rt.Active == MeshHop && alt != "":
		want = alt
	case rt.Active != pref && rt.Active != MeshHop && !rt.Members[rt.Active].Up:
		want = chooseBackup(alt, mesh, pref)
	}
	if want == rt.Active {
		return rt
	}
	if !rt.LastSwitch.IsZero() && now.Sub(rt.LastSwitch) < Cooldown {
		return rt
	}
	rt.Active = want
	rt.LastSwitch = now
	return rt
}

func chooseBackup(alt string, mesh bool, pref string) string {
	if alt != "" {
		return alt
	}
	if mesh {
		return MeshHop
	}
	return pref
}

func firstUp(ids []string, health map[string]MemberHealth) string {
	for _, id := range ids {
		if health[id].Up {
			return id
		}
	}
	return ""
}

// Members returns the exits in a pool, in failover order.
// The hk pool drops residential exits; those belong to hk-residential.
func Members(t model.Topology, poolName string) []model.Node {
	var members []model.Node
	for _, n := range t.Nodes {
		if n.Role != model.RoleExit || n.Pool != poolName {
			continue
		}
		if poolName == "hk" && n.Residential {
			continue
		}
		members = append(members, n)
	}
	sort.Slice(members, func(i, j int) bool {
		if members[i].IXBound != members[j].IXBound {
			return members[i].IXBound
		}
		if members[i].PoolPriority != members[j].PoolPriority {
			return members[i].PoolPriority < members[j].PoolPriority
		}
		return members[i].ID < members[j].ID
	})
	return members
}

// Preferred is the member installed as the pool's next hop until health
// says otherwise.
func Preferred(members []model.Node) (model.Node, bool) {
	if len(members) == 0 {
		return model.Node{}, false
	}
	return members[0], true
}

// Names is Members filtered to IDs, same order.
func Names(members []model.Node) []string {
	out := make([]string, 0, len(members))
	for _, n := range members {
		out = append(out, n.ID)
	}
	return out
}

// View is what the panel lists. Health is filled by the API when a sample
// has been reported; it is empty on a fresh install.
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

// Pools groups every exit pool in the topology.
func Pools(t model.Topology, meshPools map[string]bool, health map[string]Runtime) []View {
	names := map[string]bool{}
	for _, n := range t.Nodes {
		if n.Role == model.RoleExit && n.Pool != "" {
			names[n.Pool] = true
		}
	}
	var ids []string
	for id := range names {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	var out []View
	for _, id := range ids {
		members := Members(t, id)
		if len(members) == 0 {
			continue
		}
		v := View{
			ID:           id,
			Preferred:    members[0].ID,
			Residential:  allResidential(members),
			MeshBackup:   meshPools[id],
			FailsNeed:    FailsNeed,
			RecoversNeed: RecoversNeed,
			CooldownSec:  int(Cooldown / time.Second),
		}
		if rt, ok := health[id]; ok {
			v.Active = rt.Active
		}
		for _, n := range members {
			item := Member{
				ID: n.ID, Name: n.Name, IXBound: n.IXBound,
				Residential: n.Residential, Priority: n.PoolPriority,
				Preferred: n.ID == members[0].ID,
			}
			if rt, ok := health[id]; ok {
				if h, ok := rt.Members[n.ID]; ok {
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

func allResidential(members []model.Node) bool {
	if len(members) == 0 {
		return false
	}
	for _, n := range members {
		if !n.Residential {
			return false
		}
	}
	return true
}
