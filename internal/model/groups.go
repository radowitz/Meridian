package model

import (
	"fmt"
	"sort"
	"strings"
)

// GroupMode says who picks a region group's member.
type GroupMode string

const (
	// GroupAuto: the first member of the effective order, moved by link
	// health (and, per service, by unlock results) inside the group.
	GroupAuto GroupMode = "auto"
	// GroupManual: the member the operator chose (RegionGroup.Chosen).
	GroupManual GroupMode = "manual"
)

// OnFailure is what a manual group does when its chosen member fails.
type OnFailure string

const (
	// OnFailureHold keeps the chosen member and raises an alert. Default.
	OnFailureHold OnFailure = "hold"
	// OnFailureFallback temporarily uses the next eligible member of the
	// effective order (alerting), and returns to the chosen member under
	// the recovery rules automatic mode uses.
	OnFailureFallback OnFailure = "fallback"
)

// RegionGroup is a country/region group of exits: the object rules and the
// default foreign traffic select exits through. Several groups may share a
// region (a datacentre and a residential Hong Kong group, say) and an exit
// may belong to several groups. See docs/architecture.md「地区组」.
type RegionGroup struct {
	ID     string `json:"id"`
	Name   string `json:"name"`
	Region string `json:"region,omitempty"`
	// Members are exit IDs in the operator's order. The effective order
	// (internal/pool.Effective) filters hard constraints first and then puts
	// IX-bound members ahead, keeping this order otherwise.
	Members []string  `json:"members"`
	Mode    GroupMode `json:"mode"`
	// Chosen is the manual member. Empty in automatic mode.
	Chosen string `json:"chosen,omitempty"`
	// OnFailure applies to manual mode only; empty means hold.
	OnFailure OnFailure `json:"on_failure,omitempty"`

	RequireResidential bool `json:"require_residential,omitempty"`
	ExcludeResidential bool `json:"exclude_residential,omitempty"`
	RequireV6          bool `json:"require_v6,omitempty"`

	Notes string `json:"notes,omitempty"`
	// MigratedFrom is "pool:<name>#<variant>" for a group created from the
	// old pool fields; reruns of the migration find the group by it.
	MigratedFrom string `json:"migrated_from,omitempty"`
}

// EffectiveOnFailure is OnFailure with the default applied.
func (g RegionGroup) EffectiveOnFailure() OnFailure {
	if g.Mode == GroupManual && g.OnFailure == OnFailureFallback {
		return OnFailureFallback
	}
	if g.Mode == GroupManual {
		return OnFailureHold
	}
	return ""
}

// ResidentialRequired: the rule may only use residential exits. Netflix and
// Disney+ rules require it by name as well (the design's hard rule).
func ResidentialRequired(r Rule) bool {
	if r.RequireResidential {
		return true
	}
	blob := strings.ToLower(r.Name + " " + r.MatchValue + " " + r.Geosite)
	return strings.Contains(blob, "netflix") || strings.Contains(blob, "disney")
}

// LegacyPoolOrder sorts pool members the way the old pool did: IX-bound
// first, then lower PoolPriority, then ID.
func LegacyPoolOrder(nodes []Node) {
	sort.SliceStable(nodes, func(i, j int) bool {
		if nodes[i].IXBound != nodes[j].IXBound {
			return nodes[i].IXBound
		}
		if nodes[i].PoolPriority != nodes[j].PoolPriority {
			return nodes[i].PoolPriority < nodes[j].PoolPriority
		}
		return nodes[i].ID < nodes[j].ID
	})
}

// poolVariant is one way rules used a pool: mode plus hard constraints.
type poolVariant struct {
	pool  string
	pin   bool
	resi  bool
	v6    bool
	isDef bool // the default foreign traffic (hk, auto, no constraints)
}

func (v poolVariant) key() string {
	k := "auto"
	if v.pin {
		k = "pin"
	}
	if v.resi {
		k += "-resi"
	}
	if v.v6 {
		k += "-v6"
	}
	return k
}

func (v poolVariant) migratedFrom() string { return "pool:" + v.pool + "#" + v.key() }

func (v poolVariant) less(o poolVariant) bool {
	if v.pin != o.pin {
		return !v.pin
	}
	if v.resi != o.resi {
		return !v.resi
	}
	return !v.v6 && o.v6
}

// MigrationReport says what MigrateRegionGroups did. Changed is false when
// the document was already migrated (the migration is idempotent).
type MigrationReport struct {
	Changed       bool     `json:"changed"`
	CreatedGroups []string `json:"created_groups,omitempty"`
	Rules         int      `json:"rules,omitempty"`
	Nodes         int      `json:"nodes,omitempty"`
	// HubTiers are the hubs whose tier the migration wrote (a lone hub
	// becomes the primary; see hubs.go).
	HubTiers []string `json:"hub_tiers,omitempty"`
}

// MigrateRegionGroups turns the legacy pool fields (Node.Pool,
// Node.PoolPriority, Rule.TargetPool, Rule.Mode) into region groups and
// clears them. It is a pure in-memory rewrite: the caller saves the result
// in one write, so an interrupted run leaves the stored document untouched,
// and running it again on its own output changes nothing. A document that
// already has groups and receives legacy fields (an old client) has them
// merged into the groups migrated from that pool. See
// docs/architecture.md「迁移」.
func MigrateRegionGroups(t *Topology) MigrationReport {
	var rep MigrationReport
	// Pool members in the old preference order.
	byPool := map[string][]Node{}
	for _, n := range t.Nodes {
		if n.Role == RoleExit && n.Pool != "" {
			byPool[n.Pool] = append(byPool[n.Pool], n)
		}
	}
	for p := range byPool {
		LegacyPoolOrder(byPool[p])
	}
	// Variants the rules need.
	variants := map[string]map[string]poolVariant{}
	addVariant := func(v poolVariant) {
		if variants[v.pool] == nil {
			variants[v.pool] = map[string]poolVariant{}
		}
		if old, ok := variants[v.pool][v.key()]; ok {
			v.isDef = v.isDef || old.isDef
		}
		variants[v.pool][v.key()] = v
	}
	ruleVariant := map[int]poolVariant{}
	for i, r := range t.Rules {
		if r.TargetPool == "" || r.TargetExit != "" {
			continue
		}
		v := poolVariant{pool: r.TargetPool, pin: r.Mode == ModePin, resi: ResidentialRequired(r), v6: r.RequireV6}
		ruleVariant[i] = v
		addVariant(v)
	}
	if t.Settings.DefaultGroup == "" {
		if _, has := byPool["hk"]; has || variants["hk"] != nil {
			addVariant(poolVariant{pool: "hk", isDef: true})
		}
	}
	for p := range byPool {
		if len(variants[p]) == 0 {
			addVariant(poolVariant{pool: p})
		}
	}
	pools := make([]string, 0, len(variants))
	for p := range variants {
		pools = append(pools, p)
	}
	sort.Strings(pools)

	taken := map[string]bool{}
	byOrigin := map[string]int{}
	for i, g := range t.Groups {
		taken[g.ID] = true
		if g.MigratedFrom != "" {
			byOrigin[g.MigratedFrom] = i
		}
	}
	groupFor := map[string]string{} // migratedFrom → group ID
	for _, p := range pools {
		vs := make([]poolVariant, 0, len(variants[p]))
		for _, v := range variants[p] {
			vs = append(vs, v)
		}
		sort.Slice(vs, func(i, j int) bool { return vs[i].less(vs[j]) })
		// Members of this pool already migrated into some group, for a
		// variant that appears only now (an old client's rule).
		var existing []string
		migratedBefore := false
		for _, g := range t.Groups {
			if strings.HasPrefix(g.MigratedFrom, "pool:"+p+"#") {
				existing = appendMissing(existing, g.Members...)
				migratedBefore = true
			}
		}
		for vi, v := range vs {
			if i, ok := byOrigin[v.migratedFrom()]; ok {
				groupFor[v.migratedFrom()] = t.Groups[i].ID
				continue
			}
			// The pool's name goes to its first variant; a variant that
			// appears after the pool was migrated gets a suffixed ID.
			id := migratedID(p, v, vi == 0 && !migratedBefore, taken)
			taken[id] = true
			members := append([]string{}, existing...)
			for _, n := range byPool[p] {
				members = appendMissing(members, n.ID)
			}
			g := RegionGroup{
				ID:                 id,
				Name:               migratedName(p, v),
				Region:             commonRegion(*t, members),
				Members:            members,
				Mode:               GroupAuto,
				RequireResidential: v.resi,
				ExcludeResidential: p == "hk" && !v.resi,
				RequireV6:          v.v6,
				MigratedFrom:       v.migratedFrom(),
			}
			if g.Members == nil {
				g.Members = []string{}
			}
			if v.pin {
				g.Mode = GroupManual
				g.OnFailure = OnFailureFallback
				g.Chosen = firstEligible(*t, g)
			}
			t.Groups = append(t.Groups, g)
			byOrigin[v.migratedFrom()] = len(t.Groups) - 1
			groupFor[v.migratedFrom()] = id
			rep.CreatedGroups = append(rep.CreatedGroups, id)
			rep.Changed = true
		}
	}
	// Nodes: add to every group migrated from their pool, then clear.
	for i := range t.Nodes {
		n := &t.Nodes[i]
		if n.Pool == "" && n.PoolPriority == 0 {
			continue
		}
		if n.Pool != "" && n.Role == RoleExit {
			for gi := range t.Groups {
				if strings.HasPrefix(t.Groups[gi].MigratedFrom, "pool:"+n.Pool+"#") && !containsString(t.Groups[gi].Members, n.ID) {
					t.Groups[gi].Members = append(t.Groups[gi].Members, n.ID)
					// An existing manual group keeps its choice; a group
					// created above already chose.
				}
			}
		}
		n.Pool, n.PoolPriority = "", 0
		rep.Nodes++
		rep.Changed = true
	}
	// Rules: point at the variant's group, clear the legacy fields.
	for i := range t.Rules {
		r := &t.Rules[i]
		if r.TargetPool == "" && r.Mode == "" {
			continue
		}
		if r.TargetPool == "" && r.TargetGroup != "" {
			// A migrated rule that carries a mode is rejected by validation
			// (rule_mode_removed), not silently rewritten.
			continue
		}
		if v, ok := ruleVariant[i]; ok {
			r.TargetGroup = groupFor[v.migratedFrom()]
		}
		r.TargetPool, r.Mode = "", ""
		rep.Rules++
		rep.Changed = true
	}
	if t.Settings.DefaultGroup == "" {
		if id, ok := groupFor[poolVariant{pool: "hk"}.migratedFrom()]; ok {
			t.Settings.DefaultGroup = id
			rep.Changed = true
		}
	}
	if ids := migrateHubs(t); len(ids) > 0 {
		rep.HubTiers = ids
		rep.Changed = true
	}
	return rep
}

// NewGroupID derives a free group ID from a name or region ("hk", "hk-2"…).
func NewGroupID(base string, t Topology) string {
	taken := map[string]bool{}
	for _, g := range t.Groups {
		taken[g.ID] = true
	}
	stem := sanitizeID(base)
	id := stem
	for i := 2; taken[id]; i++ {
		id = fmt.Sprintf("%s-%d", stem, i)
	}
	return id
}

func migratedID(pool string, v poolVariant, base bool, taken map[string]bool) string {
	stem := sanitizeID(pool)
	if !base {
		stem = sanitizeID(pool + "-" + v.key())
	}
	id := stem
	for i := 2; taken[id]; i++ {
		id = fmt.Sprintf("%s-%d", stem, i)
	}
	return id
}

func migratedName(pool string, v poolVariant) string {
	name := pool
	if v.pin {
		name += "（钉死）"
	}
	if v.resi {
		name += "（家宽）"
	}
	if v.v6 {
		name += "（IPv6）"
	}
	return name
}

// sanitizeID folds a free-form pool name into [a-z0-9-], at most 41 chars.
func sanitizeID(s string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(s) {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			b.WriteRune(r)
		default:
			b.WriteByte('-')
		}
	}
	out := strings.Trim(b.String(), "-")
	if out == "" {
		out = "group"
	}
	if len(out) > 36 {
		out = strings.TrimRight(out[:36], "-")
	}
	return out
}

func commonRegion(t Topology, members []string) string {
	region := ""
	for _, id := range members {
		n, ok := t.NodeByID(id)
		if !ok || n.Region == "" {
			continue
		}
		if region == "" {
			region = n.Region
		} else if region != n.Region {
			return ""
		}
	}
	return region
}

// firstEligible is the old pinned target: the first member in legacy order
// that the group's constraints admit.
func firstEligible(t Topology, g RegionGroup) string {
	for _, id := range g.Members {
		n, ok := t.NodeByID(id)
		if !ok || n.Role != RoleExit {
			continue
		}
		if g.RequireResidential && !n.Residential || g.ExcludeResidential && n.Residential || g.RequireV6 && !n.EgressV6 {
			continue
		}
		if n.IXBound {
			return id
		}
	}
	for _, id := range g.Members {
		n, ok := t.NodeByID(id)
		if !ok || n.Role != RoleExit {
			continue
		}
		if g.RequireResidential && !n.Residential || g.ExcludeResidential && n.Residential || g.RequireV6 && !n.EgressV6 {
			continue
		}
		return id
	}
	return ""
}

func appendMissing(list []string, ids ...string) []string {
	for _, id := range ids {
		if !containsString(list, id) {
			list = append(list, id)
		}
	}
	return list
}

func containsString(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}
