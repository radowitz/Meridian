package api

// The unlock page by region: GET /api/unlock/matrix and POST /api/unlock/adopt.
//
// Services are global (probed on every exit) or regional (probed only on
// exits of their regions; probe.Adapter.ProbeRegions). An exit's regions
// are the Region fields of the region groups it belongs to (exitRegions).
// The matrix has one section per region that has exits: Global (every
// exit) first, then the regions in regionOrder. Each section is a service ×
// exit table whose cell is one of unlocked / local / blocked / unverified /
// untested, from the newest unexpired result per family.
//
// After a probe each service gets a recommended exit: an unlocked one,
// for a global service preferring members of the region group its rules
// target now, then the more stable (families unlocked, link health) and
// faster one. 采用 points the service's rules (serviceRules: rule ID,
// primary-check domains, rule-set / geosite / keyword platform names)
// at the recommended exit's region group and makes that group prefer the
// exit (first in member order; the chosen member of a manual group). It
// goes through the rules' automatic apply or reports that a deploy is
// needed. See docs/unlock-methods.md「按地区探测」.

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/radowitz/meridian/internal/compile"
	"github.com/radowitz/meridian/internal/model"
	"github.com/radowitz/meridian/internal/pool"
	"github.com/radowitz/meridian/internal/probe"
	"github.com/radowitz/meridian/internal/unlock"
)

// regionOrder is the display order of regional sections; other regions
// follow alphabetically.
var regionOrder = []string{"hk", "tw", "jp", "us", "sg", "my"}

var regionNames = map[string]string{
	probe.RegionGlobal: "全球", "hk": "香港", "tw": "台湾", "jp": "日本", "us": "美国", "sg": "新加坡",
	"my": "马来西亚", "th": "泰国", "id": "印尼", "vn": "越南", "ph": "菲律宾", "kr": "韩国", "gb": "英国", "uk": "英国",
}

// Cell states.
const (
	cellUnlocked   = "unlocked"   // 解锁
	cellLocal      = "local"      // 仅本地: the platform answered, only reachability is known
	cellBlocked    = "blocked"    // 不可用
	cellUnverified = "unverified" // 未测到: failed, unknown, or the exit address was not confirmed
	cellUntested   = "untested"   // 未测
)

var cellRank = map[string]int{cellUnlocked: 4, cellLocal: 3, cellBlocked: 2, cellUnverified: 1, cellUntested: 0}

// exitRegions maps an exit to the regions of its region groups.
func exitRegions(t model.Topology) map[string][]string {
	out := map[string][]string{}
	for _, g := range t.Groups {
		r := unlock.NormRegion(g.Region)
		if r == "" {
			continue
		}
		for _, m := range g.Members {
			if !containsStr(out[m], r) {
				out[m] = append(out[m], r)
			}
		}
	}
	return out
}

// scopedTargets lists, per exit, the adapters a probe of scope sends
// there ("" all, "global", or a region code): a global adapter on every
// exit, a regional adapter only on exits of its regions.
func scopedTargets(t model.Topology, exits map[string]compile.ProbeExit, scope string) map[string][]string {
	regions := exitRegions(t)
	scope = strings.ToLower(strings.TrimSpace(scope))
	out := map[string][]string{}
	for id := range exits {
		if scope != "" && scope != probe.RegionGlobal && !containsStr(regions[id], unlock.NormRegion(scope)) {
			continue
		}
		for _, a := range probe.Catalog {
			if !probe.Probeable(a.Service) || !a.InScope(scope) || !a.ProbesOn(regions[id]) {
				continue
			}
			out[id] = append(out[id], a.Service)
		}
	}
	return out
}

// ruleRetargetable: a rule 采用 may move (it targets a group or an exit).
func ruleRetargetable(r model.Rule) bool {
	return r.MatchType != model.MatchQUICReject && r.TargetAction == "" && (r.TargetGroup != "" || r.TargetExit != "")
}

// ruleOfService reports whether r belongs to the adapter's service: its
// ID is the service, or a domain is under the service's primary-check
// domains, or a rule-set / geosite / keyword name carries the service's own
// platform name. The mihomo policy-group label is not ownership (one label
// often carries several services); it stays for the Rules filter and
// POST /api/rules/retarget.
// ruleSetName: a rule stores its rule set by ID; ownership is decided on
// the rule set's name ("RULE-SET Netflix" stores rs-…, named "Netflix").
func ruleSetName(t model.Topology, r model.Rule) string {
	if rs, ok := t.RuleSetByID(r.RuleSet); ok {
		return rs.Name
	}
	return ""
}

func ruleOfService(t model.Topology, r model.Rule, a probe.Adapter) bool {
	if r.ID == a.Service {
		return true
	}
	switch r.MatchType {
	case model.MatchDomain, model.MatchSuffix:
		if a.MatchesDomain(r.MatchValue) {
			return true
		}
	case model.MatchKeyword, model.MatchGeosite, model.MatchRuleSet:
		if a.MatchesName(r.MatchValue) {
			return true
		}
	}
	for _, d := range r.Domains {
		if a.MatchesDomain(d) {
			return true
		}
	}
	return a.MatchesName(r.Geosite) || a.MatchesName(r.RuleSet) || a.MatchesName(ruleSetName(t, r))
}

// aiRule: the rule belongs to a disabled AI service. The unlock page never
// moves AI rules (they keep their target, by default the US group).
func aiRule(t model.Topology, r model.Rule) bool {
	for _, d := range probe.Disabled {
		if ruleOfService(t, r, d) {
			return true
		}
	}
	return false
}

// serviceRules are the indexes of the enabled, retargetable rules of the
// adapter's service.
func serviceRules(t model.Topology, a probe.Adapter) []int {
	var out []int
	for i, r := range t.Rules {
		if r.Enabled && ruleRetargetable(r) && ruleOfService(t, r, a) && !aiRule(t, r) {
			out = append(out, i)
		}
	}
	return out
}

type matrixExit struct {
	ID      string   `json:"id"`
	Name    string   `json:"name"`
	Regions []string `json:"regions"`
	Groups  []string `json:"groups"`
	// Identity is the exit's current identity digest (exit_identity.go;
	// no secret in it). A manual save names it; "" = no probe identity.
	Identity string `json:"identity,omitempty"`
}

type matrixCell struct {
	ExitID string `json:"exit_id"`
	State  string `json:"state"`
	// Region is the platform's region read-out (when the method gives one).
	Region string `json:"region,omitempty"`
	// Reason says why a cell is unverified (exit address not confirmed,
	// timeout, unrecognised answer …).
	Reason    string     `json:"reason,omitempty"`
	LatencyMS int64      `json:"latency_ms,omitempty"`
	At        *time.Time `json:"at,omitempty"`
	// unlocked families and failures, for stability.
	okFams   int
	failFams int
}

type matrixRec struct {
	ExitID    string `json:"exit_id"`
	ExitName  string `json:"exit_name"`
	Group     string `json:"group"`
	GroupName string `json:"group_name"`
	// Adopted: the rules already target Group and it prefers ExitID.
	Adopted bool `json:"adopted"`
}

type matrixService struct {
	ID    string       `json:"id"`
	Name  string       `json:"name"`
	Rules []string     `json:"rules"`
	Cells []matrixCell `json:"cells"`
	// Targets are the region groups the rules point at now.
	Targets   []string   `json:"targets"`
	Recommend *matrixRec `json:"recommend"`
	// Groups are the region groups 手动 may point the rules at (出口组).
	Groups []matrixGroupOpt `json:"groups"`
	// Current is where the rules send the service now (nil: no rule).
	Current *matrixCurrent `json:"current"`
}

// matrixGroupOpt is a region group of the service's probe scope that holds
// one of its in-scope exits and meets its rules' hard constraints.
type matrixGroupOpt struct {
	ID            string `json:"id"`
	Name          string `json:"name"`
	Preferred     string `json:"preferred,omitempty"`
	PreferredName string `json:"preferred_name,omitempty"`
	// Identity digests the in-scope members' identities ("" when one has
	// none); a group save names it.
	Identity string `json:"identity,omitempty"`
}

// matrixCurrent is the service's actual direction: a group and the exit it
// selects now, or a pinned exit.
type matrixCurrent struct {
	Group     string `json:"group,omitempty"`
	GroupName string `json:"group_name,omitempty"`
	Exit      string `json:"exit,omitempty"`
	ExitName  string `json:"exit_name,omitempty"`
	Pinned    bool   `json:"pinned"`
	// Mixed: the service's rules go to different places (several groups,
	// pinned exits, or a per-rule automatic choice inside an auto group);
	// each distinct direction is listed and the fields above stay empty.
	Mixed []matrixCurrent `json:"mixed,omitempty"`
}

type matrixRegion struct {
	Code     string          `json:"code"`
	Name     string          `json:"name"`
	Exits    []matrixExit    `json:"exits"`
	Services []matrixService `json:"services"`
}

// cellOf folds the stored results of one adapter on one exit (both
// families) into a cell: the best state wins; expired results and results
// without the exit's current identity digest count as untested.
func cellOf(exitID, identity string, items []probeJobItem, now time.Time, pol unlock.Policy) matrixCell {
	c := matrixCell{ExitID: exitID, State: cellUntested}
	for _, it := range items {
		if it.FinishedAt == nil || (pol.TTL > 0 && now.Sub(*it.FinishedAt) > pol.TTL) {
			continue
		}
		// Evidence about another identity (or none) is not evidence.
		if it.Identity == "" || it.Identity != identity {
			continue
		}
		st := ""
		switch it.Category {
		case probe.CatUnlocked:
			st = cellUnlocked
			c.okFams++
		case probe.CatNetworkOK:
			st = cellLocal
		case probe.CatNotUnlocked:
			st = cellBlocked
		case probe.CatFailed, probe.CatUnknown:
			st = cellUnverified
			c.failFams++
		default:
			continue
		}
		if it.StartedAt != nil && st == cellUnlocked {
			d := it.FinishedAt.Sub(*it.StartedAt).Milliseconds()
			if c.LatencyMS == 0 || d < c.LatencyMS {
				c.LatencyMS = d
			}
		}
		if cellRank[st] <= cellRank[c.State] {
			continue
		}
		c.State, c.Region, c.At, c.Reason = st, it.Region, it.FinishedAt, ""
		if st == cellUnverified {
			c.Reason = firstNonEmpty(it.Error, it.Egress, it.Evidence, "没有可用的应答")
		}
	}
	return c
}

func firstNonEmpty(ss ...string) string {
	for _, s := range ss {
		if strings.TrimSpace(s) != "" {
			return s
		}
	}
	return ""
}

// groupPrefers: the group selects exit (first eligible member, or the
// chosen member of a manual group).
func groupPrefers(t model.Topology, g model.RegionGroup, exit string) bool {
	return pool.Select(t, g, nil).Target == exit
}

// ruleNeeds are the hard constraints of the service's rules.
func ruleNeeds(t model.Topology, rules []int) (needResi, needV6 bool) {
	for _, i := range rules {
		needResi = needResi || model.ResidentialRequired(t.Rules[i])
		needV6 = needV6 || t.Rules[i].RequireV6
	}
	return needResi, needV6
}

// groupFor is the region group a service's rules would target to use exit:
// a group that can select the exit, meets the rules' hard constraints
// (residential, IPv6) and, for a regional service, is of one of its
// regions; one the rules target now wins. nil when there is none.
func groupFor(t model.Topology, a probe.Adapter, exit string, targets []string, rules []int) (*model.RegionGroup, bool) {
	needResi, needV6 := ruleNeeds(t, rules)
	var best *model.RegionGroup
	inTarget := false
	for _, g := range sortedGroups(t) {
		if (needResi && !g.RequireResidential) || (needV6 && !g.RequireV6) {
			continue
		}
		if !containsStr(pool.Select(t, g, nil).Order, exit) {
			continue
		}
		if !a.Global() && !containsStr(a.ProbeRegions(), unlock.NormRegion(g.Region)) {
			continue
		}
		isTarget := containsStr(targets, g.ID)
		if best == nil || (isTarget && !inTarget) {
			gg := g
			best, inTarget = &gg, isTarget
		}
	}
	return best, inTarget
}

// recAdopted: the rules already target the group and it prefers the exit.
func recAdopted(t model.Topology, g model.RegionGroup, exit string, rules []int) bool {
	ok := len(rules) > 0 && groupPrefers(t, g, exit)
	for _, i := range rules {
		ok = ok && t.Rules[i].TargetGroup == g.ID
	}
	return ok
}

// groupScope checks a group as a 手动 target of a service whose in-scope
// exits are scope: "400:…" when the group is outside the service's probe
// scope or holds none of those exits, "409:…" when it misses a hard
// constraint of the rules; "" when it qualifies.
func groupScope(t model.Topology, a probe.Adapter, g model.RegionGroup, scope []string, rules []int) string {
	if !a.Global() && !containsStr(a.ProbeRegions(), unlock.NormRegion(g.Region)) {
		return "400:这个出口组不在该服务的探测范围内"
	}
	has := false
	for _, m := range g.Members {
		has = has || containsStr(scope, m)
	}
	if !has {
		return "400:这个出口组没有该服务探测范围内的出口"
	}
	if needResi, needV6 := ruleNeeds(t, rules); (needResi && !g.RequireResidential) || (needV6 && !g.RequireV6) {
		return "409:这个出口组不满足规则约束（家宽 / IPv6）"
	}
	return ""
}

// groupIdentity digests the identities of the group's in-scope members;
// "" when one of them has no identity.
func groupIdentity(g model.RegionGroup, scope []string, idents map[string]string) string {
	var parts []string
	for _, m := range g.Members {
		if !containsStr(scope, m) {
			continue
		}
		if idents[m] == "" {
			return ""
		}
		parts = append(parts, m+"="+idents[m])
	}
	if len(parts) == 0 {
		return ""
	}
	sort.Strings(parts)
	sum := sha256.Sum256([]byte(strings.Join(parts, "\n")))
	return "g" + identityVersion + ":" + hex.EncodeToString(sum[:16])
}

// groupOptions are the 出口组 of a service row.
func groupOptions(t model.Topology, a probe.Adapter, scope []string, rules []int, idents map[string]string) []matrixGroupOpt {
	out := []matrixGroupOpt{}
	for _, g := range sortedGroups(t) {
		if groupScope(t, a, g, scope, rules) != "" {
			continue
		}
		o := matrixGroupOpt{ID: g.ID, Name: g.Name, Identity: groupIdentity(g, scope, idents)}
		if p := pool.Select(t, g, nil).Target; p != "" {
			o.Preferred, o.PreferredName = p, nodeName(t, p)
		}
		out = append(out, o)
	}
	return out
}

// currentOf is where the service's rules send it now (the first rule's
// target), nil without rules.
func currentOf(t model.Topology, rules []int, decisions map[string]string) *matrixCurrent {
	if len(rules) == 0 {
		return nil
	}
	var dirs []matrixCurrent
	seen := map[string]bool{}
	for _, i := range rules {
		c := ruleDirection(t, t.Rules[i], decisions)
		k := c.Group + "|" + c.Exit + "|" + fmt.Sprint(c.Pinned)
		if !seen[k] {
			seen[k] = true
			dirs = append(dirs, c)
		}
	}
	if len(dirs) == 1 {
		return &dirs[0]
	}
	return &matrixCurrent{Mixed: dirs}
}

// ruleDirection is where one rule sends traffic, as the compiler decides it
// (compile.ruleExit): a pinned exit; in an automatic group the per-rule
// unlock decision when it names another member of the group's order, else
// the group's selection.
func ruleDirection(t model.Topology, r model.Rule, decisions map[string]string) matrixCurrent {
	if r.TargetExit != "" {
		return matrixCurrent{Exit: r.TargetExit, ExitName: nodeName(t, r.TargetExit), Pinned: true}
	}
	c := matrixCurrent{Group: r.TargetGroup, GroupName: r.TargetGroup}
	g, ok := t.GroupByID(r.TargetGroup)
	if !ok {
		return c
	}
	c.GroupName = g.Name
	sel := pool.Select(t, g, nil)
	exit := sel.Target
	if g.Mode == model.GroupAuto {
		if id := decisions[r.ID]; id != "" && id != sel.Target && containsStr(sel.Order, id) {
			exit = id
		}
	}
	if exit != "" {
		c.Exit, c.ExitName = exit, nodeName(t, exit)
	}
	return c
}

// recommend picks the exit for a service from its cells, or nil when no
// cell is unlocked. targets are the groups its rules point at now; for a
// global service an exit in one of them wins over a better one elsewhere.
func recommend(t model.Topology, a probe.Adapter, cells []matrixCell, targets []string, rules []int, runtime map[string]pool.Runtime) *matrixRec {
	type cand struct {
		cell     matrixCell
		group    model.RegionGroup
		inTarget bool
		health   int
		// inUse: the service's rules already target this group and it
		// prefers this exit. An unlocked, healthy exit in use is kept:
		// probe latencies differ by tens of milliseconds between runs, which
		// is no reason to suggest moving a working service.
		inUse bool
	}
	var cs []cand
	for _, c := range cells {
		if c.State != cellUnlocked {
			continue
		}
		best, inTarget := groupFor(t, a, c.ExitID, targets, rules)
		if best == nil {
			continue
		}
		h := 0
		if rt, ok := runtime[best.ID]; ok {
			if mh, ok := rt.Members[c.ExitID]; ok {
				h = mh.Fails
				if !mh.Up {
					h += 100
				}
			}
		}
		cs = append(cs, cand{cell: c, group: *best, inTarget: inTarget, health: h, inUse: recAdopted(t, *best, c.ExitID, rules)})
	}
	if len(cs) == 0 {
		return nil
	}
	sort.SliceStable(cs, func(i, j int) bool {
		x, y := cs[i], cs[j]
		if xk, yk := x.inUse && x.health == 0 && x.cell.failFams == 0, y.inUse && y.health == 0 && y.cell.failFams == 0; xk != yk {
			return xk
		}
		if a.Global() && x.inTarget != y.inTarget {
			return x.inTarget
		}
		if x.health != y.health {
			return x.health < y.health
		}
		if x.cell.failFams != y.cell.failFams {
			return x.cell.failFams < y.cell.failFams
		}
		if x.cell.okFams != y.cell.okFams {
			return x.cell.okFams > y.cell.okFams
		}
		if x.cell.LatencyMS != y.cell.LatencyMS {
			return x.cell.LatencyMS < y.cell.LatencyMS
		}
		return x.cell.ExitID < y.cell.ExitID
	})
	b := cs[0]
	rec := &matrixRec{ExitID: b.cell.ExitID, ExitName: nodeName(t, b.cell.ExitID), Group: b.group.ID, GroupName: b.group.Name}
	rec.Adopted = recAdopted(t, b.group, b.cell.ExitID, rules)
	return rec
}

// buildMatrix is the region sections of the unlock page.
// idents are the exits' current identity digests (exitIdentities).
func buildMatrix(t model.Topology, doc probeResultsDoc, runtime map[string]pool.Runtime, idents map[string]string, now time.Time, pol unlock.Policy) []matrixRegion {
	regions := exitRegions(t)
	exists := exitExists(t)
	var all []matrixExit
	byRegion := map[string][]matrixExit{}
	for _, n := range t.Nodes {
		if n.Role != model.RoleExit {
			continue
		}
		e := matrixExit{ID: n.ID, Name: nodeName(t, n.ID), Regions: append([]string{}, regions[n.ID]...), Groups: []string{}, Identity: idents[n.ID]}
		for _, g := range sortedGroups(t) {
			if containsStr(g.Members, n.ID) {
				e.Groups = append(e.Groups, g.ID)
			}
		}
		all = append(all, e)
		for _, r := range e.Regions {
			byRegion[r] = append(byRegion[r], e)
		}
	}
	sort.Slice(all, func(i, j int) bool { return all[i].ID < all[j].ID })
	items := map[string][]probeJobItem{}
	for _, it := range doc.Items {
		if exists(it.ExitID) {
			items[it.Service+"|"+it.ExitID] = append(items[it.Service+"|"+it.ExitID], it)
		}
	}
	codes := []string{}
	for _, r := range regionOrder {
		if len(byRegion[r]) > 0 {
			codes = append(codes, r)
		}
	}
	var rest []string
	for r := range byRegion {
		if !containsStr(regionOrder, r) {
			rest = append(rest, r)
		}
	}
	sort.Strings(rest)
	codes = append(codes, rest...)

	section := func(code string, exits []matrixExit) matrixRegion {
		sort.Slice(exits, func(i, j int) bool { return exits[i].ID < exits[j].ID })
		reg := matrixRegion{Code: code, Name: regionNames[code], Exits: exits, Services: []matrixService{}}
		if reg.Name == "" {
			reg.Name = strings.ToUpper(code)
		}
		for _, a := range probe.Catalog {
			if !probe.Probeable(a.Service) || !a.InScope(code) {
				continue
			}
			idx := serviceRules(t, a)
			svc := matrixService{ID: a.Service, Name: a.Name, Rules: []string{}, Targets: []string{}, Cells: []matrixCell{}}
			for _, i := range idx {
				svc.Rules = append(svc.Rules, t.Rules[i].ID)
				if g := t.Rules[i].TargetGroup; g != "" && !containsStr(svc.Targets, g) {
					svc.Targets = append(svc.Targets, g)
				}
			}
			for _, e := range exits {
				svc.Cells = append(svc.Cells, cellOf(e.ID, idents[e.ID], items[a.Service+"|"+e.ID], now, pol))
			}
			svc.Recommend = recommend(t, a, svc.Cells, svc.Targets, idx, runtime)
			scope := make([]string, 0, len(exits))
			for _, e := range exits {
				scope = append(scope, e.ID)
			}
			svc.Groups = groupOptions(t, a, scope, idx, idents)
			svc.Current = currentOf(t, idx, nil)
			reg.Services = append(reg.Services, svc)
		}
		return reg
	}
	out := []matrixRegion{}
	if len(all) > 0 {
		out = append(out, section(probe.RegionGlobal, append([]matrixExit{}, all...)))
	}
	for _, c := range codes {
		if reg := section(c, byRegion[c]); len(reg.Services) > 0 {
			out = append(out, reg)
		}
	}
	return out
}

func (s *Server) matrixNow() (model.Topology, []matrixRegion, error) {
	s.mu.Lock()
	t, err := s.topology()
	if err != nil {
		s.mu.Unlock()
		return t, nil, err
	}
	doc := s.loadResults()
	runtime := s.loadPools().Pools
	idents, _ := s.noteIdentities(t)
	s.mu.Unlock()
	regions := buildMatrix(t, doc, runtime, idents, time.Now().UTC(), unlockPolicy(t))
	// The direction shown is the compiled one: per-rule unlock decisions
	// can move a rule to another member of an automatic group.
	if dec := s.unlockDecisions(t); len(dec) > 0 {
		byID := map[string]int{}
		for i, r := range t.Rules {
			byID[r.ID] = i
		}
		for ri := range regions {
			for si := range regions[ri].Services {
				svc := &regions[ri].Services[si]
				var idx []int
				for _, id := range svc.Rules {
					if i, ok := byID[id]; ok {
						idx = append(idx, i)
					}
				}
				svc.Current = currentOf(t, idx, dec)
			}
		}
	}
	return t, regions, nil
}

func (s *Server) getUnlockMatrix(w http.ResponseWriter, r *http.Request) {
	_, regions, err := s.matrixNow()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	s.jobMu.Lock()
	running := ""
	if s.job != nil {
		running = s.job.id
	}
	s.jobMu.Unlock()
	writeJSON(w, http.StatusOK, map[string]any{"regions": regions, "running": running, "available": s.Prober != nil})
}

type adoptBody struct {
	Service string `json:"service"`
	Exit    string `json:"exit"`
	// Group: 手动 to a region group (出口组) instead of an exit.
	Group string `json:"group"`
	// Preview answers what saving would touch without saving.
	Preview bool `json:"preview"`
	// Manual: the operator's own pick (手动) instead of the recommendation
	// (确认): Group (the rules follow the group, which is left as it is) or
	// Exit (the rules pin the exit; it need not be unlocked). Identity is
	// the digest the panel showed (matrixExit.Identity or
	// matrixGroupOpt.Identity).
	Manual   bool   `json:"manual"`
	Identity string `json:"identity"`
}

// adoptChoice is what a save writes: 确认 (rules → Group, Group prefers
// ExitID), 手动 to a group (rules → Group only) or to an exit (rules pin
// ExitID).
type adoptChoice struct {
	Kind      string // "confirm", "group", "exit"
	Group     string
	GroupName string
	ExitID    string
	ExitName  string
}

// adoptImpact: the service's own rules, and for 确认 the other rules that
// target the same region group and so move with its new preferred exit.
// Nothing else moves when the group already prefers the exit, nor on 手动.
func adoptImpact(t model.Topology, a probe.Adapter, c adoptChoice) (service []string, others int) {
	idx := serviceRules(t, a)
	own := map[int]bool{}
	for _, i := range idx {
		own[i] = true
		service = append(service, t.Rules[i].ID)
	}
	if c.Kind != "confirm" {
		return service, 0
	}
	g, ok := t.GroupByID(c.Group)
	if !ok || groupPrefers(t, g, c.ExitID) {
		return service, 0
	}
	for i, ru := range t.Rules {
		if !own[i] && ru.TargetGroup == c.Group && ru.TargetAction == "" {
			others++
		}
	}
	return service, others
}

// findRec is the current recommendation of service in the matrix.
func findRec(regions []matrixRegion, service string) (*matrixRec, bool) {
	found := false
	for _, reg := range regions {
		for _, svc := range reg.Services {
			if svc.ID == service {
				found = true
				if svc.Recommend != nil {
					return svc.Recommend, true
				}
			}
		}
	}
	return nil, found
}

// serviceScope is the union of the service rows' exits (its probe scope);
// ok is false when the matrix has no row of it.
func serviceScope(regions []matrixRegion, service string) (scope []string, ok bool) {
	for _, reg := range regions {
		for _, svc := range reg.Services {
			if svc.ID != service {
				continue
			}
			ok = true
			for _, c := range svc.Cells {
				if !containsStr(scope, c.ExitID) {
					scope = append(scope, c.ExitID)
				}
			}
		}
	}
	return scope, ok
}

// adoptTarget is what a save would write, or an error with an HTTP status
// prefix ("409:", "400:"). 确认 takes the current recommendation, which
// must still be b.Exit. 手动 to a group: the group is in the service's
// probe scope, holds one of its in-scope exits, meets the rules' hard
// constraints and its members' identities are the ones the panel showed.
// 手动 to an exit: the exit is in scope, its identity is the one shown and
// it meets the hard constraints itself (the rules pin it).
func adoptTarget(t model.Topology, regions []matrixRegion, idents map[string]string, a probe.Adapter, b adoptBody) (adoptChoice, error) {
	if !b.Manual {
		got, _ := findRec(regions, b.Service)
		if got == nil || got.ExitID != b.Exit {
			return adoptChoice{}, errors.New("409:探测结果已变化，推荐出口不再是这个；刷新后再确认")
		}
		return adoptChoice{Kind: "confirm", Group: got.Group, GroupName: got.GroupName, ExitID: got.ExitID, ExitName: got.ExitName}, nil
	}
	scope, _ := serviceScope(regions, b.Service)
	idx := serviceRules(t, a)
	if b.Group != "" {
		g, ok := t.GroupByID(b.Group)
		if !ok {
			return adoptChoice{}, errors.New("400:没有这个出口组")
		}
		if why := groupScope(t, a, g, scope, idx); why != "" {
			return adoptChoice{}, errors.New(why)
		}
		cur := groupIdentity(g, scope, idents)
		if cur == "" || b.Identity == "" || cur != b.Identity {
			return adoptChoice{}, errors.New("409:出口组成员的配置已变化；刷新后再选")
		}
		c := adoptChoice{Kind: "group", Group: g.ID, GroupName: g.Name}
		if p := pool.Select(t, g, nil).Target; p != "" {
			c.ExitID, c.ExitName = p, nodeName(t, p)
		}
		return c, nil
	}
	if !containsStr(scope, b.Exit) {
		return adoptChoice{}, errors.New("400:这个出口不在该服务的探测范围内")
	}
	cur := idents[b.Exit]
	if cur == "" || b.Identity == "" || cur != b.Identity {
		return adoptChoice{}, errors.New("409:出口配置已变化，探测结果不再对应这个出口；刷新后再选")
	}
	n, ok := t.NodeByID(b.Exit)
	needResi, needV6 := ruleNeeds(t, idx)
	if !ok || (needResi && !n.Residential) || (needV6 && !n.EgressV6) {
		return adoptChoice{}, errors.New("409:这个出口不满足规则约束（家宽 / IPv6）")
	}
	return adoptChoice{Kind: "exit", ExitID: b.Exit, ExitName: nodeName(t, b.Exit)}, nil
}

// adoptLockedHook (tests only) runs inside the save's locks, right after the
// managed servers are read.
var adoptLockedHook func(s *Server)

// postUnlockAdopt saves a choice of the unlock page: 确认 points the
// service's rules at the recommended exit's region group and makes the
// group prefer that exit (when the latest results recommend another exit,
// or none, nothing changes, 409); 手动 points them at a group (left as it
// is) or pins an exit (see adoptTarget). All share the preview, the checks
// and the save, and take the rules' automatic apply with exactly this scope
// (rulesAutoAfterSave with an unlockEdit; 手动 touches no group).
func (s *Server) postUnlockAdopt(w http.ResponseWriter, r *http.Request) {
	var b adoptBody
	if err := decodeBody(w, r, &b); err != nil || b.Service == "" || (b.Exit == "" && (b.Group == "" || !b.Manual)) {
		writeErr(w, http.StatusBadRequest, errors.New("需要 service 和 exit（或手动选择的 group）"))
		return
	}
	a, ok := probe.Lookup(b.Service)
	if !ok {
		writeErr(w, http.StatusNotFound, errors.New("没有这个服务"))
		return
	}
	if b.Manual && b.Group != "" {
		b.Exit = ""
	}
	now := time.Now().UTC()
	if b.Preview {
		s.mu.Lock()
		t, err := s.topology()
		if err != nil {
			s.mu.Unlock()
			writeErr(w, http.StatusInternalServerError, err)
			return
		}
		doc, runtime := s.loadResults(), s.loadPools().Pools
		idents, _ := s.noteIdentities(t)
		s.mu.Unlock()
		got, err := adoptTarget(t, buildMatrix(t, doc, runtime, idents, now, unlockPolicy(t)), idents, a, b)
		if err != nil {
			s.writeSaveErr(w, nil, err)
			return
		}
		svc, others := adoptImpact(t, a, got)
		if svc == nil {
			svc = []string{}
		}
		writeJSON(w, http.StatusOK, map[string]any{"preview": true, "manual": b.Manual, "kind": got.Kind, "group": got.Group, "exit": got.ExitID, "service_rules": svc, "other_rules": others})
		return
	}
	n := 0
	var got adoptChoice
	var edit unlockEdit
	// Results, pool runtime and exit identities are read inside the save
	// (s.mu before the store lock, as everywhere), so the choice is checked
	// against the configuration being changed: a probe result or an exit
	// identity that changed since the panel showed it refuses with 409 and
	// nothing is written.
	//
	// resMu is held around all of it: a managed server's address or port
	// (patchServer) changes only under resMu, so the servers read here are
	// the ones in force when the rules are written. Order: resMu, s.mu,
	// store lock (as mutateGroups → afterGroupChange).
	s.resMu.Lock()
	s.mu.Lock()
	servers := s.serverMap()
	if adoptLockedHook != nil {
		adoptLockedHook(s)
	}
	_, before, issues, err := s.saveRulesChecked(func(t *model.Topology) error {
		doc, runtime := s.loadResults(), s.loadPools().Pools
		idents, _ := s.observeIdentities(exitIdentities(*t, servers))
		c, err := adoptTarget(*t, buildMatrix(*t, doc, runtime, idents, now, unlockPolicy(*t)), idents, a, b)
		if err != nil {
			return err
		}
		got = c
		idx := serviceRules(*t, a)
		if len(idx) == 0 {
			return errors.New("404:没有规则属于这个服务")
		}
		edit = unlockEdit{}
		for _, i := range idx {
			ru := &t.Rules[i]
			if c.Kind == "exit" {
				ru.TargetGroup, ru.TargetExit = "", c.ExitID
			} else {
				ru.TargetGroup, ru.TargetExit = c.Group, ""
			}
			edit.Rules = append(edit.Rules, ru.ID)
			n++
		}
		if c.Kind != "confirm" {
			return nil
		}
		t.Groups = append([]model.RegionGroup(nil), t.Groups...)
		for i := range t.Groups {
			g := &t.Groups[i]
			if g.ID != c.Group {
				continue
			}
			edit.Group = unlockGroupOf(*g)
			g.Members = append([]string(nil), g.Members...)
			if g.Mode == model.GroupManual {
				g.Chosen = c.ExitID
			} else {
				m := []string{c.ExitID}
				for _, id := range g.Members {
					if id != c.ExitID {
						m = append(m, id)
					}
				}
				g.Members = m
				// The effective order puts IX-bound members first, so moving
				// the exit to the front is not always enough. Then pin it
				// (manual) and keep failover: a failing pinned exit falls
				// back to the next member and returns when it recovers.
				if !groupPrefers(*t, *g, c.ExitID) {
					g.Mode, g.Chosen, g.OnFailure = model.GroupManual, c.ExitID, model.OnFailureFallback
				}
			}
			if !groupPrefers(*t, *g, c.ExitID) {
				return errors.New("409:地区组的约束不允许把这个出口设为首选")
			}
		}
		return nil
	})
	s.mu.Unlock()
	s.resMu.Unlock()
	if s.writeSaveErr(w, issues, err) {
		return
	}
	writeJSON(w, http.StatusOK, withRulesAuto(map[string]any{"updated": n, "manual": b.Manual, "kind": got.Kind, "group": got.Group, "exit": got.ExitID, "rules": edit.Rules}, s.rulesAutoAfterSave(before, "unlock", edit)))
}
