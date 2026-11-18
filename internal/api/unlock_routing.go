package api

// The unlock routing view (GET /api/unlock "owners"): every place an
// unlock decision is made or shown (servicesOf) with its candidates and,
// per candidate, the evidence the state machine holds, what the panel
// computes as the exit in use, why, and when it last switched.
//
// Measured vs inferred: the evidence column is what probes measured (with
// the time the panel received it and whether it is still valid under the
// result lifetime). The exit in use is the panel's computation from that
// evidence (面板推算); it reaches the gateway only through the install
// (pending_apply says it has not yet). Nothing here reads the gateway.

import (
	"github.com/radowitz/meridian/internal/probe"
	"sort"
	"time"

	"github.com/radowitz/meridian/internal/compile"
	"github.com/radowitz/meridian/internal/model"
	"github.com/radowitz/meridian/internal/unlock"
)

type recentProbeView struct {
	Service  string         `json:"service"`
	Family   unlock.Family  `json:"family"`
	Category probe.Category `json:"category"`
	At       time.Time      `json:"at"`
	Expired  bool           `json:"expired"`
}

type candidateView struct {
	Recent []recentProbeView `json:"recent,omitempty"`
	ExitID string            `json:"exit_id"`
	Name   string            `json:"name"`
	Region string            `json:"region,omitempty"`
	// TCPOnly: an external SOCKS exit (probes and traffic: TCP over IPv4).
	TCPOnly bool `json:"tcp_only,omitempty"`
	// Evidence: ok, failed, expired or "" (never measured).
	Evidence string     `json:"evidence"`
	SeenAt   *time.Time `json:"seen_at,omitempty"`
	Active   bool       `json:"active"`
	Default  bool       `json:"default"`
}

type ownerView struct {
	Key  string `json:"key"`
	Name string `json:"name"`
	// Kind: rule (a rule aimed at a region group, the built-in auto-*
	// rules among them).
	Kind      string `json:"kind"`
	Group     string `json:"group,omitempty"`
	GroupName string `json:"group_name,omitempty"`
	Region    string `json:"region,omitempty"`
	// Mode: auto (results move it), pinned (manual group: recorded only).
	Mode       string          `json:"mode"`
	PinReason  string          `json:"pin_reason,omitempty"`
	Probes     []string        `json:"probes"`
	Candidates []candidateView `json:"candidates"`
	// Default is where it stays when no candidate is known good (the
	// member the group selects); Active the panel's computed exit in use.
	Default string `json:"default,omitempty"`
	Active  string `json:"active,omitempty"`
	// Inferred is always true: Active is computed by the panel, not read
	// from the gateway.
	Inferred     bool       `json:"inferred"`
	Demoted      bool       `json:"demoted"`
	Unavailable  bool       `json:"unavailable"`
	SchedFails   int        `json:"sched_fails"`
	SwitchedAt   *time.Time `json:"switched_at,omitempty"`
	SwitchReason string     `json:"switch_reason,omitempty"`
	// Rules: how many enabled rules route through it.
	Rules    int      `json:"rules"`
	Warnings []string `json:"warnings"`
}

func routingView(t model.Topology, snap unlock.Snapshot, now time.Time, results ...probeResultsDoc) []ownerView {
	exits, _ := compile.ProbeExits(t)
	out := []ownerView{}
	for _, svc := range servicesOf(t) {
		if len(svc.Probes) == 0 {
			continue
		}
		st := snap.Services[svc.RuleID]
		pol := unlockPolicy(t)
		v := ownerView{Key: svc.RuleID, Name: svc.Name, Kind: "rule", Group: svc.Pool,
			Mode: "auto", Probes: append([]string{}, svc.Probes...), Candidates: []candidateView{}, Default: svc.Preferred,
			Inferred: true, Warnings: []string{}, Rules: 1}
		if g, ok := t.GroupByID(svc.Pool); ok {
			v.GroupName, v.Region = g.Name, g.Region
		}
		if svc.Pin {
			v.Mode = "pinned"
			v.PinReason = "地区组是手动模式"
		}
		v.Active = activeFor(snap, svc)
		if st.Preferred == svc.Preferred {
			v.Demoted, v.Unavailable, v.SchedFails = st.Demoted, st.Unavailable, st.SchedFails
		}
		if !st.SwitchedAt.IsZero() {
			at := st.SwitchedAt
			v.SwitchedAt, v.SwitchReason = &at, st.SwitchReason
		}
		for _, m := range svc.Members {
			c := candidateView{ExitID: m, Name: nodeName(t, m), Evidence: st.Evidence(m, now, pol), Active: m == v.Active, Default: m == svc.Preferred}
			if n, ok := t.NodeByID(m); ok {
				c.Region = n.Region
			}
			if ex, ok := exits[m]; ok {
				c.TCPOnly = ex.TCPOnly
			}
			if at, ok := st.KnownAt[m]; ok && !at.IsZero() {
				a := at
				c.SeenAt = &a
			}
			if len(results) > 0 {
				for _, id := range svc.Probes {
					for _, fam := range []unlock.Family{unlock.FamilyIPv4, unlock.FamilyIPv6} {
						it, found := results[0].Items[id+"|"+m+"|"+string(fam)]
						if !found || it.FinishedAt == nil {
							continue
						}
						ad, _ := probe.Lookup(id)
						category, _ := sanitizeCategory(ad, it.Category, it.Signal)
						if it.Category == probe.CatNotApplicable {
							category = it.Category
						}
						c.Recent = append(c.Recent, recentProbeView{Service: id, Family: fam, Category: category, At: *it.FinishedAt, Expired: now.Sub(*it.FinishedAt) > pol.TTL})
					}
				}
			}
			v.Candidates = append(v.Candidates, c)
		}
		switch {
		case len(svc.Members) == 0:
			v.Warnings = append(v.Warnings, "没有候选出口（目标地区组没有可用成员，或目标是直连 / 拒绝）")
		case v.Unavailable:
			v.Warnings = append(v.Warnings, "没有任何候选有有效的解锁证据：留在默认出口 "+nodeName(t, svc.Preferred)+"，不会随机换地区")
		}
		if v.Mode == "auto" && v.Active != "" && st.Evidence(v.Active, now, pol) == "expired" {
			v.Warnings = append(v.Warnings, "当前出口的检测结果已过期，不再是有效证据；等下一轮探测")
		}
		out = append(out, v)
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Region != out[j].Region {
			return out[i].Region < out[j].Region
		}
		return out[i].Key < out[j].Key
	})
	return out
}

// probeSchedule is the effective restraint settings, for the panel.
func probeSchedule(t model.Topology) map[string]any {
	return map[string]any{
		"interval_sec":        int(unlock.Interval(t.Settings.UnlockIntervalSec).Seconds()),
		"exit_concurrency":    exitConcurrency(t),
		"exit_request_budget": exitBudget(t),
		"result_ttl_sec":      int(unlockPolicy(t).TTL.Seconds()),
		"sched_fails_need":    unlock.SchedFailsNeed,
		"return_cooldown_sec": int(unlock.ReturnCooldown.Seconds()),
		"result_fresh_sec":    int(unlock.ResultFreshFor.Seconds()),
	}
}
