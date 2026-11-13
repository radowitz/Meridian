package model

import (
	"sort"
)

// Additional match types (see MatchType in model.go).
const (
	// MatchRuleSet uses a subscribed rule-set (Rule.RuleSet) as the match
	// source; all its entries sit at the rule's position in the list.
	MatchRuleSet MatchType = "ruleset"
	// MatchQUICReject is the position marker of the gateway's QUIC switch:
	// UDP to port 443 is refused (ICMP port unreachable) for traffic that a
	// rule BELOW this row (or the default group) sends into a tunnel; rules
	// above it are exempt, as in mihomo where they match before the
	// "AND,((DST-PORT,443),(NETWORK,UDP)),(NOT,((GEOSITE,cn)))),REJECT" rule.
	// Direct (domestic) traffic is never affected. It has no target.
	MatchQUICReject MatchType = "quic_reject"
)

// Rule targets besides a region group or an exit.
const (
	// ActionDirect: resolved by the domestic resolvers, routed direct.
	ActionDirect = "direct"
	// ActionReject: resolved normally (by the default target's resolver,
	// IPv4 only), then every connection to the learned addresses is refused
	// by the gateway: TCP with a reset, everything else with ICMP port
	// unreachable. The client sees "connection refused" at once.
	ActionReject = "reject"
)

// Rule origins.
const (
	OriginPanel  = ""
	OriginMihomo = "mihomo"
)

// RuleSet is a subscribed rule-set: a Clash/mihomo rule provider or Surge
// rule list fetched by URL (internal/ruleset). Its fetch status and
// content live outside the topology (the panel's rule-set store and the
// gateway's /var/lib/meridian/geosite/rulesets/<id>.txt).
type RuleSet struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	URL  string `json:"url"`
	// Format: "" detects; otherwise one of ruleset.Formats.
	Format string `json:"format,omitempty"`
	// Behavior is the provider's behavior (classical, domain, ipcidr) when
	// imported from mihomo; a hint for detection.
	Behavior string `json:"behavior,omitempty"`
	// Source: "policy" (GitHub raw files through the list source policy,
	// then the URL as given) or "url" (only the URL as given).
	Source string `json:"source,omitempty"`
	// IntervalSec between automatic updates; 0 means 24 hours.
	IntervalSec int `json:"interval_sec,omitempty"`
	// AllowLAN lets the URL resolve to a private (LAN) address. Loopback,
	// link-local and this host's own addresses stay refused.
	AllowLAN bool   `json:"allow_lan,omitempty"`
	Origin   string `json:"origin,omitempty"`
}

// ServiceGroup is a switchable target between rules and the data plane
// (a mihomo "select" policy group such as an AI or streaming group): rules
// point at it, and it points at exactly one of a region group, an exit,
// direct or reject. Changing it re-targets every rule using it without
// touching the rules; it takes effect through the normal install.
type ServiceGroup struct {
	ID           string `json:"id"`
	Name         string `json:"name"`
	Origin       string `json:"origin,omitempty"`
	TargetGroup  string `json:"target_group,omitempty"`
	TargetExit   string `json:"target_exit,omitempty"`
	TargetAction string `json:"target_action,omitempty"`
	// Default marks the group MATCH points at: its target is the gateway's
	// default group (Settings.DefaultGroup), so it must be a region group.
	Default bool `json:"default,omitempty"`
}

// MihomoImport is what the panel remembers between imports: the operator's
// mapping of mihomo names (line groups, region selectors, proxies) to
// panel targets, and what the last import wrote.
type MihomoImport struct {
	// Mapping: mihomo name -> "group:<id>", "exit:<id>", "direct", "reject".
	Mapping    map[string]string `json:"mapping,omitempty"`
	ImportedAt string            `json:"imported_at,omitempty"`
	// Digest of the confirmed preview.
	Digest string `json:"digest,omitempty"`
	Rules  int    `json:"rules,omitempty"`
}

// RuleSetByID finds a rule-set.
func (t Topology) RuleSetByID(id string) (RuleSet, bool) {
	for _, r := range t.RuleSets {
		if r.ID == id {
			return r, true
		}
	}
	return RuleSet{}, false
}

// ServiceByID finds a service group.
func (t Topology) ServiceByID(id string) (ServiceGroup, bool) {
	for _, s := range t.ServiceGroups {
		if s.ID == id {
			return s, true
		}
	}
	return ServiceGroup{}, false
}

// Target is a rule's effective destination after the service-group layer.
type Target struct {
	// Kind: "group", "exit", "direct", "reject" ("" unresolved).
	Kind string
	ID   string
	// Service is the service group the target came through ("" none).
	Service string
}

// ResolveTarget follows a rule's target through its service group.
func (t Topology) ResolveTarget(r Rule) Target {
	switch {
	case r.TargetAction != "":
		return Target{Kind: r.TargetAction}
	case r.TargetService != "":
		s, ok := t.ServiceByID(r.TargetService)
		if !ok {
			return Target{Service: r.TargetService}
		}
		tg := serviceTarget(s)
		tg.Service = s.ID
		return tg
	case r.TargetExit != "":
		return Target{Kind: "exit", ID: r.TargetExit}
	case r.TargetGroup != "":
		return Target{Kind: "group", ID: r.TargetGroup}
	}
	return Target{}
}

func serviceTarget(s ServiceGroup) Target {
	switch {
	case s.TargetAction != "":
		return Target{Kind: s.TargetAction}
	case s.TargetExit != "":
		return Target{Kind: "exit", ID: s.TargetExit}
	case s.TargetGroup != "":
		return Target{Kind: "group", ID: s.TargetGroup}
	}
	return Target{}
}

// LegacyRuleLess is the order the compiler used before the list became
// explicit: every manual rule before every built-in rule, then ascending
// priority, then ID.
func LegacyRuleLess(a, b Rule) bool {
	if a.Manual != b.Manual {
		return a.Manual
	}
	if a.Priority != b.Priority {
		return a.Priority < b.Priority
	}
	return a.ID < b.ID
}

// MigrateRuleOrder turns a topology from before the explicit list into one
// whose Rules slice is the evaluation order: the rules are stably sorted by
// the order the compiler used (LegacyRuleLess), so the classify chain and
// the per-rule sets keep exactly their previous order, and RulesOrdered is
// set. Priorities are left as they were (the position is the order). It reports
// whether anything changed. Whether a pair of rules now resolves
// differently (the resolver used to pick the longer of two overlapping
// names, it now takes the earlier rule) is reported by
// ordered.Analyze on the migrated list (the rules page shows it per rule).
func MigrateRuleOrder(t *Topology) bool {
	if t.RulesOrdered {
		return false
	}
	sort.SliceStable(t.Rules, func(i, j int) bool { return LegacyRuleLess(t.Rules[i], t.Rules[j]) })
	t.RulesOrdered = true
	return true
}

// EvalOrder returns the rules in evaluation order: the slice itself once
// the list is explicit, the legacy sort before.
func (t Topology) EvalOrder() []Rule {
	rules := append([]Rule(nil), t.Rules...)
	if !t.RulesOrdered {
		sort.SliceStable(rules, func(i, j int) bool { return LegacyRuleLess(rules[i], rules[j]) })
	}
	return rules
}
