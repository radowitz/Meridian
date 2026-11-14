// Package unlock is the 6-hour streaming/AI map and its hysteresis.
//
// Automatic rules may move to another member of the same pool. They never
// move to a different country: AI stays on US, Netflix/Disney+ stay on Hong
// Kong residential, Taiwan-only services stay on TW. A pinned manual rule is
// not in this map. Two consecutive scheduled failures are required before a
// move; a manual click or a single health-change probe does not count.
//
// Returning to the preferred member (canReturn) requires all of:
//
//   - the rule is demoted;
//   - the latest result the panel holds for the preferred member is a success
//     (any failure of the preferred, of any kind, clears PreferredOKAt at once,
//     so the recovery streak starts again from the next success);
//   - that latest preferred result was received within ResultFreshFor of the
//     decision (an old success cannot trigger a return);
//   - the preferred has been continuously successful for ReturnCooldown,
//     measured on the panel's own clock from the first success after its last
//     failure (PreferredOKAt). A report's own timestamp cannot shorten it.
//
// The backup's health is not part of the return condition: a working backup
// is no reason to go back, and a failing backup is handled by its own
// two-failure rule.
//
// Which reports may change state at all is decided by Ingest (report.go):
// ordering, validity window and duplicate handling per service, exit and
// address family.
package unlock

import (
	"bufio"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const (
	DefaultInterval = 6 * time.Hour
	SchedFailsNeed  = 2
	ReturnCooldown  = 30 * time.Minute
	// ResultFreshFor bounds how long ago (panel receive time) the preferred
	// member's latest result may have arrived and still count as "currently
	// healthy" for a return.
	ResultFreshFor = 30 * time.Minute
	maxHistory     = 200
)

type Kind string

const (
	KindScheduled Kind = "scheduled"
	KindManual    Kind = "manual"
	KindHealth    Kind = "health"
	// KindInconclusive is a panel-run probe that produced no platform verdict
	// for any family of a service on an exit: egress could not be confirmed,
	// the transport failed or timed out, or the response was not
	// recognisable. It never counts toward the two scheduled failures (it is
	// not scheduled), but as a non-success it ends the preferred member's
	// recovery streak and stops the exit from being picked as a known-good
	// backup. Only the panel's own probe job produces it; /api/unlock/report
	// does not accept it.
	KindInconclusive Kind = "inconclusive"
)

// State is one automatic rule's unlock decision.
type State struct {
	Pool        string `json:"pool"`
	Preferred   string `json:"preferred"`
	Active      string `json:"active"`
	SchedFails  int    `json:"sched_fails"`
	Demoted     bool   `json:"demoted"`
	Unavailable bool   `json:"unavailable"`
	// ActiveFails counts scheduled failures of the member currently carrying
	// the service, once it is no longer the preferred member. Two are
	// required before trying another member of the same pool.
	ActiveFails int             `json:"active_fails,omitempty"`
	Known       map[string]bool `json:"known,omitempty"`
	// BackupOKAt is informational: when the current backup was last proven.
	// It is not part of the return condition.
	BackupOKAt time.Time `json:"backup_ok_at,omitempty"`
	// PreferredOKAt is the start of the preferred member's current unbroken
	// success streak while demoted (panel clock). Zero after any failure.
	PreferredOKAt time.Time `json:"preferred_ok_at,omitempty"`
	// PreferredSeenAt is when the panel received the preferred member's
	// latest result, success or failure.
	PreferredSeenAt time.Time `json:"preferred_seen_at,omitempty"`
	// KnownAt is when the panel received the result recorded in Known, per
	// member. With a result lifetime (Policy.TTL) a Known entry older than
	// the lifetime is no evidence at all: it neither makes a member a
	// known-good backup nor rules it out. An entry without a time (a state
	// stored before KnownAt existed) keeps its old meaning until the
	// member's next result replaces it. See Policy.
	KnownAt map[string]time.Time `json:"known_at,omitempty"`
	// SwitchedAt and SwitchReason record the last change of Active (panel
	// clock) and why (Switch* codes). For display only.
	SwitchedAt   time.Time `json:"switched_at,omitempty"`
	SwitchReason string    `json:"switch_reason,omitempty"`
}

// Switch reasons.
const (
	// SwitchPreferredFailed: the preferred member failed SchedFailsNeed
	// scheduled probes; the service moved to a backup.
	SwitchPreferredFailed = "preferred_failed"
	// SwitchBackupFailed: the backup in use failed SchedFailsNeed scheduled
	// probes; the service moved to the next backup.
	SwitchBackupFailed = "backup_failed"
	// SwitchRecovered: the preferred member was continuously successful for
	// ReturnCooldown with a fresh result; the service returned.
	SwitchRecovered = "recovered"
	// SwitchAllFailed: no candidate is known to unlock; the service is back
	// on (or stays on) the preferred member and is marked unavailable.
	SwitchAllFailed = "all_failed"
	// SwitchGroupChanged: the group's order or preferred member changed
	// (Reconcile).
	SwitchGroupChanged = "group_changed"
)

func switchReason(prev, next State) string {
	switch {
	case next.Unavailable:
		return SwitchAllFailed
	case next.Active == next.Preferred && prev.Demoted:
		return SwitchRecovered
	case next.Demoted && !prev.Demoted:
		return SwitchPreferredFailed
	default:
		return SwitchBackupFailed
	}
}

// Policy carries the tunable parts of the state machine. The zero value is
// the behaviour before the policy existed (results never expire), which is
// what Advance, Apply, Ingest and Reconcile use.
type Policy struct {
	// TTL is how long an admitted result stays valid evidence about a
	// member (panel receive time). Zero: no expiry. An expired success is
	// not a reason to move a service onto that member, and an expired
	// failure is not a reason to keep it off; both count as "not measured".
	// The thresholds themselves (SchedFailsNeed, ReturnCooldown,
	// ResultFreshFor) do not change with it.
	TTL time.Duration
	// RequireEvidence: a backup is only ever a member with a valid (fresh,
	// successful) result. Without it a member never measured may be tried
	// when no member is known good (the behaviour before the policy). With
	// it, when no candidate has valid evidence, the service stays on the
	// preferred member and is marked unavailable (the panel warns).
	RequireEvidence bool
}

// known is s.Known[id] under pol at now: seen is false for a member never
// measured and, with a TTL, for a result older than the TTL.
func (s State) known(id string, now time.Time, pol Policy) (ok, seen bool) {
	ok, seen = s.Known[id]
	if !seen || pol.TTL <= 0 {
		return ok, seen
	}
	at, has := s.KnownAt[id]
	if !has || at.IsZero() {
		// A result recorded before KnownAt existed keeps the meaning it had
		// (an upgrade does not move or strand a service); the next result
		// for the member replaces it with a timed one.
		return ok, true
	}
	if now.Before(at) || now.Sub(at) > pol.TTL {
		return false, false
	}
	return ok, true
}

// Evidence reports what the state holds about member id at now under pol:
// "ok", "failed", "expired" (a result exists but is older than the TTL) or
// "" (never measured). For display; the machine uses known.
func (s State) Evidence(id string, now time.Time, pol Policy) string {
	ok, seen := s.Known[id]
	if !seen {
		return ""
	}
	if _, fresh := s.known(id, now, pol); !fresh {
		return "expired"
	}
	if ok {
		return "ok"
	}
	return "failed"
}

// Event is one probe verdict of one exit for one service, after Ingest has
// admitted it. At is the panel receive time and drives cooldown and
// freshness; ObservedAt (when the probe ran) is only used for ordering.
type Event struct {
	Service    string
	ExitID     string
	Family     Family
	OK         bool
	Kind       Kind
	At         time.Time
	ObservedAt time.Time
}

// Advance applies one probe. members is the pool in preference order.
// An exit outside members is ignored: that is how a US probe cannot move
// a Netflix rule, and how a Japan exit cannot become the Taiwan path.
//
// Advance does not check ordering or staleness; callers that take reports
// from the network must go through Ingest.
func Advance(s State, ev Event, members []string) State {
	return AdvanceWith(s, ev, members, Policy{})
}

// AdvanceWith is Advance under a policy (result lifetime). The decision
// rules are the same; only which earlier results still count differs.
func AdvanceWith(s State, ev Event, members []string, pol Policy) State {
	if s.Known == nil {
		s.Known = map[string]bool{}
	}
	if s.KnownAt == nil {
		s.KnownAt = map[string]time.Time{}
	}
	if s.Preferred == "" && len(members) > 0 {
		s.Preferred = members[0]
	}
	if s.Active == "" {
		s.Active = s.Preferred
	}
	if ev.ExitID == "" || !contains(members, ev.ExitID) {
		return s
	}
	s.Known[ev.ExitID] = ev.OK
	s.KnownAt[ev.ExitID] = ev.At
	if ev.ExitID == s.Preferred {
		s.PreferredSeenAt = ev.At
		if !ev.OK {
			// Any failure of the preferred, scheduled or not, breaks the
			// recovery streak. Only a later success can start it again.
			s.PreferredOKAt = time.Time{}
		}
	}
	if ev.Kind == KindScheduled && ev.ExitID == s.Preferred {
		if ev.OK {
			s.SchedFails = 0
			s.Unavailable = false
		} else {
			s.SchedFails++
		}
	}
	if ev.OK && ev.ExitID == s.Preferred && s.Demoted && s.PreferredOKAt.IsZero() {
		s.PreferredOKAt = ev.At
	}
	if ev.OK && s.Demoted && ev.ExitID == s.Active && ev.ExitID != s.Preferred {
		s.BackupOKAt = ev.At
	}
	if !s.Demoted && s.SchedFails >= SchedFailsNeed {
		if alt := pickBackup(s, members, ev.At, pol); alt != "" {
			s.Active = alt
			s.Demoted = true
			s.ActiveFails = 0
			s.Unavailable = false
			s.BackupOKAt = time.Time{}
			s.PreferredOKAt = time.Time{}
			if good, seen := s.known(alt, ev.At, pol); seen && good {
				s.BackupOKAt = ev.At
			}
		} else if ev.Kind == KindScheduled && ev.ExitID == s.Preferred && !ev.OK {
			s.Unavailable = true
			s.Active = s.Preferred
		}
	}
	// A backup that itself fails two scheduled probes is not left in place,
	// and it is not replaced with an exit from another pool. The next
	// known-good member of this pool is tried; if there is none, the service
	// is marked unavailable and put back on the preferred member.
	if s.Demoted && ev.Kind == KindScheduled && ev.ExitID == s.Active && ev.ExitID != s.Preferred {
		if ev.OK {
			s.ActiveFails = 0
		} else {
			s.ActiveFails++
			if s.ActiveFails >= SchedFailsNeed {
				s.ActiveFails = 0
				if alt := pickBackup(s, members, ev.At, pol); alt != "" && alt != s.Active {
					s.Active = alt
					s.Unavailable = false
					s.BackupOKAt = time.Time{}
					if good, seen := s.known(alt, ev.At, pol); seen && good {
						s.BackupOKAt = ev.At
					}
				} else {
					s.Unavailable = true
					s.Active = s.Preferred
					s.Demoted = false
					s.SchedFails = 0
					s.BackupOKAt = time.Time{}
					s.PreferredOKAt = time.Time{}
				}
			}
		}
	}
	if s.Demoted && s.CanReturn(ev.At) {
		s.Active = s.Preferred
		s.Demoted = false
		s.Unavailable = false
		s.SchedFails = 0
		s.BackupOKAt = time.Time{}
		s.PreferredOKAt = time.Time{}
	}
	return s
}

// CanReturn reports whether a demoted rule may go back to its preferred
// member at now (panel clock). See the package comment for the rule.
func (s State) CanReturn(now time.Time) bool {
	if !s.Demoted || s.Preferred == "" {
		return false
	}
	if ok, seen := s.Known[s.Preferred]; !seen || !ok {
		return false
	}
	if s.PreferredOKAt.IsZero() || s.PreferredSeenAt.IsZero() {
		return false
	}
	if now.Before(s.PreferredSeenAt) || now.Sub(s.PreferredSeenAt) > ResultFreshFor {
		return false
	}
	if s.PreferredSeenAt.Before(s.PreferredOKAt) {
		return false
	}
	return !now.Before(s.PreferredOKAt.Add(ReturnCooldown))
}

func pickBackup(s State, members []string, now time.Time, pol Policy) string {
	if pol.RequireEvidence {
		for _, id := range members {
			if ok, seen := s.known(id, now, pol); id != s.Preferred && seen && ok {
				return id
			}
		}
		return ""
	}
	var candidate string
	anyUnknown := false
	for _, id := range members {
		if id == s.Preferred {
			continue
		}
		ok, seen := s.known(id, now, pol)
		if seen && !ok {
			continue
		}
		if !seen {
			anyUnknown = true
		}
		if candidate == "" {
			candidate = id
		}
		if seen && ok {
			return id
		}
	}
	if candidate != "" && anyUnknown {
		return candidate
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

// Reconcile aligns a service's state with its current group: members in
// effective order and the preferred member (svc.Preferred). It is a no-op
// while both still match. When the preferred member changed, the state
// restarts on the new one, keeping what is known about each member, with
// one exception that protects the return rule: if the new preferred's
// latest result is a failure and another member is known good, the service
// stays demoted on that member, and returning needs the full CanReturn
// condition (a fresh success streak of ReturnCooldown). A just-failed exit
// is never made active by a reorder. An active member that left the group
// is dropped the same way.
func Reconcile(s State, svc Service) State {
	return ReconcileWith(s, svc, time.Time{}, Policy{})
}

// ReconcileWith is Reconcile under a policy at now: an expired result is
// neither the "just failed" preferred that keeps the service demoted nor
// the known-good member it stays on.
func ReconcileWith(s State, svc Service, now time.Time, pol Policy) State {
	if s.Preferred == svc.Preferred && (s.Active == "" || contains(svc.Members, s.Active)) {
		s.Pool = svc.Pool
		return s
	}
	known := map[string]bool{}
	knownAt := map[string]time.Time{}
	for id, ok := range s.Known {
		if contains(svc.Members, id) {
			known[id] = ok
			if at, has := s.KnownAt[id]; has {
				knownAt[id] = at
			}
		}
	}
	next := State{Pool: svc.Pool, Preferred: svc.Preferred, Active: svc.Preferred, Known: known, KnownAt: knownAt}
	if svc.Preferred == "" {
		next.Active = ""
		return next
	}
	if ok, seen := next.known(svc.Preferred, now, pol); seen && !ok {
		for _, id := range svc.Members {
			if good, seen := next.known(id, now, pol); id != svc.Preferred && seen && good {
				next.Active = id
				next.Demoted = true
				break
			}
		}
		if !next.Demoted {
			next.Unavailable = true
		}
	}
	next.SwitchedAt, next.SwitchReason = s.SwitchedAt, s.SwitchReason
	if next.Active != s.Active && s.Active != "" && !now.IsZero() {
		next.SwitchedAt, next.SwitchReason = now, SwitchGroupChanged
	}
	return next
}

// Service is one place an unlock decision is made: a rule aimed at a
// region group (a built-in auto-* rule, keyed by its rule ID) or a service
// group set to automatic selection (keyed by ServiceKey). Pool holds the
// region group ID; Members its effective order (the candidates);
// Preferred the member the group selects (where the service stays when no
// candidate is known to unlock it). Rules of a manual group, and service
// groups in fixed mode, are listed with Pin set so the panel can show them,
// but Decisions skips them.
type Service struct {
	RuleID    string   `json:"rule_id"`
	Name      string   `json:"name"`
	Pool      string   `json:"pool"`
	Preferred string   `json:"preferred"`
	Members   []string `json:"members"`
	Pin       bool     `json:"pin"`
	// Probes are the catalog adapters whose verdicts drive this service
	// (the rule's own adapter, or the service group's list).
	Probes []string `json:"probes,omitempty"`
	// ServiceGroup is the service group's ID for a service-group entry.
	ServiceGroup string `json:"service_group,omitempty"`
}

// ServiceKeyPrefix starts the state and decision key of a service group.
// A key of a rule never starts with it (callers skip such a rule ID).
const ServiceKeyPrefix = "service-group:"

// ServiceKey is the state and decision key of service group id.
func ServiceKey(id string) string { return ServiceKeyPrefix + id }

// IsServiceKey reports whether key belongs to a service group.
func IsServiceKey(key string) bool { return strings.HasPrefix(key, ServiceKeyPrefix) }

// HistoryEntry is one stored probe line.
type HistoryEntry struct {
	At         time.Time `json:"at"`
	ObservedAt time.Time `json:"observed_at,omitempty"`
	Kind       Kind      `json:"kind"`
	Service    string    `json:"service"`
	ExitID     string    `json:"exit_id"`
	Family     Family    `json:"family,omitempty"`
	OK         bool      `json:"ok"`
	// Rejected is set when Ingest refused the result (stale, out of order,
	// duplicate, future). A rejected result never changes State.
	Rejected string `json:"rejected,omitempty"`
	Note     string `json:"note,omitempty"`
}

// Snapshot is the document stored under the unlock kv key.
type Snapshot struct {
	Services map[string]State `json:"services"`
	History  []HistoryEntry   `json:"history"`
	NextRun  time.Time        `json:"next_run"`
	// PendingApply is set when an automatic rule's exit changed and the
	// rendered routes have not been installed yet.
	PendingApply bool `json:"pending_apply"`
	// Latest is the newest admitted result per ResultKey.String().
	Latest map[string]ResultRecord `json:"latest,omitempty"`
	// Applied is the newest probe run that stepped the state machine, per
	// "service|exit", across families.
	Applied map[string]ResultRecord `json:"applied,omitempty"`
	// Clock is the last receive time handed out by Stamp. It only moves
	// forward, so two reports never share a receive time.
	Clock time.Time `json:"clock,omitempty"`
}

// Interval returns the configured period, or 6 hours when unset.
func Interval(sec int) time.Duration {
	if sec <= 0 {
		return DefaultInterval
	}
	return time.Duration(sec) * time.Second
}

// Decisions is the rule-id → exit-id map the compiler applies to automatic
// rules. Pinned rules are absent. An active exit outside the pool is absent.
func Decisions(snap Snapshot, services []Service) map[string]string {
	out := map[string]string{}
	if snap.Services == nil {
		return out
	}
	for _, svc := range services {
		if svc.Pin {
			continue
		}
		st, ok := snap.Services[svc.RuleID]
		if !ok || st.Active == "" || st.Active == svc.Preferred {
			continue
		}
		// A state computed for another preferred member (the group was
		// reordered, re-chosen or re-constrained and not yet reconciled)
		// moves nothing.
		if st.Preferred != svc.Preferred {
			continue
		}
		if !contains(svc.Members, st.Active) {
			continue
		}
		out[svc.RuleID] = st.Active
	}
	return out
}

// Apply merges one already-admitted event into the snapshot. A non-empty
// note records the probe without moving the service (pinned rule, or the
// exit is not in the service's pool). Network reports go through Ingest,
// which calls Apply only for admitted results.
func Apply(snap *Snapshot, ev Event, members []string, note string) {
	ApplyWith(snap, ev, members, note, Policy{})
}

// ApplyWith is Apply under a policy.
func ApplyWith(snap *Snapshot, ev Event, members []string, note string, pol Policy) {
	if snap.Services == nil {
		snap.Services = map[string]State{}
	}
	prev := snap.Services[ev.Service]
	next := prev
	if note == "" {
		next = AdvanceWith(prev, ev, members, pol)
	}
	if prev.Active != "" && prev.Active != next.Active && next.Active != "" {
		next.SwitchedAt, next.SwitchReason = ev.At, switchReason(prev, next)
	} else if next.Unavailable && !prev.Unavailable {
		next.SwitchedAt, next.SwitchReason = ev.At, SwitchAllFailed
	}
	snap.Services[ev.Service] = next
	if prev.Active != next.Active && next.Active != "" {
		snap.PendingApply = true
	}
	snap.addHistory(HistoryEntry{
		At: ev.At, ObservedAt: ev.ObservedAt, Kind: ev.Kind, Service: ev.Service,
		ExitID: ev.ExitID, Family: ev.Family, OK: ev.OK, Note: note,
	})
}

func (snap *Snapshot) addHistory(h HistoryEntry) {
	snap.History = append(snap.History, h)
	if len(snap.History) > maxHistory {
		snap.History = snap.History[len(snap.History)-maxHistory:]
	}
}

// ParseRegionCheck reads lmc999/RegionRestrictionCheck text. A service that
// is not mentioned is left unset, so a format change cannot look like a
// failure and move a route. The container is not linked into this binary.
func ParseRegionCheck(raw string) map[string]bool {
	return ParseRegionCheckFor(raw, "")
}

// ParseRegionCheckFor is ParseRegionCheck plus the exit's region. A Yes that
// names a different catalog (Region: US on a Hong Kong exit) is a failure
// for that exit, not a success. A Yes with no region is unchanged.
func ParseRegionCheckFor(raw, exitRegion string) map[string]bool {
	out := map[string]bool{}
	sc := bufio.NewScanner(strings.NewReader(raw))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		rule, ok := ruleAlias(line)
		if !ok {
			continue
		}
		v, known := yesNo(line)
		if !known {
			continue
		}
		if v && !RegionsMatch(exitRegion, lineRegion(line)) {
			v = false
		}
		// A later "No" on the same service (for example IPv6) does not
		// erase an earlier acceptable Yes. Either family unlocking in the
		// exit's own region is enough to keep the member.
		if prev, seen := out[rule]; seen {
			out[rule] = prev || v
		} else {
			out[rule] = v
		}
	}
	return out
}

var (
	yesNoFail = regexp.MustCompile(`\b(no|failed|not available)\b`)
	yesNoPass = regexp.MustCompile(`\byes\b`)
	regionRe  = regexp.MustCompile(`(?i)region:\s*([a-z]{2,12})`)
)

func yesNo(line string) (bool, bool) {
	l := strings.ToLower(line)
	if yesNoFail.MatchString(l) && !yesNoPass.MatchString(l) {
		return false, true
	}
	if yesNoPass.MatchString(l) {
		return true, true
	}
	return false, false
}

// lineRegion is the catalog region a streaming probe reported, or empty
// when the line does not name one. "Yes" with no region is not a country.
func lineRegion(line string) string {
	m := regionRe.FindStringSubmatch(line)
	if m == nil {
		return ""
	}
	return strings.ToLower(m[1])
}

// RegionsMatch reports whether a probe result may count for an exit in
// exitRegion. A result that names a different catalog region does not:
// Netflix unlocked as US must not keep a Hong Kong residential rule.
// An empty reported region (plain Yes/No) is left to yesNo.
func RegionsMatch(exitRegion, reported string) bool {
	if strings.TrimSpace(exitRegion) == "" || reported == "" {
		return true
	}
	return normRegion(exitRegion) == normRegion(reported)
}

// NormRegion folds region spellings (HK, hongkong, Hong Kong) to one code.
func NormRegion(s string) string { return normRegion(s) }

func normRegion(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	s = strings.ReplaceAll(s, " ", "")
	s = strings.ReplaceAll(s, "-", "")
	switch s {
	case "hongkong", "hk":
		return "hk"
	case "taiwan", "tw":
		return "tw"
	case "japan", "jp":
		return "jp"
	case "singapore", "sg":
		return "sg"
	case "unitedstates", "usa", "us":
		return "us"
	default:
		return s
	}
}

func ruleAlias(line string) (string, bool) {
	l := strings.ToLower(line)
	switch {
	case strings.Contains(l, "netflix"):
		return "auto-netflix", true
	case strings.Contains(l, "disney"):
		return "auto-disney", true
	case strings.Contains(l, "bahamut") || strings.Contains(l, "巴哈"):
		return "auto-bahamut", true
	case strings.Contains(l, "kktv"):
		return "auto-kktv", true
	case strings.Contains(l, "line tv") || strings.Contains(l, "linetv"):
		return "auto-linetv", true
	case strings.Contains(l, "hami"):
		return "auto-hami", true
	case strings.Contains(l, "abema"):
		return "auto-abema", true
	default:
		return "", false
	}
}

// AIReachable treats a completed HTTP response as reachability from that
// exit. Code 0 is a timeout or reset. This is not an account check, and the
// panel records these lines with a note only: reachability never steps the
// state machine (see api.reachOnlyNote, docs/unlock-methods.md).
func AIReachable(httpCode int) bool { return httpCode > 0 }

// AIRuleID maps a curl target name onto a default-table rule.
func AIRuleID(name string) (string, bool) {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "openai", "chatgpt", "auto-openai":
		return "auto-openai", true
	case "anthropic", "claude", "auto-anthropic":
		return "auto-anthropic", true
	case "gemini", "auto-gemini":
		return "auto-gemini", true
	case "copilot", "auto-copilot":
		return "auto-copilot", true
	case "perplexity", "auto-perplexity":
		return "auto-perplexity", true
	case "grok", "auto-grok":
		return "auto-grok", true
	default:
		return "", false
	}
}

// ParseAICodes reads "rule-or-alias <http-code>" lines.
func ParseAICodes(raw string) map[string]bool {
	out := map[string]bool{}
	sc := bufio.NewScanner(strings.NewReader(raw))
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) != 2 {
			continue
		}
		id, ok := AIRuleID(f[0])
		if !ok {
			continue
		}
		code, err := strconv.Atoi(f[1])
		if err != nil {
			continue
		}
		out[id] = AIReachable(code)
	}
	return out
}
