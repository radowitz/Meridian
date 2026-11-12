// Package unlock is the 6-hour streaming/AI map and its hysteresis.
//
// Automatic rules may move to another member of the same pool. They never
// move to a different country: AI stays on US, Netflix/Disney+ stay on Hong
// Kong residential, Taiwan-only services stay on TW. A pinned manual rule is
// not in this map. Two consecutive scheduled failures are required before a
// move; a manual click or a single health-change probe does not count.
// Returning to the preferred member waits until that member succeeds again
// and 30 minutes have passed since both the backup and the preferred succeeded,
// so a still-failing preferred is not put back just because the backup works.
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
	maxHistory      = 200
)

type Kind string

const (
	KindScheduled Kind = "scheduled"
	KindManual    Kind = "manual"
	KindHealth    Kind = "health"
)

// State is one automatic rule's unlock decision.
type State struct {
	Pool          string          `json:"pool"`
	Preferred     string          `json:"preferred"`
	Active        string          `json:"active"`
	SchedFails    int             `json:"sched_fails"`
	Demoted       bool            `json:"demoted"`
	Unavailable   bool            `json:"unavailable"`
	Known         map[string]bool `json:"known,omitempty"`
	BackupOKAt    time.Time       `json:"backup_ok_at,omitempty"`
	PreferredOKAt time.Time       `json:"preferred_ok_at,omitempty"`
}

// Event is one probe of one exit for one service.
type Event struct {
	Service string
	ExitID  string
	OK      bool
	Kind    Kind
	At      time.Time
}

// Advance applies one probe. members is the pool in preference order.
// An exit outside members is ignored: that is how a US probe cannot move
// a Netflix rule, and how a Japan exit cannot become the Taiwan path.
func Advance(s State, ev Event, members []string) State {
	if s.Known == nil {
		s.Known = map[string]bool{}
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
	if ev.OK && s.Demoted && ev.ExitID == s.Active && ev.ExitID != s.Preferred && s.BackupOKAt.IsZero() {
		s.BackupOKAt = ev.At
	}
	if !s.Demoted && s.SchedFails >= SchedFailsNeed {
		if alt := pickBackup(s, members); alt != "" {
			s.Active = alt
			s.Demoted = true
			s.Unavailable = false
			s.BackupOKAt = time.Time{}
			s.PreferredOKAt = time.Time{}
			// A member already proven is the one success that starts the
			// return cooldown. An unproven member waits for its own probe.
			if good, seen := s.Known[alt]; seen && good {
				s.BackupOKAt = ev.At
			}
		} else if ev.Kind == KindScheduled && ev.ExitID == s.Preferred && !ev.OK {
			s.Unavailable = true
			s.Active = s.Preferred
		}
	}
	if s.Demoted && s.canReturn(ev.At) {
		s.Active = s.Preferred
		s.Demoted = false
		s.Unavailable = false
		s.SchedFails = 0
		s.BackupOKAt = time.Time{}
		s.PreferredOKAt = time.Time{}
	}
	return s
}

func (s State) canReturn(now time.Time) bool {
	if !s.Demoted || s.BackupOKAt.IsZero() || s.PreferredOKAt.IsZero() {
		return false
	}
	start := s.BackupOKAt
	if s.PreferredOKAt.After(start) {
		start = s.PreferredOKAt
	}
	return !now.Before(start.Add(ReturnCooldown))
}

func pickBackup(s State, members []string) string {
	var candidate string
	anyUnknown := false
	for _, id := range members {
		if id == s.Preferred {
			continue
		}
		ok, seen := s.Known[id]
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
	if candidate != "" && (anyUnknown || s.Known[candidate]) {
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

// Service is an automatic rule that follows the unlock map.
// Pinned rules are listed so the panel can show them, but Decisions skips them.
type Service struct {
	RuleID    string   `json:"rule_id"`
	Name      string   `json:"name"`
	Pool      string   `json:"pool"`
	Preferred string   `json:"preferred"`
	Members   []string `json:"members"`
	Pin       bool     `json:"pin"`
}

// HistoryEntry is one stored probe line.
type HistoryEntry struct {
	At      time.Time `json:"at"`
	Kind    Kind      `json:"kind"`
	Service string    `json:"service"`
	ExitID  string    `json:"exit_id"`
	OK      bool      `json:"ok"`
	Note    string    `json:"note,omitempty"`
}

// Snapshot is the document stored under the unlock kv key.
type Snapshot struct {
	Services map[string]State `json:"services"`
	History  []HistoryEntry   `json:"history"`
	NextRun  time.Time        `json:"next_run"`
	// PendingApply is set when an automatic rule's exit changed and the
	// rendered routes have not been installed yet.
	PendingApply bool `json:"pending_apply"`
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
		if !contains(svc.Members, st.Active) {
			continue
		}
		out[svc.RuleID] = st.Active
	}
	return out
}

// Apply merges one event into the snapshot. wrongPool notes a probe that
// must not move this service (the exit is not in the service's pool).
func Apply(snap *Snapshot, ev Event, members []string, note string) {
	if snap.Services == nil {
		snap.Services = map[string]State{}
	}
	prev := snap.Services[ev.Service]
	next := prev
	if note == "" {
		next = Advance(prev, ev, members)
	}
	snap.Services[ev.Service] = next
	if prev.Active != next.Active && next.Active != "" {
		snap.PendingApply = true
	}
	snap.History = append(snap.History, HistoryEntry{
		At: ev.At, Kind: ev.Kind, Service: ev.Service, ExitID: ev.ExitID, OK: ev.OK, Note: note,
	})
	if len(snap.History) > maxHistory {
		snap.History = snap.History[len(snap.History)-maxHistory:]
	}
}

// ParseRegionCheck reads lmc999/RegionRestrictionCheck text. A service that
// is not mentioned is left unset, so a format change cannot look like a
// failure and move a route. The container is not linked into this binary.
func ParseRegionCheck(raw string) map[string]bool {
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
		if v, known := yesNo(line); known {
			// A later "No" on the same service (for example IPv6) does not
			// erase an earlier Yes. Either family unlocking is enough to
			// keep the member; both failing marks it down.
			if prev, seen := out[rule]; seen {
				out[rule] = prev || v
			} else {
				out[rule] = v
			}
		}
	}
	return out
}

func yesNo(line string) (bool, bool) {
	l := strings.ToLower(line)
	if regexp.MustCompile(`\b(no|failed|not available)\b`).MatchString(l) && !regexp.MustCompile(`\byes\b`).MatchString(l) {
		return false, true
	}
	if regexp.MustCompile(`\byes\b`).MatchString(l) {
		return true, true
	}
	return false, false
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
// exit. Code 0 is a timeout or reset. This is not an account check.
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
