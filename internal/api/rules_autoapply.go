package api

// Automatic install of saved rule changes (settings.rules_auto_apply,
// default on).
//
// A save of the rules (PUT /api/topology changing only rules), a service
// group (POST/PATCH/DELETE /api/service-groups), a rule-set
// (POST/PATCH/DELETE /api/rule-sets) or a confirmed mihomo import is
// installed by the panel itself when, at that moment:
//
//   - the setting is on and the host agent offers the install preflight;
//   - the gateway was in sync before the change: the compile of the stored
//     topology with the rule parts as they were before the save (rules,
//     service groups, rule-sets, the import mapping, the default group) is
//     exactly what is installed — so there is no other pending change, and
//     nothing but the rule parts changed since — at the installed version
//     recorded then (checked again under the lock, right before the
//     install);
//   - the compiled change touches only the rule allowlist of
//     compile.RuleChange (the gateway's rule manifest, rule decision
//     snapshot and sniff targets, and only the rule sections of
//     smartdns.conf and meridian.nft); every other gateway file, every
//     other node's file, a file added or removed is refused;
//   - no acceptance drill, no deployment guide run, the gateway node lock
//     is free, no host transaction is unfinished, the rate limit allows it
//     (fastGate, shared with the remote-access fast path);
//   - the host preflight of exactly this bundle has neither blocking
//     findings nor warnings that need confirmation.
//
// The install is the operator's gateway transaction (applyGateway with an
// autoInstall: compiled bundle pinned by its canonical text, version +1,
// rollback-able, failures compensated by the transaction). Saves in quick
// succession are coalesced: while an install runs or within
// rulesAutoGap of the last one, a save joins one pending run that
// re-evaluates the final state when it fires (status "scheduled"); the
// outcome is kept (GET /api/rules/auto-apply). Otherwise the answer is
// apply_required with a one-line reason. Reasons and records carry no
// secret: file paths, versions and preflight IDs only.
//
// An unlock-page save (采用 / 手动, POST /api/unlock/adopt) takes the same
// path with an explicit edit scope (unlockEdit): the service's rules' target
// and one region group's member order, mode, chosen member and failover.
// The group's values before the save are recorded with the base
// (ruleParts.Groups) and restored when the installed state is rebuilt, so
// the in-sync checks still prove that nothing else is pending; the group's
// member set must be unchanged; when every coalesced save was an unlock
// save, rule differences other than those rules' targets refuse; and the
// file allowlist admits that group's gateway lines only
// (compile.RuleChange with the group). Groups are switched on their hubs,
// so a change of a hub's scripts refuses like any other node's file.
//
// Rule-set content (download or update) does not enter the compiled bundle:
// it is applied on the gateway by the host's list re-derive
// (applyRuleSetsOnHost) and needs no install
// (TestRuleSetContentIsBundleNeutral).

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/radowitz/meridian/internal/compile"
	"github.com/radowitz/meridian/internal/model"
	"github.com/radowitz/meridian/internal/provision"
)

const (
	rulesFastKey = "rules_fast_apply"
	rulesLastKey = "rules_auto_last"
	// rulesAutoHourMax / rulesAutoDayMax: automatic rule installs per hour
	// / per 24 hours.
	rulesAutoHourMax = 30
	rulesAutoDayMax  = 200
	// rulesAutoGap is the coalescing window: the minimum time between two
	// automatic rule installs. Saves inside it join one later run.
	rulesAutoGap = 20 * time.Second
)

// FastScheduled: coalesced into a pending automatic install.
const FastScheduled = "scheduled"

// ruleParts are the topology blocks a rule change may touch.
type ruleParts struct {
	Rules        []model.Rule        `json:"rules"`
	RuleSets     []model.RuleSet     `json:"rule_sets"`
	MihomoImport *model.MihomoImport `json:"mihomo_import"`
	DefaultGroup string              `json:"default_group"`
	// Groups are region groups' selection fields as installed, recorded
	// for an unlock-page save (never filled by rulePartsOf).
	Groups []unlockGroup `json:"unlock_groups,omitempty"`
}

// unlockGroup is the part of a region group an unlock-page save may change.
type unlockGroup struct {
	ID        string          `json:"id"`
	Members   []string        `json:"members"`
	Mode      model.GroupMode `json:"mode"`
	Chosen    string          `json:"chosen,omitempty"`
	OnFailure model.OnFailure `json:"on_failure,omitempty"`
}

func unlockGroupOf(g model.RegionGroup) unlockGroup {
	return unlockGroup{ID: g.ID, Members: append([]string(nil), g.Members...), Mode: g.Mode, Chosen: g.Chosen, OnFailure: g.OnFailure}
}

// unlockEdit is the scope of one unlock-page save: the group as it was
// before (确认 only; zero for 手动), and the service's rules.
type unlockEdit struct {
	Group unlockGroup
	Rules []string
}

func sameMemberSet(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	seen := map[string]int{}
	for _, x := range a {
		seen[x]++
	}
	for _, x := range b {
		seen[x]--
		if seen[x] < 0 {
			return false
		}
	}
	return true
}

// onlyTargetsDiffer: a and b are the same rules in the same order, apart
// from the targets of the rules in ids.
func onlyTargetsDiffer(a, b []model.Rule, ids map[string]bool) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		x, y := a[i], b[i]
		if x.ID != y.ID {
			return false
		}
		if ids[x.ID] {
			x.TargetGroup, x.TargetExit = y.TargetGroup, y.TargetExit
		}
		if canonJSON(x) != canonJSON(y) {
			return false
		}
	}
	return true
}

// rulePartsOf is a deep copy of t's rule parts.
func rulePartsOf(t model.Topology) ruleParts {
	p := ruleParts{Rules: t.Rules, RuleSets: t.RuleSets, MihomoImport: t.MihomoImport, DefaultGroup: t.Settings.DefaultGroup}
	var out ruleParts
	if buf, err := json.Marshal(p); err == nil {
		_ = json.Unmarshal(buf, &out)
	}
	return out
}

func (p ruleParts) into(t *model.Topology) {
	q := rulePartsOf(model.Topology{Rules: p.Rules, RuleSets: p.RuleSets, MihomoImport: p.MihomoImport, Settings: model.Settings{DefaultGroup: p.DefaultGroup}})
	t.Rules, t.RuleSets, t.MihomoImport, t.Settings.DefaultGroup = q.Rules, q.RuleSets, q.MihomoImport, q.DefaultGroup
	if len(p.Groups) == 0 {
		return
	}
	t.Groups = append([]model.RegionGroup(nil), t.Groups...)
	for _, ug := range p.Groups {
		for i := range t.Groups {
			if g := &t.Groups[i]; g.ID == ug.ID {
				g.Members, g.Mode, g.Chosen, g.OnFailure = append([]string(nil), ug.Members...), ug.Mode, ug.Chosen, ug.OnFailure
			}
		}
	}
}

// nonRuleCanon is t without its rule parts and the switch itself.
func nonRuleCanon(t model.Topology) string {
	t.Rules, t.RuleSets, t.MihomoImport = nil, nil, nil
	t.Settings.DefaultGroup, t.Settings.RulesAutoApply = "", nil
	return canonJSON(t)
}

// ruleBase is the rule state known to be installed, at that version.
type ruleBase struct {
	parts   ruleParts
	version int64
	// unlockOnly: every save since the base was an unlock-page save;
	// unlockRules are their service rules.
	unlockOnly  bool
	unlockRules map[string]bool
}

// rulesAutoState coalesces saves (in memory: a restart drops a pending run,
// the change then waits for a manual install like any other). The stored
// "scheduled" record of a run this process no longer holds (written by
// another panel process, or left without a timer) is turned into an
// interrupted apply-required record and persisted (loadRulesLastLocked); it
// is never resumed, so nothing installs without the full re-evaluation of a
// new save.
type rulesAutoState struct {
	mu      sync.Mutex
	base    *ruleBase
	active  int
	timer   *time.Timer
	lastRun time.Time
	// gap overrides rulesAutoGap (tests).
	gap time.Duration
}

// rulesAutoRecord is the latest outcome (GET /api/rules/auto-apply).
type rulesAutoRecord struct {
	At      time.Time `json:"at"`
	Trigger string    `json:"trigger"`
	fastApply
	Files []string `json:"files,omitempty"`
	// Boot is the panel process that wrote the record; Interrupted marks a
	// scheduled run that process lost (restart).
	Boot        string `json:"boot,omitempty"`
	Interrupted bool   `json:"interrupted,omitempty"`
}

// rulesInterrupted is the reason of a scheduled run lost to a restart.
const rulesInterrupted = "面板重启，合并的自动生效没有执行，需要到部署页安装"

func (s *Server) rulesGap() time.Duration {
	if s.rulesAuto.gap > 0 {
		return s.rulesAuto.gap
	}
	return rulesAutoGap
}

func (s *Server) recordRulesLast(trigger string, f fastApply, files []string) {
	rec := rulesAutoRecord{At: s.now(), Trigger: trigger, fastApply: f, Files: files, Boot: s.bootID()}
	s.mu.Lock()
	defer s.mu.Unlock()
	if buf, err := json.Marshal(rec); err == nil {
		_ = s.Store.Put(rulesLastKey, string(buf))
	}
}

// recordRulesOutcome records a run's outcome unless a newer save is already
// scheduled (its "scheduled" record stays: that run re-evaluates everything).
func (s *Server) recordRulesOutcome(trigger string, f fastApply, files []string) {
	ra := &s.rulesAuto
	ra.mu.Lock()
	defer ra.mu.Unlock()
	if ra.timer != nil {
		return
	}
	s.recordRulesLast(trigger, f, files)
}

// loadRulesLast is the latest record; a "scheduled" one that no run of
// this process holds is persisted as interrupted (apply required).
func (s *Server) loadRulesLast() *rulesAutoRecord {
	ra := &s.rulesAuto
	ra.mu.Lock()
	defer ra.mu.Unlock()
	return s.loadRulesLastLocked(ra.timer != nil || ra.active > 0)
}

// loadRulesLastLocked: caller holds rulesAuto.mu; pending is whether a run
// of this process is scheduled or running.
func (s *Server) loadRulesLastLocked(pending bool) *rulesAutoRecord {
	s.mu.Lock()
	defer s.mu.Unlock()
	raw, ok, err := s.Store.Get(rulesLastKey)
	if err != nil || !ok {
		return nil
	}
	var rec rulesAutoRecord
	if json.Unmarshal([]byte(raw), &rec) != nil {
		return nil
	}
	if rec.Status == FastScheduled && (rec.Boot != s.bootID() || !pending) {
		rec.fastApply = fastApply{Status: FastSkipped, Reason: rulesInterrupted}
		rec.Interrupted = true
		if buf, err := json.Marshal(rec); err == nil {
			_ = s.Store.Put(rulesLastKey, string(buf))
		}
	}
	return &rec
}

func rulesSkip(reason string) fastApply { return fastApply{Status: FastSkipped, Reason: reason} }

// rulesInSync reports whether the stored topology with the rule parts of
// before compiles to exactly what the gateway has installed, and that
// version. reason is "" when it does.
func (s *Server) rulesInSync(before ruleParts) (int64, string) {
	ap := s.applier(true)
	inst, err := ap.Installed()
	if err != nil || inst.Empty() || inst.Withdrawn() {
		return 0, "网关尚未安装"
	}
	t, err := s.topology()
	if err != nil {
		return 0, "读取拓扑失败"
	}
	before.into(&t)
	prev, err := s.compileWith(t, s.unlockDecisions(t))
	if err != nil {
		return 0, remoteFastPending
	}
	if d, err := ap.InstalledDiff(prev); err != nil || d == nil || !d.Empty() {
		return 0, remoteFastPending
	}
	return inst.Version, ""
}

// rulesAutoAfterSave is called after a rule save succeeded (not holding
// raMu), with the rule parts as they were before the save.
// edit is the scope of an unlock-page save (nil for every other save).
func (s *Server) rulesAutoAfterSave(before ruleParts, trigger string, edit ...unlockEdit) fastApply {
	t, err := s.topology()
	if err != nil {
		return rulesSkip("读取拓扑失败")
	}
	if !t.Settings.RulesAutoApplyOn() {
		return rulesSkip("规则自动生效已在设置里关闭")
	}
	ids := map[string]bool{}
	for _, e := range edit {
		// 手动 (group or pinned exit) changes no group.
		if e.Group.ID != "" {
			before.Groups = append(before.Groups, e.Group)
		}
		for _, id := range e.Rules {
			ids[id] = true
		}
	}
	ra := &s.rulesAuto
	ra.mu.Lock()
	if ra.active == 0 && ra.timer == nil {
		ra.mu.Unlock()
		ver, reason := s.rulesInSync(before)
		if reason != "" {
			f := rulesSkip(reason)
			s.recordRulesLast(trigger, f, nil)
			return f
		}
		ra.mu.Lock()
		if ra.active == 0 && ra.timer == nil {
			ra.base = &ruleBase{parts: before, version: ver, unlockOnly: len(edit) > 0, unlockRules: ids}
		}
	} else if ra.base != nil {
		// Coalesced into a pending run: widen its scope by this save.
		b := *ra.base
		b.parts.Groups = append([]unlockGroup(nil), b.parts.Groups...)
		for _, ug := range before.Groups {
			known := false
			for _, x := range b.parts.Groups {
				known = known || x.ID == ug.ID
			}
			if !known {
				b.parts.Groups = append(b.parts.Groups, ug)
			}
		}
		b.unlockOnly = b.unlockOnly && len(edit) > 0
		b.unlockRules = map[string]bool{}
		for id := range ra.base.unlockRules {
			b.unlockRules[id] = true
		}
		for id := range ids {
			b.unlockRules[id] = true
		}
		ra.base = &b
	}
	wait := s.rulesGap() - time.Since(ra.lastRun)
	if ra.active > 0 || ra.timer != nil || wait > 0 {
		if ra.timer == nil {
			if wait <= 0 {
				wait = s.rulesGap()
			}
			ra.timer = time.AfterFunc(wait, s.rulesAutoFire)
		}
		// Recorded under ra.mu: the run cannot record its outcome first and
		// then be overwritten by this "scheduled".
		f := fastApply{Status: FastScheduled, Reason: "连续保存已合并，稍后自动生效"}
		s.recordRulesLast(trigger, f, nil)
		ra.mu.Unlock()
		return f
	}
	ra.active++
	ra.lastRun = time.Now()
	ra.mu.Unlock()
	f := s.rulesAutoRun(trigger)
	ra.mu.Lock()
	ra.active--
	ra.mu.Unlock()
	return f
}

// rulesAutoFire runs the coalesced saves.
func (s *Server) rulesAutoFire() {
	ra := &s.rulesAuto
	ra.mu.Lock()
	ra.timer = nil
	ra.active++
	ra.lastRun = time.Now()
	ra.mu.Unlock()
	// A coalesced run may start while the previous install is still
	// closing its transaction (or holds the node lock): that is transient,
	// so wait and re-check a few times before giving up. Every attempt is
	// the full evaluation (rulesAutoEval: installed version against the
	// recorded base, sync apart from the rule parts, allowlist, other
	// pending changes, drill / deployment guide / lock exclusion, preflight,
	// switch and rate limit), so a change during the wait fails closed and
	// a stale snapshot never installs. Exhausted retries are recorded as
	// skipped (apply required), never as applied.
	var files []string
	var f fastApply
	for attempt := 0; ; attempt++ {
		files = nil
		f = s.rulesAutoEval(&files)
		if attempt >= rulesAutoBusyRetries || f.Status != FastSkipped || !rulesAutoTransient(f.Reason) {
			break
		}
		rulesAutoSleep(rulesAutoBusyWait)
	}
	ra.mu.Lock()
	if ra.timer == nil {
		s.recordRulesLast("coalesced", f, files)
	}
	ra.active--
	ra.mu.Unlock()
}

// Retries of a coalesced run that found the gateway briefly busy: at most
// rulesAutoBusyRetries more evaluations, rulesAutoBusyWait apart (about
// 10 s in all). Variables only so tests can shorten the wait or act
// between attempts (rulesAutoSleep).
var (
	rulesAutoBusyRetries = 5
	rulesAutoBusyWait    = 2 * time.Second
	rulesAutoSleep       = time.Sleep
)

func rulesAutoTransient(reason string) bool {
	return reason == "有未完成的宿主事务" || reason == "网关正忙"
}

// rulesAutoRun evaluates the stored topology against the recorded base
// and, when eligible, installs it. The outcome is recorded.
func (s *Server) rulesAutoRun(trigger string) fastApply {
	var files []string
	f := s.rulesAutoEval(&files)
	s.recordRulesOutcome(trigger, f, files)
	return f
}

func (s *Server) rulesAutoEval(files *[]string) fastApply {
	s.autoMu.Lock()
	defer s.autoMu.Unlock()
	ra := &s.rulesAuto
	ra.mu.Lock()
	base := ra.base
	ra.mu.Unlock()
	if base == nil {
		return rulesSkip(remoteFastPending)
	}
	t, err := s.topology()
	if err != nil {
		return rulesSkip("读取拓扑失败")
	}
	if !t.Settings.RulesAutoApplyOn() {
		return rulesSkip("规则自动生效已在设置里关闭")
	}
	if !s.gatewayGateActive() || s.hostPreflighter() == nil {
		return rulesSkip("宿主代理不支持安装前预检，不能自动生效")
	}
	g, reason := s.fastGate(rulesFastKey, rulesAutoHourMax, rulesAutoDayMax)
	if reason != "" {
		return rulesSkip(reason)
	}
	defer g.release()
	dec := s.unlockDecisions(t)
	next, err := s.compileWith(t, dec)
	if err != nil {
		return rulesSkip("拓扑无法编译")
	}
	if len(next.PeerKeyProblems(localNodeID)) > 0 {
		return rulesSkip("有对端缺少公钥")
	}
	d, err := g.ap.InstalledDiff(next)
	if err != nil || d == nil {
		return rulesSkip("网关安装记录不可读")
	}
	if d.Empty() {
		s.setRuleBase(t, g.inst.Version)
		return fastApply{Status: FastNone}
	}
	// Re-check under the lock: still the version recorded before the
	// change, and in sync with it apart from the rule parts.
	if g.inst.Version != base.version {
		return rulesSkip("保存之后网关又安装过别的版本，需要到部署页安装")
	}
	// An unlock-page save: exactly its fields. The group keeps its member
	// set, and with only unlock saves no rule differs but their targets.
	var groups []string
	for _, ug := range base.parts.Groups {
		cur, ok := t.GroupByID(ug.ID)
		if !ok || !sameMemberSet(cur.Members, ug.Members) {
			return rulesSkip("地区组「" + ug.ID + "」的成员在保存后变了，需要到部署页安装")
		}
		groups = append(groups, ug.ID)
	}
	if base.unlockOnly && !onlyTargetsDiffer(base.parts.Rules, t.Rules, base.unlockRules) {
		return rulesSkip("除解锁服务规则的目标外还有其他规则改动，需要到部署页安装")
	}
	prevT := t
	base.parts.into(&prevT)
	prev, err := s.compileWith(prevT, dec)
	if err != nil {
		return rulesSkip(remoteFastPending)
	}
	if pd, err := g.ap.InstalledDiff(prev); err != nil || pd == nil || !pd.Empty() {
		return rulesSkip(remoteFastPending)
	}
	changed, refused := compile.RuleChange(prev, next, localNodeID, groups...)
	*files = append(changed, refused...)
	if len(refused) > 0 {
		if len(groups) > 0 {
			var nodes []string
			gw := false
			for _, p := range refused {
				parts := strings.SplitN(p, "/", 3)
				if len(parts) < 3 || parts[1] == localNodeID {
					gw = true
					break
				}
				if !containsStr(nodes, parts[1]) {
					nodes = append(nodes, parts[1])
				}
			}
			if !gw {
				return rulesSkip(clipText("地区组的首选出口由 "+strings.Join(nodes, "、")+" 切换，需要到部署页安装", 200))
			}
		}
		return rulesSkip(clipText("改动超出规则文件："+strings.Join(refused, "、"), 200))
	}
	if len(changed) == 0 {
		return rulesSkip("还有其他待安装的改动")
	}
	ctx, cancel := context.WithTimeout(context.Background(), autoTimeout)
	defer cancel()
	pf, err := s.runHostPreflight(ctx, provision.FilesFor(next.Files, localNodeID))
	if err != nil {
		return rulesSkip("安装前预检没有完成")
	}
	if pf.Blocking {
		return rulesSkip("安装前预检有阻断项（预检 " + pf.ID + "）")
	}
	if pf.Counts.Warning > 0 {
		return rulesSkip("安装前预检有需要确认的警告（预检 " + pf.ID + "）")
	}
	s.recordFastAttempt(rulesFastKey, g.now)
	cw := &captureWriter{header: http.Header{}}
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, "/api/apply", nil)
	s.autoInstalling.Store(true)
	s.applyGateway(cw, req, applyBody{Install: true}, &autoInstall{decisions: copyDec(dec), canonical: next.Canonical()})
	s.autoInstalling.Store(false)
	out := fastInstallOutcome(cw)
	if out.Status == FastApplied {
		s.setRuleBase(t, out.Version)
	}
	return out
}

func (s *Server) setRuleBase(t model.Topology, version int64) {
	s.rulesAuto.mu.Lock()
	s.rulesAuto.base = &ruleBase{parts: rulePartsOf(t), version: version}
	s.rulesAuto.mu.Unlock()
}

// saveRulesChecked is saveTopologyChecked that also returns the rule parts
// as they were right before fn ran (under the store lock).
func (s *Server) saveRulesChecked(fn func(t *model.Topology) error) (model.Topology, ruleParts, []any, error) {
	var before ruleParts
	t, issues, err := s.saveTopologyChecked(func(t *model.Topology) error {
		before = rulePartsOf(*t)
		return fn(t)
	})
	return t, before, issues, err
}

// withRulesAuto adds the outcome to an answer.
func withRulesAuto(out map[string]any, f fastApply) map[string]any {
	out["apply_required"] = f.applyRequired()
	out["fast_apply"] = f
	return out
}

func (s *Server) getRulesAutoApply(w http.ResponseWriter, r *http.Request) {
	t, err := s.topology()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	s.rulesAuto.mu.Lock()
	pending := s.rulesAuto.timer != nil || s.rulesAuto.active > 0
	last := s.loadRulesLastLocked(pending)
	s.rulesAuto.mu.Unlock()
	writeJSON(w, http.StatusOK, map[string]any{"enabled": t.Settings.RulesAutoApplyOn(), "pending": pending, "last": last})
}
