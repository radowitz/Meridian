package api

// Automatic install of unlock decisions (settings.unlock_probe.auto_apply).
//
// When the unlock state machine changes a decision (a built-in rule or a
// service group moves to another member, or back after recovery), the
// change reaches the gateway only through an install. With auto_apply on,
// the panel runs that install itself — through applyGateway, the same code
// path as POST /api/apply with install=true: same key handling, same host
// transaction (atomic nft load, compensation on failure), same WSS and
// secret bookkeeping — but only when every condition below holds. The
// first one that does not is recorded and shown; the decision then stays
// pending for an operator, exactly as with auto_apply off.
//
//  1. in sync: the decisions the last gateway install used are recorded,
//     no host transaction is unfinished, and compiling the stored topology
//     with those decisions gives exactly the installed gateway files (by
//     hash): the gateway node's own installed state (node_state.go). So the
//     automatic install, which writes gateway files only, carries nothing
//     but the decision. Other nodes are not compared: a remote node that
//     was provisioned on its own (or has changes of its own still pending)
//     changes neither the gateway's files nor what this install writes,
//     and condition 2 refuses any decision that would change another
//     node's files. (Before per-node state the whole applied snapshot of
//     every node was compared, which refused with out_of_sync forever once
//     a remote node had been provisioned separately.)
//  2. only rule files: compiling with the new decisions differs from (1)
//     only in gateway files of compile.DecisionFiles.
//  3. rate: at least the minimum gap since the last automatic install,
//     fewer than the daily cap in the last 24 hours, and not the same
//     decisions that failed within the back-off (autoBackoff).
//  4. nothing else running: the gateway node lock (preflight, provision,
//     withdraw) is free and no host transaction holds or has left its lock;
//     otherwise it is deferred to the next evaluation, never queued.
//  5. preflight: the host preflight, run now for this bundle under the
//     node lock, has no blocking finding.
//
// Evaluations happen after every probe job, after every exit report and on
// the scheduler's one-minute tick. A failed install is compensated by the
// transaction as usual and leaves the decision pending; the same decisions
// are not tried again before autoBackoff has passed (a different decision
// set may be tried after the minimum gap). Thresholds and hysteresis of the
// state machine are not touched here.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/radowitz/meridian/internal/compile"
	"github.com/radowitz/meridian/internal/model"
	"github.com/radowitz/meridian/internal/provision"
	"github.com/radowitz/meridian/internal/unlock"
)

const (
	autoApplyKey = "unlock_auto_apply"
	// autoBackoff: after a failed automatic install, the same decisions are
	// not tried again for this long.
	autoBackoff  = time.Hour
	maxAutoLog   = 50
	autoTimeout  = 5 * time.Minute
	autoDaySpan  = 24 * time.Hour
	autoTrigTick = "tick"
)

// Codes of an evaluation (autoCheck.Code).
const (
	AutoApplied       = "applied"
	AutoNotPending    = "not_pending"
	AutoNoRecord      = "no_installed_record"
	AutoOutOfSync     = "out_of_sync"
	AutoFilesRefused  = "files_outside_allow_list"
	AutoGap           = "min_gap"
	AutoDailyCap      = "daily_cap"
	AutoBackoff       = "backoff"
	AutoBusy          = "busy"
	AutoPreflightNA   = "preflight_unavailable"
	AutoPreflightStop = "preflight_blocked"
	AutoCompileFailed = "compile_failed"
	AutoInstallFailed = "install_failed"
)

// autoAttempt is one automatic install that ran (applied or failed).
type autoAttempt struct {
	At        time.Time         `json:"at"`
	Trigger   string            `json:"trigger"`
	Decisions map[string]string `json:"decisions"`
	Hash      string            `json:"hash"`
	OK        bool              `json:"ok"`
	// Code is the install's error code when it failed (for example
	// activation_failed_compensated); Message its text.
	Code    string   `json:"code,omitempty"`
	Message string   `json:"message,omitempty"`
	Files   []string `json:"files,omitempty"`
}

// autoCheck is the latest evaluation, whatever its outcome.
type autoCheck struct {
	At        time.Time         `json:"at"`
	Trigger   string            `json:"trigger"`
	Code      string            `json:"code"`
	Message   string            `json:"message"`
	Decisions map[string]string `json:"decisions,omitempty"`
	Files     []string          `json:"files,omitempty"`
}

type autoDoc struct {
	// Installed are the decisions the last successful gateway install
	// (operator or automatic) compiled with; Recorded says that is known.
	Installed map[string]string `json:"installed,omitempty"`
	Recorded  bool              `json:"recorded"`
	// Attempts are the automatic installs, newest last.
	Attempts []autoAttempt `json:"attempts,omitempty"`
	Last     *autoCheck    `json:"last,omitempty"`
}

func (s *Server) now() time.Time {
	if s.clock != nil {
		return s.clock().UTC()
	}
	return time.Now().UTC()
}

// loadAuto / saveAuto: caller holds s.mu.
func (s *Server) loadAuto() autoDoc {
	var d autoDoc
	raw, ok, err := s.Store.Get(autoApplyKey)
	if err != nil || !ok || raw == "" || json.Unmarshal([]byte(raw), &d) != nil {
		return autoDoc{}
	}
	return d
}

func (s *Server) saveAuto(d autoDoc) {
	if len(d.Attempts) > maxAutoLog {
		d.Attempts = d.Attempts[len(d.Attempts)-maxAutoLog:]
	}
	if buf, err := json.Marshal(d); err == nil {
		_ = s.Store.Put(autoApplyKey, string(buf))
	}
}

// recordInstalledDecisions is called after every successful gateway
// install with the decisions it compiled with. The pending flag stays set
// when the decisions moved again while the install ran.
func (s *Server) recordInstalledDecisions(dec map[string]string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	d := s.loadAuto()
	d.Installed, d.Recorded = copyDec(dec), true
	s.saveAuto(d)
	snap := s.loadUnlock()
	t, err := s.topology()
	pending := err != nil || !sameDec(unlock.Decisions(snap, servicesOf(t)), dec)
	if snap.PendingApply != pending {
		snap.PendingApply = pending
		_ = s.saveUnlock(snap)
	}
}

func copyDec(m map[string]string) map[string]string {
	out := map[string]string{}
	for k, v := range m {
		out[k] = v
	}
	return out
}

func sameDec(a, b map[string]string) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if b[k] != v {
			return false
		}
	}
	return true
}

func decHash(m map[string]string) string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	h := sha256.New()
	for _, k := range keys {
		fmt.Fprintf(h, "%s=%s\n", k, m[k])
	}
	return hex.EncodeToString(h.Sum(nil))[:16]
}

type autoSettings struct {
	on       bool
	gap      time.Duration
	dailyMax int
}

func autoSettingsOf(t model.Topology) autoSettings {
	a := autoSettings{gap: model.DefaultAutoApplyMinGapSec * time.Second, dailyMax: model.DefaultAutoApplyDailyMax}
	if p := t.Settings.UnlockProbe; p != nil {
		a.on = p.AutoApply
		if p.AutoApplyMinGapSec > 0 {
			a.gap = time.Duration(p.AutoApplyMinGapSec) * time.Second
		}
		if p.AutoApplyDailyMax > 0 {
			a.dailyMax = p.AutoApplyDailyMax
		}
	}
	return a
}

// maybeAutoApply evaluates the conditions and, when all hold, installs.
// It returns the evaluation (nil when auto_apply is off: nothing is
// recorded and nothing changes from the behaviour without the setting).
func (s *Server) maybeAutoApply(trigger string) *autoCheck {
	s.autoMu.Lock()
	defer s.autoMu.Unlock()
	t, err := s.topology()
	if err != nil {
		return nil
	}
	cfg := autoSettingsOf(t)
	if !cfg.on {
		return nil
	}
	now := s.now()
	s.mu.Lock()
	snap := s.loadUnlock()
	doc := s.loadAuto()
	s.mu.Unlock()
	want := unlock.Decisions(snap, servicesOf(t))
	check := &autoCheck{At: now, Trigger: trigger, Decisions: copyDec(want)}
	finish := func(code, msg string) *autoCheck {
		check.Code, check.Message = code, msg
		s.mu.Lock()
		d := s.loadAuto()
		prev := d.Last
		d.Last = check
		s.saveAuto(d)
		// One history line per new outcome, not one per minute.
		if code != AutoNotPending && (prev == nil || prev.Code != code || decHash(prev.Decisions) != decHash(check.Decisions)) {
			sn := s.loadUnlock()
			sn.History = append(sn.History, unlock.HistoryEntry{At: now, Kind: unlock.KindManual, Note: "自动安装解锁决定：" + autoText(code) + "。" + msg})
			if len(sn.History) > 200 {
				sn.History = sn.History[len(sn.History)-200:]
			}
			_ = s.saveUnlock(sn)
		}
		s.mu.Unlock()
		return check
	}

	// Nothing to do.
	if doc.Recorded && sameDec(doc.Installed, want) {
		return finish(AutoNotPending, "已安装的就是当前的决定")
	}
	if !doc.Recorded {
		return finish(AutoNoRecord, "不知道上一次安装用的是哪些决定（升级后还没有经面板安装过网关）：先人工安装一次")
	}
	// 3. rate limits (cheap; before touching the host).
	recent := 0
	var lastOK time.Time
	for _, a := range doc.Attempts {
		if now.Sub(a.At) < autoDaySpan {
			recent++
		}
		if a.At.After(lastOK) {
			lastOK = a.At
		}
	}
	if n := len(doc.Attempts); n > 0 {
		last := doc.Attempts[n-1]
		if !last.OK && last.Hash == decHash(want) && now.Sub(last.At) < autoBackoff {
			return finish(AutoBackoff, fmt.Sprintf("同样的决定 %s 自动安装失败过，%s 之后才会再试", last.At.Format(time.RFC3339), last.At.Add(autoBackoff).Format(time.RFC3339)))
		}
	}
	if !lastOK.IsZero() && now.Sub(lastOK) < cfg.gap {
		return finish(AutoGap, fmt.Sprintf("距上一次自动安装不足 %d 分钟，%s 之后再评估", int(cfg.gap/time.Minute), lastOK.Add(cfg.gap).Format(time.RFC3339)))
	}
	if recent >= cfg.dailyMax {
		return finish(AutoDailyCap, fmt.Sprintf("最近 24 小时已自动安装 %d 次，达到上限 %d", recent, cfg.dailyMax))
	}
	// 4. nothing else running; hold the gateway node lock from here on.
	if !s.lockNode(localNodeID) {
		return finish(AutoBusy, "网关正在预检、装机或撤回，推迟到下一次评估")
	}
	defer s.unlockNode(localNodeID)
	ap := s.applier(true)
	if busy, err := ap.Busy(); err != nil || busy {
		return finish(AutoBusy, "有宿主事务正在进行或没有完成，推迟到下一次评估")
	}
	// 1. in sync before the decision.
	prev, err := s.compileWith(t, doc.Installed)
	if err != nil {
		return finish(AutoCompileFailed, "按已安装的决定编译失败："+clipText(err.Error(), 300))
	}
	inst, err := ap.Installed()
	if err != nil || inst.Empty() || inst.Withdrawn() {
		return finish(AutoOutOfSync, "网关上没有可核对的安装（未安装、已撤回或记录损坏）")
	}
	if d, err := ap.InstalledDiff(prev); err != nil || d == nil || !d.Empty() {
		return finish(AutoOutOfSync, "网关上安装的文件与按上一次决定编译的结果不一致：网关有尚未安装的其他改动，需要人工审阅安装")
	}
	// 2. only rule-derived gateway files.
	next, err := s.compileWith(t, want)
	if err != nil {
		return finish(AutoCompileFailed, "按新决定编译失败："+clipText(err.Error(), 300))
	}
	if s.autoMutate != nil {
		s.autoMutate(next)
	}
	changed, refused := compile.DecisionChange(prev, next, localNodeID)
	check.Files = append(changed, refused...)
	if len(refused) > 0 {
		return finish(AutoFilesRefused, "这次改变涉及允许列表以外的文件或别的节点："+strings.Join(refused, "、"))
	}
	if len(changed) == 0 {
		return finish(AutoNotPending, "新决定不改变网关上的任何文件")
	}
	// 5. preflight for exactly this bundle.
	if !s.gatewayGateActive() || s.hostPreflighter() == nil {
		return finish(AutoPreflightNA, "宿主执行通道不支持安装前预检，不能自动安装")
	}
	ctx, cancel := context.WithTimeout(context.Background(), autoTimeout)
	defer cancel()
	pf, err := s.runHostPreflight(ctx, provision.FilesFor(next.Files, localNodeID))
	if err != nil {
		return finish(AutoPreflightNA, "安装前预检没有完成："+clipText(err.Error(), 300))
	}
	if pf.Blocking {
		return finish(AutoPreflightStop, "安装前预检有阻断项（预检 "+pf.ID+"），没有安装")
	}
	// Install through the operator's path.
	cw := &captureWriter{header: http.Header{}}
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, "/api/apply", nil)
	s.applyGateway(cw, req, applyBody{Install: true}, &autoInstall{decisions: copyDec(want), canonical: next.Canonical()})
	att := autoAttempt{At: now, Trigger: trigger, Decisions: copyDec(want), Hash: decHash(want), OK: cw.status == http.StatusOK, Files: changed}
	if !att.OK {
		var body struct {
			Code  string `json:"code"`
			Error string `json:"error"`
		}
		_ = json.Unmarshal(cw.body, &body)
		att.Code, att.Message = body.Code, clipText(body.Error, 400)
	}
	s.mu.Lock()
	d := s.loadAuto()
	d.Attempts = append(d.Attempts, att)
	s.saveAuto(d)
	s.mu.Unlock()
	if att.OK {
		return finish(AutoApplied, "已经通过网关安装事务自动安装（改动文件："+strings.Join(changed, "、")+"）")
	}
	return finish(AutoInstallFailed, fmt.Sprintf("自动安装失败（%s）：%s；决定保持待安装，%d 分钟内不再自动重试同样的决定", att.Code, att.Message, int(autoBackoff/time.Minute)))
}

func autoText(code string) string {
	switch code {
	case AutoApplied:
		return "已安装"
	case AutoInstallFailed:
		return "失败"
	default:
		return "未执行（" + code + "）"
	}
}

// captureWriter is the response of an in-process call of applyGateway.
type captureWriter struct {
	header http.Header
	status int
	body   []byte
}

func (c *captureWriter) Header() http.Header { return c.header }
func (c *captureWriter) WriteHeader(code int) {
	if c.status == 0 {
		c.status = code
	}
}
func (c *captureWriter) Write(b []byte) (int, error) {
	if c.status == 0 {
		c.status = http.StatusOK
	}
	c.body = append(c.body, b...)
	return len(b), nil
}

// autoApplyView is the panel's view: setting, limits, latest evaluation,
// latest automatic install.
func (s *Server) autoApplyView(t model.Topology) map[string]any {
	cfg := autoSettingsOf(t)
	d := s.loadAuto()
	v := map[string]any{
		"enabled": cfg.on, "min_gap_sec": int(cfg.gap / time.Second), "daily_max": cfg.dailyMax,
		"backoff_sec": int(autoBackoff / time.Second), "installed_recorded": d.Recorded,
		"allow_list": compile.DecisionFiles,
	}
	if d.Last != nil {
		v["last_check"] = d.Last
	}
	if n := len(d.Attempts); n > 0 {
		v["last_attempt"] = d.Attempts[n-1]
	}
	return v
}
