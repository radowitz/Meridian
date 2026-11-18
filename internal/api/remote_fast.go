package api

// Fast path for remote-access device changes.
//
// After a device is added, deleted, changed or regenerated, the panel
// installs the change itself when it is nothing but the [Peer] set of the
// gateway's etc/wireguard/mra.conf. It reuses the unlock auto_apply
// machinery (autoapply.go): the same serialisation (autoMu, the gateway
// node lock, the deployment guide and host transaction checks), the same
// install path (applyGateway with an autoInstall, compiled bundle pinned by
// its canonical text) and a rate limit of the same kind. The install is an
// ordinary transaction (version +1, rollback-able, panel in sync) whose
// activation is the host agent's peer sync (wg-quick strip + wg syncconf,
// no interface restart); a failure is compensated by the transaction:
// the previous mra.conf is written back and synced.
//
// It applies only when, at that moment:
//   - no acceptance drill runs, no deployment guide run is open, the node
//     lock is free and no host transaction is unfinished;
//   - the gateway has an installed, not withdrawn, version;
//   - installing the stored topology (with the current unlock decisions)
//     would change only mra.conf (and the check script listing device
//     addresses: apply.PeerSyncFiles), and the mra.conf [Interface]
//     section is unchanged (pool, port, MTU and key are full installs);
//   - the host agent offers the peer sync and the rate limit allows it.
//
// Otherwise the answer is apply_required with a one-line reason.

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/radowitz/meridian/internal/apply"
	"github.com/radowitz/meridian/internal/hostexec"
)

const (
	remoteFastKey = "remote_fast_apply"
	// remoteFastHourMax / remoteFastDayMax: automatic peer installs per
	// hour / per 24 hours.
	remoteFastHourMax = 30
	remoteFastDayMax  = 200
	remoteFastLog     = 200
)

// Status values of a fast apply.
const (
	FastApplied = "applied"  // installed, live
	FastNone    = "none"     // nothing differs from the installed version
	FastFailed  = "failed"   // tried and compensated (or not): see reason
	FastSkipped = "required" // not eligible: a full install is needed
)

// fastApply is the answer's "fast_apply" member.
type fastApply struct {
	Status  string `json:"status"`
	Reason  string `json:"reason,omitempty"`
	Version int64  `json:"version,omitempty"`
}

// applyRequired is the answer's apply_required for this outcome (a
// scheduled automatic rule install is not: it is on its way).
func (f fastApply) applyRequired() bool {
	return f.Status != FastApplied && f.Status != FastNone && f.Status != FastScheduled
}

type remoteFastDoc struct {
	Attempts []time.Time `json:"attempts,omitempty"`
}

// remoteIfaceSection is the part of mra.conf before the first [Peer].
func remoteIfaceSection(body string) string {
	if i := strings.Index(body, "\n[Peer]"); i >= 0 {
		body = body[:i]
	}
	// Same form with or without peers: the [Interface] section alone,
	// trailing blank lines dropped (0 ↔ 1 device must compare equal).
	return strings.TrimRight(body, "\n")
}

// remoteFastPending is the reason given when the gateway already had
// changes waiting before this one: the fast path never installs them along.
const remoteFastPending = "网关上还有未安装的改动，需要到部署页安装"

// fastPre is the gateway state recorded before a device change is saved.
// Pending: the compiled bundle differed from the installed version (or
// could not be compared). Version: the installed version at that moment.
type fastPre struct {
	Installed bool
	Pending   bool
	Version   int64
}

// remoteFastPre records, before a device change is saved (under raMu),
// whether the gateway's compiled bundle matched its installed version.
func (s *Server) remoteFastPre() fastPre {
	ap := s.applier(true)
	inst, err := ap.Installed()
	if err != nil || inst.Empty() || inst.Withdrawn() {
		return fastPre{}
	}
	pre := fastPre{Installed: true, Version: inst.Version, Pending: true}
	t, err := s.topology()
	if err != nil {
		return pre
	}
	b, err := s.compileTopo(t)
	if err != nil {
		return pre
	}
	if d, err := ap.InstalledDiff(b); err == nil && d != nil && d.Empty() {
		pre.Pending = false
	}
	return pre
}

// remoteFastApply evaluates and, when eligible, installs. pre is the state
// recorded before the change was saved: only a gateway that was in sync
// then, at the same installed version, takes the fast path. Callers must
// not hold raMu (the install's secret bookkeeping takes it).
func (s *Server) remoteFastApply(pre fastPre) fastApply {
	skip := func(reason string) fastApply { return fastApply{Status: FastSkipped, Reason: reason} }
	if _, ok := s.Host.(apply.PeerSyncer); !ok {
		return skip("宿主代理不支持快速生效")
	}
	s.autoMu.Lock()
	defer s.autoMu.Unlock()
	g, reason := s.fastGate(remoteFastKey, remoteFastHourMax, remoteFastDayMax)
	if reason != "" {
		return skip(reason)
	}
	defer g.release()
	ap, inst := g.ap, g.inst
	// Bound to this change: in sync before it, and nothing installed since.
	if !pre.Installed || pre.Pending || inst.Version != pre.Version {
		return skip(remoteFastPending)
	}
	t, err := s.topology()
	if err != nil {
		return skip("读取拓扑失败")
	}
	dec := s.unlockDecisions(t)
	next, err := s.compileWith(t, dec)
	if err != nil {
		return skip("拓扑无法编译")
	}
	if len(next.PeerKeyProblems(localNodeID)) > 0 {
		return skip("有对端缺少公钥")
	}
	d, err := ap.InstalledDiff(next)
	if err != nil || d == nil {
		return skip("网关安装记录不可读")
	}
	if d.Empty() {
		return fastApply{Status: FastNone}
	}
	if !apply.PeerOnlyDiff(*d) {
		return skip("还有其他待安装的改动")
	}
	old, ok, err := ap.InstalledConfig(hostexec.RemoteAccessConf)
	nb, nok := next.Files["nodes/"+localNodeID+"/"+hostexec.RemoteAccessConf]
	if err != nil || !ok || !nok {
		return skip("网关安装记录不可读")
	}
	if remoteIfaceSection(old) != remoteIfaceSection(nb) {
		return skip("地址池、端口或接口参数改了")
	}
	s.recordFastAttempt(remoteFastKey, g.now)
	cw := &captureWriter{header: http.Header{}}
	req, _ := http.NewRequest(http.MethodPost, "/api/apply", nil)
	s.autoInstalling.Store(true)
	s.applyGateway(cw, req, applyBody{Install: true}, &autoInstall{decisions: copyDec(dec), canonical: next.Canonical(), peerSync: true})
	s.autoInstalling.Store(false)
	return fastInstallOutcome(cw)
}

func firstLineOf(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = s[:i]
	}
	return s
}

// ------------------------------------------------ shared fast-path gate ---
//
// The remote-access peer path (above) and the rule path (rules_autoapply.go)
// share their eligibility, mutual exclusion and rate limit; only the action
// differs (peer sync vs the full gateway install transaction).

// fastGated is a passed gate: the gateway node lock is held until release.
type fastGated struct {
	ap      apply.Applier
	inst    apply.Manifest
	now     time.Time
	last    time.Time // the newest recorded attempt (zero: none)
	release func()
}

// fastGate checks, in order: no acceptance drill, no open deployment guide
// run, the rate limit of key (attempts per hour / 24 hours), the gateway
// node lock (taken), no unfinished host transaction and an installed, not
// withdrawn, gateway. The caller holds autoMu. reason is "" when it passed.
func (s *Server) fastGate(key string, hourMax, dayMax int) (fastGated, string) {
	if s.drillActive() {
		return fastGated{}, "验收演练进行中"
	}
	if id := s.deployRunOpen(); id != "" {
		return fastGated{}, "部署引导未结束"
	}
	now := s.now()
	attempts := s.fastAttempts(key)
	hour, day := 0, 0
	var last time.Time
	for _, at := range attempts {
		if now.Sub(at) < time.Hour {
			hour++
		}
		if now.Sub(at) < autoDaySpan {
			day++
		}
		if at.After(last) {
			last = at
		}
	}
	if hour >= hourMax || day >= dayMax {
		return fastGated{}, "自动生效太频繁，稍后或手动安装"
	}
	if !s.lockNode(localNodeID) {
		return fastGated{}, "网关正忙"
	}
	ap := s.applier(true)
	if busy, err := ap.Busy(); err != nil || busy {
		s.unlockNode(localNodeID)
		return fastGated{}, "有未完成的宿主事务"
	}
	inst, err := ap.Installed()
	if err != nil || inst.Empty() || inst.Withdrawn() {
		s.unlockNode(localNodeID)
		return fastGated{}, "网关尚未安装"
	}
	return fastGated{ap: ap, inst: inst, now: now, last: last, release: func() { s.unlockNode(localNodeID) }}, ""
}

// fastAttempts are the recorded attempts of key.
func (s *Server) fastAttempts(key string) []time.Time {
	s.mu.Lock()
	defer s.mu.Unlock()
	var doc remoteFastDoc
	if raw, ok, err := s.Store.Get(key); err == nil && ok {
		_ = json.Unmarshal([]byte(raw), &doc)
	}
	return doc.Attempts
}

// recordFastAttempt appends an attempt of key (the newest remoteFastLog kept).
func (s *Server) recordFastAttempt(key string, at time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var doc remoteFastDoc
	if raw, ok, err := s.Store.Get(key); err == nil && ok {
		_ = json.Unmarshal([]byte(raw), &doc)
	}
	doc.Attempts = append(doc.Attempts, at)
	if len(doc.Attempts) > remoteFastLog {
		doc.Attempts = doc.Attempts[len(doc.Attempts)-remoteFastLog:]
	}
	if buf, err := json.Marshal(doc); err == nil {
		_ = s.Store.Put(key, string(buf))
	}
}

// fastInstallOutcome reads applyGateway's answer: applied with the new
// version, or failed with the first line of the error and whether the
// transaction restored the previous files. The error text is already
// redacted by the install path (writeTxnErr).
func fastInstallOutcome(cw *captureWriter) fastApply {
	if cw.status == http.StatusOK {
		var res apply.Result
		_ = json.Unmarshal(cw.body, &res)
		f := fastApply{Status: FastApplied}
		if res.Host != nil {
			f.Version = res.Host.ToVersion
		}
		return f
	}
	var body struct {
		Code        string `json:"code"`
		Error       string `json:"error"`
		Compensated *bool  `json:"compensated"`
	}
	_ = json.Unmarshal(cw.body, &body)
	reason := firstLineOf(body.Error)
	if body.Compensated != nil && *body.Compensated {
		reason += "（已恢复原配置）"
	} else if body.Compensated != nil {
		reason += "（恢复失败，需在部署页恢复）"
	}
	if reason == "" {
		reason = fmt.Sprintf("安装失败（%d）", cw.status)
	}
	return fastApply{Status: FastFailed, Reason: clipText(reason, 200)}
}
