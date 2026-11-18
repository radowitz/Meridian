package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"time"

	"github.com/radowitz/meridian/internal/hostexec"
	"github.com/radowitz/meridian/internal/sniff"
)

// The forwarder's path diagnosis (GET /api/sniff runtime.diagnosis) and the
// on-demand self-check (POST /api/sniff/selfcheck).
//
// The view separates "the unit runs" from "its paths are usable": the last
// self-check (sniff/selfcheck.go) judged against the installed rule pair
// (the hash of the target file the agent read), per-target recent
// failures, the nft counters sniff_denied (and whether it grows between
// two agent readings) and sniff_wg_outer, and the incident's signature —
// the tunnel targets failing while direct works.

// SniffSelfChecker has the forwarder run its self-check (hostexec.Client).
type SniffSelfChecker interface {
	SniffSelfCheck(ctx context.Context) (hostexec.SniffCheckReport, error)
}

// Path states of sniffDiagnosis.
const (
	sniffPathsUsable    = "usable"    // the self-check of the installed rules passed, nothing failing
	sniffPathsDegraded  = "degraded"  // the default target works; another target or recent connections fail
	sniffPathsFailing   = "failing"   // the default target failed its self-check, or the incident's signature
	sniffPathsUnchecked = "unchecked" // no current self-check of the installed rules
)

type sniffDiagnosis struct {
	Paths   string `json:"paths"`
	Message string `json:"message,omitempty"`
	// SelfCheck is the forwarder's last self-check; Verdict what it says
	// about the installed rule pair; AgeS its age at the read.
	SelfCheck *sniff.SelfCheck `json:"self_check,omitempty"`
	Verdict   *sniff.Verdict   `json:"verdict,omitempty"`
	AgeS      int64            `json:"age_s"`
	// Current: the self-check is of the installed rule pair.
	Current bool                 `json:"current"`
	Targets []sniffTargetDiag    `json:"targets"`
	WindowS int                  `json:"window_s"`
	Denied  *sniffCounterDiag    `json:"denied,omitempty"`
	WGOuter *hostexec.NFTCounter `json:"wg_outer,omitempty"`
	// TunnelConcentrated: recent failures are on tunnel targets while the
	// direct target works (the incident's signature).
	TunnelConcentrated bool `json:"tunnel_concentrated"`
}

type sniffTargetDiag struct {
	Target  string `json:"target"`
	Default bool   `json:"default,omitempty"`
	Tunnel  bool   `json:"tunnel"`
	// Check: ok, failed, unchecked, or "" (not in a current self-check).
	Check               string `json:"check,omitempty"`
	CheckReason         string `json:"check_reason,omitempty"`
	RecentOK            uint64 `json:"recent_ok"`
	RecentResolveFailed uint64 `json:"recent_resolve_failed"`
	RecentDialFailed    uint64 `json:"recent_dial_failed"`
	// RecentRelayFailed: connected, then reset / failed or no response
	// (sniff.TargetStat.RecentRelayFailed).
	RecentRelayFailed uint64     `json:"recent_relay_failed"`
	LastFailureAt     *time.Time `json:"last_failure_at,omitempty"`
	LastFailure       string     `json:"last_failure,omitempty"`
}

type sniffCounterDiag struct {
	hostexec.NFTCounter
	// Delta packets since an earlier reading SinceS seconds before (nil:
	// no earlier reading yet); Growing when Delta > 0.
	Delta   *uint64 `json:"delta,omitempty"`
	SinceS  int64   `json:"since_s,omitempty"`
	Growing bool    `json:"growing"`
}

// sniffStaleAfter: an older self-check is shown, but not as current.
const sniffStaleAfter = 2 * sniff.DefaultSelfCheckInterval

// sniffTunnelTarget: every target but direct and reject goes through a
// tunnel.
func sniffTunnelTarget(name string) bool { return name != "direct" && name != "reject" }

// sniffDiagnose reads the forwarder's health and the agent's counters.
func sniffDiagnose(st hostexec.SniffStatus) *sniffDiagnosis {
	var h sniff.Health
	if len(st.Health) == 0 || json.Unmarshal(st.Health, &h) != nil {
		return nil
	}
	readAt, err := time.Parse(time.RFC3339, st.ReadAt)
	if err != nil {
		readAt = time.Now()
	}
	d := &sniffDiagnosis{Paths: sniffPathsUnchecked, SelfCheck: h.SelfCheck, WindowS: h.StatsWindowS, Targets: []sniffTargetDiag{}}
	want := st.TargetsSHA256
	if want == "" {
		want = h.TargetsSHA256
	}
	if c := h.SelfCheck; c != nil {
		// Judged for the installed pair, not for freshness (the panel shows
		// the age; an install requires a fresh one).
		v := sniff.EvaluateSelfCheck(c, want, time.Time{}, c.FinishedAt)
		d.Verdict = &v
		if age := readAt.Sub(c.FinishedAt); age > 0 {
			d.AgeS = int64(age / time.Second)
		}
		d.Current = v.Code != sniff.VerdictStaleGeneration && v.Code != sniff.VerdictUnavailable
	}
	byName := map[string]sniffTargetDiag{}
	get := func(name string) sniffTargetDiag {
		if x, ok := byName[name]; ok {
			return x
		}
		return sniffTargetDiag{Target: name, Tunnel: sniffTunnelTarget(name)}
	}
	for _, n := range h.Targets {
		if n != "reject" {
			byName[n] = get(n)
		}
	}
	if d.Current {
		for _, t := range h.SelfCheck.Targets {
			x := get(t.Target)
			x.Default, x.Check, x.CheckReason = t.Default, t.Status, t.Reason
			byName[t.Target] = x
		}
	}
	for _, s := range h.TargetStats {
		if s.Target == "reject" {
			continue
		}
		x := get(s.Target)
		x.RecentOK, x.RecentResolveFailed, x.RecentDialFailed, x.RecentRelayFailed, x.LastFailureAt, x.LastFailure = s.RecentOK, s.RecentResolveFailed, s.RecentDialFailed, s.RecentRelayFailed, s.LastFailureAt, s.LastFailure
		byName[s.Target] = x
	}
	for _, x := range byName {
		d.Targets = append(d.Targets, x)
	}
	rank := func(t sniffTargetDiag) int {
		switch {
		case t.Default:
			return 0
		case t.Tunnel:
			return 1
		}
		return 2
	}
	sort.Slice(d.Targets, func(i, j int) bool {
		a, b := d.Targets[i], d.Targets[j]
		if rank(a) != rank(b) {
			return rank(a) < rank(b)
		}
		return a.Target < b.Target
	})
	if c, ok := st.Counters["sniff_denied"]; ok {
		cd := &sniffCounterDiag{NFTCounter: c}
		if s := st.DeniedSince; s != nil && c.Present && c.Packets >= s.Packets {
			delta := c.Packets - s.Packets
			cd.Delta, cd.SinceS, cd.Growing = &delta, int64(readAt.Sub(s.At)/time.Second), delta > 0
		}
		d.Denied = cd
	}
	if c, ok := st.Counters["sniff_wg_outer"]; ok {
		cc := c
		d.WGOuter = &cc
	}
	// The incident's signature: the tunnel targets' recent connections fail
	// (at least 5, at least 80%) while direct ones succeed (at most 20%
	// failing). A connection counts once, by how it ended: ok (the upstream
	// answered), or failed to resolve, to connect, or after the connect
	// (reset, error or no response).
	var tunFail, tunAll, dirOK, dirFail uint64
	var otherFailing []string
	recentFailing := false
	for _, t := range d.Targets {
		fail := t.RecentResolveFailed + t.RecentDialFailed + t.RecentRelayFailed
		recentFailing = recentFailing || fail > 0
		if t.Tunnel {
			tunFail += fail
			tunAll += fail + t.RecentOK
		} else {
			dirOK += t.RecentOK
			dirFail += fail
		}
		if t.Check == sniff.TargetFailed && !t.Default {
			otherFailing = append(otherFailing, t.Target)
		}
	}
	d.TunnelConcentrated = tunFail >= 5 && tunFail*5 >= tunAll*4 && dirOK > 0 && dirFail*5 <= dirOK+dirFail
	growing := d.Denied != nil && d.Denied.Growing
	switch {
	case d.Current && d.Verdict.Code == sniff.VerdictDefaultFailed:
		d.Paths, d.Message = sniffPathsFailing, "服务在运行，但"+d.Verdict.Reason+"。按名字判断到这个目标、以及没有规则命中落到默认组的连接此刻会失败。"
	case d.TunnelConcentrated:
		d.Paths = sniffPathsFailing
		d.Message = fmt.Sprintf("最近 %d 分钟经隧道的目标失败（解析、连接或连上后无回应 / 被重置）%d 次、成功 %d 次，而直连正常：这是转发服务自己经隧道的路径出了问题（例如它的出站限制拦下了 WireGuard 外层包），不是个别网站的问题。可以先关闭嗅探并重新安装，网关回到按地址分流。", d.WindowS/60, tunFail, tunAll-tunFail)
	case growing:
		d.Paths = sniffPathsDegraded
		d.Message = fmt.Sprintf("转发服务出站被拦下的计数 sniff_denied 在增长（%d 秒内 +%d 个包）：它有查询或连接没能出去。", d.Denied.SinceS, *d.Denied.Delta)
	case !d.Current:
		d.Paths = sniffPathsUnchecked
		if h.SelfCheck == nil {
			d.Message = "还没有自检结果：服务在运行，路径是否可用未知。"
		} else {
			d.Message = "最近一次自检不属于当前安装的规则，路径是否可用未知（" + d.Verdict.Reason + "）。"
		}
	case len(otherFailing) > 0:
		d.Paths, d.Message = sniffPathsDegraded, fmt.Sprintf("默认目标可用；%d 个其它目标自检未通过，按名字判断到它们的连接会失败。", len(otherFailing))
	case readAt.Sub(h.SelfCheck.FinishedAt) > sniffStaleAfter:
		d.Paths, d.Message = sniffPathsUnchecked, "最近一次自检已过去较久，不能代表现在的路径。"
	case recentFailing:
		d.Paths, d.Message = sniffPathsDegraded, "自检通过；最近有个别连接解析失败、连接失败，或连上后被重置 / 没有回应（见各目标的计数）。"
	default:
		d.Paths = sniffPathsUsable
	}
	return d
}

// postSniffSelfCheck has the forwarder run its self-check now and answers
// the view of GET /api/sniff with the new result in it.
func (s *Server) postSniffSelfCheck(w http.ResponseWriter, r *http.Request) {
	sc, ok := s.Sniff.(SniffSelfChecker)
	if s.Sniff == nil || !ok {
		writeErr(w, http.StatusServiceUnavailable, errors.New("没有配置 host agent，不能让嗅探服务自检"))
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), sniff.SelfCheckBudget+40*time.Second)
	defer cancel()
	rep, err := sc.SniffSelfCheck(ctx)
	if err != nil {
		code := http.StatusBadGateway
		if errors.Is(err, hostexec.ErrUnavailable) {
			code = http.StatusServiceUnavailable
		}
		writeErr(w, code, err)
		return
	}
	if rep.Result == nil {
		writeErr(w, http.StatusConflict, errors.New("嗅探服务没有完成自检："+rep.Error))
		return
	}
	s.getSniff(w, r)
}
