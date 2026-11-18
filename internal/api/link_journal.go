package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/radowitz/meridian/internal/apply"
	"github.com/radowitz/meridian/internal/compile"
	"github.com/radowitz/meridian/internal/hostexec"
	"github.com/radowitz/meridian/internal/linkjournal"
	"github.com/radowitz/meridian/internal/model"
	"github.com/radowitz/meridian/internal/preflight"
	"github.com/radowitz/meridian/internal/sniff"
)

// The gateway's link journal (internal/linkjournal, docs/architecture.md
// 「链路日志」), read only through the host agent's fixed requests:
//
//	GET  /api/link-log          whether the collector is installed and
//	                            running, its sources, the bounds, and the
//	                            scope: what is observed, from which source,
//	                            how often and with what evidence, and what
//	                            is not in scope
//	GET  /api/link-log/current  the state now: which path carries, every
//	                            object that is abnormal or unknown, for how
//	                            long, with the evidence
//	GET  /api/link-log/events   one page of the timeline, newest first
//	                            (query: class, kind, id, from, to, before,
//	                            limit)
//	POST /api/link-log/clear    {"confirm": true}
//
// The journal has no switch: it holds no user traffic content, and the
// collector is part of every gateway's files. It starts only with a gateway
// install (preflight → confirm → install); the panel never starts anything
// on the host itself. Journal content passes through these handlers only:
// it is never stored by the panel and is not part of the topology, a
// snapshot, an export or a diagnosis.

// LinkLogRuntime is the host agent's link-journal requests (hostexec.Client
// in main).
type LinkLogRuntime interface {
	LinkJournalStatus(ctx context.Context) (hostexec.LinkJournalStatus, error)
	LinkJournalCurrent(ctx context.Context) (hostexec.LinkJournalAnswer, error)
	LinkJournal(ctx context.Context, q linkjournal.Query) (hostexec.LinkJournalAnswer, error)
	LinkJournalClear(ctx context.Context) (hostexec.LinkJournalAnswer, error)
}

// Codes of the link journal's answers.
const (
	codeLinkLogAgentUnavailable = "agent_unavailable"
	codeLinkLogAgentOld         = "agent_old"
	codeLinkLogReadFailed       = "read_failed"
	codeLinkLogNotInstalled     = "not_installed"
	codeLinkLogNotRunning       = "not_running"
	// codeLinkLogBlocked is the pre-check's blocking finding: the host
	// binary is older than the panel and has no collector.
	codeLinkLogBlocked = "link_log_host_old"
)

// linkLogNotes is what the page says next to the log: what it is, where it
// lives, who can read it, how it is bounded.
var linkLogNotes = struct {
	Records []string `json:"records"`
	Storage []string `json:"storage"`
	Rules   []string `json:"rules"`
	Install []string `json:"install"`
}{
	Records: []string{
		"记录的是状态的变化，不是周期性的采样：每条事件有时间、对象、从什么状态到什么状态、依据、之前那个状态持续了多久",
		"事件里只有拓扑里的名字（链路、节点、地区组、接口）、状态和来源给出的原因；不含任何设备地址、域名、连接或其他流量内容",
		"每一类事件都标明依据的强弱：直接读到的状态、网关自己的探测结论、还是间接推断。网关自己的检查失败不等于对端已确认故障",
	},
	Storage: []string{
		"只存在网关本机 /var/lib/meridian-linklog（目录 0700、文件 0600，属 root）：只有 root 能读，面板经宿主代理的固定只读请求查询；不进入拓扑、快照、导出、预检或诊断信息",
		"保留最近 30 天、最多 20000 条、合计不超过 16 MiB（事件文件、检查点和它们写入时的临时副本都算在内），先到的上限生效，超出时删最旧的",
		"「清空」立即删除网关上的全部事件和已记下的状态；之后的第一次采集重新建立基线",
	},
	Rules: []string{
		"基线：采集服务第一次读到某个对象时只记下它的状态，不产生事件（不知道这个状态是何时开始的，持续时间按「至少」显示）",
		"重启：状态记在检查点里，重启后状态没变就不产生事件",
		"空窗：采集服务没有运行、某个来源读不到的那段时间记为未知；任何持续时间都不跨过空窗，空窗之后才发现的变化会标明「发生在空窗内，时间不确定」",
		"抖动：同一个对象 10 分钟内的前 4 次变化各记一条，之后的变化合并成一条「变化了 N 次」的记录（保留次数、第一次和最后一次的时间），它不是一次连续的中断；另有每小时最多 600 条的写入上限，超出的丢弃并计数",
	},
	Install: []string{
		"没有开关：采集服务是每个网关安装内容的一部分，但只在网关安装（预检 → 确认 → 安装）之后才开始运行；面板不会自己在宿主机上启动任何东西",
		"升级到带链路日志的版本之后，网关会显示有待安装的变更：新增 meridian-link-journal.service 和 /etc/meridian/link-journal.json，验收脚本多一段检查；规则集、路由、隧道、解析器配置和故障切换脚本都不变",
		"采集服务只读：不改路由、规则、接口或任何单元；它停止或崩溃时只是不记录",
	},
}

type linkLogBounds struct {
	MaxAgeS   int64              `json:"max_age_s"`
	MaxEvents int                `json:"max_events"`
	Budget    linkjournal.Budget `json:"budget"`
	// DiskBytes is the worst case on disk (the whole budget).
	DiskBytes     int64 `json:"disk_bytes"`
	MaxLine       int   `json:"max_line"`
	WritesPerHour int   `json:"writes_per_hour"`
	PageMax       int   `json:"page_max"`
}

type linkLogTiming struct {
	IntervalS        int   `json:"interval_s"`
	SlowIntervalS    int   `json:"slow_interval_s"`
	GapAfterS        int64 `json:"gap_after_s"`
	HandshakeStaleS  int   `json:"handshake_stale_s"`
	UpstreamStaleS   int   `json:"upstream_stale_s"`
	SelfCheckEveryS  int64 `json:"selfcheck_every_s"`
	SelfCheckMaxAgeS int   `json:"selfcheck_max_age_s"`
	FlapAfter        int   `json:"flap_after"`
	FlapWindowS      int64 `json:"flap_window_s"`
	FlapQuietS       int64 `json:"flap_quiet_s"`
	FlapMaxS         int64 `json:"flap_max_s"`
}

type linkLogScope struct {
	// Sources: what is observed, from where, how often, with what evidence.
	Sources []linkjournal.SourceInfo `json:"sources"`
	// NotInScope: what the gateway cannot read through an existing fixed
	// channel.
	NotInScope []linkjournal.Excluded `json:"not_in_scope"`
	// Kinds: the object kinds and what their states mean.
	Kinds []linkjournal.KindInfo `json:"kinds"`
	// Mode: how the carrying path is recorded on this topology (single |
	// dual | share); ModeNote says it in words.
	Mode     string `json:"mode,omitempty"`
	ModeNote string `json:"mode_note,omitempty"`
	// SniffOn: the forwarder is part of the topology (its self-check is
	// the only source for exits and region groups).
	SniffOn bool `json:"sniff_on"`
	// Externals: every external exit and what the gateway sees of it.
	Externals []compile.LinkJournalExternal `json:"externals"`
	// Unobserved: objects of the topology that are listed but not read.
	Unobserved []linkjournal.Object `json:"unobserved"`
	Notes      any                  `json:"notes"`
}

type linkLogRuntimeView struct {
	Available       bool            `json:"available"`
	Code            string          `json:"code,omitempty"`
	Message         string          `json:"message,omitempty"`
	UnitActive      string          `json:"unit_active,omitempty"`
	Present         bool            `json:"present"`
	ConfigInstalled bool            `json:"config_installed"`
	Health          json.RawMessage `json:"health,omitempty"`
	ReadAt          string          `json:"read_at,omitempty"`
}

type linkLogView struct {
	// Installed: the last gateway install put the collector on the host
	// (Known false: the install record cannot be read).
	Installed struct {
		Known   bool `json:"known"`
		Enabled bool `json:"enabled"`
	} `json:"installed"`
	// Pending: "install" when the collector is part of the gateway's files
	// but not installed yet (the next gateway install adds it).
	Pending string             `json:"pending,omitempty"`
	Runtime linkLogRuntimeView `json:"runtime"`
	Bounds  linkLogBounds      `json:"bounds"`
	Timing  linkLogTiming      `json:"timing"`
	Scope   linkLogScope       `json:"scope"`
	// Objects: what the journal can hold events of on this topology (the
	// filter's choices).
	Objects []linkjournal.Object `json:"objects"`
}

func linkLogBoundsNow() linkLogBounds {
	return linkLogBounds{MaxAgeS: int64(linkjournal.DefaultMaxAge / time.Second), MaxEvents: linkjournal.DefaultMaxEvents, Budget: linkjournal.SplitBudget(0),
		DiskBytes: linkjournal.DefaultMaxBytes, MaxLine: linkjournal.MaxLine, WritesPerHour: linkjournal.DefaultWritesPerHour, PageMax: linkjournal.PageMax}
}

var linkLogModeNotes = map[string]string{
	linkjournal.ModeSingle: "这个拓扑只有一台中继、没有备用枢纽：网关的故障切换服务不记录它的选择，承载路径取自路由表 102 的默认路由，所以只有切换本身，没有探测结论和原因",
	linkjournal.ModeDual:   "这个拓扑有备用枢纽：承载路径（到中继的 UDP 腿 / WSS 腿 / 备用枢纽）和探测结论取自网关故障切换服务每一轮写的记录",
	linkjournal.ModeShare:  "这个拓扑由多台中继分担：承载路径、每台中继在分担里的状态和原因、它使用的腿，取自分担控制器每一轮写的记录",
}

// linkLogInstalled: the last gateway install put the collector's unit on
// the host.
func (s *Server) linkLogInstalled() (enabled, known bool) {
	m, err := s.applier(true).Installed()
	if err != nil {
		return false, false
	}
	for _, u := range m.Units {
		if u == compile.LinkJournalUnit {
			return true, true
		}
	}
	return false, true
}

// linkLogStatus asks the agent and turns the answer (or the reason there
// is none) into the runtime view.
func (s *Server) linkLogStatus(ctx context.Context) linkLogRuntimeView {
	var rt linkLogRuntimeView
	if s.LinkLog == nil {
		rt.Code, rt.Message = codeLinkLogAgentUnavailable, "没有配置 host agent：读不到链路日志"
		return rt
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	st, err := s.LinkLog.LinkJournalStatus(ctx)
	switch {
	case errors.Is(err, hostexec.ErrLinkJournalUnsupported):
		rt.Code, rt.Message = codeLinkLogAgentOld, err.Error()
		return rt
	case errors.Is(err, hostexec.ErrUnavailable):
		rt.Code, rt.Message = codeLinkLogAgentUnavailable, "宿主执行通道不可用，读不到链路日志："+err.Error()
		return rt
	case err != nil:
		rt.Code, rt.Message = codeLinkLogReadFailed, "读不到链路日志采集服务的状态："+err.Error()
		return rt
	}
	rt = linkLogRuntimeView{Available: true, UnitActive: st.UnitActive, Present: st.Present, ConfigInstalled: st.ConfigInstalled, Health: st.Health, ReadAt: st.ReadAt}
	if st.Error != "" {
		rt.Code, rt.Message = codeLinkLogReadFailed, st.Error
	}
	return rt
}

func (s *Server) linkLogViewOf(ctx context.Context, t model.Topology) linkLogView {
	v := linkLogView{Bounds: linkLogBoundsNow(), Objects: []linkjournal.Object{}}
	v.Scope = linkLogScope{Sources: linkjournal.Inventory(), NotInScope: linkjournal.NotInScope(), Kinds: linkjournal.Kinds, Notes: linkLogNotes,
		Externals: []compile.LinkJournalExternal{}, Unobserved: []linkjournal.Object{}, SniffOn: t.SniffOn()}
	v.Timing = linkLogTiming{IntervalS: linkjournal.DefaultIntervalS, SlowIntervalS: linkjournal.DefaultIntervalS * linkjournal.DefaultSlowEvery, GapAfterS: int64(linkjournal.DefaultGapAfter / time.Second),
		HandshakeStaleS: linkjournal.DefaultHandshakeStaleS, UpstreamStaleS: linkjournal.DefaultUpstreamStaleS, SelfCheckEveryS: int64(sniff.DefaultSelfCheckInterval / time.Second),
		SelfCheckMaxAgeS: linkjournal.DefaultSelfCheckMaxAgeS, FlapAfter: linkjournal.DefaultFlapAfter, FlapWindowS: int64(linkjournal.DefaultFlapWindow / time.Second),
		FlapQuietS: int64(linkjournal.DefaultFlapQuiet / time.Second), FlapMaxS: int64(linkjournal.DefaultFlapMax / time.Second)}
	if info, err := compile.LinkJournalFor(t, s.unlockDecisions(t)); err == nil {
		c := info.Config
		v.Scope.Mode, v.Scope.ModeNote = c.Mode, linkLogModeNotes[c.Mode]
		v.Scope.Externals = info.Externals
		v.Timing.IntervalS, v.Timing.SlowIntervalS, v.Timing.HandshakeStaleS, v.Timing.UpstreamStaleS = c.IntervalS, c.IntervalS*c.SlowEvery, c.HandshakeStaleS, c.UpstreamStaleS
		for _, o := range info.Objects {
			v.Objects = append(v.Objects, o)
			if !o.Observed {
				v.Scope.Unobserved = append(v.Scope.Unobserved, o)
			}
		}
	}
	v.Installed.Enabled, v.Installed.Known = s.linkLogInstalled()
	if v.Installed.Known && !v.Installed.Enabled {
		v.Pending = "install"
	}
	v.Runtime = s.linkLogStatus(ctx)
	if v.Runtime.Available && v.Runtime.Code == "" {
		switch {
		case v.Installed.Known && !v.Installed.Enabled && !v.Runtime.Present:
			v.Runtime.Code, v.Runtime.Message = codeLinkLogNotInstalled, "链路日志的采集服务还没有安装到网关：它是网关安装内容的一部分，下一次网关安装（预检 → 确认 → 安装）之后开始记录"
		case !v.Runtime.Present:
			v.Runtime.Code, v.Runtime.Message = codeLinkLogNotRunning, "链路日志的采集服务已安装但没有运行：状态变化没有被记录（转发和故障切换不受影响）；在网关上查看 journalctl -u "+compile.LinkJournalUnit
		}
	}
	return v
}

func (s *Server) getLinkLog(w http.ResponseWriter, r *http.Request) {
	t, err := s.topology()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, s.linkLogViewOf(r.Context(), t))
}

// ------------------------------------------------------ current, events ---

// linkLogAnswerView is the envelope of the collector's answers.
type linkLogAnswerView struct {
	Available bool   `json:"available"`
	Code      string `json:"code,omitempty"`
	Message   string `json:"message,omitempty"`
	// Page: the collector's page of events, unchanged.
	Page json.RawMessage `json:"page,omitempty"`
	// Current: the collector's objects, unchanged; Summary what the page
	// shows on top of the timeline.
	Current json.RawMessage `json:"current,omitempty"`
	Summary *linkLogSummary `json:"summary,omitempty"`
}

// linkLogSummary is the state now in the page's terms.
type linkLogSummary struct {
	At time.Time `json:"at"`
	// Carrying: the path that carries now; Health the failover service's
	// last probe result of it (nil where the topology records none).
	Carrying *linkjournal.CurrentObject `json:"carrying,omitempty"`
	Health   *linkjournal.CurrentObject `json:"health,omitempty"`
	// Abnormal: every object in an abnormal state now, longest first.
	// Unknown: objects not read for longer than the gap threshold (their
	// state now is not known; State is the last one read). Flapping:
	// objects whose changes are being merged right now.
	Abnormal []linkjournal.CurrentObject `json:"abnormal"`
	Unknown  []linkjournal.CurrentObject `json:"unknown"`
	Flapping []linkjournal.CurrentObject `json:"flapping"`
	Objects  int                         `json:"objects"`
	// LastPass: the collector's last pass.
	LastPass *time.Time `json:"last_pass,omitempty"`
}

func summarizeLink(c linkjournal.Current) *linkLogSummary {
	sm := &linkLogSummary{At: c.At, Abnormal: []linkjournal.CurrentObject{}, Unknown: []linkjournal.CurrentObject{}, Flapping: []linkjournal.CurrentObject{}, Objects: len(c.Objects), LastPass: c.LastPass}
	for i := range c.Objects {
		o := c.Objects[i]
		switch {
		case o.Kind == linkjournal.KindUpstream:
			sm.Carrying = &o
		case o.Kind == linkjournal.KindHealth:
			sm.Health = &o
		}
		switch {
		case o.Stale:
			sm.Unknown = append(sm.Unknown, o)
		case o.Level == linkjournal.LevelAbnormal:
			sm.Abnormal = append(sm.Abnormal, o)
		}
		if o.Flapping != nil {
			sm.Flapping = append(sm.Flapping, o)
		}
	}
	return sm
}

func linkAnswer(v *linkLogAnswerView, ans hostexec.LinkJournalAnswer, err error) (json.RawMessage, int) {
	switch {
	case errors.Is(err, hostexec.ErrLinkJournalUnsupported):
		v.Code, v.Message = codeLinkLogAgentOld, err.Error()
	case errors.Is(err, hostexec.ErrUnavailable):
		v.Code, v.Message = codeLinkLogAgentUnavailable, err.Error()
	case err != nil:
		v.Code, v.Message = codeLinkLogReadFailed, err.Error()
	case ans.Code == "bad_request":
		v.Code, v.Message = ans.Code, ans.Error
		return nil, http.StatusBadRequest
	case ans.Code == "no_socket":
		v.Code, v.Message = codeLinkLogNotRunning, ans.Error
	case ans.Code != "":
		v.Code, v.Message = ans.Code, ans.Error
	default:
		v.Available = true
		return ans.Body, http.StatusOK
	}
	return nil, http.StatusOK
}

func (s *Server) getLinkLogCurrent(w http.ResponseWriter, r *http.Request) {
	if len(r.URL.Query()) > 0 {
		writeErr(w, http.StatusBadRequest, errors.New("这个请求不接受参数"))
		return
	}
	var v linkLogAnswerView
	if s.LinkLog == nil {
		v.Code, v.Message = codeLinkLogAgentUnavailable, "没有配置 host agent，读不到链路日志"
		writeJSON(w, http.StatusOK, v)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	ans, err := s.LinkLog.LinkJournalCurrent(ctx)
	body, _ := linkAnswer(&v, ans, err)
	if v.Available {
		var c linkjournal.Current
		if json.Unmarshal(body, &c) != nil {
			v.Available, v.Code, v.Message = false, codeLinkLogReadFailed, "链路日志采集服务的回答无法解析"
		} else {
			v.Current, v.Summary = body, summarizeLink(c)
		}
	}
	writeJSON(w, http.StatusOK, v)
}

func (s *Server) getLinkLogEvents(w http.ResponseWriter, r *http.Request) {
	q, err := linkjournal.QueryFrom(r.URL.Query())
	if err != nil {
		writeErr(w, http.StatusBadRequest, errors.New("查询条件不正确（class、kind、id、from、to、before、limit）："+err.Error()))
		return
	}
	var v linkLogAnswerView
	if s.LinkLog == nil {
		v.Code, v.Message = codeLinkLogAgentUnavailable, "没有配置 host agent，读不到链路日志"
		writeJSON(w, http.StatusOK, v)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	ans, err := s.LinkLog.LinkJournal(ctx, q)
	body, code := linkAnswer(&v, ans, err)
	if code != http.StatusOK {
		writeErr(w, code, errors.New(v.Message))
		return
	}
	v.Page = body
	writeJSON(w, http.StatusOK, v)
}

func (s *Server) postLinkLogClear(w http.ResponseWriter, r *http.Request) {
	var b struct {
		Confirm bool `json:"confirm"`
	}
	if err := decodeBody(w, r, &b); err != nil || !b.Confirm {
		writeErr(w, http.StatusBadRequest, errors.New("清空链路日志需要确认（confirm: true）"))
		return
	}
	if s.LinkLog == nil {
		writeErr(w, http.StatusServiceUnavailable, errors.New("没有配置 host agent，无法清空链路日志"))
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	ans, err := s.LinkLog.LinkJournalClear(ctx)
	var v linkLogAnswerView
	body, _ := linkAnswer(&v, ans, err)
	if !v.Available {
		writeErr(w, http.StatusServiceUnavailable, errors.New("链路日志没有清空："+v.Message))
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"cleared": body})
}

// ------------------------------------------------------ install pre-check ---

// linkLogPreflight adds the link journal's findings to a gateway pre-check.
// files are the gateway's compiled files (host paths); inst is what is
// installed now. On a gateway that was installed without the collector the
// first install with it is announced (what is added, that nothing else
// changes). When the host's meridian binary is older than the panel and has
// no collector, the install is blocked before anything is written: the
// collector's unit could not start and the whole install would be
// compensated.
func (s *Server) linkLogPreflight(ctx context.Context, files map[string]string, inst apply.Manifest, ev *preflight.Evaluation) {
	if _, ok := files["/etc/systemd/system/"+compile.LinkJournalUnit]; !ok {
		return
	}
	add := func(sev, code, msg, action string) {
		ev.Findings = append(ev.Findings, preflight.Finding{Severity: sev, Code: code, Resource: compile.LinkJournalUnit, Message: msg, Action: action})
		switch sev {
		case preflight.Blocking:
			ev.Counts.Blocking++
			ev.Blocking = true
		case preflight.Info:
			ev.Counts.Info++
		}
	}
	if s.LinkLog != nil {
		sctx, cancel := context.WithTimeout(ctx, 30*time.Second)
		_, err := s.LinkLog.LinkJournalStatus(sctx)
		cancel()
		if errors.Is(err, hostexec.ErrLinkJournalUnsupported) {
			add(preflight.Blocking, codeLinkLogBlocked, "网关宿主机上的 meridian 程序比面板旧，没有链路日志的采集服务：这次安装里的 "+compile.LinkJournalUnit+" 无法启动，安装会失败并回退",
				"在网关上重新运行 deploy/debian/install.sh 升级宿主程序，然后重新预检")
			return
		}
	}
	installed := false
	for _, u := range inst.Units {
		installed = installed || u == compile.LinkJournalUnit
	}
	if !installed && !inst.Empty() && !inst.Withdrawn() {
		add(preflight.Info, "link_log_add", "这次安装会新增链路日志的采集服务 "+compile.LinkJournalUnit+" 和它的对象清单 "+compile.LinkJournalConfigPath+
			"，验收脚本多一段检查；规则集、路由、隧道、解析器配置和故障切换脚本都不因它改变。采集服务只读网关本机的状态（故障切换记录、隧道握手、wstunnel 单元、嗅探自检），记录状态变化，不含任何流量内容；数据只在网关本机，最多 30 天、20000 条、16 MiB", "")
	}
}
