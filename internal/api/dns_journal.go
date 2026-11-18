package api

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"net/netip"
	"strconv"
	"time"

	"github.com/radowitz/meridian/internal/apply"
	"github.com/radowitz/meridian/internal/compile"
	"github.com/radowitz/meridian/internal/dnsjournal"
	"github.com/radowitz/meridian/internal/hostexec"
	"github.com/radowitz/meridian/internal/model"
	"github.com/radowitz/meridian/internal/preflight"
	"github.com/radowitz/meridian/internal/sniff"
)

// The gateway's DNS query journal (settings.dns_log; internal/dnsjournal,
// docs/architecture.md「网关解析日志」), read only through the host agent's
// fixed requests:
//
//	GET  /api/dns-log                  the switch (planned and installed),
//	                                   the capability gate with its reason,
//	                                   the reader's state, scope and bounds
//	PUT  /api/dns-log                  {"enabled", "acknowledge"}: the switch.
//	                                   Enabling needs acknowledge:true and an
//	                                   available capability; it takes effect
//	                                   with the next gateway install
//	GET  /api/dns-log/journal          one page (query: device, mac, result,
//	                                   group, from, to, text, before, limit)
//	GET  /api/dns-log/devices          per-device summary (from, to) and the
//	                                   operator's device labels
//	POST /api/dns-log/clear            {"confirm": true}. 200 {"complete":
//	                                   true, …} only when everything went.
//	                                   A clear that left something is 500
//	                                   dns_log_clear_incomplete with
//	                                   "complete": false, "residual" (what
//	                                   is left, in counts) and "errors"
//	                                   (why, in fixed words); one that did
//	                                   nothing or cannot be confirmed is 503
//	GET  /api/dns-log/related          connections of the same device around
//	                                   a query (device, at, mac, window)
//	GET  /api/sniff/journal/related    queries of the same device around a
//	                                   connection (same parameters)
//
// Journal content passes through these handlers only: it is never stored by
// the panel, logged, or part of the topology, a snapshot, an export, a
// preflight or a diagnosis. Device labels are the connection journal's
// (sniff.go): one set for both journals.

// DNSLogRuntime is the host agent's query-journal requests (hostexec.Client
// in main).
type DNSLogRuntime interface {
	DNSJournalStatus(ctx context.Context) (hostexec.DNSJournalStatus, error)
	DNSJournal(ctx context.Context, q dnsjournal.Query) (hostexec.DNSJournalAnswer, error)
	DNSJournalSummary(ctx context.Context, q dnsjournal.SummaryQuery) (hostexec.DNSJournalAnswer, error)
	DNSJournalClear(ctx context.Context) (hostexec.DNSJournalAnswer, error)
}

// Codes of the capability beyond dnsjournal's own.
const (
	codeDNSLogAgentUnavailable = "agent_unavailable"
	codeDNSLogAgentOld         = "agent_old"
	codeDNSLogReadFailed       = "read_failed"
	// codeDNSLogUnavailable refuses PUT /api/dns-log {"enabled":true} (409);
	// codeDNSLogBlocked is the pre-check's blocking finding.
	codeDNSLogUnavailable = "dns_log_unavailable"
	codeDNSLogBlocked     = "dns_log_unavailable"
	// codeDNSLogClearIncomplete: POST /api/dns-log/clear removed part of the
	// data (500); codeDNSLogClearFailed: it removed nothing, or what it did
	// cannot be confirmed (503). codeDNSLogResidual is the runtime state
	// while the gateway still holds what a clear could not delete.
	codeDNSLogClearIncomplete = "dns_log_clear_incomplete"
	codeDNSLogClearFailed     = "dns_log_clear_failed"
	codeDNSLogResidual        = "clear_incomplete"
)

// dnsLogScope is what the journal records and what it does not, the bounds,
// where it lives and what the result classes mean: shown next to the log.
var dnsLogScope = struct {
	Covered    []string `json:"covered"`
	NotCovered []string `json:"not_covered"`
	Results    []string `json:"results"`
	Storage    []string `json:"storage"`
	Switch     []string `json:"switch"`
	Identity   []string `json:"identity"`
}{
	Covered: []string{
		"网关上的 SmartDNS 应答的查询，每条一行：时间、发起查询的设备的局域网地址（读到这一行时邻居表里有它时带 MAC）、查询的名字和类型、有没有应答、由哪个解析组应答、耗时、应答里的地址条数（不保存地址本身）",
		"同一个名字被客户端重试时会有多行（一次查询一行），这是正常的",
	},
	NotCovered: []string{
		"被网关解析器自己的规则直接回答的名字（例如屏蔽的 DoH 域名）：SmartDNS 不为它们写审计行，所以「被规则拦下」不在日志里，也不会被算成别的结果",
		"各出口节点上解析器的查询：这一轮只记录网关上的查询",
		"不经过网关解析器的查询：设备自己用的加密 DNS（DoH / DoT 到别处）、直接写死的地址",
		"解析日志关闭期间、以及解析日志服务停止期间解析器轮转掉的查询",
		"应答的具体地址、上游是哪一台服务器、应答码：审计行里没有应答码",
	},
	Results: []string{
		"有应答（answered）：这一行带至少一个应答地址",
		"无应答（no_answer）：没有地址，而且在 1.5 秒内返回。名字不存在（NXDOMAIN）是这样；名字存在但没有所问类型的记录、上游很快拒绝也是这样，审计行里没有应答码，分不开",
		"无应答且慢（no_answer_slow）：没有地址，耗时 1.5 秒以上。上游失败或超时是这样（观察到约 2 秒）；很慢的「不存在」也是这样，所以只能说「多半是失败或超时」",
		"被规则拦下的名字不产生任何记录（见上），不是其中任何一类",
	},
	Storage: []string{
		"只存在网关本机 /var/lib/meridian-dnslog（目录 0700、文件 0600，属 root）：只有 root 能读，面板经宿主代理的固定只读请求查询；不进入拓扑、快照、导出、预检、诊断信息或面板自己的日志",
		"保留最近 24 小时、最多 50000 条；解析器的审计文件及其轮转副本、交接队列和结构化日志合计不超过 32 MiB（审计一侧 8 MiB、队列 2 MiB（内存）、日志 22 MiB），先到的上限生效，超出时删最旧的",
		"写不过来时丢弃日志条目并计数，不影响解析；解析日志服务停止时解析照常，只是不记录",
		"「清空」立即删除网关上的全部记录、轮转副本和审计文件的内容",
	},
	Switch: []string{
		"默认关闭。日志的内容就是设备查询的名字，所以必须明确打开；打开和关闭都在下一次网关安装（预检 → 确认 → 安装）时生效，预检里能看到解析器配置和服务的差异",
		"打开时安装会重启一次网关解析器（解析中断约一两秒）；关闭时同样重启一次",
		"关闭并安装成功之后，网关上已有的记录全部删除；只保存了关闭、还没有安装（包括取消预检）时仍在记录",
		"只有核对过审计日志行为的 SmartDNS 版本才能打开：解析器容器的镜像标签是 latest，版本可能与核对过的不同，届时这里会说明原因和处理办法",
	},
	Identity: []string{
		"设备按局域网地址归并，与连接日志相同，备注名也共用同一套；MAC 是读到这一行时内核邻居表里的值",
		"地址可能被换给另一台设备：同一地址在时间范围内出现过不止一个 MAC 时会列出来；从一条记录跳到连接日志（或反过来）时按地址加前后各几分钟的时间窗查找，两边都有 MAC 且不同的记录被排除并计数",
		"MAC 未知（邻居表里没有、读到这一行时已经太晚、远程接入设备本来就没有 MAC）时只能按地址和时间窗关联，界面会标明「仅按地址」",
	},
}

type dnsLogCapabilityView struct {
	dnsjournal.Capability
	// Facts: what the gate judged (nil when the agent could not be asked).
	Facts *dnsjournal.Facts `json:"facts,omitempty"`
}

type dnsLogRuntimeView struct {
	Available      bool                  `json:"available"`
	Code           string                `json:"code,omitempty"`
	Message        string                `json:"message,omitempty"`
	AuditInstalled bool                  `json:"audit_installed"`
	UnitActive     string                `json:"unit_active,omitempty"`
	Present        bool                  `json:"present"`
	Health         json.RawMessage       `json:"health,omitempty"`
	Sink           *dnsjournal.SinkState `json:"sink,omitempty"`
	DataFiles      int                   `json:"data_files"`
	DataBytes      int64                 `json:"data_bytes"`
	ReadAt         string                `json:"read_at,omitempty"`
	// ClearResidual: what the running reader still holds of data whose
	// deletion failed (an unfinished clear, also after the reader was
	// restarted); nil: nothing.
	ClearResidual *dnsjournal.ClearResidual `json:"clear_residual,omitempty"`
}

// dnsLogResidual reads, from the reader's health, what a failed deletion
// left on the gateway (nil: nothing, or no health).
func dnsLogResidual(health json.RawMessage) *dnsjournal.ClearResidual {
	var h dnsjournal.Health
	if len(health) == 0 || json.Unmarshal(health, &h) != nil {
		return nil
	}
	var r dnsjournal.ClearResidual
	if j := h.Journal; j != nil && j.Residual != nil {
		r.Segments, r.Records, r.Bytes = j.Residual.Segments, j.Residual.Records, j.Residual.Bytes
	}
	if h.Reader.ClearPendingAt != nil {
		r.RawFiles, r.RawBytes = h.Reader.RawResidualFiles, h.Reader.RawResidualBytes
		r.Unknown = r.RawFiles == 0
	}
	if r == (dnsjournal.ClearResidual{}) {
		return nil
	}
	return &r
}

type dnsLogView struct {
	// Setting is the topology's switch (what the next install applies).
	Setting struct {
		Enabled bool `json:"enabled"`
	} `json:"setting"`
	// Installed is what the last gateway install put on the host (Known
	// false: the install record cannot be read).
	Installed struct {
		Known   bool `json:"known"`
		Enabled bool `json:"enabled"`
	} `json:"installed"`
	// Pending: "enable" or "disable" when the next gateway install changes
	// the collection, "" when setting and install agree.
	Pending    string               `json:"pending,omitempty"`
	Capability dnsLogCapabilityView `json:"capability"`
	Runtime    dnsLogRuntimeView    `json:"runtime"`
	Bounds     dnsLogBounds         `json:"bounds"`
	Scope      any                  `json:"scope"`
	// Groups names the resolver groups a record's "group" can hold; QTypes
	// the query types by number.
	Groups []compile.DNSLogGroup `json:"groups"`
	QTypes map[string]string     `json:"qtypes"`
}

type dnsLogBounds struct {
	MaxAgeS    int64             `json:"max_age_s"`
	MaxRecords int               `json:"max_records"`
	Budget     dnsjournal.Budget `json:"budget"`
	// DiskBytes is the worst case on disk (the queue is memory).
	DiskBytes    int64 `json:"disk_bytes"`
	SlowEmptyMS  int   `json:"slow_empty_ms"`
	RelatedMaxS  int   `json:"related_window_max_s"`
	RelatedDeflS int   `json:"related_window_default_s"`
}

func dnsLogBoundsNow() dnsLogBounds {
	b := dnsjournal.SplitBudget(dnsjournal.DefaultMaxBytes, dnsjournal.Queue)
	return dnsLogBounds{MaxAgeS: int64(dnsjournal.DefaultMaxAge / time.Second), MaxRecords: dnsjournal.DefaultMaxRecords, Budget: b,
		DiskBytes: b.Raw + b.Journal, SlowEmptyMS: dnsjournal.SlowEmptyMS, RelatedMaxS: relatedWindowMax, RelatedDeflS: relatedWindowDefault}
}

func dnsQTypes() map[string]string {
	out := make(map[string]string, len(dnsjournal.QTypeNames))
	for n, s := range dnsjournal.QTypeNames {
		out[strconv.Itoa(n)] = s
	}
	return out
}

// dnsLogInstalled: the last gateway install put the reader's unit on the
// host (known false when the install record cannot be read).
func (s *Server) dnsLogInstalled() (enabled, known bool) {
	m, err := s.applier(true).Installed()
	if err != nil {
		return false, false
	}
	for _, u := range m.Units {
		if u == compile.DNSJournalUnit {
			return true, true
		}
	}
	return false, true
}

// dnsLogStatus asks the agent and turns the answer (or the reason there is
// none) into the capability and runtime views.
func (s *Server) dnsLogStatus(ctx context.Context) (dnsLogCapabilityView, dnsLogRuntimeView) {
	var c dnsLogCapabilityView
	var rt dnsLogRuntimeView
	unavailable := func(code, msg, action string) (dnsLogCapabilityView, dnsLogRuntimeView) {
		c.Code, c.Reason, c.Action = code, msg, action
		rt.Code, rt.Message = code, msg
		return c, rt
	}
	if s.DNSLog == nil {
		return unavailable(codeDNSLogAgentUnavailable, "没有配置 host agent：读不到网关解析器的版本，解析日志保持不可用", "")
	}
	ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	st, err := s.DNSLog.DNSJournalStatus(ctx)
	switch {
	case errors.Is(err, hostexec.ErrDNSJournalUnsupported):
		return unavailable(codeDNSLogAgentOld, err.Error(), "在网关上重新运行 deploy/debian/install.sh")
	case errors.Is(err, hostexec.ErrUnavailable):
		return unavailable(codeDNSLogAgentUnavailable, "宿主执行通道不可用，读不到网关解析器的版本："+err.Error(), "")
	case err != nil:
		return unavailable(codeDNSLogReadFailed, "读不到网关解析器的状态："+err.Error(), "")
	}
	f := st.Facts
	c.Capability, c.Facts = st.Capability, &f
	sink := st.Sink
	rt = dnsLogRuntimeView{Available: true, AuditInstalled: st.AuditInstalled, UnitActive: st.UnitActive, Present: st.Present, Health: st.Health,
		Sink: &sink, DataFiles: st.DataFiles, DataBytes: st.DataBytes, ReadAt: st.ReadAt, ClearResidual: dnsLogResidual(st.Health)}
	if st.Error != "" {
		rt.Code, rt.Message = codeDNSLogReadFailed, st.Error
	}
	return c, rt
}

func (s *Server) dnsLogViewOf(ctx context.Context, t model.Topology) dnsLogView {
	v := dnsLogView{Scope: dnsLogScope, Bounds: dnsLogBoundsNow(), QTypes: dnsQTypes(), Groups: []compile.DNSLogGroup{}}
	v.Setting.Enabled = t.DNSLogOn()
	v.Installed.Enabled, v.Installed.Known = s.dnsLogInstalled()
	if v.Installed.Known && v.Installed.Enabled != v.Setting.Enabled {
		v.Pending = "disable"
		if v.Setting.Enabled {
			v.Pending = "enable"
		}
	}
	v.Capability, v.Runtime = s.dnsLogStatus(ctx)
	if v.Runtime.Available && v.Runtime.Code == "" {
		switch {
		case v.Installed.Enabled && !v.Runtime.Present:
			v.Runtime.Code, v.Runtime.Message = "not_running", "解析日志已安装，但解析日志服务没有运行：查询没有被记录（解析不受影响）"
		case v.Installed.Enabled && !v.Capability.Available:
			v.Runtime.Code, v.Runtime.Message = "unverified_running", "解析日志仍在记录，但网关解析器现在的版本没有核对过（"+v.Capability.Reason+"）：关闭解析日志并安装，或按提示核对这个版本"
		case !v.Installed.Enabled && v.Installed.Known && v.Runtime.DataBytes > 0:
			v.Runtime.Code, v.Runtime.Message = "leftover", "解析日志没有安装，但网关上还留有它的数据：用「清空」删除"
		case v.Runtime.ClearResidual != nil:
			v.Runtime.Code, v.Runtime.Message = codeDNSLogResidual, "网关上还留着没有删掉的解析日志数据（"+
				dnsjournal.ClearResult{Residual: v.Runtime.ClearResidual}.Problem()+"）：排除原因后用「清空」再删一次"
		}
	}
	if gs, err := compile.DNSLogGroups(t); err == nil {
		v.Groups = gs
	}
	return v
}

func (s *Server) getDNSLog(w http.ResponseWriter, r *http.Request) {
	t, err := s.topology()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, s.dnsLogViewOf(r.Context(), t))
}

func (s *Server) putDNSLog(w http.ResponseWriter, r *http.Request) {
	var b struct {
		Enabled     *bool `json:"enabled"`
		Acknowledge bool  `json:"acknowledge"`
	}
	if err := decodeBody(w, r, &b); err != nil || b.Enabled == nil {
		writeErr(w, http.StatusBadRequest, errors.New("请求格式错误：需要 enabled"))
		return
	}
	if *b.Enabled {
		if !b.Acknowledge {
			writeErr(w, http.StatusBadRequest, errors.New("打开解析日志需要确认（acknowledge: true）：它会在网关上保存每台设备查询的名字"))
			return
		}
		// The gate, before anything is saved: an unverified resolver keeps
		// the switch off.
		c, _ := s.dnsLogStatus(r.Context())
		if !c.Available {
			writeCoded(w, http.StatusConflict, codeDNSLogUnavailable, "解析日志不可用，没有保存："+c.Reason, map[string]any{"capability": c})
			return
		}
	}
	t, issues, err := s.saveTopologyChecked(func(t *model.Topology) error {
		if *b.Enabled {
			t.Settings.DNSLog = &model.DNSLogSettings{Enabled: true}
		} else {
			// Off is the absent setting: the document and the compiled
			// bundle are exactly those of a topology that never had it.
			t.Settings.DNSLog = nil
		}
		return nil
	})
	if s.writeSaveErr(w, issues, err) {
		return
	}
	writeJSON(w, http.StatusOK, s.dnsLogViewOf(r.Context(), t))
}

// ------------------------------------------------------------- journal ---

type dnsJournalView struct {
	Available bool   `json:"available"`
	Code      string `json:"code,omitempty"`
	Message   string `json:"message,omitempty"`
	// Page / Summary: the reader's answer, unchanged.
	Page    json.RawMessage `json:"page,omitempty"`
	Summary json.RawMessage `json:"summary,omitempty"`
	// Labels are the operator's device labels (panel data, shared with the
	// connection journal).
	Labels []model.DeviceLabel `json:"labels"`
	// Enabled is the topology's switch.
	Enabled bool                  `json:"enabled"`
	Groups  []compile.DNSLogGroup `json:"groups"`
}

func dnsAnswer(v *dnsJournalView, ans hostexec.DNSJournalAnswer, err error) (json.RawMessage, int) {
	switch {
	case errors.Is(err, hostexec.ErrDNSJournalUnsupported):
		v.Code, v.Message = codeDNSLogAgentOld, err.Error()
	case errors.Is(err, hostexec.ErrUnavailable):
		v.Code, v.Message = codeDNSLogAgentUnavailable, err.Error()
	case err != nil:
		v.Code, v.Message = codeDNSLogReadFailed, err.Error()
	case ans.Code == "bad_request":
		v.Code, v.Message = ans.Code, ans.Error
		return nil, http.StatusBadRequest
	case ans.Code != "":
		v.Code, v.Message = ans.Code, ans.Error
	default:
		v.Available = true
		return ans.Body, http.StatusOK
	}
	return nil, http.StatusOK
}

func (s *Server) dnsJournalBase() (dnsJournalView, error) {
	v := dnsJournalView{Labels: []model.DeviceLabel{}, Groups: []compile.DNSLogGroup{}}
	t, err := s.topology()
	if err != nil {
		return v, err
	}
	v.Enabled = t.DNSLogOn()
	if ls, err := s.deviceLabels(); err == nil {
		v.Labels = ls
	}
	if gs, err := compile.DNSLogGroups(t); err == nil {
		v.Groups = gs
	}
	if s.DNSLog == nil {
		v.Code, v.Message = codeDNSLogAgentUnavailable, "没有配置 host agent，读不到解析日志"
	}
	return v, nil
}

func (s *Server) getDNSJournal(w http.ResponseWriter, r *http.Request) {
	q, err := dnsjournal.QueryFrom(r.URL.Query())
	if err != nil {
		writeErr(w, http.StatusBadRequest, errors.New("查询条件不正确："+err.Error()))
		return
	}
	v, err := s.dnsJournalBase()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	if s.DNSLog != nil {
		ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
		defer cancel()
		ans, err := s.DNSLog.DNSJournal(ctx, q)
		body, code := dnsAnswer(&v, ans, err)
		if code != http.StatusOK {
			writeErr(w, code, errors.New(v.Message))
			return
		}
		v.Page = body
	}
	writeJSON(w, http.StatusOK, v)
}

func (s *Server) getDNSDevices(w http.ResponseWriter, r *http.Request) {
	q, err := dnsjournal.SummaryQueryFrom(r.URL.Query())
	if err != nil {
		writeErr(w, http.StatusBadRequest, errors.New("参数只有 from、to（RFC 3339 时间）"))
		return
	}
	v, err := s.dnsJournalBase()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	if s.DNSLog != nil {
		ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
		defer cancel()
		ans, err := s.DNSLog.DNSJournalSummary(ctx, q)
		body, code := dnsAnswer(&v, ans, err)
		if code != http.StatusOK {
			writeErr(w, code, errors.New(v.Message))
			return
		}
		v.Summary = body
	}
	writeJSON(w, http.StatusOK, v)
}

func (s *Server) postDNSLogClear(w http.ResponseWriter, r *http.Request) {
	var b struct {
		Confirm bool `json:"confirm"`
	}
	if err := decodeBody(w, r, &b); err != nil || !b.Confirm {
		writeErr(w, http.StatusBadRequest, errors.New("清空解析日志需要确认（confirm: true）"))
		return
	}
	if s.DNSLog == nil {
		writeErr(w, http.StatusServiceUnavailable, errors.New("没有配置 host agent，无法清空解析日志"))
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	ans, err := s.DNSLog.DNSJournalClear(ctx)
	v := dnsJournalView{}
	body, _ := dnsAnswer(&v, ans, err)
	switch {
	case v.Available:
		writeJSON(w, http.StatusOK, map[string]any{"complete": true, "cleared": body})
	case v.Code == hostexec.DNSClearIncomplete:
		// Part of it went: say what is left (counts) and why (fixed words),
		// so the page can keep the residue in view and offer the retry.
		var res dnsjournal.ClearResult
		_ = json.Unmarshal(ans.Body, &res)
		residual := res.Residual
		if residual == nil {
			residual = &dnsjournal.ClearResidual{Unknown: true}
		}
		errs := res.Errors
		if errs == nil {
			errs = []dnsjournal.ClearError{}
		}
		writeCoded(w, http.StatusInternalServerError, codeDNSLogClearIncomplete, v.Message, map[string]any{
			"complete": false, "residual": residual, "errors": errs,
			"removed": map[string]any{"records": res.Cleared, "raw_bytes": res.RawBytes, "files": res.PurgedFiles, "bytes": res.PurgedBytes}})
	default:
		writeCoded(w, http.StatusServiceUnavailable, codeDNSLogClearFailed, "解析日志没有清空："+v.Message, map[string]any{"complete": false})
	}
}

// ------------------------------------------------------- cross-linking ---

// Bounds of a related lookup's time window (seconds on each side).
const (
	relatedWindowDefault = 120
	relatedWindowMax     = 600
	relatedLimit         = 100
)

// relatedQuery is the validated request of both related lookups.
type relatedQuery struct {
	device   string
	mac      string
	at       time.Time
	window   int
	from, to string
}

func parseRelated(r *http.Request) (relatedQuery, error) {
	var q relatedQuery
	v := r.URL.Query()
	for k, vs := range v {
		if len(vs) != 1 || (k != "device" && k != "at" && k != "mac" && k != "window") {
			return q, errors.New("参数只有 device、at、mac、window，各一个")
		}
	}
	a, err := netip.ParseAddr(v.Get("device"))
	if err != nil || a.Zone() != "" {
		return q, errors.New("device：需要设备的 IP 地址")
	}
	q.device = a.Unmap().String()
	if q.at, err = time.Parse(time.RFC3339, v.Get("at")); err != nil {
		return q, errors.New("at：需要 RFC 3339 时间")
	}
	if m := v.Get("mac"); m != "" {
		if q.mac = dnsjournal.NormMAC(m); q.mac == "" {
			return q, errors.New("mac：不是 MAC 地址")
		}
	}
	q.window = relatedWindowDefault
	if w := v.Get("window"); w != "" {
		n, err := strconv.Atoi(w)
		if err != nil || n < 1 || n > relatedWindowMax {
			return q, errors.New("window：1 到 " + strconv.Itoa(relatedWindowMax) + " 秒")
		}
		q.window = n
	}
	d := time.Duration(q.window) * time.Second
	q.from, q.to = q.at.Add(-d).UTC().Format(time.RFC3339), q.at.Add(d).UTC().Format(time.RFC3339)
	return q, nil
}

// relatedView is the answer of a related lookup. The device is an address
// (the identity both journals use); the MAC, when the caller's record has
// one, decides which of the address's records belong to the same device.
type relatedView struct {
	Available bool   `json:"available"`
	Code      string `json:"code,omitempty"`
	Message   string `json:"message,omitempty"`
	Device    string `json:"device"`
	MAC       string `json:"mac,omitempty"`
	From      string `json:"from"`
	To        string `json:"to"`
	WindowS   int    `json:"window_s"`
	// Identity: "mac" (every listed record carries the asked MAC),
	// "address" (no MAC to compare: the caller gave none, or no listed
	// record carries one) or "partial" (some listed records carry the MAC,
	// some carry none).
	Identity string `json:"identity"`
	// Listed records; OtherMAC records of the same address left out because
	// they carry another MAC (the address was used by another device);
	// NoMAC listed records without a MAC; More: the window held more than
	// the listed records.
	Records  any  `json:"records"`
	Listed   int  `json:"listed"`
	OtherMAC int  `json:"other_mac"`
	NoMAC    int  `json:"no_mac"`
	More     bool `json:"more"`
	// RecordNames (connections only): the forwarder records names.
	RecordNames *bool `json:"record_names,omitempty"`
}

func newRelatedView(q relatedQuery) relatedView {
	return relatedView{Device: q.device, MAC: q.mac, From: q.from, To: q.to, WindowS: q.window, Identity: "address"}
}

// keepByMAC decides one record of the asked address: kept unless it carries
// another MAC than the asked one.
func (v *relatedView) keepByMAC(asked, got string) bool {
	switch {
	case got == "":
		v.NoMAC++
	case asked != "" && got != asked:
		v.OtherMAC++
		return false
	}
	return true
}

func (v *relatedView) finish(asked string, listed int) {
	v.Listed = listed
	switch {
	case asked == "" || listed == v.NoMAC:
		v.Identity = "address"
	case v.NoMAC == 0:
		v.Identity = "mac"
	default:
		v.Identity = "partial"
	}
}

// getDNSLogRelated: the connections of the same device around a query.
func (s *Server) getDNSLogRelated(w http.ResponseWriter, r *http.Request) {
	q, err := parseRelated(r)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	v := newRelatedView(q)
	v.Records = []sniff.JournalRecord{}
	rt := s.sniffJournalRT()
	if rt == nil {
		v.Code, v.Message = "agent_unavailable", "没有配置 host agent，读不到连接日志"
		writeJSON(w, http.StatusOK, v)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	ans, err := rt.SniffJournal(ctx, sniff.JournalQuery{Device: q.device, From: q.from, To: q.to, Limit: relatedLimit})
	jv := sniffJournalView{}
	body, code := journalAnswer(&jv, ans, err)
	if code != http.StatusOK {
		writeErr(w, code, errors.New(jv.Message))
		return
	}
	v.Available, v.Code, v.Message = jv.Available, jv.Code, jv.Message
	if jv.Available {
		var page sniff.JournalPage
		if json.Unmarshal(body, &page) != nil {
			v.Available, v.Code, v.Message = false, "read_failed", "连接日志的回答无法解析"
		} else {
			out := []sniff.JournalRecord{}
			for _, rec := range page.Records {
				if v.keepByMAC(q.mac, dnsjournal.NormMAC(rec.MAC)) {
					out = append(out, rec)
				}
			}
			v.Records, v.More, v.RecordNames = out, page.NextBefore != 0, &page.RecordNames
			v.finish(q.mac, len(out))
		}
	}
	writeJSON(w, http.StatusOK, v)
}

// getSniffJournalRelated: the queries of the same device around a
// connection.
func (s *Server) getSniffJournalRelated(w http.ResponseWriter, r *http.Request) {
	q, err := parseRelated(r)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	v := newRelatedView(q)
	v.Records = []dnsjournal.Record{}
	if s.DNSLog == nil {
		v.Code, v.Message = codeDNSLogAgentUnavailable, "没有配置 host agent，读不到解析日志"
		writeJSON(w, http.StatusOK, v)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	ans, err := s.DNSLog.DNSJournal(ctx, dnsjournal.Query{Device: q.device, From: q.from, To: q.to, Limit: relatedLimit})
	jv := dnsJournalView{}
	body, code := dnsAnswer(&jv, ans, err)
	if code != http.StatusOK {
		writeErr(w, code, errors.New(jv.Message))
		return
	}
	v.Available, v.Code, v.Message = jv.Available, jv.Code, jv.Message
	if jv.Available {
		var page dnsjournal.Page
		if json.Unmarshal(body, &page) != nil {
			v.Available, v.Code, v.Message = false, codeDNSLogReadFailed, "解析日志的回答无法解析"
		} else {
			out := []dnsjournal.Record{}
			for _, rec := range page.Records {
				if v.keepByMAC(q.mac, rec.MAC) {
					out = append(out, rec)
				}
			}
			v.Records, v.More = out, page.NextBefore != 0
			v.finish(q.mac, len(out))
		}
	}
	writeJSON(w, http.StatusOK, v)
}

// ------------------------------------------------ install: gate and end ---

// dnsLogPreflight adds the query journal's findings to a gateway pre-check:
// files are the gateway's compiled files (host paths). When they turn the
// audit log on, the capability gate is asked again; an unavailable
// capability blocks the install, with the reason. Turning the journal on
// or off is announced, with what happens to the resolver and the records.
func (s *Server) dnsLogPreflight(ctx context.Context, files map[string]string, ev *preflight.Evaluation) {
	on := compile.SmartDNSAuditOn(files["/etc/smartdns/smartdns.conf"])
	installed, known := s.dnsLogInstalled()
	add := func(sev, code, msg, action string) {
		ev.Findings = append(ev.Findings, preflight.Finding{Severity: sev, Code: code, Resource: compile.DNSJournalUnit, Message: msg, Action: action})
		switch sev {
		case preflight.Blocking:
			ev.Counts.Blocking++
			ev.Blocking = true
		case preflight.Info:
			ev.Counts.Info++
		}
	}
	switch {
	case on:
		c, _ := s.dnsLogStatus(ctx)
		if !c.Available {
			action := c.Action
			if action != "" {
				action += "；"
			}
			add(preflight.Blocking, codeDNSLogBlocked, "解析日志已打开，但不能安装："+c.Reason, action+"或者先关闭解析日志（解析日志页的开关）再安装")
			return
		}
		if !installed {
			add(preflight.Info, "dns_log_enable", "这次安装会打开解析日志：网关解析器的配置增加审计日志（写入 "+dnsjournal.AuditFile+"），新增 "+compile.DNSJournalUnit+
				"；网关解析器会重启一次（解析中断约一两秒）。之后网关本机保存每台设备查询的名字，最多 24 小时、50000 条、32 MiB（SmartDNS "+c.Version+"，审计行为于 "+c.VerifiedOn+" 核对）", "")
		}
	case known && installed:
		add(preflight.Info, "dns_log_disable", "这次安装会关闭解析日志：网关解析器的配置去掉审计日志并重启一次，移除 "+compile.DNSJournalUnit+
			"；安装成功之后删除网关上已有的全部解析记录。取消这次预检或安装失败时继续记录、记录保留", "")
	}
}

// dnsLogAfterCommit runs after a host transaction: when it committed and
// removed the reader's unit (the journal was turned off), the records on
// the gateway are deleted now — not earlier, so a failed or compensated
// install keeps them. It returns a warning when the deletion did not
// happen (nothing of the journal's content is in it).
func (s *Server) dnsLogAfterCommit(rep *apply.HostReport) string {
	if rep == nil || !rep.Committed || s.DNSLog == nil {
		return ""
	}
	removed := false
	for _, u := range rep.Diff.UnitsRemoved {
		removed = removed || u == compile.DNSJournalUnit
	}
	if !removed {
		return ""
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	ans, err := s.DNSLog.DNSJournalClear(ctx)
	v := dnsJournalView{}
	dnsAnswer(&v, ans, err)
	if v.Available {
		return ""
	}
	msg := "解析日志已关闭并停止记录，但网关上已有的记录没有删除（" + v.Message + "）：在解析日志页用「清空」删除"
	log.Printf("dns query journal: records not deleted after the journal was turned off (%s)", v.Code)
	rep.Warnings = append(rep.Warnings, msg)
	return msg
}
