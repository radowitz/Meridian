package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"sort"
	"time"

	"github.com/radowitz/meridian/internal/hostexec"
	"github.com/radowitz/meridian/internal/model"
	"github.com/radowitz/meridian/internal/sniff"
	"github.com/radowitz/meridian/internal/validate"
)

// The name-sniffing forwarder (settings.sniff; compile/render_sniff.go,
// internal/sniff). GET /api/sniff: the setting, what it covers and what
// stays address-only, and the forwarder's health and bounded recent
// decisions read through the host agent's parameterless status read.
// PUT /api/sniff: the setting (saved into the topology like every
// setting; it takes effect with the next gateway install). The paths'
// diagnosis and POST /api/sniff/selfcheck: sniff_diag.go.
//
// The connection journal (sniff/journal.go; docs/architecture.md「设备连接
// 日志」), read only through the host agent's three fixed journal requests:
//
//	GET    /api/sniff/journal               one page (query: device, target,
//	                                        result, from, to, text, before,
//	                                        limit; validated, unknown refused)
//	GET    /api/sniff/devices               per-device summary (from, to) and
//	                                        the operator's labels
//	PUT    /api/sniff/devices/{addr}/label  set a device's label {"label"}
//	DELETE /api/sniff/devices/{addr}/label  remove it
//	POST   /api/sniff/journal/clear         {"confirm": true}: clear on the
//	                                        gateway
//
// Journal content passes through these handlers only: it is never stored by
// the panel, logged, or part of the topology, a snapshot, an export or a
// diagnosis. Labels are panel data under their own store key.

// SniffRuntime is the host agent's forwarder status read (hostexec.Client
// in main).
type SniffRuntime interface {
	SniffStatus(ctx context.Context) (hostexec.SniffStatus, error)
}

type sniffSettingView struct {
	Enabled        bool     `json:"enabled"`
	Ports          []int    `json:"ports"`
	ECHPublicNames []string `json:"ech_public_names"`
	RecordNames    bool     `json:"record_names"`
	// Configured: the stored values (nil fields mean the defaults).
	Configured *model.SniffSettings `json:"configured,omitempty"`
}

type sniffRuntimeView struct {
	Available bool            `json:"available"`
	Code      string          `json:"code,omitempty"`
	Message   string          `json:"message,omitempty"`
	Present   bool            `json:"present"`
	Active    string          `json:"active,omitempty"`
	Health    json.RawMessage `json:"health,omitempty"`
	Recent    json.RawMessage `json:"recent,omitempty"`
	ReadAt    string          `json:"read_at,omitempty"`
	// Diagnosis: are the running forwarder's paths usable (sniff_diag.go).
	Diagnosis *sniffDiagnosis `json:"diagnosis,omitempty"`
}

// sniffCoverage is the plain-language split the panel and the import
// preview show (docs/architecture.md「按域名嗅探的转发」).
var sniffCoverage = struct {
	ByName      []string `json:"by_name"`
	AddressOnly []string `json:"address_only"`
	Costs       []string `json:"costs"`
}{
	ByName: []string{
		"局域网和远程接入设备新建的 TCP 连接，目的端口在接管列表里（默认 80、443），并且客户端在 1 秒内发出了 TLS ClientHello 的 SNI 或 HTTP/1 的 Host：按名字在有序规则表里自上而下匹配（关键词规则按子串生效），再由目标自己的解析器重新解析后连接",
	},
	AddressOnly: []string{
		"所有 UDP，包括 QUIC（UDP 443 仍由「走隧道的流量拒绝 UDP 443」开关处理）",
		"不在接管列表里的 TCP 端口",
		"读不到名字的 TCP：没有 SNI、SNI 是地址、HTTP/2 明文前言、非 TLS/HTTP 协议、服务器先说话的协议、超时、畸形或超长",
		"带 ECH 且明文名字是已知 ECH 公共名（默认 cloudflare-ech.com）的连接：真名字被加密，按目的地址",
		"目的是本机、局域网、私有地址、远程接入地址池或已知 DoH 地址的连接（不接管）",
		"接管之前已经建立的连接（只接管新连接的第一个 SYN）",
		"读到了名字、但目标的解析器给不出地址的连接（名字不存在、没有可用地址、解析器全部失败或 3 秒内没有结果）：按目的地址和分类链的结果，不用名字规则的去向",
	},
	Costs: []string{
		"带 ECH 扩展、明文名字不在公共名列表里的连接按明文名字判断：浏览器发的 GREASE ECH 时这就是真名字；真正启用 ECH 而提供方的公共名不在列表里时，会按那个公共名分流（通常落到默认组）",
		"按名字判断的连接连接的是目标解析器给的地址，不是客户端自己解析到的地址",
		"所有被接管的连接经过网关上的用户态转发，占用网关的 CPU 和内存，并增加约一个往返的建立时延（服务器先说话的协议多等 1 秒）",
		"服务停止或崩溃时被接管的连接直接失败，不会回落到按地址的路径",
		"中继被淘汰时，转发服务已建立的连接不会像转发流量那样被立即重置，而是留在原中继上直到结束；新连接按新的权重分配",
	},
}

func sniffSetting(t model.Topology) sniffSettingView {
	s := t.Settings.Sniff
	v := sniffSettingView{Enabled: t.SniffOn(), Ports: s.EffectivePorts(), ECHPublicNames: s.EffectiveECHPublicNames(), Configured: s}
	if s != nil {
		v.RecordNames = s.RecordNames
	}
	return v
}

func (s *Server) getSniff(w http.ResponseWriter, r *http.Request) {
	t, err := s.topology()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	out := map[string]any{"setting": sniffSetting(t), "listen_port": validate.SniffListenPort, "coverage": sniffCoverage}
	rt := sniffRuntimeView{}
	switch {
	case s.Sniff == nil:
		rt.Code, rt.Message = "agent_unavailable", "没有配置 host agent，读不到嗅探服务的状态"
	default:
		ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
		defer cancel()
		st, err := s.Sniff.SniffStatus(ctx)
		switch {
		case err != nil && errors.Is(err, hostexec.ErrUnavailable):
			rt.Code, rt.Message = "agent_unavailable", err.Error()
		case err != nil:
			rt.Code, rt.Message = "read_failed", err.Error()
		default:
			rt.Available, rt.Present, rt.Active, rt.Health, rt.Recent, rt.ReadAt = true, st.Present, st.Active, st.Health, st.Recent, st.ReadAt
			if st.Present && st.Error == "" {
				rt.Diagnosis = sniffDiagnose(st)
			}
			switch {
			case st.Error != "":
				rt.Code, rt.Message = "read_failed", st.Error
			case !st.Present && t.SniffOn():
				rt.Code, rt.Message = "not_running", "嗅探服务没有运行（还没有按开启后的拓扑安装到网关，或服务已停止）：被接管的连接此时都会失败"
			case st.Present && !t.SniffOn():
				rt.Code, rt.Message = "not_configured", "网关上仍在运行嗅探服务，但当前拓扑已关闭它：下一次安装会移除"
			}
		}
	}
	out["runtime"] = rt
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) putSniff(w http.ResponseWriter, r *http.Request) {
	var b model.SniffSettings
	if err := decodeBody(w, r, &b); err != nil {
		writeErr(w, http.StatusBadRequest, errors.New("请求格式错误"))
		return
	}
	t, issues, err := s.saveTopologyChecked(func(t *model.Topology) error {
		v := b
		t.Settings.Sniff = &v
		return nil
	})
	if s.writeSaveErr(w, issues, err) {
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"setting": sniffSetting(t)})
}

// ------------------------------------------------------ connection journal ---

// SniffJournalRuntime is the host agent's journal requests (hostexec.Client
// in main implements it next to SniffRuntime; Server.Sniff is asked for it).
type SniffJournalRuntime interface {
	SniffJournal(ctx context.Context, q sniff.JournalQuery) (hostexec.SniffJournalAnswer, error)
	SniffJournalSummary(ctx context.Context, q sniff.JournalSummaryQuery) (hostexec.SniffJournalAnswer, error)
	SniffJournalClear(ctx context.Context) (hostexec.SniffJournalAnswer, error)
}

func (s *Server) sniffJournalRT() SniffJournalRuntime {
	if j, ok := s.Sniff.(SniffJournalRuntime); ok {
		return j
	}
	return nil
}

// sniffJournalScope is what the journal covers and what it does not, the
// bounds, where it lives and how names are handled: shown by the panel next
// to the log (docs/architecture.md「设备连接日志」).
var sniffJournalScope = struct {
	Covered    []string `json:"covered"`
	Lifecycle  []string `json:"lifecycle"`
	Results    []string `json:"results"`
	NotCovered []string `json:"not_covered"`
	Storage    []string `json:"storage"`
	NamesOn    []string `json:"names_on"`
	NamesOff   []string `json:"names_off"`
}{
	Covered: []string{
		"局域网和远程接入设备新建的、发往接管端口（默认 80、443）的 TCP 连接，也就是嗅探服务经手的每一条：开始时间、时长、来源地址（能取到时带 MAC）、原目的地址和端口、实际连接的地址、协议、判断依据（按名字 / 按地址及原因）、命中的规则、去向、结果、结束方式和原因、双向字节数（只有数量，没有内容）",
	},
	Lifecycle: []string{
		"每条连接在结束时写一条记录（拒绝、连接失败的立即结束；转发中的在任一方关闭、重置、空闲 2 小时或服务停止时结束），列表按结束时间排列，一条连接只算一次",
		"仍在转发的连接不在记录和统计里，显示在设备的「正在转发」中（每台设备最多列 50 条），结束后才成为一条记录",
		"嗅探服务正常停止或重启（例如安装新版本）时，仍打开的连接以「服务停止时中断」写入；被强行终止（kill、崩溃、断电）时这些连接没有记录，下次启动会提示一次，并给出当时（最近一分钟内）还开着的连接数",
	},
	Results: []string{
		"成功：上游连上并且至少有一个字节从上游回到客户端（之后怎样结束都算成功，结束方式另列）",
		"失败：解析失败、连接失败（附原因：超时 / 被拒绝 / 网络不可达 / 没有路由 / 被重置 / 地址族不可用 / 被本机拒绝 / 其它，以及最后尝试的地址）、连上后被重置或出错、连上后无回应（客户端发了数据但上游没有回任何字节就结束，包括空闲超时）、分类标记问题、服务停止时中断、其它",
		"不算失败：被规则拒绝（规则按设计拦下）、客户端关闭（还没判断就关闭，或连上后既没发数据也没收到数据就离开，例如预连接）、结束情况未知（旧版本在连上时就记为成功的记录）",
	},
	NotCovered: []string{
		"所有 UDP，包括 QUIC：不经过嗅探服务，没有按连接的记录",
		"不在接管列表里的 TCP 端口，以及不接管的目的地址（本机、局域网、私有地址、远程接入地址池、已知 DoH）",
		"嗅探关闭、嗅探服务停止期间的全部流量",
		"接管之前已经建立的连接",
		"DNS 查询：不在连接日志里。设备解析了哪些名字由单独的「解析日志」记录（默认关闭，需要明确打开）",
	},
	Storage: []string{
		"只存在网关本机 /var/lib/meridian-sniff（目录 0700、文件 0600，属嗅探服务账号）：只有 root 和嗅探服务自己能读，面板经宿主代理的固定只读请求查询",
		"保留最近 24 小时（按连接结束的时间）、最多 50000 条，连同轮转文件不超过 32 MiB；超出时删除最旧的；写不过来时丢弃日志条目并计数，从不影响连接",
		"不进入拓扑、快照、导出、诊断信息或面板自己的日志；关闭嗅探（下次安装移除嗅探服务）时整个日志目录随之删除",
		"「清空日志」立即删除网关上的全部记录（连同嗅探服务内存里最近结束的连接）；正在转发的连接不是记录，结束后照常写入",
	},
	NamesOn: []string{
		"已开启名字记录：每条记录还保存嗅探读到的名字（TLS 的 SNI、HTTP 的 Host，带 ECH 时是明文的外层名）",
		"名字与目的地址一起保留 24 小时（最多 50000 条），只在网关本机；随时可以「清空日志」",
		"关闭名字记录并安装后，嗅探服务重启时删掉日志里已有的全部名字，其余字段保留",
	},
	NamesOff: []string{
		"未记录名字：日志不保存任何名字（也不保存其散列），只有地址、端口和判断结果",
	},
}

type sniffJournalView struct {
	Available bool   `json:"available"`
	Code      string `json:"code,omitempty"`
	Message   string `json:"message,omitempty"`
	// Page / Summary: the forwarder's answer, unchanged.
	Page    json.RawMessage `json:"page,omitempty"`
	Summary json.RawMessage `json:"summary,omitempty"`
	// Labels are the operator's device labels (panel data).
	Labels []model.DeviceLabel `json:"labels"`
	// RecordNames is the topology's setting (what the next install
	// applies); the page / summary says what the running forwarder does.
	RecordNames bool `json:"record_names"`
	Scope       any  `json:"scope"`
}

// journalAnswer turns the agent's answer (or error) into the view's
// availability fields; it returns the body when there is one.
func journalAnswer(v *sniffJournalView, ans hostexec.SniffJournalAnswer, err error) (json.RawMessage, int) {
	switch {
	case err != nil && errors.Is(err, hostexec.ErrUnavailable):
		v.Code, v.Message = "agent_unavailable", err.Error()
	case err != nil:
		v.Code, v.Message = "read_failed", err.Error()
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

func (s *Server) journalBase() (sniffJournalView, SniffJournalRuntime, error) {
	v := sniffJournalView{Scope: sniffJournalScope, Labels: []model.DeviceLabel{}}
	t, err := s.topology()
	if err != nil {
		return v, nil, err
	}
	if t.Settings.Sniff != nil {
		v.RecordNames = t.Settings.Sniff.RecordNames
	}
	if ls, err := s.deviceLabels(); err == nil {
		v.Labels = ls
	}
	rt := s.sniffJournalRT()
	if rt == nil {
		v.Code, v.Message = "agent_unavailable", "没有配置 host agent，读不到嗅探服务的连接日志"
	}
	return v, rt, nil
}

func (s *Server) getSniffJournal(w http.ResponseWriter, r *http.Request) {
	q, err := sniff.JournalQueryFrom(r.URL.Query())
	if err != nil {
		writeErr(w, http.StatusBadRequest, errors.New("查询条件不正确："+err.Error()))
		return
	}
	v, rt, err := s.journalBase()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	if rt != nil {
		ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
		defer cancel()
		ans, err := rt.SniffJournal(ctx, q)
		body, code := journalAnswer(&v, ans, err)
		if code != http.StatusOK {
			writeErr(w, code, errors.New(v.Message))
			return
		}
		v.Page = body
	}
	writeJSON(w, http.StatusOK, v)
}

func (s *Server) getSniffDevices(w http.ResponseWriter, r *http.Request) {
	var q sniff.JournalSummaryQuery
	for k, vs := range r.URL.Query() {
		if len(vs) != 1 || (k != "from" && k != "to") {
			writeErr(w, http.StatusBadRequest, errors.New("参数只有 from、to"))
			return
		}
	}
	q.From, q.To = r.URL.Query().Get("from"), r.URL.Query().Get("to")
	if err := q.Validate(); err != nil {
		writeErr(w, http.StatusBadRequest, errors.New("时间范围不正确："+err.Error()))
		return
	}
	v, rt, err := s.journalBase()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	if rt != nil {
		ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
		defer cancel()
		ans, err := rt.SniffJournalSummary(ctx, q)
		body, code := journalAnswer(&v, ans, err)
		if code != http.StatusOK {
			writeErr(w, code, errors.New(v.Message))
			return
		}
		v.Summary = body
	}
	writeJSON(w, http.StatusOK, v)
}

func (s *Server) postSniffJournalClear(w http.ResponseWriter, r *http.Request) {
	var b struct {
		Confirm bool `json:"confirm"`
	}
	if err := decodeBody(w, r, &b); err != nil || !b.Confirm {
		writeErr(w, http.StatusBadRequest, errors.New("清空连接日志需要确认（confirm: true）"))
		return
	}
	rt := s.sniffJournalRT()
	if rt == nil {
		writeErr(w, http.StatusServiceUnavailable, errors.New("没有配置 host agent，无法清空连接日志"))
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	ans, err := rt.SniffJournalClear(ctx)
	v := sniffJournalView{}
	body, _ := journalAnswer(&v, ans, err)
	if !v.Available {
		writeErr(w, http.StatusServiceUnavailable, errors.New("连接日志没有清空："+v.Message))
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"cleared": body})
}

func (s *Server) postSniffDisconnect(w http.ResponseWriter, r *http.Request) {
	var b struct {
		Confirm bool `json:"confirm"`
	}
	if err := decodeBody(w, r, &b); err != nil || !b.Confirm {
		writeErr(w, http.StatusBadRequest, errors.New("断开所有连接需要确认"))
		return
	}
	rt, ok := s.Sniff.(interface {
		SniffDisconnect(context.Context) (hostexec.SniffJournalAnswer, error)
	})
	if !ok {
		writeErr(w, http.StatusServiceUnavailable, errors.New("宿主代理不支持断开连接"))
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	ans, err := rt.SniffDisconnect(ctx)
	v := sniffJournalView{}
	body, code := journalAnswer(&v, ans, err)
	if code != http.StatusOK || !v.Available {
		writeErr(w, http.StatusServiceUnavailable, errors.New("断开连接失败："+v.Message))
		return
	}
	writeJSON(w, http.StatusOK, body)
}

// deviceLabelsKey is the store key of the device labels.
const deviceLabelsKey = "sniff_device_labels"

func (s *Server) deviceLabels() ([]model.DeviceLabel, error) {
	raw, ok, err := s.Store.Get(deviceLabelsKey)
	if err != nil || !ok {
		return []model.DeviceLabel{}, err
	}
	var ls []model.DeviceLabel
	if err := json.Unmarshal([]byte(raw), &ls); err != nil {
		return []model.DeviceLabel{}, err
	}
	return ls, nil
}

func (s *Server) putDeviceLabel(w http.ResponseWriter, r *http.Request) {
	addr := model.NormDeviceAddress(r.PathValue("addr"))
	var b struct {
		Label string `json:"label"`
	}
	if err := decodeBody(w, r, &b); err != nil {
		writeErr(w, http.StatusBadRequest, errors.New("请求格式错误"))
		return
	}
	l := model.DeviceLabel{Address: addr, Label: b.Label, UpdatedAt: s.now().UTC().Format(time.RFC3339)}
	if addr == "" {
		writeErr(w, http.StatusBadRequest, errors.New("设备地址不是 IP 地址"))
		return
	}
	if err := l.Validate(); err != nil {
		writeErr(w, http.StatusUnprocessableEntity, err)
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	ls, err := s.deviceLabels()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	found := false
	for i := range ls {
		if ls[i].Address == addr {
			ls[i], found = l, true
		}
	}
	if !found {
		if len(ls) >= model.MaxDeviceLabels {
			writeErr(w, http.StatusUnprocessableEntity, errors.New("备注名已达上限，先删除一些"))
			return
		}
		ls = append(ls, l)
	}
	sort.Slice(ls, func(a, b int) bool { return ls[a].Address < ls[b].Address })
	raw, _ := json.Marshal(ls)
	if err := s.Store.Put(deviceLabelsKey, string(raw)); err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"label": l})
}

func (s *Server) deleteDeviceLabel(w http.ResponseWriter, r *http.Request) {
	addr := model.NormDeviceAddress(r.PathValue("addr"))
	if addr == "" {
		writeErr(w, http.StatusBadRequest, errors.New("设备地址不是 IP 地址"))
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	ls, err := s.deviceLabels()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	out := ls[:0]
	for _, l := range ls {
		if l.Address != addr {
			out = append(out, l)
		}
	}
	if len(out) == len(ls) {
		writeErr(w, http.StatusNotFound, errors.New("这个设备没有备注名"))
		return
	}
	raw, _ := json.Marshal(out)
	if err := s.Store.Put(deviceLabelsKey, string(raw)); err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
