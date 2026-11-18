package api

import (
	"context"
	"time"

	"github.com/radowitz/meridian/internal/hostexec"
	"github.com/radowitz/meridian/internal/model"
	"github.com/radowitz/meridian/internal/pathquality"
)

// Relay sharing in the panel (docs/architecture.md「多中继同时分担」). The
// gateway measures and decides; its controller writes everything into the
// upstream record, which meridian-host reads with its fixed parameterless
// read. The panel only shows it, keeping what the gateway measured apart
// from what the panel estimates (the probe traffic cost, from the
// topology's settings).

// sharingView is the relay-sharing part of GET /api/upstream.
type sharingView struct {
	// Known: a fresh relay-sharing record was read from the gateway.
	Known   bool   `json:"known"`
	Code    string `json:"code,omitempty"`
	Message string `json:"message,omitempty"`
	// Controller: go (path-step decided) or shell (the fallback: equal
	// weights, reachability only).
	Controller string         `json:"controller,omitempty"`
	Alert      string         `json:"alert,omitempty"`
	AlertText  string         `json:"alert_text,omitempty"`
	Path       string         `json:"path,omitempty"` // main | backup
	Designated string         `json:"designated,omitempty"`
	Switched   *time.Time     `json:"switched,omitempty"`
	Beat       *time.Time     `json:"beat,omitempty"`
	Relays     []sharingRelay `json:"relays"`
	Backup     *sharingBackup `json:"backup,omitempty"`
	// BackupGroup: the backup hub reached through relays (the backup
	// group; the other relays are the main group). Nil otherwise.
	BackupGroup *sharingGroup `json:"backup_group,omitempty"`
	// Settings are the effective thresholds of the topology (what the
	// next install compiles; the gateway runs what was last installed).
	Settings model.PathQuality `json:"settings"`
	// ProbeCost is estimated, not measured.
	ProbeCost probeCost `json:"probe_cost"`
	// SpeedTestCost estimates the speed tests' traffic per relay and day.
	SpeedTestCost speedTestCost `json:"speed_test_cost"`
	// EvictionImpact says what happens to existing connections.
	EvictionImpact string `json:"eviction_impact"`
}

// sharingRelay is one relay as the gateway recorded it.
type sharingRelay struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	// Group: main | backup with a backup group, empty otherwise.
	Group       string     `json:"group,omitempty"`
	Iface       string     `json:"iface,omitempty"`
	Status      string     `json:"status"`
	InSet       bool       `json:"in_set"`
	Weight      int        `json:"weight"` // of 1000 new connections
	Drain       bool       `json:"drain"`
	Reason      string     `json:"reason,omitempty"`
	StatusSince *time.Time `json:"status_since,omitempty"`
	Grade       string     `json:"grade"`
	Suspicious  string     `json:"suspicious,omitempty"`
	// Measured by the gateway (nil: not measured).
	Measured *pathMeasured `json:"measured,omitempty"`
	Traffic  pathTraffic   `json:"traffic"`
	Probe    *probeResult  `json:"probe,omitempty"`
	// Speed is the speed tests' QoS verdict and the last valid test (nil:
	// the gateway's record predates the speed tests).
	Speed *speedResult `json:"speed,omitempty"`
}

// speedResult is one relay's download speed test as the gateway recorded it.
type speedResult struct {
	// QoS: ok | throttled | unknown (no valid test yet) | off.
	QoS string `json:"qos"`
	// Mbps / At / AgeSec: the last valid test (nil: none).
	Mbps   *float64   `json:"mbps,omitempty"`
	At     *time.Time `json:"at,omitempty"`
	AgeSec *int64     `json:"age_sec,omitempty"`
	// BaselineMbps and its source: p90 (of the valid tests in the window)
	// or nominal (too few tests yet).
	BaselineMbps float64 `json:"baseline_mbps"`
	BaselineSrc  string  `json:"baseline_src,omitempty"`
	// ThresholdMbps / RecoverMbps: below the first twice in a row is
	// throttled; one test at or above the second recovers (from settings).
	ThresholdMbps float64 `json:"threshold_mbps"`
	RecoverMbps   float64 `json:"recover_mbps"`
}

type pathMeasured struct {
	// RTTms / LossPct: averaged (EWMA over passes); Last*: the last pass.
	RTTms       *float64   `json:"rtt_ms,omitempty"`
	LossPct     *float64   `json:"loss_pct,omitempty"`
	LastRTTms   *float64   `json:"last_rtt_ms,omitempty"`
	LastLossPct *float64   `json:"last_loss_pct,omitempty"`
	At          *time.Time `json:"at,omitempty"`
}

type pathTraffic struct {
	RxBytes  int64 `json:"rx_bytes"`
	TxBytes  int64 `json:"tx_bytes"`
	RxBps    int64 `json:"rx_bps"`
	TxBps    int64 `json:"tx_bps"`
	NewConns int64 `json:"new_conns"`
}

type probeResult struct {
	At         *time.Time `json:"at,omitempty"`
	Kbps       *int64     `json:"kbps,omitempty"`
	LossPct    *float64   `json:"loss_pct,omitempty"`
	OK         *bool      `json:"ok,omitempty"`
	BytesToday int64      `json:"bytes_today"`
}

// sharingGroup is the backup group: its hub and relays (IDs, config order).
type sharingGroup struct {
	Hub    string   `json:"hub"`
	Name   string   `json:"name"`
	Relays []string `json:"relays"`
}

type sharingBackup struct {
	Hub      string        `json:"hub"`
	Name     string        `json:"name"`
	Iface    string        `json:"iface"`
	Grade    string        `json:"grade"`
	Drain    bool          `json:"drain"`
	Measured *pathMeasured `json:"measured,omitempty"`
	Traffic  pathTraffic   `json:"traffic"`
}

// probeCost is the throughput probes' billed traffic, estimated from the
// settings: one probe, and the most a relay can use per day.
type probeCost struct {
	Enabled          bool   `json:"enabled"`
	BytesPerProbe    int64  `json:"bytes_per_probe"`
	MinIntervalSec   int    `json:"min_interval_sec"`
	MaxProbesPerDay  int64  `json:"max_probes_per_day"`
	MaxBytesPerDay   int64  `json:"max_bytes_per_day"`
	DailyBudgetBytes int64  `json:"daily_budget_bytes"`
	Source           string `json:"source"` // estimated
	Trigger          string `json:"trigger"`
}

// speedTestCost is the download speed tests' traffic, estimated from the
// settings (one test downloads speed_test_mb MiB through the relay).
type speedTestCost struct {
	Enabled      bool   `json:"enabled"`
	BytesPerTest int64  `json:"bytes_per_test"`
	IntervalSec  int    `json:"interval_sec"`
	TestsPerDay  int64  `json:"tests_per_day"`
	BytesPerDay  int64  `json:"bytes_per_day"`
	Source       string `json:"source"` // estimated
}

func estimateSpeedTestCost(pq model.PathQuality) speedTestCost {
	c := speedTestCost{Enabled: !pq.SpeedTestOff, BytesPerTest: int64(pq.SpeedTestMB) << 20, IntervalSec: pq.SpeedTestIntervalSec, Source: "estimated"}
	if c.Enabled && pq.SpeedTestIntervalSec > 0 {
		c.TestsPerDay = int64(86400 / pq.SpeedTestIntervalSec)
		c.BytesPerDay = c.TestsPerDay * c.BytesPerTest
	}
	return c
}

func estimateProbeCost(pq model.PathQuality) probeCost {
	per := pathquality.ProbeCostEstimate(pq)
	budget := int64(pq.ProbeDailyBudgetMB) * 1024 * 1024
	n := int64(86400 / pq.ProbeMinIntervalSec)
	if per > 0 && budget/per < n {
		n = budget / per
	}
	c := probeCost{Enabled: !pq.ProbeOff, BytesPerProbe: per, MinIntervalSec: pq.ProbeMinIntervalSec, MaxProbesPerDay: n, MaxBytesPerDay: n * per, DailyBudgetBytes: budget, Source: "estimated",
		Trigger: "只在该中继有业务流量、且被动信号可疑（丢包或时延轻度升高、负载下时延膨胀、单位权重的下行量远低于其他中继）时触发；因吞吐不足被剔除的中继在重新加入前也要先通过一次探测。"}
	if pq.ProbeOff {
		c.MaxProbesPerDay, c.MaxBytesPerDay = 0, 0
	}
	return c
}

func evictionImpact(pq model.PathQuality) string {
	if pq.KeepConnectionsOnEvict {
		return "剔除只停止向该中继分配新连接；已在它上面的连接保留（若该中继已经不通，这些连接会卡到应用自己超时）。降权和恢复都不迁移已有连接。"
	}
	return "剔除时，该中继上已有的 TCP 连接会被网关重置（应用会立刻在健康的中继上重连），其他流（UDP/QUIC 等）在下一个包改走分担集合里的中继；轻度劣化的降权、停止分配和恢复都不迁移已有连接。"
}

var alertTexts = map[string]string{
	pathquality.AlertAllPoor:           "所有中继都低于可用下限：保留最好且仍可达的一台独占承载（retained_best），全部完全不通才切备用枢纽",
	pathquality.AlertBackupNotBetter:   "所有中继都低于可用下限，备用枢纽也不比它们好：留在相对较好的中继上，不来回切换",
	pathquality.AlertBackupUnusable:    "所有中继都低于可用下限，备用枢纽也不可用：留在相对较好的中继上",
	pathquality.AlertAllThrottled:      "所有可达的中继都被测速判定为限速（qos_throttled）：保留最近一次测速最好的一台独占承载，不切备用枢纽",
	pathquality.AlertNothingReachable:  "没有任何路径应答：流量停在隧道里被丢弃，不会从局域网口直出",
	pathquality.AlertOnBackup:          "所有中继的每条腿都完全不通（all_relays_down），正由备用枢纽承载",
	pathquality.AlertOnBackupReturning: "备用枢纽承载中，已有中继重新应答：连续 3 轮（约 15 秒）可达且距上次切换满最短间隔即切回主链路，不要求质量良好（relay_reachable）",
	"controller_unavailable":           "网关上的控制程序（meridian path-step）不可用：本轮按应急规则运行（可达的中继平均分担，只按通断剔除）",
	"apply_failed":                     "切换未能完整应用，已恢复到上一次成功的路径；自动切换暂停，退避后最多重试 3 次",
	"recovery_blocked":                 "切换失败且无法恢复上一次成功的路径：转发已被拦截（管理 SSH 除外），承载未知；需重新安装网关后恢复",
	"config_changed":                   "网关配置与上一次成功切换的版本不一致：自动切换已阻断，需重新安装网关",
	"install_failed":                   "网关安装未完成：转发已被拦截（管理 SSH 除外），需重新安装",
	"guard_failed":                     "无法建立切换保护：自动切换已阻断，需重新安装网关",
}

// groupAlertTexts replace alertTexts with a backup group.
var groupAlertTexts = map[string]string{
	pathquality.AlertOnBackup:          "主组中继的每条腿都完全不通，正由备用组经中继承载到备用枢纽",
	pathquality.AlertOnBackupReturning: "备用组承载中，主组已有中继重新应答：连续 3 轮可达且距上次切换满 120 秒即切回主组",
}

func beatFresh(rec *hostexec.UpstreamState) bool {
	return time.Since(time.Unix(rec.Beat, 0)) <= upstreamFresh
}

func tsp(epoch int64) *time.Time {
	if epoch <= 0 {
		return nil
	}
	t := time.Unix(epoch, 0).UTC()
	return &t
}

func msp(us *int64) *float64 {
	if us == nil {
		return nil
	}
	v := float64(*us) / 1000
	return &v
}

func pctp(permille *int64) *float64 {
	if permille == nil {
		return nil
	}
	v := float64(*permille) / 10
	return &v
}

func baseSharing(t model.Topology) *sharingView {
	pq := t.Settings.PathQuality.Effective()
	v := &sharingView{Settings: pq, ProbeCost: estimateProbeCost(pq), SpeedTestCost: estimateSpeedTestCost(pq), EvictionImpact: evictionImpact(pq), Relays: []sharingRelay{}}
	grouped := t.RelayBackup()
	for _, r := range t.SharingRelays() {
		sr := sharingRelay{ID: r.ID, Name: r.Name, Status: "unknown", Grade: "none"}
		if grouped {
			sr.Group = t.RelayGroupOf(r.ID)
		}
		v.Relays = append(v.Relays, sr)
	}
	if grouped {
		h, _ := t.BackupHub()
		g := &sharingGroup{Hub: h.ID, Name: h.Name}
		for _, r := range t.BackupGroupRelays() {
			g.Relays = append(g.Relays, r.ID)
		}
		v.BackupGroup = g
	}
	return v
}

func sharingFromRecord(t model.Topology, rec *hostexec.UpstreamState, fresh bool) *sharingView {
	v := baseSharing(t)
	names := map[string]string{}
	for _, r := range t.SharingRelays() {
		names[r.ID] = r.Name
	}
	v.Controller, v.Alert, v.Path, v.Designated = rec.Controller, rec.Alert, rec.Path, rec.Designated
	v.AlertText = alertTexts[rec.Alert]
	if rec.BackupGroup != nil && groupAlertTexts[rec.Alert] != "" {
		v.AlertText = groupAlertTexts[rec.Alert]
	}
	v.Switched, v.Beat = tsp(rec.Switched), tsp(rec.Beat)
	v.Known = fresh
	if !fresh {
		v.Code, v.Message = "stale", "网关的中继记录已超过 60 秒没有更新（切换服务可能没有运行）"
	}
	v.Relays = v.Relays[:0]
	for _, r := range rec.Relays {
		name, ok := names[r.ID]
		if !ok {
			v.Code, v.Message, v.Known = "record_mismatch", "网关记录里的中继 "+r.ID+" 不在当前拓扑里：网关还没有按当前拓扑安装", false
			name = r.ID
		}
		sr := sharingRelay{ID: r.ID, Name: name, Iface: r.Iface, Status: r.Status, Weight: r.Weight, Drain: r.Drain, Reason: r.Reason,
			StatusSince: tsp(r.StatusSince), Grade: r.Grade, Suspicious: r.Suspicious,
			Group:   r.Group,
			InSet:   r.Weight > 0 && (rec.Path == "main" || rec.BackupGroup != nil),
			Traffic: pathTraffic{RxBytes: r.RxBytes, TxBytes: r.TxBytes, RxBps: r.RxBps, TxBps: r.TxBps, NewConns: r.NewConns}}
		if r.MeasuredAt > 0 {
			sr.Measured = &pathMeasured{RTTms: msp(r.RTTus), LossPct: pctp(r.LossPermille), LastRTTms: msp(r.LastRTTus), LastLossPct: pctp(r.LastLoss), At: tsp(r.MeasuredAt)}
		}
		if r.ProbeAt > 0 || r.ProbeBytesToday > 0 {
			sr.Probe = &probeResult{At: tsp(r.ProbeAt), Kbps: r.ProbeKbps, LossPct: pctp(r.ProbeLoss), OK: r.ProbeOK, BytesToday: r.ProbeBytesToday}
		}
		if r.QoS != "" {
			sr.Speed = speedFromRecord(sharingSettings(t), r, rec.Beat)
		}
		v.Relays = append(v.Relays, sr)
	}
	v.BackupGroup = nil
	if g := rec.BackupGroup; g != nil {
		name := g.Hub
		if h, ok := t.BackupHub(); ok && h.ID == g.Hub {
			name = h.Name
		}
		v.BackupGroup = &sharingGroup{Hub: g.Hub, Name: name, Relays: append([]string(nil), g.Relays...)}
	}
	if b := rec.Backup; b != nil {
		name := b.Hub
		if h, ok := t.BackupHub(); ok && h.ID == b.Hub {
			name = h.Name
		}
		sb := &sharingBackup{Hub: b.Hub, Name: name, Iface: b.Iface, Grade: b.Grade, Drain: b.Drain,
			Traffic: pathTraffic{RxBytes: b.RxBytes, TxBytes: b.TxBytes}}
		if b.MeasuredAt > 0 {
			sb.Measured = &pathMeasured{RTTms: msp(b.RTTus), LossPct: pctp(b.LossPermille), LastRTTms: msp(b.LastRTTus), LastLossPct: pctp(b.LastLoss), At: tsp(b.MeasuredAt)}
		}
		v.Backup = sb
	}
	return v
}

// sharingOnly reads the gateway's record for a single-hub topology with
// relay sharing (the carrying hub itself is known from the topology).
func (s *Server) sharingOnly(ctx context.Context, t model.Topology) *sharingView {
	v := baseSharing(t)
	if s.Upstream == nil {
		v.Code, v.Message = "agent_unavailable", "没有配置 host agent，读不到网关记录的中继状态"
		return v
	}
	ctx, cancel := context.WithTimeout(ctx, statusAgentTimeout)
	defer cancel()
	st, err := s.Upstream.UpstreamStatus(ctx)
	switch {
	case err != nil:
		v.Code, v.Message = "agent_unavailable", err.Error()
		return v
	case !st.Present:
		v.Code, v.Message = "not_recorded", "网关还没有中继记录（还没有按多中继拓扑安装到本机，或切换服务没有运行）"
		return v
	case st.Record == nil:
		v.Code, v.Message = "invalid_record", "网关的中继记录无法解析："+st.Error
		return v
	case st.Record.Version != 2:
		v.Code, v.Message = "record_mismatch", "网关记录的是单中继格式：网关还没有按当前拓扑安装"
		return v
	}
	return sharingFromRecord(t, st.Record, beatFresh(st.Record))
}

func sharingSettings(t model.Topology) model.PathQuality { return t.Settings.PathQuality.Effective() }

func speedFromRecord(s model.PathQuality, r hostexec.UpstreamRelay, beat int64) *speedResult {
	base := float64(r.BaselineKbps) / 1000
	sp := &speedResult{QoS: r.QoS, BaselineMbps: base, BaselineSrc: r.BaselineSrc,
		ThresholdMbps: base * float64(s.QoSThrottlePct) / 100, RecoverMbps: base * float64(s.QoSRecoverPct) / 100}
	if r.SpeedKbps != nil && *r.SpeedKbps > 0 {
		m := float64(*r.SpeedKbps) / 1000
		sp.Mbps, sp.At = &m, tsp(r.SpeedAt)
		age := beat - r.SpeedAt
		if age < 0 {
			age = 0
		}
		sp.AgeSec = &age
	}
	return sp
}
