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
	// Settings are the effective thresholds of the topology (what the
	// next install compiles; the gateway runs what was last installed).
	Settings model.PathQuality `json:"settings"`
	// ProbeCost is estimated, not measured.
	ProbeCost probeCost `json:"probe_cost"`
	// EvictionImpact says what happens to existing connections.
	EvictionImpact string `json:"eviction_impact"`
}

// sharingRelay is one relay as the gateway recorded it.
type sharingRelay struct {
	ID          string     `json:"id"`
	Name        string     `json:"name"`
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
	pathquality.AlertAllPoor:          "所有中继都低于可用下限，没有备用枢纽：留在相对较好的中继上",
	pathquality.AlertBackupNotBetter:  "所有中继都低于可用下限，备用枢纽也不比它们好：留在相对较好的中继上，不来回切换",
	pathquality.AlertBackupUnusable:   "所有中继都低于可用下限，备用枢纽也不可用：留在相对较好的中继上",
	pathquality.AlertNothingReachable: "没有任何路径应答：流量停在隧道里被丢弃，不会从局域网口直出",
	pathquality.AlertOnBackup:         "主链路整体不好用，正由备用枢纽承载",
	"controller_unavailable":          "网关上的控制程序（meridian path-step）不可用：本轮按应急规则运行（可达的中继平均分担，只按通断剔除）",
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
	v := &sharingView{Settings: pq, ProbeCost: estimateProbeCost(pq), EvictionImpact: evictionImpact(pq), Relays: []sharingRelay{}}
	for _, r := range t.SharingRelays() {
		v.Relays = append(v.Relays, sharingRelay{ID: r.ID, Name: r.Name, Status: "unknown", Grade: "none"})
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
			InSet:   r.Weight > 0 && rec.Path == "main",
			Traffic: pathTraffic{RxBytes: r.RxBytes, TxBytes: r.TxBytes, RxBps: r.RxBps, TxBps: r.TxBps, NewConns: r.NewConns}}
		if r.MeasuredAt > 0 {
			sr.Measured = &pathMeasured{RTTms: msp(r.RTTus), LossPct: pctp(r.LossPermille), LastRTTms: msp(r.LastRTTus), LastLossPct: pctp(r.LastLoss), At: tsp(r.MeasuredAt)}
		}
		if r.ProbeAt > 0 || r.ProbeBytesToday > 0 {
			sr.Probe = &probeResult{At: tsp(r.ProbeAt), Kbps: r.ProbeKbps, LossPct: pctp(r.ProbeLoss), OK: r.ProbeOK, BytesToday: r.ProbeBytesToday}
		}
		v.Relays = append(v.Relays, sr)
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
