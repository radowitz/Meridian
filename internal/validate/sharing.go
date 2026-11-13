package validate

import (
	"fmt"

	"github.com/radowitz/meridian/internal/model"
)

// Relay sharing (docs/architecture.md「多中继同时分担」): any number of
// domestic relays (two or more turn sharing on), each with its own link
// from the gateway and its own tunnel to the primary hub, with or without a
// backup hub; and the path-quality settings, checked whether sharing is on
// or not (so a saved value is always valid).

// MaxSharingRelays is pathquality.MaxRelays (a test keeps them equal).
const MaxSharingRelays = 12

func checkSharing(t model.Topology, nodes map[string]model.Node) []Issue {
	var out []Issue
	add := func(code, nodeID, linkID, field, format string, a ...any) {
		out = append(out, Issue{Code: code, Severity: SeverityError, NodeID: nodeID, LinkID: linkID, Field: field, Message: fmt.Sprintf(format, a...)})
	}
	out = append(out, checkPathQuality(t)...)
	relays := t.SharingRelays()
	if len(relays) < 2 {
		return out
	}
	if len(relays) > MaxSharingRelays {
		add("too_many_relays", relays[MaxSharingRelays].ID, "", "role", "网关连着 %d 台中继，同时分担最多 %d 台。", len(relays), MaxSharingRelays)
	}
	if t.Settings.IXReplacementMode {
		out = append(out, Issue{Code: "ix_replacement_mode_sharing", Severity: SeverityError, Field: "ix_replacement_mode",
			Message: "多台中继同时分担时不使用「IX 替换模式」：中继的取舍由网关按路径质量自动完成。关掉 ix_replacement_mode。"})
	}
	gw := firstRole(t, model.RoleGateway)
	primary := primaryHub(t)
	for _, r := range relays {
		gwLinks, hubLinks := 0, 0
		for _, l := range t.Links {
			if !l.Enabled || l.Standby || !tunnelTransport(l.Transport) || l.Transport == model.TransportIXReplacementWSS {
				continue
			}
			other := ""
			switch r.ID {
			case l.From:
				other = l.To
			case l.To:
				other = l.From
			default:
				continue
			}
			o := nodes[other]
			switch {
			case other == gw.ID:
				gwLinks++
			case other == primary.ID, o.Role == model.RoleIX:
				// The IX node of the older model stands for the dedicated
				// line to the primary hub (the path check covers it).
				hubLinks++
				if l.Transport != model.TransportDirectWG {
					add("sharing_relay_hub_transport", r.ID, l.ID, "transport", "中继 %s 到主枢纽的隧道 %s 用的是 %s。多台中继分担时这一段只支持 direct_wg（中继自己的东向切换只认 direct_wg）。", r.Name, linkName(l), l.Transport)
				}
			}
		}
		if gwLinks > 1 {
			add("sharing_relay_multiple_links", r.ID, "", "", "网关到中继 %s 有 %d 条启用的链路。每台中继只能有一条（UDP+WSS 双腿请用 udp_wss_failover）；多出来的那条请删掉或停用。", r.Name, gwLinks)
		}
		if hubLinks == 0 {
			add("sharing_relay_no_hub_link", r.ID, "", "", "中继 %s 没有到主枢纽 %s 的隧道（启用、非待命的 direct_wg 或 udp_wss_failover）。多台中继分担时，每台中继都要自己连到主枢纽，网关才能对它做端到端测量。", r.Name, primary.Name)
		}
		if hubLinks > 1 {
			add("sharing_relay_multiple_hub_links", r.ID, "", "", "中继 %s 到主枢纽有 %d 条启用的隧道，只能有一条。", r.Name, hubLinks)
		}
	}
	return out
}

func checkPathQuality(t model.Topology) []Issue {
	pq := t.Settings.PathQuality
	if pq == nil {
		return nil
	}
	var out []Issue
	bad := func(field, format string, a ...any) {
		out = append(out, Issue{Code: "invalid_path_quality", Severity: SeverityError, Field: "path_quality." + field, Message: fmt.Sprintf(format, a...)})
	}
	rng := func(field, label string, v, lo, hi int) {
		if v != 0 && (v < lo || v > hi) {
			bad(field, "%s 要在 %d 到 %d 之间（0 表示默认值）。", label, lo, hi)
		}
	}
	rng("mild_loss_permille", "轻度劣化丢包（‰）", pq.MildLossPermille, 1, 999)
	rng("poor_loss_permille", "可用下限丢包（‰）", pq.PoorLossPermille, 1, 1000)
	rng("mild_rtt_ms", "轻度劣化时延（毫秒）", pq.MildRTTMS, 10, 5000)
	rng("poor_rtt_ms", "可用下限时延（毫秒）", pq.PoorRTTMS, 10, 10000)
	rng("reduce_after_sec", "降权前的持续时间（秒）", pq.ReduceAfterSec, 5, 3600)
	rng("standby_after_sec", "停止分配前的持续时间（秒）", pq.StandbyAfterSec, 5, 3600)
	rng("evict_after_sec", "低于下限多久剔除（秒）", pq.EvictAfterSec, 5, 3600)
	rng("down_after_sec", "完全不通多久剔除（秒）", pq.DownAfterSec, 5, 600)
	rng("recover_after_sec", "恢复前须保持良好的时间（秒）", pq.RecoverAfterSec, 10, 7200)
	rng("ramp_step_sec", "逐步加回的每步时间（秒）", pq.RampStepSec, 5, 600)
	rng("backup_after_sec", "全部中继剔除多久改走备用枢纽（秒）", pq.BackupAfterSec, 5, 3600)
	rng("return_after_sec", "主链路良好多久切回（秒）", pq.ReturnAfterSec, 10, 7200)
	rng("min_dwell_sec", "两次切换枢纽的最短间隔（秒）", pq.MinDwellSec, 10, 7200)
	rng("switch_advantage_pct", "切换所需的质量优势（%）", pq.SwitchAdvantagePct, 5, 200)
	rng("probe_bytes", "吞吐探测大小（字节）", pq.ProbeBytes, 16*1024, 16*1024*1024)
	rng("probe_rate_kbps", "吞吐探测速率（kbit/s）", pq.ProbeRateKbps, 100, 1000000)
	rng("probe_min_interval_sec", "同一中继两次吞吐探测的最短间隔（秒）", pq.ProbeMinIntervalSec, 60, 86400)
	rng("probe_daily_budget_mb", "每台中继每天的探测预算（MB）", pq.ProbeDailyBudgetMB, 1, 10240)
	rng("probe_floor_kbps", "吞吐下限（kbit/s）", pq.ProbeFloorKbps, 32, 1000000)
	rng("probe_loss_permille", "探测丢包上限（‰）", pq.ProbeLossPermille, 10, 990)
	e := pq.Effective()
	if e.MildLossPermille >= e.PoorLossPermille {
		bad("mild_loss_permille", "轻度劣化丢包（%d‰）必须小于可用下限丢包（%d‰）。", e.MildLossPermille, e.PoorLossPermille)
	}
	if e.MildRTTMS >= e.PoorRTTMS {
		bad("mild_rtt_ms", "轻度劣化时延（%d ms）必须小于可用下限时延（%d ms）。", e.MildRTTMS, e.PoorRTTMS)
	}
	if e.ReduceAfterSec > e.StandbyAfterSec {
		bad("reduce_after_sec", "降权（%d 秒）不能晚于停止分配（%d 秒）。", e.ReduceAfterSec, e.StandbyAfterSec)
	}
	if e.ProbeFloorKbps > e.ProbeRateKbps {
		bad("probe_floor_kbps", "吞吐下限（%d kbit/s）不能高于探测速率（%d kbit/s）：探测本身就达不到。", e.ProbeFloorKbps, e.ProbeRateKbps)
	}
	if !e.ProbeOff {
		// One probe must fit in the daily budget.
		per := int64(e.ProbeBytes/1200+1) * 2 * (1200 + 88)
		if per > int64(e.ProbeDailyBudgetMB)*1024*1024 {
			bad("probe_daily_budget_mb", "每天的探测预算（%d MB）连一次探测（约 %d KB）都放不下。", e.ProbeDailyBudgetMB, per/1024)
		}
	}
	sharing := map[string]bool{}
	for _, r := range t.SharingRelays() {
		sharing[r.ID] = true
	}
	seen := map[string]bool{}
	disabled := 0
	for _, o := range pq.Overrides {
		switch {
		case !sharing[o.Relay]:
			bad("overrides", "手动覆盖里的 %q 不是网关直连的中继。", o.Relay)
		case seen[o.Relay]:
			bad("overrides", "中继 %q 的手动覆盖重复了。", o.Relay)
		case o.Weight < 0 || o.Weight > 100:
			bad("overrides", "中继 %q 的固定权重要在 1 到 100 之间（0 表示自动）。", o.Relay)
		case o.Disabled && o.Weight != 0:
			bad("overrides", "中继 %q 不能既停用又固定权重。", o.Relay)
		}
		seen[o.Relay] = true
		if o.Disabled {
			disabled++
		}
	}
	if len(sharing) > 0 && disabled >= len(sharing) {
		bad("overrides", "手动覆盖停用了全部中继：主链路将无路可走。至少保留一台。")
	}
	return out
}
