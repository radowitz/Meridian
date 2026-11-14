package validate

import (
	"fmt"
	"strings"

	"github.com/radowitz/meridian/internal/model"
	rulesorder "github.com/radowitz/meridian/internal/ordered"
	"github.com/radowitz/meridian/internal/probe"
	"github.com/radowitz/meridian/internal/ruleset"
)

// checkRuleSetsAndServices validates the subscribed rule-sets, the service
// groups and the QUIC switch row.
func checkRuleSetsAndServices(t model.Topology) []Issue {
	var out []Issue
	ids, names := map[string]bool{}, map[string]bool{}
	for _, rs := range t.RuleSets {
		bad := func(field, msg string) {
			out = append(out, Issue{Code: "bad_rule_set", Severity: SeverityError, Field: field, Message: fmt.Sprintf("规则集「%s」：%s", rs.Name, msg)})
		}
		if !rulesorder.RuleSetIDOK(rs.ID) || ids[rs.ID] {
			bad("id", "ID 不合法或重复（小写字母、数字、短横线）。")
		}
		ids[rs.ID] = true
		if strings.TrimSpace(rs.Name) == "" || names[strings.ToLower(rs.Name)] {
			bad("name", "名称为空或重复。")
		}
		names[strings.ToLower(rs.Name)] = true
		if err := ruleset.CheckURL(rs.URL); err != nil {
			bad("url", err.Error())
		}
		if !ruleset.FormatOK(rs.Format) {
			bad("format", "格式不认识。")
		}
		if rs.Source != "" && rs.Source != ruleset.SourceURL && rs.Source != ruleset.SourcePolicy {
			bad("source", "下载方式只能是 url 或 policy。")
		}
		if rs.IntervalSec != 0 && (rs.IntervalSec < 3600 || rs.IntervalSec > 30*86400) {
			bad("interval_sec", "更新间隔要在 1 小时到 30 天之间。")
		}
		if len(rs.Exclude) > rulesorder.MaxExclusions {
			bad("exclude", fmt.Sprintf("排除条目最多 %d 条。", rulesorder.MaxExclusions))
		} else if errs := ruleset.CheckStoredExclusions(rs.Exclude, rs.Format); len(errs) > 0 {
			bad("exclude", fmt.Sprintf("排除条目第 %d 行「%s」：%s。", errs[0].Line, errs[0].Text, errs[0].Error))
		}
	}
	sids := map[string]bool{}
	defaults := 0
	for _, s := range t.ServiceGroups {
		bad := func(code, msg string) {
			out = append(out, Issue{Code: code, Severity: SeverityError, Field: "service_groups", Message: fmt.Sprintf("服务组「%s」：%s", s.Name, msg)})
		}
		if !idRe.MatchString(s.ID) || sids[s.ID] {
			bad("bad_id", "ID 不合法或重复。")
		}
		sids[s.ID] = true
		n := 0
		for _, v := range []string{s.TargetGroup, s.TargetExit, s.TargetAction} {
			if v != "" {
				n++
			}
		}
		switch {
		case n > 1:
			bad("service_target_conflict", "只能指向一个地区组、出口、直连或拒绝。")
		case s.TargetGroup != "":
			if _, ok := t.GroupByID(s.TargetGroup); !ok {
				bad("group_not_found", "指向的地区组 "+s.TargetGroup+" 不存在。")
			}
		case s.TargetExit != "":
			if n, ok := t.NodeByID(s.TargetExit); !ok || n.Role != model.RoleExit {
				bad("exit_not_found", "指向的出口 "+s.TargetExit+" 不存在。")
			}
		case s.TargetAction != "":
			if s.TargetAction != model.ActionDirect && s.TargetAction != model.ActionReject {
				bad("bad_action", "动作只能是 direct 或 reject。")
			}
		}
		if s.Default {
			defaults++
			if s.TargetGroup == "" || s.TargetGroup != t.Settings.DefaultGroup {
				bad("service_default_mismatch", "它是兜底（MATCH）的服务组，必须指向默认地区组（"+t.Settings.DefaultGroup+"）。改兜底请在服务组里改，面板会同时改默认组。")
			}
		}
	}
	out = append(out, checkServiceSelection(t)...)
	if defaults > 1 {
		out = append(out, Issue{Code: "service_default_mismatch", Severity: SeverityError, Field: "service_groups", Message: "只能有一个兜底（MATCH）服务组。"})
	}
	quic := 0
	for _, r := range t.Rules {
		if r.Enabled && r.MatchType == model.MatchQUICReject {
			quic++
		}
	}
	if quic > 1 {
		out = append(out, Issue{Code: "quic_row_repeated", Severity: SeverityError, Field: "rules", Message: "QUIC 开关只能有一行（它的位置决定哪些规则豁免）。"})
	}
	return out
}

// checkServiceSelection validates the unlock binding of service groups
// (model.ServiceGroup Select / Probes) and the probe settings. One adapter
// is decided in one place only: a probe bound to a service group in
// automatic mode must not also be the adapter of an enabled built-in rule
// aimed at a region group (that rule has its own unlock state), or the two
// would move overlapping traffic independently.
func checkServiceSelection(t model.Topology) []Issue {
	var out []Issue
	builtin := map[string]string{}
	for _, r := range t.Rules {
		if r.Enabled && r.TargetGroup != "" && probe.Probeable(r.ID) {
			builtin[r.ID] = r.Name
		}
	}
	used := map[string]bool{}
	for _, r := range t.Rules {
		if r.Enabled && r.TargetService != "" {
			used[r.TargetService] = true
		}
	}
	for _, s := range t.ServiceGroups {
		add := func(code, sev, msg string) {
			out = append(out, Issue{Code: code, Severity: sev, Field: "service_groups", GroupID: s.TargetGroup, Message: fmt.Sprintf("服务组「%s」：%s", s.Name, msg)})
		}
		if s.Select != "" && s.Select != model.SelectAuto {
			add("service_select_bad", SeverityError, "选择方式只能是固定（空）或 auto。")
		}
		seen := map[string]bool{}
		verdicts := 0
		for _, id := range s.Probes {
			a, ok := probe.Lookup(id)
			switch {
			case !ok:
				add("service_probe_unknown", SeverityError, "检测项 "+id+" 不在探测目录里。")
				continue
			case seen[id]:
				add("service_probe_unknown", SeverityError, "检测项 "+id+" 重复。")
				continue
			}
			seen[id] = true
			if a.Capability == probe.CapRegionVerdict || a.Capability == probe.CapVerdict {
				verdicts++
			}
			if s.Select == model.SelectAuto {
				if name, clash := builtin[id]; clash {
					add("unlock_owner_conflict", SeverityError, fmt.Sprintf("检测项 %s 同时是已启用的内置规则「%s」的自动选择依据。同一个服务只能由一处决定出口：停用该内置规则，或把 %s 从这个服务组的自动选择里去掉。", id, name, id))
				}
				if g, ok := t.GroupByID(s.TargetGroup); ok {
					var outside []string
					for _, m := range g.Members {
						if n, ok := t.NodeByID(m); ok && n.Region != "" && !a.CoversRegion(n.Region) {
							outside = append(outside, m)
						}
					}
					if len(outside) > 0 {
						add("service_probe_region", SeverityWarning, fmt.Sprintf("检测项 %s 只能判断 %s 地区；候选出口 %s 不在其中，在它们上面只会得到“不在该地区”的结论。", id, strings.Join(a.Regions, "、"), strings.Join(outside, "、")))
					}
				}
			}
		}
		if s.Select != model.SelectAuto {
			continue
		}
		switch {
		case s.Default:
			add("service_auto_default", SeverityWarning, "兜底（MATCH）服务组不按检测结果自动选择（它承载全部未匹配的境外流量）：自动设置被忽略，检测结果只记录。")
		case s.TargetGroup == "":
			add("service_auto_target", SeverityWarning, "自动选择只对指向地区组的服务组起作用（候选就是该组的成员）；现在指向出口、直连或拒绝，等于钉死：检测结果只记录。")
		}
		if len(s.Probes) == 0 {
			add("service_auto_probes", SeverityError, "自动选择至少要绑定一个检测项。")
		} else if verdicts == 0 {
			add("service_auto_probes", SeverityError, "绑定的检测项都只能判断到达性，永远得不到解锁结论，自动选择不会有任何依据。")
		}
		if g, ok := t.GroupByID(s.TargetGroup); ok && g.Mode == model.GroupManual {
			add("service_auto_pinned", SeverityWarning, "目标地区组是手动模式：手动选择优先，检测结果只记录，不移动出口。")
		}
		if !used[s.ID] {
			add("service_auto_unused", SeverityWarning, "没有启用的规则指向这个服务组：检测结果只展示，不影响任何流量（不会自动新增规则）。")
		}
	}
	if p := t.Settings.UnlockProbe; p != nil {
		bad := func(field, msg string) {
			out = append(out, Issue{Code: "unlock_probe_settings", Severity: SeverityError, Field: "unlock_probe." + field, Message: msg})
		}
		if p.ExitConcurrency != 0 && (p.ExitConcurrency < 1 || p.ExitConcurrency > model.MaxUnlockExitConcurrency) {
			bad("exit_concurrency", fmt.Sprintf("同时探测的出口数只能是 1 到 %d。", model.MaxUnlockExitConcurrency))
		}
		if p.ExitRequestBudget != 0 && (p.ExitRequestBudget < model.MinUnlockExitBudget || p.ExitRequestBudget > model.MaxUnlockExitBudget) {
			bad("exit_request_budget", fmt.Sprintf("每个出口每轮的请求预算要在 %d 到 %d 之间。", model.MinUnlockExitBudget, model.MaxUnlockExitBudget))
		}
		if p.AutoApplyMinGapSec != 0 && (p.AutoApplyMinGapSec < model.MinAutoApplyMinGapSec || p.AutoApplyMinGapSec > model.MaxAutoApplyMinGapSec) {
			bad("auto_apply_min_gap_sec", fmt.Sprintf("两次自动安装的最小间隔要在 %d 秒到 %d 秒之间。", model.MinAutoApplyMinGapSec, model.MaxAutoApplyMinGapSec))
		}
		if p.AutoApplyDailyMax != 0 && (p.AutoApplyDailyMax < 1 || p.AutoApplyDailyMax > model.MaxAutoApplyDailyMax) {
			bad("auto_apply_daily_max", fmt.Sprintf("每 24 小时自动安装次数上限要在 1 到 %d 之间。", model.MaxAutoApplyDailyMax))
		}
		if p.ResultTTLSec != 0 {
			interval := t.Settings.UnlockIntervalSec
			if interval <= 0 {
				interval = 6 * 3600
			}
			switch {
			case p.ResultTTLSec < model.MinUnlockResultTTLSec || p.ResultTTLSec > model.MaxUnlockResultTTLSec:
				bad("result_ttl_sec", "结果有效期要在 1 小时到 7 天之间。")
			case p.ResultTTLSec < interval:
				bad("result_ttl_sec", "结果有效期短于探测间隔：下一轮之前所有结果都已过期，自动选择永远找不到有依据的备选。")
			}
		}
	}
	return out
}
