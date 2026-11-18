package validate

import (
	"fmt"
	"strings"

	"github.com/radowitz/meridian/internal/model"
	rulesorder "github.com/radowitz/meridian/internal/ordered"
	"github.com/radowitz/meridian/internal/ruleset"
)

// checkRuleSetsAndServices validates the subscribed rule-sets, the probe
// settings and the QUIC switch row.
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
	out = append(out, checkUnlockProbeSettings(t)...)
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

// checkUnlockProbeSettings validates the probe settings.
func checkUnlockProbeSettings(t model.Topology) []Issue {
	var out []Issue
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
