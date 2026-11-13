package validate

import (
	"fmt"
	"strings"

	"github.com/radowitz/meridian/internal/model"
	rulesorder "github.com/radowitz/meridian/internal/ordered"
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
