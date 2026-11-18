package api

import (
	"testing"

	"github.com/radowitz/meridian/internal/model"
)

// The referrers of a region group include the rules pointing at it and
// the rule-sets those rules use. Synthetic names only.
func TestGroupRefsRuleSets(t *testing.T) {
	topo := model.Topology{
		RuleSets: []model.RuleSet{{ID: "rs-video", Name: "视频集"}, {ID: "rs-other", Name: "无关"}},
		Rules: []model.Rule{
			{ID: "r1", Name: "直连规则", TargetGroup: "jp"},
			{ID: "r2", Name: "视频", MatchType: model.MatchRuleSet, RuleSet: "rs-video", TargetGroup: "jp", MihomoGroup: "流媒体"},
			{ID: "r3", Name: "别的", MatchType: model.MatchRuleSet, RuleSet: "rs-other", TargetExit: "ex1"},
		},
	}
	refs := groupRefs(topo, "jp")
	got := map[string]string{}
	for _, r := range refs {
		got[r.Kind+":"+r.ID] = r.Name
	}
	want := map[string]string{
		"rule:r1":           "直连规则",
		"rule:r2":           "视频（规则集 视频集）",
		"rule_set:rs-video": "视频集",
	}
	if len(got) != len(want) {
		t.Fatalf("refs %+v", refs)
	}
	for k, v := range want {
		if got[k] != v {
			t.Fatalf("%s = %q, refs %+v", k, got[k], refs)
		}
	}
	if refs[0].Kind != "rule" {
		t.Fatalf("direct rules first: %+v", refs)
	}
}
