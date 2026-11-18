package compile

import (
	"strings"
	"testing"

	"github.com/radowitz/meridian/internal/defaults"
	"github.com/radowitz/meridian/internal/model"
)

func moveGroup(tp model.Topology, id string) model.Topology {
	tp.Groups = append([]model.RegionGroup(nil), tp.Groups...)
	for i := range tp.Groups {
		g := &tp.Groups[i]
		if g.ID == id {
			g.Members = append([]string{g.Members[len(g.Members)-1]}, g.Members[:len(g.Members)-1]...)
			g.Mode, g.Chosen, g.OnFailure = model.GroupManual, g.Members[0], model.OnFailureFallback
		}
	}
	return tp
}

// An unlock-page save moves one group's selection: the gateway's group
// comment lines are accepted only for that group, and the hub scripts (the
// group is switched there) are another node's files, always refused.
func TestRuleChangeUnlockGroup(t *testing.T) {
	tp := defaults.Example()
	base := compileDec(t, tp, nil)
	next := compileDec(t, moveGroup(tp, "us"), nil)

	changed, refused := RuleChange(base, next, "gw", "us")
	gwRefused, hubRefused := false, false
	for _, p := range refused {
		if strings.HasPrefix(p, "nodes/gw/") {
			gwRefused = true
		} else {
			hubRefused = true
		}
	}
	if gwRefused || !hubRefused {
		t.Fatalf("allowed group: changed %v refused %v", changed, refused)
	}
	found := false
	for _, p := range changed {
		found = found || p == "nodes/gw/"+RuleNFTFile
	}
	if !found {
		t.Fatalf("gateway nft not accepted: %v", changed)
	}

	// Without the allowance, or for another group, the gateway nft is refused.
	for _, groups := range [][]string{nil, {"hk"}} {
		_, refused := RuleChange(base, next, "gw", groups...)
		bad := false
		for _, p := range refused {
			bad = bad || strings.HasPrefix(p, "nodes/gw/"+RuleNFTFile)
		}
		if !bad {
			t.Fatalf("groups %v: gateway group line accepted: %v", groups, refused)
		}
	}

	// Gateway-only view (the hub files equal): exactly the allowlist.
	only := *next
	only.Files = map[string]string{}
	for p, b := range next.Files {
		if strings.HasPrefix(p, "nodes/gw/") {
			only.Files[p] = b
		} else {
			only.Files[p] = base.Files[p]
		}
	}
	if _, refused := RuleChange(base, &only, "gw", "us"); len(refused) > 0 {
		t.Fatalf("gateway-only group move refused: %v", refused)
	}
}
