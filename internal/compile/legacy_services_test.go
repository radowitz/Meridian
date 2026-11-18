package compile

import (
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/radowitz/meridian/internal/defaults"
	"github.com/radowitz/meridian/internal/model"
)

// legacyDoc turns topo into a document from before service groups were
// removed: one service group per region group (plus one on an exit and one
// direct), and every rule aimed at a group goes through its service group.
func legacyDoc(t *testing.T, topo model.Topology) []byte {
	t.Helper()
	b, err := json.Marshal(topo)
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatal(err)
	}
	var sgs []map[string]any
	for _, g := range topo.Groups {
		sgs = append(sgs, map[string]any{"id": "svc-" + g.ID, "name": "策略 " + g.ID, "origin": "mihomo", "target_group": g.ID,
			"select": "auto", "probes": []string{"auto-netflix"}, "default": g.ID == topo.Settings.DefaultGroup})
	}
	sgs = append(sgs, map[string]any{"id": "svc-direct", "name": "直连组", "target_action": "direct"})
	rules, _ := doc["rules"].([]any)
	for i, x := range rules {
		r := x.(map[string]any)
		switch {
		case r["target_group"] != nil:
			r["target_service"] = "svc-" + r["target_group"].(string)
			delete(r, "target_group")
		case r["target_exit"] != nil:
			id := r["target_exit"].(string)
			sgs = append(sgs, map[string]any{"id": fmt.Sprintf("svc-exit-%d", i), "name": "出口 " + id, "target_exit": id})
			r["target_service"] = fmt.Sprintf("svc-exit-%d", i)
			delete(r, "target_exit")
		}
	}
	doc["service_groups"] = sgs
	out, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func exampleTopologies(t *testing.T) map[string]model.Topology {
	out := map[string]model.Topology{
		"example":  defaults.Example(),
		"dual_hub": defaults.DualHubExample(),
		"nested":   defaults.NestedExample(),
		"external": defaults.ExternalExample(),
	}
	shared := defaults.SharedRelaysExample()
	model.MigrateRegionGroups(&shared)
	out["shared_relays"] = shared
	for k, v := range sniffTopologies(t) {
		out["sniff_"+k] = v
	}
	return out
}

// An old topology with service groups decodes into one whose rules point
// at the service groups' targets directly; every rule keeps its exit (mark)
// and the compiled bundle is byte-identical. Decoding the written result
// again changes nothing and writes no service group.
func TestLegacyServiceGroupsMigrateWithSameExits(t *testing.T) {
	for name, topo := range exampleTopologies(t) {
		raw := legacyDoc(t, topo)
		if !strings.Contains(string(raw), `"target_service"`) {
			t.Fatalf("%s: the legacy document routes nothing through a service group", name)
		}
		var mig model.Topology
		if err := json.Unmarshal(raw, &mig); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		for i, r := range mig.Rules {
			o := topo.Rules[i]
			if r.TargetGroup != o.TargetGroup || r.TargetExit != o.TargetExit || r.TargetAction != o.TargetAction {
				t.Fatalf("%s: rule %s target %+v, want %+v", name, r.ID, mig.ResolveTarget(r), topo.ResolveTarget(o))
			}
			if (o.TargetGroup != "" || o.TargetExit != "") && r.MihomoGroup == "" {
				t.Fatalf("%s: rule %s lost its policy-group label", name, r.ID)
			}
		}
		e1, g1 := plans(t, topo)
		e2, g2 := plans(t, mig)
		p1, p2 := planRules(topo, e1, g1, nil), planRules(mig, e2, g2, nil)
		if len(p1) != len(p2) {
			t.Fatalf("%s: %d rule plans, want %d", name, len(p2), len(p1))
		}
		for i := range p1 {
			if p1[i].Rule.ID != p2[i].Rule.ID || p1[i].Mark != p2[i].Mark || p1[i].Action != p2[i].Action {
				t.Fatalf("%s: rule %s mark %#x/%q, want %#x/%q", name, p2[i].Rule.ID, p2[i].Mark, p2[i].Action, p1[i].Mark, p1[i].Action)
			}
		}
		b1, err1 := Compile(topo)
		b2, err2 := Compile(mig)
		if (err1 == nil) != (err2 == nil) {
			t.Fatalf("%s: compile %v, migrated %v", name, err1, err2)
		}
		if err1 == nil && !reflect.DeepEqual(b1.Files, b2.Files) {
			for k, v := range b1.Files {
				if b2.Files[k] != v {
					t.Errorf("%s: %s differs after migration", name, k)
				}
			}
		}
		// Idempotent: written again, nothing of the service groups is left.
		w, err := json.Marshal(mig)
		if err != nil {
			t.Fatal(err)
		}
		if s := string(w); strings.Contains(s, "service_groups") || strings.Contains(s, "target_service") || strings.Contains(s, `"probes"`) {
			t.Fatalf("%s: the migrated document still writes service groups", name)
		}
		var again model.Topology
		if err := json.Unmarshal(w, &again); err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(again, mig) {
			t.Fatalf("%s: a second decode changed the topology", name)
		}
	}
}

// A rule whose service group is missing cannot be migrated: the decode
// fails with a message naming the rule.
func TestLegacyServiceGroupMissingBlocks(t *testing.T) {
	doc := `{"settings":{},"nodes":[],"links":[],"rules":[{"id":"r1","name":"AI","target_service":"svc-gone"}],"service_groups":[]}`
	var tp model.Topology
	err := json.Unmarshal([]byte(doc), &tp)
	if err == nil || !strings.Contains(err.Error(), "AI") {
		t.Fatalf("err = %v", err)
	}
}
