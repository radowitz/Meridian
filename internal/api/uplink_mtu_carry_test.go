package api

import (
	"fmt"
	"strings"
	"testing"

	"github.com/radowitz/meridian/internal/compile"
	"github.com/radowitz/meridian/internal/defaults"
	"github.com/radowitz/meridian/internal/model"
)

// The adoption preview lists the path MTU / MSS of every exit whose
// carrying paths include the adopted link, also when that link is not on
// the reported primary path (a non-preferred sharing relay, the backup hub
// to the exit, a WSS companion leg, a nested exit's inner link), and only
// those exits (compile's TestClampsFollowEveryCarryingPath checks the
// clamps of the same cases).
func TestMTUPreviewFollowsEveryCarryingPath(t *testing.T) {
	shared := defaults.SharedRelaysExample()
	model.MigrateRegionGroups(&shared)
	dual := defaults.DualHubExample()
	model.MigrateRegionGroups(&dual)
	nested := defaults.NestedExample()
	model.MigrateRegionGroups(&nested)
	// The sharing relay that is not on dc1's reported path.
	b, err := compile.Compile(shared)
	if err != nil {
		t.Fatal(err)
	}
	other := "gw-access2"
	for _, p := range b.Paths {
		if p.ExitID != "dc1" {
			continue
		}
		for _, l := range p.Links {
			if l == "gw-access2" {
				other = "gw-access"
			}
		}
	}
	for _, c := range []struct {
		name   string
		topo   model.Topology
		change mtuChange
		lower  []string // exits whose path MTU must drop to 1280
		keep   []string // exits the link cannot carry
	}{
		{"non-preferred sharing relay", shared, mtuChange{LinkID: other, Field: "mtu", To: 1280}, []string{"dc1", "dc2"}, nil},
		{"backup hub to exit", dual, mtuChange{LinkID: "hkb-dc1", Field: "mtu", To: 1280}, []string{"dc1"}, []string{"dc2"}},
		{"WSS companion leg", shared, mtuChange{LinkID: "gw-access", Field: "wss_mtu", To: 1280}, []string{"dc1", "dc2"}, nil},
		{"nested exit's inner link", nested, mtuChange{LinkID: "twnat-dc1", Field: "mtu", To: 1280}, []string{"twnat"}, []string{"dc1", "dc2"}},
		{"another exit's link", dual, mtuChange{LinkID: "ix-dc2", Field: "mtu", To: 1280}, []string{"dc2"}, []string{"dc1"}},
	} {
		t.Run(c.name, func(t *testing.T) {
			p := mtuProposalFor(c.topo, []mtuChange{c.change})
			if p.Error != "" {
				t.Fatal(p.Error)
			}
			got := map[string]pathMTUDiff{}
			for _, d := range p.Paths {
				got[d.ExitID] = d
			}
			for _, id := range c.lower {
				d, ok := got[id]
				if !ok || d.MTUBefore != 1360 || d.MTUAfter != 1280 || d.MSS4After != 1240 || d.MSS6After != 1220 {
					t.Errorf("%s: preview %+v, want 1360 → 1280 (MSS 1240/1220)", id, d)
				}
			}
			for _, id := range c.keep {
				if d, ok := got[id]; ok {
					t.Errorf("%s: the link cannot carry it, yet the preview changes it: %+v", id, d)
				}
			}
			if len(p.Nodes) == 0 {
				t.Error("the preview lists no node file differences")
			}
		})
	}
}

// TestMTUPreviewGroupMeshPath: the adoption preview lists each switched
// region group's path MTU (its Mesh fallback included) before and after,
// with the same values the compiled group clamp carries: the report, the
// preview and the gateway ruleset agree.
func TestMTUPreviewGroupMeshPath(t *testing.T) {
	topo := defaults.Example()
	model.MigrateRegionGroups(&topo)
	for _, c := range []struct {
		name   string
		change mtuChange
		groups map[string][2]int // group → MTU before, after
		exits  bool              // exit paths change too
	}{
		// A larger Mesh path under us's Mesh leg (1280 → 1300: what it
		// leaves the WireGuard leg goes from 1216 to 1232): exit us and the
		// groups that can switch to it follow, nothing else.
		{"Mesh leg", mtuChange{LinkID: "hub-us-mesh", Field: "mtu", From: 1280, To: 1300}, map[string][2]int{"us": {1216, 1232}, "us-pin": {1216, 1232}}, true},
		// A smaller gateway uplink: every exit and every group without a
		// Mesh leg drops to 1300; the groups with one stay at 1216.
		{"gateway uplink", mtuChange{LinkID: "gw-access", Field: "mtu", To: 1300}, map[string][2]int{"hk-residential": {1360, 1300}, "jp": {1360, 1300}, "relay": {1360, 1300}, "sg": {1360, 1300}, "tw": {1360, 1300}}, true},
	} {
		t.Run(c.name, func(t *testing.T) {
			p := mtuProposalFor(topo, []mtuChange{c.change})
			if p.Error != "" {
				t.Fatal(p.Error)
			}
			if (len(p.Paths) > 0) != c.exits {
				t.Errorf("exit path diffs %+v, want changes: %v", p.Paths, c.exits)
			}
			got := map[string]groupPathMTUDiff{}
			for _, d := range p.GroupPaths {
				got[d.GroupID] = d
			}
			if len(got) != len(c.groups) {
				t.Errorf("group diffs %+v, want exactly %v", p.GroupPaths, c.groups)
			}
			after, err := compile.Compile(applyMTUChanges(topo, []mtuChange{c.change}))
			if err != nil {
				t.Fatal(err)
			}
			gw := after.Files["nodes/gw/etc/nftables.d/meridian.nft"]
			groups, err := compile.PlanGroups(applyMTUChanges(topo, []mtuChange{c.change}))
			if err != nil {
				t.Fatal(err)
			}
			for id, w := range c.groups {
				d, ok := got[id]
				if !ok || d.MTUBefore != w[0] || d.MTUAfter != w[1] || d.MSS4After != w[1]-40 || d.MSS6After != w[1]-60 {
					t.Errorf("%s: preview %+v, want %d → %d", id, d, w[0], w[1])
					continue
				}
				for _, r := range after.GroupPaths {
					if r.GroupID == id && (r.MTU != d.MTUAfter || r.MSS4 != d.MSS4After || r.MSS6 != d.MSS6After) {
						t.Errorf("%s: preview %+v disagrees with the compiled report %+v", id, d, r)
					}
				}
				if !d.Mesh {
					continue
				}
				for _, g := range groups {
					if g.Group.ID != id {
						continue
					}
					for _, v := range []int{d.MSS4After, d.MSS6After} {
						rule := fmt.Sprintf("meta mark %#x meta nfproto ipv%d tcp option maxseg size > %d tcp option maxseg size set %d", g.Mark, map[bool]int{true: 4, false: 6}[v == d.MSS4After], v, v)
						if !strings.Contains(gw, rule) {
							t.Errorf("%s: the gateway ruleset has no %q", id, rule)
						}
					}
				}
			}
		})
	}
}
