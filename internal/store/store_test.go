package store

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"

	"github.com/radowitz/meridian/internal/defaults"
	"github.com/radowitz/meridian/internal/model"
)

func openTest(t *testing.T) *Store {
	t.Helper()
	s, err := Open(filepath.Join(t.TempDir(), "meridian.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

// Server references round-trip; a redacted private key in a save keeps the
// stored one; nothing but the topology is in the row.
func TestSaveKeepsKeysAndServerRefs(t *testing.T) {
	s := openTest(t)
	key := strings.Repeat("A", 43) + "="
	topo := model.Topology{Nodes: []model.Node{
		{ID: "gw", Role: model.RoleGateway, PrivateKey: key},
		{ID: "hub", Role: model.RoleHub, ServerID: "srv-hub"},
	}}
	if err := s.Save(topo); err != nil {
		t.Fatal(err)
	}
	red := Redact(topo)
	if red.Nodes[0].PrivateKey != "***" {
		t.Fatal("not redacted")
	}
	if err := s.Save(red); err != nil {
		t.Fatal(err)
	}
	got, ok, err := s.Load()
	if err != nil || !ok || got.Nodes[0].PrivateKey != key || got.Nodes[1].ServerID != "srv-hub" {
		t.Fatalf("%+v %v", got, err)
	}
}

func TestUpdateIsSerialised(t *testing.T) {
	s := openTest(t)
	if found, err := s.Update(func(*model.Topology) (bool, error) { t.Fatal("called without a topology"); return false, nil }); found || err != nil {
		t.Fatalf("%v %v", found, err)
	}
	if err := s.Save(model.Topology{}); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _ = s.Update(func(t *model.Topology) (bool, error) {
				t.Rules = append(t.Rules, model.Rule{ID: "r"})
				return true, nil
			})
		}()
	}
	wg.Wait()
	got, _, _ := s.Load()
	if len(got.Rules) != 20 {
		t.Fatalf("lost updates: %d", len(got.Rules))
	}
	// An error or "no change" saves nothing.
	boom := errors.New("boom")
	if _, err := s.Update(func(t *model.Topology) (bool, error) { t.Rules = nil; return true, boom }); err != boom {
		t.Fatal(err)
	}
	if got, _, _ := s.Load(); len(got.Rules) != 20 {
		t.Fatal("failed update saved")
	}
}

// legacyExample is the example topology as it looked before region groups:
// pools on nodes, target_pool + mode on rules.
func legacyExample() model.Topology {
	t := defaults.Example()
	pools := map[string]struct {
		pool string
		prio int
	}{
		"hk-ix": {"hk", 0}, "hk-2": {"hk", 10}, "hk-resi": {"hk-residential", 0}, "hk-resi-2": {"hk-residential", 10},
		"jp": {"jp", 0}, "sg": {"sg", 0}, "us": {"us", 0}, "us-2": {"us", 10},
		"ds-relay": {"relay", 0}, "v6-exit": {"v6", 0}, "v6-v4out": {"v6-nat", 0}, "tw": {"tw", 0},
	}
	for i := range t.Nodes {
		if p, ok := pools[t.Nodes[i].ID]; ok {
			t.Nodes[i].Pool, t.Nodes[i].PoolPriority = p.pool, p.prio
		}
	}
	for i := range t.Rules {
		r := &t.Rules[i]
		if r.TargetGroup == "us-pin" {
			r.TargetPool, r.Mode = "us", model.ModePin
		} else {
			r.TargetPool, r.Mode = r.TargetGroup, model.ModeAuto
		}
		r.TargetGroup = ""
	}
	t.Groups, t.Settings.DefaultGroup = nil, ""
	return t
}

func groupsEqual(t *testing.T, got, want []model.RegionGroup) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("groups: got %d, want %d", len(got), len(want))
	}
	for i := range want {
		g, w := got[i], want[i]
		g.Name, w.Name, g.Notes, w.Notes = "", "", "", ""
		if strings.Join(g.Members, ",") != strings.Join(w.Members, ",") {
			t.Errorf("%s members %v, want %v", w.ID, g.Members, w.Members)
		}
		g.Members, w.Members = nil, nil
		if fmt.Sprintf("%+v", g) != fmt.Sprintf("%+v", w) {
			t.Errorf("group\n got %+v\nwant %+v", g, w)
		}
	}
}

// The migration reproduces the example's groups from the old pools: IX
// first then pool_priority then ID, a pinned and an automatic rule on the
// same pool become two groups, the default group is hk.
func TestMigrationOfLegacyExample(t *testing.T) {
	legacy := legacyExample()
	rep := model.MigrateRegionGroups(&legacy)
	if !rep.Changed || rep.Rules != len(legacy.Rules) {
		t.Fatalf("report %+v", rep)
	}
	want := defaults.Example()
	sortGroups := func(gs []model.RegionGroup) {
		sort.Slice(gs, func(i, j int) bool { return gs[i].ID < gs[j].ID })
	}
	sortGroups(legacy.Groups)
	sortGroups(want.Groups)
	groupsEqual(t, legacy.Groups, want.Groups)
	if legacy.Settings.DefaultGroup != "hk" {
		t.Fatalf("default group %q", legacy.Settings.DefaultGroup)
	}
	for i := range want.Rules {
		g, w := legacy.Rules[i], want.Rules[i]
		if g.TargetGroup != w.TargetGroup || g.TargetPool != "" || g.Mode != "" {
			t.Errorf("rule %s -> %q (pool %q mode %q), want %q", w.ID, g.TargetGroup, g.TargetPool, g.Mode, w.TargetGroup)
		}
	}
	for _, n := range legacy.Nodes {
		if n.Pool != "" || n.PoolPriority != 0 {
			t.Errorf("node %s kept pool fields", n.ID)
		}
	}
	// Idempotent.
	before, _ := json.Marshal(legacy)
	if rep := model.MigrateRegionGroups(&legacy); rep.Changed {
		t.Fatalf("second run changed: %+v", rep)
	}
	after, _ := json.Marshal(legacy)
	if string(before) != string(after) {
		t.Fatal("second run rewrote the document")
	}
}

// Same pool with pin and auto but also different priorities: IX-bound wins,
// then priority, then ID; residential rules get their own constrained group.
func TestMigrationVariantsAndOrder(t *testing.T) {
	topo := model.Topology{
		Nodes: []model.Node{
			{ID: "z", Role: model.RoleExit, Pool: "p", PoolPriority: 1},
			{ID: "y", Role: model.RoleExit, Pool: "p", PoolPriority: 1},
			{ID: "x", Role: model.RoleExit, Pool: "p", PoolPriority: 5, IXBound: true},
			{ID: "w", Role: model.RoleExit, Pool: "p"},
			{ID: "r", Role: model.RoleExit, Pool: "p", Residential: true, PoolPriority: 9},
		},
		Rules: []model.Rule{
			{ID: "a", Name: "a", TargetPool: "p", Mode: model.ModeAuto, Enabled: true},
			{ID: "b", Name: "b", TargetPool: "p", Mode: model.ModePin, Enabled: true},
			{ID: "c", Name: "Netflix", TargetPool: "p", Mode: model.ModeAuto, Enabled: true},
			{ID: "d", Name: "d", TargetPool: "p", Enabled: true},
			{ID: "e", Name: "e", TargetPool: "p", TargetExit: "w", Mode: model.ModePin, Enabled: true},
		},
	}
	model.MigrateRegionGroups(&topo)
	byID := map[string]model.RegionGroup{}
	for _, g := range topo.Groups {
		byID[g.ID] = g
	}
	auto, pin, resi := byID["p"], byID["p-pin"], byID["p-auto-resi"]
	if strings.Join(auto.Members, ",") != "x,w,y,z,r" || auto.Mode != model.GroupAuto {
		t.Fatalf("auto group %+v", auto)
	}
	if pin.Mode != model.GroupManual || pin.Chosen != "x" || pin.OnFailure != model.OnFailureFallback {
		t.Fatalf("pin group %+v", pin)
	}
	if !resi.RequireResidential || resi.Mode != model.GroupAuto {
		t.Fatalf("resi group %+v", resi)
	}
	want := map[string]string{"a": "p", "b": "p-pin", "c": "p-auto-resi", "d": "p", "e": ""}
	for _, r := range topo.Rules {
		if r.TargetGroup != want[r.ID] || r.TargetPool != "" || r.Mode != "" {
			t.Errorf("rule %s -> %q pool %q mode %q", r.ID, r.TargetGroup, r.TargetPool, r.Mode)
		}
	}
	if topo.Rules[4].TargetExit != "w" {
		t.Fatal("explicit exit lost")
	}
}

// An old client writes legacy fields into a migrated document: the node
// joins the groups migrated from its pool, the rule finds or creates the
// variant group, nothing is duplicated.
func TestMigrationMergesLegacyInput(t *testing.T) {
	topo := defaults.Example()
	topo.Nodes = append(topo.Nodes, model.Node{ID: "us-3", Role: model.RoleExit, Region: "us", Pool: "us", PoolPriority: 20})
	topo.Rules = append(topo.Rules,
		model.Rule{ID: "new-pin", Name: "n", TargetPool: "us", Mode: model.ModePin, Enabled: true},
		model.Rule{ID: "new-jp-pin", Name: "j", TargetPool: "jp", Mode: model.ModePin, Enabled: true},
	)
	n := len(topo.Groups)
	model.MigrateRegionGroups(&topo)
	if len(topo.Groups) != n+1 {
		t.Fatalf("groups %d, want %d (only jp-pin is new)", len(topo.Groups), n+1)
	}
	us, _ := topo.GroupByID("us")
	usPin, _ := topo.GroupByID("us-pin")
	jpPin, ok := topo.GroupByID("jp-pin")
	if strings.Join(us.Members, ",") != "us,us-2,us-3" || strings.Join(usPin.Members, ",") != "us,us-2,us-3" {
		t.Fatalf("us %v us-pin %v", us.Members, usPin.Members)
	}
	if !ok || jpPin.Chosen != "jp" || jpPin.Mode != model.GroupManual {
		t.Fatalf("jp-pin %+v", jpPin)
	}
	for _, r := range topo.Rules {
		if r.ID == "new-pin" && r.TargetGroup != "us-pin" || r.ID == "new-jp-pin" && r.TargetGroup != "jp-pin" {
			t.Errorf("rule %s -> %s", r.ID, r.TargetGroup)
		}
	}
	// A migrated rule that sends a mode is left for validation to refuse.
	topo.Rules[0].Mode = model.ModePin
	model.MigrateRegionGroups(&topo)
	if topo.Rules[0].Mode != model.ModePin {
		t.Fatal("migration silently dropped a contradictory mode")
	}
}

// The store reads legacy rows as groups, persists the migration once, and a
// crash before the write leaves the old row, migrated again on the next read.
func TestStoreMigratesOnLoadAndPersistsOnce(t *testing.T) {
	s := openTest(t)
	raw, _ := json.Marshal(legacyExample())
	if err := s.Put("topology", string(raw)); err != nil {
		t.Fatal(err)
	}
	got, ok, err := s.Load()
	if err != nil || !ok || got.Settings.DefaultGroup != "hk" || len(got.Groups) != len(defaults.Example().Groups) {
		t.Fatalf("load: %v %v %+v", ok, err, got.Settings)
	}
	still, _, _ := s.Get("topology")
	if !strings.Contains(still, `"target_pool"`) {
		t.Fatal("Load wrote the row (only MigrateRegionGroups / Save may)")
	}
	again, _, _ := s.Load()
	a, _ := json.Marshal(got)
	b, _ := json.Marshal(again)
	if string(a) != string(b) {
		t.Fatal("two reads of the unmigrated row differ")
	}
	rep, err := s.MigrateRegionGroups()
	if err != nil || !rep.Changed {
		t.Fatalf("persist: %+v %v", rep, err)
	}
	row, _, _ := s.Get("topology")
	if strings.Contains(row, `"target_pool"`) || strings.Contains(row, `"pool"`) || strings.Contains(row, `"mode":"pin"`) {
		t.Fatal("legacy fields left in the stored row")
	}
	if rep, err := s.MigrateRegionGroups(); err != nil || rep.Changed {
		t.Fatalf("second persist: %+v %v", rep, err)
	}
	row2, _, _ := s.Get("topology")
	if row != row2 {
		t.Fatal("second run rewrote the row")
	}
	// Save never stores legacy fields either.
	leg := legacyExample()
	if err := s.Save(leg); err != nil {
		t.Fatal(err)
	}
	row3, _, _ := s.Get("topology")
	if strings.Contains(row3, `"target_pool"`) {
		t.Fatal("Save stored legacy fields")
	}
}

// examples/topology.example.json is the example topology in the current
// format: nothing left to migrate, and identical to defaults.Example().
func TestExampleJSONIsCurrent(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "examples", "topology.example.json"))
	if err != nil {
		t.Fatal(err)
	}
	var topo model.Topology
	if err := json.Unmarshal(raw, &topo); err != nil {
		t.Fatal(err)
	}
	if rep := model.MigrateRegionGroups(&topo); rep.Changed {
		t.Fatalf("example still needs migration: %+v", rep)
	}
	want, _ := json.MarshalIndent(defaults.Example(), "", "  ")
	if strings.TrimSpace(string(raw)) != string(want) {
		t.Fatal("examples/topology.example.json is out of date with defaults.Example()")
	}
}
