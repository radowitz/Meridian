package model

import (
	"encoding/json"
	"fmt"
	"reflect"
	"testing"
)

func allocTopo(linkIDs ...string) Topology {
	t := Topology{
		Nodes: []Node{{ID: "gw", Role: RoleGateway}, {ID: "r", Role: RoleRelay}, {ID: "e2", Role: RoleExit}, {ID: "e1", Role: RoleExit}},
		Groups: []RegionGroup{
			{ID: "g2"}, {ID: "g1"},
		},
	}
	for _, id := range linkIDs {
		t.Links = append(t.Links, Link{ID: id, From: "gw", To: "r", Transport: TransportDirectWG, Enabled: true})
	}
	return t
}

func TestMigrateAllocationsIsPositions(t *testing.T) {
	topo := allocTopo("c", "a", "b")
	topo.Links = append(topo.Links,
		Link{ID: "aa-off", From: "gw", To: "r", Transport: TransportDirectWG, Enabled: false},
		Link{ID: "mesh", From: "gw", To: "r", Transport: TransportCFMesh, Enabled: true},
		Link{ID: "0-wss", From: "gw", To: "r", Transport: TransportWGOverWSS, Enabled: true},
	)
	if !MigrateAllocations(&topo) {
		t.Fatal("first migration reported no change")
	}
	a := topo.Allocations
	// Enabled tunnel links sorted by ID: 0-wss, a, b, c → 0..3, exactly
	// the old index; the disabled one gets the next free slot; cf_mesh
	// gets none.
	want := map[string]Slot{"0-wss": {0}, "a": {1}, "b": {2}, "c": {3}, "aa-off": {4}}
	if !reflect.DeepEqual(a.Links, want) {
		t.Fatalf("links = %v, want %v", a.Links, want)
	}
	if !reflect.DeepEqual(a.Exits, map[string]Slot{"e1": {0}, "e2": {1}}) || !reflect.DeepEqual(a.Groups, map[string]Slot{"g1": {2}, "g2": {3}}) {
		t.Fatalf("marks = %v %v", a.Exits, a.Groups)
	}
	before, _ := json.Marshal(topo)
	if MigrateAllocations(&topo) {
		t.Fatal("second migration reported a change")
	}
	after, _ := json.Marshal(topo)
	if string(before) != string(after) {
		t.Fatal("second migration changed the document")
	}
	// EffectiveAllocations of the nil table is the same numbering.
	legacy := allocTopo("c", "a", "b")
	legacy.Links = topo.Links
	if eff := EffectiveAllocations(legacy); !reflect.DeepEqual(eff.Links, want) {
		t.Fatalf("effective = %v", eff.Links)
	}
}

func TestReconcileKeepsRetiresAndAppends(t *testing.T) {
	base := allocTopo("a", "b", "c")
	MigrateAllocations(&base)
	stored := base.Allocations.Clone()

	// The client reorders, drops the table, deletes b and adds two links
	// whose IDs sort first.
	next := allocTopo("0-new", "c", "a", "00-new")
	next.Allocations = &Allocations{Links: map[string]Slot{"a": {7}, "c": {0}}}
	ReconcileAllocations(stored, &next)
	got := next.Allocations
	if got.Links["a"] != (Slot{0}) || got.Links["c"] != (Slot{2}) {
		t.Fatalf("stored slots not kept: %v", got.Links)
	}
	// b's slot 1 is retired and not reused in the same save; the new links
	// get the lowest never-used slots, in ID order.
	if !reflect.DeepEqual(got.RetiredLinks, []int{1}) {
		t.Fatalf("retired = %v", got.RetiredLinks)
	}
	if got.Links["0-new"] != (Slot{3}) || got.Links["00-new"] != (Slot{4}) {
		t.Fatalf("new slots = %v", got.Links)
	}
	if !reflect.DeepEqual(base.Allocations, stored) {
		t.Fatal("reconcile mutated the base")
	}
	// Reconciling again against its own result changes nothing.
	again := next
	again.Allocations = got.Clone()
	ReconcileAllocations(got, &again)
	if !reflect.DeepEqual(again.Allocations, got) {
		t.Fatalf("not idempotent: %v vs %v", again.Allocations, got)
	}
}

func TestReconcileReusesRetiredOnlyWhenExhaustedAndNotSameSave(t *testing.T) {
	var ids []string
	for i := 0; i < MaxLinkSlots; i++ {
		ids = append(ids, fmt.Sprintf("l%03d", i))
	}
	full := allocTopo(ids...)
	MigrateAllocations(&full)
	if len(full.Allocations.Links) != MaxLinkSlots {
		t.Fatalf("got %d slots", len(full.Allocations.Links))
	}
	// Delete l005 and add x in one save: no never-used slot is left and
	// slot 5 was retired by this save, so x gets nothing.
	same := allocTopo(append(append([]string{}, ids[:5]...), append(ids[6:], "x")...)...)
	ReconcileAllocations(full.Allocations, &same)
	if _, ok := same.Allocations.LinkSlot("x"); ok {
		t.Fatalf("x took a slot retired in the same save: %v", same.Allocations.Links["x"])
	}
	if !reflect.DeepEqual(same.Allocations.RetiredLinks, []int{5}) {
		t.Fatalf("retired = %v", same.Allocations.RetiredLinks)
	}
	// The next save may reuse it (oldest retired first).
	later := same
	later.Allocations = same.Allocations.Clone()
	ReconcileAllocations(same.Allocations, &later)
	if s, ok := later.Allocations.LinkSlot("x"); !ok || s != 5 {
		t.Fatalf("x = %v %v, want retired slot 5", s, ok)
	}
	if len(later.Allocations.RetiredLinks) != 0 {
		t.Fatalf("reused slot still retired: %v", later.Allocations.RetiredLinks)
	}
}

func TestReconcileAcceptsImportedSlotsAndAvoidsCollisions(t *testing.T) {
	base := allocTopo("a")
	MigrateAllocations(&base)
	next := allocTopo("a", "b", "c")
	next.Allocations = &Allocations{Links: map[string]Slot{"a": {9}, "b": {6}, "c": {0}}}
	ReconcileAllocations(base.Allocations, &next)
	got := next.Allocations.Links
	// a is stored (0); b's own slot is free and taken; c's collides with a
	// and gets the lowest free one.
	if got["a"] != (Slot{0}) || got["b"] != (Slot{6}) || got["c"] != (Slot{1}) {
		t.Fatalf("links = %v", got)
	}
}

func TestFillAvoidsManualAddressesPortsAndIfaceNames(t *testing.T) {
	topo := allocTopo("a")
	MigrateAllocations(&topo)
	// Slot 1's subnet is typed into a, slot 2's port is a's wg_port, a
	// host interface is called m03.
	topo.Links[0].FromV4, topo.Links[0].ToV4 = "10.66.2.1", "10.66.2.2"
	topo.Links[0].WGPort = LinkDefaultWGPort(2)
	topo.Nodes[1].WANInterface = "m03"
	topo.Links = append(topo.Links, Link{ID: "b", From: "gw", To: "r", Transport: TransportDirectWG, Enabled: true})
	eff := EffectiveAllocations(topo)
	if s, _ := eff.LinkSlot("b"); s != 4 {
		t.Fatalf("b got slot %d, want 4", s)
	}
	// A failover link also needs the slot's WSS-leg port and subnets
	// (slot 1 is still blocked by a's typed-in subnet).
	topo.Links = append(topo.Links, Link{ID: "c", From: "gw", To: "r", Transport: TransportUDPWSSFailover, Enabled: true})
	eff = EffectiveAllocations(topo)
	if s, _ := eff.LinkSlot("c"); s != 5 {
		t.Fatalf("c got slot %d, want 5", s)
	}
}

func TestMarkSlotsStableAndRetired(t *testing.T) {
	base := allocTopo()
	MigrateAllocations(&base)
	next := allocTopo()
	next.Nodes = append(next.Nodes, Node{ID: "e0", Role: RoleExit})
	next.Groups = next.Groups[:1] // g1 deleted
	ReconcileAllocations(base.Allocations, &next)
	a := next.Allocations
	if a.Exits["e1"] != (Slot{0}) || a.Exits["e2"] != (Slot{1}) || a.Groups["g2"] != (Slot{3}) {
		t.Fatalf("existing marks moved: %v %v", a.Exits, a.Groups)
	}
	if a.Exits["e0"] != (Slot{4}) {
		t.Fatalf("new exit = %v, want never-used slot 4", a.Exits["e0"])
	}
	if !reflect.DeepEqual(a.RetiredMarks, []int{2}) {
		t.Fatalf("retired marks = %v", a.RetiredMarks)
	}
}

func TestAllocationsJSONShape(t *testing.T) {
	topo := allocTopo("a")
	MigrateAllocations(&topo)
	raw, _ := json.Marshal(topo.Allocations)
	want := `{"links":{"a":{"slot":0}},"exits":{"e1":{"slot":0},"e2":{"slot":1}},"groups":{"g1":{"slot":2},"g2":{"slot":3}}}`
	if string(raw) != want {
		t.Fatalf("json = %s", raw)
	}
	// A migrated topology without any object still has a (empty) table:
	// it is not mistaken for a document from before the table.
	empty := Topology{}
	MigrateAllocations(&empty)
	b, _ := json.Marshal(empty)
	var back Topology
	_ = json.Unmarshal(b, &back)
	if back.Allocations == nil {
		t.Fatalf("empty table lost in JSON: %s", b)
	}
}
