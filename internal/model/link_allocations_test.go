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
	// the old index; the disabled one gets the next free slot. A cf_mesh
	// link was not an interface in such a document: it is not counted in
	// the positions and takes a slot after every other link, although its
	// ID sorts before some of them.
	want := map[string]Slot{"0-wss": {0}, "a": {1}, "b": {2}, "c": {3}, "aa-off": {4}, "mesh": {5}}
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

// ---- Mesh underlay slots

func meshAllocTopo() Topology {
	return Topology{
		Nodes: []Node{
			{ID: "gw", Role: RoleGateway}, {ID: "r", Role: RoleRelay}, {ID: "hub", Role: RoleHub},
			{ID: "us", Role: RoleExit, PathV4: true}, {ID: "jp", Role: RoleExit, PathV4: true}, {ID: "sg", Role: RoleExit, PathV4: true},
			{ID: "v6", Role: RoleExit, PathV6: true, V6Workaround: WorkaroundMesh},
		},
		Links: []Link{
			{ID: "gw-r", From: "gw", To: "r", Transport: TransportDirectWG, Enabled: true},
			{ID: "hub-us", From: "hub", To: "us", Transport: TransportDirectWG, Enabled: true},
			{ID: "hub-jp", From: "hub", To: "jp", Transport: TransportDirectWG, Enabled: true},
			{ID: "hub-sg", From: "hub", To: "sg", Transport: TransportDirectWG, Enabled: true},
			{ID: "hub-us-mesh", From: "hub", To: "us", Transport: TransportCFMesh, Enabled: true, Standby: true},
			{ID: "a-jp-mesh", From: "jp", To: "hub", Transport: TransportCFMesh, Enabled: true, Standby: true},
			{ID: "hub-v6-mesh", From: "hub", To: "v6", Transport: TransportCFMesh, Enabled: true, Standby: true},
		},
	}
}

// Every exit at the end of a cf_mesh link gets one Mesh underlay slot (in
// exit-ID order), and with it one address of the pool; an exit without a
// Mesh edge gets none, and a topology without Mesh edges has no Mesh table
// at all (its stored document does not change).
func TestMeshUnderlayAllocation(t *testing.T) {
	topo := meshAllocTopo()
	ReconcileAllocations(nil, &topo)
	want := map[string]Slot{"jp": {0}, "us": {1}, "v6": {2}}
	if !reflect.DeepEqual(topo.Allocations.Mesh, want) {
		t.Fatalf("mesh slots %v, want %v", topo.Allocations.Mesh, want)
	}
	legs := topo.MeshLegs()
	got := map[string]string{}
	for _, m := range legs {
		if m.Hub != "hub" {
			t.Fatalf("leg %s hub %q", m.Link.ID, m.Hub)
		}
		got[m.Exit] = m.Route()
		if (m.Exit == "v6") != m.Sole {
			t.Fatalf("leg %s: sole %v", m.Link.ID, m.Sole)
		}
	}
	if !reflect.DeepEqual(got, map[string]string{"jp": "10.68.0.1/32", "us": "10.68.0.2/32", "v6": "10.68.0.3/32"}) {
		t.Fatalf("routes %v", got)
	}
	// Another pool: the same slots, other addresses.
	topo.Settings.MeshUnderlayPrefix = "172.20.9.0/28"
	if m, ok := topo.MeshLegOf("hub", "us"); !ok || m.Route() != "172.20.9.2/32" {
		t.Fatalf("us in 172.20.9.0/28: %+v %v", m, ok)
	}

	plain := allocTopo("a", "b")
	ReconcileAllocations(nil, &plain)
	if plain.Allocations.Mesh != nil || plain.Allocations.RetiredMesh != nil || plain.HasMeshLegs() {
		t.Fatalf("a topology without Mesh edges got a Mesh table: %+v", plain.Allocations)
	}
	raw, _ := json.Marshal(plain.Allocations)
	if string(raw) == "" || contains(string(raw), "mesh") {
		t.Fatalf("its stored table mentions mesh: %s", raw)
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

// A Mesh address stays with its exit: adding, removing, disabling or
// reordering other Mesh edges never moves it; a removed edge's slot is
// retired and not handed out in the same save, nor while a fresh one is
// left.
func TestMeshUnderlaySlotsAreStable(t *testing.T) {
	topo := meshAllocTopo()
	ReconcileAllocations(nil, &topo)
	base := topo.Allocations.Clone()

	// Disable us's Mesh edge and add one for sg: us keeps its slot, sg gets
	// the next fresh one.
	next := meshAllocTopo()
	for i := range next.Links {
		if next.Links[i].ID == "hub-us-mesh" {
			next.Links[i].Enabled = false
		}
	}
	next.Links = append([]Link{{ID: "0-sg-mesh", From: "hub", To: "sg", Transport: TransportCFMesh, Enabled: true, Standby: true}}, next.Links...)
	ReconcileAllocations(base, &next)
	if !reflect.DeepEqual(next.Allocations.Mesh, map[string]Slot{"jp": {0}, "us": {1}, "v6": {2}, "sg": {3}}) {
		t.Fatalf("after adding sg: %v", next.Allocations.Mesh)
	}
	// The slot table a client sends back cannot move an existing exit.
	forged := meshAllocTopo()
	forged.Allocations = &Allocations{Mesh: map[string]Slot{"us": {0}, "jp": {1}, "v6": {7}}}
	ReconcileAllocations(base, &forged)
	if !reflect.DeepEqual(forged.Allocations.Mesh, base.Mesh) {
		t.Fatalf("a client table moved Mesh slots: %v", forged.Allocations.Mesh)
	}

	// Remove jp's edge: slot 0 is retired; a new exit in the same save does
	// not get it.
	gone := meshAllocTopo()
	var links []Link
	for _, l := range gone.Links {
		if l.ID != "a-jp-mesh" {
			links = append(links, l)
		}
	}
	gone.Links = append(links, Link{ID: "sg-mesh", From: "hub", To: "sg", Transport: TransportCFMesh, Enabled: true, Standby: true})
	ReconcileAllocations(base, &gone)
	a := gone.Allocations
	if _, still := a.Mesh["jp"]; still || !reflect.DeepEqual(a.RetiredMesh, []int{0}) || a.Mesh["sg"].Slot != 3 || a.Mesh["us"].Slot != 1 {
		t.Fatalf("after removing jp's edge: %v retired %v", a.Mesh, a.RetiredMesh)
	}
	// The exit's link slot and mark slot never depended on it.
	if a.Exits["jp"] != base.Exits["jp"] || a.Links["hub-jp"] != base.Links["hub-jp"] {
		t.Fatalf("removing a Mesh edge moved another allocation")
	}
	// Clone copies the Mesh table.
	c := a.Clone()
	c.Mesh["us"] = Slot{9}
	if a.Mesh["us"].Slot != 1 {
		t.Fatal("Clone shares the Mesh table")
	}
}

// The pool: IPv4 only, a network address, /16 to /30; an address is host
// slot+1 and never the network or broadcast address.
func TestMeshUnderlayPrefixAndAddr(t *testing.T) {
	for raw, ok := range map[string]bool{
		"": true, "10.68.0.0/24": true, "172.20.0.0/16": true, "192.168.77.4/30": true,
		"10.68.0.1/24": false, "10.0.0.0/8": false, "10.68.0.0/31": false, "fd68::/64": false, "nonsense": false,
	} {
		topo := Topology{Settings: Settings{MeshUnderlayPrefix: raw}}
		if _, err := topo.MeshUnderlayPrefix(); (err == nil) != ok {
			t.Errorf("pool %q: err %v, want ok %v", raw, err, ok)
		}
	}
	def, _ := Topology{}.MeshUnderlayPrefix()
	if def.String() != DefaultMeshUnderlayPrefix {
		t.Fatalf("default pool %s", def)
	}
	if a, ok := MeshUnderlayAddr(def, 0); !ok || a.String() != "10.68.0.1" {
		t.Fatalf("slot 0: %v %v", a, ok)
	}
	if a, ok := MeshUnderlayAddr(def, MaxMeshSlots-1); !ok || a.String() != fmt.Sprintf("10.68.0.%d", MaxMeshSlots) {
		t.Fatalf("last slot: %v %v", a, ok)
	}
	small, _ := Topology{Settings: Settings{MeshUnderlayPrefix: "192.168.77.4/30"}}.MeshUnderlayPrefix()
	if a, ok := MeshUnderlayAddr(small, 1); !ok || a.String() != "192.168.77.6" {
		t.Fatalf("/30 slot 1: %v %v", a, ok)
	}
	if _, ok := MeshUnderlayAddr(small, 2); ok {
		t.Fatal("/30 gave out its broadcast address")
	}
	if _, ok := MeshUnderlayAddr(def, -1); ok {
		t.Fatal("negative slot")
	}
}
