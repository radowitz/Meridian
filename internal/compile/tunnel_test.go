package compile

import (
	"encoding/json"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/radowitz/meridian/internal/defaults"
	"github.com/radowitz/meridian/internal/model"
	"github.com/radowitz/meridian/internal/validate"
)

// Stable allocation (model.Allocations): interface names, default ports and
// subnets of a link, and the marks of an exit or group, follow their own
// persisted slot, never their position among the others.

// nodeFiles groups a bundle's files by node ("_top" for the shared ones).
func nodeFiles(t *testing.T, topo model.Topology) map[string]map[string]string {
	t.Helper()
	b, err := Compile(topo)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	out := map[string]map[string]string{}
	for p, body := range b.Files {
		node := "_top"
		if strings.HasPrefix(p, "nodes/") {
			node = strings.SplitN(p, "/", 3)[1]
		}
		if out[node] == nil {
			out[node] = map[string]string{}
		}
		out[node][p] = body
	}
	return out
}

// changedNodes are the nodes whose file set or any file differs.
func changedNodes(a, b map[string]map[string]string) []string {
	all := map[string]bool{}
	for n := range a {
		all[n] = true
	}
	for n := range b {
		all[n] = true
	}
	var out []string
	for n := range all {
		if !reflect.DeepEqual(a[n], b[n]) {
			out = append(out, n)
		}
	}
	sort.Strings(out)
	return out
}

// endsOf are the tunnel ends of the links (an IX end resolves to its
// dedicated-line neighbour), sorted.
func endsOf(t *testing.T, topo model.Topology, links ...model.Link) []string {
	t.Helper()
	set := map[string]bool{}
	for _, l := range links {
		w, e, ok := validate.TunnelEnds(topo, l)
		if !ok {
			t.Fatalf("link %s has no ends", l.ID)
		}
		set[w.ID], set[e.ID] = true, true
	}
	var out []string
	for n := range set {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

func migrated(topo model.Topology) model.Topology {
	model.MigrateAllocations(&topo)
	return topo
}

func withLinks(topo model.Topology, add ...model.Link) model.Topology {
	n := topo
	n.Links = append(append([]model.Link(nil), topo.Links...), add...)
	model.ReconcileAllocations(topo.Allocations, &n)
	return n
}

func withoutLinks(topo model.Topology, ids ...string) model.Topology {
	drop := map[string]bool{}
	for _, id := range ids {
		drop[id] = true
	}
	n := topo
	n.Links = nil
	for _, l := range topo.Links {
		if !drop[l.ID] {
			n.Links = append(n.Links, l)
		}
	}
	model.ReconcileAllocations(topo.Allocations, &n)
	return n
}

// Links whose IDs sort before every existing one: with position-derived
// numbering each of them renumbered every other link.
var extraLinks = []model.Link{
	{ID: "a-ix-dc1-wss", From: "ix", To: "dc1", Transport: model.TransportWGOverWSS, Enabled: true, Standby: true},
	{ID: "a-gw-ali-b", From: "gw", To: "ali", Transport: model.TransportDirectWG, Enabled: true, Standby: true},
	{ID: "a-hk5-dc1-b", From: "hk5", To: "dc1", Transport: model.TransportDirectWG, Enabled: true, Standby: true},
	{ID: "a-ali-ix-b", From: "ali", To: "ix", Transport: model.TransportUDPWSSFailover, Enabled: true, Standby: true},
}

func multiNodeExamples() map[string]func() model.Topology {
	return map[string]func() model.Topology{
		"dual_hub":      defaults.DualHubExample,
		"shared_relays": defaults.SharedRelaysExample,
	}
}

// The migration inherits what is installed: a migrated topology (and its
// JSON round trip, i.e. an export brought back) compiles byte-identically
// to the same topology without a table, and migrating twice is a no-op.
func TestAllocationMigrationCompilesIdentically(t *testing.T) {
	cases := map[string]func() model.Topology{"example": defaults.Example}
	for k, v := range multiNodeExamples() {
		cases[k] = v
	}
	cases["group_dns"] = func() model.Topology { topo, _ := groupDNSExample(); return topo }
	for name, mk := range cases {
		legacy := mk()
		lb, err := Compile(legacy)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		m := migrated(mk())
		if m.Allocations == nil {
			t.Fatalf("%s: no table after migration", name)
		}
		mb, err := Compile(m)
		if err != nil {
			t.Fatalf("%s migrated: %v", name, err)
		}
		if lb.Canonical() != mb.Canonical() {
			t.Fatalf("%s: the migrated topology compiles differently", name)
		}
		raw, _ := json.Marshal(m)
		var back model.Topology
		if err := json.Unmarshal(raw, &back); err != nil {
			t.Fatal(err)
		}
		if model.MigrateAllocations(&back) {
			t.Fatalf("%s: second migration changed the table", name)
		}
		bb, err := Compile(back)
		if err != nil {
			t.Fatal(err)
		}
		if bb.Canonical() != lb.Canonical() {
			t.Fatalf("%s: JSON round trip compiles differently", name)
		}
	}
}

// The golden files stay valid for the migrated topologies: same digests,
// no regeneration (the store migrates the allocation table after the
// region-group migration, as here).
func TestGoldenSingleHubUnchangedAfterMigration(t *testing.T) {
	b, err := Compile(migrated(defaults.Example()))
	if err != nil {
		t.Fatal(err)
	}
	checkGolden(t, "single_hub_example.golden", b)
	topo, dec := groupDNSExample()
	model.MigrateRegionGroups(&topo)
	b, err = CompileWithDecisions(migrated(topo), dec)
	if err != nil {
		t.Fatal(err)
	}
	checkGolden(t, "single_hub_groupdns.golden", b)
}

func TestAllocationReorderLinksIdentical(t *testing.T) {
	for name, mk := range multiNodeExamples() {
		base := migrated(withLinks(migrated(mk()), extraLinks[0], extraLinks[1]))
		want, err := Compile(base)
		if err != nil {
			t.Fatal(err)
		}
		rev := base
		rev.Links = nil
		for i := len(base.Links) - 1; i >= 0; i-- {
			rev.Links = append(rev.Links, base.Links[i])
		}
		rev.Nodes = append([]model.Node(nil), base.Nodes...)
		sort.Slice(rev.Nodes, func(i, j int) bool { return rev.Nodes[i].ID > rev.Nodes[j].ID })
		got, err := Compile(rev)
		if err != nil {
			t.Fatal(err)
		}
		if got.Canonical() != want.Canonical() {
			t.Fatalf("%s: reordering links and nodes changed the output", name)
		}
	}
}

// Adding a link changes only the nodes at its two ends; every other node's
// files stay byte-identical (with position-derived numbering every node
// changed: the interfaces of all later links were renamed and renumbered).
func TestAllocationAddLinkChangesOnlyItsEnds(t *testing.T) {
	for name, mk := range multiNodeExamples() {
		base := migrated(mk())
		before := nodeFiles(t, base)
		for _, l := range extraLinks {
			next := withLinks(base, l)
			got := changedNodes(before, nodeFiles(t, next))
			if want := endsOf(t, next, l); !reflect.DeepEqual(got, want) {
				t.Errorf("%s: adding %s changed %v, want only its ends %v", name, l.ID, got, want)
			}
			// Every link that was there keeps its slot.
			for id, s := range base.Allocations.Links {
				if next.Allocations.Links[id] != s {
					t.Errorf("%s: adding %s moved %s from %v to %v", name, l.ID, id, s, next.Allocations.Links[id])
				}
			}
		}
	}
}

// Removing a link changes only its ends. The links removed here were added
// after the migration (higher slots than the installed ones), the usual
// case. (A link that sorts first in the gateway's tunnel order also feeds
// the gateway's underlay4 set order and, for a relay's hub link, the
// gateway's relay probe target; removing such a link changes the gateway as
// well: the probe for a real reason, the set order cosmetically.)
func TestAllocationRemoveLinkChangesOnlyItsEnds(t *testing.T) {
	for name, mk := range multiNodeExamples() {
		base := withLinks(migrated(mk()), extraLinks...)
		before := nodeFiles(t, base)
		for _, l := range extraLinks {
			next := withoutLinks(base, l.ID)
			got := changedNodes(before, nodeFiles(t, next))
			if want := endsOf(t, base, l); !reflect.DeepEqual(got, want) {
				t.Errorf("%s: removing %s changed %v, want only its ends %v", name, l.ID, got, want)
			}
			if s, _ := base.Allocations.LinkSlot(l.ID); len(next.Allocations.RetiredLinks) != 1 || next.Allocations.RetiredLinks[0] != s {
				t.Errorf("%s: removing %s retired %v, want [%d]", name, l.ID, next.Allocations.RetiredLinks, s)
			}
			for id, s := range next.Allocations.Links {
				if base.Allocations.Links[id] != s {
					t.Errorf("%s: removing %s moved %s", name, l.ID, id)
				}
			}
		}
	}
}

// A topology migrated with the extra links in it (their ID-order positions
// put them first, slots 0–3) keeps every other link's slot when one of
// them is removed: the interfaces of the others are not renamed.
func TestAllocationRemoveFirstLinkKeepsOthers(t *testing.T) {
	full := defaults.SharedRelaysExample()
	full.Links = append(full.Links, extraLinks...)
	base := migrated(full)
	if s, _ := base.Allocations.LinkSlot("a-ali-ix-b"); s != 0 {
		t.Fatalf("setup: a-ali-ix-b slot %d", s)
	}
	before := nodeFiles(t, base)
	next := withoutLinks(base, "a-ali-ix-b")
	got := changedNodes(before, nodeFiles(t, next))
	// ali and ix are its ends; the gateway probes the relay through its
	// first hub tunnel, which was this one.
	if want := []string{"ali", "gw", "ix"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("changed %v, want %v", got, want)
	}
	for _, tun := range mustTunnels(t, next) {
		if s, _ := base.Allocations.LinkSlot(tun.LinkID); tun.Base != model.LinkIface(s) {
			t.Fatalf("%s renamed to %s", tun.LinkID, tun.Base)
		}
	}
}

// Delete one link and add another in the same save: the new link does not
// take the deleted link's interface (it may still exist on the old ends
// with another peer and key), and only the ends of both links change.
func TestAllocationDeleteAndAddInOneSave(t *testing.T) {
	base := withLinks(migrated(defaults.SharedRelaysExample()), extraLinks[0])
	oldSlot, _ := base.Allocations.LinkSlot(extraLinks[0].ID)
	before := nodeFiles(t, base)

	next := base
	next.Links = nil
	for _, l := range base.Links {
		if l.ID != extraLinks[0].ID {
			next.Links = append(next.Links, l)
		}
	}
	next.Links = append(next.Links, extraLinks[2])
	model.ReconcileAllocations(base.Allocations, &next)
	newSlot, ok := next.Allocations.LinkSlot(extraLinks[2].ID)
	if !ok || newSlot == oldSlot {
		t.Fatalf("new link slot %d (ok=%v), deleted link had %d", newSlot, ok, oldSlot)
	}
	for id, s := range next.Allocations.Links {
		if id != extraLinks[2].ID && s.Slot == newSlot {
			t.Fatalf("new link shares slot %d with %s", newSlot, id)
		}
	}
	if !reflect.DeepEqual(next.Allocations.RetiredLinks, []int{oldSlot}) {
		t.Fatalf("retired = %v", next.Allocations.RetiredLinks)
	}
	got := changedNodes(before, nodeFiles(t, next))
	want := endsOf(t, base, extraLinks[0])
	for _, n := range endsOf(t, next, extraLinks[2]) {
		if !contains(want, n) {
			want = append(want, n)
		}
	}
	sort.Strings(want)
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("changed %v, want %v", got, want)
	}
	// The new interface name is not the deleted one's.
	for _, tun := range mustTunnels(t, next) {
		if tun.LinkID == extraLinks[2].ID && tun.Base == model.LinkIface(oldSlot) {
			t.Fatalf("new link reuses %s", tun.Base)
		}
	}
}

func contains(xs []string, s string) bool {
	for _, x := range xs {
		if x == s {
			return true
		}
	}
	return false
}

// Explicit values keep precedence over the slot's defaults.
func TestAllocationExplicitValuesWin(t *testing.T) {
	topo := migrated(defaults.DualHubExample())
	for i := range topo.Links {
		if topo.Links[i].ID == "ix-dc1" {
			topo.Links[i].WGPort = 40001
			topo.Links[i].FromV4, topo.Links[i].ToV4 = "10.66.90.1", "10.66.90.2"
		}
	}
	slot, _ := topo.Allocations.LinkSlot("ix-dc1")
	for _, tun := range mustTunnels(t, topo) {
		if tun.LinkID != "ix-dc1" {
			continue
		}
		if tun.Base != model.LinkIface(slot) || tun.WGPort != 40001 || tun.WestV4 != "10.66.90.1" || tun.EastV4 != "10.66.90.2" {
			t.Fatalf("tunnel = %s port %d %s/%s", tun.Base, tun.WGPort, tun.WestV4, tun.EastV4)
		}
		_, _, w6, e6 := model.LinkAutoAddrs(slot)
		if tun.WestULA != w6 || tun.EastULA != e6 {
			t.Fatalf("ULA = %s/%s, want the slot's %s/%s", tun.WestULA, tun.EastULA, w6, e6)
		}
	}
}

// Exits and groups: adding an exit or a group whose ID sorts first moves no
// other exit's or group's mark, table, transit or resolver address, and
// leaves the other exits' files alone.
func TestAllocationExitsAndGroupsStable(t *testing.T) {
	base := defaults.SharedRelaysExample()
	base.Groups = append(base.Groups, model.RegionGroup{ID: "m-other", Name: "other", Region: "hk", Members: []string{"dc2"}, Mode: model.GroupAuto, ExcludeResidential: true})
	base = migrated(base)
	before := nodeFiles(t, base)
	marks := func(topo model.Topology) map[string]ExitPlan {
		tuns := mustTunnels(t, topo)
		out := map[string]ExitPlan{}
		for _, e := range planExits(topo, tuns) {
			out["exit/"+e.Node.ID] = ExitPlan{Index: e.Index, Mark: e.Mark, Table: e.Table, TransitV4: e.TransitV4, TransitV6: e.TransitV6, Resolver: e.Resolver}
		}
		for _, g := range planGroups(topo, planExits(topo, tuns)) {
			out["group/"+g.Group.ID] = ExitPlan{Index: g.Index, Mark: g.Mark, Table: g.Table, TransitV4: g.TransitV4, TransitV6: g.TransitV6, Resolver: g.Resolver}
		}
		return out
	}
	m0 := marks(base)

	next := base
	next.Nodes = append(append([]model.Node(nil), base.Nodes...), model.Node{ID: "a-dc0", Name: "dc0", Role: model.RoleExit, Region: "hk", Managed: true,
		EndpointV4: "203.0.113.43", WANInterface: "eth0", PathV4: true, EgressV4: true})
	next.Links = append(append([]model.Link(nil), base.Links...),
		model.Link{ID: "ix-a-dc0", From: "ix", To: "a-dc0", Transport: model.TransportDirectWG, Enabled: true},
		model.Link{ID: "hk5-a-dc0", From: "hk5", To: "a-dc0", Transport: model.TransportDirectWG, Enabled: true})
	next.Groups = append([]model.RegionGroup{{ID: "a-grp", Name: "a", Region: "hk", Members: []string{"a-dc0"}, Mode: model.GroupAuto, ExcludeResidential: true}}, base.Groups...)
	model.ReconcileAllocations(base.Allocations, &next)
	m1 := marks(next)
	for k, v := range m0 {
		if m1[k] != v {
			t.Errorf("%s moved: %+v → %+v", k, v, m1[k])
		}
	}
	if len(m1) != len(m0)+2 {
		t.Fatalf("plans = %d, want %d", len(m1), len(m0)+2)
	}
	got := changedNodes(before, nodeFiles(t, next))
	// The new exit, the hubs (tables, tunnels) and the gateway (marks,
	// rules) change; the existing exits and the relays do not.
	for _, n := range []string{"dc1", "dc2", "ali", "ali2"} {
		if contains(got, n) {
			t.Errorf("adding an exit and a group changed %s (changed: %v)", n, got)
		}
	}
	for _, n := range []string{"a-dc0", "gw", "ix", "hk5"} {
		if !contains(got, n) {
			t.Errorf("%s did not change (changed: %v)", n, got)
		}
	}
}

// Link slots, not positions, number the tunnels; a link without a slot
// (exhaustion) is refused by validation before compile.
func TestAllocationExhaustionRefused(t *testing.T) {
	topo := migrated(defaults.DualHubExample())
	ghost := topo.Allocations.Clone()
	for s := 0; s < model.MaxLinkSlots; s++ {
		if !slotUsed(ghost, s) {
			ghost.Links["ghost-"+model.LinkIface(s)] = model.Slot{Slot: s}
		}
	}
	topo.Allocations = ghost
	topo.Links = append(topo.Links, extraLinks[1])
	_, err := Compile(topo)
	ve, ok := err.(*ValidationError)
	if !ok {
		t.Fatalf("compile err = %v, want a validation error", err)
	}
	found := false
	for _, is := range ve.Result.Issues {
		if is.Code == "link_alloc_exhausted" && is.LinkID == extraLinks[1].ID {
			found = true
		}
	}
	if !found {
		t.Fatalf("no link_alloc_exhausted for %s: %+v", extraLinks[1].ID, ve.Result.Issues)
	}
}

func slotUsed(a *model.Allocations, s int) bool {
	for _, v := range a.Links {
		if v.Slot == s {
			return true
		}
	}
	return false
}

func TestLinkResourcesShowSlotValues(t *testing.T) {
	topo := migrated(defaults.DualHubExample())
	topo.Links = append(topo.Links, model.Link{ID: "zz-off", From: "gw", To: "ali", Transport: model.TransportDirectWG})
	model.ReconcileAllocations(topo.Allocations, &topo)
	res := LinkResources(topo)
	by := map[string]LinkResource{}
	for _, r := range res {
		by[r.LinkID] = r
	}
	gw := by["gw-ali"]
	slot, _ := topo.Allocations.LinkSlot("gw-ali")
	if gw.State != "allocated" || gw.Slot == nil || *gw.Slot != slot || len(gw.Legs) != 2 ||
		gw.Legs[0].Iface != model.LinkIface(slot) || gw.Legs[1].Iface != model.LinkIface(slot)+"w" ||
		gw.WGPort != model.LinkDefaultWGPort(slot) || gw.WSSLegPort != gw.WGPort+1 || gw.LocalPort != model.LinkDefaultLocalPort(slot) {
		t.Fatalf("gw-ali = %+v", gw)
	}
	off := by["zz-off"]
	if off.Enabled || off.State != "allocated" || off.Slot == nil || len(off.Legs) != 1 {
		t.Fatalf("disabled link = %+v", off)
	}
	marks := MarkResources(topo)
	if len(marks) != 3 || marks[0].ID != "dc1" || marks[0].Mark != "0x101" || marks[2].Kind != "group" || marks[2].TransitV4 != "10.66.200.12" {
		t.Fatalf("marks = %+v", marks)
	}
}
