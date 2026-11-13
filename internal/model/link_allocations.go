package model

import (
	"fmt"
	"net/netip"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

var tunnelIfaceRe = regexp.MustCompile(`^m([0-9]{2,3})w?$`)

// Stable resource allocation (docs/architecture.md「接口名、端口和网段的分配」).
//
// Every tunnel link owns one link slot; every exit and every region group
// owns one mark slot. A slot is allocated once, stored in
// Topology.Allocations under the object's ID, and never changes while the
// object exists: adding, removing, reordering, enabling or disabling other
// links (or exits, or groups) leaves it alone. Everything that used to be
// derived from a link's position in the sorted link list is derived from
// its slot instead, with the same formulas:
//
//	interface       m%02d (slot), the WSS leg of udp_wss_failover m%02dw
//	WireGuard port  51820 + slot (the WSS leg of udp_wss_failover +1)
//	wstunnel local  52000 + slot
//	tunnel v4       10.66.(slot+1).1 / .2 in 10.66.(slot+1).0/30
//	tunnel ULA      fd66:0:0:(slot+1)::1 / ::2
//	WSS-leg v4      10.66.(100+slot).1 / .2, ULA fd66:0:0:(0x80+slot)::1 / ::2
//
// and for a mark slot: fwmark 0x101 + slot, hub table 201 + slot, transit
// 10.66.200.(10+slot) / fd66:0:0:ff::(10+slot), resolver fd66::54:(slot+1)
// (exit) or fd66::53:(slot+1) (group). Explicit values on the link
// (wg_port, wss_local_port, the node's listen_port, from_v4 …) still win.
//
// A topology without the table (nil) is a document from before the table
// existed: its slots are its positions, exactly as the compiler numbered
// them before (MigrateAllocations), so the first compile after an upgrade
// is byte-identical. The store writes the table on the first save and
// keeps it authoritative from then on (ReconcileAllocations).

const (
	// MaxLinkSlots bounds link slots: slot 98 is the last one whose
	// addresses stay apart (10.66.99.0/30 below the WSS-leg range
	// 10.66.100–198, which stays below the transit 10.66.200.0/24).
	MaxLinkSlots = 99
	// MaxMarkSlots is the number of exit and group marks (fwmark 0x101 …,
	// transit 10.66.200.10–249, hub tables 201–440).
	MaxMarkSlots = 240

	linkPortBase  = 51820
	localPortBase = 52000
)

// Allocations is the persisted slot table. Map keys are object IDs.
type Allocations struct {
	// Links: link ID → link slot (tunnel links only).
	Links map[string]Slot `json:"links,omitempty"`
	// Exits (exit node ID) and Groups (region group ID) share the mark
	// slot space.
	Exits  map[string]Slot `json:"exits,omitempty"`
	Groups map[string]Slot `json:"groups,omitempty"`
	// RetiredLinks / RetiredMarks are slots whose owner was deleted, oldest
	// first. A retired slot is not given to a new object while a slot that
	// was never used is left, and never in the save that retired it: its
	// interface, port and addresses may still exist on hosts that were not
	// re-provisioned since.
	RetiredLinks []int `json:"retired_links,omitempty"`
	RetiredMarks []int `json:"retired_marks,omitempty"`
}

// Slot is one allocation.
type Slot struct {
	Slot int `json:"slot"`
}

// Clone is a deep copy (nil stays nil).
func (a *Allocations) Clone() *Allocations {
	if a == nil {
		return nil
	}
	out := &Allocations{
		Links:        cloneSlots(a.Links),
		Exits:        cloneSlots(a.Exits),
		Groups:       cloneSlots(a.Groups),
		RetiredLinks: append([]int(nil), a.RetiredLinks...),
		RetiredMarks: append([]int(nil), a.RetiredMarks...),
	}
	return out
}

func cloneSlots(m map[string]Slot) map[string]Slot {
	if m == nil {
		return nil
	}
	out := make(map[string]Slot, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

// LinkSlot is l's slot (ok false: none allocated).
func (a *Allocations) LinkSlot(id string) (int, bool) {
	if a == nil {
		return 0, false
	}
	s, ok := a.Links[id]
	return s.Slot, ok
}

// ExitSlot / GroupSlot are the mark slots.
func (a *Allocations) ExitSlot(id string) (int, bool) {
	if a == nil {
		return 0, false
	}
	s, ok := a.Exits[id]
	return s.Slot, ok
}

func (a *Allocations) GroupSlot(id string) (int, bool) {
	if a == nil {
		return 0, false
	}
	s, ok := a.Groups[id]
	return s.Slot, ok
}

// TunnelTransport: the transport becomes a WireGuard interface (and so
// needs a link slot).
func TunnelTransport(tr Transport) bool {
	switch tr {
	case TransportDirectWG, TransportWGOverWSS, TransportUDPWSSFailover, TransportIXReplacementWSS:
		return true
	}
	return false
}

// WSSTransport: the link has a WSS leg (wstunnel client port).
func WSSTransport(tr Transport) bool {
	switch tr {
	case TransportWGOverWSS, TransportUDPWSSFailover, TransportIXReplacementWSS:
		return true
	}
	return false
}

// LinkIface is the interface stem of a link slot; the WSS leg of
// udp_wss_failover appends "w".
func LinkIface(slot int) string { return fmt.Sprintf("m%02d", slot) }

// LinkDefaultWGPort / LinkDefaultLocalPort are the default ports of a slot.
func LinkDefaultWGPort(slot int) int    { return linkPortBase + slot }
func LinkDefaultLocalPort(slot int) int { return localPortBase + slot }

// LinkAutoAddrs are the default tunnel addresses (west, east) of a slot.
func LinkAutoAddrs(slot int) (westV4, eastV4, westULA, eastULA string) {
	n := slot + 1
	return fmt.Sprintf("10.66.%d.1", n), fmt.Sprintf("10.66.%d.2", n),
		fmt.Sprintf("fd66:0:0:%x::1", n), fmt.Sprintf("fd66:0:0:%x::2", n)
}

// LinkCompanionAddrs are the addresses of the WSS leg of udp_wss_failover.
func LinkCompanionAddrs(slot int) (westV4, eastV4, westULA, eastULA string) {
	host := 100 + slot
	return fmt.Sprintf("10.66.%d.1", host), fmt.Sprintf("10.66.%d.2", host),
		fmt.Sprintf("fd66:0:0:%x::1", 0x80+slot), fmt.Sprintf("fd66:0:0:%x::2", 0x80+slot)
}

// LinkAutoBlocks are the /30 and /64 a slot's default addresses sit in
// (primary leg, then the WSS leg).
func LinkAutoBlocks(slot int) (v4, ula, compV4, compULA netip.Prefix) {
	w4, _, w6, _ := LinkAutoAddrs(slot)
	c4, _, c6, _ := LinkCompanionAddrs(slot)
	return netip.PrefixFrom(netip.MustParseAddr(w4), 30).Masked(), netip.PrefixFrom(netip.MustParseAddr(w6), 64).Masked(),
		netip.PrefixFrom(netip.MustParseAddr(c4), 30).Masked(), netip.PrefixFrom(netip.MustParseAddr(c6), 64).Masked()
}

func sortedLinks(t Topology, keep func(Link) bool) []Link {
	var out []Link
	for _, l := range t.Links {
		if keep(l) {
			out = append(out, l)
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

func sortedExits(t Topology) []string {
	var out []string
	for _, n := range t.Nodes {
		if n.Role == RoleExit {
			out = append(out, n.ID)
		}
	}
	sort.Strings(out)
	return out
}

func sortedGroups(t Topology) []string {
	var out []string
	for _, g := range t.Groups {
		out = append(out, g.ID)
	}
	sort.Strings(out)
	return out
}

// wantsLinkSlot: the link has (or keeps) a link slot. Disabled tunnel
// links keep theirs, so enabling them again changes nothing else.
func wantsLinkSlot(l Link) bool { return l.ID != "" && TunnelTransport(l.Transport) }

// legacyAllocations is the position-derived numbering of the compiler
// before the table existed: enabled tunnel links sorted by ID get 0, 1, …;
// exits sorted by ID get 0 … E-1 and groups sorted by ID E, E+1, …
func legacyAllocations(t Topology) *Allocations {
	a := &Allocations{Links: map[string]Slot{}, Exits: map[string]Slot{}, Groups: map[string]Slot{}}
	i := 0
	for _, l := range sortedLinks(t, func(l Link) bool { return l.Enabled && TunnelTransport(l.Transport) }) {
		if _, dup := a.Links[l.ID]; dup || l.ID == "" {
			// Duplicate IDs are refused by validation; they never compiled.
			i++
			continue
		}
		if i < MaxLinkSlots {
			a.Links[l.ID] = Slot{i}
		}
		i++
	}
	exits := sortedExits(t)
	for j, id := range exits {
		if j < MaxMarkSlots && id != "" {
			a.Exits[id] = Slot{j}
		}
	}
	for j, id := range sortedGroups(t) {
		if k := len(exits) + j; k < MaxMarkSlots && id != "" {
			a.Groups[id] = Slot{k}
		}
	}
	return a
}

// MigrateAllocations fills Topology.Allocations of a document from before
// the table existed with the numbering its interfaces, ports, addresses
// and marks were compiled with (legacyAllocations), then gives the objects
// that had no number (disabled tunnel links) the lowest free slot. A
// topology that already has a table is left alone. Reports whether it
// changed anything; running it again is a no-op.
func MigrateAllocations(t *Topology) bool {
	if t.Allocations != nil {
		return false
	}
	a := legacyAllocations(*t)
	a.fill(*t, nil)
	t.Allocations = a
	return true
}

// EffectiveAllocations is the complete table compile and validation use:
// the stored table (or the migrated one for a document without it) with a
// slot for every tunnel link, exit and group that has none yet, chosen
// exactly as a save would choose it. Entries are not repaired: a duplicate
// or out-of-range slot stays and validation refuses it.
func EffectiveAllocations(t Topology) *Allocations {
	var a *Allocations
	if t.Allocations == nil {
		a = legacyAllocations(t)
	} else {
		a = t.Allocations.Clone()
	}
	a.fill(t, nil)
	return a
}

// ReconcileAllocations makes next's table authoritative against base, the
// table stored before this save (nil: nothing stored, next's own table or
// its migration is the base):
//
//   - an object base knows keeps base's slot, whatever next carries;
//   - a base entry whose object is gone is retired;
//   - an object base does not know takes the slot next carries for it when
//     that slot is in range, free, and was not retired by this same save
//     (an imported document's own allocation), else the lowest free slot.
//
// It never mutates base or next's old table; next.Allocations is replaced.
func ReconcileAllocations(base *Allocations, next *Topology) {
	if base == nil {
		if next.Allocations == nil {
			MigrateAllocations(next)
			return
		}
		base = &Allocations{RetiredLinks: next.Allocations.RetiredLinks, RetiredMarks: next.Allocations.RetiredMarks}
	}
	client := next.Allocations
	out := &Allocations{Links: map[string]Slot{}, Exits: map[string]Slot{}, Groups: map[string]Slot{}}
	retiredNow := map[int]bool{}
	retiredMarksNow := map[int]bool{}

	// Links.
	present := map[string]bool{}
	for _, l := range next.Links {
		if l.ID != "" {
			present[l.ID] = true
		}
	}
	for _, l := range sortedLinks(*next, func(Link) bool { return true }) {
		if s, ok := base.Links[l.ID]; ok {
			out.Links[l.ID] = s
		}
	}
	var baseIDs []string
	for id := range base.Links {
		baseIDs = append(baseIDs, id)
	}
	sort.Strings(baseIDs)
	retired := append([]int(nil), base.RetiredLinks...)
	for _, id := range baseIDs {
		if !present[id] {
			s := base.Links[id].Slot
			retiredNow[s] = true
			retired = appendUnique(retired, s)
		}
	}
	// Exits and groups.
	isExit := map[string]bool{}
	for _, n := range next.Nodes {
		if n.Role == RoleExit && n.ID != "" {
			isExit[n.ID] = true
		}
	}
	isGroup := map[string]bool{}
	for _, g := range next.Groups {
		if g.ID != "" {
			isGroup[g.ID] = true
		}
	}
	retiredM := append([]int(nil), base.RetiredMarks...)
	for _, kind := range []struct {
		base, out map[string]Slot
		live      map[string]bool
	}{{base.Exits, out.Exits, isExit}, {base.Groups, out.Groups, isGroup}} {
		var ids []string
		for id := range kind.base {
			ids = append(ids, id)
		}
		sort.Strings(ids)
		for _, id := range ids {
			if kind.live[id] {
				kind.out[id] = kind.base[id]
			} else {
				s := kind.base[id].Slot
				retiredMarksNow[s] = true
				retiredM = appendUnique(retiredM, s)
			}
		}
	}
	out.RetiredLinks, out.RetiredMarks = retired, retiredM

	// Entries next carries for objects base does not know (an import).
	if client != nil {
		usedL := out.usedLinkSlots()
		for _, l := range sortedLinks(*next, wantsLinkSlot) {
			if _, ok := out.Links[l.ID]; ok {
				continue
			}
			if s, ok := client.Links[l.ID]; ok && s.Slot >= 0 && s.Slot < MaxLinkSlots && !usedL[s.Slot] && !retiredNow[s.Slot] {
				out.Links[l.ID] = s
				usedL[s.Slot] = true
				out.RetiredLinks = removeInt(out.RetiredLinks, s.Slot)
			}
		}
		usedM := out.usedMarkSlots()
		for _, kind := range []struct {
			ids       []string
			client    map[string]Slot
			outSlots  map[string]Slot
			retiredNw map[int]bool
		}{{sortedExits(*next), client.Exits, out.Exits, retiredMarksNow}, {sortedGroups(*next), client.Groups, out.Groups, retiredMarksNow}} {
			for _, id := range kind.ids {
				if _, ok := kind.outSlots[id]; ok || id == "" {
					continue
				}
				if s, ok := kind.client[id]; ok && s.Slot >= 0 && s.Slot < MaxMarkSlots && !usedM[s.Slot] && !kind.retiredNw[s.Slot] {
					kind.outSlots[id] = s
					usedM[s.Slot] = true
					out.RetiredMarks = removeInt(out.RetiredMarks, s.Slot)
				}
			}
		}
	}
	out.fill(*next, &retiredSets{links: retiredNow, marks: retiredMarksNow})
	next.Allocations = out
}

type retiredSets struct{ links, marks map[int]bool }

func appendUnique(xs []int, v int) []int {
	for _, x := range xs {
		if x == v {
			return xs
		}
	}
	return append(xs, v)
}

func removeInt(xs []int, v int) []int {
	var out []int
	for _, x := range xs {
		if x != v {
			out = append(out, x)
		}
	}
	return out
}

func (a *Allocations) usedLinkSlots() map[int]bool {
	used := map[int]bool{}
	for _, s := range a.Links {
		used[s.Slot] = true
	}
	return used
}

func (a *Allocations) usedMarkSlots() map[int]bool {
	used := map[int]bool{}
	for _, s := range a.Exits {
		used[s.Slot] = true
	}
	for _, s := range a.Groups {
		used[s.Slot] = true
	}
	return used
}

// fill gives every tunnel link, exit and group without a slot the lowest
// slot that is not used, not retired and (for links) collides with no
// explicit address or port in t; when none is left, the oldest retired slot
// that this save did not retire. Objects that still get none stay without
// (validation reports the exhaustion). Order: by ID, so the result is
// deterministic.
func (a *Allocations) fill(t Topology, now *retiredSets) {
	if a.Links == nil {
		a.Links = map[string]Slot{}
	}
	if a.Exits == nil {
		a.Exits = map[string]Slot{}
	}
	if a.Groups == nil {
		a.Groups = map[string]Slot{}
	}
	if now == nil {
		now = &retiredSets{}
	}
	var pending []Link
	for _, l := range sortedLinks(t, wantsLinkSlot) {
		if _, ok := a.Links[l.ID]; !ok {
			pending = append(pending, l)
		}
	}
	if len(pending) > 0 {
		used := a.usedLinkSlots()
		retired := map[int]bool{}
		for _, s := range a.RetiredLinks {
			retired[s] = true
		}
		av := newAvoid(t, a)
		for _, l := range pending {
			pick := -1
			for s := 0; s < MaxLinkSlots && pick < 0; s++ {
				if !used[s] && !retired[s] && av.ok(l, s) {
					pick = s
				}
			}
			for _, s := range a.RetiredLinks {
				if pick >= 0 {
					break
				}
				if !used[s] && !now.links[s] && s >= 0 && s < MaxLinkSlots && av.ok(l, s) {
					pick = s
				}
			}
			if pick < 0 {
				continue
			}
			a.Links[l.ID] = Slot{pick}
			used[pick] = true
			a.RetiredLinks = removeInt(a.RetiredLinks, pick)
			av.take(l, pick)
		}
	}
	used := a.usedMarkSlots()
	retired := map[int]bool{}
	for _, s := range a.RetiredMarks {
		retired[s] = true
	}
	for _, kind := range []struct {
		ids   []string
		slots map[string]Slot
	}{{sortedExits(t), a.Exits}, {sortedGroups(t), a.Groups}} {
		for _, id := range kind.ids {
			if _, ok := kind.slots[id]; ok || id == "" {
				continue
			}
			pick := -1
			for s := 0; s < MaxMarkSlots && pick < 0; s++ {
				if !used[s] && !retired[s] {
					pick = s
				}
			}
			for _, s := range a.RetiredMarks {
				if pick >= 0 {
					break
				}
				if !used[s] && !now.marks[s] && s >= 0 && s < MaxMarkSlots {
					pick = s
				}
			}
			if pick < 0 {
				continue
			}
			kind.slots[id] = Slot{pick}
			used[pick] = true
			a.RetiredMarks = removeInt(a.RetiredMarks, pick)
		}
	}
}

// avoid is what a new link slot must not collide with: explicit tunnel
// addresses of other links, the LAN prefixes, and every port some link or
// node already sets or defaults to (conservatively across all nodes).
type avoid struct {
	addrs []netip.Prefix
	ports map[int]bool
	// slots whose interface name an operator gave a host interface
	// (lan/wan/ingress interface "m03" …).
	slots map[int]bool
}

func newAvoid(t Topology, a *Allocations) *avoid {
	av := &avoid{ports: map[int]bool{}, slots: map[int]bool{}}
	names := []string{t.Settings.LANInterface}
	for _, n := range t.Nodes {
		names = append(names, n.LANInterface, n.WANInterface, n.IngressInterface)
	}
	for _, name := range names {
		if m := tunnelIfaceRe.FindStringSubmatch(strings.TrimSpace(name)); m != nil {
			if s, err := strconv.Atoi(m[1]); err == nil && s < MaxLinkSlots && LinkIface(s) == "m"+m[1] {
				av.slots[s] = true
			}
		}
	}
	for _, l := range t.Links {
		for _, s := range []string{l.FromV4, l.ToV4, l.FromULA, l.ToULA} {
			if ip, err := netip.ParseAddr(strings.TrimSpace(s)); err == nil {
				av.addrs = append(av.addrs, netip.PrefixFrom(ip, ip.BitLen()))
			}
		}
		if l.WGPort > 0 {
			av.ports[l.WGPort] = true
			if l.Transport == TransportUDPWSSFailover {
				av.ports[l.WGPort+1] = true
			}
		}
		if l.WSSLocalPort > 0 {
			av.ports[l.WSSLocalPort] = true
		}
		if s, ok := a.Links[l.ID]; ok {
			av.take(l, s.Slot)
		}
	}
	for _, n := range t.Nodes {
		if n.ListenPort > 0 {
			av.ports[n.ListenPort] = true
		}
		if n.WSSListenPort > 0 {
			av.ports[n.WSSListenPort] = true
		}
		for _, s := range []string{n.LANIPv4, n.LANIPv6Prefix} {
			if p, err := netip.ParsePrefix(strings.TrimSpace(s)); err == nil {
				av.addrs = append(av.addrs, p.Masked())
			}
		}
	}
	for _, s := range []string{t.Settings.GatewayLANIP, t.Settings.LANIPv6Prefix} {
		if p, err := netip.ParsePrefix(strings.TrimSpace(s)); err == nil {
			av.addrs = append(av.addrs, p.Masked())
		}
	}
	return av
}

// linkPortsAt are the ports link l binds by default at slot s.
func linkPortsAt(l Link, s int) []int {
	var out []int
	if l.WGPort == 0 {
		out = append(out, LinkDefaultWGPort(s))
		if l.Transport == TransportUDPWSSFailover {
			out = append(out, LinkDefaultWGPort(s)+1)
		}
	}
	if WSSTransport(l.Transport) && l.WSSLocalPort == 0 {
		out = append(out, LinkDefaultLocalPort(s))
	}
	return out
}

func (av *avoid) take(l Link, s int) {
	for _, p := range linkPortsAt(l, s) {
		av.ports[p] = true
	}
}

func (av *avoid) ok(l Link, s int) bool {
	if av.slots[s] {
		return false
	}
	for _, p := range linkPortsAt(l, s) {
		if av.ports[p] {
			return false
		}
	}
	v4, ula, c4, c6 := LinkAutoBlocks(s)
	var blocks []netip.Prefix
	if l.FromV4 == "" || l.ToV4 == "" {
		blocks = append(blocks, v4)
	}
	if l.FromULA == "" || l.ToULA == "" {
		blocks = append(blocks, ula)
	}
	if l.Transport == TransportUDPWSSFailover {
		blocks = append(blocks, c4, c6)
	}
	for _, b := range blocks {
		for _, x := range av.addrs {
			if b.Overlaps(x) {
				return false
			}
		}
	}
	return true
}
