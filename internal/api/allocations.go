package api

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/radowitz/meridian/internal/compile"
	"github.com/radowitz/meridian/internal/model"
)

// allocationChange is one thing a save of the working copy would change
// about a link the stored topology already has: its interface names, ports
// or tunnel addresses. The slot itself never changes (the stored table is
// authoritative); these come from explicit edits (wg_port, addresses, the
// node's listen_port, the transport, enabling or disabling).
type allocationChange struct {
	LinkID string `json:"link_id"`
	What   string `json:"what"`
	Before string `json:"before"`
	After  string `json:"after"`
}

// postAllocations answers what each link and each exit/group holds in the
// working copy (the body; empty: the stored topology), with the slots a
// save would give it, and what a save would change about the stored links.
// Read-only: nothing is saved.
func (s *Server) postAllocations(w http.ResponseWriter, r *http.Request) {
	cur, err := s.topology()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	t, err := s.bodyOrStored(r)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	links := compile.LinkResources(t)
	stored := map[string]compile.LinkResource{}
	for _, lr := range compile.LinkResources(cur) {
		stored[lr.LinkID] = lr
	}
	type linkOut struct {
		compile.LinkResource
		// New: the stored table has no slot for this link yet; the save
		// gives it the one shown.
		New bool `json:"new"`
	}
	out := make([]linkOut, 0, len(links))
	var changes []allocationChange
	for _, lr := range links {
		_, known := cur.Allocations.LinkSlot(lr.LinkID)
		out = append(out, linkOut{LinkResource: lr, New: !known && lr.Slot != nil})
		if old, ok := stored[lr.LinkID]; ok && known {
			changes = append(changes, diffLinkResource(old, lr)...)
		}
	}
	var retiredLinks, retiredMarks []int
	if t.Allocations != nil {
		retiredLinks, retiredMarks = t.Allocations.RetiredLinks, t.Allocations.RetiredMarks
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"links":         out,
		"marks":         compile.MarkResources(t),
		"changes":       changes,
		"retired_links": retiredLinks,
		"retired_marks": retiredMarks,
		"max_links":     model.MaxLinkSlots,
		"max_marks":     model.MaxMarkSlots,
	})
}

func legSummary(lr compile.LinkResource) (ifaces, v4, ula string) {
	var a, b, c []string
	for _, l := range lr.Legs {
		a = append(a, l.Iface)
		b = append(b, l.WestV4+"↔"+l.EastV4)
		c = append(c, l.WestULA+"↔"+l.EastULA)
	}
	return strings.Join(a, " "), strings.Join(b, " "), strings.Join(c, " ")
}

func diffLinkResource(old, cur compile.LinkResource) []allocationChange {
	var out []allocationChange
	add := func(what, before, after string) {
		if before != after {
			out = append(out, allocationChange{LinkID: cur.LinkID, What: what, Before: before, After: after})
		}
	}
	if old.State != "allocated" || cur.State != "allocated" {
		add("state", old.State, cur.State)
		return out
	}
	oi, o4, o6 := legSummary(old)
	ni, n4, n6 := legSummary(cur)
	add("interface", oi, ni)
	add("listener", old.Listener, cur.Listener)
	add("wg_port", fmt.Sprint(old.WGPort), fmt.Sprint(cur.WGPort))
	add("wss_leg_port", fmt.Sprint(old.WSSLegPort), fmt.Sprint(cur.WSSLegPort))
	add("local_port", fmt.Sprint(old.LocalPort), fmt.Sprint(cur.LocalPort))
	add("tunnel_v4", o4, n4)
	add("tunnel_ula", o6, n6)
	add("enabled", fmt.Sprint(old.Enabled), fmt.Sprint(cur.Enabled))
	return out
}
