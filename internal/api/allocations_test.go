package api

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/radowitz/meridian/internal/defaults"
	"github.com/radowitz/meridian/internal/model"
)

// storeLegacyRow writes a topology row as a version before the allocation
// table wrote it.
func storeLegacyRow(t *testing.T, s *Server, topo model.Topology) {
	t.Helper()
	topo.Allocations = nil
	raw, err := json.Marshal(topo)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Store.Put("topology", string(raw)); err != nil {
		t.Fatal(err)
	}
}

func compileFiles(t *testing.T, s *Server, body []byte) map[string]string {
	t.Helper()
	rr := do(s, http.MethodPost, "/api/compile", body)
	if rr.Code != http.StatusOK {
		t.Fatalf("compile: %d %s", rr.Code, rr.Body.String())
	}
	var out struct {
		Files map[string]string `json:"files"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	return out.Files
}

func sameFiles(a, b map[string]string) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if b[k] != v {
			return false
		}
	}
	return true
}

// After an upgrade the stored topology compiles exactly as before (so the
// panel shows no pending change), the table survives a whole-document save
// from the editor even when the editor sends another (or none), and the
// allocation view reports a real edit.
func TestAllocationsAcrossUpgradeAndSave(t *testing.T) {
	s := newTest(t)
	legacy := defaults.DualHubExample()
	storeLegacyRow(t, s, legacy)
	before := compileFiles(t, s, nil) // in-memory migration on Load
	if wrote, err := s.Store.MigrateAllocations(); err != nil || !wrote {
		t.Fatalf("migrate: %v %v", wrote, err)
	}
	after := compileFiles(t, s, nil)
	if !sameFiles(before, after) {
		t.Fatal("the migrated stored topology compiles differently")
	}
	raw, _ := json.Marshal(legacy)
	if !sameFiles(compileFiles(t, s, raw), after) {
		t.Fatal("a submitted document without the table compiles differently from the stored one")
	}

	rr := do(s, http.MethodGet, "/api/topology", nil)
	var topo model.Topology
	if err := json.Unmarshal(rr.Body.Bytes(), &topo); err != nil {
		t.Fatal(err)
	}
	if topo.Allocations == nil {
		t.Fatal("GET /api/topology has no allocations")
	}
	orig := topo.Allocations.Clone()

	// The editor adds a link whose ID sorts first, sends a tampered table
	// and edits one port.
	topo.Links = append(topo.Links, model.Link{ID: "a-gw-ali-b", From: "gw", To: "ali", Transport: model.TransportDirectWG, Enabled: true, Standby: true})
	topo.Allocations.Links["gw-ali"] = model.Slot{Slot: 50}
	for i := range topo.Links {
		if topo.Links[i].ID == "ix-dc1" {
			topo.Links[i].WGPort = 40001
		}
	}
	work, _ := json.Marshal(topo)

	rr = do(s, http.MethodPost, "/api/topology/allocations", work)
	if rr.Code != http.StatusOK {
		t.Fatalf("allocations: %d %s", rr.Code, rr.Body.String())
	}
	var view struct {
		Links []struct {
			LinkID string `json:"link_id"`
			Slot   *int   `json:"slot"`
			New    bool   `json:"new"`
			Legs   []struct {
				Iface string `json:"iface"`
			} `json:"legs"`
		} `json:"links"`
		Changes []allocationChange `json:"changes"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &view); err != nil {
		t.Fatal(err)
	}
	for _, l := range view.Links {
		switch l.LinkID {
		case "gw-ali":
			if l.Slot == nil || *l.Slot != orig.Links["gw-ali"].Slot || l.New || l.Legs[0].Iface != model.LinkIface(*l.Slot) {
				t.Fatalf("gw-ali view: %+v", l)
			}
		case "a-gw-ali-b":
			if l.Slot == nil || !l.New || *l.Slot != len(orig.Links) {
				t.Fatalf("new link view: %+v", l)
			}
		}
	}
	if len(view.Changes) != 1 || view.Changes[0].LinkID != "ix-dc1" || view.Changes[0].What != "wg_port" || view.Changes[0].After != "40001" {
		t.Fatalf("changes = %+v", view.Changes)
	}

	rr = do(s, http.MethodPut, "/api/topology", work)
	if rr.Code != http.StatusOK {
		t.Fatalf("save: %d %s", rr.Code, rr.Body.String())
	}
	stored, _, _ := s.Store.Load()
	for id, slot := range orig.Links {
		if stored.Allocations.Links[id] != slot {
			t.Fatalf("%s moved %v → %v", id, slot, stored.Allocations.Links[id])
		}
	}
	if s, ok := stored.Allocations.LinkSlot("a-gw-ali-b"); !ok || s != len(orig.Links) {
		t.Fatalf("new link stored at %d %v", s, ok)
	}
}

// PUT ?import=1 takes the document's own table (an export brought back into
// a panel that already stored something else).
func TestImportKeepsDocumentAllocations(t *testing.T) {
	s := newTest(t)
	if rr := do(s, http.MethodGet, "/api/topology", nil); rr.Code != http.StatusOK { // seeds the example
		t.Fatal(rr.Body.String())
	}
	doc := defaults.DualHubExample()
	model.MigrateAllocations(&doc)
	doc.Allocations.Links["ix-dc1"] = model.Slot{Slot: 30} // its own history
	raw, _ := json.Marshal(doc)
	if rr := do(s, http.MethodPut, "/api/topology?import=1", raw); rr.Code != http.StatusOK {
		t.Fatalf("import: %d %s", rr.Code, rr.Body.String())
	}
	stored, _, _ := s.Store.Load()
	if !jsonEqual(stored.Allocations.Links, doc.Allocations.Links) {
		t.Fatalf("stored %+v, document %+v", stored.Allocations.Links, doc.Allocations.Links)
	}
	// Without import=1 the stored table wins over the document's (doc2 has
	// ix-dc1 at its position, the stored table at 30).
	doc2 := defaults.DualHubExample()
	model.MigrateAllocations(&doc2)
	if rr := do(s, http.MethodPut, "/api/topology", mustJSON(doc2)); rr.Code != http.StatusOK {
		t.Fatalf("save: %d %s", rr.Code, rr.Body.String())
	}
	again, _, _ := s.Store.Load()
	if again.Allocations.Links["ix-dc1"] != (model.Slot{Slot: 30}) {
		t.Fatalf("a plain save moved ix-dc1 to %v", again.Allocations.Links["ix-dc1"])
	}
}

func jsonEqual(a, b any) bool {
	x, _ := json.Marshal(a)
	y, _ := json.Marshal(b)
	return string(x) == string(y)
}
