package compile

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/radowitz/meridian/internal/model"
)

// A stored topology in the pre-redesign format (exit pools, rule
// target_pool, no region groups; internal/api/testdata) compiles to exactly
// its pinned bundle. The fixture still uses the pre-T3 topology; the only
// v1.0.3 change to the pin is the hub failover script for the zero-loss
// Mesh latency threshold.
func TestStoredLegacyTopologyCompileUnchanged(t *testing.T) {
	raw, err := os.ReadFile("../api/testdata/pre-redesign-topology.json")
	if err != nil {
		t.Fatal(err)
	}
	var topo model.Topology
	if err := json.Unmarshal(raw, &topo); err != nil {
		t.Fatal(err)
	}
	model.MigrateRegionGroups(&topo)
	b, err := Compile(topo)
	if err != nil {
		t.Fatalf("compile: %v (%+v)", err, b.Issues)
	}
	want, err := os.ReadFile("testdata/stored_legacy_topology.golden")
	if err != nil {
		t.Fatal(err)
	}
	// Only the failover scripts' comment text may differ (role-neutral
	// wording); every other byte is pinned.
	if got := goldenDigest(withLegacyFailoverComments(b)); got != string(want) {
		t.Fatal("a stored pre-redesign topology no longer compiles to its pinned bytes")
	}
}
