package compile

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/radowitz/meridian/internal/model"
)

// A stored topology in the pre-redesign format (exit pools, rule
// target_pool, no region groups; internal/api/testdata) compiles to exactly
// the bytes it compiled to before the T3 template work and the fixture
// renaming. The golden was written by the compiler as it stood before T3
// touched any code (docs/privacy-inventory.md「T3 处理结果」) and, unlike the
// example goldens, is not regenerated: renaming the example fixtures is
// data only and must not move a stored topology's output.
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
