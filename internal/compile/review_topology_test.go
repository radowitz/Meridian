package compile

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"reflect"
	"testing"

	"github.com/radowitz/meridian/internal/model"
)

// The evidence contains exact compiler bytes, not installed credentials.
// Frozen from HEAD 391aa50 before any production code changes.
// This test deliberately has no baseline regeneration mode.
type reviewFile struct {
	SHA256 string `json:"sha256"`
	Bytes  []byte `json:"bytes_base64"`
}
type reviewBaseline struct {
	Source         string                `json:"source"`
	TopologySHA256 string                `json:"topology_sha256"`
	Order          []string              `json:"apply_order"`
	Files          map[string]reviewFile `json:"files"`
}

func TestReviewTopologyBaseline(t *testing.T) {
	const fixture = "testdata/review_topology.json"
	const evidence = "../../docs/evidence/review-391aa50"
	raw, err := os.ReadFile(fixture)
	if err != nil {
		t.Fatal(err)
	}
	var topo model.Topology
	if err := json.Unmarshal(raw, &topo); err != nil {
		t.Fatal(err)
	}
	exits := 0
	for _, n := range topo.Nodes {
		if n.Role == model.RoleIX || n.IXLine {
			t.Fatal("review topology must have no IX")
		}
		if n.Role == model.RoleExit {
			exits++
		}
	}
	if exits != 7 || !topo.RelayBackup() || len(topo.MeshLegs()) == 0 {
		t.Fatal("missing required topology coverage")
	}
	b, err := Compile(topo)
	if err != nil {
		t.Fatalf("compile: %v (%+v)", err, b.Issues)
	}
	sum := sha256.Sum256(raw)
	got := reviewBaseline{Source: "391aa50c05d2b8e444875c08bd8bc3766922ef3b", TopologySHA256: hex.EncodeToString(sum[:]), Order: b.Order, Files: map[string]reviewFile{}}
	// The failover scripts' comment text is role-neutral now; compared
	// with the old wording so every other byte stays frozen.
	for p, body := range withLegacyFailoverComments(withoutDNSHostsInclude(b)).Files {
		sum := sha256.Sum256([]byte(body))
		got.Files[p] = reviewFile{hex.EncodeToString(sum[:]), []byte(body)}
	}
	path := evidence + "/baseline-bundles.json"
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var want reviewBaseline
	if err := json.Unmarshal(data, &want); err != nil {
		t.Fatal(err)
	}
	// T1's bytes stay frozen. A later task's necessary change is accepted
	// per file only: the T1 digest it replaces and the new digest, each with
	// the confirmed defect recorded in docs/review-391aa50.md.
	accepted := map[string]acceptedChange{}
	if data, err := os.ReadFile(evidence + "/t2-accepted.json"); err == nil {
		if err := json.Unmarshal(data, &accepted); err != nil {
			t.Fatal(err)
		}
	}
	for p, a := range accepted {
		w, ok := want.Files[p]
		g, gok := got.Files[p]
		if !ok || !gok || w.SHA256 != a.From || a.Reason == "" {
			t.Fatalf("accepted change %s does not replace a frozen T1 file or has no reason", p)
		}
		if g.SHA256 != a.To {
			t.Errorf("%s: %s, accepted %s", p, g.SHA256, a.To)
		}
		delete(got.Files, p)
		delete(want.Files, p)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatal("review compile bytes, file set, input digest or apply order changed; explain the confirmed defect before changing evidence")
	}
}

type acceptedChange struct {
	From   string `json:"from_sha256"`
	To     string `json:"to_sha256"`
	Reason string `json:"reason"`
}
