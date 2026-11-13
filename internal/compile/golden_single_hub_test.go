package compile

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/radowitz/meridian/internal/defaults"
	"github.com/radowitz/meridian/internal/model"
)

// Single-hub topologies that use none of the dual-hub features (no backup
// hub, no IX-line hub) must compile to exactly what they compiled to before
// the dual-hub work. The golden files hold one "<sha256> <path>" line per
// bundle file plus the apply order, generated from the pre-change compiler;
// set MERIDIAN_UPDATE_GOLDEN=1 to rewrite them after an intended change.
func goldenDigest(b *Bundle) string {
	var lines []string
	for p, body := range b.Files {
		sum := sha256.Sum256([]byte(body))
		lines = append(lines, hex.EncodeToString(sum[:])+" "+p)
	}
	sort.Strings(lines)
	return "# apply-order: " + strings.Join(b.Order, " ") + "\n" + strings.Join(lines, "\n") + "\n"
}

func checkGolden(t *testing.T, name string, b *Bundle) {
	t.Helper()
	path := filepath.Join("testdata", name)
	got := goldenDigest(b)
	if os.Getenv("MERIDIAN_UPDATE_GOLDEN") == "1" {
		if err := os.WriteFile(path, []byte(got), 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if got == string(want) {
		return
	}
	wl := map[string]bool{}
	for _, l := range strings.Split(string(want), "\n") {
		wl[l] = true
	}
	for _, l := range strings.Split(got, "\n") {
		if !wl[l] {
			t.Errorf("%s: changed or new: %s", name, l)
		}
	}
	t.Fatalf("%s: the single-hub compile output changed", name)
}

func TestGoldenSingleHubUnchanged(t *testing.T) {
	cases := []struct {
		name string
		topo func(t *testing.T) (model.Topology, map[string]string)
	}{
		{"single_hub_example.golden", func(*testing.T) (model.Topology, map[string]string) { return defaults.Example(), nil }},
		{"single_hub_groupdns.golden", func(*testing.T) (model.Topology, map[string]string) { return groupDNSExample() }},
		{"single_hub_remote_access.golden", func(t *testing.T) (model.Topology, map[string]string) {
			topo, _ := raExample(t)
			// Fixed keys: raExample generates fresh ones.
			for i := range topo.RemoteAccess.Devices {
				topo.RemoteAccess.Devices[i].PublicKey = base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{byte(i + 1)}, 32))
			}
			topo.RemoteAccess.PublicKey = base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{9}, 32))
			return topo, nil
		}},
	}
	for _, c := range cases {
		topo, dec := c.topo(t)
		// Migration is part of loading a stored topology; an old document
		// must come out of it compiling to the same bundle.
		model.MigrateRegionGroups(&topo)
		b, err := CompileWithDecisions(topo, dec)
		if err != nil {
			t.Fatal(err)
		}
		checkGolden(t, c.name, b)
	}
}
