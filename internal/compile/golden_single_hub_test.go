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
	"github.com/radowitz/meridian/internal/dnsjournal"
	"github.com/radowitz/meridian/internal/model"
)

// Single-hub topologies that use none of the dual-hub features (no backup
// hub, no IX-line hub) must compile to exactly what they compiled to before
// the dual-hub work. The golden files hold one "<sha256> <path>" line per
// bundle file plus the apply order, generated from the pre-change compiler;
// set MERIDIAN_UPDATE_GOLDEN=1 to rewrite them after an intended change.
//
// The example has Mesh edges, so these three files were regenerated when a
// cf_mesh link became a WireGuard leg carried over the Mesh (the hub, the
// exits with a Mesh leg and the gateway's per-mark clamps changed; see
// mesh_transport.go). That change must not reach a topology without Mesh
// edges: TestNoMeshCompileUnchangedByMeshTransport pins the same examples
// with their Mesh edges removed, and the four examples that never had one,
// to the compiler from before it.
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

// preLogCompile pins the example topologies to what the compiler produced
// before the three logs and the SOCKS credential version existed (commit
// 4824a78, the last one before that work): one SHA-256 over the apply order
// and the "<sha256> <path>" line of every file, computed there with
// goldenDigest. Key: example name, then "" or "sniff".
//
// Since then a gateway gained exactly two files (the link journal's unit
// and object list) and one block in its verify script; nothing else may
// differ for a topology that has no encrypted exit upstream configured and
// the query journal off — with or without an external SOCKS exit (its
// carrier's redirector config gets a version line only from the panel, for
// a credential rotated past the store's baseline: internal/api
// socks_version.go, TestSOCKSVersionUpgrade).
//
// Like the golden files, the digests follow an intended change of the
// compiled text: MERIDIAN_UPDATE_GOLDEN=1 logs the current ones (go test -v)
// instead of comparing. From then on they pin that change, no longer the
// compiler before the logs.
var preLogCompile = map[string][2]string{
	// The example has Mesh edges: its digests follow the host-level Mesh
	// change (mesh_transport.go). The other four have none and are still
	// the digests of the compiler before the logs, except shared_relays:
	// its gateway scripts carry the protected switch transaction (T2; QA:
	// failed-fallback counters restored, a killed pass past its commit point finishes;
	// docs/review-391aa50.md).
	"example":       {"ef8393edf6f3439b6e6d79a97a8b5bfa7fc72ca967b6d065ab3342413409a495", "5794daa2fbe9198d792f3ddfc1dd115ed6eaed45c2f2c3433d45316a7223cc4a"},
	"dual_hub":      {"d5e979cb59d92032fbb3e3b027362cc656454a6add1c75df9968b42ef6f20814", "37483a5e0b5c22cf751c90f3191837b7c6de1418e902304ae145ee74d5e59a18"},
	"shared_relays": {"5cffa269f2f16a797b9e0559b7149a90941bcdfa6b5f91e1c6b77c344e383522", "d09c976a35b849b327e3805f873c6b950fbe7a1b7ab90c81df4b420db6a88258"},
	"nested":        {"7961814763c704c95d7ac32a93247db69ca8e6eb14537d20adca297235477f5f", "43553cc7e51aa44545750f9026e8605542ff0dce1b80bbb0c30b15a7447f6559"},
	"external":      {"77d036e0748478b4aeee61a211a7db1f54c5ddb3d530d7fe4770fd4ab34e0a5f", "5129eea53d70c8b7cbcb479a0d33b4c2532d9e373b78cc6732e9e8f89a9dbe84"},
}

// withoutLinkJournal is b as the pre-log compiler would have produced it:
// the gateway's two link-journal files dropped and the link-journal block
// taken out of its verify script. It fails when the bundle carries the
// link journal anywhere else.
func withoutLinkJournal(t *testing.T, b *Bundle, gw string) *Bundle {
	t.Helper()
	pre := "nodes/" + gw + "/"
	out := &Bundle{Order: b.Order, Files: map[string]string{}}
	dropped := 0
	for p, body := range b.Files {
		switch p {
		case pre + "etc/systemd/system/" + LinkJournalUnit, pre + strings.TrimPrefix(LinkJournalConfigPath, "/"):
			dropped++
			continue
		case pre + "usr/local/sbin/meridian-verify.sh":
			stripped := strings.Replace(body, linkLogVerifyBlock+"\n", "", 1)
			if stripped == body {
				t.Fatalf("%s has no link-journal block", p)
			}
			body = stripped
		}
		out.Files[p] = body
	}
	if dropped != 2 {
		t.Fatalf("the gateway has %d link-journal files, want the unit and the object list", dropped)
	}
	return out
}

// Byte-for-byte against the compiler before the logs: with no encrypted
// exit upstream and the query journal off, every file of every node is what
// it was — the exits' resolver configs, the carrier's redirector config of
// an external SOCKS exit (placeholders only, no version line), every relay
// and hub — and the gateway differs only by the link journal's two files
// and its verify block. The same holds when the settings are spelled out
// as "off" instead of being absent.
func TestCompileUnchangedSinceBeforeTheLogs(t *testing.T) {
	examples := map[string]func() model.Topology{"example": defaults.Example, "dual_hub": defaults.DualHubExample, "shared_relays": defaults.SharedRelaysExample,
		"nested": defaults.NestedExample, "external": defaults.ExternalExample}
	if len(examples) != len(preLogCompile) {
		t.Fatal("an example has no pinned digest")
	}
	variants := map[string]func(*model.Topology){
		"as stored": func(*model.Topology) {},
		"query journal set and off": func(topo *model.Topology) {
			topo.Settings.DNSLog = &model.DNSLogSettings{Enabled: false}
		},
		"every exit's upstream set to builtin": func(topo *model.Topology) {
			topo.Nodes = append([]model.Node(nil), topo.Nodes...)
			for i := range topo.Nodes {
				if topo.Nodes[i].Role == model.RoleExit && !model.IsExternal(topo.Nodes[i]) {
					topo.Nodes[i].ExitDNS = &model.ExitDNSUpstream{Protocol: model.ExitDNSBuiltin}
				}
			}
		},
	}
	for name, mk := range examples {
		for si, sniffed := range []bool{false, true} {
			for vname, vary := range variants {
				topo := mk()
				if sniffed {
					topo.Settings.Sniff = &model.SniffSettings{Enabled: true}
				}
				vary(&topo)
				model.MigrateRegionGroups(&topo)
				b, err := Compile(topo)
				if err != nil {
					t.Fatalf("%s: %v", name, err)
				}
				gw := ""
				for _, n := range topo.Nodes {
					if n.Role == model.RoleGateway {
						gw = n.ID
					}
				}
				sum := sha256.Sum256([]byte(goldenDigest(withLegacyFailoverComments(withoutLinkJournal(t, withoutTrafficCounters(t, topo, withoutProbeDNSException(t, topo, b)), gw)))))
				if os.Getenv("MERIDIAN_UPDATE_GOLDEN") == "1" {
					t.Logf("%s (sniff %v, %s): %s", name, sniffed, vname, hex.EncodeToString(sum[:]))
				} else if got := hex.EncodeToString(sum[:]); got != preLogCompile[name][si] {
					t.Errorf("%s (sniff %v, %s): the compile output differs from the compiler before the logs beyond the gateway's link journal (%s, pinned %s)",
						name, sniffed, vname, got, preLogCompile[name][si])
				}
				// Nothing of the query journal, and no credential version, in
				// what a compile produces by itself.
				for p, body := range b.Files {
					for _, bad := range []string{"audit-enable", dnsjournal.StateDir, DNSJournalUnit, "meridian-socks-version"} {
						if strings.Contains(body, bad) || strings.Contains(p, bad) {
							t.Errorf("%s (sniff %v, %s): %s carries %q", name, sniffed, vname, p, bad)
						}
					}
				}
			}
		}
	}
}
