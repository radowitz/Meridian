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
// to the compiler from before it. The example hub failover digest also
// records the v1.0.3 zero-loss Mesh latency threshold.
func goldenDigest(b *Bundle) string {
	var lines []string
	for p, body := range b.Files {
		sum := sha256.Sum256([]byte(body))
		lines = append(lines, hex.EncodeToString(sum[:])+" "+p)
	}
	sort.Strings(lines)
	return "# apply-order: " + strings.Join(b.Order, " ") + "\n" + strings.Join(lines, "\n") + "\n"
}

// Ignore the opt-in Hosts drop-in when comparing with historical
// compiler snapshots. New golden files retain the directive.
func withoutDNSHostsInclude(b *Bundle) *Bundle {
	out := *b
	out.Files = make(map[string]string, len(b.Files))
	for p, body := range b.Files {
		if strings.HasSuffix(p, "/etc/smartdns/smartdns.conf") {
			body = strings.ReplaceAll(body, model.DNSHostsInclude+"\n", "")
		}
		out.Files[p] = body
	}
	return &out
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

// preLogCompile pins the example topologies, with the v1.0.3 Mesh selector
// update in the Mesh example, to what the compiler produced
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
	"example":       {"64b6e37cc0fbd5ea789292d5032113b2a70c802fa14f16ad09a2cf99974c070a", "5a3c48c9453a63f84c5512095f830694013d3978b7e70d625fc09a542e1cf4b3"},
	"dual_hub":      {"9c77a6cb7140c28ebd71c9bf2c22a23a701be5f4aa4117b0a14bc51779d20a3a", "446dc28f0a6826bc4f24d759e9dc24a2ab2f3144a92a9e872186fa48c2c9be32"},
	"shared_relays": {"a074fb85055c0b1a12a35a40f9194a9c7d66f776e2857bea2fd79733d27fabc4", "04ef8a7cb655ed12542e122f2db0247049d93c4d7688f4215a2f8a04be5d0af9"},
	"nested":        {"d8e97ec433e32d27091c72ceaf062ab57e5b78cee682ebd906157ed21b914bb1", "f6cf850a3f0b198a3441b9b4f23ad733ac864f51b66d30d2c24cb8b681a77e2b"},
	"external":      {"d9cd9652ed88152a8a3f87bc13d5a72cfca56026cac35d7e4a7c2ebf30ae8306", "8718e00e4429683ebdf3cab26a3dfe983f60a90ceb79048ee03ef5c65896e3ee"},
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
				sum := sha256.Sum256([]byte(goldenDigest(withLegacyFailoverComments(withoutLinkJournal(t, withoutTrafficCounters(t, topo, withoutProbeDNSException(t, topo, withoutDNSHostsInclude(b))), gw)))))
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
