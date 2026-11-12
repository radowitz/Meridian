package apply

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/radowitz/meridian/internal/compile"
	"github.com/radowitz/meridian/internal/defaults"
)

func TestDiffApplyRollback(t *testing.T) {
	dir := t.TempDir()
	ap := Applier{DataDir: dir, LocalID: "gw"}
	b, err := compile.Compile(defaults.Example())
	if err != nil {
		t.Fatal(err)
	}
	diff, err := ap.Diff(b.Canonical())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(diff, "added") && !strings.Contains(diff, "+") {
		t.Fatalf("first diff should show additions, got %d bytes", len(diff))
	}
	dry, err := ap.Apply(b, true)
	if err != nil {
		t.Fatal(err)
	}
	if !dry.DryRun {
		t.Fatal("expected dry run")
	}
	if _, err := os.Stat(filepath.Join(dir, "applied")); err == nil {
		t.Fatal("dry run must not write applied/")
	}
	res, err := ap.Apply(b, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Wrote) == 0 {
		t.Fatal("expected files")
	}
	body, err := os.ReadFile(filepath.Join(dir, "applied", "nodes", "gw", "etc", "nftables.d", "meridian.nft"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(body), "flush ruleset") {
		t.Fatal("installed nft must not flush the ruleset")
	}
	for _, idiom := range []string{
		"table inet meridian_guard\ndelete table inet meridian_guard\ntable inet meridian_guard {\n",
		"table inet meridian\ndelete table inet meridian\ntable inet meridian {\n",
	} {
		if !strings.Contains(string(body), idiom) {
			t.Fatalf("installed nft is not one atomic batch, missing %q", idiom)
		}
	}
	same, err := ap.Diff(b.Canonical())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(same, "没有变化") {
		t.Fatalf("second diff = %s", same[:min(200, len(same))])
	}

	topo := defaults.Example()
	topo.Settings.IXReplacementMode = true
	next, err := compile.Compile(topo)
	if err != nil {
		t.Fatal(err)
	}
	changed, err := ap.Diff(next.Canonical())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(changed, "ix-replacement") {
		t.Fatal("diff should mention the replacement route")
	}
	if _, err := ap.Apply(next, false); err != nil {
		t.Fatal(err)
	}
	if err := ap.Rollback(); err != nil {
		t.Fatal(err)
	}
	back, err := os.ReadFile(filepath.Join(dir, "applied", "nodes", "ali", "usr", "local", "sbin", "meridian-routes.sh"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(back), "meridian-east-preferred: ix ") {
		t.Fatal("rollback did not restore the IX route")
	}
}

func TestRejectsPathEscape(t *testing.T) {
	if _, err := safeBundlePath("../etc/passwd"); err == nil {
		t.Fatal("expected rejection")
	}
	if _, err := safeBundlePath("nodes/gw/etc/shadow"); err == nil {
		t.Fatal("expected rejection of unmanaged path")
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// testKey returns a throwaway WireGuard-shaped key. Never a real one.
func testKey(t *testing.T) string {
	t.Helper()
	var raw [32]byte
	if _, err := rand.Read(raw[:]); err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(raw[:])
}

func gwConfs(t *testing.T, root string) map[string]string {
	t.Helper()
	matches, err := filepath.Glob(filepath.Join(root, "etc", "wireguard", "*.conf"))
	if err != nil {
		t.Fatal(err)
	}
	if len(matches) == 0 {
		t.Fatal("no WireGuard configs installed")
	}
	out := map[string]string{}
	for _, m := range matches {
		info, err := os.Stat(m)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != 0o600 {
			t.Fatalf("%s mode %v, want 0600", m, info.Mode().Perm())
		}
		body, err := os.ReadFile(m)
		if err != nil {
			t.Fatal(err)
		}
		out[m] = string(body)
	}
	return out
}

// assertNoSecret walks dir and fails if any file holds key.
func assertNoSecret(t *testing.T, dir, key string) {
	t.Helper()
	err := filepath.Walk(dir, func(p string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return err
		}
		body, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		if strings.Contains(string(body), key) {
			t.Errorf("private key leaked into %s", p)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestInstallInjectsKeyAndKeepsSnapshotsRedacted(t *testing.T) {
	data, host := t.TempDir(), t.TempDir()
	key := testKey(t)
	activated := 0
	ap := Applier{DataDir: data, Install: true, LocalID: "gw", PrivateKey: key, HostRoot: host,
		Activate: func() error { activated++; return nil }}
	// A pre-existing world-readable config must end up 0600.
	if err := os.MkdirAll(filepath.Join(host, "etc", "wireguard"), 0o755); err != nil {
		t.Fatal(err)
	}
	b, err := compile.Compile(defaults.Example())
	if err != nil {
		t.Fatal(err)
	}
	var first string
	for p := range nodeFiles(b.Files, "gw") {
		if isWireGuardConf(p) {
			first = p
			break
		}
	}
	if first == "" {
		t.Fatal("gateway has no WireGuard config")
	}
	if err := os.WriteFile(filepath.Join(host, filepath.FromSlash(first)), []byte("old\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	// First install.
	res, err := ap.Apply(b, false)
	if err != nil {
		t.Fatal(err)
	}
	if activated != 1 {
		t.Fatalf("activate ran %d times", activated)
	}
	for p, body := range gwConfs(t, host) {
		if strings.Contains(body, compile.PrivateKeyPlaceholder) || !strings.Contains(body, "PrivateKey = "+key+"\n") {
			t.Fatalf("%s was not injected", p)
		}
	}
	if strings.Contains(res.Diff, key) || strings.Contains(strings.Join(res.Wrote, "\n"), key) {
		t.Fatal("result leaked the key")
	}
	assertNoSecret(t, data, key)
	snap, err := os.ReadFile(filepath.Join(data, "applied", filepath.FromSlash("nodes/gw/"+first)))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(snap), "PrivateKey = "+compile.PrivateKeyPlaceholder) {
		t.Fatal("snapshot must keep the placeholder")
	}

	// Reuse on a later apply with a changed topology.
	topo := defaults.Example()
	topo.Settings.IXReplacementMode = true
	next, err := compile.Compile(topo)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ap.Apply(next, false); err != nil {
		t.Fatal(err)
	}
	for p, body := range gwConfs(t, host) {
		if !strings.Contains(body, "PrivateKey = "+key+"\n") {
			t.Fatalf("%s lost the key on reuse", p)
		}
	}
	// Runtime rollback also injects.
	if err := ap.Rollback(); err != nil {
		t.Fatal(err)
	}
	for p, body := range gwConfs(t, host) {
		if !strings.Contains(body, "PrivateKey = "+key+"\n") {
			t.Fatalf("%s lost the key on rollback", p)
		}
	}
	assertNoSecret(t, data, key)
}

func TestInstallWithoutKeyFailsBeforeOverwrite(t *testing.T) {
	b, err := compile.Compile(defaults.Example())
	if err != nil {
		t.Fatal(err)
	}
	for name, key := range map[string]string{"missing": "", "malformed": "not-a-key\nPostUp = id"} {
		t.Run(name, func(t *testing.T) {
			data, host := t.TempDir(), t.TempDir()
			sentinel := filepath.Join(host, "etc", "nftables.d", "meridian.nft")
			if err := os.MkdirAll(filepath.Dir(sentinel), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(sentinel, []byte("previous\n"), 0o644); err != nil {
				t.Fatal(err)
			}
			activated := false
			ap := Applier{DataDir: data, Install: true, LocalID: "gw", PrivateKey: key, HostRoot: host,
				Activate: func() error { activated = true; return nil }}
			_, err := ap.Apply(b, false)
			if err == nil {
				t.Fatal("install without a usable key must fail")
			}
			if key != "" && strings.Contains(err.Error(), key) {
				t.Fatal("error echoed the key")
			}
			if body, _ := os.ReadFile(sentinel); string(body) != "previous\n" {
				t.Fatal("host config overwritten before the key check")
			}
			if _, err := os.Stat(filepath.Join(host, "etc", "wireguard")); err == nil {
				t.Fatal("wireguard dir created before the key check")
			}
			if _, err := os.Stat(filepath.Join(data, "applied")); err == nil {
				t.Fatal("snapshot rotated before the key check")
			}
			if activated {
				t.Fatal("activate ran")
			}
		})
	}
}

func TestRollbackWithoutKeyLeavesSnapshots(t *testing.T) {
	data := t.TempDir()
	b, err := compile.Compile(defaults.Example())
	if err != nil {
		t.Fatal(err)
	}
	rec := Applier{DataDir: data, LocalID: "gw"}
	if _, err := rec.Apply(b, false); err != nil {
		t.Fatal(err)
	}
	if _, err := rec.Apply(b, false); err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(filepath.Join(data, "applied", "canonical.txt"))
	ap := Applier{DataDir: data, Install: true, LocalID: "gw", HostRoot: t.TempDir(), Activate: func() error { return nil }}
	if err := ap.Rollback(); err == nil {
		t.Fatal("rollback install without a key must fail")
	}
	after, _ := os.ReadFile(filepath.Join(data, "applied", "canonical.txt"))
	if string(before) != string(after) {
		t.Fatal("snapshots swapped before the key check")
	}
}

// A firewall load failure in meridian-up.sh must reach the caller as an
// error, and the installed up script must be the one that loads the single
// nft batch before routes, with no separate delete. Kernel behaviour is
// covered by the Linux netns test in internal/compile.
func TestInstallSurfacesFirewallLoadFailure(t *testing.T) {
	data, host := t.TempDir(), t.TempDir()
	b, err := compile.Compile(defaults.Example())
	if err != nil {
		t.Fatal(err)
	}
	const msg = "meridian-nft-load-failed: the batch was aborted as a whole; previous Meridian tables kept"
	ap := Applier{DataDir: data, Install: true, LocalID: "gw", PrivateKey: testKey(t), HostRoot: host,
		Activate: func() error { return errors.New(msg) }}
	_, err = ap.Apply(b, false)
	if err == nil || !strings.Contains(err.Error(), "meridian-nft-load-failed") {
		t.Fatalf("activation failure not surfaced: %v", err)
	}
	// First activation failed: the transaction is compensated back to
	// "nothing installed", so the host copy is gone. Check the bundle's.
	var te *TxnError
	if !errors.As(err, &te) || !te.Compensated {
		t.Fatalf("expected a compensated transaction error, got %v", err)
	}
	if _, err := os.Stat(filepath.Join(host, "usr", "local", "sbin", "meridian-up.sh")); !os.IsNotExist(err) {
		t.Fatal("failed first activation left the up script installed")
	}
	s := b.File("nodes/gw/usr/local/sbin/meridian-up.sh")
	if strings.Contains(s, "delete table") {
		t.Fatal("installed up script still deletes the table in its own nft process")
	}
	load := strings.Index(s, `nft -f "$MERIDIAN_NFT"`)
	routes := strings.Index(s, "/usr/local/sbin/meridian-routes.sh")
	if load < 0 || routes < 0 || load > routes {
		t.Fatal("installed up script must load the nft batch before the routes")
	}
}
