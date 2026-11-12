package apply

import (
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
