package preflight

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/radowitz/meridian/internal/compile"
	"github.com/radowitz/meridian/internal/defaults"
	"github.com/radowitz/meridian/internal/model"
)

// alpineFiles are the example's "jp" exit compiled as an Alpine exit.
func alpineFiles(t *testing.T) map[string]string {
	t.Helper()
	topo := defaults.Example()
	for i := range topo.Nodes {
		if topo.Nodes[i].ID == "jp" {
			topo.Nodes[i].OS = model.OSAlpine
		}
	}
	b, err := compile.Compile(topo)
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]string{}
	for p, body := range b.Files {
		if strings.HasPrefix(p, "nodes/jp/") {
			out["/"+strings.TrimPrefix(p, "nodes/jp/")] = body
		}
	}
	return out
}

func alpineReport(t *testing.T, fp Footprint, ipFull bool) Report {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", "alpine319-lxc.txt"))
	if err != nil {
		t.Fatal(err)
	}
	v := "no"
	if ipFull {
		v = "yes"
	}
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "r.txt"), []byte(strings.Replace(string(raw), "@IPFULL@", v, 1)), 0o644)
	cwd, _ := os.Getwd()
	rel, _ := filepath.Rel(filepath.Join(cwd, "testdata"), filepath.Join(dir, "r.txt"))
	return fixture(t, rel, fp, nil, "")
}

func TestAlpineExitPreflight(t *testing.T) {
	fp := FootprintOf(alpineFiles(t))
	ctx := remote("jp")
	ctx.OS = model.OSAlpine
	ev := Evaluate(alpineReport(t, fp, true), fp, ctx)
	if b := codes(ev, Blocking); len(b) != 0 {
		t.Fatalf("an Alpine exit is blocked: %v\n%+v", b, ev.Findings)
	}
	if !strings.HasPrefix(ev.Platform, "Alpine 3.19.1 x86_64") {
		t.Fatalf("platform %q", ev.Platform)
	}
	if has(ev, "", CodeLowMemory) {
		t.Fatal("200 MB is enough for an Alpine exit (no container): no low-memory warning")
	}
	planned := map[string]string{}
	for _, p := range ev.Packages {
		planned[p.Package] = p.Action
	}
	if planned["wireguard-tools"] != "install" || planned["nftables"] != "install" || planned["iproute2"] != "none" {
		t.Fatalf("packages %+v", ev.Packages)
	}
	// Only BusyBox's ip: its tables and rules cannot be trusted, refused.
	if f := find(Evaluate(alpineReport(t, fp, false), fp, ctx), CodeOSUnsupported); len(f) != 1 || f[0].Resource != "iproute2" || !strings.Contains(f[0].Action, "apk add iproute2") {
		t.Fatalf("BusyBox ip: %+v", f)
	}

	// The node and the host must agree on the system.
	if !has(Evaluate(alpineReport(t, fp, true), fp, remote("jp")), Blocking, CodeOSUnsupported) {
		t.Fatal("an Alpine host for a node not marked Alpine is accepted")
	}
	deb := FootprintOf(nodeFiles(t, "jp"))
	if !has(Evaluate(fixture(t, "clean-debian13.txt", deb, nil, ""), deb, ctx), Blocking, CodeOSUnsupported) {
		t.Fatal("a Debian host for a node marked Alpine is accepted")
	}
}

func TestAlpineVersion(t *testing.T) {
	for v, ok := range map[string]bool{"3.19.1": true, "3.19": true, "3.20.3": true, "4.0": true, "3.18.6": false, "edge": false, "": false} {
		if alpineVersionOK(v) != ok {
			t.Errorf("%q: want %v", v, ok)
		}
	}
}

// An enabled OpenRC nftables service flushes the whole ruleset when it
// stops: refused before anything changes.
func TestAlpineNFTablesServiceRefused(t *testing.T) {
	fp := FootprintOf(alpineFiles(t))
	ctx := remote("jp")
	ctx.OS = model.OSAlpine
	r := alpineReport(t, fp, true)
	r.Units["nftables.service"] = UnitState{Active: "active", Enabled: "enabled"}
	r.NFTStop = "flush"
	if !has(Evaluate(r, fp, ctx), Blocking, CodeNFTFlush) {
		t.Fatal("an enabled OpenRC nftables service is accepted")
	}
}
