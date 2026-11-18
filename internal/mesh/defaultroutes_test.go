package mesh_test

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/radowitz/meridian/internal/mesh"
)

// runDetect runs the fixed detection script with a stub ip whose route
// output for each family is given; fail6 makes the IPv6 route read fail.
func runDetect(t *testing.T, routes4, routes6 string, fail6 bool) string {
	t.Helper()
	dir := t.TempDir()
	write := func(name, body string) {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("r4", routes4)
	write("r6", routes6)
	f6 := ""
	if fail6 {
		f6 = "exit 2"
	}
	stub := fmt.Sprintf(`#!/bin/sh
case "$*" in
"-o -4 addr show") echo "5: CloudflareWARP    inet 100.96.0.7/32 scope global CloudflareWARP";;
"-N -4 route show table all") cat %[1]s/r4;;
"-N -6 route show table all") %[2]s
  cat %[1]s/r6;;
"-N -6 rule show") echo "5209:	not from all fwmark 0x100cf lookup 65743";;
*) ;;
esac
`, dir, f6)
	if err := os.WriteFile(filepath.Join(dir, "ip"), []byte(stub), 0o755); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("bash", "-c", mesh.DetectScript())
	cmd.Env = []string{"PATH=" + dir + ":/usr/bin:/bin"}
	out, _ := cmd.CombinedOutput()
	return string(out)
}

func ordinaryDefaults(n int) string {
	var b strings.Builder
	for i := 0; i < n; i++ {
		fmt.Fprintf(&b, "default via 10.0.%d.1 dev eth%d table %d metric 100\n", i, i%4, 100+i)
	}
	return b.String()
}

func TestDetectFindsWARPDefaultAfterManyOrdinaryRoutes(t *testing.T) {
	v6 := strings.ReplaceAll(ordinaryDefaults(20), "10.0.", "fd00::") + "default dev CloudflareWARP table 65743 metric 1024\n"
	out := runDetect(t, ordinaryDefaults(20), v6, false)
	d := mesh.ParseHostMesh(out, acct, mesh.Reserved{})
	if d.Coexist.OK || !d.Coexist.GlobalDefault {
		t.Fatalf("IPv6 WARP default after 20 ordinary routes not blocked: %+v\n%s", d.Coexist, out)
	}
	// Only ordinary routes: no takeover, no truncation.
	out = runDetect(t, ordinaryDefaults(40), strings.ReplaceAll(ordinaryDefaults(40), "10.0.", "fd00::"), false)
	if d := mesh.ParseHostMesh(out, acct, mesh.Reserved{}); !d.Coexist.OK {
		t.Fatalf("ordinary routes flagged: %+v\n%s", d.Coexist, out)
	}
}

func TestDetectDefaultRouteReadFailureOrTruncationBlocks(t *testing.T) {
	out := runDetect(t, ordinaryDefaults(2), "", true)
	if !strings.Contains(out, "MESHHOST defread 6 fail") {
		t.Fatalf("failed read not reported:\n%s", out)
	}
	if d := mesh.ParseHostMesh(out, acct, mesh.Reserved{}); d.Coexist.OK {
		t.Fatalf("failed read passed: %+v", d.Coexist)
	}
	var many strings.Builder
	for i := 0; i < 40; i++ {
		fmt.Fprintf(&many, "default dev CloudflareWARP table 65743 metric %d\n", i)
	}
	out = runDetect(t, "", many.String(), false)
	if !strings.Contains(out, "MESHHOST deftrunc 6 40") {
		t.Fatalf("truncation not reported:\n%s", out)
	}
	for _, line := range []string{"MESHHOST deftrunc 6 40", "MESHHOST defread 4 fail"} {
		d := mesh.ParseHostMesh(hostOut(append(append([]string(nil), meshHost...), line)...), acct, mesh.Reserved{})
		if d.Coexist.OK || d.Reusable {
			t.Fatalf("%s passed: %+v", line, d.Coexist)
		}
	}
}
