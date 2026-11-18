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

// runDetectRules runs the fixed detection script with a stub ip whose IPv6
// policy rules and IPv6 default routes are given; failRules6 makes the IPv6
// rule read fail.
func runDetectRules(t *testing.T, rules6, routes6 string, failRules6 bool) string {
	t.Helper()
	dir := t.TempDir()
	for name, body := range map[string]string{"u6": rules6, "r6": routes6} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	f := ""
	if failRules6 {
		f = "exit 2"
	}
	stub := fmt.Sprintf(`#!/bin/sh
case "$*" in
"-o -4 addr show") echo "5: CloudflareWARP    inet 100.96.0.7/32 scope global CloudflareWARP";;
"-N -6 route show table all") cat %[1]s/r6;;
"-N -6 rule show") %[2]s
  cat %[1]s/u6;;
*) ;;
esac
`, dir, f)
	if err := os.WriteFile(filepath.Join(dir, "ip"), []byte(stub), 0o755); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("bash", "-c", mesh.DetectScript())
	cmd.Env = []string{"PATH=" + dir + ":/usr/bin:/bin"}
	out, _ := cmd.CombinedOutput()
	return string(out)
}

func ordinaryRules(n int) string {
	var b strings.Builder
	for i := 0; i < n; i++ {
		fmt.Fprintf(&b, "%d:\tfrom fd00::%x lookup %d\n", 100+i, i, 300+i)
	}
	return b.String()
}

// A WARP rule after more than 64 ordinary rules still names its custom
// table, and that table's IPv6 default route blocks.
func TestDetectFindsWARPRuleAfterManyOrdinaryRules(t *testing.T) {
	rules := ordinaryRules(80) + "69999:\tnot from all fwmark 0x100cf lookup 4242\n"
	out := runDetectRules(t, rules, "default dev eth0 table 4242 metric 1024\n", false)
	if !strings.Contains(out, "lookup 4242") {
		t.Fatalf("WARP rule dropped from the output:\n%s", out)
	}
	d := mesh.ParseHostMesh(out, acct, mesh.Reserved{})
	if d.Coexist.OK || d.Reusable {
		t.Fatalf("a WARP table with an IPv6 default route must block: %+v", d.Coexist)
	}
}

// Ordinary rules alone are filtered out and do not block.
func TestDetectIgnoresManyOrdinaryRules(t *testing.T) {
	out := runDetectRules(t, ordinaryRules(80), "", false)
	if strings.Contains(out, "ruletrunc") || strings.Contains(out, "ruleread") {
		t.Fatalf("ordinary rules reported as truncated or unreadable:\n%s", out)
	}
}

func TestDetectRuleReadFailureBlocks(t *testing.T) {
	out := runDetectRules(t, "", "", true)
	if !strings.Contains(out, "ruleread 6 fail") {
		t.Fatalf("missing ruleread marker:\n%s", out)
	}
	d := mesh.ParseHostMesh(out, acct, mesh.Reserved{})
	if d.Coexist.OK || d.Reusable {
		t.Fatalf("an unreadable rule set must block: %+v", d.Coexist)
	}
}

func TestDetectTooManyWARPRulesBlocks(t *testing.T) {
	var b strings.Builder
	for i := 0; i < 70; i++ {
		fmt.Fprintf(&b, "%d:\tnot from all fwmark 0x100cf lookup 65743\n", 5000+i)
	}
	out := runDetectRules(t, b.String(), "", false)
	if !strings.Contains(out, "ruletrunc 6 70") {
		t.Fatalf("missing ruletrunc marker:\n%s", out)
	}
	d := mesh.ParseHostMesh(out, acct, mesh.Reserved{})
	if d.Coexist.OK {
		t.Fatalf("truncated WARP rules must block: %+v", d.Coexist)
	}
}

// A long IPv6 WARP rule whose lookup table falls past the output line limit:
// the host's own table list still names the table, its default route via an
// ordinary interface blocks, and the over-long rule itself blocks.
func TestDetectLongWARPRuleKeepsItsTable(t *testing.T) {
	long := "70000:\tnot from 2001:db8:aaaa:bbbb:cccc:dddd:eeee:0/112 to 2001:db8:1111:2222:3333:4444:5555:0/112 iif eth0 oif eth1 sport 1000-2000 dport 3000-4000 ipproto udp fwmark 0x100cf lookup 4343\n"
	out := runDetectRules(t, ordinaryRules(3)+long, "default via fe80::1 dev eth0 table 4343 metric 1024\n", false)
	if !strings.Contains(out, "warptables 6") || !strings.Contains(out, "4343") {
		t.Fatalf("host table list missing:\n%s", out)
	}
	if !strings.Contains(out, "rulelong 6 1") {
		t.Fatalf("missing rulelong marker:\n%s", out)
	}
	d := mesh.ParseHostMesh(out, acct, mesh.Reserved{})
	if d.Coexist.OK || d.Reusable || !d.Coexist.GlobalDefault {
		t.Fatalf("a WARP table default route must block even when its rule is cut: %+v", d.Coexist)
	}
}

// A rule into WARP's fixed table without WARP's mark is still WARP's, so a
// priority clash with Meridian blocks.
func TestDetectFixedTableRuleWithoutMarkClashes(t *testing.T) {
	out := runDetectRules(t, ordinaryRules(3)+"18201:\tfrom all lookup 65743\n", "", false)
	if !strings.Contains(out, "lookup 65743") {
		t.Fatalf("fixed-table rule dropped:\n%s", out)
	}
	d := mesh.ParseHostMesh(out, acct, mesh.Reserved{Priorities: []int{18201}})
	if d.Coexist.OK {
		t.Fatalf("a priority clash on WARP's fixed table must block: %+v", d.Coexist)
	}
}

// Tables given by name (an ip that ignores -N) cannot be mapped to numbers:
// a named custom WARP table with a default route, and a named fixed table on
// a rule without WARP's mark, both block.
func TestDetectNamedTablesBlock(t *testing.T) {
	out := runDetectRules(t, ordinaryRules(3)+"69999:\tnot from all fwmark 0x100cf lookup warp_custom\n", "default dev eth0 table warp_custom metric 1024\n", false)
	d := mesh.ParseHostMesh(out, acct, mesh.Reserved{})
	if d.Coexist.OK || d.Reusable {
		t.Fatalf("a named WARP table must block: %+v\n%s", d.Coexist, out)
	}
	out = runDetectRules(t, ordinaryRules(3)+"18201:\tfrom all lookup cloudflare\n", "", false)
	d = mesh.ParseHostMesh(out, acct, mesh.Reserved{Priorities: []int{18201}})
	if d.Coexist.OK {
		t.Fatalf("a named table on a rule must block: %+v\n%s", d.Coexist, out)
	}
}
