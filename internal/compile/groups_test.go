package compile

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/radowitz/meridian/internal/defaults"
	"github.com/radowitz/meridian/internal/model"
	"github.com/radowitz/meridian/internal/pool"
)

func plans(t *testing.T, topo model.Topology) ([]ExitPlan, []GroupPlan) {
	t.Helper()
	tunnels, err := buildTunnels(topo)
	if err != nil {
		t.Fatal(err)
	}
	exits := planExits(topo, tunnels)
	return exits, planGroups(topo, exits)
}

func mustGroup(t *testing.T, gs []GroupPlan, id string) GroupPlan {
	t.Helper()
	g, ok := groupByID(gs, id)
	if !ok {
		t.Fatalf("no group plan %s", id)
	}
	return g
}

// Marks: a group rule uses the group mark when the hub can switch it; a
// rule pinned to an exit, or moved by the unlock map, uses the member's
// own mark; a manual group ignores the unlock map.
func TestGroupMarksInClassifier(t *testing.T) {
	topo := defaults.Example()
	topo.Rules = append(topo.Rules, model.Rule{
		ID: "pin-hk2", Name: "pin", Manual: true, Priority: 5, Enabled: true,
		MatchType: model.MatchDomain, MatchValue: "pin.example.com", TargetExit: "hk-2",
	})
	exits, groups := plans(t, topo)
	us, usPin, hk := mustGroup(t, groups, "us"), mustGroup(t, groups, "us-pin"), mustGroup(t, groups, "hk")
	if !us.Dynamic || !usPin.Dynamic || !hk.Dynamic {
		t.Fatal("direct-WireGuard groups must be switchable")
	}
	for _, g := range groups {
		if g.Index < len(exits) || g.Mark != exitMark(g.Index) || g.Table != 201+g.Index {
			t.Fatalf("group %s index %d mark %#x table %d", g.Group.ID, g.Index, g.Mark, g.Table)
		}
	}
	us2, _ := exitByID(exits, "us-2")
	hk2, _ := exitByID(exits, "hk-2")
	decisions := map[string]string{"auto-openai": "us-2", "manual-example": "us-2"}
	rules := planRules(topo, exits, groups, decisions)
	marks := map[string]uint32{}
	for _, rp := range rules {
		marks[rp.Rule.ID] = rp.Mark
	}
	if marks["auto-anthropic"] != us.Mark {
		t.Errorf("group rule mark %#x, want group mark %#x", marks["auto-anthropic"], us.Mark)
	}
	if marks["auto-openai"] != us2.Mark {
		t.Errorf("unlock-moved rule mark %#x, want member mark %#x", marks["auto-openai"], us2.Mark)
	}
	if marks["manual-example"] != usPin.Mark {
		t.Errorf("manual group followed the unlock map: %#x", marks["manual-example"])
	}
	if marks["pin-hk2"] != hk2.Mark {
		t.Errorf("explicit exit mark %#x, want %#x", marks["pin-hk2"], hk2.Mark)
	}
	// A pure-v6 exit behind the dual-stack relay is selected statically on
	// its own mark; its group is not switched by the hub.
	v6 := mustGroup(t, groups, "v6")
	if v6.Dynamic || !v6.HasTarget || v6.Policy().Try[0] != "v6-exit" || !v6.Policy().Hold {
		t.Fatalf("relay-reached group: %+v", v6.Policy())
	}
	if tg, _ := groupTarget(v6); tg.Mark != v6.Target.Mark {
		t.Fatal("static-only group must use the member's mark")
	}

	b, err := CompileWithDecisions(topo, decisions)
	if err != nil {
		t.Fatal(err)
	}
	nft := b.File("nodes/gw/etc/nftables.d/meridian.nft")
	routes := b.File("nodes/gw/usr/local/sbin/meridian-routes.sh")
	if !strings.Contains(nft, fmt.Sprintf("# default-exit hk-ix group hk mark %#x", hk.Mark)) {
		t.Fatal("default traffic must use the hk group mark")
	}
	last := guardLastExitMark(exits, groups...)
	for _, m := range regexp.MustCompile(`meta mark set (0x[0-9a-f]+)`).FindAllStringSubmatch(nft, -1) {
		v, _ := strconv.ParseUint(m[1], 0, 32)
		if uint32(v) == markDomestic {
			continue
		}
		if uint32(v) < markExitBase || uint32(v) > last {
			t.Errorf("classifier mark %s outside the guard range %#x-%#x", m[1], markExitBase, last)
		}
		if !strings.Contains(routes, fmt.Sprintf("ip rule add fwmark %s lookup 102 ", m[1])) {
			t.Errorf("mark %s has no table-102 rule", m[1])
		}
		if !strings.Contains(nft, fmt.Sprintf("meta mark %s snat to ", m[1])) {
			t.Errorf("mark %s has no transit SNAT", m[1])
		}
	}
}

// The guard's exit-mark range and the routes script's selector cleanup
// follow the number of exits plus groups, and the guard's interface set is
// the gateway's WireGuard interfaces whatever the group membership is.
func TestGuardFollowsGroupMarks(t *testing.T) {
	base := defaults.Example()
	b0, err := Compile(base)
	if err != nil {
		t.Fatal(err)
	}
	guard0 := b0.File("nodes/gw/etc/nftables.d/meridian-guard.nft")
	if !strings.Contains(guard0, "meta mark 0x101-0x140 oifname") {
		t.Fatalf("small topology keeps the 64-mark range:\n%s", guard0)
	}
	// Membership change: same marks, same interface set.
	moved := defaults.Example()
	for i := range moved.Groups {
		if moved.Groups[i].ID == "hk" {
			moved.Groups[i].Members = []string{"hk-ix"}
		}
	}
	b1, err := Compile(moved)
	if err != nil {
		t.Fatal(err)
	}
	if b1.File("nodes/gw/etc/nftables.d/meridian-guard.nft") != guard0 {
		t.Fatal("guard changed with group membership")
	}
	line := checkLine(b1.File("nodes/hk-hub/usr/local/sbin/meridian-failover.sh"), "'hk'")
	if line == "" || strings.Contains(line, "'hk-2'") {
		t.Fatalf("removed member still a switch candidate: %q", line)
	}
	// Many groups: the range widens and the cleanup loop covers it.
	many := defaults.Example()
	for i := 0; i < 60; i++ {
		many.Groups = append(many.Groups, model.RegionGroup{ID: fmt.Sprintf("extra-%02d", i), Name: "x", Mode: model.GroupAuto, Members: []string{"jp"}})
	}
	b2, err := Compile(many)
	if err != nil {
		t.Fatal(err)
	}
	exits, groups := plans(t, many)
	last := guardLastExitMark(exits, groups...)
	if last <= exitMarkLast {
		t.Fatalf("last mark %#x did not widen", last)
	}
	if !strings.Contains(b2.File("nodes/gw/etc/nftables.d/meridian-guard.nft"), fmt.Sprintf("meta mark 0x101-%#x oifname", last)) {
		t.Fatal("guard range does not cover the group marks")
	}
	if !strings.Contains(b2.File("nodes/gw/usr/local/sbin/meridian-routes.sh"), fmt.Sprintf("for n in $(seq 0 %d); do", last-markExitBase)) {
		t.Fatal("selector cleanup does not cover the group marks")
	}
	for _, f := range []string{"nodes/gw/etc/nftables.d/meridian-guard.nft", "nodes/gw/etc/nftables.d/meridian.nft"} {
		if strings.Contains(b2.File(f), "mmesh") {
			t.Fatalf("%s admits mmesh", f)
		}
	}
}

func checkLine(script, gid string) string {
	for _, l := range strings.Split(script, "\n") {
		if strings.HasPrefix(strings.TrimSpace(l), "group_step "+gid+" ") {
			return l
		}
	}
	return ""
}

// Static routes and the failover script share group_hop and the Mesh
// next-hops byte for byte; the static default of every dynamic group is the
// compiled target's hop, which is also what the failover script resets to.
func TestStaticAndDynamicAgree(t *testing.T) {
	topo := defaults.Example()
	b, err := Compile(topo)
	if err != nil {
		t.Fatal(err)
	}
	_, groups := plans(t, topo)
	routes := b.File("nodes/hk-hub/usr/local/sbin/meridian-routes.sh")
	fail := b.File("nodes/hk-hub/usr/local/sbin/meridian-failover.sh")
	prelude := groupHopPrelude(groups)
	if !strings.Contains(routes, prelude) || !strings.Contains(fail, prelude) {
		t.Fatal("routes and failover do not share the same group_hop prelude")
	}
	rt := b.File("nodes/hk-hub/etc/iproute2/rt_tables.d/meridian.conf")
	for _, g := range groups {
		if !strings.Contains(rt, fmt.Sprintf("%d\t%s", g.Table, g.tableName())) {
			t.Errorf("rt_tables misses %s", g.Group.ID)
		}
		if !strings.Contains(routes, fmt.Sprintf("ip rule add from %s/32 lookup %d priority %d", g.TransitV4, g.Table, prioHubExitFrom+g.Index)) {
			t.Errorf("hub has no source rule for group %s", g.Group.ID)
		}
		hop := fmt.Sprintf("group_hop %d %s", g.Table, shQuote(g.Target.HubIface))
		if !g.Dynamic {
			if strings.Contains(routes, fmt.Sprintf("group_hop %d ", g.Table)) {
				t.Errorf("static-only group %s got a hop", g.Group.ID)
			}
			continue
		}
		if !strings.Contains(routes, hop) || !strings.Contains(fail, "  "+hop+" || true") {
			t.Errorf("group %s: static hop and reset hop differ (%s)", g.Group.ID, hop)
		}
		line := checkLine(fail, shQuote(g.Group.ID))
		pol := g.Policy()
		want := fmt.Sprintf("group_step %s %d %s %d %d %d %s", shQuote(g.Group.ID), g.Table, shQuote(g.Target.Node.ID), boolNum(pol.Mesh), boolNum(pol.Hold), boolNum(pol.Manual), shQuote(pol.TargetReason))
		if !strings.HasPrefix(strings.TrimSpace(line), want) {
			t.Errorf("check line %q, want prefix %q", line, want)
		}
		for _, e := range g.Try {
			if !strings.Contains(line, fmt.Sprintf("%s %s %s", shQuote(e.Node.ID), shQuote(e.HubIface), shQuote(e.PeerV4))) {
				t.Errorf("group %s: member %s missing from the switch order", g.Group.ID, e.Node.ID)
			}
		}
	}
	// No exit table is ever handed to group_hop, and the hub no longer
	// rewrites per-exit tables.
	if strings.Contains(fail, "apply_pool_hop") || strings.Contains(fail, "/run/meridian/pool") {
		t.Fatal("old per-exit pool switching is still present")
	}
	if !strings.Contains(b.File("nodes/hk-hub/usr/local/sbin/meridian-up.sh"), "systemctl restart meridian-failover.service") {
		t.Fatal("an install must restart the switcher with the new policy")
	}
}

// ---- generated hub script under bash, against pool.StepGroup ----------

type hubHarness struct {
	t      *testing.T
	dir    string
	run    string
	ctrl   string
	script string
	peers  map[string]string // member → peer address
}

func newHubHarness(t *testing.T, topo model.Topology) *hubHarness {
	t.Helper()
	if !bashOK() {
		t.Skip("bash not available")
	}
	b, err := Compile(topo)
	if err != nil {
		t.Fatal(err)
	}
	h := &hubHarness{t: t, dir: t.TempDir(), peers: map[string]string{}}
	h.run = filepath.Join(h.dir, "run")
	h.ctrl = filepath.Join(h.dir, "ctrl")
	bin := filepath.Join(h.dir, "bin")
	for _, d := range []string{h.run, h.ctrl, bin} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	stub := func(name, body string) {
		if err := os.WriteFile(filepath.Join(bin, name), []byte("#!/bin/bash\n"+body), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	stub("ip", fmt.Sprintf(`if [ "$1" = link ]; then [ -f %q/link ]; exit; fi
echo "ip $*" >> %q/ip.log
`, h.ctrl, h.ctrl))
	stub("ping", fmt.Sprintf(`peer="${@: -1}"
[ "$(cat %q/peer-$peer 2>/dev/null || echo 1)" = 1 ]
`, h.ctrl))
	stub("date", fmt.Sprintf(`cat %q/now`, h.ctrl))
	full := b.File("nodes/hk-hub/usr/local/sbin/meridian-failover.sh")
	cut := strings.Index(full, "# --- main loop ---")
	if cut < 0 {
		t.Fatal("no main-loop marker")
	}
	h.script = strings.ReplaceAll(full[:cut], "/run/meridian", h.run)
	h.script = "export PATH=" + bin + ":$PATH\n" + h.script
	_, groups := plans(t, topo)
	for _, g := range groups {
		for _, e := range g.Try {
			h.peers[e.Node.ID] = e.PeerV4
		}
	}
	return h
}

func (h *hubHarness) set(name, val string) {
	if err := os.WriteFile(filepath.Join(h.ctrl, name), []byte(val), 0o644); err != nil {
		h.t.Fatal(err)
	}
}

func (h *hubHarness) up(member string, ok bool) {
	v := "0"
	if ok {
		v = "1"
	}
	h.set("peer-"+h.peers[member], v)
}

func (h *hubHarness) bash(cmd string) (string, error) {
	f := filepath.Join(h.dir, "drive.sh")
	if err := os.WriteFile(f, []byte(h.script+"\n"+cmd+"\n"), 0o600); err != nil {
		h.t.Fatal(err)
	}
	out, err := exec.Command("bash", f).CombinedOutput()
	return string(out), err
}

func (h *hubHarness) tick(now int64) {
	h.set("now", strconv.FormatInt(now, 10))
	if out, err := h.bash("check_groups"); err != nil {
		h.t.Fatalf("check_groups: %v\n%s", err, out)
	}
}

func (h *hubHarness) state(gid, file string) string {
	b, _ := os.ReadFile(filepath.Join(h.run, "group", gid, file))
	return strings.TrimSpace(string(b))
}

func (h *hubHarness) log() string {
	b, _ := os.ReadFile(filepath.Join(h.ctrl, "ip.log"))
	return string(b)
}

// Drive the hub's group_step and pool.StepGroup with the same samples and
// clock: they must pick the same member with the same reason at every step,
// and every switch must install the same route group_hop would.
func TestHubGroupStepMatchesStateMachine(t *testing.T) {
	topo := defaults.Example()
	h := newHubHarness(t, topo)
	_, groups := plans(t, topo)
	hk := mustGroup(t, groups, "hk")
	pol := hk.Policy()
	ix, two := hk.Try[0], hk.Try[1]
	if ix.Node.ID != "hk-ix" || two.Node.ID != "hk-2" || !pol.Mesh {
		t.Fatalf("unexpected hk plan %+v", pol)
	}
	var rt pool.Runtime
	now := int64(1_800_000_000)
	step := func(ixUp, twoUp bool, note string) {
		t.Helper()
		now += 5
		h.up("hk-ix", ixUp)
		h.up("hk-2", twoUp)
		h.up("us", true)
		h.up("us-2", true)
		h.tick(now)
		rt = pool.StepGroup(rt, pol, map[string]bool{"hk-ix": ixUp, "hk-2": twoUp}, time.Unix(now, 0))
		if got := h.state("hk", "active"); got != rt.Active {
			t.Fatalf("%s: hub active %q, model %q", note, got, rt.Active)
		}
		if got := h.state("hk", "reason"); got != rt.Reason {
			t.Fatalf("%s: hub reason %q, model %q", note, got, rt.Reason)
		}
		if got := h.state("hk", "alert") == "1"; got != rt.Alert {
			t.Fatalf("%s: hub alert %v, model %v", note, got, rt.Alert)
		}
	}
	step(true, true, "cold")
	step(false, true, "one failure")
	step(false, true, "two failures")
	step(false, true, "three failures")
	if rt.Active != "hk-2" {
		t.Fatalf("no failover: %+v", rt)
	}
	if !strings.Contains(h.log(), fmt.Sprintf("ip route replace default dev %s table %d", two.HubIface, hk.Table)) {
		t.Fatalf("failover route not installed:\n%s", h.log())
	}
	for i := 0; i < pool.RecoversNeed; i++ {
		step(true, true, "recovering")
	}
	// One failure inside the recovery streak, then successes: no return
	// until a full new streak.
	step(false, true, "failure while recovering")
	for i := 0; i < 40; i++ {
		step(true, true, "streak")
		if rt.Active == "hk-ix" {
			break
		}
	}
	if rt.Active != "hk-ix" {
		t.Fatalf("never returned: %+v", rt)
	}
	streak := rt.Members["hk-ix"].OKSince.Unix()
	if now-streak < int64(pool.Cooldown/time.Second) {
		t.Fatalf("returned after %ds of success, before the %v streak", now-streak, pool.Cooldown)
	}
	// Both down: Mesh, but only once sealed; otherwise blackholed.
	for i := 0; i < pool.FailsNeed; i++ {
		step(false, false, "all down, unsealed")
	}
	if rt.Active != pool.MeshHop || !strings.Contains(h.log(), fmt.Sprintf("ip route replace blackhole default table %d", hk.Table)) {
		t.Fatalf("unsealed mesh must blackhole:\n%s", h.log())
	}
	h.set("link", "1")
	if err := os.WriteFile(filepath.Join(h.run, "mesh-sealed"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if out, err := h.bash(fmt.Sprintf("group_hop %d mmesh", hk.Table)); err != nil {
		t.Fatalf("%v %s", err, out)
	}
	if !strings.Contains(h.log(), fmt.Sprintf("ip route replace default via 169.254.66.2 dev mmesh table %d", hk.Table)) ||
		!strings.Contains(h.log(), fmt.Sprintf("ip -6 route replace default via fe80::66:2 dev mmesh table %d", hk.Table)) {
		t.Fatalf("mesh hop without explicit next-hops:\n%s", h.log())
	}
}

func TestHubGroupHopRefusesForeignTables(t *testing.T) {
	topo := defaults.Example()
	h := newHubHarness(t, topo)
	exits, groups := plans(t, topo)
	ix, _ := exitByID(exits, "hk-ix")
	for _, table := range []string{"100", "102", "150", "main", strconv.Itoa(ix.Table), "999"} {
		if out, err := h.bash("group_hop " + table + " wg0"); err == nil || !strings.Contains(out, "refused") {
			t.Errorf("group_hop accepted table %s: %v %s", table, err, out)
		}
	}
	if strings.Contains(h.log(), "route") {
		t.Fatalf("a refused hop touched routes:\n%s", h.log())
	}
	g := mustGroup(t, groups, "hk")
	if out, err := h.bash(fmt.Sprintf("group_hop %d wg0", g.Table)); err != nil {
		t.Fatalf("own table refused: %v %s", err, out)
	}
}

// Manual groups on the hub: hold never moves and alerts; fallback moves to
// the next eligible member and alerts until it returns.
func TestHubManualHoldAndFallback(t *testing.T) {
	for _, mode := range []model.OnFailure{model.OnFailureHold, model.OnFailureFallback} {
		t.Run(string(mode), func(t *testing.T) {
			topo := defaults.Example()
			for i := range topo.Groups {
				if topo.Groups[i].ID == "us-pin" {
					topo.Groups[i].OnFailure = mode
				}
			}
			h := newHubHarness(t, topo)
			_, groups := plans(t, topo)
			g := mustGroup(t, groups, "us-pin")
			pol := g.Policy()
			if pol.Hold != (mode == model.OnFailureHold) || !pol.Manual || pol.TargetReason != pool.ReasonChosen {
				t.Fatalf("policy %+v", pol)
			}
			var rt pool.Runtime
			now := int64(1_800_000_000)
			for i := 0; i < pool.FailsNeed+1; i++ {
				now += 5
				h.up("us", false)
				h.up("us-2", true)
				h.up("hk-ix", true)
				h.up("hk-2", true)
				h.tick(now)
				rt = pool.StepGroup(rt, pol, map[string]bool{"us": false, "us-2": true}, time.Unix(now, 0))
			}
			wantActive, wantReason := "us", pool.ReasonHeld
			if mode == model.OnFailureFallback {
				wantActive, wantReason = "us-2", pool.ReasonFallback
			}
			if h.state("us-pin", "active") != wantActive || h.state("us-pin", "reason") != wantReason || h.state("us-pin", "alert") != "1" {
				t.Fatalf("hub: active %s reason %s alert %s", h.state("us-pin", "active"), h.state("us-pin", "reason"), h.state("us-pin", "alert"))
			}
			if rt.Active != wantActive || rt.Reason != wantReason || !rt.Alert {
				t.Fatalf("model: %+v", rt)
			}
			touched := strings.Contains(h.log(), fmt.Sprintf("table %d", g.Table))
			if touched != (mode == model.OnFailureFallback) {
				t.Fatalf("hold must not touch table %d; fallback must:\n%s", g.Table, h.log())
			}
		})
	}
}
