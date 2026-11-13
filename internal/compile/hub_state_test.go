package compile

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/radowitz/meridian/internal/defaults"
	"github.com/radowitz/meridian/internal/hubstate"
	"github.com/radowitz/meridian/internal/model"
	"github.com/radowitz/meridian/internal/pool"
	"github.com/radowitz/meridian/internal/sshexec"
)

// readState runs the panel's fixed read command (sshexec.GroupStateCommand)
// against the harness's state directory, with the same stubs.
func (h *hubHarness) readState() string {
	h.t.Helper()
	cmd := strings.ReplaceAll(sshexec.GroupStateCommand, "/run/meridian", h.run)
	c := exec.Command("bash", "-c", cmd)
	c.Env = append(os.Environ(), "PATH="+filepath.Join(h.dir, "bin")+":"+os.Getenv("PATH"))
	out, err := c.Output()
	if err != nil {
		h.t.Fatalf("read command: %v", err)
	}
	return string(out)
}

// judge parses the read and evaluates group gid as the panel would, with
// the panel's clock equal to the hub's.
func (h *hubHarness) judge(topo model.Topology, gid string) (hubstate.Snapshot, hubstate.Actual) {
	h.t.Helper()
	snap, err := hubstate.Parse(h.readState())
	if err != nil {
		h.t.Fatalf("parse: %v", err)
	}
	_, groups := plans(h.t, topo)
	g := mustGroup(h.t, groups, gid)
	pol := g.Policy()
	spec := hubstate.GroupSpec{ID: gid, Dynamic: g.Dynamic, Members: pol.Try, Mesh: pol.Mesh}
	at := time.Unix(snap.Now, 0)
	rd := &hubstate.Read{ReadAt: at, Snapshot: &snap}
	return snap, hubstate.Evaluate(spec, rd, GroupPlanID(groups), HubStaleAfter(groups), at)
}

func (h *hubHarness) report(gid string) map[string]string {
	h.t.Helper()
	b, err := os.ReadFile(filepath.Join(h.run, "group", gid, "report"))
	if err != nil {
		h.t.Fatalf("no report for %s: %v", gid, err)
	}
	out := map[string]string{}
	for _, l := range strings.Split(strings.TrimSpace(string(b)), "\n") {
		k, v, _ := strings.Cut(l, " ")
		out[k] = v
	}
	return out
}

func (h *hubHarness) reset(now int64) {
	h.t.Helper()
	h.set("now", fmt.Sprint(now))
	if out, err := h.bash("reset_groups"); err != nil {
		h.t.Fatalf("reset_groups: %v\n%s", err, out)
	}
}

func allUp(h *hubHarness) {
	for _, id := range []string{"hk-ix", "hk-2", "us", "us-2", "jp", "sg", "tw", "hk-resi", "hk-resi-2"} {
		if _, ok := h.peers[id]; ok {
			h.up(id, true)
		}
	}
}

// The hub records the plan it runs at start, a heartbeat every pass, and a
// successful switch with the member really in the table, the reason and
// the time; the panel's parser reads it through the fixed command as ok.
func TestHubStateRecordsSwitch(t *testing.T) {
	topo := defaults.Example()
	h := newHubHarness(t, topo)
	_, groups := plans(t, topo)
	hk := mustGroup(t, groups, "hk")
	now := int64(1_800_000_000)
	h.reset(now)
	plan, err := os.ReadFile(filepath.Join(h.run, "group-plan"))
	if err != nil || strings.TrimSpace(string(plan)) != fmt.Sprintf("plan %s %d", GroupPlanID(groups), now) {
		t.Fatalf("group-plan %q %v", plan, err)
	}
	full := h.script
	if !strings.Contains(full, "GROUP_PLAN="+GroupPlanID(groups)+"\n") {
		t.Fatal("the failover script does not carry its plan identifier")
	}

	allUp(h)
	now += 5
	h.tick(now)
	r := h.report("hk")
	if r["hop"] != "hk-ix" || r["active"] != "hk-ix" || r["reason"] != pool.ReasonPreferred || r["result"] != "ok" ||
		r["beat"] != fmt.Sprint(now) || r["switched"] != "0" || r["plan"] != GroupPlanID(groups) {
		t.Fatalf("first pass report %v", r)
	}
	_, a := h.judge(topo, "hk")
	if a.State != hubstate.StateOK || a.Active != "hk-ix" || a.LastSwitch != nil || a.RunningSince == nil || !*a.DeployedMatches {
		t.Fatalf("first pass actual %+v", a)
	}

	// The heartbeat advances with every pass.
	now += 5
	h.tick(now)
	if got := h.report("hk")["beat"]; got != fmt.Sprint(now) {
		t.Fatalf("heartbeat %s, want %d", got, now)
	}

	// hk-ix fails: after FailsNeed passes the hub switches to hk-2.
	var switchedAt int64
	for i := 0; i < pool.FailsNeed; i++ {
		now += 5
		h.up("hk-ix", false)
		h.tick(now)
		if switchedAt == 0 && h.report("hk")["hop"] == "hk-2" {
			switchedAt = now
		}
	}
	r = h.report("hk")
	if switchedAt == 0 || r["hop"] != "hk-2" || r["active"] != "hk-2" || r["reason"] != pool.ReasonFailover ||
		r["switched"] != fmt.Sprint(switchedAt) || r["result"] != "ok" {
		t.Fatalf("after failover %v", r)
	}
	if !strings.Contains(h.log(), fmt.Sprintf("ip route replace default dev %s table %d", hk.Try[1].HubIface, hk.Table)) {
		t.Fatal("no route change logged")
	}
	_, a = h.judge(topo, "hk")
	if a.State != hubstate.StateOK || a.Active != "hk-2" || a.Reason != pool.ReasonFailover || a.LastSwitch == nil || a.LastSwitch.Unix() != switchedAt {
		t.Fatalf("after failover actual %+v", a)
	}
	// No temporary file is left behind.
	if left, _ := filepath.Glob(filepath.Join(h.run, "group", "*", ".report.*")); len(left) != 0 {
		t.Fatalf("temporary report files left: %v", left)
	}

	// All down, Mesh not sealed: the switcher chooses Mesh, the table is a
	// blackhole and the report says so (not "mmesh").
	for i := 0; i < pool.FailsNeed; i++ {
		now += 5
		h.up("hk-2", false)
		h.tick(now)
	}
	r = h.report("hk")
	if r["active"] != "mmesh" || r["hop"] != "blackhole" || r["result"] != "ok" {
		t.Fatalf("unsealed mesh %v", r)
	}
	_, a = h.judge(topo, "hk")
	if a.State != hubstate.StateOK || a.Active != "" || a.Hop != hubstate.HopBlackhole || a.Reason != pool.ReasonMesh {
		t.Fatalf("unsealed mesh actual %+v", a)
	}
}

// A switch whose route change fails is recorded as failed with the hop
// that is still in the table; the panel reports switch_failed and does not
// show a member in use. When the change later succeeds the report is ok
// and keeps the last failure.
func TestHubStateRecordsFailedSwitch(t *testing.T) {
	topo := defaults.Example()
	h := newHubHarness(t, topo)
	_, groups := plans(t, topo)
	hk := mustGroup(t, groups, "hk")
	now := int64(1_800_000_000)
	h.reset(now)
	allUp(h)
	now += 5
	h.tick(now)
	h.set(fmt.Sprintf("fail-%d", hk.Table), "1")
	for i := 0; i < pool.FailsNeed; i++ {
		now += 5
		h.up("hk-ix", false)
		h.tick(now)
	}
	r := h.report("hk")
	if r["result"] != "failed" || r["want"] != "hk-2" || r["hop"] != "hk-ix" || r["active"] != "hk-ix" ||
		r["switched"] != "0" || r["lastfail"] != fmt.Sprintf("hk-2 %d", now) {
		t.Fatalf("failed switch report %v", r)
	}
	if got := h.state("hk", "active"); got != "hk-ix" {
		t.Fatalf("switcher state changed on a failed hop: %s", got)
	}
	_, a := h.judge(topo, "hk")
	if a.State != hubstate.StateSwitchFailed || a.Code != hubstate.CodeHopFailed || a.Active != "" ||
		a.Reported == nil || a.Reported.Hop != "hk-ix" || a.Reported.Want != "hk-2" || a.Reported.FailedAt == nil {
		t.Fatalf("failed switch actual %+v", a)
	}

	// The route change works again: the next pass switches.
	if err := os.Remove(filepath.Join(h.ctrl, fmt.Sprintf("fail-%d", hk.Table))); err != nil {
		t.Fatal(err)
	}
	failedAt := now
	now += 5
	h.tick(now)
	r = h.report("hk")
	if r["result"] != "ok" || r["hop"] != "hk-2" || r["switched"] != fmt.Sprint(now) || r["lastfail"] != fmt.Sprintf("hk-2 %d", failedAt) {
		t.Fatalf("after recovery %v", r)
	}
	if _, a = h.judge(topo, "hk"); a.State != hubstate.StateOK || a.Active != "hk-2" {
		t.Fatalf("after recovery actual %+v", a)
	}

	// The table is changed behind the switcher's back: diverged.
	h.set(fmt.Sprintf("tbl4-%d", hk.Table), "default dev wg-foreign")
	now += 5
	h.tick(now)
	if r = h.report("hk"); r["result"] != "diverged" || r["hop"] != "split" {
		t.Fatalf("diverged %v", r)
	}
	if _, a = h.judge(topo, "hk"); a.State != hubstate.StateSwitchFailed || a.Code != hubstate.CodeTableDiverged || a.Active != "" {
		t.Fatalf("diverged actual %+v", a)
	}
}

// A heartbeat that stopped is stale on the hub's own clock; a hub running
// another plan is a version mismatch. Neither shows a member.
func TestHubStateStaleAndVersion(t *testing.T) {
	topo := defaults.Example()
	h := newHubHarness(t, topo)
	_, groups := plans(t, topo)
	now := int64(1_800_000_000)
	h.reset(now)
	allUp(h)
	now += 5
	h.tick(now)
	// The loop stops; the hub's clock moves on.
	h.set("now", fmt.Sprint(now+int64(HubStaleAfter(groups)/time.Second)+1))
	_, a := h.judge(topo, "hk")
	if a.State != hubstate.StateStale || a.Code != hubstate.CodeHeartbeatOld || a.Active != "" || a.HubReportedAt == nil {
		t.Fatalf("stale actual %+v", a)
	}
	h.set("now", fmt.Sprint(now+int64(HubStaleAfter(groups)/time.Second)))
	if _, a = h.judge(topo, "hk"); a.State != hubstate.StateOK {
		t.Fatalf("at the threshold %+v", a)
	}

	// The panel's topology changes the order of group us: the hub still
	// runs the old plan.
	next := defaults.Example()
	for i := range next.Groups {
		if next.Groups[i].ID == "us" {
			m := next.Groups[i].Members
			for l, r := 0, len(m)-1; l < r; l, r = l+1, r-1 {
				m[l], m[r] = m[r], m[l]
			}
		}
	}
	_, nextGroups := plans(t, next)
	if GroupPlanID(nextGroups) == GroupPlanID(groups) {
		t.Fatal("plan identifier ignores the group order")
	}
	if _, a = h.judge(next, "hk"); a.State != hubstate.StateVersionMismatch || a.DeployedMatches == nil || *a.DeployedMatches || a.Active != "" {
		t.Fatalf("version mismatch actual %+v", a)
	}
	// A change outside the groups does not change the plan.
	other := defaults.Example()
	other.Rules = other.Rules[:len(other.Rules)-1]
	_, otherGroups := plans(t, other)
	if GroupPlanID(otherGroups) != GroupPlanID(groups) {
		t.Fatal("plan identifier follows unrelated rules")
	}
}

// A reader never sees half a report while the loop writes.
func TestHubStateWritesAreAtomic(t *testing.T) {
	topo := defaults.Example()
	h := newHubHarness(t, topo)
	now := int64(1_800_000_000)
	h.reset(now)
	allUp(h)
	now += 5
	h.tick(now)
	path := filepath.Join(h.run, "group", "hk", "report")
	var stop atomic.Bool
	var reads, bad atomic.Int64
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for !stop.Load() {
			b, err := os.ReadFile(path)
			if err != nil {
				bad.Add(1)
				continue
			}
			reads.Add(1)
			s := string(b)
			if !strings.HasPrefix(s, hubstate.ReportHeader+"\n") || !strings.HasSuffix(s, "\nend\n") {
				bad.Add(1)
			}
		}
	}()
	for i := 0; i < 10; i++ {
		now += 5
		h.up("hk-ix", i%4 != 0)
		h.tick(now)
	}
	stop.Store(true)
	wg.Wait()
	if bad.Load() != 0 || reads.Load() == 0 {
		t.Fatalf("%d partial or missing reads out of %d", bad.Load(), reads.Load())
	}
	if !strings.Contains(h.script, `} > "$tmp" && mv -f "$tmp" "$dir/report"`) {
		t.Fatal("report is not written through a rename")
	}
}

// The loop interval the staleness rule is built on is the one in the
// script, and only the hub's failover script carries the reporting.
func TestHubStateScriptShape(t *testing.T) {
	if !strings.Contains(failoverLoopHub, fmt.Sprintf("\n  sleep %d\n", int(HubLoopInterval/time.Second))) {
		t.Fatal("HubLoopInterval differs from the hub loop's sleep")
	}
	b, err := Compile(defaults.Example())
	if err != nil {
		t.Fatal(err)
	}
	for path, body := range b.Files {
		hub := strings.HasPrefix(path, "nodes/hk-hub/") && strings.HasSuffix(path, "meridian-failover.sh")
		if strings.Contains(body, "group_record") != hub || strings.Contains(body, "GROUP_PLAN=") != hub {
			t.Errorf("%s: group reporting present=%v, want %v", path, !hub, hub)
		}
	}
	if strings.Contains(b.File("nodes/hk-hub/usr/local/sbin/meridian-routes.sh"), "group_record") {
		t.Error("the routes script must not record state")
	}
}
