package hubstate

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

const plan = "0123456789abcdef01234567"

const hubNow = int64(1_800_000_100)

func report(lines ...string) string {
	base := map[string]string{
		"group": "hk", "plan": plan, "beat": fmt.Sprint(hubNow - 3), "hop": "hk-2", "active": "hk-2",
		"reason": "failover", "alert": "0", "switched": fmt.Sprint(hubNow - 60), "result": "ok",
	}
	order := []string{"group", "plan", "beat", "hop", "active", "reason", "alert", "switched", "result"}
	var extra []string
	for _, l := range lines {
		k, v, _ := strings.Cut(l, " ")
		if _, ok := base[k]; ok {
			base[k] = v
		} else {
			extra = append(extra, l)
		}
	}
	var b strings.Builder
	b.WriteString(ReportHeader + "\n")
	for _, k := range order {
		if base[k] == "-" {
			continue
		}
		fmt.Fprintf(&b, "%s %s\n", k, base[k])
	}
	for _, l := range extra {
		b.WriteString(l + "\n")
	}
	b.WriteString("end\n")
	return b.String()
}

func output(blocks ...string) string {
	return fmt.Sprintf("%s\nnow %d\nplan %s %d\n%s%s\n", Header, hubNow, plan, hubNow-3600, strings.Join(blocks, ""), Footer)
}

var spec = GroupSpec{ID: "hk", Dynamic: true, Members: []string{"hk-ix", "hk-2"}, Mesh: true}

func judge(t *testing.T, out string) Actual {
	t.Helper()
	snap, err := Parse(out)
	if err != nil {
		t.Fatalf("parse: %v\n%s", err, out)
	}
	at := time.Unix(hubNow, 0)
	return Evaluate(spec, &Read{ReadAt: at, Snapshot: &snap}, plan, 60*time.Second, at)
}

func TestEvaluateStates(t *testing.T) {
	a := judge(t, output(report()))
	if a.State != StateOK || a.Active != "hk-2" || a.Reason != "failover" || a.LastSwitch == nil || a.LastSwitch.Unix() != hubNow-60 ||
		a.RunningSince == nil || a.ReadAt == nil || a.HubReportedAt == nil || a.DeployedMatches == nil || !*a.DeployedMatches {
		t.Fatalf("ok %+v", a)
	}
	if a = judge(t, output(report("switched 0"))); a.State != StateOK || a.LastSwitch != nil {
		t.Fatalf("no switch since start %+v", a)
	}
	if a = judge(t, output(report("beat "+fmt.Sprint(hubNow-61), "switched 0"))); a.State != StateStale || a.Code != CodeHeartbeatOld || a.Active != "" {
		t.Fatalf("stale %+v", a)
	}
	if a = judge(t, output(report("plan ffffffffffffffffffffffff"))); a.State != StateVersionMismatch || a.Active != "" || *a.DeployedMatches {
		t.Fatalf("mismatch %+v", a)
	}
	if a = judge(t, output(report("result failed", "want hk-ix", "hop hk-2", "active hk-2", "lastfail hk-ix "+fmt.Sprint(hubNow-3)))); a.State != StateSwitchFailed ||
		a.Code != CodeHopFailed || a.Active != "" || a.Reported.Hop != "hk-2" || a.Reported.Want != "hk-ix" {
		t.Fatalf("failed %+v", a)
	}
	// A report claiming ok while the table differs from the choice is not
	// believed.
	if a = judge(t, output(report("hop hk-ix", "active hk-2"))); a.State != StateSwitchFailed || a.Code != CodeTableDiverged {
		t.Fatalf("inconsistent ok %+v", a)
	}
	if a = judge(t, output(report("hop blackhole", "active mmesh", "reason mesh", "alert 1"))); a.State != StateOK || a.Active != "" || a.Hop != HopBlackhole {
		t.Fatalf("unsealed mesh %+v", a)
	}
	if a = judge(t, output(report("hop mmesh", "active mmesh", "reason mesh", "alert 1"))); a.State != StateOK || a.Active != "mmesh" {
		t.Fatalf("mesh %+v", a)
	}
	// Unknown members are refused.
	for _, l := range []string{"hop us-2", "active us-2", "hop evil"} {
		if a = judge(t, output(report(l))); a.State != StateUnavailable || a.Code != CodeInvalidReport || a.Active != "" {
			t.Fatalf("%s: %+v", l, a)
		}
	}
	noMesh := spec
	noMesh.Mesh = false
	snap, _ := Parse(output(report("hop mmesh", "active mmesh", "reason mesh")))
	at := time.Unix(hubNow, 0)
	if a = Evaluate(noMesh, &Read{ReadAt: at, Snapshot: &snap}, plan, time.Minute, at); a.Code != CodeInvalidReport {
		t.Fatalf("mesh without a mesh edge %+v", a)
	}
	// Missing group / missing plan.
	if a = judge(t, output()); a.State != StateUnavailable || a.Code != CodeStateMissing {
		t.Fatalf("missing %+v", a)
	}
	noPlan := fmt.Sprintf("%s\nnow %d\n%s%s\n", Header, hubNow, report(), Footer)
	if a = judge(t, noPlan); a.State != StateUnavailable || a.Code != CodeStateMissing {
		t.Fatalf("no plan %+v", a)
	}
	// An unknown group is simply not this group.
	other := strings.Replace(report(), "group hk\n", "group gone\n", 1)
	if a = judge(t, output(other)); a.Code != CodeStateMissing {
		t.Fatalf("other group %+v", a)
	}
	// Not switchable, never read, read failed.
	if a = Evaluate(GroupSpec{ID: "v6"}, nil, plan, time.Minute, at); a.State != StateNotSwitchable {
		t.Fatalf("static %+v", a)
	}
	if a = Evaluate(spec, nil, plan, time.Minute, at); a.State != StateNeverRead || a.ReadAt != nil {
		t.Fatalf("never %+v", a)
	}
	if a = Evaluate(spec, &Read{ReadAt: at, ErrorCode: CodeSSHFailed, SSHCode: "timeout", Error: "x"}, plan, time.Minute, at); a.State != StateUnavailable || a.Code != CodeSSHFailed || a.SSHCode != "timeout" {
		t.Fatalf("ssh %+v", a)
	}
	if a = Evaluate(spec, &Read{ReadAt: at, Snapshot: &snap}, "", time.Minute, at); a.Code != CodePlanUnavailable {
		t.Fatalf("no current plan %+v", a)
	}
}

// Staleness is judged on the hub's clock; a skewed hub clock only shifts
// the displayed times. An old read no longer counts.
func TestEvaluateClock(t *testing.T) {
	snap, err := Parse(output(report()))
	if err != nil {
		t.Fatal(err)
	}
	panel := time.Unix(hubNow, 0).Add(2 * time.Hour) // hub clock two hours behind
	a := Evaluate(spec, &Read{ReadAt: panel, Snapshot: &snap}, plan, time.Minute, panel)
	if a.State != StateOK || *a.ClockSkewSec != 7200 || !a.LastSwitch.Equal(panel.Add(-60*time.Second)) {
		t.Fatalf("skewed %+v", a)
	}
	a = Evaluate(spec, &Read{ReadAt: panel, Snapshot: &snap}, plan, time.Minute, panel.Add(ReadMaxAge+time.Second))
	if a.State != StateStale || a.Code != CodeReadOld || a.Active != "" {
		t.Fatalf("old read %+v", a)
	}
}

func TestParseRejects(t *testing.T) {
	cases := map[string]string{
		"empty":          "",
		"no header":      strings.Replace(output(report()), Header, "hello", 1),
		"no footer":      strings.TrimSuffix(output(report()), Footer+"\n"),
		"truncated":      output(report())[:len(output(report()))/2],
		"bad now":        strings.Replace(output(report()), fmt.Sprintf("now %d", hubNow), "now 12", 1),
		"bad plan":       strings.Replace(output(report()), "plan "+plan+" ", "plan zz ", 1),
		"future beat":    output(report("beat " + fmt.Sprint(hubNow+60))),
		"ancient switch": output(report("switched 1000")),
		"switch>beat":    output(report("switched "+fmt.Sprint(hubNow), "beat "+fmt.Sprint(hubNow-10))),
		"unknown field":  output(report("extra 1")),
		"dup field":      output(report("hop hk-2")+"") + "",
		"missing field":  output(report("hop -")),
		"bad reason":     output(report("reason because")),
		"bad result":     output(report("result maybe")),
		"failed no want": output(report("result failed")),
		"want when ok":   output(report("want hk-ix")),
		"shell chars":    output(report("hop $(reboot)")),
		"control char":   output(report("hop hk\x1b-2")),
		"dup group":      output(report(), report()),
		"two values":     output(report("hop hk-2 hk-ix")),
		"unterminated":   strings.Replace(output(report()), "end\n", "", 1),
		"stray line":     strings.Replace(output(report()), Footer, "garbage\n"+Footer, 1),
	}
	// A real duplicate field.
	cases["dup field"] = output(strings.Replace(report(), "hop hk-2\n", "hop hk-2\nhop hk-ix\n", 1))
	for name, out := range cases {
		if _, err := Parse(out); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	big := output(strings.Repeat(report(), 1)) + strings.Repeat("x", MaxOutput)
	_, err := Parse(big)
	if pe, ok := err.(*ParseError); !ok || pe.Code != "oversized" {
		t.Fatalf("oversized: %v", err)
	}
	// Exactly at the limit is judged by its content, not refused for size.
	if _, err := Parse(output(report())); err != nil {
		t.Fatal(err)
	}
}
