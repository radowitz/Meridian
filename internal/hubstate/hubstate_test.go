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

// hubID is the identity the test reads were taken from (documentation
// address, fake fingerprint).
var hubID = NewIdentity("hk-hub", "srv-1", "203.0.113.10", 22, "SHA256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")

var spec = GroupSpec{ID: "hk", Dynamic: true, Members: []string{"hk-ix", "hk-2"}, Mesh: true}

func judge(t *testing.T, out string) Actual {
	t.Helper()
	snap, err := Parse(out)
	if err != nil {
		t.Fatalf("parse: %v\n%s", err, out)
	}
	at := time.Unix(hubNow, 0)
	return Evaluate(spec, &Read{ReadAt: at, Identity: hubID, Snapshot: &snap}, hubID, plan, 60*time.Second, at)
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
	if a = Evaluate(noMesh, &Read{ReadAt: at, Identity: hubID, Snapshot: &snap}, hubID, plan, time.Minute, at); a.Code != CodeInvalidReport {
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
	if a = Evaluate(GroupSpec{ID: "v6"}, nil, hubID, plan, time.Minute, at); a.State != StateNotSwitchable {
		t.Fatalf("static %+v", a)
	}
	if a = Evaluate(spec, nil, hubID, plan, time.Minute, at); a.State != StateNeverRead || a.ReadAt != nil {
		t.Fatalf("never %+v", a)
	}
	if a = Evaluate(spec, &Read{ReadAt: at, Identity: hubID, ErrorCode: CodeSSHFailed, SSHCode: "timeout", Error: "x"}, hubID, plan, time.Minute, at); a.State != StateUnavailable || a.Code != CodeSSHFailed || a.SSHCode != "timeout" {
		t.Fatalf("ssh %+v", a)
	}
	if a = Evaluate(spec, &Read{ReadAt: at, Identity: hubID, Snapshot: &snap}, hubID, "", time.Minute, at); a.Code != CodePlanUnavailable {
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
	a := Evaluate(spec, &Read{ReadAt: panel, Identity: hubID, Snapshot: &snap}, hubID, plan, time.Minute, panel)
	if a.State != StateOK || *a.ClockSkewSec != 7200 || !a.LastSwitch.Equal(panel.Add(-60*time.Second)) {
		t.Fatalf("skewed %+v", a)
	}
	a = Evaluate(spec, &Read{ReadAt: panel, Identity: hubID, Snapshot: &snap}, hubID, plan, time.Minute, panel.Add(ReadMaxAge+time.Second))
	if a.State != StateStale || a.Code != CodeReadOld || a.Active != "" {
		t.Fatalf("old read %+v", a)
	}
}

// A read only describes the hub identity it was taken from: any change of
// hub node, server, address, port or pinned key makes it unknown at once,
// whatever it says and however fresh it is.
func TestEvaluateIdentity(t *testing.T) {
	snap, err := Parse(output(report()))
	if err != nil {
		t.Fatal(err)
	}
	at := time.Unix(hubNow, 0)
	ok := &Read{ReadAt: at, Identity: hubID, Snapshot: &snap}
	if a := Evaluate(spec, ok, hubID, plan, time.Minute, at); a.State != StateOK {
		t.Fatalf("same identity %+v", a)
	}
	// Equal after normalisation.
	same := NewIdentity("hk-hub", "srv-1", " 203.0.113.10 ", 0, "SHA256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	if a := Evaluate(spec, ok, same, plan, time.Minute, at); a.State != StateOK {
		t.Fatalf("normalised identity %+v", a)
	}
	changes := map[string]Identity{
		"hub node":    NewIdentity("hk-hub2", "srv-1", "203.0.113.10", 22, hubID.Fingerprint),
		"server":      NewIdentity("hk-hub", "srv-2", "203.0.113.10", 22, hubID.Fingerprint),
		"address":     NewIdentity("hk-hub", "srv-1", "203.0.113.11", 22, hubID.Fingerprint),
		"port":        NewIdentity("hk-hub", "srv-1", "203.0.113.10", 2222, hubID.Fingerprint),
		"fingerprint": NewIdentity("hk-hub", "srv-1", "203.0.113.10", 22, "SHA256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"),
		"unpinned":    NewIdentity("hk-hub", "srv-1", "203.0.113.10", 22, ""),
		"no hub":      {},
	}
	for name, cur := range changes {
		a := Evaluate(spec, ok, cur, plan, time.Minute, at)
		if a.State != StateUnavailable || a.Code != CodeIdentityChanged || a.Active != "" || a.Hop != "" || a.LastSwitch != nil || a.ReadAt == nil || a.Message == "" {
			t.Fatalf("%s: %+v", name, a)
		}
		// A failed read of the old hub is just as irrelevant.
		failed := &Read{ReadAt: at, Identity: hubID, ErrorCode: CodeSSHFailed}
		if a = Evaluate(spec, failed, cur, plan, time.Minute, at); a.Code != CodeIdentityChanged {
			t.Fatalf("%s failed read: %+v", name, a)
		}
	}
	// The pin is contradicted (mismatch): same identity, but no report
	// counts while it lasts.
	contradicted := hubID
	contradicted.Trusted = false
	if a := Evaluate(spec, ok, contradicted, plan, time.Minute, at); a.State != StateUnavailable || a.Code != CodeIdentityChanged || a.Active != "" {
		t.Fatalf("contradicted pin %+v", a)
	}
	if !contradicted.Equal(hubID) {
		t.Fatal("trust is not part of the identity")
	}
	// A read stored before reads carried an identity is never believed.
	legacy := &Read{ReadAt: at, Identity: Identity{HubNode: "hk-hub", ServerID: "srv-1"}, Snapshot: &snap}
	if a := Evaluate(spec, legacy, hubID, plan, time.Minute, at); a.Code != CodeIdentityChanged {
		t.Fatalf("legacy read %+v", a)
	}
	// A report without a pinned key is never ok, even if nothing changed.
	unpinned := NewIdentity("hk-hub", "srv-1", "203.0.113.10", 22, "")
	if a := Evaluate(spec, &Read{ReadAt: at, Identity: unpinned, Snapshot: &snap}, unpinned, plan, time.Minute, at); a.State == StateOK {
		t.Fatalf("report without a pinned key %+v", a)
	}
	// A failed read stays meaningful while its (incomplete) identity is
	// still the current one: the hub that cannot be read says why.
	noKey := &Read{ReadAt: at, Identity: unpinned, ErrorCode: CodeServerNotReady}
	if a := Evaluate(spec, noKey, unpinned, plan, time.Minute, at); a.Code != CodeServerNotReady {
		t.Fatalf("failed read of the current hub %+v", a)
	}
}

func TestNormalizeAddress(t *testing.T) {
	for in, want := range map[string]string{
		"203.0.113.10":        "203.0.113.10",
		" 203.0.113.10\t":     "203.0.113.10",
		"::ffff:203.0.113.10": "203.0.113.10",
		"[2001:DB8:0:0::1]":   "2001:db8::1",
		"Hub.Example.NET.":    "hub.example.net",
		"hub.example.net":     "hub.example.net",
	} {
		if got := NormalizeAddress(in); got != want {
			t.Errorf("%q: %q, want %q", in, got, want)
		}
	}
	if NewIdentity("n", "s", "a.example.net", 0, "f").Port != 22 {
		t.Fatal("port 0 is 22")
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

// Two hubs (primary and backup): a read is judged only against the hub it
// was taken from. The backup's read never describes the primary (other hub
// node, server, address, key), even with the same plan; a read of the
// right hub with the other hub's plan is a version mismatch, not ok.
func TestEvaluateIdentityPerHub(t *testing.T) {
	snap, err := Parse(output(report()))
	if err != nil {
		t.Fatal(err)
	}
	at := time.Unix(hubNow, 0)
	primary := NewIdentity("ix", "srv-ix", "198.51.100.10", 2222, "SHA256:iiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiii")
	backup := NewIdentity("hk5", "srv-hk5", "203.0.113.30", 22, "SHA256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
	fromBackup := &Read{ReadAt: at, Identity: backup, Snapshot: &snap}
	if a := Evaluate(spec, fromBackup, backup, plan, time.Minute, at); a.State != StateOK {
		t.Fatalf("backup read on the backup: %+v", a)
	}
	if a := Evaluate(spec, fromBackup, primary, plan, time.Minute, at); a.State != StateUnavailable || a.Code != CodeIdentityChanged || a.Active != "" {
		t.Fatalf("backup read judged as the primary: %+v", a)
	}
	// Same server, but the node is now the other hub (tiers swapped).
	swapped := NewIdentity("ix", "srv-hk5", "203.0.113.30", 22, "SHA256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
	if a := Evaluate(spec, fromBackup, swapped, plan, time.Minute, at); a.Code != CodeIdentityChanged {
		t.Fatalf("swapped hub node accepted: %+v", a)
	}
	// The primary's plan differs from the backup's: the backup's report is
	// not ok against the primary's plan ID.
	if a := Evaluate(spec, fromBackup, backup, "fedcba9876543210fedcba98", time.Minute, at); a.State != StateVersionMismatch {
		t.Fatalf("other hub's plan accepted: %+v", a)
	}
}
