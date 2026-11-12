package unlock

import (
	"testing"
	"time"
)

func members() []string { return []string{"us", "us-2"} }

func TestOneScheduledFailureDoesNotMove(t *testing.T) {
	s := State{Pool: "us", Preferred: "us", Active: "us"}
	s = Advance(s, Event{ExitID: "us", OK: false, Kind: KindScheduled, At: at(0)}, members())
	if s.Active != "us" || s.Demoted || s.SchedFails != 1 {
		t.Fatalf("%+v", s)
	}
}

func TestTwoScheduledFailuresMoveInsidePool(t *testing.T) {
	s := State{Pool: "us", Preferred: "us", Active: "us", Known: map[string]bool{"us-2": true}}
	s = Advance(s, Event{ExitID: "us", OK: false, Kind: KindScheduled, At: at(0)}, members())
	s = Advance(s, Event{ExitID: "us", OK: false, Kind: KindScheduled, At: at(6 * 3600)}, members())
	if !s.Demoted || s.Active != "us-2" {
		t.Fatalf("%+v", s)
	}
}

func TestSuccessResetsTheFailureStreak(t *testing.T) {
	s := State{Pool: "us", Preferred: "us", Active: "us"}
	s = Advance(s, Event{ExitID: "us", OK: false, Kind: KindScheduled, At: at(0)}, members())
	s = Advance(s, Event{ExitID: "us", OK: true, Kind: KindScheduled, At: at(1)}, members())
	s = Advance(s, Event{ExitID: "us", OK: false, Kind: KindScheduled, At: at(2)}, members())
	if s.Demoted || s.SchedFails != 1 {
		t.Fatalf("streak should have reset: %+v", s)
	}
}

func TestManualAndHealthDoNotCountAsScheduled(t *testing.T) {
	s := State{Pool: "us", Preferred: "us", Active: "us"}
	s = Advance(s, Event{ExitID: "us", OK: false, Kind: KindManual, At: at(0)}, members())
	s = Advance(s, Event{ExitID: "us", OK: false, Kind: KindHealth, At: at(1)}, members())
	s = Advance(s, Event{ExitID: "us", OK: false, Kind: KindScheduled, At: at(2)}, members())
	if s.Demoted || s.SchedFails != 1 {
		t.Fatalf("%+v", s)
	}
}

func TestNoCountryChangeWhenThePoolIsExhausted(t *testing.T) {
	s := State{Pool: "us", Preferred: "us", Active: "us", Known: map[string]bool{"us-2": false}}
	s = Advance(s, Event{ExitID: "us", OK: false, Kind: KindScheduled, At: at(0)}, members())
	s = Advance(s, Event{ExitID: "us", OK: false, Kind: KindScheduled, At: at(1)}, []string{"us", "us-2"})
	if s.Active != "us" || !s.Unavailable || s.Demoted {
		t.Fatalf("should stay and alarm: %+v", s)
	}
	// A Japan exit is not a member. Feeding it must not move the service.
	s = Advance(s, Event{ExitID: "jp", OK: true, Kind: KindScheduled, At: at(2)}, members())
	if s.Active != "us" {
		t.Fatalf("left the US pool: %+v", s)
	}
}

func TestReturnWaitsForPreferredAndCooldown(t *testing.T) {
	s := State{Pool: "us", Preferred: "us", Active: "us", Known: map[string]bool{"us-2": true}}
	s = Advance(s, Event{ExitID: "us", OK: false, Kind: KindScheduled, At: at(0)}, members())
	s = Advance(s, Event{ExitID: "us", OK: false, Kind: KindScheduled, At: at(1)}, members())
	if s.Active != "us-2" {
		t.Fatal(s)
	}
	// Backup succeeds, preferred still down: do not return after 30 minutes.
	s = Advance(s, Event{ExitID: "us-2", OK: true, Kind: KindScheduled, At: at(10)}, members())
	s = Advance(s, Event{ExitID: "us-2", OK: true, Kind: KindManual, At: at(10 + int(ReturnCooldown/time.Second) + 5)}, members())
	if s.Active != "us-2" || !s.Demoted {
		t.Fatalf("returned while preferred is still down: %+v", s)
	}
	recovered := at(100)
	s = Advance(s, Event{ExitID: "us", OK: true, Kind: KindScheduled, At: recovered}, members())
	if s.Active != "us-2" {
		t.Fatalf("returned before the 30 minute cooldown: %+v", s)
	}
	s = Advance(s, Event{ExitID: "us", OK: true, Kind: KindManual, At: recovered.Add(ReturnCooldown + time.Second)}, members())
	if s.Active != "us" || s.Demoted {
		t.Fatalf("should be back on preferred: %+v", s)
	}
}

func TestPinIsNotADecision(t *testing.T) {
	snap := Snapshot{Services: map[string]State{
		"auto-openai":    {Preferred: "us", Active: "us-2", Pool: "us"},
		"manual-example": {Preferred: "us", Active: "us-2", Pool: "us"},
	}}
	dec := Decisions(snap, []Service{
		{RuleID: "auto-openai", Pool: "us", Preferred: "us", Members: members()},
		{RuleID: "manual-example", Pool: "us", Preferred: "us", Members: members(), Pin: true},
	})
	if dec["auto-openai"] != "us-2" {
		t.Fatalf("auto decision = %v", dec)
	}
	if _, ok := dec["manual-example"]; ok {
		t.Fatal("pinned rule was included in the unlock map")
	}
}

func TestBackupFailureDoesNotLeaveThePool(t *testing.T) {
	s := State{Pool: "us", Preferred: "us", Active: "us", Known: map[string]bool{"us-2": true}}
	s = Advance(s, Event{ExitID: "us", OK: false, Kind: KindScheduled, At: at(0)}, members())
	s = Advance(s, Event{ExitID: "us", OK: false, Kind: KindScheduled, At: at(1)}, members())
	if s.Active != "us-2" || !s.Demoted {
		t.Fatalf("did not demote: %+v", s)
	}
	s = Advance(s, Event{ExitID: "us-2", OK: false, Kind: KindScheduled, At: at(2)}, members())
	if s.Active != "us-2" || !s.Demoted || s.ActiveFails != 1 {
		t.Fatalf("one backup failure moved the route: %+v", s)
	}
	s = Advance(s, Event{ExitID: "us-2", OK: false, Kind: KindScheduled, At: at(3)}, members())
	if s.Active != "us" || !s.Unavailable || s.Demoted {
		t.Fatalf("backup exhaustion should alarm inside the US pool: %+v", s)
	}
}

func TestRegionMismatchIsNotSuccess(t *testing.T) {
	raw := "Netflix: Yes (Region: US)\nDisney+: Yes (Region: HK)\nBahamut: Yes\n"
	got := ParseRegionCheckFor(raw, "hk")
	if got["auto-netflix"] {
		t.Fatal("a US catalog counted as a Hong Kong unlock")
	}
	if !got["auto-disney"] || !got["auto-bahamut"] {
		t.Fatalf("%v", got)
	}
	if !ParseRegionCheck(raw)["auto-netflix"] {
		t.Fatal("a Yes with no exit region must stay a Yes")
	}
}

func TestParseRegionCheckDoesNotInventFailures(t *testing.T) {
	raw := "" +
		"Netflix: Yes (Region: HK)\n" +
		"[Disney+] IPv4: No\n" +
		"something else entirely\n" +
		"Bahamut: Yes\n"
	got := ParseRegionCheck(raw)
	if !got["auto-netflix"] || got["auto-disney"] || !got["auto-bahamut"] {
		t.Fatalf("%v", got)
	}
	if _, ok := got["auto-openai"]; ok {
		t.Fatal("unmentioned service must stay unknown")
	}
	if ParseAICodes("openai 000\nclaude 401\n")["auto-openai"] {
		t.Fatal("http 000 is a failed connection")
	}
	if !ParseAICodes("openai 403\n")["auto-openai"] {
		t.Fatal("a completed HTTP status is reachability, not an account check")
	}
}

func at(sec int) time.Time {
	return time.Date(2026, 11, 12, 0, 0, 0, 0, time.UTC).Add(time.Duration(sec) * time.Second)
}

// Review 5b01903 P2 (absorbed from unlock_repro_test.go): demoted onto b,
// a and b both succeeded at t0, then a scheduled probe of a FAILS at
// t0+31m. The old code returned to a on that failed probe because it only
// looked at the historical success timestamps.
func TestReviewReturnToFailingPreferred(t *testing.T) {
	now := time.Date(2026, 11, 12, 0, 0, 0, 0, time.UTC)
	s := State{Preferred: "a", Active: "b", Demoted: true, Known: map[string]bool{"a": true, "b": true}, PreferredOKAt: now, PreferredSeenAt: now, BackupOKAt: now}
	s = Advance(s, Event{ExitID: "a", OK: false, Kind: KindScheduled, At: now.Add(31 * time.Minute)}, []string{"a", "b"})
	if s.Active == "a" || !s.Demoted {
		t.Fatalf("returned to preferred a on its FAILED scheduled probe: %+v", s)
	}
	if !s.PreferredOKAt.IsZero() {
		t.Fatalf("a failure must clear the recovery start: %+v", s)
	}
	// A later success of the backup, past the old cooldown, still must not
	// put the service back on a.
	s = Advance(s, Event{ExitID: "b", OK: true, Kind: KindScheduled, At: now.Add(2 * time.Hour)}, []string{"a", "b"})
	if s.Active != "b" || !s.Demoted {
		t.Fatalf("returned after a failed preferred probe: %+v", s)
	}
}

func TestPreferredFailureRestartsCooldown(t *testing.T) {
	m := []string{"a", "b"}
	t0 := at(0)
	s := State{Preferred: "a", Active: "b", Demoted: true, Known: map[string]bool{"b": true}}
	s = Advance(s, Event{ExitID: "a", OK: true, Kind: KindScheduled, At: t0}, m)
	if !s.PreferredOKAt.Equal(t0) {
		t.Fatalf("first success should start the streak: %+v", s)
	}
	// Manual failures also break the streak: a failure is never evidence of health.
	s = Advance(s, Event{ExitID: "a", OK: false, Kind: KindManual, At: t0.Add(20 * time.Minute)}, m)
	s = Advance(s, Event{ExitID: "a", OK: true, Kind: KindManual, At: t0.Add(25 * time.Minute)}, m)
	s = Advance(s, Event{ExitID: "a", OK: true, Kind: KindManual, At: t0.Add(35 * time.Minute)}, m)
	if s.Active != "b" {
		t.Fatalf("cooldown was counted from before the failure: %+v", s)
	}
	s = Advance(s, Event{ExitID: "a", OK: true, Kind: KindScheduled, At: t0.Add(25*time.Minute + ReturnCooldown)}, m)
	if s.Active != "a" || s.Demoted {
		t.Fatalf("30 minutes of continuous recovery should return: %+v", s)
	}
}

func TestStalePreferredSuccessDoesNotReturn(t *testing.T) {
	m := []string{"a", "b"}
	s := State{Preferred: "a", Active: "b", Demoted: true, Known: map[string]bool{"b": true}}
	s = Advance(s, Event{ExitID: "a", OK: true, Kind: KindScheduled, At: at(0)}, m)
	// Hours later only the backup reports. The preferred's last word is old.
	s = Advance(s, Event{ExitID: "b", OK: true, Kind: KindScheduled, At: at(0).Add(6 * time.Hour)}, m)
	if s.Active != "b" {
		t.Fatalf("a 6-hour-old success triggered a return: %+v", s)
	}
	if s.CanReturn(at(0).Add(6 * time.Hour)) {
		t.Fatal("CanReturn accepted an expired preferred result")
	}
	s = Advance(s, Event{ExitID: "a", OK: true, Kind: KindScheduled, At: at(0).Add(6*time.Hour + time.Minute)}, m)
	if s.Active != "a" {
		t.Fatalf("a fresh success after an unbroken streak should return: %+v", s)
	}
}
