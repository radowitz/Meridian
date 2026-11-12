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
