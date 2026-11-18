package pathquality

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/radowitz/meridian/internal/hostexec"
	"github.com/radowitz/meridian/internal/model"
)

// speedConfig is testConfig with the speed tests compiled.
func speedConfig(t *testing.T, mut func(*model.PathQuality)) Config {
	t.Helper()
	c := testConfig(t, mut)
	c.SpeedPort = SpeedPort
	c.Relays[0].Legs[0].Local, c.Relays[0].Legs[0].Remote = "10.66.3.1", "10.66.3.2"
	c.Relays[0].Legs[1].Local, c.Relays[0].Legs[1].Remote = "10.66.102.1", "10.66.102.2"
	c.Relays[1].Legs[0].Local, c.Relays[1].Legs[0].Remote = "10.66.4.1", "10.66.4.2"
	b, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	pc, err := ParseConfig(b)
	if err != nil {
		t.Fatal(err)
	}
	return pc
}

func defSettings() model.PathQuality { return model.PathQualityDefaults() }

// fold runs a sequence of tests (kbps; <0 = not measured) through FoldSample.
func fold(t *testing.T, at0 int64, kbps ...int) (QoSVerdict, []SpeedSample) {
	t.Helper()
	var v QoSVerdict
	var log []SpeedSample
	for i, k := range kbps {
		x := SpeedSample{At: at0 + int64(i)*1800}
		if k >= 0 {
			x.OK, x.Kbps, x.Bytes, x.ElapsedMS = true, k, 20<<20, 1000
		} else {
			x.Reason = SpeedFailConnect
		}
		x = FoldSample(&v, log, x, defSettings(), 200_000)
		log = append(log, x)
	}
	return v, log
}

func TestQoSTwoConsecutiveLowThrottle(t *testing.T) {
	// Nominal 200 Mbit/s: 25% = 50 Mbit/s.
	if v, _ := fold(t, 1e9, 180_000, 40_000); v.State != QoSOK || v.LowStreak != 1 {
		t.Fatalf("one low test throttled: %+v", v)
	}
	if v, _ := fold(t, 1e9, 180_000, 40_000, 60_000, 40_000); v.State != QoSOK {
		t.Fatalf("non-consecutive lows throttled: %+v", v)
	}
	v, _ := fold(t, 1e9, 180_000, 40_000, 30_000)
	if v.State != QoSThrottled || v.BaselineSrc != BaselineNominal || v.BaselineKbps != 200_000 {
		t.Fatalf("two lows: %+v", v)
	}
	// Failed tests neither count as slow nor break the run.
	if v, _ := fold(t, 1e9, 180_000, 40_000, -1, -1, 30_000); v.State != QoSThrottled || v.FailReason != SpeedFailConnect {
		t.Fatalf("not measured broke the streak: %+v", v)
	}
	if v, _ := fold(t, 1e9, -1, -1, -1, -1); v.State != QoSUnknown || v.LastKbps != 0 {
		t.Fatalf("failures produced a verdict: %+v", v)
	}
}

func TestQoSRecoverAtHalfBaseline(t *testing.T) {
	v, _ := fold(t, 1e9, 40_000, 40_000, 90_000) // 45%: stays
	if v.State != QoSThrottled {
		t.Fatalf("recovered below 50%%: %+v", v)
	}
	v, _ = fold(t, 1e9, 40_000, 40_000, 100_000) // 50%
	if v.State != QoSOK || v.LowStreak != 0 {
		t.Fatalf("not recovered at 50%%: %+v", v)
	}
}

func TestQoSBaselineP90AndOutliers(t *testing.T) {
	s := defSettings()
	var log []SpeedSample
	at := int64(1e9)
	for i := 0; i < 20; i++ {
		log = append(log, SpeedSample{At: at + int64(i)*1800, OK: true, Kbps: 100_000 + i*1000})
	}
	// An isolated spike, throttled samples and failures stay out.
	log = append(log, SpeedSample{At: at + 21*1800, OK: true, Kbps: 900_000})
	log = append(log, SpeedSample{At: at + 22*1800, OK: true, Kbps: 5_000, Low: true})
	log = append(log, SpeedSample{At: at + 23*1800, Reason: SpeedFailShort})
	b, src := Baseline(log, at+24*1800, s, 200_000)
	if src != BaselineP90 || b != 117_000 {
		t.Fatalf("baseline %d %s", b, src)
	}
	// Outside the window: back to nominal.
	if b, src := Baseline(log, at+30*86400, s, 200_000); src != BaselineNominal || b != 200_000 {
		t.Fatalf("old samples counted: %d %s", b, src)
	}
	// Per-relay nominal.
	s.Overrides = []model.RelayOverride{{Relay: "access", NominalMbps: 100}}
	if NominalKbps(s, "access") != 100_000 || NominalKbps(s, "access2") != 200_000 {
		t.Fatal("nominal override")
	}
	// Implausible result: not measured.
	var v QoSVerdict
	if x := FoldSample(&v, nil, SpeedSample{At: 1, OK: true, Kbps: 50_000_000}, defSettings(), 200_000); x.OK || x.Reason != SpeedFailInvalid {
		t.Fatalf("implausible accepted: %+v", x)
	}
}

func TestQoSFileRoundTripAndRefusals(t *testing.T) {
	c := speedConfig(t, nil)
	text := FormatQoS(c, map[string]*QoSVerdict{"access": {State: QoSThrottled, Since: 5, LastKbps: 3000, LastAt: 9, BaselineKbps: 150_000, BaselineSrc: BaselineP90}})
	q, err := ParseQoS(c, text)
	if err != nil || q["access"].State != QoSThrottled || q["access2"].State != QoSUnknown || q["access2"].LastKbps != 0 || q["access"].BaselineKbps != 150_000 {
		t.Fatalf("%v %+v\n%s", err, q, text)
	}
	for _, bad := range []string{
		strings.Replace(text, "throttled", "slow", 1),
		strings.Replace(text, "relay access2", "relay other", 1),
		strings.Replace(text, " p90", " max", 1),
		strings.Replace(text, "end\n", "", 1),
		strings.Replace(text, " 3000 ", " 3e3 ", 1),
		"relay access ok 0 - 0 1 nominal\n" + text,
	} {
		if _, err := ParseQoS(c, bad); err == nil {
			t.Errorf("accepted:\n%s", bad)
		}
	}
}

// throttle sets the verdict the sim's passes read.
func (s *sim) throttle(ids ...string) {
	s.qos = map[string]QoSEntry{}
	for i, r := range s.c.Relays {
		e := QoSEntry{ID: r.ID, State: QoSOK, LastKbps: 150_000 + i*1000, LastAt: s.now, BaselineKbps: 180_000, BaselineSrc: BaselineP90}
		for _, id := range ids {
			if id == r.ID {
				e.State, e.LastKbps = QoSThrottled, 10_000+i*1000
			}
		}
		s.qos[r.ID] = e
	}
}

func TestThrottledRelayCarriesNothingWhileOthersAreFine(t *testing.T) {
	s := newSim(t, speedConfig(t, nil))
	s.throttle()
	s.passes(4, good(30), good(300), good(60))
	// RTT no longer weighs: equal shares despite 30 vs 300 ms.
	if a, b := weights(s.d); a != 500 || b != 500 {
		t.Fatalf("weights %d/%d", a, b)
	}
	s.throttle("access2")
	s.pass(good(30), good(30), good(60))
	if r := s.relay("access2"); r.Status != StatusReduced || r.Reason != ReasonQoSThrottled || r.Drain {
		t.Fatalf("access2 %+v", r)
	}
	if a, b := weights(s.d); a != 1000 || b != 0 || s.d.Upstream != UpstreamMain {
		t.Fatalf("weights %d/%d on %s", a, b, s.d.Upstream)
	}
	// Recovered: ramped back (25 → 50 → 100 %), never a backup switch.
	s.throttle()
	seen := map[int]bool{}
	for i := 0; i < 20; i++ {
		s.pass(good(30), good(30), good(60))
		_, b := weights(s.d)
		seen[b] = true
	}
	if r := s.relay("access2"); r.Status != StatusActive || !seen[200] || !seen[333] {
		t.Fatalf("ramp: %+v seen %v", r, seen)
	}
}

func TestAllThrottledKeepsTheFastestNoBackup(t *testing.T) {
	s := newSim(t, speedConfig(t, nil))
	s.throttle("access", "access2") // access2 tested faster (11 vs 10 Mbit/s)
	s.passes(10, good(30), good(30), good(60))
	if s.d.Upstream != UpstreamMain || s.st.Alert != AlertAllThrottled {
		t.Fatalf("%s %s", s.d.Upstream, s.st.Alert)
	}
	if r := s.relay("access2"); r.Reason != ReasonRetained {
		t.Fatalf("fastest not retained: %+v", r)
	}
	if a, b := weights(s.d); a != 0 || b != 1000 {
		t.Fatalf("weights %d/%d", a, b)
	}
	// access recovers: access2 released back to reduced, access carries.
	s.throttle("access2")
	s.passes(3, good(30), good(30), good(60))
	if r := s.relay("access2"); r.Reason != ReasonQoSThrottled {
		t.Fatalf("not released: %+v", r)
	}
	if a, _ := weights(s.d); a != 1000 {
		t.Fatalf("access weight %d", a)
	}
}

func TestAllDownTakesBackupThrottledDoesNotAndReturns(t *testing.T) {
	s := newSim(t, speedConfig(t, nil))
	s.throttle("access", "access2")
	s.passes(30, good(30), good(30), good(60))
	if s.d.Upstream != UpstreamMain {
		t.Fatal("throttling took the backup")
	}
	s.passes(8, down(), down(), good(60))
	if s.d.Upstream != UpstreamBackup || s.st.SwitchReason != SwitchAllDown {
		t.Fatalf("all down: %s", s.d.Upstream)
	}
	// Reachable (still throttled): 3 passes and the dwell, then back.
	sw := s.st.LastSwitch
	for s.now+PassInterval-sw < 120 {
		s.pass(good(30), good(30), good(60))
		if s.d.Upstream != UpstreamMain && s.st.Alert != AlertOnBackupReturning && s.st.MainReachablePasses > 0 {
			t.Fatalf("alert %s", s.st.Alert)
		}
	}
	s.pass(good(30), good(30), good(60))
	if s.d.Upstream != UpstreamMain || s.st.SwitchReason != SwitchRelayReachable {
		t.Fatalf("no return: %s %s", s.d.Upstream, s.st.SwitchReason)
	}
	s.pass(good(30), good(30), good(60))
	if a, b := weights(s.d); a+b != 1000 || a != 0 && b != 0 {
		t.Fatalf("one throttled relay should carry alone: %d/%d", a, b)
	}
}

func TestHighRTTAndLossNoLongerReduceOrEvict(t *testing.T) {
	s := newSim(t, speedConfig(t, nil))
	s.passes(60, lossy(800, 2), good(30), good(60)) // 60% loss, 800 ms
	if r := s.relay("access"); r.Status != StatusActive || r.Grade != GradeGood {
		t.Fatalf("quality degraded a reachable relay: %+v", r)
	}
	if a, b := weights(s.d); a != 500 || b != 500 {
		t.Fatalf("weights %d/%d", a, b)
	}
	// Telemetry is kept.
	if s.relay("access").RTTEWMA < 700 || s.relay("access").LossEWMA < 500 {
		t.Fatalf("telemetry lost: %+v", s.relay("access"))
	}
}

func TestNoVerdictOrStaleOrOffMeansNotThrottled(t *testing.T) {
	s := newSim(t, speedConfig(t, nil))
	s.throttle("access")
	e := s.qos["access"]
	e.LastAt = s.now - QoSMaxAge(s.c.Settings) - 100
	s.qos["access"] = e
	s.passes(3, good(30), good(30), good(60))
	if r := s.relay("access"); r.Throttled || r.QoS != QoSUnknown {
		t.Fatalf("stale verdict used: %+v", r)
	}
	off := newSim(t, testConfig(t, nil)) // no speed port compiled
	off.throttle("access")
	off.passes(3, good(30), good(30), good(60))
	if r := off.relay("access"); r.Throttled || r.QoS != QoSOff {
		t.Fatalf("verdict used without speed tests: %+v", r)
	}
}

func TestOldStateQualityReductionMigrated(t *testing.T) {
	c := speedConfig(t, nil)
	s := newSim(t, c)
	s.passes(4, good(30), good(30), good(60))
	raw, _ := json.Marshal(s.st)
	var old map[string]any
	_ = json.Unmarshal(raw, &old)
	old["version"] = 1
	rs := old["relays"].(map[string]any)
	rs["access"].(map[string]any)["status"], rs["access"].(map[string]any)["reason"], rs["access"].(map[string]any)["grade"] = StatusReduced, ReasonMildRTT, GradeMild
	rs["access2"].(map[string]any)["status"], rs["access2"].(map[string]any)["reason"] = StatusEvicted, ReasonPoorLoss
	raw, _ = json.Marshal(old)
	s.st = nil
	if err := json.Unmarshal(raw, &s.st); err != nil {
		t.Fatal(err)
	}
	s.pass(good(30), good(30), good(60))
	if s.st.Version != StateVersion || s.relay("access").Status != StatusActive || s.relay("access2").Status != StatusActive {
		t.Fatalf("not migrated: %d %+v %+v", s.st.Version, s.relay("access"), s.relay("access2"))
	}
	if a, b := weights(s.d); a != 500 || b != 500 {
		t.Fatalf("weights %d/%d", a, b)
	}
}

func TestDisabledNeverRetainedAndLegMissKeepsRetained(t *testing.T) {
	c := speedConfig(t, func(p *model.PathQuality) {
		p.Overrides = []model.RelayOverride{{Relay: "access", Disabled: true}}
	})
	s := newSim(t, c)
	s.throttle("access2")
	s.passes(10, good(30), good(30), good(60))
	if s.relay("access").Status != StatusDisabled || s.relay("access2").Reason != ReasonRetained {
		t.Fatalf("access %+v access2 %+v", s.relay("access"), s.relay("access2"))
	}
	// Retained access (both throttled, access2 down), selected UDP leg dark, WSS answers.
	s2 := newSim(t, speedConfig(t, nil))
	s2.throttle("access", "access2")
	s2.passes(10, good(30), down(), good(60))
	wss := good(30)
	wss.udpLegDown = true
	for i := 0; i < 20; i++ {
		s2.pass(wss, down(), good(60))
		if s2.d.Upstream != UpstreamMain || s2.d.Relays[0].Weight == 0 {
			t.Fatalf("pass %d: %s %+v", i, s2.d.Upstream, s2.relay("access"))
		}
	}
	if s2.relay("access").Leg != "m02w" {
		t.Fatal("did not move to the WSS leg")
	}
}

func TestStatusRecordCarriesQoSAndParses(t *testing.T) {
	s := newSim(t, speedConfig(t, nil))
	s.throttle("access2")
	s.passes(3, good(30), good(30), good(60))
	rec := FormatStatus(s.c, s.st, s.now, "go")
	st, err := hostexec.ParseUpstream(rec)
	if err != nil {
		t.Fatalf("%v\n%s", err, rec)
	}
	r := st.Relays[1]
	if r.QoS != QoSThrottled || r.SpeedKbps == nil || *r.SpeedKbps != 11_000 || r.BaselineKbps != 180_000 || r.BaselineSrc != BaselineP90 || r.Reason != ReasonQoSThrottled {
		t.Fatalf("%+v\n%s", r, rec)
	}
}
