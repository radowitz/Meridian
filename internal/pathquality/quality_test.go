package pathquality

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/radowitz/meridian/internal/model"
)

// testConfig: relay "ali" with a UDP and a WSS leg, relay "ali2" with one
// leg, and the backup hub "hk5"; default settings.
func testConfig(t *testing.T, mut func(*model.PathQuality)) Config {
	t.Helper()
	s := model.PathQualityDefaults()
	if mut != nil {
		mut(&s)
	}
	c := Config{
		Version: ConfigVersion, Interval: PassInterval, ProbeSource: "10.66.200.2", PrimaryHub: "ix",
		Relays: []RelayConfig{
			{ID: "ali", Index: 1, Legs: []Leg{{"m02", "udp"}, {"m02w", "wss"}}, Probe: "10.66.1.2", Value: RelayMark(1), Table: 111},
			{ID: "ali2", Index: 2, Legs: []Leg{{"m03", "udp"}}, Probe: "10.66.2.2", Value: RelayMark(2), Table: 112},
		},
		Backup:   &BackupConfig{Hub: "hk5", Iface: "m04", Probe: "10.66.5.2", Value: BackupMark, Table: 109},
		Settings: s,
	}
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

// path describes one path on one pass.
type path struct {
	rttMS      float64
	recv       int // of 5; 0 = down
	legs       []int
	rxBps      uint64
	tcpOut     uint64 // per pass
	tcpIn      uint64
	newConns   uint64
	probe      *ProbeResult
	udpLegDown bool
}

func good(rtt float64) path { return path{rttMS: rtt, recv: 5} }
func lossy(rtt float64, recv int) path {
	return path{rttMS: rtt, recv: recv}
}
func down() path { return path{} }

// sim drives Step with cumulative counters.
type sim struct {
	t   *testing.T
	c   Config
	st  *State
	now int64
	cum map[string]*[4]uint64 // rx, tcpOut, tcpIn, new
	d   Decision
}

func newSim(t *testing.T, c Config) *sim {
	return &sim{t: t, c: c, now: 1_700_000_000, cum: map[string]*[4]uint64{}}
}

func (s *sim) sample(id string, legs []Leg, p path) PathSample {
	cu := s.cum[id]
	if cu == nil {
		cu = &[4]uint64{}
		s.cum[id] = cu
	}
	cu[0] += p.rxBps * PassInterval
	cu[1] += p.tcpOut
	cu[2] += p.tcpIn
	cu[3] += p.newConns
	ps := PathSample{TCPOut: cu[1], TCPIn: cu[2], New: cu[3], Probe: p.probe}
	for i, l := range legs {
		ls := LegSample{Iface: l.Iface, Sent: 5, Recv: p.recv, RTTus: int64(p.rttMS * 1000)}
		if i == 0 && p.udpLegDown {
			ls.Recv, ls.RTTus = 0, 0
		}
		if i == 0 {
			ls.RxBytes = cu[0]
		}
		ps.Legs = append(ps.Legs, ls)
	}
	return ps
}

// pass runs one pass 5 s after the previous one.
func (s *sim) pass(ali, ali2, bk path) Decision {
	s.now += PassInterval
	m := Measurement{Now: s.now, Relays: map[string]PathSample{
		"ali":  s.sample("ali", s.c.Relays[0].Legs, ali),
		"ali2": s.sample("ali2", s.c.Relays[1].Legs, ali2),
	}}
	b := s.sample("hk5", []Leg{{Iface: "m04"}}, bk)
	m.Backup = &b
	s.st, s.d = Step(s.c, s.st, m)
	if _, err := ParseDecision(s.c, FormatDecision(s.d)); err != nil {
		s.t.Fatalf("pass at +%d: decision refused: %v\n%s", s.now-1_700_000_000, err, FormatDecision(s.d))
	}
	return s.d
}

func (s *sim) passes(n int, ali, ali2, bk path) Decision {
	for i := 0; i < n; i++ {
		s.pass(ali, ali2, bk)
	}
	return s.d
}

func weights(d Decision) (int, int) { return d.Relays[0].Weight, d.Relays[1].Weight }

func (s *sim) relay(id string) *RelayState { return s.st.Relays[id] }

func TestEqualWeightsWhenQualityIsSimilar(t *testing.T) {
	s := newSim(t, testConfig(t, nil))
	d := s.passes(10, good(30), good(36), good(60))
	if a, b := weights(d); a != 500 || b != 500 {
		t.Fatalf("weights %d/%d, want 500/500 (within the deadband)", a, b)
	}
	if d.Upstream != UpstreamMain || d.Designated != "ali" {
		t.Fatalf("decision %+v", d)
	}
}

func TestWeightsFollowQuality(t *testing.T) {
	s := newSim(t, testConfig(t, nil))
	d := s.passes(10, good(30), good(80), good(60))
	a, b := weights(d)
	if a+b != Buckets || a <= b || b < 250 || b > 400 {
		t.Fatalf("weights %d/%d: the slower relay should get roughly a third", a, b)
	}
}

func TestDegradeEvictRecoverWithHysteresis(t *testing.T) {
	s := newSim(t, testConfig(t, nil))
	s.passes(4, good(30), good(30), good(60))
	// ali2 loses 2 of 5 echoes: below the floor (150‰) after two passes,
	// evicted 30 s later; ali takes every new connection.
	var evictedAt int64
	for i := 0; i < 12; i++ {
		s.pass(good(30), lossy(30, 3), good(60))
		if s.relay("ali2").Status == StatusEvicted && evictedAt == 0 {
			evictedAt = s.now
		}
	}
	if evictedAt == 0 {
		t.Fatalf("ali2 never evicted: %+v", s.relay("ali2"))
	}
	if r := s.relay("ali2"); r.Reason != ReasonPoorLoss || !r.Drain {
		t.Fatalf("ali2 reason %q drain %v", r.Reason, r.Drain)
	}
	if a, b := weights(s.d); a != 1000 || b != 0 {
		t.Fatalf("weights %d/%d after eviction", a, b)
	}
	// Noisy recovery: good passes broken by a bad one never re-admit it.
	for i := 0; i < 60; i++ {
		if i%10 == 9 {
			s.pass(good(30), lossy(30, 2), good(60))
		} else {
			s.pass(good(30), good(30), good(60))
		}
		if s.relay("ali2").Weight != 0 {
			t.Fatalf("re-admitted after a noisy stretch at pass %d: %+v", i, s.relay("ali2"))
		}
	}
	// Clean: the loss average decays, then RecoverAfter (120 s) of good,
	// then 25% → 50% → full weight, one ramp step (30 s) each.
	var seen []int
	for i := 0; i < 80 && s.relay("ali2").Status != StatusActive; i++ {
		s.pass(good(30), good(30), good(60))
		if w := s.relay("ali2").Weight; w > 0 && (len(seen) == 0 || seen[len(seen)-1] != w) {
			seen = append(seen, w)
		}
	}
	if s.relay("ali2").Status != StatusActive {
		t.Fatalf("ali2 did not recover: %+v", s.relay("ali2"))
	}
	if len(seen) < 3 || seen[0] != 200 || seen[len(seen)-1] != 500 {
		t.Fatalf("re-admission weights %v, want a ramp 200 → … → 500", seen)
	}
	if s.relay("ali2").Drain {
		t.Fatal("drain still set after recovery")
	}
}

func TestMildDegradationReducesThenStops(t *testing.T) {
	s := newSim(t, testConfig(t, nil))
	s.passes(4, good(30), good(30), good(60))
	// ali2 at 250 ms: mild (≥200), not poor (<400). The averaged RTT
	// crosses 200 ms on the fifth pass; ReduceAfter (20 s) later it is
	// reduced, StandbyAfter (60 s) later it gets no new connections.
	n := 0
	for ; n < 20 && s.relay("ali2").Status != StatusReduced; n++ {
		s.pass(good(30), good(250), good(60))
	}
	if n < 8 || n > 10 {
		t.Fatalf("reduced after %d passes, want 8–10", n)
	}
	if a, b := weights(s.d); b == 0 || b > 250 || a+b != Buckets {
		t.Fatalf("reduced weights %d/%d", a, b)
	}
	for ; n < 40 && s.relay("ali2").Status != StatusStandby; n++ {
		s.pass(good(30), good(250), good(60))
	}
	if n < 16 || n > 18 {
		t.Fatalf("standby after %d passes, want 16–18", n)
	}
	if _, b := weights(s.d); b != 0 {
		t.Fatalf("standby relay still gets new connections: %d", b)
	}
	if s.relay("ali2").Drain {
		t.Fatal("standby (mild) must not clear existing connections")
	}
}

func TestStandbyNeverEmptiesTheSet(t *testing.T) {
	s := newSim(t, testConfig(t, nil))
	d := s.passes(20, good(250), good(260), good(600))
	if a, b := weights(d); a+b != Buckets {
		t.Fatalf("both mildly degraded: weights %d/%d", a, b)
	}
	if d.Upstream != UpstreamMain {
		t.Fatal("mild degradation alone must not move to the backup")
	}
}

func TestNoFlappingUnderNoisyInput(t *testing.T) {
	s := newSim(t, testConfig(t, nil))
	changes, last := 0, -1
	for i := 0; i < 200; i++ {
		ali2 := good(30)
		switch i % 4 {
		case 1:
			ali2 = lossy(30+float64(i%7)*10, 4)
		case 3:
			ali2 = good(30 + float64(i%5)*15)
		}
		d := s.pass(good(30+float64(i%3)*5), ali2, good(60))
		if _, b := weights(d); b != last {
			changes++
			last = b
		}
		if d.Upstream != UpstreamMain {
			t.Fatalf("pass %d: left the main path on noise", i)
		}
	}
	if changes > 8 {
		t.Fatalf("%d weight changes in 200 noisy passes", changes)
	}
}

func TestAllRelaysDownTakesTheBackup(t *testing.T) {
	s := newSim(t, testConfig(t, nil))
	s.passes(4, good(30), good(30), good(60))
	s.passes(3, down(), down(), good(60))
	if s.d.Upstream != UpstreamMain {
		t.Fatal("left the main path before DownAfter")
	}
	s.passes(2, down(), down(), good(60))
	d := s.d
	if d.Upstream != UpstreamBackup || d.Designated != UpstreamBackup {
		t.Fatalf("not on the backup: %+v", d)
	}
	if a, b := weights(d); a != 0 || b != 0 {
		t.Fatalf("relay weights on the backup: %d/%d", a, b)
	}
	if !d.Relays[0].Drain || !d.Relays[1].Drain {
		t.Fatal("evicted relays should be drained")
	}
	if s.st.Alert != AlertOnBackup {
		t.Fatalf("alert %q", s.st.Alert)
	}
	// Return: a relay good for ReturnAfter (120 s, after its loss average
	// has decayed) and the dwell → main again; never earlier.
	n := 0
	for ; n < 80 && s.d.Upstream == UpstreamBackup; n++ {
		s.pass(good(30), down(), good(60))
	}
	if s.d.Upstream != UpstreamMain {
		t.Fatalf("did not return to the main path: %+v", s.st)
	}
	if n*PassInterval < 120 || n*PassInterval > 240 {
		t.Fatalf("returned after %d s", n*PassInterval)
	}
	if s.d.Designated != "ali" || s.d.BackupDrain {
		t.Fatalf("after return: %+v", s.d)
	}
}

func TestAllPoorBackupBetterTakesTheBackup(t *testing.T) {
	s := newSim(t, testConfig(t, nil))
	s.passes(4, good(30), good(30), good(60))
	for i := 0; i < 20 && s.d.Upstream == UpstreamMain; i++ {
		s.pass(lossy(30, 3), lossy(40, 3), good(60))
	}
	if s.d.Upstream != UpstreamBackup {
		t.Fatalf("all relays poor and the backup good: still %s (%+v)", s.d.Upstream, s.st)
	}
}

func TestAllPoorBackupNotBetterStaysAndAlerts(t *testing.T) {
	s := newSim(t, testConfig(t, nil))
	s.passes(4, good(30), good(30), good(60))
	for i := 0; i < 30; i++ {
		s.pass(lossy(30, 3), lossy(80, 3), lossy(60, 2))
		if s.d.Upstream != UpstreamMain {
			t.Fatalf("pass %d: moved to a backup that is not better", i)
		}
	}
	if s.st.Alert != AlertBackupNotBetter {
		t.Fatalf("alert %q", s.st.Alert)
	}
	a, b := weights(s.d)
	if a != 1000 || b != 0 {
		t.Fatalf("the comparatively better relay should carry: %d/%d", a, b)
	}
	if s.d.Relays[0].Drain || !s.d.Relays[1].Drain {
		t.Fatalf("drain flags %+v", s.d.Relays)
	}
	if !strings.Contains(FormatStatus(s.c, s.st, s.now, "go"), "state degraded\n") {
		t.Fatal("status should say degraded")
	}
}

func TestNothingReachableFailsClosed(t *testing.T) {
	s := newSim(t, testConfig(t, nil))
	s.passes(4, good(30), good(30), good(60))
	before := s.d
	d := s.passes(10, down(), down(), down())
	if d.Upstream != UpstreamMain || d.Designated != before.Designated {
		t.Fatalf("nothing answers: moved anyway: %+v", d)
	}
	if a, b := weights(d); a+b != Buckets {
		t.Fatalf("weights %d/%d", a, b)
	}
	for _, r := range d.Relays {
		if r.Leg != "m02" && r.Leg != "m02w" && r.Leg != "m03" {
			t.Fatalf("leg %q is not a compiled tunnel", r.Leg)
		}
	}
	if s.st.Alert != AlertNothingReachable {
		t.Fatalf("alert %q", s.st.Alert)
	}
	if !strings.Contains(FormatStatus(s.c, s.st, s.now, "go"), "state down\n") {
		t.Fatal("status should say down")
	}
}

func TestPingsFineNoThroughputIsDetected(t *testing.T) {
	s := newSim(t, testConfig(t, func(p *model.PathQuality) { p.ProbeMinIntervalSec = 300 }))
	s.passes(4, good(30), good(30), good(60))
	// ali2 carries traffic and its RTT triples under load (30 → 120 ms):
	// suspicious, so a probe is requested.
	busy := func(rtt float64) path {
		p := good(rtt)
		p.rxBps, p.tcpOut, p.tcpIn, p.newConns = 200*1024, 400, 380, 10
		return p
	}
	s.pass(busy(30), busy(120), good(60))
	if !s.relay("ali2").ProbeWanted {
		t.Fatalf("no probe requested: %+v", s.relay("ali2").PathState)
	}
	if s.relay("ali").ProbeWanted {
		t.Fatal("the healthy relay must not be probed")
	}
	// The probe: 437 sent, 60 delivered in 1.1 s → far below the floor.
	p := busy(120)
	p.probe = &ProbeResult{Sent: 437, Recv: 60, PacketBytes: 1200, ElapsedMS: 1100}
	s.pass(busy(30), p, good(60))
	if g := s.relay("ali2").Grade; g != GradePoor || s.relay("ali2").Why != ReasonNoThroughput {
		t.Fatalf("grade %s (%s) after a failed probe", g, s.relay("ali2").Why)
	}
	if s.relay("ali2").ProbeBytesToday == 0 {
		t.Fatal("probe cost not accounted")
	}
	s.passes(7, busy(30), busy(120), good(60))
	if r := s.relay("ali2"); r.Status != StatusEvicted || r.Reason != ReasonNoThroughput {
		t.Fatalf("ali2 %s/%s", r.Status, r.Reason)
	}
	// Small pings are fine again, but re-admission waits for a passing probe.
	// The failed probe counts until the next probe is allowed (300 s),
	// then RecoverAfter (120 s) of good passes: a probe is requested.
	s.passes(80, good(30), good(30), good(60))
	if r := s.relay("ali2"); r.Status != StatusEvicted || !r.ProbeWanted {
		t.Fatalf("re-admitted without a passing probe: %+v", r)
	}
	ok := good(30)
	ok.probe = &ProbeResult{Sent: 437, Recv: 437, PacketBytes: 1200, ElapsedMS: 1000}
	s.pass(good(30), ok, good(60))
	s.pass(good(30), good(30), good(60))
	if r := s.relay("ali2"); r.Status != StatusRecovering {
		t.Fatalf("after a passing probe: %s", r.Status)
	}
}

func TestNoDeliveryEvicts(t *testing.T) {
	s := newSim(t, testConfig(t, nil))
	s.passes(4, good(30), good(30), good(60))
	black := good(30)
	black.tcpOut, black.newConns = 120, 8
	for i := 0; i < 10; i++ {
		s.pass(good(30), black, good(60))
	}
	if r := s.relay("ali2"); r.Status != StatusEvicted || r.Reason != ReasonNoDelivery {
		t.Fatalf("ali2 %s/%s", r.Status, r.Reason)
	}
	// One-way UDP is not counted (TCP only): an upload with ACKs is fine.
	s2 := newSim(t, testConfig(t, nil))
	up := good(30)
	up.tcpOut, up.tcpIn = 400, 200
	s2.passes(20, good(30), up, good(60))
	if st := s2.relay("ali2").Status; st != StatusActive {
		t.Fatalf("upload with ACKs: %s", st)
	}
}

func TestProbeBudgetAndSwitch(t *testing.T) {
	c := testConfig(t, func(p *model.PathQuality) { p.ProbeOff = true })
	s := newSim(t, c)
	busy := good(120)
	busy.rxBps = 200 * 1024
	s.passes(4, good(30), good(30), good(60))
	s.passes(3, good(30), busy, good(60))
	if s.relay("ali2").ProbeWanted {
		t.Fatal("probes are off")
	}
	c = testConfig(t, func(p *model.PathQuality) { p.ProbeDailyBudgetMB = 1 })
	s = newSim(t, c)
	s.st = NewState(c, s.now)
	s.st.Relays["ali2"].ProbeDay = "2023-11-14"
	s.st.Relays["ali2"].ProbeBytesToday = 1024 * 1024
	s.passes(4, good(30), good(30), good(60))
	s.passes(3, good(30), busy, good(60))
	if s.relay("ali2").ProbeWanted {
		t.Fatal("budget spent: no probe")
	}
}

func TestLegFailoverWithHysteresis(t *testing.T) {
	s := newSim(t, testConfig(t, nil))
	udpDown := good(30)
	udpDown.udpLegDown = true
	s.passes(2, udpDown, good(30), good(60))
	if s.relay("ali").Leg != "m02" {
		t.Fatal("left the UDP leg before legFailsNeed")
	}
	s.pass(udpDown, good(30), good(60))
	if s.d.Relays[0].Leg != "m02w" {
		t.Fatalf("leg %s, want the WSS leg", s.d.Relays[0].Leg)
	}
	if s.relay("ali").Status != StatusActive {
		t.Fatal("a relay whose WSS leg answers is not down")
	}
	s.passes(4, good(30), good(30), good(60))
	if s.d.Relays[0].Leg != "m02w" {
		t.Fatal("returned to UDP before legRecoversNeed")
	}
	s.pass(good(30), good(30), good(60))
	if s.d.Relays[0].Leg != "m02" {
		t.Fatalf("leg %s, want back on UDP", s.d.Relays[0].Leg)
	}
}

func TestManualOverride(t *testing.T) {
	c := testConfig(t, func(p *model.PathQuality) {
		p.Overrides = []model.RelayOverride{{Relay: "ali2", Disabled: true}}
	})
	s := newSim(t, c)
	d := s.passes(3, good(30), good(30), good(60))
	if a, b := weights(d); a != 1000 || b != 0 || s.relay("ali2").Status != StatusDisabled || d.Relays[1].Drain {
		t.Fatalf("disabled: %d/%d %s drain=%v", a, b, s.relay("ali2").Status, d.Relays[1].Drain)
	}
	c = testConfig(t, func(p *model.PathQuality) {
		p.Overrides = []model.RelayOverride{{Relay: "ali", Weight: 30}}
	})
	s = newSim(t, c)
	d = s.passes(3, good(30), good(30), good(60))
	if a, b := weights(d); a != 231 || b != 769 {
		t.Fatalf("pinned 30 vs auto 100: %d/%d", a, b)
	}
}

func TestNormalize(t *testing.T) {
	for _, c := range []struct {
		in, want []int
	}{
		{[]int{100, 100}, []int{500, 500}},
		{[]int{100, 100, 100}, []int{334, 333, 333}},
		{[]int{100, 0}, []int{1000, 0}},
		{[]int{0, 0}, []int{0, 0}},
		{[]int{25, 100}, []int{200, 800}},
	} {
		got := Normalize(c.in)
		for i := range got {
			if got[i] != c.want[i] {
				t.Errorf("Normalize(%v) = %v, want %v", c.in, got, c.want)
				break
			}
		}
	}
}

func TestConfigChangeResetsState(t *testing.T) {
	c := testConfig(t, nil)
	s := newSim(t, c)
	s.passes(10, down(), good(30), good(60))
	if s.relay("ali").Status != StatusEvicted {
		t.Fatal("setup")
	}
	c2 := testConfig(t, func(p *model.PathQuality) { p.EvictAfterSec = 60 })
	s.c = c2
	s.pass(good(30), good(30), good(60))
	if s.relay("ali").Status != StatusActive || s.st.ConfigHash != c2.Hash() {
		t.Fatalf("state not reset for a new config: %+v", s.relay("ali"))
	}
}

func TestParseConfigStrict(t *testing.T) {
	c := testConfig(t, nil)
	b, _ := json.Marshal(c)
	for _, bad := range []string{
		strings.Replace(string(b), `"version":1`, `"version":2`, 1),
		strings.Replace(string(b), `"iface":"m03"`, `"iface":"m03; rm -rf /"`, 1),
		strings.Replace(string(b), `"probe_source":"10.66.200.2"`, `"probe_source":"x"`, 1),
		strings.Replace(string(b), `"table":112`, `"table":12`, 1),
		strings.Replace(string(b), `"value":131072`, `"value":65536`, 1),
		strings.Replace(string(b), `{"version"`, `{"extra":1,"version"`, 1),
	} {
		if _, err := ParseConfig([]byte(bad)); err == nil {
			t.Errorf("accepted: %s", bad)
		}
	}
}

func TestParseDecisionRefuses(t *testing.T) {
	c := testConfig(t, nil)
	ok := "meridian-pathq 1\nupstream main\ndesignated ali\nrelay ali m02 500 0\nrelay ali2 m03 500 0\nbackup 0\nend\n"
	if _, err := ParseDecision(c, ok); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{
		strings.Replace(ok, "m03 500", "eth0 500", 1),
		strings.Replace(ok, "m03 500", "m03 400", 1),
		strings.Replace(ok, "designated ali", "designated hk5", 1),
		strings.Replace(ok, "upstream main", "upstream backup", 1),
		strings.Replace(ok, "relay ali2", "relay ali3", 1),
		strings.Replace(ok, "backup 0", "backup 2", 1),
	} {
		if _, err := ParseDecision(c, bad); err == nil {
			t.Errorf("accepted:\n%s", bad)
		}
	}
	bk := "meridian-pathq 1\nupstream backup\ndesignated backup\nrelay ali m02 0 1\nrelay ali2 m03 0 1\nbackup 0\nend\n"
	if _, err := ParseDecision(c, bk); err != nil {
		t.Fatal(err)
	}
}

func TestParsePingAndCounters(t *testing.T) {
	out := "PING 10.66.1.2 (10.66.1.2) from 10.66.200.2 m02: 56(84) bytes of data.\n\n--- 10.66.1.2 ping statistics ---\n5 packets transmitted, 4 received, 20% packet loss, time 803ms\nrtt min/avg/max/mdev = 31.204/35.880/41.002/3.900 ms\n"
	s, r, rtt := ParsePing(out)
	if s != 5 || r != 4 || rtt != 35880 {
		t.Fatalf("%d %d %d", s, r, rtt)
	}
	if s, r, _ := ParsePing("5 packets transmitted, 0 received, 100% packet loss, time 4ms\n"); s != 5 || r != 0 {
		t.Fatal("all lost")
	}
	js := `{"nftables": [{"metainfo": {"version": "1.1.3"}}, {"counter": {"family": "inet", "name": "share_r1_new", "table": "meridian", "handle": 3, "packets": 12, "bytes": 720}}, {"counter": {"family": "inet", "name": "x", "table": "other", "handle": 3, "packets": 9, "bytes": 1}}]}`
	m := ParseNFTCounters(js)
	if m["share_r1_new"] != 12 || len(m) != 1 {
		t.Fatalf("%v", m)
	}
}

func TestProbeCostEstimate(t *testing.T) {
	d := model.PathQualityDefaults()
	got := ProbeCostEstimate(d)
	// 436 packets of 1200 bytes, each way, with ~88 bytes of headers.
	if got < 1_000_000 || got > 1_200_000 {
		t.Fatalf("estimate %d", got)
	}
}
