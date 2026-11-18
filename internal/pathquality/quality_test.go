package pathquality

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/radowitz/meridian/internal/model"
)

// testConfig: relay "access" with a UDP and a WSS leg, relay "access2" with one
// leg, and the backup hub "hkb"; default settings.
func testConfig(t *testing.T, mut func(*model.PathQuality)) Config {
	t.Helper()
	s := model.PathQualityDefaults()
	if mut != nil {
		mut(&s)
	}
	c := Config{
		Version: ConfigVersion, Interval: PassInterval, ProbeSource: "10.66.200.2", PrimaryHub: "ix",
		Relays: []RelayConfig{
			{ID: "access", Index: 1, Legs: []Leg{{Iface: "m02", Mode: "udp"}, {Iface: "m02w", Mode: "wss"}}, Probe: "10.66.1.2", Value: RelayMark(1), Table: 111},
			{ID: "access2", Index: 2, Legs: []Leg{{Iface: "m03", Mode: "udp"}}, Probe: "10.66.2.2", Value: RelayMark(2), Table: 112},
		},
		Backup:   &BackupConfig{Hub: "hkb", Iface: "m04", Probe: "10.66.5.2", Value: BackupMark, Table: 109},
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
	// qos is the verdict file this pass reads (nil: none).
	qos map[string]QoSEntry
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
func (s *sim) pass(access, access2, bk path) Decision {
	s.now += PassInterval
	m := Measurement{Now: s.now, Relays: map[string]PathSample{
		"access":  s.sample("access", s.c.Relays[0].Legs, access),
		"access2": s.sample("access2", s.c.Relays[1].Legs, access2),
	}}
	b := s.sample("hkb", []Leg{{Iface: "m04"}}, bk)
	m.Backup = &b
	m.QoS = s.qos
	s.st, s.d = Step(s.c, s.st, m)
	if _, err := ParseDecision(s.c, FormatDecision(s.d)); err != nil {
		s.t.Fatalf("pass at +%d: decision refused: %v\n%s", s.now-1_700_000_000, err, FormatDecision(s.d))
	}
	return s.d
}

func (s *sim) passes(n int, access, access2, bk path) Decision {
	for i := 0; i < n; i++ {
		s.pass(access, access2, bk)
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
	if d.Upstream != UpstreamMain || d.Designated != "access" {
		t.Fatalf("decision %+v", d)
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
		access2 := good(30)
		switch i % 4 {
		case 1:
			access2 = lossy(30+float64(i%7)*10, 4)
		case 3:
			access2 = good(30 + float64(i%5)*15)
		}
		d := s.pass(good(30+float64(i%3)*5), access2, good(60))
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
	// Return: a relay answering for 3 passes and min_dwell_sec (120 s)
	// since the switch → main again; never earlier.
	n := 0
	for ; n < 80 && s.d.Upstream == UpstreamBackup; n++ {
		s.pass(good(30), down(), good(60))
	}
	if s.d.Upstream != UpstreamMain {
		t.Fatalf("did not return to the main path: %+v", s.st)
	}
	if since := s.now - s.st.UpstreamSince; n*PassInterval < 110 || n*PassInterval > 130 || s.st.SwitchReason != SwitchRelayReachable {
		t.Fatalf("returned after %d s (%d), reason %q", n*PassInterval, since, s.st.SwitchReason)
	}
	if s.d.Designated != "access" || s.d.BackupDrain {
		t.Fatalf("after return: %+v", s.d)
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

func TestProbeBudgetAndSwitch(t *testing.T) {
	c := testConfig(t, func(p *model.PathQuality) { p.ProbeOff = true })
	s := newSim(t, c)
	busy := good(120)
	busy.rxBps = 200 * 1024
	s.passes(4, good(30), good(30), good(60))
	s.passes(3, good(30), busy, good(60))
	if s.relay("access2").ProbeWanted {
		t.Fatal("probes are off")
	}
	c = testConfig(t, func(p *model.PathQuality) { p.ProbeDailyBudgetMB = 1 })
	s = newSim(t, c)
	s.st = NewState(c, s.now)
	s.st.Relays["access2"].ProbeDay = "2023-11-14"
	s.st.Relays["access2"].ProbeBytesToday = 1024 * 1024
	s.passes(4, good(30), good(30), good(60))
	s.passes(3, good(30), busy, good(60))
	if s.relay("access2").ProbeWanted {
		t.Fatal("budget spent: no probe")
	}
}

func TestLegFailoverWithHysteresis(t *testing.T) {
	s := newSim(t, testConfig(t, nil))
	udpDown := good(30)
	udpDown.udpLegDown = true
	s.passes(2, udpDown, good(30), good(60))
	if s.relay("access").Leg != "m02" {
		t.Fatal("left the UDP leg before legFailsNeed")
	}
	s.pass(udpDown, good(30), good(60))
	if s.d.Relays[0].Leg != "m02w" {
		t.Fatalf("leg %s, want the WSS leg", s.d.Relays[0].Leg)
	}
	if s.relay("access").Status != StatusActive {
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
		p.Overrides = []model.RelayOverride{{Relay: "access2", Disabled: true}}
	})
	s := newSim(t, c)
	d := s.passes(3, good(30), good(30), good(60))
	if a, b := weights(d); a != 1000 || b != 0 || s.relay("access2").Status != StatusDisabled || d.Relays[1].Drain {
		t.Fatalf("disabled: %d/%d %s drain=%v", a, b, s.relay("access2").Status, d.Relays[1].Drain)
	}
	c = testConfig(t, func(p *model.PathQuality) {
		p.Overrides = []model.RelayOverride{{Relay: "access", Weight: 30}}
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
	if s.relay("access").Status != StatusEvicted {
		t.Fatal("setup")
	}
	c2 := testConfig(t, func(p *model.PathQuality) { p.EvictAfterSec = 60 })
	s.c = c2
	s.pass(good(30), good(30), good(60))
	if s.relay("access").Status != StatusActive || s.st.ConfigHash != c2.Hash() {
		t.Fatalf("state not reset for a new config: %+v", s.relay("access"))
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
	ok := "meridian-pathq 1\nupstream main\ndesignated access\nrelay access m02 500 0\nrelay access2 m03 500 0\nbackup 0\nend\n"
	if _, err := ParseDecision(c, ok); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{
		strings.Replace(ok, "m03 500", "eth0 500", 1),
		strings.Replace(ok, "m03 500", "m03 400", 1),
		strings.Replace(ok, "designated access", "designated hkb", 1),
		strings.Replace(ok, "upstream main", "upstream backup", 1),
		strings.Replace(ok, "relay access2", "relay access3", 1),
		strings.Replace(ok, "backup 0", "backup 2", 1),
	} {
		if _, err := ParseDecision(c, bad); err == nil {
			t.Errorf("accepted:\n%s", bad)
		}
	}
	bk := "meridian-pathq 1\nupstream backup\ndesignated backup\nrelay access m02 0 1\nrelay access2 m03 0 1\nbackup 0\nend\n"
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

func TestOldStateAllEvictedRetainsAndReturnsFromScoreBackup(t *testing.T) {
	// A state persisted by the earlier policy: every relay evicted for
	// quality, on the main path, no all_down_since. The next pass retains.
	c := testConfig(t, nil)
	s := newSim(t, c)
	s.passes(20, lossy(30, 3), lossy(40, 3), good(60))
	raw, _ := json.Marshal(s.st)
	var old map[string]any
	_ = json.Unmarshal(raw, &old)
	delete(old, "all_down_since")
	for _, r := range old["relays"].(map[string]any) {
		r.(map[string]any)["status"], r.(map[string]any)["reason"] = StatusEvicted, ReasonPoorLoss
	}
	raw, _ = json.Marshal(old)
	s.st = nil
	if err := json.Unmarshal(raw, &s.st); err != nil {
		t.Fatal(err)
	}
	s.pass(lossy(30, 3), lossy(40, 3), good(60))
	if s.d.Upstream != UpstreamMain || s.relay("access").Reason != ReasonRetained {
		t.Fatalf("old state: %s %+v", s.d.Upstream, s.relay("access"))
	}
	// An old state already on the backup through a score advantage (no
	// main_reachable_passes field) returns under the reachability rule:
	// relays still poor but answering, 3 passes, dwell long met.
	s.st.Upstream, s.st.Designated, s.st.LastSwitch = UpstreamBackup, UpstreamBackup, s.now-1000
	raw, _ = json.Marshal(s.st)
	old = map[string]any{}
	_ = json.Unmarshal(raw, &old)
	delete(old, "main_reachable_passes")
	delete(old, "switch_reason")
	raw, _ = json.Marshal(old)
	s.st = nil
	if err := json.Unmarshal(raw, &s.st); err != nil {
		t.Fatal(err)
	}
	s.passes(2, lossy(30, 3), lossy(40, 3), good(60))
	if s.d.Upstream != UpstreamBackup || s.st.Alert != AlertOnBackupReturning {
		t.Fatalf("left the backup before 3 reachable passes: %s %s", s.d.Upstream, s.st.Alert)
	}
	s.pass(lossy(30, 3), lossy(40, 3), good(60))
	if s.d.Upstream != UpstreamMain || s.st.SwitchReason != SwitchRelayReachable || s.relay("access").Reason != ReasonRetained {
		t.Fatalf("old score-backup state did not return: %s %q %+v", s.d.Upstream, s.st.SwitchReason, s.relay("access"))
	}
}

// Dwell met, but fewer than 3 consecutive reachable passes (a flapping
// relay) → stays on the backup.
func TestBackupNoReturnBeforeThreeReachablePasses(t *testing.T) {
	s := newSim(t, testConfig(t, nil))
	s.passes(4, good(30), good(30), good(60))
	s.passes(5, down(), down(), good(60))
	s.passes(30, down(), down(), good(60)) // dwell long met
	for i := 0; i < 10; i++ {
		s.passes(2, lossy(30, 2), down(), good(60))
		s.pass(down(), down(), good(60))
		if s.d.Upstream != UpstreamBackup {
			t.Fatalf("returned with only 2 consecutive reachable passes (round %d)", i)
		}
	}
	s.passes(3, lossy(30, 2), down(), good(60))
	if s.d.Upstream != UpstreamMain {
		t.Fatal("did not return after 3 consecutive reachable passes")
	}
}
