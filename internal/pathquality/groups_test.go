package pathquality

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/radowitz/meridian/internal/model"
)

// The backup group: relay "access" (main group, primary hub) and relays
// "bk1", "bk2" (backup group, WG over WSS to the backup hub "hkb"); no
// gateway-direct backup. Synthetic probe results, controlled clock.

func groupConfig(t *testing.T) Config {
	t.Helper()
	c := Config{
		Version: ConfigVersion, Interval: PassInterval, ProbeSource: "10.66.200.2", PrimaryHub: "hub", BackupHub: "hkb",
		Relays: []RelayConfig{
			{ID: "access", Index: 1, Legs: []Leg{{Iface: "m05", Mode: "udp"}, {Iface: "m05w", Mode: "wss"}}, Probe: "10.66.1.2", Value: RelayMark(1), Table: 111},
			{ID: "bk1", Index: 2, Legs: []Leg{{Iface: "m06", Mode: "udp"}, {Iface: "m06w", Mode: "wss"}}, Probe: "10.66.2.2", Value: RelayMark(2), Table: 112, Group: GroupBackup},
			{ID: "bk2", Index: 3, Legs: []Leg{{Iface: "m07", Mode: "udp"}, {Iface: "m07w", Mode: "wss"}}, Probe: "10.66.3.2", Value: RelayMark(3), Table: 113, Group: GroupBackup},
		},
		Settings: model.PathQualityDefaults(),
	}
	b, _ := json.Marshal(c)
	pc, err := ParseConfig(b)
	if err != nil {
		t.Fatal(err)
	}
	return pc
}

type gsim struct {
	*sim
}

func (g gsim) pass(access, bk1, bk2 path) Decision {
	s := g.sim
	s.now += PassInterval
	m := Measurement{Now: s.now, Relays: map[string]PathSample{
		"access": s.sample("access", s.c.Relays[0].Legs, access),
		"bk1":    s.sample("bk1", s.c.Relays[1].Legs, bk1),
		"bk2":    s.sample("bk2", s.c.Relays[2].Legs, bk2),
	}}
	s.st, s.d = Step(s.c, s.st, m)
	if _, err := ParseDecision(s.c, FormatDecision(s.d)); err != nil {
		s.t.Fatalf("+%d: decision refused: %v\n%s", s.now-1_700_000_000, err, FormatDecision(s.d))
	}
	return s.d
}

func (g gsim) passes(n int, access, bk1, bk2 path) Decision {
	for i := 0; i < n; i++ {
		g.pass(access, bk1, bk2)
	}
	return g.d
}

func w3(d Decision) [3]int { return [3]int{d.Relays[0].Weight, d.Relays[1].Weight, d.Relays[2].Weight} }

func TestGroupConfigChecks(t *testing.T) {
	c := groupConfig(t)
	if !c.Grouped() || c.Backup != nil {
		t.Fatal("not grouped")
	}
	if w := InitialWeights(c); w[0] != 1000 || w[1] != 0 || w[2] != 0 {
		t.Fatalf("initial weights %v", w)
	}
	for _, bad := range []func(*Config){
		func(c *Config) { c.BackupHub = "" },
		func(c *Config) { c.Relays[0].Group = GroupBackup },
		func(c *Config) { c.Relays[1].Group = "other" },
		func(c *Config) {
			c.Backup = &BackupConfig{Hub: "hkb", Iface: "m04", Probe: "10.66.5.2", Value: BackupMark, Table: 109}
		},
	} {
		x := c
		x.Relays = append([]RelayConfig(nil), c.Relays...)
		bad(&x)
		b, _ := json.Marshal(x)
		if _, err := ParseConfig(b); err == nil {
			t.Fatalf("accepted %+v", x)
		}
	}
}

func TestGroupMainSharesAlone(t *testing.T) {
	g := gsim{newSim(t, groupConfig(t))}
	d := g.passes(10, good(30), good(40), good(40))
	if d.Upstream != UpstreamMain || w3(d) != [3]int{1000, 0, 0} || d.Designated != "access" {
		t.Fatalf("decision %+v", d)
	}
	// The backup group keeps being measured.
	if !g.relay("bk1").Reachable || g.relay("bk1").Grade != GradeGood {
		t.Fatalf("bk1 not measured: %+v", g.relay("bk1"))
	}
	// One leg failing on the only main relay does not switch.
	d = g.passes(10, path{rttMS: 30, recv: 5, udpLegDown: true}, good(40), good(40))
	if d.Upstream != UpstreamMain {
		t.Fatal("a partial failure switched to the backup group")
	}
}

func TestGroupSwitchShareAndReturn(t *testing.T) {
	g := gsim{newSim(t, groupConfig(t))}
	g.passes(30, good(30), good(40), good(40))
	// Under the existing rule: every main relay, every leg, unreachable
	// (confirmed for backup_after_sec, or evicted).
	var d Decision
	for i := 0; i < 12 && d.Upstream != UpstreamBackup; i++ {
		d = g.pass(down(), good(40), good(40))
	}
	if d.Upstream != UpstreamBackup {
		t.Fatalf("main group wholly down: upstream %s", d.Upstream)
	}
	if w := w3(d); w[0] != 0 || w[1] != 500 || w[2] != 500 {
		t.Fatalf("backup group weights %v", w)
	}
	if g.st.Alert != AlertOnBackup {
		t.Fatalf("alert %q", g.st.Alert)
	}
	if d.Designated != "bk1" {
		t.Fatalf("designated %s", d.Designated)
	}
	out := FormatStatus(g.c, g.st, g.now, "go")
	if !strings.Contains(out, "\nhub hkb\ntier backup\n") || !strings.Contains(out, "\nbackup_group hkb bk1 bk2\n") || !strings.Contains(out, "\niface m06\n") {
		t.Fatalf("record:\n%s", out)
	}
	// Sharing within the backup group: bk2 down → bk1 carries alone.
	d = g.passes(6, down(), good(40), down())
	if d.Upstream != UpstreamBackup || w3(d) != [3]int{0, 1000, 0} {
		t.Fatalf("bk2 down: %+v", d)
	}
	g.passes(10, down(), good(40), good(40))
	// Main answers again: back after 3 reachable passes and 120 s since
	// the switch.
	switched := g.st.LastSwitch
	for i := 0; i < 40; i++ {
		d = g.pass(good(30), good(40), good(40))
		if d.Upstream == UpstreamMain {
			break
		}
	}
	if d.Upstream != UpstreamMain || g.st.SwitchReason != SwitchRelayReachable {
		t.Fatalf("no return: %+v", g.st)
	}
	if g.now-switched < 120 || g.st.MainReachablePasses < ReturnReachablePasses {
		t.Fatalf("returned after %d s, %d passes", g.now-switched, g.st.MainReachablePasses)
	}
	if w := w3(d); w[0] != 1000 || d.Designated != "access" {
		t.Fatalf("back on main: %v %s", w, d.Designated)
	}
}

func TestGroupNoSwitchWhenBackupGroupDown(t *testing.T) {
	g := gsim{newSim(t, groupConfig(t))}
	g.passes(30, good(30), down(), down())
	d := g.passes(10, down(), down(), down())
	if d.Upstream != UpstreamMain || g.st.Alert != AlertNothingReachable {
		t.Fatalf("everything down: %+v alert %s", d, g.st.Alert)
	}
}
