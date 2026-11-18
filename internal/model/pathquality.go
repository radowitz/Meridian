package model

// PathQuality is the gateway's relay-sharing policy (several domestic
// relays carrying the main path at the same time, weighted by measured path
// quality; docs/architecture.md「多中继同时分担」). Every field is optional:
// zero means the default (PathQualityDefaults). It only matters when the
// gateway has two or more relays, or the hub has Mesh legs (loss/RTT,
// switching advantage, return time, dwell and MeshWindowSamples). A topology
// with one relay and no Mesh legs compiles as before. Hosts apply it: the values
// are compiled into /etc/meridian/path-quality.json and installed by the
// install transaction. Relay policy changes need a gateway install; Mesh
// leg policy changes need provisioning to the primary hub.
type PathQuality struct {
	// MeshWindowSamples is the rolling number of five-echo batches per exit leg (default 6).
	MeshWindowSamples int `json:"mesh_window_samples,omitempty"`

	// Mild degradation: loss (per mille, averaged) or RTT (ms, averaged,
	// gateway → relay → primary hub) at or above these values.
	MildLossPermille int `json:"mild_loss_permille,omitempty"`
	MildRTTMS        int `json:"mild_rtt_ms,omitempty"`
	// The usable floor: at or above these the path is "poor" (below the
	// floor). A failed throughput probe or TCP traffic that gets no reply
	// at all also counts as poor.
	PoorLossPermille int `json:"poor_loss_permille,omitempty"`
	PoorRTTMS        int `json:"poor_rtt_ms,omitempty"`

	// ReduceAfterSec: mildly degraded this long → its weight is capped.
	// StandbyAfterSec: mildly degraded this long while a better relay is in
	// the set → it gets no new connections (existing ones stay).
	ReduceAfterSec  int `json:"reduce_after_sec,omitempty"`
	StandbyAfterSec int `json:"standby_after_sec,omitempty"`
	// EvictAfterSec: poor this long → evicted. DownAfterSec: no answer at
	// all this long → evicted.
	EvictAfterSec int `json:"evict_after_sec,omitempty"`
	DownAfterSec  int `json:"down_after_sec,omitempty"`
	// RecoverAfterSec: good this long → re-admitted at a low weight, which
	// then doubles every RampStepSec until it is full again.
	RecoverAfterSec int `json:"recover_after_sec,omitempty"`
	RampStepSec     int `json:"ramp_step_sec,omitempty"`
	// KeepConnectionsOnEvict turns off the default rule that an evicted
	// relay's existing TCP connections are reset (so applications reconnect
	// on a healthy relay) and its other flows are moved.
	KeepConnectionsOnEvict bool `json:"keep_connections_on_evict,omitempty"`

	// BackupAfterSec: every relay evicted this long → the backup hub is
	// considered. ReturnAfterSec: on the backup, a relay good this long →
	// back to the main path. MinDwellSec: least time between two switches
	// of the carrying hub (not applied when leaving a path that answers
	// nothing). SwitchAdvantagePct: the other side must score at least this
	// much better to switch for quality alone.
	BackupAfterSec     int `json:"backup_after_sec,omitempty"`
	ReturnAfterSec     int `json:"return_after_sec,omitempty"`
	MinDwellSec        int `json:"min_dwell_sec,omitempty"`
	SwitchAdvantagePct int `json:"switch_advantage_pct,omitempty"`

	// Throughput probes (billed relay traffic). ProbeOff disables them.
	// A probe is a paced burst of large ICMP echoes inside the tunnel to
	// the primary hub (ProbeBytes each way at ProbeRateKbps), sent only
	// when the relay carries business traffic and its passive signals look
	// suspicious, at most once per ProbeMinIntervalSec per relay and within
	// ProbeDailyBudgetMB per relay and day. Below ProbeFloorKbps delivered,
	// or above ProbeLossPermille lost, the relay has no usable throughput.
	ProbeOff            bool `json:"probe_off,omitempty"`
	ProbeBytes          int  `json:"probe_bytes,omitempty"`
	ProbeRateKbps       int  `json:"probe_rate_kbps,omitempty"`
	ProbeMinIntervalSec int  `json:"probe_min_interval_sec,omitempty"`
	ProbeDailyBudgetMB  int  `json:"probe_daily_budget_mb,omitempty"`
	ProbeFloorKbps      int  `json:"probe_floor_kbps,omitempty"`
	ProbeLossPermille   int  `json:"probe_loss_permille,omitempty"`

	// Download speed tests (the relays' QoS verdict; docs/architecture.md
	// 「多中继同时分担」). Every SpeedTestIntervalSec the gateway downloads
	// SpeedTestMB from a fixed endpoint on each relay, bound to that relay's
	// tunnel address and reached only through that relay's route mark; the
	// tests are staggered so only one runs at a time. A relay whose last two
	// valid tests are both below QoSThrottlePct of its baseline is
	// qos_throttled (the others carry its share); one test at or above
	// QoSRecoverPct brings it back (ramped). The baseline is the 90th
	// percentile of the valid tests of the last QoSBaselineDays (isolated
	// spikes and throttled samples excluded); with too few samples it is
	// NominalMbps (per relay: RelayOverride.NominalMbps). A failed test is
	// "not measured", never a slow sample. RTT and loss no longer reduce or
	// evict a relay: only being unreachable does. SpeedTestOff stops the
	// tests (no relay is then ever throttled). Changing SpeedTestMB also
	// needs the relays provisioned (their endpoint serves a fixed size).
	SpeedTestOff         bool `json:"speed_test_off,omitempty"`
	SpeedTestIntervalSec int  `json:"speed_test_interval_sec,omitempty"`
	SpeedTestMB          int  `json:"speed_test_mb,omitempty"`
	QoSThrottlePct       int  `json:"qos_throttle_pct,omitempty"`
	QoSRecoverPct        int  `json:"qos_recover_pct,omitempty"`
	QoSBaselineDays      int  `json:"qos_baseline_days,omitempty"`
	NominalMbps          int  `json:"nominal_mbps,omitempty"`

	// Overrides are the manual override (off unless listed): a relay can be
	// disabled (no new connections; existing ones stay) or pinned to a
	// fixed weight (1–100; it still leaves the set when it stops
	// answering). Empty: fully automatic.
	Overrides []RelayOverride `json:"overrides,omitempty"`
}

// RelayOverride is one manual override of the automatic weights.
type RelayOverride struct {
	Relay    string `json:"relay"`
	Disabled bool   `json:"disabled,omitempty"`
	Weight   int    `json:"weight,omitempty"`
	// NominalMbps is this relay's nominal bandwidth (the QoS baseline until
	// enough tests exist); 0: PathQuality.NominalMbps.
	NominalMbps int `json:"nominal_mbps,omitempty"`
}

// SpeedTestSizesMB is the whitelist of download sizes a relay serves.
var SpeedTestSizesMB = []int{5, 10, 20, 50}

// PathQualityDefaults are the documented defaults
// (docs/architecture.md「多中继同时分担」).
func PathQualityDefaults() PathQuality {
	return PathQuality{
		MildLossPermille:     30,
		MildRTTMS:            200,
		PoorLossPermille:     150,
		PoorRTTMS:            400,
		ReduceAfterSec:       20,
		StandbyAfterSec:      60,
		EvictAfterSec:        30,
		DownAfterSec:         15,
		RecoverAfterSec:      120,
		RampStepSec:          30,
		BackupAfterSec:       30,
		ReturnAfterSec:       120,
		MinDwellSec:          120,
		SwitchAdvantagePct:   25,
		ProbeBytes:           512 * 1024,
		ProbeRateKbps:        4000,
		ProbeMinIntervalSec:  900,
		ProbeDailyBudgetMB:   64,
		ProbeFloorKbps:       1000,
		ProbeLossPermille:    300,
		SpeedTestIntervalSec: 1800,
		SpeedTestMB:          20,
		QoSThrottlePct:       25,
		QoSRecoverPct:        50,
		QoSBaselineDays:      7,
		NominalMbps:          200,
	}
}

// Effective fills every zero field with its default. Booleans and
// overrides are kept as they are.
func (p *PathQuality) Effective() PathQuality {
	d := PathQualityDefaults()
	if p == nil {
		return d
	}
	out := *p
	fill := func(v *int, def int) {
		if *v == 0 {
			*v = def
		}
	}
	fill(&out.MildLossPermille, d.MildLossPermille)
	fill(&out.MildRTTMS, d.MildRTTMS)
	fill(&out.PoorLossPermille, d.PoorLossPermille)
	fill(&out.PoorRTTMS, d.PoorRTTMS)
	fill(&out.ReduceAfterSec, d.ReduceAfterSec)
	fill(&out.StandbyAfterSec, d.StandbyAfterSec)
	fill(&out.EvictAfterSec, d.EvictAfterSec)
	fill(&out.DownAfterSec, d.DownAfterSec)
	fill(&out.RecoverAfterSec, d.RecoverAfterSec)
	fill(&out.RampStepSec, d.RampStepSec)
	fill(&out.BackupAfterSec, d.BackupAfterSec)
	fill(&out.ReturnAfterSec, d.ReturnAfterSec)
	fill(&out.MinDwellSec, d.MinDwellSec)
	fill(&out.SwitchAdvantagePct, d.SwitchAdvantagePct)
	fill(&out.ProbeBytes, d.ProbeBytes)
	fill(&out.ProbeRateKbps, d.ProbeRateKbps)
	fill(&out.ProbeMinIntervalSec, d.ProbeMinIntervalSec)
	fill(&out.ProbeDailyBudgetMB, d.ProbeDailyBudgetMB)
	fill(&out.ProbeFloorKbps, d.ProbeFloorKbps)
	fill(&out.ProbeLossPermille, d.ProbeLossPermille)
	fill(&out.SpeedTestIntervalSec, d.SpeedTestIntervalSec)
	fill(&out.SpeedTestMB, d.SpeedTestMB)
	fill(&out.QoSThrottlePct, d.QoSThrottlePct)
	fill(&out.QoSRecoverPct, d.QoSRecoverPct)
	fill(&out.QoSBaselineDays, d.QoSBaselineDays)
	fill(&out.NominalMbps, d.NominalMbps)
	out.Overrides = append([]RelayOverride(nil), p.Overrides...)
	return out
}

// SharingRelays lists the relays that carry the main path together: every
// relay node with an enabled, non-standby link from the gateway, sorted by
// ID. Two or more turn on relay sharing (Topology.RelaySharing).
func (t Topology) SharingRelays() []Node {
	gw := ""
	for _, n := range t.Nodes {
		if n.Role == RoleGateway {
			gw = n.ID
			break
		}
	}
	linked := map[string]bool{}
	for _, l := range t.Links {
		if !l.Enabled || l.Standby {
			continue
		}
		switch l.Transport {
		case TransportDirectWG, TransportWGOverWSS, TransportUDPWSSFailover:
		default:
			continue
		}
		if l.From == gw {
			linked[l.To] = true
		}
		if l.To == gw {
			linked[l.From] = true
		}
	}
	var out []Node
	for _, n := range t.Nodes {
		if n.Role == RoleRelay && linked[n.ID] {
			out = append(out, n)
		}
	}
	sortNodes(out)
	return out
}

// RelaySharing: the gateway shares the main path across two or more relays
// (per-connection weighted assignment, quality measurement, automatic
// weights). A topology with one relay compiles exactly as before.
func (t Topology) RelaySharing() bool { return len(t.SharingRelays()) >= 2 }

func sortNodes(ns []Node) {
	for i := 1; i < len(ns); i++ {
		for j := i; j > 0 && ns[j].ID < ns[j-1].ID; j-- {
			ns[j], ns[j-1] = ns[j-1], ns[j]
		}
	}
}
