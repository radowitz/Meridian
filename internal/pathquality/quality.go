package pathquality

import (
	"math"
	"sort"
	"time"

	"github.com/radowitz/meridian/internal/model"
)

// Grades of one path on one pass, worst last.
const (
	GradeGood = "good"
	GradeMild = "mild"
	GradePoor = "poor"
	GradeDown = "down"
	// GradeNone: never measured yet.
	GradeNone = "none"
)

// Relay statuses.
const (
	// StatusActive: in the sharing set at its quality weight.
	StatusActive = "active"
	// StatusReduced: mildly degraded for ReduceAfterSec: weight capped.
	StatusReduced = "reduced"
	// StatusStandby: mildly degraded for StandbyAfterSec while a better
	// relay is in the set: no new connections, existing ones stay.
	StatusStandby = "standby"
	// StatusEvicted: below the floor (or silent) for long enough: no new
	// connections; existing ones are cleared unless configured otherwise.
	StatusEvicted = "evicted"
	// StatusRecovering: good again for RecoverAfterSec: re-admitted at a
	// fraction of its weight that doubles every RampStepSec.
	StatusRecovering = "recovering"
	// StatusDisabled: manual override.
	StatusDisabled = "disabled"
)

// Carrying-path upstream values.
const (
	UpstreamMain   = "main"
	UpstreamBackup = "backup"
)

// Alerts.
const (
	AlertNone             = ""
	AlertAllPoor          = "all_relays_poor" // no relay usable, no backup (or backup not configured)
	AlertBackupNotBetter  = "all_relays_poor_backup_not_better"
	AlertBackupUnusable   = "all_relays_poor_backup_unusable"
	AlertNothingReachable = "nothing_reachable"
	AlertOnBackup         = "on_backup"
)

// Reasons (status changes; Reason of a relay).
const (
	ReasonDown         = "down"
	ReasonPoorLoss     = "poor_loss"
	ReasonPoorRTT      = "poor_rtt"
	ReasonNoThroughput = "no_throughput"
	ReasonNoDelivery   = "no_delivery"
	ReasonMildLoss     = "mild_loss"
	ReasonMildRTT      = "mild_rtt"
	ReasonInflation    = "rtt_inflation"
	ReasonRelapse      = "relapse"
	ReasonRecovered    = "recovered"
	ReasonManual       = "manual"
)

// Passive-signal constants (documented, not settings).
const (
	// ewmaAlpha smooths loss and RTT per pass (5 s): a step change shows
	// about 2/3 within three passes.
	ewmaAlpha = 0.3
	// minTCPPackets: fewer TCP packets sent into a relay on one pass say
	// nothing about delivery.
	minTCPPackets = 20
	// noDeliveryPasses: passes in a row with TCP sent and (almost) nothing
	// back before the relay counts as poor.
	noDeliveryPasses = 3
	// loadedBps: a relay carrying at least this (rx+tx bytes/s) is loaded:
	// its RTT then reflects behaviour under load.
	loadedBps = 64 * 1024
	// businessBps: below this the relay carries no business traffic worth
	// a throughput probe.
	businessBps = 16 * 1024
	// lowDeliveryPeerBps / lowDeliveryRatio: a relay delivering less than
	// 1/4 of a peer's bytes per unit of weight, while that peer delivers at
	// least this much, is suspicious.
	lowDeliveryPeerBps = 128 * 1024
	lowDeliveryRatio   = 4
	// legFailsNeed / legRecoversNeed: leg (UDP/WSS) hysteresis in passes.
	legFailsNeed    = 3
	legRecoversNeed = 5
	// weightDeadband: relays scoring within 30% of the best get equal
	// weight ("near-equal when quality is similar").
	weightDeadband = 1.3
	// weightDeadbandMS: relays within this many score points (ms) of the
	// best are equal too, so a few milliseconds of jitter on a short path
	// do not shift weights.
	weightDeadbandMS = 10.0
	// weightChurn: raw weights (0–100) are only re-published when one moves
	// by at least this much or the set changes.
	weightChurn = 10
	// rttInflation: under load, an RTT this many times the path's baseline
	// (and at least inflationMinMS above it) is suspicious.
	rttInflation   = 3.0
	inflationMinMS = 50.0
	// gradeHysteresis: a path leaves a grade only below this fraction of
	// the threshold that put it there.
	gradeHysteresis = 0.7
	// scoreAlpha smooths the score the weights are computed from (slower
	// than the grade: weights should not chase noise).
	scoreAlpha = 0.1
	// weightHoldSec: quality-only weight changes are published at most
	// this often (status changes are published at once).
	weightHoldSec = 30
)

// rampLevels are the re-admission fractions (percent of the quality weight).
var rampLevels = []int{25, 50, 100}

// LegSample is one pass on one gateway interface.
type LegSample struct {
	Iface string `json:"iface"`
	Sent  int    `json:"sent"`
	Recv  int    `json:"recv"`
	// RTTus is the average echo round trip of the replies (0: none).
	RTTus int64 `json:"rtt_us"`
	// RxBytes/TxBytes are the interface's cumulative counters.
	RxBytes uint64 `json:"rx_bytes"`
	TxBytes uint64 `json:"tx_bytes"`
	// Handshake is the WireGuard latest handshake (epoch, 0 unknown).
	Handshake int64 `json:"handshake"`
}

// ProbeResult is one throughput probe (a paced burst of large echoes).
type ProbeResult struct {
	Sent        int   `json:"sent"`
	Recv        int   `json:"recv"`
	PacketBytes int   `json:"packet_bytes"`
	ElapsedMS   int64 `json:"elapsed_ms"`
}

// Kbps is the delivered rate of the probe (replies only, one direction).
func (p ProbeResult) Kbps() int {
	if p.ElapsedMS <= 0 {
		return 0
	}
	return int(int64(p.Recv) * int64(p.PacketBytes) * 8 / p.ElapsedMS)
}

// LossPermille of the probe.
func (p ProbeResult) LossPermille() int {
	if p.Sent <= 0 {
		return 1000
	}
	return (p.Sent - p.Recv) * 1000 / p.Sent
}

// Cost is the probe's billed bytes on the relay, both directions, with
// IPv4 + ICMP headers and the WireGuard overhead (about 60 bytes).
func (p ProbeResult) Cost() int64 {
	per := int64(p.PacketBytes + 28 + 60)
	return int64(p.Sent)*per + int64(p.Recv)*per
}

// PathSample is one pass on one path (a relay, or the backup hub).
type PathSample struct {
	Legs []LegSample `json:"legs"`
	// TCPOut/TCPIn: cumulative TCP packets of this relay's connections,
	// original direction (from the LAN) and reply direction; New: new
	// connections assigned (nft counters share_r<i>_*).
	TCPOut uint64 `json:"tcp_out"`
	TCPIn  uint64 `json:"tcp_in"`
	New    uint64 `json:"new"`
	// Probe is set when a throughput probe ran on this pass.
	Probe *ProbeResult `json:"probe,omitempty"`
}

// Measurement is one pass of the gateway's loop.
type Measurement struct {
	Now    int64                 `json:"now"`
	Relays map[string]PathSample `json:"relays"`
	Backup *PathSample           `json:"backup,omitempty"`
}

// PathState is what the controller keeps about one path between passes.
type PathState struct {
	Leg      string `json:"leg"`
	LegFails []int  `json:"leg_fails"`
	LegOKs   []int  `json:"leg_oks"`

	Have     bool    `json:"have"`
	LossEWMA float64 `json:"loss_ewma"` // per mille
	RTTEWMA  float64 `json:"rtt_ewma"`  // ms
	BaseRTT  float64 `json:"base_rtt"`  // ms
	LastRTT  float64 `json:"last_rtt"`  // ms, 0: no reply
	LastLoss int     `json:"last_loss"` // per mille
	// ScoreAvg is the slowly averaged score the weights use.
	ScoreAvg   float64 `json:"score_avg"`
	MeasuredAt int64   `json:"measured_at"`

	Grade     string `json:"grade"`
	GoodSince int64  `json:"good_since"`
	MildSince int64  `json:"mild_since"`
	PoorSince int64  `json:"poor_since"`
	DownSince int64  `json:"down_since"`
	// Why is the reason for the current grade (mild/poor/down).
	Why string `json:"why"`

	PrevSet    bool   `json:"prev_set"`
	PrevRx     uint64 `json:"prev_rx"`
	PrevTx     uint64 `json:"prev_tx"`
	PrevTCPOut uint64 `json:"prev_tcp_out"`
	PrevTCPIn  uint64 `json:"prev_tcp_in"`
	PrevNew    uint64 `json:"prev_new"`
	RxBytes    uint64 `json:"rx_bytes"`
	TxBytes    uint64 `json:"tx_bytes"`
	RxBps      int64  `json:"rx_bps"`
	TxBps      int64  `json:"tx_bps"`
	NewConns   uint64 `json:"new_conns"`
	Loaded     bool   `json:"loaded"`

	NoDeliveryStreak int    `json:"no_delivery_streak"`
	NoDeliveryAt     int64  `json:"no_delivery_at"`
	Suspicious       string `json:"suspicious"`

	ProbeAt         int64  `json:"probe_at"`
	ProbeOK         bool   `json:"probe_ok"`
	ProbeKbps       int    `json:"probe_kbps"`
	ProbeLoss       int    `json:"probe_loss"`
	ProbeFailedAt   int64  `json:"probe_failed_at"`
	ProbeDay        string `json:"probe_day"`
	ProbeBytesToday int64  `json:"probe_bytes_today"`
	// ProbeWanted: run a throughput probe on the next pass.
	ProbeWanted bool `json:"probe_wanted"`
}

// RelayState is one relay's controller state.
type RelayState struct {
	PathState
	Status      string `json:"status"`
	StatusSince int64  `json:"status_since"`
	Reason      string `json:"reason"`
	RampLevel   int    `json:"ramp_level"`
	RampSince   int64  `json:"ramp_since"`
	Raw         int    `json:"raw"`
	RawStatus   string `json:"raw_status"`
	Weight      int    `json:"weight"`
	Drain       bool   `json:"drain"`
}

// State is persisted between passes (/run/meridian/pathq/state.json).
type State struct {
	Version         int                    `json:"version"`
	ConfigHash      string                 `json:"config_hash"`
	Upstream        string                 `json:"upstream"`
	UpstreamSince   int64                  `json:"upstream_since"`
	LastSwitch      int64                  `json:"last_switch"`
	AllEvictedSince int64                  `json:"all_evicted_since"`
	MainGoodSince   int64                  `json:"main_good_since"`
	Alert           string                 `json:"alert"`
	WeightsAt       int64                  `json:"weights_at"`
	Designated      string                 `json:"designated"`
	Relays          map[string]*RelayState `json:"relays"`
	Backup          *PathState             `json:"backup,omitempty"`
	BackupDrain     bool                   `json:"backup_drain"`
	Passes          int64                  `json:"passes"`
}

// Decision is what the shell applies.
type Decision struct {
	Upstream string
	// Designated is the relay (or "backup") table 102 follows: group DNS
	// of this host and every exit-marked packet without a relay mark.
	Designated string
	Relays     []RelayDecision
	// BackupDrain clears the backup hub's connections.
	BackupDrain bool
}

// RelayDecision is one relay's part of a Decision.
type RelayDecision struct {
	ID     string
	Leg    string
	Weight int
	Drain  bool
}

// NewState is the state an install starts from: every relay active at
// equal weight on its preferred leg, the main path carrying.
func NewState(c Config, now int64) *State {
	st := &State{Version: 1, ConfigHash: c.Hash(), Upstream: UpstreamMain, UpstreamSince: now, Relays: map[string]*RelayState{}}
	w := EqualWeights(len(c.Relays))
	for i, r := range c.Relays {
		st.Relays[r.ID] = &RelayState{
			PathState: newPathState(r.Legs),
			Status:    StatusActive, StatusSince: now, Raw: 100, Weight: w[i],
		}
	}
	if c.Backup != nil {
		ps := newPathState([]Leg{{Iface: c.Backup.Iface, Mode: "wss"}})
		st.Backup = &ps
	}
	st.Designated = c.Relays[0].ID
	return st
}

func newPathState(legs []Leg) PathState {
	return PathState{Leg: legs[0].Iface, LegFails: make([]int, len(legs)), LegOKs: make([]int, len(legs)), Grade: GradeNone}
}

// EqualWeights splits Buckets over n relays (the remainder to the first).
func EqualWeights(n int) []int {
	if n <= 0 {
		return nil
	}
	out := make([]int, n)
	for i := range out {
		out[i] = Buckets / n
	}
	out[0] += Buckets - (Buckets/n)*n
	return out
}

// InitialDecision is what the static install applies (NewState's).
func InitialDecision(c Config) Decision {
	return decisionOf(c, NewState(c, 0))
}

// Step runs one pass. st is updated in place (a nil or foreign state is
// replaced by NewState). It never returns a decision that routes outside
// the compiled interfaces: legs come from the config, weights sum to
// Buckets on the main path (or are all zero on the backup).
func Step(c Config, st *State, m Measurement) (*State, Decision) {
	now := m.Now
	if st == nil || st.ConfigHash != c.Hash() || st.Version != 1 || len(st.Relays) != len(c.Relays) {
		st = NewState(c, now)
	}
	for _, r := range c.Relays {
		if st.Relays[r.ID] == nil {
			st = NewState(c, now)
			break
		}
	}
	if c.Backup != nil && st.Backup == nil {
		st = NewState(c, now)
	}
	st.Passes++
	s := c.Settings
	// 1. Measurements → per-path quality.
	for _, r := range c.Relays {
		rs := st.Relays[r.ID]
		sample, ok := m.Relays[r.ID]
		observe(&rs.PathState, r.Legs, sample, ok, now, s)
	}
	if c.Backup != nil {
		var sample PathSample
		ok := m.Backup != nil
		if ok {
			sample = *m.Backup
		}
		observe(st.Backup, []Leg{{Iface: c.Backup.Iface}}, sample, ok, now, s)
	}
	markLowDelivery(c, st)
	// 2. Relay status machine.
	for _, r := range c.Relays {
		transition(st.Relays[r.ID], r.ID, now, s)
	}
	// 3. Weights and the carrying path.
	weigh(c, st, now)
	carry(c, st, now)
	// 4. Throughput probes for the next pass.
	for _, r := range c.Relays {
		wantProbe(&st.Relays[r.ID].PathState, st.Relays[r.ID], now, s)
	}
	return st, decisionOf(c, st)
}

func decisionOf(c Config, st *State) Decision {
	d := Decision{Upstream: st.Upstream, Designated: st.Designated, BackupDrain: st.BackupDrain}
	for _, r := range c.Relays {
		rs := st.Relays[r.ID]
		w := rs.Weight
		if st.Upstream == UpstreamBackup {
			w = 0
		}
		d.Relays = append(d.Relays, RelayDecision{ID: r.ID, Leg: rs.Leg, Weight: w, Drain: rs.Drain})
	}
	return d
}

// observe folds one pass into a path's state and grades it.
func observe(ps *PathState, legs []Leg, sample PathSample, ok bool, now int64, s model.PathQuality) {
	// Leg choice with hysteresis: the preferred (first) leg unless it has
	// failed legFailsNeed passes; back to it after legRecoversNeed answers.
	answered := func(i int) bool {
		return ok && i < len(sample.Legs) && sample.Legs[i].Recv > 0
	}
	if len(ps.LegFails) != len(legs) {
		ps.LegFails, ps.LegOKs = make([]int, len(legs)), make([]int, len(legs))
	}
	cur := 0
	for i, l := range legs {
		if l.Iface == ps.Leg {
			cur = i
		}
		if answered(i) {
			ps.LegOKs[i]++
			ps.LegFails[i] = 0
		} else {
			ps.LegFails[i]++
			ps.LegOKs[i] = 0
		}
	}
	switch {
	case cur != 0 && ps.LegOKs[0] >= legRecoversNeed:
		cur = 0
	case ps.LegFails[cur] >= legFailsNeed:
		for i := range legs {
			if answered(i) {
				cur = i
				break
			}
		}
	}
	ps.Leg = legs[cur].Iface

	// Counters over all legs (traffic of the path).
	var rx, tx uint64
	if ok {
		for _, l := range sample.Legs {
			rx += l.RxBytes
			tx += l.TxBytes
		}
	}
	interval := int64(PassInterval)
	if ps.MeasuredAt > 0 && now > ps.MeasuredAt {
		interval = now - ps.MeasuredAt
	}
	dOut, dIn := uint64(0), uint64(0)
	if ok {
		if ps.PrevSet {
			ps.RxBps = int64(delta(rx, ps.PrevRx)) / interval
			ps.TxBps = int64(delta(tx, ps.PrevTx)) / interval
			dOut, dIn = delta(sample.TCPOut, ps.PrevTCPOut), delta(sample.TCPIn, ps.PrevTCPIn)
			ps.NewConns += delta(sample.New, ps.PrevNew)
		}
		ps.PrevSet = true
		ps.PrevRx, ps.PrevTx, ps.PrevTCPOut, ps.PrevTCPIn, ps.PrevNew = rx, tx, sample.TCPOut, sample.TCPIn, sample.New
		ps.RxBytes, ps.TxBytes = rx, tx
	}
	ps.Loaded = ps.RxBps+ps.TxBps >= loadedBps
	// Passive delivery: TCP sent into the relay with (almost) nothing back.
	if dOut >= minTCPPackets {
		if dIn*20 < dOut {
			ps.NoDeliveryStreak++
			ps.NoDeliveryAt = now
		} else {
			ps.NoDeliveryStreak = 0
		}
	}

	// Ping burst on the leg in use.
	var ls LegSample
	if ok && cur < len(sample.Legs) {
		ls = sample.Legs[cur]
	}
	down := ls.Sent == 0 || ls.Recv == 0
	loss := 1000
	if ls.Sent > 0 {
		loss = (ls.Sent - ls.Recv) * 1000 / ls.Sent
	}
	ps.LastLoss = loss
	ps.MeasuredAt = now
	if !ps.Have {
		ps.LossEWMA = float64(loss)
	} else {
		ps.LossEWMA += ewmaAlpha * (float64(loss) - ps.LossEWMA)
	}
	if !down {
		rtt := float64(ls.RTTus) / 1000
		ps.LastRTT = rtt
		if !ps.Have || ps.RTTEWMA == 0 {
			ps.RTTEWMA = rtt
		} else {
			ps.RTTEWMA += ewmaAlpha * (rtt - ps.RTTEWMA)
		}
		switch {
		case ps.BaseRTT == 0 || rtt < ps.BaseRTT:
			ps.BaseRTT = rtt
		case !ps.Loaded:
			// The baseline follows a lasting change of the idle RTT slowly.
			ps.BaseRTT += 0.02 * (rtt - ps.BaseRTT)
		}
		inst := rtt + float64(loss)
		if ps.ScoreAvg == 0 {
			ps.ScoreAvg = inst
		} else {
			ps.ScoreAvg += scoreAlpha * (inst - ps.ScoreAvg)
		}
	} else {
		ps.LastRTT = 0
	}
	ps.Have = true

	// Throughput probe result.
	day := time.Unix(now, 0).UTC().Format("2006-01-02")
	if ps.ProbeDay != day {
		ps.ProbeDay, ps.ProbeBytesToday = day, 0
	}
	if ok && sample.Probe != nil {
		p := *sample.Probe
		ps.ProbeWanted = false
		ps.ProbeAt = now
		ps.ProbeKbps, ps.ProbeLoss = p.Kbps(), p.LossPermille()
		ps.ProbeOK = ps.ProbeLoss <= s.ProbeLossPermille && ps.ProbeKbps >= s.ProbeFloorKbps
		ps.ProbeBytesToday += p.Cost()
		if !ps.ProbeOK {
			ps.ProbeFailedAt = now
		}
	}

	// Grade.
	grade, why := GradeGood, ""
	inflated := ps.Loaded && ps.BaseRTT > 0 && ps.LastRTT >= rttInflation*ps.BaseRTT && ps.LastRTT-ps.BaseRTT >= inflationMinMS
	probeFailed := ps.ProbeFailedAt > 0 && ps.ProbeFailedAt == ps.ProbeAt && now-ps.ProbeFailedAt < int64(s.ProbeMinIntervalSec)
	noDelivery := ps.NoDeliveryStreak >= noDeliveryPasses && now-ps.NoDeliveryAt < int64(s.RecoverAfterSec)
	// Leaving a grade needs the value clearly below its threshold
	// (gradeHysteresis), so a path hovering at a threshold does not flip
	// grade, and with it its timers, on every pass.
	prev := gradeRank(ps.Grade)
	lim := func(v int, rank int) float64 {
		if prev >= rank {
			return float64(v) * gradeHysteresis
		}
		return float64(v)
	}
	switch {
	case down:
		grade, why = GradeDown, ReasonDown
	case probeFailed:
		grade, why = GradePoor, ReasonNoThroughput
	case noDelivery:
		grade, why = GradePoor, ReasonNoDelivery
	case ps.LossEWMA >= lim(s.PoorLossPermille, 2):
		grade, why = GradePoor, ReasonPoorLoss
	case ps.RTTEWMA >= lim(s.PoorRTTMS, 2):
		grade, why = GradePoor, ReasonPoorRTT
	case ps.LossEWMA >= lim(s.MildLossPermille, 1):
		grade, why = GradeMild, ReasonMildLoss
	case ps.RTTEWMA >= lim(s.MildRTTMS, 1):
		grade, why = GradeMild, ReasonMildRTT
	case inflated:
		grade, why = GradeMild, ReasonInflation
	}
	ps.Grade, ps.Why = grade, why
	since := func(v *int64, on bool) {
		switch {
		case on && *v == 0:
			*v = now
		case !on:
			*v = 0
		}
	}
	rank := gradeRank(grade)
	since(&ps.GoodSince, rank == 0)
	since(&ps.MildSince, rank >= 1)
	since(&ps.PoorSince, rank >= 2)
	since(&ps.DownSince, rank >= 3)
	ps.Suspicious = ""
	switch {
	case inflated:
		ps.Suspicious = ReasonInflation
	case grade == GradeMild:
		ps.Suspicious = why
	}
}

func gradeRank(g string) int {
	switch g {
	case GradeMild:
		return 1
	case GradePoor:
		return 2
	case GradeDown:
		return 3
	}
	return 0
}

func delta(cur, prev uint64) uint64 {
	if cur < prev {
		// Counter reset (the nft table was reloaded, or the interface was
		// re-created): count from zero.
		return cur
	}
	return cur - prev
}

// markLowDelivery flags a loaded relay that delivers far less per unit of
// weight than a peer: a passive hint (no decision on its own) that may
// trigger a throughput probe.
func markLowDelivery(c Config, st *State) {
	best := 0.0
	for _, r := range c.Relays {
		rs := st.Relays[r.ID]
		if rs.Weight > 0 && rs.RxBps >= lowDeliveryPeerBps {
			if v := float64(rs.RxBps) / float64(rs.Weight); v > best {
				best = v
			}
		}
	}
	if best == 0 {
		return
	}
	for _, r := range c.Relays {
		rs := st.Relays[r.ID]
		if rs.Weight > 0 && rs.NewConns > 0 && rs.Suspicious == "" && float64(rs.RxBps)/float64(rs.Weight)*lowDeliveryRatio < best {
			rs.Suspicious = "low_delivery"
		}
	}
}

// transition moves a relay's status by its grade timers.
func transition(rs *RelayState, id string, now int64, s model.PathQuality) {
	set := func(status, reason string) {
		if rs.Status != status {
			rs.Status, rs.StatusSince = status, now
		}
		rs.Reason = reason
	}
	elapsed := func(since int64, sec int) bool { return since > 0 && now-since >= int64(sec) }
	for _, o := range s.Overrides {
		if o.Relay == id && o.Disabled {
			set(StatusDisabled, ReasonManual)
			return
		}
	}
	if rs.Status == StatusDisabled {
		set(StatusActive, ReasonManual)
	}
	evict := func() bool {
		switch {
		case elapsed(rs.DownSince, s.DownAfterSec):
			set(StatusEvicted, ReasonDown)
		case elapsed(rs.PoorSince, s.EvictAfterSec):
			set(StatusEvicted, rs.Why)
		default:
			return false
		}
		return true
	}
	switch rs.Status {
	case StatusActive, StatusReduced, StatusRecovering:
		if evict() {
			return
		}
		if rs.Status == StatusRecovering && rs.Grade != GradeGood {
			if rs.Grade == GradeMild {
				set(StatusReduced, rs.Why)
			} else {
				set(StatusEvicted, ReasonRelapse)
			}
			return
		}
		switch {
		case elapsed(rs.MildSince, s.StandbyAfterSec):
			set(StatusStandby, rs.Why)
		case elapsed(rs.MildSince, s.ReduceAfterSec):
			set(StatusReduced, rs.Why)
		case rs.Status == StatusReduced && elapsed(rs.GoodSince, s.RecoverAfterSec):
			set(StatusActive, ReasonRecovered)
		case rs.Status == StatusRecovering && now-rs.RampSince >= int64(s.RampStepSec):
			rs.RampLevel++
			rs.RampSince = now
			if rs.RampLevel >= len(rampLevels) {
				set(StatusActive, ReasonRecovered)
			}
		}
	case StatusStandby:
		if evict() {
			return
		}
		if elapsed(rs.GoodSince, s.RecoverAfterSec) {
			set(StatusRecovering, ReasonRecovered)
			rs.RampLevel, rs.RampSince = 1, now
		}
	case StatusEvicted:
		if !elapsed(rs.GoodSince, s.RecoverAfterSec) {
			return
		}
		// Evicted for no throughput: re-admission waits for a passing
		// probe, unless probes are off or the budget is spent.
		if rs.Reason == ReasonNoThroughput && probeAllowed(&rs.PathState, now, s, true) && !(rs.ProbeOK && rs.ProbeAt > rs.StatusSince) {
			rs.ProbeWanted = true
			return
		}
		set(StatusRecovering, ReasonRecovered)
		rs.RampLevel, rs.RampSince = 1, now
	default:
		set(StatusActive, "")
	}
}

func inSet(status string) bool {
	return status == StatusActive || status == StatusReduced || status == StatusRecovering
}

// Score is the fixed quality comparison: averaged RTT in ms plus averaged
// loss in per mille (1% loss weighs like 10 ms), with a large penalty for
// poor and a larger one for down. Lower is better.
func Score(ps PathState) float64 {
	v := ps.RTTEWMA + ps.LossEWMA
	switch ps.Grade {
	case GradePoor:
		v += 10000
	case GradeDown, GradeNone:
		v += 1000000
	}
	return v
}

// weigh sets every relay's raw weight (0–100) and the normalised weights.
func weigh(c Config, st *State, now int64) {
	s := c.Settings
	raw := make([]int, len(c.Relays))
	// Standby is only meaningful while a better relay is in the set.
	betterInSet := false
	for _, r := range c.Relays {
		rs := st.Relays[r.ID]
		if inSet(rs.Status) && rs.Grade == GradeGood {
			betterInSet = true
		}
	}
	best := math.Inf(1)
	for _, r := range c.Relays {
		rs := st.Relays[r.ID]
		if (inSet(rs.Status) || (rs.Status == StatusStandby && !betterInSet)) && rs.Grade != GradeDown {
			best = math.Min(best, weightScore(rs.PathState))
		}
	}
	any := false
	for i, r := range c.Relays {
		rs := st.Relays[r.ID]
		eligible := inSet(rs.Status) || (rs.Status == StatusStandby && !betterInSet)
		if !eligible || rs.Grade == GradeDown {
			continue
		}
		w := qualityWeight(weightScore(rs.PathState), best)
		for _, o := range s.Overrides {
			if o.Relay == r.ID && o.Weight > 0 {
				w = o.Weight
			}
		}
		switch rs.Status {
		case StatusReduced:
			if w > 25 {
				w = 25
			}
		case StatusRecovering:
			lvl := rs.RampLevel
			if lvl < 1 {
				lvl = 1
			}
			if lvl > len(rampLevels) {
				lvl = len(rampLevels)
			}
			w = w * rampLevels[lvl-1] / 100
			if w < 1 {
				w = 1
			}
		}
		raw[i] = w
		any = true
	}
	st.Alert = AlertNone
	if !any {
		// No relay is in the set: the comparatively best one that still
		// answers carries (if the main path is chosen at all; carry()
		// decides about the backup). Nothing answers: keep what was there.
		bi, bs := -1, math.Inf(1)
		for i, r := range c.Relays {
			rs := st.Relays[r.ID]
			if rs.Status == StatusDisabled || rs.Grade == GradeDown || rs.Grade == GradeNone {
				continue
			}
			if v := Score(rs.PathState); v < bs {
				bi, bs = i, v
			}
		}
		if bi < 0 {
			for i, r := range c.Relays {
				raw[i] = st.Relays[r.ID].Raw
			}
			st.Alert = AlertNothingReachable
		} else {
			raw[bi] = 100
			st.Alert = AlertAllPoor
		}
	}
	// Churn: keep the published raw weights unless one moved enough or
	// the set changed.
	structural, quality := false, false
	for i, r := range c.Relays {
		rs := st.Relays[r.ID]
		switch {
		case (rs.Raw == 0) != (raw[i] == 0) || rs.Status != rs.RawStatus:
			structural = true
		case abs(rs.Raw-raw[i]) >= weightChurn:
			quality = true
		}
	}
	if structural || (quality && now-st.WeightsAt >= weightHoldSec) {
		for i, r := range c.Relays {
			rs := st.Relays[r.ID]
			rs.Raw, rs.RawStatus = raw[i], rs.Status
		}
		st.WeightsAt = now
	}
	cur := make([]int, len(c.Relays))
	for i, r := range c.Relays {
		cur[i] = st.Relays[r.ID].Raw
	}
	norm := Normalize(cur)
	for i, r := range c.Relays {
		rs := st.Relays[r.ID]
		rs.Weight = norm[i]
	}
	setDrains(c, st)
	// Table 102 (this host's own marked traffic: group DNS) follows the
	// heaviest relay; ties go to the first.
	bi, bw := -1, 0
	for i, r := range c.Relays {
		if w := st.Relays[r.ID].Weight; w > bw {
			bi, bw = i, w
		}
	}
	if bi >= 0 {
		st.Designated = c.Relays[bi].ID
	}
}

// setDrains: an evicted relay that gets no new connections (weight 0, or
// the backup hub carries) has its existing connections cleared, unless
// the operator keeps them.
func setDrains(c Config, st *State) {
	for _, r := range c.Relays {
		rs := st.Relays[r.ID]
		rs.Drain = rs.Status == StatusEvicted && (rs.Weight == 0 || st.Upstream == UpstreamBackup) && !c.Settings.KeepConnectionsOnEvict
	}
}

// weightScore is the slowly averaged score (rtt + loss) the weights use.
func weightScore(ps PathState) float64 {
	if ps.ScoreAvg > 0 {
		return ps.ScoreAvg
	}
	return ps.RTTEWMA + ps.LossEWMA
}

// qualityWeight: 100 within the deadband of the best score, else falling
// with the score ratio, in steps of 5, never below 10.
func qualityWeight(score, best float64) int {
	if best <= 0 || math.IsInf(best, 1) || score <= best*weightDeadband || score-best <= weightDeadbandMS {
		return 100
	}
	w := int(math.Round(100*best*weightDeadband/score/5)) * 5
	if w < 10 {
		w = 10
	}
	if w > 100 {
		w = 100
	}
	return w
}

// Normalize turns raw weights into integers summing to Buckets (largest
// remainder, ties to the lower index). All zero stays all zero.
func Normalize(raw []int) []int {
	out := make([]int, len(raw))
	total := 0
	for _, w := range raw {
		if w > 0 {
			total += w
		}
	}
	if total == 0 {
		return out
	}
	type rem struct {
		i int
		r int
	}
	var rems []rem
	sum := 0
	for i, w := range raw {
		if w <= 0 {
			continue
		}
		out[i] = w * Buckets / total
		sum += out[i]
		rems = append(rems, rem{i, w * Buckets % total})
	}
	sort.SliceStable(rems, func(a, b int) bool { return rems[a].r > rems[b].r })
	for k := 0; sum < Buckets; k++ {
		out[rems[k%len(rems)].i]++
		sum++
	}
	return out
}

// carry decides the carrying hub (main path or backup hub).
func carry(c Config, st *State, now int64) {
	s := c.Settings
	elapsed := func(since int64, sec int) bool { return since > 0 && now-since >= int64(sec) }
	dwellOK := st.LastSwitch == 0 || now-st.LastSwitch >= int64(s.MinDwellSec)
	nIn, reachable, good := 0, 0, false
	bestMain := math.Inf(1)
	for _, r := range c.Relays {
		rs := st.Relays[r.ID]
		if inSet(rs.Status) {
			nIn++
		}
		if rs.Status == StatusDisabled {
			continue
		}
		if rs.Grade != GradeDown && rs.Grade != GradeNone {
			reachable++
			bestMain = math.Min(bestMain, Score(rs.PathState))
		}
		if rs.Grade == GradeGood {
			good = true
		}
	}
	if good {
		if st.MainGoodSince == 0 {
			st.MainGoodSince = now
		}
	} else {
		st.MainGoodSince = 0
	}
	if nIn == 0 {
		if st.AllEvictedSince == 0 {
			st.AllEvictedSince = now
		}
	} else {
		st.AllEvictedSince = 0
	}
	switchTo := func(up string) {
		st.Upstream, st.UpstreamSince, st.LastSwitch = up, now, now
	}
	st.BackupDrain = false
	if c.Backup == nil {
		return
	}
	b := st.Backup
	// The backup is usable while it answers; whether to use it is the fixed
	// score comparison (a poor backup is only taken over poor relays when it
	// is better by the switching advantage, which in practice it is not).
	backupUsable := b.Grade != GradeDown && b.Grade != GradeNone
	backupScore := Score(*b)
	better := func(x, y float64) bool { // x better than y by the advantage
		return x*float64(100+s.SwitchAdvantagePct) <= y*100
	}
	switch st.Upstream {
	case UpstreamMain:
		if nIn > 0 {
			// A relay is in the set. Connections still on the backup hub
			// from an earlier takeover are cleared once it stops answering.
			st.BackupDrain = elapsed(b.DownSince, s.DownAfterSec) && !s.KeepConnectionsOnEvict
			return
		}
		mainDown := reachable == 0
		if !mainDown && !elapsed(st.AllEvictedSince, s.BackupAfterSec) {
			return
		}
		switch {
		case !backupUsable && mainDown:
			st.Alert = AlertNothingReachable
		case !backupUsable:
			st.Alert = AlertBackupUnusable
		case mainDown || better(backupScore, bestMain):
			if mainDown || dwellOK {
				switchTo(UpstreamBackup)
				st.Alert = AlertOnBackup
			}
		default:
			st.Alert = AlertBackupNotBetter
		}
	case UpstreamBackup:
		st.Alert = AlertOnBackup
		backupDown := elapsed(b.DownSince, s.DownAfterSec)
		switch {
		case elapsed(st.MainGoodSince, s.ReturnAfterSec) && dwellOK:
			switchTo(UpstreamMain)
			st.Alert = AlertNone
		case reachable > 0 && (backupDown || (b.Grade == GradePoor && better(bestMain, backupScore) && dwellOK)):
			switchTo(UpstreamMain)
			st.Alert = AlertNone
		case reachable == 0 && b.Grade == GradeDown:
			st.Alert = AlertNothingReachable
		}
		if st.Upstream == UpstreamMain {
			// Back on the main path: if no relay is in the set yet, the
			// comparatively best reachable one carries (weigh ran before).
			weigh(c, st, now)
		}
	}
	if st.Upstream == UpstreamBackup {
		st.Designated = UpstreamBackup
	}
	setDrains(c, st)
}

// probeAllowed: probes on, the interval since the last one passed and the
// day's budget has room for one more.
func probeAllowed(ps *PathState, now int64, s model.PathQuality, _ bool) bool {
	if s.ProbeOff {
		return false
	}
	if ps.ProbeAt > 0 && now-ps.ProbeAt < int64(s.ProbeMinIntervalSec) {
		return false
	}
	return ps.ProbeBytesToday+ProbeCostEstimate(s) <= int64(s.ProbeDailyBudgetMB)*1024*1024
}

// ProbeCostEstimate is the billed bytes of one probe (both directions,
// headers and WireGuard overhead), an estimate shown by the panel.
func ProbeCostEstimate(s model.PathQuality) int64 {
	n := int64(probePackets(s))
	return 2 * n * int64(probePacketBytes+28+60)
}

// probePacketBytes is the ICMP payload of a probe packet.
const probePacketBytes = 1200

func probePackets(s model.PathQuality) int {
	n := s.ProbeBytes / probePacketBytes
	if n < 10 {
		n = 10
	}
	return n
}

// wantProbe asks for a throughput probe on the next pass: business
// traffic on the relay and a suspicious passive signal (mild loss or RTT,
// RTT inflation under load, low delivery against a peer).
func wantProbe(ps *PathState, rs *RelayState, now int64, s model.PathQuality) {
	if ps.ProbeWanted {
		return
	}
	if rs.Weight == 0 || ps.RxBps+ps.TxBps < businessBps {
		return
	}
	if ps.Suspicious == "" {
		return
	}
	if probeAllowed(ps, now, s, false) {
		ps.ProbeWanted = true
	}
}

func abs(v int) int {
	if v < 0 {
		return -v
	}
	return v
}
