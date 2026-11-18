package pathquality

import (
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/radowitz/meridian/internal/model"
)

// The relays' QoS verdict (docs/architecture.md「多中继同时分担」): a domestic
// relay's line is checked by downloading a fixed amount from it every
// speed_test_interval_sec (speedtest.go). A relay is qos_throttled after two
// consecutive valid tests below qos_throttle_pct of its baseline, and clear
// again after one test at or above qos_recover_pct. A test that failed is
// "not measured": it neither counts as slow nor breaks a run of slow ones.
//
// The verdict is written atomically to QoSPath (QoS file format below) by
// the speed-test process after every test; "meridian path-step" and the
// shell fallback of meridian-failover.sh both read only that file to decide
// which relays carry: neither infers throttling itself, and throttling never
// takes the backup hub (only every relay being unreachable does).

// QoS verdicts.
const (
	QoSOK        = "ok"
	QoSThrottled = "throttled"
	QoSUnknown   = "unknown" // no valid test yet
	QoSOff       = "off"     // speed tests are off (or not compiled)
)

// Baseline sources.
const (
	BaselineNominal = "nominal"
	BaselineP90     = "p90"
)

// Reasons of a relay throttled / recovered on its QoS verdict.
const (
	ReasonQoSThrottled = "qos_throttled"
	ReasonQoSRecovered = "qos_recovered"
)

// Not-measured reasons of a speed test.
const (
	SpeedFailUnreachable = "unreachable"   // the relay answers no ping on any leg
	SpeedFailPath        = "path_mismatch" // the relay's route mark does not lead to its leg
	SpeedFailConnect     = "connect_failed"
	SpeedFailShort       = "short_read" // closed (or timed out) before enough bytes
	SpeedFailDisabled    = "disabled"   // the relay is disabled by override
	SpeedFailInvalid     = "invalid"    // an implausible result
)

const (
	// baselineMinSamples: fewer valid (not throttled) tests in the window
	// and the baseline is the nominal bandwidth.
	baselineMinSamples = 6
	// spikeFactor: a top value more than this times the next one is an
	// isolated spike and is left out of the baseline (at most spikeDrops).
	spikeFactor = 2
	spikeDrops  = 2
	// maxPlausibleKbps: a result above this (10 Gbit/s) is not a measurement.
	maxPlausibleKbps = 10_000_000
	// MaxSpeedSamples bounds the stored tests per relay (7 days at 30 min
	// is 336).
	MaxSpeedSamples = 512
)

// SpeedSample is one download test of one relay.
type SpeedSample struct {
	At        int64  `json:"at"`
	Leg       string `json:"leg,omitempty"`
	OK        bool   `json:"ok"`
	Kbps      int    `json:"kbps,omitempty"`
	Bytes     int64  `json:"bytes"`
	ElapsedMS int64  `json:"elapsed_ms"`
	// Reason: why it was not measured (OK false).
	Reason string `json:"reason,omitempty"`
	// Low: below the throttle threshold of the baseline when judged (such
	// samples never raise or lower the baseline).
	Low bool `json:"low,omitempty"`
}

// QoSVerdict is one relay's verdict after its latest test.
type QoSVerdict struct {
	State     string `json:"state"`
	Since     int64  `json:"since"`
	LowStreak int    `json:"low_streak"`
	// LastKbps / LastAt: the latest valid test (0: none).
	LastKbps     int    `json:"last_kbps"`
	LastAt       int64  `json:"last_at"`
	BaselineKbps int    `json:"baseline_kbps"`
	BaselineSrc  string `json:"baseline_src"`
	// FailAt / FailReason: the latest test that measured nothing.
	FailAt     int64  `json:"fail_at,omitempty"`
	FailReason string `json:"fail_reason,omitempty"`
}

// NominalKbps is relay id's nominal bandwidth.
func NominalKbps(s model.PathQuality, id string) int {
	mbps := s.NominalMbps
	for _, o := range s.Overrides {
		if o.Relay == id && o.NominalMbps > 0 {
			mbps = o.NominalMbps
		}
	}
	if mbps <= 0 {
		mbps = 200
	}
	return mbps * 1000
}

// Baseline is the relay's reference speed at time now: the 90th percentile
// (nearest rank) of the valid, not-throttled tests of the last
// qos_baseline_days, isolated top spikes left out; the nominal bandwidth
// while there are fewer than baselineMinSamples of them.
func Baseline(samples []SpeedSample, now int64, s model.PathQuality, nominalKbps int) (int, string) {
	days := s.QoSBaselineDays
	if days <= 0 {
		days = 7
	}
	from := now - int64(days)*86400
	var v []int
	for _, x := range samples {
		if x.OK && !x.Low && x.At > from && x.At <= now && x.Kbps > 0 {
			v = append(v, x.Kbps)
		}
	}
	if len(v) < baselineMinSamples {
		return nominalKbps, BaselineNominal
	}
	sort.Sort(sort.Reverse(sort.IntSlice(v)))
	for d := 0; d < spikeDrops && len(v) > baselineMinSamples && v[0] > spikeFactor*v[1]; d++ {
		v = v[1:]
	}
	// Ascending nearest rank: ceil(0.9 n).
	n := len(v)
	k := (9*n + 9) / 10 // 1-based rank from the bottom
	return v[n-k], BaselineP90
}

// FoldSample judges one test against the earlier ones (samples, which do
// not include x) and updates the verdict. It returns x with Low set.
func FoldSample(v *QoSVerdict, samples []SpeedSample, x SpeedSample, s model.PathQuality, nominalKbps int) SpeedSample {
	if v.State == "" {
		v.State = QoSUnknown
	}
	if x.OK && (x.Kbps <= 0 || x.Kbps > maxPlausibleKbps) {
		x.OK, x.Reason, x.Kbps = false, SpeedFailInvalid, 0
	}
	base, src := Baseline(samples, x.At, s, nominalKbps)
	v.BaselineKbps, v.BaselineSrc = base, src
	if !x.OK {
		// Not measured: the streak of slow tests is neither extended nor
		// broken, the verdict stays.
		v.FailAt, v.FailReason = x.At, x.Reason
		return x
	}
	v.LastKbps, v.LastAt = x.Kbps, x.At
	low := int64(x.Kbps)*100 < int64(base)*int64(s.QoSThrottlePct)
	high := int64(x.Kbps)*100 >= int64(base)*int64(s.QoSRecoverPct)
	x.Low = low
	switch v.State {
	case QoSThrottled:
		if high {
			v.State, v.Since, v.LowStreak = QoSOK, x.At, 0
		} else if low {
			v.LowStreak++
		}
	default:
		if low {
			v.LowStreak++
			if v.LowStreak >= 2 {
				v.State, v.Since = QoSThrottled, x.At
			} else if v.State == QoSUnknown {
				v.State, v.Since = QoSOK, x.At
			}
		} else {
			if v.State != QoSOK {
				v.State, v.Since = QoSOK, x.At
			}
			v.LowStreak = 0
		}
	}
	return x
}

// QoSHeader starts the verdict file.
const QoSHeader = "meridian-qos 1"

// QoSPath is the verdict file on the gateway (persistent: a reboot keeps a
// throttled relay throttled until a test says otherwise).
const QoSPath = "/var/lib/meridian-pathq/qos"

// QoSEntry is one relay line of the verdict file.
type QoSEntry struct {
	ID           string
	State        string
	Since        int64
	LastKbps     int // 0: no valid test
	LastAt       int64
	BaselineKbps int
	BaselineSrc  string
}

// FormatQoS renders the verdict file (relay config order):
//
//	meridian-qos 1
//	relay <id> <ok|throttled|unknown> <since> <last kbps|-> <last at> <baseline kbps> <nominal|p90>
//	end
//
// The shell fallback reads it with the same strictness (share_qos_read).
func FormatQoS(c Config, v map[string]*QoSVerdict) string {
	var sb strings.Builder
	sb.WriteString(QoSHeader + "\n")
	for _, r := range c.Relays {
		q := v[r.ID]
		if q == nil {
			q = &QoSVerdict{State: QoSUnknown, BaselineKbps: NominalKbps(c.Settings, r.ID), BaselineSrc: BaselineNominal}
		}
		st := q.State
		if st == "" {
			st = QoSUnknown
		}
		src := q.BaselineSrc
		if src == "" {
			src = BaselineNominal
		}
		fmt.Fprintf(&sb, "relay %s %s %d %s %d %d %s\n", r.ID, st, q.Since, intOr(q.LastKbps > 0, q.LastKbps), q.LastAt, q.BaselineKbps, src)
	}
	sb.WriteString("end\n")
	return sb.String()
}

var reQoSNum = regexp.MustCompile(`^[0-9]{1,12}$`)

// ParseQoS reads the verdict file strictly against the config: any
// deviation refuses the whole file (the caller then treats every relay as
// not throttled).
func ParseQoS(c Config, text string) (map[string]QoSEntry, error) {
	bad := errors.New("qos: format")
	lines := strings.Split(strings.TrimRight(text, "\n"), "\n")
	if len(text) > 4096 || len(lines) != len(c.Relays)+2 || lines[0] != QoSHeader || lines[len(lines)-1] != "end" {
		return nil, bad
	}
	out := map[string]QoSEntry{}
	for i, r := range c.Relays {
		f := strings.Split(lines[1+i], " ")
		if len(f) != 8 || f[0] != "relay" || f[1] != r.ID {
			return nil, bad
		}
		e := QoSEntry{ID: r.ID, State: f[2], BaselineSrc: f[7]}
		switch e.State {
		case QoSOK, QoSThrottled, QoSUnknown:
		default:
			return nil, bad
		}
		if e.BaselineSrc != BaselineNominal && e.BaselineSrc != BaselineP90 {
			return nil, bad
		}
		nums := []string{f[3], f[5], f[6]}
		if f[4] != "-" {
			nums = append(nums, f[4])
		}
		for _, n := range nums {
			if !reQoSNum.MatchString(n) {
				return nil, bad
			}
		}
		e.Since, _ = strconv.ParseInt(f[3], 10, 64)
		e.LastAt, _ = strconv.ParseInt(f[5], 10, 64)
		e.BaselineKbps, _ = strconv.Atoi(f[6])
		if f[4] != "-" {
			e.LastKbps, _ = strconv.Atoi(f[4])
		}
		out[r.ID] = e
	}
	return out, nil
}

// QoSMaxAge is how long a verdict counts after its latest valid test: the
// baseline window (a verdict nobody refreshed for that long is dropped,
// e.g. after the speed tests were turned off).
func QoSMaxAge(s model.PathQuality) int64 {
	d := s.QoSBaselineDays
	if d <= 0 {
		d = 7
	}
	return int64(d) * 86400
}

// Throttled: the entry says throttled and is fresh at now.
func (e QoSEntry) Throttled(now int64, s model.PathQuality) bool {
	return e.State == QoSThrottled && e.LastAt > 0 && now-e.LastAt <= QoSMaxAge(s)
}
