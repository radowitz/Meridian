package hostexec

import (
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// The relay-sharing form of the upstream record ("meridian-upstream 2",
// pathquality.FormatStatus). Every line has a fixed shape; any deviation
// refuses the whole record.

// MaxUpstreamRelays bounds the relay lines (pathquality.MaxRelays).
const MaxUpstreamRelays = 12

var (
	reUpCode   = regexp.MustCompile(`^[a-z][a-z0-9_]{0,47}$`)
	reUpNumber = regexp.MustCompile(`^[0-9]{1,15}$`)
)

var (
	upRelayStatuses = map[string]bool{"active": true, "reduced": true, "standby": true, "evicted": true, "recovering": true, "disabled": true}
	upGrades        = map[string]bool{"good": true, "mild": true, "poor": true, "down": true, "none": true}
)

const relayFields = 25 // "relay" + 24 values
const backupFields = 12

func parseUpstream2(lines []string) (UpstreamState, error) {
	st := UpstreamState{Version: 2}
	if len(lines) < 14 || lines[len(lines)-1] != "end" {
		return st, errors.New("上游记录格式不对")
	}
	head := []string{"beat", "path", "iface", "hub", "tier", "since", "state", "controller", "alert", "switched", "designated"}
	for i, key := range head {
		l := lines[1+i]
		f := strings.Fields(l)
		if len(f) != 2 || strings.Join(f, " ") != l || f[0] != key {
			return st, fmt.Errorf("上游记录第 %d 行格式不对", i+2)
		}
		v := f[1]
		num := func() (int64, error) {
			if !reUpEpoch.MatchString(v) {
				return 0, fmt.Errorf("上游记录第 %d 行时间不对", i+2)
			}
			return strconv.ParseInt(v, 10, 64)
		}
		var err error
		switch key {
		case "beat":
			st.Beat, err = num()
		case "since":
			st.Since, err = num()
		case "switched":
			st.Switched, err = num()
		case "path":
			if v != "main" && v != "backup" {
				return st, errors.New("上游记录的路径未知")
			}
			st.Path = v
		case "iface", "hub", "designated":
			if !reUpToken.MatchString(v) {
				return st, fmt.Errorf("上游记录第 %d 行的值不合格", i+2)
			}
			switch key {
			case "iface":
				st.Iface = v
			case "hub":
				st.Hub = v
			default:
				st.Designated = v
			}
		case "tier":
			if v != "primary" && v != "backup" {
				return st, errors.New("上游记录的枢纽层级未知")
			}
			st.Tier = v
		case "state":
			switch v {
			case UpstreamStatic, UpstreamOK, UpstreamSwitching, UpstreamDown, UpstreamDegraded:
			default:
				return st, errors.New("上游记录的状态未知")
			}
			st.State = v
		case "controller":
			if v != "go" && v != "shell" {
				return st, errors.New("上游记录的控制者未知")
			}
			st.Controller = v
		case "alert":
			if v != "-" {
				if !reUpCode.MatchString(v) {
					return st, errors.New("上游记录的告警不合格")
				}
				st.Alert = v
			}
		}
		if err != nil {
			return st, err
		}
	}
	rest := lines[1+len(head) : len(lines)-1]
	seen := map[string]bool{}
	for k, l := range rest {
		f := strings.Fields(l)
		if strings.Join(f, " ") != l || len(f) == 0 {
			return st, fmt.Errorf("上游记录第 %d 行格式不对", len(head)+2+k)
		}
		switch {
		case f[0] == "relay" && len(f) == relayFields && st.Backup == nil:
			r, err := parseRelayLine(f)
			if err != nil {
				return st, err
			}
			if seen[r.ID] || len(st.Relays) == MaxUpstreamRelays {
				return st, errors.New("上游记录的中继重复或过多")
			}
			seen[r.ID] = true
			st.Relays = append(st.Relays, r)
		case f[0] == "backup" && len(f) == backupFields && st.Backup == nil:
			b, err := parseBackupLine(f)
			if err != nil {
				return st, err
			}
			st.Backup = &b
		default:
			return st, fmt.Errorf("上游记录第 %d 行格式不对", len(head)+2+k)
		}
	}
	if len(st.Relays) == 0 {
		return st, errors.New("上游记录没有中继")
	}
	if st.Since > st.Beat || st.Switched > st.Beat {
		return st, errors.New("上游记录的切换时间晚于心跳")
	}
	return st, nil
}

// fieldReader walks the values of one line with strict per-field checks.
type fieldReader struct {
	f   []string
	i   int
	err error
}

func (r *fieldReader) next() string {
	r.i++
	return r.f[r.i]
}

func (r *fieldReader) token() string {
	v := r.next()
	if r.err == nil && !reUpToken.MatchString(v) {
		r.err = fmt.Errorf("上游记录的第 %d 个字段不合格", r.i)
	}
	return v
}

func (r *fieldReader) code() string {
	v := r.next()
	if v == "-" {
		return ""
	}
	if r.err == nil && !reUpCode.MatchString(v) {
		r.err = fmt.Errorf("上游记录的第 %d 个字段不合格", r.i)
	}
	return v
}

func (r *fieldReader) num() int64 {
	v := r.next()
	if !reUpNumber.MatchString(v) {
		if r.err == nil {
			r.err = fmt.Errorf("上游记录的第 %d 个字段不是数字", r.i)
		}
		return 0
	}
	n, _ := strconv.ParseInt(v, 10, 64)
	return n
}

func (r *fieldReader) opt() *int64 {
	if r.f[r.i+1] == "-" {
		r.i++
		return nil
	}
	n := r.num()
	return &n
}

func (r *fieldReader) flag() bool {
	switch r.next() {
	case "0":
		return false
	case "1":
		return true
	}
	if r.err == nil {
		r.err = fmt.Errorf("上游记录的第 %d 个字段不是 0/1", r.i)
	}
	return false
}

func (r *fieldReader) oneOf(set map[string]bool) string {
	v := r.next()
	if !set[v] && r.err == nil {
		r.err = fmt.Errorf("上游记录的第 %d 个字段取值未知", r.i)
	}
	return v
}

func parseRelayLine(f []string) (UpstreamRelay, error) {
	r := &fieldReader{f: f}
	var x UpstreamRelay
	x.ID = r.token()
	x.Iface = r.token()
	x.Status = r.oneOf(upRelayStatuses)
	x.Weight = int(r.num())
	x.Drain = r.flag()
	x.Reason = r.code()
	x.StatusSince = r.num()
	x.Grade = r.oneOf(upGrades)
	x.RTTus = r.opt()
	x.LossPermille = r.opt()
	x.LastRTTus = r.opt()
	x.LastLoss = r.opt()
	x.MeasuredAt = r.num()
	x.RxBytes = r.num()
	x.TxBytes = r.num()
	x.RxBps = r.num()
	x.TxBps = r.num()
	x.NewConns = r.num()
	x.Suspicious = r.code()
	x.ProbeAt = r.num()
	x.ProbeKbps = r.opt()
	x.ProbeLoss = r.opt()
	switch v := r.next(); v {
	case "-":
	case "0", "1":
		ok := v == "1"
		x.ProbeOK = &ok
	default:
		if r.err == nil {
			r.err = errors.New("上游记录的探测结果不合格")
		}
	}
	x.ProbeBytesToday = r.num()
	if r.err == nil && x.Weight > 1000 {
		r.err = errors.New("上游记录的权重越界")
	}
	if r.err == nil && x.LossPermille != nil && *x.LossPermille > 1000 {
		r.err = errors.New("上游记录的丢包越界")
	}
	return x, r.err
}

func parseBackupLine(f []string) (UpstreamBackup, error) {
	r := &fieldReader{f: f}
	var b UpstreamBackup
	b.Hub = r.token()
	b.Iface = r.token()
	b.Grade = r.oneOf(upGrades)
	b.RTTus = r.opt()
	b.LossPermille = r.opt()
	b.LastRTTus = r.opt()
	b.LastLoss = r.opt()
	b.MeasuredAt = r.num()
	b.RxBytes = r.num()
	b.TxBytes = r.num()
	b.Drain = r.flag()
	return b, r.err
}
