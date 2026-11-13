package pathquality

import (
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// DecisionHeader starts the decision path-step prints for the shell.
const DecisionHeader = "meridian-pathq 1"

// FormatDecision is the decision the shell's share_decide reads:
//
//	meridian-pathq 1
//	upstream <main|backup>
//	designated <relay id|backup>
//	relay <id> <leg iface> <weight 0-1000> <drain 0|1>   (one per relay, config order)
//	backup <drain 0|1>
//	end
func FormatDecision(d Decision) string {
	var sb strings.Builder
	sb.WriteString(DecisionHeader + "\n")
	fmt.Fprintf(&sb, "upstream %s\ndesignated %s\n", d.Upstream, d.Designated)
	for _, r := range d.Relays {
		fmt.Fprintf(&sb, "relay %s %s %d %d\n", r.ID, r.Leg, r.Weight, b2i(r.Drain))
	}
	fmt.Fprintf(&sb, "backup %d\nend\n", b2i(d.BackupDrain))
	return sb.String()
}

var reDecisionToken = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._@-]{0,63}$`)

// ParseDecision checks a decision against the config (the same checks the
// shell makes, for tests and for the controller's own output).
func ParseDecision(c Config, out string) (Decision, error) {
	var d Decision
	lines := strings.Split(strings.TrimRight(out, "\n"), "\n")
	if len(lines) != 5+len(c.Relays) || lines[0] != DecisionHeader || lines[len(lines)-1] != "end" {
		return d, errors.New("decision: shape")
	}
	f := strings.Fields(lines[1])
	if len(f) != 2 || f[0] != "upstream" || (f[1] != UpstreamMain && f[1] != UpstreamBackup) {
		return d, errors.New("decision: upstream")
	}
	d.Upstream = f[1]
	f = strings.Fields(lines[2])
	if len(f) != 2 || f[0] != "designated" || !reDecisionToken.MatchString(f[1]) {
		return d, errors.New("decision: designated")
	}
	d.Designated = f[1]
	sum := 0
	for i, r := range c.Relays {
		f = strings.Fields(lines[3+i])
		if len(f) != 5 || f[0] != "relay" || f[1] != r.ID {
			return d, fmt.Errorf("decision: relay %s", r.ID)
		}
		ok := false
		for _, l := range r.Legs {
			ok = ok || l.Iface == f[2]
		}
		w, err := strconv.Atoi(f[3])
		if !ok || err != nil || w < 0 || w > Buckets || (f[4] != "0" && f[4] != "1") {
			return d, fmt.Errorf("decision: relay %s values", r.ID)
		}
		sum += w
		d.Relays = append(d.Relays, RelayDecision{ID: r.ID, Leg: f[2], Weight: w, Drain: f[4] == "1"})
	}
	f = strings.Fields(lines[3+len(c.Relays)])
	if len(f) != 2 || f[0] != "backup" || (f[1] != "0" && f[1] != "1") {
		return d, errors.New("decision: backup")
	}
	d.BackupDrain = f[1] == "1"
	switch {
	case d.Upstream == UpstreamMain && sum != Buckets:
		return d, errors.New("decision: weights do not sum to the bucket count")
	case d.Upstream == UpstreamBackup && (sum != 0 || c.Backup == nil || d.Designated != UpstreamBackup):
		return d, errors.New("decision: backup with relay weights")
	case d.Upstream == UpstreamMain:
		if _, ok := c.RelayByID(d.Designated); !ok {
			return d, errors.New("decision: designated is not a relay")
		}
	}
	return d, nil
}

func b2i(v bool) int {
	if v {
		return 1
	}
	return 0
}

// StatusHeader2 is the relay-sharing form of the gateway's upstream record
// (the single-relay form is "meridian-upstream 1", compile.upstreamShell).
const StatusHeader2 = "meridian-upstream 2"

// FormatStatus renders the upstream record the controller writes each
// pass (hostexec.ParseUpstream reads it strictly):
//
//	meridian-upstream 2
//	beat <epoch>
//	path <main|backup>
//	iface <ifname>                 the interface table 102 follows
//	hub <node id>
//	tier <primary|backup>
//	since <epoch>                  the carrying hub since
//	state <static|ok|degraded|down>
//	controller <go|shell>
//	alert <code|->
//	switched <epoch>               last change of the carrying hub (0: none)
//	designated <relay id|backup>
//	relay <id> <iface> <status> <weight> <drain> <reason|-> <status since>
//	      <grade> <rtt_us|-> <loss‰|-> <last rtt_us|-> <last loss‰|-> <measured at>
//	      <rx bytes> <tx bytes> <rx B/s> <tx B/s> <new conns> <suspicious|->
//	      <probe at> <probe kbps|-> <probe loss‰|-> <probe ok 0|1|-> <probe bytes today>
//	backup <hub> <iface> <grade> <rtt_us|-> <loss‰|-> <last rtt_us|-> <last loss‰|->
//	       <measured at> <rx bytes> <tx bytes> <drain>
//	end
//
// (each relay and the backup line is one line; "-" is "not measured").
func FormatStatus(c Config, st *State, beat int64, controller string) string {
	var sb strings.Builder
	sb.WriteString(StatusHeader2 + "\n")
	iface, hub, tier := "", c.PrimaryHub, "primary"
	if st.Upstream == UpstreamBackup && c.Backup != nil {
		iface, hub, tier = c.Backup.Iface, c.Backup.Hub, "backup"
	} else if rs := st.Relays[st.Designated]; rs != nil {
		iface = rs.Leg
	} else {
		iface = c.Relays[0].Legs[0].Iface
	}
	state := "ok"
	switch st.Alert {
	case AlertNothingReachable:
		state = "down"
	case AlertAllPoor, AlertBackupNotBetter, AlertBackupUnusable:
		state = "degraded"
	}
	if st.Passes == 0 {
		state = "static"
	}
	alert := st.Alert
	if alert == "" {
		alert = "-"
	}
	fmt.Fprintf(&sb, "beat %d\npath %s\niface %s\nhub %s\ntier %s\nsince %d\nstate %s\ncontroller %s\nalert %s\nswitched %d\ndesignated %s\n",
		beat, st.Upstream, iface, hub, tier, st.UpstreamSince, state, controller, alert, st.LastSwitch, st.Designated)
	for _, r := range c.Relays {
		rs := st.Relays[r.ID]
		probeOK := "-"
		if rs.ProbeAt > 0 {
			probeOK = strconv.Itoa(b2i(rs.ProbeOK))
		}
		w := rs.Weight
		if st.Upstream == UpstreamBackup {
			w = 0
		}
		fmt.Fprintf(&sb, "relay %s %s %s %d %d %s %d %s %s %s %s %s %d %d %d %d %d %d %s %d %s %s %s %d\n",
			r.ID, rs.Leg, rs.Status, w, b2i(rs.Drain), dash(rs.Reason), rs.StatusSince,
			gradeOr(rs.Grade), usOr(rs.Have && rs.RTTEWMA > 0, rs.RTTEWMA), intOr(rs.Have, int(rs.LossEWMA+0.5)),
			usOr(rs.LastRTT > 0, rs.LastRTT), intOr(rs.Have, rs.LastLoss), rs.MeasuredAt,
			rs.RxBytes, rs.TxBytes, rs.RxBps, rs.TxBps, rs.NewConns, dash(rs.Suspicious),
			rs.ProbeAt, intOr(rs.ProbeAt > 0, rs.ProbeKbps), intOr(rs.ProbeAt > 0, rs.ProbeLoss), probeOK, rs.ProbeBytesToday)
	}
	if b := st.Backup; b != nil && c.Backup != nil {
		fmt.Fprintf(&sb, "backup %s %s %s %s %s %s %s %d %d %d %d\n",
			c.Backup.Hub, c.Backup.Iface, gradeOr(b.Grade), usOr(b.Have && b.RTTEWMA > 0, b.RTTEWMA), intOr(b.Have, int(b.LossEWMA+0.5)),
			usOr(b.LastRTT > 0, b.LastRTT), intOr(b.Have, b.LastLoss), b.MeasuredAt, b.RxBytes, b.TxBytes, b2i(st.BackupDrain))
	}
	sb.WriteString("end\n")
	return sb.String()
}

func dash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

func gradeOr(g string) string {
	if g == "" {
		return GradeNone
	}
	return g
}

func usOr(ok bool, ms float64) string {
	if !ok {
		return "-"
	}
	return strconv.FormatInt(int64(ms*1000+0.5), 10)
}

func intOr(ok bool, v int) string {
	if !ok {
		return "-"
	}
	return strconv.Itoa(v)
}
