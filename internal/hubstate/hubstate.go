// Package hubstate parses and judges what the hub reports about its region
// groups. The hub's failover loop records, per switchable group, the hop
// its group table really holds, the switcher's reason, the last switch,
// whether a switch command failed, a heartbeat and the identifier of the
// group plan it runs (internal/compile hub_state.go). The panel reads all
// of it with one fixed SSH command (sshexec.GroupStateCommand) and keeps
// the parsed result with the time of the read.
//
// Nothing the hub prints is trusted beyond its meaning: the output is
// bounded, every line must match the strict grammar below, timestamps must
// be sane on the hub's own clock, and member IDs are checked against the
// group's compiled switch order when the state is judged (Evaluate). A
// state is only "ok" — shown as the member actually in use — when the
// report is fresh, was written by the plan the panel would deploy now, and
// the hub saw the table holding what its switcher chose.
package hubstate

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/radowitz/meridian/internal/pool"
)

// Output grammar (one item per line, "\n" separated, printable ASCII):
//
//	meridian-group-state 1
//	now <epoch>                       the hub's clock when it answered
//	plan <id> <epoch>                 optional: /run/meridian/group-plan
//	(meridian-group-report 1 … end)*  one block per /run/meridian/group/*/report
//	meridian-group-state-end
const (
	Header       = "meridian-group-state 1"
	Footer       = "meridian-group-state-end"
	ReportHeader = "meridian-group-report 1"
	reportFooter = "end"
)

// MaxOutput bounds the accepted output; the command prints at most one
// byte more (head -c), so a longer answer is recognised as oversized.
const MaxOutput = 64 << 10

// maxGroups bounds the report blocks.
const maxGroups = 256

// Time sanity on the hub's clock: nothing before 2020-01-01, nothing more
// than MaxFuture after the hub's own "now".
const (
	minEpoch  = 1577836800
	maxEpoch  = 7258118400 // 2200-01-01
	MaxFuture = 5 * time.Second
)

// ReadMaxAge: a read older than this (panel clock) no longer shows the
// actual member; the page refreshes it.
const ReadMaxAge = 10 * time.Minute

// SkewWarn: hub and panel clocks further apart than this are reported
// (clock_skew_sec is always returned). Staleness never depends on the skew:
// the heartbeat is compared with the hub's own "now" from the same read.
const SkewWarn = 5 * time.Minute

// Hops besides member IDs. mmesh is the Mesh sidecar; the others say the
// table holds no member.
const (
	HopMesh       = pool.MeshHop
	HopBlackhole  = "blackhole"
	HopNone       = "none"
	HopOther      = "other"
	HopSplit      = "split"
	HopUnreadable = "unreadable"
)

// Results of the last pass.
const (
	ResultOK       = "ok"
	ResultFailed   = "failed"
	ResultDiverged = "diverged"
)

// Report is one group's report.
type Report struct {
	Group        string `json:"group"`
	Plan         string `json:"plan"`
	Beat         int64  `json:"beat"`
	Hop          string `json:"hop"`
	Active       string `json:"active"`
	Reason       string `json:"reason"`
	Alert        bool   `json:"alert"`
	Switched     int64  `json:"switched"`
	Result       string `json:"result"`
	Want         string `json:"want,omitempty"`
	LastFailWant string `json:"lastfail_want,omitempty"`
	LastFailAt   int64  `json:"lastfail_at,omitempty"`
}

// Snapshot is one parsed read.
type Snapshot struct {
	Now     int64             `json:"now"`
	Plan    string            `json:"plan,omitempty"`
	PlanAt  int64             `json:"plan_at,omitempty"`
	Reports map[string]Report `json:"reports"`
}

// ParseError says why an output was refused. Code is "oversized" or
// "malformed"; Msg never quotes more than a short, cleaned excerpt.
type ParseError struct {
	Code string
	Msg  string
}

func (e *ParseError) Error() string { return e.Msg }

func malformed(line int, format string, a ...any) error {
	return &ParseError{Code: "malformed", Msg: fmt.Sprintf("第 %d 行：%s", line, fmt.Sprintf(format, a...))}
}

var (
	reToken  = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)
	rePlan   = regexp.MustCompile(`^[0-9a-f]{24}$`)
	reNumber = regexp.MustCompile(`^[0-9]{1,12}$`)
)

var reasons = map[string]bool{
	pool.ReasonPreferred: true, pool.ReasonChosen: true, pool.ReasonConstraint: true,
	pool.ReasonFailover: true, pool.ReasonFallback: true, pool.ReasonHeld: true, pool.ReasonMesh: true,
}

var specialHops = map[string]bool{
	HopMesh: true, HopBlackhole: true, HopNone: true, HopOther: true, HopSplit: true, HopUnreadable: true,
}

// Parse checks the whole output against the grammar. It does not know the
// topology: unknown groups and members are judged by Evaluate.
func Parse(out string) (Snapshot, error) {
	if len(out) > MaxOutput {
		return Snapshot{}, &ParseError{Code: "oversized", Msg: fmt.Sprintf("枢纽输出超过 %d 字节，拒绝解析", MaxOutput)}
	}
	for i := 0; i < len(out); i++ {
		c := out[i]
		if c != '\n' && (c < 0x20 || c > 0x7e) {
			return Snapshot{}, &ParseError{Code: "malformed", Msg: "枢纽输出含有不可打印字符"}
		}
	}
	lines := strings.Split(strings.TrimRight(out, "\n"), "\n")
	if len(lines) < 3 || lines[0] != Header {
		return Snapshot{}, malformed(1, "不是地区组状态输出")
	}
	if lines[len(lines)-1] != Footer {
		return Snapshot{}, malformed(len(lines), "输出不完整（缺少结束行）")
	}
	snap := Snapshot{Reports: map[string]Report{}}
	f := strings.Fields(lines[1])
	if len(f) != 2 || f[0] != "now" {
		return Snapshot{}, malformed(2, "缺少枢纽时间")
	}
	now, ok := epoch(f[1])
	if !ok || now < minEpoch {
		return Snapshot{}, malformed(2, "枢纽时间不合理")
	}
	snap.Now = now
	limit := now + int64(MaxFuture/time.Second)
	sane := func(v string, zeroOK bool) (int64, bool) {
		n, ok := epoch(v)
		if !ok {
			return 0, false
		}
		if n == 0 {
			return 0, zeroOK
		}
		return n, n >= minEpoch && n <= limit
	}
	i := 2
	if f := strings.Fields(lines[i]); len(f) > 0 && f[0] == "plan" {
		if len(f) != 3 || !rePlan.MatchString(f[1]) {
			return Snapshot{}, malformed(i+1, "部署标识格式不对")
		}
		at, ok := sane(f[2], false)
		if !ok {
			return Snapshot{}, malformed(i+1, "部署记录时间不合理")
		}
		snap.Plan, snap.PlanAt = f[1], at
		i++
	}
	body := lines[i : len(lines)-1]
	for j := 0; j < len(body); {
		start := i + j + 1
		if body[j] != ReportHeader {
			return Snapshot{}, malformed(start, "期望地区组报告")
		}
		end := -1
		for k := j + 1; k < len(body); k++ {
			if body[k] == reportFooter {
				end = k
				break
			}
		}
		if end < 0 {
			return Snapshot{}, malformed(start, "地区组报告没有结束")
		}
		r, err := parseReport(body[j+1:end], start, sane)
		if err != nil {
			return Snapshot{}, err
		}
		if _, dup := snap.Reports[r.Group]; dup {
			return Snapshot{}, malformed(start, "地区组重复出现")
		}
		if len(snap.Reports) >= maxGroups {
			return Snapshot{}, malformed(start, "地区组过多")
		}
		snap.Reports[r.Group] = r
		j = end + 1
	}
	return snap, nil
}

func epoch(v string) (int64, bool) {
	if !reNumber.MatchString(v) {
		return 0, false
	}
	n, err := strconv.ParseInt(v, 10, 64)
	return n, err == nil && n <= maxEpoch
}

func parseReport(lines []string, start int, sane func(string, bool) (int64, bool)) (Report, error) {
	var r Report
	seen := map[string]bool{}
	for k, l := range lines {
		ln := start + 1 + k
		f := strings.Fields(l)
		if len(f) < 2 || strings.Join(f, " ") != l {
			return Report{}, malformed(ln, "格式不对")
		}
		key := f[0]
		if seen[key] {
			return Report{}, malformed(ln, "字段 %s 重复", key)
		}
		seen[key] = true
		one := func() (string, error) {
			if len(f) != 2 || !reToken.MatchString(f[1]) {
				return "", malformed(ln, "字段 %s 的值不合格", key)
			}
			return f[1], nil
		}
		var err error
		switch key {
		case "group":
			r.Group, err = one()
		case "plan":
			if len(f) != 2 || !rePlan.MatchString(f[1]) {
				return Report{}, malformed(ln, "部署标识格式不对")
			}
			r.Plan = f[1]
		case "beat", "switched":
			if len(f) != 2 {
				return Report{}, malformed(ln, "字段 %s 格式不对", key)
			}
			n, ok := sane(f[1], key == "switched")
			if !ok {
				return Report{}, malformed(ln, "字段 %s 的时间不合理", key)
			}
			if key == "beat" {
				r.Beat = n
			} else {
				r.Switched = n
			}
		case "hop":
			r.Hop, err = one()
		case "active":
			r.Active, err = one()
		case "reason":
			r.Reason, err = one()
			if err == nil && !reasons[r.Reason] {
				return Report{}, malformed(ln, "未知的原因")
			}
		case "alert":
			if len(f) != 2 || (f[1] != "0" && f[1] != "1") {
				return Report{}, malformed(ln, "告警标记格式不对")
			}
			r.Alert = f[1] == "1"
		case "result":
			r.Result, err = one()
			if err == nil && r.Result != ResultOK && r.Result != ResultFailed && r.Result != ResultDiverged {
				return Report{}, malformed(ln, "未知的结果")
			}
		case "want":
			r.Want, err = one()
		case "lastfail":
			if len(f) != 3 || !reToken.MatchString(f[1]) {
				return Report{}, malformed(ln, "lastfail 格式不对")
			}
			n, ok := sane(f[2], false)
			if !ok {
				return Report{}, malformed(ln, "lastfail 的时间不合理")
			}
			r.LastFailWant, r.LastFailAt = f[1], n
		default:
			return Report{}, malformed(ln, "未知字段")
		}
		if err != nil {
			return Report{}, err
		}
	}
	for _, k := range []string{"group", "plan", "beat", "hop", "active", "reason", "alert", "switched", "result"} {
		if !seen[k] {
			return Report{}, malformed(start, "地区组报告缺少字段 %s", k)
		}
	}
	if (r.Result == ResultFailed) != (r.Want != "") {
		return Report{}, malformed(start, "切换失败的报告必须带 want，其他报告不能带")
	}
	if r.Switched > r.Beat {
		return Report{}, malformed(start, "上次切换晚于心跳")
	}
	return r, nil
}

// ---------------------------------------------------------- judgement ---

// Actual states.
const (
	StateOK              = "ok"
	StateStale           = "stale"
	StateVersionMismatch = "version_mismatch"
	StateSwitchFailed    = "switch_failed"
	StateUnavailable     = "unavailable"
	StateNotSwitchable   = "not_switchable"
	StateNeverRead       = "never_read"
)

// Machine reasons (Actual.Code).
const (
	CodeNoHub             = "no_hub"
	CodeHubNoServer       = "hub_no_server"
	CodeServerNotReady    = "server_not_ready"
	CodeSSHFailed         = "ssh_failed"
	CodeStateMissing      = "state_missing"
	CodeParseError        = "parse_error"
	CodeInvalidReport     = "invalid_report"
	CodePlanUnavailable   = "plan_unavailable"
	CodeHeartbeatOld      = "heartbeat_old"
	CodeReadOld           = "read_old"
	CodePlanDiffers       = "plan_differs"
	CodeHopFailed         = "hop_failed"
	CodeTableDiverged     = "table_diverged"
	CodeStaticOrHold      = "static_only"
	CodeNotRead           = "not_read"
	CodeRefreshInProgress = "refresh_in_progress"
)

// Read is one stored attempt to read the hub (successful or not).
type Read struct {
	ReadAt    time.Time `json:"read_at"`
	HubNode   string    `json:"hub_node,omitempty"`
	ServerID  string    `json:"server_id,omitempty"`
	ErrorCode string    `json:"error_code,omitempty"`
	// SSHCode is the connector's code when ErrorCode is ssh_failed or
	// server_not_ready.
	SSHCode  string    `json:"ssh_code,omitempty"`
	Error    string    `json:"error,omitempty"`
	Snapshot *Snapshot `json:"snapshot,omitempty"`
}

// Skew is panel time minus hub time at the read (positive: hub behind).
func (r Read) Skew() time.Duration {
	if r.Snapshot == nil {
		return 0
	}
	return r.ReadAt.Sub(time.Unix(r.Snapshot.Now, 0))
}

// GroupSpec is what the panel compiled for one group.
type GroupSpec struct {
	ID string
	// Dynamic: the hub switches this group (otherwise there is no hub
	// state to read).
	Dynamic bool
	// Members is the compiled switch order (member IDs the hub may use).
	Members []string
	Mesh    bool
}

// Reported is what the hub said in a non-ok state: shown as the hub's
// unconfirmed report, never as the member in use.
type Reported struct {
	Hop      string     `json:"hop"`
	Active   string     `json:"active,omitempty"`
	Want     string     `json:"want,omitempty"`
	FailedAt *time.Time `json:"failed_at,omitempty"`
}

// Actual is the hub's state for one group as the panel judged it.
// Active, Hop, Reason, Alert, LastSwitch and RunningSince are set only in
// state ok.
type Actual struct {
	State string `json:"state"`
	// Code is the machine reason of every state but ok.
	Code    string `json:"code,omitempty"`
	SSHCode string `json:"ssh_code,omitempty"`
	Message string `json:"message,omitempty"`
	// Active is the member the group table really uses: a member ID,
	// "mmesh", or "" when the table is a blackhole (Hop says which).
	Active       string     `json:"active"`
	Hop          string     `json:"hop,omitempty"`
	Reason       string     `json:"reason,omitempty"`
	Alert        bool       `json:"alert"`
	LastSwitch   *time.Time `json:"last_switch"`
	RunningSince *time.Time `json:"running_since,omitempty"`
	ReadAt       *time.Time `json:"read_at"`
	// HubReportedAt is the report's heartbeat, on the panel's clock.
	HubReportedAt   *time.Time `json:"hub_reported_at"`
	DeployedMatches *bool      `json:"deployed_matches"`
	ClockSkewSec    *int64     `json:"clock_skew_sec,omitempty"`
	Reported        *Reported  `json:"reported,omitempty"`
}

func tp(t time.Time) *time.Time { return &t }

func bp(b bool) *bool { return &b }

// Evaluate judges one group against the last read. currentPlan is the
// GroupPlanID the panel compiles now ("" when it cannot compile);
// staleAfter is compile.HubStaleAfter; now is the panel's clock.
func Evaluate(g GroupSpec, rd *Read, currentPlan string, staleAfter time.Duration, now time.Time) Actual {
	if !g.Dynamic {
		return Actual{State: StateNotSwitchable, Code: CodeStaticOrHold,
			Message: "枢纽不切换这个组（成员经中继或 Mesh 到达，或没有可用成员），没有枢纽运行状态可读"}
	}
	if rd == nil {
		return Actual{State: StateNeverRead, Code: CodeNotRead, Message: "还没有读取过枢纽的运行状态"}
	}
	a := Actual{ReadAt: tp(rd.ReadAt)}
	if rd.ErrorCode != "" || rd.Snapshot == nil {
		a.State, a.Code, a.SSHCode, a.Message = StateUnavailable, rd.ErrorCode, rd.SSHCode, rd.Error
		if a.Code == "" {
			a.Code = CodeParseError
		}
		return a
	}
	snap := rd.Snapshot
	skew := rd.Skew()
	sk := int64(skew / time.Second)
	a.ClockSkewSec = &sk
	at := func(e int64) *time.Time { return tp(time.Unix(e, 0).Add(skew).UTC()) }
	if currentPlan == "" {
		a.State, a.Code, a.Message = StateUnavailable, CodePlanUnavailable, "面板无法编译当前拓扑的地区组计划，不能核对枢纽运行的版本"
		return a
	}
	r, ok := snap.Reports[g.ID]
	if snap.Plan == "" || !ok {
		a.State, a.Code = StateUnavailable, CodeStateMissing
		a.Message = "枢纽上没有这个组的运行记录（切换服务没有运行，或枢纽还没装过带状态记录的版本）"
		if snap.Plan != "" {
			a.DeployedMatches = bp(snap.Plan == currentPlan)
		}
		return a
	}
	a.HubReportedAt = at(r.Beat)
	matches := snap.Plan == currentPlan && r.Plan == currentPlan
	a.DeployedMatches = bp(matches)
	if !matches {
		a.State, a.Code = StateVersionMismatch, CodePlanDiffers
		a.Message = "枢纽运行的地区组计划不是面板当前的配置：枢纽还没有按当前拓扑装机"
		return a
	}
	member := map[string]bool{}
	for _, m := range g.Members {
		member[m] = true
	}
	choice := func(v string) bool { return member[v] || (v == HopMesh && g.Mesh) }
	hopOK := choice(r.Hop) || (specialHops[r.Hop] && r.Hop != HopMesh)
	if !hopOK || !choice(r.Active) || (r.Want != "" && !choice(r.Want)) || (r.LastFailWant != "" && !choice(r.LastFailWant)) {
		a.State, a.Code = StateUnavailable, CodeInvalidReport
		a.Message = "枢纽报告里的成员不属于这个组的切换顺序，拒绝采信"
		return a
	}
	if age := snap.Now - r.Beat; age > int64(staleAfter/time.Second) {
		a.State, a.Code = StateStale, CodeHeartbeatOld
		a.Message = fmt.Sprintf("枢纽这个组的心跳已停 %d 秒（超过 %d 秒），切换服务可能没有运行", age, int64(staleAfter/time.Second))
		return a
	}
	if now.Sub(rd.ReadAt) > ReadMaxAge {
		a.State, a.Code = StateStale, CodeReadOld
		a.Message = fmt.Sprintf("上次读取已超过 %d 分钟，需要重新读取", int(ReadMaxAge/time.Minute))
		return a
	}
	// The hub's own consistency check, and the panel's: the table must hold
	// what the switcher chose (a Mesh choice whose sidecar is not sealed is
	// a blackhole by design).
	consistent := r.Hop == r.Active || (r.Active == HopMesh && r.Hop == HopBlackhole)
	if r.Result != ResultOK || !consistent {
		a.State = StateSwitchFailed
		rep := &Reported{Hop: r.Hop, Active: r.Active, Want: r.Want}
		if r.Result == ResultFailed {
			a.Code = CodeHopFailed
			a.Message = fmt.Sprintf("枢纽切换到 %s 的路由命令失败；枢纽读到的路由表仍是 %s（未确认可用）", r.Want, hopText(r.Hop))
			if r.LastFailAt > 0 {
				rep.FailedAt = at(r.LastFailAt)
			}
		} else {
			a.Code = CodeTableDiverged
			a.Message = fmt.Sprintf("枢纽的路由表（%s）与切换器的选择（%s）不一致", hopText(r.Hop), hopText(r.Active))
		}
		a.Reported = rep
		return a
	}
	a.State = StateOK
	a.Hop, a.Reason, a.Alert = r.Hop, r.Reason, r.Alert
	if r.Hop != HopBlackhole {
		a.Active = r.Hop
	}
	if r.Switched > 0 {
		a.LastSwitch = at(r.Switched)
	}
	if snap.PlanAt > 0 {
		a.RunningSince = at(snap.PlanAt)
	}
	return a
}

func hopText(h string) string {
	switch h {
	case HopMesh:
		return "Mesh 备路"
	case HopBlackhole:
		return "黑洞"
	case HopNone:
		return "没有默认路由"
	case HopOther:
		return "非成员接口"
	case HopSplit:
		return "IPv4 与 IPv6 不一致"
	case HopUnreadable:
		return "读不到"
	}
	return h
}
