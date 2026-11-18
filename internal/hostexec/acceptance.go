package hostexec

// Acceptance actions (docs/verification.md「验收目录」; the panel's 验收 page).
//
// Two kinds, both fixed:
//
//   - The read-only tunnel path check (POST /v1/acceptance/paths). Its only
//     parameter is a list of Meridian interface names, each of which must
//     pass ValidInterface and be in the ledger. Per interface it runs
//     "ip -o link show dev <if>", "wg show <if> latest-handshakes" and
//     "wg show <if> transfer" (the parsers of wgstatus.go) and returns the
//     link state, how many peers there are, the age of the freshest
//     handshake and the byte counters. No public key leaves the host.
//
//   - Three drills that change the running host for a bounded time and put
//     it back (POST /v1/drill/start, …/status, …/cancel, …/retry,
//     …/release):
//
//     DrillFirewallReload  restarts meridian.service (meridian-up.sh, the
//     same step an install runs) and samples, while it
//     runs, whether the guard table stays loaded.
//     DrillRelayIsolation  drops this host's outbound packets to one
//     relay's tunnel endpoint for BlockSeconds.
//     DrillHubIsolation    the same for every relay of the main path, so
//     the gateway has to move to the backup hub.
//
// Parameters name interfaces only (ledger-checked, and for the isolation
// drills also named by the gateway's own upstream record). The address that
// is blocked is never a parameter: the agent reads it from
// "wg show <if> endpoints". There is no command, path, host or URL in any
// request, and the durations are bounded (DrillMinBlock…DrillMaxBlock).
//
// The block is a table of its own, DrillTable, loaded with one "nft -f" of
// a file the agent writes: an output-hook chain that drops packets to the
// addresses in two sets. Every element carries a kernel timeout a little
// longer than the drill, so the block ends by itself even when the agent is
// killed (the independent safety timer); the agent removes the table when
// the drill ends and, after a restart, before anything else is allowed.
//
// A drill is recorded on disk (DefaultDrillState) before the host is
// changed: the state before (DrillSnapshot), the restore plan, the
// deadlines and the phase. Every way out — the deadline, a cancel, a failed
// step, a timeout, an agent restart — goes through the same restore, which
// removes the block and then compares the host with the snapshot: the nft
// tables and their rules, the policy rules, the route tables, the managed
// links and the upstream record (path, hub, each relay's status and
// weight). A healthy data plane is not enough. When the comparison still
// differs after the wait, the data plane is re-activated through the same
// steps RestoreDataPlane uses and compared again (RestoreTopology,
// restore.go). A restore that cannot be verified leaves the record in
// DrillRestoreFailed with the differences listed: new drills, activate,
// rollback and withdraw are refused until a retry verifies it or the
// operator releases it (possible only once the block itself is verified
// gone, and never reported as restored).

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

// Drill kinds and the read-only check, as the acceptance catalog names them.
const (
	DrillFirewallReload = "drill_firewall_reload"
	DrillRelayIsolation = "drill_relay_isolation"
	DrillHubIsolation   = "drill_hub_isolation"
	// CheckTunnelPaths is the read-only tunnel path check.
	CheckTunnelPaths = "check_tunnel_paths"
)

// DrillTable is the agent's own block table. Nothing else writes it.
const DrillTable = "inet meridian_drill"

// DefaultDrillState is where the drill record is kept.
const DefaultDrillState = "/var/lib/meridian-host/drill.json"

// Bounds of a drill.
const (
	// DrillMinBlock / DrillMaxBlock bound BlockSeconds of an isolation.
	DrillMinBlock = 20
	DrillMaxBlock = 90
	// DrillReloadLimit bounds the restart of meridian.service in a reload
	// drill (seconds).
	DrillReloadLimit = 120
	// DrillSafetyMargin is added to BlockSeconds for the kernel timeout of
	// the blocked addresses (seconds).
	DrillSafetyMargin = 15
	// DrillRecoverPasses, DrillLoopInterval and DrillCooldown mirror the
	// failover loop (compile/upstream.go: RECOVERS_NEED, sleep, COOLDOWN):
	// an evicted relay or a switched path comes back only after that many
	// passing rounds and the cooldown since the last switch.
	DrillRecoverPasses = 5
	DrillLoopInterval  = 5
	DrillCooldown      = 120
	// DrillVerifyWait is how long a restore waits for the host to equal the
	// snapshot before it re-activates the data plane (seconds). It covers
	// the loop's own recovery (5 passes + 120 s cooldown, about four
	// minutes measured on a real gateway) with margin: no re-activation
	// fires while the loop is still bringing the relay back by itself.
	DrillVerifyWait = 360
	// DrillFallbackWait is the wait after that re-activation (seconds).
	DrillFallbackWait = 90
	// DrillRetryWait is the shortest wait of a retry or of a restore after
	// a failed change (seconds); drillRecoveryWait extends it to the end of
	// the loop's recovery window.
	DrillRetryWait = 30
	// DrillUpstreamFresh: an isolation starts only when the failover loop
	// wrote its record within this many seconds (it is what will react).
	DrillUpstreamFresh = 60
	// DrillBackupHandshake: with a single-relay record the backup path
	// counts as usable when its tunnel shook hands within this many seconds.
	DrillBackupHandshake = 180
	// MaxPathInterfaces bounds a path check.
	MaxPathInterfaces = 16
)

// Phases of a drill record.
const (
	// DrillPrepared: the snapshot and the plan are on disk, the host has
	// not been changed yet (or the agent stopped before it recorded that).
	DrillPrepared = "prepared"
	// DrillActive: the change is in place.
	DrillActive = "active"
	// DrillRestoring: the restore is running.
	DrillRestoring = "restoring"
	// DrillRestored: the block is gone and the host equals the snapshot.
	DrillRestored = "restored"
	// DrillRestoreFailed: the restore could not be verified. Blocks every
	// new change until a retry verifies it or it is released.
	DrillRestoreFailed = "restore_failed"
	// DrillReleased: an operator released a failed restore. The host was
	// not verified equal to the snapshot; this is never "restored".
	DrillReleased = "released"
)

// Outcomes of what the drill observed (independent of the restore).
const (
	DrillMet      = "met"       // the expected reaction was observed
	DrillNotMet   = "not_met"   // the drill ran, the reaction was not observed
	DrillPartial  = "partial"   // part of it (see Observed)
	DrillAborted  = "aborted"   // cancelled or interrupted before a conclusion
	DrillFailedOp = "op_failed" // a step of the drill itself failed
)

// DrillRequest is the whole parameter set of a drill.
type DrillRequest struct {
	RequestID string `json:"request_id"`
	Kind      string `json:"kind"`
	// Interfaces are the tunnel interfaces to isolate: exactly one for
	// DrillRelayIsolation, every relay of the main path for
	// DrillHubIsolation, none for DrillFirewallReload.
	Interfaces []string `json:"interfaces,omitempty"`
	// BackupInterface is the backup hub's tunnel (DrillHubIsolation only):
	// the agent starts only when that path is usable.
	BackupInterface string `json:"backup_interface,omitempty"`
	// BlockSeconds is how long an isolation lasts.
	BlockSeconds int `json:"block_seconds,omitempty"`
	// Fingerprint is the configuration fingerprint the operator's
	// confirmation was bound to (recorded with the drill, 64 hex digits).
	Fingerprint string `json:"fingerprint"`
}

var (
	drillIfaceRe = regexp.MustCompile(`^m[0-9]{2,3}w?$`)
	drillFPRe    = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

// ValidateDrill checks a request completely before anything is read or
// changed on the host.
func ValidateDrill(req DrillRequest) error {
	if !requestIDRe.MatchString(req.RequestID) {
		return errors.New("request_id 不合法")
	}
	if !drillFPRe.MatchString(req.Fingerprint) {
		return errors.New("fingerprint 必须是 64 位十六进制的配置指纹")
	}
	tunnels := func(names []string) error {
		return uniq("interface", names, func(s string) bool { return drillIfaceRe.MatchString(s) && ValidInterface(s) })
	}
	switch req.Kind {
	case DrillFirewallReload:
		if len(req.Interfaces) != 0 || req.BackupInterface != "" || req.BlockSeconds != 0 {
			return errors.New("防火墙重载演练不接受任何目标或时长")
		}
		return nil
	case DrillRelayIsolation:
		if len(req.Interfaces) != 1 {
			return errors.New("中继隔离演练只接受一个中继隧道接口")
		}
		if req.BackupInterface != "" {
			return errors.New("中继隔离演练不接受备用接口")
		}
	case DrillHubIsolation:
		if len(req.Interfaces) < 1 || len(req.Interfaces) > MaxUpstreamRelays {
			return errors.New("主枢纽隔离演练要列出主链路的全部中继隧道接口")
		}
		if !drillIfaceRe.MatchString(req.BackupInterface) || !ValidInterface(req.BackupInterface) {
			return errors.New("主枢纽隔离演练要指明备用枢纽的隧道接口")
		}
		if contains(req.Interfaces, req.BackupInterface) {
			return errors.New("备用接口不能同时是隔离目标")
		}
	default:
		return fmt.Errorf("不支持的演练 %q", req.Kind)
	}
	if err := tunnels(req.Interfaces); err != nil {
		return err
	}
	if req.BlockSeconds < DrillMinBlock || req.BlockSeconds > DrillMaxBlock {
		return fmt.Errorf("block_seconds 必须在 %d 到 %d 之间", DrillMinBlock, DrillMaxBlock)
	}
	return nil
}

// DrillUpstream is the part of the upstream record a drill compares.
type DrillUpstream struct {
	Version int               `json:"version"`
	Path    string            `json:"path"`
	Iface   string            `json:"iface"`
	Hub     string            `json:"hub"`
	Tier    string            `json:"tier"`
	State   string            `json:"state"`
	Relays  []DrillRelayState `json:"relays,omitempty"`
}

// DrillRelayState is one relay as the upstream record shows it.
type DrillRelayState struct {
	ID     string `json:"id"`
	Iface  string `json:"iface"`
	Status string `json:"status"`
	// Reason is the controller's reason (retained_best marks the relay kept
	// in the set although below the floor).
	Reason string `json:"reason,omitempty"`
	Weight int    `json:"weight"`
}

// DrillSnapshot is the state a restore must bring back. Rule and route
// texts are kept as SHA-256 digests: the record holds no address.
type DrillSnapshot struct {
	TakenAt time.Time `json:"taken_at"`
	// Tables are the nft tables loaded ("inet meridian", …), sorted.
	Tables []string `json:"tables"`
	// Rules is, per Meridian table, the digest of its rules without
	// counters and without set contents (nft -s -t list table).
	Rules map[string]string `json:"rules"`
	// PolicyRules are the digests of "ip -4 rule show" / "ip -6 rule show".
	PolicyRules map[string]string `json:"policy_rules"`
	// Routes is, per ledger route table and family ("102/4"), the digest of
	// its routes ("absent" when the table does not exist).
	Routes map[string]string `json:"routes"`
	// Links is, per ledger interface, up | down | absent.
	Links map[string]string `json:"links"`
	// Upstream is nil when the host has no upstream record.
	Upstream *DrillUpstream `json:"upstream,omitempty"`
}

// DrillObservation is one sample taken while the drill ran.
type DrillObservation struct {
	// AfterMS is the time since the change was applied.
	AfterMS int64  `json:"after_ms"`
	Summary string `json:"summary"`
}

// DrillRecord is the persisted state of one drill.
type DrillRecord struct {
	ID              string        `json:"id"`
	Kind            string        `json:"kind"`
	Interfaces      []string      `json:"interfaces,omitempty"`
	BackupInterface string        `json:"backup_interface,omitempty"`
	BlockSeconds    int           `json:"block_seconds,omitempty"`
	Fingerprint     string        `json:"fingerprint"`
	Phase           string        `json:"phase"`
	StartedAt       time.Time     `json:"started_at"`
	ChangedAt       *time.Time    `json:"changed_at,omitempty"`
	Deadline        time.Time     `json:"deadline"`
	RestoreDeadline time.Time     `json:"restore_deadline"`
	FinishedAt      *time.Time    `json:"finished_at,omitempty"`
	Snapshot        DrillSnapshot `json:"snapshot"`
	// Plan is the restore plan, written before the change.
	Plan []string `json:"plan"`
	// Blocked is how many addresses the block covers (never which).
	Blocked int `json:"blocked,omitempty"`
	// Expect is what the drill looks for; Outcome whether it was seen;
	// Observed the samples (changes only) and Findings the conclusions.
	Expect   string             `json:"expect"`
	Outcome  string             `json:"outcome,omitempty"`
	Observed []DrillObservation `json:"observed,omitempty"`
	Findings []string           `json:"findings,omitempty"`
	Steps    []Step             `json:"steps,omitempty"`
	// Trigger is why the restore started: deadline, cancel, failure,
	// startup, retry.
	Trigger string `json:"trigger,omitempty"`
	// OwnChangeCleared: the block table was verified absent.
	OwnChangeCleared bool `json:"own_change_cleared"`
	// Reactivated: the restore had to re-activate the data plane.
	Reactivated bool `json:"reactivated,omitempty"`
	// Residual lists what still differs from the snapshot. Never empty in
	// DrillRestoreFailed.
	Residual []string `json:"residual,omitempty"`
	Attempts int      `json:"attempts,omitempty"`
	Error    string   `json:"error,omitempty"`
}

// Unresolved reports whether the record still blocks new changes.
func (r *DrillRecord) Unresolved() bool {
	if r == nil {
		return false
	}
	switch r.Phase {
	case DrillRestored, DrillReleased:
		return false
	}
	return true
}

// DrillStatus is the agent's answer to every drill request.
type DrillStatus struct {
	// Record is the current or the last drill; nil when there never was one.
	Record *DrillRecord `json:"record,omitempty"`
	// Blocked: an unresolved record refuses new drills and host changes.
	Blocked bool `json:"blocked"`
	// Running: the drill or its restore is in progress in this agent.
	Running bool   `json:"running"`
	Error   string `json:"error,omitempty"`
}

// drillState is the agent's in-memory side of the record.
type drillState struct {
	mu      sync.Mutex
	loaded  bool
	loadErr error
	rec     *DrillRecord
	running bool
	cancel  chan struct{} // closed by a cancel request
}

func (a *Agent) drillPath() string { return a.DrillStatePath }

func (a *Agent) drillRulesPath() string {
	if a.DrillStatePath == "" {
		return ""
	}
	return filepath.Join(filepath.Dir(a.DrillStatePath), "drill.nft")
}

// drillSecond is one second of drill time (tests shorten it).
func (a *Agent) drillSecond() time.Duration {
	if a.DrillSecond > 0 {
		return a.DrillSecond
	}
	return time.Second
}

func (a *Agent) drillPoll() time.Duration {
	if a.DrillPoll > 0 {
		return a.DrillPoll
	}
	return 5 * time.Second
}

// drillLoad reads the record once. A record that cannot be read blocks
// (the agent cannot tell whether a block is still loaded).
func (a *Agent) drillLoad() {
	d := &a.drill
	if d.loaded {
		return
	}
	d.loaded = true
	if a.drillPath() == "" {
		return
	}
	b, err := os.ReadFile(a.drillPath())
	if errors.Is(err, os.ErrNotExist) {
		return
	}
	if err != nil {
		d.loadErr = fmt.Errorf("读不到演练记录：%w", err)
		return
	}
	var rec DrillRecord
	if err := json.Unmarshal(b, &rec); err != nil {
		d.loadErr = fmt.Errorf("演练记录损坏：%w", err)
		return
	}
	d.rec = &rec
}

func (a *Agent) drillSave(rec *DrillRecord) error {
	if a.drillPath() == "" {
		return nil
	}
	if a.DrillSaveFault != nil {
		if err := a.DrillSaveFault(rec.Phase); err != nil {
			return err
		}
	}
	b, err := json.MarshalIndent(rec, "", "  ")
	if err != nil {
		return err
	}
	return writeFileAtomic(a.drillPath(), b, 0o600)
}

// drillGate refuses a new change while a drill is unresolved.
func (a *Agent) drillGate() error {
	d := &a.drill
	d.mu.Lock()
	defer d.mu.Unlock()
	a.drillLoad()
	if d.loadErr != nil {
		return fmt.Errorf("拒绝：%v；先在宿主上确认 %s 没有加载并处理记录文件", d.loadErr, DrillTable)
	}
	if d.rec.Unresolved() {
		if d.rec.Phase == DrillRestoreFailed {
			return fmt.Errorf("拒绝：演练 %s 的恢复没有核验通过（%s），先在「验收」页重试恢复", d.rec.ID, strings.Join(d.rec.Residual, "；"))
		}
		return fmt.Errorf("拒绝：演练 %s 正在进行或恢复中（阶段 %s），等它结束", d.rec.ID, d.rec.Phase)
	}
	return nil
}

// status returns a copy of the record.
func (a *Agent) drillStatusLocked() DrillStatus {
	d := &a.drill
	a.drillLoad()
	st := DrillStatus{Running: d.running}
	if d.loadErr != nil {
		st.Blocked, st.Error = true, d.loadErr.Error()
		return st
	}
	if d.rec != nil {
		cp := *d.rec
		cp.Observed = append([]DrillObservation(nil), d.rec.Observed...)
		cp.Steps = append([]Step(nil), d.rec.Steps...)
		cp.Findings = append([]string(nil), d.rec.Findings...)
		cp.Residual = append([]string(nil), d.rec.Residual...)
		st.Record = &cp
		st.Blocked = cp.Unresolved()
	}
	return st
}

// DrillStatus reports the current or the last drill.
func (a *Agent) DrillStatus() DrillStatus {
	a.init()
	a.drill.mu.Lock()
	defer a.drill.mu.Unlock()
	return a.drillStatusLocked()
}

// RecoverDrills restores a drill an earlier agent process left unfinished.
// main calls it before serving; every request path calls it too (through
// init), so nothing is changed on the host before it has started. It
// returns at once: the restore runs in the background holding the action
// lock, and the gate refuses changes until it has ended.
func (a *Agent) RecoverDrills() {
	a.init()
}

func (a *Agent) drillRecoverOnStart() {
	d := &a.drill
	d.mu.Lock()
	a.drillLoad()
	rec := d.rec
	need := d.loadErr == nil && rec != nil && (rec.Phase == DrillPrepared || rec.Phase == DrillActive || rec.Phase == DrillRestoring)
	if need {
		d.running = true
	}
	d.mu.Unlock()
	if !need {
		return
	}
	a.sem <- struct{}{} // nothing else can hold it yet: init runs once, first
	a.beginAction()
	go func() {
		defer a.drillDone()
		a.drillRestore(rec, "startup", time.Duration(DrillVerifyWait)*a.drillSecond())
	}()
}

// ---------------------------------------------------------------- reads ---

func digest(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

// normText drops trailing blanks and empty lines, so a digest does not
// depend on them.
func normText(s string) string {
	var out []string
	for _, l := range strings.Split(s, "\n") {
		l = strings.TrimRight(l, " \t\r")
		if l != "" {
			out = append(out, l)
		}
	}
	return strings.Join(out, "\n")
}

var (
	shareMapRe   = regexp.MustCompile(`map \{[^{}]*\}`)
	shareRangeRe = regexp.MustCompile(`^\d+(?:-\d+)?\s*:\s*`)
)

// normShareMaps drops the ranges of the relay-sharing maps (compile/share.go:
// "map { 0-473 : 0x…, 474-999 : 0x… }" in relay_assign and relay_redirect)
// so that a rules digest does not change with the weights the quality
// controller moves on its own. Which marks carry traffic is kept (sorted):
// a relay that no longer gets new connections is still a difference.
func normShareMaps(s string) string {
	return shareMapRe.ReplaceAllStringFunc(s, func(m string) string {
		inner := strings.TrimSuffix(strings.TrimPrefix(m, "map {"), "}")
		var els []string
		for _, el := range strings.Split(inner, ",") {
			el = strings.TrimSpace(el)
			if el == "" {
				continue
			}
			if !shareRangeRe.MatchString(el) {
				return m // not a weight map: keep as is
			}
			els = append(els, shareRangeRe.ReplaceAllString(el, ""))
		}
		sort.Strings(els)
		return "map { " + strings.Join(els, ", ") + " }"
	})
}

var nftTableListRe = regexp.MustCompile(`^table (inet|ip|ip6|arp|bridge|netdev) ([A-Za-z0-9_.-]{1,64})$`)

// nftTables lists the loaded nft tables ("inet meridian", …).
func (x *run) nftTables() ([]string, error) {
	out, err := x.cmd(x.a.StepTimeout, "nft", "list", "tables")
	if err != nil {
		return nil, fmt.Errorf("nft list tables 失败：%s", clip(firstLine(err.Error()+" "+out)))
	}
	var tabs []string
	for _, l := range strings.Split(out, "\n") {
		l = strings.TrimSpace(l)
		if l == "" {
			continue
		}
		m := nftTableListRe.FindStringSubmatch(l)
		if m == nil {
			return nil, errors.New("nft list tables 的输出无法解析")
		}
		tabs = append(tabs, m[1]+" "+m[2])
	}
	sort.Strings(tabs)
	return tabs, nil
}

func linkState(out string, err error) string {
	if err != nil {
		return "absent"
	}
	if i := strings.IndexByte(out, '<'); i >= 0 {
		if j := strings.IndexByte(out[i:], '>'); j > 0 {
			for _, f := range strings.Split(out[i+1:i+j], ",") {
				if f == "UP" {
					return "up"
				}
			}
		}
	}
	return "down"
}

func drillUpstreamOf(st UpstreamStatus) (*DrillUpstream, error) {
	if !st.Present {
		return nil, nil
	}
	if st.Record == nil {
		return nil, errors.New("上游记录读不出来：" + st.Error)
	}
	r := st.Record
	u := &DrillUpstream{Version: r.Version, Path: r.Path, Iface: r.Iface, Hub: r.Hub, Tier: r.Tier, State: r.State}
	for _, rl := range r.Relays {
		u.Relays = append(u.Relays, DrillRelayState{ID: rl.ID, Iface: rl.Iface, Status: rl.Status, Reason: rl.Reason, Weight: rl.Weight})
	}
	return u, nil
}

// drillSnapshot reads the state a restore compares. Read-only commands with
// fixed arguments; interface and table names come from the ledger.
func (a *Agent) drillSnapshot(ctx context.Context) (DrillSnapshot, error) {
	x := &run{a: a, ctx: ctx}
	snap := DrillSnapshot{TakenAt: time.Now().UTC(), Rules: map[string]string{}, PolicyRules: map[string]string{}, Routes: map[string]string{}, Links: map[string]string{}}
	if err := a.ledger.load(); err != nil {
		return snap, err
	}
	tabs, err := x.nftTables()
	if err != nil {
		return snap, err
	}
	snap.Tables = tabs
	for _, t := range tabs {
		if !nftTables[t] {
			continue
		}
		fam, name, _ := strings.Cut(t, " ")
		out, err := x.cmd(a.StepTimeout, "nft", "-s", "-t", "list", "table", fam, name)
		if err != nil {
			return snap, fmt.Errorf("读不到 nft 表 %s：%s", t, clip(firstLine(err.Error())))
		}
		snap.Rules[t] = digest(normShareMaps(normText(out)))
	}
	for _, fam := range []string{"-4", "-6"} {
		out, err := x.cmd(a.StepTimeout, "ip", fam, "rule", "show")
		if err != nil {
			return snap, fmt.Errorf("读不到策略规则（ip %s rule show）：%s", fam, clip(firstLine(err.Error())))
		}
		snap.PolicyRules[fam[1:]] = digest(normText(out))
	}
	led := a.ledger.data
	for _, n := range led.RouteTables {
		for _, fam := range []string{"-4", "-6"} {
			key := fmt.Sprintf("%d/%s", n, fam[1:])
			out, err := x.cmd(a.StepTimeout, "ip", fam, "route", "show", "table", fmt.Sprint(n))
			if err != nil {
				snap.Routes[key] = "absent"
				continue
			}
			snap.Routes[key] = digest(normText(out))
		}
	}
	for _, i := range led.Interfaces {
		out, err := x.cmd(a.StepTimeout, "ip", "-o", "link", "show", "dev", i)
		snap.Links[i] = linkState(out, err)
	}
	up, err := drillUpstreamOf(a.UpstreamStatus(ctx))
	if err != nil {
		return snap, err
	}
	snap.Upstream = up
	return snap, ctx.Err()
}

func stateEquals(want, got string) bool {
	// "static" is the install's own record before the loop measured
	// anything: a measured "ok" restores it.
	return want == got || (want == UpstreamStatic && got == UpstreamOK)
}

// relayStatusEquals: a relay is back to its state before the drill only
// when its status is exactly the same (active stays active). A relay that is
// still recovering (ramping back up) or reduced is not back yet; the verify
// wait (DrillVerifyWait) covers the measured recovering→active ramp. Only
// weights are ignored (drillWeightNotes records them).
func relayStatusEquals(want, got string) bool {
	return want == got
}

// relayRetained is pathquality.ReasonRetained (the record's reason token).
const relayRetained = "retained_best"

func dashIfEmpty(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

// drillDiff lists how now differs from the snapshot. Empty means equal.
func drillDiff(want, now DrillSnapshot) []string {
	var out []string
	if strings.Join(want.Tables, ",") != strings.Join(now.Tables, ",") {
		out = append(out, fmt.Sprintf("nft 表不同：演练前 [%s]，现在 [%s]", strings.Join(want.Tables, "、"), strings.Join(now.Tables, "、")))
	}
	for _, t := range sortedKeys(want.Rules) {
		if got, ok := now.Rules[t]; ok && got != want.Rules[t] {
			out = append(out, "nft 表 "+t+" 的规则与演练前不同")
		}
	}
	for _, f := range sortedKeys(want.PolicyRules) {
		if now.PolicyRules[f] != want.PolicyRules[f] {
			out = append(out, "IPv"+f+" 策略规则（ip rule）与演练前不同")
		}
	}
	for _, k := range sortedKeys(want.Routes) {
		if now.Routes[k] != want.Routes[k] {
			tbl, fam, _ := strings.Cut(k, "/")
			out = append(out, fmt.Sprintf("路由表 %s（IPv%s）与演练前不同", tbl, fam))
		}
	}
	for _, i := range sortedKeys(want.Links) {
		if now.Links[i] != want.Links[i] {
			out = append(out, fmt.Sprintf("接口 %s：演练前 %s，现在 %s", i, want.Links[i], now.Links[i]))
		}
	}
	switch {
	case want.Upstream == nil && now.Upstream == nil:
	case want.Upstream == nil || now.Upstream == nil:
		out = append(out, "上游记录的有无与演练前不同")
	default:
		w, n := want.Upstream, now.Upstream
		if w.Path != n.Path || w.Iface != n.Iface || w.Hub != n.Hub || w.Tier != n.Tier {
			out = append(out, fmt.Sprintf("承载路径：演练前 %s/%s 经 %s（%s），现在 %s/%s 经 %s（%s）", w.Path, w.Iface, w.Hub, w.Tier, n.Path, n.Iface, n.Hub, n.Tier))
		}
		if !stateEquals(w.State, n.State) {
			out = append(out, fmt.Sprintf("上游状态：演练前 %s，现在 %s", w.State, n.State))
		}
		got := map[string]DrillRelayState{}
		for _, r := range n.Relays {
			got[r.ID] = r
		}
		for _, r := range w.Relays {
			g, ok := got[r.ID]
			switch {
			case !ok:
				out = append(out, "中继 "+r.ID+" 不在上游记录里了")
			case g.Iface != r.Iface:
				out = append(out, fmt.Sprintf("中继 %s：演练前经 %s，现在经 %s", r.ID, r.Iface, g.Iface))
			case (r.Reason == relayRetained) != (g.Reason == relayRetained):
				// reduced-and-retained (every relay below the floor) is not
				// the same state as reduced in a healthy set.
				out = append(out, fmt.Sprintf("中继 %s：演练前 %s/%s，现在 %s/%s", r.ID, r.Status, dashIfEmpty(r.Reason), g.Status, dashIfEmpty(g.Reason)))
			case !relayStatusEquals(r.Status, g.Status):
				// Weights are not compared: the quality controller moves
				// them on its own (drillWeightNotes records them).
				out = append(out, fmt.Sprintf("中继 %s：演练前 %s，现在 %s", r.ID, r.Status, g.Status))
			}
		}
		if len(n.Relays) != len(w.Relays) {
			out = append(out, fmt.Sprintf("中继数量：演练前 %d，现在 %d", len(w.Relays), len(n.Relays)))
		}
	}
	return out
}

// drillWeightNotes lists relay weights that differ from the snapshot. They
// are observations only, never a restore difference.
func drillWeightNotes(want, now DrillSnapshot) []string {
	if want.Upstream == nil || now.Upstream == nil {
		return nil
	}
	got := map[string]int{}
	for _, r := range now.Upstream.Relays {
		got[r.ID] = r.Weight
	}
	status := map[string]string{}
	for _, r := range now.Upstream.Relays {
		status[r.ID] = r.Status
	}
	var out []string
	for _, r := range want.Upstream.Relays {
		if st, ok := status[r.ID]; ok && st != r.Status {
			out = append(out, fmt.Sprintf("中继 %s 状态：演练前 %s，现在 %s（须回到演练前状态才算恢复）", r.ID, r.Status, st))
		}
		if w, ok := got[r.ID]; ok && w != r.Weight {
			out = append(out, fmt.Sprintf("中继 %s 权重：演练前 %d，恢复后 %d（质量控制器动态调整，不作为恢复判据）", r.ID, r.Weight, w))
		}
	}
	return out
}

func sortedKeys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// ----------------------------------------------------------- endpoints ---

// parseEndpoints parses "wg show <if> endpoints": "<public key>\t<addr:port>"
// per line, "(none)" for a peer without one. Only the addresses are kept.
func parseEndpoints(out string) ([]netip.Addr, error) {
	var addrs []netip.Addr
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		f := strings.Fields(line)
		if len(f) != 2 || !validWGKey(f[0]) {
			return nil, errors.New("endpoints 输出无法解析")
		}
		if f[1] == "(none)" {
			continue
		}
		ap, err := netip.ParseAddrPort(f[1])
		if err != nil {
			return nil, errors.New("endpoints 输出无法解析")
		}
		addrs = append(addrs, ap.Addr().Unmap().WithZone(""))
	}
	return addrs, nil
}

// blockable: an address the block may name. Loopback (a tunnel carried by
// the local WSS client), unspecified, link-local and multicast addresses
// and Meridian's own tunnel ranges are never blocked.
func blockable(ad netip.Addr) bool {
	if !ad.IsValid() || ad.IsLoopback() || ad.IsUnspecified() || ad.IsMulticast() || ad.IsLinkLocalUnicast() || ad.IsLinkLocalMulticast() {
		return false
	}
	return !tunnelULA.Contains(ad) && !tunnel4.Contains(ad)
}

var tunnel4 = netip.MustParsePrefix("10.66.0.0/16")

// drillRules renders the block table. The agent builds every byte of it.
func drillRules(addrs []netip.Addr, timeoutSeconds int) string {
	var v4, v6 []string
	for _, ad := range addrs {
		el := fmt.Sprintf("%s timeout %ds", ad, timeoutSeconds)
		if ad.Is4() {
			v4 = append(v4, el)
		} else {
			v6 = append(v6, el)
		}
	}
	set := func(name, typ string, els []string) string {
		s := "\tset " + name + " {\n\t\ttype " + typ + "\n\t\tflags timeout\n"
		if len(els) > 0 {
			s += "\t\telements = { " + strings.Join(els, ", ") + " }\n"
		}
		return s + "\t}\n"
	}
	fam, name, _ := strings.Cut(DrillTable, " ")
	return "# written by meridian-host for one acceptance drill; removed when it ends\n" +
		"table " + fam + " " + name + " {\n" +
		set("block4", "ipv4_addr", v4) + set("block6", "ipv6_addr", v6) +
		"\tchain out {\n\t\ttype filter hook output priority 0; policy accept;\n" +
		"\t\tip daddr @block4 counter drop\n\t\tip6 daddr @block6 counter drop\n\t}\n}\n"
}

// ------------------------------------------------------------- starting ---

// drillPrecheck validates an isolation against the host's own state and
// returns the addresses to block.
func (a *Agent) drillPrecheck(ctx context.Context, req DrillRequest, snap DrillSnapshot) ([]netip.Addr, error) {
	x := &run{a: a, ctx: ctx}
	led := a.ledger.data
	for _, i := range append(append([]string(nil), req.Interfaces...), req.BackupInterface) {
		if i != "" && !contains(led.Interfaces, i) {
			return nil, fmt.Errorf("接口 %s 不在宿主的受管清单里（从未由 Meridian 激活）", i)
		}
	}
	if a.drillRulesPath() == "" {
		return nil, errors.New("agent 没有演练状态目录，隔离演练不可用")
	}
	st := a.UpstreamStatus(ctx)
	if !st.Present || st.Record == nil {
		return nil, errors.New("网关没有可读的上游记录（" + UpstreamStateFile + "）：没有故障切换循环可以观察，演练没有开始")
	}
	rec := st.Record
	if age := time.Now().Unix() - rec.Beat; age > DrillUpstreamFresh || age < -DrillUpstreamFresh {
		return nil, fmt.Errorf("上游记录的心跳已经 %d 秒没有更新：故障切换循环不在运行，演练没有开始", age)
	}
	if rec.Tier != "primary" || rec.Path == "backup" {
		return nil, errors.New("网关现在不在主链路上（已由备用枢纽承载）：演练没有开始")
	}
	if rec.State != UpstreamOK {
		return nil, fmt.Errorf("上游状态是 %s，不是 ok：演练没有开始", rec.State)
	}
	carrying := func(r UpstreamRelay) bool { return (r.Status == "active" || r.Status == "reduced") && r.Weight > 0 }
	switch req.Kind {
	case DrillRelayIsolation:
		if rec.Version != 2 {
			return nil, errors.New("这台网关只有一个中继：剔除它就是主枢纽隔离，请改用主枢纽隔离演练")
		}
		target, others := false, 0
		for _, r := range rec.Relays {
			switch {
			case r.Iface == req.Interfaces[0]:
				if !carrying(r) {
					return nil, fmt.Errorf("中继 %s 现在是 %s，没有在分担：演练没有开始", r.ID, r.Status)
				}
				target = true
			case carrying(r):
				others++
			}
		}
		if !target {
			return nil, fmt.Errorf("接口 %s 不是上游记录里任何中继的隧道", req.Interfaces[0])
		}
		if others == 0 {
			return nil, errors.New("没有另一个在分担的中继：隔离它会中断全部境外流量，演练没有开始")
		}
	case DrillHubIsolation:
		var want []string
		if rec.Version == 2 {
			for _, r := range rec.Relays {
				if r.Status != "disabled" {
					want = append(want, r.Iface)
				}
			}
			if rec.Backup == nil || rec.Backup.Iface != req.BackupInterface {
				return nil, errors.New("上游记录里没有这个备用枢纽接口：没有备用路径，演练没有开始")
			}
			if rec.Backup.Grade == "down" || rec.Backup.Grade == "none" {
				return nil, fmt.Errorf("备用枢纽现在的质量是 %s：隔离主枢纽会中断全部境外流量，演练没有开始", rec.Backup.Grade)
			}
		} else {
			want = []string{rec.Iface}
			if snap.Links[req.BackupInterface] != "up" {
				return nil, errors.New("备用枢纽的隧道接口不在或没有启用：演练没有开始")
			}
			out, err := x.cmd(a.StepTimeout, "wg", "show", req.BackupInterface, "latest-handshakes")
			if err != nil {
				return nil, errors.New("读不到备用枢纽隧道的握手：演练没有开始")
			}
			hs, err := ParseLatestHandshakes(out)
			if err != nil {
				return nil, err
			}
			fresh := false
			for _, v := range hs {
				fresh = fresh || (v > 0 && time.Now().Unix()-v <= DrillBackupHandshake)
			}
			if !fresh {
				return nil, fmt.Errorf("备用枢纽的隧道 %d 秒内没有握手：隔离主枢纽会中断全部境外流量，演练没有开始", DrillBackupHandshake)
			}
		}
		got := sortedCopy(req.Interfaces)
		sort.Strings(want)
		if strings.Join(got, ",") != strings.Join(want, ",") {
			return nil, fmt.Errorf("隔离目标必须正好是主链路的全部中继隧道（%s）", strings.Join(want, "、"))
		}
	}
	var addrs []netip.Addr
	seen := map[netip.Addr]bool{}
	for _, i := range req.Interfaces {
		out, err := x.cmd(a.StepTimeout, "wg", "show", i, "endpoints")
		if err != nil {
			return nil, fmt.Errorf("读不到 %s 的隧道端点：%s", i, clip(firstLine(err.Error())))
		}
		eps, err := parseEndpoints(out)
		if err != nil {
			return nil, err
		}
		n := 0
		for _, ad := range eps {
			if !blockable(ad) {
				continue
			}
			n++
			if !seen[ad] {
				seen[ad] = true
				addrs = append(addrs, ad)
			}
		}
		if n == 0 {
			return nil, fmt.Errorf("隧道 %s 没有可隔离的公网端点（经本机 WSS 承载的隧道端点在回环上）：这条链路的演练要人工做", i)
		}
	}
	if req.BackupInterface != "" {
		if out, err := x.cmd(a.StepTimeout, "wg", "show", req.BackupInterface, "endpoints"); err == nil {
			if eps, err := parseEndpoints(out); err == nil {
				for _, ad := range eps {
					if seen[ad] {
						return nil, errors.New("备用枢纽与被隔离的中继共用一个端点地址：隔离会同时切断备用路径，演练没有开始")
					}
				}
			}
		}
	}
	return addrs, nil
}

func drillPlan(kind string) (expect string, plan []string) {
	switch kind {
	case DrillFirewallReload:
		return "重载期间兜底表 " + GuardTable + " 一直加载，没有出现「转发开着而两张表都不在」的采样",
			[]string{
				"核对 nft 表及规则、策略规则、路由表、接口和上游记录与演练前的快照一致",
				"不一致时经 meridian.service 重新激活数据面（与 RestoreDataPlane 相同的步骤），再核对一次",
				"仍不一致：记录保持「恢复未核验」，列出差异，拒绝新的演练和宿主变更",
			}
	case DrillRelayIsolation:
		expect = "被隔离的中继被剔除（权重降为 0、状态 evicted），承载路径仍是主链路"
	default:
		expect = "承载路径切到备用枢纽"
	}
	return expect, []string{
		"删除演练阻断表 " + DrillTable + "（表里的地址另有内核超时，agent 不在也会失效）并确认它不在了",
		"等待网关的故障切换循环回到演练前的状态，核对 nft 表及规则、策略规则、路由表、接口和上游记录（路径、枢纽、每个中继的状态；权重由质量控制器动态调整，只记录不比较）与快照一致；被隔离的中继要重新 active，等待覆盖故障切换循环的恢复（连续 5 次成功 + 120 秒冷却）",
		"到时仍不一致：经 meridian.service 重新激活数据面（与 RestoreDataPlane 相同的步骤），再核对一次",
		"仍不一致：记录保持「恢复未核验」，列出差异，拒绝新的演练和宿主变更",
	}
}

// DrillStart validates and starts one drill. 200: started (the record says
// how far it got); 400: refused request; 409: a precondition of the host
// does not hold or another drill is unresolved; 503: the agent is busy.
func (a *Agent) DrillStart(ctx context.Context, req DrillRequest) (DrillStatus, int) {
	a.init()
	if err := ValidateDrill(req); err != nil {
		return DrillStatus{Error: err.Error()}, http.StatusBadRequest
	}
	if err := a.drillGate(); err != nil {
		st := a.DrillStatus()
		st.Error = err.Error()
		return st, http.StatusConflict
	}
	select {
	case a.sem <- struct{}{}:
	default:
		return DrillStatus{Error: "宿主正在执行另一个动作（安装、回滚或撤回），演练没有开始"}, http.StatusServiceUnavailable
	}
	release := func() { <-a.sem }
	// Again under the lock: another start may have won.
	if err := a.drillGate(); err != nil {
		release()
		st := a.DrillStatus()
		st.Error = err.Error()
		return st, http.StatusConflict
	}
	refuse := func(err error) (DrillStatus, int) {
		release()
		st := a.DrillStatus()
		st.Error = err.Error()
		return st, http.StatusConflict
	}
	if err := a.ledger.load(); err != nil {
		return refuse(err)
	}
	rctx, cancel := context.WithTimeout(ctx, 2*a.StepTimeout)
	defer cancel()
	x := &run{a: a, ctx: rctx}
	if _, err := x.cmd(a.StepTimeout, "systemctl", "is-active", "--quiet", coreUnit); err != nil {
		return refuse(errors.New(coreUnit + " 没有在运行：网关数据面没有安装或已撤回，演练没有开始"))
	}
	snap, err := a.drillSnapshot(rctx)
	if err != nil {
		return refuse(fmt.Errorf("读不到演练前的状态，宿主没有改动：%w", err))
	}
	if contains(snap.Tables, DrillTable) {
		return refuse(errors.New("宿主上已经有 " + DrillTable + "（上一次演练的残留）：先恢复它"))
	}
	for _, t := range []string{"inet meridian", GuardTable} {
		if !contains(snap.Tables, t) {
			return refuse(fmt.Errorf("nft 表 %s 没有加载：数据面不完整，演练没有开始", t))
		}
	}
	var addrs []netip.Addr
	if req.Kind != DrillFirewallReload {
		if addrs, err = a.drillPrecheck(rctx, req, snap); err != nil {
			return refuse(err)
		}
	}
	now := time.Now().UTC()
	sec := a.drillSecond()
	block := time.Duration(req.BlockSeconds) * sec
	if req.Kind == DrillFirewallReload {
		block = time.Duration(DrillReloadLimit) * sec
	}
	expect, plan := drillPlan(req.Kind)
	rec := &DrillRecord{
		ID: req.RequestID, Kind: req.Kind, Interfaces: req.Interfaces, BackupInterface: req.BackupInterface,
		BlockSeconds: req.BlockSeconds, Fingerprint: req.Fingerprint, Phase: DrillPrepared,
		StartedAt: now, Deadline: now.Add(block), RestoreDeadline: now.Add(block + time.Duration(DrillVerifyWait)*sec),
		Snapshot: snap, Plan: plan, Expect: expect, Blocked: len(addrs),
	}
	// The record is on disk before the host changes.
	if err := a.drillSave(rec); err != nil {
		return refuse(fmt.Errorf("演练记录写不下去，宿主没有改动：%w", err))
	}
	d := &a.drill
	d.mu.Lock()
	d.rec, d.running, d.cancel = rec, true, make(chan struct{})
	stop := d.cancel
	d.mu.Unlock()
	a.beginAction()

	isReload := req.Kind == DrillFirewallReload
	if isReload {
		// Nothing is loaded for a reload: the restart itself is the change.
	} else if err := a.drillBlock(rctx, rec, addrs); err != nil {
		// Nothing, or an unknown part, was loaded: restore at once.
		a.drillUpdate(rec, func(r *DrillRecord) { r.Outcome, r.Error = DrillFailedOp, err.Error() })
		a.drillRestore(rec, "failure", a.drillRecoveryWait(rec))
		a.drillDone()
		return a.DrillStatus(), http.StatusOK
	}
	at := time.Now().UTC()
	a.drillUpdate(rec, func(r *DrillRecord) { r.Phase, r.ChangedAt = DrillActive, &at })
	if err := a.drillSave(rec); err != nil {
		// The change is in but cannot be recorded as such: take it out now
		// (the prepared record on disk already tells a restart to restore).
		a.drillUpdate(rec, func(r *DrillRecord) { r.Outcome, r.Error = DrillFailedOp, "演练记录写不下去："+err.Error() })
		a.drillRestore(rec, "failure", a.drillRecoveryWait(rec))
		a.drillDone()
		return a.DrillStatus(), http.StatusOK
	}
	go func() {
		defer a.drillDone()
		var trigger string
		if isReload {
			trigger = a.drillReload(rec, stop)
		} else {
			trigger = a.drillObserve(rec, stop)
		}
		a.drillRestore(rec, trigger, time.Duration(DrillVerifyWait)*sec)
	}()
	return a.DrillStatus(), http.StatusOK
}

// drillDone releases the action lock a drill held and only then reports
// it as no longer running, so a caller that sees "not running" can act.
func (a *Agent) drillDone() {
	a.endAction()
	<-a.sem
	a.drill.mu.Lock()
	a.drill.running = false
	a.drill.mu.Unlock()
}

func (a *Agent) drillUpdate(rec *DrillRecord, f func(*DrillRecord)) {
	a.drill.mu.Lock()
	f(rec)
	a.drill.mu.Unlock()
}

func (a *Agent) drillStep(rec *DrillRecord, name string, ok bool, detail string) {
	a.drillUpdate(rec, func(r *DrillRecord) { r.Steps = append(r.Steps, Step{Name: name, OK: ok, Detail: clip(detail)}) })
}

// drillBlock writes and loads the block table.
func (a *Agent) drillBlock(ctx context.Context, rec *DrillRecord, addrs []netip.Addr) error {
	x := &run{a: a, ctx: ctx}
	path := a.drillRulesPath()
	// The kernel timeout is in real seconds whatever the drill clock is.
	if err := writeFileAtomic(path, []byte(drillRules(addrs, rec.BlockSeconds+DrillSafetyMargin)), 0o600); err != nil {
		a.drillStep(rec, "write block rules", false, err.Error())
		return fmt.Errorf("写不了阻断规则文件：%w", err)
	}
	if out, err := x.cmd(a.StepTimeout, "nft", "-c", "-f", path); err != nil {
		a.drillStep(rec, "check block rules", false, err.Error()+"\n"+out)
		return errors.New("阻断规则没有通过 nft 的检查，没有加载")
	}
	if out, err := x.cmd(a.StepTimeout, "nft", "-f", path); err != nil {
		a.drillStep(rec, "load "+DrillTable, false, err.Error()+"\n"+out)
		return errors.New("阻断规则加载失败")
	}
	a.drillStep(rec, "load "+DrillTable, true, fmt.Sprintf("%d 个端点地址，内核超时 %d 秒", len(addrs), rec.BlockSeconds+DrillSafetyMargin))
	return nil
}

func (a *Agent) drillObserveOnce(rec *DrillRecord, since time.Time, summary string) {
	a.drillUpdate(rec, func(r *DrillRecord) {
		if n := len(r.Observed); n > 0 && r.Observed[n-1].Summary == summary {
			return
		}
		if len(r.Observed) >= 64 {
			return
		}
		r.Observed = append(r.Observed, DrillObservation{AfterMS: time.Since(since).Milliseconds(), Summary: summary})
	})
}

// drillObserve samples the upstream record until the block's deadline or a
// cancel, and concludes whether the expected reaction was seen.
func (a *Agent) drillObserve(rec *DrillRecord, stop <-chan struct{}) string {
	start := time.Now()
	deadline := time.NewTimer(time.Until(rec.Deadline))
	defer deadline.Stop()
	tick := time.NewTicker(a.drillPoll())
	defer tick.Stop()
	target := ""
	if rec.Kind == DrillRelayIsolation {
		target = rec.Interfaces[0]
	}
	var zeroAt, evictAt, backupAt, downAt time.Duration
	sample := func() {
		ctx, cancel := context.WithTimeout(context.Background(), a.StepTimeout)
		defer cancel()
		up, err := drillUpstreamOf(a.UpstreamStatus(ctx))
		if err != nil || up == nil {
			a.drillObserveOnce(rec, start, "上游记录读不出来")
			return
		}
		el := time.Since(start)
		if el <= 0 {
			el = 1
		}
		parts := []string{fmt.Sprintf("路径 %s 经 %s（%s），状态 %s", up.Path, up.Hub, up.Tier, up.State)}
		for _, r := range up.Relays {
			parts = append(parts, fmt.Sprintf("中继 %s %s 权重 %d", r.ID, r.Status, r.Weight))
			if r.Iface == target {
				if r.Weight == 0 && zeroAt == 0 {
					zeroAt = el
				}
				if r.Status == "evicted" && evictAt == 0 {
					evictAt = el
				}
			}
		}
		if (up.Path == "backup" || up.Tier == "backup") && backupAt == 0 {
			backupAt = el
		}
		if up.State == UpstreamDown && downAt == 0 {
			downAt = el
		}
		a.drillObserveOnce(rec, start, strings.Join(parts, "；"))
	}
	trigger := "deadline"
	sample()
loop:
	for {
		select {
		case <-stop:
			trigger = "cancel"
			break loop
		case <-deadline.C:
			sample()
			break loop
		case <-tick.C:
			sample()
		}
	}
	secs := func(d time.Duration) string {
		return fmt.Sprintf("%.0f 秒", float64(d)/float64(a.drillSecond()))
	}
	a.drillUpdate(rec, func(r *DrillRecord) {
		switch {
		case rec.Kind == DrillRelayIsolation && evictAt > 0 && backupAt == 0:
			r.Outcome = DrillMet
			r.Findings = append(r.Findings, "中继在阻断后约 "+secs(evictAt)+" 被剔除，承载路径一直是主链路")
		case rec.Kind == DrillRelayIsolation && zeroAt > 0 && backupAt == 0:
			r.Outcome = DrillPartial
			r.Findings = append(r.Findings, "中继的权重在约 "+secs(zeroAt)+" 降为 0，但在演练时长内没有看到状态变成 evicted")
		case rec.Kind == DrillRelayIsolation && backupAt > 0:
			r.Outcome = DrillNotMet
			r.Findings = append(r.Findings, "隔离一个中继后承载路径在约 "+secs(backupAt)+" 切到了备用枢纽：其余中继没有接住流量")
		case rec.Kind == DrillHubIsolation && backupAt > 0:
			r.Outcome = DrillMet
			r.Findings = append(r.Findings, "承载路径在阻断后约 "+secs(backupAt)+" 切到备用枢纽")
		case trigger == "cancel":
			r.Outcome = DrillAborted
			r.Findings = append(r.Findings, "演练在得出结论前被取消")
		default:
			r.Outcome = DrillNotMet
			r.Findings = append(r.Findings, "演练时长内没有看到预期的变化（"+r.Expect+"）")
		}
		if zeroAt > 0 && evictAt > 0 {
			r.Findings = append(r.Findings, "权重先在约 "+secs(zeroAt)+" 降为 0")
		}
		if downAt > 0 {
			r.Findings = append(r.Findings, "期间上游状态出现过 down（约 "+secs(downAt)+" 起）")
		}
	})
	return trigger
}

// procValue reads one /proc/sys value ("" when it cannot be read).
func (a *Agent) procValue(rel string) string {
	p := "/" + rel
	if a.PreflightRoot != "" {
		p = filepath.Join(a.PreflightRoot, rel)
	}
	b, err := os.ReadFile(p)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

// drillReload restarts meridian.service and samples the tables while it
// runs. A cancel cannot stop a restart that has begun; it only ends the
// sampling early.
func (a *Agent) drillReload(rec *DrillRecord, stop <-chan struct{}) string {
	start := time.Now()
	limit := time.Duration(DrillReloadLimit) * a.drillSecond()
	if a.UpTimeout > 0 && a.UpTimeout < limit {
		limit = a.UpTimeout
	}
	ctx, cancel := context.WithTimeout(context.Background(), limit+a.StepTimeout)
	defer cancel()
	x := &run{a: a, ctx: ctx}
	samples, guardGone, bothGone, unread := 0, 0, 0, 0
	sample := func(label string) {
		tabs, err := x.nftTables()
		samples++
		if err != nil {
			unread++
			a.drillObserveOnce(rec, start, label+"：nft 表读不出来")
			return
		}
		guard, main := contains(tabs, GuardTable), contains(tabs, "inet meridian")
		fwd6, fwd4 := a.procValue("proc/sys/net/ipv6/conf/all/forwarding"), a.procValue("proc/sys/net/ipv4/ip_forward")
		if !guard {
			guardGone++
		}
		if !guard && !main && (fwd6 == "1" || fwd4 == "1" || fwd6 == "" || fwd4 == "") {
			bothGone++
		}
		word := func(b bool) string {
			if b {
				return "在"
			}
			return "不在"
		}
		fw := func(v string) string {
			switch v {
			case "1":
				return "开"
			case "0":
				return "关"
			}
			return "读不到"
		}
		a.drillObserveOnce(rec, start, fmt.Sprintf("%s：兜底表%s，主表%s，转发 v4 %s / v6 %s", label, word(guard), word(main), fw(fwd4), fw(fwd6)))
	}
	sample("重载前")
	done := make(chan error, 1)
	go func() {
		_, _ = x.cmd(a.StepTimeout, "systemctl", "reset-failed", coreUnit)
		out, err := x.cmd(limit, "systemctl", "restart", coreUnit)
		if err != nil {
			err = fmt.Errorf("%v\n%s", err, out)
		}
		done <- err
	}()
	tick := time.NewTicker(a.drillSampleEvery())
	defer tick.Stop()
	trigger := "deadline"
	var rerr error
wait:
	for {
		select {
		case rerr = <-done:
			break wait
		case <-tick.C:
			sample("重载中")
		case <-stop:
			trigger = "cancel"
			rerr = <-done
			break wait
		}
	}
	sample("重载后")
	a.drillStep(rec, "restart "+coreUnit+"（meridian-up.sh）", rerr == nil, errText(rerr))
	a.drillUpdate(rec, func(r *DrillRecord) {
		r.Findings = append(r.Findings, fmt.Sprintf("重载用时约 %d 毫秒，采样 %d 次：兜底表不在 %d 次，「转发未确认关闭且两张表都不在」%d 次，读不出 %d 次", time.Since(start).Milliseconds(), samples, guardGone, bothGone, unread))
		switch {
		case rerr != nil:
			r.Outcome, r.Error = DrillFailedOp, "重启 "+coreUnit+" 失败："+clip(firstLine(rerr.Error()))
			trigger = "failure"
		case bothGone > 0 || guardGone > 0:
			r.Outcome = DrillNotMet
		case unread > 0:
			r.Outcome = DrillPartial
			r.Findings = append(r.Findings, "有采样读不出 nft 表，不能说每一次都看到了兜底表")
		default:
			r.Outcome = DrillMet
		}
		r.Findings = append(r.Findings, "这是宿主上的采样（间隔约 "+a.drillSampleEvery().String()+"），看不到两次采样之间的瞬间，也看不到客户端的包：客户端是否外泄要另做人工抓包")
	})
	return trigger
}

func (a *Agent) drillSampleEvery() time.Duration {
	if a.DrillSample > 0 {
		return a.DrillSample
	}
	return 250 * time.Millisecond
}

// ------------------------------------------------------------ restoring ---

// directDoer runs health and activate inside the agent, for a restore that
// already holds the action lock.
type directDoer struct{ a *Agent }

func (d directDoer) Do(ctx context.Context, req Request) (Result, error) {
	var res Result
	switch req.Action {
	case ActionHealth:
		res = d.a.health(ctx, req.Resources)
	case ActionActivate:
		res = d.a.activate(ctx, req.Resources)
	default:
		return Result{}, fmt.Errorf("恢复不使用动作 %q", req.Action)
	}
	res.RequestID, res.Action = req.RequestID, req.Action
	if !res.OK {
		return res, errors.New(res.Error)
	}
	return res, nil
}

// drillClearOwn removes the block table and its rules file and verifies
// that the table is gone. The error says what could not be confirmed.
func (a *Agent) drillClearOwn(ctx context.Context, rec *DrillRecord) error {
	x := &run{a: a, ctx: ctx}
	fam, name, _ := strings.Cut(DrillTable, " ")
	tabs, err := x.nftTables()
	if err != nil {
		a.drillStep(rec, "list nft tables", false, err.Error())
		return errors.New("无法确认演练阻断表 " + DrillTable + " 是否还在（" + err.Error() + "）")
	}
	if contains(tabs, DrillTable) {
		if out, err := x.cmd(a.StepTimeout, "nft", "delete", "table", fam, name); err != nil {
			a.drillStep(rec, "delete "+DrillTable, false, err.Error()+"\n"+out)
			return errors.New("演练阻断表 " + DrillTable + " 删除失败，仍然加载着（表里的地址到内核超时后失效）")
		}
		tabs, err = x.nftTables()
		if err != nil || contains(tabs, DrillTable) {
			a.drillStep(rec, "delete "+DrillTable, false, "删除后仍然列出")
			return errors.New("演练阻断表 " + DrillTable + " 删除后仍然列出")
		}
		a.drillStep(rec, "delete "+DrillTable, true, "")
	} else {
		a.drillStep(rec, "delete "+DrillTable, true, "不在")
	}
	if p := a.drillRulesPath(); p != "" {
		if err := os.Remove(p); err != nil && !errors.Is(err, os.ErrNotExist) {
			a.drillStep(rec, "remove block rules file", false, err.Error())
			return errors.New("阻断规则文件删不掉（表已经不在）")
		}
	}
	return nil
}

// drillRecoveryWait is the wait of a restore that does not follow a full
// drill (a failure while applying the change, a retry): the failover loop
// may still be bringing an evicted relay back by itself (5 passes + 120 s
// cooldown), so no re-activation fires before DrillVerifyWait has passed
// since the block ended (or was started, when it never became active). At
// least DrillRetryWait.
func (a *Agent) drillRecoveryWait(rec *DrillRecord) time.Duration {
	sec := a.drillSecond()
	from := rec.Deadline
	if rec.ChangedAt == nil || from.IsZero() {
		from = rec.StartedAt
	}
	if now := time.Now(); from.After(now) {
		from = now // the block was cut short: recovery starts now
	}
	wait := time.Until(from.Add(time.Duration(DrillVerifyWait) * sec))
	if lo := time.Duration(DrillRetryWait) * sec; wait < lo {
		wait = lo
	}
	if hi := time.Duration(DrillVerifyWait) * sec; wait > hi {
		wait = hi
	}
	return wait
}

// drillRestore is the one way out of a drill. It never reports restored
// unless the block is verified gone and the host equals the snapshot.
func (a *Agent) drillRestore(rec *DrillRecord, trigger string, wait time.Duration) {
	a.drillUpdate(rec, func(r *DrillRecord) {
		r.Phase, r.Trigger, r.Residual = DrillRestoring, trigger, nil
		r.Attempts++
		if trigger == "startup" && r.Outcome == "" {
			r.Outcome = DrillAborted
			r.Findings = append(r.Findings, "agent 在演练中途重启：没有得出结论，只做了恢复")
		}
	})
	_ = a.drillSave(rec) // the phase on disk already asks for a restore
	ctx, cancel := context.WithTimeout(context.Background(), wait+time.Duration(DrillFallbackWait)*a.drillSecond()+a.ActionTimeout)
	defer cancel()

	ownErr := a.drillClearOwn(ctx, rec)
	var residual, weightNotes []string
	verify := func(vctx context.Context) ([]string, error) {
		now, err := a.drillSnapshot(vctx)
		if err != nil {
			return nil, err
		}
		weightNotes = drillWeightNotes(rec.Snapshot, now)
		return drillDiff(rec.Snapshot, now), nil
	}
	rep, rerr := RestoreTopology(ctx, directDoer{a}, a.forwardingOf(rec), verify, TopologyRestoreOptions{
		IDPrefix: "drill/" + rec.ID + fmt.Sprintf("/%d", rec.Attempts), Wait: wait,
		FallbackWait: time.Duration(DrillFallbackWait) * a.drillSecond(), Poll: a.drillPoll(),
		// A block that may still be loaded makes a re-activation pointless.
		MayActivate: ownErr == nil,
	})
	residual = rep.Residual
	if ownErr != nil {
		residual = append([]string{ownErr.Error()}, residual...)
	}
	if rerr != nil && len(residual) == 0 {
		residual = []string{"恢复核验没有完成：" + rerr.Error()}
	}
	now := time.Now().UTC()
	a.drillUpdate(rec, func(r *DrillRecord) {
		r.Steps = append(r.Steps, rep.Steps...)
		r.OwnChangeCleared = ownErr == nil
		r.Reactivated = r.Reactivated || rep.Activated
		r.Residual = residual
		r.Findings = append(r.Findings, weightNotes...)
		r.FinishedAt = &now
		if len(residual) == 0 {
			r.Phase = DrillRestored
		} else {
			r.Phase = DrillRestoreFailed
		}
	})
	if err := a.drillSave(rec); err != nil {
		// The terminal phase is not on disk: a restart restores again,
		// which is safe. Say so in memory.
		a.drillUpdate(rec, func(r *DrillRecord) {
			if r.Phase == DrillRestored {
				r.Phase = DrillRestoreFailed
				r.Residual = []string{"恢复已核验，但演练记录写不下去（" + err.Error() + "）：重试恢复以写入记录"}
			}
		})
	}
}

// forwardingOf: forwarding must be on again after a restore when the drill
// started on a forwarding gateway (it always does: the data plane ran).
func (a *Agent) forwardingOf(*DrillRecord) func() (bool, error) {
	return func() (bool, error) {
		v4, v6 := a.procValue("proc/sys/net/ipv4/ip_forward"), a.procValue("proc/sys/net/ipv6/conf/all/forwarding")
		if v4 == "" || v6 == "" {
			return false, errors.New("读不到 /proc/sys 的转发开关")
		}
		return v4 == "1" && v6 == "1", nil
	}
}

// DrillCancel ends the running drill early: its restore starts now.
func (a *Agent) DrillCancel(id string) (DrillStatus, int) {
	a.init()
	d := &a.drill
	d.mu.Lock()
	a.drillLoad()
	if d.rec == nil || d.rec.ID != id {
		st := a.drillStatusLocked()
		d.mu.Unlock()
		st.Error = "没有这个演练"
		return st, http.StatusNotFound
	}
	if d.running && d.cancel != nil && (d.rec.Phase == DrillActive || d.rec.Phase == DrillPrepared) {
		select {
		case <-d.cancel:
		default:
			close(d.cancel)
		}
	}
	st := a.drillStatusLocked()
	d.mu.Unlock()
	return st, http.StatusOK
}

// DrillRetry runs the restore of a failed one again (bounded, in the
// request). 409 when there is nothing to retry.
func (a *Agent) DrillRetry(id string) (DrillStatus, int) {
	a.init()
	d := &a.drill
	d.mu.Lock()
	a.drillLoad()
	rec := d.rec
	if rec == nil || rec.ID != id || rec.Phase != DrillRestoreFailed || d.running {
		st := a.drillStatusLocked()
		d.mu.Unlock()
		st.Error = "这个演练现在不能重试恢复（只有「恢复未核验」的演练可以）"
		return st, http.StatusConflict
	}
	d.mu.Unlock()
	select {
	case a.sem <- struct{}{}:
	default:
		return DrillStatus{Error: "宿主正在执行另一个动作，稍后重试"}, http.StatusServiceUnavailable
	}
	defer func() { <-a.sem }()
	d.mu.Lock()
	if d.running || rec.Phase != DrillRestoreFailed {
		st := a.drillStatusLocked()
		d.mu.Unlock()
		st.Error = "恢复已经在运行"
		return st, http.StatusConflict
	}
	d.running = true
	d.mu.Unlock()
	a.beginAction()
	a.drillRestore(rec, "retry", a.drillRecoveryWait(rec))
	a.endAction()
	d.mu.Lock()
	d.running = false
	d.mu.Unlock()
	return a.DrillStatus(), http.StatusOK
}

// DrillRelease gives up verifying a failed restore so that the operator
// can change the host again (an install or a rollback is then the way to a
// known state). Only when the block table is verified gone now; the record
// becomes DrillReleased with its differences kept, never DrillRestored.
func (a *Agent) DrillRelease(ctx context.Context, id string) (DrillStatus, int) {
	a.init()
	d := &a.drill
	d.mu.Lock()
	a.drillLoad()
	rec := d.rec
	if rec == nil || rec.ID != id || rec.Phase != DrillRestoreFailed || d.running {
		st := a.drillStatusLocked()
		d.mu.Unlock()
		st.Error = "这个演练现在不能解除（只有「恢复未核验」的演练可以）"
		return st, http.StatusConflict
	}
	d.mu.Unlock()
	select {
	case a.sem <- struct{}{}:
	default:
		return DrillStatus{Error: "宿主正在执行另一个动作，稍后重试"}, http.StatusServiceUnavailable
	}
	defer func() { <-a.sem }()
	cctx, cancel := context.WithTimeout(ctx, 2*a.StepTimeout)
	defer cancel()
	tabs, err := (&run{a: a, ctx: cctx}).nftTables()
	if err != nil || contains(tabs, DrillTable) {
		st := a.DrillStatus()
		st.Error = "演练阻断表 " + DrillTable + " 还在或无法确认已删除：不能解除，先重试恢复"
		return st, http.StatusConflict
	}
	now := time.Now().UTC()
	prev := *rec
	a.drillUpdate(rec, func(r *DrillRecord) {
		r.Phase, r.OwnChangeCleared, r.FinishedAt = DrillReleased, true, &now
		r.Findings = append(r.Findings, "操作者解除了未核验的恢复：宿主没有被确认回到演练前的状态")
	})
	if err := a.drillSave(rec); err != nil {
		a.drillUpdate(rec, func(r *DrillRecord) { *r = prev })
		st := a.DrillStatus()
		st.Error = "演练记录写不下去，没有解除：" + err.Error()
		return st, http.StatusInternalServerError
	}
	return a.DrillStatus(), http.StatusOK
}

// ---------------------------------------------------------- path check ---

// PathCheckRequest is the whole parameter set of the tunnel path check.
type PathCheckRequest struct {
	RequestID  string   `json:"request_id"`
	Interfaces []string `json:"interfaces"`
}

// PathLink is one interface as read.
type PathLink struct {
	Interface string `json:"interface"`
	// State: up | down | absent.
	State string `json:"state"`
	// WireGuard is false for the Mesh veth (no peers to read).
	WireGuard bool `json:"wireguard"`
	Peers     int  `json:"peers"`
	// HandshakeAgeS is the age of the freshest handshake; nil: none yet.
	HandshakeAgeS *int64 `json:"handshake_age_s,omitempty"`
	RxBytes       int64  `json:"rx_bytes"`
	TxBytes       int64  `json:"tx_bytes"`
	Error         string `json:"error,omitempty"`
}

// PathCheckResult is the answer.
type PathCheckResult struct {
	CheckedAt time.Time  `json:"checked_at"`
	Links     []PathLink `json:"links"`
	Error     string     `json:"error,omitempty"`
}

// ValidatePathCheck checks a request completely before anything runs.
func ValidatePathCheck(req PathCheckRequest) error {
	if !requestIDRe.MatchString(req.RequestID) {
		return errors.New("request_id 不合法")
	}
	if len(req.Interfaces) == 0 || len(req.Interfaces) > MaxPathInterfaces {
		return fmt.Errorf("interfaces 要有 1 到 %d 个受管接口", MaxPathInterfaces)
	}
	return uniq("interface", req.Interfaces, ValidInterface)
}

// PathCheck reads the named managed interfaces. 200: read; 400/403:
// refused; 503: busy.
func (a *Agent) PathCheck(ctx context.Context, req PathCheckRequest) (PathCheckResult, int) {
	a.init()
	res := PathCheckResult{CheckedAt: time.Now().UTC(), Links: []PathLink{}}
	if err := ValidatePathCheck(req); err != nil {
		res.Error = err.Error()
		return res, http.StatusBadRequest
	}
	wait, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	select {
	case a.sem <- struct{}{}:
	case <-wait.Done():
		res.Error = "宿主正在执行另一个动作，路径检查没有执行"
		return res, http.StatusServiceUnavailable
	}
	err := a.ledger.load()
	led := a.ledger.data
	<-a.sem
	if err != nil {
		res.Error = err.Error()
		return res, http.StatusForbidden
	}
	for _, i := range req.Interfaces {
		if !contains(led.Interfaces, i) {
			res.Error = fmt.Sprintf("拒绝：接口 %s 不在宿主的受管清单里（从未由 Meridian 激活）；没有读取任何接口", i)
			return res, http.StatusForbidden
		}
	}
	timeout := a.StepTimeout
	if timeout > 10*time.Second {
		timeout = 10 * time.Second
	}
	x := &run{a: a, ctx: ctx}
	now := time.Now().Unix()
	for _, i := range req.Interfaces {
		out, err := x.cmd(timeout, "ip", "-o", "link", "show", "dev", i)
		l := PathLink{Interface: i, State: linkState(out, err), WireGuard: i != "mmesh"}
		if l.State == "absent" || !l.WireGuard {
			res.Links = append(res.Links, l)
			continue
		}
		hs, err := x.cmd(timeout, "wg", "show", i, "latest-handshakes")
		var hm map[string]int64
		if err == nil {
			hm, err = ParseLatestHandshakes(hs)
		}
		if err != nil {
			l.Error = "读不到握手：" + clip(firstLine(err.Error()))
			res.Links = append(res.Links, l)
			continue
		}
		l.Peers = len(hm)
		var newest int64
		for _, v := range hm {
			if v > newest {
				newest = v
			}
		}
		if newest > 0 {
			age := now - newest
			if age < 0 {
				age = 0
			}
			l.HandshakeAgeS = &age
		}
		if tr, err := x.cmd(timeout, "wg", "show", i, "transfer"); err == nil {
			if tm, err := ParseTransfer(tr); err == nil {
				for _, v := range tm {
					l.RxBytes += v[0]
					l.TxBytes += v[1]
				}
			}
		}
		res.Links = append(res.Links, l)
	}
	return res, http.StatusOK
}

// ------------------------------------------------------------- handlers ---

type drillIDBody struct {
	ID string `json:"id"`
}

func decodeStrictBody(w http.ResponseWriter, r *http.Request, v any) bool {
	dec := json.NewDecoder(io.LimitReader(r.Body, 8<<10))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil && !errors.Is(err, io.EOF) {
		writeJSON(w, http.StatusBadRequest, DrillStatus{Error: "请求格式不正确"})
		return false
	}
	return true
}

func (a *Agent) serveDrillStart(w http.ResponseWriter, r *http.Request) {
	if !a.authorize(w, r) {
		return
	}
	var req DrillRequest
	if !decodeStrictBody(w, r, &req) {
		return
	}
	st, code := a.DrillStart(r.Context(), req)
	writeJSON(w, code, st)
}

func (a *Agent) serveDrillStatus(w http.ResponseWriter, r *http.Request) {
	if !a.authorize(w, r) {
		return
	}
	var empty struct{}
	if !decodeStrictBody(w, r, &empty) {
		return
	}
	writeJSON(w, http.StatusOK, a.DrillStatus())
}

func (a *Agent) serveDrillOp(op func(id string) (DrillStatus, int)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !a.authorize(w, r) {
			return
		}
		var b drillIDBody
		if !decodeStrictBody(w, r, &b) {
			return
		}
		if !requestIDRe.MatchString(b.ID) {
			writeJSON(w, http.StatusBadRequest, DrillStatus{Error: "id 不合法"})
			return
		}
		st, code := op(b.ID)
		writeJSON(w, code, st)
	}
}

func (a *Agent) servePathCheck(w http.ResponseWriter, r *http.Request) {
	if !a.authorize(w, r) {
		return
	}
	var req PathCheckRequest
	dec := json.NewDecoder(io.LimitReader(r.Body, 8<<10))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, PathCheckResult{Error: "请求格式不正确"})
		return
	}
	res, code := a.PathCheck(r.Context(), req)
	writeJSON(w, code, res)
}

// --------------------------------------------------------------- client ---

// ErrDrillRefused wraps the agent's refusal of a drill request (a failed
// precondition, another drill, a busy agent). Nothing was changed.
var ErrDrillRefused = errors.New("宿主拒绝了演练请求")

func (c *Client) drillCall(ctx context.Context, path string, body any, timeout time.Duration) (DrillStatus, error) {
	var st DrillStatus
	code, err := c.post(ctx, path, body, timeout, &st)
	if err != nil {
		return st, err
	}
	if code != http.StatusOK {
		return st, fmt.Errorf("%w（%d）：%s", ErrDrillRefused, code, st.Error)
	}
	return st, nil
}

// DrillStart asks the agent to start a drill (not retried: a lost answer
// is resolved by DrillStatus, the drill ends by its own clock).
func (c *Client) DrillStart(ctx context.Context, req DrillRequest) (DrillStatus, error) {
	if err := ValidateDrill(req); err != nil {
		return DrillStatus{}, err
	}
	return c.drillCall(ctx, "/v1/drill/start", req, 3*time.Minute)
}

// DrillStatus reads the current or the last drill.
func (c *Client) DrillStatus(ctx context.Context) (DrillStatus, error) {
	return c.drillCall(ctx, "/v1/drill/status", struct{}{}, 15*time.Second)
}

// DrillCancel ends the running drill early.
func (c *Client) DrillCancel(ctx context.Context, id string) (DrillStatus, error) {
	return c.drillCall(ctx, "/v1/drill/cancel", drillIDBody{ID: id}, 15*time.Second)
}

// DrillRetry retries the restore of a failed one.
func (c *Client) DrillRetry(ctx context.Context, id string) (DrillStatus, error) {
	return c.drillCall(ctx, "/v1/drill/retry", drillIDBody{ID: id}, 10*time.Minute)
}

// DrillRelease releases a failed restore whose block is verified gone.
func (c *Client) DrillRelease(ctx context.Context, id string) (DrillStatus, error) {
	return c.drillCall(ctx, "/v1/drill/release", drillIDBody{ID: id}, time.Minute)
}

// PathCheck asks the agent for the tunnel path check.
func (c *Client) PathCheck(ctx context.Context, req PathCheckRequest) (PathCheckResult, error) {
	if err := ValidatePathCheck(req); err != nil {
		return PathCheckResult{}, err
	}
	var res PathCheckResult
	code, err := c.post(ctx, "/v1/acceptance/paths", req, time.Minute, &res)
	if err != nil {
		return res, err
	}
	if code != http.StatusOK {
		return res, fmt.Errorf("host agent 拒绝路径检查（%d）：%s", code, res.Error)
	}
	return res, nil
}
