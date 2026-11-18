package api

// The 验收 page: the acceptance catalog (internal/acceptance), carrying an
// item out and the stored results.
//
//	GET  /api/acceptance                       catalog, applicability, results, the host's drill
//	GET  /api/acceptance/summary               per item: state and newest valid results (for the links on other pages)
//	POST /api/acceptance/items/{id}/prepare    the second confirmation of a drill
//	POST /api/acceptance/items/{id}/run        carry out a check or a confirmed drill
//	POST /api/acceptance/items/{id}/cancel     stop the running one (a drill is restored)
//	POST /api/acceptance/items/{id}/signoff    record a person's result with a note
//	POST /api/acceptance/drill/retry           retry the restore of a drill that was not verified
//	POST /api/acceptance/drill/release         release such a drill once its block is gone
//
// Nothing here runs a command. A check is one of the fixed requests the
// host agent already had (health, the exit resolver check, the unlock
// probe) or the read-only path check; a drill is one of hostexec's three.
// Every parameter is resolved here against what is installed and what the
// gateway itself reports: a relay must be a relay of the topology that the
// gateway's own upstream record names, an interface must be in the
// installed manifest, an exit must be a checkable exit of the compiled
// plan, a platform must be in the probe catalog. The request body carries
// ids only; there is no field for a command, a path, a host or a URL.
//
// A drill takes the gateway node lock and the host transaction lock for
// its whole duration, so no install, rollback, recovery, withdraw or
// second drill overlaps it; the host agent refuses the same on its side.
// The agent keeps its own clock: this process or the browser going away
// does not keep a block in place (hostexec/acceptance.go).

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/radowitz/meridian/internal/acceptance"
	"github.com/radowitz/meridian/internal/apply"
	"github.com/radowitz/meridian/internal/compile"
	"github.com/radowitz/meridian/internal/hostexec"
	"github.com/radowitz/meridian/internal/mesh"
	"github.com/radowitz/meridian/internal/model"
	"github.com/radowitz/meridian/internal/probe"
	"github.com/radowitz/meridian/internal/provision"
	"github.com/radowitz/meridian/internal/unlock"
	"github.com/radowitz/meridian/internal/verify"
)

// DrillRuntime is the host agent's acceptance actions (hostexec.Client in
// main). Nil: drills and the path check are unavailable.
type DrillRuntime interface {
	DrillStart(ctx context.Context, req hostexec.DrillRequest) (hostexec.DrillStatus, error)
	DrillStatus(ctx context.Context) (hostexec.DrillStatus, error)
	DrillCancel(ctx context.Context, id string) (hostexec.DrillStatus, error)
	DrillRetry(ctx context.Context, id string) (hostexec.DrillStatus, error)
	DrillRelease(ctx context.Context, id string) (hostexec.DrillStatus, error)
	PathCheck(ctx context.Context, req hostexec.PathCheckRequest) (hostexec.PathCheckResult, error)
}

// Codes of the acceptance endpoints.
const (
	codeAccUnknownItem   = "acceptance_unknown_item"   // 404
	codeAccBusy          = "acceptance_busy"           // 409: another item is being carried out
	codeAccBlocked       = "acceptance_blocked"        // 409: a drill on the host is unresolved
	codeAccNotApplicable = "acceptance_not_applicable" // 409: the item does not apply to this topology / install
	codeAccBadTarget     = "acceptance_bad_target"     // 400: a parameter is not an installed resource
	codeAccConfirm       = "acceptance_confirm"        // 409: missing, expired or changed confirmation
	codeAccDrillActive   = "acceptance_drill_active"   // 409: an install or rollback during a drill
	codeAccRefused       = "acceptance_refused"        // 409: the host agent refused the drill
)

const (
	// accMaxDNSExits bounds one resolver check run.
	accMaxDNSExits = 16
	// accDrillLimit bounds how long the panel follows one drill: the
	// longest block, the restore's waits and a margin.
	accDrillLimit = (hostexec.DrillReloadLimit + hostexec.DrillVerifyWait + hostexec.DrillFallbackWait + 360) * time.Second
	// accDefaultBlock is the isolation time when the request names none.
	accDefaultBlock = 45
)

// accJob is the one acceptance item being carried out.
type accJob struct {
	ID        string    `json:"id"`
	ItemID    string    `json:"item_id"`
	Action    string    `json:"action"`
	Target    string    `json:"target,omitempty"`
	Drill     bool      `json:"drill"`
	StartedAt time.Time `json:"started_at"`
	// Phase is a short word for the page: running, drilling, restoring.
	Phase  string `json:"phase"`
	cancel context.CancelFunc
	done   chan struct{}
}

func (s *Server) accStoreOf() *acceptance.Store {
	s.accMu.Lock()
	defer s.accMu.Unlock()
	if s.accStore == nil {
		s.accStore = acceptance.NewStore(s.Store)
	}
	return s.accStore
}

func (s *Server) accPollEvery() time.Duration {
	if s.AccPoll > 0 {
		return s.AccPoll
	}
	return 2 * time.Second
}

func (s *Server) registerAcceptance(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/acceptance", s.getAcceptance)
	mux.HandleFunc("GET /api/acceptance/summary", s.getAcceptanceSummary)
	mux.HandleFunc("POST /api/acceptance/items/{id}/prepare", s.postAcceptancePrepare)
	mux.HandleFunc("POST /api/acceptance/items/{id}/run", s.postAcceptanceRun)
	mux.HandleFunc("POST /api/acceptance/items/{id}/cancel", s.postAcceptanceCancel)
	mux.HandleFunc("POST /api/acceptance/items/{id}/signoff", s.postAcceptanceSignoff)
	mux.HandleFunc("POST /api/acceptance/drill/retry", s.postAcceptanceDrillRetry)
	mux.HandleFunc("POST /api/acceptance/drill/release", s.postAcceptanceDrillRelease)
}

// drillActive reports whether this panel is carrying out a drill now.
func (s *Server) drillActive() bool {
	s.accMu.Lock()
	defer s.accMu.Unlock()
	return s.accJob != nil && s.accJob.Drill
}

// refuseDuringDrill answers 409 for an install, a rollback or a recovery
// while a drill runs. Nothing of the request has been carried out.
func (s *Server) refuseDuringDrill(w http.ResponseWriter) bool {
	if !s.drillActive() {
		return false
	}
	writeCoded(w, http.StatusConflict, codeAccDrillActive, "验收演练正在进行（或正在恢复）：等它结束再安装、回滚或恢复；宿主上没有改动", nil)
	return true
}

// ------------------------------------------------------------- context ---

// accContext is everything a request needs to judge the items: the
// topology, the compiled bundle, what is installed and the fingerprint.
type accContext struct {
	topo      model.Topology
	bundle    *compile.Bundle // nil: the topology does not compile
	compErr   string
	installed apply.Manifest
	pending   bool
	fp        string
	state     string // in_sync | changed | not_installed | withdrawn | invalid | unknown
}

func (s *Server) accContextOf() (accContext, error) {
	var c accContext
	t, err := s.topology()
	if err != nil {
		return c, err
	}
	c.topo = t
	ap := s.applier(true)
	inst, err := ap.Installed()
	if err != nil {
		return c, err
	}
	c.installed = inst
	if p, err := ap.Pending(); err != nil {
		return c, err
	} else if p != nil {
		c.pending = true
	}
	compiled := ""
	b, err := s.compileTopo(t)
	if err != nil {
		c.compErr = err.Error()
	} else {
		c.bundle = b
		compiled = hashText(b.Canonical())
	}
	c.fp = acceptance.Fingerprint(compiled, inst.Canonical, inst.Version)
	switch {
	case c.bundle == nil:
		c.state = "invalid"
	case inst.Empty():
		c.state = "not_installed"
	case inst.Withdrawn():
		c.state = "withdrawn"
	case inst.Canonical == "":
		c.state = "unknown"
	case inst.Canonical == compiled:
		c.state = "in_sync"
	default:
		c.state = "changed"
	}
	return c, nil
}

// gatewayRuns: the gateway data plane is installed and not withdrawn.
func (c accContext) gatewayRuns() bool { return !c.installed.Empty() && !c.installed.Withdrawn() }

var accTunnelRe = regexp.MustCompile(`^m[0-9]{2,3}w?$`)

// tunnelInterfaces are the installed manifest's tunnel interfaces.
func (c accContext) tunnelInterfaces() []string {
	var out []string
	for _, i := range c.installed.Interfaces {
		if accTunnelRe.MatchString(i) && hostexec.ValidInterface(i) {
			out = append(out, i)
		}
	}
	sort.Strings(out)
	return out
}

func (c accContext) installedIface(name string) bool {
	return contains(c.installed.Interfaces, name) && accTunnelRe.MatchString(name)
}

// applicable says whether the item applies to this topology at all.
func (s *Server) accApplicable(c accContext, it acceptance.Item) (bool, string) {
	switch it.ID {
	case "remote-access":
		if !c.topo.RemoteAccess.Active() {
			return false, "远程接入没有启用"
		}
	case "mesh-e2e", "integration-mesh-veth":
		if c.bundle == nil {
			return false, "拓扑没有通过校验，无法判断是否有 Mesh 备路"
		}
		if len(mesh.BuildPlan(c.topo, c.bundle.Files).Nodes) == 0 {
			return false, "这份拓扑没有 Mesh 备路"
		}
	case "relay-removal":
		if !c.topo.RelaySharing() {
			return false, "只有一台中继在分担：剔除它等同于主枢纽隔离"
		}
	case "hub-failover":
		if !c.topo.DualHub() {
			return false, "这份拓扑没有备用枢纽"
		}
	case "sniff-client", "integration-netns-sniff":
		if !c.topo.SniffOn() {
			return false, "按域名嗅探没有开启"
		}
	}
	return true, ""
}

// runnable says whether the item's fixed action can be started now, and
// if not, why. Manual items are never "run".
func (s *Server) accRunnable(c accContext, it acceptance.Item) (bool, string) {
	switch it.Mode {
	case acceptance.ModeManual:
		return false, ""
	case acceptance.ModeDrill:
		switch {
		case s.Drill == nil:
			return false, "面板没有宿主执行通道，不能做演练"
		case !c.gatewayRuns():
			return false, "网关没有安装（或已撤回）：没有可演练的数据面"
		case c.pending:
			return false, "有未完成的宿主事务，先在「部署」页恢复"
		}
		return true, ""
	}
	switch it.Action {
	case acceptance.ActionConfigAudit:
		if c.bundle == nil {
			return false, "拓扑没有通过校验，没有可核对的配置"
		}
	case hostexec.ActionHealth:
		if s.Host == nil {
			return false, "面板没有宿主执行通道"
		}
		if !c.gatewayRuns() {
			return false, "网关没有安装（或已撤回）"
		}
	case acceptance.ActionResolverCheck:
		if _, ok := s.Prober.(DNSCheckRuntime); !ok || s.Prober == nil {
			return false, "面板没有宿主代理的检查能力"
		}
		if !c.gatewayRuns() {
			return false, "网关没有安装（或已撤回）：宿主代理只问已安装配置里的出口解析器"
		}
	case hostexec.CheckTunnelPaths:
		if s.Drill == nil {
			return false, "面板没有宿主执行通道"
		}
		if len(c.tunnelInterfaces()) == 0 {
			return false, "已安装清单里没有隧道接口（网关没有安装）"
		}
	case acceptance.ActionProbe:
		if s.Prober == nil {
			return false, "面板没有宿主探测能力"
		}
	}
	return true, ""
}

// ---------------------------------------------------------------- view ---

type accTarget struct {
	ID    string `json:"id"`
	Label string `json:"label"`
	// Note: the relay's state as the gateway reports it.
	Note string `json:"note,omitempty"`
	// Selectable is false for a target the drill would refuse.
	Selectable bool `json:"selectable"`
}

type accEvidence struct {
	ID     string `json:"id"`
	Title  string `json:"title"`
	Status string `json:"status"`
	Detail string `json:"detail"`
}

type accItemView struct {
	acceptance.Item
	Applicable bool   `json:"applicable"`
	Reason     string `json:"reason,omitempty"`
	Runnable   bool   `json:"runnable"`
	RunBlocked string `json:"run_blocked,omitempty"`
	// Targets are the installed resources a drill may name (relay-removal).
	Targets []accTarget `json:"targets,omitempty"`
	acceptance.ItemView
	// ConfigEvidence is the current result of the item's configuration
	// checks (read now from the compiled bundle); KnownLimits the limits
	// that go with it.
	ConfigEvidence []accEvidence `json:"config_evidence"`
	KnownLimits    []accEvidence `json:"known_limits"`
}

type accDrillView struct {
	// Available: the panel can ask the host agent about drills.
	Available bool `json:"available"`
	// Blocked: an unresolved drill on the host refuses new drills and host
	// changes. Running: it (or its restore) is in progress.
	Blocked bool   `json:"blocked"`
	Running bool   `json:"running"`
	ItemID  string `json:"item_id,omitempty"`
	// Record is the host's record, without the snapshot digests.
	Record *accDrillRecord `json:"record,omitempty"`
	Error  string          `json:"error,omitempty"`
}

type accDrillRecord struct {
	ID               string                      `json:"id"`
	Kind             string                      `json:"kind"`
	Interfaces       []string                    `json:"interfaces,omitempty"`
	Phase            string                      `json:"phase"`
	StartedAt        time.Time                   `json:"started_at"`
	Deadline         time.Time                   `json:"deadline"`
	RestoreDeadline  time.Time                   `json:"restore_deadline"`
	FinishedAt       *time.Time                  `json:"finished_at,omitempty"`
	Plan             []string                    `json:"plan"`
	Expect           string                      `json:"expect"`
	Outcome          string                      `json:"outcome,omitempty"`
	Observed         []hostexec.DrillObservation `json:"observed,omitempty"`
	Findings         []string                    `json:"findings,omitempty"`
	Trigger          string                      `json:"trigger,omitempty"`
	OwnChangeCleared bool                        `json:"own_change_cleared"`
	Reactivated      bool                        `json:"reactivated,omitempty"`
	Residual         []string                    `json:"residual,omitempty"`
	Attempts         int                         `json:"attempts,omitempty"`
	Error            string                      `json:"error,omitempty"`
}

func drillRecordView(r *hostexec.DrillRecord) *accDrillRecord {
	if r == nil {
		return nil
	}
	return &accDrillRecord{
		ID: r.ID, Kind: r.Kind, Interfaces: r.Interfaces, Phase: r.Phase, StartedAt: r.StartedAt, Deadline: r.Deadline,
		RestoreDeadline: r.RestoreDeadline, FinishedAt: r.FinishedAt, Plan: r.Plan, Expect: r.Expect, Outcome: r.Outcome,
		Observed: r.Observed, Findings: r.Findings, Trigger: r.Trigger, OwnChangeCleared: r.OwnChangeCleared,
		Reactivated: r.Reactivated, Residual: r.Residual, Attempts: r.Attempts, Error: r.Error,
	}
}

var drillItemOf = map[string]string{
	hostexec.DrillFirewallReload: "ipv6-firewall-reload",
	hostexec.DrillRelayIsolation: "relay-removal",
	hostexec.DrillHubIsolation:   "hub-failover",
}

type accView struct {
	Fingerprint string `json:"fingerprint"`
	Config      struct {
		// State: in_sync | changed | not_installed | withdrawn | invalid | unknown.
		State            string `json:"state"`
		InstalledVersion int64  `json:"installed_version,omitempty"`
		Error            string `json:"error,omitempty"`
	} `json:"config"`
	Running *accJob       `json:"running"`
	Drill   accDrillView  `json:"drill"`
	Items   []accItemView `json:"items"`
	// Summary counts the applicable items by state.
	Summary map[string]int `json:"summary"`
	// ConfirmTTL is how long a drill confirmation is valid (seconds).
	ConfirmTTL int `json:"confirm_ttl_seconds"`
}

func (s *Server) currentAccJob() *accJob {
	s.accMu.Lock()
	defer s.accMu.Unlock()
	if s.accJob == nil {
		return nil
	}
	cp := *s.accJob
	return &cp
}

// drillStatus asks the host agent for its drill record (short timeout).
func (s *Server) drillStatus(ctx context.Context) (hostexec.DrillStatus, accDrillView) {
	var v accDrillView
	if s.Drill == nil {
		v.Error = "面板没有宿主执行通道"
		return hostexec.DrillStatus{}, v
	}
	cctx, cancel := context.WithTimeout(ctx, statusAgentTimeout)
	defer cancel()
	st, err := s.Drill.DrillStatus(cctx)
	if err != nil {
		v.Error = "读不到宿主上的演练状态：" + err.Error()
		return st, v
	}
	v.Available, v.Blocked, v.Running, v.Record = true, st.Blocked, st.Running, drillRecordView(st.Record)
	if st.Error != "" {
		v.Error = st.Error
	}
	if st.Record != nil {
		v.ItemID = drillItemOf[st.Record.Kind]
	}
	return st, v
}

func (s *Server) getAcceptance(w http.ResponseWriter, r *http.Request) {
	// Read first: a job that is gone here has stored its result, so a view
	// without a running job always carries that job's result.
	running := s.currentAccJob()
	c, err := s.accContextOf()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	st, dv := s.drillStatus(r.Context())
	// A drill this panel did not see end (it restarted, or the answer was
	// lost) is taken into the results from the host's record.
	if dv.Available && st.Record != nil && !st.Running {
		s.accAdoptDrill(st.Record)
	}
	views, err := s.accStoreOf().View(c.fp)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	var checks []verify.Item
	if c.bundle != nil {
		checks = verify.CheckBundle(c.topo, c.bundle.Files)
	}
	byID := map[string]verify.Item{}
	for _, v := range checks {
		byID[v.ID] = v
	}
	var out accView
	out.Fingerprint, out.ConfirmTTL = c.fp, acceptance.ConfirmTTLSeconds
	out.Config.State, out.Config.InstalledVersion, out.Config.Error = c.state, c.installed.Version, c.compErr
	out.Running, out.Drill, out.Summary = running, dv, map[string]int{}
	var relays []accTarget
	if c.topo.RelaySharing() {
		relays = s.accRelayTargets(r.Context(), c)
	}
	for _, it := range acceptance.Catalog() {
		iv := accItemView{Item: it, ItemView: views[it.ID], ConfigEvidence: []accEvidence{}, KnownLimits: []accEvidence{}}
		iv.Applicable, iv.Reason = s.accApplicable(c, it)
		if iv.Applicable {
			iv.Runnable, iv.RunBlocked = s.accRunnable(c, it)
			out.Summary[iv.State]++
		} else {
			out.Summary["not_applicable"]++
		}
		if it.ID == "relay-removal" && iv.Applicable {
			iv.Targets = relays
		}
		for _, id := range it.ConfigChecks {
			if v, ok := byID[id]; ok {
				iv.ConfigEvidence = append(iv.ConfigEvidence, accEvidence{ID: v.ID, Title: v.Title, Status: v.Status, Detail: v.Detail})
			}
		}
		for _, id := range it.Limits {
			if v, ok := byID[id]; ok {
				iv.KnownLimits = append(iv.KnownLimits, accEvidence{ID: v.ID, Title: v.Title, Status: v.Status, Detail: v.Detail})
			}
		}
		out.Items = append(out.Items, iv)
	}
	writeJSON(w, http.StatusOK, out)
}

type accSummaryPart struct {
	Part    string    `json:"part"`
	Outcome string    `json:"outcome"`
	At      time.Time `json:"at"`
	Summary string    `json:"summary"`
}

type accSummaryItem struct {
	ID         string `json:"id"`
	Title      string `json:"title"`
	Mode       string `json:"mode"`
	Applicable bool   `json:"applicable"`
	Reason     string `json:"reason,omitempty"`
	State      string `json:"state"`
	// Valid are the newest results under the current configuration, one
	// per part that has one; Stale counts the results that no longer count.
	Valid    []accSummaryPart `json:"valid"`
	Stale    int              `json:"stale"`
	Deferred string           `json:"deferred,omitempty"`
}

// getAcceptanceSummary is what the other pages read to link their
// "not verified" notes to an item and show its newest valid result. It
// asks the host nothing.
func (s *Server) getAcceptanceSummary(w http.ResponseWriter, r *http.Request) {
	c, err := s.accContextOf()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	views, err := s.accStoreOf().View(c.fp)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	items := []accSummaryItem{}
	leak := map[string]string{}
	for _, it := range acceptance.Catalog() {
		v := views[it.ID]
		si := accSummaryItem{ID: it.ID, Title: it.Title, Mode: it.Mode, State: v.State, Valid: []accSummaryPart{}, Deferred: it.Deferred}
		si.Applicable, si.Reason = s.accApplicable(c, it)
		for _, p := range v.Parts {
			if p.Valid != nil {
				si.Valid = append(si.Valid, accSummaryPart{Part: p.Part, Outcome: p.Valid.Outcome, At: p.Valid.At, Summary: p.Valid.Summary})
			}
		}
		for _, h := range v.History {
			if h.Stale {
				si.Stale++
			}
		}
		items = append(items, si)
		for _, id := range it.LeakItems {
			if own, ok := acceptance.ForLeakItem(id); ok {
				leak[id] = own.ID
			}
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"fingerprint": c.fp, "items": items, "leak_items": leak})
}

// accRelayTargets lists the relays a relay isolation may name: relays of
// the topology that the gateway's own upstream record names, on an
// interface of the installed manifest.
func (s *Server) accRelayTargets(ctx context.Context, c accContext) []accTarget {
	out := []accTarget{}
	rec := s.accUpstream(ctx)
	if rec == nil {
		return out
	}
	carrying := 0
	for _, r := range rec.Relays {
		if (r.Status == "active" || r.Status == "reduced") && r.Weight > 0 {
			carrying++
		}
	}
	for _, r := range rec.Relays {
		n, ok := c.topo.NodeByID(r.ID)
		if !ok || n.Role != model.RoleRelay || !c.installedIface(r.Iface) {
			continue
		}
		name := n.Name
		if name == "" {
			name = n.ID
		}
		is := (r.Status == "active" || r.Status == "reduced") && r.Weight > 0
		out = append(out, accTarget{ID: n.ID, Label: name, Note: fmt.Sprintf("%s，权重 %d", r.Status, r.Weight), Selectable: is && carrying >= 2})
	}
	return out
}

// accUpstream reads the gateway's upstream record (nil: none readable).
func (s *Server) accUpstream(ctx context.Context) *hostexec.UpstreamState {
	if s.Upstream == nil {
		return nil
	}
	cctx, cancel := context.WithTimeout(ctx, statusAgentTimeout)
	defer cancel()
	st, err := s.Upstream.UpstreamStatus(cctx)
	if err != nil || !st.Present || st.Record == nil {
		return nil
	}
	return st.Record
}

// --------------------------------------------------------- drill params ---

// drillPlan is a drill resolved against the installed state.
type drillPlan struct {
	req    hostexec.DrillRequest
	target string // what the confirmation is bound to
	label  string
}

type accRunBody struct {
	// ConfirmToken is the token of POST …/prepare (drills).
	ConfirmToken string `json:"confirm_token,omitempty"`
	// Target is a relay node id (relay-removal).
	Target string `json:"target,omitempty"`
	// BlockSeconds is the isolation time (relay-removal, hub-failover).
	BlockSeconds int `json:"block_seconds,omitempty"`
	// Exits narrows dns-leak and unlock to these exits; Services narrows
	// unlock to these probe catalog ids.
	Exits    []string `json:"exits,omitempty"`
	Services []string `json:"services,omitempty"`
}

var accRunFields = []string{"confirm_token", "target", "block_seconds", "exits", "services"}

type accError struct {
	status int
	code   string
	msg    string
}

func (e *accError) Error() string { return e.msg }

func accErr(status int, code, format string, args ...any) *accError {
	return &accError{status: status, code: code, msg: fmt.Sprintf(format, args...)}
}

func writeAccErr(w http.ResponseWriter, err error) {
	var ae *accError
	if errors.As(err, &ae) {
		writeCoded(w, ae.status, ae.code, ae.msg, nil)
		return
	}
	writeErr(w, http.StatusInternalServerError, err)
}

// failoverBackupIface reads the backup path's interface from the compiled
// gateway files (compile.upstreamPrelude: UP_NAME=(…) and UP_IFACE=(…)).
func failoverBackupIface(files map[string]string) string {
	for _, body := range files {
		i := strings.Index(body, "\nUP_NAME=(")
		if i < 0 {
			continue
		}
		rest := body[i+1:]
		var names, ifaces []string
		for _, l := range strings.SplitN(rest, "\n", 3)[:2] {
			vals := strings.Fields(strings.TrimSuffix(l[strings.IndexByte(l, '(')+1:], ")"))
			for k := range vals {
				vals[k] = strings.Trim(vals[k], `'"`)
			}
			if strings.HasPrefix(l, "UP_NAME=") {
				names = vals
			} else if strings.HasPrefix(l, "UP_IFACE=") {
				ifaces = vals
			}
		}
		for k, n := range names {
			if n == "backup" && k < len(ifaces) {
				return ifaces[k]
			}
		}
	}
	return ""
}

// accDrillPlan resolves a drill's parameters. Only ids of installed
// resources come out of it.
func (s *Server) accDrillPlan(ctx context.Context, c accContext, it acceptance.Item, body accRunBody) (drillPlan, error) {
	p := drillPlan{req: hostexec.DrillRequest{Kind: it.Action, Fingerprint: c.fp}}
	if it.Action == hostexec.DrillFirewallReload {
		if body.Target != "" || body.BlockSeconds != 0 {
			return p, accErr(http.StatusBadRequest, codeAccBadTarget, "防火墙重载演练不接受目标或时长")
		}
		p.target, p.label = "gateway", "网关防火墙重载"
		return p, nil
	}
	block := body.BlockSeconds
	if block == 0 {
		block = accDefaultBlock
	}
	if block < hostexec.DrillMinBlock || block > hostexec.DrillMaxBlock {
		return p, accErr(http.StatusBadRequest, codeAccBadTarget, "隔离时长必须在 %d 到 %d 秒之间", hostexec.DrillMinBlock, hostexec.DrillMaxBlock)
	}
	p.req.BlockSeconds = block
	rec := s.accUpstream(ctx)
	if rec == nil {
		return p, accErr(http.StatusConflict, codeAccNotApplicable, "读不到网关的上游记录：没有故障切换循环可以观察，演练不能开始")
	}
	switch it.Action {
	case hostexec.DrillRelayIsolation:
		n, ok := c.topo.NodeByID(body.Target)
		if !ok || n.Role != model.RoleRelay {
			return p, accErr(http.StatusBadRequest, codeAccBadTarget, "目标必须是拓扑里的一台中继")
		}
		iface := ""
		for _, r := range rec.Relays {
			if r.ID == n.ID {
				iface = r.Iface
			}
		}
		if iface == "" || !c.installedIface(iface) {
			return p, accErr(http.StatusBadRequest, codeAccBadTarget, "中继 %s 不在网关的上游记录里，或它的隧道接口不在已安装清单里", n.ID)
		}
		p.req.Interfaces = []string{iface}
		p.target, p.label = n.ID, "隔离中继 "+n.ID+"（"+iface+"）"
	case hostexec.DrillHubIsolation:
		if body.Target != "" {
			return p, accErr(http.StatusBadRequest, codeAccBadTarget, "主枢纽隔离演练不接受目标：它隔离主链路的全部中继")
		}
		var ifaces []string
		backup := ""
		if rec.Version == 2 {
			for _, r := range rec.Relays {
				if r.Status != "disabled" {
					ifaces = append(ifaces, r.Iface)
				}
			}
			if rec.Backup != nil {
				backup = rec.Backup.Iface
			}
		} else {
			ifaces = []string{rec.Iface}
			if c.bundle != nil {
				backup = failoverBackupIface(provision.FilesFor(c.bundle.Files, localNodeID))
			}
		}
		for _, i := range append(append([]string(nil), ifaces...), backup) {
			if !c.installedIface(i) {
				return p, accErr(http.StatusConflict, codeAccNotApplicable, "主链路或备用枢纽的隧道接口不在已安装清单里（网关还没有按当前拓扑安装）")
			}
		}
		sort.Strings(ifaces)
		p.req.Interfaces, p.req.BackupInterface = ifaces, backup
		p.target, p.label = "primary-hub:"+rec.Hub, "隔离主枢纽 "+rec.Hub+" 的全部中继（"+strings.Join(ifaces, "、")+"）"
	}
	return p, nil
}

// accItem resolves the path's item and refuses what cannot be carried out.
func (s *Server) accItem(r *http.Request) (acceptance.Item, accContext, error) {
	it, ok := acceptance.Lookup(r.PathValue("id"))
	if !ok {
		return it, accContext{}, accErr(http.StatusNotFound, codeAccUnknownItem, "没有这个验收项")
	}
	c, err := s.accContextOf()
	if err != nil {
		return it, c, err
	}
	if ok, why := s.accApplicable(c, it); !ok {
		return it, c, accErr(http.StatusConflict, codeAccNotApplicable, "这一项不适用：%s", why)
	}
	return it, c, nil
}

func (s *Server) postAcceptancePrepare(w http.ResponseWriter, r *http.Request) {
	var body accRunBody
	if err := decodeStrict(w, r, &body, []string{"target", "block_seconds"}, nil, true); err != nil {
		writeResErr(w, err)
		return
	}
	it, c, err := s.accItem(r)
	if err != nil {
		writeAccErr(w, err)
		return
	}
	if it.Mode != acceptance.ModeDrill {
		writeCoded(w, http.StatusBadRequest, codeBadRequest, "只有会打断流量的演练需要二次确认", nil)
		return
	}
	if ok, why := s.accRunnable(c, it); !ok {
		writeCoded(w, http.StatusConflict, codeAccNotApplicable, why, nil)
		return
	}
	if err := s.accHostFree(r.Context()); err != nil {
		writeAccErr(w, err)
		return
	}
	p, err := s.accDrillPlan(r.Context(), c, it, body)
	if err != nil {
		writeAccErr(w, err)
		return
	}
	cf := s.accConfirm.Issue(it.ID, it.Action, accBinding(p), c.fp, s.now())
	writeJSON(w, http.StatusOK, map[string]any{
		"confirmation":  cf,
		"item_id":       it.ID,
		"label":         p.label,
		"impact":        it.Impact,
		"max_seconds":   it.MaxSeconds,
		"block_seconds": p.req.BlockSeconds,
		"restore":       it.Restore,
		"config_state":  c.state,
	})
}

// accHostFree refuses a new drill while the host still has one that is
// running, restoring or was left unverified. (The agent refuses it too;
// this says so before a confirmation is asked for.)
func (s *Server) accHostFree(ctx context.Context) error {
	st, dv := s.drillStatus(ctx)
	if dv.Available && st.Blocked {
		phase := ""
		if st.Record != nil {
			phase = st.Record.Phase
		}
		return accErr(http.StatusConflict, codeAccBlocked, "网关宿主上还有没结束或恢复未核验的演练（%s）：先处理它，页面顶部有重试恢复", phase)
	}
	return nil
}

// accBinding is what a confirmation is bound to besides the item, the
// action and the fingerprint: the target and the isolation time.
func accBinding(p drillPlan) string {
	return fmt.Sprintf("%s/%s/%d", p.target, strings.Join(p.req.Interfaces, ","), p.req.BlockSeconds)
}

// ----------------------------------------------------------------- run ---

func (s *Server) postAcceptanceRun(w http.ResponseWriter, r *http.Request) {
	var body accRunBody
	if err := decodeStrict(w, r, &body, accRunFields, nil, true); err != nil {
		writeResErr(w, err)
		return
	}
	it, c, err := s.accItem(r)
	if err != nil {
		writeAccErr(w, err)
		return
	}
	if it.Mode == acceptance.ModeManual {
		writeCoded(w, http.StatusBadRequest, codeBadRequest, "这一项由人执行：按步骤做完后签收，面板不代跑", nil)
		return
	}
	if ok, why := s.accRunnable(c, it); !ok {
		writeCoded(w, http.StatusConflict, codeAccNotApplicable, why, nil)
		return
	}
	// One item at a time.
	job := &accJob{ID: "acc-" + randHex(6), ItemID: it.ID, Action: it.Action, Drill: it.Mode == acceptance.ModeDrill, StartedAt: s.now(), Phase: "running", done: make(chan struct{})}
	s.accMu.Lock()
	if s.accJob != nil {
		busy := s.accJob.ItemID
		s.accMu.Unlock()
		writeCoded(w, http.StatusConflict, codeAccBusy, "验收项 "+busy+" 正在执行，等它结束", nil)
		return
	}
	s.accJob = job
	s.accMu.Unlock()
	release := func() {
		s.accMu.Lock()
		s.accJob = nil
		s.accMu.Unlock()
		close(job.done)
	}
	started := *job
	if it.Mode == acceptance.ModeDrill {
		if err := s.accStartDrill(r.Context(), c, it, body, job, &started, release); err != nil {
			writeAccErr(w, err)
			return
		}
	} else {
		run, err := s.accCheck(c, it, body)
		if err != nil {
			release()
			writeAccErr(w, err)
			return
		}
		ctx, cancel := context.WithTimeout(context.Background(), 12*time.Minute)
		s.accSet(job, func(j *accJob) { j.cancel = cancel })
		go func() {
			defer release()
			defer cancel()
			start := s.now()
			results := run(ctx)
			for _, res := range results {
				res.RunID, res.Method, res.Fingerprint, res.InstalledVersion = job.ID, acceptance.ModeAuto, c.fp, c.installed.Version
				if res.Action == "" {
					res.Action = it.Action
				}
				res.At = s.now()
				res.DurationMS = res.At.Sub(start).Milliseconds()
				if ctx.Err() == context.Canceled && res.Outcome != acceptance.OutcomePass && res.Outcome != acceptance.OutcomeFail {
					res.Outcome = acceptance.OutcomeCancelled
				}
				_, _ = s.accStoreOf().Add(res)
			}
		}()
	}
	writeJSON(w, http.StatusAccepted, map[string]any{"job": started})
}

// accSet changes the running job's fields under the lock its readers use.
func (s *Server) accSet(job *accJob, f func(*accJob)) {
	s.accMu.Lock()
	f(job)
	s.accMu.Unlock()
}

// accStartDrill redeems the confirmation, takes the locks and starts the
// drill on the host. On success a goroutine follows it to its end and
// releases everything; on a refusal nothing is held.
func (s *Server) accStartDrill(ctx context.Context, c accContext, it acceptance.Item, body accRunBody, job, started *accJob, release func()) error {
	fail := func(err error) error { release(); return err }
	if err := s.accHostFree(ctx); err != nil {
		return fail(err)
	}
	p, err := s.accDrillPlan(ctx, c, it, body)
	if err != nil {
		return fail(err)
	}
	// The confirmation was given for exactly this action, target, time and
	// configuration; anything else, or too late, means confirming again.
	if err := s.accConfirm.Redeem(body.ConfirmToken, it.ID, it.Action, accBinding(p), c.fp, s.now()); err != nil {
		return fail(accErr(http.StatusConflict, codeAccConfirm, "%s", err.Error()))
	}
	if !s.lockNode(localNodeID) {
		return fail(accErr(http.StatusConflict, codeNodeBusy, "%s", s.busyMessage(localNodeID)))
	}
	unlockTxn, err := s.applier(true).Hold()
	if err != nil {
		s.unlockNode(localNodeID)
		code := codeNodeBusy
		if errors.Is(err, apply.ErrPending) {
			code = codeTxnPending
		}
		return fail(accErr(http.StatusConflict, code, "%s：演练没有开始", err.Error()))
	}
	unlock := func() { unlockTxn(); s.unlockNode(localNodeID) }
	p.req.RequestID = job.ID
	s.accSet(job, func(j *accJob) { j.Target, j.Phase = p.target, "drilling" })
	started.Target, started.Phase = p.target, "drilling"
	sctx, cancel := context.WithTimeout(ctx, 3*time.Minute)
	st, err := s.Drill.DrillStart(sctx, p.req)
	cancel()
	if err != nil && (st.Record == nil || st.Record.ID != job.ID) {
		// Refused or unreachable before a record of this drill exists: when
		// the answer was lost the host may still have started it, and then
		// it ends by its own clock; the next read of the page adopts it.
		unlock()
		code, status := codeAccRefused, http.StatusConflict
		if errors.Is(err, hostexec.ErrUnavailable) {
			code, status = codeHostUnavailable, http.StatusServiceUnavailable
		}
		return fail(accErr(status, code, "演练没有开始：%s", err.Error()))
	}
	go func() {
		defer release()
		defer unlock()
		s.accFollowDrill(job, st)
	}()
	return nil
}

// accFollowDrill polls the host until the drill and its restore ended,
// then stores the result. The host does not depend on this loop.
func (s *Server) accFollowDrill(job *accJob, st hostexec.DrillStatus) {
	deadline := time.Now().Add(accDrillLimit)
	if s.AccDrillLimit > 0 {
		deadline = time.Now().Add(s.AccDrillLimit)
	}
	for {
		if st.Record != nil && st.Record.ID == job.ID && !st.Running {
			s.accAdoptDrill(st.Record)
			return
		}
		if st.Record != nil && st.Record.ID == job.ID {
			phase := "drilling"
			if st.Record.Phase == hostexec.DrillRestoring {
				phase = "restoring"
			}
			s.accSet(job, func(j *accJob) { j.Phase = phase })
		}
		if time.Now().After(deadline) {
			break
		}
		time.Sleep(s.accPollEvery())
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		next, err := s.Drill.DrillStatus(ctx)
		cancel()
		if err == nil {
			st = next
		}
	}
	// The host never reported an end within the limit. Say exactly that;
	// the next read adopts the record once the host answers.
	c, err := s.accContextOf()
	if err != nil {
		return
	}
	_, _ = s.accStoreOf().Add(acceptance.Result{
		RunID: job.ID, ItemID: job.ItemID, Part: acceptance.PartMeasured, Method: acceptance.ModeDrill, Action: job.Action, Target: job.Target,
		Outcome: acceptance.OutcomeError, At: s.now(), Fingerprint: c.fp, InstalledVersion: c.installed.Version,
		Summary: "结果不明：宿主代理没有在期限内报告演练结束。宿主按自己的时钟恢复；能读到它的记录后这里会更新",
	})
}

// accAdoptDrill stores (or updates) the result of a finished drill from
// the host's record. The fingerprint is the one the drill was confirmed
// under, so a result is never attributed to a later configuration.
func (s *Server) accAdoptDrill(rec *hostexec.DrillRecord) {
	itemID, ok := drillItemOf[rec.Kind]
	if !ok || rec.Unresolved() && rec.Phase != hostexec.DrillRestoreFailed {
		return
	}
	res := drillResult(itemID, rec)
	if old, found, err := s.accStoreOf().FindRun(itemID, acceptance.PartMeasured, rec.ID); err != nil || found && old.Outcome == res.Outcome && old.Summary == res.Summary {
		return
	}
	if ap := s.applier(true); res.InstalledVersion == 0 {
		if inst, err := ap.Installed(); err == nil {
			res.InstalledVersion = inst.Version
		}
	}
	_, _ = s.accStoreOf().Add(res)
}

// drillResult maps the host's record to a stored result. A restore that
// was not verified is never a pass, whatever the drill observed.
func drillResult(itemID string, rec *hostexec.DrillRecord) acceptance.Result {
	res := acceptance.Result{
		RunID: rec.ID, ItemID: itemID, Part: acceptance.PartMeasured, Method: acceptance.ModeDrill, Action: rec.Kind,
		Fingerprint: rec.Fingerprint, At: rec.StartedAt, Residual: rec.Residual,
	}
	if rec.FinishedAt != nil {
		res.At = *rec.FinishedAt
		res.DurationMS = rec.FinishedAt.Sub(rec.StartedAt).Milliseconds()
	}
	if rec.Kind == hostexec.DrillRelayIsolation && rec.Snapshot.Upstream != nil && len(rec.Interfaces) == 1 {
		for _, r := range rec.Snapshot.Upstream.Relays {
			if r.Iface == rec.Interfaces[0] {
				res.Target = r.ID
			}
		}
	}
	res.Details = append(res.Details, "预期："+rec.Expect)
	res.Details = append(res.Details, rec.Findings...)
	for _, o := range rec.Observed {
		res.Details = append(res.Details, fmt.Sprintf("+%d 秒 %s", o.AfterMS/1000, o.Summary))
	}
	restored := "恢复：已删除演练的改动，并核对与演练前的状态一致"
	if rec.Reactivated {
		restored += "（期间重新激活过数据面）"
	}
	switch rec.Phase {
	case hostexec.DrillRestoreFailed:
		res.Outcome = acceptance.OutcomeRestoreFailed
		res.Summary = "恢复没有核验通过：宿主与演练前的状态不一致，已阻断新的演练和宿主变更"
	case hostexec.DrillReleased:
		res.Outcome = acceptance.OutcomeRestoreFailed
		res.Summary = "恢复没有核验通过，操作者已解除阻断：宿主没有被确认回到演练前的状态"
	default:
		res.Details = append(res.Details, restored)
		switch rec.Outcome {
		case hostexec.DrillMet:
			res.Outcome, res.Summary = acceptance.OutcomePass, "观察到预期的变化，并已恢复到演练前的状态"
		case hostexec.DrillNotMet:
			res.Outcome, res.Summary = acceptance.OutcomeFail, "没有观察到预期的变化；已恢复到演练前的状态"
		case hostexec.DrillPartial:
			res.Outcome, res.Summary = acceptance.OutcomeInconclusive, "只观察到一部分预期的变化；已恢复到演练前的状态"
		case hostexec.DrillAborted:
			res.Outcome, res.Summary = acceptance.OutcomeCancelled, "演练在得出结论前结束；已恢复到演练前的状态"
		default:
			res.Outcome, res.Summary = acceptance.OutcomeError, "演练的步骤失败；已恢复到演练前的状态"
			if rec.Error != "" {
				res.Details = append(res.Details, rec.Error)
			}
		}
	}
	return res
}

// accCheck resolves a read-only check and returns the function that runs
// it. Parameters are validated here, before anything starts.
func (s *Server) accCheck(c accContext, it acceptance.Item, body accRunBody) (func(context.Context) []acceptance.Result, error) {
	if body.ConfirmToken != "" || body.Target != "" || body.BlockSeconds != 0 {
		return nil, accErr(http.StatusBadRequest, codeAccBadTarget, "只读检查不接受确认、目标或时长")
	}
	if it.Action != acceptance.ActionResolverCheck && it.Action != acceptance.ActionProbe && (len(body.Exits) > 0 || len(body.Services) > 0) {
		return nil, accErr(http.StatusBadRequest, codeAccBadTarget, "这一项不接受出口或平台参数")
	}
	one := func(part, outcome, summary string, details []string) []acceptance.Result {
		return []acceptance.Result{{ItemID: it.ID, Part: part, Outcome: outcome, Summary: summary, Details: details}}
	}
	switch it.Action {
	case acceptance.ActionConfigAudit:
		return func(context.Context) []acceptance.Result { return s.accConfigAudit(c) }, nil

	case hostexec.ActionHealth:
		res := hostexec.Resources{Units: c.installed.Units, Interfaces: c.installed.Interfaces, NFTTables: c.installed.NFTTables, DNS: c.installed.DNS}
		req := hostexec.Request{Action: hostexec.ActionHealth, RequestID: "acc-health-" + randHex(4), Resources: res}
		if err := hostexec.Validate(req); err != nil {
			return nil, accErr(http.StatusConflict, codeAccNotApplicable, "已安装清单里有不受管的资源名：%s", err.Error())
		}
		return func(ctx context.Context) []acceptance.Result {
			out, err := s.Host.Do(ctx, req)
			var details []string
			for _, st := range out.Steps {
				mark := "通过"
				if !st.OK {
					mark = "失败"
				}
				details = append(details, st.Name+"："+mark)
			}
			details = append(details, out.Warnings...)
			switch {
			case err != nil && len(out.Steps) == 0:
				return one(acceptance.PartMeasured, acceptance.OutcomeError, "健康检查没有执行："+err.Error(), nil)
			case err != nil || !out.OK:
				return one(acceptance.PartMeasured, acceptance.OutcomeFail, "数据面健康检查失败："+out.Error, details)
			}
			return one(acceptance.PartMeasured, acceptance.OutcomePass, fmt.Sprintf("已安装的 %d 个单元、%d 个接口和 %d 张 nft 表都在（采样两次）", len(res.Units), len(res.Interfaces), len(res.NFTTables)), details)
		}, nil

	case acceptance.ActionResolverCheck:
		p, err := compile.ResolutionPlan(c.topo, s.unlockDecisions(c.topo))
		if err != nil {
			return nil, accErr(http.StatusConflict, codeAccNotApplicable, "拓扑没有通过校验：%s", err.Error())
		}
		want := map[string]bool{}
		for _, id := range body.Exits {
			want[id] = true
		}
		var exits []compile.DNSExitRow
		for _, ex := range p.Exits {
			if !ex.Checkable {
				if want[ex.ID] {
					return nil, accErr(http.StatusBadRequest, codeAccBadTarget, "出口 %s 没有可检查的隧道解析器", ex.ID)
				}
				continue
			}
			if len(want) == 0 || want[ex.ID] {
				exits = append(exits, ex)
				delete(want, ex.ID)
			}
		}
		if len(body.Exits) > 0 && len(want) > 0 {
			return nil, accErr(http.StatusBadRequest, codeAccBadTarget, "出口不在拓扑里")
		}
		if len(exits) == 0 {
			return nil, accErr(http.StatusConflict, codeAccNotApplicable, "没有可检查的出口解析器")
		}
		if len(exits) > accMaxDNSExits {
			if len(body.Exits) > 0 {
				return nil, accErr(http.StatusBadRequest, codeAccBadTarget, "一次最多检查 %d 个出口", accMaxDNSExits)
			}
			exits = exits[:accMaxDNSExits]
		}
		rt := s.Prober.(DNSCheckRuntime)
		return func(ctx context.Context) []acceptance.Result {
			okN, details := 0, []string{}
			for _, ex := range exits {
				if ctx.Err() != nil {
					details = append(details, "出口 "+ex.ID+"：已取消，没有检查")
					continue
				}
				cctx, cancel := context.WithTimeout(ctx, hostexec.DNSCheckTimeout+20*time.Second)
				res, err := rt.DNSCheck(cctx, hostexec.DNSCheckRequest{RequestID: "acc-dns-" + randHex(6), ExitID: ex.ID, Resolver: ex.Resolver})
				cancel()
				switch {
				case err != nil:
					details = append(details, "出口 "+ex.ID+"：没有完成（"+clipText(err.Error(), 120)+"）")
				case res.Outcome == "answer" || res.Outcome == "nxdomain":
					okN++
					details = append(details, fmt.Sprintf("出口 %s：隧道解析器回答了（%s，%d 毫秒）", ex.ID, res.Outcome, res.DurationMS))
				default:
					details = append(details, fmt.Sprintf("出口 %s：%s", ex.ID, res.Outcome))
				}
			}
			details = append(details, "解析器能回答不等于没有泄漏：客户端的 DNS 要按人工步骤在测试机上确认")
			if okN == len(exits) {
				return one(acceptance.PartMeasured, acceptance.OutcomePass, fmt.Sprintf("%d 个出口的隧道解析器都经隧道回答了（不代表无泄漏）", okN), details)
			}
			return one(acceptance.PartMeasured, acceptance.OutcomeFail, fmt.Sprintf("%d 个出口里有 %d 个的隧道解析器没有回答", len(exits), len(exits)-okN), details)
		}, nil

	case hostexec.CheckTunnelPaths:
		ifaces := c.tunnelInterfaces()
		if len(ifaces) > hostexec.MaxPathInterfaces {
			ifaces = ifaces[:hostexec.MaxPathInterfaces]
		}
		req := hostexec.PathCheckRequest{RequestID: "acc-path-" + randHex(6), Interfaces: ifaces}
		if err := hostexec.ValidatePathCheck(req); err != nil {
			return nil, accErr(http.StatusConflict, codeAccNotApplicable, "%s", err.Error())
		}
		return func(ctx context.Context) []acceptance.Result {
			res, err := s.Drill.PathCheck(ctx, req)
			if err != nil {
				return one(acceptance.PartMeasured, acceptance.OutcomeError, "隧道路径检查没有完成："+err.Error(), nil)
			}
			bad, details := 0, []string{}
			for _, l := range res.Links {
				switch {
				case l.State != "up":
					bad++
					details = append(details, fmt.Sprintf("接口 %s：%s", l.Interface, l.State))
				case l.Error != "":
					bad++
					details = append(details, fmt.Sprintf("接口 %s：%s", l.Interface, l.Error))
				case l.HandshakeAgeS == nil:
					bad++
					details = append(details, fmt.Sprintf("接口 %s：%d 个对端，还没有握手", l.Interface, l.Peers))
				case *l.HandshakeAgeS > hostexec.DrillBackupHandshake:
					bad++
					details = append(details, fmt.Sprintf("接口 %s：最近一次握手在 %d 秒前（超过 %d 秒）", l.Interface, *l.HandshakeAgeS, hostexec.DrillBackupHandshake))
				default:
					details = append(details, fmt.Sprintf("接口 %s：%d 个对端，%d 秒前握手", l.Interface, l.Peers, *l.HandshakeAgeS))
				}
			}
			journal := "没有部署记录"
			published := false
			if j, err := s.deployer(nil, nil).Load(); err != nil {
				journal = "部署记录读不出来"
			} else if j != nil {
				journal, published = j.State, j.State == mesh.StatePublished
			}
			details = append(details, "Mesh 部署记录："+journal, "这里只看到网关一侧的隧道；Mesh 在枢纽与出口之间的转发要按人工步骤抓包确认")
			switch {
			case bad > 0:
				return one(acceptance.PartMeasured, acceptance.OutcomeFail, fmt.Sprintf("%d 个隧道接口里有 %d 个不在、没有启用或没有近期握手", len(res.Links), bad), details)
			case !published:
				return one(acceptance.PartMeasured, acceptance.OutcomeInconclusive, "网关一侧的隧道都在握手，但 Mesh 路由没有处于「已发布」状态", details)
			}
			return one(acceptance.PartMeasured, acceptance.OutcomePass, fmt.Sprintf("网关一侧的 %d 个隧道接口都在握手，Mesh 路由已发布（不代表 Mesh 转发已验证）", len(res.Links)), details)
		}, nil

	case acceptance.ActionProbe:
		for _, id := range body.Services {
			if !probe.Probeable(id) {
				return nil, accErr(http.StatusBadRequest, codeAccBadTarget, "平台 %q 不在探测目录里", clipText(id, 40))
			}
		}
		for _, id := range body.Exits {
			if n, ok := c.topo.NodeByID(id); !ok || n.Role != model.RoleExit {
				return nil, accErr(http.StatusBadRequest, codeAccBadTarget, "出口不在拓扑里")
			}
		}
		if len(body.Exits) > maxSelectExits || len(body.Services) > len(probe.Catalog) {
			return nil, accErr(http.StatusBadRequest, codeAccBadTarget, "出口或平台数量超出上限")
		}
		sel := probeSelection{Services: body.Services, Exits: body.Exits}
		return func(ctx context.Context) []acceptance.Result {
			job, err := s.startProbeJob(unlock.KindManual, sel)
			if err != nil {
				return one(acceptance.PartMeasured, acceptance.OutcomeError, "解锁探测没有开始："+err.Error(), nil)
			}
			s.jobMu.Lock()
			h := s.job
			s.jobMu.Unlock()
			if h != nil && h.id == job.ID {
				select {
				case <-h.done:
				case <-ctx.Done():
					h.cancel()
					<-h.done
				}
			}
			s.mu.Lock()
			doc := s.loadJobs()
			s.mu.Unlock()
			for _, j := range doc.Jobs {
				if j.ID == job.ID {
					job = j
				}
			}
			return one(acceptance.PartMeasured, probeOutcome(job), probeSummary(job), probeDetails(job))
		}, nil
	}
	return nil, accErr(http.StatusBadRequest, codeBadRequest, "这一项没有可执行的固定动作")
}

func probeOutcome(j probeJob) string {
	switch {
	case j.State == jobCancelled:
		return acceptance.OutcomeCancelled
	case j.State != jobDone:
		return acceptance.OutcomeError
	}
	done := 0
	for _, it := range j.Items {
		if it.State == itemDone && it.Error == "" {
			done++
		}
	}
	if done == 0 {
		return acceptance.OutcomeFail
	}
	return acceptance.OutcomePass
}

func probeSummary(j probeJob) string {
	done, failed, skipped := 0, 0, 0
	exits := map[string]bool{}
	for _, it := range j.Items {
		exits[it.ExitID] = true
		switch {
		case it.State == itemSkipped:
			skipped++
		case it.State == itemDone && it.Error == "":
			done++
		default:
			failed++
		}
	}
	return fmt.Sprintf("探测任务 %s（%s）：%d 个出口，%d 项有结果，%d 项没有完成，%d 项跳过。各平台的结论与分级见「解锁」页；这不等于真实平台上能看", j.ID, j.State, len(exits), done, failed, skipped)
}

func probeDetails(j probeJob) []string {
	by := map[string]int{}
	for _, it := range j.Items {
		if it.State == itemDone && it.Grade != "" {
			by[string(it.Grade)]++
		}
	}
	var out []string
	for _, g := range []probe.Grade{probe.GradePlatform, probe.GradeReachability, probe.GradeUnknown, probe.GradeError, probe.GradeNotApplicable} {
		if n := by[string(g)]; n > 0 {
			out = append(out, fmt.Sprintf("分级 %s：%d 项", g, n))
		}
	}
	if j.Error != "" {
		out = append(out, clipText(j.Error, 200))
	}
	return out
}

// accConfigAudit reads the compiled bundle and stores the configuration
// part of every item that has one. A pass says the generated text contains
// the rules; it says nothing about the running host.
func (s *Server) accConfigAudit(c accContext) []acceptance.Result {
	checks := verify.CheckBundle(c.topo, c.bundle.Files)
	byID := map[string]verify.Item{}
	pass, fail, skip := 0, 0, 0
	var failing []string
	for _, v := range checks {
		byID[v.ID] = v
		if v.Scope != verify.ScopeAutomated {
			continue
		}
		switch v.Status {
		case verify.Pass:
			pass++
		case verify.Fail:
			fail++
			failing = append(failing, "配置缺失："+v.Title)
		default:
			skip++
		}
	}
	const note = "只说明生成的配置文本包含这些规则：不说明已经加载到网关，更不能证明实机不泄露"
	overall := acceptance.Result{ItemID: "config-audit", Part: acceptance.PartConfig, Action: acceptance.ActionConfigAudit, Outcome: acceptance.OutcomePass,
		Summary: fmt.Sprintf("%d 项配置包含，%d 项不适用（不等于实机通过）", pass, skip), Details: []string{note}}
	if fail > 0 {
		overall.Outcome = acceptance.OutcomeFail
		overall.Summary = fmt.Sprintf("%d 项配置缺失，%d 项配置包含", fail, pass)
		overall.Details = append(failing, note)
	}
	out := []acceptance.Result{overall}
	for _, it := range acceptance.Catalog() {
		if it.ID == "config-audit" || !it.Needs(acceptance.PartConfig) || len(it.ConfigChecks) == 0 {
			continue
		}
		if ok, _ := s.accApplicable(c, it); !ok {
			continue
		}
		p, f := 0, 0
		var details []string
		for _, id := range it.ConfigChecks {
			v, ok := byID[id]
			if !ok {
				continue
			}
			switch v.Status {
			case verify.Pass:
				p++
				details = append(details, "配置包含："+v.Title)
			case verify.Fail:
				f++
				details = append(details, "配置缺失："+v.Title)
			default:
				details = append(details, "不适用："+v.Title)
			}
		}
		r := acceptance.Result{ItemID: it.ID, Part: acceptance.PartConfig, Action: acceptance.ActionConfigAudit, Details: append(details, note)}
		switch {
		case f > 0:
			r.Outcome, r.Summary = acceptance.OutcomeFail, fmt.Sprintf("相关的生成配置有 %d 项缺失", f)
		case p > 0:
			r.Outcome, r.Summary = acceptance.OutcomePass, fmt.Sprintf("相关的 %d 项生成配置都包含（不等于实机通过）", p)
		default:
			r.Outcome, r.Summary = acceptance.OutcomeInconclusive, "相关的生成配置检查都不适用于这份拓扑"
		}
		out = append(out, r)
	}
	return out
}

// -------------------------------------------------- cancel and sign-off ---

func (s *Server) postAcceptanceCancel(w http.ResponseWriter, r *http.Request) {
	if err := decodeStrict(w, r, &struct{}{}, nil, nil, true); err != nil {
		writeResErr(w, err)
		return
	}
	id := r.PathValue("id")
	s.accMu.Lock()
	job := s.accJob
	var cancelJob context.CancelFunc
	if job != nil {
		cancelJob = job.cancel
	}
	s.accMu.Unlock()
	if job == nil || job.ItemID != id {
		writeCoded(w, http.StatusConflict, codeAccBusy, "这一项没有在执行", nil)
		return
	}
	if job.Drill {
		ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
		defer cancel()
		if _, err := s.Drill.DrillCancel(ctx, job.ID); err != nil {
			writeCoded(w, http.StatusBadGateway, codeHostUnavailable, "取消没有送到宿主代理："+err.Error()+"。宿主仍会在演练的截止时间自己恢复", nil)
			return
		}
		writeJSON(w, http.StatusAccepted, map[string]any{"cancelling": job.ID, "note": "宿主已开始恢复；恢复核对完成后这一项才结束"})
		return
	}
	if cancelJob != nil {
		cancelJob()
	}
	select {
	case <-job.done:
	case <-time.After(15 * time.Second):
	}
	writeJSON(w, http.StatusOK, map[string]any{"cancelled": job.ID})
}

type accSignoffBody struct {
	Outcome string `json:"outcome"`
	Note    string `json:"note"`
}

func (s *Server) postAcceptanceSignoff(w http.ResponseWriter, r *http.Request) {
	var body accSignoffBody
	if err := decodeStrict(w, r, &body, []string{"outcome", "note"}, nil, false); err != nil {
		writeResErr(w, err)
		return
	}
	it, c, err := s.accItem(r)
	if err != nil {
		writeAccErr(w, err)
		return
	}
	if !it.Needs(acceptance.PartSignoff) {
		writeCoded(w, http.StatusBadRequest, codeBadRequest, "这一项没有人工签收的部分：它的结果只能来自执行", nil)
		return
	}
	if body.Outcome != acceptance.OutcomePass && body.Outcome != acceptance.OutcomeFail {
		writeCoded(w, http.StatusBadRequest, codeBadRequest, "签收结果只能是通过（pass）或不通过（fail）", nil)
		return
	}
	if len(body.Note) > 4000 {
		writeCoded(w, http.StatusBadRequest, codeBadRequest, "备注过长", nil)
		return
	}
	summary := "人工签收：通过"
	if body.Outcome == acceptance.OutcomeFail {
		summary = "人工签收：不通过"
	}
	res, err := s.accStoreOf().Add(acceptance.Result{
		ItemID: it.ID, Part: acceptance.PartSignoff, Method: acceptance.ModeManual, Outcome: body.Outcome, At: s.now(),
		Fingerprint: c.fp, InstalledVersion: c.installed.Version, Summary: summary, Note: body.Note,
	})
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"result": res})
}

// ------------------------------------------------------ retry / release ---

type accDrillBody struct {
	ID string `json:"id"`
	// Confirm must be "release" for a release.
	Confirm string `json:"confirm,omitempty"`
}

func (s *Server) accDrillOp(w http.ResponseWriter, r *http.Request, release bool) {
	var body accDrillBody
	if err := decodeStrict(w, r, &body, []string{"id", "confirm"}, nil, false); err != nil {
		writeResErr(w, err)
		return
	}
	if s.Drill == nil {
		writeCoded(w, http.StatusServiceUnavailable, codeHostUnavailable, "面板没有宿主执行通道", nil)
		return
	}
	if release && body.Confirm != "release" {
		writeCoded(w, http.StatusBadRequest, codeConfirmRequired, "解除阻断要输入 release 确认：宿主没有被确认回到演练前的状态，这一项不会显示为已恢复", nil)
		return
	}
	// The same locks as a drill: a retry may re-activate the data plane.
	if !s.lockNode(localNodeID) {
		refuseBusy(w, localNodeID)
		return
	}
	defer s.unlockNode(localNodeID)
	unlockTxn, err := s.applier(true).Hold()
	if err != nil {
		writeCoded(w, http.StatusConflict, codeNodeBusy, err.Error(), nil)
		return
	}
	defer unlockTxn()
	var st hostexec.DrillStatus
	if release {
		ctx, cancel := context.WithTimeout(r.Context(), time.Minute)
		defer cancel()
		st, err = s.Drill.DrillRelease(ctx, body.ID)
	} else {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
		defer cancel()
		st, err = s.Drill.DrillRetry(ctx, body.ID)
	}
	if err != nil {
		code, status := codeAccRefused, http.StatusConflict
		if errors.Is(err, hostexec.ErrUnavailable) {
			code, status = codeHostUnavailable, http.StatusServiceUnavailable
		}
		writeCoded(w, status, code, err.Error(), map[string]any{"drill": drillRecordView(st.Record)})
		return
	}
	if st.Record != nil {
		s.accAdoptDrill(st.Record)
	}
	writeJSON(w, http.StatusOK, map[string]any{"drill": accDrillView{Available: true, Blocked: st.Blocked, Running: st.Running, Record: drillRecordView(st.Record)}})
}

func (s *Server) postAcceptanceDrillRetry(w http.ResponseWriter, r *http.Request) {
	s.accDrillOp(w, r, false)
}

func (s *Server) postAcceptanceDrillRelease(w http.ResponseWriter, r *http.Request) {
	s.accDrillOp(w, r, true)
}
