package mesh

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/radowitz/meridian/internal/model"
)

// Stages of a panel Mesh deployment, in order. Each one only starts when
// every earlier one succeeded.
//
//  1. plan       compute and validate both ends' IPv4/IPv6 addresses,
//     next-hops and interface scope; check topology conflicts
//     and the routes to publish. No side effects.
//  2. preflight  read-only check on every Mesh host: tools, existing Mesh
//     state not owned by this run, address/route conflicts,
//     stale "default dev mmesh" scripts on the hub.
//  3. cf_node    create one Cloudflare Mesh node per host. The sidecar
//     cannot enrol without its token, so this inert object (no
//     routes, status "inactive") has to exist before the
//     sidecar starts. Ownership is recorded before the call.
//  4. sidecar    write the compiled sidecar files and the token on each
//     host, start the sidecar, wire the veth with explicit
//     next-hops and seal it.
//  5. health     on each host: both veth next-hops answer, neighbour
//     entries only for them, policy rule and return routes in
//     the sidecar, warp-cli Connected; at Cloudflare: node
//     status "healthy". Nothing is published before this passes.
//  6. routes     publish the planned CIDR routes for the exit nodes.
//  7. activate   re-seal the sidecars of exits that publish a region-group
//     resolver address, then the hub, so each table 170 picks the
//     routes up.
//
// The resulting state is "published", and the data plane stays "unverified":
// publishing routes is not evidence that packets cross the Mesh.
const (
	StagePlan      = "plan"
	StagePreflight = "preflight"
	StageCFNode    = "cf_node"
	StageSidecar   = "sidecar"
	StageHealth    = "health"
	StageRoutes    = "routes"
	StageActivate  = "activate"
)

// Stages lists the stages in order.
var Stages = []string{StagePlan, StagePreflight, StageCFNode, StageSidecar, StageHealth, StageRoutes, StageActivate}

// Run states.
const (
	StateRunning            = "running"
	StatePublished          = "published"
	StateFailed             = "failed"              // failed; everything this run created was withdrawn
	StateCompensating       = "compensating"        // withdrawal in progress (or interrupted)
	StateCompensationFailed = "compensation_failed" // something could not be withdrawn; retry withdraw
	StateWithdrawn          = "withdrawn"           // operator withdrew a published run
)

// DataplaneUnverified is the only data-plane status the panel can report:
// it has no Linux packet-forwarding evidence (deploy/verify-mesh-veth.sh
// and the human checks in docs/verification.md).
const DataplaneUnverified = "unverified"

// Resource states for ownership records.
const (
	ResIntent  = "intent"  // recorded before the call; may or may not exist
	ResCreated = "created" // exists and this run created it
	ResRemoved = "removed" // withdrawn by compensation
)

// StageRecord is one stage of the persisted journal.
type StageRecord struct {
	Name     string   `json:"name"`
	Status   string   `json:"status"` // pending | running | done | failed | skipped
	Started  string   `json:"started,omitempty"`
	Finished string   `json:"finished,omitempty"`
	Error    string   `json:"error,omitempty"`
	Detail   []string `json:"detail,omitempty"`
}

// OwnedNode is a Cloudflare Mesh node this run created (or tried to).
type OwnedNode struct {
	NodeID string `json:"node_id"` // Meridian node
	Name   string `json:"name"`    // unique per run, used to find an intent after a crash
	CFID   string `json:"cf_id,omitempty"`
	State  string `json:"state"`
	Error  string `json:"error,omitempty"`
}

// OwnedRoute is a Cloudflare route this run published (or tried to).
type OwnedRoute struct {
	LinkID   string `json:"link_id"`
	ExitID   string `json:"exit_id"`
	Network  string `json:"network"`
	TunnelID string `json:"tunnel_id"`
	Comment  string `json:"comment"`
	CFID     string `json:"cf_id,omitempty"`
	State    string `json:"state"`
	Error    string `json:"error,omitempty"`
}

// HostPin is the SSH target a run actually used for one node: the address,
// port and user it connected to (after request-level overrides and the
// defaults were applied) and the SSH host key fingerprint the host
// presented on first contact. Every later action of the run, and every
// withdrawal of it, goes to exactly this target and requires exactly this
// key; the topology is never consulted again. Not a secret, but the
// operator's infrastructure: it lives only in the 0600 journal and in the
// panel's journal view.
//
// Schema 3 adds the managed server and the SSH credential the run used.
// A withdrawal connects through that server with that credential (its
// current generation, so a credential rotated in place keeps working); the
// credential store refuses to delete or re-point either while the run is
// not fully withdrawn.
type HostPin struct {
	NodeID       string     `json:"node_id"`
	Name         string     `json:"name,omitempty"`
	Role         model.Role `json:"role"`
	ServerID     string     `json:"server_id,omitempty"`
	CredentialID string     `json:"credential_id,omitempty"`
	SSHHost      string     `json:"ssh_host"`
	SSHPort      int        `json:"ssh_port"`
	SSHUser      string     `json:"ssh_user"`
	HostKey      string     `json:"host_key,omitempty"` // ssh.FingerprintSHA256 of the host key
}

func (h HostPin) target() NodeTarget {
	return NodeTarget{ID: h.NodeID, Name: h.Name, Role: h.Role, ServerID: h.ServerID, CredentialID: h.CredentialID,
		SSHHost: h.SSHHost, SSHPort: h.SSHPort, SSHUser: h.SSHUser, HostKey: h.HostKey}
}

func (h HostPin) addr() string { return fmt.Sprintf("%s@%s:%d", h.SSHUser, h.SSHHost, h.SSHPort) }

// pinFor snapshots a plan node's effective SSH target (port 22 and user
// root are the SSH defaults the remote applies when they are unset).
func pinFor(n NodeTarget) HostPin {
	h := HostPin{NodeID: n.ID, Name: n.Name, Role: n.Role, ServerID: n.ServerID, CredentialID: n.CredentialID,
		SSHHost: n.SSHHost, SSHPort: n.SSHPort, SSHUser: n.SSHUser, HostKey: n.HostKey}
	if h.SSHPort == 0 {
		h.SSHPort = 22
	}
	if h.SSHUser == "" {
		h.SSHUser = "root"
	}
	return h
}

// OwnedRemote is a host this run wrote sidecar files to (or tried to). It
// carries the pinned target it was written to, so compensation restores
// that machine and no other.
type OwnedRemote struct {
	NodeID string  `json:"node_id"`
	Host   HostPin `json:"host"`
	State  string  `json:"state"`
	Error  string  `json:"error,omitempty"`
}

// Journal is the persisted record of one deployment run
// (<DataDir>/mesh/deploy.json, 0600). It never contains a secret.
type Journal struct {
	Schema int    `json:"schema"`
	RunID  string `json:"run_id"`
	State  string `json:"state"`
	// AccountID is the Cloudflare account every node and route of this run
	// lives in. Compensation only runs with credentials for this account,
	// and the stored credentials cannot be switched to another account
	// until the run is fully withdrawn.
	AccountID string `json:"account_id"`
	// AccountRef is the credential-store account (its object id) the run
	// was started with; informational, the binding is AccountID.
	AccountRef string `json:"account_ref,omitempty"`
	// Hosts are the SSH targets the run pinned (one per plan node).
	Hosts      []HostPin     `json:"hosts"`
	Started    string        `json:"started"`
	Updated    string        `json:"updated"`
	FailAfter  string        `json:"fail_after,omitempty"`
	Stages     []StageRecord `json:"stages"`
	Nodes      []OwnedNode   `json:"nodes"`
	Routes     []OwnedRoute  `json:"routes"`
	Remotes    []OwnedRemote `json:"remotes"`
	Targets    []string      `json:"targets"`
	Error      string        `json:"error,omitempty"`
	CompErrors []string      `json:"compensation_errors,omitempty"`
	Dataplane  string        `json:"dataplane"`
}

// Busy reports whether the journal blocks a new run.
func (j *Journal) Busy() bool {
	if j == nil {
		return false
	}
	switch j.State {
	case StateRunning, StateCompensating, StateCompensationFailed, StatePublished:
		return true
	}
	return false
}

// ErrBusy: a run is in progress, published, or not fully withdrawn.
var ErrBusy = errors.New("已有 Mesh 部署处于进行中、已发布或补偿未完成的状态；先撤回（可重复执行）再部署")

// ErrNothingToWithdraw: there is no run with resources to withdraw.
var ErrNothingToWithdraw = errors.New("没有需要撤回的 Mesh 部署")

// ErrAccountMismatch: the stored Cloudflare credentials are not for the
// account the run deployed to; nothing is withdrawn with them.
var ErrAccountMismatch = errors.New("保存的 Cloudflare 凭据与部署记录绑定的账户不一致，拒绝撤回")

// ErrAccountLocked: a run that is not fully withdrawn is bound to its
// Cloudflare account; only the token of that account may be replaced.
var ErrAccountLocked = errors.New("还有已发布或未撤回完的 Mesh 部署绑定在原 Cloudflare 账户上；撤回完成前不能切换账户（同一账户可以更换 API token）")

// ErrCredentialsInUse: credentials cannot be deleted while a run needs them.
var ErrCredentialsInUse = errors.New("还有已发布或未撤回完的 Mesh 部署，撤回需要这份凭据；先撤回再删除")

// JournalSchema is the current journal format. Schema 2 added the pinned
// SSH targets and the Cloudflare account binding; schema 3 the managed
// server and SSH credential of each pinned host (see UpgradeJournal).
const JournalSchema = 3

// ErrHostsBlocked: a pinned host cannot be reached through its server and
// credential; the withdrawal did nothing.
var ErrHostsBlocked = errors.New("撤回被阻断：部署记录里的主机无法通过原服务器和 SSH 凭据连接，本次没有撤回任何东西")

// ErrJournalTooNew: the journal was written by a newer program.
var ErrJournalTooNew = errors.New("Mesh 部署记录的版本比本程序新，拒绝处理")

// Deployer runs and compensates deployments.
type Deployer struct {
	Dir string // <DataDir>/mesh
	// Creds, when set, is read under the deployment lock by Deploy and
	// Withdraw, and Connect builds the Cloudflare client from it; CF and
	// AccountID are then overwritten. Without Creds, CF and AccountID are
	// used as given (the account CF talks to).
	Creds     CredentialSource
	Connect   func(Credentials) (Cloudflare, error)
	CF        Cloudflare
	AccountID string
	Remote    Remote
	// Select, when set, is called by Deploy under the deployment lock after
	// the busy check and before the credentials are loaded (the panel
	// selects the requested account for Mesh there).
	Select func() error
	// ResolvePin fills ServerID / CredentialID of a pin recorded before
	// schema 3 (UpgradeJournal). It returns false when it cannot tell.
	ResolvePin func(h HostPin) (serverID, credentialID string, ok bool)
	// CheckHosts is called by Withdraw under the lock, before anything is
	// compensated; an error stops the withdrawal (wrapped in
	// ErrHostsBlocked) and nothing is changed.
	CheckHosts func(j *Journal) error
	accountRef string
	// Redact is applied to every string stored or returned.
	Redact *Redactor
	// Now is the clock (tests).
	Now func() time.Time
	// HealthWait bounds how long health waits for Cloudflare "healthy";
	// HealthPoll is the polling interval.
	HealthWait time.Duration
	HealthPoll time.Duration
	// FailAfter injects a failure after the named stage succeeded
	// (verification drill; the API only accepts it when
	// MERIDIAN_MESH_FAULT_INJECTION=1).
	FailAfter string
}

// deployMu serialises deployments, withdrawals and credential changes, so
// the account check and the credential write cannot interleave with a run.
var deployMu sync.Mutex

// bindCloudflare loads the stored credentials (under deployMu) and builds
// the client for them.
func (d *Deployer) bindCloudflare() error {
	if d.Creds == nil {
		return nil
	}
	c, err := d.Creds.Load()
	if err != nil {
		return err
	}
	if d.Redact != nil {
		d.Redact.Add(c.APIToken)
	}
	connect := d.Connect
	if connect == nil {
		connect = func(c Credentials) (Cloudflare, error) { return NewCFClient(c) }
	}
	cf, err := connect(c)
	if err != nil {
		return err
	}
	d.CF, d.AccountID, d.accountRef = cf, c.AccountID, c.Ref
	return nil
}

// SaveCredentials validates and stores c under the deployment lock. While a
// run is running, published or not fully withdrawn, only credentials for
// the account it deployed to are accepted (token rotation); switching to
// another account is refused with ErrAccountLocked.
func (d *Deployer) SaveCredentials(c Credentials) error {
	deployMu.Lock()
	defer deployMu.Unlock()
	if d.Creds == nil {
		return errors.New("没有凭据存储")
	}
	j, err := d.Load()
	if err != nil {
		return err
	}
	if j.Busy() {
		bound := j.AccountID
		if bound == "" {
			// A journal without an account binding: only the account that
			// is stored now may stay.
			cur, err := d.Creds.Load()
			if err != nil {
				return fmt.Errorf("%w：%v", ErrAccountLocked, err)
			}
			bound = cur.AccountID
		}
		if strings.TrimSpace(c.AccountID) != bound {
			return fmt.Errorf("%w（部署账户 %s）", ErrAccountLocked, bound)
		}
	}
	return d.Creds.Save(c)
}

// DeleteCredentials removes the stored credentials under the deployment
// lock, unless a run still needs them.
func (d *Deployer) DeleteCredentials() error {
	deployMu.Lock()
	defer deployMu.Unlock()
	if d.Creds == nil {
		return errors.New("没有凭据存储")
	}
	j, err := d.Load()
	if err != nil {
		return err
	}
	if j.Busy() {
		return ErrCredentialsInUse
	}
	return d.Creds.Delete()
}

func (d *Deployer) now() string {
	if d.Now != nil {
		return d.Now().UTC().Format(time.RFC3339)
	}
	return time.Now().UTC().Format(time.RFC3339)
}

func (d *Deployer) red(s string) string {
	if d.Redact == nil {
		return s
	}
	return d.Redact.Redact(s)
}

func (d *Deployer) path() string { return filepath.Join(d.Dir, "deploy.json") }

// Load returns the current journal, or nil.
func (d *Deployer) Load() (*Journal, error) {
	b, err := os.ReadFile(d.path())
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var j Journal
	if err := json.Unmarshal(b, &j); err != nil {
		return nil, errors.New("Mesh 部署记录损坏")
	}
	if j.Schema > JournalSchema {
		return nil, fmt.Errorf("%w（版本 %d）", ErrJournalTooNew, j.Schema)
	}
	return &j, nil
}

// upgrade brings a schema-2 journal to schema 3 in memory: every pin
// without a server gets the server and credential ResolvePin names, and
// the copy of the pin in each owned remote follows. A pin ResolvePin
// cannot place keeps an empty server id (the withdrawal of that host is
// then blocked, see CheckHosts). Pins already carrying a server are never
// changed. Schema-1 journals (no pins) are left alone. It reports whether
// anything changed.
func (d *Deployer) upgrade(j *Journal) bool {
	if j == nil || j.Schema < 2 {
		return false
	}
	changed := false
	if j.Schema < JournalSchema {
		j.Schema = JournalSchema
		changed = true
	}
	if d.ResolvePin == nil {
		return changed
	}
	for i := range j.Hosts {
		h := &j.Hosts[i]
		if h.ServerID != "" && h.CredentialID != "" {
			continue
		}
		sid, cid, ok := d.ResolvePin(*h)
		if !ok || sid == "" || (h.ServerID != "" && sid != h.ServerID) {
			continue
		}
		if h.ServerID == "" {
			h.ServerID = sid
			changed = true
		}
		if h.CredentialID == "" && cid != "" {
			h.CredentialID = cid
			changed = true
		}
		for k := range j.Remotes {
			rm := &j.Remotes[k]
			if rm.NodeID == h.NodeID && rm.Host.SSHHost == h.SSHHost && rm.Host.SSHPort == h.SSHPort && rm.Host.SSHUser == h.SSHUser && rm.Host.HostKey == h.HostKey {
				rm.Host.ServerID, rm.Host.CredentialID = h.ServerID, h.CredentialID
			}
		}
	}
	return changed
}

// UpgradeJournal upgrades and saves the current journal under the
// deployment lock (the panel calls it at startup). Idempotent.
func (d *Deployer) UpgradeJournal() (*Journal, error) {
	deployMu.Lock()
	defer deployMu.Unlock()
	j, err := d.Load()
	if err != nil || j == nil {
		return j, err
	}
	if d.upgrade(j) {
		if err := d.saveKeepTime(j); err != nil {
			return j, err
		}
	}
	return j, nil
}

func (d *Deployer) saveKeepTime(j *Journal) error {
	b, _ := json.MarshalIndent(j, "", "  ")
	return writeAtomic(d.path(), []byte(d.red(string(b))), 0o600)
}

func (d *Deployer) save(j *Journal) error {
	j.Updated = d.now()
	b, _ := json.MarshalIndent(j, "", "  ")
	return writeAtomic(d.path(), []byte(d.red(string(b))), 0o600)
}

func newRunID() string {
	var b [8]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

func (j *Journal) stage(name string) *StageRecord {
	for i := range j.Stages {
		if j.Stages[i].Name == name {
			return &j.Stages[i]
		}
	}
	return nil
}

// StageError is a failed run. Compensated is true only when everything the
// run created was withdrawn and restored.
type StageError struct {
	Stage       string
	Err         error
	Compensated bool
	CompErrors  []string
	Journal     *Journal
}

func (e *StageError) Error() string {
	if e.Compensated {
		return fmt.Sprintf("Mesh 部署在「%s」阶段失败，已撤回本次创建的路由、节点和 sidecar：%v", e.Stage, e.Err)
	}
	return fmt.Sprintf("Mesh 部署在「%s」阶段失败：%v；补偿未完成（%s）。部署记录已保留，修复后可重复执行撤回", e.Stage, e.Err, strings.Join(e.CompErrors, "；"))
}

func (e *StageError) Unwrap() error { return e.Err }

// Deploy runs every stage of plan. On failure it compensates and returns a
// *StageError. A successful run ends in StatePublished with the data plane
// still unverified.
func (d *Deployer) Deploy(ctx context.Context, plan Plan) (*Journal, error) {
	deployMu.Lock()
	defer deployMu.Unlock()
	prev, err := d.Load()
	if err != nil {
		return nil, err
	}
	if prev.Busy() {
		return prev, ErrBusy
	}
	if d.Select != nil {
		if err := d.Select(); err != nil {
			return nil, err
		}
	}
	if err := d.bindCloudflare(); err != nil {
		return nil, err
	}
	if !ValidAccountID(d.AccountID) {
		return nil, errors.New("没有可绑定的 Cloudflare 账户")
	}
	if err := os.MkdirAll(d.Dir, 0o700); err != nil {
		return nil, err
	}
	if prev != nil {
		b, _ := json.MarshalIndent(prev, "", "  ")
		_ = writeAtomic(filepath.Join(d.Dir, "deploy.previous.json"), b, 0o600)
	}
	j := &Journal{Schema: JournalSchema, RunID: newRunID(), State: StateRunning, AccountID: d.AccountID, AccountRef: d.accountRef, Started: d.now(), FailAfter: d.FailAfter, Dataplane: DataplaneUnverified}
	for _, s := range Stages {
		j.Stages = append(j.Stages, StageRecord{Name: s, Status: "pending"})
	}
	for _, n := range plan.Nodes {
		j.Targets = append(j.Targets, n.ID)
		j.Hosts = append(j.Hosts, pinFor(n))
	}
	if err := d.save(j); err != nil {
		return nil, err
	}
	steps := []struct {
		name string
		fn   func(context.Context, *Journal, Plan, *StageRecord) error
	}{
		{StagePlan, d.stagePlan},
		{StagePreflight, d.stagePreflight},
		{StageCFNode, d.stageCFNode},
		{StageSidecar, d.stageSidecar},
		{StageHealth, d.stageHealth},
		{StageRoutes, d.stageRoutes},
		{StageActivate, d.stageActivate},
	}
	for _, st := range steps {
		rec := j.stage(st.name)
		rec.Status = "running"
		rec.Started = d.now()
		if err := d.save(j); err != nil {
			return j, d.fail(ctx, j, st.name, err)
		}
		err := st.fn(ctx, j, plan, rec)
		if err == nil && d.FailAfter == st.name {
			err = fmt.Errorf("故障注入：在「%s」阶段完成后注入失败", st.name)
		}
		rec.Finished = d.now()
		if err != nil {
			rec.Status = "failed"
			rec.Error = d.red(err.Error())
			return j, d.fail(ctx, j, st.name, err)
		}
		rec.Status = "done"
		if err := d.save(j); err != nil {
			return j, d.fail(ctx, j, st.name, err)
		}
	}
	j.State = StatePublished
	if err := d.save(j); err != nil {
		return j, err
	}
	return j, nil
}

func (d *Deployer) fail(ctx context.Context, j *Journal, stage string, cause error) error {
	for i := range j.Stages {
		if j.Stages[i].Status == "pending" {
			j.Stages[i].Status = "skipped"
		}
	}
	j.Error = d.red(cause.Error())
	compErrs := d.compensate(ctx, j)
	if len(compErrs) == 0 {
		j.State = StateFailed
	} else {
		j.State = StateCompensationFailed
	}
	_ = d.save(j)
	return &StageError{Stage: stage, Err: errors.New(d.red(cause.Error())), Compensated: len(compErrs) == 0, CompErrors: compErrs, Journal: j}
}

// Withdraw compensates the current run: a published one (operator
// withdrawal), a failed one whose compensation did not finish, or one that
// was interrupted. It is idempotent: finished steps are skipped.
func (d *Deployer) Withdraw(ctx context.Context) (*Journal, error) {
	deployMu.Lock()
	defer deployMu.Unlock()
	j, err := d.Load()
	if err != nil {
		return nil, err
	}
	if j == nil || !j.Busy() {
		return j, ErrNothingToWithdraw
	}
	if d.upgrade(j) {
		if err := d.saveKeepTime(j); err != nil {
			return j, err
		}
	}
	// Compensation acts only in the account the run deployed to. The
	// credentials are read here, under the same lock that SaveCredentials
	// takes, so they cannot change between this check and the calls.
	if err := d.bindCloudflare(); err != nil {
		return j, err
	}
	if j.AccountID == "" {
		return j, fmt.Errorf("%w：部署记录没有绑定 Cloudflare 账户", ErrAccountMismatch)
	}
	if d.AccountID != j.AccountID {
		return j, fmt.Errorf("%w：凭据账户 %s，部署账户 %s；请先保存原账户的凭据", ErrAccountMismatch, d.AccountID, j.AccountID)
	}
	if d.CheckHosts != nil {
		if err := d.CheckHosts(j); err != nil {
			return j, fmt.Errorf("%w：%s", ErrHostsBlocked, d.red(err.Error()))
		}
	}
	published := j.State == StatePublished
	if j.State == StateRunning && j.Error == "" {
		j.Error = "部署被中断（进程重启或超时），按撤回处理"
	}
	errs := d.compensate(ctx, j)
	switch {
	case len(errs) > 0:
		j.State = StateCompensationFailed
	case published || j.Error == "":
		// A published run (or the retry of its withdrawal: it never had
		// a stage error) ends as withdrawn, not as a failed deployment.
		j.State = StateWithdrawn
	default:
		j.State = StateFailed
	}
	if err := d.save(j); err != nil {
		return j, err
	}
	if len(errs) > 0 {
		return j, &StageError{Stage: "withdraw", Err: errors.New("撤回未完成"), CompErrors: errs, Journal: j}
	}
	return j, nil
}

// compensate withdraws, in reverse order, only what this run owns:
// published routes, the sidecar and files on each host, then the
// Cloudflare nodes. Each record is saved as soon as it changes, so a crash
// in the middle resumes where it stopped. It continues past a failure and
// returns every error.
func (d *Deployer) compensate(ctx context.Context, j *Journal) []string {
	j.State = StateCompensating
	j.CompErrors = nil
	_ = d.save(j)
	var errs []string
	note := func(what string, err error) string {
		msg := d.red(fmt.Sprintf("%s：%v", what, err))
		errs = append(errs, msg)
		return msg
	}
	// 1. routes
	for i := range j.Routes {
		r := &j.Routes[i]
		if r.State == ResRemoved {
			continue
		}
		if err := d.removeRoute(ctx, r); err != nil {
			r.Error = note("撤回路由 "+r.Network, err)
		} else {
			r.State, r.Error = ResRemoved, ""
		}
		_ = d.save(j)
	}
	// 2. hosts: restore managed files and remove what the run created.
	for i := range j.Remotes {
		rm := &j.Remotes[i]
		if rm.State == ResRemoved {
			continue
		}
		err := d.restoreHost(ctx, j, rm)
		if err != nil {
			rm.Error = note("恢复主机 "+rm.NodeID, err)
		} else {
			rm.State, rm.Error = ResRemoved, ""
		}
		_ = d.save(j)
	}
	// 3. Cloudflare nodes.
	for i := range j.Nodes {
		n := &j.Nodes[i]
		if n.State == ResRemoved {
			continue
		}
		if err := d.removeNode(ctx, n); err != nil {
			n.Error = note("删除 Cloudflare 节点 "+n.Name, err)
		} else {
			n.State, n.Error = ResRemoved, ""
		}
		_ = d.save(j)
	}
	j.CompErrors = errs
	return errs
}

// restoreHost runs the restore script on the pinned target the run wrote
// to, requiring the host key seen at deploy time. A host that reports no
// backup directory for the run counts as restored only if the run never
// confirmed an install there (the install script creates that directory
// before it writes anything); for a confirmed install it is an error: the
// files, token and sidecar are somewhere this withdrawal did not reach.
func (d *Deployer) restoreHost(ctx context.Context, j *Journal, rm *OwnedRemote) error {
	h := rm.Host
	if h.NodeID == "" {
		h.NodeID = rm.NodeID
	}
	if h.SSHHost == "" || h.HostKey == "" {
		return errors.New("部署记录没有固定这台主机的 SSH 地址与主机指纹，拒绝在无法确认身份的主机上恢复；请人工检查原主机")
	}
	script, err := RestoreScript(j.RunID, DefaultAddressing())
	if err != nil {
		return err
	}
	out, seen, err := d.Remote.Exec(ctx, h.target(), ActRestore, script)
	if err == nil && seen != h.HostKey {
		err = fmt.Errorf("%s 出示的 SSH 主机指纹 %q 不是部署时固定的 %s", h.addr(), seen, h.HostKey)
	}
	if err == nil {
		switch {
		case strings.Contains(out, "MESH_RESTORE_ABSENT"):
			if rm.State == ResCreated {
				err = fmt.Errorf("%s 上没有本次运行（%s）的备份目录，但部署记录显示 sidecar 已在这台主机安装；不能当作已恢复，请人工检查", h.addr(), j.RunID)
			}
		case strings.Contains(out, "MESH_RESTORE_OK"):
		default:
			err = errors.New("恢复脚本没有报告 MESH_RESTORE_OK")
		}
	}
	if err != nil {
		return fmt.Errorf("%v %s", err, tail(d.red(out)))
	}
	return nil
}

// pin returns the pinned target of a node of this run.
func (j *Journal) pin(id string) *HostPin {
	for i := range j.Hosts {
		if j.Hosts[i].NodeID == id {
			return &j.Hosts[i]
		}
	}
	return nil
}

// exec runs a fixed action on a node of the run through its pinned target.
// The first contact records the host key; every later one requires it.
func (d *Deployer) exec(ctx context.Context, j *Journal, id string, act Action, script string) (string, error) {
	h := j.pin(id)
	if h == nil {
		return "", fmt.Errorf("节点 %s 不在本次运行的主机列表里", id)
	}
	out, seen, err := d.Remote.Exec(ctx, h.target(), act, script)
	if err != nil {
		return out, err
	}
	switch {
	case seen == "":
		return out, fmt.Errorf("%s 没有报告 SSH 主机指纹", h.addr())
	case h.HostKey == "":
		h.HostKey = seen
		if err := d.save(j); err != nil {
			return out, err
		}
	case seen != h.HostKey:
		return out, fmt.Errorf("%s 出示的 SSH 主机指纹 %s 不是本次运行首次连接时的 %s", h.addr(), seen, h.HostKey)
	}
	return out, nil
}

func (d *Deployer) removeRoute(ctx context.Context, r *OwnedRoute) error {
	if r.CFID == "" {
		// The create call may have succeeded without us seeing the id.
		if r.TunnelID == "" {
			return nil
		}
		list, err := d.CF.ListRoutes(ctx, r.TunnelID)
		if err != nil {
			return err
		}
		for _, x := range list {
			if x.Network == r.Network && x.Comment == r.Comment && x.DeletedAt == "" {
				r.CFID = x.ID
			}
		}
		if r.CFID == "" {
			return nil
		}
	}
	err := d.CF.DeleteRoute(ctx, r.CFID)
	if err == nil {
		return nil
	}
	// Treat "already gone" as done only if it really is not listed.
	if errors.Is(err, ErrNotFound) {
		list, lerr := d.CF.ListRoutes(ctx, r.TunnelID)
		if lerr != nil {
			return err
		}
		for _, x := range list {
			if x.ID == r.CFID && x.DeletedAt == "" {
				return err
			}
		}
		return nil
	}
	return err
}

func (d *Deployer) removeNode(ctx context.Context, n *OwnedNode) error {
	if n.CFID == "" {
		list, err := d.CF.ListNodes(ctx)
		if err != nil {
			return err
		}
		for _, x := range list {
			if x.Name == n.Name && x.DeletedAt == "" {
				n.CFID = x.ID
			}
		}
		if n.CFID == "" {
			return nil
		}
	}
	err := d.CF.DeleteNode(ctx, n.CFID)
	if err == nil {
		return nil
	}
	if errors.Is(err, ErrNotFound) {
		got, gerr := d.CF.GetNode(ctx, n.CFID)
		if errors.Is(gerr, ErrNotFound) || (gerr == nil && got.DeletedAt != "") {
			return nil
		}
	}
	return err
}

func (d *Deployer) stagePlan(_ context.Context, j *Journal, p Plan, rec *StageRecord) error {
	a := p.Addressing
	rec.Detail = append(rec.Detail,
		fmt.Sprintf("IPv4 主机 %s dev %s ↔ sidecar %s dev %s；出口表 default via %s dev %s", a.HostV4CIDR(), a.HostIface, a.SidecarV4CIDR(), a.PeerIface, a.NextHopV4(), a.HostIface),
		fmt.Sprintf("IPv6 主机 %s dev %s ↔ sidecar %s dev %s；出口表 default via %s dev %s（链路本地，作用域 %s）", a.HostV6CIDR(), a.HostIface, a.SidecarV6CIDR(), a.PeerIface, a.NextHopV6(), a.HostIface, a.HostIface),
		fmt.Sprintf("固定 MAC %s / %s，双方永久邻居；sidecar 回程 %s via %s、%s via %s", a.HostMAC, a.SidecarMAC, strings.Join(p.ReturnV4, " "), a.HostV4, strings.Join(p.ReturnV6, " "), a.HostV6),
	)
	for _, r := range p.Routes {
		rec.Detail = append(rec.Detail, fmt.Sprintf("待发布路由 %s → 出口 %s（边 %s）", r.Network, r.ExitID, r.LinkID))
	}
	if !p.OK() {
		var msgs []string
		for _, is := range p.Issues {
			msgs = append(msgs, is.Message)
		}
		return errors.New(strings.Join(msgs, "；"))
	}
	for _, n := range p.Nodes {
		if n.SSHHost == "" {
			return fmt.Errorf("节点 %s 没有 SSH 主机", n.ID)
		}
	}
	return nil
}

func (d *Deployer) stagePreflight(ctx context.Context, j *Journal, p Plan, rec *StageRecord) error {
	var failed []string
	for _, n := range p.Nodes {
		script, err := PreflightScript(j.RunID, n.Role, p.Addressing)
		if err != nil {
			return err
		}
		out, err := d.exec(ctx, j, n.ID, ActPreflight, script)
		for _, l := range ParseChecks(d.red(out)) {
			rec.Detail = append(rec.Detail, n.ID+": "+l)
		}
		if err != nil || !strings.Contains(out, "MESH_PREFLIGHT_OK") {
			failed = append(failed, n.ID)
		}
	}
	if len(failed) > 0 {
		return fmt.Errorf("预检发现冲突或无法连接：%s", strings.Join(failed, ", "))
	}
	return nil
}

func (d *Deployer) stageCFNode(ctx context.Context, j *Journal, p Plan, rec *StageRecord) error {
	for _, n := range p.Nodes {
		name := fmt.Sprintf("meridian-%s-%s", n.ID, j.RunID)
		j.Nodes = append(j.Nodes, OwnedNode{NodeID: n.ID, Name: name, State: ResIntent})
		idx := len(j.Nodes) - 1
		if err := d.save(j); err != nil {
			return err
		}
		got, err := d.CF.CreateNode(ctx, name)
		if err != nil {
			return fmt.Errorf("创建 Cloudflare Mesh 节点 %s：%w", name, err)
		}
		j.Nodes[idx].CFID, j.Nodes[idx].State = got.ID, ResCreated
		rec.Detail = append(rec.Detail, fmt.Sprintf("%s: Cloudflare 节点 %s（%s，状态 %s）", n.ID, name, got.ID, got.Status))
		if err := d.save(j); err != nil {
			return err
		}
	}
	return nil
}

func (j *Journal) cfID(node string) string {
	for _, n := range j.Nodes {
		if n.NodeID == node && n.State == ResCreated {
			return n.CFID
		}
	}
	return ""
}

func (d *Deployer) stageSidecar(ctx context.Context, j *Journal, p Plan, rec *StageRecord) error {
	for _, n := range p.Nodes {
		id := j.cfID(n.ID)
		if id == "" {
			return fmt.Errorf("节点 %s 没有本次创建的 Cloudflare 节点", n.ID)
		}
		// Retry only the token request on failure (Cloudflare guidance);
		// never recreate the node here.
		var tok string
		var err error
		for attempt := 0; attempt < 3; attempt++ {
			if tok, err = d.CF.NodeToken(ctx, id); err == nil {
				break
			}
		}
		if err != nil {
			return fmt.Errorf("读取节点 %s 的令牌：%w", n.ID, err)
		}
		if d.Redact != nil {
			d.Redact.Add(tok)
		}
		script, err := InstallScript(j.RunID, n.Files, tok)
		if err != nil {
			return err
		}
		h := j.pin(n.ID)
		if h == nil || h.HostKey == "" {
			return fmt.Errorf("节点 %s 没有在预检中固定 SSH 主机指纹", n.ID)
		}
		j.Remotes = append(j.Remotes, OwnedRemote{NodeID: n.ID, Host: *h, State: ResIntent})
		idx := len(j.Remotes) - 1
		if err := d.save(j); err != nil {
			return err
		}
		out, err := d.exec(ctx, j, n.ID, ActInstall, script)
		if err == nil && !strings.Contains(out, "MESH_INSTALL_OK") {
			err = errors.New("安装脚本没有报告 MESH_INSTALL_OK")
		}
		if err != nil {
			return fmt.Errorf("%s 部署 sidecar：%v %s", n.ID, err, tail(d.red(out)))
		}
		j.Remotes[idx].State = ResCreated
		rec.Detail = append(rec.Detail, n.ID+": sidecar 已启动并封装（两个下一跳在主机侧可达）")
		if err := d.save(j); err != nil {
			return err
		}
	}
	return nil
}

func (d *Deployer) stageHealth(ctx context.Context, j *Journal, p Plan, rec *StageRecord) error {
	var failed []string
	for _, n := range p.Nodes {
		script, err := HealthScript(j.RunID, p.Addressing, p.ReturnV4, p.ReturnV6)
		if err != nil {
			return err
		}
		out, err := d.exec(ctx, j, n.ID, ActHealth, script)
		for _, l := range ParseChecks(d.red(out)) {
			rec.Detail = append(rec.Detail, n.ID+": "+l)
		}
		if err != nil || !strings.Contains(out, "MESH_HEALTH_OK") {
			failed = append(failed, n.ID)
		}
	}
	if len(failed) > 0 {
		return fmt.Errorf("sidecar 健康检查失败：%s", strings.Join(failed, ", "))
	}
	wait, poll := d.HealthWait, d.HealthPoll
	if wait <= 0 {
		wait = 2 * time.Minute
	}
	if poll <= 0 {
		poll = 5 * time.Second
	}
	for _, n := range p.Nodes {
		id := j.cfID(n.ID)
		deadline := time.Now().Add(wait)
		for {
			got, err := d.CF.GetNode(ctx, id)
			if err == nil && got.Status == "healthy" {
				rec.Detail = append(rec.Detail, n.ID+": Cloudflare 节点状态 healthy")
				break
			}
			if time.Now().After(deadline) {
				if err != nil {
					return fmt.Errorf("%s: 读取 Cloudflare 节点状态失败：%w", n.ID, err)
				}
				return fmt.Errorf("%s: Cloudflare 节点状态是 %q，不是 healthy", n.ID, got.Status)
			}
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(poll):
			}
		}
	}
	return nil
}

func (d *Deployer) stageRoutes(ctx context.Context, j *Journal, p Plan, rec *StageRecord) error {
	for _, r := range p.Routes {
		tunnel := j.cfID(r.ExitID)
		if tunnel == "" {
			return fmt.Errorf("出口 %s 没有本次创建的 Cloudflare 节点", r.ExitID)
		}
		comment := fmt.Sprintf("meridian run %s link %s", j.RunID, r.LinkID)
		j.Routes = append(j.Routes, OwnedRoute{LinkID: r.LinkID, ExitID: r.ExitID, Network: r.Network, TunnelID: tunnel, Comment: comment, State: ResIntent})
		idx := len(j.Routes) - 1
		if err := d.save(j); err != nil {
			return err
		}
		got, err := d.CF.CreateRoute(ctx, r.Network, tunnel, comment)
		if err != nil {
			return fmt.Errorf("发布路由 %s：%w", r.Network, err)
		}
		j.Routes[idx].CFID, j.Routes[idx].State = got.ID, ResCreated
		rec.Detail = append(rec.Detail, fmt.Sprintf("已发布 %s → %s（%s）", r.Network, r.ExitID, got.ID))
		if err := d.save(j); err != nil {
			return err
		}
	}
	return nil
}

func (d *Deployer) stageActivate(ctx context.Context, j *Journal, p Plan, rec *StageRecord) error {
	hub, ok := p.Hub()
	if !ok {
		return errors.New("计划里没有枢纽")
	}
	// An exit that answers a region group's resolver over the Mesh replies
	// through its own sidecar's table 170, which must hold the Mesh routes
	// Cloudflare installed after the sidecar was sealed. Exits first, the
	// hub last (its table 170 picks up the routes just published).
	seen := map[string]bool{}
	for _, r := range p.Routes {
		if r.Purpose != PurposeGroupResolver || seen[r.ExitID] {
			continue
		}
		seen[r.ExitID] = true
		if err := d.refresh(ctx, j, r.ExitID, rec); err != nil {
			return fmt.Errorf("出口 %s 重新封装：%v", r.ExitID, err)
		}
	}
	if err := d.refresh(ctx, j, hub.ID, rec); err != nil {
		return fmt.Errorf("枢纽重新封装：%v", err)
	}
	rec.Detail = append(rec.Detail, "路由已发布。数据面仍是「未验证」：需要 deploy/verify-mesh-veth.sh 与真实转发证据。")
	return nil
}

// refresh re-seals one host's sidecar (RefreshScript) and records its
// table 170.
func (d *Deployer) refresh(ctx context.Context, j *Journal, nodeID string, rec *StageRecord) error {
	script, err := RefreshScript(j.RunID)
	if err != nil {
		return err
	}
	out, err := d.exec(ctx, j, nodeID, ActRefresh, script)
	for _, l := range ParseChecks(d.red(out)) {
		rec.Detail = append(rec.Detail, nodeID+": "+l)
	}
	if err == nil && !strings.Contains(out, "MESH_REFRESH_OK") {
		err = errors.New("刷新脚本没有报告 MESH_REFRESH_OK")
	}
	if err != nil {
		return fmt.Errorf("%v %s", err, tail(d.red(out)))
	}
	return nil
}

func tail(s string) string {
	s = strings.TrimSpace(s)
	if len(s) > 600 {
		s = "…" + s[len(s)-600:]
	}
	return s
}

// StageDetail returns the recorded detail lines of a stage.
func (j *Journal) StageDetail(name string) []string {
	if s := j.stage(name); s != nil {
		return s.Detail
	}
	return nil
}
