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
//  1. plan       validate the allocated exit /32 and WireGuard leg,
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
//  7. activate   re-seal the exit sidecars, then the shared hub.
//     Only WireGuard UDP to allocated peer addresses is carried.
//
// The resulting state is "published", and the data plane stays "unverified":
// publishing routes is not evidence that packets cross the Mesh.
const (
	StagePlan      = "plan"
	StagePreflight = "preflight"
	StageCFNode    = "cf_node"
	StageInstall   = "install" // the host-level Linux connector
	StageHealth    = "health"
	StageActivate  = "activate"
	// StageSidecar / StageRoutes: stages of deployments made while the
	// panel installed Docker sidecars and published routes; only found in
	// old journals.
	StageSidecar = "sidecar"
	StageRoutes  = "routes"
)

// Stages lists the stages in order.
var Stages = []string{StagePlan, StagePreflight, StageCFNode, StageInstall, StageHealth, StageActivate}

// Run states.
const (
	StateRunning            = "running"
	StatePublished          = "published"
	StateFailed             = "failed"              // failed; everything this run created was withdrawn
	StateCompensating       = "compensating"        // withdrawal in progress (or interrupted)
	StateCompensationFailed = "compensation_failed" // something could not be withdrawn; retry withdraw
	StateWithdrawn          = "withdrawn"           // operator withdrew a published run
	// StatePendingProvision (legs only): an end got its connector in this
	// run; the leg is used after the hub and exit are re-provisioned with
	// the new Mesh address and deployed again.
	StatePendingProvision = "pending_provision"
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
	NodeID string `json:"node_id"`
	// Kind is RemoteConnector for a host-level Linux connector this run
	// installed; "" (RemoteSidecar) for a legacy Docker sidecar record.
	Kind string `json:"kind,omitempty"`
	// Created lists what the connector install actually created on the
	// host (repo, key, package, registration), as reported by the host;
	// withdrawal removes exactly these and nothing that existed before.
	Created []string `json:"created,omitempty"`
	// MeshAddr / MeshIface: what the installed connector reported.
	MeshAddr  string  `json:"mesh_addr,omitempty"`
	MeshIface string  `json:"mesh_iface,omitempty"`
	RunID     string  `json:"run_id,omitempty"` // backup owner, stable across incremental runs
	Host      HostPin `json:"host"`
	State     string  `json:"state"`
	Error     string  `json:"error,omitempty"`
}

// Kinds of OwnedRemote.
const (
	RemoteSidecar   = ""
	RemoteConnector = "host_connector"
)

// Journal is the persisted record of one deployment run
// (<DataDir>/mesh/deploy.json, 0600). It never contains a secret.
type Journal struct {
	Schema        int         `json:"schema"`
	Underlay      bool        `json:"underlay,omitempty"`
	Legs          []LegRecord `json:"legs,omitempty"`
	Baseline      *Journal    `json:"baseline,omitempty"` // durable rollback boundary for an incremental run
	WithdrawLinks []string    `json:"withdraw_links,omitempty"`
	RunID         string      `json:"run_id"`
	State         string      `json:"state"`
	// AccountID is the Cloudflare account every node and route of this run
	// lives in. Compensation only runs with credentials for this account,
	// and the stored credentials cannot be switched to another account
	// until the run is fully withdrawn.
	AccountID string `json:"account_id"`
	// AccountRef is the credential-store account (its object id) the run
	// was started with; informational, the binding is AccountID.
	AccountRef string `json:"account_ref,omitempty"`
	// Hosts are the SSH targets the run pinned (one per plan node).
	Hosts     []HostPin     `json:"hosts"`
	Started   string        `json:"started"`
	Updated   string        `json:"updated"`
	FailAfter string        `json:"fail_after,omitempty"`
	Stages    []StageRecord `json:"stages"`
	Nodes     []OwnedNode   `json:"nodes"`
	Routes    []OwnedRoute  `json:"routes"`
	Remotes   []OwnedRemote `json:"remotes"`
	Targets   []string      `json:"targets"`
	// Existing are the plan nodes that reuse a host-level Mesh node
	// (origin existing_host). Nothing of theirs is ever recorded as owned,
	// and compensation and withdrawal never act on them.
	Existing   []string `json:"existing_hosts,omitempty"`
	Error      string   `json:"error,omitempty"`
	CompErrors []string `json:"compensation_errors,omitempty"`
	Dataplane  string   `json:"dataplane"`
}

// Busy reports whether the journal owns resources and locks its account.
// Published underlay runs may accept additional, unchanged-host legs.
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
var ErrBusy = errors.New("Mesh 没有可新增的腿，或存在待恢复 / 旧版部署；旧版须先撤回、重新下发枢纽和出口再部署，未完成恢复可重试撤回")

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
// Schema 4 separates shared resources from legs and persists incremental
// rollback boundaries and individual withdrawal selections.
const JournalSchema = 4

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
	// HostDetected stores the detection of a node this run installed
	// (panel-owned); HostRemoved invalidates it once the node is removed.
	HostDetected func(model.HostMeshDetection) error
	HostRemoved  func(nodeID string)
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
		return fmt.Sprintf("Mesh 部署在「%s」阶段失败，已撤回本次创建的 Cloudflare 节点和主机上的安装：%v", e.Stage, e.Err)
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
	if prev.Busy() && (prev.State != StatePublished || !prev.Underlay) {
		return prev, ErrBusy
	}
	if prev != nil && prev.State == StatePublished {
		if err := checkIncrement(prev, plan); err != nil {
			return prev, err
		}
	}
	if d.Select != nil {
		if err := d.Select(); err != nil {
			return nil, err
		}
	}
	if err := d.bindCloudflare(); err != nil {
		return nil, err
	}
	if prev != nil && prev.Busy() && d.AccountID != prev.AccountID {
		return prev, ErrAccountMismatch
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
	j.Underlay = true
	if prev != nil && prev.State == StatePublished {
		j.Baseline = prev
		j.Nodes = append(j.Nodes, prev.Nodes...)
		j.Remotes = append(j.Remotes, prev.Remotes...)
		j.Routes = append(j.Routes, prev.Routes...)
	}
	for _, leg := range plan.Legs {
		state := StateRunning
		if prev != nil && prev.State == StatePublished && prev.legPublished(leg.LinkID) {
			state = StatePublished
		}
		j.Legs = append(j.Legs, LegRecord{LegPlan: leg, State: state})
	}
	for _, s := range Stages {
		j.Stages = append(j.Stages, StageRecord{Name: s, Status: "pending"})
	}
	for _, n := range plan.Nodes {
		j.Targets = append(j.Targets, n.ID)
		j.Hosts = append(j.Hosts, pinFor(n))
		if n.Existing() {
			j.Existing = append(j.Existing, n.ID)
		}
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
		{StageInstall, d.stageInstall},
		{StageHealth, d.stageHealth},
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
	for i := range j.Legs {
		if j.Legs[i].Reuse == ReusePending {
			j.Legs[i].State = StatePendingProvision
		} else {
			j.Legs[i].State = StatePublished
		}
	}
	j.Baseline = nil
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
	recovery, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	compErrs := d.compensate(recovery, j)
	if len(compErrs) == 0 {
		j.State = StateFailed
		for i := range j.Legs {
			if j.Legs[i].State != StatePublished {
				j.Legs[i].State = StateFailed
			}
		}
		if j.Baseline != nil {
			*j = *j.Baseline
		}
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
	return d.withdraw(ctx, "")
}

func (d *Deployer) withdraw(ctx context.Context, link string) (*Journal, error) {
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
	if link != "" {
		if j.State != StatePublished || !j.Underlay {
			return j, ErrBusy
		}
		found := false
		for _, leg := range j.Legs {
			found = found || (leg.LinkID == link && leg.State != StateWithdrawn)
		}
		if !found {
			return j, ErrNothingToWithdraw
		}
		j.WithdrawLinks = []string{link}
		if err := d.save(j); err != nil {
			return j, err
		}
	}
	published := j.State == StatePublished
	baseline := j.Baseline
	if j.State == StateRunning && j.Error == "" {
		j.Error = "部署被中断（进程重启或超时），按撤回处理"
	}
	errs := d.compensate(ctx, j)
	switch {
	case len(errs) == 0 && baseline != nil:
		*j = *baseline
	case len(errs) > 0:
		j.State = StateCompensationFailed
	case len(j.WithdrawLinks) > 0:
		for i := range j.Legs {
			for _, id := range j.WithdrawLinks {
				if j.Legs[i].LinkID == id {
					j.Legs[i].State = StateWithdrawn
				}
			}
		}
		j.WithdrawLinks = nil
		j.State = StateWithdrawn
		for _, leg := range j.Legs {
			if leg.State != StateWithdrawn {
				j.State = StatePublished
			}
		}
	case published || j.Error == "":
		// A published run (or the retry of its withdrawal: it never had
		// a stage error) ends as withdrawn, not as a failed deployment.
		j.State = StateWithdrawn
		for i := range j.Legs {
			j.Legs[i].State = StateWithdrawn
		}
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
	var errs []string
	if err := d.save(j); err != nil {
		return append(errs, "保存撤回进度失败："+d.red(err.Error()))
	}
	note := func(what string, err error) string {
		msg := d.red(fmt.Sprintf("%s：%v", what, err))
		errs = append(errs, msg)
		return msg
	}
	// 1. routes
	for i := range j.Routes {
		r := &j.Routes[i]
		if r.State == ResRemoved || j.keepRoute(*r) {
			continue
		}
		if err := d.removeRoute(ctx, r); err != nil {
			r.Error = note("撤回路由 "+r.Network, err)
		} else {
			r.State, r.Error = ResRemoved, ""
		}
		if err := d.save(j); err != nil {
			return append(errs, "保存撤回进度失败："+d.red(err.Error()))
		}
	}
	// 2. hosts: restore managed files and remove what the run created.
	for i := range j.Remotes {
		rm := &j.Remotes[i]
		if rm.State == ResRemoved || j.existing(rm.NodeID) || j.keepHost(rm.NodeID) || j.routePending(rm.NodeID) {
			continue
		}
		err := d.restoreHost(ctx, j, rm)
		if err != nil {
			rm.Error = note("恢复主机 "+rm.NodeID, err)
		} else {
			rm.State, rm.Error = ResRemoved, ""
			if rm.Kind == RemoteConnector && d.HostRemoved != nil {
				d.HostRemoved(rm.NodeID)
			}
		}
		if err := d.save(j); err != nil {
			return append(errs, "保存撤回进度失败："+d.red(err.Error()))
		}
	}
	// 3. Cloudflare nodes.
	for i := range j.Nodes {
		n := &j.Nodes[i]
		if n.State == ResRemoved || j.existing(n.NodeID) || j.keepHost(n.NodeID) || j.routePending(n.NodeID) {
			continue
		}
		// Keep the registration until the host and its token are restored.
		if j.hostPending(n.NodeID) {
			note("保留 Cloudflare 节点 "+n.NodeID, errors.New("主机恢复未完成"))
			continue
		}
		if err := d.removeNode(ctx, n); err != nil {
			n.Error = note("删除 Cloudflare 节点 "+n.Name, err)
		} else {
			n.State, n.Error = ResRemoved, ""
		}
		if err := d.save(j); err != nil {
			return append(errs, "保存撤回进度失败："+d.red(err.Error()))
		}
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
	act := ActRestore
	script, err := RestoreScript(remoteRun(j, rm), DefaultAddressing())
	if rm.Kind == RemoteConnector {
		act = ActConnectorRemove
		script, err = ConnectorRemoveScript(remoteRun(j, rm))
	}
	if err != nil {
		return err
	}
	out, seen, err := d.Remote.Exec(ctx, h.target(), act, script)
	if err == nil && seen != h.HostKey {
		err = fmt.Errorf("%s 出示的 SSH 主机指纹 %q 不是部署时固定的 %s", h.addr(), seen, h.HostKey)
	}
	if err == nil {
		switch {
		case strings.Contains(out, "MESH_RESTORE_ABSENT"):
			if rm.State == ResCreated {
				err = fmt.Errorf("%s 上没有本次运行（%s）的备份目录，但部署记录显示面板已在这台主机安装；不能当作已恢复，请人工检查", h.addr(), j.RunID)
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
	for _, n := range p.Nodes {
		switch {
		case n.Existing():
			rec.Detail = append(rec.Detail, fmt.Sprintf("%s: 沿用主机上已有的 Mesh 节点 %s（%s）：不注册、不安装、撤回时不动它", n.ID, n.MeshAddr, n.MeshIface))
		case n.PanelHost():
			rec.Detail = append(rec.Detail, fmt.Sprintf("%s: 沿用面板之前安装的主机级节点 %s（%s）", n.ID, n.MeshAddr, n.MeshIface))
		case n.Install:
			rec.Detail = append(rec.Detail, fmt.Sprintf("%s: 安装主机级 Linux 节点（%s，源 %s），以 connector 注册到 Mesh 账户；不接管默认路由；撤回时只移除本次创建的部分", n.ID, PackageName, RepoURL))
		}
	}
	for _, l := range p.Legs {
		if l.Reuse == ReusePending {
			rec.Detail = append(rec.Detail, fmt.Sprintf("腿 %s：一端本次新装，装好后重新下发枢纽和出口、再部署一次，这条腿才会使用新的 Mesh 地址", l.LinkID))
		} else {
			rec.Detail = append(rec.Detail, fmt.Sprintf("腿 %s：WireGuard Endpoint 是出口 %s 的 Mesh 地址 %s；不发布路由", l.LinkID, l.ExitID, l.Network))
		}
	}
	if !p.OK() {
		var msgs []string
		for _, is := range p.Issues {
			msgs = append(msgs, is.Message)
		}
		return errors.New(strings.Join(msgs, "；"))
	}
	hosts := map[string]bool{}
	for _, n := range p.Nodes {
		if n.SSHHost == "" {
			return fmt.Errorf("节点 %s 没有 SSH 主机", n.ID)
		}
		if !n.Install && !n.HostNode() {
			return fmt.Errorf("节点 %s 既不是主机级 Mesh 节点也不在本次安装（不再部署 sidecar）", n.ID)
		}
		pin := pinFor(n)
		key := fmt.Sprintf("%s:%d", pin.SSHHost, pin.SSHPort)
		if hosts[key] {
			return fmt.Errorf("主机 %s 对应多个 Mesh 节点；一台主机只有一个 Mesh 节点，请合并节点规划", key)
		}
		hosts[key] = true
	}
	return nil
}

func (d *Deployer) stagePreflight(ctx context.Context, j *Journal, p Plan, rec *StageRecord) error {
	var failed []string
	for _, n := range p.Nodes {
		// A node that already is a host-level node (reused or installed
		// earlier) is detected again first: still there, in this run's
		// account, and WARP clear of Meridian in both families.
		if !n.Install {
			if err := d.hostHealth(ctx, j, n, rec); err != nil {
				rec.Detail = append(rec.Detail, n.ID+": "+d.red(err.Error()))
				failed = append(failed, n.ID+": "+d.red(err.Error()))
				continue
			}
		}
		script, err := DeploymentPreflight(j, p, n)
		if err != nil {
			return err
		}
		act := ActPreflight
		if n.Install {
			act = ActConnectorPreflight
		}
		out, err := d.exec(ctx, j, n.ID, act, script)
		var conflicts []string
		for _, l := range ParseChecks(d.red(out)) {
			rec.Detail = append(rec.Detail, n.ID+": "+l)
			if reason, ok := strings.CutPrefix(l, "MESH_CONFLICT "); ok {
				conflicts = append(conflicts, reason)
			}
		}
		if err != nil || !strings.Contains(out, "MESH_PREFLIGHT_OK") {
			reason := strings.Join(conflicts, "；")
			if reason == "" && err != nil {
				reason = d.red(err.Error())
			}
			if reason == "" {
				reason = "远端没有返回预检通过标记"
			}
			failed = append(failed, n.ID+": "+reason)
		}
	}
	if len(failed) > 0 {
		return fmt.Errorf("预检发现冲突或无法连接：%s", strings.Join(failed, ", "))
	}
	return nil
}

// stageCFNode creates one Cloudflare connector registration per host this
// run installs. Nothing is created for a host that already is a node.
func (d *Deployer) stageCFNode(ctx context.Context, j *Journal, p Plan, rec *StageRecord) error {
	for _, n := range p.Nodes {
		if !n.Install {
			rec.Detail = append(rec.Detail, n.ID+": 已是主机级节点，不创建 Cloudflare 节点")
			continue
		}
		if j.cfID(n.ID) != "" {
			continue
		}
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

// stageInstall installs the host-level connector on every Install host.
// The node token is read here, added to the redactor, and passed only into
// the install script (ConnectorInstallScript); it is never stored.
func (d *Deployer) stageInstall(ctx context.Context, j *Journal, p Plan, rec *StageRecord) error {
	for _, n := range p.Nodes {
		if !n.Install {
			continue
		}
		id := j.cfID(n.ID)
		if id == "" {
			return fmt.Errorf("节点 %s 没有本次创建的 Cloudflare 节点", n.ID)
		}
		fpr := RepoKeyFingerprint()
		if fpr == "" {
			return fmt.Errorf("没有配置签名公钥指纹（%s），不安装", RepoKeyFingerprintEnv)
		}
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
		script, err := ConnectorInstallScript(j.RunID, n.Codename, fpr, tok)
		tok = ""
		if err != nil {
			return errors.New(d.red(err.Error()))
		}
		h := j.pin(n.ID)
		if h == nil || h.HostKey == "" {
			return fmt.Errorf("节点 %s 没有在预检中固定 SSH 主机指纹", n.ID)
		}
		j.Remotes = append(j.Remotes, OwnedRemote{NodeID: n.ID, Kind: RemoteConnector, RunID: j.RunID, Host: *h, State: ResIntent})
		idx := len(j.Remotes) - 1
		if err := d.save(j); err != nil {
			return err
		}
		out, err := d.exec(ctx, j, n.ID, ActConnectorInstall, script)
		j.Remotes[idx].Created = ParseCreated(out)
		if err == nil && !strings.Contains(out, "MESH_INSTALL_OK") {
			err = errors.New("安装脚本没有报告 MESH_INSTALL_OK")
		}
		if err != nil {
			// Whatever the host marked as created is withdrawn by
			// compensation (the remote stays an intent with its markers).
			_ = d.save(j)
			return fmt.Errorf("%s 安装主机级 Mesh 节点：%v %s", n.ID, err, tail(d.red(out)))
		}
		j.Remotes[idx].State = ResCreated
		addr, iface, ok := ParseNodeAddr(out)
		if !ok {
			_ = d.save(j)
			return fmt.Errorf("%s 安装后没有报告 100.96.0.0/12 内的 Mesh 地址", n.ID)
		}
		j.Remotes[idx].MeshAddr, j.Remotes[idx].MeshIface = addr, iface
		rec.Detail = append(rec.Detail, fmt.Sprintf("%s: 已安装并注册（%s on %s）；本次创建：%s", n.ID, addr, iface, strings.Join(j.Remotes[idx].Created, "、")))
		if err := d.save(j); err != nil {
			return err
		}
	}
	return nil
}

// stageHealth re-runs the fixed read-only detection on every host of the
// plan: a host-level node with the expected address and interface, the
// selected account where it can be compared, and no conflict of WARP's
// policy routing with Meridian's tables, marks and priorities (a full
// tunnel is a conflict). Installed nodes must also be healthy in
// Cloudflare.
func (d *Deployer) stageHealth(ctx context.Context, j *Journal, p Plan, rec *StageRecord) error {
	var failed []string
	for _, n := range p.Nodes {
		if err := d.hostHealth(ctx, j, n, rec); err != nil {
			rec.Detail = append(rec.Detail, n.ID+": "+d.red(err.Error()))
			failed = append(failed, n.ID)
		}
	}
	if len(failed) > 0 {
		return fmt.Errorf("Mesh 节点检查失败：%s", strings.Join(failed, ", "))
	}
	wait, poll := d.HealthWait, d.HealthPoll
	if wait <= 0 {
		wait = 2 * time.Minute
	}
	if poll <= 0 {
		poll = 5 * time.Second
	}
	for _, n := range p.Nodes {
		if !n.Install {
			continue
		}
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

// stageActivate records each installed node's detection (panel-owned) for
// the panel, so the next compile uses its Mesh address. It changes nothing
// on a host: there is no sidecar to seal and no route to publish.
func (d *Deployer) stageActivate(ctx context.Context, j *Journal, p Plan, rec *StageRecord) error {
	if _, ok := p.Hub(); !ok {
		return errors.New("计划里没有枢纽")
	}
	for _, n := range p.Nodes {
		if !n.Install {
			continue
		}
		rm := j.connector(n.ID)
		if rm == nil || rm.MeshAddr == "" {
			return fmt.Errorf("%s 没有安装记录", n.ID)
		}
		if d.HostDetected != nil {
			det := model.HostMeshDetection{NodeID: n.ID, ServerID: n.ServerID, CheckedAt: d.now(), HostKey: rm.Host.HostKey,
				State: model.HostMeshExisting, Reasons: []string{}, WarpSvc: true, WarpCLI: true, Mode: "connector",
				Account: model.AccountMatched, AccountID: j.AccountID, MeshAddr: rm.MeshAddr, Iface: rm.MeshIface, MemAvailMB: -1,
				Coexist:  model.HostMeshCoexist{OK: true, WARPRules: []string{}, Tables: []int{}, Conflicts: []string{}},
				Reusable: true, Origin: model.MeshOriginPanelHost, PanelOwned: true}
			if err := d.HostDetected(det); err != nil {
				return fmt.Errorf("记录 %s 的 Mesh 节点：%v", n.ID, err)
			}
		}
		rec.Detail = append(rec.Detail, fmt.Sprintf("%s: Mesh 地址 %s 已记录；重新下发枢纽和出口后再部署一次，Mesh 腿才会启用", n.ID, rm.MeshAddr))
	}
	rec.Detail = append(rec.Detail, "不发布任何路由。数据面仍是「未验证」：要看到枢纽的 Mesh 腿握手成功、流量从出口自己的公网地址出去，才算 Mesh 承载了这条 WireGuard。")
	return nil
}

// connector returns the connector install record of node id in this run.
func (j *Journal) connector(id string) *OwnedRemote {
	for i := range j.Remotes {
		if j.Remotes[i].NodeID == id && j.Remotes[i].Kind == RemoteConnector && j.Remotes[i].State == ResCreated {
			return &j.Remotes[i]
		}
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

// existing reports whether node id reuses a host-level Mesh node in this run.
func (j *Journal) existing(id string) bool {
	for _, e := range j.Existing {
		if e == id {
			return true
		}
	}
	return false
}

// hostHealth re-runs the fixed read-only detection on a plan host. A
// reused node must still be there unchanged; an installed one must be a
// node with the address its install reported, in the run's account where
// confirmed in the run's account (every node; unreadable blocks), and with
// WARP's policy routing clear of Meridian's in both families.
func (d *Deployer) hostHealth(ctx context.Context, j *Journal, n NodeTarget, rec *StageRecord) error {
	out, err := d.exec(ctx, j, n.ID, ActDetect, DetectScript())
	if err != nil {
		return fmt.Errorf("检测 Mesh 节点：%v", err)
	}
	got := ParseHostMesh(out, j.AccountID, n.Reserved)
	want, iface := n.MeshAddr, n.MeshIface
	if n.Install {
		rm := j.connector(n.ID)
		if rm == nil {
			return errors.New("没有安装记录")
		}
		want, iface = rm.MeshAddr, rm.MeshIface
	}
	// Every node, reused or installed, must be confirmed in the run's
	// account: a mismatch or an account that cannot be read blocks.
	if got.Account != model.AccountMatched {
		why := got.AccountReason
		if why == "" {
			why = "账户无法确认"
		}
		return fmt.Errorf("Mesh 节点不在部署账户里，阻断：%s", why)
	}
	if got.State != model.HostMeshExisting || got.MeshAddr != want || got.Iface != iface {
		return fmt.Errorf("Mesh 节点与记录不一致（状态 %s，地址 %q，接口 %q；应为 %s on %s）；重新检测后再部署", got.State, got.MeshAddr, got.Iface, want, iface)
	}
	if !got.Coexist.OK {
		return fmt.Errorf("WARP 与 Meridian 冲突，阻断：%s", strings.Join(got.Coexist.Conflicts, "；"))
	}
	rec.Detail = append(rec.Detail, fmt.Sprintf("%s: Mesh 节点在（%s on %s），与 Meridian 的表、标记和规则不冲突", n.ID, got.MeshAddr, got.Iface))
	return nil
}
