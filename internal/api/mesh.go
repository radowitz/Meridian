package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"time"

	"github.com/radowitz/meridian/internal/credentials"
	"github.com/radowitz/meridian/internal/mesh"
	"github.com/radowitz/meridian/internal/model"
	"github.com/radowitz/meridian/internal/sshexec"
)

// Mesh deployment from the panel. The Cloudflare account is a stored,
// reusable account (credential store) referred to by ID; SSH goes through
// each plan node's managed server with its stored credential (internal/
// sshexec), only to servers whose host key the operator confirmed. No
// request carries key material, an SSH target or a token. See
// internal/mesh for the stages.

const meshDataplaneNote = "Mesh 数据面：未验证。路由发布成功不等于 Mesh 可用；需要在隔离的 Linux 主机上运行 deploy/verify-mesh-veth.sh 并存档，再按 docs/verification.md 做真实转发与人工签收。"

func (s *Server) meshDir() string { return filepath.Join(s.DataDir, "mesh") }

func meshFaultInjection() bool { return os.Getenv("MERIDIAN_MESH_FAULT_INJECTION") == "1" }

func (s *Server) meshPlan(t model.Topology) (mesh.Plan, error) {
	b, err := s.compileTopo(t)
	if err != nil {
		return mesh.Plan{}, err
	}
	p := mesh.BuildPlan(t, b.Files)
	// A node is reached only through its managed server: address, port,
	// user, credential and the confirmed host key all come from there. A
	// node without a server has no SSH target at all.
	cs, _ := s.credStore()
	for i := range p.Nodes {
		nt := &p.Nodes[i]
		nt.SSHHost, nt.SSHPort, nt.SSHUser, nt.HostKey, nt.ServerID, nt.CredentialID = "", 0, "", "", "", ""
		n, ok := t.NodeByID(nt.ID)
		if !ok || n.ServerID == "" || cs == nil {
			continue
		}
		sv, err := cs.Server(n.ServerID)
		if err != nil {
			continue
		}
		nt.ServerID, nt.CredentialID = sv.ID, sv.CredentialID
		nt.SSHHost, nt.SSHPort, nt.SSHUser = sv.Address, sv.Port, sv.User
		if sv.HostKey.State == model.HostKeyTrusted {
			nt.HostKey = sv.HostKey.Fingerprint
		}
	}
	return p, nil
}

// meshNodeReadiness is one plan node's server readiness.
type meshNodeReadiness struct {
	NodeID     string     `json:"node_id"`
	Name       string     `json:"name"`
	Role       model.Role `json:"role"`
	ServerID   string     `json:"server_id"`
	ServerName string     `json:"server_name"`
	// Ready: on a server with a trusted host key and a credential.
	Ready bool `json:"ready"`
	// Missing: server, credential, host_key.
	Missing []string `json:"missing"`
	// HostKey is the trusted fingerprint the deployment will pin.
	HostKey    string `json:"host_key,omitempty"`
	AuthMethod string `json:"auth_method,omitempty"`
}

func (s *Server) meshReadiness(t model.Topology, p mesh.Plan) []meshNodeReadiness {
	cs, _ := s.credStore()
	out := []meshNodeReadiness{}
	for _, nt := range p.Nodes {
		r := meshNodeReadiness{NodeID: nt.ID, Name: nt.Name, Role: nt.Role, Missing: []string{}}
		n, _ := t.NodeByID(nt.ID)
		var sv model.Server
		var err error = errors.New("no server")
		if n.ServerID != "" && cs != nil {
			sv, err = cs.Server(n.ServerID)
		}
		if err != nil {
			r.Missing = append(r.Missing, "server")
			out = append(out, r)
			continue
		}
		r.ServerID, r.ServerName, r.AuthMethod = sv.ID, sv.Name, sv.Auth
		if sv.CredentialID == "" {
			r.Missing = append(r.Missing, "credential")
		} else if _, err := cs.SSHCredential(sv.CredentialID); err != nil {
			r.Missing = append(r.Missing, "credential")
		}
		if sv.HostKey.State != model.HostKeyTrusted {
			r.Missing = append(r.Missing, "host_key")
		} else {
			r.HostKey = sv.HostKey.Fingerprint
		}
		r.Ready = len(r.Missing) == 0
		out = append(out, r)
	}
	return out
}

// meshAccountSummary names the account a deployment uses.
type meshAccountSummary struct {
	ID              string                       `json:"id"`
	Name            string                       `json:"name"`
	AccountID       string                       `json:"account_id"`
	Source          string                       `json:"source"` // request | selected
	PermissionCheck *credentials.PermissionCheck `json:"permission_check"`
}

// deployer reads the Cloudflare credentials itself, under the deployment
// lock, so a concurrent credential change cannot slip between the account
// check and the Cloudflare calls of a deployment or withdrawal.
func (s *Server) deployer(rem mesh.Remote, red *mesh.Redactor) *mesh.Deployer {
	creds := s.meshCreds()
	connect := func(c mesh.Credentials) (mesh.Cloudflare, error) { return mesh.NewCFClient(c) }
	if s.MeshCF != nil {
		connect = s.MeshCF
	}
	d := &mesh.Deployer{Dir: s.meshDir(), Creds: creds, Connect: connect, Remote: rem, Redact: red}
	if cs, err := s.credStore(); err == nil {
		d.ResolvePin = s.resolvePin(cs)
		d.CheckHosts = s.checkHosts(cs)
	}
	return d
}

func (s *Server) getMesh(w http.ResponseWriter, r *http.Request) {
	t, err := s.topology()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	resp := map[string]any{
		"dataplane":       mesh.DataplaneUnverified,
		"dataplane_note":  meshDataplaneNote,
		"fault_injection": meshFaultInjection(),
		"stages":          mesh.Stages,
	}
	if c, err := s.meshCreds().Load(); err == nil {
		resp["credentials"] = c.View()
	} else if !errors.Is(err, mesh.ErrNoCredentials) {
		resp["credentials_error"] = err.Error()
	}
	resp["mesh_account"] = nil
	if cs, err := s.credStore(); err == nil {
		if id := cs.MeshAccount(); id != "" {
			if a, err := cs.Account(id); err == nil {
				resp["mesh_account"] = meshAccountSummary{ID: a.ID, Name: a.Name, AccountID: a.AccountID, Source: "selected", PermissionCheck: a.PermissionCheck}
			}
		}
	}
	if p, err := s.meshPlan(t); err == nil {
		resp["plan"] = p
		resp["plan_servers"] = s.meshReadiness(t, p)
	} else {
		resp["plan_error"] = err.Error()
	}
	d := s.deployer(nil, nil)
	if j, err := d.Load(); err == nil {
		resp["journal"] = j
	} else {
		resp["journal_error"] = err.Error()
	}
	writeJSON(w, http.StatusOK, resp)
}

type meshCredBody struct {
	AccountID string `json:"account_id"`
	APIToken  string `json:"api_token"`
}

func (s *Server) putMeshCredentials(w http.ResponseWriter, r *http.Request) {
	var body meshCredBody
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&body); err != nil {
		writeErr(w, http.StatusBadRequest, errors.New("请求格式错误"))
		return
	}
	c := mesh.Credentials{AccountID: body.AccountID, APIToken: body.APIToken}
	// Checked and written under the deployment lock: while a run is not
	// fully withdrawn only its own account may be stored (token rotation).
	if err := s.deployer(nil, nil).SaveCredentials(c); err != nil {
		// The message never echoes the token.
		code := http.StatusBadRequest
		if errors.Is(err, mesh.ErrAccountLocked) {
			code = http.StatusConflict
		}
		writeErr(w, code, err)
		return
	}
	c, _ = s.meshCreds().Load()
	writeJSON(w, http.StatusOK, map[string]any{"credentials": c.View()})
}

func (s *Server) deleteMeshCredentials(w http.ResponseWriter, r *http.Request) {
	if err := s.deployer(nil, nil).DeleteCredentials(); err != nil {
		code := http.StatusInternalServerError
		if errors.Is(err, mesh.ErrCredentialsInUse) {
			code = http.StatusConflict
		}
		writeErr(w, code, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"credentials": nil})
}

type meshDeployBody struct {
	// Account is the credential-store id of the Cloudflare account to
	// deploy with; empty means the account selected for Mesh. A different
	// account becomes the selected one (allowed only while no deployment
	// is bound; the deploy is refused otherwise anyway).
	Account string `json:"account"`
	// FailAfter injects a failure after the named stage. Only accepted
	// when MERIDIAN_MESH_FAULT_INJECTION=1 (compensation drill).
	FailAfter string `json:"fail_after,omitempty"`
}

// meshRemoved are request fields of the pre-server API (400 field_removed).
var meshRemoved = []string{"private_key_pem", "trust_new_host", "nodes", "ssh_host", "ssh_port", "ssh_user"}

// sshRemote runs the deployer's fixed scripts through the managed server
// of each target, with the credential and host key the target names (the
// plan node's during a deploy, the journal's pin during a withdrawal). The
// connector refuses an untrusted server, a host presenting another key and
// a server whose endpoint no longer matches the pin, before authenticating.
//
// The connector's pool lets the stages of one run (preflight, install,
// health check, compensation) share one login per host. sshRemote also
// remembers the most restrictive SSH refusal it met, so a stage that failed
// because a host rate-limited the panel is reported with that code.
type sshRemote struct {
	conn *sshexec.Connector

	mu    sync.Mutex
	code  string // ssh_rate_limited when any host refused this source
	retry int
}

func (r *sshRemote) Exec(ctx context.Context, n mesh.NodeTarget, act mesh.Action, script string) (string, string, error) {
	if n.ServerID == "" {
		return "", "", fmt.Errorf("节点 %s 没有关联的服务器，拒绝连接", n.ID)
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Minute)
	defer cancel()
	res, err := r.conn.RunScript(ctx, sshexec.Target{ServerID: n.ServerID, CredentialID: n.CredentialID,
		Address: n.SSHHost, Port: n.SSHPort, User: n.SSHUser, Fingerprint: n.HostKey}, script)
	if sshexec.CodeOf(err) == sshexec.CodeRateLimited {
		r.mu.Lock()
		r.code = sshexec.CodeRateLimited
		if ra := sshexec.RetryAfterOf(err); ra > r.retry {
			r.retry = ra
		}
		r.mu.Unlock()
	}
	return res.Output, res.Fingerprint, err
}

// sshRefusal is what writeMeshResult adds to a failed run's response.
func sshRefusal(rem mesh.Remote) (string, int) {
	r, ok := rem.(*sshRemote)
	if !ok {
		return "", 0
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.code, r.retry
}

// meshRemote is the SSH executor (tests replace it with MeshRemote).
func (s *Server) meshRemote() (mesh.Remote, error) {
	if s.MeshRemote != nil {
		return s.MeshRemote(), nil
	}
	cs, err := s.credStore()
	if err != nil {
		return nil, err
	}
	return &sshRemote{conn: s.connector(cs)}, nil
}

func (s *Server) postMeshDeploy(w http.ResponseWriter, r *http.Request) {
	var body meshDeployBody
	if err := decodeStrict(w, r, &body, []string{"account", "fail_after"}, meshRemoved, true); err != nil {
		writeResErr(w, err)
		return
	}
	if body.FailAfter != "" {
		if !meshFaultInjection() {
			writeErr(w, http.StatusBadRequest, errors.New("fail_after 只在设置 MERIDIAN_MESH_FAULT_INJECTION=1 时可用"))
			return
		}
		known := false
		for _, st := range mesh.Stages {
			known = known || st == body.FailAfter
		}
		if !known {
			writeErr(w, http.StatusBadRequest, errors.New("fail_after 不是已知阶段"))
			return
		}
	}
	cs, err := s.credStore()
	if err != nil {
		writeResErr(w, err)
		return
	}
	acct := meshAccountSummary{ID: body.Account, Source: "request"}
	if acct.ID == "" {
		acct.ID, acct.Source = cs.MeshAccount(), "selected"
		if acct.ID == "" {
			writeResErr(w, &credentials.Error{Code: codeNoMeshAccount, Field: "account",
				Msg: "没有选择 Mesh 使用的 Cloudflare 账户；在请求里给出 account（账户 ID），或先在 Cloudflare 页选择"})
			return
		}
	}
	a, err := cs.Account(acct.ID)
	if err != nil {
		var ce *credentials.Error
		if errors.As(err, &ce) {
			ce.Field = "account"
		}
		writeResErr(w, err)
		return
	}
	acct.Name, acct.AccountID, acct.PermissionCheck = a.Name, a.AccountID, a.PermissionCheck
	t, err := s.topology()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	plan, err := s.meshPlan(t)
	if err != nil {
		writeErr(w, http.StatusUnprocessableEntity, err)
		return
	}
	// A plan that is invalid fails in its own stage (nothing is created);
	// a valid one must have every host on an operable server first.
	if plan.OK() {
		var notReady []meshNodeReadiness
		for _, rd := range s.meshReadiness(t, plan) {
			if !rd.Ready {
				notReady = append(notReady, rd)
			}
		}
		if len(notReady) > 0 {
			writeJSON(w, http.StatusConflict, map[string]any{
				"error":     "Mesh 计划里有节点的服务器还没就绪（需要关联服务器、选择 SSH 凭据并确认主机指纹）；没有执行任何阶段",
				"code":      codeServersNotReady,
				"not_ready": notReady,
				"account":   acct,
			})
			return
		}
	}
	rem, err := s.meshRemote()
	if err != nil {
		writeResErr(w, err)
		return
	}
	red := &mesh.Redactor{}
	d := s.deployer(rem, red)
	d.FailAfter = body.FailAfter
	if acct.Source == "request" {
		id := acct.ID
		d.Select = func() error { return cs.SetMeshAccount(id) }
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Minute)
	defer cancel()
	j, err := d.Deploy(ctx, plan)
	writeMeshResult(w, j, err, red, &acct, rem)
}

func (s *Server) postMeshWithdraw(w http.ResponseWriter, r *http.Request) {
	// A withdrawal acts on the hosts pinned in the journal (server,
	// credential, endpoint and host key) and the Cloudflare account the run
	// is bound to: the request carries nothing.
	var body struct{}
	if err := decodeStrict(w, r, &body, nil, append(append([]string{}, meshRemoved...), "fail_after", "account"), true); err != nil {
		writeResErr(w, err)
		return
	}
	rem, err := s.meshRemote()
	if err != nil {
		writeResErr(w, err)
		return
	}
	red := &mesh.Redactor{}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Minute)
	defer cancel()
	j, err := s.deployer(rem, red).Withdraw(ctx)
	writeMeshResult(w, j, err, red, nil, rem)
}

func writeMeshResult(w http.ResponseWriter, j *mesh.Journal, err error, red *mesh.Redactor, acct *meshAccountSummary, rem mesh.Remote) {
	resp := map[string]any{"journal": j, "dataplane": mesh.DataplaneUnverified, "dataplane_note": meshDataplaneNote}
	if acct != nil {
		resp["account"] = acct
	}
	if err == nil {
		writeJSON(w, http.StatusOK, resp)
		return
	}
	resp["error"] = red.Redact(err.Error())
	// A host that refused the panel's source address ("Not allowed at this
	// time"): said explicitly, with how long the panel stays away from it.
	if code, retry := sshRefusal(rem); code != "" {
		resp["ssh_code"] = code
		resp["retry_after"] = retry
		if retry > 0 {
			w.Header().Set("Retry-After", strconv.Itoa(retry))
		}
	}
	var se *mesh.StageError
	conflict := map[error]string{
		mesh.ErrBusy: "busy", mesh.ErrNothingToWithdraw: "nothing_to_withdraw", mesh.ErrAccountMismatch: "account_mismatch",
		mesh.ErrNoCredentials: codeNoMeshAccount, mesh.ErrHostsBlocked: "hosts_blocked", mesh.ErrJournalTooNew: "journal_too_new",
	}
	for e, code := range conflict {
		if errors.Is(err, e) {
			resp["code"] = code
			writeJSON(w, http.StatusConflict, resp)
			return
		}
	}
	switch {
	case errors.As(err, &se):
		resp["code"] = "stage_failed"
		resp["stage"] = se.Stage
		resp["compensated"] = se.Compensated
		resp["compensation_errors"] = se.CompErrors
		writeJSON(w, http.StatusBadGateway, resp)
	default:
		var ce *credentials.Error
		if errors.As(err, &ce) {
			resp["code"] = ce.Code
			writeJSON(w, codeStatus(ce.Code), resp)
			return
		}
		writeJSON(w, http.StatusInternalServerError, resp)
	}
}
