package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/radowitz/meridian/internal/mesh"
	"github.com/radowitz/meridian/internal/model"
	"github.com/radowitz/meridian/internal/provision"
	"golang.org/x/crypto/ssh"
)

// Mesh deployment from the panel. The Cloudflare API token is written once
// (PUT /api/mesh/credentials) and never returned; the SSH key is supplied
// per request and never stored. See internal/mesh for the stages.

const meshDataplaneNote = "Mesh 数据面：未验证。路由发布成功不等于 Mesh 可用；需要在隔离的 Linux 主机上运行 deploy/verify-mesh-veth.sh 并存档，再按 docs/verification.md 做真实转发与人工签收。"

func (s *Server) meshDir() string { return filepath.Join(s.DataDir, "mesh") }

func (s *Server) meshCreds() mesh.CredStore { return mesh.CredStore{Dir: s.meshDir()} }

func meshFaultInjection() bool { return os.Getenv("MERIDIAN_MESH_FAULT_INJECTION") == "1" }

func (s *Server) meshPlan(t model.Topology) (mesh.Plan, error) {
	b, err := s.compileTopo(t)
	if err != nil {
		return mesh.Plan{}, err
	}
	return mesh.BuildPlan(t, b.Files), nil
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
	return &mesh.Deployer{Dir: s.meshDir(), Creds: &creds, Connect: connect, Remote: rem, Redact: red}
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
	if p, err := s.meshPlan(t); err == nil {
		resp["plan"] = p
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

type meshSSHTarget struct {
	SSHHost string `json:"ssh_host"`
	SSHPort int    `json:"ssh_port"`
	SSHUser string `json:"ssh_user"`
}

type meshRunBody struct {
	PrivateKeyPEM string                   `json:"private_key_pem"`
	TrustNewHost  bool                     `json:"trust_new_host"`
	Nodes         map[string]meshSSHTarget `json:"nodes"`
	// FailAfter injects a failure after the named stage. Only accepted
	// when MERIDIAN_MESH_FAULT_INJECTION=1 (compensation drill).
	FailAfter string `json:"fail_after,omitempty"`
}

// sshRemote runs the deployer's fixed scripts over SSH. It connects to
// exactly the target the deployer passes (the plan node during a deploy,
// the target pinned in the journal during a withdrawal) and never looks a
// node up in the topology. A pinned host key must match; an unpinned host
// (first contact of a deploy) is accepted only with trust_new_host, and the
// key it presented is returned so the deployer pins it.
type sshRemote struct {
	key   string
	trust bool
}

func (r *sshRemote) Exec(ctx context.Context, n mesh.NodeTarget, act mesh.Action, script string) (string, string, error) {
	if n.SSHHost == "" {
		return "", "", fmt.Errorf("节点 %s 没有 SSH 目标", n.ID)
	}
	user := n.SSHUser
	if user == "" {
		user = "root"
	}
	var seen string
	check := meshHostKeyCheck(n, r.trust, &seen)
	ctx, cancel := context.WithTimeout(ctx, 10*time.Minute)
	defer cancel()
	out, err := provision.RunScript(ctx, provision.SSHRequest{Host: n.SSHHost, Port: n.SSHPort, User: user, PrivateKeyPEM: r.key, KnownHosts: check}, script)
	return out, seen, err
}

// meshHostKeyCheck accepts exactly the pinned key of n, or, when nothing is
// pinned yet, any key only if trust is set; the accepted fingerprint is
// stored in *seen.
func meshHostKeyCheck(n mesh.NodeTarget, trust bool, seen *string) ssh.HostKeyCallback {
	return func(_ string, _ net.Addr, key ssh.PublicKey) error {
		fp := ssh.FingerprintSHA256(key)
		switch {
		case n.HostKey != "" && fp != n.HostKey:
			return fmt.Errorf("%s 的 SSH 主机指纹是 %s，不是部署时固定的 %s；拒绝连接", n.SSHHost, fp, n.HostKey)
		case n.HostKey == "" && !trust:
			return fmt.Errorf("没有 %s 的主机指纹记录（%s）。确认指纹后勾选「信任首次见到的主机指纹」", n.SSHHost, fp)
		}
		*seen = fp
		return nil
	}
}

// meshDeps builds the remote and the redactor for one request (the
// Cloudflare client is built by the deployer under its lock). Tests
// replace MeshRemote.
func (s *Server) meshDeps(body meshRunBody) (mesh.Remote, *mesh.Redactor, error) {
	red := &mesh.Redactor{}
	red.Add(body.PrivateKeyPEM)
	if s.MeshRemote != nil {
		return s.MeshRemote(), red, nil
	}
	if body.PrivateKeyPEM == "" {
		return nil, nil, errors.New("需要 SSH 私钥（只在本次请求中使用，不保存）")
	}
	return &sshRemote{key: body.PrivateKeyPEM, trust: body.TrustNewHost}, red, nil
}

func decodeMeshRun(w http.ResponseWriter, r *http.Request) (meshRunBody, error) {
	var body meshRunBody
	raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 64<<10))
	if err != nil {
		return body, err
	}
	if len(strings.TrimSpace(string(raw))) == 0 {
		return body, nil
	}
	return body, json.Unmarshal(raw, &body)
}

func (s *Server) postMeshDeploy(w http.ResponseWriter, r *http.Request) {
	body, err := decodeMeshRun(w, r)
	if err != nil {
		writeErr(w, http.StatusBadRequest, errors.New("请求格式错误"))
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
	rem, red, err := s.meshDeps(body)
	if err != nil {
		writeErr(w, http.StatusConflict, err)
		return
	}
	// Request-level SSH overrides apply to the plan nodes; the deployer
	// pins the resulting targets in the journal.
	for id := range body.Nodes {
		if _, ok := plan.Node(id); !ok {
			writeErr(w, http.StatusBadRequest, fmt.Errorf("SSH 覆盖里的节点 %s 不在 Mesh 计划里", id))
			return
		}
	}
	for i := range plan.Nodes {
		if o, ok := body.Nodes[plan.Nodes[i].ID]; ok {
			if o.SSHHost != "" {
				plan.Nodes[i].SSHHost = o.SSHHost
			}
			if o.SSHPort != 0 {
				plan.Nodes[i].SSHPort = o.SSHPort
			}
			if o.SSHUser != "" {
				plan.Nodes[i].SSHUser = o.SSHUser
			}
		}
	}
	d := s.deployer(rem, red)
	d.FailAfter = body.FailAfter
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Minute)
	defer cancel()
	j, err := d.Deploy(ctx, plan)
	writeMeshResult(w, j, err, red)
}

func (s *Server) postMeshWithdraw(w http.ResponseWriter, r *http.Request) {
	body, err := decodeMeshRun(w, r)
	if err != nil {
		writeErr(w, http.StatusBadRequest, errors.New("请求格式错误"))
		return
	}
	// A withdrawal acts on the hosts pinned in the journal (address, port,
	// user and host key seen at deploy time), never on the current
	// topology, and only the SSH credential is taken from the request.
	if len(body.Nodes) > 0 || body.TrustNewHost || body.FailAfter != "" {
		writeErr(w, http.StatusBadRequest, errors.New("撤回只使用部署时固定的主机与主机指纹，只接受 SSH 私钥；不接受 SSH 目标覆盖、trust_new_host 或 fail_after"))
		return
	}
	rem, red, err := s.meshDeps(body)
	if err != nil {
		writeErr(w, http.StatusConflict, err)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Minute)
	defer cancel()
	j, err := s.deployer(rem, red).Withdraw(ctx)
	writeMeshResult(w, j, err, red)
}

func writeMeshResult(w http.ResponseWriter, j *mesh.Journal, err error, red *mesh.Redactor) {
	resp := map[string]any{"journal": j, "dataplane": mesh.DataplaneUnverified, "dataplane_note": meshDataplaneNote}
	if err == nil {
		writeJSON(w, http.StatusOK, resp)
		return
	}
	resp["error"] = red.Redact(err.Error())
	var se *mesh.StageError
	switch {
	case errors.Is(err, mesh.ErrBusy), errors.Is(err, mesh.ErrNothingToWithdraw),
		errors.Is(err, mesh.ErrAccountMismatch), errors.Is(err, mesh.ErrNoCredentials):
		writeJSON(w, http.StatusConflict, resp)
	case errors.As(err, &se):
		resp["stage"] = se.Stage
		resp["compensated"] = se.Compensated
		resp["compensation_errors"] = se.CompErrors
		writeJSON(w, http.StatusBadGateway, resp)
	default:
		writeJSON(w, http.StatusInternalServerError, resp)
	}
}
