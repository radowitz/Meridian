package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/radowitz/meridian/internal/credentials"
	"github.com/radowitz/meridian/internal/mesh"
	"github.com/radowitz/meridian/internal/model"
	"github.com/radowitz/meridian/internal/sshexec"
)

// Operations against managed servers and Cloudflare accounts: host key
// discovery, the connection test, the Cloudflare token permission check,
// and the glue that lets provisioning and Mesh deployments run by server
// and account ID. See docs/architecture.md「服务器、SSH 凭据与 Cloudflare
// 账户」.

const (
	codeFieldRemoved     = "field_removed"
	codeUnknownField     = "unknown_field"
	codeNoServer         = "no_server"
	codeServersNotReady  = "servers_not_ready"
	codeNoMeshAccount    = "no_mesh_account"
	codeCheckUnavailable = "check_failed"
)

func (s *Server) registerSSHOps(mux *http.ServeMux) {
	mux.HandleFunc("POST /api/servers/{id}/host-key/discover", s.discoverHostKey)
	mux.HandleFunc("POST /api/servers/{id}/test", s.testServer)
	mux.HandleFunc("GET /api/cloudflare/requirements", s.getCloudflareRequirements)
	mux.HandleFunc("POST /api/cloudflare/accounts/{id}/check", s.checkAccount)
}

// connector is the SSH path to managed servers. Every connector shares
// the server's pool: one authenticated connection serves the steps of a
// flow (sshexec.Pool for how reuse is bounded).
func (s *Server) connector(cs *credentials.Store) *sshexec.Connector {
	return &sshexec.Connector{Store: cs, Dial: s.SSHDial, Pool: s.sshPool()}
}

// sshPool returns the server's SSH connection pool.
func (s *Server) sshPool() *sshexec.Pool {
	s.sshPoolMu.Lock()
	defer s.sshPoolMu.Unlock()
	if s.SSHPool == nil {
		s.SSHPool = &sshexec.Pool{}
	}
	return s.SSHPool
}

// Close releases the pooled SSH connections (idempotent).
func (s *Server) Close() {
	s.sshPoolMu.Lock()
	p := s.SSHPool
	s.sshPoolMu.Unlock()
	p.CloseAll()
}

// decodeStrict reads a JSON object (at most 64 KiB) and refuses fields of
// the old API (field_removed) and unknown fields (unknown_field), so a
// client sending a removed field learns it instead of being ignored. An
// empty body is accepted when allowEmpty.
func decodeStrict(w http.ResponseWriter, r *http.Request, dst any, allowed, removed []string, allowEmpty bool) error {
	raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 64<<10))
	if err != nil {
		return badRequest()
	}
	if len(strings.TrimSpace(string(raw))) == 0 {
		if allowEmpty {
			return nil
		}
		return badRequest()
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		return badRequest()
	}
	keys := make([]string, 0, len(fields))
	for k := range fields {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		for _, x := range removed {
			if k == x {
				return &credentials.Error{Code: codeFieldRemoved, Field: k,
					Msg: fmt.Sprintf("字段 %s 已移除：SSH 目标和凭据来自服务器管理（按服务器 ID 解析），主机指纹在服务器页确认，Cloudflare 账户按 ID 引用", k)}
			}
		}
		ok := false
		for _, x := range allowed {
			ok = ok || k == x
		}
		if !ok {
			return &credentials.Error{Code: codeUnknownField, Field: k, Msg: fmt.Sprintf("不认识的字段 %s", k)}
		}
	}
	if err := json.Unmarshal(raw, dst); err != nil {
		return badRequest()
	}
	return nil
}

// checkServerOperable is what every operation needs before it connects: a
// node on a managed server whose host key is trusted and which has a
// credential. Checked before keys are generated or anything is compiled;
// the connector checks it again at connection time.
func checkServerOperable(cs *credentials.Store, n model.Node) error {
	if n.ServerID == "" {
		return &credentials.Error{Code: codeNoServer, Field: "node_id",
			Msg: fmt.Sprintf("节点 %s 还没有关联服务器；先在服务器管理里添加服务器，再在拓扑里为节点选择它", n.ID)}
	}
	sv, err := cs.Server(n.ServerID)
	if err != nil {
		return err
	}
	return serverOperable(cs, sv)
}

func serverOperable(cs *credentials.Store, sv model.Server) error {
	switch sv.HostKey.State {
	case model.HostKeyTrusted:
	case model.HostKeyMismatch:
		return &credentials.Error{Code: credentials.CodeHostKeyMismatch, Field: "host_key",
			Msg: fmt.Sprintf("服务器 %s 出示了与固定指纹不同的主机指纹；核实后重新确认或清除记录", sv.Name)}
	default:
		return &credentials.Error{Code: sshexec.CodeUntrusted, Field: "host_key",
			Msg: fmt.Sprintf("服务器 %s 的主机指纹还没有确认；先「发现指纹」并核对确认", sv.Name)}
	}
	if sv.CredentialID == "" {
		return &credentials.Error{Code: credentials.CodeNoCredential, Field: "credential_id",
			Msg: fmt.Sprintf("服务器 %s 还没有选择 SSH 凭据", sv.Name)}
	}
	if _, err := cs.SSHCredential(sv.CredentialID); err != nil {
		return err
	}
	return nil
}

// writeSSHErr maps a connector error to {"error","code"}.
func writeSSHErr(w http.ResponseWriter, err error) {
	var ce *credentials.Error
	if errors.As(err, &ce) {
		writeResErr(w, err)
		return
	}
	code := sshexec.CodeOf(err)
	status := http.StatusBadGateway
	switch code {
	case sshexec.CodeNotFound:
		status = http.StatusNotFound
	case sshexec.CodeUntrusted, sshexec.CodeMismatch, sshexec.CodeNoCredential, sshexec.CodeTargetChanged, sshexec.CodePinMismatch:
		status = http.StatusConflict
	case sshexec.CodeRateLimited:
		status = rateLimitHeaders(w, err)
	case "":
		code = credentials.CodeStorage
		status = http.StatusInternalServerError
	}
	body := map[string]any{"error": err.Error(), "code": code}
	if ra := sshexec.RetryAfterOf(err); ra > 0 {
		body["retry_after"] = ra
	}
	writeJSON(w, status, body)
}

// rateLimitHeaders sets Retry-After for an ssh_rate_limited error and
// returns its status (503: the server refuses this source for a while; the
// panel will not connect before Retry-After).
func rateLimitHeaders(w http.ResponseWriter, err error) int {
	if ra := sshexec.RetryAfterOf(err); ra > 0 {
		w.Header().Set("Retry-After", strconv.Itoa(ra))
	}
	return http.StatusServiceUnavailable
}

// ---------------------------------------------------- host-key discovery ---

// discoverHostKey connects only far enough to read the host key: no
// authentication is attempted and nothing runs. The key is recorded
// (discovered, or mismatch against a pin) and returned for the operator to
// compare before confirming it with POST …/host-key/trust.
func (s *Server) discoverHostKey(w http.ResponseWriter, r *http.Request) {
	cs, t, ok := s.resCtx(w)
	if !ok {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 40*time.Second)
	defer cancel()
	d, err := s.connector(cs).Discover(ctx, r.PathValue("id"))
	if err != nil {
		writeSSHErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"discovery": d,
		"server":    s.serverView(cs, d.Server, t),
	})
}

// --------------------------------------------------- connection test ---

// testServer logs in with the stored credential and runs the fixed
// sshexec.TestCommand (architecture, kernel, OS name). The result is
// recorded on the server. 409 when the test cannot be attempted (key not
// trusted, no credential); otherwise 200 with test.ok true or false.
func (s *Server) testServer(w http.ResponseWriter, r *http.Request) {
	cs, _, ok := s.resCtx(w)
	if !ok {
		return
	}
	id := r.PathValue("id")
	sv, err := cs.Server(id)
	if err != nil {
		writeResErr(w, err)
		return
	}
	if err := serverOperable(cs, sv); err != nil && credentials.CodeHostKeyMismatch != resCode(err) {
		writeResErr(w, err)
		return
	}
	ct, err := s.connector(cs).Test(r.Context(), id)
	if err != nil {
		writeSSHErr(w, err)
		return
	}
	sv, err = cs.RecordConnectionTest(id, ct)
	if err != nil {
		writeResErr(w, err)
		return
	}
	t, _ := s.topology()
	out := map[string]any{"test": sv.LastTest, "server": s.serverView(cs, sv, t)}
	// A login the server does not accept comes with what to do about it,
	// including the credential's public key (never anything secret).
	if h := s.loginHelpFor(cs, id, ct.Code, ct.Offered); h != nil && !ct.OK {
		out["login_help"] = h
	}
	writeJSON(w, http.StatusOK, out)
}

func resCode(err error) string {
	var ce *credentials.Error
	if errors.As(err, &ce) {
		return ce.Code
	}
	return ""
}

// ----------------------------------------------------------- Cloudflare ---

// What the permission check does and does not establish (for the panel).
var permissionCheckScope = map[string][]string{
	"does": {
		"GET /accounts/{account_id}/tokens/verify（账户令牌；失败时再试 GET /user/tokens/verify 用户令牌）：token 是否有效、是否 active",
		"GET /accounts/{account_id}/warp_connector?per_page=1：能否在这个账户读取 Mesh 节点",
		"GET /accounts/{account_id}/teamnet/routes?per_page=1&is_deleted=false：能否在这个账户读取路由",
	},
	"does_not": {
		"不创建、不修改、不删除任何东西",
		"不能证明写权限：两个列表接口同时接受 Read 与 Write 权限",
		"不读取 token 的权限清单（那需要额外的 API Tokens Read 权限）",
	},
}

func (s *Server) getCloudflareRequirements(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"permissions": mesh.RequiredPermissions,
		"how_to":      mesh.TokenHowTo,
		"check":       permissionCheckScope,
	})
}

// checkAccount runs the read-only permission check with the account's
// stored token and records the result. 200 whenever the check ran (see
// check.ok / checks[].status); the token never appears in the result.
func (s *Server) checkAccount(w http.ResponseWriter, r *http.Request) {
	cs, err := s.credStore()
	if err != nil {
		writeResErr(w, err)
		return
	}
	id := r.PathValue("id")
	a, tok, err := cs.AccountToken(id)
	if err != nil {
		writeResErr(w, err)
		return
	}
	client, err := mesh.NewCFClient(mesh.Credentials{AccountID: a.AccountID, APIToken: tok})
	if err != nil {
		writeResErr(w, &credentials.Error{Code: codeCheckUnavailable, Msg: credentials.Scrub(err.Error(), tok)})
		return
	}
	if s.CloudflareAPIBase != "" {
		client.Base = s.CloudflareAPIBase
	}
	pc := client.CheckPermissions(r.Context())
	pc.Detail = credentials.Scrub(pc.Detail, tok)
	for i := range pc.Checks {
		pc.Checks[i].Detail = credentials.Scrub(pc.Checks[i].Detail, tok)
	}
	for i := range pc.Confirmed {
		pc.Confirmed[i] = credentials.Scrub(pc.Confirmed[i], tok)
	}
	out, err := cs.RecordPermissionCheck(id, pc)
	if err != nil {
		writeResErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"check": out.PermissionCheck, "account": accountViewOf(cs, out, s.meshState(cs))})
}

// ------------------------------------------------- deployment pins ---

// deploymentPins is the credential store's view of the Mesh journal: the
// hosts a deployment that is not fully withdrawn still needs. It reads
// only the journal file (it runs under the store lock).
func (s *Server) deploymentPins() ([]credentials.PinnedHost, error) {
	j, err := (&mesh.Deployer{Dir: s.meshDir()}).Load()
	if err != nil {
		return nil, err
	}
	// Node deployments (provision records) that may still be on their
	// host pin the server and credential a withdraw needs (withdraw.go).
	out := s.nodeDeploymentPins()
	if j == nil || !j.Busy() {
		return out, nil
	}
	ref := credentials.Ref{Kind: "mesh_deployment", ID: j.RunID, Name: "Mesh 部署（" + j.State + "）"}
	for _, h := range j.Hosts {
		out = append(out, credentials.PinnedHost{Deployment: ref, ServerID: h.ServerID, CredentialID: h.CredentialID,
			Address: h.SSHHost, Port: h.SSHPort, User: h.SSHUser})
	}
	return out, nil
}

// resolvePin places a pin of a schema-2 journal on a server: the server of
// the pin's node when its endpoint still matches, else the server migrated
// from that node, else the only server with that endpoint. The credential
// is that server's current one.
func (s *Server) resolvePin(cs *credentials.Store) func(h mesh.HostPin) (string, string, bool) {
	return func(h mesh.HostPin) (string, string, bool) {
		match := func(sv model.Server) bool {
			return sv.Address == h.SSHHost && sv.Port == h.SSHPort && sv.User == h.SSHUser
		}
		if h.ServerID != "" {
			sv, err := cs.Server(h.ServerID)
			if err != nil {
				return "", "", false
			}
			return sv.ID, sv.CredentialID, true
		}
		if t, err := s.topology(); err == nil {
			if n, ok := t.NodeByID(h.NodeID); ok && n.ServerID != "" {
				if sv, err := cs.Server(n.ServerID); err == nil && match(sv) {
					return sv.ID, sv.CredentialID, true
				}
			}
		}
		var found []model.Server
		for _, sv := range cs.Servers() {
			if sv.MigratedFrom == "node:"+h.NodeID && match(sv) {
				return sv.ID, sv.CredentialID, true
			}
			if match(sv) {
				found = append(found, sv)
			}
		}
		if len(found) == 1 {
			return found[0].ID, found[0].CredentialID, true
		}
		return "", "", false
	}
}

// checkHosts blocks a withdrawal before anything is compensated when a
// host that still has to be restored cannot be reached through its pinned
// server and credential.
func (s *Server) checkHosts(cs *credentials.Store) func(j *mesh.Journal) error {
	return func(j *mesh.Journal) error {
		var probs []string
		for _, rm := range j.Remotes {
			if rm.State == mesh.ResRemoved {
				continue
			}
			h := rm.Host
			who := fmt.Sprintf("%s（%s@%s:%d）", rm.NodeID, h.SSHUser, h.SSHHost, h.SSHPort)
			if h.ServerID == "" {
				probs = append(probs, who+" 在部署记录里没有对应的服务器；在服务器管理里添加这台主机（同一地址、端口、用户）并确认同一主机指纹后重试")
				continue
			}
			sv, err := cs.Server(h.ServerID)
			if err != nil {
				probs = append(probs, fmt.Sprintf("%s 固定的服务器 %s 已不存在", who, h.ServerID))
				continue
			}
			if sv.Address != h.SSHHost || sv.Port != h.SSHPort || sv.User != h.SSHUser {
				probs = append(probs, fmt.Sprintf("%s 固定的服务器 %s 现在指向 %s@%s:%d", who, sv.Name, sv.User, sv.Address, sv.Port))
				continue
			}
			cid := h.CredentialID
			if cid == "" {
				cid = sv.CredentialID
			}
			if cid == "" {
				probs = append(probs, fmt.Sprintf("%s 没有可用的 SSH 凭据；为服务器 %s 选择凭据后重试", who, sv.Name))
				continue
			}
			if _, err := cs.SSHCredential(cid); err != nil {
				probs = append(probs, fmt.Sprintf("%s 固定的 SSH 凭据 %s 已不存在", who, cid))
			}
		}
		if len(probs) > 0 {
			return errors.New(strings.Join(probs, "；"))
		}
		return nil
	}
}

// UpgradeMeshJournal upgrades a schema-2 deployment journal (pins get their
// server and credential). Called at startup by MigrateCredentials.
func (s *Server) upgradeMeshJournal(cs *credentials.Store) error {
	d := &mesh.Deployer{Dir: s.meshDir(), ResolvePin: s.resolvePin(cs)}
	_, err := d.UpgradeJournal()
	return err
}
