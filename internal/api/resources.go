package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"path/filepath"
	"strings"

	"github.com/radowitz/meridian/internal/credentials"
	"github.com/radowitz/meridian/internal/mesh"
	"github.com/radowitz/meridian/internal/model"
)

// Managed servers, reusable SSH credentials and Cloudflare accounts.
// Secrets are write-only: requests may carry them, responses never do, and
// every error text from these handlers is scrubbed of the request's
// secrets. See docs/architecture.md「服务器、SSH 凭据与 Cloudflare 账户」.

// secretsDir is where the credential store lives: SecretsDir, or
// <DataDir>/secrets. Never inside a snapshot directory.
func (s *Server) secretsDir() string {
	if s.SecretsDir != "" {
		return s.SecretsDir
	}
	return filepath.Join(s.DataDir, "secrets")
}

// credStore opens the credential store once and runs the migrations the
// first time. An open failure is returned on every call (and retried).
func (s *Server) credStore() (*credentials.Store, error) {
	s.credMu.Lock()
	defer s.credMu.Unlock()
	if s.creds != nil {
		return s.creds, nil
	}
	cs, err := credentials.Open(s.secretsDir())
	if err != nil {
		return nil, err
	}
	s.creds = cs
	// The store refuses to delete or re-point a server or credential that
	// a deployment which is not fully withdrawn still needs.
	cs.SetDeploymentPins(s.deploymentPins)
	for _, e := range s.migrate(cs) {
		log.Printf("credential migration: %v", e)
	}
	return cs, nil
}

// MigrateCredentials opens the credential store and runs the migrations
// (the old Mesh credential file, topology ssh_* fields). It is idempotent;
// main calls it at startup. Errors are also logged; none contains a secret.
func (s *Server) MigrateCredentials() []error {
	cs, err := s.credStore()
	if err != nil {
		return []error{err}
	}
	return s.migrate(cs)
}

func (s *Server) migrate(cs *credentials.Store) []error {
	var errs []error
	if err := mesh.WithDeploymentLock(func() error {
		_, err := cs.MigrateLegacyCloudflare(filepath.Join(s.meshDir(), "cloudflare.json"))
		return err
	}); err != nil {
		errs = append(errs, fmt.Errorf("Cloudflare 凭据：%w", err))
	}
	if err := s.migrateNodes(cs); err != nil {
		errs = append(errs, fmt.Errorf("节点 SSH 目标：%w", err))
	}
	if err := s.upgradeMeshJournal(cs); err != nil {
		errs = append(errs, fmt.Errorf("Mesh 部署记录升级：%w", err))
	}
	return errs
}

// migrateNodes moves topology ssh_* fields into servers.
func (s *Server) migrateNodes(cs *credentials.Store) error {
	s.resMu.Lock()
	defer s.resMu.Unlock()
	return s.migrateNodesLocked(cs)
}

func (s *Server) migrateNodesLocked(cs *credentials.Store) error {
	var pins []credentials.HostPin
	if j, err := (&mesh.Deployer{Dir: s.meshDir()}).Load(); err == nil && j != nil {
		for _, h := range j.Hosts {
			pins = append(pins, credentials.HostPin{NodeID: h.NodeID, Address: h.SSHHost, Port: h.SSHPort, Fingerprint: h.HostKey})
		}
	}
	_, err := s.Store.Update(func(t *model.Topology) (bool, error) { return cs.MigrateNodes(t, pins) })
	return err
}

// ------------------------------------------------------------ errors ---

func codeStatus(code string) int {
	switch code {
	case credentials.CodeNotFound:
		return http.StatusNotFound
	case credentials.CodeInUse, credentials.CodeConflict, codeAccountLocked,
		credentials.CodeHostKeyNotSeen, credentials.CodeHostKeyChanged, credentials.CodeHostKeyMismatch,
		codeNoServer, codeServersNotReady, codeNoMeshAccount, credentials.CodeNoCredential, "host_key_untrusted":
		return http.StatusConflict
	case credentials.CodeStorage, credentials.CodeInsecureStorage:
		return http.StatusInternalServerError
	case codeCheckUnavailable:
		return http.StatusBadGateway
	case codeBadRequest, codeFieldRemoved, codeUnknownField:
		return http.StatusBadRequest
	default:
		return http.StatusUnprocessableEntity
	}
}

const (
	codeBadRequest    = "bad_request"
	codeAccountLocked = "account_locked"
)

// writeResErr writes {"error","code","field"?,"in_use_by"?} with every
// secret of the request scrubbed from the text.
func writeResErr(w http.ResponseWriter, err error, secrets ...string) {
	var ce *credentials.Error
	if !errors.As(err, &ce) {
		ce = &credentials.Error{Code: credentials.CodeStorage, Msg: err.Error()}
	}
	body := map[string]any{"error": credentials.Scrub(ce.Msg, secrets...), "code": ce.Code}
	if ce.Field != "" {
		body["field"] = ce.Field
	}
	if ce.InUse != nil {
		body["in_use_by"] = ce.InUse
	}
	writeJSON(w, codeStatus(ce.Code), body)
}

func badRequest() error {
	return &credentials.Error{Code: codeBadRequest, Msg: "请求格式错误"}
}

// decodeBody reads a JSON object (at most 64 KiB). Decoder messages can
// quote input, so any failure becomes the fixed "请求格式错误".
func decodeBody(w http.ResponseWriter, r *http.Request, dst any) error {
	raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 64<<10))
	if err != nil {
		return badRequest()
	}
	if len(strings.TrimSpace(string(raw))) == 0 {
		return badRequest()
	}
	if err := json.Unmarshal(raw, dst); err != nil {
		return badRequest()
	}
	return nil
}

// ------------------------------------------------------- references ---

// meshState is the Mesh deployment journal and, when it is busy (running,
// published or not fully withdrawn), the Cloudflare account id it is bound
// to. Call under mesh.WithDeploymentLock when the result guards a change.
type meshState struct {
	j     *mesh.Journal
	busy  bool
	bound string
}

func (s *Server) meshState(cs *credentials.Store) meshState {
	j, err := (&mesh.Deployer{Dir: s.meshDir()}).Load()
	if err != nil || j == nil {
		// An unreadable journal is treated as busy with an unknown account:
		// nothing bound may be removed while it cannot be checked.
		return meshState{busy: err != nil}
	}
	st := meshState{j: j, busy: j.Busy(), bound: j.AccountID}
	if st.busy && st.bound == "" {
		// A journal from before the binding: the selected account stays.
		if id := cs.MeshAccount(); id != "" {
			if a, err := cs.Account(id); err == nil {
				st.bound = a.AccountID
			}
		}
	}
	return st
}

func (m meshState) ref() credentials.Ref {
	if m.j == nil {
		return credentials.Ref{Kind: "mesh_deployment", ID: "unknown", Name: "Mesh 部署记录无法读取"}
	}
	return credentials.Ref{Kind: "mesh_deployment", ID: m.j.RunID, Name: "Mesh 部署（" + m.j.State + "）"}
}

// serverRefs: topology nodes on the server, and deployments that pinned
// it (from the journal's pins, so a deleted node does not hide one).
func serverRefs(cs *credentials.Store, id string, t model.Topology) []credentials.Ref {
	refs := []credentials.Ref{}
	for _, n := range t.Nodes {
		if n.ServerID == id {
			refs = append(refs, credentials.Ref{Kind: "node", ID: n.ID, Name: n.Name})
		}
	}
	return append(refs, cs.DeploymentRefsForServer(id)...)
}

// credRefs: servers using the credential, and deployments that pinned it.
func credRefs(cs *credentials.Store, id string) []credentials.Ref {
	refs := append([]credentials.Ref{}, cs.ServersUsing(id)...)
	return append(refs, cs.DeploymentRefsForCredential(id)...)
}

func accountRefs(a credentials.CloudflareAccount, m meshState) []credentials.Ref {
	if m.busy && (m.bound == "" || m.bound == a.AccountID) {
		return []credentials.Ref{m.ref()}
	}
	return []credentials.Ref{}
}

// ------------------------------------------------------------- views ---

type credSummary struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	Kind string `json:"kind"`
}

type serverView struct {
	model.Server
	Credential *credSummary      `json:"credential"`
	InUseBy    []credentials.Ref `json:"in_use_by"`
	// Operable: a credential is selected and the host key is trusted —
	// what provisioning and deployments require.
	Operable bool `json:"operable"`
	// Ready: operable and the last connection test passed.
	Ready   bool     `json:"ready"`
	Missing []string `json:"missing"`
	// Node is the topology node running on this server, if any.
	Node *credentials.Ref `json:"node"`
}

func (s *Server) serverView(cs *credentials.Store, sv model.Server, t model.Topology) serverView {
	v := serverView{Server: sv, InUseBy: serverRefs(cs, sv.ID, t), Missing: []string{}}
	if sv.Tags == nil {
		v.Tags = []string{}
	}
	if sv.CredentialID != "" {
		if c, err := cs.SSHCredential(sv.CredentialID); err == nil {
			v.Credential = &credSummary{ID: c.ID, Name: c.Name, Kind: c.Kind}
		}
	}
	if v.Credential == nil {
		v.Missing = append(v.Missing, "credential")
	}
	if sv.HostKey.State != model.HostKeyTrusted {
		v.Missing = append(v.Missing, "host_key")
	}
	v.Operable = len(v.Missing) == 0
	if sv.LastTest == nil || !sv.LastTest.OK {
		v.Missing = append(v.Missing, "connection_test")
	}
	v.Ready = len(v.Missing) == 0
	for _, r := range v.InUseBy {
		if r.Kind == "node" {
			r := r
			v.Node = &r
			break
		}
	}
	return v
}

type credView struct {
	credentials.SSHCredential
	InUseBy []credentials.Ref `json:"in_use_by"`
}

type accountView struct {
	credentials.CloudflareAccount
	UsedForMesh     bool              `json:"used_for_mesh"`
	BoundDeployment *credentials.Ref  `json:"bound_deployment"`
	InUseBy         []credentials.Ref `json:"in_use_by"`
}

func accountViewOf(cs *credentials.Store, a credentials.CloudflareAccount, m meshState) accountView {
	v := accountView{CloudflareAccount: a, UsedForMesh: cs.MeshAccount() == a.ID, InUseBy: accountRefs(a, m)}
	if len(v.InUseBy) > 0 {
		r := v.InUseBy[0]
		v.BoundDeployment = &r
	}
	return v
}

// resCtx loads what every resource handler needs.
func (s *Server) resCtx(w http.ResponseWriter) (*credentials.Store, model.Topology, bool) {
	cs, err := s.credStore()
	if err != nil {
		writeResErr(w, err)
		return nil, model.Topology{}, false
	}
	t, err := s.topology()
	if err != nil {
		writeResErr(w, err)
		return nil, model.Topology{}, false
	}
	return cs, t, true
}

func (s *Server) registerResources(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/servers", s.listServers)
	mux.HandleFunc("POST /api/servers", s.createServer)
	mux.HandleFunc("GET /api/servers/{id}", s.getServer)
	mux.HandleFunc("PATCH /api/servers/{id}", s.patchServer)
	mux.HandleFunc("DELETE /api/servers/{id}", s.deleteServer)
	mux.HandleFunc("POST /api/servers/{id}/host-key/trust", s.trustHostKey)
	mux.HandleFunc("DELETE /api/servers/{id}/host-key", s.forgetHostKey)

	mux.HandleFunc("GET /api/ssh-credentials", s.listCreds)
	mux.HandleFunc("POST /api/ssh-credentials", s.createCred)
	mux.HandleFunc("GET /api/ssh-credentials/{id}", s.getCred)
	mux.HandleFunc("PATCH /api/ssh-credentials/{id}", s.patchCred)
	mux.HandleFunc("PUT /api/ssh-credentials/{id}/secret", s.rotateCred)
	mux.HandleFunc("DELETE /api/ssh-credentials/{id}", s.deleteCred)

	mux.HandleFunc("GET /api/cloudflare/accounts", s.listAccounts)
	mux.HandleFunc("POST /api/cloudflare/accounts", s.createAccount)
	mux.HandleFunc("GET /api/cloudflare/accounts/{id}", s.getAccount)
	mux.HandleFunc("PATCH /api/cloudflare/accounts/{id}", s.patchAccount)
	mux.HandleFunc("PUT /api/cloudflare/accounts/{id}/token", s.rotateAccountToken)
	mux.HandleFunc("DELETE /api/cloudflare/accounts/{id}", s.deleteAccount)
	mux.HandleFunc("PUT /api/cloudflare/mesh-account", s.putMeshAccount)
}

// ----------------------------------------------------------- servers ---

func (s *Server) listServers(w http.ResponseWriter, r *http.Request) {
	cs, t, ok := s.resCtx(w)
	if !ok {
		return
	}
	out := []serverView{}
	for _, sv := range cs.Servers() {
		out = append(out, s.serverView(cs, sv, t))
	}
	writeJSON(w, http.StatusOK, map[string]any{"servers": out})
}

func (s *Server) getServer(w http.ResponseWriter, r *http.Request) {
	cs, t, ok := s.resCtx(w)
	if !ok {
		return
	}
	sv, err := cs.Server(r.PathValue("id"))
	if err != nil {
		writeResErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"server": s.serverView(cs, sv, t)})
}

func (s *Server) createServer(w http.ResponseWriter, r *http.Request) {
	cs, _, ok := s.resCtx(w)
	if !ok {
		return
	}
	var in credentials.ServerInput
	if err := decodeBody(w, r, &in); err != nil {
		writeResErr(w, err)
		return
	}
	s.resMu.Lock()
	sv, err := cs.CreateServer(in)
	s.resMu.Unlock()
	if err != nil {
		writeResErr(w, err)
		return
	}
	t, _ := s.topology()
	writeJSON(w, http.StatusCreated, map[string]any{"server": s.serverView(cs, sv, t)})
}

func (s *Server) patchServer(w http.ResponseWriter, r *http.Request) {
	cs, _, ok := s.resCtx(w)
	if !ok {
		return
	}
	var p credentials.ServerPatch
	if err := decodeBody(w, r, &p); err != nil {
		writeResErr(w, err)
		return
	}
	s.resMu.Lock()
	var sv model.Server
	// Under the deployment lock: a deployment pins servers when it starts.
	err := mesh.WithDeploymentLock(func() error {
		var err error
		sv, err = cs.UpdateServer(r.PathValue("id"), p)
		return err
	})
	s.resMu.Unlock()
	if err != nil {
		writeResErr(w, err)
		return
	}
	t, _ := s.topology()
	writeJSON(w, http.StatusOK, map[string]any{"server": s.serverView(cs, sv, t)})
}

func (s *Server) deleteServer(w http.ResponseWriter, r *http.Request) {
	cs, _, ok := s.resCtx(w)
	if !ok {
		return
	}
	id := r.PathValue("id")
	s.resMu.Lock()
	defer s.resMu.Unlock()
	err := mesh.WithDeploymentLock(func() error {
		sv, err := cs.Server(id)
		if err != nil {
			return err
		}
		t, err := s.topology()
		if err != nil {
			return err
		}
		if refs := serverRefs(cs, id, t); len(refs) > 0 {
			return &credentials.Error{Code: credentials.CodeInUse, InUse: refs,
				Msg: fmt.Sprintf("服务器 %s 仍被引用（拓扑节点或未撤回完的 Mesh 部署），先解除引用", sv.Name)}
		}
		return cs.DeleteServer(id)
	})
	if err != nil {
		writeResErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"deleted": id})
}

func (s *Server) trustHostKey(w http.ResponseWriter, r *http.Request) {
	cs, t, ok := s.resCtx(w)
	if !ok {
		return
	}
	var body struct {
		Fingerprint string `json:"fingerprint"`
	}
	if err := decodeBody(w, r, &body); err != nil {
		writeResErr(w, err)
		return
	}
	sv, err := cs.TrustHostKey(r.PathValue("id"), body.Fingerprint)
	if err != nil {
		writeResErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"server": s.serverView(cs, sv, t)})
}

func (s *Server) forgetHostKey(w http.ResponseWriter, r *http.Request) {
	cs, t, ok := s.resCtx(w)
	if !ok {
		return
	}
	sv, err := cs.ForgetHostKey(r.PathValue("id"))
	if err != nil {
		writeResErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"server": s.serverView(cs, sv, t)})
}

// --------------------------------------------------- SSH credentials ---

type credBody struct {
	credentials.SSHSecretInput
	Name  string `json:"name"`
	Notes string `json:"notes"`
}

func (s *Server) credView(cs *credentials.Store, c credentials.SSHCredential) credView {
	return credView{SSHCredential: c, InUseBy: credRefs(cs, c.ID)}
}

func (s *Server) listCreds(w http.ResponseWriter, r *http.Request) {
	cs, _, ok := s.resCtx(w)
	if !ok {
		return
	}
	out := []credView{}
	for _, c := range cs.SSHCredentials() {
		out = append(out, s.credView(cs, c))
	}
	writeJSON(w, http.StatusOK, map[string]any{"credentials": out})
}

func (s *Server) getCred(w http.ResponseWriter, r *http.Request) {
	cs, _, ok := s.resCtx(w)
	if !ok {
		return
	}
	c, err := cs.SSHCredential(r.PathValue("id"))
	if err != nil {
		writeResErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"credential": s.credView(cs, c)})
}

func (s *Server) createCred(w http.ResponseWriter, r *http.Request) {
	cs, _, ok := s.resCtx(w)
	if !ok {
		return
	}
	var body credBody
	if err := decodeBody(w, r, &body); err != nil {
		writeResErr(w, err)
		return
	}
	c, err := cs.CreateSSHCredential(body.Name, body.Notes, body.SSHSecretInput)
	if err != nil {
		writeResErr(w, err, body.Secrets()...)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"credential": s.credView(cs, c)})
}

func (s *Server) patchCred(w http.ResponseWriter, r *http.Request) {
	cs, _, ok := s.resCtx(w)
	if !ok {
		return
	}
	var p credentials.CredentialPatch
	if err := decodeBody(w, r, &p); err != nil {
		writeResErr(w, err)
		return
	}
	c, err := cs.UpdateSSHCredential(r.PathValue("id"), p)
	if err != nil {
		writeResErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"credential": s.credView(cs, c)})
}

func (s *Server) rotateCred(w http.ResponseWriter, r *http.Request) {
	cs, _, ok := s.resCtx(w)
	if !ok {
		return
	}
	var in credentials.SSHSecretInput
	if err := decodeBody(w, r, &in); err != nil {
		writeResErr(w, err)
		return
	}
	c, err := cs.RotateSSHCredential(r.PathValue("id"), in)
	if err != nil {
		writeResErr(w, err, in.Secrets()...)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"credential": s.credView(cs, c)})
}

func (s *Server) deleteCred(w http.ResponseWriter, r *http.Request) {
	cs, _, ok := s.resCtx(w)
	if !ok {
		return
	}
	id := r.PathValue("id")
	s.resMu.Lock()
	defer s.resMu.Unlock()
	err := mesh.WithDeploymentLock(func() error {
		c, err := cs.SSHCredential(id)
		if err != nil {
			return err
		}
		if refs := credRefs(cs, id); len(refs) > 0 {
			return &credentials.Error{Code: credentials.CodeInUse, InUse: refs,
				Msg: fmt.Sprintf("SSH 凭据 %s 仍被服务器或未撤回完的 Mesh 部署使用，先改用别的凭据或撤回", c.Name)}
		}
		return cs.DeleteSSHCredential(id)
	})
	if err != nil {
		writeResErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"deleted": id})
}

// ----------------------------------------------- Cloudflare accounts ---

func (s *Server) listAccounts(w http.ResponseWriter, r *http.Request) {
	cs, err := s.credStore()
	if err != nil {
		writeResErr(w, err)
		return
	}
	m := s.meshState(cs)
	out := []accountView{}
	for _, a := range cs.Accounts() {
		out = append(out, accountViewOf(cs, a, m))
	}
	var sel any
	if id := cs.MeshAccount(); id != "" {
		sel = id
	}
	writeJSON(w, http.StatusOK, map[string]any{"accounts": out, "mesh_account": sel})
}

func (s *Server) getAccount(w http.ResponseWriter, r *http.Request) {
	cs, err := s.credStore()
	if err != nil {
		writeResErr(w, err)
		return
	}
	a, err := cs.Account(r.PathValue("id"))
	if err != nil {
		writeResErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"account": accountViewOf(cs, a, s.meshState(cs))})
}

func (s *Server) createAccount(w http.ResponseWriter, r *http.Request) {
	cs, err := s.credStore()
	if err != nil {
		writeResErr(w, err)
		return
	}
	var in credentials.AccountInput
	if err := decodeBody(w, r, &in); err != nil {
		writeResErr(w, err)
		return
	}
	a, err := cs.CreateAccount(in)
	if err != nil {
		writeResErr(w, err, in.APIToken)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"account": accountViewOf(cs, a, s.meshState(cs))})
}

func (s *Server) patchAccount(w http.ResponseWriter, r *http.Request) {
	cs, err := s.credStore()
	if err != nil {
		writeResErr(w, err)
		return
	}
	var p credentials.AccountPatch
	if err := decodeBody(w, r, &p); err != nil {
		writeResErr(w, err)
		return
	}
	id := r.PathValue("id")
	var out credentials.CloudflareAccount
	err = mesh.WithDeploymentLock(func() error {
		cur, err := cs.Account(id)
		if err != nil {
			return err
		}
		if p.AccountID != nil && strings.TrimSpace(*p.AccountID) != cur.AccountID {
			if m := s.meshState(cs); len(accountRefs(cur, m)) > 0 {
				return &credentials.Error{Code: codeAccountLocked, Field: "account_id", InUse: accountRefs(cur, m),
					Msg: mesh.ErrAccountLocked.Error()}
			}
		}
		out, err = cs.UpdateAccount(id, p)
		return err
	})
	if err != nil {
		writeResErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"account": accountViewOf(cs, out, s.meshState(cs))})
}

func (s *Server) rotateAccountToken(w http.ResponseWriter, r *http.Request) {
	cs, err := s.credStore()
	if err != nil {
		writeResErr(w, err)
		return
	}
	var body struct {
		APIToken string `json:"api_token"`
	}
	if err := decodeBody(w, r, &body); err != nil {
		writeResErr(w, err)
		return
	}
	var out credentials.CloudflareAccount
	// Same account, new token: always allowed, also while bound. Taken
	// under the deployment lock so a running withdrawal reads one token.
	err = mesh.WithDeploymentLock(func() error {
		var err error
		out, err = cs.RotateAccountToken(r.PathValue("id"), body.APIToken)
		return err
	})
	if err != nil {
		writeResErr(w, err, body.APIToken)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"account": accountViewOf(cs, out, s.meshState(cs))})
}

func (s *Server) deleteAccount(w http.ResponseWriter, r *http.Request) {
	cs, err := s.credStore()
	if err != nil {
		writeResErr(w, err)
		return
	}
	id := r.PathValue("id")
	err = mesh.WithDeploymentLock(func() error {
		a, err := cs.Account(id)
		if err != nil {
			return err
		}
		if refs := accountRefs(a, s.meshState(cs)); len(refs) > 0 {
			return &credentials.Error{Code: credentials.CodeInUse, InUse: refs, Msg: mesh.ErrCredentialsInUse.Error()}
		}
		return cs.DeleteAccount(id)
	})
	if err != nil {
		writeResErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"deleted": id})
}

func (s *Server) putMeshAccount(w http.ResponseWriter, r *http.Request) {
	cs, err := s.credStore()
	if err != nil {
		writeResErr(w, err)
		return
	}
	var body struct {
		Account string `json:"account"`
	}
	if err := decodeBody(w, r, &body); err != nil {
		writeResErr(w, err)
		return
	}
	err = mesh.WithDeploymentLock(func() error {
		next := ""
		if body.Account != "" {
			a, err := cs.Account(body.Account)
			if err != nil {
				return err
			}
			next = a.AccountID
		}
		if m := s.meshState(cs); m.busy && (next == "" || next != m.bound) {
			return &credentials.Error{Code: codeAccountLocked, Field: "account", InUse: []credentials.Ref{m.ref()},
				Msg: mesh.ErrAccountLocked.Error()}
		}
		return cs.SetMeshAccount(body.Account)
	})
	if err != nil {
		writeResErr(w, err)
		return
	}
	var sel any
	if id := cs.MeshAccount(); id != "" {
		sel = id
	}
	writeJSON(w, http.StatusOK, map[string]any{"mesh_account": sel})
}

// ------------------------------------------- Mesh credential adapter ---

// meshAccountSource is the deployer's view of the credential store: the
// account selected for Mesh. The old Mesh card endpoints use it too.
type meshAccountSource struct {
	cs  *credentials.Store
	err error
}

func (s *Server) meshCreds() meshAccountSource {
	cs, err := s.credStore()
	return meshAccountSource{cs: cs, err: err}
}

func (m meshAccountSource) Load() (mesh.Credentials, error) {
	if m.err != nil {
		return mesh.Credentials{}, m.err
	}
	id := m.cs.MeshAccount()
	if id == "" {
		return mesh.Credentials{}, mesh.ErrNoCredentials
	}
	a, tok, err := m.cs.AccountToken(id)
	if errors.Is(err, credentials.ErrNotFound) {
		return mesh.Credentials{}, mesh.ErrNoCredentials
	}
	if err != nil {
		return mesh.Credentials{}, err
	}
	return mesh.Credentials{AccountID: a.AccountID, APIToken: tok, Ref: a.ID}, nil
}

// Save stores c as the Mesh account: the token of the selected account is
// rotated when the account id is the same; otherwise an existing account
// with that id is rotated and selected, or a new one is created and
// selected. Called under the deployment lock by Deployer.SaveCredentials,
// which has already enforced the binding.
func (m meshAccountSource) Save(c mesh.Credentials) error {
	if m.err != nil {
		return m.err
	}
	acct, tok := strings.TrimSpace(c.AccountID), strings.TrimSpace(c.APIToken)
	if !mesh.ValidAccountID(acct) {
		return errors.New("Cloudflare account id 应为 32 位十六进制")
	}
	if !mesh.ValidAPIToken(tok) {
		return errors.New("Cloudflare API token 格式无效（只允许字母、数字、- 和 _，不含空白）")
	}
	if id := m.cs.MeshAccount(); id != "" {
		if a, err := m.cs.Account(id); err == nil && a.AccountID == acct {
			_, err := m.cs.RotateAccountToken(id, tok)
			return err
		}
	}
	if a, ok := m.cs.AccountByCloudflareID(acct); ok {
		if _, err := m.cs.RotateAccountToken(a.ID, tok); err != nil {
			return err
		}
		return m.cs.SetMeshAccount(a.ID)
	}
	a, err := m.cs.CreateAccount(credentials.AccountInput{Name: "Cloudflare " + acct[:8], AccountID: acct, APIToken: tok})
	if err != nil {
		return err
	}
	return m.cs.SetMeshAccount(a.ID)
}

// Delete removes the account selected for Mesh.
func (m meshAccountSource) Delete() error {
	if m.err != nil {
		return m.err
	}
	id := m.cs.MeshAccount()
	if id == "" {
		return nil
	}
	return m.cs.DeleteAccount(id)
}

// ------------------------------------------------- topology references ---

// checkNodeServers enforces the node → server references of a topology
// about to be saved: the gateway has none, every server exists, no two
// nodes share one, and a node with a server has no old ssh_* fields.
func checkNodeServers(cs *credentials.Store, t model.Topology) error {
	used := map[string]string{}
	for _, n := range t.Nodes {
		if n.ServerID == "" {
			continue
		}
		if n.Role == model.RoleGateway {
			return &credentials.Error{Code: "gateway_server", Field: "nodes." + n.ID + ".server_id",
				Msg: fmt.Sprintf("网关 %s 是本机，不能关联远端服务器", n.ID)}
		}
		if _, err := cs.Server(n.ServerID); err != nil {
			return &credentials.Error{Code: "unknown_server", Field: "nodes." + n.ID + ".server_id",
				Msg: fmt.Sprintf("节点 %s 引用的服务器 %s 不存在", n.ID, n.ServerID)}
		}
		if other, dup := used[n.ServerID]; dup {
			return &credentials.Error{Code: "server_shared", Field: "nodes." + n.ID + ".server_id",
				Msg: fmt.Sprintf("节点 %s 和 %s 不能共用服务器 %s", other, n.ID, n.ServerID)}
		}
		used[n.ServerID] = n.ID
		if n.SSHHost != "" || n.SSHPort != 0 || n.SSHUser != "" {
			return &credentials.Error{Code: "ssh_fields_moved", Field: "nodes." + n.ID + ".ssh_host",
				Msg: fmt.Sprintf("节点 %s 已关联服务器 %s：SSH 地址、端口和用户在服务器管理里修改，拓扑里的 ssh_* 要留空", n.ID, n.ServerID)}
		}
	}
	return nil
}

// sshTarget is a node's SSH address: its server's, or the old fields.
func sshTarget(cs *credentials.Store, n model.Node) (host string, port int, user string) {
	if n.ServerID != "" && cs != nil {
		if sv, err := cs.Server(n.ServerID); err == nil {
			return sv.Address, sv.Port, sv.User
		}
	}
	return n.SSHHost, n.SSHPort, n.SSHUser
}
