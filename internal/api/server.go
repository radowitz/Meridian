// Package api is the LAN-only control plane. It refuses to listen on all
// interfaces unless MERIDIAN_ALLOW_ANY_BIND=1.
package api

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/radowitz/meridian/internal/apply"
	"github.com/radowitz/meridian/internal/compile"
	"github.com/radowitz/meridian/internal/defaults"
	"github.com/radowitz/meridian/internal/hostexec"
	"github.com/radowitz/meridian/internal/mesh"
	"github.com/radowitz/meridian/internal/model"
	"github.com/radowitz/meridian/internal/provision"
	"github.com/radowitz/meridian/internal/store"
	"github.com/radowitz/meridian/internal/validate"
)

type Server struct {
	Store   *store.Store
	DataDir string
	WebDir  string
	// Token is required on /api except /api/health. An empty token disables
	// the check so unit tests can call the handler directly. main always sets one.
	Token string
	// HostRoot is where an install writes host files. Empty means "/".
	// Tests point it at a temp dir.
	HostRoot string
	// Host is the host execution boundary (a hostexec.Client to
	// meridian-host). main always sets it; an install without it fails
	// explicitly instead of skipping service activation.
	Host apply.Runtime
	// Activate is a test shim used when Host is nil (see apply.Applier).
	Activate func() error
	// MeshCF and MeshRemote replace the Cloudflare client and the SSH
	// executor of the Mesh deployment (tests only; nil means the real ones).
	MeshCF     func(mesh.Credentials) (mesh.Cloudflare, error)
	MeshRemote func() mesh.Remote
	// Prober is the host agent's read-only unlock probe (the same
	// hostexec.Client as Host in main). Nil: the panel cannot probe and the
	// scheduler records that, without inventing results.
	Prober ProbeRuntime
	// ProbeJobTimeout bounds one probe job; zero means 15 minutes.
	ProbeJobTimeout time.Duration
	// mu covers read-modify-write of the unlock, pool and probe-job documents.
	mu sync.Mutex
	// jobMu guards job, the one probe job that may run at a time.
	jobMu sync.Mutex
	job   *jobHandle
	// keyMu serialises key resolution so two installs cannot generate two keys.
	keyMu sync.Mutex
}

// localNodeID is the node whose files an install writes on this host.
const localNodeID = "gw"

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/health", s.health)
	mux.HandleFunc("GET /api/meta", s.meta)
	mux.HandleFunc("GET /api/topology", s.getTopology)
	mux.HandleFunc("PUT /api/topology", s.putTopology)
	mux.HandleFunc("POST /api/validate", s.postValidate)
	mux.HandleFunc("POST /api/compile", s.postCompile)
	mux.HandleFunc("POST /api/diff", s.postDiff)
	mux.HandleFunc("POST /api/apply", s.postApply)
	mux.HandleFunc("POST /api/rollback", s.postRollback)
	mux.HandleFunc("GET /api/host", s.getHost)
	mux.HandleFunc("POST /api/host/recover", s.postHostRecover)
	mux.HandleFunc("POST /api/provision", s.postProvision)
	mux.HandleFunc("GET /api/pools", s.getPools)
	mux.HandleFunc("POST /api/pools/health", s.postPoolHealth)
	mux.HandleFunc("GET /api/unlock", s.getUnlock)
	mux.HandleFunc("POST /api/unlock/report", s.postUnlockReport)
	mux.HandleFunc("POST /api/unlock/run", s.postUnlockRun)
	mux.HandleFunc("GET /api/unlock/jobs", s.getUnlockJobs)
	mux.HandleFunc("POST /api/unlock/jobs/{id}/cancel", s.postUnlockJobCancel)
	mux.HandleFunc("GET /api/leakcheck", s.getLeakcheck)
	mux.HandleFunc("GET /api/mesh", s.getMesh)
	mux.HandleFunc("PUT /api/mesh/credentials", s.putMeshCredentials)
	mux.HandleFunc("DELETE /api/mesh/credentials", s.deleteMeshCredentials)
	mux.HandleFunc("POST /api/mesh/deploy", s.postMeshDeploy)
	mux.HandleFunc("POST /api/mesh/withdraw", s.postMeshWithdraw)
	if s.WebDir != "" {
		mux.Handle("/", http.FileServer(http.Dir(s.WebDir)))
	}
	return s.withAuth(mux)
}

func (s *Server) withAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.Token == "" || r.URL.Path == "/api/health" || !strings.HasPrefix(r.URL.Path, "/api/") {
			next.ServeHTTP(w, r)
			return
		}
		got := r.Header.Get("Authorization")
		const prefix = "Bearer "
		if !strings.HasPrefix(got, prefix) || !constTimeEq(strings.TrimPrefix(got, prefix), s.Token) {
			writeErr(w, http.StatusUnauthorized, errors.New("需要面板口令"))
			return
		}
		next.ServeHTTP(w, r)
	})
}

func constTimeEq(got, want string) bool {
	if len(got) != len(want) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(got), []byte(want)) == 1
}

// LoadOrCreateToken returns MERIDIAN_TOKEN when set, otherwise a token stored
// at path with mode 0600. The value is never logged.
func LoadOrCreateToken(envValue, path string) (string, error) {
	if strings.TrimSpace(envValue) != "" {
		if strings.ContainsAny(envValue, "\r\n") {
			return "", errors.New("MERIDIAN_TOKEN 不能包含换行")
		}
		return strings.TrimSpace(envValue), nil
	}
	if b, err := os.ReadFile(path); err == nil {
		tok := strings.TrimSpace(string(b))
		if tok != "" && !strings.ContainsAny(tok, "\r\n") {
			return tok, nil
		}
	}
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	tok := hex.EncodeToString(raw)
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return "", err
	}
	if err := os.WriteFile(path, []byte(tok+"\n"), 0o600); err != nil {
		return "", err
	}
	return tok, nil
}

func (s *Server) health(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok", "service": "meridian"})
}

func (s *Server) meta(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"transports": []string{
			string(model.TransportDirectWG),
			string(model.TransportWGOverWSS),
			string(model.TransportUDPWSSFailover),
			string(model.TransportIXReplacementWSS),
			string(model.TransportDedicatedLine),
			string(model.TransportCFMesh),
		},
		"roles":       []string{"gateway", "relay", "ix", "hub", "exit"},
		"match_types": []string{"domain", "suffix", "keyword", "geosite", "cidr", "geoip", "asn"},
		"modes":       []string{"pin", "auto"},
		"phase":       3,
		"features": []string{
			"pools",
			"mesh-sidecar",
			"unlock-hysteresis",
			"pure-v6",
			"nat64-reserved",
			"leak-checklist",
		},
	})
}

func (s *Server) topology() (model.Topology, error) {
	t, ok, err := s.Store.Load()
	if err != nil {
		return model.Topology{}, err
	}
	if !ok {
		t = defaults.Example()
		if err := s.Store.Save(t); err != nil {
			return model.Topology{}, err
		}
	}
	return t, nil
}

func (s *Server) getTopology(w http.ResponseWriter, r *http.Request) {
	t, err := s.topology()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, store.Redact(t))
}

func (s *Server) putTopology(w http.ResponseWriter, r *http.Request) {
	t, err := decodeTopo(r)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	res := validate.Run(t)
	draft := r.URL.Query().Get("draft") == "1" || t.Settings.Draft
	if res.HasErrors() && !draft {
		writeJSON(w, http.StatusUnprocessableEntity, map[string]any{
			"error":  "拓扑校验未通过，未保存。可带 ?draft=1 保存草稿。",
			"issues": res.Issues,
			"paths":  res.Paths,
		})
		return
	}
	if err := s.Store.Save(t); err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	stored, _ := s.topology()
	writeJSON(w, http.StatusOK, map[string]any{
		"topology": store.Redact(stored),
		"issues":   res.Issues,
		"paths":    res.Paths,
		"draft":    draft,
	})
}

func (s *Server) postValidate(w http.ResponseWriter, r *http.Request) {
	t, err := s.bodyOrStored(r)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	writeJSON(w, http.StatusOK, validate.Run(t))
}

func (s *Server) postCompile(w http.ResponseWriter, r *http.Request) {
	t, err := s.bodyOrStored(r)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	b, err := s.compileTopo(t)
	if err != nil {
		var ve *compile.ValidationError
		if errors.As(err, &ve) {
			writeJSON(w, http.StatusUnprocessableEntity, map[string]any{
				"error":  err.Error(),
				"issues": ve.Result.Issues,
				"paths":  ve.Result.Paths,
			})
			return
		}
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"order":  b.Order,
		"issues": b.Issues,
		"paths":  b.Paths,
		"files":  b.Files,
	})
}

func (s *Server) postDiff(w http.ResponseWriter, r *http.Request) {
	t, err := s.bodyOrStored(r)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	b, err := s.compileTopo(t)
	if err != nil {
		writeErr(w, http.StatusUnprocessableEntity, err)
		return
	}
	diff, err := s.applier(false).Diff(b.Canonical())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"diff": diff, "order": b.Order, "issues": b.Issues})
}

type applyBody struct {
	DryRun  bool `json:"dry_run"`
	Install bool `json:"install"`
}

func (s *Server) postApply(w http.ResponseWriter, r *http.Request) {
	var body applyBody
	if err := decodeOptional(r, &body); err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	install := body.Install && !body.DryRun
	var t model.Topology
	var key string
	var err error
	if install {
		// A peer without a usable public key would only be caught by
		// "wg setconf" after the host was touched. Refuse first: before the
		// key is generated, before any file is written or snapshot moves.
		// Compile, preview and diff keep accepting such a topology.
		if pre, err := s.topology(); err == nil {
			if pb, err := s.compileTopo(pre); err == nil && refusePeerKeys(w, pb) {
				return
			}
		}
		// First install generates and stores the gateway key; later installs
		// reuse it. Resolution happens before compile so peers see the
		// matching public key, and before any host file is written.
		t, key, err = s.resolveKey(localNodeID, provision.KeyGenerateIfMissing)
		if err != nil {
			writeErr(w, http.StatusConflict, err)
			return
		}
	} else {
		t, err = s.topology()
		if err != nil {
			writeErr(w, http.StatusInternalServerError, err)
			return
		}
	}
	b, err := s.compileTopo(t)
	if err != nil {
		var ve *compile.ValidationError
		if errors.As(err, &ve) {
			writeJSON(w, http.StatusUnprocessableEntity, map[string]any{"error": err.Error(), "issues": ve.Result.Issues})
			return
		}
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	if install && refusePeerKeys(w, b) {
		return
	}
	ap := s.applier(body.Install)
	ap.PrivateKey = key
	res, err := ap.Apply(b, body.DryRun)
	if err != nil {
		writeTxnErr(w, err, key, http.StatusInternalServerError)
		return
	}
	if !body.DryRun {
		s.clearUnlockPending()
	}
	writeJSON(w, http.StatusOK, res)
}

// refusePeerKeys answers 422 when the local node's WireGuard configs in b
// name a peer whose public key is missing, the placeholder or malformed.
func refusePeerKeys(w http.ResponseWriter, b *compile.Bundle) bool {
	probs := b.PeerKeyProblems(localNodeID)
	if len(probs) == 0 {
		return false
	}
	seen := map[string]bool{}
	var peers []string
	for _, p := range probs {
		if !seen[p.Peer] {
			seen[p.Peer] = true
			peers = append(peers, p.Peer)
		}
	}
	writeJSON(w, http.StatusUnprocessableEntity, map[string]any{
		"error": fmt.Sprintf("拒绝安装：本机 WireGuard 配置里这些对端节点没有可用的公钥（缺失、仍是占位符或格式不对）：%s。"+
			"先在对端生成密钥（「生成脚本」/ provision 的 generate_keys）或在拓扑里填入 44 字符的 base64 公钥；宿主上没有写入任何文件。",
			strings.Join(peers, "、")),
		"peer_key_problems": probs,
	})
	return true
}

type rollbackBody struct {
	// Install makes it a runtime rollback: host files, interfaces, units and
	// tables follow the previous snapshot in the same transaction.
	Install bool `json:"install"`
	// SnapshotOnly explicitly asks for a data-dir-only swap on a host that
	// has Meridian installed. Without it such a request is refused.
	SnapshotOnly bool `json:"snapshot_only"`
}

func (s *Server) postRollback(w http.ResponseWriter, r *http.Request) {
	var body rollbackBody
	if err := decodeOptional(r, &body); err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	if body.Install && body.SnapshotOnly {
		writeErr(w, http.StatusBadRequest, errors.New("install 与 snapshot_only 不能同时设置"))
		return
	}
	ap := s.applier(body.Install)
	ap.SnapshotOnly = body.SnapshotOnly
	if body.Install {
		_, key, err := s.resolveKey(localNodeID, provision.KeyReuse)
		if err != nil {
			writeErr(w, http.StatusConflict, err)
			return
		}
		ap.PrivateKey = key
	}
	rep, err := ap.RollbackReport()
	if err != nil {
		writeTxnErr(w, err, ap.PrivateKey, http.StatusConflict)
		return
	}
	mode := "snapshot"
	if body.Install {
		mode = "runtime"
	}
	writeJSON(w, http.StatusOK, map[string]any{"status": "rolled_back", "mode": mode, "host": rep})
}

// writeTxnErr maps install/rollback failures. A failed host transaction
// carries its report (steps, diff, whether it was compensated).
func writeTxnErr(w http.ResponseWriter, err error, key string, fallback int) {
	msg := apply.RedactSecret(err.Error(), key)
	var te *apply.TxnError
	switch {
	case errors.Is(err, apply.ErrNoHostExec):
		writeErr(w, http.StatusServiceUnavailable, errors.New(msg))
	case errors.Is(err, apply.ErrPending), errors.Is(err, apply.ErrRuntimeRollbackRequired):
		writeErr(w, http.StatusConflict, errors.New(msg))
	case errors.As(err, &te):
		writeJSON(w, http.StatusInternalServerError, map[string]any{
			"error":       msg,
			"compensated": te.Compensated,
			"host":        te.Report,
		})
	default:
		writeErr(w, fallback, errors.New(msg))
	}
}

// getHost reports what is installed on the host, any unfinished
// transaction and whether the host execution boundary answers.
func (s *Server) getHost(w http.ResponseWriter, r *http.Request) {
	ap := s.applier(true)
	inst, err := ap.Installed()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	pending, err := ap.Pending()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	agent := map[string]any{"ok": false}
	switch {
	case s.Host != nil:
		ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
		_, perr := s.Host.Do(ctx, hostexec.Request{Action: hostexec.ActionHealth, RequestID: "status-" + randHex(4)})
		cancel()
		agent["ok"] = perr == nil
		if perr != nil {
			agent["error"] = perr.Error()
		}
	case s.Activate != nil:
		agent["ok"] = true
		agent["error"] = "test shim"
	default:
		agent["error"] = apply.ErrNoHostExec.Error()
	}
	var installed any
	if !inst.Empty() {
		installed = map[string]any{
			"version": inst.Version, "created_at": inst.CreatedAt, "files": len(inst.Files),
			"interfaces": inst.Interfaces, "units": inst.Units, "nft_tables": inst.NFTTables,
			"route_tables": inst.RouteTables, "dns": inst.DNS,
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"installed": installed, "pending": pending, "agent": agent})
}

// postHostRecover compensates (or finishes) an unfinished host transaction.
func (s *Server) postHostRecover(w http.ResponseWriter, r *http.Request) {
	rep, err := s.RecoverHost()
	if err != nil {
		writeTxnErr(w, err, "", http.StatusConflict)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"status": "recovered", "host": rep})
}

// RecoverHost runs apply.Recover with the gateway key. main calls it at
// startup so a transaction interrupted by a restart is not left half-done.
func (s *Server) RecoverHost() (*apply.HostReport, error) {
	ap := s.applier(true)
	if p, err := ap.Pending(); err != nil || p == nil {
		return nil, err
	}
	// The key is needed only to rewrite WireGuard configs; a gateway that
	// never had one cannot have them installed.
	if _, key, err := s.resolveKey(localNodeID, provision.KeyReuse); err == nil {
		ap.PrivateKey = key
	}
	rep, err := ap.Recover()
	if err != nil {
		return rep, errors.New(apply.RedactSecret(err.Error(), ap.PrivateKey))
	}
	return rep, nil
}

func randHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// resolveKey loads the topology, resolves nodeID's private key under policy
// and persists a generated key or a filled-in public key before returning.
func (s *Server) resolveKey(nodeID string, policy provision.KeyPolicy) (model.Topology, string, error) {
	s.keyMu.Lock()
	defer s.keyMu.Unlock()
	t, err := s.topology()
	if err != nil {
		return model.Topology{}, "", err
	}
	key, changed, err := provision.ResolveNodeKey(&t, nodeID, policy)
	if err != nil {
		return model.Topology{}, "", err
	}
	if changed {
		if err := s.Store.Save(t); err != nil {
			return model.Topology{}, "", err
		}
	}
	return t, key, nil
}

type provisionBody struct {
	NodeID        string `json:"node_id"`
	SSHHost       string `json:"ssh_host"`
	SSHPort       int    `json:"ssh_port"`
	SSHUser       string `json:"ssh_user"`
	PrivateKeyPEM string `json:"private_key_pem"`
	DryRun        bool   `json:"dry_run"`
	TrustNewHost  bool   `json:"trust_new_host"`
	GenerateKeys  bool   `json:"generate_keys"`
}

func (s *Server) postProvision(w http.ResponseWriter, r *http.Request) {
	var body provisionBody
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	t, err := s.topology()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	node, ok := t.NodeByID(body.NodeID)
	if !ok {
		writeErr(w, http.StatusNotFound, errors.New("节点不存在"))
		return
	}
	if !node.Managed {
		writeErr(w, http.StatusBadRequest, errors.New("该节点不需要装机（例如 IX 专线）"))
		return
	}
	run := !body.DryRun && body.PrivateKeyPEM != ""
	var key, pub string
	switch {
	case body.GenerateKeys && !body.DryRun:
		// Rotate: store the new pair before compiling so peer configs carry
		// the matching public key.
		t, key, err = s.resolveKey(node.ID, provision.KeyRotate)
		if err != nil {
			writeErr(w, http.StatusInternalServerError, err)
			return
		}
		node, _ = t.NodeByID(node.ID)
		pub = node.PublicKey
	case run:
		// generate_keys=false reuses the stored key. A node without one fails
		// here, before SSH connects or any remote config is overwritten.
		t, key, err = s.resolveKey(node.ID, provision.KeyReuse)
		if err != nil {
			writeErr(w, http.StatusConflict, err)
			return
		}
	}
	b, err := s.compileTopo(t)
	if err != nil {
		writeErr(w, http.StatusUnprocessableEntity, err)
		return
	}
	files := provision.FilesFor(b.Files, node.ID)
	if !run {
		// Preview: built from the redacted files, so it carries the
		// placeholder and refuses to run if copied to a host.
		writeJSON(w, http.StatusOK, map[string]any{
			"dry_run":    true,
			"node_id":    node.ID,
			"public_key": pub,
			"script":     provision.Redact(provision.Script(node.Name, files), key),
		})
		return
	}
	injected, err := provision.InjectPrivate(files, key)
	if err != nil {
		writeErr(w, http.StatusConflict, err)
		return
	}
	script := provision.Script(node.Name, injected)
	host := body.SSHHost
	if host == "" {
		host = node.SSHHost
	}
	user := body.SSHUser
	if user == "" {
		user = node.SSHUser
	}
	if user == "" {
		user = "root"
	}
	out, err := provision.Run(provision.SSHRequest{
		Host: host, Port: body.SSHPort, User: user,
		PrivateKeyPEM: body.PrivateKeyPEM, TrustNewHost: body.TrustNewHost,
	}, script)
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]any{
			"error":  provision.Redact(err.Error(), key),
			"output": provision.Redact(out, key),
		})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"dry_run":    false,
		"node_id":    node.ID,
		"public_key": pub,
		"output":     provision.Redact(out, key),
	})
}

func (s *Server) applier(install bool) apply.Applier {
	return apply.Applier{DataDir: s.DataDir, Install: install, LocalID: localNodeID, HostRoot: s.HostRoot, Host: s.Host, Activate: s.Activate}
}

func (s *Server) bodyOrStored(r *http.Request) (model.Topology, error) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		return model.Topology{}, err
	}
	if len(strings.TrimSpace(string(body))) == 0 || string(body) == "{}" {
		return s.topology()
	}
	var t model.Topology
	if err := json.Unmarshal(body, &t); err != nil {
		return model.Topology{}, err
	}
	if len(t.Nodes) == 0 {
		return s.topology()
	}
	return t, nil
}

func decodeTopo(r *http.Request) (model.Topology, error) {
	var t model.Topology
	if err := json.NewDecoder(r.Body).Decode(&t); err != nil {
		return model.Topology{}, err
	}
	return t, nil
}

func decodeOptional(r *http.Request, dest any) error {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		return err
	}
	if len(strings.TrimSpace(string(body))) == 0 {
		return nil
	}
	return json.Unmarshal(body, dest)
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(v)
}

func writeErr(w http.ResponseWriter, code int, err error) {
	writeJSON(w, code, map[string]string{"error": err.Error()})
}

// CheckBind rejects wildcard listeners. The panel is LAN-only.
func CheckBind(addr string) error {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return err
	}
	if host == "" || host == "0.0.0.0" || host == "::" || host == "[::]" {
		if os.Getenv("MERIDIAN_ALLOW_ANY_BIND") != "1" {
			return errors.New("面板只监听局域网地址，拒绝 0.0.0.0 / ::。开发时请设置 MERIDIAN_BIND=127.0.0.1:8787")
		}
	}
	return nil
}
