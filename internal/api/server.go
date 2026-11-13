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
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/radowitz/meridian/internal/apply"
	"github.com/radowitz/meridian/internal/artifacts"
	"github.com/radowitz/meridian/internal/compile"
	"github.com/radowitz/meridian/internal/credentials"
	"github.com/radowitz/meridian/internal/defaults"
	"github.com/radowitz/meridian/internal/hostexec"
	"github.com/radowitz/meridian/internal/mesh"
	"github.com/radowitz/meridian/internal/model"
	"github.com/radowitz/meridian/internal/provision"
	"github.com/radowitz/meridian/internal/sshexec"
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
	// SSHDial replaces the TCP dialer of SSH connections to managed
	// servers (tests only; nil means net.Dialer).
	SSHDial func(ctx context.Context, network, addr string) (net.Conn, error)
	// SSHPool lends authenticated SSH connections across the steps of one
	// operation flow and remembers rate-limited endpoints
	// (sshexec.Pool; nil means a default pool, created on first use).
	SSHPool   *sshexec.Pool
	sshPoolMu sync.Mutex
	// CloudflareAPIBase replaces the Cloudflare API base URL of the token
	// permission check (tests only).
	CloudflareAPIBase string
	// RemoteStatus reads the remote-access interface's peer status through
	// the host agent (hostexec.Client in main). Nil: runtime unavailable.
	RemoteStatus RemoteStatusRuntime
	// Upstream reads which path and hub carry the gateway's traffic (the
	// gateway's upstream record, through the host agent; hostexec.Client in
	// main). Nil: with a backup hub the carrying hub is unknown.
	Upstream UpstreamRuntime
	// Prober is the host agent's read-only unlock probe (the same
	// hostexec.Client as Host in main). Nil: the panel cannot probe and the
	// scheduler records that, without inventing results.
	Prober ProbeRuntime
	// ProbeJobTimeout bounds one probe job; zero means 15 minutes.
	ProbeJobTimeout time.Duration
	// Lists is the host agent's list update action (the same
	// hostexec.Client in main). Nil: "update now" answers 503.
	Lists ListsRuntime
	// listsMu guards listsJob, the one list update that may run at a time.
	listsMu  sync.Mutex
	listsJob *listsJob
	// mu covers read-modify-write of the unlock, pool and probe-job documents.
	mu sync.Mutex
	// groupHubMu guards groupHubBusy: one read of the hub's group state
	// at a time.
	groupHubMu   sync.Mutex
	groupHubBusy bool
	// jobMu guards job, the one probe job that may run at a time.
	jobMu sync.Mutex
	job   *jobHandle
	// keyMu serialises key resolution so two installs cannot generate two keys.
	keyMu sync.Mutex
	// Artifacts are the panel-delivered binaries (internal/artifacts),
	// loaded and verified at startup. Nil: none available; installs that
	// need one are refused by the preflight.
	Artifacts *artifacts.Bundle
	// SecretsDir holds the credential store (servers, SSH credentials,
	// Cloudflare accounts and their secrets). Empty means <DataDir>/secrets.
	// It is never part of a snapshot, the topology or an export.
	SecretsDir string
	credMu     sync.Mutex
	creds      *credentials.Store
	// resMu keeps node → server and server → credential references
	// consistent across topology saves and deletions.
	resMu sync.Mutex
	// raMu serialises remote-access changes with the WireGuard secret
	// garbage collection (a new PSK is stored before the topology names it).
	raMu sync.Mutex
	// HostPreflight is meridian-host's read-only install pre-check
	// (hostexec.Client in main). Nil: taken from Host when it implements
	// it; an install to a real host without it is refused.
	HostPreflight HostPreflightRuntime
	// provMu guards provBusy (one preflight or provision per node), the
	// deployment id and the provision outcomes.
	provMu   sync.Mutex
	provBusy map[string]bool
}

// localNodeID is the node whose files an install writes on this host.
const localNodeID = "gw"

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/health", s.health)
	mux.HandleFunc("GET /api/meta", s.meta)
	mux.HandleFunc("GET /api/topology", s.getTopology)
	mux.HandleFunc("PUT /api/topology", s.putTopology)
	mux.HandleFunc("POST /api/topology/allocations", s.postAllocations)
	mux.HandleFunc("POST /api/validate", s.postValidate)
	mux.HandleFunc("POST /api/compile", s.postCompile)
	mux.HandleFunc("POST /api/diff", s.postDiff)
	mux.HandleFunc("POST /api/apply", s.postApply)
	mux.HandleFunc("POST /api/rollback", s.postRollback)
	mux.HandleFunc("GET /api/host", s.getHost)
	mux.HandleFunc("GET /api/status", s.getStatus)
	mux.HandleFunc("GET /api/upstream", s.getUpstream)
	mux.HandleFunc("POST /api/host/recover", s.postHostRecover)
	mux.HandleFunc("POST /api/provision", s.postProvision)
	mux.HandleFunc("GET /api/pools", s.getPools)
	mux.HandleFunc("POST /api/pools/health", s.postPoolHealth)
	mux.HandleFunc("GET /api/unlock", s.getUnlock)
	mux.HandleFunc("POST /api/unlock/report", s.postUnlockReport)
	mux.HandleFunc("POST /api/unlock/run", s.postUnlockRun)
	mux.HandleFunc("GET /api/unlock/jobs", s.getUnlockJobs)
	mux.HandleFunc("GET /api/unlock/jobs/{id}", s.getUnlockJob)
	mux.HandleFunc("GET /api/unlock/catalog", s.getUnlockCatalog)
	mux.HandleFunc("GET /api/unlock/results", s.getUnlockResults)
	mux.HandleFunc("POST /api/unlock/results/prune", s.postUnlockResultsPrune)
	mux.HandleFunc("POST /api/unlock/jobs/{id}/cancel", s.postUnlockJobCancel)
	mux.HandleFunc("GET /api/leakcheck", s.getLeakcheck)
	mux.HandleFunc("GET /api/mesh", s.getMesh)
	mux.HandleFunc("PUT /api/mesh/credentials", s.putMeshCredentials)
	mux.HandleFunc("DELETE /api/mesh/credentials", s.deleteMeshCredentials)
	mux.HandleFunc("POST /api/mesh/deploy", s.postMeshDeploy)
	mux.HandleFunc("POST /api/mesh/withdraw", s.postMeshWithdraw)
	s.registerResources(mux)
	s.registerRegionGroups(mux)
	s.registerLists(mux)
	s.registerRemoteAccess(mux)
	s.registerSSHOps(mux)
	s.registerPreflight(mux)
	mux.HandleFunc("GET /api/artifacts", s.getArtifacts)
	s.registerWithdraw(mux)
	s.registerWSS(mux)
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
		"modes":       []string{string(model.GroupAuto), string(model.GroupManual)},
		"on_failure":  []string{string(model.OnFailureHold), string(model.OnFailureFallback)},
		"phase":       3,
		"features": []string{
			"pools",
			"region-groups",
			"mesh-sidecar",
			"unlock-hysteresis",
			"pure-v6",
			"nat64-reserved",
			"leak-checklist",
			"remote-access",
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
	// ?import=1: the document replaces the stored one wholesale (an export
	// brought back): its own allocation table counts, every slot the stored
	// topology used is retired. Without it the stored table is
	// authoritative (store.Save).
	imported := r.URL.Query().Get("import") == "1"
	// remote_access is owned by /api/remote-access: a whole-document save
	// (the topology editor) keeps the stored block, whatever it sent.
	s.raMu.Lock()
	defer s.raMu.Unlock()
	cur, err := s.topology()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	t.RemoteAccess = cur.RemoteAccess.Clone()
	// Validate what will be stored: the slots the store will keep or give
	// (the save reconciles again under the store lock, with the same result
	// unless another save slipped in between).
	if imported {
		store.ReconcileImport(cur.Allocations, &t)
	} else {
		model.ReconcileAllocations(cur.Allocations, &t)
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
	// Server references can only be checked with the credential store; a
	// topology without any can still be saved while the store is broken.
	cs, cerr := s.credStore()
	if cerr != nil {
		for _, n := range t.Nodes {
			if n.ServerID != "" {
				writeResErr(w, cerr)
				return
			}
		}
	}
	s.resMu.Lock()
	if cs != nil {
		if err := checkNodeServers(cs, t); err != nil {
			s.resMu.Unlock()
			writeResErr(w, err)
			return
		}
	}
	save := s.Store.Save
	if imported {
		save = s.Store.SaveImport
	}
	if err := save(t); err != nil {
		s.resMu.Unlock()
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	// Old ssh_* fields typed into a node become a server right away.
	merr := cerr
	if cs != nil {
		merr = s.migrateNodesLocked(cs)
		// An imported fixed-path topology: the fields move out (random
		// path and certificate instead), as at startup.
		if werr := s.migrateWSS(cs); werr != nil && merr == nil {
			merr = werr
		}
	}
	s.resMu.Unlock()
	stored, _ := s.topology()
	// Group orders or choices may have changed with the document.
	s.afterGroupChange(stored, "")
	if merr != nil {
		writeJSON(w, http.StatusOK, map[string]any{
			"topology":        store.Redact(stored),
			"issues":          res.Issues,
			"paths":           res.Paths,
			"draft":           draft,
			"migration_error": merr.Error(),
		})
		return
	}
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
	ap := s.applier(false)
	diff, err := ap.Diff(b.Canonical())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	// installed: the gateway files an install would add, change or remove
	// compared with what is installed now (by hash; null when nothing is
	// installed). It answers "what will an install change" when the text
	// diff above is empty because the change was applied but not installed.
	inst, err := ap.InstalledDiff(b)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"diff": diff, "order": b.Order, "issues": b.Issues, "installed": inst})
}

type applyBody struct {
	DryRun  bool `json:"dry_run"`
	Install bool `json:"install"`
	// PreflightID is the reviewed install pre-check (POST /api/host/preflight).
	// Required for the first install; the check is re-run before any install.
	PreflightID string `json:"preflight_id,omitempty"`
}

// Error codes of POST /api/apply, POST /api/rollback and POST /api/host/recover.
// Every refusal and failure carries one in "code"; the panel decides on the
// code, never on the message text. A missing or unhealthy host agent is
// codeHostUnavailable ("host_unavailable", 503 when there is none).
const (
	codeLegacyRefused          = "legacy_install_refused" // 409: an old install without a manifest cannot be adopted
	codeTxnPending             = "transaction_pending"    // 409: an unfinished host transaction must be recovered first
	codePeerKeysMissing        = "peer_keys_missing"      // 422: peers in the gateway's WireGuard configs have no usable public key
	codeTopologyInvalid        = "topology_invalid"       // 422: the stored topology does not validate (issues)
	codeLANMismatch            = "lan_interface_mismatch" // 422: as topology_invalid, the gateway LAN interface disagrees
	codeActivationCompensated  = "activation_failed_compensated"
	codeActivationUncompensate = "activation_failed_uncompensated"
	codeCommitFailed           = "commit_failed"           // 500: host converged, bookkeeping failed; recover finishes it
	codeNothingToRollback      = "nothing_to_rollback"     // 409
	codeRollbackModeRequired   = "rollback_mode_required"  // 409: installed host, neither install nor snapshot_only
	codeGatewayKey             = "gateway_key_unavailable" // 409: the gateway private key cannot be resolved
	codeHostStateMalformed     = "host_state_malformed"    // 500
	codeApplyFailed            = "apply_failed"            // fallback
)

func writeCoded(w http.ResponseWriter, status int, code, msg string, extra map[string]any) {
	body := map[string]any{"error": msg, "code": code}
	for k, v := range extra {
		body[k] = v
	}
	writeJSON(w, status, body)
}

// refuseInvalid answers 422 topology_invalid (or lan_interface_mismatch
// when that is among the errors) for a validation failure.
func refuseInvalid(w http.ResponseWriter, err error) bool {
	var ve *compile.ValidationError
	if !errors.As(err, &ve) {
		return false
	}
	code := codeTopologyInvalid
	for _, iss := range ve.Result.Issues {
		if iss.Severity == validate.SeverityError && iss.Code == "lan_interface_mismatch" {
			code = codeLANMismatch
		}
	}
	writeCoded(w, http.StatusUnprocessableEntity, code, err.Error(), map[string]any{"issues": ve.Result.Issues})
	return true
}

func (s *Server) postApply(w http.ResponseWriter, r *http.Request) {
	var body applyBody
	if err := decodeOptional(r, &body); err != nil {
		writeCoded(w, http.StatusBadRequest, codeBadRequest, err.Error(), nil)
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
			pb, err := s.compileTopo(pre)
			if err == nil && refusePeerKeys(w, pb) {
				return
			}
			if err != nil && refuseInvalid(w, err) {
				return
			}
			// The install pre-check (meridian-host's read-only preflight)
			// runs before the gateway key is generated or anything is
			// written: blocking findings, a stale or changed review, or a
			// first install without one are refused here.
			if err == nil && !s.gateGatewayInstall(w, r, provision.FilesFor(pb.Files, localNodeID), body.PreflightID) {
				return
			}
		}
		// First install generates and stores the gateway key; later installs
		// reuse it. Resolution happens before compile so peers see the
		// matching public key, and before any host file is written.
		t, key, err = s.resolveKey(localNodeID, provision.KeyGenerateIfMissing)
		if err != nil {
			writeCoded(w, http.StatusConflict, codeGatewayKey, err.Error(), nil)
			return
		}
	} else {
		t, err = s.topology()
		if err != nil {
			writeCoded(w, http.StatusInternalServerError, credentials.CodeStorage, err.Error(), nil)
			return
		}
	}
	b, err := s.compileTopo(t)
	if err != nil {
		if refuseInvalid(w, err) {
			return
		}
		writeCoded(w, http.StatusBadRequest, codeTopologyInvalid, err.Error(), nil)
		return
	}
	if install && refusePeerKeys(w, b) {
		return
	}
	ap := s.applier(body.Install)
	ap.PrivateKey = key
	if install {
		ap.Secrets = s.wgSecrets()
	}
	res, err := ap.Apply(b, body.DryRun)
	if install {
		ok, unknown := wssInstallResult(err)
		msg := ""
		if err != nil {
			msg = apply.RedactSecrets(err.Error(), key, ap.Secrets)
		}
		s.recordWSS(localNodeID, b, ok, unknown, msg)
	}
	if err != nil {
		writeTxnErr(w, err, key, http.StatusInternalServerError, ap.Secrets)
		return
	}
	if !body.DryRun {
		s.clearUnlockPending()
		s.GCRemoteSecrets()
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
		"code": codePeerKeysMissing,
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
		writeCoded(w, http.StatusBadRequest, codeBadRequest, err.Error(), nil)
		return
	}
	if body.Install && body.SnapshotOnly {
		writeCoded(w, http.StatusBadRequest, codeBadRequest, "install 与 snapshot_only 不能同时设置", nil)
		return
	}
	ap := s.applier(body.Install)
	ap.SnapshotOnly = body.SnapshotOnly
	if body.Install {
		_, key, err := s.resolveKey(localNodeID, provision.KeyReuse)
		if err != nil {
			writeCoded(w, http.StatusConflict, codeGatewayKey, err.Error(), nil)
			return
		}
		ap.PrivateKey = key
		ap.Secrets = s.wgSecrets()
	}
	rep, err := ap.RollbackReport()
	if body.Install && err == nil {
		// The previous snapshot may carry earlier WSS material: the
		// gateway's WSS ends are unknown until installed again.
		s.markWSSNode(localNodeID, model.WSSStageUnknown, "网关运行时回滚到上一个快照")
	}
	if err != nil {
		writeTxnErr(w, err, ap.PrivateKey, http.StatusConflict, ap.Secrets)
		return
	}
	s.GCRemoteSecrets()
	mode := "snapshot"
	if body.Install {
		mode = "runtime"
	}
	writeJSON(w, http.StatusOK, map[string]any{"status": "rolled_back", "mode": mode, "host": rep})
}

// writeTxnErr maps install/rollback failures to a status and a stable code.
// A failed host transaction carries its report (steps, diff, whether it was
// compensated).
func writeTxnErr(w http.ResponseWriter, err error, key string, fallback int, secrets ...map[string]string) {
	msg := apply.RedactSecret(err.Error(), key)
	for _, m := range secrets {
		msg = apply.RedactSecrets(msg, "", m)
	}
	var te *apply.TxnError
	switch {
	case errors.Is(err, apply.ErrNoHostExec):
		writeCoded(w, http.StatusServiceUnavailable, codeHostUnavailable, msg, nil)
	case errors.Is(err, apply.ErrHostAgentFailed):
		writeCoded(w, fallback, codeHostUnavailable, msg, nil)
	case errors.Is(err, apply.ErrPending):
		writeCoded(w, http.StatusConflict, codeTxnPending, msg, nil)
	case errors.Is(err, apply.ErrRuntimeRollbackRequired):
		writeCoded(w, http.StatusConflict, codeRollbackModeRequired, msg, nil)
	case errors.Is(err, apply.ErrLegacyInstall):
		writeCoded(w, http.StatusConflict, codeLegacyRefused, msg, nil)
	case errors.Is(err, apply.ErrNoPrevious):
		writeCoded(w, http.StatusConflict, codeNothingToRollback, msg, nil)
	case errors.Is(err, apply.ErrWithdrawnState):
		writeCoded(w, http.StatusConflict, codeGatewayWithdrawn, msg, nil)
	case errors.As(err, &te):
		code := codeActivationUncompensate
		switch {
		case te.Compensated:
			code = codeActivationCompensated
		case te.CompErr == nil:
			code = codeCommitFailed
		}
		writeCoded(w, http.StatusInternalServerError, code, msg, map[string]any{
			"compensated": te.Compensated,
			"host":        te.Report,
		})
	case errors.Is(err, apply.ErrMalformedState):
		writeCoded(w, http.StatusInternalServerError, codeHostStateMalformed, msg, nil)
	default:
		writeCoded(w, fallback, codeApplyFailed, msg, nil)
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
			"route_tables": inst.RouteTables, "dns": inst.DNS, "origin": inst.Origin, "withdrawn": inst.Withdrawn(),
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
	ap.Secrets = s.wgSecrets()
	rep, err := ap.Recover()
	if err != nil {
		return rep, errors.New(apply.RedactSecrets(err.Error(), ap.PrivateKey, ap.Secrets))
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

func (s *Server) applier(install bool) apply.Applier {
	a := apply.Applier{DataDir: s.DataDir, Install: install, LocalID: localNodeID, HostRoot: s.HostRoot, Host: s.Host, Activate: s.Activate}
	// The gateway's binaries (wstunnel for a WSS client) come from the same
	// verified bundle as the remote nodes'. main always loads one; a nil
	// bundle (bare test servers) leaves binaries unmanaged.
	if s.Artifacts != nil {
		a.Artifacts, a.Arch = s.Artifacts, artifacts.UnameArch(runtime.GOARCH)
	}
	return a
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
	// Legacy pool fields in a submitted document become region groups,
	// exactly as the store would read them.
	model.MigrateRegionGroups(&t)
	// The working copy compiles with the slots a save would give it: the
	// stored table is authoritative, whatever the document carries.
	cur, err := s.topology()
	if err != nil {
		return model.Topology{}, err
	}
	model.ReconcileAllocations(cur.Allocations, &t)
	return t, nil
}

func decodeTopo(r *http.Request) (model.Topology, error) {
	var t model.Topology
	if err := json.NewDecoder(r.Body).Decode(&t); err != nil {
		return model.Topology{}, err
	}
	model.MigrateRegionGroups(&t)
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
