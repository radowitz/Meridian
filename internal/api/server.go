// Package api is the LAN-only control plane. It refuses to listen on all
// interfaces unless MERIDIAN_ALLOW_ANY_BIND=1.
package api

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/radowitz/meridian/internal/apply"
	"github.com/radowitz/meridian/internal/compile"
	"github.com/radowitz/meridian/internal/defaults"
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
	// mu covers read-modify-write of the unlock and pool documents.
	mu sync.Mutex
}

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
	mux.HandleFunc("POST /api/provision", s.postProvision)
	mux.HandleFunc("GET /api/pools", s.getPools)
	mux.HandleFunc("POST /api/pools/health", s.postPoolHealth)
	mux.HandleFunc("GET /api/unlock", s.getUnlock)
	mux.HandleFunc("POST /api/unlock/report", s.postUnlockReport)
	mux.HandleFunc("POST /api/unlock/run", s.postUnlockRun)
	mux.HandleFunc("GET /api/leakcheck", s.getLeakcheck)
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
	t, err := s.topology()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
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
	res, err := s.applier(body.Install).Apply(b, body.DryRun)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	if !body.DryRun {
		s.clearUnlockPending()
	}
	writeJSON(w, http.StatusOK, res)
}

func (s *Server) postRollback(w http.ResponseWriter, r *http.Request) {
	var body applyBody
	_ = decodeOptional(r, &body)
	if err := s.applier(body.Install).Rollback(); err != nil {
		writeErr(w, http.StatusConflict, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "rolled_back"})
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
	b, err := s.compileTopo(t)
	if err != nil {
		writeErr(w, http.StatusUnprocessableEntity, err)
		return
	}
	files := provision.FilesFor(b.Files, node.ID)
	var pub string
	if body.GenerateKeys && !body.DryRun {
		kp, err := provision.GenerateKeypair()
		if err != nil {
			writeErr(w, http.StatusInternalServerError, err)
			return
		}
		files = provision.InjectPrivate(files, kp.Private)
		pub = kp.Public
		for i := range t.Nodes {
			if t.Nodes[i].ID == node.ID {
				t.Nodes[i].PublicKey = kp.Public
				t.Nodes[i].PrivateKey = kp.Private
			}
		}
		if err := s.Store.Save(t); err != nil {
			writeErr(w, http.StatusInternalServerError, err)
			return
		}
	}
	script := provision.Script(node.Name, files)
	if body.DryRun || body.PrivateKeyPEM == "" {
		writeJSON(w, http.StatusOK, map[string]any{
			"dry_run":    true,
			"node_id":    node.ID,
			"public_key": pub,
			"script":     provision.Redact(script, lookupPrivate(t, node.ID)),
		})
		return
	}
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
			"error":  err.Error(),
			"output": provision.Redact(out, lookupPrivate(t, node.ID)),
		})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"dry_run":    false,
		"node_id":    node.ID,
		"public_key": pub,
		"output":     provision.Redact(out, lookupPrivate(t, node.ID)),
	})
}

func lookupPrivate(t model.Topology, id string) string {
	n, ok := t.NodeByID(id)
	if !ok {
		return ""
	}
	return n.PrivateKey
}

func (s *Server) applier(install bool) apply.Applier {
	return apply.Applier{DataDir: s.DataDir, Install: install, LocalID: "gw"}
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
