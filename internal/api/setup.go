package api

// Panel initialisation and administrator credentials.
//
// States of a data directory (Auth.State):
//
//   - setup_required: a fresh install. No panel.token, no admin.json, no
//     stored topology and no MERIDIAN_TOKEN. Every /api path except
//     /api/health and /api/setup/* answers 403 setup_required, so nothing
//     can be compiled, installed or deployed. The only way forward is
//     POST /api/setup with the one-time setup code the operator generates
//     on the host (`meridian setup-code`), from a LAN or loopback source.
//   - ready: admin.json exists, or the data directory is an existing
//     deployment (panel.token, MERIDIAN_TOKEN or a stored topology). An
//     existing deployment keeps logging in with its token exactly as
//     before; adding an administrator password is optional and never
//     required to keep access (no lock-out on upgrade).
//
// Files (all 0600 in the data directory):
//
//   - panel.token: the bearer token every API request carries (unchanged).
//   - admin.json: username and scrypt hash of the administrator password.
//     The password itself is never stored or logged.
//   - setup.code.json: SHA-256 of the one-time setup code, its expiry and
//     the failed attempts. The code itself is printed only to the terminal
//     of the operator who ran `meridian setup-code`; it is never logged and
//     never stored in plain text. It is removed when setup completes and
//     invalidated after setupMaxAttempts failures or setupCodeTTL.
//   - login-lockout.json: failed administrator logins per source address
//     and their lockouts (bounded, expiring; see login_lockout.go).

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"golang.org/x/crypto/scrypt"
)

// Auth states reported by GET /api/setup/status.
const (
	AuthSetupRequired = "setup_required"
	AuthReady         = "ready"
)

const (
	adminFile        = "admin.json"
	setupCodeFile    = "setup.code.json"
	tokenFile        = "panel.token"
	setupCodeTTL     = time.Hour
	setupMaxAttempts = 5
	minPasswordLen   = 12
	loginMaxFailures = 5
	loginLockout     = time.Minute
)

// scrypt cost; a variable so tests can lower it.
var scryptN = 1 << 15

// Auth holds the panel's credential state for one data directory.
type Auth struct {
	dir      string
	envToken string
	// legacy: the directory is an existing deployment (token or topology
	// from before the setup flow).
	legacy bool

	mu    sync.Mutex
	token string
	admin *adminRecord
	// lockouts: failed logins per source (login_lockout.go).
	lockouts map[string]lockoutEntry
	now      func() time.Time
}

type adminRecord struct {
	Version   int    `json:"version"`
	Username  string `json:"username"`
	Salt      string `json:"salt"`
	Hash      string `json:"hash"`
	N         int    `json:"n"`
	R         int    `json:"r"`
	P         int    `json:"p"`
	CreatedAt string `json:"created_at"`
}

type setupCodeRecord struct {
	SHA256    string `json:"sha256"`
	ExpiresAt string `json:"expires_at"`
	Failures  int    `json:"failures"`
}

// LoadAuth reads the credential state of dir. envToken is MERIDIAN_TOKEN;
// hasTopology reports whether the store already holds a topology (an
// existing deployment). It never creates a token for a fresh directory:
// that happens only when setup completes.
func LoadAuth(dir, envToken string, hasTopology bool) (*Auth, error) {
	a := &Auth{dir: dir, now: time.Now}
	if v := strings.TrimSpace(envToken); v != "" {
		if strings.ContainsAny(v, "\r\n") {
			return nil, errors.New("MERIDIAN_TOKEN 不能包含换行")
		}
		a.envToken = v
	}
	a.loadLockouts()
	if b, err := os.ReadFile(filepath.Join(dir, adminFile)); err == nil {
		var rec adminRecord
		if err := json.Unmarshal(b, &rec); err != nil || rec.Hash == "" || rec.Username == "" {
			return nil, fmt.Errorf("%s 无法解析；恢复备份或删除后用旧口令登录重新设置", adminFile)
		}
		a.admin = &rec
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	_, tokErr := os.Stat(filepath.Join(dir, tokenFile))
	a.legacy = a.admin == nil && (a.envToken != "" || tokErr == nil || hasTopology)
	if a.admin != nil || a.legacy {
		tok, err := LoadOrCreateToken(a.envToken, filepath.Join(dir, tokenFile))
		if err != nil {
			return nil, err
		}
		a.token = tok
	}
	return a, nil
}

// State is setup_required or ready.
func (a *Auth) State() string {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.token == "" {
		return AuthSetupRequired
	}
	return AuthReady
}

// Token is the bearer token ("" before setup).
func (a *Auth) Token() string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.token
}

// TokenPath is where the bearer token lives (for the start-up log line).
func (a *Auth) TokenPath() string { return filepath.Join(a.dir, tokenFile) }

// NewSetupCode replaces the one-time setup code and returns it. Only the
// operator's terminal sees the value (cmd: meridian setup-code).
func NewSetupCode(dir string) (string, error) {
	if _, err := os.Stat(filepath.Join(dir, adminFile)); err == nil {
		return "", errors.New("面板已经初始化，不需要初始化码")
	}
	raw := make([]byte, 10)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	code := strings.ToUpper(hex.EncodeToString(raw))
	code = code[0:5] + "-" + code[5:10] + "-" + code[10:15] + "-" + code[15:20]
	rec := setupCodeRecord{SHA256: sha256Hex(normCode(code)), ExpiresAt: time.Now().Add(setupCodeTTL).UTC().Format(time.RFC3339)}
	if err := writeJSON0600(filepath.Join(dir, setupCodeFile), rec); err != nil {
		return "", err
	}
	return code, nil
}

func normCode(s string) string {
	return strings.ToUpper(strings.ReplaceAll(strings.TrimSpace(s), "-", ""))
}

func sha256Hex(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

func writeJSON0600(path string, v any) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, append(b, '\n'), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func hashPassword(pw string, salt []byte, n, r, p int) ([]byte, error) {
	return scrypt.Key([]byte(pw), salt, n, r, p, 32)
}

func newAdminRecord(user, pw string, now time.Time) (*adminRecord, error) {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}
	h, err := hashPassword(pw, salt, scryptN, 8, 1)
	if err != nil {
		return nil, err
	}
	return &adminRecord{Version: 1, Username: user, Salt: hex.EncodeToString(salt), Hash: hex.EncodeToString(h),
		N: scryptN, R: 8, P: 1, CreatedAt: now.UTC().Format(time.RFC3339)}, nil
}

func (rec *adminRecord) check(user, pw string) bool {
	salt, err1 := hex.DecodeString(rec.Salt)
	want, err2 := hex.DecodeString(rec.Hash)
	if err1 != nil || err2 != nil {
		return false
	}
	got, err := hashPassword(pw, salt, rec.N, rec.R, rec.P)
	if err != nil {
		return false
	}
	userOK := subtle.ConstantTimeCompare([]byte(user), []byte(rec.Username)) == 1
	return subtle.ConstantTimeCompare(got, want) == 1 && userOK
}

func checkCredentialsInput(user, pw string) error {
	user = strings.TrimSpace(user)
	if user == "" || len(user) > 64 || strings.ContainsAny(user, "\r\n\t ") {
		return errors.New("用户名不能为空，不超过 64 个字符，不含空白")
	}
	if utf8.RuneCountInString(pw) < minPasswordLen || len(pw) > 1024 {
		return fmt.Errorf("密码至少 %d 个字符", minPasswordLen)
	}
	return nil
}

// Setup completes initialisation: it checks the one-time code, stores the
// administrator and creates the bearer token, which it returns.
func (a *Auth) Setup(code, user, pw string) (string, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.token != "" {
		return "", errSetupDone
	}
	if err := checkCredentialsInput(user, pw); err != nil {
		return "", err
	}
	path := filepath.Join(a.dir, setupCodeFile)
	b, err := os.ReadFile(path)
	if err != nil {
		return "", errSetupCode
	}
	var rec setupCodeRecord
	if json.Unmarshal(b, &rec) != nil || rec.SHA256 == "" {
		return "", errSetupCode
	}
	exp, err := time.Parse(time.RFC3339, rec.ExpiresAt)
	if err != nil || !a.now().Before(exp) || rec.Failures >= setupMaxAttempts {
		_ = os.Remove(path)
		return "", errSetupCode
	}
	if subtle.ConstantTimeCompare([]byte(sha256Hex(normCode(code))), []byte(rec.SHA256)) != 1 {
		rec.Failures++
		if rec.Failures >= setupMaxAttempts {
			_ = os.Remove(path)
		} else {
			_ = writeJSON0600(path, rec)
		}
		return "", errSetupCode
	}
	adm, err := newAdminRecord(strings.TrimSpace(user), pw, a.now())
	if err != nil {
		return "", err
	}
	// admin.json first: a crash before the token is written leaves an
	// initialised directory whose token is created on the next start.
	if err := writeJSON0600(filepath.Join(a.dir, adminFile), adm); err != nil {
		return "", err
	}
	tok, err := LoadOrCreateToken(a.envToken, filepath.Join(a.dir, tokenFile))
	if err != nil {
		return "", err
	}
	_ = os.Remove(path)
	a.admin, a.token, a.legacy = adm, tok, false
	return tok, nil
}

// Login checks the administrator credentials from source remote (the
// request's RemoteAddr) and returns the bearer token. Failures lock out
// that source only (login_lockout.go).
func (a *Auth) Login(remote, user, pw string) (string, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.token == "" {
		return "", errSetupRequired
	}
	if a.admin == nil {
		return "", errors.New("还没有设置管理员密码；请用面板口令登录")
	}
	key := sourceKey(remote)
	if a.lockedOut(key) {
		return "", errLocked
	}
	if !a.admin.check(strings.TrimSpace(user), pw) {
		a.recordFailure(key)
		return "", errBadLogin
	}
	a.recordSuccess(key)
	return a.token, nil
}

// SetAdmin sets or changes the administrator (the caller is authenticated
// by the bearer token). Changing an existing password needs the current one.
func (a *Auth) SetAdmin(current, user, pw string) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.token == "" {
		return errSetupRequired
	}
	if err := checkCredentialsInput(user, pw); err != nil {
		return err
	}
	if a.admin != nil && !a.admin.check(a.admin.Username, current) {
		return errBadLogin
	}
	adm, err := newAdminRecord(strings.TrimSpace(user), pw, a.now())
	if err != nil {
		return err
	}
	if err := writeJSON0600(filepath.Join(a.dir, adminFile), adm); err != nil {
		return err
	}
	a.admin, a.legacy = adm, false
	return nil
}

func (a *Auth) status() map[string]any {
	a.mu.Lock()
	defer a.mu.Unlock()
	st := AuthReady
	if a.token == "" {
		st = AuthSetupRequired
	}
	return map[string]any{"state": st, "admin": a.admin != nil, "token_login": a.token != ""}
}

var (
	errSetupDone     = errors.New("面板已经初始化")
	errSetupCode     = errors.New("初始化码无效或已过期；在网关上重新运行 meridian setup-code")
	errSetupRequired = errors.New("面板还没有初始化")
	errBadLogin      = errors.New("用户名或密码不对")
	errLocked        = errors.New("失败次数过多，请一分钟后再试")
)

// lanSource reports whether a request comes from loopback, a private or
// link-local address (RFC 1918, ULA, fe80::/10) or the remote-access device
// pools. The setup endpoint refuses everything else, so a panel bound to a
// public address by mistake still cannot be claimed from the WAN.
func (s *Server) lanSource(r *http.Request) bool {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	ip, err := netip.ParseAddr(host)
	if err != nil {
		return false
	}
	ip = ip.Unmap()
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() {
		return true
	}
	if s.Store != nil {
		if t, ok, err := s.Store.Load(); err == nil && ok && t.RemoteAccess != nil {
			for _, p := range []string{t.RemoteAccess.IPv4Prefix, t.RemoteAccess.IPv6Prefix} {
				if pf, err := netip.ParsePrefix(p); err == nil && pf.Contains(ip) {
					return true
				}
			}
		}
	}
	return false
}

func (s *Server) registerSetup(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/setup/status", func(w http.ResponseWriter, r *http.Request) {
		if s.Auth == nil {
			writeJSON(w, http.StatusOK, map[string]any{"state": AuthReady, "admin": false, "token_login": true})
			return
		}
		writeJSON(w, http.StatusOK, s.Auth.status())
	})
	mux.HandleFunc("POST /api/setup", func(w http.ResponseWriter, r *http.Request) {
		if s.Auth == nil {
			writeErr(w, http.StatusConflict, errSetupDone)
			return
		}
		if !s.lanSource(r) {
			writeErr(w, http.StatusForbidden, errors.New("初始化只能从局域网或本机进行"))
			return
		}
		var body struct {
			Code     string `json:"code"`
			Username string `json:"username"`
			Password string `json:"password"`
		}
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8<<10)).Decode(&body); err != nil {
			writeErr(w, http.StatusBadRequest, err)
			return
		}
		tok, err := s.Auth.Setup(body.Code, body.Username, body.Password)
		switch {
		case errors.Is(err, errSetupDone):
			writeErr(w, http.StatusConflict, err)
		case errors.Is(err, errSetupCode):
			writeErr(w, http.StatusForbidden, err)
		case err != nil:
			writeErr(w, http.StatusBadRequest, err)
		default:
			writeJSON(w, http.StatusOK, map[string]string{"token": tok})
		}
	})
	mux.HandleFunc("POST /api/auth/login", func(w http.ResponseWriter, r *http.Request) {
		if s.Auth == nil {
			writeErr(w, http.StatusNotFound, errors.New("没有管理员账户"))
			return
		}
		var body struct {
			Username string `json:"username"`
			Password string `json:"password"`
		}
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8<<10)).Decode(&body); err != nil {
			writeErr(w, http.StatusBadRequest, err)
			return
		}
		tok, err := s.Auth.Login(r.RemoteAddr, body.Username, body.Password)
		switch {
		case errors.Is(err, errLocked):
			writeErr(w, http.StatusTooManyRequests, err)
		case errors.Is(err, errSetupRequired):
			writeJSON(w, http.StatusForbidden, map[string]string{"error": err.Error(), "code": AuthSetupRequired})
		case err != nil:
			writeErr(w, http.StatusUnauthorized, err)
		default:
			writeJSON(w, http.StatusOK, map[string]string{"token": tok})
		}
	})
	// Authenticated (withAuth): set or change the administrator.
	mux.HandleFunc("PUT /api/auth/admin", func(w http.ResponseWriter, r *http.Request) {
		if s.Auth == nil {
			writeErr(w, http.StatusNotFound, errors.New("没有管理员账户"))
			return
		}
		var body struct {
			Current  string `json:"current_password"`
			Username string `json:"username"`
			Password string `json:"password"`
		}
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8<<10)).Decode(&body); err != nil {
			writeErr(w, http.StatusBadRequest, err)
			return
		}
		if err := s.Auth.SetAdmin(body.Current, body.Username, body.Password); err != nil {
			code := http.StatusBadRequest
			if errors.Is(err, errBadLogin) {
				code = http.StatusForbidden
			}
			writeErr(w, code, err)
			return
		}
		writeJSON(w, http.StatusOK, s.Auth.status())
	})
}

// publicAPIPath: reachable without a token (and before setup).
func publicAPIPath(p string) bool {
	switch p {
	case "/api/health", "/api/setup/status", "/api/setup", "/api/auth/login":
		return true
	}
	return false
}
