package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/radowitz/meridian/internal/compile"
	"github.com/radowitz/meridian/internal/model"
	"github.com/radowitz/meridian/internal/store"
	"github.com/radowitz/meridian/internal/validate"
)

func init() { scryptN = 1 << 10 } // fast hashes in tests

type authFix struct {
	t   *testing.T
	dir string
	st  *store.Store
	s   *Server
	h   http.Handler
}

func openAuthFix(t *testing.T, dir, envToken string) *authFix {
	t.Helper()
	st, err := store.Open(filepath.Join(dir, "meridian.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	_, has, err := st.Load()
	if err != nil {
		t.Fatal(err)
	}
	a, err := LoadAuth(dir, envToken, has)
	if err != nil {
		t.Fatal(err)
	}
	s := &Server{Store: st, DataDir: dir, Auth: a, Token: a.Token(), Artifacts: testArtifacts(t, filepath.Join(t.TempDir(), "artifacts"))}
	return &authFix{t: t, dir: dir, st: st, s: s, h: s.Handler()}
}

func (f *authFix) do(method, path, remote, token string, body any) (int, map[string]any) {
	f.t.Helper()
	var rd *bytes.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	} else {
		rd = bytes.NewReader(nil)
	}
	req := httptest.NewRequest(method, path, rd)
	req.RemoteAddr = remote
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	f.h.ServeHTTP(rec, req)
	out := map[string]any{}
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	return rec.Code, out
}

const lan = "10.0.0.20:50000"

// A fresh data directory: no default token or password, everything but
// setup refused (so nothing can be deployed), setup only from the LAN with
// the one-time code, the code dies after the attempt limit, and no
// author topology or network is loaded.
func TestFreshInstallRequiresSetup(t *testing.T) {
	dir := t.TempDir()
	f := openAuthFix(t, dir, "")
	if f.s.Auth.State() != AuthSetupRequired || f.s.Auth.Token() != "" {
		t.Fatal("fresh install must start uninitialised, without a token")
	}
	if _, err := os.Stat(filepath.Join(dir, "panel.token")); err == nil {
		t.Fatal("a fresh install must not create panel.token before setup")
	}
	if c, _ := f.do("GET", "/api/health", lan, "", nil); c != 200 {
		t.Fatalf("health %d", c)
	}
	for _, p := range []string{"/api/topology", "/api/meta"} {
		if c, b := f.do("GET", p, lan, "", nil); c != 403 || b["code"] != AuthSetupRequired {
			t.Fatalf("%s before setup: %d %v", p, c, b)
		}
	}
	for _, p := range []string{"/api/apply", "/api/compile", "/api/mesh/deploy"} {
		if c, _ := f.do("POST", p, lan, "anything", map[string]any{}); c != 403 {
			t.Fatalf("%s before setup: %d", p, c)
		}
	}
	if c, b := f.do("GET", "/api/setup/status", lan, "", nil); c != 200 || b["state"] != AuthSetupRequired {
		t.Fatalf("status %d %v", c, b)
	}
	cred := map[string]any{"username": "admin", "password": "correct horse battery"}
	// No code generated yet.
	cred["code"] = "AAAAA-BBBBB-CCCCC-DDDDD"
	if c, _ := f.do("POST", "/api/setup", lan, "", cred); c != 403 {
		t.Fatalf("setup without a code: %d", c)
	}
	code, err := NewSetupCode(dir)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(filepath.Join(dir, setupCodeFile))
	if strings.Contains(string(raw), normCode(code)) || strings.Contains(string(raw), code) {
		t.Fatal("setup code stored in plain text")
	}
	if fi, _ := os.Stat(filepath.Join(dir, setupCodeFile)); fi.Mode().Perm() != 0o600 {
		t.Fatalf("setup code file mode %v", fi.Mode().Perm())
	}
	// From the WAN: refused even with the right code.
	cred["code"] = code
	for _, wan := range []string{"203.0.113.9:1234", "[2001:db8::9]:1234"} {
		if c, _ := f.do("POST", "/api/setup", wan, "", cred); c != 403 {
			t.Fatalf("setup from %s: %d", wan, c)
		}
	}
	// Weak password refused without consuming the code.
	if c, _ := f.do("POST", "/api/setup", lan, "", map[string]any{"code": code, "username": "admin", "password": "short"}); c != 400 {
		t.Fatalf("weak password: %d", c)
	}
	// Guessing: the code dies after setupMaxAttempts failures.
	for i := 0; i < setupMaxAttempts; i++ {
		if c, _ := f.do("POST", "/api/setup", lan, "", map[string]any{"code": "WRONG", "username": "x", "password": "correct horse battery"}); c != 403 {
			t.Fatalf("wrong code %d: %d", i, c)
		}
	}
	if c, _ := f.do("POST", "/api/setup", lan, "", cred); c != 403 {
		t.Fatalf("code must be invalid after %d failures: %d", setupMaxAttempts, c)
	}
	// Recovery: a new code, then setup from the LAN.
	code, err = NewSetupCode(dir)
	if err != nil {
		t.Fatal(err)
	}
	cred["code"] = strings.ToLower(code)
	c, b := f.do("POST", "/api/setup", "[::1]:999", "", cred)
	tok, _ := b["token"].(string)
	if c != 200 || len(tok) < 32 {
		t.Fatalf("setup: %d %v", c, b)
	}
	if _, err := os.Stat(filepath.Join(dir, setupCodeFile)); !os.IsNotExist(err) {
		t.Fatal("setup code must be removed after setup")
	}
	adm, _ := os.ReadFile(filepath.Join(dir, adminFile))
	if strings.Contains(string(adm), "correct horse battery") {
		t.Fatal("password stored in plain text")
	}
	if c, _ := f.do("POST", "/api/setup", lan, "", cred); c != 409 {
		t.Fatalf("second setup: %d", c)
	}
	if _, err := NewSetupCode(dir); err == nil {
		t.Fatal("setup-code after initialisation must fail")
	}
	// The token works; no token is refused.
	if c, _ := f.do("GET", "/api/meta", lan, "", nil); c != 401 {
		t.Fatalf("meta without token: %d", c)
	}
	c, topo := f.do("GET", "/api/topology", lan, tok, nil)
	if c != 200 {
		t.Fatalf("topology: %d", c)
	}
	if nodes, _ := topo["nodes"].([]any); len(nodes) != 0 {
		t.Fatalf("fresh install loaded a topology with %d nodes", len(nodes))
	}
	tb, _ := json.Marshal(topo)
	for _, bad := range []string{"192.168.", "家宽", "阿里云"} {
		if strings.Contains(string(tb), bad) {
			t.Fatalf("fresh topology carries a built-in value %q: %s", bad, tb)
		}
	}
	if _, ok, _ := f.st.Load(); ok {
		t.Fatal("reading the fresh topology must not store one")
	}
	// Login with the administrator; wrong passwords lock out briefly.
	if c, b := f.do("POST", "/api/auth/login", lan, "", map[string]any{"username": "admin", "password": "correct horse battery"}); c != 200 || b["token"] != tok {
		t.Fatalf("login: %d %v", c, b)
	}
	for i := 0; i < loginMaxFailures; i++ {
		f.do("POST", "/api/auth/login", lan, "", map[string]any{"username": "admin", "password": "nope nope nope"})
	}
	if c, _ := f.do("POST", "/api/auth/login", lan, "", map[string]any{"username": "admin", "password": "correct horse battery"}); c != 429 {
		t.Fatalf("lockout: %d", c)
	}
	// Per source: another LAN client still logs in.
	if c, _ := f.do("POST", "/api/auth/login", "10.0.0.21:40000", "", map[string]any{"username": "admin", "password": "correct horse battery"}); c != 200 {
		t.Fatalf("other source locked out: %d", c)
	}
	if fi, err := os.Stat(filepath.Join(dir, lockoutFile)); err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("lockout file: %v %v", fi, err)
	}
	// A restart keeps the state, including the lockout.
	f.st.Close()
	g := openAuthFix(t, dir, "")
	if g.s.Auth.State() != AuthReady || g.s.Auth.Token() != tok {
		t.Fatal("restart lost the initialised state")
	}
	if c, _ := g.do("POST", "/api/auth/login", lan, "", map[string]any{"username": "admin", "password": "correct horse battery"}); c != 429 {
		t.Fatalf("restart cleared the lockout: %d", c)
	}
}

// The upgrade contract: a data directory from before the setup flow (a
// panel.token and the old-format topology fixture, no admin.json) stays
// usable with its token; adding an administrator is optional and never
// changes the token; the stored topology keeps its explicit LAN values
// and compiles with them (no built-in fallback appears).
func TestUpgradeKeepsTokenAndStoredTopology(t *testing.T) {
	dir := t.TempDir()
	const oldTok = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	if err := os.WriteFile(filepath.Join(dir, "panel.token"), []byte(oldTok+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join("testdata", "pre-redesign-topology.json"))
	if err != nil {
		t.Fatal(err)
	}
	st, err := store.Open(filepath.Join(dir, "meridian.db"))
	if err != nil {
		t.Fatal(err)
	}
	if err := st.Put("topology", string(raw)); err != nil {
		t.Fatal(err)
	}
	st.Close()

	f := openAuthFix(t, dir, "")
	if f.s.Auth.State() != AuthReady || f.s.Auth.Token() != oldTok {
		t.Fatalf("old deployment must stay ready with its token, got %q", f.s.Auth.State())
	}
	if c, b := f.do("GET", "/api/setup/status", lan, "", nil); c != 200 || b["state"] != AuthReady || b["admin"] != false {
		t.Fatalf("status %v", b)
	}
	if c, _ := f.do("POST", "/api/setup", lan, "", map[string]any{"code": "x", "username": "admin", "password": "correct horse battery"}); c != 409 {
		t.Fatalf("setup on an initialised deployment: %d", c)
	}
	c, topo := f.do("GET", "/api/topology", "203.0.113.9:1", oldTok, nil)
	if c != 200 {
		t.Fatalf("old token refused: %d", c)
	}
	if nodes, _ := topo["nodes"].([]any); len(nodes) == 0 {
		t.Fatal("stored topology not served")
	}
	// Optional administrator for the old deployment.
	if c, _ := f.do("PUT", "/api/auth/admin", lan, "", map[string]any{"username": "admin", "password": "correct horse battery"}); c != 401 {
		t.Fatalf("admin without token: %d", c)
	}
	if c, _ := f.do("PUT", "/api/auth/admin", lan, oldTok, map[string]any{"username": "admin", "password": "correct horse battery"}); c != 200 {
		t.Fatalf("set admin: %d", c)
	}
	if c, _ := f.do("PUT", "/api/auth/admin", lan, oldTok, map[string]any{"current_password": "wrong wrong wrong", "username": "admin", "password": "another long password"}); c != 403 {
		t.Fatalf("change admin with a wrong current password: %d", c)
	}
	if c, b := f.do("POST", "/api/auth/login", lan, "", map[string]any{"username": "admin", "password": "correct horse battery"}); c != 200 || b["token"] != oldTok {
		t.Fatalf("login after upgrade: %d %v", c, b)
	}
	f.st.Close()
	g := openAuthFix(t, dir, "")
	if g.s.Auth.Token() != oldTok {
		t.Fatal("token changed across restart")
	}
	if c, _ := g.do("GET", "/api/meta", lan, oldTok, nil); c != 200 {
		t.Fatalf("old token after admin set: %d", c)
	}

	// The stored topology keeps its explicit values; it binds where it did.
	stored, ok, err := g.st.Load()
	if err != nil || !ok {
		t.Fatal("stored topology lost")
	}
	if got := ResolveBind("", stored, true, "127.0.0.1:8787"); got != stored.Settings.PanelBind || got == "" {
		t.Fatalf("upgrade bind %q, stored %q", got, stored.Settings.PanelBind)
	}
	b, err := compile.Compile(stored)
	if err != nil {
		t.Fatal(err)
	}
	host := strings.SplitN(stored.Settings.GatewayLANIP, "/", 2)[0]
	var all strings.Builder
	for _, v := range b.Files {
		all.WriteString(v)
	}
	if !strings.Contains(all.String(), host) {
		t.Fatalf("compiled output lacks the stored gateway address %s", host)
	}
	for _, ph := range []string{model.UnsetLANPrefix, model.UnsetLANHost, model.UnsetRouterHost} {
		if p, err := netip.ParsePrefix(stored.Settings.GatewayLANIP); err == nil && p.Masked().String() == ph {
			// The synthetic fixture's LAN is the placeholder's own
			// documentation /24; its host and router still differ.
			continue
		}
		if regexp.MustCompile(`(^|[^0-9.])` + regexp.QuoteMeta(ph) + `([^0-9]|$)`).MatchString(all.String()) {
			t.Fatalf("stored topology compiled with placeholder %s", ph)
		}
	}
}

// MERIDIAN_TOKEN alone, or a stored topology without a token file (a
// deployment whose token file was lost), is an existing deployment too.
func TestUpgradeOtherLegacyShapes(t *testing.T) {
	dir := t.TempDir()
	f := openAuthFix(t, dir, "env-token-value")
	if f.s.Auth.State() != AuthReady || f.s.Auth.Token() != "env-token-value" {
		t.Fatal("MERIDIAN_TOKEN deployment locked out")
	}
	if c, _ := f.do("GET", "/api/meta", lan, "env-token-value", nil); c != 200 {
		t.Fatalf("env token: %d", c)
	}

	dir2 := t.TempDir()
	st, err := store.Open(filepath.Join(dir2, "meridian.db"))
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(filepath.Join("testdata", "pre-redesign-topology.json"))
	if err := st.Put("topology", string(raw)); err != nil {
		t.Fatal(err)
	}
	st.Close()
	g := openAuthFix(t, dir2, "")
	if g.s.Auth.State() != AuthReady || g.s.Auth.Token() == "" {
		t.Fatal("deployment with a stored topology must not need setup")
	}
	if b, _ := os.ReadFile(filepath.Join(dir2, "panel.token")); strings.TrimSpace(string(b)) != g.s.Auth.Token() {
		t.Fatal("token not persisted for the operator to read")
	}
}

func TestResolveBind(t *testing.T) {
	stored := model.Topology{Settings: model.Settings{PanelBind: "198.51.100.7:8787"}}
	cases := []struct {
		env    string
		t      model.Topology
		stored bool
		want   string
	}{
		{"10.1.2.3:9000", stored, true, "10.1.2.3:9000"},
		{"", stored, true, "198.51.100.7:8787"},
		{"", stored, false, "127.0.0.1:8787"},
		{"", model.Topology{Settings: model.Settings{PanelBind: "0.0.0.0:8787"}}, true, "127.0.0.1:8787"},
		{"", model.Topology{Settings: model.Settings{PanelBind: "gw.example:8787"}}, true, "127.0.0.1:8787"},
		{"", model.Topology{}, true, "127.0.0.1:8787"},
	}
	for _, c := range cases {
		if got := ResolveBind(c.env, c.t, c.stored, "127.0.0.1:8787"); got != c.want {
			t.Errorf("ResolveBind(%q, %q) = %q, want %q", c.env, c.t.Settings.PanelBind, got, c.want)
		}
	}
}

// The fresh-install topology carries no LAN, and validation asks for one
// instead of falling back to a built-in network.
func TestEmptyTopologyNeedsGatewayLAN(t *testing.T) {
	f := openAuthFix(t, t.TempDir(), "x")
	tp, err := f.s.topology()
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, is := range validate.Run(tp).Issues {
		if is.Code == "missing_gateway_lan" {
			found = true
		}
	}
	if !found {
		t.Fatal("empty topology must report missing_gateway_lan")
	}
}

func TestLoginLockoutBoundedAndExpiring(t *testing.T) {
	now := time.Date(2026, 11, 18, 0, 0, 0, 0, time.UTC)
	a := &Auth{dir: t.TempDir(), now: func() time.Time { return now }}
	a.loadLockouts()
	// IPv6 sources count per /64.
	if sourceKey("[2001:db8:1:2::5]:1") != sourceKey("[2001:db8:1:2::ffff]:2") || sourceKey("[2001:db8:1:3::5]:1") == sourceKey("[2001:db8:1:2::5]:1") {
		t.Fatal("IPv6 /64 keying")
	}
	if sourceKey("[::ffff:10.0.0.1]:1") != "10.0.0.1" {
		t.Fatal("mapped IPv4")
	}
	for i := 0; i < loginMaxFailures; i++ {
		a.recordFailure("10.0.0.1")
	}
	if !a.lockedOut("10.0.0.1") || a.lockedOut("10.0.0.2") {
		t.Fatal("lockout per source")
	}
	now = now.Add(loginLockout)
	if a.lockedOut("10.0.0.1") {
		t.Fatal("lockout does not expire")
	}
	for i := 0; i < loginMaxSources+50; i++ {
		now = now.Add(time.Second)
		a.recordFailure(fmt.Sprintf("10.1.%d.%d", i/256, i%256))
	}
	if len(a.lockouts) > loginMaxSources {
		t.Fatalf("table not bounded: %d", len(a.lockouts))
	}
	if fi, err := os.Stat(filepath.Join(a.dir, lockoutFile)); err != nil || fi.Size() > lockoutFileLimit {
		t.Fatalf("file: %v %v", fi, err)
	}
	now = now.Add(loginFailWindow + loginLockout)
	b := &Auth{dir: a.dir, now: func() time.Time { return now }}
	b.loadLockouts()
	if len(b.lockouts) != 0 {
		t.Fatalf("expired entries kept: %d", len(b.lockouts))
	}
}
