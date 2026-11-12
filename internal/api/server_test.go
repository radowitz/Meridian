package api

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/radowitz/meridian/internal/model"
	"github.com/radowitz/meridian/internal/store"
)

func newTest(t *testing.T) *Server {
	t.Helper()
	dir := t.TempDir()
	st, err := store.Open(filepath.Join(dir, "meridian.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	return &Server{Store: st, DataDir: dir}
}

func TestHealthAndSeedAndRedact(t *testing.T) {
	s := newTest(t)
	rr := do(s, http.MethodGet, "/api/health", nil)
	if rr.Code != 200 || !strings.Contains(rr.Body.String(), "meridian") {
		t.Fatal(rr.Body.String())
	}
	rr = do(s, http.MethodGet, "/api/topology", nil)
	if rr.Code != 200 {
		t.Fatal(rr.Body.String())
	}
	var topo model.Topology
	if err := json.Unmarshal(rr.Body.Bytes(), &topo); err != nil {
		t.Fatal(err)
	}
	if len(topo.Nodes) < 5 || topo.Settings.ROSIPv4 != "192.168.100.1" {
		t.Fatalf("seed failed: %+v", topo.Settings)
	}
	topo.Nodes[0].PrivateKey = "super-secret-wireguard-key"
	raw, _ := json.Marshal(topo)
	req := httptest.NewRequest(http.MethodPut, "/api/topology?draft=1", bytes.NewReader(raw))
	rr = httptest.NewRecorder()
	s.Handler().ServeHTTP(rr, req)
	if rr.Code != 200 {
		t.Fatal(rr.Code, rr.Body.String())
	}
	if strings.Contains(rr.Body.String(), "super-secret-wireguard-key") {
		t.Fatal("private key leaked in the response")
	}
	rr = do(s, http.MethodGet, "/api/topology", nil)
	if strings.Contains(rr.Body.String(), "super-secret-wireguard-key") {
		t.Fatal("private key leaked on GET")
	}
	if !strings.Contains(rr.Body.String(), `"private_key":"***"`) && !strings.Contains(rr.Body.String(), `"private_key": "***"`) {
		t.Fatal("expected redacted marker")
	}
}

func TestValidateCompileApplyProvision(t *testing.T) {
	s := newTest(t)
	do(s, http.MethodGet, "/api/topology", nil)
	rr := do(s, http.MethodPost, "/api/validate", []byte(`{}`))
	if rr.Code != 200 || strings.Contains(rr.Body.String(), `"severity":"error"`) {
		t.Fatalf("example should validate: %s", rr.Body.String())
	}
	rr = do(s, http.MethodPost, "/api/diff", []byte(`{}`))
	if rr.Code != 200 || !strings.Contains(rr.Body.String(), "diff") {
		t.Fatal(rr.Body.String())
	}
	rr = do(s, http.MethodPost, "/api/apply", []byte(`{"dry_run":true}`))
	if rr.Code != 200 || !strings.Contains(rr.Body.String(), `"dry_run":true`) {
		t.Fatal(rr.Body.String())
	}
	rr = do(s, http.MethodPost, "/api/apply", []byte(`{"dry_run":false,"install":false}`))
	if rr.Code != 200 {
		t.Fatal(rr.Body.String())
	}
	rr = do(s, http.MethodPost, "/api/rollback", []byte(`{}`))
	if rr.Code == 200 {
		t.Fatal("rollback with no previous snapshot should fail")
	}
	rr = do(s, http.MethodPost, "/api/provision", []byte(`{"node_id":"ali","dry_run":true}`))
	if rr.Code != 200 || !strings.Contains(rr.Body.String(), "meridian-up.sh") {
		t.Fatal(rr.Body.String())
	}
	if strings.Contains(rr.Body.String(), "flush ruleset") {
		t.Fatal("provision script flushes nftables")
	}
	rr = do(s, http.MethodPost, "/api/provision", []byte(`{"node_id":"ix","dry_run":true}`))
	if rr.Code == 200 {
		t.Fatal("IX must not be provisioned over SSH")
	}
}

func TestRejectsIXBypassSave(t *testing.T) {
	s := newTest(t)
	do(s, http.MethodGet, "/api/topology", nil)
	tpo, _, _ := s.Store.Load()
	var links []model.Link
	for _, l := range tpo.Links {
		if l.ID == "ali-ix" || l.ID == "ix-hub" {
			continue
		}
		links = append(links, l)
	}
	tpo.Links = links
	raw, _ := json.Marshal(tpo)
	req := httptest.NewRequest(http.MethodPut, "/api/topology", bytes.NewReader(raw))
	rr := httptest.NewRecorder()
	s.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusUnprocessableEntity {
		t.Fatalf("code %d body %s", rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), "path_missing_ix") && !strings.Contains(rr.Body.String(), "path_not_found") {
		t.Fatal(rr.Body.String())
	}
}

func TestTokenRequired(t *testing.T) {
	s := newTest(t)
	s.Token = "test-token"
	rr := do(s, http.MethodGet, "/api/health", nil)
	if rr.Code != 200 {
		t.Fatalf("health should stay open: %d", rr.Code)
	}
	rr = do(s, http.MethodGet, "/api/topology", nil)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("missing token: %d %s", rr.Code, rr.Body.String())
	}
	req := httptest.NewRequest(http.MethodGet, "/api/topology", nil)
	req.Header.Set("Authorization", "Bearer test-token")
	rr = httptest.NewRecorder()
	s.Handler().ServeHTTP(rr, req)
	if rr.Code != 200 {
		t.Fatal(rr.Body.String())
	}
	dir := t.TempDir()
	tok, err := LoadOrCreateToken("", dir+"/panel.token")
	if err != nil || len(tok) < 32 {
		t.Fatal(err)
	}
	again, err := LoadOrCreateToken("", dir+"/panel.token")
	if err != nil || again != tok {
		t.Fatalf("token not stable: %q %q %v", tok, again, err)
	}
	if _, err := LoadOrCreateToken("bad\ntoken", dir+"/other"); err == nil {
		t.Fatal("newline token should be rejected")
	}
}

func TestPoolsUnlockAndLeakcheck(t *testing.T) {
	s := newTest(t)
	do(s, http.MethodGet, "/api/topology", nil)
	rr := do(s, http.MethodGet, "/api/pools", nil)
	if rr.Code != 200 || !strings.Contains(rr.Body.String(), `"id":"hk"`) || !strings.Contains(rr.Body.String(), "hk-ix") {
		t.Fatal(rr.Body.String())
	}
	rr = do(s, http.MethodPost, "/api/pools/health", []byte(`{"observations":[{"id":"hk-ix","up":false},{"id":"hk-2","up":true}]}`))
	if rr.Code != 200 || strings.Contains(rr.Body.String(), `"active":"hk-2"`) {
		t.Fatalf("one failure must not move the pool: %s", rr.Body.String())
	}
	for i := 0; i < 3; i++ {
		rr = do(s, http.MethodPost, "/api/pools/health", []byte(`{"observations":[{"id":"hk-ix","up":false},{"id":"hk-2","up":true}]}`))
	}
	if rr.Code != 200 || !strings.Contains(rr.Body.String(), `"active":"hk-2"`) {
		t.Fatalf("pool did not fail over: %s", rr.Body.String())
	}
	rr = do(s, http.MethodPost, "/api/unlock/report", []byte(`{"exit_id":"us","kind":"scheduled","raw":"Netflix: No\n","ai":"openai 000\n"}`))
	if rr.Code != 200 {
		t.Fatal(rr.Body.String())
	}
	if strings.Contains(rr.Body.String(), `"auto-openai":"jp"`) || strings.Contains(rr.Body.String(), `"active":"jp"`) {
		t.Fatal("unlock left the pool")
	}
	body := rr.Body.String()
	if !strings.Contains(body, "不在该服务的池里") && !strings.Contains(body, "auto-netflix") {
		t.Fatalf("netflix probe from US should be recorded as out of pool: %s", body)
	}
	rr = do(s, http.MethodPost, "/api/unlock/run", []byte(`{}`))
	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("missing probe command: %d %s", rr.Code, rr.Body.String())
	}
	rr = do(s, http.MethodGet, "/api/leakcheck", nil)
	if rr.Code != 200 || !strings.Contains(rr.Body.String(), "webrtc_host_gua") || !strings.Contains(rr.Body.String(), "known_limitation") {
		t.Fatal(rr.Body.String())
	}
}

func TestPhase23RequiresToken(t *testing.T) {
	s := newTest(t)
	s.Token = "test-token"
	calls := []struct {
		method, path, body string
	}{
		{http.MethodPost, "/api/unlock/report", `{"exit_id":"us","kind":"scheduled","ai":"openai 200"}`},
		{http.MethodPost, "/api/pools/health", `{"observations":[{"id":"hk-ix","up":false}]}`},
		{http.MethodPost, "/api/unlock/run", `{}`},
		{http.MethodGet, "/api/unlock", ""},
		{http.MethodGet, "/api/pools", ""},
		{http.MethodGet, "/api/leakcheck", ""},
	}
	for _, c := range calls {
		var body []byte
		if c.body != "" {
			body = []byte(c.body)
		}
		rr := do(s, c.method, c.path, body)
		if rr.Code != http.StatusUnauthorized {
			t.Fatalf("%s %s without token: %d %s", c.method, c.path, rr.Code, rr.Body.String())
		}
	}
}

func TestUnlockReportClockAndExec(t *testing.T) {
	s := newTest(t)
	do(s, http.MethodGet, "/api/topology", nil)
	fail := `{"exit_id":"us","kind":"scheduled","ai":"openai 000"}`
	for i := 0; i < 2; i++ {
		rr := do(s, http.MethodPost, "/api/unlock/report", []byte(fail))
		if rr.Code != 200 {
			t.Fatal(rr.Body.String())
		}
	}
	past := time.Now().UTC().Add(-2 * time.Hour).Format(time.RFC3339)
	older := time.Now().UTC().Add(-90 * time.Minute).Format(time.RFC3339)
	rr := do(s, http.MethodPost, "/api/unlock/report", []byte(`{"exit_id":"us-2","kind":"scheduled","at":"`+past+`","ai":"openai 200"}`))
	if rr.Code != 200 {
		t.Fatal(rr.Body.String())
	}
	rr = do(s, http.MethodPost, "/api/unlock/report", []byte(`{"exit_id":"us","kind":"scheduled","at":"`+older+`","ai":"openai 200"}`))
	if rr.Code != 200 {
		t.Fatal(rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), `"auto-openai":"us-2"`) {
		t.Fatalf("backdated timestamps skipped the return cooldown: %s", rr.Body.String())
	}
	rr = do(s, http.MethodPost, "/api/unlock/report", []byte(`{"exit_id":"hk-resi","kind":"scheduled","raw":"Netflix: Yes (Region: US)\n"}`))
	if rr.Code != 200 {
		t.Fatal(rr.Body.String())
	}
	body := rr.Body.String()
	if !strings.Contains(body, `"sched_fails":1`) {
		t.Fatalf("US Netflix catalog was treated as a Hong Kong success: %s", body)
	}
	if strings.Contains(body, `"auto-netflix":"jp"`) || strings.Contains(body, `"active":"jp"`) {
		t.Fatal(body)
	}

	t.Setenv("MERIDIAN_UNLOCK_EXEC", "/bin/echo hello")
	rr = do(s, http.MethodPost, "/api/unlock/run", []byte(`{}`))
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("shell-shaped exec: %d %s", rr.Code, rr.Body.String())
	}
	t.Setenv("MERIDIAN_UNLOCK_EXEC", "/bin/echo")
	rr = do(s, http.MethodPost, "/api/unlock/run", []byte(`{}`))
	if rr.Code != http.StatusBadGateway {
		t.Fatalf("echo should not be parsed as a probe result: %d %s", rr.Code, rr.Body.String())
	}
	dir := t.TempDir()
	script := filepath.Join(dir, "probe")
	if err := os.WriteFile(script, []byte("#!/bin/sh\nif [ -n \"$MERIDIAN_TOKEN\" ]; then exit 1; fi\nprintf '%s\\n' '{\"exit_id\":\"us\",\"kind\":\"manual\",\"ai\":\"openai 200\"}'\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("MERIDIAN_UNLOCK_EXEC", script)
	t.Setenv("MERIDIAN_TOKEN", "super-secret-panel-token")
	rr = do(s, http.MethodPost, "/api/unlock/run", []byte(`{}`))
	if rr.Code != 200 {
		t.Fatalf("script probe: %d %s", rr.Code, rr.Body.String())
	}
}

func TestBindGuard(t *testing.T) {
	if err := CheckBind("0.0.0.0:8787"); err == nil {
		t.Fatal("wildcard bind should be refused")
	}
	if err := CheckBind("192.168.100.88:8787"); err != nil {
		t.Fatal(err)
	}
	if err := CheckBind("127.0.0.1:8787"); err != nil {
		t.Fatal(err)
	}
}

func do(s *Server, method, path string, body []byte) *httptest.ResponseRecorder {
	var rdr io.Reader
	if body != nil {
		rdr = bytes.NewReader(body)
	}
	req := httptest.NewRequest(method, path, rdr)
	rr := httptest.NewRecorder()
	s.Handler().ServeHTTP(rr, req)
	return rr
}
