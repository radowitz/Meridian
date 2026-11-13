package api

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/radowitz/meridian/internal/compile"
	"github.com/radowitz/meridian/internal/hostexec"
	"github.com/radowitz/meridian/internal/mesh"
	"github.com/radowitz/meridian/internal/model"
	"github.com/radowitz/meridian/internal/probe"
	"github.com/radowitz/meridian/internal/store"
	"github.com/radowitz/meridian/internal/unlock"
)

func newTest(t *testing.T) *Server {
	t.Helper()
	dir := t.TempDir()
	st, err := store.Open(filepath.Join(dir, "meridian.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	return &Server{Store: st, DataDir: dir, Artifacts: testArtifacts(t, filepath.Join(dir, "artifacts"))}
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
	for _, want := range []string{
		`"id":"dnsleak_client","status":"pending_signoff","scope":"human"`,
		`"id":"ros_ula_blackhole","status":"pending_signoff","scope":"human"`,
		`"id":"netns_reload_no_leak","status":"unknown","scope":"integration"`,
		`"id":"lists_update_runtime","status":"unknown","scope":"integration"`,
		`"id":"real_exit_switch","status":"pending_signoff","scope":"human"`,
		`"id":"unlock_platform_verdicts","status":"pending_signoff","scope":"human"`,
		`"id":"group_marks_routed","status":"pass","scope":"automated"`,
	} {
		if !strings.Contains(rr.Body.String(), want) {
			t.Fatalf("leakcheck must not report unexecuted evidence as passed; missing %s", want)
		}
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
		{http.MethodGet, "/api/unlock/jobs", ""},
		{http.MethodPost, "/api/unlock/jobs/job-x/cancel", ""},
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

func TestUnlockReportClock(t *testing.T) {
	s := newTest(t)
	do(s, http.MethodGet, "/api/topology", nil)
	fail := `{"exit_id":"us","kind":"scheduled","services":{"openai":false}}`
	for i := 0; i < 2; i++ {
		rr := do(s, http.MethodPost, "/api/unlock/report", []byte(fail))
		if rr.Code != 200 {
			t.Fatal(rr.Body.String())
		}
	}
	past := time.Now().UTC().Add(-2 * time.Hour).Format(time.RFC3339)
	older := time.Now().UTC().Add(-90 * time.Minute).Format(time.RFC3339)
	rr := do(s, http.MethodPost, "/api/unlock/report", []byte(`{"exit_id":"us-2","kind":"scheduled","at":"`+past+`","services":{"openai":true}}`))
	if rr.Code != 200 {
		t.Fatal(rr.Body.String())
	}
	rr = do(s, http.MethodPost, "/api/unlock/report", []byte(`{"exit_id":"us","kind":"scheduled","at":"`+older+`","services":{"openai":true}}`))
	if rr.Code != 200 {
		t.Fatal(rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), `"auto-openai":"us-2"`) {
		t.Fatalf("backdated timestamps skipped the return cooldown: %s", rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), `"rejected":"stale"`) {
		t.Fatalf("a report older than the validity window must be rejected as stale: %s", rr.Body.String())
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

	// MERIDIAN_UNLOCK_EXEC is no longer read: without a host agent the
	// panel cannot probe, whatever that variable says.
	t.Setenv("MERIDIAN_UNLOCK_EXEC", "/bin/echo")
	rr = do(s, http.MethodPost, "/api/unlock/run", []byte(`{}`))
	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("unlock run without a host agent: %d %s", rr.Code, rr.Body.String())
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

func installTest(t *testing.T) (*Server, string, *int) {
	t.Helper()
	s := newTest(t)
	s.HostRoot = t.TempDir()
	n := 0
	s.Activate = func() error { n++; return nil }
	withPeerKeys(t, s)
	return s, s.HostRoot, &n
}

// withPeerKeys gives every node except the gateway a well-formed public key
// (a fixed test value, not a real key), as after its own key generation. An
// install refuses peers without one (TestApplyInstallRefusesMissingPeerKeys).
func withPeerKeys(t *testing.T, s *Server) {
	t.Helper()
	do(s, http.MethodGet, "/api/topology", nil)
	topo, ok, err := s.Store.Load()
	if err != nil || !ok {
		t.Fatalf("load: %v %v", ok, err)
	}
	for i := range topo.Nodes {
		if topo.Nodes[i].ID != localNodeID {
			raw := make([]byte, 32)
			for j := range raw {
				raw[j] = byte(i + 1)
			}
			topo.Nodes[i].PublicKey = base64.StdEncoding.EncodeToString(raw)
		}
	}
	if err := s.Store.Save(topo); err != nil {
		t.Fatal(err)
	}
}

// A peer without a usable public key is refused with 422 before the key is
// generated, any host file is written or a snapshot moves, naming the peer
// nodes. Compile and dry runs keep working for such a topology.
func TestApplyInstallRefusesMissingPeerKeys(t *testing.T) {
	s := newTest(t)
	s.HostRoot = t.TempDir()
	activated := 0
	s.Activate = func() error { activated++; return nil }
	withPeerKeys(t, s)
	topo, _, _ := s.Store.Load()
	for i := range topo.Nodes {
		switch topo.Nodes[i].ID {
		case "ali":
			topo.Nodes[i].PublicKey = ""
		case "hk-hub":
			topo.Nodes[i].PublicKey = "not-a-key"
		}
	}
	if err := s.Store.Save(topo); err != nil {
		t.Fatal(err)
	}
	rr := do(s, http.MethodPost, "/api/apply", []byte(`{"install":true}`))
	if rr.Code != http.StatusUnprocessableEntity {
		t.Fatal(rr.Code, rr.Body.String())
	}
	body := rr.Body.String()
	for _, peer := range []string{"ali", "hk-hub", "peer_key_problems"} {
		if !strings.Contains(body, peer) {
			t.Fatalf("refusal does not name %s: %s", peer, body)
		}
	}
	if entries, _ := os.ReadDir(s.HostRoot); len(entries) != 0 {
		t.Fatal("host written although peer keys were missing")
	}
	if activated != 0 {
		t.Fatal("activate ran")
	}
	for _, sub := range []string{"applied", "previous", "host"} {
		if _, err := os.Stat(filepath.Join(s.DataDir, sub)); err == nil {
			t.Fatalf("%s written although peer keys were missing", sub)
		}
	}
	if gw := storedNode(t, s, localNodeID); gw.PrivateKey != "" {
		t.Fatal("gateway key generated before the refusal")
	}
	// Preview paths still work.
	if rr := do(s, http.MethodPost, "/api/compile", []byte(`{}`)); rr.Code != 200 {
		t.Fatal("compile refused an incomplete topology", rr.Code)
	}
	if rr := do(s, http.MethodPost, "/api/apply", []byte(`{"dry_run":true}`)); rr.Code != 200 {
		t.Fatal("dry run refused an incomplete topology", rr.Code, rr.Body.String())
	}
	if rr := do(s, http.MethodPost, "/api/diff", []byte(`{}`)); rr.Code != 200 {
		t.Fatal("diff refused an incomplete topology", rr.Code)
	}
}

func storedNode(t *testing.T, s *Server, id string) model.Node {
	t.Helper()
	topo, ok, err := s.Store.Load()
	if err != nil || !ok {
		t.Fatalf("load: %v %v", ok, err)
	}
	n, found := topo.NodeByID(id)
	if !found {
		t.Fatalf("node %s missing", id)
	}
	return n
}

func hostWG(t *testing.T, root string) []string {
	t.Helper()
	matches, _ := filepath.Glob(filepath.Join(root, "etc", "wireguard", "*.conf"))
	if len(matches) == 0 {
		t.Fatal("no WireGuard configs installed")
	}
	var out []string
	for _, m := range matches {
		info, err := os.Stat(m)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != 0o600 {
			t.Fatalf("%s mode %v", m, info.Mode().Perm())
		}
		b, _ := os.ReadFile(m)
		out = append(out, string(b))
	}
	return out
}

func TestApplyInstallInjectsStoredKey(t *testing.T) {
	s, host, activated := installTest(t)
	do(s, http.MethodGet, "/api/topology", nil)

	// First install generates and stores the gateway key.
	rr := do(s, http.MethodPost, "/api/apply", []byte(`{"install":true}`))
	if rr.Code != 200 {
		t.Fatal(rr.Code, rr.Body.String())
	}
	gw := storedNode(t, s, "gw")
	if gw.PrivateKey == "" || gw.PublicKey == "" {
		t.Fatal("first install did not store a key pair")
	}
	key := gw.PrivateKey
	if strings.Contains(rr.Body.String(), key) {
		t.Fatal("apply response leaked the key")
	}
	for _, body := range hostWG(t, host) {
		if !strings.Contains(body, "PrivateKey = "+key+"\n") || strings.Contains(body, "__MERIDIAN_PRIVATE_KEY__") {
			t.Fatal("installed config was not injected")
		}
	}
	if *activated != 1 {
		t.Fatalf("activate ran %d times", *activated)
	}
	// Peers of the gateway now carry its public key.
	rr = do(s, http.MethodPost, "/api/compile", []byte(`{}`))
	if rr.Code != 200 || !strings.Contains(rr.Body.String(), gw.PublicKey) {
		t.Fatal("compiled peers do not carry the generated public key")
	}
	// Compile, diff, topology and snapshots stay redacted.
	for _, path := range []string{"/api/compile", "/api/diff"} {
		rr = do(s, http.MethodPost, path, []byte(`{}`))
		if strings.Contains(rr.Body.String(), key) {
			t.Fatalf("%s leaked the key", path)
		}
	}
	if !strings.Contains(do(s, http.MethodPost, "/api/compile", []byte(`{}`)).Body.String(), "__MERIDIAN_PRIVATE_KEY__") {
		t.Fatal("compile preview must keep the placeholder")
	}
	if strings.Contains(do(s, http.MethodGet, "/api/topology", nil).Body.String(), key) {
		t.Fatal("topology leaked the key")
	}
	for _, sub := range []string{"applied", "previous"} {
		_ = filepath.Walk(filepath.Join(s.DataDir, sub), func(p string, info os.FileInfo, err error) error {
			if err == nil && !info.IsDir() {
				if b, _ := os.ReadFile(p); strings.Contains(string(b), key) {
					t.Errorf("snapshot %s holds the key", p)
				}
			}
			return nil
		})
	}

	// Second install reuses the stored key.
	rr = do(s, http.MethodPost, "/api/apply", []byte(`{"install":true}`))
	if rr.Code != 200 {
		t.Fatal(rr.Code, rr.Body.String())
	}
	if again := storedNode(t, s, "gw"); again.PrivateKey != key || again.PublicKey != gw.PublicKey {
		t.Fatal("second install replaced the stored key")
	}
	for _, body := range hostWG(t, host) {
		if !strings.Contains(body, "PrivateKey = "+key+"\n") {
			t.Fatal("reuse lost the key")
		}
	}
	// Runtime rollback injects the same key.
	rr = do(s, http.MethodPost, "/api/rollback", []byte(`{"install":true}`))
	if rr.Code != 200 || strings.Contains(rr.Body.String(), key) {
		t.Fatal(rr.Code, rr.Body.String())
	}
	for _, body := range hostWG(t, host) {
		if !strings.Contains(body, "PrivateKey = "+key+"\n") {
			t.Fatal("rollback lost the key")
		}
	}
}

func TestApplyInstallRefusesPublicOnlyGateway(t *testing.T) {
	s, host, activated := installTest(t)
	do(s, http.MethodGet, "/api/topology", nil)
	topo, _, _ := s.Store.Load()
	for i := range topo.Nodes {
		if topo.Nodes[i].ID == "gw" {
			topo.Nodes[i].PublicKey = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
		}
	}
	if err := s.Store.Save(topo); err != nil {
		t.Fatal(err)
	}
	rr := do(s, http.MethodPost, "/api/apply", []byte(`{"install":true}`))
	if rr.Code != http.StatusConflict {
		t.Fatal(rr.Code, rr.Body.String())
	}
	if entries, _ := os.ReadDir(host); len(entries) != 0 {
		t.Fatal("host written although the key was missing")
	}
	if *activated != 0 {
		t.Fatal("activate ran")
	}
	if _, err := os.Stat(filepath.Join(s.DataDir, "applied")); err == nil {
		t.Fatal("snapshot written although the key was missing")
	}
}

// Provisioning runs only through the node's managed server: a node
// without one (or with an untrusted one) is refused before any key is
// generated, and a preview never needs a server.
func TestProvisionKeyPaths(t *testing.T) {
	s := newTest(t)
	do(s, http.MethodGet, "/api/topology", nil)
	rr := do(s, http.MethodPost, "/api/provision", []byte(`{"node_id":"tw","generate_keys":false}`))
	if rr.Code != http.StatusConflict || !strings.Contains(rr.Body.String(), `"code":"no_server"`) {
		t.Fatal(rr.Code, rr.Body.String())
	}
	rr = do(s, http.MethodPost, "/api/provision", []byte(`{"node_id":"tw","generate_keys":true}`))
	if rr.Code != http.StatusConflict {
		t.Fatal(rr.Code, rr.Body.String())
	}
	if tw := storedNode(t, s, "tw"); tw.PrivateKey != "" {
		t.Fatal("a refused provision generated a key")
	}
	// A preview needs no server and carries the placeholder.
	rr = do(s, http.MethodPost, "/api/provision", []byte(`{"node_id":"tw","dry_run":true}`))
	if rr.Code != 200 || !strings.Contains(rr.Body.String(), "__MERIDIAN_PRIVATE_KEY__") || !strings.Contains(rr.Body.String(), "refusing to overwrite") {
		t.Fatal(rr.Code, rr.Body.String())
	}
	// The old request fields are refused, not ignored.
	for _, f := range []string{`"ssh_host":"192.0.2.1"`, `"ssh_port":22`, `"ssh_user":"root"`, `"private_key_pem":"junk"`, `"trust_new_host":true`} {
		rr = do(s, http.MethodPost, "/api/provision", []byte(`{"node_id":"tw","dry_run":true,`+f+`}`))
		if rr.Code != http.StatusBadRequest || !strings.Contains(rr.Body.String(), `"code":"field_removed"`) {
			t.Fatal(f, rr.Code, rr.Body.String())
		}
	}
}

// The panel's rollback used to send {} and only swap snapshots while the
// host kept running the newer config. On an installed host that is now
// refused unless the caller asks for runtime rollback or explicitly for a
// snapshot-only swap.
func TestRollbackModeIsExplicitAfterInstall(t *testing.T) {
	s, host, _ := installTest(t)
	do(s, http.MethodGet, "/api/topology", nil)
	for i := 0; i < 2; i++ {
		if rr := do(s, http.MethodPost, "/api/apply", []byte(`{"install":true}`)); rr.Code != 200 {
			t.Fatal(rr.Code, rr.Body.String())
		}
	}
	rr := do(s, http.MethodPost, "/api/rollback", []byte(`{}`))
	if rr.Code != http.StatusConflict || !strings.Contains(rr.Body.String(), "install=true") {
		t.Fatal(rr.Code, rr.Body.String())
	}
	if rr := do(s, http.MethodPost, "/api/rollback", []byte(`{"install":true,"snapshot_only":true}`)); rr.Code != http.StatusBadRequest {
		t.Fatal(rr.Code, rr.Body.String())
	}
	rr = do(s, http.MethodPost, "/api/rollback", []byte(`{"install":true}`))
	if rr.Code != 200 || !strings.Contains(rr.Body.String(), `"mode":"runtime"`) || !strings.Contains(rr.Body.String(), `"committed":true`) {
		t.Fatal(rr.Code, rr.Body.String())
	}
	if len(hostWG(t, host)) == 0 {
		t.Fatal("runtime rollback removed the configs")
	}
	rr = do(s, http.MethodPost, "/api/rollback", []byte(`{"snapshot_only":true}`))
	if rr.Code != 200 || !strings.Contains(rr.Body.String(), `"mode":"snapshot"`) {
		t.Fatal(rr.Code, rr.Body.String())
	}
	rr = do(s, http.MethodGet, "/api/host", nil)
	if rr.Code != 200 || !strings.Contains(rr.Body.String(), `"version":`) || !strings.Contains(rr.Body.String(), `"pending":null`) {
		t.Fatal(rr.Code, rr.Body.String())
	}
}

// Without a host execution boundary an install to the real root fails
// explicitly (503) before any snapshot or host file is written.
func TestApplyInstallWithoutHostExecFails(t *testing.T) {
	s := newTest(t) // HostRoot "/" and no Host: the production misconfiguration
	withPeerKeys(t, s)
	rr := do(s, http.MethodPost, "/api/apply", []byte(`{"install":true}`))
	if rr.Code != http.StatusServiceUnavailable || !strings.Contains(rr.Body.String(), "宿主执行能力") {
		t.Fatal(rr.Code, rr.Body.String())
	}
	if _, err := os.Stat(filepath.Join(s.DataDir, "applied")); err == nil {
		t.Fatal("snapshot written without host exec")
	}
	if rr := do(s, http.MethodGet, "/api/host", nil); !strings.Contains(rr.Body.String(), `"ok":false`) {
		t.Fatal(rr.Body.String())
	}
}

// A failed activation is reported with the transaction report and the
// compensation outcome, never as success.
func TestApplyInstallFailureReportsCompensation(t *testing.T) {
	s, host, _ := installTest(t)
	s.Activate = func() error { return errors.New("meridian-systemd-missing: cannot start meridian-failover.service") }
	do(s, http.MethodGet, "/api/topology", nil)
	rr := do(s, http.MethodPost, "/api/apply", []byte(`{"install":true}`))
	if rr.Code != http.StatusInternalServerError || !strings.Contains(rr.Body.String(), `"compensated":true`) ||
		!strings.Contains(rr.Body.String(), "meridian-systemd-missing") {
		t.Fatal(rr.Code, rr.Body.String())
	}
	if m, _ := filepath.Glob(filepath.Join(host, "etc", "wireguard", "*.conf")); len(m) != 0 {
		t.Fatal("failed first install left configs")
	}
	if rr := do(s, http.MethodPost, "/api/host/recover", nil); rr.Code != 200 {
		t.Fatal(rr.Code, rr.Body.String())
	}
}

func zeroTime(v any) bool { return v == nil || v == "0001-01-01T00:00:00Z" }

func unlockState(t *testing.T, s *Server, id string) map[string]any {
	t.Helper()
	rr := do(s, http.MethodGet, "/api/unlock", nil)
	var v struct {
		States map[string]map[string]any `json:"states"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &v); err != nil {
		t.Fatal(err)
	}
	return v.States[id]
}

// Review 5b01903 P2 through the API: once demoted, a late-delivered success
// observed before a newer failure is rejected, and a failure of the
// preferred always clears the recovery start.
func TestUnlockReportOrderingAndFailureBlocksReturn(t *testing.T) {
	s := newTest(t)
	do(s, http.MethodGet, "/api/topology", nil)
	post := func(exit, at, ai string) string {
		body := `{"exit_id":"` + exit + `","kind":"scheduled","services":{"openai":` + fmt.Sprint(ai == "openai 200") + `}`
		if at != "" {
			body += `,"at":"` + at + `"`
		}
		rr := do(s, http.MethodPost, "/api/unlock/report", []byte(body+"}"))
		if rr.Code != 200 {
			t.Fatalf("%d %s", rr.Code, rr.Body.String())
		}
		return rr.Body.String()
	}
	now := time.Now().UTC()
	ts := func(d time.Duration) string { return now.Add(d).Format(time.RFC3339) }
	post("us-2", ts(-50*time.Minute), "openai 200")
	post("us", ts(-45*time.Minute), "openai 000")
	post("us", ts(-40*time.Minute), "openai 000")
	if st := unlockState(t, s, "auto-openai"); st["active"] != "us-2" || st["demoted"] != true {
		t.Fatalf("did not demote: %v", st)
	}
	post("us", ts(-30*time.Minute), "openai 200")
	if st := unlockState(t, s, "auto-openai"); zeroTime(st["preferred_ok_at"]) {
		t.Fatalf("success should start the recovery streak: %v", st)
	}
	post("us", ts(-5*time.Minute), "openai 000")
	if st := unlockState(t, s, "auto-openai"); !zeroTime(st["preferred_ok_at"]) {
		t.Fatalf("failure did not clear the recovery start: %v", st)
	}
	body := post("us", ts(-10*time.Minute), "openai 200")
	if !strings.Contains(body, `"rejected":"out_of_order"`) {
		t.Fatalf("late success was admitted: %s", body)
	}
	if st := unlockState(t, s, "auto-openai"); st["active"] != "us-2" || !zeroTime(st["preferred_ok_at"]) {
		t.Fatalf("late success changed the state: %v", st)
	}
	if body := post("us", ts(time.Hour), "openai 200"); !strings.Contains(body, `"rejected":"future"`) {
		t.Fatalf("future report admitted: %s", body)
	}
	rr := do(s, http.MethodPost, "/api/unlock/report", []byte(`{"exit_id":"us","kind":"scheduled","family":"ipx","ai":"openai 200"}`))
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("bad family accepted: %d", rr.Code)
	}
}

// Concurrent deliveries are serialised by the server lock; whatever the
// arrival order, the newest observation decides.
func TestUnlockReportConcurrentNewestWins(t *testing.T) {
	s := newTest(t)
	do(s, http.MethodGet, "/api/topology", nil)
	now := time.Now().UTC()
	var wg sync.WaitGroup
	for i := 0; i < 12; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			code := "200"
			if i == 11 {
				code = "000" // the newest observation is a failure
			}
			at := now.Add(time.Duration(i-20) * time.Minute).Format(time.RFC3339)
			rr := do(s, http.MethodPost, "/api/unlock/report", []byte(`{"exit_id":"us","kind":"manual","family":"ipv4","at":"`+at+`","services":{"openai":`+fmt.Sprint(code == "200")+`}}`))
			if rr.Code != 200 {
				t.Errorf("%d %s", rr.Code, rr.Body.String())
			}
		}(i)
	}
	wg.Wait()
	snap := s.loadUnlock()
	rec, ok := snap.Latest["auto-openai|us|ipv4"]
	want, _ := time.Parse(time.RFC3339, now.Add(-9*time.Minute).Format(time.RFC3339))
	if !ok || rec.OK || !rec.ObservedAt.Equal(want) {
		t.Fatalf("latest is not the newest observation: %+v", rec)
	}
	if st := snap.Services["auto-openai"]; st.Known["us"] {
		t.Fatalf("an older success overwrote the newest failure: %+v", st)
	}
}

// ---- Mesh panel deployment ------------------------------------------------

// memCF is an in-memory mesh.Cloudflare (no network).
type memCF struct {
	mu        sync.Mutex
	nodes     map[string]mesh.CFNode
	routes    map[string]mesh.CFRoute
	seq       int
	nodeToken string
	failRoute bool
}

func (m *memCF) id() string {
	m.seq++
	return fmt.Sprintf("00000000-0000-4000-8000-%012d", m.seq)
}
func (m *memCF) CreateNode(_ context.Context, name string) (mesh.CFNode, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	n := mesh.CFNode{ID: m.id(), Name: name, Status: "healthy"}
	m.nodes[n.ID] = n
	return n, nil
}
func (m *memCF) GetNode(_ context.Context, id string) (mesh.CFNode, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	n, ok := m.nodes[id]
	if !ok {
		return n, mesh.ErrNotFound
	}
	return n, nil
}
func (m *memCF) ListNodes(context.Context) ([]mesh.CFNode, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []mesh.CFNode
	for _, n := range m.nodes {
		out = append(out, n)
	}
	return out, nil
}
func (m *memCF) DeleteNode(_ context.Context, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.nodes, id)
	return nil
}
func (m *memCF) NodeToken(context.Context, string) (string, error) { return m.nodeToken, nil }
func (m *memCF) CreateRoute(_ context.Context, network, tunnel, comment string) (mesh.CFRoute, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.failRoute {
		return mesh.CFRoute{}, errors.New("route refused")
	}
	r := mesh.CFRoute{ID: m.id(), Network: network, TunnelID: tunnel, Comment: comment}
	m.routes[r.ID] = r
	return r, nil
}
func (m *memCF) ListRoutes(_ context.Context, tunnel string) ([]mesh.CFRoute, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []mesh.CFRoute
	for _, r := range m.routes {
		if r.TunnelID == tunnel {
			out = append(out, r)
		}
	}
	return out, nil
}
func (m *memCF) DeleteRoute(_ context.Context, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.routes, id)
	return nil
}

// okRemote answers like healthy hosts; each presents host key fpFor(<id>)
// (or keys[<id>]) and it records the target of every call.
type okRemote struct {
	calls   []string
	targets []mesh.NodeTarget
	keys    map[string]string
}

func (r *okRemote) Exec(_ context.Context, n mesh.NodeTarget, act mesh.Action, _ string) (string, string, error) {
	key := fpFor(n.ID)
	if r.keys[n.ID] != "" {
		key = r.keys[n.ID]
	}
	if n.HostKey != "" && n.HostKey != key {
		return "", "", errors.New("host key mismatch")
	}
	r.calls = append(r.calls, string(act)+"/"+n.ID)
	r.targets = append(r.targets, n)
	switch act {
	case mesh.ActPreflight:
		return "MESH_PREFLIGHT_OK\n", key, nil
	case mesh.ActInstall:
		return "MESH_INSTALL_OK\n", key, nil
	case mesh.ActHealth:
		return "MESH_HEALTH_OK\n", key, nil
	case mesh.ActRefresh:
		return "MESH_REFRESH_OK\n", key, nil
	default:
		return "MESH_RESTORE_OK\n", key, nil
	}
}

// ---- panel-run unlock probes -----------------------------------------------

// fakeProber stands in for meridian-host's /v1/probe. answer decides each
// service's category; nothing leaves the test.
type fakeProber struct {
	mu       sync.Mutex
	reqs     []hostexec.ProbeRequest
	answer   func(req hostexec.ProbeRequest, svc string) probe.Category
	egressOK func(req hostexec.ProbeRequest) bool
	block    bool
	delay    time.Duration
	inflight int
	maxIn    int
}

func (f *fakeProber) Probe(ctx context.Context, req hostexec.ProbeRequest) (probe.Report, error) {
	if err := hostexec.ValidateProbe(req); err != nil {
		return probe.Report{}, err
	}
	f.mu.Lock()
	f.reqs = append(f.reqs, req)
	f.inflight++
	if f.inflight > f.maxIn {
		f.maxIn = f.inflight
	}
	block, delay := f.block, f.delay
	f.mu.Unlock()
	defer func() { f.mu.Lock(); f.inflight--; f.mu.Unlock() }()
	if block {
		<-ctx.Done()
		return probe.Report{}, ctx.Err()
	}
	if delay > 0 {
		select {
		case <-time.After(delay):
		case <-ctx.Done():
			return probe.Report{}, ctx.Err()
		}
	}
	fam, _ := unlock.ParseFamily(req.Family)
	now := time.Now().UTC()
	rep := probe.Report{ExitID: req.ExitID, Family: fam, StartedAt: now, FinishedAt: now,
		Egress: probe.Egress{Confirmed: true, IP: "203.0.113.99", Region: req.Region, Interface: "m00", Basis: "region", Evidence: "fake egress " + req.Region}}
	if f.egressOK != nil && !f.egressOK(req) {
		rep.Egress = probe.Egress{Error: "fake: egress CN"}
	}
	for _, svc := range req.Services {
		// Default: what a healthy adapter of that capability reports.
		cat := probe.CatUnlocked
		if a, _ := probe.Lookup(svc); a.Capability == probe.CapReachability {
			cat = probe.CatNetworkOK
		}
		if f.answer != nil {
			cat = f.answer(req, svc)
		}
		r := probe.Result{Service: svc, Family: fam, StartedAt: now, FinishedAt: now.Add(time.Millisecond), Category: cat, Evidence: "fixture " + string(cat)}
		if cat == probe.CatUnlocked || cat == probe.CatNotUnlocked {
			r.Region = req.Region
		}
		if cat == probe.CatFailed {
			r.Error = "fixture failure"
		}
		rep.Results = append(rep.Results, r)
	}
	return rep, nil
}

func (f *fakeProber) requests() []hostexec.ProbeRequest {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]hostexec.ProbeRequest(nil), f.reqs...)
}

type jobsView struct {
	Jobs    []probeJob `json:"jobs"`
	Running string     `json:"running"`
	Catalog []struct {
		Service string `json:"service"`
	} `json:"catalog"`
}

func getJobs(t *testing.T, s *Server) jobsView {
	t.Helper()
	rr := do(s, http.MethodGet, "/api/unlock/jobs", nil)
	if rr.Code != 200 {
		t.Fatal(rr.Body.String())
	}
	var v jobsView
	if err := json.Unmarshal(rr.Body.Bytes(), &v); err != nil {
		t.Fatal(err)
	}
	return v
}

func runJob(t *testing.T, s *Server, body string) probeJob {
	t.Helper()
	rr := do(s, http.MethodPost, "/api/unlock/run", []byte(body))
	if rr.Code != http.StatusAccepted {
		t.Fatalf("run: %d %s", rr.Code, rr.Body.String())
	}
	if !s.waitProbeJob(10 * time.Second) {
		t.Fatal("job did not finish")
	}
	return getJobs(t, s).Jobs[0]
}

func probeServer(t *testing.T, f *fakeProber) *Server {
	s := newTest(t)
	s.Prober = f
	do(s, http.MethodGet, "/api/topology", nil)
	return s
}

func unlockView(t *testing.T, s *Server) (map[string]unlock.State, []unlock.HistoryEntry, map[string]string) {
	t.Helper()
	rr := do(s, http.MethodGet, "/api/unlock", nil)
	var v struct {
		States    map[string]unlock.State `json:"states"`
		History   []unlock.HistoryEntry   `json:"history"`
		Decisions map[string]string       `json:"decisions"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &v); err != nil {
		t.Fatal(err)
	}
	return v.States, v.History, v.Decisions
}

func TestPanelProbeManualRun(t *testing.T) {
	f := &fakeProber{answer: func(req hostexec.ProbeRequest, svc string) probe.Category {
		if req.ExitID == "hk-resi" {
			return probe.CatUnlocked
		}
		return probe.CatNotUnlocked
	}}
	s := probeServer(t, f)
	job := runJob(t, s, `{"services":["auto-netflix"]}`)
	if job.Kind != unlock.KindManual || job.State != jobDone || job.FinishedAt == nil {
		t.Fatalf("%+v", job)
	}
	// hk-resi and hk-resi-2, each over IPv4 and IPv6.
	if len(job.Items) != 4 {
		t.Fatalf("items: %+v", job.Items)
	}
	for _, it := range job.Items {
		if it.StartedAt == nil || it.FinishedAt == nil || it.Category == "" || it.Egress == "" || it.Ingest != "accepted" || it.ExitRegion != "hk" {
			t.Fatalf("item incomplete: %+v", it)
		}
	}
	reqs := f.requests()
	if len(reqs) != 4 {
		t.Fatalf("requests: %+v", reqs)
	}
	exits, err := compile.ProbeExits(mustTopo(t, s))
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range reqs {
		ex := exits[r.ExitID]
		if r.Mark != ex.Mark || r.TransitV4 != ex.TransitV4 || r.TransitV6 != ex.TransitV6 || r.Resolver != ex.Resolver || r.Region != "hk" {
			t.Fatalf("request does not pin the exit: %+v vs %+v", r, ex)
		}
		if len(r.Services) != 1 || r.Services[0] != "auto-netflix" {
			t.Fatalf("services: %v", r.Services)
		}
	}
	states, hist, _ := unlockView(t, s)
	if st := states["auto-netflix"]; st.SchedFails != 0 || st.Demoted {
		t.Fatalf("a manual run must not count toward demotion: %+v", st)
	}
	n := 0
	for _, h := range hist {
		if h.Service == "auto-netflix" && h.Kind == unlock.KindManual {
			n++
			if h.Family != "ipv4+ipv6" {
				t.Fatalf("one state step per exit run with both families: %+v", h)
			}
		}
	}
	if n != 2 {
		t.Fatalf("history: %+v", hist)
	}
}

func mustTopo(t *testing.T, s *Server) model.Topology {
	t.Helper()
	topo, err := s.topology()
	if err != nil {
		t.Fatal(err)
	}
	return topo
}

func forceDue(t *testing.T, s *Server) {
	t.Helper()
	s.mu.Lock()
	snap := s.loadUnlock()
	snap.NextRun = time.Now().UTC().Add(-time.Minute)
	if err := s.saveUnlock(snap); err != nil {
		t.Fatal(err)
	}
	s.mu.Unlock()
}

func TestPanelProbeSchedulerSharesChainAndStores(t *testing.T) {
	f := &fakeProber{answer: func(req hostexec.ProbeRequest, svc string) probe.Category {
		if svc == "auto-openai" && req.ExitID == "us" {
			return probe.CatNotUnlocked
		}
		if a, _ := probe.Lookup(svc); a.Capability == probe.CapReachability {
			return probe.CatNetworkOK
		}
		return probe.CatUnlocked
	}}
	s := probeServer(t, f)
	for round := 1; round <= 2; round++ {
		forceDue(t, s)
		before := time.Now().UTC()
		s.tickUnlock()
		if !s.waitProbeJob(10 * time.Second) {
			t.Fatal("scheduled job did not finish")
		}
		job := getJobs(t, s).Jobs[0]
		if job.Kind != unlock.KindScheduled || job.State != jobDone {
			t.Fatalf("round %d: %+v", round, job)
		}
		s.mu.Lock()
		next := s.loadUnlock().NextRun
		s.mu.Unlock()
		if !next.After(before.Add(5 * time.Hour)) {
			t.Fatalf("NextRun not advanced: %v", next)
		}
		states, _, dec := unlockView(t, s)
		st := states["auto-openai"]
		switch round {
		case 1:
			if st.SchedFails != 1 || st.Demoted {
				t.Fatalf("one scheduled failure: %+v", st)
			}
		case 2:
			if !st.Demoted || dec["auto-openai"] != "us-2" {
				t.Fatalf("two scheduled failures must demote within the pool: %+v %v", st, dec)
			}
		}
	}
	// Every service with an adapter was probed; none without one.
	seen := map[string]bool{}
	for _, r := range f.requests() {
		for _, s := range r.Services {
			seen[s] = true
		}
	}
	if !seen["auto-netflix"] || !seen["auto-grok"] || !seen["auto-bahamut"] || !seen["auto-mytvsuper"] || !seen["auto-abema"] {
		t.Fatalf("scheduled selection: %v", seen)
	}
	// Without a host agent, the scheduler records the miss and moves on.
	s.Prober = nil
	forceDue(t, s)
	s.tickUnlock()
	_, hist, _ := unlockView(t, s)
	if last := hist[len(hist)-1]; last.Kind != unlock.KindScheduled || !strings.Contains(last.Note, "没有发起探测") {
		t.Fatalf("missing-agent note: %+v", last)
	}
}

func TestPanelProbeNoVerdictIsInconclusive(t *testing.T) {
	f := &fakeProber{
		answer: func(req hostexec.ProbeRequest, svc string) probe.Category {
			switch {
			case req.ExitID == "us" && req.Family == "ipv4":
				return probe.CatUnlocked
			case req.ExitID == "us":
				return probe.CatFailed
			default:
				return probe.CatUnlocked // the agent claims an unlock...
			}
		},
		// ...but could not confirm us-2's egress: no verdict may survive.
		egressOK: func(req hostexec.ProbeRequest) bool { return req.ExitID != "us-2" },
	}
	s := probeServer(t, f)
	for i := 0; i < 3; i++ {
		forceDue(t, s)
		s.tickUnlock()
		if !s.waitProbeJob(10 * time.Second) {
			t.Fatal("job did not finish")
		}
	}
	job := getJobs(t, s).Jobs[0]
	for _, it := range job.Items {
		if it.Service != "auto-openai" {
			continue
		}
		switch {
		case it.ExitID == "us" && it.Family == unlock.FamilyIPv4:
			if it.Ingest != "accepted" {
				t.Fatalf("%+v", it)
			}
		case it.ExitID == "us":
			if it.Category != probe.CatFailed || it.Ingest != "not_ingested:no_verdict" {
				t.Fatalf("v6 failure in a run with a v4 verdict: %+v", it)
			}
		default:
			if it.Category != probe.CatFailed || it.Ingest != "accepted:inconclusive" || !strings.Contains(it.Egress, "未确认") {
				t.Fatalf("unconfirmed egress must not become a verdict: %+v", it)
			}
		}
	}
	states, hist, _ := unlockView(t, s)
	if st := states["auto-openai"]; st.Demoted || st.SchedFails != 0 || st.Known["us-2"] {
		t.Fatalf("no-verdict probes must neither demote nor count as good: %+v", st)
	}
	found := false
	for _, h := range hist {
		found = found || (h.Kind == unlock.KindInconclusive && h.ExitID == "us-2")
	}
	if !found {
		t.Fatal("inconclusive results must be stored")
	}
}

func TestPanelProbeCancelAndTimeout(t *testing.T) {
	f := &fakeProber{block: true}
	s := probeServer(t, f)
	_, histBefore, _ := unlockView(t, s)
	rr := do(s, http.MethodPost, "/api/unlock/run", []byte(`{"services":["auto-openai"],"families":["ipv4"]}`))
	if rr.Code != http.StatusAccepted {
		t.Fatal(rr.Body.String())
	}
	var started struct {
		Job probeJob `json:"job"`
	}
	_ = json.Unmarshal(rr.Body.Bytes(), &started)
	if rr := do(s, http.MethodPost, "/api/unlock/run", []byte(`{}`)); rr.Code != http.StatusConflict {
		t.Fatalf("second job while one runs: %d", rr.Code)
	}
	deadline := time.Now().Add(5 * time.Second)
	for len(f.requests()) == 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	rr = do(s, http.MethodPost, "/api/unlock/jobs/"+started.Job.ID+"/cancel", nil)
	if rr.Code != 200 {
		t.Fatalf("cancel: %d %s", rr.Code, rr.Body.String())
	}
	job := getJobs(t, s).Jobs[0]
	if job.State != jobCancelled {
		t.Fatalf("%+v", job)
	}
	for _, it := range job.Items {
		if it.Category != probe.CatFailed || !strings.HasPrefix(it.Ingest, "not_ingested:") {
			t.Fatalf("cancelled item: %+v", it)
		}
	}
	if _, hist, _ := unlockView(t, s); len(hist) != len(histBefore) {
		t.Fatalf("a cancelled job must not ingest anything: %+v", hist)
	}
	if rr := do(s, http.MethodPost, "/api/unlock/jobs/"+started.Job.ID+"/cancel", nil); rr.Code != http.StatusConflict {
		t.Fatalf("cancel of a finished job: %d", rr.Code)
	}

	s.ProbeJobTimeout = 150 * time.Millisecond
	job = runJob(t, s, `{"services":["auto-openai"],"exits":["us"],"families":["ipv4"]}`)
	if job.State != jobTimedOut {
		t.Fatalf("timeout: %+v", job)
	}
}

func TestPanelProbeRefusesArbitraryInput(t *testing.T) {
	s := newTest(t)
	do(s, http.MethodGet, "/api/topology", nil)
	if rr := do(s, http.MethodPost, "/api/unlock/run", []byte(`{}`)); rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("no agent: %d", rr.Code)
	}
	s.Prober = &fakeProber{}
	for _, body := range []string{
		`{"url":"https://evil.example/"}`,
		`{"command":"curl https://evil.example"}`,
		`{"services":["https://evil.example/"]}`,
		`{"services":["auto-nope"]}`,
		`{"groups":["no-such-group"]}`,
		`{"services":["auto-openai"],"exits":["gw"]}`,
		`{"services":["auto-openai"],"families":["any"]}`,
		`{"services":["auto-openai"],"exits":["203.0.113.9"]}`,
	} {
		if rr := do(s, http.MethodPost, "/api/unlock/run", []byte(body)); rr.Code != http.StatusBadRequest {
			t.Errorf("%s: %d %s", body, rr.Code, rr.Body.String())
		}
	}
	// An explicitly requested family the exit cannot egress on is recorded,
	// not sent.
	job := runJob(t, s, `{"services":["auto-netflix"],"exits":["sg"],"families":["ipv6"]}`)
	if len(job.Items) != 1 || job.Items[0].State != itemSkipped || job.Items[0].Ingest != "not_ingested:not_sent" {
		t.Fatalf("%+v", job.Items)
	}
	if v := getJobs(t, s); len(v.Catalog) == 0 {
		t.Fatal("catalog missing")
	}
}

// Probe results and exit reports arriving concurrently all go through one
// writer lock: nothing is lost, and the agent never sees more than the
// configured number of exits at once.
func TestPanelProbeConcurrentWithReports(t *testing.T) {
	f := &fakeProber{delay: 20 * time.Millisecond}
	s := probeServer(t, f)
	rr := do(s, http.MethodPost, "/api/unlock/run", []byte(`{}`))
	if rr.Code != http.StatusAccepted {
		t.Fatal(rr.Body.String())
	}
	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if rr := do(s, http.MethodPost, "/api/unlock/report", []byte(`{"exit_id":"hk-resi","kind":"scheduled","raw":"Bahamut: Yes\n"}`)); rr.Code != 200 {
				t.Errorf("report: %d %s", rr.Code, rr.Body.String())
			}
		}()
	}
	wg.Wait()
	if !s.waitProbeJob(20 * time.Second) {
		t.Fatal("job did not finish")
	}
	job := getJobs(t, s).Jobs[0]
	if job.State != jobDone {
		t.Fatalf("%+v", job)
	}
	_, hist, _ := unlockView(t, s)
	reports := 0
	for _, h := range hist {
		if h.Service == "auto-bahamut" && h.ExitID == "hk-resi" {
			reports++
		}
	}
	if reports != 10 {
		t.Fatalf("lost exit reports: %d", reports)
	}
	for _, it := range job.Items {
		if it.State == itemSkipped && it.Ingest == "not_ingested:family_not_supported" {
			continue // IPv4-only adapter on IPv6: not sent
		}
		want := "accepted"
		if it.Capability == probe.CapReachability {
			want = "accepted:inconclusive"
		}
		if it.Ingest != want {
			t.Fatalf("lost probe result: %+v", it)
		}
		ok := false
		for _, h := range hist {
			kind := unlock.KindManual
			if want == "accepted:inconclusive" {
				kind = unlock.KindInconclusive
			}
			ok = ok || (h.Service == it.Service && h.ExitID == it.ExitID && h.Kind == kind)
		}
		if !ok {
			t.Fatalf("accepted item missing from history: %+v", it)
		}
	}
	f.mu.Lock()
	maxIn := f.maxIn
	f.mu.Unlock()
	if maxIn > probeExitConcurrency {
		t.Fatalf("concurrency cap exceeded: %d", maxIn)
	}
}
