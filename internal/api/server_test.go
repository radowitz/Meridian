package api

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

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
