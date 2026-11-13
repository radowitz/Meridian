package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/radowitz/meridian/internal/apply"
	"github.com/radowitz/meridian/internal/model"
)

// codeOf decodes the "code" of an error body.
func codeOf(t *testing.T, body []byte) string {
	t.Helper()
	var v struct {
		Code string `json:"code"`
	}
	if err := json.Unmarshal(body, &v); err != nil {
		t.Fatalf("%v: %s", err, body)
	}
	return v.Code
}

func expectCode(t *testing.T, s *Server, path, body string, status int, code string) {
	t.Helper()
	rr := do(s, http.MethodPost, path, []byte(body))
	if rr.Code != status || codeOf(t, rr.Body.Bytes()) != code {
		t.Fatalf("%s %s: want %d %s, got %d %s", path, body, status, code, rr.Code, rr.Body.String())
	}
}

// Every refusal and failure of POST /api/apply and POST /api/rollback carries
// a stable machine code; the HTTP statuses are unchanged.
func TestApplyAndRollbackErrorCodes(t *testing.T) {
	t.Run("no host agent", func(t *testing.T) {
		s := newTest(t)
		withPeerKeys(t, s)
		expectCode(t, s, "/api/apply", `{"install":true}`, http.StatusServiceUnavailable, "host_unavailable")
	})
	t.Run("host agent unhealthy", func(t *testing.T) {
		s := newTest(t)
		withPeerKeys(t, s)
		s.Host = downHost{}
		rr := do(s, http.MethodPost, "/api/apply", []byte(`{"install":true}`))
		if c := codeOf(t, rr.Body.Bytes()); c != "host_unavailable" {
			t.Fatal(rr.Code, rr.Body.String())
		}
	})
	t.Run("missing peer keys", func(t *testing.T) {
		s := newTest(t)
		s.HostRoot = t.TempDir()
		s.Activate = func() error { return nil }
		do(s, http.MethodGet, "/api/topology", nil)
		expectCode(t, s, "/api/apply", `{"install":true}`, http.StatusUnprocessableEntity, "peer_keys_missing")
	})
	t.Run("topology invalid, before any key is generated", func(t *testing.T) {
		s, _, _ := installTest(t)
		topo, _, _ := s.Store.Load()
		topo.Settings.Draft = true
		topo.Links = nil
		if err := s.Store.Save(topo); err != nil {
			t.Fatal(err)
		}
		expectCode(t, s, "/api/apply", `{"install":true}`, http.StatusUnprocessableEntity, "topology_invalid")
		if gw := storedNode(t, s, localNodeID); gw.PrivateKey != "" {
			t.Fatal("gateway key generated for an invalid topology")
		}
		expectCode(t, s, "/api/apply", `{"install":false}`, http.StatusUnprocessableEntity, "topology_invalid")
	})
	t.Run("lan interface mismatch", func(t *testing.T) {
		s, _, _ := installTest(t)
		topo, _, _ := s.Store.Load()
		topo.Settings.Draft = true
		topo.Settings.LANInterface = "eth0"
		for i := range topo.Nodes {
			if topo.Nodes[i].ID == localNodeID {
				topo.Nodes[i].LANInterface = "eth9"
			}
		}
		if err := s.Store.Save(topo); err != nil {
			t.Fatal(err)
		}
		expectCode(t, s, "/api/apply", `{"install":true}`, http.StatusUnprocessableEntity, "lan_interface_mismatch")
	})
	t.Run("activation failed and compensated", func(t *testing.T) {
		s, _, _ := installTest(t)
		s.Activate = func() error { return errors.New("activation failed") }
		expectCode(t, s, "/api/apply", `{"install":true}`, http.StatusInternalServerError, "activation_failed_compensated")
	})
	t.Run("activation failed and compensation failed, then pending", func(t *testing.T) {
		s, _, _ := installTest(t)
		if rr := do(s, http.MethodPost, "/api/apply", []byte(`{"install":true}`)); rr.Code != 200 {
			t.Fatal(rr.Code, rr.Body.String())
		}
		topo, _, _ := s.Store.Load()
		topo.Rules = append(topo.Rules, model.Rule{ID: "code-test", Name: "code test", Manual: true, Enabled: true,
			Priority: 9999, MatchType: "domain", MatchValue: "example.org", TargetGroup: topo.Settings.DefaultGroup})
		if err := s.Store.Save(topo); err != nil {
			t.Fatal(err)
		}
		s.Activate = func() error { return errors.New("activation failed") }
		expectCode(t, s, "/api/apply", `{"install":true}`, http.StatusInternalServerError, "activation_failed_uncompensated")
		expectCode(t, s, "/api/apply", `{"install":true}`, http.StatusConflict, "transaction_pending")
		expectCode(t, s, "/api/rollback", `{"install":true}`, http.StatusConflict, "transaction_pending")
	})
	t.Run("nothing to roll back", func(t *testing.T) {
		s := newTest(t)
		do(s, http.MethodGet, "/api/topology", nil)
		expectCode(t, s, "/api/rollback", `{}`, http.StatusConflict, "nothing_to_rollback")
	})
	t.Run("rollback mode required", func(t *testing.T) {
		s, _, _ := installTest(t)
		for i := 0; i < 2; i++ {
			if rr := do(s, http.MethodPost, "/api/apply", []byte(`{"install":true}`)); rr.Code != 200 {
				t.Fatal(rr.Code, rr.Body.String())
			}
		}
		expectCode(t, s, "/api/rollback", `{}`, http.StatusConflict, "rollback_mode_required")
		expectCode(t, s, "/api/rollback", `{"install":true,"snapshot_only":true}`, http.StatusBadRequest, "bad_request")
	})
	// The refusal itself is exercised in internal/apply
	// (TestLegacyInstallRefusedTouchesNothing); here only its mapping.
	t.Run("legacy install refused", func(t *testing.T) {
		rr := httptest.NewRecorder()
		writeTxnErr(rr, fmt.Errorf("%w：旧版私钥与面板保存的不同", apply.ErrLegacyInstall), "", http.StatusInternalServerError)
		if rr.Code != http.StatusConflict || codeOf(t, rr.Body.Bytes()) != "legacy_install_refused" {
			t.Fatal(rr.Code, rr.Body.String())
		}
	})
}

// GET /api/status says whether a rollback has anything to go back to, and
// POST /api/diff lists what an install would change against the installed
// manifest even when the change was applied but not installed.
func TestStatusPreviousAvailableAndInstalledDiff(t *testing.T) {
	s, _, _ := installTest(t)
	var st struct {
		PreviousAvailable bool `json:"previous_available"`
	}
	read := func() {
		rr := do(s, http.MethodGet, "/api/status", nil)
		if err := json.Unmarshal(rr.Body.Bytes(), &st); err != nil {
			t.Fatal(err)
		}
	}
	read()
	if st.PreviousAvailable {
		t.Fatal("nothing applied yet, but previous_available")
	}
	var d struct {
		Diff      string         `json:"diff"`
		Installed map[string]any `json:"installed"`
	}
	diff := func() {
		rr := do(s, http.MethodPost, "/api/diff", []byte(`{}`))
		if rr.Code != 200 {
			t.Fatal(rr.Code, rr.Body.String())
		}
		d.Installed = nil
		if err := json.Unmarshal(rr.Body.Bytes(), &d); err != nil {
			t.Fatal(err)
		}
	}
	diff()
	if d.Installed != nil {
		t.Fatalf("nothing installed, but installed diff %v", d.Installed)
	}
	if rr := do(s, http.MethodPost, "/api/apply", []byte(`{"install":true}`)); rr.Code != 200 {
		t.Fatal(rr.Code, rr.Body.String())
	}
	if read(); st.PreviousAvailable {
		t.Fatal("first install has no previous snapshot")
	}
	diff()
	if d.Installed == nil || len(d.Installed) != 0 {
		t.Fatalf("in sync: want an empty installed diff, got %v", d.Installed)
	}

	// Change a rule and apply without installing: the text diff is empty,
	// the installed diff names the changed gateway file.
	topo, _, _ := s.Store.Load()
	topo.Rules = append(topo.Rules, model.Rule{ID: "diff-test", Name: "diff test", Manual: true, Enabled: true,
		Priority: 9999, MatchType: "domain", MatchValue: "example.org", TargetGroup: topo.Settings.DefaultGroup})
	if err := s.Store.Save(topo); err != nil {
		t.Fatal(err)
	}
	if rr := do(s, http.MethodPost, "/api/apply", []byte(`{"install":false}`)); rr.Code != 200 {
		t.Fatal(rr.Code, rr.Body.String())
	}
	if read(); !st.PreviousAvailable {
		t.Fatal("after a second apply a previous snapshot exists")
	}
	diff()
	if strings.TrimSpace(d.Diff) != "（没有变化）" && strings.TrimSpace(d.Diff) != "" {
		t.Fatalf("text diff should be empty after apply: %q", d.Diff)
	}
	changed, _ := d.Installed["files_changed"].([]any)
	if len(changed) == 0 {
		t.Fatalf("installed diff does not name the changed files: %v", d.Installed)
	}
}
