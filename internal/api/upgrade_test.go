package api

import (
	"bytes"
	"encoding/json"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/radowitz/meridian/internal/credentials"
	"github.com/radowitz/meridian/internal/mesh"
	"github.com/radowitz/meridian/internal/model"
	"github.com/radowitz/meridian/internal/store"
)

// TestUpgradeFromPreRedesignDataDir is the end-to-end upgrade contract: a
// data directory as main@5b01903 left it — the topology row with exit
// pools, rule target_pool/mode and node ssh_* fields (the repository
// example of that commit, testdata/pre-redesign-topology.json, with two
// SSH targets made real-looking), the Mesh card's mesh/cloudflare.json and
// a schema-2 Mesh journal, no secrets/ directory — goes through the
// startup sequence of cmd/meridian (RecoverHost, MigrateCredentials,
// Store.MigrateRegionGroups) and comes out as region groups, servers with
// the journal's pinned host key, a Cloudflare account bound to the
// deployment and a schema-3 journal. The token ends up only in secrets/
// and nowhere in responses, logs, the row or the journal; references block
// deletion; a second start changes nothing; the result compiles.
//
// The individual migrations have their own tests (store_test.go,
// credentials/store_test.go, mesh/upgrade_test.go,
// TestMigrationKeepsDeploymentsAndIsIdempotent); this one covers them
// together and in main's order.
func TestUpgradeFromPreRedesignDataDir(t *testing.T) {
	var logs bytes.Buffer
	log.SetOutput(&logs)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })

	raw, err := os.ReadFile(filepath.Join("testdata", "pre-redesign-topology.json"))
	if err != nil {
		t.Fatal(err)
	}
	legacy := strings.Replace(string(raw), `"ssh_host": "hk-hub.example.invalid"`, `"ssh_host": "198.51.100.120"`, 1)
	legacy = strings.Replace(legacy, `"ssh_host": "jp.example.invalid"`, `"ssh_host": "jp-exit.example.net"`, 1)
	if legacy == string(raw) || !strings.Contains(legacy, `"target_pool"`) || strings.Contains(legacy, `"groups"`) {
		t.Fatal("fixture is not the pre-redesign example")
	}
	data := t.TempDir()
	open := func() *store.Store {
		st, err := store.Open(filepath.Join(data, "meridian.db"))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { st.Close() })
		return st
	}
	st := open()
	if err := st.Put("topology", legacy); err != nil { // the row as the old panel wrote it
		t.Fatal(err)
	}
	s := &Server{Store: st, DataDir: data}
	acct, tok := rnd(t, 16), "cfapitoken_"+rnd(t, 15)
	if err := (mesh.CredStore{Dir: s.meshDir()}).Save(mesh.Credentials{AccountID: acct, APIToken: tok}); err != nil {
		t.Fatal(err)
	}
	_, hk := throwawayKey(t)
	pin := mesh.HostPin{NodeID: "hk-hub", Role: model.RoleHub, SSHHost: "198.51.100.120", SSHPort: 22, SSHUser: "root", HostKey: hk}
	writeJournal(t, s, mesh.Journal{Schema: 2, RunID: "run-old", State: mesh.StatePublished, AccountID: acct, Hosts: []mesh.HostPin{pin},
		Remotes: []mesh.OwnedRemote{{NodeID: "hk-hub", Host: pin, State: mesh.ResCreated}}})
	if _, err := os.Stat(filepath.Join(data, "secrets")); !os.IsNotExist(err) {
		t.Fatal("a pre-redesign data directory has no secrets/")
	}

	// cmd/meridian/main.go, in its order.
	start := func(s *Server, st *store.Store) {
		t.Helper()
		if rep, err := s.RecoverHost(); err != nil || rep != nil {
			t.Fatalf("recover on a data dir without a host journal: %+v %v", rep, err)
		}
		if errs := s.MigrateCredentials(); len(errs) != 0 {
			t.Fatal(errs)
		}
		if _, err := st.MigrateRegionGroups(); err != nil {
			t.Fatal(err)
		}
	}
	start(s, st)

	// Pools became groups; nothing legacy is left in the stored row.
	row, _, _ := st.Get("topology")
	for _, legacyField := range []string{`"target_pool"`, `"pool_priority"`, `"pool":`, `"198.51.100.120"`, `"jp-exit.example.net"`} {
		if strings.Contains(row, legacyField) {
			t.Errorf("stored topology still has %s", legacyField)
		}
	}
	topo, _, _ := st.Load()
	if topo.Settings.DefaultGroup != "hk" || len(topo.Groups) == 0 {
		t.Fatalf("groups not migrated: default %q, %d groups", topo.Settings.DefaultGroup, len(topo.Groups))
	}
	for _, r := range topo.Rules {
		if r.TargetPool != "" || r.Mode != "" || (r.TargetGroup == "" && r.TargetExit == "") {
			t.Errorf("rule %s not migrated: group %q exit %q pool %q", r.ID, r.TargetGroup, r.TargetExit, r.TargetPool)
		}
	}
	// Real SSH targets became servers (placeholder .invalid hosts and the
	// gateway are left as they were); the journal's pinned key is trusted.
	hub, _ := topo.NodeByID("hk-hub")
	jp, _ := topo.NodeByID("jp")
	if hub.ServerID != "srv-hk-hub" || jp.ServerID != "srv-jp" || hub.SSHHost != "" || jp.SSHHost != "" {
		t.Fatalf("servers not linked: hub %q jp %q", hub.ServerID, jp.ServerID)
	}
	rr := do(s, http.MethodGet, "/api/servers/srv-hk-hub", nil)
	var sv struct{ Server serverView }
	decode(t, rr, &sv)
	if sv.Server.Address != "198.51.100.120" || sv.Server.HostKey.Fingerprint != hk || sv.Server.HostKey.State != model.HostKeyTrusted {
		t.Fatalf("migrated server: %s", rr.Body.String())
	}
	// cloudflare.json became the account bound to the deployment.
	if _, err := os.Stat(filepath.Join(s.meshDir(), "cloudflare.json")); !os.IsNotExist(err) {
		t.Fatal("mesh/cloudflare.json kept")
	}
	assertSecretFiles(t, s.secretsDir(), tok)
	rr = do(s, http.MethodGet, "/api/cloudflare/accounts", nil)
	if !strings.Contains(rr.Body.String(), `"id":"`+credentials.LegacyCloudflareID+`"`) || !strings.Contains(rr.Body.String(), `"used_for_mesh":true`) {
		t.Fatalf("account: %s", rr.Body.String())
	}
	// Schema-2 journal became schema 3 with the migrated server.
	j, err := (&mesh.Deployer{Dir: s.meshDir()}).Load()
	if err != nil || j.Schema != 3 || j.RunID != "run-old" || j.AccountID != acct || j.Hosts[0].ServerID != "srv-hk-hub" || j.Hosts[0].HostKey != hk {
		t.Fatalf("journal: %+v %v", j, err)
	}

	// References block deletion: the pinned server, the bound account, the
	// default group.
	for _, p := range []string{"/api/servers/srv-hk-hub", "/api/cloudflare/accounts/" + credentials.LegacyCloudflareID, "/api/region-groups/hk"} {
		if rr := do(s, http.MethodDelete, p, nil); rr.Code != http.StatusConflict {
			t.Errorf("DELETE %s: %d %s", p, rr.Code, rr.Body.String())
		}
	}

	// The upgraded configuration compiles and the leak check runs on it.
	for _, p := range []string{"/api/compile", "/api/diff"} {
		if rr := do(s, http.MethodPost, p, []byte(`{}`)); rr.Code != http.StatusOK || strings.Contains(rr.Body.String(), tok) {
			t.Fatalf("%s after upgrade: %d", p, rr.Code)
		}
	}
	rr = do(s, http.MethodGet, "/api/leakcheck", nil)
	if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), `"id":"group_marks_routed","status":"pass"`) {
		t.Fatalf("leakcheck after upgrade: %d %s", rr.Code, rr.Body.String())
	}

	// The token is nowhere but secrets/: not in responses, the row, the
	// journal, snapshots or logs.
	for _, p := range []string{"/api/topology", "/api/mesh", "/api/servers", "/api/cloudflare/accounts", "/api/status"} {
		if strings.Contains(do(s, http.MethodGet, p, nil).Body.String(), tok) {
			t.Fatalf("token in GET %s", p)
		}
	}
	assertNowhereElse(t, data, s.secretsDir(), tok)

	// A second start (a restart of the upgraded panel) changes nothing.
	journal1, _ := os.ReadFile(filepath.Join(s.meshDir(), "deploy.json"))
	index1, _ := os.ReadFile(filepath.Join(s.secretsDir(), "index.json"))
	st.Close()
	st2 := open()
	s2 := &Server{Store: st2, DataDir: data}
	start(s2, st2)
	row2, _, _ := st2.Get("topology")
	journal2, _ := os.ReadFile(filepath.Join(s.meshDir(), "deploy.json"))
	index2, _ := os.ReadFile(filepath.Join(s.secretsDir(), "index.json"))
	if row2 != row || !bytes.Equal(journal1, journal2) || !bytesEqualJSON(index1, index2) {
		t.Fatal("a second start rewrote the upgraded state")
	}
	if strings.Contains(logs.String(), tok) {
		t.Fatal("token in the logs")
	}
}

// bytesEqualJSON compares two JSON documents by value.
func bytesEqualJSON(a, b []byte) bool {
	var x, y any
	if json.Unmarshal(a, &x) != nil || json.Unmarshal(b, &y) != nil {
		return bytes.Equal(a, b)
	}
	xa, _ := json.Marshal(x)
	ya, _ := json.Marshal(y)
	return bytes.Equal(xa, ya)
}

// A group referenced only as the default group cannot be deleted; once
// the default moves away it can.
func TestDefaultGroupReferenceBlocksDeletion(t *testing.T) {
	s := newTest(t)
	do(s, http.MethodGet, "/api/topology", nil)
	rr := do(s, http.MethodPost, "/api/region-groups", []byte(`{"name":"香港手选","region":"hk","mode":"manual","chosen":"hk-2","members":["hk-2","hk-ix"]}`))
	if rr.Code != http.StatusCreated {
		t.Fatal(rr.Body.String())
	}
	if rr := do(s, http.MethodPut, "/api/region-groups/default", []byte(`{"group":"hk-2"}`)); rr.Code != 200 {
		t.Fatal(rr.Body.String())
	}
	rr = do(s, http.MethodDelete, "/api/region-groups/hk-2", nil)
	if rr.Code != http.StatusConflict || !strings.Contains(rr.Body.String(), `"default_group"`) {
		t.Fatalf("delete of the default group: %d %s", rr.Code, rr.Body.String())
	}
	if rr := do(s, http.MethodPut, "/api/region-groups/default", []byte(`{"group":"hk"}`)); rr.Code != 200 {
		t.Fatal(rr.Body.String())
	}
	if rr := do(s, http.MethodDelete, "/api/region-groups/hk-2", nil); rr.Code != 200 {
		t.Fatalf("delete after the default moved: %d %s", rr.Code, rr.Body.String())
	}
}
