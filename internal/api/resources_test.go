package api

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/radowitz/meridian/internal/credentials"
	"github.com/radowitz/meridian/internal/mesh"
	"github.com/radowitz/meridian/internal/model"
	"golang.org/x/crypto/ssh"
)

func rnd(t *testing.T, n int) string {
	t.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(b)
}

func throwawayKey(t *testing.T) (string, string) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	blk, err := ssh.MarshalPrivateKey(priv, "")
	if err != nil {
		t.Fatal(err)
	}
	sp, _ := ssh.NewPublicKey(pub)
	return string(pem.EncodeToMemory(blk)), ssh.FingerprintSHA256(sp)
}

func mustJSON(v any) []byte {
	b, _ := json.Marshal(v)
	return b
}

func decode(t *testing.T, rr *httptest.ResponseRecorder, v any) {
	t.Helper()
	if err := json.Unmarshal(rr.Body.Bytes(), v); err != nil {
		t.Fatalf("%v: %s", err, rr.Body.String())
	}
}

// assertSecretFiles: the store directory is 0700, every file in it 0600,
// and secret is in exactly one file, under secrets/.
func assertSecretFiles(t *testing.T, dir, secret string) {
	t.Helper()
	if fi, err := os.Stat(dir); err != nil || fi.Mode().Perm() != 0o700 {
		t.Fatalf("store dir %s: %v", dir, err)
	}
	var hits []string
	_ = filepath.Walk(dir, func(p string, fi os.FileInfo, err error) error {
		if err != nil || fi.IsDir() {
			return nil
		}
		if fi.Mode().Perm() != 0o600 {
			t.Errorf("%s mode %o", p, fi.Mode().Perm())
		}
		if b, _ := os.ReadFile(p); bytes.Contains(b, []byte(secret)) {
			hits = append(hits, p)
		}
		return nil
	})
	if len(hits) != 1 || filepath.Base(filepath.Dir(hits[0])) != "secrets" {
		t.Fatalf("secret stored in %v", hits)
	}
}

// assertNowhereElse fails when secret is in any file under root outside
// skip (the credential store).
func assertNowhereElse(t *testing.T, root, skip, secret string) {
	t.Helper()
	_ = filepath.Walk(root, func(p string, fi os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if fi.IsDir() && p == skip {
			return filepath.SkipDir
		}
		if !fi.IsDir() {
			if b, _ := os.ReadFile(p); bytes.Contains(b, []byte(secret)) {
				t.Errorf("secret found in %s", p)
			}
		}
		return nil
	})
}

func errCode(t *testing.T, rr *httptest.ResponseRecorder) (string, []credentials.Ref) {
	t.Helper()
	var body struct {
		Error   string            `json:"error"`
		Code    string            `json:"code"`
		InUseBy []credentials.Ref `json:"in_use_by"`
	}
	decode(t, rr, &body)
	if body.Error == "" {
		t.Fatalf("no error text: %s", rr.Body.String())
	}
	return body.Code, body.InUseBy
}

// Full lifecycle through the REST API: credentials (password, imported
// and generated keys, rotation), servers, node references, deletion
// refused with the referrers, write-only secrets in every response.
func TestResourceLifecycleAndReferences(t *testing.T) {
	s := newTest(t)
	do(s, http.MethodGet, "/api/topology", nil)
	var logs bytes.Buffer
	log.SetOutput(&logs)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })

	pw := rnd(t, 2) // 4 characters
	rr := do(s, http.MethodPost, "/api/ssh-credentials", mustJSON(map[string]any{"name": "运维密码", "kind": "password", "password": pw}))
	if rr.Code != http.StatusCreated || strings.Contains(rr.Body.String(), pw) || !strings.Contains(rr.Body.String(), `"secret_set":true`) {
		t.Fatalf("%d %s", rr.Code, rr.Body.String())
	}
	var pwc struct{ Credential credView }
	decode(t, rr, &pwc)
	assertSecretFiles(t, s.secretsDir(), `"password":"`+pw+`"`)

	keyPEM, fp := throwawayKey(t)
	rr = do(s, http.MethodPost, "/api/ssh-credentials", mustJSON(map[string]any{"name": "导入的钥匙", "kind": "private_key", "private_key": keyPEM, "comment": "ops"}))
	if rr.Code != http.StatusCreated || strings.Contains(rr.Body.String(), "PRIVATE KEY") || !strings.Contains(rr.Body.String(), fp) {
		t.Fatalf("%d %s", rr.Code, rr.Body.String())
	}
	var kc struct{ Credential credView }
	decode(t, rr, &kc)

	rr = do(s, http.MethodPost, "/api/ssh-credentials", mustJSON(map[string]any{"name": "生成的钥匙", "kind": "private_key", "generate": true}))
	var gc struct{ Credential credView }
	decode(t, rr, &gc)
	if rr.Code != http.StatusCreated || !strings.HasPrefix(gc.Credential.PublicKey, "ssh-ed25519 ") || !gc.Credential.Generated {
		t.Fatalf("%d %s", rr.Code, rr.Body.String())
	}

	// Rotation keeps the ID and changes the fingerprint.
	rr = do(s, http.MethodPut, "/api/ssh-credentials/"+gc.Credential.ID+"/secret", []byte(`{"generate":true}`))
	var rc struct{ Credential credView }
	decode(t, rr, &rc)
	if rr.Code != 200 || rc.Credential.ID != gc.Credential.ID || rc.Credential.Fingerprint == gc.Credential.Fingerprint || rc.Credential.RotatedAt == "" {
		t.Fatalf("%d %s", rr.Code, rr.Body.String())
	}

	// A bad key: fixed message, the input is not echoed.
	junk := "-----BEGIN OPENSSH PRIVATE KEY-----\n" + rnd(t, 30) + "\n-----END OPENSSH PRIVATE KEY-----"
	rr = do(s, http.MethodPost, "/api/ssh-credentials", mustJSON(map[string]any{"name": "x", "kind": "private_key", "private_key": junk}))
	if code, _ := errCode(t, rr); rr.Code != http.StatusUnprocessableEntity || code != credentials.CodeInvalidKey || strings.Contains(rr.Body.String(), junk[40:70]) {
		t.Fatalf("%d %s", rr.Code, rr.Body.String())
	}
	// Malformed JSON: no decoder text (which may quote input).
	rr = do(s, http.MethodPost, "/api/ssh-credentials", []byte(`{"name":"x","password":`+pw))
	if code, _ := errCode(t, rr); rr.Code != http.StatusBadRequest || code != "bad_request" || strings.Contains(rr.Body.String(), pw) {
		t.Fatalf("%d %s", rr.Code, rr.Body.String())
	}

	// Servers.
	rr = do(s, http.MethodPost, "/api/servers", mustJSON(map[string]any{"name": "香港枢纽", "address": "198.51.100.10", "auth": "key", "credential_id": pwc.Credential.ID}))
	if code, _ := errCode(t, rr); code != credentials.CodeKindMismatch {
		t.Fatalf("%d %s", rr.Code, rr.Body.String())
	}
	rr = do(s, http.MethodPost, "/api/servers", mustJSON(map[string]any{"name": "香港枢纽", "address": "198.51.100.10", "auth": "key", "credential_id": kc.Credential.ID, "tags": []string{"hk"}}))
	var sv struct{ Server serverView }
	decode(t, rr, &sv)
	if rr.Code != http.StatusCreated || sv.Server.Port != 22 || sv.Server.User != "root" || sv.Server.Ready || sv.Server.Operable || strings.Join(sv.Server.Missing, ",") != "host_key,connection_test" ||
		sv.Server.Credential == nil || sv.Server.Credential.ID != kc.Credential.ID {
		t.Fatalf("%d %s", rr.Code, rr.Body.String())
	}
	srvID := sv.Server.ID

	// Host key: confirm only what was discovered.
	cs, _ := s.credStore()
	_, hk := throwawayKey(t)
	if _, err := cs.ObserveHostKey(srvID, "ssh-ed25519", hk); err != nil {
		t.Fatal(err)
	}
	_, other := throwawayKey(t)
	rr = do(s, http.MethodPost, "/api/servers/"+srvID+"/host-key/trust", mustJSON(map[string]string{"fingerprint": other}))
	if code, _ := errCode(t, rr); rr.Code != http.StatusConflict || code != credentials.CodeHostKeyChanged {
		t.Fatalf("%d %s", rr.Code, rr.Body.String())
	}
	rr = do(s, http.MethodPost, "/api/servers/"+srvID+"/host-key/trust", mustJSON(map[string]string{"fingerprint": hk}))
	decode(t, rr, &sv)
	// Trusted with a credential: operable; ready only after a passing
	// connection test.
	if rr.Code != 200 || !sv.Server.Operable || sv.Server.Ready || strings.Join(sv.Server.Missing, ",") != "connection_test" || sv.Server.HostKey.State != model.HostKeyTrusted {
		t.Fatalf("%d %s", rr.Code, rr.Body.String())
	}

	// Topology references: gateway refused, unknown refused, sharing
	// refused, ssh_* next to server_id refused.
	topo, _, _ := s.Store.Load()
	put := func(mut func(*model.Topology)) *httptest.ResponseRecorder {
		tt, _, _ := s.Store.Load()
		mut(&tt)
		return do(s, http.MethodPut, "/api/topology?draft=1", mustJSON(tt))
	}
	setSrv := func(id, srv string) func(*model.Topology) {
		return func(tt *model.Topology) {
			for i := range tt.Nodes {
				if tt.Nodes[i].ID == id {
					tt.Nodes[i].ServerID = srv
					tt.Nodes[i].SSHHost, tt.Nodes[i].SSHPort, tt.Nodes[i].SSHUser = "", 0, ""
				}
			}
		}
	}
	for _, c := range []struct {
		mut  func(*model.Topology)
		code string
	}{
		{setSrv("gw", srvID), "gateway_server"},
		{setSrv("hk-hub", "srv-nope"), "unknown_server"},
		{func(tt *model.Topology) { setSrv("hk-hub", srvID)(tt); setSrv("jp", srvID)(tt) }, "server_shared"},
		{func(tt *model.Topology) {
			setSrv("hk-hub", srvID)(tt)
			for i := range tt.Nodes {
				if tt.Nodes[i].ID == "hk-hub" {
					tt.Nodes[i].SSHHost = "203.0.113.1"
				}
			}
		}, "ssh_fields_moved"},
	} {
		rr := put(c.mut)
		if code, _ := errCode(t, rr); rr.Code != http.StatusUnprocessableEntity || code != c.code {
			t.Fatalf("%s: %d %s", c.code, rr.Code, rr.Body.String())
		}
	}
	if rr := put(setSrv("hk-hub", srvID)); rr.Code != 200 {
		t.Fatalf("%d %s", rr.Code, rr.Body.String())
	}
	_ = topo

	// The server and its credential cannot be deleted while referenced.
	rr = do(s, http.MethodDelete, "/api/servers/"+srvID, nil)
	if code, refs := errCode(t, rr); rr.Code != http.StatusConflict || code != credentials.CodeInUse || len(refs) != 1 || refs[0].Kind != "node" || refs[0].ID != "hk-hub" {
		t.Fatalf("%d %s", rr.Code, rr.Body.String())
	}
	rr = do(s, http.MethodDelete, "/api/ssh-credentials/"+kc.Credential.ID, nil)
	if code, refs := errCode(t, rr); rr.Code != http.StatusConflict || code != credentials.CodeInUse || len(refs) != 1 || refs[0].ID != srvID {
		t.Fatalf("%d %s", rr.Code, rr.Body.String())
	}
	rr = do(s, http.MethodGet, "/api/servers/"+srvID, nil)
	decode(t, rr, &sv)
	if sv.Server.Node == nil || sv.Server.Node.ID != "hk-hub" {
		t.Fatalf("%s", rr.Body.String())
	}
	// Mesh plans and provisioning reach the node at the server's address.
	if tt, _, _ := s.Store.Load(); true {
		if p, err := s.meshPlan(tt); err == nil {
			if n, ok := p.Node("hk-hub"); ok && n.SSHHost != "198.51.100.10" {
				t.Fatalf("plan target %+v", n)
			}
		}
	}
	// Unlink, then delete both.
	if rr := put(setSrv("hk-hub", "")); rr.Code != 200 {
		t.Fatalf("%d %s", rr.Code, rr.Body.String())
	}
	if rr := do(s, http.MethodDelete, "/api/servers/"+srvID, nil); rr.Code != 200 {
		t.Fatalf("%d %s", rr.Code, rr.Body.String())
	}
	if rr := do(s, http.MethodDelete, "/api/ssh-credentials/"+kc.Credential.ID, nil); rr.Code != 200 {
		t.Fatalf("%d %s", rr.Code, rr.Body.String())
	}
	if rr := do(s, http.MethodGet, "/api/ssh-credentials/"+kc.Credential.ID, nil); rr.Code != http.StatusNotFound {
		t.Fatalf("%d", rr.Code)
	}

	// Lists: metadata only.
	for _, p := range []string{"/api/servers", "/api/ssh-credentials", "/api/cloudflare/accounts", "/api/topology", "/api/mesh"} {
		rr := do(s, http.MethodGet, p, nil)
		if rr.Code != 200 || strings.Contains(rr.Body.String(), pw) || strings.Contains(rr.Body.String(), "PRIVATE KEY") {
			t.Fatalf("%s: %d %s", p, rr.Code, rr.Body.String())
		}
	}
	if strings.Contains(logs.String(), pw) || strings.Contains(logs.String(), "PRIVATE KEY") {
		t.Fatal("secret in the log")
	}
}

// Error text that would carry a short secret is scrubbed.
func TestErrorsScrubShortSecrets(t *testing.T) {
	pw := "Qx7!"
	rr := httptest.NewRecorder()
	writeResErr(rr, &credentials.Error{Code: credentials.CodeStorage, Msg: "auth failed for " + pw}, pw)
	if strings.Contains(rr.Body.String(), pw) || rr.Code != 500 {
		t.Fatal(rr.Body.String())
	}
	rr = httptest.NewRecorder()
	writeResErr(rr, os.ErrPermission, pw)
	if rr.Code != 500 || !strings.Contains(rr.Body.String(), `"code":"storage_error"`) {
		t.Fatal(rr.Body.String())
	}
}

func writeJournal(t *testing.T, s *Server, j mesh.Journal) {
	t.Helper()
	if err := os.MkdirAll(s.meshDir(), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(s.meshDir(), "deploy.json"), mustJSON(j), 0o600); err != nil {
		t.Fatal(err)
	}
}

// Migration of an existing install: the Mesh card's credential file becomes
// a Cloudflare account selected for Mesh, nodes with SSH targets become
// servers (pinned host keys imported), the deployment journal is untouched
// and still withdrawable with the same account, and a second run (or a run
// after an interruption) duplicates nothing.
func TestMigrationKeepsDeploymentsAndIsIdempotent(t *testing.T) {
	s := newTest(t)
	do(s, http.MethodGet, "/api/topology", nil) // seeds the example
	// Simulate the old install: a real-looking SSH target on two nodes and
	// the old credential file, written before the credential store opened.
	topo, _, _ := s.Store.Load()
	for i := range topo.Nodes {
		switch topo.Nodes[i].ID {
		case "hk-hub":
			topo.Nodes[i].SSHHost, topo.Nodes[i].SSHPort, topo.Nodes[i].SSHUser = "198.51.100.20", 2200, "ops"
		case "jp":
			topo.Nodes[i].SSHHost = "jp-exit.example.net"
		}
	}
	if err := s.Store.Save(topo); err != nil {
		t.Fatal(err)
	}
	acct, tok := rnd(t, 16), "cfapitoken_"+rnd(t, 15)
	if err := (mesh.CredStore{Dir: s.meshDir()}).Save(mesh.Credentials{AccountID: acct, APIToken: tok}); err != nil {
		t.Fatal(err)
	}
	_, hk := throwawayKey(t)
	// A schema-2 journal: pins without server or credential.
	pin := mesh.HostPin{NodeID: "hk-hub", Role: model.RoleHub, SSHHost: "198.51.100.20", SSHPort: 2200, SSHUser: "ops", HostKey: hk}
	j := mesh.Journal{Schema: 2, RunID: "run1", State: mesh.StatePublished, AccountID: acct, Hosts: []mesh.HostPin{pin},
		Remotes: []mesh.OwnedRemote{{NodeID: "hk-hub", Host: pin, State: mesh.ResCreated}}}
	writeJournal(t, s, j)

	if errs := s.MigrateCredentials(); len(errs) != 0 {
		t.Fatal(errs)
	}
	if _, err := os.Stat(filepath.Join(s.meshDir(), "cloudflare.json")); !os.IsNotExist(err) {
		t.Fatal("old credential file kept")
	}
	assertSecretFiles(t, s.secretsDir(), tok)
	// The journal is upgraded to schema 3: the pin (and the owned remote's
	// copy) now names the server migrated from the node; nothing else of
	// the run changed.
	up, err := (&mesh.Deployer{Dir: s.meshDir()}).Load()
	if err != nil || up.Schema != 3 || up.RunID != "run1" || up.State != mesh.StatePublished || up.AccountID != acct || len(up.Hosts) != 1 {
		t.Fatalf("upgraded journal: %+v %v", up, err)
	}
	want := pin
	want.ServerID = "srv-hk-hub"
	if up.Hosts[0] != want || up.Remotes[0].Host != want || up.Remotes[0].State != mesh.ResCreated {
		t.Fatalf("upgraded pin %+v / %+v", up.Hosts[0], up.Remotes[0])
	}
	journalBefore, _ := os.ReadFile(filepath.Join(s.meshDir(), "deploy.json"))
	c, err := s.meshCreds().Load()
	if err != nil || c.AccountID != acct || c.APIToken != tok {
		t.Fatalf("deployer credentials after migration: %v", err)
	}
	topo, _, _ = s.Store.Load()
	hub, _ := topo.NodeByID("hk-hub")
	if hub.ServerID != "srv-hk-hub" || hub.SSHHost != "" {
		t.Fatalf("%+v", hub)
	}
	rr := do(s, http.MethodGet, "/api/servers/srv-hk-hub", nil)
	var sv struct{ Server serverView }
	decode(t, rr, &sv)
	if sv.Server.Address != "198.51.100.20" || sv.Server.Port != 2200 || sv.Server.HostKey.Fingerprint != hk || sv.Server.HostKey.State != model.HostKeyTrusted {
		t.Fatalf("%s", rr.Body.String())
	}
	// The pinned host of the busy deployment is a referrer.
	var inUse bool
	for _, r := range sv.Server.InUseBy {
		inUse = inUse || (r.Kind == "mesh_deployment" && r.ID == "run1")
	}
	if !inUse {
		t.Fatalf("deployment not listed: %+v", sv.Server.InUseBy)
	}

	// Idempotent: again, and again after the old file reappears (crash
	// between the index write and the file removal) and a topology whose
	// save was lost (crash between the server write and the topology save).
	if err := (mesh.CredStore{Dir: s.meshDir()}).Save(mesh.Credentials{AccountID: acct, APIToken: tok}); err != nil {
		t.Fatal(err)
	}
	topo, _, _ = s.Store.Load()
	for i := range topo.Nodes {
		if topo.Nodes[i].ID == "jp" {
			topo.Nodes[i].ServerID, topo.Nodes[i].SSHHost = "", "jp-exit.example.net"
		}
	}
	if err := s.Store.Save(topo); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		if errs := s.MigrateCredentials(); len(errs) != 0 {
			t.Fatal(errs)
		}
	}
	if after, _ := os.ReadFile(filepath.Join(s.meshDir(), "deploy.json")); !bytes.Equal(after, journalBefore) {
		t.Fatal("repeated migration changed the upgraded journal")
	}
	cs, _ := s.credStore()
	if n := len(cs.Accounts()); n != 1 {
		t.Fatalf("%d accounts", n)
	}
	if n := len(cs.Servers()); n != 2 {
		t.Fatalf("%d servers: %+v", n, cs.Servers())
	}
	topo, _, _ = s.Store.Load()
	if jp, _ := topo.NodeByID("jp"); jp.ServerID != "srv-jp" {
		t.Fatalf("%+v", jp)
	}
	assertSecretFiles(t, s.secretsDir(), tok)
}

// The binding rules of the Mesh deployment apply to the account objects:
// the bound account cannot be deleted, re-pointed or deselected while the
// run is not fully withdrawn; its token can be rotated; other accounts are
// free.
func TestCloudflareAccountBinding(t *testing.T) {
	s := newTest(t)
	acct, tok := rnd(t, 16), "cfapitoken_"+rnd(t, 15)
	rr := do(s, http.MethodPost, "/api/cloudflare/accounts", mustJSON(map[string]string{"name": "主账户", "account_id": acct, "api_token": tok}))
	var a struct{ Account accountView }
	decode(t, rr, &a)
	if rr.Code != http.StatusCreated || strings.Contains(rr.Body.String(), tok) || !a.Account.TokenSet || a.Account.UsedForMesh {
		t.Fatalf("%d %s", rr.Code, rr.Body.String())
	}
	assertSecretFiles(t, s.secretsDir(), tok)
	rr = do(s, http.MethodPost, "/api/cloudflare/accounts", mustJSON(map[string]string{"name": "x", "account_id": "nothex", "api_token": "short"}))
	if code, _ := errCode(t, rr); rr.Code != http.StatusUnprocessableEntity || code != credentials.CodeInvalid || strings.Contains(rr.Body.String(), "short") {
		t.Fatalf("%d %s", rr.Code, rr.Body.String())
	}
	other := rnd(t, 16)
	rr = do(s, http.MethodPost, "/api/cloudflare/accounts", mustJSON(map[string]string{"name": "备用", "account_id": other, "api_token": "cfapitoken_" + rnd(t, 15)}))
	var b struct{ Account accountView }
	decode(t, rr, &b)

	if rr := do(s, http.MethodPut, "/api/cloudflare/mesh-account", mustJSON(map[string]string{"account": a.Account.ID})); rr.Code != 200 {
		t.Fatalf("%d %s", rr.Code, rr.Body.String())
	}
	writeJournal(t, s, mesh.Journal{Schema: mesh.JournalSchema, RunID: "run9", State: mesh.StateCompensationFailed, AccountID: acct})

	rr = do(s, http.MethodDelete, "/api/cloudflare/accounts/"+a.Account.ID, nil)
	if code, refs := errCode(t, rr); rr.Code != http.StatusConflict || code != credentials.CodeInUse || len(refs) != 1 || refs[0].ID != "run9" {
		t.Fatalf("%d %s", rr.Code, rr.Body.String())
	}
	rr = do(s, http.MethodPatch, "/api/cloudflare/accounts/"+a.Account.ID, mustJSON(map[string]string{"account_id": other}))
	if code, _ := errCode(t, rr); rr.Code != http.StatusConflict || code != "account_locked" {
		t.Fatalf("%d %s", rr.Code, rr.Body.String())
	}
	for _, sel := range []string{b.Account.ID, ""} {
		rr = do(s, http.MethodPut, "/api/cloudflare/mesh-account", mustJSON(map[string]string{"account": sel}))
		if code, _ := errCode(t, rr); rr.Code != http.StatusConflict || code != "account_locked" {
			t.Fatalf("select %q: %d %s", sel, rr.Code, rr.Body.String())
		}
	}
	tok2 := "cfapitoken_" + rnd(t, 15)
	rr = do(s, http.MethodPut, "/api/cloudflare/accounts/"+a.Account.ID+"/token", mustJSON(map[string]string{"api_token": tok2}))
	if rr.Code != 200 || strings.Contains(rr.Body.String(), tok2) {
		t.Fatalf("%d %s", rr.Code, rr.Body.String())
	}
	if c, err := s.meshCreds().Load(); err != nil || c.APIToken != tok2 || c.AccountID != acct {
		t.Fatal("rotation not used by the deployer")
	}
	rr = do(s, http.MethodGet, "/api/cloudflare/accounts", nil)
	var list struct {
		Accounts    []accountView
		MeshAccount string `json:"mesh_account"`
	}
	decode(t, rr, &list)
	if list.MeshAccount != a.Account.ID || len(list.Accounts) != 2 {
		t.Fatalf("%s", rr.Body.String())
	}
	for _, v := range list.Accounts {
		if (v.ID == a.Account.ID) != (v.BoundDeployment != nil) {
			t.Fatalf("binding view: %+v", v)
		}
	}
	// The unbound account is free; after withdrawal the bound one too.
	if rr := do(s, http.MethodDelete, "/api/cloudflare/accounts/"+b.Account.ID, nil); rr.Code != 200 {
		t.Fatalf("%d %s", rr.Code, rr.Body.String())
	}
	writeJournal(t, s, mesh.Journal{Schema: mesh.JournalSchema, RunID: "run9", State: mesh.StateWithdrawn, AccountID: acct})
	if rr := do(s, http.MethodDelete, "/api/cloudflare/accounts/"+a.Account.ID, nil); rr.Code != 200 {
		t.Fatalf("%d %s", rr.Code, rr.Body.String())
	}
	if _, err := s.meshCreds().Load(); err != mesh.ErrNoCredentials {
		t.Fatalf("deleted selected account still used: %v", err)
	}
}

// Secrets never reach snapshots, compiled bundles, diffs or responses of
// the data-plane endpoints, whatever servers and credentials exist.
func TestSecretsStayOutOfSnapshotsAndBundles(t *testing.T) {
	s := newTest(t)
	do(s, http.MethodGet, "/api/topology", nil)
	pw := rnd(t, 2)
	keyPEM, _ := throwawayKey(t)
	tok := "cfapitoken_" + rnd(t, 15)
	var c struct{ Credential credView }
	rr := do(s, http.MethodPost, "/api/ssh-credentials", mustJSON(map[string]any{"name": "p", "kind": "password", "password": pw}))
	decode(t, rr, &c)
	do(s, http.MethodPost, "/api/ssh-credentials", mustJSON(map[string]any{"name": "k", "kind": "private_key", "private_key": keyPEM}))
	do(s, http.MethodPost, "/api/cloudflare/accounts", mustJSON(map[string]string{"name": "a", "account_id": rnd(t, 16), "api_token": tok}))
	rr = do(s, http.MethodPost, "/api/servers", mustJSON(map[string]any{"name": "hub", "address": "198.51.100.30", "auth": "password", "credential_id": c.Credential.ID}))
	var sv struct{ Server serverView }
	decode(t, rr, &sv)
	topo, _, _ := s.Store.Load()
	for i := range topo.Nodes {
		if topo.Nodes[i].ID == "hk-hub" {
			topo.Nodes[i].ServerID, topo.Nodes[i].SSHHost, topo.Nodes[i].SSHPort, topo.Nodes[i].SSHUser = sv.Server.ID, "", 0, ""
		}
	}
	if rr := do(s, http.MethodPut, "/api/topology?draft=1", mustJSON(topo)); rr.Code != 200 {
		t.Fatalf("%d %s", rr.Code, rr.Body.String())
	}
	var bodies []string
	for i := 0; i < 2; i++ { // two snapshots: applied and previous
		rr := do(s, http.MethodPost, "/api/apply", []byte(`{}`))
		if rr.Code != 200 {
			t.Fatalf("%d %s", rr.Code, rr.Body.String())
		}
		bodies = append(bodies, rr.Body.String())
	}
	for _, p := range []string{"/api/compile", "/api/diff", "/api/validate"} {
		bodies = append(bodies, do(s, http.MethodPost, p, []byte(`{}`)).Body.String())
	}
	bodies = append(bodies, do(s, http.MethodGet, "/api/topology", nil).Body.String())
	pemLine := strings.Split(strings.TrimSpace(keyPEM), "\n")[1]
	for _, b := range bodies {
		for _, sec := range []string{`"` + pw + `"`, pemLine, tok} {
			if strings.Contains(b, sec) {
				t.Fatalf("secret in a response")
			}
		}
	}
	if _, err := os.Stat(filepath.Join(s.DataDir, "applied")); err != nil {
		t.Fatal("no snapshot was written")
	}
	for _, sec := range []string{`"password":"` + pw + `"`, pemLine, tok} {
		assertNowhereElse(t, s.DataDir, s.secretsDir(), sec)
	}
	// The SQLite file is under DataDir too: the walk above covered it.
}
