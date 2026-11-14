package api

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"encoding/pem"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/radowitz/meridian/internal/defaults"
)

// Seams between modules that the per-package secret tests do not cross
// (docs/verification.md lists where each secret contract is tested).

// noSecretIn fails when any of secrets occurs in text.
func noSecretIn(t *testing.T, where, text string, secrets ...string) {
	t.Helper()
	for _, v := range secrets {
		if v != "" && strings.Contains(text, v) {
			t.Fatalf("secret in %s", where)
		}
	}
}

// readOnlyViews are the GET endpoints that show configuration or state.
var readOnlyViews = []string{"/api/topology", "/api/servers", "/api/ssh-credentials", "/api/cloudflare/accounts", "/api/mesh", "/api/status", "/api/remote-access", "/api/leakcheck"}

// Server with a passphrase-protected key → connection test → provision:
// the key resolved by credential ID reaches only the SSH session; the
// passphrase and the PEM appear in no response, log, compiled bundle,
// diff or file outside secrets/.
func TestKeyCredentialProvisionKeepsKeyInStore(t *testing.T) {
	var logs bytes.Buffer
	log.SetOutput(&logs)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })
	s := newTest(t)
	do(s, http.MethodGet, "/api/topology", nil)
	srv := startSSH(t)
	pass := "pp-" + rnd(t, 6)
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	blk, err := ssh.MarshalPrivateKeyWithPassphrase(priv, "", []byte(pass))
	if err != nil {
		t.Fatal(err)
	}
	signer, _ := ssh.NewSignerFromKey(priv)
	srv.SetAuthorizedKey(signer.PublicKey())
	pemText := string(pem.EncodeToMemory(blk))
	pemLine := strings.Split(pemText, "\n")[2] // a base64 body line
	secrets := []string{pass, pemLine}

	rr := do(s, http.MethodPost, "/api/ssh-credentials", mustJSON(map[string]any{"name": "钥匙", "kind": "private_key", "private_key": pemText, "passphrase": pass}))
	noSecretIn(t, "credential create", rr.Body.String(), secrets...)
	var c struct{ Credential credView }
	decode(t, rr, &c)
	rr = do(s, http.MethodPost, "/api/servers", mustJSON(map[string]any{"name": "台湾出口", "address": srv.Host, "port": srv.Port, "user": "ops", "auth": "key", "credential_id": c.Credential.ID}))
	var sv struct{ Server serverView }
	decode(t, rr, &sv)
	topo, _, _ := s.Store.Load()
	for i := range topo.Nodes {
		if topo.Nodes[i].ID == "tw" {
			topo.Nodes[i].ServerID, topo.Nodes[i].SSHHost, topo.Nodes[i].SSHPort, topo.Nodes[i].SSHUser = sv.Server.ID, "", 0, ""
		}
	}
	if err := s.Store.Save(topo); err != nil {
		t.Fatal(err)
	}
	do(s, http.MethodPost, "/api/servers/"+sv.Server.ID+"/host-key/discover", nil)
	do(s, http.MethodPost, "/api/servers/"+sv.Server.ID+"/host-key/trust", mustJSON(map[string]string{"fingerprint": srv.Fingerprint()}))
	rr = do(s, http.MethodPost, "/api/servers/"+sv.Server.ID+"/test", nil)
	if rr.Code != 200 || !strings.Contains(rr.Body.String(), `"ok":true`) {
		t.Fatalf("test: %d %s", rr.Code, rr.Body.String())
	}
	noSecretIn(t, "connection test", rr.Body.String(), secrets...)

	pfID := reviewPreflight(t, s, "tw")
	rr = do(s, http.MethodPost, "/api/provision", []byte(`{"node_id":"tw","generate_keys":true,"preflight_id":"`+pfID+`"}`))
	tw := storedNode(t, s, "tw")
	if rr.Code != 200 || !strings.Contains(rr.Body.String(), "MERIDIAN_PROVISION_OK") || !strings.Contains(rr.Body.String(), `"auth_method":"key"`) {
		t.Fatalf("provision over a key: %d %s", rr.Code, rr.Body.String())
	}
	secrets = append(secrets, tw.PrivateKey)
	noSecretIn(t, "provision response", rr.Body.String(), secrets...)
	if !strings.Contains(lastScript(srv.Stdins()), tw.PrivateKey) {
		t.Fatal("the generated node key did not reach the provision script")
	}
	for _, p := range []string{"/api/compile", "/api/diff", "/api/validate"} {
		noSecretIn(t, "POST "+p, do(s, http.MethodPost, p, []byte(`{}`)).Body.String(), secrets...)
	}
	for _, p := range readOnlyViews {
		noSecretIn(t, "GET "+p, do(s, http.MethodGet, p, nil).Body.String(), secrets...)
	}
	noSecretIn(t, "logs", logs.String(), secrets...)
	assertNowhereElse(t, s.DataDir, s.secretsDir(), pass)
	assertNowhereElse(t, s.DataDir, s.secretsDir(), pemLine)
}

// Account → Mesh deploy (an injected failure first) → withdraw: the API
// token, the SSH password and the Cloudflare node token appear in no
// response, log or file outside secrets/ (the node token nowhere at all).
func TestMeshSecretsAcrossDeployAndWithdraw(t *testing.T) {
	var logs bytes.Buffer
	log.SetOutput(&logs)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })
	f := newMeshFix(t, true)
	s := f.s
	secrets := []string{f.apiTok, f.pw, f.cf.nodeToken}
	walk := func(stage string) {
		t.Helper()
		for _, v := range []string{f.apiTok, f.pw} {
			assertNowhereElse(t, s.DataDir, s.secretsDir(), v)
		}
		assertNowhereElse(t, s.DataDir, filepath.Join(s.DataDir, "no-such-dir"), f.cf.nodeToken)
		for _, p := range readOnlyViews {
			noSecretIn(t, stage+": GET "+p, do(s, http.MethodGet, p, nil).Body.String(), secrets...)
		}
	}
	t.Setenv("MERIDIAN_MESH_FAULT_INJECTION", "1")
	rr := do(s, http.MethodPost, "/api/mesh/deploy", []byte(`{"fail_after":"routes"}`))
	if rr.Code != http.StatusBadGateway {
		t.Fatalf("injected failure: %d %s", rr.Code, rr.Body.String())
	}
	noSecretIn(t, "failed deploy", rr.Body.String(), secrets...)
	walk("after a failed deploy")
	rr = do(s, http.MethodPost, "/api/mesh/deploy", []byte(`{}`))
	if rr.Code != 200 {
		t.Fatalf("deploy: %d %s", rr.Code, rr.Body.String())
	}
	noSecretIn(t, "deploy", rr.Body.String(), secrets...)
	walk("after deploy")
	rr = do(s, http.MethodPost, "/api/mesh/withdraw", nil)
	if rr.Code != 200 || !strings.Contains(rr.Body.String(), `"state":"withdrawn"`) {
		t.Fatalf("withdraw: %d %s", rr.Code, rr.Body.String())
	}
	noSecretIn(t, "withdraw", rr.Body.String(), secrets...)
	walk("after withdraw")
	noSecretIn(t, "logs", logs.String(), secrets...)
}

// Device create → regenerate → install: device private keys exist only in
// the one-time responses — not in secrets/, the data directory, the
// installed host tree or the logs; the new PSK is in secrets/ and the
// installed mra.conf only; the old PSK and old device key are gone.
func TestRegeneratedDeviceKeysAreNeverStored(t *testing.T) {
	var logs bytes.Buffer
	log.SetOutput(&logs)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })
	s, host, _ := installTest(t)
	raCall(t, s, http.MethodPut, "/api/remote-access", `{"enabled":true,"endpoint":"home.example.net","listen_port":51900}`, 200)
	phone := raCall(t, s, http.MethodPost, "/api/remote-access/devices", `{"name":"phone"}`, 201)
	oldPriv := cfgPrivate.FindStringSubmatch(phone.Config.Text)[1]
	oldPSK := cfgPSK.FindStringSubmatch(phone.Config.Text)[1]
	if rr := do(s, http.MethodPost, "/api/apply", []byte(`{"install":true}`)); rr.Code != 200 {
		t.Fatal(rr.Body.String())
	}
	re := raCall(t, s, http.MethodPost, "/api/remote-access/devices/"+phone.Device.ID+"/regenerate", "", 200)
	newPriv := cfgPrivate.FindStringSubmatch(re.Config.Text)[1]
	newPSK := cfgPSK.FindStringSubmatch(re.Config.Text)[1]
	rr := do(s, http.MethodPost, "/api/apply", []byte(`{"install":true}`))
	if rr.Code != 200 {
		t.Fatal(rr.Body.String())
	}
	noSecretIn(t, "install response", rr.Body.String(), oldPriv, newPriv, oldPSK, newPSK)
	for _, p := range readOnlyViews {
		noSecretIn(t, "GET "+p, do(s, http.MethodGet, p, nil).Body.String(), oldPriv, newPriv, oldPSK, newPSK)
	}
	none := filepath.Join(s.DataDir, "no-such-dir")
	for _, v := range []string{oldPriv, newPriv} {
		assertNowhereElse(t, s.DataDir, none, v) // secrets/ included
		assertNowhereElse(t, host, none, v)
	}
	assertNowhereElse(t, s.DataDir, s.secretsDir(), newPSK)
	mra, err := os.ReadFile(filepath.Join(host, "etc", "wireguard", "mra.conf"))
	if err != nil || !strings.Contains(string(mra), newPSK) || strings.Contains(string(mra), oldPSK) || !strings.Contains(string(mra), re.Device.PublicKey) {
		t.Fatalf("installed mra.conf does not carry the regenerated peer: %v", err)
	}
	noSecretIn(t, "logs", logs.String(), oldPriv, newPriv, oldPSK, newPSK)
}

// SOCKS credentials of external exits: write-only through the API; a
// topology naming an unknown credential is not saved; a referenced one is
// not deleted; the material reaches no view, compile output, diff or file
// outside secrets/ (it is injected only into a carrier's provision script).
func TestSOCKSCredentialSeams(t *testing.T) {
	var logs bytes.Buffer
	log.SetOutput(&logs)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })
	s := newTest(t)
	user, pass := "su-"+rnd(t, 6), "sp-"+rnd(t, 8)
	secrets := []string{user, pass}
	rr := do(s, http.MethodPost, "/api/socks-credentials", mustJSON(map[string]any{"name": "路由器", "username": user, "password": pass}))
	if rr.Code != http.StatusCreated {
		t.Fatalf("create %d %s", rr.Code, rr.Body.String())
	}
	noSecretIn(t, "socks credential create", rr.Body.String(), secrets...)
	var c struct {
		Credential struct {
			ID        string `json:"id"`
			SecretSet bool   `json:"secret_set"`
		}
	}
	decode(t, rr, &c)
	if c.Credential.ID == "" || !c.Credential.SecretSet {
		t.Fatalf("credential %+v", c)
	}
	// A bad password is refused without being echoed.
	bad := "bad pass@" + rnd(t, 4)
	rr = do(s, http.MethodPost, "/api/socks-credentials", mustJSON(map[string]any{"name": "x", "username": "u", "password": bad}))
	if rr.Code < 400 || strings.Contains(rr.Body.String(), bad) {
		t.Fatalf("bad password: %d %s", rr.Code, rr.Body.String())
	}

	// The external example with an unknown credential is refused; with the
	// stored one it is saved.
	topo := defaults.ExternalExample()
	for i := range topo.Nodes {
		if topo.Nodes[i].External != nil {
			topo.Nodes[i].External.CredentialID = "socks-000000000000"
		}
	}
	raw, _ := json.Marshal(topo)
	rr = do(s, http.MethodPut, "/api/topology", raw)
	if rr.Code < 400 || !strings.Contains(rr.Body.String(), "external_credential_missing") {
		t.Fatalf("unknown credential saved: %d %s", rr.Code, rr.Body.String())
	}
	for i := range topo.Nodes {
		if topo.Nodes[i].External != nil {
			topo.Nodes[i].External.CredentialID = c.Credential.ID
		}
	}
	raw, _ = json.Marshal(topo)
	if rr = do(s, http.MethodPut, "/api/topology", raw); rr.Code != 200 {
		t.Fatalf("save: %d %s", rr.Code, rr.Body.String())
	}
	// Deleting it now is refused, naming the exit.
	rr = do(s, http.MethodDelete, "/api/socks-credentials/"+c.Credential.ID, nil)
	if rr.Code != http.StatusConflict || !strings.Contains(rr.Body.String(), "my1") {
		t.Fatalf("delete in use: %d %s", rr.Code, rr.Body.String())
	}
	views := append([]string{"/api/socks-credentials"}, readOnlyViews...)
	for _, p := range views {
		noSecretIn(t, p, do(s, http.MethodGet, p, nil).Body.String(), secrets...)
	}
	for _, p := range []string{"/api/compile", "/api/diff"} {
		rr := do(s, http.MethodPost, p, []byte(`{}`))
		noSecretIn(t, p, rr.Body.String(), secrets...)
	}
	if rr := do(s, http.MethodPost, "/api/compile", []byte(`{}`)); !strings.Contains(rr.Body.String(), "__MERIDIAN_SECRET_"+c.Credential.ID+"-pass__") {
		t.Fatalf("compile output lacks the placeholder: %.300s", rr.Body.String())
	}
	_ = filepath.Walk(s.DataDir, func(p string, fi os.FileInfo, err error) error {
		if err != nil || fi.IsDir() || strings.Contains(p, string(filepath.Separator)+"secrets"+string(filepath.Separator)) {
			return nil
		}
		b, _ := os.ReadFile(p)
		noSecretIn(t, p, string(b), secrets...)
		return nil
	})
	noSecretIn(t, "logs", logs.String(), secrets...)
	// With no exit using it, it can be deleted.
	topo.Nodes = topo.Nodes[:len(topo.Nodes)-1]
	topo.Groups = topo.Groups[:1]
	topo.Rules = topo.Rules[:1]
	raw, _ = json.Marshal(topo)
	if rr = do(s, http.MethodPut, "/api/topology", raw); rr.Code != 200 {
		t.Fatalf("save without the exit: %d %s", rr.Code, rr.Body.String())
	}
	if rr = do(s, http.MethodDelete, "/api/socks-credentials/"+c.Credential.ID, nil); rr.Code != 200 {
		t.Fatalf("delete: %d %s", rr.Code, rr.Body.String())
	}
}
