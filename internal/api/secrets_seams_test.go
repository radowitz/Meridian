package api

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/radowitz/meridian/internal/compile"
	"github.com/radowitz/meridian/internal/defaults"
	"github.com/radowitz/meridian/internal/dnsjournal"
	"github.com/radowitz/meridian/internal/hostexec"
	"github.com/radowitz/meridian/internal/linkjournal"
	"github.com/radowitz/meridian/internal/model"
	"github.com/radowitz/meridian/internal/preflight"
	"github.com/radowitz/meridian/internal/provision"
	"github.com/radowitz/meridian/internal/sniff"
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
	rr := do(s, http.MethodPost, "/api/mesh/deploy", []byte(`{"fail_after":"install","confirm_install":true}`))
	if rr.Code != http.StatusBadGateway {
		t.Fatalf("injected failure: %d %s", rr.Code, rr.Body.String())
	}
	noSecretIn(t, "failed deploy", rr.Body.String(), secrets...)
	walk("after a failed deploy")
	rr = do(s, http.MethodPost, "/api/mesh/deploy", []byte(`{"confirm_install":true}`))
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
	raCall(t, s, http.MethodPut, "/api/remote-access", `{"enabled":true,"endpoint":"home.example.net","listen_port":51999}`, 200)
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
	if rr.Code != http.StatusConflict || !strings.Contains(rr.Body.String(), "myext") {
		t.Fatalf("delete in use: %d %s", rr.Code, rr.Body.String())
	}
	// check: the material is in no view, compile output, diff, plan, file
	// outside secrets/ or log; compile output carries the placeholder and
	// the credential's version (a counter, socks_version.go).
	check := func(version int) {
		t.Helper()
		views := append([]string{"/api/socks-credentials", "/api/provision/state", "/api/deploy", "/api/deployments"}, readOnlyViews...)
		for _, p := range views {
			noSecretIn(t, p, do(s, http.MethodGet, p, nil).Body.String(), secrets...)
		}
		for _, p := range []string{"/api/compile", "/api/diff", "/api/validate"} {
			rr := do(s, http.MethodPost, p, []byte(`{}`))
			noSecretIn(t, p, rr.Body.String(), secrets...)
		}
		rr := do(s, http.MethodPost, "/api/compile", []byte(`{}`))
		if !strings.Contains(rr.Body.String(), "__MERIDIAN_SECRET_"+c.Credential.ID+"-pass__") {
			t.Fatalf("compile output lacks the placeholder: %.300s", rr.Body.String())
		}
		if !strings.Contains(rr.Body.String(), fmt.Sprintf("%s%s=%d ", socksVersionMarker, c.Credential.ID, version)) {
			t.Fatalf("compile output lacks version %d", version)
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
	}
	check(1)
	// Rotated: neither the old nor the new pair appears anywhere, the
	// answer names the carrier that now needs an install, and the index
	// keeps counters only.
	user2, pass2 := "su-"+rnd(t, 6), "sp-"+rnd(t, 8)
	secrets = append(secrets, user2, pass2)
	rr = do(s, http.MethodPut, "/api/socks-credentials/"+c.Credential.ID+"/secret", mustJSON(map[string]any{"username": user2, "password": pass2}))
	if rr.Code != 200 || !strings.Contains(rr.Body.String(), `"pending":["dc2"]`) {
		t.Fatalf("rotate: %d %s", rr.Code, rr.Body.String())
	}
	noSecretIn(t, "socks credential rotate", rr.Body.String(), secrets...)
	check(2)
	idx, err := os.ReadFile(filepath.Join(s.secretsDir(), "index.json"))
	if err != nil || !strings.Contains(string(idx), "socks_version_baseline") {
		t.Fatalf("index: %v", err)
	}
	noSecretIn(t, "credential index", string(idx), secrets...)
	// The old pair is gone from disk altogether, the new one is in
	// secrets/ only.
	none := filepath.Join(s.DataDir, "no-such-dir")
	assertNowhereElse(t, s.DataDir, none, pass)
	assertNowhereElse(t, s.DataDir, s.secretsDir(), pass2)
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

// nodeDigests is the bundle digest of every node of the stored topology
// (the gateway included): what a preflight is reviewed for, what the
// per-node state and the deployment plan compare.
func nodeDigests(t *testing.T, s *Server) map[string]string {
	t.Helper()
	topo, err := s.topology()
	if err != nil {
		t.Fatal(err)
	}
	b, err := s.compileTopo(topo)
	if err != nil {
		t.Fatalf("%v: %s", err, do(s, http.MethodPost, "/api/validate", []byte(`{}`)).Body.String())
	}
	out := map[string]string{}
	for _, n := range topo.Nodes {
		if files := provision.FilesFor(b.Files, n.ID); len(files) > 0 {
			out[n.ID] = preflight.BundleDigest(files)
		}
	}
	return out
}

// changedNodes lists the nodes whose digest differs between a and b.
func changedNodes(a, b map[string]string) string {
	var out []string
	for id, d := range b {
		if a[id] != d {
			out = append(out, id)
		}
	}
	for id := range a {
		if _, ok := b[id]; !ok {
			out = append(out, id+" (gone)")
		}
	}
	sort.Strings(out)
	return strings.Join(out, " ")
}

// The secrets and the three journals together, on one gateway with an
// external SOCKS exit, an encrypted exit upstream with an account
// identifier, the forwarder with name recording and the query journal on:
//
//   - a secret (the SOCKS username and password before and after a
//     rotation, the DNS account identifier) is in no view, compile output,
//     diff, validation, preflight, install report, export, stored
//     document, file outside secrets/ or panel log — and in no journal
//     answer either;
//   - journal content (a query's name, a link event's evidence, a
//     connection's name, a device's MAC) is in the journals' own answers
//     and nowhere else: no configuration or status view, no compile
//     output, no diff, no preflight or install report, no export, no
//     stored document, no file on the host or in the data directory, no
//     panel log;
//   - no node's digest depends on a journal being read or growing; turning
//     the query journal on changes the gateway's digest only; a SOCKS
//     rotation changes the carrier's digest only, by the credential's
//     version (a counter: rotating to the same values changes it again),
//     never by the material.
func TestSecretsAndJournalsStayInTheirChannels(t *testing.T) {
	s := newTest(t)
	s.HostRoot = t.TempDir()
	// The host agent's stand-in of the demo rig: every action succeeds and an
	// activation of the forwarder reports its self-check.
	s.Host, s.HostPreflight = demoHost{root: s.HostRoot}, &fakeHostPreflight{}
	var logs bytes.Buffer
	log.SetOutput(&logs)
	defer log.SetOutput(os.Stderr)

	// --- secrets: a SOCKS credential and a DNS account identifier.
	user, pass := "su-"+rnd(t, 8), "sp-"+rnd(t, 10)
	account := "acct" + rnd(t, 10)
	secrets := []string{user, pass, account}
	var sc, da struct {
		Credential struct{ ID string }
		Account    struct{ ID string }
	}
	decode(t, do(s, http.MethodPost, "/api/socks-credentials", mustJSON(map[string]any{"name": "路由器", "username": user, "password": pass})), &sc)
	decode(t, do(s, http.MethodPost, "/api/dns-accounts", mustJSON(map[string]any{"name": "示例加密解析服务", "account": account})), &da)
	if sc.Credential.ID == "" || da.Account.ID == "" {
		t.Fatalf("credentials: %+v %+v", sc, da)
	}
	topo := defaults.ExternalExample()
	for i := range topo.Nodes {
		if topo.Nodes[i].External != nil {
			topo.Nodes[i].External.CredentialID = sc.Credential.ID
		}
	}
	if rr := do(s, http.MethodPut, "/api/topology", mustJSON(topo)); rr.Code != 200 {
		t.Fatalf("save: %d %s", rr.Code, rr.Body.String())
	}
	withPeerKeys(t, s)
	// An external exit has no key of its own.
	if _, err := s.Store.Update(func(tp *model.Topology) (bool, error) {
		for i := range tp.Nodes {
			if tp.Nodes[i].External != nil {
				tp.Nodes[i].PublicKey = ""
			}
		}
		return true, nil
	}); err != nil {
		t.Fatal(err)
	}
	if rr := do(s, http.MethodPut, "/api/sniff", mustJSON(map[string]any{"enabled": true, "record_names": true})); rr.Code != 200 {
		t.Fatalf("sniff: %d %s", rr.Code, rr.Body.String())
	}
	if rr := do(s, http.MethodPut, "/api/dns/upstream", mustJSON(map[string]any{"global": map[string]any{"protocol": "dot", "addresses": []string{"192.0.2.153"},
		"tls_host_name": "{account}.dns.example.net", "account_credential": da.Account.ID}})); rr.Code != 200 {
		t.Fatalf("upstream: %d %s", rr.Code, rr.Body.String())
	}

	// --- journals: synthetic queries, link events and connections behind
	// the host agent's requests, each with a marker of its own.
	qMark, eMark, cMark, mac := "q-"+rnd(t, 8), "e-"+rnd(t, 8), "c-"+rnd(t, 8), "02:00:5e:"+strings.ToLower(rndHexPairs(t))
	now := time.Now().UTC().Truncate(time.Second)
	dj, err := dnsjournal.Open(dnsjournal.Config{Dir: filepath.Join(t.TempDir(), "dns")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(dj.Close)
	query := func(ago time.Duration, n int) {
		dj.Add(dnsjournal.Record{Time: now.Add(-ago), Client: "192.0.2.10", MAC: mac, Name: fmt.Sprintf("%s-%d.example.com", qMark, n), QType: 1, Result: dnsjournal.ResultAnswered, Group: "default", ElapsedMS: 3, Answers: 1})
		dj.Flush()
	}
	query(40*time.Second, 1)
	lj, err := linkjournal.Open(linkjournal.Options{Dir: filepath.Join(t.TempDir(), "link")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(lj.Close)
	observe := func(ago time.Duration, state string) {
		lj.Observe(now.Add(-ago), []linkjournal.Observation{{Class: linkjournal.ClassExternalExit, Kind: linkjournal.KindExternal, ID: "myext", Label: "外部出口 myext", State: state,
			Source: linkjournal.SourceSelfCheck, Evidence: eMark + " " + state}})
	}
	observe(3*time.Minute, linkjournal.CheckOK)
	observe(2*time.Minute, linkjournal.CheckFailed)
	cj, err := sniff.OpenJournal(sniff.JournalConfig{Dir: filepath.Join(t.TempDir(), "conn"), RecordNames: true})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(cj.Close)
	connect := func(ago time.Duration, n int) {
		cj.Add(sniff.ConnRecord{Start: now.Add(-ago), Source: "192.0.2.10", MAC: mac, Dest: "198.51.100.7:443", Proto: "tls", Name: fmt.Sprintf("%s-%d.example.net", cMark, n), Sniffed: true, By: "name",
			Target: "direct", Result: sniff.ResultOK, End: sniff.EndClientClosed, DurationMS: 900, Conn: uint64(n)})
		cj.Flush()
	}
	connect(38*time.Second, 1)
	s.DNSLog = &fakeDNSLog{st: verifiedStatus(), j: dj}
	s.LinkLog = &fakeLinkLog{j: lj, st: hostexec.LinkJournalStatus{ReadAt: now.Format(time.RFC3339), UnitActive: "active", Present: true, ConfigInstalled: true, Health: json.RawMessage(`{"ready":true}`)}}
	s.Sniff = &demoSniff{j: cj, st: hostexec.SniffStatus{Present: true, Active: "active", ReadAt: now.Format(time.RFC3339)}}
	content := []string{qMark, eMark, cMark, mac}

	// The journals' own answers: where the content belongs.
	at := now.Add(-39 * time.Second).Format(time.RFC3339)
	own := map[string]string{
		"/api/dns-log/journal":                                  qMark,
		"/api/dns-log/devices":                                  qMark,
		"/api/sniff/journal/related?device=192.0.2.10&at=" + at: qMark,
		"/api/sniff/journal":                                    cMark,
		"/api/sniff/devices":                                    mac,
		"/api/dns-log/related?device=192.0.2.10&at=" + at:       cMark,
		"/api/link-log/current":                                 eMark,
		"/api/link-log/events":                                  eMark,
	}
	readOwn := func() {
		t.Helper()
		for p, want := range own {
			rr := do(s, http.MethodGet, p, nil)
			if rr.Code != 200 || !strings.Contains(rr.Body.String(), want) {
				t.Fatalf("%s does not show its journal's content: %d %.300s", p, rr.Code, rr.Body.String())
			}
			noSecretIn(t, p, rr.Body.String(), secrets...)
		}
	}
	// Everything else. Secrets are looked for everywhere; journal content
	// everywhere but in the journals' own answers.
	views := append([]string{"/api/socks-credentials", "/api/dns-accounts", "/api/dns", "/api/dns/config?node=dc2", "/api/dns/config?node=gw", "/api/provision/state", "/api/deploy", "/api/deployments", "/api/host",
		"/api/artifacts", "/api/upstream", "/api/sniff", "/api/dns-log", "/api/link-log", "/api/rules/analysis", "/api/wss", "/api/region-groups", "/api/unlock"}, readOnlyViews...)
	scan := func(what, body string) {
		t.Helper()
		noSecretIn(t, what, body, secrets...)
		for _, c := range content {
			if strings.Contains(body, c) {
				t.Errorf("%s carries journal content (%s…)", what, c[:2])
			}
		}
	}
	scanAll := func(stage string) {
		t.Helper()
		for _, p := range views {
			scan(stage+": GET "+p, do(s, http.MethodGet, p, nil).Body.String())
		}
		for _, p := range []string{"/api/compile", "/api/diff", "/api/validate", "/api/topology/allocations"} {
			scan(stage+": POST "+p, do(s, http.MethodPost, p, []byte(`{}`)).Body.String())
		}
		for _, key := range []string{"topology", preflightKey(localNodeID)} {
			raw, _, _ := s.Store.Get(key)
			scan(stage+": stored "+key, raw)
		}
		for _, root := range []string{s.HostRoot, s.DataDir} {
			_ = filepath.Walk(root, func(p string, fi os.FileInfo, err error) error {
				if err != nil || !fi.Mode().IsRegular() || strings.Contains(p, string(filepath.Separator)+"secrets"+string(filepath.Separator)) {
					return nil
				}
				if b, err := os.ReadFile(p); err == nil {
					scan(stage+": file "+p, string(b))
				}
				return nil
			})
		}
		scan(stage+": panel log", logs.String())
	}

	// A preflight and an install of the gateway, and what they answer.
	install := func(stage string) {
		t.Helper()
		rr := do(s, http.MethodPost, "/api/host/preflight", nil)
		scan(stage+": POST /api/host/preflight", rr.Body.String())
		var pf struct{ Preflight preflightRecord }
		decode(t, rr, &pf)
		rr = do(s, http.MethodPost, "/api/apply", mustJSON(map[string]any{"install": true, "preflight_id": pf.Preflight.ID}))
		if rr.Code != 200 {
			t.Fatalf("%s: install: %d %s", stage, rr.Code, rr.Body.String())
		}
		scan(stage+": POST /api/apply", rr.Body.String())
	}
	// The first install creates the gateway's key and the WSS material its
	// peers' files name: the digests are compared from here on.
	install("first install")

	// --- reading the journals, and the journals growing, change no digest.
	d0 := nodeDigests(t, s)
	if len(d0) < 5 || d0["gw"] == "" || d0["dc2"] == "" {
		t.Fatalf("digests %v", d0)
	}
	readOwn()
	scanAll("journals read")
	query(20*time.Second, 2)
	connect(18*time.Second, 2)
	observe(time.Minute, linkjournal.CheckOK)
	if rr := do(s, http.MethodPut, "/api/sniff/devices/192.0.2.10/label", mustJSON(map[string]string{"label": "示例设备"})); rr.Code != 200 {
		t.Fatalf("label: %d %s", rr.Code, rr.Body.String())
	}
	readOwn()
	if diff := changedNodes(d0, nodeDigests(t, s)); diff != "" {
		t.Fatalf("reading the journals, new records or a device label changed the digest of: %s", diff)
	}

	// --- the query journal on: the gateway's digest only.
	if rr := do(s, http.MethodPut, "/api/dns-log", []byte(`{"enabled":true,"acknowledge":true}`)); rr.Code != 200 {
		t.Fatalf("dns-log on: %d %s", rr.Code, rr.Body.String())
	}
	d1 := nodeDigests(t, s)
	if diff := changedNodes(d0, d1); diff != "gw" {
		t.Fatalf("turning the query journal on changed the digest of %q, want the gateway only", diff)
	}
	// The install that puts the query journal's reader on the host.
	install("journal on")
	readOwn()
	scanAll("installed")
	if diff := changedNodes(d1, nodeDigests(t, s)); diff != "" {
		t.Fatalf("the install changed the digest of: %s", diff)
	}

	// --- a SOCKS rotation: the carrier's digest only, by the version.
	gost := func() string {
		t.Helper()
		tp, _ := s.topology()
		b, err := s.compileTopo(tp)
		if err != nil {
			t.Fatal(err)
		}
		return b.Files["nodes/dc2"+compile.ExtProxyConfig]
	}
	versionLine := func(v int) string { return fmt.Sprintf("%s%s=%d ", socksVersionMarker, sc.Credential.ID, v) }
	if !strings.Contains(gost(), versionLine(1)) {
		t.Fatalf("the carrier's config lacks version 1: %.200s", gost())
	}
	user2, pass2 := "su-"+rnd(t, 8), "sp-"+rnd(t, 10)
	secrets = append(secrets, user2, pass2)
	rotate := func(u, p string) {
		t.Helper()
		rr := do(s, http.MethodPut, "/api/socks-credentials/"+sc.Credential.ID+"/secret", mustJSON(map[string]any{"username": u, "password": p}))
		if rr.Code != 200 {
			t.Fatalf("rotate: %d %s", rr.Code, rr.Body.String())
		}
		scan("SOCKS rotation answer", rr.Body.String())
	}
	rotate(user2, pass2)
	d2 := nodeDigests(t, s)
	if diff := changedNodes(d1, d2); diff != "dc2" || !strings.Contains(gost(), versionLine(2)) {
		t.Fatalf("the rotation changed the digest of %q (want the carrier dc2 only, by version 2)", diff)
	}
	// The same values again: the digest follows the counter, not the material.
	rotate(user2, pass2)
	d3 := nodeDigests(t, s)
	if diff := changedNodes(d2, d3); diff != "dc2" || !strings.Contains(gost(), versionLine(3)) {
		t.Fatalf("rotating to the same values changed the digest of %q (want dc2 only, by version 3)", diff)
	}
	// What differs in the carrier's config between the versions is that one line.
	if g := gost(); strings.Count(g, "__MERIDIAN_SECRET_"+sc.Credential.ID+"-") != 2 || strings.Count(g, socksVersionMarker) != 1 {
		t.Fatalf("the carrier's config after two rotations: %.300s", g)
	}
	readOwn()
	scanAll("rotated")
	// The credential index keeps counters only; the old pair is gone from
	// disk, the new one is in secrets/ alone.
	idx, err := os.ReadFile(filepath.Join(s.secretsDir(), "index.json"))
	if err != nil {
		t.Fatal(err)
	}
	noSecretIn(t, "credential index", string(idx), secrets...)
	assertNowhereElse(t, s.DataDir, filepath.Join(s.DataDir, "no-such-dir"), pass)
	assertNowhereElse(t, s.DataDir, s.secretsDir(), pass2)
}

// rndHexPairs is three random hex pairs "aa:bb:cc".
func rndHexPairs(t *testing.T) string {
	t.Helper()
	b := make([]byte, 3)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return fmt.Sprintf("%02x:%02x:%02x", b[0], b[1], b[2])
}
