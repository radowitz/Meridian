package api

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/radowitz/meridian/internal/credentials"
	"github.com/radowitz/meridian/internal/hostexec"
	"github.com/radowitz/meridian/internal/model"
	"github.com/radowitz/meridian/internal/sshexec"
	"github.com/radowitz/meridian/internal/sshexec/sshtest"
)

func startSSH(t *testing.T) *sshtest.Server {
	t.Helper()
	srv, err := sshtest.Start()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(srv.Close)
	srv.SetHandler(func(cmd, stdin string) (string, uint32) {
		if cmd == sshexec.TestCommand {
			return "MERIDIAN_ARCH=aarch64\nMERIDIAN_KERNEL=6.12.1\nPRETTY_NAME=\"Debian GNU/Linux 13 (trixie)\"\n", 0
		}
		if cmd == "bash -s" && strings.Contains(stdin, "echo MERIDIAN_PROVISION_OK") {
			return "MERIDIAN_PROVISION_OK\n", 0
		}
		return "unexpected", 1
	})
	return srv
}

// The full path of a new server through the API: credential, server,
// discovery (no authentication), explicit trust, connection test, then a
// provision that runs over the stored credential. Nothing runs before the
// key is trusted; a changed host key is refused before authentication.
func TestServerReadinessAndProvisionOverPassword(t *testing.T) {
	var logs bytes.Buffer
	log.SetOutput(&logs)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })
	s := newTest(t)
	do(s, http.MethodGet, "/api/topology", nil)
	srv := startSSH(t)
	pw := "pw-" + rnd(t, 6)
	srv.SetPassword(pw)

	rr := do(s, http.MethodPost, "/api/ssh-credentials", mustJSON(map[string]any{"name": "运维密码", "kind": "password", "password": pw}))
	var c struct{ Credential credView }
	decode(t, rr, &c)
	rr = do(s, http.MethodPost, "/api/servers", mustJSON(map[string]any{"name": "台湾出口", "address": srv.Host, "port": srv.Port, "user": "ops", "auth": "password", "credential_id": c.Credential.ID}))
	var sv struct{ Server serverView }
	decode(t, rr, &sv)
	id := sv.Server.ID
	topo, _, _ := s.Store.Load()
	for i := range topo.Nodes {
		if topo.Nodes[i].ID == "tw" {
			topo.Nodes[i].ServerID, topo.Nodes[i].SSHHost, topo.Nodes[i].SSHPort, topo.Nodes[i].SSHUser = id, "", 0, ""
		}
	}
	if err := s.Store.Save(topo); err != nil {
		t.Fatal(err)
	}

	// Untrusted: test and provision refused, no key generated, no login.
	rr = do(s, http.MethodPost, "/api/servers/"+id+"/test", nil)
	if code, _ := errCode(t, rr); rr.Code != http.StatusConflict || code != sshexec.CodeUntrusted {
		t.Fatalf("test untrusted: %d %s", rr.Code, rr.Body.String())
	}
	rr = do(s, http.MethodPost, "/api/provision", []byte(`{"node_id":"tw","generate_keys":true}`))
	if code, _ := errCode(t, rr); rr.Code != http.StatusConflict || code != sshexec.CodeUntrusted {
		t.Fatalf("provision untrusted: %d %s", rr.Code, rr.Body.String())
	}
	if storedNode(t, s, "tw").PrivateKey != "" || srv.AuthAttempts() != 0 {
		t.Fatal("refused provision generated a key or logged in")
	}

	// Discovery reads the key without authenticating.
	rr = do(s, http.MethodPost, "/api/servers/"+id+"/host-key/discover", nil)
	var disc struct {
		Discovery sshexec.Discovery
		Server    serverView
	}
	decode(t, rr, &disc)
	if rr.Code != 200 || disc.Discovery.Fingerprint != srv.Fingerprint() || disc.Server.HostKey.State != model.HostKeyDiscovered || srv.AuthAttempts() != 0 {
		t.Fatalf("discover: %d %s", rr.Code, rr.Body.String())
	}
	if rr = do(s, http.MethodPost, "/api/servers/"+id+"/host-key/trust", mustJSON(map[string]string{"fingerprint": disc.Discovery.Fingerprint})); rr.Code != 200 {
		t.Fatal(rr.Body.String())
	}
	rr = do(s, http.MethodPost, "/api/servers/"+id+"/test", nil)
	var tr struct {
		Test   model.ConnectionTest
		Server serverView
	}
	decode(t, rr, &tr)
	if rr.Code != 200 || !tr.Test.OK || tr.Test.AuthMethod != "password" || tr.Test.Arch != "aarch64" || !tr.Server.Ready || len(tr.Server.Missing) != 0 {
		t.Fatalf("test: %d %s", rr.Code, rr.Body.String())
	}

	rr = do(s, http.MethodPost, "/api/provision", []byte(`{"node_id":"tw","generate_keys":true}`))
	tw := storedNode(t, s, "tw")
	if rr.Code != 200 || !strings.Contains(rr.Body.String(), "MERIDIAN_PROVISION_OK") || !strings.Contains(rr.Body.String(), `"auth_method":"password"`) ||
		!strings.Contains(rr.Body.String(), tw.PublicKey) {
		t.Fatalf("provision: %d %s", rr.Code, rr.Body.String())
	}
	if strings.Contains(rr.Body.String(), tw.PrivateKey) || strings.Contains(rr.Body.String(), pw) {
		t.Fatal("secret in provision response")
	}
	cmds, stdins := srv.Commands(), srv.Stdins()
	if cmds[len(cmds)-1] != "bash -s" || !strings.Contains(stdins[len(stdins)-1], tw.PrivateKey) {
		t.Fatal("script with the injected key was not sent on stdin")
	}

	// Rotating the credential clears the last test (no longer ready).
	if rr = do(s, http.MethodPut, "/api/ssh-credentials/"+c.Credential.ID+"/secret", mustJSON(map[string]string{"password": pw + "x"})); rr.Code != 200 {
		t.Fatal(rr.Body.String())
	}
	rr = do(s, http.MethodGet, "/api/servers/"+id, nil)
	decode(t, rr, &sv)
	if sv.Server.LastTest != nil || sv.Server.Ready || !sv.Server.Operable {
		t.Fatalf("after rotation: %s", rr.Body.String())
	}

	// The host is "reinstalled": refused before authentication, pin kept.
	srv.SetHostKey(sshtest.NewHostKey())
	attempts := srv.AuthAttempts()
	rr = do(s, http.MethodPost, "/api/provision", []byte(`{"node_id":"tw"}`))
	if code, _ := errCode(t, rr); rr.Code != http.StatusConflict || code != credentials.CodeHostKeyMismatch || srv.AuthAttempts() != attempts {
		t.Fatalf("mismatch: %d %s", rr.Code, rr.Body.String())
	}
	rr = do(s, http.MethodGet, "/api/servers/"+id, nil)
	decode(t, rr, &sv)
	if sv.Server.HostKey.State != model.HostKeyMismatch || sv.Server.HostKey.Fingerprint != disc.Discovery.Fingerprint {
		t.Fatalf("pin: %+v", sv.Server.HostKey)
	}
	if strings.Contains(logs.String(), pw) || strings.Contains(logs.String(), tw.PrivateKey) {
		t.Fatal("secret in logs")
	}
	// The connection test records the refusal as its result.
	rr = do(s, http.MethodPost, "/api/servers/"+id+"/test", nil)
	decode(t, rr, &tr)
	if rr.Code != 200 || tr.Test.OK || tr.Test.Code != credentials.CodeHostKeyMismatch || srv.AuthAttempts() != attempts {
		t.Fatalf("test on mismatch: %d %s", rr.Code, rr.Body.String())
	}
}

func TestConnectionTestOverKey(t *testing.T) {
	s := newTest(t)
	srv := startSSH(t)
	pass := "pp-" + rnd(t, 4)
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	blk, err := ssh.MarshalPrivateKeyWithPassphrase(priv, "", []byte(pass))
	if err != nil {
		t.Fatal(err)
	}
	signer, _ := ssh.NewSignerFromKey(priv)
	srv.SetAuthorizedKey(signer.PublicKey())
	pemText := string(pem.EncodeToMemory(blk))
	rr := do(s, http.MethodPost, "/api/ssh-credentials", mustJSON(map[string]any{"name": "钥匙", "kind": "private_key", "private_key": pemText, "passphrase": pass}))
	var c struct{ Credential credView }
	decode(t, rr, &c)
	rr = do(s, http.MethodPost, "/api/servers", mustJSON(map[string]any{"name": "k", "address": srv.Host, "port": srv.Port, "auth": "key", "credential_id": c.Credential.ID}))
	var sv struct{ Server serverView }
	decode(t, rr, &sv)
	do(s, http.MethodPost, "/api/servers/"+sv.Server.ID+"/host-key/discover", nil)
	do(s, http.MethodPost, "/api/servers/"+sv.Server.ID+"/host-key/trust", mustJSON(map[string]string{"fingerprint": srv.Fingerprint()}))
	rr = do(s, http.MethodPost, "/api/servers/"+sv.Server.ID+"/test", nil)
	if rr.Code != 200 || !strings.Contains(rr.Body.String(), `"ok":true`) || !strings.Contains(rr.Body.String(), `"auth_method":"key"`) || strings.Contains(rr.Body.String(), pass) {
		t.Fatalf("%d %s", rr.Code, rr.Body.String())
	}
}

// ------------------------------------------------- Cloudflare check ---

type cfFake struct {
	mu      sync.Mutex
	token   string
	acct    string
	verify  int // status of account verify (0 = active)
	nodes   int
	routes  int
	methods []string
}

func (f *cfFake) handler(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	f.methods = append(f.methods, r.Method+" "+r.URL.Path)
	f.mu.Unlock()
	fail := func(code int, msg string) {
		w.WriteHeader(code)
		_ = json.NewEncoder(w).Encode(map[string]any{"success": false, "errors": []map[string]any{{"code": 10000, "message": msg}}, "result": nil})
	}
	ok := func(v any) {
		_ = json.NewEncoder(w).Encode(map[string]any{"success": true, "errors": []any{}, "result": v})
	}
	if r.Header.Get("Authorization") != "Bearer "+f.token {
		fail(401, "Authentication error")
		return
	}
	base := "/client/v4/accounts/" + f.acct
	switch r.URL.Path {
	case base + "/tokens/verify":
		if f.verify != 0 {
			fail(f.verify, "Invalid API Token")
			return
		}
		ok(map[string]any{"id": "abc", "status": "active"})
	case "/client/v4/user/tokens/verify":
		fail(401, "Invalid API Token")
	case base + "/warp_connector":
		if f.nodes != 0 {
			fail(f.nodes, "Authorization error")
			return
		}
		ok([]any{})
	case base + "/teamnet/routes":
		if f.routes != 0 {
			fail(f.routes, "Authorization error")
			return
		}
		ok([]any{})
	default:
		fail(404, "not found")
	}
}

func TestCloudflarePermissionCheck(t *testing.T) {
	s := newTest(t)
	acct, tok := rnd(t, 16), "cfapitoken_"+rnd(t, 16)
	fake := &cfFake{token: tok, acct: acct}
	ts := httptest.NewServer(http.HandlerFunc(fake.handler))
	defer ts.Close()
	s.CloudflareAPIBase = ts.URL + "/client/v4"
	rr := do(s, http.MethodPost, "/api/cloudflare/accounts", mustJSON(map[string]string{"name": "a", "account_id": acct, "api_token": tok}))
	var a struct{ Account accountView }
	decode(t, rr, &a)

	check := func() credentials.PermissionCheck {
		t.Helper()
		rr := do(s, http.MethodPost, "/api/cloudflare/accounts/"+a.Account.ID+"/check", nil)
		if rr.Code != 200 || strings.Contains(rr.Body.String(), tok) {
			t.Fatalf("%d %s", rr.Code, rr.Body.String())
		}
		var out struct {
			Check   credentials.PermissionCheck
			Account accountView
		}
		decode(t, rr, &out)
		if out.Account.PermissionCheck == nil || out.Account.PermissionCheck.OK != out.Check.OK {
			t.Fatal("result not recorded on the account")
		}
		return out.Check
	}
	pc := check()
	if !pc.OK || pc.TokenStatus != "active" || pc.TokenKind != "account" || len(pc.Confirmed) != 3 || len(pc.Unconfirmed) == 0 || len(pc.Missing) != 0 {
		t.Fatalf("all good: %+v", pc)
	}
	for _, m := range fake.methods {
		if !strings.HasPrefix(m, "GET ") {
			t.Fatalf("check made a non-GET call: %s", m)
		}
	}
	fake.routes = 403
	pc = check()
	if pc.OK || strings.Join(pc.Missing, ",") != "Cloudflare One Networks Write" {
		t.Fatalf("routes denied: %+v", pc)
	}
	// A token Cloudflare does not accept.
	fake.token = "cfapitoken_" + rnd(t, 16)
	pc = check()
	if pc.OK || len(pc.Missing) != 3 || pc.Checks[0].Status != "denied" {
		t.Fatalf("bad token: %+v", pc)
	}
	// Unreachable API: errors, not "missing".
	ts.Close()
	pc = check()
	if pc.OK || len(pc.Missing) != 0 || pc.Checks[0].Status != "error" {
		t.Fatalf("unreachable: %+v", pc)
	}
	idx, _ := os.ReadFile(filepath.Join(s.secretsDir(), "index.json"))
	if strings.Contains(string(idx), tok) {
		t.Fatal("token in the index")
	}
	rr = do(s, http.MethodGet, "/api/cloudflare/requirements", nil)
	if !strings.Contains(rr.Body.String(), "Cloudflare One Connectors Write") || !strings.Contains(rr.Body.String(), "Cloudflare One Networks Write") || !strings.Contains(rr.Body.String(), `"does_not"`) {
		t.Fatal(rr.Body.String())
	}
}

// ----------------------------------------------- remote-access runtime ---

type fakeRemoteStatus struct {
	st  hostexec.WGStatus
	err error
}

func (f *fakeRemoteStatus) RemoteAccessStatus(context.Context) (hostexec.WGStatus, error) {
	return f.st, f.err
}

func TestRemoteAccessRuntime(t *testing.T) {
	s := newTest(t)
	do(s, http.MethodGet, "/api/topology", nil)
	type dev struct {
		ID           string         `json:"id"`
		PublicKey    string         `json:"public_key"`
		Runtime      *deviceRuntime `json:"runtime"`
		RuntimeState string         `json:"runtime_state"`
	}
	type resp struct {
		Devices []dev             `json:"devices"`
		Device  dev               `json:"device"`
		Runtime remoteRuntimeView `json:"runtime"`
	}
	get := func() resp {
		t.Helper()
		rr := do(s, http.MethodGet, "/api/remote-access", nil)
		var out resp
		decode(t, rr, &out)
		return out
	}
	if r := get(); r.Runtime.State != "disabled" || r.Runtime.Available {
		t.Fatalf("%+v", r.Runtime)
	}
	raCall(t, s, http.MethodPut, "/api/remote-access", `{"enabled":true,"endpoint":"home.example.net","listen_port":51900}`, 200)
	var created []dev
	for _, n := range []string{"phone", "laptop", "tablet"} {
		rr := do(s, http.MethodPost, "/api/remote-access/devices", []byte(`{"name":"`+n+`"}`))
		var out resp
		decode(t, rr, &out)
		if out.Device.RuntimeState != "not_read" || out.Device.Runtime != nil {
			t.Fatalf("mutation invented runtime: %+v", out.Device)
		}
		created = append(created, out.Device)
	}
	raCall(t, s, http.MethodPatch, "/api/remote-access/devices/"+created[2].ID, `{"enabled":false}`, 200)

	// No agent configured.
	r := get()
	if r.Runtime.State != "agent_unavailable" || r.Runtime.Available {
		t.Fatalf("%+v", r.Runtime)
	}
	for _, d := range r.Devices {
		if d.Runtime != nil || (d.ID == created[2].ID) != (d.RuntimeState == "disabled") || (d.ID != created[2].ID && d.RuntimeState != "unavailable") {
			t.Fatalf("%+v", d)
		}
	}
	// Agent unreachable.
	s.RemoteStatus = &fakeRemoteStatus{err: fmt.Errorf("%w：没有 socket", hostexec.ErrUnavailable)}
	if r := get(); r.Runtime.State != "agent_unavailable" {
		t.Fatalf("%+v", r.Runtime)
	}
	s.RemoteStatus = &fakeRemoteStatus{err: errors.New("wg show transfer 失败")}
	if r := get(); r.Runtime.State != "error" || r.Devices[0].Runtime != nil {
		t.Fatalf("%+v", r.Runtime)
	}
	// Interface absent (not applied yet).
	s.RemoteStatus = &fakeRemoteStatus{st: hostexec.WGStatus{Interface: "mra", ReadAt: time.Now().UTC().Format(time.RFC3339)}}
	if r := get(); r.Runtime.State != "interface_absent" || r.Devices[0].RuntimeState != "unavailable" {
		t.Fatalf("%+v", r.Runtime)
	}
	// Present: phone shook hands 30 s ago, laptop never, tablet disabled
	// (its peer row, if any, is ignored), and the old phone row from
	// another key is not matched.
	now := time.Now().UTC()
	s.RemoteStatus = &fakeRemoteStatus{st: hostexec.WGStatus{Interface: "mra", Present: true, ReadAt: now.Format(time.RFC3339), Peers: []hostexec.WGPeer{
		{PublicKey: created[0].PublicKey, LatestHandshake: now.Add(-30 * time.Second).Unix(), RxBytes: 1200, TxBytes: 3400},
		{PublicKey: created[1].PublicKey},
		{PublicKey: created[2].PublicKey, LatestHandshake: now.Unix(), RxBytes: 9},
	}}}
	r = get()
	byID := map[string]dev{}
	for _, d := range r.Devices {
		byID[d.ID] = d
	}
	if p := byID[created[0].ID]; p.RuntimeState != "ok" || p.Runtime == nil || !p.Runtime.Online || p.Runtime.RxBytes != 1200 || p.Runtime.TxBytes != 3400 || p.Runtime.LastHandshakeAt == nil {
		t.Fatalf("phone %+v", p)
	}
	if l := byID[created[1].ID]; l.RuntimeState != "ok" || l.Runtime.Online || l.Runtime.LastHandshakeAt != nil {
		t.Fatalf("laptop %+v", l)
	}
	if tb := byID[created[2].ID]; tb.RuntimeState != "disabled" || tb.Runtime != nil {
		t.Fatalf("tablet %+v", tb)
	}
	// A device not on the interface yet (created after the last apply).
	s.RemoteStatus.(*fakeRemoteStatus).st.Peers = s.RemoteStatus.(*fakeRemoteStatus).st.Peers[:1]
	rr := do(s, http.MethodGet, "/api/remote-access/devices/"+created[1].ID, nil)
	var one resp
	decode(t, rr, &one)
	if one.Device.RuntimeState != "not_installed" || one.Device.Runtime != nil || !one.Runtime.Available {
		t.Fatalf("%+v", one)
	}
}
