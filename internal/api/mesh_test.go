package api

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/radowitz/meridian/internal/credentials"
	"github.com/radowitz/meridian/internal/mesh"
	"github.com/radowitz/meridian/internal/model"
)

// fpFor is a valid ssh.FingerprintSHA256-shaped fingerprint per host.
func fpFor(id string) string {
	sum := sha256.Sum256([]byte("host-" + id))
	return "SHA256:" + base64.RawStdEncoding.EncodeToString(sum[:])
}

type meshFix struct {
	s       *Server
	cs      *credentials.Store
	cf      *memCF
	rem     *okRemote
	used    []mesh.Credentials
	acct    string // credential-store id of the selected account
	cfAcct  string
	apiTok  string
	pw      string
	credID  string
	servers map[string]string // node id -> server id
}

// newMeshFix: a topology whose CF Mesh links have routes, every Mesh plan
// node on its own trusted server (password credential), and a Cloudflare
// account created (selected only when sel).
func newMeshFix(t *testing.T, sel bool) *meshFix {
	t.Helper()
	f := &meshFix{s: newTest(t), servers: map[string]string{}}
	f.cf = &memCF{nodes: map[string]mesh.CFNode{}, routes: map[string]mesh.CFRoute{}, nodeToken: "eyJnode" + strings.Repeat("q", 30)}
	f.rem = &okRemote{keys: map[string]string{}}
	f.s.MeshCF = func(c mesh.Credentials) (mesh.Cloudflare, error) {
		f.used = append(f.used, c)
		return f.cf, nil
	}
	f.s.MeshRemote = func() mesh.Remote { return f.rem }
	do(f.s, http.MethodGet, "/api/topology", nil)
	cs, err := f.s.credStore()
	if err != nil {
		t.Fatal(err)
	}
	f.cs = cs
	f.pw = "pw-" + rnd(t, 6)
	c, err := cs.CreateSSHCredential("运维", "", credentials.SSHSecretInput{Kind: credentials.KindPassword, Password: f.pw})
	if err != nil {
		t.Fatal(err)
	}
	f.credID = c.ID
	f.cfAcct, f.apiTok = rnd(t, 16), "cfapitoken_"+rnd(t, 16)
	f.rem.account = f.cfAcct
	rr := do(f.s, http.MethodPost, "/api/cloudflare/accounts", mustJSON(map[string]string{"name": "主账户", "account_id": f.cfAcct, "api_token": f.apiTok}))
	var a struct{ Account accountView }
	decode(t, rr, &a)
	f.acct = a.Account.ID
	if sel {
		if rr := do(f.s, http.MethodPut, "/api/cloudflare/mesh-account", mustJSON(map[string]string{"account": f.acct})); rr.Code != 200 {
			t.Fatal(rr.Body.String())
		}
	}
	// The stored example already has its Mesh legs; each exit publishes the
	// one address the panel allocated for it.
	topo, _, _ := f.s.Store.Load()
	plan, err := f.s.meshPlan(topo)
	if err != nil || !plan.OK() {
		t.Fatalf("fixture plan: %v %+v", err, plan.Issues)
	}
	for i, n := range plan.Nodes {
		sv, err := cs.CreateServer(credentials.ServerInput{Name: "srv " + n.ID, Address: fmt.Sprintf("198.51.100.%d", 10+i), User: "ops", Auth: model.AuthPassword, CredentialID: c.ID})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := cs.ObserveHostKey(sv.ID, "ssh-ed25519", fpFor(n.ID)); err != nil {
			t.Fatal(err)
		}
		if _, err := cs.TrustHostKey(sv.ID, fpFor(n.ID)); err != nil {
			t.Fatal(err)
		}
		f.servers[n.ID] = sv.ID
	}
	for i := range topo.Nodes {
		if id, ok := f.servers[topo.Nodes[i].ID]; ok {
			topo.Nodes[i].ServerID, topo.Nodes[i].SSHHost, topo.Nodes[i].SSHPort, topo.Nodes[i].SSHUser = id, "", 0, ""
		}
	}
	if err := f.s.Store.Save(topo); err != nil {
		t.Fatal(err)
	}
	// No host is a Mesh node yet: every plan node can get the host-level
	// connector (synthetic detections; the deploy confirms the plan).
	t.Setenv(mesh.RepoKeyFingerprintEnv, "0123456789ABCDEF0123456789ABCDEF01234567")
	hm := map[string]model.HostMeshDetection{}
	for _, n := range plan.Nodes {
		d := mesh.ParseHostMesh("MESHHOST svc stopped\nMESHHOST cli absent\nMESHHOST memavail 1048576\nMESHHOST os debian bookworm\nMESHHOST arch x86_64\nMESHHOST apt present\nMESHHOST systemd present\nMESHHOST repo 200\nMESHHOST done 1\n", "", mesh.Reserved{})
		d.NodeID = n.ID
		hm[n.ID] = d
	}
	if err := mesh.SaveHostMesh(f.s.meshDir(), hm); err != nil {
		t.Fatal(err)
	}
	return f
}

func (f *meshFix) journal(t *testing.T) *mesh.Journal {
	t.Helper()
	j, err := (&mesh.Deployer{Dir: f.s.meshDir()}).Load()
	if err != nil {
		t.Fatal(err)
	}
	return j
}

func TestMeshRequestsRefuseOldFields(t *testing.T) {
	f := newMeshFix(t, true)
	for _, body := range []string{`{"private_key_pem":"x"}`, `{"trust_new_host":true}`, `{"nodes":{"hk-hub":{"ssh_host":"x"}}}`, `{"ssh_host":"x"}`} {
		rr := do(f.s, http.MethodPost, "/api/mesh/deploy", []byte(body))
		if code, _ := errCode(t, rr); rr.Code != http.StatusBadRequest || code != codeFieldRemoved {
			t.Fatalf("deploy %s: %d %s", body, rr.Code, rr.Body.String())
		}
	}
	if rr := do(f.s, http.MethodPost, "/api/mesh/deploy", []byte(`{"bogus":1}`)); rr.Code != http.StatusBadRequest {
		t.Fatalf("unknown field: %d", rr.Code)
	}
	for _, body := range []string{`{"private_key_pem":"x"}`, `{"trust_new_host":true}`, `{"nodes":{}}`, `{"fail_after":"routes"}`, `{"account":"x"}`} {
		rr := do(f.s, http.MethodPost, "/api/mesh/withdraw", []byte(body))
		if code, _ := errCode(t, rr); rr.Code != http.StatusBadRequest || code != codeFieldRemoved {
			t.Fatalf("withdraw %s: %d %s", body, rr.Code, rr.Body.String())
		}
	}
	if len(f.rem.calls) != 0 || len(f.cf.nodes) != 0 {
		t.Fatal("a refused request did something")
	}
}

// Deploy and withdraw by ID: servers, credential and account are resolved
// by the backend and pinned in the schema-3 journal; credential rotation
// between deploy and withdraw keeps withdrawal working; pinned servers and
// credentials cannot be deleted or re-pointed; deleting the node from the
// topology does not lose the pin; account switching stays locked.
func TestMeshDeployAndWithdrawByID(t *testing.T) {
	f := newMeshFix(t, false)
	s := f.s
	// Nothing selected and nothing named: refused before any stage.
	rr := do(s, http.MethodPost, "/api/mesh/deploy", nil)
	if code, _ := errCode(t, rr); rr.Code != http.StatusConflict || code != codeNoMeshAccount {
		t.Fatalf("no account: %d %s", rr.Code, rr.Body.String())
	}
	if rr := do(s, http.MethodPut, "/api/cloudflare/mesh-account", mustJSON(map[string]string{"account": f.acct})); rr.Code != 200 {
		t.Fatal(rr.Body.String())
	}
	// Fault injection only when enabled; when enabled it compensates.
	if rr := do(s, http.MethodPost, "/api/mesh/deploy", []byte(`{"fail_after":"install","confirm_install":true}`)); rr.Code != http.StatusBadRequest {
		t.Fatalf("fail_after accepted: %d", rr.Code)
	}
	t.Setenv("MERIDIAN_MESH_FAULT_INJECTION", "1")
	rr = do(s, http.MethodPost, "/api/mesh/deploy", []byte(`{"fail_after":"install","confirm_install":true}`))
	if rr.Code != http.StatusBadGateway || !strings.Contains(rr.Body.String(), `"compensated":true`) || len(f.cf.nodes) != 0 || len(f.cf.routes) != 0 {
		t.Fatalf("injected failure: %d %s", rr.Code, rr.Body.String())
	}

	rr = do(s, http.MethodPost, "/api/mesh/deploy", []byte(`{"confirm_install":true}`))
	var dep struct {
		Journal mesh.Journal
		Account meshAccountSummary
	}
	decode(t, rr, &dep)
	if rr.Code != 200 || dep.Journal.State != mesh.StatePublished || dep.Account.ID != f.acct || dep.Account.Source != "selected" || dep.Account.AccountID != f.cfAcct {
		t.Fatalf("deploy: %d %s", rr.Code, rr.Body.String())
	}
	j := dep.Journal
	if j.Schema != mesh.JournalSchema || j.AccountID != f.cfAcct || j.AccountRef != f.acct || len(j.Hosts) != len(f.servers) {
		t.Fatalf("journal %+v", j)
	}
	for _, h := range j.Hosts {
		if h.ServerID != f.servers[h.NodeID] || h.CredentialID != f.credID || h.HostKey != fpFor(h.NodeID) || h.SSHUser != "ops" {
			t.Fatalf("pin %+v", h)
		}
	}
	for _, tg := range f.rem.targets {
		if tg.ServerID != f.servers[tg.ID] || tg.CredentialID != f.credID || tg.HostKey != fpFor(tg.ID) {
			t.Fatalf("remote target %+v", tg)
		}
	}
	raw, _ := os.ReadFile(filepath.Join(s.meshDir(), "deploy.json"))
	for _, sec := range []string{f.apiTok, f.cf.nodeToken, f.pw} {
		if strings.Contains(rr.Body.String(), sec) || strings.Contains(string(raw), sec) {
			t.Fatal("secret in response or journal")
		}
	}
	deployed := map[string]bool{}
	for _, c := range f.rem.calls {
		if strings.HasPrefix(c, "connector_install/") {
			deployed[strings.TrimPrefix(c, "connector_install/")] = true
		}
	}
	if !deployed["us"] || !deployed["hk-hub"] {
		t.Fatalf("fixture: %v", deployed)
	}

	// The node "us" is deleted from the topology; its server stays pinned.
	topo, _, _ := s.Store.Load()
	var nodes []model.Node
	for _, n := range topo.Nodes {
		if n.ID != "us" {
			nodes = append(nodes, n)
		}
	}
	topo.Nodes = nodes
	var links []model.Link
	for _, l := range topo.Links {
		if l.From != "us" && l.To != "us" {
			links = append(links, l)
		}
	}
	topo.Links = links
	if err := s.Store.Save(topo); err != nil {
		t.Fatal(err)
	}
	usSrv := f.servers["us"]
	rr = do(s, http.MethodDelete, "/api/servers/"+usSrv, nil)
	if code, refs := errCode(t, rr); rr.Code != http.StatusConflict || code != credentials.CodeInUse || len(refs) != 1 || refs[0].Kind != "mesh_deployment" || refs[0].ID != j.RunID {
		t.Fatalf("delete pinned server: %d %s", rr.Code, rr.Body.String())
	}
	if err := f.cs.DeleteServer(usSrv); err == nil {
		t.Fatal("store deleted a pinned server")
	}
	for _, patch := range []string{`{"address":"203.0.113.9"}`, `{"port":2222}`, `{"user":"root"}`, `{"credential_id":""}`} {
		rr = do(s, http.MethodPatch, "/api/servers/"+usSrv, []byte(patch))
		if code, _ := errCode(t, rr); rr.Code != http.StatusConflict || code != credentials.CodeInUse {
			t.Fatalf("re-point %s: %d %s", patch, rr.Code, rr.Body.String())
		}
	}
	if rr = do(s, http.MethodPatch, "/api/servers/"+usSrv, []byte(`{"name":"美国（改名）"}`)); rr.Code != 200 {
		t.Fatalf("rename: %d %s", rr.Code, rr.Body.String())
	}
	rr = do(s, http.MethodDelete, "/api/ssh-credentials/"+f.credID, nil)
	if code, refs := errCode(t, rr); rr.Code != http.StatusConflict || code != credentials.CodeInUse || len(refs) == 0 {
		t.Fatalf("delete pinned credential: %d %s", rr.Code, rr.Body.String())
	}
	// Account rules: no switch while bound; token rotation allowed.
	other := rnd(t, 16)
	rr = do(s, http.MethodPost, "/api/cloudflare/accounts", mustJSON(map[string]string{"name": "另一个", "account_id": other, "api_token": "cfapitoken_" + rnd(t, 16)}))
	var oa struct{ Account accountView }
	decode(t, rr, &oa)
	if rr = do(s, http.MethodPut, "/api/cloudflare/mesh-account", mustJSON(map[string]string{"account": oa.Account.ID})); rr.Code != http.StatusConflict {
		t.Fatalf("switch while bound: %d %s", rr.Code, rr.Body.String())
	}
	tok2 := "cfapitoken_" + rnd(t, 16)
	if rr = do(s, http.MethodPut, "/api/cloudflare/accounts/"+f.acct+"/token", mustJSON(map[string]string{"api_token": tok2})); rr.Code != 200 {
		t.Fatalf("token rotation: %d", rr.Code)
	}
	// SSH credential rotated in place between deploy and withdraw.
	pw2 := "pw2-" + rnd(t, 6)
	if rr = do(s, http.MethodPut, "/api/ssh-credentials/"+f.credID+"/secret", mustJSON(map[string]string{"password": pw2})); rr.Code != 200 {
		t.Fatalf("rotation: %d %s", rr.Code, rr.Body.String())
	}

	before := len(f.rem.calls)
	rr = do(s, http.MethodPost, "/api/mesh/withdraw", nil)
	if rr.Code != 200 || !strings.Contains(rr.Body.String(), `"state":"withdrawn"`) || len(f.cf.routes) != 0 || len(f.cf.nodes) != 0 {
		t.Fatalf("withdraw: %d %s", rr.Code, rr.Body.String())
	}
	restored := map[string]mesh.NodeTarget{}
	for i := before; i < len(f.rem.calls); i++ {
		if strings.HasPrefix(f.rem.calls[i], "connector_remove/") {
			restored[f.rem.targets[i].ID] = f.rem.targets[i]
		}
	}
	if len(restored) != len(deployed) {
		t.Fatalf("restored %v, deployed %v", restored, deployed)
	}
	if h := restored["us"]; h.ServerID != usSrv || h.CredentialID != f.credID || h.HostKey != fpFor("us") {
		t.Fatalf("deleted node restored at %+v", h)
	}
	if last := f.used[len(f.used)-1]; last.AccountID != f.cfAcct || last.APIToken != tok2 {
		t.Fatal("withdrawal did not use the rotated token of the deployment account")
	}
	for _, sec := range []string{tok2, pw2} {
		if strings.Contains(rr.Body.String(), sec) {
			t.Fatal("secret in response")
		}
	}
	// Withdrawn: the server is free again.
	if rr = do(s, http.MethodDelete, "/api/servers/"+usSrv, nil); rr.Code != 200 {
		t.Fatalf("delete after withdrawal: %d %s", rr.Code, rr.Body.String())
	}
}

func TestMeshDeployRefusesUnreadyServers(t *testing.T) {
	f := newMeshFix(t, true)
	hub := f.servers["hk-hub"]
	if rr := do(f.s, http.MethodDelete, "/api/servers/"+hub+"/host-key", nil); rr.Code != 200 {
		t.Fatal(rr.Body.String())
	}
	rr := do(f.s, http.MethodPost, "/api/mesh/deploy", []byte(`{"confirm_install":true}`))
	if code, _ := errCode(t, rr); rr.Code != http.StatusConflict || code != codeServersNotReady || !strings.Contains(rr.Body.String(), `"missing":["host_key"]`) {
		t.Fatalf("%d %s", rr.Code, rr.Body.String())
	}
	if len(f.rem.calls) != 0 || len(f.cf.nodes) != 0 || f.journal(t) != nil {
		t.Fatal("an unready deployment did something")
	}
	rr = do(f.s, http.MethodGet, "/api/mesh", nil)
	if !strings.Contains(rr.Body.String(), `"plan_servers"`) || !strings.Contains(rr.Body.String(), `"missing":["host_key"]`) {
		t.Fatal(rr.Body.String())
	}
}

// An explicit account becomes the Mesh account and the journal's binding.
func TestMeshDeployWithExplicitAccount(t *testing.T) {
	f := newMeshFix(t, true)
	b := rnd(t, 16)
	rr := do(f.s, http.MethodPost, "/api/cloudflare/accounts", mustJSON(map[string]string{"name": "B", "account_id": b, "api_token": "cfapitoken_" + rnd(t, 16)}))
	var ba struct{ Account accountView }
	decode(t, rr, &ba)
	f.rem.account = b // the hosts register into the explicitly chosen account
	if rr := do(f.s, http.MethodPost, "/api/mesh/deploy", []byte(`{"account":"cf-missing"}`)); rr.Code != http.StatusNotFound {
		t.Fatalf("unknown account: %d %s", rr.Code, rr.Body.String())
	}
	rr = do(f.s, http.MethodPost, "/api/mesh/deploy", mustJSON(map[string]any{"account": ba.Account.ID, "confirm_install": true}))
	var dep struct {
		Journal mesh.Journal
		Account meshAccountSummary
	}
	decode(t, rr, &dep)
	if rr.Code != 200 || dep.Account.Source != "request" || dep.Account.ID != ba.Account.ID || dep.Journal.AccountID != b || dep.Journal.AccountRef != ba.Account.ID {
		t.Fatalf("%d %s", rr.Code, rr.Body.String())
	}
	if f.cs.MeshAccount() != ba.Account.ID {
		t.Fatal("explicit account not selected")
	}
	if rr := do(f.s, http.MethodPut, "/api/cloudflare/mesh-account", mustJSON(map[string]string{"account": f.acct})); rr.Code != http.StatusConflict {
		t.Fatalf("switch back while bound: %d", rr.Code)
	}
	if rr := do(f.s, http.MethodPost, "/api/mesh/withdraw", nil); rr.Code != 200 {
		t.Fatalf("withdraw: %d %s", rr.Code, rr.Body.String())
	}
	if last := f.used[len(f.used)-1]; last.AccountID != b {
		t.Fatal("withdrawal used another account")
	}
}

// A pinned server or credential that no longer exists blocks the whole
// withdrawal before anything is compensated.
func TestMeshWithdrawBlockedWhenPinnedServerOrCredentialMissing(t *testing.T) {
	f := newMeshFix(t, true)
	if rr := do(f.s, http.MethodPost, "/api/mesh/deploy", []byte(`{"confirm_install":true}`)); rr.Code != 200 {
		t.Fatal(rr.Body.String())
	}
	good := f.journal(t)
	nodes, routes := len(f.cf.nodes), len(f.cf.routes)
	for _, mut := range []func(h *mesh.HostPin){
		func(h *mesh.HostPin) { h.ServerID = "srv-gone" },
		func(h *mesh.HostPin) { h.CredentialID = "key-gone" },
	} {
		j := *good
		j.Remotes = append([]mesh.OwnedRemote(nil), good.Remotes...)
		mut(&j.Remotes[0].Host)
		writeJournal(t, f.s, j)
		before := len(f.rem.calls)
		rr := do(f.s, http.MethodPost, "/api/mesh/withdraw", nil)
		if !strings.Contains(rr.Body.String(), `"code":"hosts_blocked"`) || rr.Code != http.StatusConflict {
			t.Fatalf("%d %s", rr.Code, rr.Body.String())
		}
		after := f.journal(t)
		if after.State != mesh.StatePublished || len(f.rem.calls) != before || len(f.cf.nodes) != nodes || len(f.cf.routes) != routes {
			t.Fatalf("blocked withdrawal changed something: %s", after.State)
		}
		for _, r := range after.Remotes {
			if r.State == mesh.ResRemoved {
				t.Fatal("remote marked removed")
			}
		}
		for _, r := range after.Routes {
			if r.State == mesh.ResRemoved {
				t.Fatal("route marked removed")
			}
		}
	}
	writeJournal(t, f.s, *good)
	if rr := do(f.s, http.MethodPost, "/api/mesh/withdraw", nil); rr.Code != 200 {
		t.Fatalf("withdraw: %d %s", rr.Code, rr.Body.String())
	}
}

// A schema-2 journal pins hosts by address only. Before the upgrade the
// store already protects the server with that endpoint; the withdrawal
// upgrades the journal and goes through the server and its credential.
func TestMeshSchema2JournalWithdrawal(t *testing.T) {
	f := newMeshFix(t, true)
	if rr := do(f.s, http.MethodPost, "/api/mesh/deploy", []byte(`{"confirm_install":true}`)); rr.Code != 200 {
		t.Fatal(rr.Body.String())
	}
	j := f.journal(t)
	j.Schema, j.AccountRef = 2, ""
	strip := func(h *mesh.HostPin) { h.ServerID, h.CredentialID = "", "" }
	for i := range j.Hosts {
		strip(&j.Hosts[i])
	}
	for i := range j.Remotes {
		strip(&j.Remotes[i].Host)
	}
	writeJournal(t, f.s, *j)
	hub := f.servers["hk-hub"]
	if refs := f.cs.DeploymentRefsForServer(hub); len(refs) != 1 || refs[0].ID != j.RunID {
		t.Fatalf("schema-2 pin does not protect its server: %+v", refs)
	}
	if refs := f.cs.DeploymentRefsForCredential(f.credID); len(refs) != 1 {
		t.Fatalf("schema-2 pin does not protect its credential: %+v", refs)
	}
	before := len(f.rem.calls)
	if rr := do(f.s, http.MethodPost, "/api/mesh/withdraw", nil); rr.Code != 200 {
		t.Fatalf("withdraw: %d %s", rr.Code, rr.Body.String())
	}
	for i := before; i < len(f.rem.calls); i++ {
		if tg := f.rem.targets[i]; tg.ServerID != f.servers[tg.ID] || tg.CredentialID != f.credID {
			t.Fatalf("upgraded pin not used: %+v", tg)
		}
	}
	if up := f.journal(t); up.Schema != mesh.JournalSchema || up.State != mesh.StateWithdrawn {
		t.Fatalf("%d %s", up.Schema, up.State)
	}
}

func TestMeshWithdrawSingleLegKeepsOtherPublishedResources(t *testing.T) {
	f := newMeshFix(t, true)
	rr := do(f.s, http.MethodPost, "/api/mesh/deploy", []byte(`{"confirm_install":true}`))
	if rr.Code != http.StatusOK {
		t.Fatalf("deploy: %d %s", rr.Code, rr.Body.String())
	}
	before := f.journal(t)
	if len(before.Legs) < 2 {
		t.Fatal("fixture needs two legs")
	}
	link := before.Legs[0].LinkID
	rr = do(f.s, http.MethodPost, "/api/mesh/withdraw", []byte(fmt.Sprintf(`{"link_id":%q}`, link)))
	if rr.Code != http.StatusOK {
		t.Fatalf("withdraw leg: %d %s", rr.Code, rr.Body.String())
	}
	after := f.journal(t)
	if after.State != mesh.StatePublished || len(f.cf.routes) != 0 || len(f.cf.nodes) != len(before.Nodes)-1 {
		t.Fatalf("removed shared resources: %+v", after)
	}
	for _, l := range after.Legs {
		if l.LinkID == link && l.State != mesh.StateWithdrawn {
			t.Fatal("selected leg not marked withdrawn")
		}
	}
	count := len(f.rem.calls)
	rr = do(f.s, http.MethodPost, "/api/mesh/withdraw", []byte(`{"link_id":"unknown; command"}`))
	if rr.Code != http.StatusConflict || len(f.rem.calls) != count {
		t.Fatalf("unrecorded leg executed: %d %s", rr.Code, rr.Body.String())
	}
	rr = do(f.s, http.MethodPost, "/api/mesh/withdraw", []byte(`{"link_id":"x","command":"anything"}`))
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("unknown field: %d", rr.Code)
	}
}

// Detection through the pinned server: an existing host node is recorded as
// not panel-owned and shown by GET /api/mesh; a node without output is a
// detection failure; an untrusted server is never contacted.
func TestMeshDetectHostNodes(t *testing.T) {
	f := newMeshFix(t, true)
	topo, _, _ := f.s.Store.Load()
	plan, _ := f.s.meshPlan(topo)
	var exit, hub string
	for _, n := range plan.Nodes {
		if n.Role == model.RoleExit && exit == "" {
			exit = n.ID
		} else if n.Role == model.RoleHub && hub == "" {
			hub = n.ID
		}
	}
	f.rem.detect = map[string]string{
		exit: "MESHHOST svc running\nMESHHOST cli present\nMESHHOST mode Mode: WarpConnector\nMESHHOST reg Account ID: " + f.cfAcct + strings.Repeat("0", 32-len(f.cfAcct)) +
			"\nMESHHOST addr CloudflareWARP 100.96.0.7/32\nMESHHOST memavail 66560\nMESHHOST done 1\n",
	}
	rr := do(f.s, http.MethodPost, "/api/mesh/detect", mustJSON(map[string]string{}))
	if rr.Code != 200 {
		t.Fatal(rr.Body.String())
	}
	var res struct{ Detections []model.HostMeshDetection }
	decode(t, rr, &res)
	got := map[string]model.HostMeshDetection{}
	for _, d := range res.Detections {
		got[d.NodeID] = d
	}
	e := got[exit]
	if e.State != model.HostMeshExisting || e.MeshAddr != "100.96.0.7" || e.Origin != model.MeshOriginExisting || e.PanelOwned || e.HostKey != fpFor(exit) {
		t.Fatalf("exit: %+v", e)
	}
	if h := got[hub]; h.State != model.HostMeshFailed {
		t.Fatalf("hub without output: %+v", h)
	}
	for _, c := range f.rem.calls {
		if !strings.HasPrefix(c, "detect/") {
			t.Fatalf("non-detect action %s", c)
		}
	}
	var st struct {
		HostMesh map[string]model.HostMeshDetection `json:"host_mesh"`
	}
	decode(t, do(f.s, http.MethodGet, "/api/mesh", nil), &st)
	if st.HostMesh[exit].State != model.HostMeshExisting {
		t.Fatalf("GET /api/mesh: %+v", st.HostMesh)
	}
	if rr := do(f.s, http.MethodPost, "/api/mesh/detect", mustJSON(map[string]string{"ssh_host": "192.0.2.1"})); rr.Code != 400 {
		t.Fatalf("removed field: %d", rr.Code)
	}
}

// One end of a Mesh leg reuses an existing host-level node (synthetic
// detection): the plan publishes nothing, every other end gets the
// host-level connector after confirm_install, the installed nodes are
// recorded panel-owned, and nothing is ever written to the reused host.
func TestMeshDeployReusesExistingExitNode(t *testing.T) {
	f := newMeshFix(t, true)
	topo, _, _ := f.s.Store.Load()
	hub, _ := topo.PrimaryHub()
	var exit string
	for _, m := range topo.MeshLegs() {
		exit = m.Exit
		break
	}
	hm, _ := mesh.LoadHostMesh(f.s.meshDir())
	hm[exit] = model.HostMeshDetection{NodeID: exit, State: model.HostMeshExisting, Reusable: true, Origin: model.MeshOriginExisting, MeshAddr: "100.96.0.11", Iface: "CloudflareWARP"}
	if err := mesh.SaveHostMesh(f.s.meshDir(), hm); err != nil {
		t.Fatal(err)
	}
	f.rem.detect = map[string]string{exit: "MESHHOST svc running\nMESHHOST cli present\nMESHHOST mode Mode: WarpConnector\nMESHHOST reg Account ID: " + f.cfAcct + "\nMESHHOST addr CloudflareWARP 100.96.0.11/32\nMESHHOST done 1\n"}
	var view struct {
		Plan mesh.Plan `json:"plan"`
	}
	decode(t, do(f.s, http.MethodGet, "/api/mesh", nil), &view)
	if len(view.Plan.Install) != len(hm)-1 || view.Plan.Install[0] != hub.ID || len(view.Plan.Routes) != 0 {
		t.Fatalf("install_confirm: %v routes %v", view.Plan.Install, view.Plan.Routes)
	}
	for _, id := range view.Plan.Install {
		if id == exit {
			t.Fatal("the reused exit is to be installed")
		}
	}
	if rr := do(f.s, http.MethodPost, "/api/mesh/deploy", nil); rr.Code == http.StatusOK || !strings.Contains(rr.Body.String(), "confirm_install") {
		t.Fatalf("unconfirmed: %d %s", rr.Code, rr.Body.String())
	}
	if rr := do(f.s, http.MethodPost, "/api/mesh/deploy", []byte(`{"confirm_install":true}`)); rr.Code != http.StatusOK {
		t.Fatalf("confirmed: %d %s", rr.Code, rr.Body.String())
	}
	for _, c := range f.rem.calls {
		if strings.HasPrefix(c, "connector_") && strings.HasSuffix(c, "/"+exit) {
			t.Fatalf("wrote to the reused exit: %v", f.rem.calls)
		}
	}
	if j := f.journal(t); len(j.Existing) != 1 || j.Existing[0] != exit {
		t.Fatalf("journal existing: %v", j.Existing)
	}
	// The installed hub is now a panel-owned host node for the next compile.
	after, _ := f.s.meshHostDetections()
	if d := after[hub.ID]; d.Origin != model.MeshOriginPanelHost || !d.PanelOwned || model.MeshHostOf(d) == nil {
		t.Fatalf("hub detection after install: %+v", d)
	}
	if d := after[exit]; d.Origin != model.MeshOriginExisting || d.PanelOwned {
		t.Fatalf("exit detection: %+v", d)
	}
	if rr := do(f.s, http.MethodPost, "/api/mesh/withdraw", nil); rr.Code != http.StatusOK {
		t.Fatalf("withdraw: %d %s", rr.Code, rr.Body.String())
	}
	for _, c := range f.rem.calls {
		if c == "connector_remove/"+exit || c == "restore/"+exit {
			t.Fatal("withdrawal touched the reused exit")
		}
	}
	after, _ = f.s.meshHostDetections()
	if d := after[hub.ID]; model.MeshHostOf(d) != nil || d.State != model.HostMeshFailed {
		t.Fatalf("withdrawn panel node still usable: %+v", d)
	}
}
