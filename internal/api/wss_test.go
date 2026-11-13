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

	"github.com/radowitz/meridian/internal/model"
	"github.com/radowitz/meridian/internal/sshexec"
)

type wssResp struct {
	Listeners []wssListenerView `json:"listeners"`
}

func getWSSView(t *testing.T, s *Server) (wssResp, string) {
	t.Helper()
	rr := do(s, http.MethodGet, "/api/wss", nil)
	if rr.Code != 200 {
		t.Fatalf("GET /api/wss: %d %s", rr.Code, rr.Body.String())
	}
	var out wssResp
	if err := json.Unmarshal(rr.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	return out, rr.Body.String()
}

func (r wssResp) listener(id string) *wssListenerView {
	for i := range r.Listeners {
		if r.Listeners[i].NodeID == id {
			return &r.Listeners[i]
		}
	}
	return nil
}

// wssSecretValues are the WSS secrets and, for PEM keys, their body lines.
func wssSecretValues(t *testing.T, s *Server) []string {
	t.Helper()
	cs, err := s.credStore()
	if err != nil {
		t.Fatal(err)
	}
	m, err := cs.WSSSecrets()
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, v := range m {
		out = append(out, v)
		for _, line := range strings.Split(v, "\n") {
			if len(line) >= 16 && !strings.HasPrefix(line, "-----") {
				out = append(out, line)
			}
		}
	}
	if len(out) == 0 {
		t.Fatal("no WSS secrets generated")
	}
	return out
}

func partyStage(v *wssListenerView, party string) int {
	for _, p := range v.Parties {
		if p.Party == party {
			return p.Installed
		}
	}
	return -99
}

// Gateway install with WSS carriers: the path prefixes reach only the
// host's 0600 files; the API (views, compile, diff, status), the logs, the
// data directory (snapshots, database) and the topology export never carry
// a WSS secret; the panel shows "set", fingerprints and stages. A
// certificate rotation of a listener the gateway dials then completes
// through gateway installs and the old key is deleted.
func TestWSSGatewayInstallSecretsAndRotation(t *testing.T) {
	var logs bytes.Buffer
	log.SetOutput(&logs)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })
	s, host, _ := installTest(t)
	rr := do(s, http.MethodPost, "/api/apply", []byte(`{"install":true}`))
	if rr.Code != 200 {
		t.Fatalf("install: %d %s", rr.Code, rr.Body.String())
	}
	secrets := wssSecretValues(t, s)
	noSecretIn(t, "install response", rr.Body.String(), secrets...)
	cs, _ := s.credStore()
	st := cs.WSSState()
	ali := st.Listener("ali")
	sec, _ := cs.WSSSecrets()
	env, err := os.ReadFile(filepath.Join(host, "etc/meridian/wss/client-gw-ali.env"))
	if err != nil || !strings.Contains(string(env), "WSTUNNEL_HTTP_UPGRADE_PATH_PREFIX="+sec[ali.Links[0].Path.SecretID]+"\n") {
		t.Fatalf("host env: %v %s", err, env)
	}
	if fi, _ := os.Stat(filepath.Join(host, "etc/meridian/wss/client-gw-ali.env")); fi.Mode().Perm() != 0o600 {
		t.Fatalf("env mode %o", fi.Mode().Perm())
	}
	if trust, _ := os.ReadFile(filepath.Join(host, "etc/meridian/wss/client-gw-ali.trust.pem")); !strings.Contains(string(trust), strings.TrimSpace(ali.Cert.CertPEM)) {
		t.Fatal("host trust file")
	}
	for _, p := range []string{"/api/compile", "/api/diff", "/api/validate"} {
		noSecretIn(t, "POST "+p, do(s, http.MethodPost, p, []byte(`{}`)).Body.String(), secrets...)
	}
	for _, p := range append(readOnlyViews, "/api/wss", "/api/host", "/api/provision/state") {
		noSecretIn(t, "GET "+p, do(s, http.MethodGet, p, nil).Body.String(), secrets...)
	}
	for _, v := range secrets {
		assertNowhereElse(t, s.DataDir, s.secretsDir(), v)
	}
	if strings.Contains(do(s, http.MethodGet, "/api/topology", nil).Body.String(), "wss_path_prefix") {
		t.Fatal("topology export still has a path field")
	}
	view, raw := getWSSView(t, s)
	if strings.Contains(raw, "wssp-") || strings.Contains(raw, "wssk-") || strings.Contains(raw, "PRIVATE KEY") {
		t.Fatal("the view names secret ids or a key")
	}
	v := view.listener("ali")
	if v == nil || !v.Links[0].PathSet || v.Cert.Fingerprint != ali.Cert.Fingerprint || v.Cert.DaysLeft < 360 || partyStage(v, "client:gw-ali") != 0 || partyStage(v, "server") != model.WSSStageNone {
		t.Fatalf("view %+v", v)
	}

	// Certificate rotation of "ali": the gateway's client is the only
	// deployed end, so two gateway installs finish it.
	rr = do(s, http.MethodPost, "/api/wss/listeners/ali/regenerate-cert", nil)
	if rr.Code != 200 || !strings.Contains(rr.Body.String(), `"committed":false`) {
		t.Fatalf("regenerate: %d %s", rr.Code, rr.Body.String())
	}
	if rr := do(s, http.MethodPost, "/api/wss/listeners/ali/regenerate-cert", nil); rr.Code != http.StatusConflict {
		t.Fatalf("second regenerate: %d", rr.Code)
	}
	view, _ = getWSSView(t, s)
	v = view.listener("ali")
	if v.PendingCert == nil || !v.Rotating || len(v.NextSteps) != 1 || v.NextSteps[0].NodeID != "gw" || v.NextSteps[0].To != 3 {
		t.Fatalf("rotation view %+v", v)
	}
	oldKey := ali.Cert.KeySecretID
	if rr := do(s, http.MethodPost, "/api/apply", []byte(`{"install":true}`)); rr.Code != 200 {
		t.Fatalf("install 2: %d %s", rr.Code, rr.Body.String())
	}
	st = cs.WSSState()
	if l := st.Listener("ali"); l.Rotating() || l.Cert.Fingerprint != v.PendingCert.Fingerprint {
		t.Fatalf("rotation not committed: %+v", l)
	}
	// The old key stays while a gateway snapshot (the previous bundle,
	// for a rollback) names it, and goes with the next install.
	hasKey := func() bool {
		for _, m := range cs.WSSSecretIDs() {
			if m.ID == oldKey {
				return true
			}
		}
		return false
	}
	if !hasKey() || !strings.Contains(strings.Join(cs.WSSUnusedSecrets(), " "), oldKey) {
		t.Fatal("old key must be unused but kept for the previous snapshot")
	}
	// The bundles of install 1 and 2 named it (the never-installed
	// server "ali" rendered at stage 1 then); two more installs rotate
	// both out of applied/ and previous/.
	for i := 3; i <= 4; i++ {
		if rr := do(s, http.MethodPost, "/api/apply", []byte(`{"install":true}`)); rr.Code != 200 {
			t.Fatalf("install %d: %d %s", i, rr.Code, rr.Body.String())
		}
	}
	if hasKey() {
		t.Fatal("old key not deleted once no snapshot names it")
	}
	trust, _ := os.ReadFile(filepath.Join(host, "etc/meridian/wss/client-gw-ali.trust.pem"))
	if strings.Count(string(trust), "BEGIN CERTIFICATE") != 1 || !strings.Contains(string(trust), v.PendingCert.Fingerprint) {
		t.Fatalf("trust after rotation:\n%s", trust)
	}
	// A runtime rollback makes the gateway's ends uncertain.
	if rr := do(s, http.MethodPost, "/api/rollback", []byte(`{"install":true}`)); rr.Code != 200 {
		t.Fatalf("rollback: %d %s", rr.Code, rr.Body.String())
	}
	view, _ = getWSSView(t, s)
	if v := view.listener("ali"); !v.Inconsistent || !strings.Contains(mustString(v.Warnings), "配置不确定") || len(v.NextSteps) != 1 || v.NextSteps[0].NodeID != "gw" {
		t.Fatalf("after rollback %+v", v)
	}
	noSecretIn(t, "logs", logs.String(), secrets...)
}

func mustString(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}

// Migration of a fixed-path topology: the first start moves the fields out
// of the topology, generates random paths and certificates, keeps the old
// prefix accepted on a listener whose ends were deployed, and is
// idempotent. The panel shows the migration state.
func TestWSSLegacyMigrationThroughThePanel(t *testing.T) {
	s := newTest(t)
	do(s, http.MethodGet, "/api/topology", nil)
	topo, _, _ := s.Store.Load()
	for i := range topo.Nodes {
		switch topo.Nodes[i].ID {
		case "ali":
			topo.Nodes[i].WSSPathPrefix = "old-fixed-prefix"
			topo.Nodes[i].TLSCertPath, topo.Nodes[i].TLSKeyPath = "/etc/meridian/tls/fullchain.pem", "/etc/meridian/tls/privkey.pem"
		case "hk-hub":
			topo.Nodes[i].WSSPathPrefix = "old-hub-prefix"
		}
	}
	if err := s.Store.Save(topo); err != nil {
		t.Fatal(err)
	}
	// ali was provisioned by the old version; the hub never was.
	s.saveOutcome(provisionOutcome{NodeID: "ali", OK: true, ServerID: "srv-x"})
	cs, err := s.credStore() // runs the migrations
	if err != nil {
		t.Fatal(err)
	}
	stored, _, _ := s.Store.Load()
	for _, n := range stored.Nodes {
		if n.WSSPathPrefix != "" || n.TLSCertPath != "" || n.TLSKeyPath != "" {
			t.Fatalf("node %s keeps legacy fields", n.ID)
		}
	}
	st := cs.WSSState()
	ali, hub := st.Listener("ali"), st.Listener("hk-hub")
	if !ali.Legacy || ali.Links[0].Legacy == nil || ali.InstalledStage(model.WSSPartyServer) != 0 {
		t.Fatalf("ali %+v", ali)
	}
	// hk-hub's dialer ali was deployed: the hub is a migration too, with
	// its own old prefix; its server never ran.
	if !hub.Legacy || hub.InstalledStage(model.WSSPartyServer) != model.WSSStageNone || hub.Link("ali-hub-wss").Legacy == nil {
		t.Fatalf("hub %+v", hub)
	}
	sec, _ := cs.WSSSecrets()
	if sec[ali.Links[0].Legacy.SecretID] != "old-fixed-prefix" || sec[hub.Link("ali-hub-wss").Legacy.SecretID] != "old-hub-prefix" {
		t.Fatal("old prefixes not carried")
	}
	before, _ := json.Marshal(st)
	if errs := s.migrate(cs); len(errs) != 0 {
		t.Fatal(errs)
	}
	after, _ := json.Marshal(cs.WSSState())
	if string(before) != string(after) {
		t.Fatal("migration not idempotent")
	}
	view, _ := getWSSView(t, s)
	v := view.listener("ali")
	if !v.Legacy || !v.Links[0].LegacyPath || !strings.Contains(mustString(v.Warnings), "旧版固定路径迁移") {
		t.Fatalf("view %+v", v)
	}
	// ali's only dialer (the gateway) never ran the old version: its
	// server can drop the old prefix at once (stage 3).
	if len(v.NextSteps) != 1 || v.NextSteps[0].NodeID != "ali" || v.NextSteps[0].To != 3 {
		t.Fatalf("ali steps: %+v", v.NextSteps)
	}
	// The hub's old client (ali) did: the hub accepts both prefixes until
	// ali's client runs the new configuration; ali's client goes first.
	hv := view.listener("hk-hub")
	if len(hv.NextSteps) != 1 || hv.NextSteps[0].Party != "client:ali-hub-wss" || hv.NextSteps[0].To != 3 {
		t.Fatalf("hub steps: %+v", hv.NextSteps)
	}
	b, err := s.compileTopo(stored)
	if err != nil {
		t.Fatal(err)
	}
	yaml := b.File("nodes/hk-hub/etc/meridian/wss/server.yaml")
	k := hub.Link("ali-hub-wss")
	if !strings.Contains(yaml, model.SecretPlaceholder(k.Legacy.SecretID)+"|"+model.SecretPlaceholder(k.Path.SecretID)) {
		t.Fatalf("migration server rule\n%s", yaml)
	}
	if y := b.File("nodes/ali/etc/meridian/wss/server.yaml"); strings.Contains(y, model.SecretPlaceholder(ali.Links[0].Legacy.SecretID)) {
		t.Fatalf("ali needs no old prefix\n%s", y)
	}
	// Importing an old topology later moves the fields out again without
	// making anything legacy.
	topo2, _, _ := s.Store.Load()
	topo2.Nodes[1].WSSPathPrefix = "imported"
	raw, _ := json.Marshal(topo2)
	if rr := do(s, http.MethodPut, "/api/topology?draft=1", raw); rr.Code != 200 {
		t.Fatalf("put: %d %s", rr.Code, rr.Body.String())
	}
	if n := storedNode(t, s, topo2.Nodes[1].ID); n.WSSPathPrefix != "" {
		t.Fatal("imported legacy field kept")
	}
}

// Remote provision of a WSS listener and client: the node's path prefixes
// and private key reach the provision script on the pinned SSH session and
// nothing else; the outcome records the node's stages.
func TestWSSProvisionInjectsOnlyIntoTheScript(t *testing.T) {
	var logs bytes.Buffer
	log.SetOutput(&logs)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })
	s := newTest(t)
	do(s, http.MethodGet, "/api/topology", nil)
	srv := startSSH(t)
	pw := "pw-" + rnd(t, 8)
	srv.SetPassword(pw)
	srv.SetHandler(func(cmd, stdin string) (string, uint32) {
		if out, ok := cleanPreflight(cmd, stdin, ""); ok {
			return out, 0
		}
		if cmd == "bash -s" && strings.Contains(stdin, "echo MERIDIAN_PROVISION_OK") {
			return "MERIDIAN_PROVISION_OK\n", 0
		}
		if cmd == sshexec.TestCommand {
			return "MERIDIAN_ARCH=x86_64\n", 0
		}
		return "unexpected", 1
	})
	rr := do(s, http.MethodPost, "/api/ssh-credentials", mustJSON(map[string]any{"name": "pw", "kind": "password", "password": pw}))
	var c struct{ Credential credView }
	decode(t, rr, &c)
	rr = do(s, http.MethodPost, "/api/servers", mustJSON(map[string]any{"name": "中继", "address": srv.Host, "port": srv.Port, "user": "root", "auth": "password", "credential_id": c.Credential.ID}))
	var sv struct{ Server serverView }
	decode(t, rr, &sv)
	topo, _, _ := s.Store.Load()
	for i := range topo.Nodes {
		if topo.Nodes[i].ID == "ali" {
			topo.Nodes[i].ServerID, topo.Nodes[i].SSHHost, topo.Nodes[i].SSHPort, topo.Nodes[i].SSHUser = sv.Server.ID, "", 0, ""
		}
	}
	if err := s.Store.Save(topo); err != nil {
		t.Fatal(err)
	}
	do(s, http.MethodPost, "/api/servers/"+sv.Server.ID+"/host-key/discover", nil)
	do(s, http.MethodPost, "/api/servers/"+sv.Server.ID+"/host-key/trust", mustJSON(map[string]string{"fingerprint": srv.Fingerprint()}))
	// Preview: placeholders only, refuses to run.
	rr = do(s, http.MethodPost, "/api/provision", []byte(`{"node_id":"ali","dry_run":true}`))
	secrets := wssSecretValues(t, s)
	noSecretIn(t, "preview", rr.Body.String(), secrets...)
	if !strings.Contains(rr.Body.String(), "__MERIDIAN_SECRET_wssk-") || !strings.Contains(rr.Body.String(), "refusing") {
		t.Fatalf("preview must carry placeholders and refuse: %s", rr.Body.String()[:200])
	}
	pf := reviewPreflight(t, s, "ali")
	rr = do(s, http.MethodPost, "/api/provision", []byte(`{"node_id":"ali","generate_keys":true,"preflight_id":"`+pf+`"}`))
	if rr.Code != 200 {
		t.Fatalf("provision: %d %s", rr.Code, rr.Body.String())
	}
	noSecretIn(t, "provision response", rr.Body.String(), secrets...)
	cs, _ := s.credStore()
	st := cs.WSSState()
	sec, _ := cs.WSSSecrets()
	ali := st.Listener("ali")
	hub := st.Listener("hk-hub")
	stdins := srv.Stdins()
	last := stdins[len(stdins)-1]
	for _, want := range []string{sec[ali.Cert.KeySecretID], sec[ali.Links[0].Path.SecretID], sec[hub.Link("ali-hub-wss").Path.SecretID]} {
		if !strings.Contains(last, strings.TrimSpace(want)) {
			t.Fatal("a WSS secret of this node did not reach the provision script")
		}
	}
	for _, other := range []string{sec[hub.Cert.KeySecretID], sec[hub.Link("gw-hub-wss").Path.SecretID]} {
		if strings.Contains(last, strings.TrimSpace(other)) {
			t.Fatal("another node's WSS secret reached this node")
		}
	}
	if ali.InstalledStage(model.WSSPartyServer) != 0 || hub.InstalledStage("client:ali-hub-wss") != 0 {
		t.Fatalf("stages not recorded: %+v %+v", ali.Installed, hub.Installed)
	}
	for _, p := range append(readOnlyViews, "/api/wss", "/api/provision/state") {
		noSecretIn(t, "GET "+p, do(s, http.MethodGet, p, nil).Body.String(), secrets...)
	}
	for _, v := range secrets {
		assertNowhereElse(t, s.DataDir, s.secretsDir(), v)
	}
	noSecretIn(t, "logs", logs.String(), secrets...)
}
