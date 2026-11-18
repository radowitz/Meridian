package api

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"

	"github.com/radowitz/meridian/internal/hostexec"
	"github.com/radowitz/meridian/internal/model"
	"github.com/radowitz/meridian/internal/sshexec"
)

// The whole panel flow once, in the panel's order, through the HTTP API:
//
//	credential → server → fingerprint → connection test → topology binding
//	→ remote preflight → first provision → gateway preflight → gateway
//	install → withdraw (remote node, then gateway)
//
// Every remote host is simulated: the remote node is the in-process SSH
// server (sshtest) answering the fixed preflight, the provision script and
// the withdraw script with synthetic output; the gateway is a real
// hostexec.Agent on a Unix socket, reached through the real hostexec.Client,
// whose program runner is simulated (nothing is executed) and whose
// pre-check reads a fake root. Addresses are documentation ranges, secrets
// are random per run, and nothing here touches a real host.
//
// At each step the next step is first tried too early and must be refused
// with the code the panel shows, then the prerequisite is done.

// simGateway is the gateway's program runner: systemctl, ip and nft answer
// like a Debian host on which meridian-up.sh succeeds. It records every call.
type simGateway struct {
	mu    sync.Mutex
	calls []string
	units map[string]bool // active
}

func (g *simGateway) Run(_ context.Context, prog string, args ...string) (string, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	line := prog + " " + strings.Join(args, " ")
	g.calls = append(g.calls, line)
	if prog == "systemctl" && len(args) >= 2 {
		switch args[0] {
		case "cat":
			if strings.HasPrefix(args[1], "meridian") {
				return "[Unit]\n", nil
			}
			return "", errSim
		case "restart":
			g.units[args[1]] = true
			return "", nil
		case "stop":
			delete(g.units, args[1])
			return "", nil
		case "is-active":
			if g.units[args[1]] {
				return "active\n", nil
			}
			return "inactive\n", errSim
		case "is-enabled":
			return "disabled\n", errSim
		}
		return "", nil
	}
	if prog == "docker" {
		return "", errSim
	}
	return "", nil
}

func (g *simGateway) ran(prefix string) int {
	g.mu.Lock()
	defer g.mu.Unlock()
	n := 0
	for _, c := range g.calls {
		if strings.HasPrefix(c, prefix) {
			n++
		}
	}
	return n
}

type simErr string

func (e simErr) Error() string { return string(e) }

const errSim = simErr("exit status 1")

// rootPreflight passes the agent's pre-check report through unchanged except
// for the uid line: the test does not run as root, the agent in production
// does (meridian-host.service). Everything else comes from the agent.
type rootPreflight struct{ c *hostexec.Client }

var uidLine = regexp.MustCompile(`(?m)^uid \d+$`)

func (p rootPreflight) Preflight(ctx context.Context, paths []string) (string, error) {
	rep, err := p.c.Preflight(ctx, paths)
	return uidLine.ReplaceAllString(rep, "uid 0"), err
}

// startGatewayAgent serves a hostexec.Agent on a Unix socket in a short
// temporary directory (socket paths are limited to ~100 bytes).
func startGatewayAgent(t *testing.T) (*hostexec.Client, *simGateway) {
	t.Helper()
	dir, err := os.MkdirTemp("", "mh")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	tokenFile := filepath.Join(dir, "token")
	if _, err := hostexec.LoadOrCreateToken(tokenFile); err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(dir, "root")
	for p, body := range map[string]string{
		"etc/os-release":            "PRETTY_NAME=\"Debian GNU/Linux 13 (trixie)\"\nID=debian\nVERSION_ID=\"13\"\nVERSION_CODENAME=trixie\n",
		"proc/meminfo":              "MemTotal:        2015040 kB\nMemAvailable:    1650220 kB\n",
		"proc/sys/kernel/osrelease": "6.12.12-amd64\n",
		"usr/bin/wg":                "#!/bin/sh\n",
		"usr/sbin/nft":              "#!/bin/sh\n",
		"usr/sbin/ip":               "#!/bin/sh\n",
		"usr/bin/systemctl":         "#!/bin/sh\n",
		"usr/sbin/smartdns":         "#!/bin/sh\n",
		"usr/bin/wstunnel":          "#!/bin/sh\n",
		"usr/bin/apt-get":           "#!/bin/sh\n",
	} {
		full := filepath.Join(root, p)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(body), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.MkdirAll(filepath.Join(root, "run/systemd/system"), 0o755); err != nil {
		t.Fatal(err)
	}
	sim := &simGateway{units: map[string]bool{}}
	agent := &hostexec.Agent{
		Token:         func() (string, error) { return hostexec.LoadOrCreateToken(tokenFile) },
		Runner:        sim,
		PreflightRoot: root,
	}
	l, err := hostexec.ListenUnix(filepath.Join(dir, "s", "agent.sock"))
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = agent.Serve(l) }()
	t.Cleanup(func() { l.Close() })
	return &hostexec.Client{Socket: filepath.Join(dir, "s", "agent.sock"), TokenFile: tokenFile, Retries: 1}, sim
}

func TestPanelFlowEndToEnd(t *testing.T) {
	s := newTest(t)
	s.HostRoot = t.TempDir()
	client, gw := startGatewayAgent(t)
	s.Host, s.Prober, s.HostPreflight = client, nil, rootPreflight{client}

	// The remote exit "tw": an SSH server that answers the test command,
	// the fixed preflight, the provision script and the withdraw script.
	srv := startSSH(t)
	pw := "pw-" + rnd(t, 8)
	srv.SetPassword(pw)
	var mu sync.Mutex
	var provisionRuns, withdrawRuns int
	srv.SetHandler(func(cmd, stdin string) (string, uint32) {
		if cmd == sshexec.TestCommand {
			return "MERIDIAN_ARCH=x86_64\nMERIDIAN_KERNEL=6.12.12\nPRETTY_NAME=\"Debian GNU/Linux 13 (trixie)\"\n", 0
		}
		if out, ok := cleanPreflight(cmd, stdin, ""); ok {
			return out, 0
		}
		if cmd != "bash -s" {
			return "unexpected", 1
		}
		mu.Lock()
		defer mu.Unlock()
		switch {
		case strings.Contains(stdin, "# Meridian withdraw"):
			withdrawRuns++
			if scriptVars(stdin)["ACTION"] == "plan" {
				return planOK(), 0
			}
			return "MERIDIAN_REMOVED iface m14\nMERIDIAN_REMOVED file /etc/wireguard/m14.conf\nMERIDIAN_WITHDRAW_OK\n", 0
		case strings.Contains(stdin, "echo MERIDIAN_PROVISION_OK"):
			provisionRuns++
			return "MERIDIAN_PROVISION_OK\n", 0
		}
		return "unexpected", 1
	})
	runs := func() (int, int) { mu.Lock(); defer mu.Unlock(); return provisionRuns, withdrawRuns }
	refuse := func(step string, rr interface {
		Result() *http.Response
	}, status int, code string) {
		t.Helper()
		res := rr.Result()
		var body struct {
			Code  string `json:"code"`
			Error string `json:"error"`
		}
		_ = json.NewDecoder(res.Body).Decode(&body)
		if res.StatusCode != status || body.Code != code {
			t.Fatalf("%s: want %d %s, got %d %s (%s)", step, status, code, res.StatusCode, body.Code, body.Error)
		}
	}

	// Topology with every other peer keyed (they would have been provisioned
	// the same way); "tw" has no key yet.
	var topo model.Topology
	decode(t, do(s, http.MethodGet, "/api/topology", nil), &topo)
	for i := range topo.Nodes {
		if id := topo.Nodes[i].ID; id != localNodeID && id != "tw" {
			raw := make([]byte, 32)
			for j := range raw {
				raw[j] = byte(i + 1)
			}
			topo.Nodes[i].PublicKey = base64.StdEncoding.EncodeToString(raw)
		}
	}
	putTopo := func(step string, topo model.Topology) *http.Response {
		t.Helper()
		return do(s, http.MethodPut, "/api/topology", mustJSON(topo)).Result()
	}
	if res := putTopo("seed", topo); res.StatusCode != 200 {
		t.Fatalf("seed topology: %d", res.StatusCode)
	}

	// 1. Credential. A server cannot name a credential that does not exist.
	rr := do(s, http.MethodPost, "/api/servers", mustJSON(map[string]any{"name": "台湾出口", "address": srv.Host, "port": srv.Port, "user": "root", "auth": "password", "credential_id": "cred-missing"}))
	if rr.Code < 400 || rr.Code >= 500 {
		t.Fatalf("server with a missing credential: %d %s", rr.Code, rr.Body.String())
	}
	var c struct{ Credential credView }
	decode(t, do(s, http.MethodPost, "/api/ssh-credentials", mustJSON(map[string]any{"name": "运维密码", "kind": "password", "password": pw})), &c)
	if c.Credential.ID == "" {
		t.Fatal("credential not created")
	}

	// 2. Server.
	var sv struct{ Server serverView }
	decode(t, do(s, http.MethodPost, "/api/servers", mustJSON(map[string]any{"name": "台湾出口", "address": srv.Host, "port": srv.Port, "user": "root", "auth": "password", "credential_id": c.Credential.ID})), &sv)
	id := sv.Server.ID
	if id == "" || sv.Server.Ready {
		t.Fatalf("server %+v", sv.Server)
	}

	// 3. Fingerprint. Before trust nothing logs in: the connection test is
	// refused; a fingerprint that is not the one discovered is not trusted.
	refuse("test before trust", do(s, http.MethodPost, "/api/servers/"+id+"/test", nil), http.StatusConflict, sshexec.CodeUntrusted)
	if srv.AuthAttempts() != 0 {
		t.Fatal("logged in before the host key was trusted")
	}
	var disc struct{ Discovery sshexec.Discovery }
	decode(t, do(s, http.MethodPost, "/api/servers/"+id+"/host-key/discover", nil), &disc)
	if disc.Discovery.Fingerprint != srv.Fingerprint() {
		t.Fatalf("discovered %q", disc.Discovery.Fingerprint)
	}
	if rr := do(s, http.MethodPost, "/api/servers/"+id+"/host-key/trust", mustJSON(map[string]string{"fingerprint": "SHA256:" + strings.Repeat("A", 43)})); rr.Code == 200 {
		t.Fatalf("trusted a fingerprint that was not discovered: %s", rr.Body.String())
	}
	if rr := do(s, http.MethodPost, "/api/servers/"+id+"/host-key/trust", mustJSON(map[string]string{"fingerprint": disc.Discovery.Fingerprint})); rr.Code != 200 {
		t.Fatalf("trust: %d %s", rr.Code, rr.Body.String())
	}

	// 4. Connection test: the server is "ready" only after it passed.
	decode(t, do(s, http.MethodGet, "/api/servers/"+id, nil), &sv)
	if sv.Server.Ready || !sv.Server.Operable {
		t.Fatalf("trusted, untested: %+v", sv.Server)
	}
	var tr struct {
		Test   model.ConnectionTest
		Server serverView
	}
	decode(t, do(s, http.MethodPost, "/api/servers/"+id+"/test", nil), &tr)
	if !tr.Test.OK || !tr.Server.Ready {
		t.Fatalf("test: %+v", tr)
	}

	// 5. Topology binding: without it the node has no server to run on.
	refuse("preflight before binding", do(s, http.MethodPost, "/api/provision/preflight", mustJSON(map[string]any{"node_id": "tw"})), http.StatusConflict, codeNoServer)
	decode(t, do(s, http.MethodGet, "/api/topology", nil), &topo)
	for i := range topo.Nodes {
		if topo.Nodes[i].ID == "tw" {
			topo.Nodes[i].ServerID, topo.Nodes[i].SSHHost, topo.Nodes[i].SSHPort, topo.Nodes[i].SSHUser = id, "", 0, ""
		}
	}
	if res := putTopo("bind", topo); res.StatusCode != 200 {
		t.Fatalf("bind: %d", res.StatusCode)
	}

	// 6. Remote preflight: a first install without a reviewed one is refused
	// before a key is generated or the script runs.
	refuse("provision before preflight", do(s, http.MethodPost, "/api/provision", []byte(`{"node_id":"tw","generate_keys":true}`)), http.StatusConflict, codePreflightRequired)
	if p, _ := runs(); p != 0 || storedNode(t, s, "tw").PrivateKey != "" {
		t.Fatal("refused provision ran the script or generated a key")
	}
	// The gateway refuses a first install without a reviewed preflight too.
	// (A gateway install does not wait for exit nodes: only its direct
	// WireGuard peers need keys, covered by TestApplyInstallRefusesMissingPeerKeys.)
	refuse("gateway install before any preflight", do(s, http.MethodPost, "/api/apply", []byte(`{"install":true}`)), http.StatusConflict, codePreflightRequired)
	pid := reviewPreflight(t, s, "tw")

	// 7. First provision.
	rr = do(s, http.MethodPost, "/api/provision", mustJSON(map[string]any{"node_id": "tw", "generate_keys": true, "preflight_id": pid}))
	if rr.Code != 200 || !strings.Contains(rr.Body.String(), `"outcome":"installed"`) {
		t.Fatalf("provision: %d %s", rr.Code, rr.Body.String())
	}
	tw := storedNode(t, s, "tw")
	if tw.PublicKey == "" || tw.PrivateKey == "" {
		t.Fatal("provision did not leave a key pair")
	}
	if d := deployment(t, s, "tw"); !d.OnHost || d.Fingerprint != srv.Fingerprint() || d.ServerID != id {
		t.Fatalf("deployment record %+v", d)
	}

	// 8. Gateway preflight: still required, and nothing reached the
	// agent's activate before it.
	refuse("gateway install before preflight", do(s, http.MethodPost, "/api/apply", []byte(`{"install":true}`)), http.StatusConflict, codePreflightRequired)
	if gw.ran("systemctl restart meridian.service") != 0 {
		t.Fatal("activated before the gateway preflight")
	}
	var hp struct{ Preflight preflightRecord }
	rr = do(s, http.MethodPost, "/api/host/preflight", nil)
	decode(t, rr, &hp)
	if rr.Code != 200 || hp.Preflight.Kind != "gateway" || hp.Preflight.Blocking || hp.Preflight.ID == "" {
		t.Fatalf("gateway preflight: %d %s", rr.Code, rr.Body.String())
	}

	// A reviewed preflight is bound to the bundle it saw: a topology edit
	// after the review makes it stale.
	decode(t, do(s, http.MethodGet, "/api/topology", nil), &topo)
	topo.Rules = append(topo.Rules, model.Rule{ID: "e2e-rule", Name: "e2e", Manual: true, Enabled: true, Priority: 9999,
		MatchType: "domain", MatchValue: "example.net", TargetGroup: topo.Settings.DefaultGroup})
	if res := putTopo("edit", topo); res.StatusCode != 200 {
		t.Fatalf("edit: %d", res.StatusCode)
	}
	refuse("gateway install with a preflight of another bundle", do(s, http.MethodPost, "/api/apply", mustJSON(map[string]any{"install": true, "preflight_id": hp.Preflight.ID})), http.StatusConflict, codeBundleChanged)
	decode(t, do(s, http.MethodPost, "/api/host/preflight", nil), &hp)

	// 9. Gateway install through the agent: activated, committed, in sync.
	rr = do(s, http.MethodPost, "/api/apply", mustJSON(map[string]any{"install": true, "preflight_id": hp.Preflight.ID}))
	if rr.Code != 200 {
		t.Fatalf("install: %d %s", rr.Code, rr.Body.String())
	}
	var inst struct {
		Host struct {
			Committed bool `json:"committed"`
			Sysctl    *struct {
				Checked bool `json:"checked"`
				Written []any
			} `json:"sysctl"`
		} `json:"host"`
	}
	decode(t, rr, &inst)
	if !inst.Host.Committed || inst.Host.Sysctl == nil || inst.Host.Sysctl.Checked || len(inst.Host.Sysctl.Written) == 0 {
		t.Fatalf("install report: %s", rr.Body.String())
	}
	if gw.ran("systemctl restart meridian.service") != 1 {
		t.Fatalf("meridian.service restarted %d times", gw.ran("systemctl restart meridian.service"))
	}
	st := getStatus(t, s)
	if st.Install.State != "in_sync" || !st.Agent.OK {
		t.Fatalf("status after install: %+v %+v", st.Install, st.Agent)
	}

	// 10. Withdraw. The remote node: plan first, explicit confirmation.
	code, out := wdPlan(t, s, "tw", "")
	if code != 200 {
		t.Fatalf("withdraw plan: %d %v", code, out)
	}
	plan := planID(t, out)
	if c, o := wdRun(s, "tw", plan, ""); c != http.StatusBadRequest || o["code"] != codeConfirmRequired {
		t.Fatalf("withdraw without confirmation: %d %v", c, o)
	}
	if c, o := wdRun(s, "tw", plan, "tw"); c != 200 || o["outcome"] != withdrawStateDone {
		t.Fatalf("withdraw: %d %v", c, o)
	}
	if d := deployment(t, s, "tw"); d.OnHost || d.Status != "withdrawn" {
		t.Fatalf("after withdraw %+v", d)
	}
	// The gateway: confirmation names the node, the guard stays.
	refuse("gateway withdraw without confirmation", do(s, http.MethodPost, "/api/host/withdraw", mustJSON(map[string]any{"confirm": "yes"})), http.StatusBadRequest, codeConfirmRequired)
	rr = do(s, http.MethodPost, "/api/host/withdraw", mustJSON(map[string]any{"confirm": localNodeID}))
	if rr.Code != 200 || !strings.Contains(rr.Body.String(), `"status":"withdrawn"`) {
		t.Fatalf("gateway withdraw: %d %s", rr.Code, rr.Body.String())
	}
	if gw.ran("sysctl -w net.ipv4.ip_forward=0") == 0 || gw.ran("nft list table inet meridian_guard") == 0 {
		t.Fatal("gateway withdraw did not turn forwarding off and check the guard")
	}
	if st := getStatus(t, s); st.Install.State != "withdrawn" {
		t.Fatalf("status after withdraw: %+v", st.Install)
	}
	if _, w := runs(); w < 2 {
		t.Fatalf("withdraw scripts run: %d", w)
	}

	// No secret in any response the panel serves for this flow.
	for _, p := range []string{"/api/topology", "/api/servers", "/api/ssh-credentials", "/api/deployments", "/api/status", "/api/host", "/api/provision/state"} {
		noSecretIn(t, p, do(s, http.MethodGet, p, nil).Body.String(), pw, tw.PrivateKey)
	}
}
