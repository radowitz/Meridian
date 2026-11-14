package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/radowitz/meridian/internal/artifacts"
	"github.com/radowitz/meridian/internal/compile"
	"github.com/radowitz/meridian/internal/hostexec"
	"github.com/radowitz/meridian/internal/model"
	"github.com/radowitz/meridian/internal/preflight"
	"github.com/radowitz/meridian/internal/sshexec"
	"github.com/radowitz/meridian/internal/sshexec/sshtest"
	"github.com/radowitz/meridian/internal/validate"
)

// cleanReport is a fresh Debian 13 host with nothing in the way.
const cleanReport = `meridian-preflight 1
uid 0
arch x86_64
kernel 6.12.12-amd64
os-id debian
os-version 13
os-pretty Debian GNU/Linux 13 (trixie)
systemd yes
mem-total-kb 2015040
mem-avail-kb 1650220
disk-avail-kb 15000000
cmd wg yes
cmd nft yes
cmd ip yes
cmd apt-get yes
cmd systemctl yes
cmd smartdns yes
cmd wstunnel yes
sysctl net.ipv4.ip_forward 1
sysctl net.ipv6.conf.all.forwarding 1
link lo
link eth0
addr eth0 192.0.2.10/24
route4 default via 192.0.2.1 dev eth0
route4 192.0.2.0/24 dev eth0 proto kernel scope link src 192.0.2.10
rule4 0:	from all lookup local
rule4 32766:	from all lookup main
ss tcp LISTEN 0 128 0.0.0.0:22 0.0.0.0:* users:(("sshd",pid=512,fd=3))
unit docker.service inactive not-found 0
nftables-conf absent
`

// cleanPreflight answers the fixed preflight (and only it) with the clean
// report plus extra, listing every requested path as absent.
func cleanPreflight(cmd, stdin, extra string) (string, bool) {
	if stdin != preflight.Script() || !strings.HasPrefix(cmd, "bash -s") {
		return "", false
	}
	var b strings.Builder
	b.WriteString(cleanReport)
	if _, args, ok := strings.Cut(cmd, " -- "); ok {
		for _, a := range strings.Fields(args) {
			p := strings.Trim(a, "'")
			// The panel-delivered binaries are already there with the
			// pinned digest (no transfer); TestProvisionStagesBinaries
			// covers the transfer.
			if name, ok := strings.CutPrefix(p, "/usr/local/sbin/meridian-"); ok && preflight.IsArtifactPath(p) {
				data := fakeArtifact(name, "x86_64")
				b.WriteString(fmt.Sprintf("path %s file %d no %s\n", p, len(data), artifacts.SHA256Of(data)))
				continue
			}
			b.WriteString("path " + p + " absent\n")
		}
	}
	b.WriteString(extra)
	b.WriteString(preflight.EndMarker + "\n")
	return b.String(), true
}

// reviewPreflight runs the preflight for node and returns its id.
func reviewPreflight(t *testing.T, s *Server, node string) string {
	t.Helper()
	rr := do(s, http.MethodPost, "/api/provision/preflight", mustJSON(map[string]any{"node_id": node}))
	var out struct{ Preflight preflightRecord }
	if rr.Code != http.StatusOK || json.Unmarshal(rr.Body.Bytes(), &out) != nil || out.Preflight.ID == "" {
		t.Fatalf("preflight: %d %s", rr.Code, rr.Body.String())
	}
	return out.Preflight.ID
}

// gateFix is a node "tw" on a trusted password server whose SSH handler
// answers the preflight with the clean report plus a switchable extra, and
// the provision script with a switchable answer.
type gateFix struct {
	s      *Server
	srv    *sshtest.Server
	id     string
	credID string
	pw     string
	mu     sync.Mutex
	extra  string
	script func(stdin string) (string, uint32)
	// host is the synthetic host's own record (journal and manifest
	// header) that NodeStateCommand reads; hostRecord, when set, decides
	// it from the last script and its answer instead of the default.
	host       string
	hostRecord func(stdin, out string, code uint32) string
}

// scriptVar reads a M_<NAME>='…' assignment of a provision script.
func scriptVar(stdin, name string) string {
	_, rest, ok := strings.Cut(stdin, "\n"+name+"='")
	if !ok {
		return ""
	}
	v, _, _ := strings.Cut(rest, "'")
	return v
}

// defaultHostRecord is what a real host's journal and manifest would say
// after the script answered out.
func defaultHostRecord(stdin, out string, prev string) string {
	run, node, dep, srv, bundle := scriptVar(stdin, "M_RUN"), scriptVar(stdin, "M_NODE"), scriptVar(stdin, "M_DEPLOYMENT"), scriptVar(stdin, "M_SERVER"), scriptVar(stdin, "M_BUNDLE")
	j := func(state string) string {
		return "journal meridian-node-journal 1\njournal state " + state + "\njournal node " + node + "\njournal deployment " + dep + "\njournal run " + run + "\n"
	}
	man := func() string {
		return "manifest node " + node + "\nmanifest deployment " + dep + "\nmanifest server " + srv + "\nmanifest bundle " + bundle + "\n"
	}
	keepMan := ""
	for _, l := range strings.Split(prev, "\n") {
		if strings.HasPrefix(l, "manifest ") {
			keepMan += l + "\n"
		}
	}
	switch {
	case strings.Contains(out, "MERIDIAN_PROVISION_OK"):
		return j("done") + man()
	case strings.Contains(out, "MERIDIAN_COMPENSATED"):
		return j("compensated") + keepMan
	case strings.Contains(out, "MERIDIAN_COMPENSATION_INCOMPLETE"):
		return j("incomplete") + keepMan
	}
	return prev
}

func (f *gateFix) setExtra(e string) { f.mu.Lock(); f.extra = e; f.mu.Unlock() }

func newGateFix(t *testing.T) *gateFix {
	t.Helper()
	f := &gateFix{s: newTest(t)}
	do(f.s, http.MethodGet, "/api/topology", nil)
	f.srv = startSSH(t)
	f.pw = "pw-" + rnd(t, 8)
	f.srv.SetPassword(f.pw)
	f.script = func(string) (string, uint32) { return "MERIDIAN_PROVISION_OK\n", 0 }
	f.srv.SetHandler(func(cmd, stdin string) (string, uint32) {
		f.mu.Lock()
		extra, script := f.extra, f.script
		f.mu.Unlock()
		if out, ok := cleanPreflight(cmd, stdin, extra); ok {
			return out, 0
		}
		if cmd == "bash -s" && strings.Contains(stdin, "echo MERIDIAN_PROVISION_OK") {
			out, code := script(stdin)
			f.mu.Lock()
			if f.hostRecord != nil {
				f.host = f.hostRecord(stdin, out, code)
			} else {
				f.host = defaultHostRecord(stdin, out, f.host)
			}
			f.mu.Unlock()
			return out, code
		}
		if cmd == sshexec.NodeStateCommand {
			f.mu.Lock()
			h := f.host
			f.mu.Unlock()
			return "meridian-node-state 1\n" + h + "meridian-node-state-end\n", 0
		}
		if cmd == sshexec.TestCommand {
			return "MERIDIAN_ARCH=x86_64\n", 0
		}
		return "unexpected", 1
	})
	rr := do(f.s, http.MethodPost, "/api/ssh-credentials", mustJSON(map[string]any{"name": "pw", "kind": "password", "password": f.pw}))
	var c struct{ Credential credView }
	decode(t, rr, &c)
	f.credID = c.Credential.ID
	rr = do(f.s, http.MethodPost, "/api/servers", mustJSON(map[string]any{"name": "台湾出口", "address": f.srv.Host, "port": f.srv.Port, "user": "root", "auth": "password", "credential_id": c.Credential.ID}))
	var sv struct{ Server serverView }
	decode(t, rr, &sv)
	f.id = sv.Server.ID
	topo, _, _ := f.s.Store.Load()
	for i := range topo.Nodes {
		if topo.Nodes[i].ID == "tw" {
			topo.Nodes[i].ServerID, topo.Nodes[i].SSHHost, topo.Nodes[i].SSHPort, topo.Nodes[i].SSHUser = f.id, "", 0, ""
		}
	}
	if err := f.s.Store.Save(topo); err != nil {
		t.Fatal(err)
	}
	do(f.s, http.MethodPost, "/api/servers/"+f.id+"/host-key/discover", nil)
	if rr := do(f.s, http.MethodPost, "/api/servers/"+f.id+"/host-key/trust", mustJSON(map[string]string{"fingerprint": f.srv.Fingerprint()})); rr.Code != 200 {
		t.Fatal(rr.Body.String())
	}
	return f
}

// lastScript is the last provision script sent.
func lastScript(stdins []string) string {
	for i := len(stdins) - 1; i >= 0; i-- {
		if strings.Contains(stdins[i], "echo MERIDIAN_PROVISION_OK") {
			return stdins[i]
		}
	}
	return ""
}

func (f *gateFix) provisionScripts() int {
	n := 0
	for _, in := range f.srv.Stdins() {
		if strings.Contains(in, "echo MERIDIAN_PROVISION_OK") {
			n++
		}
	}
	return n
}

func (f *gateFix) preflight(t *testing.T) preflightRecord {
	t.Helper()
	rr := do(f.s, http.MethodPost, "/api/provision/preflight", mustJSON(map[string]any{"node_id": "tw"}))
	var out struct{ Preflight preflightRecord }
	if rr.Code != 200 || json.Unmarshal(rr.Body.Bytes(), &out) != nil {
		t.Fatalf("preflight: %d %s", rr.Code, rr.Body.String())
	}
	return out.Preflight
}

func (f *gateFix) provision(id string) *httptest.ResponseRecorder {
	body := map[string]any{"node_id": "tw", "generate_keys": true}
	if id != "" {
		body["preflight_id"] = id
	}
	return do(f.s, http.MethodPost, "/api/provision", mustJSON(body))
}

func TestProvisionPreflightPlanAndGates(t *testing.T) {
	var logs bytes.Buffer
	log.SetOutput(&logs)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })
	f := newGateFix(t)
	s := f.s

	// The plan: target identity, managed resources, intended changes.
	rec := f.preflight(t)
	if rec.Kind != "remote" || rec.Target == nil || rec.Target.Address != f.srv.Host || rec.Target.Port != f.srv.Port ||
		rec.Target.Fingerprint != f.srv.Fingerprint() || rec.Target.ServerID != f.id || rec.Target.CredentialID != f.credID {
		t.Fatalf("target %+v", rec.Target)
	}
	if rec.Blocking || !rec.FirstInstall || rec.Ownership != preflight.OwnNone || len(rec.Changes) == 0 || len(rec.Footprint.Files) == 0 ||
		len(rec.NotChecked) == 0 || rec.ExpiresAt.Sub(rec.At) != preflightTTL || len(rec.Bundle) != 64 {
		t.Fatalf("record %+v", rec)
	}
	// The command is the fixed script on stdin with validated paths only.
	cmds, stdins := f.srv.Commands(), f.srv.Stdins()
	last := cmds[len(cmds)-1]
	if stdins[len(stdins)-1] != preflight.Script() || !strings.HasPrefix(last, "bash -s -- '/etc/") || strings.ContainsAny(strings.ReplaceAll(last, "'", ""), ";|&$`") {
		t.Fatalf("preflight command %q", last)
	}
	if rr := do(s, http.MethodGet, "/api/provision/preflight/tw", nil); rr.Code != 200 || !strings.Contains(rr.Body.String(), rec.ID) {
		t.Fatalf("get: %d %s", rr.Code, rr.Body.String())
	}

	// First install without a reviewed preflight: refused before any key is
	// rotated and before the script runs. (The preflight itself gives every
	// managed node without a key its pair, panel-side only, so that peers'
	// configurations never carry a placeholder; a refused provision must
	// leave that key as it is.)
	keyBefore := storedNode(t, s, "tw").PrivateKey
	if rr := f.provision(""); rr.Code != http.StatusConflict || codeOf(t, rr.Body.Bytes()) != codePreflightRequired {
		t.Fatalf("required: %d %s", rr.Code, rr.Body.String())
	}
	if storedNode(t, s, "tw").PrivateKey != keyBefore || f.provisionScripts() != 0 {
		t.Fatal("refused provision generated or rotated a key, or ran the script")
	}

	// Stale.
	old := s.loadPreflight("tw")
	old.ExpiresAt = time.Now().Add(-time.Minute)
	if err := s.savePreflight(old); err != nil {
		t.Fatal(err)
	}
	if rr := f.provision(old.ID); rr.Code != http.StatusConflict || codeOf(t, rr.Body.Bytes()) != codePreflightStale {
		t.Fatalf("stale: %d %s", rr.Code, rr.Body.String())
	}
	// Unknown / replaced id.
	if rr := f.provision("pf-0000"); rr.Code != http.StatusConflict || codeOf(t, rr.Body.Bytes()) != codePreflightStale {
		t.Fatalf("unknown id: %d %s", rr.Code, rr.Body.String())
	}
	// Bundle changed since the review.
	rec = f.preflight(t)
	tampered := s.loadPreflight("tw")
	tampered.Bundle = strings.Repeat("0", 64)
	_ = s.savePreflight(tampered)
	if rr := f.provision(rec.ID); rr.Code != http.StatusConflict || codeOf(t, rr.Body.Bytes()) != codeBundleChanged {
		t.Fatalf("bundle: %d %s", rr.Code, rr.Body.String())
	}
	// Target identity changed: the server now uses another credential.
	rec = f.preflight(t)
	rr := do(s, http.MethodPost, "/api/ssh-credentials", mustJSON(map[string]any{"name": "pw2", "kind": "password", "password": f.pw}))
	var c2 struct{ Credential credView }
	decode(t, rr, &c2)
	if rr := do(s, http.MethodPatch, "/api/servers/"+f.id, mustJSON(map[string]any{"credential_id": c2.Credential.ID})); rr.Code != 200 {
		t.Fatal(rr.Body.String())
	}
	if rr := f.provision(rec.ID); rr.Code != http.StatusConflict || codeOf(t, rr.Body.Bytes()) != sshexec.CodeTargetChanged {
		t.Fatalf("target changed: %d %s", rr.Code, rr.Body.String())
	}
	// Blocking findings in the reviewed result.
	f.setExtra("ipt ipv4 -P FORWARD DROP\nunit docker.service active enabled 7\n")
	rec = f.preflight(t)
	if !rec.Blocking || rec.Counts.Blocking == 0 {
		t.Fatalf("not blocking: %+v", rec.Findings)
	}
	if rr := f.provision(rec.ID); rr.Code != http.StatusConflict || codeOf(t, rr.Body.Bytes()) != codePreflightBlocked {
		t.Fatalf("blocked: %d %s", rr.Code, rr.Body.String())
	}
	// Clean when reviewed, blocking when re-run right before execution.
	f.setExtra("")
	rec = f.preflight(t)
	f.setExtra("ss udp UNCONN 0 0 0.0.0.0:53 0.0.0.0:* users:((\"dnsmasq\",pid=9,fd=4))\n")
	rr = f.provision(rec.ID)
	if rr.Code != http.StatusConflict || codeOf(t, rr.Body.Bytes()) != codePreflightBlocked || !strings.Contains(rr.Body.String(), preflight.CodePortInUse) {
		t.Fatalf("re-run blocked: %d %s", rr.Code, rr.Body.String())
	}
	// A new warning since the review.
	f.setExtra("")
	rec = f.preflight(t)
	f.setExtra("unit ufw.service active enabled 3\n")
	if rr := f.provision(rec.ID); rr.Code != http.StatusConflict || codeOf(t, rr.Body.Bytes()) != codePreflightChanged {
		t.Fatalf("changed: %d %s", rr.Code, rr.Body.String())
	}
	if storedNode(t, s, "tw").PrivateKey != keyBefore || f.provisionScripts() != 0 {
		t.Fatal("a refused provision generated or rotated a key, or ran the script")
	}

	// Passes: reviewed, re-run clean, script runs with the pinned identity.
	f.setExtra("")
	rec = f.preflight(t)
	rr = f.provision(rec.ID)
	if rr.Code != 200 || !strings.Contains(rr.Body.String(), `"outcome":"installed"`) || f.provisionScripts() != 1 {
		t.Fatalf("pass: %d %s", rr.Code, rr.Body.String())
	}
	in := lastScript(f.srv.Stdins())
	if !strings.Contains(in, "M_EXPECT='none'") || !strings.Contains(in, "M_NODE='tw'") || !strings.Contains(in, "M_BUNDLE='"+rec.Bundle+"'") {
		t.Fatal("script not bound to the preflight")
	}
	if st := s.loadOutcomes()["tw"]; !st.OK || !st.Installed || st.ServerID != f.id {
		t.Fatalf("outcome %+v", st)
	}
	// Later runs (updates) need no reviewed id; the preflight still runs.
	before := len(f.srv.Commands())
	if rr := do(s, http.MethodPost, "/api/provision", []byte(`{"node_id":"tw"}`)); rr.Code != 200 {
		t.Fatalf("update: %d %s", rr.Code, rr.Body.String())
	}
	if cmds := f.srv.Commands()[before:]; len(cmds) != 3 || cmds[2] != sshexec.NodeStateCommand {
		t.Fatalf("update ran %q, want preflight + script + the read-only node-state read", cmds)
	}
	// ... and is still refused when the re-run blocks.
	f.setExtra("ipt ipv4 -P FORWARD DROP\n")
	if rr := do(s, http.MethodPost, "/api/provision", []byte(`{"node_id":"tw"}`)); rr.Code != http.StatusConflict || codeOf(t, rr.Body.Bytes()) != codePreflightBlocked {
		t.Fatalf("update blocked: %d %s", rr.Code, rr.Body.String())
	}
	// No secret in any response or log.
	tw := storedNode(t, s, "tw")
	for _, p := range []string{"/api/provision/preflight/tw", "/api/provision/state"} {
		noSecretIn(t, p, do(s, http.MethodGet, p, nil).Body.String(), f.pw, tw.PrivateKey)
	}
	noSecretIn(t, "logs", logs.String(), f.pw, tw.PrivateKey)
	assertNowhereElse(t, s.DataDir, s.secretsDir(), f.pw)
}

func TestProvisionFailureOutcomes(t *testing.T) {
	f := newGateFix(t)
	s := f.s
	run := func(answer string, code uint32) (int, string, map[string]any) {
		f.mu.Lock()
		f.script = func(string) (string, uint32) { return answer, code }
		f.mu.Unlock()
		rec := f.preflight(t)
		rr := f.provision(rec.ID)
		var body map[string]any
		_ = json.Unmarshal(rr.Body.Bytes(), &body)
		return rr.Code, rr.Body.String(), body
	}
	status, raw, body := run("MERIDIAN_COMPENSATING exit=1\nMERIDIAN_KEPT package wireguard-tools\nMERIDIAN_COMPENSATED\n", 1)
	if status != http.StatusBadGateway || body["code"] != codeProvisionCompensated || body["outcome"] != "compensated" || !strings.Contains(raw, "wireguard-tools") {
		t.Fatalf("compensated: %d %s", status, raw)
	}
	if st := s.loadOutcomes()["tw"]; st.OK || st.Installed || st.Code != codeProvisionCompensated {
		t.Fatalf("outcome %+v", st)
	}
	status, raw, body = run("MERIDIAN_COMPENSATING exit=1\nMERIDIAN_LEFTOVER interface m14\nMERIDIAN_COMPENSATION_INCOMPLETE\n", 1)
	if status != http.StatusBadGateway || body["code"] != codeProvisionLeftovers || body["outcome"] != "left_behind" {
		t.Fatalf("leftovers: %d %s", status, raw)
	}
	if left, _ := body["leftovers"].([]any); len(left) != 1 || left[0] != "interface m14" {
		t.Fatalf("leftovers list %v", body["leftovers"])
	}
	status, raw, body = run("MERIDIAN_REFUSED manifest_appeared\n", 3)
	if status != http.StatusConflict || body["code"] != codeProvisionRefused || body["reason"] != "manifest_appeared" {
		t.Fatalf("refused: %d %s", status, raw)
	}
	// Exit 0 without the success marker is never success.
	status, raw, body = run("something else\n", 0)
	if status != http.StatusBadGateway || body["outcome"] != "unknown" {
		t.Fatalf("unknown: %d %s", status, raw)
	}
	// Still a first install: nothing ever succeeded.
	if rr := f.provision(""); codeOf(t, rr.Body.Bytes()) != codePreflightRequired {
		t.Fatalf("after failures: %d %s", rr.Code, rr.Body.String())
	}
	if st := s.loadOutcomes()["tw"]; st.Installed || st.Code != sshexec.CodeCommandFailed {
		t.Fatalf("state %+v", st)
	}
}

// Login-method errors: accurate code and the copyable public key.
func TestLoginHelp(t *testing.T) {
	f := newGateFix(t)
	s := f.s
	// A panel-generated key credential exists.
	rr := do(s, http.MethodPost, "/api/ssh-credentials", mustJSON(map[string]any{"name": "面板密钥", "kind": "private_key", "generate": true}))
	var kc struct{ Credential credView }
	decode(t, rr, &kc)
	if kc.Credential.PublicKey == "" {
		t.Fatalf("generated key %s", rr.Body.String())
	}
	// The server accepts only keys; the credential is a password.
	f.srv.OfferOnly("publickey")
	rr = do(s, http.MethodPost, "/api/provision/preflight", mustJSON(map[string]any{"node_id": "tw"}))
	var body struct {
		Code      string
		LoginHelp *loginHelp `json:"login_help"`
	}
	_ = json.Unmarshal(rr.Body.Bytes(), &body)
	if rr.Code != http.StatusBadGateway || body.Code != sshexec.CodeAuthMethodUnavailable || body.LoginHelp == nil ||
		len(body.LoginHelp.KeyCredentials) != 1 || body.LoginHelp.KeyCredentials[0].PublicKey != kc.Credential.PublicKey {
		t.Fatalf("password not offered: %d %s", rr.Code, rr.Body.String())
	}
	rr = do(s, http.MethodPost, "/api/servers/"+f.id+"/test", nil)
	if !strings.Contains(rr.Body.String(), `"login_help"`) || !strings.Contains(rr.Body.String(), kc.Credential.PublicKey) {
		t.Fatalf("test: %s", rr.Body.String())
	}
	// Switch the server to the key; the key is not in authorized_keys yet.
	f.srv.OfferOnly()
	if rr := do(s, http.MethodPatch, "/api/servers/"+f.id, mustJSON(map[string]any{"auth": "key", "credential_id": kc.Credential.ID})); rr.Code != 200 {
		t.Fatal(rr.Body.String())
	}
	rr = do(s, http.MethodPost, "/api/provision/preflight", mustJSON(map[string]any{"node_id": "tw"}))
	_ = json.Unmarshal(rr.Body.Bytes(), &body)
	if body.Code != sshexec.CodeAuthFailed || body.LoginHelp == nil || body.LoginHelp.PublicKey != kc.Credential.PublicKey ||
		!strings.Contains(strings.Join(body.LoginHelp.Steps, " "), "authorized_keys") {
		t.Fatalf("key rejected: %d %s", rr.Code, rr.Body.String())
	}
	if strings.Contains(rr.Body.String(), "PRIVATE KEY") || strings.Contains(rr.Body.String(), f.pw) {
		t.Fatal("secret in login help")
	}
	if !body.LoginHelp.KeyOffered || !containsString(body.LoginHelp.Offered, "publickey") {
		t.Fatalf("key rejected: publickey must be reported as offered: %+v", body.LoginHelp)
	}
	// Public key login not offered at all (a password-only server such as
	// the IX): no public key is shown, the way forward is its password.
	f.srv.OfferOnly("password")
	body.Code, body.LoginHelp = "", nil
	rr = do(s, http.MethodPost, "/api/provision/preflight", mustJSON(map[string]any{"node_id": "tw"}))
	_ = json.Unmarshal(rr.Body.Bytes(), &body)
	steps := ""
	if body.LoginHelp != nil {
		steps = strings.Join(body.LoginHelp.Steps, " ")
	}
	if body.Code != sshexec.CodeAuthMethodUnavailable || body.LoginHelp == nil || body.LoginHelp.PublicKey != "" || len(body.LoginHelp.KeyCredentials) != 0 ||
		body.LoginHelp.KeyOffered || !containsString(body.LoginHelp.Offered, "password") || !strings.Contains(steps, "密码凭据") || !strings.Contains(steps, "PubkeyAuthentication") {
		t.Fatalf("key not offered: %d %s", rr.Code, rr.Body.String())
	}
	if strings.Contains(rr.Body.String(), kc.Credential.PublicKey) {
		t.Fatal("a public key must not be suggested to a server that does not offer publickey")
	}
	rr = do(s, http.MethodPost, "/api/servers/"+f.id+"/test", nil)
	var tb struct {
		Test struct {
			Code    string
			Offered []string `json:"offered_methods"`
		}
		LoginHelp *loginHelp `json:"login_help"`
	}
	_ = json.Unmarshal(rr.Body.Bytes(), &tb)
	if tb.Test.Code != sshexec.CodeAuthMethodUnavailable || !containsString(tb.Test.Offered, "password") || tb.LoginHelp == nil || tb.LoginHelp.PublicKey != "" || strings.Contains(rr.Body.String(), kc.Credential.PublicKey) {
		t.Fatalf("connection test on a password-only server: %s", rr.Body.String())
	}

	// Back to the password credential on the password-only server: it
	// works, nothing suggests a key.
	if rr := do(s, http.MethodPatch, "/api/servers/"+f.id, mustJSON(map[string]any{"auth": "password", "credential_id": f.credID})); rr.Code != 200 {
		t.Fatal(rr.Body.String())
	}
	rr = do(s, http.MethodPost, "/api/servers/"+f.id+"/test", nil)
	if !strings.Contains(rr.Body.String(), `"ok":true`) || strings.Contains(rr.Body.String(), `"login_help"`) {
		t.Fatalf("password-only server with its password: %s", rr.Body.String())
	}
	// A wrong password on the password-only server: update the password,
	// no key advice.
	f.srv.SetPassword("another-" + f.pw)
	tb.LoginHelp = nil
	rr = do(s, http.MethodPost, "/api/servers/"+f.id+"/test", nil)
	_ = json.Unmarshal(rr.Body.Bytes(), &tb)
	if tb.LoginHelp == nil || tb.LoginHelp.Code != sshexec.CodeAuthFailed || len(tb.LoginHelp.KeyCredentials) != 0 || tb.LoginHelp.KeyOffered || strings.Contains(rr.Body.String(), kc.Credential.PublicKey) {
		t.Fatalf("wrong password, password-only: %s", rr.Body.String())
	}
	// A wrong password on a server that also offers publickey: the key
	// is offered as an alternative.
	f.srv.OfferOnly()
	tb.LoginHelp = nil
	rr = do(s, http.MethodPost, "/api/servers/"+f.id+"/test", nil)
	_ = json.Unmarshal(rr.Body.Bytes(), &tb)
	if tb.LoginHelp == nil || tb.LoginHelp.Code != sshexec.CodeAuthFailed || !tb.LoginHelp.KeyOffered || len(tb.LoginHelp.KeyCredentials) != 1 || tb.LoginHelp.KeyCredentials[0].PublicKey != kc.Credential.PublicKey {
		t.Fatalf("wrong password, publickey offered: %s", rr.Body.String())
	}
}

func containsString(list []string, v string) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}

// ------------------------------------------------------------ gateway ---

type fakeHostPreflight struct {
	mu sync.Mutex
	// raw, when set, is a whole report template (testdata of
	// internal/preflight): @PATHS@ becomes every requested path present
	// with a Meridian marker, followed by extra.
	raw   string
	extra string
	err   error
	calls int
	paths []string
}

func (f *fakeHostPreflight) Preflight(_ context.Context, paths []string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	f.paths = paths
	if f.err != nil {
		return "", f.err
	}
	if f.raw != "" {
		var b strings.Builder
		for _, p := range paths {
			b.WriteString("path " + p + " file 100 yes " + strings.Repeat("c", 64) + "\n")
		}
		b.WriteString(f.extra)
		return strings.Replace(f.raw, "@PATHS@\n", b.String(), 1), nil
	}
	var b strings.Builder
	b.WriteString(cleanReport)
	for _, p := range paths {
		b.WriteString("path " + p + " absent\n")
	}
	b.WriteString(f.extra + preflight.EndMarker + "\n")
	return b.String(), nil
}

// The update path on a gateway that runs the previous install: the agent
// reports the install's own SmartDNS container, wstunnel units and lo
// transit addresses (sanitized real case). The re-run passes and the
// install goes ahead; a foreign resolver next to it still blocks.
func TestGatewayUpdateGateOnOwnInstall(t *testing.T) {
	s, _, activated := installTest(t)
	hp := &fakeHostPreflight{}
	s.HostPreflight = hp
	rr := do(s, http.MethodPost, "/api/host/preflight", nil)
	var out struct{ Preflight preflightRecord }
	_ = json.Unmarshal(rr.Body.Bytes(), &out)
	if rr := do(s, http.MethodPost, "/api/apply", mustJSON(map[string]any{"install": true, "preflight_id": out.Preflight.ID})); rr.Code != 200 || *activated != 1 {
		t.Fatalf("first install: %d %s", rr.Code, rr.Body.String())
	}
	raw, err := os.ReadFile("../preflight/testdata/gateway-installed.txt")
	if err != nil {
		t.Fatal(err)
	}
	hp.mu.Lock()
	hp.raw = string(raw)
	hp.mu.Unlock()
	rr = do(s, http.MethodPost, "/api/host/preflight", nil)
	_ = json.Unmarshal(rr.Body.Bytes(), &out)
	if rr.Code != 200 || out.Preflight.Blocking || out.Preflight.Ownership != preflight.OwnSame {
		t.Fatalf("own install reported as conflict: %d %s", rr.Code, rr.Body.String())
	}
	if rr := do(s, http.MethodPost, "/api/apply", []byte(`{"install":true}`)); rr.Code != 200 || *activated != 2 {
		t.Fatalf("update: %d %s", rr.Code, rr.Body.String())
	}
	hp.mu.Lock()
	hp.extra = "ss udp UNCONN 0 0 0.0.0.0:53 0.0.0.0:*\nssc udp UNCONN 0 0 0.0.0.0:53 0.0.0.0:* cgroup:/system.slice/dnsmasq.service\n"
	hp.mu.Unlock()
	rr = do(s, http.MethodPost, "/api/apply", []byte(`{"install":true}`))
	if rr.Code != http.StatusConflict || codeOf(t, rr.Body.Bytes()) != codePreflightBlocked || !strings.Contains(rr.Body.String(), "dnsmasq") || *activated != 2 {
		t.Fatalf("foreign resolver: %d %s", rr.Code, rr.Body.String())
	}
}

func TestGatewayInstallPreflightGate(t *testing.T) {
	s, _, activated := installTest(t)
	hp := &fakeHostPreflight{}
	s.HostPreflight = hp

	// First install without a reviewed pre-check.
	rr := do(s, http.MethodPost, "/api/apply", []byte(`{"install":true}`))
	if rr.Code != http.StatusConflict || codeOf(t, rr.Body.Bytes()) != codePreflightRequired || *activated != 0 {
		t.Fatalf("required: %d %s", rr.Code, rr.Body.String())
	}
	if gw := storedNode(t, s, localNodeID); gw.PrivateKey != "" {
		t.Fatal("gateway key generated before the pre-check")
	}
	// Docker's FORWARD DROP on the gateway blocks.
	hp.extra = "ipt ipv4 -P FORWARD DROP\nunit docker.service active enabled 5\n"
	rr = do(s, http.MethodPost, "/api/host/preflight", nil)
	var out struct{ Preflight preflightRecord }
	if rr.Code != 200 || json.Unmarshal(rr.Body.Bytes(), &out) != nil || out.Preflight.Kind != "gateway" || !out.Preflight.Blocking {
		t.Fatalf("host preflight: %d %s", rr.Code, rr.Body.String())
	}
	for _, p := range hp.paths {
		if !preflight.ValidPath(p) {
			t.Fatalf("invalid path sent to the agent: %s", p)
		}
	}
	rr = do(s, http.MethodPost, "/api/apply", mustJSON(map[string]any{"install": true, "preflight_id": out.Preflight.ID}))
	if rr.Code != http.StatusConflict || codeOf(t, rr.Body.Bytes()) != codePreflightBlocked || *activated != 0 {
		t.Fatalf("blocked: %d %s", rr.Code, rr.Body.String())
	}
	// Clean: installs; the check ran again right before.
	hp.extra = ""
	rr = do(s, http.MethodPost, "/api/host/preflight", []byte(`{}`))
	_ = json.Unmarshal(rr.Body.Bytes(), &out)
	calls := hp.calls
	rr = do(s, http.MethodPost, "/api/apply", mustJSON(map[string]any{"install": true, "preflight_id": out.Preflight.ID}))
	if rr.Code != 200 || *activated != 1 || hp.calls != calls+1 {
		t.Fatalf("install: %d %s (activated %d, calls %d→%d)", rr.Code, rr.Body.String(), *activated, calls, hp.calls)
	}
	// Later installs re-run the check without a reviewed id; still gated.
	hp.extra = "ipt ipv4 -P FORWARD DROP\n"
	if rr := do(s, http.MethodPost, "/api/apply", []byte(`{"install":true}`)); rr.Code != http.StatusConflict || codeOf(t, rr.Body.Bytes()) != codePreflightBlocked {
		t.Fatalf("update blocked: %d %s", rr.Code, rr.Body.String())
	}
	hp.extra = ""
	if rr := do(s, http.MethodPost, "/api/apply", []byte(`{"install":true}`)); rr.Code != 200 {
		t.Fatalf("update: %d %s", rr.Code, rr.Body.String())
	}
	// The agent cannot run the check: refused, nothing written.
	hp.err = hostexec.ErrPreflightUnsupported
	if rr := do(s, http.MethodPost, "/api/apply", []byte(`{"install":true}`)); rr.Code != http.StatusServiceUnavailable || codeOf(t, rr.Body.Bytes()) != codeHostUnavailable {
		t.Fatalf("unsupported: %d %s", rr.Code, rr.Body.String())
	}
	hp.err = errors.New("boom")
	if rr := do(s, http.MethodPost, "/api/host/preflight", nil); rr.Code != http.StatusBadGateway || codeOf(t, rr.Body.Bytes()) != codePreflightFailed {
		t.Fatalf("failed: %d %s", rr.Code, rr.Body.String())
	}
	// Unknown fields are refused: the action takes no parameter.
	if rr := do(s, http.MethodPost, "/api/host/preflight", []byte(`{"paths":["/etc/shadow"]}`)); rr.Code != http.StatusBadRequest {
		t.Fatalf("params: %d %s", rr.Code, rr.Body.String())
	}
}

func TestGatewayInstallWithoutPreflightCapability(t *testing.T) {
	s, _, activated := installTest(t)
	s.Host = downHost{}
	rr := do(s, http.MethodPost, "/api/apply", []byte(`{"install":true}`))
	if rr.Code != http.StatusServiceUnavailable || codeOf(t, rr.Body.Bytes()) != codeHostUnavailable || *activated != 0 {
		t.Fatalf("%d %s", rr.Code, rr.Body.String())
	}
	if rr := do(s, http.MethodPost, "/api/host/preflight", nil); rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("host preflight: %d %s", rr.Code, rr.Body.String())
	}
}

// A port the gateway's bundle binds, taken by another program: the
// blocking finding names the topology field that sets it, and changing
// that field changes the bundle (bundle digest) and clears the finding.
func TestGatewayPortConflictNamesTheField(t *testing.T) {
	s, _, _ := installTest(t)
	hp := &fakeHostPreflight{}
	s.HostPreflight = hp
	topo, _, _ := s.Store.Load()
	var lp validate.PortUse
	for _, u := range validate.NodePorts(topo, localNodeID) {
		if u.Field == "wss_local_port" {
			lp = u
			break
		}
	}
	if lp.Port == 0 {
		t.Fatal("gateway has no wstunnel client port in the example")
	}
	hp.extra = fmt.Sprintf("ss udp UNCONN 0 0 127.0.0.1:%d 0.0.0.0:* users:((\"other-tunnel\",pid=901,fd=3))\n", lp.Port)
	rr := do(s, http.MethodPost, "/api/host/preflight", nil)
	var out struct{ Preflight preflightRecord }
	if rr.Code != 200 || json.Unmarshal(rr.Body.Bytes(), &out) != nil || !out.Preflight.Blocking {
		t.Fatalf("host preflight: %d %s", rr.Code, rr.Body.String())
	}
	var f *preflight.Finding
	for i := range out.Preflight.Findings {
		if out.Preflight.Findings[i].Code == preflight.CodePortInUse {
			f = &out.Preflight.Findings[i]
		}
	}
	if f == nil || f.Fix == nil || f.Fix.Kind != "link" || f.Fix.ID != lp.ID || f.Fix.Field != "wss_local_port" || !strings.Contains(f.Message, "other-tunnel") {
		t.Fatalf("finding %+v", f)
	}
	bundle := out.Preflight.Bundle
	for i := range topo.Links {
		if topo.Links[i].ID == lp.ID {
			topo.Links[i].WSSLocalPort = 52900
		}
	}
	if err := s.Store.Save(topo); err != nil {
		t.Fatal(err)
	}
	rr = do(s, http.MethodPost, "/api/host/preflight", nil)
	_ = json.Unmarshal(rr.Body.Bytes(), &out)
	if out.Preflight.Bundle == bundle || out.Preflight.Blocking {
		t.Fatalf("after moving the port: %d %s", rr.Code, rr.Body.String())
	}
}

// A first deployment installs nodes one at a time. The first node's
// configuration names peers that have never been installed: the preflight
// gives every managed node its key (panel-side only), so the script that
// reaches the host never carries the public-key placeholder, and the
// reviewed bundle stays the same when the peers are installed later.
func TestFirstInstallPeersGetKeysBeforeAnyHostIsTouched(t *testing.T) {
	f := newGateFix(t)
	s := f.s
	topo, _, _ := s.Store.Load()
	var peers []string
	for i := range topo.Nodes {
		if topo.Nodes[i].Managed && topo.Nodes[i].Role != model.RoleGateway {
			topo.Nodes[i].PublicKey, topo.Nodes[i].PrivateKey = "", ""
			peers = append(peers, topo.Nodes[i].ID)
		}
	}
	if err := s.Store.Save(topo); err != nil {
		t.Fatal(err)
	}
	id := reviewPreflight(t, s, "tw")
	after, _, _ := s.Store.Load()
	for _, n := range after.Nodes {
		if n.Managed && !compile.ValidWGKey(n.PublicKey) {
			t.Errorf("managed node %s has no usable public key after the preflight: %q", n.ID, n.PublicKey)
		}
	}
	if rr := f.provision(id); rr.Code != http.StatusOK {
		t.Fatalf("provision after preflight: %d %s", rr.Code, rr.Body.String())
	}
	for _, in := range f.srv.Stdins() {
		if strings.Contains(in, "EXAMPLE_PUBLIC_KEY_DO_NOT_USE") {
			t.Fatal("a script sent to the host names a peer by the public-key placeholder")
		}
	}
	if f.provisionScripts() != 1 {
		t.Fatalf("provision scripts sent: %d, want 1", f.provisionScripts())
	}
	// The hub's key did not change when tw was installed.
	hubBefore, _ := after.NodeByID("hk-hub")
	final, _, _ := s.Store.Load()
	hubAfter, _ := final.NodeByID("hk-hub")
	if hubBefore.PublicKey != hubAfter.PublicKey {
		t.Fatal("a peer's key changed during the node's install")
	}
	_ = peers

	// An unmanaged peer whose key nobody entered cannot be generated: the
	// panel refuses before connecting.
	topo, _, _ = s.Store.Load()
	for i := range topo.Nodes {
		if topo.Nodes[i].ID == "hk-hub" {
			topo.Nodes[i].Managed, topo.Nodes[i].PublicKey, topo.Nodes[i].PrivateKey = false, "", ""
		}
	}
	if err := s.Store.Save(topo); err != nil {
		t.Fatal(err)
	}
	accepted := f.srv.Accepted()
	rr := do(s, http.MethodPost, "/api/provision/preflight", mustJSON(map[string]any{"node_id": "tw"}))
	if rr.Code != http.StatusUnprocessableEntity || !strings.Contains(rr.Body.String(), codePeerKeysMissing) {
		t.Fatalf("keyless unmanaged peer: %d %s", rr.Code, rr.Body.String())
	}
	if f.srv.Accepted() != accepted {
		t.Fatal("the refusal connected to the server")
	}
}
