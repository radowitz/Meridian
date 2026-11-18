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
	"github.com/radowitz/meridian/internal/defaults"
	"github.com/radowitz/meridian/internal/hostexec"
	"github.com/radowitz/meridian/internal/model"
	"github.com/radowitz/meridian/internal/mtu"
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
addr eth0 198.51.100.250/24
route4 default via 198.51.100.1 dev eth0
route4 198.51.100.0/24 dev eth0 proto kernel scope link src 198.51.100.250
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
		if strings.HasPrefix(l, "manifest ") || strings.HasPrefix(l, "linkmtu ") {
			keepMan += l + "\n"
		}
	}
	switch {
	case strings.Contains(out, "MERIDIAN_PROVISION_OK"):
		return j("done") + man() + installedLinkMTU(stdin)
	case strings.Contains(out, "MERIDIAN_COMPENSATED"):
		return j("compensated") + keepMan
	case strings.Contains(out, "MERIDIAN_COMPENSATION_INCOMPLETE"):
		return j("incomplete") + keepMan
	}
	return prev
}

// installedLinkMTU: the "linkmtu IFACE MTU" lines of a host whose
// activation applied every WireGuard config the provision script on stdin
// writes (each interface at its config's MTU).
func installedLinkMTU(stdin string) string {
	var b strings.Builder
	iface := ""
	for _, l := range strings.Split(stdin, "\n") {
		if p, ok := strings.CutPrefix(l, "m_track '/etc/wireguard/"); ok {
			iface = strings.TrimSuffix(strings.TrimSuffix(p, "'"), ".conf")
			continue
		}
		if strings.HasPrefix(l, "m_track ") {
			iface = ""
			continue
		}
		if m, ok := strings.CutPrefix(l, "MTU = "); ok && iface != "" {
			b.WriteString("linkmtu " + iface + " " + strings.TrimSpace(m) + "\n")
			iface = ""
		}
	}
	return b.String()
}

// hostLinkMTU: the "linkmtu" lines of a synthetic host record, which a
// preflight of that host reports too.
func hostLinkMTU(host string) string {
	var b strings.Builder
	for _, l := range strings.Split(host, "\n") {
		if strings.HasPrefix(l, "linkmtu ") {
			b.WriteString(l + "\n")
		}
	}
	return b.String()
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
		extra, script := f.extra+hostLinkMTU(f.host), f.script
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

// ------------------------------------------------------- uplink MTU ---

// carrierOf is node's leg of link in the stored topology.
func carrierOf(t *testing.T, s *Server, node, link, mode string) mtu.Carrier {
	t.Helper()
	topo, _, _ := s.Store.Load()
	cs, err := compile.UplinkCarriers(topo, node)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range cs {
		if c.LinkID == link && c.Mode == mode {
			return c
		}
	}
	t.Fatalf("%s has no leg %s/%s", node, link, mode)
	return mtu.Carrier{}
}

func uplinkView(t *testing.T, s *Server) uplinkMTUView {
	t.Helper()
	rr := do(s, http.MethodGet, "/api/mtu/uplinks", nil)
	var v uplinkMTUView
	if rr.Code != 200 || json.Unmarshal(rr.Body.Bytes(), &v) != nil {
		t.Fatalf("uplinks: %d %s", rr.Code, rr.Body.String())
	}
	return v
}

func legOf(t *testing.T, v uplinkMTUView, link, mode string) uplinkLeg {
	t.Helper()
	for _, l := range v.Legs {
		if l.LinkID == link && l.Mode == mode {
			return l
		}
	}
	t.Fatalf("no leg %s/%s in %+v", link, mode, v.Legs)
	return uplinkLeg{}
}

func endOf(t *testing.T, l uplinkLeg, node string) uplinkEnd {
	t.Helper()
	for _, e := range l.Ends {
		if e.NodeID == node {
			return e
		}
	}
	t.Fatalf("leg %s has no end %s: %+v", l.LinkID, node, l.Ends)
	return uplinkEnd{}
}

func linkMTUOf(t *testing.T, s *Server, id string) int {
	t.Helper()
	topo, _, _ := s.Store.Load()
	for _, l := range topo.Links {
		if l.ID == id {
			return l.MTU
		}
	}
	t.Fatalf("no link %s", id)
	return 0
}

// The exit tw dials the hub over a 1472-byte uplink (the measured case):
// its preflight asks the host for the route to the hub, blocks the first
// install of the leg and names the suggestion; the panel offers it with
// the per-node differences; only the explicit adoption writes the link's
// MTU field, compare-and-set, and nothing reaches any host.
func TestUplinkMTUSuggestionAndAdoption(t *testing.T) {
	f := newGateFix(t)
	s := f.s
	c := carrierOf(t, s, "tw", "tw-hub", "udp")
	if c.Peer == "" || c.TunnelMTU != 1420 || !c.Dials {
		t.Fatalf("carrier %+v", c)
	}
	topo0, _, _ := s.Store.Load()

	// Before any preflight: unknown, nothing offered.
	v := uplinkView(t, s)
	if l := legOf(t, v, "tw-hub", "udp"); l.Status != preflight.UplinkUnknown || l.Adoptable || endOf(t, l, "tw").Status != uplinkNoPreflight {
		t.Fatalf("before preflight %+v", l)
	}
	if v.Proposal != nil || len(v.NotVerified) == 0 || v.TTLHours != 24 {
		t.Fatalf("view %+v", v)
	}

	f.setExtra("linkmtu lo 65536\nlinkmtu eth0 1472\nuproute 4 " + c.Peer + " eth0 -\n")
	rec := f.preflight(t)
	cmds := f.srv.Commands()
	if last := cmds[len(cmds)-1]; !strings.Contains(last, " 'route4:"+c.Peer+"'") {
		t.Fatalf("the preflight did not ask for the route to the hub: %q", last)
	}
	if len(rec.Uplinks) != 1 || rec.Uplinks[0].Status != preflight.UplinkTooSmall || rec.Uplinks[0].Suggested != 1408 || !rec.Blocking {
		t.Fatalf("record uplinks %+v blocking %v", rec.Uplinks, rec.Blocking)
	}
	var fnd *preflight.Finding
	for i := range rec.Findings {
		if rec.Findings[i].Code == preflight.CodeUplinkMTUTooSmall {
			fnd = &rec.Findings[i]
		}
	}
	if fnd == nil || fnd.Severity != preflight.Blocking || fnd.Fix == nil || fnd.Fix.ID != "tw-hub" || fnd.Fix.Field != "mtu" {
		t.Fatalf("finding %+v", fnd)
	}

	v = uplinkView(t, s)
	l := legOf(t, v, "tw-hub", "udp")
	if l.Status != preflight.UplinkTooSmall || l.Suggested != 1408 || l.Limiting != "tw" || !l.Adoptable || l.Configured != 1420 || l.TunnelMTU != 1420 || l.Field != "mtu" {
		t.Fatalf("leg %+v", l)
	}
	if e := endOf(t, l, "tw"); e.Status != preflight.UplinkTooSmall || e.Dev != "eth0" || e.UplinkMTU != 1472 || e.Shortfall != 8 || e.PreflightID != rec.ID {
		t.Fatalf("tw end %+v", e)
	}
	if e := endOf(t, l, "hk-hub"); e.Status != uplinkNoPreflight {
		t.Fatalf("hub end %+v", e)
	}
	if !strings.Contains(l.Note, "还没有验证") {
		t.Fatalf("the unverified other end is not named: %q", l.Note)
	}
	p := v.Proposal
	if p == nil || p.Error != "" || len(p.Changes) != 1 || p.Changes[0] != (mtuChange{LinkID: "tw-hub", Field: "mtu", From: 1420, To: 1408, FromEffective: 1420}) {
		t.Fatalf("proposal %+v", p)
	}
	nodes := map[string][]string{}
	for _, n := range p.Nodes {
		nodes[n.NodeID] = n.Files
	}
	if len(nodes) != 2 || !containsStr(nodes["tw"], "/etc/wireguard/m14.conf") || !containsStr(nodes["hk-hub"], "/etc/wireguard/m14.conf") {
		t.Fatalf("per-node differences %+v", p.Nodes)
	}
	// Showing it changed nothing.
	if linkMTUOf(t, s, "tw-hub") != 1420 || f.provisionScripts() != 0 {
		t.Fatal("the suggestion changed the topology or reached a host")
	}

	// Adoption must name exactly what was shown.
	for _, bad := range []map[string]any{
		{"changes": []map[string]any{{"link_id": "tw-hub", "field": "mtu", "from": 1420, "to": 1400}}},
		{"changes": []map[string]any{{"link_id": "tw-hub", "field": "mtu", "from": 0, "to": 1408}}},
		{"changes": []map[string]any{{"link_id": "tw-hub", "field": "wss_mtu", "from": 1420, "to": 1408}}},
		{"changes": []map[string]any{{"link_id": "hub-jp", "field": "mtu", "from": 1420, "to": 1408}}},
	} {
		rr := do(s, http.MethodPost, "/api/mtu/adopt", mustJSON(bad))
		if rr.Code != http.StatusConflict || codeOf(t, rr.Body.Bytes()) != codeMTUSuggestionChanged {
			t.Fatalf("%v: %d %s", bad, rr.Code, rr.Body.String())
		}
	}
	for _, bad := range []string{`{}`, `{"changes":[]}`, `{"changes":[{"link_id":"tw-hub"}]}`, `{"changes":[],"auto":true}`} {
		if rr := do(s, http.MethodPost, "/api/mtu/adopt", []byte(bad)); rr.Code != http.StatusBadRequest {
			t.Fatalf("%s: %d %s", bad, rr.Code, rr.Body.String())
		}
	}
	if linkMTUOf(t, s, "tw-hub") != 1420 {
		t.Fatal("a refused adoption wrote the topology")
	}

	rr := do(s, http.MethodPost, "/api/mtu/adopt", mustJSON(map[string]any{"changes": []map[string]any{{"link_id": "tw-hub", "field": "mtu", "from": 1420, "to": 1408}}}))
	if rr.Code != 200 || !strings.Contains(rr.Body.String(), "没有下发") {
		t.Fatalf("adopt: %d %s", rr.Code, rr.Body.String())
	}
	if linkMTUOf(t, s, "tw-hub") != 1408 || f.provisionScripts() != 0 {
		t.Fatal("adoption did not write exactly the field, or reached a host")
	}
	topo1, _, _ := s.Store.Load()
	for i, lk := range topo1.Links {
		if lk.ID != "tw-hub" && (lk.MTU != topo0.Links[i].MTU || lk.WSSMTU != topo0.Links[i].WSSMTU) {
			t.Fatalf("link %s changed", lk.ID)
		}
	}
	// The same observation, judged for the adopted MTU: fits; nothing more
	// to adopt; adopting again is refused.
	v = uplinkView(t, s)
	if l := legOf(t, v, "tw-hub", "udp"); endOf(t, l, "tw").Status != preflight.UplinkFits || l.Adoptable || v.Proposal != nil {
		t.Fatalf("after adoption %+v %+v", l, v.Proposal)
	}
	if rr := do(s, http.MethodPost, "/api/mtu/adopt", mustJSON(map[string]any{"changes": []map[string]any{{"link_id": "tw-hub", "field": "mtu", "from": 1420, "to": 1408}}})); rr.Code != http.StatusConflict {
		t.Fatalf("second adoption: %d", rr.Code)
	}
	// The next preflight has the new MTU and no longer blocks on it.
	rec = f.preflight(t)
	if len(rec.Uplinks) != 1 || rec.Uplinks[0].Status != preflight.UplinkFits || rec.Uplinks[0].TunnelMTU != 1408 {
		t.Fatalf("after adoption %+v", rec.Uplinks)
	}
	for _, x := range rec.Findings {
		if x.Code == preflight.CodeUplinkMTUTooSmall {
			t.Fatalf("still too small: %+v", x)
		}
	}
}

// A fact is used only while it is bound to the node's identity, the
// current plan and is fresh; otherwise it is stale or unknown and nothing
// is offered.
func TestUplinkMTUFactBinding(t *testing.T) {
	f := newGateFix(t)
	s := f.s
	c := carrierOf(t, s, "tw", "tw-hub", "udp")
	tooSmall := "linkmtu eth0 1472\nuproute 4 " + c.Peer + " eth0 -\n"
	check := func(name, status string) {
		t.Helper()
		l := legOf(t, uplinkView(t, s), "tw-hub", "udp")
		if e := endOf(t, l, "tw"); e.Status != status || l.Adoptable || l.Status == preflight.UplinkTooSmall {
			t.Fatalf("%s: end %+v leg %+v", name, e, l)
		}
	}
	// Unknown: an older host report (no interface MTUs / no route answer).
	f.setExtra("")
	rec := f.preflight(t)
	if rec.Uplinks[0].Status != preflight.UplinkUnknown || rec.Blocking {
		t.Fatalf("unknown %+v blocking %v", rec.Uplinks, rec.Blocking)
	}
	check("unknown", preflight.UplinkUnknown)

	// Too old.
	f.setExtra(tooSmall)
	f.preflight(t)
	old := s.loadPreflight("tw")
	old.At = time.Now().Add(-uplinkFactTTL - time.Minute)
	_ = s.savePreflight(old)
	check("old", uplinkStale)

	// Another node's record under this key (wrong node).
	f.preflight(t)
	wrong := s.loadPreflight("tw")
	wrong.NodeID = "jp"
	if err := s.Store.Put(preflightKey("tw"), string(mustJSON(wrong))); err != nil {
		t.Fatal(err)
	}
	check("wrong node", uplinkStale)

	// Another panel's deployment.
	f.preflight(t)
	other := s.loadPreflight("tw")
	other.Deployment = "dep-other"
	_ = s.savePreflight(other)
	check("other deployment", uplinkStale)

	// The plan changed: the hub moved to another address.
	f.preflight(t)
	topo, _, _ := s.Store.Load()
	for i := range topo.Nodes {
		if topo.Nodes[i].ID == "hk-hub" {
			topo.Nodes[i].EndpointV4 = "203.0.113.99"
		}
	}
	if err := s.Store.Save(topo); err != nil {
		t.Fatal(err)
	}
	check("plan changed", uplinkStale)

	// The target changed: the server now uses another credential.
	f.setExtra("linkmtu eth0 1472\nuproute 4 203.0.113.99 eth0 -\n")
	f.preflight(t)
	if l := legOf(t, uplinkView(t, s), "tw-hub", "udp"); !l.Adoptable {
		t.Fatalf("fresh fact not offered: %+v", l)
	}
	rr := do(s, http.MethodPost, "/api/ssh-credentials", mustJSON(map[string]any{"name": "pw2", "kind": "password", "password": f.pw}))
	var c2 struct{ Credential credView }
	decode(t, rr, &c2)
	if rr := do(s, http.MethodPatch, "/api/servers/"+f.id, mustJSON(map[string]any{"credential_id": c2.Credential.ID})); rr.Code != 200 {
		t.Fatal(rr.Body.String())
	}
	check("target changed", uplinkStale)
}

// routesHostPreflight is the host agent with route lookups.
type routesHostPreflight struct {
	*fakeHostPreflight
	routes []string
}

func (r *routesHostPreflight) PreflightRoutes(ctx context.Context, paths, routes []string) (string, error) {
	r.mu.Lock()
	r.routes = routes
	r.mu.Unlock()
	return r.Preflight(ctx, paths)
}

// The gateway: its legs' route lookups reach the host agent; a leg not yet
// installed blocks the first install, an installed one only warns and the
// update goes ahead.
func TestGatewayUplinkMTU(t *testing.T) {
	s, _, activated := installTest(t)
	hp := &routesHostPreflight{fakeHostPreflight: &fakeHostPreflight{}}
	s.HostPreflight = hp
	c := carrierOf(t, s, "gw", "gw-access", "udp")
	if c.Mark != "0x4d72" || c.TunnelMTU != 1412 {
		t.Fatalf("gateway carrier %+v", c)
	}
	// 1412 + 60 = 1472 fits exactly; 1450 does not.
	hp.extra = "linkmtu eth0 1450\nuproute 4 " + c.Peer + " eth0 -\n"
	rr := do(s, http.MethodPost, "/api/host/preflight", nil)
	var out struct{ Preflight preflightRecord }
	_ = json.Unmarshal(rr.Body.Bytes(), &out)
	if !containsStr(hp.routes, "route4:"+c.Peer) {
		t.Fatalf("routes %v", hp.routes)
	}
	var sev string
	for _, x := range out.Preflight.Findings {
		if x.Code == preflight.CodeUplinkMTUTooSmall && x.Resource == "m02" {
			sev = x.Severity
		}
	}
	if sev != preflight.Blocking {
		t.Fatalf("first install of a leg that does not fit: %q %s", sev, rr.Body.String())
	}
	// With a fitting uplink the first install goes ahead.
	hp.extra = "linkmtu eth0 1472\nuproute 4 " + c.Peer + " eth0 -\n"
	rr = do(s, http.MethodPost, "/api/host/preflight", nil)
	_ = json.Unmarshal(rr.Body.Bytes(), &out)
	if rr := do(s, http.MethodPost, "/api/apply", mustJSON(map[string]any{"install": true, "preflight_id": out.Preflight.ID})); rr.Code != 200 || *activated != 1 {
		t.Fatalf("first install: %d %s", rr.Code, rr.Body.String())
	}
	// Installed: the same shortfall only warns and the update is not blocked.
	hp.extra = "linkmtu eth0 1450\nuproute 4 " + c.Peer + " eth0 -\n"
	rr = do(s, http.MethodPost, "/api/host/preflight", nil)
	_ = json.Unmarshal(rr.Body.Bytes(), &out)
	sev = ""
	for _, x := range out.Preflight.Findings {
		if x.Code == preflight.CodeUplinkMTUTooSmall && x.Resource == "m02" {
			sev = x.Severity
		}
	}
	if sev != preflight.Warning || out.Preflight.Blocking {
		t.Fatalf("deployed leg: %q blocking %v", sev, out.Preflight.Blocking)
	}
	if rr := do(s, http.MethodPost, "/api/apply", mustJSON(map[string]any{"install": true, "preflight_id": out.Preflight.ID})); rr.Code != 200 || *activated != 2 {
		t.Fatalf("update with a deployed too-small leg: %d %s", rr.Code, rr.Body.String())
	}
	// And the panel offers the suggestion for the gateway's end.
	l := legOf(t, uplinkView(t, s), "gw-access", "udp")
	if e := endOf(t, l, "gw"); e.Status != preflight.UplinkTooSmall || e.Suggested != 1376 || !l.Adoptable || l.Suggested != 1376 {
		t.Fatalf("gateway end %+v leg %+v", e, l)
	}
}

// The carrier of an external SOCKS exit whose proxy does not answer: the
// panel's preflight blocks a first enable and warns (only that exit is
// affected) when the host's own record — this node, deployment and server,
// an unchanged meridian-up.sh carrying the same external exit — shows it
// already deployed. The panel's own records never downgrade it.
func TestCarrierPreflightExternalProxyByInstallIdentity(t *testing.T) {
	s := newTest(t)
	rr := do(s, http.MethodPost, "/api/socks-credentials", mustJSON(map[string]any{"name": "路由器", "username": "u-" + rnd(t, 4), "password": "p-" + rnd(t, 8)}))
	var sc struct{ Credential struct{ ID string } }
	decode(t, rr, &sc)
	topo := defaults.ExternalExample()
	for i := range topo.Nodes {
		if topo.Nodes[i].External != nil {
			topo.Nodes[i].External.CredentialID = sc.Credential.ID
		}
	}
	if rr := do(s, http.MethodPut, "/api/topology", mustJSON(topo)); rr.Code != 200 {
		t.Fatalf("save: %d %s", rr.Code, rr.Body.String())
	}
	srv := startSSH(t)
	pw := "pw-" + rnd(t, 8)
	srv.SetPassword(pw)
	var mu sync.Mutex
	extra := ""
	srv.SetHandler(func(cmd, stdin string) (string, uint32) {
		mu.Lock()
		defer mu.Unlock()
		if out, ok := cleanPreflight(cmd, stdin, extra); ok {
			return out, 0
		}
		return "unexpected", 1
	})
	rr = do(s, http.MethodPost, "/api/ssh-credentials", mustJSON(map[string]any{"name": "pw", "kind": "password", "password": pw}))
	var c struct{ Credential credView }
	decode(t, rr, &c)
	rr = do(s, http.MethodPost, "/api/servers", mustJSON(map[string]any{"name": "承载节点", "address": srv.Host, "port": srv.Port, "user": "root", "auth": "password", "credential_id": c.Credential.ID}))
	var sv struct{ Server serverView }
	decode(t, rr, &sv)
	do(s, http.MethodPost, "/api/servers/"+sv.Server.ID+"/host-key/discover", nil)
	if rr := do(s, http.MethodPost, "/api/servers/"+sv.Server.ID+"/host-key/trust", mustJSON(map[string]string{"fingerprint": srv.Fingerprint()})); rr.Code != 200 {
		t.Fatal(rr.Body.String())
	}
	stored, _, _ := s.Store.Load()
	for i := range stored.Nodes {
		if stored.Nodes[i].ID == "dc2" {
			stored.Nodes[i].ServerID = sv.Server.ID
		}
	}
	if err := s.Store.Save(stored); err != nil {
		t.Fatal(err)
	}
	dep := mustDeployment(t, s)
	const upHash = "3333333333333333333333333333333333333333333333333333333333333333"
	tunnel := "link wg9\nroute4 198.51.100.64/30 dev wg9 proto kernel scope link src 198.51.100.65\ntcpconnect 198.51.100.66 1080 fail\n"
	record := func(server, marker string) string {
		return "path /usr/local/sbin/meridian-up.sh file 4096 yes " + upHash + "\n" + marker +
			"manifest-begin\nmanifest node dc2\nmanifest deployment " + dep + "\nmanifest server " + server + "\nmanifest file /usr/local/sbin/meridian-up.sh " + upHash +
			"\nmanifest-end\njournal-begin\njournal state done\njournal run run-x\njournal-end\n"
	}
	finding := func(host string) preflight.Finding {
		t.Helper()
		mu.Lock()
		extra = tunnel + host
		mu.Unlock()
		rr := do(s, http.MethodPost, "/api/provision/preflight", mustJSON(map[string]any{"node_id": "dc2"}))
		var out struct{ Preflight preflightRecord }
		if rr.Code != 200 || json.Unmarshal(rr.Body.Bytes(), &out) != nil {
			t.Fatalf("preflight: %d %s", rr.Code, rr.Body.String())
		}
		if !containsString(out.Preflight.Footprint.PreflightProbes(), "tcp4:198.51.100.66:1080") {
			t.Fatalf("no probe of the proxy: %v", out.Preflight.Footprint.PreflightProbes())
		}
		for _, f := range out.Preflight.Findings {
			if f.Code == preflight.CodeExternalProxy {
				return f
			}
		}
		t.Fatalf("no %s finding", preflight.CodeExternalProxy)
		return preflight.Finding{}
	}
	same := "extinstalled myext 198.51.100.66 1080 wg9\n"
	if f := finding(""); f.Severity != preflight.Blocking || !strings.Contains(f.Message, "首次启用") {
		t.Fatalf("first enable: %+v", f)
	}
	if f := finding(record(sv.Server.ID, same)); f.Severity != preflight.Warning || !strings.Contains(f.Message, "只有经外部出口 myext 的流量受影响") {
		t.Fatalf("already deployed: %+v", f)
	}
	if f := finding(record(sv.Server.ID, "extinstalled myext 198.51.100.66 1081 wg9\n")); f.Severity != preflight.Blocking || !strings.Contains(f.Message, "新的代理配置") {
		t.Fatalf("changed proxy: %+v", f)
	}
	if f := finding(record("srv-other", same)); f.Severity != preflight.Blocking {
		t.Fatalf("another server's record: %+v", f)
	}
	// The panel recording the node as installed changes nothing: only the
	// host's record counts.
	s.saveOutcome(provisionOutcome{NodeID: "dc2", ServerID: sv.Server.ID, OK: true, Outcome: "installed", Installed: true, InstalledBundle: strings.Repeat("a", 64)})
	if f := finding(""); f.Severity != preflight.Blocking {
		t.Fatalf("panel record downgraded it: %+v", f)
	}
}

// A managed node whose only links are disabled is refused by the
// preflight and the install before anything connects to its server, and
// the deploy page data lists it as blocking.
func TestLinklessNodeRefusedBeforeConnecting(t *testing.T) {
	f := newGateFix(t)
	topo, _, _ := f.s.Store.Load()
	for i := range topo.Links {
		if topo.Links[i].From == "tw" || topo.Links[i].To == "tw" {
			topo.Links[i].Enabled = false
		}
	}
	if err := f.s.Store.Save(topo); err != nil {
		t.Fatal(err)
	}
	before := len(f.srv.Stdins())
	for _, rr := range []*httptest.ResponseRecorder{
		do(f.s, http.MethodPost, "/api/provision/preflight", mustJSON(map[string]any{"node_id": "tw"})),
		f.provision(""),
	} {
		var out struct {
			Code     string
			Error    string
			Findings []preflight.Finding
		}
		decode(t, rr, &out)
		if rr.Code != http.StatusUnprocessableEntity || out.Code != preflight.CodeNoLink || !strings.HasPrefix(out.Error, "这个节点还没有链路") ||
			len(out.Findings) != 1 || out.Findings[0].Severity != preflight.Blocking {
			t.Fatalf("want node_has_no_link refusal, got %d %s", rr.Code, rr.Body.String())
		}
	}
	if n := len(f.srv.Stdins()); n != before {
		t.Fatalf("server was contacted %d times", n-before)
	}
	var dv struct {
		NodeBlockers []preflight.Finding `json:"node_blockers"`
	}
	decode(t, do(f.s, http.MethodGet, "/api/deploy", nil), &dv)
	found := false
	for _, b := range dv.NodeBlockers {
		found = found || (b.Resource == "tw" && b.Code == preflight.CodeNoLink)
	}
	if !found {
		t.Fatalf("deploy view node_blockers = %+v", dv.NodeBlockers)
	}
}
