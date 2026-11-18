package api

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"

	"github.com/radowitz/meridian/internal/apply"
	"github.com/radowitz/meridian/internal/hostexec"
	"github.com/radowitz/meridian/internal/mesh"
	"github.com/radowitz/meridian/internal/sshexec"
	"github.com/radowitz/meridian/internal/sshexec/sshtest"
	"github.com/radowitz/meridian/internal/unlock"
)

func unlockHistory(exit string) unlock.HistoryEntry {
	return unlock.HistoryEntry{Service: "netflix", ExitID: exit, Kind: unlock.KindScheduled, OK: true}
}

// wdHost answers the fixed withdraw script for the gate fixture's server.
// reply gets the script's mode, action and digest and returns the output
// and exit status the script would give.
type wdHost struct {
	mu    sync.Mutex
	reply func(mode, action, digest string) (string, uint32)
	runs  []string // stdin of every withdraw script
}

var assignRe = regexp.MustCompile(`(?m)^M_([A-Z]+)='([^']*)'$`)

func scriptVars(stdin string) map[string]string {
	out := map[string]string{}
	for _, m := range assignRe.FindAllStringSubmatch(stdin, -1) {
		if _, seen := out[m[1]]; !seen {
			out[m[1]] = m[2]
		}
	}
	return out
}

const planDigest = "1111111111111111111111111111111111111111111111111111111111111111"

func planOK() string {
	return "MERIDIAN_OWNER tw dep srv\nMERIDIAN_PLAN iface m14 present\nMERIDIAN_PLAN file /etc/wireguard/m14.conf present\nMERIDIAN_PLAN_DIGEST " + planDigest + "\nMERIDIAN_PLAN_OK\n"
}

// withdrawFix is a provisioned node "tw" (gate fixture) whose server also
// answers withdraw scripts through h.
func withdrawFix(t *testing.T) (*gateFix, *wdHost) {
	t.Helper()
	f := newGateFix(t)
	h := &wdHost{reply: func(mode, action, digest string) (string, uint32) {
		if action == "plan" {
			return planOK(), 0
		}
		return "MERIDIAN_REMOVED iface m14\nMERIDIAN_REMOVED file /etc/wireguard/m14.conf\nMERIDIAN_KEPT package wireguard-tools (installed by Meridian, kept on purpose)\nMERIDIAN_WITHDRAW_OK\n", 0
	}}
	prev := f.script
	f.mu.Lock()
	f.script = func(stdin string) (string, uint32) {
		if strings.Contains(stdin, "# Meridian withdraw") {
			v := scriptVars(stdin)
			h.mu.Lock()
			h.runs = append(h.runs, stdin)
			reply := h.reply
			h.mu.Unlock()
			return reply(v["MODE"], v["ACTION"], v["DIGEST"])
		}
		return prev(stdin)
	}
	f.mu.Unlock()
	// The fixture's handler routes only provision scripts to f.script;
	// widen it to the withdraw script.
	f.srv.SetHandler(func(cmd, stdin string) (string, uint32) {
		f.mu.Lock()
		extra, script := f.extra, f.script
		f.mu.Unlock()
		if out, ok := cleanPreflight(cmd, stdin, extra); ok {
			return out, 0
		}
		if cmd == "bash -s" && (strings.Contains(stdin, "echo MERIDIAN_PROVISION_OK") || strings.Contains(stdin, "# Meridian withdraw")) {
			return script(stdin)
		}
		if cmd == sshexec.TestCommand {
			return "MERIDIAN_ARCH=x86_64\n", 0
		}
		return "unexpected", 1
	})
	id := f.preflight(t).ID
	if rr := f.provision(id); rr.Code != 200 {
		t.Fatalf("provision: %d %s", rr.Code, rr.Body.String())
	}
	return f, h
}

func (h *wdHost) set(reply func(mode, action, digest string) (string, uint32)) {
	h.mu.Lock()
	h.reply = reply
	h.mu.Unlock()
}

func (h *wdHost) count() int { h.mu.Lock(); defer h.mu.Unlock(); return len(h.runs) }

func wdPlan(t *testing.T, s *Server, node, mode string) (int, map[string]any) {
	t.Helper()
	rr := do(s, http.MethodPost, "/api/provision/withdraw/plan", mustJSON(map[string]any{"node_id": node, "mode": mode}))
	var out map[string]any
	_ = json.Unmarshal(rr.Body.Bytes(), &out)
	return rr.Code, out
}

func planID(t *testing.T, out map[string]any) string {
	t.Helper()
	p, _ := out["plan"].(map[string]any)
	id, _ := p["id"].(string)
	if id == "" {
		t.Fatalf("no plan id: %v", out)
	}
	return id
}

func wdRun(s *Server, node, plan, confirm string) (int, map[string]any) {
	rr := do(s, http.MethodPost, "/api/provision/withdraw", mustJSON(map[string]any{"node_id": node, "plan_id": plan, "confirm": confirm}))
	var out map[string]any
	_ = json.Unmarshal(rr.Body.Bytes(), &out)
	return rr.Code, out
}

func deployment(t *testing.T, s *Server, node string) deploymentView {
	t.Helper()
	rr := do(s, http.MethodGet, "/api/deployments", nil)
	var out struct {
		Nodes []deploymentView `json:"nodes"`
	}
	decode(t, rr, &out)
	for _, d := range out.Nodes {
		if d.NodeID == node {
			return d
		}
	}
	t.Fatalf("no deployment record for %s: %s", node, rr.Body.String())
	return deploymentView{}
}

func refKinds(t *testing.T, s *Server, serverID string) string {
	t.Helper()
	var out struct{ Server serverView }
	decode(t, do(s, http.MethodGet, "/api/servers/"+serverID, nil), &out)
	var kinds []string
	for _, r := range out.Server.InUseBy {
		kinds = append(kinds, r.Kind)
	}
	return strings.Join(kinds, ",")
}

// The whole remote path: the record binds the identity and pins the
// server and credential; plan → confirm → partial → re-plan → withdrawn;
// the pin is released only after a verified withdraw; a re-run answers
// "already withdrawn"; the record can then be forgotten.
func TestNodeWithdrawStateMachine(t *testing.T) {
	f, h := withdrawFix(t)
	s := f.s
	d := deployment(t, s, "tw")
	if !d.OnHost || d.Status != "installed" || d.ServerID != f.id || d.CredentialID != f.credID || d.Fingerprint != f.srv.Fingerprint() || d.User != "root" {
		t.Fatalf("record %+v", d)
	}
	// Pinned: the server cannot be repointed or deleted, the credential not deleted.
	if !strings.Contains(refKinds(t, s, f.id), "node_deployment") {
		t.Fatalf("server not pinned by the deployment: %s", refKinds(t, s, f.id))
	}
	if rr := do(s, http.MethodPatch, "/api/servers/"+f.id, mustJSON(map[string]any{"address": "192.0.2.99"})); rr.Code != http.StatusConflict {
		t.Fatalf("repoint pinned server: %d %s", rr.Code, rr.Body.String())
	}
	if rr := do(s, http.MethodDelete, "/api/ssh-credentials/"+f.credID, nil); rr.Code != http.StatusConflict {
		t.Fatalf("delete pinned credential: %d", rr.Code)
	}

	// Plan, then the confirmation rules.
	code, out := wdPlan(t, s, "tw", "")
	if code != 200 {
		t.Fatalf("plan %d %v", code, out)
	}
	pid := planID(t, out)
	if c, o := wdRun(s, "tw", pid, ""); c != http.StatusBadRequest || o["code"] != codeConfirmRequired {
		t.Fatalf("no confirm: %d %v", c, o)
	}
	if c, o := wdRun(s, "tw", "wp-nope", "tw"); c != http.StatusConflict || o["code"] != codeWithdrawPlanStale {
		t.Fatalf("unknown plan: %d %v", c, o)
	}
	// The script carries only validated identity values and the plan digest.
	h.set(func(mode, action, digest string) (string, uint32) {
		if digest != planDigest {
			return "MERIDIAN_REFUSED plan_changed\n", 3
		}
		return "MERIDIAN_REMOVED iface m14\nMERIDIAN_LEFTOVER file /etc/sysctl.d/99-meridian.conf (changed since the install: kept, check it by hand)\nMERIDIAN_WITHDRAW_PARTIAL\n", 4
	})
	c, o := wdRun(s, "tw", pid, "tw")
	if c != http.StatusBadGateway || o["outcome"] != withdrawStatePartial || len(o["leftovers"].([]any)) != 1 {
		t.Fatalf("partial: %d %v", c, o)
	}
	last := h.runs[len(h.runs)-1]
	v := scriptVars(last)
	dep, _ := s.deploymentID()
	if v["NODE"] != "tw" || v["SERVER"] != f.id || v["DEPLOYMENT"] != dep || v["MODE"] != "manifest" || v["ACTION"] != "run" || v["DIGEST"] != planDigest {
		t.Fatalf("script vars %v", v)
	}
	if d := deployment(t, s, "tw"); d.Status != "withdraw_partial" || !d.OnHost {
		t.Fatalf("after partial %+v", d)
	}
	if !strings.Contains(refKinds(t, s, f.id), "node_deployment") {
		t.Fatal("pin released after a partial withdraw")
	}
	// The plan is single use.
	if c, o := wdRun(s, "tw", pid, "tw"); c != http.StatusConflict || o["code"] != codeWithdrawPlanStale {
		t.Fatalf("reused plan: %d %v", c, o)
	}

	// Re-plan and finish.
	h.set(func(mode, action, digest string) (string, uint32) {
		if action == "plan" {
			return planOK(), 0
		}
		return "MERIDIAN_REMOVED file /etc/sysctl.d/99-meridian.conf\nMERIDIAN_KEPT sysctl runtime values\nMERIDIAN_WITHDRAW_OK\n", 0
	})
	_, out = wdPlan(t, s, "tw", "manifest")
	c, o = wdRun(s, "tw", planID(t, out), "tw")
	if c != 200 || o["outcome"] != withdrawStateDone || len(o["kept"].([]any)) != 1 {
		t.Fatalf("withdraw: %d %v", c, o)
	}
	d = deployment(t, s, "tw")
	if d.OnHost || d.Status != "withdrawn" || d.Installed {
		t.Fatalf("after withdraw %+v", d)
	}
	if strings.Contains(refKinds(t, s, f.id), "node_deployment") {
		t.Fatal("pin kept after a verified withdraw")
	}
	// The next provision of the node is a first install again.
	if rr := f.provision(""); rr.Code != http.StatusConflict || codeOf(t, rr.Body.Bytes()) != codePreflightRequired {
		t.Fatalf("provision after withdraw: %d %s", rr.Code, rr.Body.String())
	}

	// Idempotent: the host says it is withdrawn already.
	h.set(func(mode, action, digest string) (string, uint32) { return "MERIDIAN_WITHDRAW_ALREADY\n", 0 })
	code, out = wdPlan(t, s, "tw", "")
	if code != 200 || out["already_withdrawn"] != true {
		t.Fatalf("second plan: %d %v", code, out)
	}
	if rr := do(s, http.MethodDelete, "/api/provision/state/tw", nil); rr.Code != 200 {
		t.Fatalf("forget: %d %s", rr.Code, rr.Body.String())
	}
}

// Identity binding: a changed host key, a key re-pinned to another host
// and a node moved to another server are handled without ever running the
// script on a different host than the one provisioned.
func TestNodeWithdrawIdentityBinding(t *testing.T) {
	f, h := withdrawFix(t)
	s := f.s
	// Node moved to another server in the topology: provisioning there is
	// refused while the old install is not withdrawn …
	other := startSSH(t)
	rr := do(s, http.MethodPost, "/api/servers", mustJSON(map[string]any{"name": "另一台", "address": other.Host, "port": other.Port, "user": "root", "auth": "password", "credential_id": f.credID}))
	var sv struct{ Server serverView }
	decode(t, rr, &sv)
	topo, _, _ := s.Store.Load()
	for i := range topo.Nodes {
		if topo.Nodes[i].ID == "tw" {
			topo.Nodes[i].ServerID = sv.Server.ID
		}
	}
	_ = s.Store.Save(topo)
	do(s, http.MethodPost, "/api/servers/"+sv.Server.ID+"/host-key/discover", nil)
	do(s, http.MethodPost, "/api/servers/"+sv.Server.ID+"/host-key/trust", mustJSON(map[string]string{"fingerprint": other.Fingerprint()}))
	if rr := do(s, http.MethodPost, "/api/provision/preflight", mustJSON(map[string]any{"node_id": "tw"})); rr.Code != http.StatusConflict || codeOf(t, rr.Body.Bytes()) != codeDeployedElsewhere {
		t.Fatalf("preflight on the new server: %d %s", rr.Code, rr.Body.String())
	}
	// … and the withdraw goes to the recorded server, not the new one.
	before := len(other.Stdins())
	if code, out := wdPlan(t, s, "tw", ""); code != 200 {
		t.Fatalf("plan %d %v", code, out)
	}
	if len(other.Stdins()) != before || h.count() != 1 {
		t.Fatal("the withdraw reached the node's new server")
	}

	// The recorded server's trusted key changes (forgotten, another key
	// trusted): refused before anything runs.
	if rr := do(s, http.MethodDelete, "/api/servers/"+f.id+"/host-key", nil); rr.Code != 200 {
		t.Fatalf("forget key: %d %s", rr.Code, rr.Body.String())
	}
	if code, out := wdPlan(t, s, "tw", ""); code != http.StatusConflict || out["code"] != sshexec.CodePinMismatch {
		t.Fatalf("untrusted key: %d %v", code, out)
	}
	f.srv.SetHostKey(sshtest.NewHostKey())
	do(s, http.MethodPost, "/api/servers/"+f.id+"/host-key/discover", nil)
	if rr := do(s, http.MethodPost, "/api/servers/"+f.id+"/host-key/trust", mustJSON(map[string]string{"fingerprint": f.srv.Fingerprint()})); rr.Code != 200 {
		t.Fatalf("trust new key: %d %s", rr.Code, rr.Body.String())
	}
	if code, out := wdPlan(t, s, "tw", ""); code != http.StatusConflict || out["code"] != sshexec.CodePinMismatch {
		t.Fatalf("re-pinned host: %d %v", code, out)
	}
	if h.count() != 1 {
		t.Fatal("a script ran against a host with another key")
	}
	if d := deployment(t, s, "tw"); d.IdentityProblem == "" || !d.OnHost {
		t.Fatalf("identity problem not shown: %+v", d)
	}
}

// Refusals from the host, an unreachable host and an inconclusive run are
// never reported as withdrawn; the deployment stays pinned.
func TestNodeWithdrawRefusedUnreachableUnknown(t *testing.T) {
	f, h := withdrawFix(t)
	s := f.s
	h.set(func(mode, action, digest string) (string, uint32) {
		return "MERIDIAN_OWNER jp dep-other srv-9\nMERIDIAN_REFUSED manifest_other\n", 3
	})
	code, out := wdPlan(t, s, "tw", "")
	if code != http.StatusConflict || out["code"] != codeWithdrawRefused || out["reason"] != "manifest_other" || !strings.Contains(out["error"].(string), "另一个节点") {
		t.Fatalf("other owner: %d %v", code, out)
	}
	h.set(func(mode, action, digest string) (string, uint32) { return "MERIDIAN_REFUSED manifest_missing\n", 3 })
	if code, out := wdPlan(t, s, "tw", ""); code != http.StatusConflict || out["reason"] != "manifest_missing" {
		t.Fatalf("missing manifest: %d %v", code, out)
	}

	// Inconclusive: exit 0 without a marker.
	h.set(func(mode, action, digest string) (string, uint32) {
		if action == "plan" {
			return planOK(), 0
		}
		return "connection reset\n", 0
	})
	_, out = wdPlan(t, s, "tw", "")
	c, o := wdRun(s, "tw", planID(t, out), "tw")
	if c != http.StatusBadGateway || o["outcome"] != withdrawStateUnknown {
		t.Fatalf("unknown: %d %v", c, o)
	}
	if d := deployment(t, s, "tw"); d.Status != "withdraw_unknown" || !d.OnHost {
		t.Fatalf("after unknown %+v", d)
	}

	// Unreachable host: not started, still installed.
	h.set(func(mode, action, digest string) (string, uint32) { return planOK(), 0 })
	_, out = wdPlan(t, s, "tw", "")
	pid := planID(t, out)
	f.srv.Close()
	c, o = wdRun(s, "tw", pid, "tw")
	if c != http.StatusBadGateway || o["outcome"] != withdrawStateNotStarted {
		t.Fatalf("unreachable: %d %v", c, o)
	}
	if d := deployment(t, s, "tw"); !d.OnHost || d.Status == "withdrawn" {
		t.Fatalf("after unreachable %+v", d)
	}

	// The server is gone for good: abandon (typed confirmation) releases
	// the pin without claiming anything was removed.
	if rr := do(s, http.MethodPost, "/api/provision/withdraw/abandon", mustJSON(map[string]any{"node_id": "tw", "confirm": "x"})); rr.Code != http.StatusBadRequest {
		t.Fatalf("abandon without confirm: %d", rr.Code)
	}
	if rr := do(s, http.MethodPost, "/api/provision/withdraw/abandon", mustJSON(map[string]any{"node_id": "tw", "confirm": "tw"})); rr.Code != 200 {
		t.Fatalf("abandon: %d %s", rr.Code, rr.Body.String())
	}
	d := deployment(t, s, "tw")
	if d.Status != "abandoned" || d.OnHost || d.Withdraw == nil || !strings.Contains(d.Withdraw.Message, "未核实") {
		t.Fatalf("abandoned %+v", d)
	}
	if strings.Contains(refKinds(t, s, f.id), "node_deployment") {
		t.Fatal("abandoned deployment still pins the server")
	}
}

// A node with an active Mesh deployment on its host is withdrawn only
// after the Mesh withdrawal (which keeps its own host and account binding).
func TestNodeWithdrawWaitsForMesh(t *testing.T) {
	f, h := withdrawFix(t)
	s := f.s
	j := mesh.Journal{Schema: mesh.JournalSchema, RunID: "run-mesh-1", State: mesh.StatePublished, AccountID: "acct-example",
		Hosts: []mesh.HostPin{{NodeID: "tw", ServerID: f.id, CredentialID: f.credID, SSHHost: f.srv.Host, SSHPort: f.srv.Port, SSHUser: "root", HostKey: f.srv.Fingerprint()}}}
	b, _ := json.Marshal(j)
	if err := os.MkdirAll(s.meshDir(), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(s.meshDir(), "deploy.json"), b, 0o600); err != nil {
		t.Fatal(err)
	}
	_, out := wdPlan(t, s, "tw", "")
	n := h.count()
	c, o := wdRun(s, "tw", planID(t, out), "tw")
	if c != http.StatusConflict || o["code"] != codeMeshDeployed || h.count() != n {
		t.Fatalf("mesh bound: %d %v", c, o)
	}
	if d := deployment(t, s, "tw"); d.MeshBound == "" {
		t.Fatal("deploy record does not say Mesh binds the node")
	}
	// Mesh withdrawn: the node withdraw goes ahead.
	j.State = mesh.StateWithdrawn
	b, _ = json.Marshal(j)
	_ = os.WriteFile(filepath.Join(s.meshDir(), "deploy.json"), b, 0o600)
	_, out = wdPlan(t, s, "tw", "")
	if c, o := wdRun(s, "tw", planID(t, out), "tw"); c != 200 || o["outcome"] != withdrawStateDone {
		t.Fatalf("after mesh withdraw: %d %v", c, o)
	}
}

// An interrupted provision is recovered from the panel (journal mode).
func TestNodeWithdrawRecoversInterruptedProvision(t *testing.T) {
	f := newGateFix(t)
	s := f.s
	f.mu.Lock()
	f.script = func(stdin string) (string, uint32) {
		return "MERIDIAN_COMPENSATING exit=1\nMERIDIAN_LEFTOVER interface m14\nMERIDIAN_COMPENSATION_INCOMPLETE\n", 1
	}
	f.mu.Unlock()
	if rr := f.provision(f.preflight(t).ID); rr.Code == 200 {
		t.Fatal("setup: provision should fail")
	}
	d := deployment(t, s, "tw")
	if d.Status != "left_behind" || !d.OnHost {
		t.Fatalf("left behind %+v", d)
	}
	h := &wdHost{reply: func(mode, action, digest string) (string, uint32) {
		if mode != "journal" {
			return "MERIDIAN_REFUSED journal_incomplete\n", 3
		}
		if action == "plan" {
			return "MERIDIAN_PLAN remove file /etc/wireguard/m14.conf\nMERIDIAN_PLAN_DIGEST " + planDigest + "\nMERIDIAN_PLAN_OK\n", 0
		}
		return "MERIDIAN_COMPENSATING exit=1\nMERIDIAN_COMPENSATED\n", 1
	}}
	f.srv.SetHandler(func(cmd, stdin string) (string, uint32) {
		if cmd == "bash -s" && strings.Contains(stdin, "# Meridian withdraw") {
			v := scriptVars(stdin)
			return h.reply(v["MODE"], v["ACTION"], v["DIGEST"])
		}
		return "unexpected", 1
	})
	if code, out := wdPlan(t, s, "tw", "manifest"); code != http.StatusConflict || out["reason"] != "journal_incomplete" {
		t.Fatalf("manifest mode: %d %v", code, out)
	}
	_, out := wdPlan(t, s, "tw", "journal")
	c, o := wdRun(s, "tw", planID(t, out), "tw")
	if c != 200 || o["outcome"] != withdrawStateRecovered {
		t.Fatalf("recover: %d %v", c, o)
	}
	if d := deployment(t, s, "tw"); d.OnHost || d.Status != "not_installed" {
		t.Fatalf("after recovery %+v", d)
	}
}

// Gateway: withdraw down to the guard through the transaction, idempotent,
// no rollback afterwards, guard released only as a separate step.
func TestGatewayWithdrawAPI(t *testing.T) {
	s, root, _ := installTest(t)
	if rr := do(s, http.MethodPost, "/api/apply", mustJSON(map[string]any{"install": true})); rr.Code != 200 {
		t.Fatalf("install: %d %s", rr.Code, rr.Body.String())
	}
	if rr := do(s, http.MethodPost, "/api/host/withdraw", mustJSON(map[string]any{"confirm": "yes"})); rr.Code != http.StatusBadRequest || codeOf(t, rr.Body.Bytes()) != codeConfirmRequired {
		t.Fatalf("confirm: %d %s", rr.Code, rr.Body.String())
	}
	rr := do(s, http.MethodPost, "/api/host/withdraw", mustJSON(map[string]any{"confirm": "gw"}))
	var res struct {
		Status  string            `json:"status"`
		Removed apply.WithdrawSet `json:"removed"`
		Kept    []string          `json:"kept"`
	}
	decode(t, rr, &res)
	if rr.Code != 200 || res.Status != "withdrawn" || len(res.Removed.Files) == 0 || !strings.Contains(strings.Join(res.Kept, "\n"), "inet meridian_guard") {
		t.Fatalf("withdraw: %d %s", rr.Code, rr.Body.String())
	}
	if _, err := os.Stat(filepath.Join(root, filepath.FromSlash(hostexec.GuardBootFile))); err != nil {
		t.Fatal("guard boot file removed")
	}
	if _, err := os.Stat(filepath.Join(root, "usr", "local", "sbin", "meridian-up.sh")); err == nil {
		t.Fatal("up script left")
	}
	var dep struct {
		Gateway gatewayDeploymentView `json:"gateway"`
	}
	decode(t, do(s, http.MethodGet, "/api/deployments", nil), &dep)
	if !dep.Gateway.Withdrawn || dep.Gateway.Installed || dep.Gateway.Last == nil || dep.Gateway.Last.State != "withdrawn" {
		t.Fatalf("gateway view %+v", dep.Gateway)
	}
	if rr := do(s, http.MethodGet, "/api/status", nil); !strings.Contains(rr.Body.String(), `"state":"withdrawn"`) {
		t.Fatalf("status: %s", rr.Body.String())
	}
	decode(t, do(s, http.MethodPost, "/api/host/withdraw", mustJSON(map[string]any{"confirm": "gw"})), &res)
	if res.Status != "already_withdrawn" {
		t.Fatalf("second withdraw %+v", res)
	}
	if rr := do(s, http.MethodPost, "/api/rollback", mustJSON(map[string]any{"install": true})); rr.Code != http.StatusConflict || codeOf(t, rr.Body.Bytes()) != codeGatewayWithdrawn {
		t.Fatalf("rollback after withdraw: %d %s", rr.Code, rr.Body.String())
	}
	decode(t, do(s, http.MethodPost, "/api/host/withdraw", mustJSON(map[string]any{"confirm": "gw", "release_guard": true})), &res)
	if res.Status != "guard_released" {
		t.Fatalf("release guard %+v", res)
	}
	if _, err := os.Stat(filepath.Join(root, filepath.FromSlash(hostexec.GuardBootFile))); err == nil {
		t.Fatal("guard file left after release")
	}
	if rr := do(s, http.MethodPost, "/api/host/withdraw", mustJSON(map[string]any{"confirm": "gw"})); rr.Code != http.StatusConflict || codeOf(t, rr.Body.Bytes()) != codeNothingInstalled {
		t.Fatalf("nothing installed: %d %s", rr.Code, rr.Body.String())
	}
}

// Unlock results of exits that no longer exist are not shown as current:
// left out by default, marked when asked for, and prunable; admission
// records are untouched.
func TestUnlockResultsOfRemovedExits(t *testing.T) {
	s := newTest(t)
	do(s, http.MethodGet, "/api/topology", nil)
	s.mu.Lock()
	s.recordResults([]probeJobItem{
		{Service: "netflix", ExitID: "tw", Family: "ipv4", State: "done"},
		{Service: "netflix", ExitID: "gone-exit", Family: "ipv4", State: "done"},
	})
	snap := s.loadUnlock()
	snap.History = append(snap.History, unlockHistory("gone-exit"))
	_ = s.saveUnlock(snap)
	s.mu.Unlock()

	var res struct {
		Results      []resultRow        `json:"results"`
		RemovedExits []removedExitCount `json:"removed_exits"`
	}
	decode(t, do(s, http.MethodGet, "/api/unlock/results", nil), &res)
	if len(res.Results) != 1 || res.Results[0].ExitID != "tw" || len(res.RemovedExits) != 1 || res.RemovedExits[0].ExitID != "gone-exit" {
		t.Fatalf("default view %+v", res)
	}
	decode(t, do(s, http.MethodGet, "/api/unlock/results?include_removed=1", nil), &res)
	marked := false
	for _, r := range res.Results {
		if r.ExitID == "gone-exit" {
			marked = r.ExitRemoved && !r.IsActive
		}
	}
	if !marked {
		t.Fatalf("removed exit not marked: %+v", res.Results)
	}
	var un struct {
		RemovedExits []string `json:"removed_exits"`
	}
	decode(t, do(s, http.MethodGet, "/api/unlock", nil), &un)
	if strings.Join(un.RemovedExits, ",") != "gone-exit" {
		t.Fatalf("unlock removed_exits %v", un.RemovedExits)
	}
	var pr struct {
		Removed int      `json:"removed"`
		Exits   []string `json:"exits"`
	}
	decode(t, do(s, http.MethodPost, "/api/unlock/results/prune", nil), &pr)
	if pr.Removed != 1 || strings.Join(pr.Exits, ",") != "gone-exit" {
		t.Fatalf("prune %+v", pr)
	}
	decode(t, do(s, http.MethodGet, "/api/unlock/results?include_removed=1", nil), &res)
	if len(res.Results) != 1 || len(res.RemovedExits) != 0 {
		t.Fatalf("after prune %+v", res)
	}
	// History (and admission state) are kept: still marked, not deleted.
	decode(t, do(s, http.MethodGet, "/api/unlock", nil), &un)
	if strings.Join(un.RemovedExits, ",") != "gone-exit" {
		t.Fatal("prune deleted unlock history")
	}
}
