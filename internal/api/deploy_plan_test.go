package api

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/radowitz/meridian/internal/credentials"
	"github.com/radowitz/meridian/internal/defaults"
	"github.com/radowitz/meridian/internal/model"
	"github.com/radowitz/meridian/internal/sshexec"
	"github.com/radowitz/meridian/internal/sshexec/sshtest"
)

// The ordered deployment guide (deploy_plan.go). The order is tested as a
// pure function on the documentation topologies; the run against the local
// SSH stand-ins (sshtest), the fake host preflight and the activation shim.
// No remote host is contacted.

// ------------------------------------------------------------------ order ---

// orderTopo: two relays, the IX as primary hub (SSH through a port-forward
// on the first relay), a backup hub, a relay exit with a nested exit behind
// it, a plain exit carrying an external SOCKS exit.
func orderTopo() model.Topology {
	t := defaults.NestedExample()
	sh := defaults.SharedRelaysExample()
	for _, n := range sh.Nodes {
		if n.ID == "ali2" {
			t.Nodes = append(t.Nodes, n)
		}
	}
	for _, l := range sh.Links {
		if strings.Contains(l.ID, "ali2") {
			t.Links = append(t.Links, l)
		}
	}
	ex := defaults.ExternalExample()
	for _, n := range ex.Nodes {
		if n.ID == "my1" {
			t.Nodes = append(t.Nodes, n)
		}
	}
	return t
}

// orderServers gives every managed node a direct server; the IX's is the
// first relay's public address on another port (a TCP port-forward).
func orderServers(t model.Topology) (model.Topology, map[string]model.Server) {
	out := map[string]model.Server{}
	for i := range t.Nodes {
		n := &t.Nodes[i]
		if !n.Managed || n.Role == model.RoleGateway {
			continue
		}
		id := "srv-" + n.ID
		n.ServerID = id
		out[id] = model.Server{ID: id, Name: n.ID, Address: fmt.Sprintf("192.0.2.%d", 10+i), Port: 22, User: "root", CredentialID: "c1",
			HostKey: model.HostKey{State: model.HostKeyTrusted, Fingerprint: "SHA256:" + n.ID}}
	}
	ali, _ := t.NodeByID("ali")
	sv := out["srv-ix"]
	sv.Address, sv.Port = ali.EndpointV4, 2222
	out["srv-ix"] = sv
	sv = out["srv-ali"]
	sv.Address = ali.EndpointV4
	out["srv-ali"] = sv
	return t, out
}

func allPending(t model.Topology) map[string]bool {
	p := map[string]bool{}
	for _, n := range t.Nodes {
		if n.Managed {
			p[n.ID] = true
		}
	}
	return p
}

func orderIDs(steps []orderedStep) []string {
	var out []string
	for _, s := range steps {
		out = append(out, s.ID)
	}
	return out
}

func stepOf(steps []orderedStep, id string) orderedStep {
	for _, s := range steps {
		if s.ID == id {
			return s
		}
	}
	return orderedStep{}
}

func TestDeployOrderNestedRelaysHubs(t *testing.T) {
	topo, servers := orderServers(orderTopo())
	steps, notes := deployOrder(topo, servers, allPending(topo), true)
	got := strings.Join(orderIDs(steps), ",")
	// Nested exit before its relay exit, exits before the backup hub, the
	// backup before the primary (the IX), hubs before both relays, the
	// gateway last; the external SOCKS exit has no step at all.
	if want := "tw2,dc1,dc2,hk5,ix,ali,ali2,gw"; got != want {
		t.Fatalf("order %s, want %s (notes %v)", got, want, notes)
	}
	if len(notes) != 0 {
		t.Fatalf("notes %v", notes)
	}
	for _, id := range []string{"tw2", "dc1", "dc2", "hk5", "ix", "ali", "ali2", "gw"} {
		if stepOf(steps, id).Reason == "" {
			t.Fatalf("%s has no reason", id)
		}
	}
	if r := stepOf(steps, "dc1").Reason; !strings.Contains(r, "中继出口") {
		t.Fatalf("relay exit reason %q", r)
	}
	if r := stepOf(steps, "dc2").Reason; !strings.Contains(r, "外部 SOCKS 出口") {
		t.Fatalf("carrier reason %q", r)
	}
	if r := stepOf(steps, "ali").Reason; !strings.Contains(r, "2 台中继") {
		t.Fatalf("relay reason %q", r)
	}
	if r := stepOf(steps, "hk5").Reason; !strings.Contains(r, "备用枢纽") {
		t.Fatalf("backup hub reason %q", r)
	}
	// The IX's SSH goes through a port-forward on the first relay: an edge
	// (already satisfied by the tiers), warned on both.
	if w := strings.Join(stepOf(steps, "ix").Warnings, "|"); !strings.Contains(w, "端口转发") {
		t.Fatalf("ix warnings %q", w)
	}
	if w := strings.Join(stepOf(steps, "ali").Warnings, "|"); !strings.Contains(w, "端口转发") {
		t.Fatalf("ali warnings %q", w)
	}
	// Only what is pending: an unchanged node has no step and changes
	// nothing else's order.
	p := allPending(topo)
	delete(p, "dc2")
	delete(p, "ali2")
	steps, _ = deployOrder(topo, servers, p, true)
	if got := strings.Join(orderIDs(steps), ","); got != "tw2,dc1,hk5,ix,ali,gw" {
		t.Fatalf("partial order %s", got)
	}
}

func TestDeployOrderManagementChannels(t *testing.T) {
	topo, servers := orderServers(orderTopo())
	// dc2 is managed through a jump over the first relay, tw2 through its
	// tunnel address; the second relay's SSH is a port-forward on dc1.
	sv := servers["srv-dc2"]
	sv.Channel = &model.ManagementChannel{Mode: model.ChannelJump, ViaServerID: "srv-ali"}
	servers["srv-dc2"] = sv
	sv = servers["srv-tw2"]
	sv.Channel = &model.ManagementChannel{Mode: model.ChannelTunnel, Address: "10.66.1.2"}
	servers["srv-tw2"] = sv
	dc1, _ := topo.NodeByID("dc1")
	sv = servers["srv-ali2"]
	sv.Address, sv.Port = dc1.EndpointV4, 2200
	servers["srv-ali2"] = sv
	servers["srv-dc1"] = func() model.Server { s := servers["srv-dc1"]; s.Address = dc1.EndpointV4; return s }()

	steps, notes := deployOrder(topo, servers, allPending(topo), false)
	ids := orderIDs(steps)
	pos := map[string]int{}
	for i, id := range ids {
		pos[id] = i
	}
	if len(notes) != 0 {
		t.Fatalf("notes %v", notes)
	}
	// ali2 moved ahead of dc1 (its SSH goes through dc1's host), the
	// gateway is still last, the jump target before its jump host.
	if pos["ali2"] > pos["dc1"] || ids[len(ids)-1] != "gw" || pos["dc2"] > pos["ali"] {
		t.Fatalf("order %v", ids)
	}
	if r := stepOf(steps, "ali2").Reason; !strings.Contains(r, "因管理通道提前") {
		t.Fatalf("ali2 reason %q", r)
	}
	if w := strings.Join(stepOf(steps, "dc2").Warnings, "|"); !strings.Contains(w, "跳转管理") {
		t.Fatalf("dc2 warnings %q", w)
	}
	if w := strings.Join(stepOf(steps, "ali").Warnings, "|"); !strings.Contains(w, "经这台服务器跳转管理") {
		t.Fatalf("ali warnings %q", w)
	}
	w := strings.Join(stepOf(steps, "tw2").Warnings, "|")
	if !strings.Contains(w, "经隧道地址 10.66.1.2") || !strings.Contains(w, "隧道还不存在") {
		t.Fatalf("tw2 warnings %q", w)
	}
	// Contradicting channels (dc1 jumps through ali2, whose SSH goes
	// through dc1's host): the base order, said so.
	sv = servers["srv-dc1"]
	sv.Channel = &model.ManagementChannel{Mode: model.ChannelJump, ViaServerID: "srv-ali2"}
	servers["srv-dc1"] = sv
	steps, notes = deployOrder(topo, servers, allPending(topo), true)
	if len(notes) != 1 || !strings.Contains(notes[0], "成环") || orderIDs(steps)[len(steps)-1] != "gw" {
		t.Fatalf("cycle: %v %v", orderIDs(steps), notes)
	}
}

func TestTopologyVersionIgnoresPositionsKeysAndRemoteAccess(t *testing.T) {
	a := defaults.Example()
	v := topologyVersion(a)
	b := defaults.Example()
	b.Nodes[1].X, b.Nodes[1].Y, b.Nodes[1].PrivateKey = 999, 999, "secret"
	b.RemoteAccess = &model.RemoteAccess{Enabled: true}
	if topologyVersion(b) != v {
		t.Fatal("positions, private keys or remote access changed the version")
	}
	if a.Nodes[1].PrivateKey != "" {
		t.Fatal("the input was modified")
	}
	b.Nodes[1].WANInterface = "ens9"
	if topologyVersion(b) == v {
		t.Fatal("a real change kept the version")
	}
}

// -------------------------------------------------------------------- run ---

// deployFix is the example topology with every managed remote node on its
// own trusted server: the nodes named in sshNodes on an SSH stand-in, the
// others on documentation addresses and recorded as installed with
// exactly their current content (so the plan skips them). The gateway
// installs through the activation shim with the fake host preflight.
type deployFix struct {
	s      *Server
	hp     *fakeHostPreflight
	act    int
	failGW bool
	mu     sync.Mutex
	srv    map[string]*sshtest.Server
	sid    map[string]string
	extra  map[string]string
	script map[string]func(stdin string) (string, uint32)
	host   map[string]string
	runs   map[string]int
}

func newDeployFix(t *testing.T, sshNodes ...string) *deployFix {
	t.Helper()
	s := newTest(t)
	s.HostRoot = t.TempDir()
	f := &deployFix{s: s, hp: &fakeHostPreflight{}, srv: map[string]*sshtest.Server{}, sid: map[string]string{}, extra: map[string]string{},
		script: map[string]func(string) (string, uint32){}, host: map[string]string{}, runs: map[string]int{}}
	s.HostPreflight = f.hp
	s.Activate = func() error {
		f.mu.Lock()
		defer f.mu.Unlock()
		f.act++
		if f.failGW {
			f.failGW = false // the compensating activation succeeds
			return errors.New("synthetic activation failure")
		}
		return nil
	}
	do(s, http.MethodGet, "/api/topology", nil)
	pw := "pw-" + rnd(t, 8)
	rr := do(s, http.MethodPost, "/api/ssh-credentials", mustJSON(map[string]any{"name": "pw", "kind": "password", "password": pw}))
	var c struct{ Credential credView }
	decode(t, rr, &c)
	cs, err := s.credStore()
	if err != nil {
		t.Fatal(err)
	}
	isSSH := map[string]bool{}
	for _, n := range sshNodes {
		isSSH[n] = true
	}
	topo, _, _ := s.Store.Load()
	for i := range topo.Nodes {
		n := &topo.Nodes[i]
		if !n.Managed || n.Role == model.RoleGateway {
			continue
		}
		if isSSH[n.ID] {
			node := n.ID
			srv := startSSH(t)
			srv.SetPassword(pw)
			srv.SetHandler(func(cmd, stdin string) (string, uint32) { return f.answer(node, cmd, stdin) })
			sv, err := cs.CreateServer(credentials.ServerInput{Name: "机器 " + node, Address: srv.Host, Port: srv.Port, User: "root", Auth: model.AuthPassword, CredentialID: c.Credential.ID})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := cs.ObserveHostKey(sv.ID, "ssh-ed25519", srv.Fingerprint()); err != nil {
				t.Fatal(err)
			}
			if _, err := cs.TrustHostKey(sv.ID, srv.Fingerprint()); err != nil {
				t.Fatal(err)
			}
			f.srv[node], f.sid[node] = srv, sv.ID
			n.ServerID = sv.ID
			continue
		}
		sv, err := cs.CreateServer(credentials.ServerInput{Name: "机器 " + n.ID, Address: fmt.Sprintf("192.0.2.%d", 10+i), Port: 22, User: "root", Auth: model.AuthPassword, CredentialID: c.Credential.ID})
		if err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256([]byte("example host key " + n.ID))
		fp := "SHA256:" + base64.RawStdEncoding.EncodeToString(sum[:])
		if _, err := cs.ObserveHostKey(sv.ID, "ssh-ed25519", fp); err != nil {
			t.Fatal(err)
		}
		if _, err := cs.TrustHostKey(sv.ID, fp); err != nil {
			t.Fatal(err)
		}
		f.sid[n.ID] = sv.ID
		n.ServerID = sv.ID
	}
	if err := s.Store.Save(topo); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.ensureNodeKeys(); err != nil {
		t.Fatal(err)
	}
	f.markInSync(t, func(id string) bool { return !isSSH[id] })
	return f
}

// markInSync records the selected remote nodes as installed with exactly
// their current content on their current server.
func (f *deployFix) markInSync(t *testing.T, sel func(string) bool) {
	t.Helper()
	l, err := f.s.liveDeploy()
	if err != nil {
		t.Fatal(err)
	}
	for _, n := range l.t.Nodes {
		if !n.Managed || n.Role == model.RoleGateway || !sel(n.ID) {
			continue
		}
		id := l.idents[n.ID]
		f.s.saveOutcome(provisionOutcome{NodeID: n.ID, ServerID: id.ServerID, Address: id.Address, Port: id.Port, Fingerprint: id.Fingerprint,
			User: id.User, CredentialID: id.CredentialID, Bundle: l.bundles[n.ID], At: time.Now().UTC(), OK: true, Outcome: "installed", Run: "run-seed"})
	}
}

func (f *deployFix) answer(node, cmd, stdin string) (string, uint32) {
	f.mu.Lock()
	extra, script := f.extra[node], f.script[node]
	f.mu.Unlock()
	if out, ok := cleanPreflight(cmd, stdin, extra); ok {
		return out, 0
	}
	if cmd == "bash -s" && strings.Contains(stdin, "echo MERIDIAN_PROVISION_OK") {
		out, code := "MERIDIAN_PROVISION_OK\n", uint32(0)
		if script != nil {
			out, code = script(stdin)
		}
		f.mu.Lock()
		f.runs[node]++
		f.host[node] = defaultHostRecord(stdin, out, f.host[node])
		f.mu.Unlock()
		return out, code
	}
	if cmd == sshexec.NodeStateCommand {
		f.mu.Lock()
		h := f.host[node]
		f.mu.Unlock()
		return "meridian-node-state 1\n" + h + "meridian-node-state-end\n", 0
	}
	return "unexpected", 1
}

func (f *deployFix) setScript(node string, fn func(string) (string, uint32)) {
	f.mu.Lock()
	f.script[node] = fn
	f.mu.Unlock()
}

func (f *deployFix) scripts(node string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.runs[node]
}

type deployResp struct {
	Run *struct {
		ID          string            `json:"id"`
		State       string            `json:"state"`
		StopReason  string            `json:"stop_reason"`
		Stale       bool              `json:"stale"`
		StaleReason string            `json:"stale_reason"`
		Affected    []string          `json:"affected"`
		Current     string            `json:"current"`
		Steps       []deployStepView  `json:"steps"`
		Skipped     []planSkip        `json:"skipped"`
		Preflight   *preflightRecord  `json:"preflight"`
		Extra       map[string]string `json:"-"`
	} `json:"run"`
	Plan            *deployPlan `json:"plan"`
	TopologyVersion string      `json:"topology_version"`
	Code            string      `json:"code"`
	Error           string      `json:"error"`
	RetryAfter      int         `json:"retry_after"`
}

func (f *deployFix) call(t *testing.T, method, path string, body any, want int) deployResp {
	t.Helper()
	var raw []byte
	if body != nil {
		raw = mustJSON(body)
	}
	rr := do(f.s, method, path, raw)
	var out deployResp
	if err := json.Unmarshal(rr.Body.Bytes(), &out); err != nil {
		t.Fatalf("%s %s: %v %s", method, path, err, rr.Body.String())
	}
	if want != 0 && rr.Code != want {
		t.Fatalf("%s %s: %d (want %d) %s", method, path, rr.Code, want, rr.Body.String())
	}
	return out
}

func (f *deployFix) get(t *testing.T) deployResp {
	t.Helper()
	return f.call(t, http.MethodGet, "/api/deploy", nil, http.StatusOK)
}

func (f *deployFix) start(t *testing.T) string {
	t.Helper()
	out := f.call(t, http.MethodPost, "/api/deploy/runs", map[string]any{}, http.StatusOK)
	if out.Run == nil || out.Run.ID == "" {
		t.Fatal("no run")
	}
	return out.Run.ID
}

func (f *deployFix) preflight(t *testing.T, run, node string, want int) deployResp {
	t.Helper()
	return f.call(t, http.MethodPost, "/api/deploy/runs/"+run+"/preflight", map[string]any{"node_id": node}, want)
}

func (f *deployFix) install(t *testing.T, run, node string, want int) deployResp {
	t.Helper()
	cur := f.step(t, node)
	return f.call(t, http.MethodPost, "/api/deploy/runs/"+run+"/install", map[string]any{"node_id": node, "preflight_id": cur.PreflightID}, want)
}

func (f *deployFix) step(t *testing.T, node string) deployStepView {
	t.Helper()
	out := f.get(t)
	if out.Run == nil {
		t.Fatal("no run")
	}
	for _, st := range out.Run.Steps {
		if st.NodeID == node {
			return st
		}
	}
	t.Fatalf("no step %s", node)
	return deployStepView{}
}

func stepIDs(out deployResp) string {
	var ids []string
	for _, st := range out.Run.Steps {
		ids = append(ids, st.NodeID)
	}
	return strings.Join(ids, ",")
}

// The whole run: plan, skip, order, per-node preflight and confirmation,
// install, health; the gateway last; logins per node as in the single-node
// flow.
func TestDeployRunHappyPath(t *testing.T) {
	f := newDeployFix(t, "sg", "tw")
	plan := f.get(t).Plan
	if plan == nil || len(plan.Steps) != 3 {
		t.Fatalf("plan %+v", plan)
	}
	if got := plan.Steps[0].NodeID + "," + plan.Steps[1].NodeID + "," + plan.Steps[2].NodeID; got != "sg,tw,gw" {
		t.Fatalf("plan order %s", got)
	}
	skipped := map[string]string{}
	for _, sk := range plan.Skipped {
		skipped[sk.NodeID] = sk.Kind
	}
	if skipped["us"] != "in_sync" || skipped["ali"] != "in_sync" || skipped["ix"] != "unmanaged" {
		t.Fatalf("skipped %v", skipped)
	}
	run := f.start(t)
	// Install without a reviewed preflight: refused, nothing ran.
	f.call(t, http.MethodPost, "/api/deploy/runs/"+run+"/install", map[string]any{"node_id": "sg", "preflight_id": "pf-x"}, http.StatusConflict)
	// Out of order: refused.
	if out := f.preflight(t, run, "tw", http.StatusConflict); out.Code != codeDeployNotCurrent {
		t.Fatalf("out of order: %+v", out)
	}
	for _, node := range []string{"sg", "tw"} {
		out := f.preflight(t, run, node, http.StatusOK)
		st := f.step(t, node)
		if st.Phase != phaseReview || !st.CanInstall || !st.ConfirmationValid || out.Run.Preflight == nil || out.Run.Preflight.ID != st.PreflightID {
			t.Fatalf("%s after preflight: %+v", node, st)
		}
		if len(out.Run.Preflight.Changes) == 0 {
			t.Fatalf("%s: the review shows no changes", node)
		}
		f.install(t, run, node, http.StatusOK)
		st = f.step(t, node)
		if st.Phase != phaseDone || st.Outcome != "installed" || st.Health == nil || st.Health.Verify != verifyOK || st.Health.Source != "remote_script" {
			t.Fatalf("%s after install: %+v", node, st)
		}
		// One preflight and one install of the single-node flow: the pooled
		// login carries the re-run and the script.
		if l := f.srv[node].Logins(); l > 2 {
			t.Fatalf("%s: %d logins", node, l)
		}
	}
	f.preflight(t, run, "gw", http.StatusOK)
	out := f.install(t, run, "gw", http.StatusOK)
	st := f.step(t, "gw")
	if st.Phase != phaseDone || st.Health == nil || st.Health.Source != "gateway_transaction" || f.act != 1 {
		t.Fatalf("gateway: %+v (activations %d)", st, f.act)
	}
	if out.Run.State != runDone {
		t.Fatalf("run %s", out.Run.State)
	}
	// Every node is now in sync: nothing to plan, no new run.
	if p := f.get(t).Plan; len(p.Steps) != 0 {
		t.Fatalf("still pending: %+v", p.Steps)
	}
	if out := f.call(t, http.MethodPost, "/api/deploy/runs", map[string]any{}, http.StatusConflict); out.Code != codeDeployNothing {
		t.Fatalf("%+v", out)
	}
}

// A compensated install stops the run; the next node cannot be started;
// the re-check reads the host and the retry is an explicit confirmation.
func TestDeployRunStopsOnCompensationAndRecovers(t *testing.T) {
	f := newDeployFix(t, "sg", "tw")
	run := f.start(t)
	f.setScript("sg", func(string) (string, uint32) { return "MERIDIAN_COMPENSATING exit=1\nMERIDIAN_COMPENSATED\n", 1 })
	f.preflight(t, run, "sg", http.StatusOK)
	out := f.install(t, run, "sg", http.StatusOK)
	st := f.step(t, "sg")
	if out.Run.State != runStopped || st.Phase != phaseFailed || st.Outcome != "compensated" || st.CanInstall {
		t.Fatalf("after compensation: %s %+v", out.Run.State, st)
	}
	if !strings.Contains(out.Run.StopReason, "已补偿") {
		t.Fatalf("stop reason %q", out.Run.StopReason)
	}
	if out := f.preflight(t, run, "tw", http.StatusConflict); out.Code != codeDeployNotCurrent {
		t.Fatalf("next node started: %+v", out)
	}
	// Install again without a re-check: refused.
	f.call(t, http.MethodPost, "/api/deploy/runs/"+run+"/install", map[string]any{"node_id": "sg", "preflight_id": st.PreflightID}, http.StatusConflict)
	if n := f.scripts("sg"); n != 1 {
		t.Fatalf("scripts %d", n)
	}
	f.setScript("sg", nil)
	out = f.preflight(t, run, "sg", http.StatusOK)
	if st := f.step(t, "sg"); st.Phase != phaseReview || out.Run.State != runActive {
		t.Fatalf("after the re-check: %s %+v", out.Run.State, st)
	}
	f.install(t, run, "sg", http.StatusOK)
	if st := f.step(t, "sg"); st.Phase != phaseDone {
		t.Fatalf("retry: %+v", st)
	}
	// tw is next now; sg stays done.
	f.preflight(t, run, "tw", http.StatusOK)
}

// An unknown outcome stops the run; the re-check finds the content on the
// host and adopts it instead of installing again.
func TestDeployRunUnknownThenAdoptsHostRecord(t *testing.T) {
	f := newDeployFix(t, "sg", "tw")
	run := f.start(t)
	f.setScript("sg", func(string) (string, uint32) { return "garbled\n", 1 })
	f.preflight(t, run, "sg", http.StatusOK)
	bundle := f.step(t, "sg").ReviewBundle
	out := f.install(t, run, "sg", http.StatusOK)
	if st := f.step(t, "sg"); out.Run.State != runStopped || st.Phase != phaseUnknown {
		t.Fatalf("unknown: %s %+v", out.Run.State, st)
	}
	// What the host really did: the run completed.
	f.mu.Lock()
	f.extra["sg"] = "manifest-begin\nmanifest node sg\nmanifest deployment " + mustDeployment(t, f.s) + "\nmanifest server " + f.sid["sg"] +
		"\nmanifest bundle " + bundle + "\nmanifest-end\njournal-begin\njournal state done\njournal run run-x\njournal-end\n"
	f.mu.Unlock()
	f.preflight(t, run, "sg", http.StatusOK)
	st := f.step(t, "sg")
	if st.Phase != phaseDone || st.Outcome != "adopted" || st.Evidence != "host_record" || f.scripts("sg") != 1 {
		t.Fatalf("adopt: %+v scripts %d", st, f.scripts("sg"))
	}
	if ns := nodeState(t, f.s, "sg"); ns.State != nodeInSync {
		t.Fatalf("node state %+v", ns)
	}
	if g := f.get(t); g.Run.State != runActive || g.Run.Current != "tw" {
		t.Fatalf("run %s current %s", g.Run.State, g.Run.Current)
	}
}

// A topology save while a plan is open: the run is stale until re-planned;
// the re-plan keeps what is still valid and says what it dropped.
func TestDeployPlanInvalidatedByTopologyChange(t *testing.T) {
	f := newDeployFix(t, "sg", "tw")
	run := f.start(t)
	f.preflight(t, run, "sg", http.StatusOK)
	reviewedJP := f.step(t, "sg").PreflightID
	// Moving a node on the canvas is not a change.
	if _, err := f.s.Store.Update(func(tp *model.Topology) (bool, error) {
		tp.Nodes[3].X += 40
		return true, nil
	}); err != nil {
		t.Fatal(err)
	}
	if g := f.get(t); g.Run.Stale {
		t.Fatal("stale after a canvas move")
	}
	// A real change of tw's files.
	if _, err := f.s.Store.Update(func(tp *model.Topology) (bool, error) {
		for i := range tp.Nodes {
			if tp.Nodes[i].ID == "tw" {
				tp.Nodes[i].WANInterface = "ens9"
			}
		}
		return true, nil
	}); err != nil {
		t.Fatal(err)
	}
	g := f.get(t)
	if !g.Run.Stale || !strings.Contains(strings.Join(g.Run.Affected, ","), "tw") || strings.Contains(strings.Join(g.Run.Affected, ","), "sg") {
		t.Fatalf("stale %v affected %v", g.Run.Stale, g.Run.Affected)
	}
	if out := f.install(t, run, "sg", http.StatusConflict); out.Code != codeDeployPlanStale {
		t.Fatalf("%+v", out)
	}
	if f.scripts("sg") != 0 {
		t.Fatal("installed on a stale plan")
	}
	out := f.call(t, http.MethodPost, "/api/deploy/runs/"+run+"/replan", map[string]any{}, http.StatusOK)
	if out.Run.Stale || stepIDs(out) != "sg,tw,gw" {
		t.Fatalf("replan %v %s", out.Run.Stale, stepIDs(out))
	}
	// sg's content did not change: its reviewed preflight stays.
	if st := f.step(t, "sg"); st.PreflightID != reviewedJP || !st.CanInstall {
		t.Fatalf("sg after replan %+v", st)
	}
	f.install(t, run, "sg", http.StatusOK)
	// tw's review is made after the change; a later change of tw's content
	// invalidates that review with the reason, and the install is refused.
	f.preflight(t, run, "tw", http.StatusOK)
	if _, err := f.s.Store.Update(func(tp *model.Topology) (bool, error) {
		for i := range tp.Nodes {
			if tp.Nodes[i].ID == "tw" {
				tp.Nodes[i].WANInterface = "ens10"
			}
		}
		return true, nil
	}); err != nil {
		t.Fatal(err)
	}
	out = f.call(t, http.MethodPost, "/api/deploy/runs/"+run+"/replan", map[string]any{}, http.StatusOK)
	st := f.step(t, "tw")
	if st.Phase != phasePending || !strings.Contains(st.Invalidated, "内容变了") || st.PreflightID != "" {
		t.Fatalf("tw after replan %+v", st)
	}
	if f.scripts("tw") != 0 {
		t.Fatal("tw installed")
	}
	_ = out
}

// A server identity change between review and confirmation invalidates
// the confirmation (not the run) and says why.
func TestDeployConfirmationInvalidatedByIdentityChange(t *testing.T) {
	f := newDeployFix(t, "sg", "tw")
	run := f.start(t)
	f.preflight(t, run, "sg", http.StatusOK)
	rr := do(f.s, http.MethodPost, "/api/ssh-credentials", mustJSON(map[string]any{"name": "pw2", "kind": "password", "password": "pw-other-" + rnd(t, 4)}))
	var c struct{ Credential credView }
	decode(t, rr, &c)
	if rr := do(f.s, http.MethodPatch, "/api/servers/"+f.sid["sg"], mustJSON(map[string]any{"credential_id": c.Credential.ID})); rr.Code != 200 {
		t.Fatalf("patch: %d %s", rr.Code, rr.Body.String())
	}
	st := f.step(t, "sg")
	if st.CanInstall || st.ConfirmationValid || !strings.Contains(strings.Join(st.Changes, "|"), "服务器身份变了") {
		t.Fatalf("after identity change %+v", st)
	}
	out := f.install(t, run, "sg", http.StatusConflict)
	if out.Code != codeDeployInvalidated || !strings.Contains(out.Error, "服务器身份变了") {
		t.Fatalf("%+v", out)
	}
	if st := f.step(t, "sg"); st.Phase != phasePending || !strings.Contains(st.Invalidated, "服务器身份变了") || f.scripts("sg") != 0 {
		t.Fatalf("after refusal %+v", st)
	}
}

// One run at a time; one step at a time.
func TestDeployNoDoubleStart(t *testing.T) {
	f := newDeployFix(t, "sg")
	run := f.start(t)
	if out := f.call(t, http.MethodPost, "/api/deploy/runs", map[string]any{}, http.StatusConflict); out.Code != codeDeployRunActive {
		t.Fatalf("%+v", out)
	}
	// A step in flight in this process: every other action waits.
	f.s.deployMu.Lock()
	r := f.s.loadRunLocked()
	r.Steps[0].Phase, r.Steps[0].Boot = phaseInstalling, f.s.bootID()
	f.s.saveRunLocked(r)
	f.s.deployMu.Unlock()
	if out := f.preflight(t, run, "sg", http.StatusConflict); out.Code != codeDeployStepRunning {
		t.Fatalf("%+v", out)
	}
	if out := f.call(t, http.MethodPost, "/api/deploy/runs/"+run+"/cancel", map[string]any{}, http.StatusConflict); out.Code != codeDeployStepRunning {
		t.Fatalf("%+v", out)
	}
	if g := f.get(t); g.Run.Steps[0].Phase != phaseInstalling || !g.Run.Steps[0].InFlight {
		t.Fatalf("%+v", g.Run.Steps[0])
	}
	// A stale plan version from the operator's screen: refused.
	f.s.deployMu.Lock()
	r = f.s.loadRunLocked()
	r.Steps[0].Phase, r.Steps[0].Boot = phasePending, ""
	r.State = runCancelled
	f.s.saveRunLocked(r)
	f.s.deployMu.Unlock()
	if out := f.call(t, http.MethodPost, "/api/deploy/runs", map[string]any{"topology_version": "0000"}, http.StatusConflict); out.Code != codeDeployPlanStale {
		t.Fatalf("%+v", out)
	}
	f.start(t)
}

// A panel restart with a step in flight: the install is unknown (never
// done) and stops the run; an interrupted preflight goes back to pending.
func TestDeployRestartWithStepInFlight(t *testing.T) {
	f := newDeployFix(t, "sg", "tw")
	f.start(t)
	f.s.deployMu.Lock()
	r := f.s.loadRunLocked()
	r.Steps[0].Phase, r.Steps[0].Boot, r.Steps[0].PreflightID = phaseInstalling, "boot-old", "pf-old"
	f.s.saveRunLocked(r)
	f.s.deployMu.Unlock()

	// The restarted panel: same store, a new process.
	s2 := &Server{Store: f.s.Store, DataDir: f.s.DataDir, HostRoot: f.s.HostRoot, Artifacts: f.s.Artifacts, HostPreflight: f.hp, Activate: f.s.Activate}
	f2 := &deployFix{s: s2}
	g := f2.get(t)
	st := g.Run.Steps[0]
	if g.Run.State != runStopped || st.Phase != phaseUnknown || st.Outcome != "interrupted" || st.PreflightID != "" || st.InFlight {
		t.Fatalf("after restart: %s %+v", g.Run.State, st)
	}
	if !strings.Contains(g.Run.StopReason, "面板重启") {
		t.Fatalf("stop reason %q", g.Run.StopReason)
	}
	// Persisted: a second restart sees the same.
	s3 := &Server{Store: f.s.Store, DataDir: f.s.DataDir}
	s3.deployMu.Lock()
	if r := s3.loadRunLocked(); r.Steps[0].Phase != phaseUnknown {
		t.Fatalf("not persisted: %+v", r.Steps[0])
	}
	s3.deployMu.Unlock()

	// An interrupted preflight is read-only: back to pending.
	s2.deployMu.Lock()
	r = s2.loadRunLocked()
	r.Steps[0].Phase, r.Steps[0].Boot, r.State = phasePreflight, "boot-older", runActive
	s2.saveRunLocked(r)
	s2.deployMu.Unlock()
	if st := f2.get(t).Run.Steps[0]; st.Phase != phasePending || st.Outcome != "interrupted" {
		t.Fatalf("interrupted preflight %+v", st)
	}
}

// A server that refuses the panel's source address: the step waits for
// retry_after and the guide does not connect before it.
func TestDeployRespectsRetryAfter(t *testing.T) {
	f := newDeployFix(t, "sg")
	run := f.start(t)
	f.srv["sg"].RefuseBeforeBanner("Not allowed at this time")
	f.preflight(t, run, "sg", http.StatusOK)
	st := f.step(t, "sg")
	if st.Phase != phasePending || st.Code != sshexec.CodeRateLimited || st.RetryAt == nil || st.WaitSeconds <= 0 || st.CanPreflight || !st.NotExecuted {
		t.Fatalf("rate limited %+v", st)
	}
	accepted := f.srv["sg"].Accepted()
	out := f.preflight(t, run, "sg", http.StatusConflict)
	if out.Code != codeDeployWait || out.RetryAfter <= 0 {
		t.Fatalf("%+v", out)
	}
	if f.srv["sg"].Accepted() != accepted || f.srv["sg"].Logins() != 0 {
		t.Fatal("the guide connected during the wait")
	}
}

// The gateway step and the unattended unlock install never run at the same
// time: the guide refuses while the automatic install holds the gateway,
// and the automatic install defers while a run is open.
func TestDeployGatewayAndUnattendedInstall(t *testing.T) {
	f := newDeployFix(t)
	run := f.start(t)
	if g := f.get(t); stepIDs(g) != "gw" {
		t.Fatalf("steps %s", stepIDs(g))
	}
	// The automatic install holds the gateway.
	if !f.s.lockNode(localNodeID) {
		t.Fatal("lock")
	}
	f.s.autoInstalling.Store(true)
	f.preflight(t, run, "gw", http.StatusOK)
	st := f.step(t, "gw")
	if st.Phase != phasePending || !strings.Contains(st.Message, "无人值守的解锁自动安装") {
		t.Fatalf("busy: %+v", st)
	}
	f.s.autoInstalling.Store(false)
	f.s.unlockNode(localNodeID)

	// The other way round: an open run defers the automatic install.
	f.s.clock = func() time.Time { return time.Now() }
	if _, err := f.s.Store.Update(func(tp *model.Topology) (bool, error) {
		tp.Settings.UnlockProbe = &model.UnlockProbeSettings{AutoApply: true}
		return true, nil
	}); err != nil {
		t.Fatal(err)
	}
	f.s.mu.Lock()
	d := f.s.loadAuto()
	d.Recorded, d.Installed = true, map[string]string{"x": "y"}
	f.s.saveAuto(d)
	f.s.mu.Unlock()
	if c := f.s.maybeAutoApply("test"); c == nil || c.Code != AutoBusy || !strings.Contains(c.Message, "按顺序部署引导") {
		t.Fatalf("auto: %+v", c)
	}
	// The topology changed (settings): re-plan, then the gateway install;
	// the first activation fails and is compensated: stopped, then
	// recovered by a re-check and a confirmed retry.
	f.call(t, http.MethodPost, "/api/deploy/runs/"+run+"/replan", map[string]any{}, http.StatusOK)
	f.mu.Lock()
	f.failGW = true
	f.mu.Unlock()
	f.preflight(t, run, "gw", http.StatusOK)
	out := f.install(t, run, "gw", http.StatusOK)
	if st := f.step(t, "gw"); out.Run.State != runStopped || st.Phase != phaseFailed || st.Outcome != "compensated" {
		t.Fatalf("compensated: %s %+v", out.Run.State, st)
	}
	f.preflight(t, run, "gw", http.StatusOK)
	out = f.install(t, run, "gw", http.StatusOK)
	if st := f.step(t, "gw"); out.Run.State != runDone || st.Phase != phaseDone || st.Health == nil || st.Health.Source != "gateway_transaction" || !st.Health.Committed {
		t.Fatalf("retry: %s %+v", out.Run.State, st)
	}
	// Done: the automatic install is no longer deferred by the guide.
	if c := f.s.maybeAutoApply("test"); c != nil && strings.Contains(c.Message, "按顺序部署引导") {
		t.Fatalf("still deferred: %+v", c)
	}
}

// The status bar knows the open run.
func TestDeployRunInStatus(t *testing.T) {
	f := newDeployFix(t, "sg")
	status := func() *deployStatus {
		t.Helper()
		rr := do(f.s, http.MethodGet, "/api/status", nil)
		var out struct {
			DeployRun *deployStatus `json:"deploy_run"`
		}
		if rr.Code != 200 || json.Unmarshal(rr.Body.Bytes(), &out) != nil {
			t.Fatalf("%d %s", rr.Code, rr.Body.String())
		}
		return out.DeployRun
	}
	if st := status(); st != nil {
		t.Fatalf("%+v", st)
	}
	run := f.start(t)
	if st := status(); st == nil || st.ID != run || st.Current != "sg" || st.Total != 2 || st.State != runActive {
		t.Fatalf("%+v", st)
	}
	f.call(t, http.MethodPost, "/api/deploy/runs/"+run+"/cancel", map[string]any{}, http.StatusOK)
	if st := status(); st != nil {
		t.Fatalf("after cancel %+v", st)
	}
}
