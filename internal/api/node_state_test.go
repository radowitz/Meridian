package api

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/radowitz/meridian/internal/model"
	"github.com/radowitz/meridian/internal/sshexec"
	"github.com/radowitz/meridian/internal/sshexec/sshtest"
)

// The remote install, its compensation and the per-node state, over the
// local SSH stand-in with a synthetic host record (journal and manifest
// header). No remote host is contacted.

func (f *gateFix) runProvision(t *testing.T, answer string, code uint32) (int, map[string]any) {
	t.Helper()
	f.mu.Lock()
	f.script = func(string) (string, uint32) { return answer, code }
	f.mu.Unlock()
	rec := f.preflight(t)
	rr := f.provision(rec.ID)
	var body map[string]any
	_ = json.Unmarshal(rr.Body.Bytes(), &body)
	return rr.Code, body
}

func nodeState(t *testing.T, s *Server, node string) nodeInstallState {
	t.Helper()
	for _, n := range getStatusFull(t, s).Nodes {
		if n.NodeID == node {
			return n
		}
	}
	t.Fatalf("node %s not in status", node)
	return nodeInstallState{}
}

// The script failed and the host compensated, but the compensation marker
// did not reach the panel: the host's journal for this run, read on the
// same login right after the script, says "compensated", and so does the
// panel (not "unknown").
func TestCompensationWithoutMarkerReadFromJournal(t *testing.T) {
	f := newGateFix(t)
	f.hostRecord = func(stdin, _ string, _ uint32) string {
		// What the host really did: compensated this very run.
		return defaultHostRecord(stdin, "MERIDIAN_COMPENSATED", "")
	}
	status, body := f.runProvision(t, "meridian: wg-quick failed\nRTNETLINK answers: File exists\n", 1)
	if status != http.StatusBadGateway || body["outcome"] != "compensated" || body["code"] != codeProvisionCompensated || body["evidence"] != "host_journal" {
		t.Fatalf("%d %v", status, body)
	}
	if !strings.Contains(body["error"].(string), "journal") {
		t.Fatalf("message %v", body["error"])
	}
	if st := f.s.loadOutcomes()["tw"]; st.Outcome != "compensated" || st.Evidence != "host_journal" || st.Installed {
		t.Fatalf("record %+v", st)
	}
	// The journal of another run (an older one) is not evidence: unknown.
	f.hostRecord = func(stdin, _ string, _ uint32) string {
		return strings.ReplaceAll(defaultHostRecord(stdin, "MERIDIAN_COMPENSATED", ""), "journal run run-", "journal run old-")
	}
	if _, body := f.runProvision(t, "garbled\n", 1); body["outcome"] != "unknown" {
		t.Fatalf("other run: %v", body)
	}
	// Incomplete compensation in the journal: left behind, with the leftovers.
	f.hostRecord = func(stdin, _ string, _ uint32) string {
		return defaultHostRecord(stdin, "MERIDIAN_COMPENSATION_INCOMPLETE", "") + "journal leftover interface m14\n"
	}
	if _, body := f.runProvision(t, "", 1); body["outcome"] != "left_behind" || body["code"] != codeProvisionLeftovers {
		t.Fatalf("incomplete: %v", body)
	}
}

// Per node: installing one remote node does not make any other node, nor
// the gateway, look pending; a change of that node's own files does. The
// install is verified against the host's record on the same login.
func TestPerNodeInstallState(t *testing.T) {
	f := newGateFix(t)
	s := f.s
	before := getStatusFull(t, s)
	gwBefore := before.Install.State
	if st := nodeState(t, s, "tw"); st.State != nodeNotInstalled || !st.Pending {
		t.Fatalf("before %+v", st)
	}
	status, body := f.runProvision(t, "MERIDIAN_PROVISION_OK\n", 0)
	if status != 200 || body["outcome"] != "installed" {
		t.Fatalf("%d %v", status, body)
	}
	if v, _ := body["verify"].(map[string]any); v["state"] != verifyOK || v["source"] != "post_install" {
		t.Fatalf("verify %v", body["verify"])
	}
	tw := nodeState(t, s, "tw")
	if tw.State != nodeInSync || tw.Pending || tw.InstalledBundle == "" || tw.InstalledBundle != tw.CurrentBundle ||
		tw.InstalledTarget == nil || tw.InstalledTarget.ServerID != f.id || tw.Verify == nil || tw.Verify.State != verifyOK {
		t.Fatalf("tw %+v", tw)
	}
	after := getStatusFull(t, s)
	if after.Install.State != gwBefore {
		t.Fatalf("the gateway's state moved from %s to %s because a remote node was installed", gwBefore, after.Install.State)
	}
	for _, n := range after.Nodes {
		if n.NodeID != "tw" && n.State == nodeInSync {
			t.Fatalf("node %s became in sync by installing tw: %+v", n.NodeID, n)
		}
	}
	// A change to another node's files only: tw stays in sync.
	if _, err := s.Store.Update(func(tp *model.Topology) (bool, error) {
		for i := range tp.Nodes {
			if tp.Nodes[i].ID == "us" {
				tp.Nodes[i].WANInterface = "ens9"
			}
		}
		return true, nil
	}); err != nil {
		t.Fatal(err)
	}
	if st := nodeState(t, s, "tw"); st.State != nodeInSync {
		t.Fatalf("tw after a change of us: %+v", st)
	}
	// A failed, compensated attempt leaves the previous install recorded.
	prev := s.loadOutcomes()["tw"].InstalledBundle
	if _, body := f.runProvision(t, "MERIDIAN_COMPENSATING exit=1\nMERIDIAN_COMPENSATED\n", 1); body["outcome"] != "compensated" {
		t.Fatalf("%v", body)
	}
	if o := s.loadOutcomes()["tw"]; !o.Installed || o.InstalledBundle != prev {
		t.Fatalf("installed record lost by a failed attempt: %+v", o)
	}
	if st := nodeState(t, s, "tw"); st.State != nodeInSync || st.LastOutcome != "compensated" {
		t.Fatalf("tw after a compensated update: %+v", st)
	}
	// A change of tw's own files: pending for tw.
	if _, err := s.Store.Update(func(tp *model.Topology) (bool, error) {
		for i := range tp.Nodes {
			if tp.Nodes[i].ID == "tw" {
				tp.Nodes[i].WANInterface = "ens10"
			}
		}
		return true, nil
	}); err != nil {
		t.Fatal(err)
	}
	if st := nodeState(t, s, "tw"); st.State != nodeChanged || !st.Pending {
		t.Fatalf("tw after its own change: %+v", st)
	}
	// The provision state endpoint carries the same rows.
	rr := do(s, http.MethodGet, "/api/provision/state", nil)
	if !strings.Contains(rr.Body.String(), `"states":[`) || !strings.Contains(rr.Body.String(), `"installed_bundle":"`+prev+`"`) {
		t.Fatalf("provision state %s", rr.Body.String())
	}
}

// A record written before per-node state: migrated from its own successful
// outcome, or (when the last attempt failed) filled from the host's
// manifest by the next preflight. Idempotent.
func TestNodeStateMigration(t *testing.T) {
	f := newGateFix(t)
	s := f.s
	if _, body := f.runProvision(t, "MERIDIAN_PROVISION_OK\n", 0); body["outcome"] != "installed" {
		t.Fatalf("%v", body)
	}
	o := s.loadOutcomes()["tw"]
	bundle := o.InstalledBundle
	// Strip the new fields: an old record whose last outcome was success.
	o.InstalledBundle, o.InstalledAt, o.InstalledRun, o.InstalledTarget, o.Verify = "", nil, "", nil, nil
	s.putOutcomesLocked(t, o)
	if st := nodeState(t, s, "tw"); st.State != nodeInSync || st.InstalledBundle != bundle {
		t.Fatalf("migrated from the outcome: %+v", st)
	}
	// An old record whose last attempt failed after an install: unknown
	// until a preflight reads the host's manifest.
	o.OK, o.Outcome, o.Code = false, "compensated", codeProvisionCompensated
	s.putOutcomesLocked(t, o)
	if st := nodeState(t, s, "tw"); st.State != nodeUnknown || !strings.Contains(st.Reason, "预检") {
		t.Fatalf("before the preflight: %+v", st)
	}
	f.setExtra("manifest-begin\nmanifest node tw\nmanifest deployment " + mustDeployment(t, s) + "\nmanifest server " + f.id + "\nmanifest bundle " + bundle + "\nmanifest-end\n")
	f.preflight(t)
	st := nodeState(t, s, "tw")
	if st.State != nodeInSync || st.InstalledBundle != bundle || st.Verify == nil || st.Verify.Source != "preflight" || st.Verify.State != verifyOK {
		t.Fatalf("after the preflight: %+v", st)
	}
	f.preflight(t) // again: same result
	if st2 := nodeState(t, s, "tw"); st2.InstalledBundle != bundle || st2.State != nodeInSync {
		t.Fatalf("second preflight: %+v", st2)
	}
}

func mustDeployment(t *testing.T, s *Server) string {
	t.Helper()
	d, err := s.deploymentID()
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func (s *Server) putOutcomesLocked(t *testing.T, o provisionOutcome) {
	t.Helper()
	s.provMu.Lock()
	defer s.provMu.Unlock()
	raw := map[string]provisionOutcome{}
	if v, ok, _ := s.Store.Get(provisionStateKey); ok {
		_ = json.Unmarshal([]byte(v), &raw)
	}
	raw[o.NodeID] = o
	b, _ := json.Marshal(raw)
	if err := s.Store.Put(provisionStateKey, string(b)); err != nil {
		t.Fatal(err)
	}
}

// The node's server is managed through a jump over the relay node's
// server: preflight and install run over it (one relay connection), with
// both hops' own pinned keys; a jump through a server that is not a
// managed relay is refused before anything is dialed, and there is no
// fallback to the direct path.
func TestProvisionOverJumpChannel(t *testing.T) {
	f := newGateFix(t)
	s := f.s
	relay := startSSH(t)
	relayPw := "relay-" + rnd(t, 6)
	relay.SetPassword(relayPw)
	relay.AllowForwarding(true)
	rr := do(s, http.MethodPost, "/api/ssh-credentials", mustJSON(map[string]any{"name": "relay", "kind": "password", "password": relayPw}))
	var c struct{ Credential credView }
	decode(t, rr, &c)
	rr = do(s, http.MethodPost, "/api/servers", mustJSON(map[string]any{"name": "中继", "address": relay.Host, "port": relay.Port, "user": "root", "auth": "password", "credential_id": c.Credential.ID}))
	var rsv struct{ Server serverView }
	decode(t, rr, &rsv)
	do(s, http.MethodPost, "/api/servers/"+rsv.Server.ID+"/host-key/discover", nil)
	if rr := do(s, http.MethodPost, "/api/servers/"+rsv.Server.ID+"/host-key/trust", mustJSON(map[string]string{"fingerprint": relay.Fingerprint()})); rr.Code != 200 {
		t.Fatal(rr.Body.String())
	}
	// The tw server is reached through the relay.
	if rr := do(s, http.MethodPatch, "/api/servers/"+f.id, mustJSON(map[string]any{"channel": map[string]any{"mode": "jump", "via_server_id": rsv.Server.ID}})); rr.Code != 200 {
		t.Fatalf("patch: %s", rr.Body.String())
	}
	// Not yet a managed relay's server: refused, nothing dialed on either.
	acc, racc := f.srv.Accepted(), relay.Accepted()
	rr = do(s, http.MethodPost, "/api/provision/preflight", mustJSON(map[string]any{"node_id": "tw"}))
	if rr.Code == 200 || codeOf(t, rr.Body.Bytes()) != sshexec.CodeChannelNotAllowed || !strings.Contains(rr.Body.String(), `"not_executed":true`) {
		t.Fatalf("policy: %d %s", rr.Code, rr.Body.String())
	}
	if f.srv.Accepted() != acc || relay.Accepted() != racc {
		t.Fatal("dialed although the jump is not allowed (or fell back to the direct path)")
	}
	// The relay node of the topology runs on it: allowed.
	topo, _, _ := s.Store.Load()
	for i := range topo.Nodes {
		if topo.Nodes[i].ID == "ali" {
			topo.Nodes[i].ServerID, topo.Nodes[i].SSHHost, topo.Nodes[i].SSHPort, topo.Nodes[i].SSHUser = rsv.Server.ID, "", 0, ""
		}
	}
	if err := s.Store.Save(topo); err != nil {
		t.Fatal(err)
	}
	s.sshPool().CloseAll()
	direct := f.srv.Accepted()
	status, body := f.runProvision(t, "MERIDIAN_PROVISION_OK\n", 0)
	if status != 200 || body["outcome"] != "installed" || body["channel"] != model.ChannelJump {
		t.Fatalf("%d %v", status, body)
	}
	if len(relay.Commands()) != 0 {
		t.Fatalf("the relay ran %v", relay.Commands())
	}
	if relay.Accepted()-racc != 1 || len(relay.Forwards()) != 1 {
		t.Fatalf("relay connections %d forwards %v (one flow, one connection)", relay.Accepted()-racc, relay.Forwards())
	}
	if f.srv.Accepted()-direct != 1 || f.srv.Logins() == 0 {
		t.Fatalf("target connections %d", f.srv.Accepted()-direct)
	}
	for _, r := range append(relay.Requests(), f.srv.Requests()...) {
		if strings.Contains(r, "agent") {
			t.Fatalf("agent forwarding requested: %s", r)
		}
	}
	// The relay's key changes: refused on the relay hop, nothing reaches tw.
	s.sshPool().CloseAll()
	relay.SetHostKey(sshtest.NewHostKey())
	scripts := f.provisionScripts()
	rr = do(s, http.MethodPost, "/api/provision/preflight", mustJSON(map[string]any{"node_id": "tw"}))
	if codeOf(t, rr.Body.Bytes()) != sshexec.CodeMismatch || !strings.Contains(rr.Body.String(), `"hop":"relay"`) || f.provisionScripts() != scripts {
		t.Fatalf("relay key change: %d %s", rr.Code, rr.Body.String())
	}
}
