package api

import (
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/radowitz/meridian/internal/model"
	"github.com/radowitz/meridian/internal/sshexec"
)

// Verify-only steps of the deployment guide (deploy_verify.go), on the
// local SSH stand-ins of the deployment tests. Nothing leaves the machine.

// unverified records nodes as installed with exactly their current content
// but without a read-back of the host's record: the guide plans a
// verify-only step for each.
func (f *deployFix) unverified(t *testing.T, nodes ...string) {
	t.Helper()
	l, err := f.s.liveDeploy()
	if err != nil {
		t.Fatal(err)
	}
	for _, node := range nodes {
		id := l.idents[node]
		bundle := l.bundles[node]
		f.s.updateOutcome(node, func(o *provisionOutcome) {
			*o = provisionOutcome{NodeID: node, ServerID: id.ServerID, Address: id.Address, Port: id.Port, Fingerprint: id.Fingerprint,
				User: id.User, CredentialID: id.CredentialID, Bundle: bundle, At: time.Now().UTC(), OK: true, Outcome: "installed", Run: "run-u",
				Installed: true, InstalledBundle: bundle, InstalledRun: "run-u",
				InstalledTarget: &targetIdentity{ServerID: id.ServerID, Address: id.Address, Port: id.Port, User: id.User, Fingerprint: id.Fingerprint, CredentialID: id.CredentialID}}
		})
	}
}

// hostHas makes node's host hold a record of bundle (server: its own).
func (f *deployFix) hostHas(t *testing.T, node, server, bundle string) {
	t.Helper()
	f.mu.Lock()
	f.extra[node] = "manifest-begin\nmanifest node " + node + "\nmanifest deployment " + mustDeployment(t, f.s) + "\nmanifest server " + server +
		"\nmanifest bundle " + bundle + "\nmanifest-end\njournal-begin\njournal state done\njournal run run-u\njournal-end\n"
	f.mu.Unlock()
}

type verifyResp struct {
	deployResp
	Verify []verifyOutcome `json:"verify"`
}

func (f *deployFix) verify(t *testing.T, run string, body map[string]any, want int) verifyResp {
	t.Helper()
	rr := do(f.s, http.MethodPost, "/api/deploy/runs/"+run+"/verify", mustJSON(body))
	var out verifyResp
	decode(t, rr, &out)
	if want != 0 && rr.Code != want {
		t.Fatalf("verify %v: %d (want %d) %s", body, rr.Code, want, rr.Body.String())
	}
	return out
}

func resultOf(out verifyResp, node string) verifyOutcome {
	for _, v := range out.Verify {
		if v.NodeID == node {
			return v
		}
	}
	return verifyOutcome{}
}

// The scheduling rule: verify-only steps are not in the install order,
// each can be verified while the install steps wait, a batch goes on past
// an unreachable server, does not contact a server in its rate-limit wait,
// and the install order and its per-node confirmation are unchanged.
func TestDeployVerifyOnlyOutsideOrder(t *testing.T) {
	f := newDeployFix(t, "sg", "tw", "us")
	f.unverified(t, "sg", "tw", "us")
	plan := f.get(t).Plan
	verify := map[string]bool{}
	for _, st := range plan.Steps {
		if st.VerifyOnly {
			verify[st.NodeID] = true
			if !strings.Contains(st.Reason, "只需核对") {
				t.Fatalf("%s reason %q", st.NodeID, st.Reason)
			}
		}
	}
	if len(verify) != 3 || plan.Steps[0].NodeID != "gw" || plan.Steps[0].VerifyOnly {
		t.Fatalf("plan %+v", plan.Steps)
	}
	run := f.start(t)
	if g := f.get(t); g.Run.Current != "gw" {
		t.Fatalf("current %q (a verify-only step must never be current)", g.Run.Current)
	}

	// tw alone, while the install step (gw) has not even been preflighted.
	l, _ := f.s.liveDeploy()
	f.hostHas(t, "tw", f.sid["tw"], l.bundles["tw"])
	out := f.verify(t, run, map[string]any{"node_id": "tw"}, http.StatusOK)
	st := f.step(t, "tw")
	if r := resultOf(out, "tw"); r.Result != verifyResVerified || st.Phase != phaseDone || st.Completion != completionAdopted || st.VerifyState != "verified" {
		t.Fatalf("tw: %+v %+v", r, st)
	}
	if st.Verified == nil || st.Verified.Plan != f.get(t).TopologyVersion || st.Verified.Bundle != l.bundles["tw"] ||
		st.Verified.ServerID != f.sid["tw"] || st.Verified.Fingerprint != f.srv["tw"].Fingerprint() || st.Verified.NodeID != "tw" {
		t.Fatalf("binding %+v", st.Verified)
	}
	if f.srv["tw"].Logins() != 1 || f.scripts("tw") != 0 {
		t.Fatalf("tw: %d logins, %d scripts", f.srv["tw"].Logins(), f.scripts("tw"))
	}

	// sg cannot be reached; us refuses the panel's address (rate limit).
	f.srv["sg"].Close()
	f.srv["us"].RefuseBeforeBanner("Not allowed at this time")
	f.hostHas(t, "us", f.sid["us"], l.bundles["us"])
	out = f.verify(t, run, map[string]any{"all": true}, http.StatusOK)
	if len(out.Verify) != 2 {
		t.Fatalf("batch %+v", out.Verify)
	}
	if r := resultOf(out, "sg"); r.Result != verifyResUnreachable || r.Code != sshexec.CodeUnreachable || r.Message == "" {
		t.Fatalf("sg %+v", r)
	}
	if r := resultOf(out, "us"); r.Result != verifyResWaiting || r.WaitSeconds <= 0 {
		t.Fatalf("us %+v", r)
	}
	sg, us := f.step(t, "sg"), f.step(t, "us")
	if sg.VerifyState != "unreachable" || sg.Phase != phasePending || !sg.NotExecuted || us.VerifyState != "waiting" || us.CanVerify || us.WaitSeconds <= 0 {
		t.Fatalf("after batch: sg %+v us %+v", sg, us)
	}
	if g := f.get(t); g.Run.State != runActive || g.Run.Current != "gw" {
		t.Fatalf("an unreachable verify stopped the run: %s %s", g.Run.State, g.Run.Current)
	}
	// The second batch does not contact us during its wait (shown as
	// waiting) and does not retry anything by itself beyond one attempt.
	accepted := f.srv["us"].Accepted()
	out = f.verify(t, run, map[string]any{"all": true}, http.StatusOK)
	if r := resultOf(out, "us"); r.Result != verifyResWaiting || f.srv["us"].Accepted() != accepted {
		t.Fatalf("us contacted during its wait: %+v", r)
	}
	// A single verify during the wait is refused with the wait.
	if out := f.verify(t, run, map[string]any{"node_id": "us"}, http.StatusConflict); out.Code != codeDeployWait || out.RetryAfter <= 0 {
		t.Fatalf("%+v", out)
	}
	// The preflight endpoint on a verify-only step is its verify.
	if out := f.preflight(t, run, "us", http.StatusConflict); out.Code != codeDeployWait {
		t.Fatalf("%+v", out)
	}

	// The install order is unchanged: gw is the only step that can be
	// preflighted and installed, with its own confirmation.
	f.preflight(t, run, "gw", http.StatusOK)
	if g := f.step(t, "gw"); !g.CanInstall {
		t.Fatalf("gw %+v", g)
	}
	f.install(t, run, "gw", http.StatusOK)
	if g := f.get(t); g.Run.State == runDone {
		t.Fatal("done with verify steps outstanding")
	}
	// Once us's wait is over and sg answers again, the run completes.
	f.s.deployMu.Lock()
	r := f.s.loadRunLocked()
	for i := range r.Steps {
		r.Steps[i].RetryAt = nil
	}
	f.s.saveRunLocked(r)
	f.s.deployMu.Unlock()
	f.s.sshPoolMu.Lock()
	f.s.SSHPool = nil
	f.s.sshPoolMu.Unlock()
	f.srv["us"].RefuseBeforeBanner("")
	f.verify(t, run, map[string]any{"node_id": "us"}, http.StatusOK)
	f.mu.Lock()
	delete(f.extra, "sg")
	f.mu.Unlock()
	if out := f.verify(t, run, map[string]any{"node_id": "sg"}, http.StatusOK); resultOf(out, "sg").Result != verifyResUnreachable {
		t.Fatalf("%+v", out.Verify)
	}
	g := f.get(t)
	if g.Run.State != runActive {
		t.Fatalf("run %s", g.Run.State)
	}
	if f.scripts("sg")+f.scripts("tw")+f.scripts("us") != 0 {
		t.Fatal("a verify installed something")
	}
}

// A host whose record differs: never adopted; the step becomes an install
// step in the dependency order (before the gateway) and needs the
// operator's confirmation like any other.
func TestDeployVerifyDiffersBecomesInstall(t *testing.T) {
	f := newDeployFix(t, "sg")
	f.unverified(t, "sg")
	run := f.start(t)
	f.hostHas(t, "sg", f.sid["sg"], "0000000000000000")
	out := f.verify(t, run, map[string]any{"node_id": "sg"}, http.StatusOK)
	st := f.step(t, "sg")
	if r := resultOf(out, "sg"); r.Result != verifyResDiffers {
		t.Fatalf("%+v", r)
	}
	if st.VerifyOnly || st.VerifyState != "differs" || st.Phase != phaseReview || st.Completion != "" || !strings.Contains(st.VerifyDiff, "内容摘要") {
		t.Fatalf("sg %+v", st)
	}
	if ns := nodeState(t, f.s, "sg"); ns.Verify == nil || ns.Verify.State == verifyOK {
		t.Fatalf("adopted: %+v", ns.Verify)
	}
	g := f.get(t)
	if stepIDs(g) != "sg,gw" || g.Run.Current != "sg" {
		t.Fatalf("order %s current %s", stepIDs(g), g.Run.Current)
	}
	// The gateway waits for sg; sg installs only after its confirmation.
	if out := f.preflight(t, run, "gw", http.StatusConflict); out.Code != codeDeployNotCurrent {
		t.Fatalf("%+v", out)
	}
	if f.scripts("sg") != 0 {
		t.Fatal("installed without confirmation")
	}
	f.install(t, run, "sg", http.StatusOK)
	if st := f.step(t, "sg"); st.Phase != phaseDone || st.Completion != completionInstalled || f.scripts("sg") != 1 {
		t.Fatalf("after install %+v", st)
	}
	// A re-plan keeps it an install step (the mismatch is recorded).
	plan := f.get(t).Plan
	for _, ps := range plan.Steps {
		if ps.NodeID == "sg" && ps.VerifyOnly {
			t.Fatalf("sg verify-only again: %+v", ps)
		}
	}
}

// A verify result is bound to the plan, the node, the server and its
// pinned host key: a stale plan, a changed server identity or a record of
// another server is never taken as verification, and nothing is contacted
// for a refusal.
func TestDeployVerifyBinding(t *testing.T) {
	t.Run("stale plan", func(t *testing.T) {
		f := newDeployFix(t, "sg")
		f.unverified(t, "sg")
		run := f.start(t)
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
		out := f.verify(t, run, map[string]any{"node_id": "sg"}, http.StatusConflict)
		if out.Code != codeDeployPlanStale || f.srv["sg"].Accepted() != 0 {
			t.Fatalf("%+v (accepted %d)", out, f.srv["sg"].Accepted())
		}
		// The batch records the refusal and connects to nothing.
		bo := f.verify(t, run, map[string]any{"all": true}, http.StatusOK)
		if r := resultOf(bo, "sg"); r.Result != verifyResRefused || f.srv["sg"].Accepted() != 0 {
			t.Fatalf("%+v", r)
		}
	})
	t.Run("host key other than planned", func(t *testing.T) {
		// The plan was computed for another pinned key of the server (the
		// server's identity cannot be edited while its node is installed;
		// the stored plan stands in for one made before a re-pin).
		f := newDeployFix(t, "sg")
		f.unverified(t, "sg")
		run := f.start(t)
		f.s.deployMu.Lock()
		r := f.s.loadRunLocked()
		for i := range r.Steps {
			if r.Steps[i].NodeID == "sg" {
				pt := *r.Steps[i].PlanTarget
				pt.Fingerprint = "SHA256:another-host-key"
				r.Steps[i].PlanTarget = &pt
			}
		}
		f.s.saveRunLocked(r)
		f.s.deployMu.Unlock()
		l, _ := f.s.liveDeploy()
		f.hostHas(t, "sg", f.sid["sg"], l.bundles["sg"])
		out := f.verify(t, run, map[string]any{"node_id": "sg"}, http.StatusConflict)
		if out.Code != codeDeployPlanStale || f.srv["sg"].Accepted() != 0 {
			t.Fatalf("%+v (accepted %d)", out, f.srv["sg"].Accepted())
		}
		if st := f.step(t, "sg"); st.Phase == phaseDone || st.Verified != nil || len(st.Changes) == 0 {
			t.Fatalf("%+v", st)
		}
	})
	t.Run("record of another server", func(t *testing.T) {
		f := newDeployFix(t, "sg")
		f.unverified(t, "sg")
		run := f.start(t)
		l, _ := f.s.liveDeploy()
		f.hostHas(t, "sg", "srv-somewhere-else", l.bundles["sg"])
		out := f.verify(t, run, map[string]any{"node_id": "sg"}, http.StatusOK)
		if r := resultOf(out, "sg"); r.Result != verifyResDiffers {
			t.Fatalf("%+v", r)
		}
		if st := f.step(t, "sg"); st.Phase == phaseDone || st.Verified != nil || !strings.Contains(st.VerifyDiff, "srv-somewhere-else") {
			t.Fatalf("%+v", st)
		}
	})
	t.Run("an install step is not verified", func(t *testing.T) {
		f := newDeployFix(t, "sg")
		run := f.start(t)
		if out := f.verify(t, run, map[string]any{"node_id": "sg"}, http.StatusConflict); out.Code != codeDeployNotVerify {
			t.Fatalf("%+v", out)
		}
		if out := f.verify(t, run, map[string]any{"node_id": "sg", "all": true}, http.StatusBadRequest); out.Code == "" {
			t.Fatalf("%+v", out)
		}
	})
}

// Only verify steps: the run completes when every one is verified; the
// summary names them as adopted (not installed, health not re-checked).
func TestDeployVerifyCompletesRun(t *testing.T) {
	f := newDeployFix(t, "sg", "tw")
	f.unverified(t, "sg", "tw")
	// The gateway is already in sync: only the verify steps remain.
	f.preflightGatewayInstalled(t)
	l, _ := f.s.liveDeploy()
	f.hostHas(t, "sg", f.sid["sg"], l.bundles["sg"])
	f.hostHas(t, "tw", f.sid["tw"], l.bundles["tw"])
	run := f.start(t)
	if g := f.get(t); g.Run.Current != "" || stepIDs(g) != "sg,tw" {
		t.Fatalf("current %q steps %s", g.Run.Current, stepIDs(g))
	}
	out := f.verify(t, run, map[string]any{"all": true}, http.StatusOK)
	if out.Run.State != runDone || out.Run.Summary == nil || len(out.Run.Summary.Adopted) != 2 || out.Run.Summary.AllChecked {
		t.Fatalf("%s %+v", out.Run.State, out.Run.Summary)
	}
	if f.srv["sg"].Logins() != 1 || f.srv["tw"].Logins() != 1 {
		t.Fatalf("logins sg %d tw %d", f.srv["sg"].Logins(), f.srv["tw"].Logins())
	}
}

// preflightGatewayInstalled installs the gateway (outside the guide).
func (f *deployFix) preflightGatewayInstalled(t *testing.T) {
	t.Helper()
	var pf struct {
		Preflight struct {
			ID string `json:"id"`
		} `json:"preflight"`
	}
	decode(t, do(f.s, http.MethodPost, "/api/host/preflight", mustJSON(map[string]any{})), &pf)
	if rr := do(f.s, http.MethodPost, "/api/apply", mustJSON(map[string]any{"install": true, "preflight_id": pf.Preflight.ID})); rr.Code != http.StatusOK {
		t.Fatalf("apply: %d %s", rr.Code, rr.Body.String())
	}
}
