package api

import (
	"bytes"
	"encoding/json"
	"log"
	"net/http"
	"os"
	"strings"
	"testing"

	"github.com/radowitz/meridian/internal/compile"
	"github.com/radowitz/meridian/internal/preflight"
	"github.com/radowitz/meridian/internal/provision"
)

// The version line: written only into a config that names a DNS account
// credential with a known version, read back the same, never a value.
func TestDNSAccountVersionStamp(t *testing.T) {
	id := "dnsacct-0123456789ab"
	body := "bind :53\n" + compile.ExitDNSRestrictedMarker + "\nserver-tls 192.0.2.53:853 -host-name __MERIDIAN_SECRET_" + id + "__.dns.example.net\n"
	got := stampDNSAccountVersions(body, map[string]int{id: 3})
	if !strings.Contains(got, compile.ExitDNSRestrictedMarker+"\n"+dnsAccountVersionMarker+"3 ") || strings.Count(got, "__MERIDIAN_SECRET_") != 1 {
		t.Fatalf("stamped:\n%s", got)
	}
	if v := dnsAccountVersionsIn(got); len(v) != 1 || v[id] != 3 {
		t.Fatalf("read back %v", v)
	}
	if v := dnsAccountVersionsIn(body); v != nil {
		t.Fatalf("unstamped read back %v", v)
	}
	// No credential, an unknown one, or no marker: unchanged.
	plain := "bind :53\nserver 1.1.1.1\n"
	for _, c := range []struct {
		body string
		vers map[string]int
	}{{plain, map[string]int{id: 1}}, {body, map[string]int{}}, {strings.Replace(body, compile.ExitDNSRestrictedMarker+"\n", "", 1), map[string]int{id: 1}}} {
		if got := stampDNSAccountVersions(c.body, c.vers); got != c.body {
			t.Fatalf("changed:\n%s", got)
		}
	}
	// The secret placeholders of other kinds are not DNS accounts.
	if ids := dnsAccountIDsIn("x __MERIDIAN_SECRET_socks-0123456789ab-user__ y"); len(ids) != 0 {
		t.Fatalf("%v", ids)
	}
}

// dnsConfigOf is the 解析配置 view's row of node.
func dnsConfigOf(t *testing.T, s *Server, node string) dnsConfigState {
	t.Helper()
	var v struct {
		Configs []dnsConfigState `json:"configs"`
	}
	rr := do(s, http.MethodGet, "/api/dns", nil)
	if rr.Code != 200 {
		t.Fatalf("dns view %d %s", rr.Code, rr.Body.String())
	}
	decode(t, rr, &v)
	for _, c := range v.Configs {
		if c.Node == node {
			return c
		}
	}
	t.Fatalf("no config row for %s", node)
	return dnsConfigState{}
}

func bundlesOf(t *testing.T, s *Server) map[string]string {
	t.Helper()
	out := map[string]string{}
	for _, n := range getStatusFull(t, s).Nodes {
		out[n.NodeID] = n.CurrentBundle
	}
	return out
}

// Rotating a DNS account identifier: every exit that uses it (global
// setting, no builtin override) is "changed" with the rotation as reason
// and an install step of the deployment plan; nodes that do not use it
// keep their bundle; a preflight reviewed before the rotation is refused;
// a new preflight and install bring the exit back in sync with the new
// version recorded, and the 解析配置 view follows. Neither the old nor the
// new value is anywhere but the install script.
func TestDNSAccountRotationMarksExitsPending(t *testing.T) {
	var logs bytes.Buffer
	log.SetOutput(&logs)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })
	f := newGateFix(t)
	s := f.s
	oldV, newV := "acct"+rnd(t, 5), "acct"+rnd(t, 5)
	secrets := []string{oldV, newV}
	rr := do(s, http.MethodPost, "/api/dns-accounts", mustJSON(map[string]any{"name": "示例服务", "account": oldV}))
	var c struct {
		Account dnsAccountView `json:"account"`
	}
	decode(t, rr, &c)
	id := c.Account.ID
	if c.Account.Version != 1 {
		t.Fatalf("created %+v", c.Account)
	}
	up := dotUpstream(id)
	up["exits"] = map[string]any{"hk-2": map[string]any{"protocol": "builtin"}}
	if rr := do(s, http.MethodPut, "/api/dns/upstream", mustJSON(up)); rr.Code != 200 {
		t.Fatalf("save: %d %s", rr.Code, rr.Body.String())
	}

	rr = f.provision(f.preflight(t).ID)
	if rr.Code != 200 {
		t.Fatalf("provision: %d %s", rr.Code, rr.Body.String())
	}
	if !strings.Contains(lastScript(f.srv.Stdins()), "-host-name "+oldV+".dns.example.net") {
		t.Fatal("the first install did not inject the value")
	}
	st := nodeState(t, s, "tw")
	if st.State != nodeInSync || st.InstalledDNSAccountVersions[id] != 1 || st.DNSAccountVersions[id] != 1 {
		t.Fatalf("after install %+v", st)
	}
	if c := dnsConfigOf(t, s, "tw"); c.Installed != "same" || c.AccountVersion != 1 || c.InstalledAccountVersion != 1 {
		t.Fatalf("dns view after install %+v", c)
	}
	before := bundlesOf(t, s)
	reviewed := f.preflight(t) // reviewed before the rotation

	// Rotate.
	rr = do(s, http.MethodPut, "/api/dns-accounts/"+id+"/secret", mustJSON(map[string]any{"account": newV}))
	if rr.Code != 200 {
		t.Fatalf("rotate %d %s", rr.Code, rr.Body.String())
	}
	noSecretIn(t, "rotate", rr.Body.String(), secrets...)
	var rot struct {
		Account dnsAccountView `json:"account"`
		Pending []string       `json:"pending"`
		Note    string         `json:"note"`
	}
	decode(t, rr, &rot)
	if rot.Account.Version != 2 || !containsString(rot.Pending, "tw") || containsString(rot.Pending, "hk-2") || !strings.Contains(rot.Note, "tw") {
		t.Fatalf("rotate answer %+v", rot)
	}

	// State: the referencing exits changed, everything else as before.
	st = nodeState(t, s, "tw")
	if st.State != nodeChanged || !st.Pending || !strings.Contains(st.Reason, "已轮换") || st.DNSAccountVersions[id] != 2 || st.InstalledDNSAccountVersions[id] != 1 {
		t.Fatalf("after rotation %+v", st)
	}
	topo, _, _ := s.Store.Load()
	after := bundlesOf(t, s)
	for _, n := range topo.Nodes {
		if !n.Managed || n.Role == "gateway" {
			continue
		}
		uses := len(exitDNSCredentials(topo, n.ID)) > 0
		if changed := before[n.ID] != after[n.ID]; changed != uses {
			t.Fatalf("node %s uses the credential: %v, bundle changed: %v", n.ID, uses, changed)
		}
	}
	if before["hk-2"] != after["hk-2"] || before["access"] != after["access"] {
		t.Fatal("a node that does not use the credential changed")
	}

	// The deployment plan installs it (not verify-only, not adopted).
	var dv struct {
		Plan *deployPlan `json:"plan"`
	}
	decode(t, do(s, http.MethodGet, "/api/deploy", nil), &dv)
	found := false
	for _, step := range dv.Plan.Steps {
		if step.NodeID == "tw" {
			found = true
			if step.VerifyOnly || step.PlanState != nodeChanged || step.PlanBundle != after["tw"] {
				t.Fatalf("plan step %+v", step)
			}
		}
	}
	if !found {
		t.Fatalf("tw is not in the plan: %+v", dv.Plan)
	}

	// The 解析配置 view: planned 2, installed 1.
	if c := dnsConfigOf(t, s, "tw"); c.Installed != "differs" || c.AccountVersion != 2 || c.InstalledAccountVersion != 1 || !strings.Contains(c.Detail, "已轮换") {
		t.Fatalf("dns view after rotation %+v", c)
	}

	// The preflight reviewed before the rotation no longer counts.
	n := f.provisionScripts()
	rr = f.provision(reviewed.ID)
	if rr.Code != http.StatusConflict || !strings.Contains(rr.Body.String(), codeBundleChanged) || f.provisionScripts() != n {
		t.Fatalf("stale preflight: %d %s", rr.Code, rr.Body.String())
	}

	// A new preflight shows the version; the install injects the new value.
	pf := f.preflight(t)
	if pf.DNSAccounts[id] != 2 {
		t.Fatalf("preflight versions %v", pf.DNSAccounts)
	}
	ok := false
	for _, ch := range pf.Evaluation.Changes {
		ok = ok || ch.Resource == "/etc/smartdns/smartdns.conf" && strings.Contains(ch.Detail, id+" 版本 2")
	}
	if !ok {
		t.Fatalf("preflight changes %+v", pf.Evaluation.Changes)
	}
	rr = f.provision(pf.ID)
	if rr.Code != 200 {
		t.Fatalf("reinstall: %d %s", rr.Code, rr.Body.String())
	}
	script := lastScript(f.srv.Stdins())
	if !strings.Contains(script, "-host-name "+newV+".dns.example.net") || strings.Contains(script, oldV) || !strings.Contains(script, dnsAccountVersionMarker+"2 ") {
		t.Fatal("the reinstall did not carry the new value and version only")
	}
	st = nodeState(t, s, "tw")
	if st.State != nodeInSync || st.Pending || st.InstalledDNSAccountVersions[id] != 2 {
		t.Fatalf("after reinstall %+v", st)
	}
	if c := dnsConfigOf(t, s, "tw"); c.Installed != "same" || c.AccountVersion != 2 || c.InstalledAccountVersion != 2 {
		t.Fatalf("dns view after reinstall %+v", c)
	}

	// Secret hygiene, old and new value.
	for _, p := range []string{"/api/compile", "/api/diff", "/api/validate"} {
		noSecretIn(t, "POST "+p, do(s, http.MethodPost, p, []byte(`{}`)).Body.String(), secrets...)
	}
	views := append([]string{"/api/dns", "/api/dns/config?node=tw", "/api/dns-accounts", "/api/provision/state", "/api/provision/preflight/tw", "/api/deploy", "/api/deployments"}, readOnlyViews...)
	for _, p := range views {
		noSecretIn(t, "GET "+p, do(s, http.MethodGet, p, nil).Body.String(), secrets...)
	}
	noSecretIn(t, "logs", logs.String(), secrets...)
	for _, v := range secrets {
		assertNowhereElse(t, s.DataDir, s.secretsDir(), v)
	}
	if rr := do(s, http.MethodPost, "/api/compile", []byte(`{}`)); !strings.Contains(rr.Body.String(), dnsAccountVersionMarker+"2 ") {
		t.Fatalf("compile output lacks the version: %.300s", rr.Body.String())
	}
}

// An open deployment run goes stale when a credential its exits use is
// rotated (the plan version folds the versions in); a topology without
// an account keeps the topology's version.
func TestDNSAccountRotationStalesDeployVersion(t *testing.T) {
	s := newTest(t)
	do(s, http.MethodGet, "/api/topology", nil)
	l, err := s.liveDeploy()
	if err != nil {
		t.Fatal(err)
	}
	if l.version != topologyVersion(l.t) {
		t.Fatal("a topology without an account changed its plan version")
	}
	rr := do(s, http.MethodPost, "/api/dns-accounts", mustJSON(map[string]any{"name": "示例服务", "account": "acct" + rnd(t, 5)}))
	var c struct {
		Account dnsAccountView `json:"account"`
	}
	decode(t, rr, &c)
	if rr := do(s, http.MethodPut, "/api/dns/upstream", mustJSON(dotUpstream(c.Account.ID))); rr.Code != 200 {
		t.Fatalf("save: %d %s", rr.Code, rr.Body.String())
	}
	l1, _ := s.liveDeploy()
	do(s, http.MethodPut, "/api/dns-accounts/"+c.Account.ID+"/secret", mustJSON(map[string]any{"account": "acct" + rnd(t, 5)}))
	l2, _ := s.liveDeploy()
	if l1.version == l2.version || topologyVersion(l1.t) != topologyVersion(l2.t) {
		t.Fatalf("plan version %s → %s", l1.version, l2.version)
	}
}

// Upgrade: a node installed before versions were recorded. One whose files
// name no DNS account stays in sync (its files are byte-identical); one
// that names one is pending, and the reason says why.
func TestDNSAccountVersionUpgrade(t *testing.T) {
	f := newGateFix(t)
	s := f.s
	if rr := f.provision(f.preflight(t).ID); rr.Code != 200 {
		t.Fatalf("provision: %d %s", rr.Code, rr.Body.String())
	}
	b, err := s.compileTopo(mustTopo(t, s))
	if err != nil {
		t.Fatal(err)
	}
	for p, body := range b.Files {
		if strings.Contains(body, dnsAccountVersionMarker) {
			t.Fatalf("%s carries a version line without any account", p)
		}
	}
	// A record from before: no versions at all.
	s.updateOutcome("tw", func(o *provisionOutcome) { o.DNSAccounts, o.InstalledDNSAccounts = nil, nil })
	if st := nodeState(t, s, "tw"); st.State != nodeInSync || st.Pending {
		t.Fatalf("no account, old record: %+v", st)
	}

	// Now with an account, installed by a panel that did not stamp it.
	rr := do(s, http.MethodPost, "/api/dns-accounts", mustJSON(map[string]any{"name": "示例服务", "account": "acct" + rnd(t, 5)}))
	var c struct {
		Account dnsAccountView `json:"account"`
	}
	decode(t, rr, &c)
	if rr := do(s, http.MethodPut, "/api/dns/upstream", mustJSON(dotUpstream(c.Account.ID))); rr.Code != 200 {
		t.Fatalf("save: %d %s", rr.Code, rr.Body.String())
	}
	b, err = s.compileTopo(mustTopo(t, s))
	if err != nil {
		t.Fatal(err)
	}
	files := provision.FilesFor(b.Files, "tw")
	legacy := map[string]string{}
	for p, body := range files {
		if i := strings.Index(body, dnsAccountVersionMarker); i >= 0 {
			j := strings.Index(body[i:], "\n")
			body = body[:i] + body[i+j+1:]
		}
		legacy[p] = body
	}
	if preflight.BundleDigest(legacy) == preflight.BundleDigest(files) {
		t.Fatal("the stamp did not change the exit's files")
	}
	s.updateOutcome("tw", func(o *provisionOutcome) {
		o.InstalledBundle, o.Bundle = preflight.BundleDigest(legacy), preflight.BundleDigest(legacy)
		o.DNSAccounts, o.InstalledDNSAccounts = nil, nil
	})
	st := nodeState(t, s, "tw")
	if st.State != nodeChanged || !st.Pending || !strings.Contains(st.Reason, "没有账户标识的版本") || st.InstalledDNSAccountVersions != nil {
		t.Fatalf("legacy with account: %+v", st)
	}
	if c := dnsConfigOf(t, s, "tw"); c.Installed != "differs" || c.AccountVersion != 1 || c.InstalledAccountVersion != 0 || !strings.Contains(c.Detail, "没有账户标识的版本") {
		t.Fatalf("dns view legacy %+v", c)
	}
	// A record from before versions existed still decodes.
	var o provisionOutcome
	if err := json.Unmarshal([]byte(`{"node_id":"tw","installed":true,"installed_bundle":"x"}`), &o); err != nil || o.InstalledDNSAccounts != nil {
		t.Fatalf("%v %+v", err, o)
	}
}

// The rotate endpoint: panel token required, a malformed value refused
// without being echoed, an unknown credential 404, nothing changed.
func TestDNSAccountRotateValidation(t *testing.T) {
	s := newTest(t)
	do(s, http.MethodGet, "/api/topology", nil)
	rr := do(s, http.MethodPost, "/api/dns-accounts", mustJSON(map[string]any{"name": "示例服务", "account": "acct" + rnd(t, 5)}))
	var c struct {
		Account dnsAccountView `json:"account"`
	}
	decode(t, rr, &c)
	s.Token = "tok-" + rnd(t, 4)
	for _, m := range []string{http.MethodPut, http.MethodPatch} {
		p := "/api/dns-accounts/" + c.Account.ID
		if m == http.MethodPut {
			p += "/secret"
		}
		if rr := do(s, m, p, mustJSON(map[string]any{"account": "acct" + rnd(t, 5)})); rr.Code != http.StatusUnauthorized {
			t.Fatalf("%s %s without token: %d", m, p, rr.Code)
		}
	}
	s.Token = ""
	bad := "bad/" + rnd(t, 3)
	if rr := do(s, http.MethodPut, "/api/dns-accounts/"+c.Account.ID+"/secret", mustJSON(map[string]any{"account": bad})); rr.Code < 400 || rr.Code >= 500 || strings.Contains(rr.Body.String(), bad) {
		t.Fatalf("bad value: %d %s", rr.Code, rr.Body.String())
	}
	if rr := do(s, http.MethodPut, "/api/dns-accounts/dnsacct-000000000000/secret", mustJSON(map[string]any{"account": "acct" + rnd(t, 5)})); rr.Code != http.StatusNotFound {
		t.Fatalf("unknown: %d %s", rr.Code, rr.Body.String())
	}
	cs, _ := s.credStore()
	if v := cs.DNSAccountVersions([]string{c.Account.ID}); v[c.Account.ID] != 1 {
		t.Fatalf("refused rotations changed the version: %v", v)
	}
}
