package api

import (
	"bytes"
	"context"
	"log"
	"net/http"
	"os"
	"strings"
	"testing"

	"github.com/radowitz/meridian/internal/compile"
	"github.com/radowitz/meridian/internal/hostexec"
	"github.com/radowitz/meridian/internal/probe"
)

// dotUpstream is the global DoT upstream of an invented provider with an
// account label.
func dotUpstream(cred string) map[string]any {
	return map[string]any{"global": map[string]any{"protocol": "dot", "addresses": []string{"192.0.2.53", "2001:db8::53"},
		"tls_host_name": "{account}.dns.example.net", "account_credential": cred}}
}

// The account value of an exit's DNS upstream: accepted once, injected
// only into the provision script of the exits (their SmartDNS config,
// written 0600), and absent from every response, the compile output, the
// diff, the preflight (which shows the upstream with the account masked),
// the panel's data files (topology, snapshots, preflight and outcome
// records) and the logs.
func TestDNSAccountSeams(t *testing.T) {
	var logs bytes.Buffer
	log.SetOutput(&logs)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })
	f := newGateFix(t)
	s := f.s
	acct := "acct" + rnd(t, 5)
	secrets := []string{acct}
	rr := do(s, http.MethodPost, "/api/dns-accounts", mustJSON(map[string]any{"name": "示例服务", "account": acct}))
	if rr.Code != http.StatusCreated {
		t.Fatalf("create %d %s", rr.Code, rr.Body.String())
	}
	noSecretIn(t, "create", rr.Body.String(), secrets...)
	var c struct {
		Account struct {
			ID        string `json:"id"`
			SecretSet bool   `json:"secret_set"`
		}
	}
	decode(t, rr, &c)
	if !strings.HasPrefix(c.Account.ID, "dnsacct-") || !c.Account.SecretSet {
		t.Fatalf("%+v", c)
	}
	// A malformed value is refused without being echoed.
	bad := "bad/" + rnd(t, 3)
	if rr := do(s, http.MethodPost, "/api/dns-accounts", mustJSON(map[string]any{"name": "x", "account": bad})); rr.Code < 400 || strings.Contains(rr.Body.String(), bad) {
		t.Fatalf("bad value: %d %s", rr.Code, rr.Body.String())
	}
	// An unknown credential is refused; validation refuses bad shapes.
	if rr := do(s, http.MethodPut, "/api/dns/upstream", mustJSON(dotUpstream("dnsacct-000000000000"))); rr.Code != http.StatusConflict {
		t.Fatalf("unknown credential: %d %s", rr.Code, rr.Body.String())
	}
	for _, u := range []map[string]any{
		{"protocol": "dot", "addresses": []string{"10.1.2.3"}, "tls_host_name": "dns.example.net"},
		{"protocol": "dot", "addresses": []string{"223.5.5.5"}, "tls_host_name": "dns.example.net"},
		{"protocol": "dot", "addresses": []string{"192.0.2.53"}, "tls_host_name": "dns.{account}.example.net", "account_credential": c.Account.ID},
		{"protocol": "dot", "addresses": []string{"192.0.2.53"}, "tls_host_name": ""},
		{"protocol": "builtin"},
		{"protocol": "doh", "addresses": []string{"192.0.2.53"}, "tls_host_name": "dns.example.net", "path": "/q?x=1"},
	} {
		if rr := do(s, http.MethodPut, "/api/dns/upstream", mustJSON(map[string]any{"global": u})); rr.Code != http.StatusUnprocessableEntity || !strings.Contains(rr.Body.String(), "exit_dns_invalid") {
			t.Fatalf("%v: %d %s", u, rr.Code, rr.Body.String())
		}
	}
	rr = do(s, http.MethodPut, "/api/dns/upstream", mustJSON(dotUpstream(c.Account.ID)))
	if rr.Code != 200 {
		t.Fatalf("save: %d %s", rr.Code, rr.Body.String())
	}
	noSecretIn(t, "save", rr.Body.String(), secrets...)
	// In use: the delete is refused.
	if rr := do(s, http.MethodDelete, "/api/dns-accounts/"+c.Account.ID, nil); rr.Code != http.StatusConflict {
		t.Fatalf("delete in use: %d %s", rr.Code, rr.Body.String())
	}

	// The preflight names the upstream with the account masked.
	pf := f.preflight(t)
	found := false
	for _, ch := range pf.Evaluation.Changes {
		if ch.Resource == "/etc/smartdns/smartdns.conf" && strings.Contains(ch.Detail, "出口解析上游：DoT 192.0.2.53:853") && strings.Contains(ch.Detail, compile.MaskedAccount) {
			found = true
		}
	}
	if !found {
		t.Fatalf("preflight has no upstream change: %+v", pf.Evaluation.Changes)
	}
	rr = f.provision(pf.ID)
	if rr.Code != 200 {
		t.Fatalf("provision: %d %s", rr.Code, rr.Body.String())
	}
	noSecretIn(t, "provision response", rr.Body.String(), secrets...)
	script := lastScript(f.srv.Stdins())
	if !strings.Contains(script, "server-tls 192.0.2.53:853 -host-name "+acct+".dns.example.net -tls-host-verify "+acct+".dns.example.net\n") ||
		!strings.Contains(script, "server-tls [2001:db8::53]:853 -host-name "+acct+".dns.example.net") {
		t.Fatal("the account did not reach the exit's SmartDNS config in the provision script")
	}
	if strings.Contains(script, "__MERIDIAN_SECRET_") {
		t.Fatal("a placeholder reached the host")
	}
	_, conf, _ := strings.Cut(script, "m_track '/etc/smartdns/smartdns.conf'")
	if !strings.Contains(strings.SplitN(conf, "cat >", 2)[0], "chmod 600") {
		t.Fatal("the exit's SmartDNS config with the account is not written 0600")
	}

	for _, p := range []string{"/api/compile", "/api/diff", "/api/validate"} {
		noSecretIn(t, "POST "+p, do(s, http.MethodPost, p, []byte(`{}`)).Body.String(), secrets...)
	}
	views := append([]string{"/api/dns", "/api/dns/config?node=tw", "/api/dns-accounts", "/api/provision/state", "/api/provision/preflight/tw"}, readOnlyViews...)
	for _, p := range views {
		noSecretIn(t, "GET "+p, do(s, http.MethodGet, p, nil).Body.String(), secrets...)
	}
	rr = do(s, http.MethodGet, "/api/dns/config?node=tw", nil)
	if rr.Code != 200 || !strings.Contains(rr.Body.String(), compile.MaskedAccount+".dns.example.net") || strings.Contains(rr.Body.String(), "__MERIDIAN_SECRET_") {
		t.Fatalf("config view: %d %.400s", rr.Code, rr.Body.String())
	}
	if rr := do(s, http.MethodPost, "/api/compile", []byte(`{}`)); !strings.Contains(rr.Body.String(), "__MERIDIAN_SECRET_"+c.Account.ID+"__.dns.example.net") {
		t.Fatalf("compile output lacks the placeholder: %.300s", rr.Body.String())
	}
	noSecretIn(t, "logs", logs.String(), secrets...)
	assertNowhereElse(t, s.DataDir, s.secretsDir(), acct)
}

// Every DNS endpoint needs the panel token; the check refuses an exit
// that is not one, and without the host agent nothing runs.
func TestDNSAuthAndCheck(t *testing.T) {
	s := newTest(t)
	s.Token = "tok-" + rnd(t, 4)
	for _, r := range []struct{ m, p string }{
		{http.MethodGet, "/api/dns"}, {http.MethodGet, "/api/dns/config?node=tw"}, {http.MethodPut, "/api/dns/upstream"},
		{http.MethodPost, "/api/dns/check"}, {http.MethodGet, "/api/dns-accounts"}, {http.MethodPost, "/api/dns-accounts"},
		{http.MethodDelete, "/api/dns-accounts/dnsacct-000000000000"},
	} {
		if rr := do(s, r.m, r.p, []byte(`{}`)); rr.Code != http.StatusUnauthorized {
			t.Fatalf("%s %s without token: %d", r.m, r.p, rr.Code)
		}
	}
	s.Token = ""
	if rr := do(s, http.MethodPost, "/api/dns/check", mustJSON(map[string]any{"exit_id": "tw"})); rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("no agent: %d %s", rr.Code, rr.Body.String())
	}
	fp := &fakeDNSCheck{}
	s.Prober = fp
	if rr := do(s, http.MethodPost, "/api/dns/check", mustJSON(map[string]any{"exit_id": "nope"})); rr.Code != http.StatusBadRequest {
		t.Fatalf("unknown exit: %d %s", rr.Code, rr.Body.String())
	}
	rr := do(s, http.MethodPost, "/api/dns/check", mustJSON(map[string]any{"exit_id": "tw"}))
	if rr.Code != 200 || fp.req.ExitID != "tw" || !strings.HasPrefix(fp.req.Resolver, "fd66:") {
		t.Fatalf("check: %d %s %+v", rr.Code, rr.Body.String(), fp.req)
	}
	// The view carries the result, the forwarder state and the unverified notes.
	var v struct {
		Paths  []compile.DNSPathRow      `json:"paths"`
		Exits  []compile.DNSExitRow      `json:"exits"`
		Checks []hostexec.DNSCheckResult `json:"checks"`
		Config []dnsConfigState          `json:"configs"`
		Fwd    dnsForwarderView          `json:"forwarder"`
		Unver  []string                  `json:"unverified"`
	}
	rr = do(s, http.MethodGet, "/api/dns", nil)
	if rr.Code != 200 {
		t.Fatalf("%d %s", rr.Code, rr.Body.String())
	}
	decode(t, rr, &v)
	scopes := map[string]bool{}
	for _, p := range v.Paths {
		scopes[p.Scope] = true
	}
	for _, sc := range []string{"clients", "domestic", "unlisted", "exit", "reject", "doh_block", "gateway"} {
		if !scopes[sc] {
			t.Fatalf("no %s row: %+v", sc, v.Paths)
		}
	}
	if len(v.Checks) != 1 || v.Checks[0].Outcome != "answer" || len(v.Unver) == 0 || v.Fwd.Available {
		t.Fatalf("%+v", v)
	}
	for _, c := range v.Config {
		if c.Installed != "not_installed" || c.PlannedSHA256 == "" {
			t.Fatalf("config state %+v", c)
		}
	}
	if rr := do(s, http.MethodGet, "/api/dns/config?node=nope", nil); rr.Code != http.StatusNotFound {
		t.Fatalf("unknown node: %d", rr.Code)
	}
}

type fakeDNSCheck struct{ req hostexec.DNSCheckRequest }

func (f *fakeDNSCheck) Probe(context.Context, hostexec.ProbeRequest) (probe.Report, error) {
	return probe.Report{}, nil
}

func (f *fakeDNSCheck) DNSCheck(_ context.Context, req hostexec.DNSCheckRequest) (hostexec.DNSCheckResult, error) {
	f.req = req
	return hostexec.DNSCheckResult{ExitID: req.ExitID, Resolver: req.Resolver, Name: hostexec.DNSCheckName, QType: "A", Outcome: "answer", Answers: 1, DurationMS: 31}, nil
}

// The demo's DNS account value is in no generated fixture (they show the
// upstream with the account masked).
func TestDemoFixturesNoDNSAccount(t *testing.T) {
	entries, err := os.ReadDir(demoFixtureDir)
	if err != nil {
		t.Fatal(err)
	}
	seen := false
	for _, e := range entries {
		b, err := os.ReadFile(demoFixtureDir + "/" + e.Name())
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(b), demoDNSAccount) {
			t.Fatalf("the demo DNS account value is in %s", e.Name())
		}
		seen = seen || strings.Contains(string(b), "dns.example.net")
	}
	if !seen {
		t.Fatal("no fixture shows the demo upstream")
	}
}

// The whole-topology save never writes the exits' upstream: omitted it is
// kept, a different value is refused (409), the same value passes.
func TestDNSUpstreamIsIndependent(t *testing.T) {
	s := newTest(t)
	do(s, http.MethodGet, "/api/topology", nil)
	up := map[string]any{"protocol": "dot", "addresses": []string{"192.0.2.53"}, "tls_host_name": "dns.example.net"}
	if rr := do(s, http.MethodPut, "/api/dns/upstream", mustJSON(map[string]any{"global": up, "exits": map[string]any{"tw": map[string]any{"protocol": "builtin"}}})); rr.Code != 200 {
		t.Fatalf("%d %s", rr.Code, rr.Body.String())
	}
	topo, _, _ := s.Store.Load()
	stale := topo
	stale.Settings.ExitDNS = nil
	stale.Nodes = append(stale.Nodes[:0:0], topo.Nodes...)
	for i := range stale.Nodes {
		stale.Nodes[i].ExitDNS = nil
	}
	if rr := do(s, http.MethodPut, "/api/topology", mustJSON(stale)); rr.Code != 200 {
		t.Fatalf("omitted: %d %s", rr.Code, rr.Body.String())
	}
	if got, _, _ := s.Store.Load(); got.Settings.ExitDNS == nil || got.Settings.ExitDNS.Addresses[0] != "192.0.2.53" {
		t.Fatalf("omitted upstream was dropped: %+v", got.Settings.ExitDNS)
	}
	other := topo
	o := *topo.Settings.ExitDNS
	o.Addresses = []string{"198.51.100.7"}
	other.Settings.ExitDNS = &o
	if rr := do(s, http.MethodPut, "/api/topology", mustJSON(other)); rr.Code != http.StatusConflict || !strings.Contains(rr.Body.String(), "settings.exit_dns") {
		t.Fatalf("changed upstream: %d %s", rr.Code, rr.Body.String())
	}
	if rr := do(s, http.MethodPut, "/api/topology", mustJSON(topo)); rr.Code != 200 {
		t.Fatalf("round trip: %d %s", rr.Code, rr.Body.String())
	}
}

// One exit's override is saved alone: the global setting and every other
// exit's override are kept (an absent "global" is not null), the response
// lists the exits whose effective upstream changed, null hands an exit back
// to the global setting, an explicit "global": null still clears it, and an
// override on the gateway is refused by the same validation.
func TestDNSUpstreamPerExitKeepsOthers(t *testing.T) {
	s := newTest(t)
	do(s, http.MethodGet, "/api/topology", nil)
	global := map[string]any{"protocol": "dot", "addresses": []string{"192.0.2.53"}, "tls_host_name": "dns.example.net"}
	if rr := do(s, http.MethodPut, "/api/dns/upstream", mustJSON(map[string]any{"global": global, "exits": map[string]any{"tw": map[string]any{"protocol": "builtin"}}})); rr.Code != 200 {
		t.Fatalf("seed: %d %s", rr.Code, rr.Body.String())
	}
	own := map[string]any{"protocol": "doh", "addresses": []string{"198.51.100.53"}, "tls_host_name": "doh.example.org", "path": "/dns-query"}
	rr := do(s, http.MethodPut, "/api/dns/upstream", mustJSON(map[string]any{"exits": map[string]any{"jp": own}}))
	if rr.Code != 200 {
		t.Fatalf("one exit: %d %s", rr.Code, rr.Body.String())
	}
	var out struct {
		Changed []string `json:"changed_exits"`
	}
	decode(t, rr, &out)
	if len(out.Changed) != 1 || out.Changed[0] != "jp" {
		t.Fatalf("changed exits: %+v", out.Changed)
	}
	topo, _, _ := s.Store.Load()
	if topo.Settings.ExitDNS == nil || topo.Settings.ExitDNS.Addresses[0] != "192.0.2.53" {
		t.Fatalf("the global setting was not kept: %+v", topo.Settings.ExitDNS)
	}
	for _, n := range topo.Nodes {
		switch n.ID {
		case "tw":
			if n.ExitDNS == nil || n.ExitDNS.Protocol != "builtin" {
				t.Fatalf("tw's override was not kept: %+v", n.ExitDNS)
			}
		case "jp":
			if n.ExitDNS == nil || n.ExitDNS.Protocol != "doh" || n.ExitDNS.Path != "/dns-query" {
				t.Fatalf("jp's override: %+v", n.ExitDNS)
			}
		default:
			if n.ExitDNS != nil {
				t.Fatalf("%s got an override: %+v", n.ID, n.ExitDNS)
			}
		}
	}
	// Same value again: nothing changed.
	rr = do(s, http.MethodPut, "/api/dns/upstream", mustJSON(map[string]any{"exits": map[string]any{"jp": own}}))
	decode(t, rr, &out)
	if rr.Code != 200 || len(out.Changed) != 0 {
		t.Fatalf("unchanged save: %d %+v", rr.Code, out.Changed)
	}
	// A bad override is refused with the shared validation; nothing is written.
	bad := map[string]any{"protocol": "dot", "addresses": []string{"10.1.2.3"}, "tls_host_name": "dns.example.net"}
	if rr := do(s, http.MethodPut, "/api/dns/upstream", mustJSON(map[string]any{"exits": map[string]any{"jp": bad}})); rr.Code != http.StatusUnprocessableEntity || !strings.Contains(rr.Body.String(), "exit_dns_invalid") {
		t.Fatalf("bad override: %d %s", rr.Code, rr.Body.String())
	}
	// Not applicable: the gateway, and an unknown node.
	if rr := do(s, http.MethodPut, "/api/dns/upstream", mustJSON(map[string]any{"exits": map[string]any{"gw": map[string]any{"protocol": "builtin"}}})); rr.Code != http.StatusUnprocessableEntity || !strings.Contains(rr.Body.String(), "只能设在受管出口上") {
		t.Fatalf("gateway override: %d %s", rr.Code, rr.Body.String())
	}
	if rr := do(s, http.MethodPut, "/api/dns/upstream", mustJSON(map[string]any{"exits": map[string]any{"nope": nil}})); rr.Code != http.StatusNotFound {
		t.Fatalf("unknown node: %d %s", rr.Code, rr.Body.String())
	}
	// An empty body changes nothing and is refused.
	if rr := do(s, http.MethodPut, "/api/dns/upstream", []byte(`{}`)); rr.Code != http.StatusBadRequest {
		t.Fatalf("empty body: %d %s", rr.Code, rr.Body.String())
	}
	// null: jp follows the global setting again; the others are untouched.
	rr = do(s, http.MethodPut, "/api/dns/upstream", mustJSON(map[string]any{"exits": map[string]any{"jp": nil}}))
	decode(t, rr, &out)
	if rr.Code != 200 || len(out.Changed) != 1 || out.Changed[0] != "jp" {
		t.Fatalf("back to global: %d %+v", rr.Code, out.Changed)
	}
	topo, _, _ = s.Store.Load()
	for _, n := range topo.Nodes {
		if (n.ID == "jp" && n.ExitDNS != nil) || (n.ID == "tw" && n.ExitDNS == nil) {
			t.Fatalf("%s: %+v", n.ID, n.ExitDNS)
		}
	}
	if topo.Settings.ExitDNS == nil {
		t.Fatal("the global setting was dropped")
	}
	// An explicit null global still clears it (every exit following it changes; tw keeps builtin).
	rr = do(s, http.MethodPut, "/api/dns/upstream", []byte(`{"global":null}`))
	decode(t, rr, &out)
	if rr.Code != 200 {
		t.Fatalf("clear global: %d %s", rr.Code, rr.Body.String())
	}
	if got, _, _ := s.Store.Load(); got.Settings.ExitDNS != nil {
		t.Fatalf("global not cleared: %+v", got.Settings.ExitDNS)
	}
	for _, id := range out.Changed {
		if id == "tw" {
			t.Fatalf("tw keeps the built-in resolvers; it did not change: %+v", out.Changed)
		}
	}
	if len(out.Changed) == 0 {
		t.Fatal("clearing the global setting changed no exit")
	}
}
