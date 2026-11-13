package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/radowitz/meridian/internal/model"
)

// recordingFetch wraps fakeFetch and records the options of every fetcher.
type recordingFetch struct {
	mu   sync.Mutex
	opts []RuleSetFetchOptions
}

func authServer(t *testing.T) (*Server, *fakeFetch, *recordingFetch) {
	s, f := importServer(t)
	s.SecretsDir = filepath.Join(t.TempDir(), "secrets")
	rec := &recordingFetch{}
	s.RuleSetFetch = func(o RuleSetFetchOptions) RuleSetFetcher {
		rec.mu.Lock()
		rec.opts = append(rec.opts, o)
		rec.mu.Unlock()
		return f
	}
	return s, f, rec
}

func waitRS(t *testing.T, s *Server, id string, ok func(*RuleSetStatus) bool) *RuleSetStatus {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		if x := s.loadRSStatus()[id]; x != nil && ok(x) {
			return x
		}
		if time.Now().After(deadline) {
			t.Fatalf("rule-set %s: state not reached: %+v", id, s.loadRSStatus()[id])
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// grepTree lists the files under dir containing needle.
func grepTree(t *testing.T, dir, needle string) []string {
	t.Helper()
	var hits []string
	filepath.Walk(dir, func(p string, fi os.FileInfo, err error) error {
		if err == nil && !fi.IsDir() {
			if b, err := os.ReadFile(p); err == nil && strings.Contains(string(b), needle) {
				hits = append(hits, p)
			}
		}
		return nil
	})
	return hits
}

// The subscription credential is write-only: stored in the credential
// store, sent to the downloader for the configured origin, never in a
// response, the topology, the panel data directory or an error.
func TestRuleSetAuthWriteOnly(t *testing.T) {
	s, f, rec := authServer(t)
	tok := "fake-rs-token-31415926"
	f.mu.Lock()
	f.body["https://private.example.org/p.list"] = "DOMAIN-SUFFIX,priv.example.net\n"
	f.mu.Unlock()

	// A URL with a token is refused without being echoed.
	rr := do(s, http.MethodPost, "/api/rule-sets", []byte(`{"name":"P","url":"https://private.example.org/p.list?token=`+tok+`"}`))
	if rr.Code != http.StatusUnprocessableEntity || !strings.Contains(rr.Body.String(), "url_has_secret") || strings.Contains(rr.Body.String(), tok) {
		t.Fatalf("secret URL: %d %s", rr.Code, rr.Body.String())
	}
	rr = do(s, http.MethodPost, "/api/rule-sets", []byte(`{"name":"P","url":"https://u:`+tok+`@private.example.org/p.list"}`))
	if rr.Code != http.StatusUnprocessableEntity || strings.Contains(rr.Body.String(), tok) {
		t.Fatalf("userinfo URL: %d %s", rr.Code, rr.Body.String())
	}
	// An invalid credential is refused without being echoed.
	rr = do(s, http.MethodPost, "/api/rule-sets", []byte(`{"name":"P","url":"https://private.example.org/p.list","auth":{"kind":"bearer","token":"has space `+tok+`"}}`))
	if rr.Code != http.StatusUnprocessableEntity || strings.Contains(rr.Body.String(), tok) {
		t.Fatalf("bad auth: %d %s", rr.Code, rr.Body.String())
	}

	rr = do(s, http.MethodPost, "/api/rule-sets", []byte(`{"name":"P","url":"https://private.example.org/p.list","auth":{"kind":"bearer","token":"`+tok+`"}}`))
	if rr.Code != http.StatusCreated || strings.Contains(rr.Body.String(), tok) {
		t.Fatalf("create: %d %s", rr.Code, rr.Body.String())
	}
	var v struct {
		RuleSet model.RuleSet `json:"rule_set"`
		Auth    *authView     `json:"auth"`
	}
	json.Unmarshal(rr.Body.Bytes(), &v)
	if v.Auth == nil || v.Auth.Kind != "bearer" || !v.Auth.SecretSet {
		t.Fatalf("auth view %+v", v.Auth)
	}
	id := v.RuleSet.ID
	waitRS(t, s, id, func(x *RuleSetStatus) bool { return x.State == "ok" })
	rec.mu.Lock()
	last := rec.opts[len(rec.opts)-1]
	rec.mu.Unlock()
	if last.Auth == nil || last.Auth.Token != tok || last.AuthOrigin != "https://private.example.org" {
		t.Fatalf("downloader options %+v", last.AuthOrigin)
	}
	// The downloader always gets the gateway's own ranges.
	if len(last.Deny) == 0 {
		t.Fatal("no deny ranges")
	}

	// A failing download whose error quotes the URL and the credential
	// shows neither.
	f.mu.Lock()
	delete(f.body, "https://private.example.org/p.list")
	f.mu.Unlock()
	errFetch := &errFetcher{msg: `Get "https://private.example.org/p.list?token=` + tok + `": Bearer ` + tok}
	s.RuleSetFetch = func(o RuleSetFetchOptions) RuleSetFetcher { return errFetch }
	do(s, http.MethodPost, "/api/rule-sets/"+id+"/update", nil)
	st := waitRS(t, s, id, func(x *RuleSetStatus) bool { return x.LastError != "" })
	if strings.Contains(st.LastError, tok) {
		t.Fatalf("credential in the status: %s", st.LastError)
	}

	// Nothing the panel answers or keeps outside the credential store
	// carries it.
	for _, path := range []string{"/api/rule-sets", "/api/topology"} {
		if rr := do(s, http.MethodGet, path, nil); strings.Contains(rr.Body.String(), tok) {
			t.Fatalf("%s carries the credential", path)
		}
	}
	for _, h := range grepTree(t, s.DataDir, tok) {
		if !strings.HasPrefix(h, s.secretsDir()) {
			t.Fatalf("credential outside the credential store: %s", h)
		}
	}
	if hits := grepTree(t, s.secretsDir(), tok); len(hits) != 1 {
		t.Fatalf("credential stored in %v", hits)
	}

	// Moving the URL to another origin drops the credential (it must not
	// follow the URL to a host of the editor's choosing).
	if rr := do(s, http.MethodPatch, "/api/rule-sets/"+id, []byte(`{"url":"https://other.example.net/p.list"}`)); rr.Code != 200 {
		t.Fatal(rr.Body.String())
	}
	if s.ruleSetAuthView(id) != nil {
		t.Fatal("credential kept across an origin change")
	}
	// PUT sets it again; DELETE of the rule-set removes it.
	if rr := do(s, http.MethodPut, "/api/rule-sets/"+id+"/auth", []byte(`{"kind":"basic","username":"u","password":"`+tok+`"}`)); rr.Code != 200 || strings.Contains(rr.Body.String(), tok) {
		t.Fatalf("put auth: %d %s", rr.Code, rr.Body.String())
	}
	if a := s.ruleSetAuthView(id); a == nil || a.Kind != "basic" {
		t.Fatalf("after put: %+v", a)
	}
	if rr := do(s, http.MethodDelete, "/api/rule-sets/"+id, nil); rr.Code != 200 {
		t.Fatal(rr.Body.String())
	}
	if hits := grepTree(t, s.secretsDir(), tok); len(hits) != 0 {
		t.Fatalf("credential left after the rule-set was deleted: %v", hits)
	}
}

type errFetcher struct{ msg string }

func (e *errFetcher) Get(context.Context, string) ([]byte, error) { return nil, errors.New(e.msg) }

// A rule-set URL stored with a credential (an older version, an imported
// document) is moved into the credential store at startup.
func TestRuleSetSecretURLMigration(t *testing.T) {
	s, _, _ := authServer(t)
	tok := "fake-mig-token-2718"
	if _, err := s.Store.Update(func(tp *model.Topology) (bool, error) {
		tp.RuleSets = append(tp.RuleSets, model.RuleSet{ID: "rs-old", Name: "Old", URL: "https://private.example.org/o.list?raw=1&token=" + tok})
		return true, nil
	}); err != nil {
		t.Fatal(err)
	}
	if rr := do(s, http.MethodGet, "/api/topology", nil); strings.Contains(rr.Body.String(), tok) {
		t.Fatal("topology response carries the credential before the migration")
	}
	if errs := s.MigrateCredentials(); len(errs) != 0 {
		t.Fatal(errs)
	}
	tp, _ := s.topology()
	rs, _ := tp.RuleSetByID("rs-old")
	if rs.URL != "https://private.example.org/o.list?raw=1" {
		t.Fatalf("URL after migration %q", rs.URL)
	}
	a, err := s.ruleSetAuth("rs-old")
	if err != nil || a == nil || a.Kind != "query" || a.Query != "token="+tok {
		t.Fatalf("migrated credential %+v %v", a, err)
	}
	// Idempotent.
	if errs := s.MigrateCredentials(); len(errs) != 0 {
		t.Fatal(errs)
	}
}

func TestGatewayDeny(t *testing.T) {
	s := newTest(t)
	tp, _ := s.topology()
	tp.Settings.GatewayLANIP = "192.0.2.1/24"
	deny := gatewayDeny(tp)
	in := func(a string) bool {
		ad := netip.MustParseAddr(a)
		for _, p := range deny {
			if p.Contains(ad) {
				return true
			}
		}
		return false
	}
	for _, a := range []string{"192.0.2.1", "10.66.1.1", "10.66.200.10", "10.67.0.5", "fd67::5"} {
		if !in(a) {
			t.Errorf("%s not refused", a)
		}
	}
	// Another LAN host (a NAS serving a list) is up to the rule-set's
	// allow_lan.
	if in("192.0.2.50") {
		t.Error("whole LAN refused")
	}
}

func TestDueRuleSets(t *testing.T) {
	now := time.Date(2026, 11, 1, 12, 0, 0, 0, time.UTC)
	tp := model.Topology{RuleSets: []model.RuleSet{{ID: "rs-b"}, {ID: "rs-a", IntervalSec: 3600}, {ID: "rs-c", IntervalSec: 7200}}}
	st := map[string]*RuleSetStatus{
		"rs-a": {LastAttempt: now.Add(-61 * time.Minute).Format(time.RFC3339)},
		"rs-b": {LastAttempt: now.Add(-23 * time.Hour).Format(time.RFC3339)},
		"rs-c": {LastAttempt: now.Add(-time.Hour).Format(time.RFC3339), LastError: "HTTP 500"},
	}
	var ids []string
	for _, rs := range dueRuleSets(tp, st, now) {
		ids = append(ids, rs.ID)
	}
	if strings.Join(ids, ",") != "rs-a" {
		t.Fatalf("due %v", ids)
	}
	// Never tried: due at once; a failed attempt also waits its interval.
	delete(st, "rs-b")
	ids = nil
	for _, rs := range dueRuleSets(tp, st, now.Add(time.Hour)) {
		ids = append(ids, rs.ID)
	}
	if strings.Join(ids, ",") != "rs-a,rs-b,rs-c" {
		t.Fatalf("due later %v", ids)
	}
}
