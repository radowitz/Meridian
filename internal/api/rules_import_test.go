package api

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/radowitz/meridian/internal/model"
	"github.com/radowitz/meridian/internal/ordered"
)

var importSecrets = []string{"fake-pass-9f8e7d", "11111111-2222-4333-8444-fakeuuidfake", "FAKEWGPRIVKEYBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=", "fake-sub-token-abc", "fake-ctl-secret"}

const importConfig = `secret: fake-ctl-secret
proxies:
  - { name: "HK Home", type: vless, server: 198.51.100.7, port: 443, uuid: 11111111-2222-4333-8444-fakeuuidfake }
  - { name: "JP WG", type: wireguard, server: 203.0.113.9, private-key: FAKEWGPRIVKEYBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=, password: fake-pass-9f8e7d }
proxy-providers:
  P: { type: http, url: "https://sub.example.org/x?token=fake-sub-token-abc" }
sel: &sel { type: select, proxies: [HK, US, DIRECT] }
proxy-groups:
  - { name: AI, <<: *sel }
  - { name: Others, <<: *sel }
  - { name: HK, type: select, proxies: ["LB-HK P"] }
  - { name: US, type: select, proxies: ["LB-US P"] }
  - { name: "LB-HK P", type: load-balance, use: [P] }
  - { name: "LB-US P", type: load-balance, use: [P] }
rule-providers:
  Ads: { type: http, behavior: classical, url: "https://rules.example.org/ads.list", interval: 86400 }
rules:
  - DOMAIN-SUFFIX,ai.example.net,AI
  - RULE-SET,Ads,REJECT
  - DOMAIN,host.example.org,DIRECT
  - MATCH,Others
`

const importSelection = `{"proxies":{"AI":{"type":"Selector","now":"US"},"Others":{"type":"Selector","now":"HK"},"HK":{"type":"Selector","now":"LB-HK P"},"US":{"type":"Selector","now":"LB-US P"}}}`

type fakeFetch struct {
	mu    sync.Mutex
	body  map[string]string
	calls []string
}

func (f *fakeFetch) Get(ctx context.Context, url string) ([]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, url)
	b, ok := f.body[url]
	if !ok {
		return nil, fmt.Errorf("HTTP 404")
	}
	return []byte(b), nil
}

func importServer(t *testing.T) (*Server, *fakeFetch) {
	s := newTest(t)
	s.RuleSetDir = filepath.Join(t.TempDir(), "rulesets")
	s.ListsDir = t.TempDir()
	f := &fakeFetch{body: map[string]string{"https://rules.example.org/ads.list": "DOMAIN-SUFFIX,ads.example.net\nDOMAIN,tracker.example.org\nPROCESS-NAME,x.exe\n"}}
	s.RuleSetFetch = func(RuleSetFetchOptions) RuleSetFetcher { return f }
	if _, err := s.topology(); err != nil {
		t.Fatal(err)
	}
	// The import maps into an explicit list.
	if _, err := s.Store.Update(func(tp *model.Topology) (bool, error) { tp.RulesOrdered = true; return true, nil }); err != nil {
		t.Fatal(err)
	}
	return s, f
}

func importReq(extra map[string]any) []byte {
	body := map[string]any{"config": importConfig, "selection": importSelection,
		"mapping": map[string]string{"LB-HK P": "group:hk-residential", "LB-US P": "group:us"}}
	for k, v := range extra {
		body[k] = v
	}
	b, _ := json.Marshal(body)
	return b
}

func previewOf(t *testing.T, rr *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var p map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &p); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestImportPreviewConfirmFlow(t *testing.T) {
	var logs bytes.Buffer
	log.SetOutput(&logs)
	defer log.SetOutput(os.Stderr)
	s, _ := importServer(t)

	// First preview: the rule-set is not downloaded yet; asking for it
	// starts a background fetch.
	rr := do(s, http.MethodPost, "/api/rules/import/preview", importReq(map[string]any{"fetch_rule_sets": true}))
	if rr.Code != 200 {
		t.Fatal(rr.Body.String())
	}
	var all bytes.Buffer
	all.Write(rr.Body.Bytes())
	p := previewOf(t, rr)
	if p["can_confirm"] == true {
		t.Fatal("confirmable before the rule-set is available")
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		rr = do(s, http.MethodPost, "/api/rules/import/preview", importReq(map[string]any{"accept": map[string][]string{"19": {"ruleset_partial"}}}))
		all.Write(rr.Body.Bytes())
		p = previewOf(t, rr)
		if p["can_confirm"] == true || time.Now().After(deadline) {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if p["can_confirm"] != true {
		t.Fatalf("not confirmable: %s", rr.Body.String())
	}
	// Confirm with a wrong digest: refused, nothing written.
	rr = do(s, http.MethodPost, "/api/rules/import/confirm", importReq(map[string]any{"accept": map[string][]string{"19": {"ruleset_partial"}}, "digest": "0000"}))
	if rr.Code != http.StatusConflict {
		t.Fatalf("stale digest: %d %s", rr.Code, rr.Body.String())
	}
	all.Write(rr.Body.Bytes())
	rr = do(s, http.MethodPost, "/api/rules/import/confirm", importReq(map[string]any{"accept": map[string][]string{"19": {"ruleset_partial"}}, "digest": p["digest"]}))
	if rr.Code != 200 {
		t.Fatalf("confirm: %d %s", rr.Code, rr.Body.String())
	}
	all.Write(rr.Body.Bytes())
	topo, _ := s.topology()
	n := 0
	for _, r := range topo.Rules {
		if r.Origin == model.OriginMihomo {
			n++
		}
	}
	if n != 3 || len(topo.ServiceGroups) != 2 || len(topo.RuleSets) != 1 || topo.Settings.DefaultGroup != "hk-residential" {
		t.Fatalf("written: %d rules, %+v, %+v, default %s", n, topo.ServiceGroups, topo.RuleSets, topo.Settings.DefaultGroup)
	}
	// The rule-set content is active on disk.
	es, ok := s.activeEntries(topo.RuleSets[0].ID)
	if !ok || len(es) != 2 {
		t.Fatalf("rule-set content: %v %v", es, ok)
	}
	// The compiled bundle is valid with the imported list.
	rr = do(s, http.MethodPost, "/api/compile", nil)
	if rr.Code != 200 {
		t.Fatalf("compile: %s", rr.Body.String())
	}
	all.Write(rr.Body.Bytes())
	rr = do(s, http.MethodGet, "/api/topology", nil)
	all.Write(rr.Body.Bytes())
	// No secret anywhere: responses, logs, the database file.
	db, _ := os.ReadFile(filepath.Join(s.DataDir, "meridian.db"))
	for _, sec := range importSecrets {
		for what, b := range map[string][]byte{"responses": all.Bytes(), "logs": logs.Bytes(), "database": db} {
			if bytes.Contains(b, []byte(sec)) {
				t.Errorf("secret %q in %s", sec, what)
			}
		}
	}
	filepath.Walk(s.DataDir, func(p string, info os.FileInfo, err error) error {
		if err == nil && !info.IsDir() {
			b, _ := os.ReadFile(p)
			for _, sec := range importSecrets {
				if bytes.Contains(b, []byte(sec)) {
					t.Errorf("secret %q in %s", sec, p)
				}
			}
		}
		return nil
	})

	// Re-import: unchanged rows are "same", nothing removed.
	rr = do(s, http.MethodPost, "/api/rules/import/preview", importReq(map[string]any{"accept": map[string][]string{"19": {"ruleset_partial"}}}))
	p = previewOf(t, rr)
	for _, row := range p["rows"].([]any) {
		r := row.(map[string]any)
		if r["action"] == "rule" && r["diff"] != "same" {
			t.Fatalf("re-import diff %v", r)
		}
	}
	// A whole-document save from the topology editor keeps the blocks.
	raw, _ := json.Marshal(func() model.Topology { x := topo; x.ServiceGroups = nil; x.RuleSets = nil; return x }())
	if rr := do(s, http.MethodPut, "/api/topology", raw); rr.Code != 200 {
		t.Fatalf("put: %s", rr.Body.String())
	}
	if after, _ := s.topology(); len(after.ServiceGroups) != 2 || len(after.RuleSets) != 1 {
		t.Fatal("topology save dropped the service groups or rule-sets")
	}
}

func TestImportBadInputsDoNotEcho(t *testing.T) {
	s, _ := importServer(t)
	for _, body := range []string{
		`{"config": "proxies:\n  - {password: fake-pass-9f8e7d\nrules: ["}`,
		`{"config": "x", "bogus-field-fake-pass-9f8e7d": 1}`,
		`not json fake-pass-9f8e7d`,
	} {
		rr := do(s, http.MethodPost, "/api/rules/import/preview", []byte(body))
		if rr.Code < 400 || strings.Contains(rr.Body.String(), "fake-pass") {
			t.Fatalf("%d %s", rr.Code, rr.Body.String())
		}
	}
}

func TestServiceGroupRetarget(t *testing.T) {
	s, _ := importServer(t)
	rr := do(s, http.MethodPost, "/api/service-groups", []byte(`{"name":"Video","target":"group:us"}`))
	if rr.Code != 201 {
		t.Fatal(rr.Body.String())
	}
	var created struct {
		ServiceGroup model.ServiceGroup `json:"service_group"`
	}
	json.Unmarshal(rr.Body.Bytes(), &created)
	id := created.ServiceGroup.ID
	// A rule that requires a residential line, through the service group.
	if _, err := s.Store.Update(func(tp *model.Topology) (bool, error) {
		tp.Rules = append(tp.Rules, model.Rule{ID: "vid", Name: "video", Enabled: true, Manual: true, MatchType: model.MatchSuffix, MatchValue: "video.example.net", TargetService: id})
		return true, nil
	}); err != nil {
		t.Fatal(err)
	}
	if rr := do(s, http.MethodPatch, "/api/service-groups/"+id, []byte(`{"target":"group:jp"}`)); rr.Code != 200 {
		t.Fatal(rr.Body.String())
	}
	topo, _ := s.topology()
	if tg := topo.ResolveTarget(topo.Rules[len(topo.Rules)-1]); tg.Kind != "group" || tg.ID != "jp" {
		t.Fatalf("rule did not follow: %+v", tg)
	}
	// Make the rule require residential: retargeting to a non-residential
	// group is refused with the validation issue.
	s.Store.Update(func(tp *model.Topology) (bool, error) {
		tp.Rules[len(tp.Rules)-1].RequireResidential = true
		for i := range tp.ServiceGroups {
			if tp.ServiceGroups[i].ID == id {
				tp.ServiceGroups[i].TargetGroup = "hk-residential"
			}
		}
		return true, nil
	})
	rr = do(s, http.MethodPatch, "/api/service-groups/"+id, []byte(`{"target":"group:us"}`))
	if rr.Code != http.StatusUnprocessableEntity || !strings.Contains(rr.Body.String(), "residential_required") {
		t.Fatalf("residential not enforced: %d %s", rr.Code, rr.Body.String())
	}
	if rr := do(s, http.MethodDelete, "/api/service-groups/"+id, nil); rr.Code != http.StatusConflict {
		t.Fatalf("delete of a used service group: %d", rr.Code)
	}
}

func TestRuleSetLifecycle(t *testing.T) {
	s, f := importServer(t)
	rr := do(s, http.MethodPost, "/api/rule-sets", []byte(`{"name":"Ads","url":"https://rules.example.org/ads.list"}`))
	if rr.Code != 201 {
		t.Fatal(rr.Body.String())
	}
	var v struct {
		RuleSet model.RuleSet `json:"rule_set"`
	}
	json.Unmarshal(rr.Body.Bytes(), &v)
	id := v.RuleSet.ID
	waitState := func(want string) map[string]any {
		deadline := time.Now().Add(5 * time.Second)
		for {
			rr := do(s, http.MethodGet, "/api/rule-sets", nil)
			var l struct {
				RuleSets []map[string]any `json:"rule_sets"`
			}
			json.Unmarshal(rr.Body.Bytes(), &l)
			for _, x := range l.RuleSets {
				st := x["status"].(map[string]any)
				if x["rule_set"].(map[string]any)["id"] == id && st["state"] == want {
					return st
				}
			}
			if time.Now().After(deadline) {
				t.Fatalf("state %s not reached: %s", want, rr.Body.String())
			}
			time.Sleep(20 * time.Millisecond)
		}
	}
	st := waitState("ok")
	if st["format"] != "surge-list" || st["unsupported"].(map[string]any)["PROCESS-NAME"] != float64(1) {
		t.Fatalf("status %v", st)
	}
	// A rule uses it: delete refused with the rule list.
	s.Store.Update(func(tp *model.Topology) (bool, error) {
		tp.Rules = append(tp.Rules, model.Rule{ID: "ads", Name: "ads", Enabled: true, Manual: true, MatchType: model.MatchRuleSet, RuleSet: id, TargetAction: model.ActionReject})
		return true, nil
	})
	if rr := do(s, http.MethodDelete, "/api/rule-sets/"+id, nil); rr.Code != http.StatusConflict || !strings.Contains(rr.Body.String(), "\"ads\"") {
		t.Fatalf("delete in use: %d %s", rr.Code, rr.Body.String())
	}
	// A failing update keeps the active version.
	f.mu.Lock()
	delete(f.body, "https://rules.example.org/ads.list")
	f.mu.Unlock()
	do(s, http.MethodPost, "/api/rule-sets/"+id+"/update", nil)
	deadline := time.Now().Add(5 * time.Second)
	for {
		if x := s.loadRSStatus()[id]; x != nil && x.LastError != "" {
			if x.State != "ok" {
				t.Fatalf("failure changed the state: %+v", x)
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("no failure recorded")
		}
		time.Sleep(20 * time.Millisecond)
	}
	if es, ok := s.activeEntries(id); !ok || len(es) != 2 {
		t.Fatal("active version lost")
	}
	// A version with new keyword entries is held back.
	f.mu.Lock()
	f.body["https://rules.example.org/ads.list"] = "DOMAIN-SUFFIX,ads.example.net\nDOMAIN-KEYWORD,adword\n"
	f.mu.Unlock()
	do(s, http.MethodPost, "/api/rule-sets/"+id+"/update", nil)
	st = waitState("held")
	if es, _ := s.activeEntries(id); len(es) != 2 {
		t.Fatal("held version activated")
	}
	if rr := do(s, http.MethodPost, "/api/rule-sets/"+id+"/activate-held", []byte(`{"accept":true}`)); rr.Code != 200 {
		t.Fatal(rr.Body.String())
	}
	if es, _ := s.activeEntries(id); len(es) != 2 || es[0].Kind != ordered.Keyword && es[1].Kind != ordered.Keyword {
		t.Fatalf("held version not active: %v", es)
	}
}

func TestRuleTester(t *testing.T) {
	s, _ := importServer(t)
	s.Store.Update(func(tp *model.Topology) (bool, error) {
		tp.Rules = append([]model.Rule{
			{ID: "first", Name: "first", Enabled: true, Manual: true, MatchType: model.MatchSuffix, MatchValue: "a.example.net", TargetGroup: "jp"},
			{ID: "second", Name: "second", Enabled: true, Manual: true, MatchType: model.MatchSuffix, MatchValue: "example.net", TargetGroup: "us"},
		}, tp.Rules...)
		return true, nil
	})
	rr := do(s, http.MethodPost, "/api/rules/test", []byte(`{"name":"x.a.example.net"}`))
	if rr.Code != 200 || !strings.Contains(rr.Body.String(), `"id":"first"`) || !strings.Contains(rr.Body.String(), `"position":1`) {
		t.Fatal(rr.Body.String())
	}
	rr = do(s, http.MethodGet, "/api/rules/analysis", nil)
	if rr.Code != 200 {
		t.Fatal(rr.Body.String())
	}
}
