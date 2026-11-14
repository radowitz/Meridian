package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/radowitz/meridian/internal/model"
	"github.com/radowitz/meridian/internal/validate"
)

func previewUntil(t *testing.T, s *Server, body map[string]any, ok func(map[string]any) bool) map[string]any {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		rr := do(s, http.MethodPost, "/api/rules/import/preview", importReq(body))
		if rr.Code != 200 {
			t.Fatalf("preview: %d %s", rr.Code, rr.Body.String())
		}
		p := previewOf(t, rr)
		if ok(p) {
			return p
		}
		if time.Now().After(deadline) {
			t.Fatalf("preview never reached the state: %s", rr.Body.String())
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func rowByLine(p map[string]any, line int) map[string]any {
	for _, r := range p["rows"].([]any) {
		m := r.(map[string]any)
		if m["line"] == float64(line) {
			return m
		}
	}
	return nil
}

func flagCodes(row map[string]any) []string {
	var out []string
	for _, f := range row["flags"].([]any) {
		out = append(out, f.(map[string]any)["code"].(string))
	}
	return out
}

// selection may be the pasted text (a JSON string) or the /proxies object
// itself; anything else gets a specific message.
func TestImportSelectionObjectOrString(t *testing.T) {
	s, _ := importServer(t)
	var obj map[string]any
	json.Unmarshal([]byte(importSelection), &obj)
	a := previewOf(t, do(s, http.MethodPost, "/api/rules/import/preview", importReq(nil)))
	b := previewOf(t, do(s, http.MethodPost, "/api/rules/import/preview", importReq(map[string]any{"selection": obj})))
	if a["digest"] != b["digest"] {
		t.Fatal("object selection previews differently from the string")
	}
	rr := do(s, http.MethodPost, "/api/rules/import/preview", importReq(map[string]any{"selection": []int{1}}))
	if rr.Code != http.StatusUnprocessableEntity || !strings.Contains(rr.Body.String(), "selection") {
		t.Fatalf("array selection: %d %s", rr.Code, rr.Body.String())
	}
	rr = do(s, http.MethodPost, "/api/rules/import/preview", importReq(map[string]any{"mapping": []string{"x"}}))
	if rr.Code != http.StatusBadRequest || !strings.Contains(rr.Body.String(), "mapping") {
		t.Fatalf("bad mapping type: %d %s", rr.Code, rr.Body.String())
	}
}

// A row whose line is not mapped shows the mapping flag only, not the
// validation finding that follows from it.
func TestImportUnmappedRowHasNoValidationNoise(t *testing.T) {
	s, _ := importServer(t)
	rr := do(s, http.MethodPost, "/api/rules/import/preview", importReq(map[string]any{"mapping": map[string]string{"LB-HK P": "group:hk-residential"}}))
	p := previewOf(t, rr)
	row := rowByLine(p, 18) // DOMAIN-SUFFIX,ai.example.net,AI → US → unmapped
	if row == nil {
		t.Fatalf("no row: %s", rr.Body.String())
	}
	codes := strings.Join(flagCodes(row), ",")
	if !strings.Contains(codes, "target_unmapped") || strings.Contains(codes, "exit_not_found") || strings.Contains(codes, "group_not_found") {
		t.Fatalf("flags %s", codes)
	}
	if row["status"] != "blocked" {
		t.Fatalf("status %v", row["status"])
	}
}

const partialConfig = `proxy-groups:
  - { name: P, type: select, proxies: ["LB-HK P"] }
  - { name: "LB-HK P", type: load-balance, use: [X] }
rule-providers:
  A: { type: http, behavior: classical, url: "https://rules.example.org/a.list" }
  B: { type: http, behavior: classical, url: "https://rules.example.org/b.list" }
rules:
  - RULE-SET,A,P
  - RULE-SET,B,P
  - DOMAIN-KEYWORD,example,P
  - MATCH,P
`

// accept_codes accepts every row of one code at once; rows still show
// individually, the summary counts them, and the digest covers the choice.
func TestImportAcceptCodes(t *testing.T) {
	s, f := importServer(t)
	f.mu.Lock()
	f.body["https://rules.example.org/a.list"] = "DOMAIN-SUFFIX,a.example.net\nPROCESS-NAME,a.exe\n"
	f.body["https://rules.example.org/b.list"] = "DOMAIN-SUFFIX,b.example.net\nPROCESS-NAME,b.exe\nPROCESS-NAME,c.exe\n"
	f.mu.Unlock()
	body := map[string]any{"config": partialConfig, "selection": "", "mapping": map[string]string{"LB-HK P": "group:hk-residential"}, "fetch_rule_sets": true}
	p := previewUntil(t, s, body, func(p map[string]any) bool {
		for _, rs := range p["rule_sets"].([]any) {
			if rs.(map[string]any)["state"] != "available" {
				return false
			}
		}
		return true
	})
	if p["can_confirm"] == true {
		t.Fatal("confirmable without accepting")
	}
	sum := map[string]map[string]any{}
	for _, x := range p["accept_summary"].([]any) {
		m := x.(map[string]any)
		sum[m["code"].(string)] = m
	}
	if l := sum["ruleset_partial"]["lines"].([]any); len(l) != 2 || sum["ruleset_partial"]["accepted"] != float64(0) {
		t.Fatalf("summary %v", sum)
	}
	if sum["keyword_expanded"] == nil {
		t.Fatalf("keyword code missing: %v", sum)
	}
	delete(body, "fetch_rule_sets")
	body["accept_codes"] = []string{"ruleset_partial", "keyword_expanded"}
	p2 := previewOf(t, do(s, http.MethodPost, "/api/rules/import/preview", importReq(body)))
	if p2["can_confirm"] != true {
		t.Fatalf("not confirmable with accept_codes: %v", p2["rows"])
	}
	for _, x := range p2["accept_summary"].([]any) {
		m := x.(map[string]any)
		if m["by_code"] != true || m["accepted"] != float64(len(m["lines"].([]any))) {
			t.Fatalf("summary with codes %v", m)
		}
	}
	for _, line := range []int{8, 9} {
		row := rowByLine(p2, line)
		if row["status"] != "accepted" {
			t.Fatalf("row %d %v", line, row)
		}
	}
	// The same acceptance per line gives the same plan and digest; no
	// acceptance a different one.
	perLine := map[string]any{"config": partialConfig, "selection": "", "mapping": map[string]string{"LB-HK P": "group:hk-residential"},
		"accept": map[string][]string{"8": {"ruleset_partial"}, "9": {"ruleset_partial"}, "10": {"keyword_expanded"}}}
	p3 := previewOf(t, do(s, http.MethodPost, "/api/rules/import/preview", importReq(perLine)))
	if p3["digest"] != p2["digest"] {
		t.Fatal("per-line and per-code acceptance differ")
	}
	if p["digest"] == p2["digest"] {
		t.Fatal("digest does not cover the acceptance")
	}
	// Confirming with the code list writes; the accepted codes are recorded.
	body["digest"] = p2["digest"]
	if rr := do(s, http.MethodPost, "/api/rules/import/confirm", importReq(body)); rr.Code != 200 {
		t.Fatalf("confirm: %s", rr.Body.String())
	}
	tp, _ := s.topology()
	n := 0
	for _, r := range tp.Rules {
		if r.Origin == model.OriginMihomo && r.MatchType == model.MatchRuleSet && strings.Join(r.Accepted, ",") == "ruleset_partial" {
			n++
		}
	}
	if n != 2 {
		t.Fatalf("accepted codes recorded on %d rules", n)
	}
	// Unknown codes are refused.
	body["accept_codes"] = []string{"target_unmapped"}
	if rr := do(s, http.MethodPost, "/api/rules/import/preview", importReq(body)); rr.Code != http.StatusUnprocessableEntity || !strings.Contains(rr.Body.String(), "bad_accept") {
		t.Fatalf("unknown code: %d %s", rr.Code, rr.Body.String())
	}
}

// A provider URL carrying a token: the preview and the topology show the
// URL without it, the download gets it, confirm stores it in the
// credential store.
func TestImportProviderURLSecret(t *testing.T) {
	s, f, rec := authServer(t)
	tok := "fake-provider-token-1618"
	f.mu.Lock()
	f.body["https://rules.example.org/p.list"] = "DOMAIN-SUFFIX,p.example.net\n"
	f.mu.Unlock()
	cfg := strings.Replace(partialConfig, `url: "https://rules.example.org/a.list"`, `url: "https://rules.example.org/p.list?token=`+tok+`"`, 1)
	cfg = strings.Replace(cfg, "  - RULE-SET,B,P\n", "", 1)
	cfg = strings.Replace(cfg, "  - DOMAIN-KEYWORD,example,P\n", "", 1)
	body := map[string]any{"config": cfg, "selection": "", "mapping": map[string]string{"LB-HK P": "group:hk-residential"}, "fetch_rule_sets": true}
	var all strings.Builder
	p := previewUntil(t, s, body, func(p map[string]any) bool {
		b, _ := json.Marshal(p)
		all.Write(b)
		rs := p["rule_sets"].([]any)
		return len(rs) == 1 && rs[0].(map[string]any)["state"] == "available"
	})
	rs := p["rule_sets"].([]any)[0].(map[string]any)
	if rs["url"] != "https://rules.example.org/p.list" || rs["auth"] != "query" {
		t.Fatalf("rule-set view %v", rs)
	}
	rec.mu.Lock()
	var got bool
	for _, o := range rec.opts {
		if o.Auth != nil && o.Auth.Query == "token="+tok && o.AuthOrigin == "https://rules.example.org" {
			got = true
		}
	}
	rec.mu.Unlock()
	if !got {
		t.Fatal("download did not get the credential")
	}
	delete(body, "fetch_rule_sets")
	body["digest"] = p["digest"]
	rr := do(s, http.MethodPost, "/api/rules/import/confirm", importReq(body))
	if rr.Code != 200 {
		t.Fatalf("confirm %s", rr.Body.String())
	}
	all.WriteString(rr.Body.String())
	all.WriteString(do(s, http.MethodGet, "/api/topology", nil).Body.String())
	all.WriteString(do(s, http.MethodGet, "/api/rule-sets", nil).Body.String())
	if strings.Contains(all.String(), tok) {
		t.Fatal("token in a response")
	}
	tp, _ := s.topology()
	if len(tp.RuleSets) != 1 || tp.RuleSets[0].URL != "https://rules.example.org/p.list" {
		t.Fatalf("stored %+v", tp.RuleSets)
	}
	a, err := s.ruleSetAuth(tp.RuleSets[0].ID)
	if err != nil || a == nil || a.Query != "token="+tok {
		t.Fatalf("credential not stored: %v", err)
	}
	for _, h := range grepTree(t, s.DataDir, tok) {
		t.Fatalf("token in %s", h)
	}
}

// ruleSetViewByID lists the rule-sets until id is in the answer (a read can
// meet the store busy with the background fetch's status write).
func ruleSetViewByID(t *testing.T, s *Server, id string) map[string]any {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		rr := do(s, http.MethodGet, "/api/rule-sets", nil)
		var l struct {
			RuleSets []map[string]any `json:"rule_sets"`
		}
		if rr.Code == http.StatusOK && json.Unmarshal(rr.Body.Bytes(), &l) == nil {
			for _, x := range l.RuleSets {
				if x["rule_set"].(map[string]any)["id"] == id {
					return x
				}
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("rule-set %s not listed: %d %s", id, rr.Code, rr.Body.String())
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// Exclusions: set on create and edit in the set's notation, stored in the
// classical form, refused per line, shown with their effect; a subscription
// update keeps them (a failed one keeps the old content); the tester uses
// the effective entries.
func TestRuleSetExclusions(t *testing.T) {
	s, f := importServer(t)
	const url = "https://rules.example.org/video.list"
	f.mu.Lock()
	f.body[url] = "DOMAIN-SUFFIX,video.example\nDOMAIN-SUFFIX,big.example\nDOMAIN,x.big.example\nDOMAIN-SUFFIX,huge.example\nDOMAIN-KEYWORD,adword\nIP-CIDR,198.51.100.0/24\n"
	f.mu.Unlock()
	// Refused lines come back one by one, nothing is stored.
	rr := do(s, http.MethodPost, "/api/rule-sets", []byte(`{"name":"Video","url":"`+url+`","format":"surge-list","exclude":["DOMAIN-SUFFIX,big.example","PROCESS-NAME,x.exe","big.example","DOMAIN,bad..example"]}`))
	if rr.Code != http.StatusUnprocessableEntity {
		t.Fatalf("%d %s", rr.Code, rr.Body.String())
	}
	var bad struct {
		Code  string `json:"code"`
		Lines []struct {
			Line  int    `json:"line"`
			Text  string `json:"text"`
			Error string `json:"error"`
		} `json:"lines"`
	}
	json.Unmarshal(rr.Body.Bytes(), &bad)
	if bad.Code != "bad_exclude" || len(bad.Lines) != 3 || bad.Lines[0].Line != 2 || bad.Lines[1].Line != 3 || bad.Lines[2].Line != 4 {
		t.Fatalf("%s", rr.Body.String())
	}
	if tp, _ := s.topology(); len(tp.RuleSets) != 0 {
		t.Fatal("stored despite refused lines")
	}
	rr = do(s, http.MethodPost, "/api/rule-sets", []byte(`{"name":"Video","url":"`+url+`","format":"surge-list","exclude":["domain-suffix,Big.example","","# note","DOMAIN-SUFFIX,huge.example","IP-CIDR,198.51.100.0/26","DOMAIN,gone.example"]}`))
	if rr.Code != 201 {
		t.Fatal(rr.Body.String())
	}
	var v struct {
		RuleSet model.RuleSet `json:"rule_set"`
	}
	json.Unmarshal(rr.Body.Bytes(), &v)
	id := v.RuleSet.ID
	if fmt.Sprint(v.RuleSet.Exclude) != "[DOMAIN-SUFFIX,big.example DOMAIN-SUFFIX,huge.example IP-CIDR,198.51.100.0/26 DOMAIN,gone.example]" {
		t.Fatalf("stored %v", v.RuleSet.Exclude)
	}
	deadline := time.Now().Add(5 * time.Second)
	var view map[string]any
	for {
		view = ruleSetViewByID(t, s, id)
		if ex, ok := view["exclusions"].(map[string]any); ok && ex["checked"] == true {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("no preview: %v", view)
		}
		time.Sleep(20 * time.Millisecond)
	}
	ex := view["exclusions"].(map[string]any)
	// 6 fetched; big.example + x.big.example + huge.example removed; the
	// /24 becomes a /26 and a /25.
	if ex["fetched"] != float64(6) || ex["effective"] != float64(4) || ex["removed"] != float64(3) || ex["stale"] != float64(1) {
		t.Fatalf("preview %v", ex)
	}
	items := ex["items"].([]any)
	if it := items[0].(map[string]any); it["removed"] != float64(2) {
		t.Fatalf("item %v", it)
	}
	if it := items[2].(map[string]any); it["trimmed"] != float64(1) {
		t.Fatalf("item %v", it)
	}
	if it := items[3].(map[string]any); it["stale"] != true || it["notice"] == "" {
		t.Fatalf("item %v", it)
	}
	// A narrower exclusion that a remaining entry still covers is refused
	// when it is added; the existing ones stay acceptable.
	rr = do(s, http.MethodPatch, "/api/rule-sets/"+id, []byte(`{"exclude":["DOMAIN-SUFFIX,big.example","DOMAIN-SUFFIX,huge.example","IP-CIDR,198.51.100.0/26","DOMAIN,gone.example","DOMAIN,a.video.example"]}`))
	if rr.Code != http.StatusUnprocessableEntity || !strings.Contains(rr.Body.String(), "DOMAIN-SUFFIX,video.example") || !strings.Contains(rr.Body.String(), `"line":5`) {
		t.Fatalf("narrower: %d %s", rr.Code, rr.Body.String())
	}
	// The rule using it, and a later rule listing an excluded name exactly.
	s.Store.Update(func(tp *model.Topology) (bool, error) {
		tp.Rules = append([]model.Rule{
			{ID: "video", Name: "video", Enabled: true, Manual: true, MatchType: model.MatchRuleSet, RuleSet: id, TargetGroup: "jp"},
			{ID: "later", Name: "later", Enabled: true, Manual: true, MatchType: model.MatchDomain, MatchValue: "x.big.example", TargetGroup: "us"},
		}, tp.Rules...)
		return true, nil
	})
	test := func(body, wantRule string) {
		t.Helper()
		rr := do(s, http.MethodPost, "/api/rules/test", []byte(body))
		if rr.Code != 200 {
			t.Fatal(rr.Body.String())
		}
		var out struct {
			Rule *struct {
				ID string `json:"id"`
			} `json:"rule"`
		}
		json.Unmarshal(rr.Body.Bytes(), &out)
		got := ""
		if out.Rule != nil {
			got = out.Rule.ID
		}
		if got != wantRule {
			t.Fatalf("%s: rule %q, want %q (%s)", body, got, wantRule, rr.Body.String())
		}
	}
	test(`{"name":"a.video.example"}`, "video")
	test(`{"name":"x.big.example"}`, "later")
	test(`{"name":"o.big.example"}`, "")
	test(`{"address":"198.51.100.9"}`, "")
	test(`{"address":"198.51.100.99"}`, "video")
	// An update with new content keeps the exclusions; the one that no
	// longer corresponds to anything is a notice, the others still apply.
	f.mu.Lock()
	f.body[url] = "DOMAIN-SUFFIX,video.example\nDOMAIN-SUFFIX,big.example\nDOMAIN,gone.example\n"
	f.mu.Unlock()
	do(s, http.MethodPost, "/api/rule-sets/"+id+"/update", nil)
	deadline = time.Now().Add(5 * time.Second)
	for {
		view = ruleSetViewByID(t, s, id)
		ex = view["exclusions"].(map[string]any)
		if ex["fetched"] == float64(3) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("update not active: %v", view)
		}
		time.Sleep(20 * time.Millisecond)
	}
	if ex["effective"] != float64(1) || ex["stale"] != float64(2) || len(view["rule_set"].(map[string]any)["exclude"].([]any)) != 4 {
		t.Fatalf("after update %v", view)
	}
	// A failed update keeps the active content and the exclusions.
	f.mu.Lock()
	delete(f.body, url)
	f.mu.Unlock()
	do(s, http.MethodPost, "/api/rule-sets/"+id+"/update", nil)
	deadline = time.Now().Add(5 * time.Second)
	for {
		if x := s.loadRSStatus()[id]; x != nil && x.LastError != "" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("no failure recorded")
		}
		time.Sleep(20 * time.Millisecond)
	}
	view = ruleSetViewByID(t, s, id)
	if ex := view["exclusions"].(map[string]any); ex["fetched"] != float64(3) || ex["effective"] != float64(1) {
		t.Fatalf("after failed update %v", view)
	}
	test(`{"name":"q.big.example"}`, "")
	// Clearing them.
	rr = do(s, http.MethodPatch, "/api/rule-sets/"+id, []byte(`{"exclude":[]}`))
	if rr.Code != 200 || strings.Contains(rr.Body.String(), `"exclusions"`) {
		t.Fatalf("%d %s", rr.Code, rr.Body.String())
	}
	test(`{"name":"q.big.example"}`, "video")
	// A topology carrying exclusions not in the stored form, or of a kind
	// the set's format cannot hold, does not validate.
	tp, _ := s.topology()
	for _, ex := range [][]string{{"big.example"}, {"DOMAIN-SUFFIX,Big.example"}} {
		x := tp
		x.RuleSets = append([]model.RuleSet(nil), tp.RuleSets...)
		x.RuleSets[0].Exclude = ex
		if !hasIssue(validateIssues(x), "bad_rule_set") {
			t.Errorf("exclusions %v validated", ex)
		}
	}
}

func hasIssue(is []validate.Issue, code string) bool {
	for _, i := range is {
		if i.Code == code {
			return true
		}
	}
	return false
}
