package api

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/radowitz/meridian/internal/model"
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
