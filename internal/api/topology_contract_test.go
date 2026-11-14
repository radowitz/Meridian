package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/radowitz/meridian/internal/model"
)

// contractServer seeds every independent resource with synthetic values:
// two service groups, a rule-set, an import mapping and the sniff setting
// in the stored document, remote access through its own endpoint.
func contractServer(t *testing.T) *Server {
	t.Helper()
	s := newTest(t)
	do(s, http.MethodGet, "/api/topology", nil)
	topo, _, err := s.Store.Load()
	if err != nil {
		t.Fatal(err)
	}
	topo.ServiceGroups = []model.ServiceGroup{
		{ID: "svc-a", Name: "服务 A", TargetGroup: "hk"},
		{ID: "svc-b", Name: "服务 B", TargetAction: model.ActionDirect},
	}
	topo.RuleSets = []model.RuleSet{{ID: "rs1", Name: "规则集一", URL: "https://rules.example.net/one.list"}}
	topo.MihomoImport = &model.MihomoImport{Mapping: map[string]string{"Line": "group:hk"}, Rules: 3}
	topo.Settings.Sniff = &model.SniffSettings{Enabled: true, Ports: []int{443}}
	if err := s.Store.Save(topo); err != nil {
		t.Fatal(err)
	}
	raCall(t, s, http.MethodPut, "/api/remote-access", `{"endpoint":"home.example.net","listen_port":51900}`, 200)
	return s
}

func fetchDoc(t *testing.T, s *Server) map[string]any {
	t.Helper()
	rr := do(s, http.MethodGet, "/api/topology", nil)
	var doc map[string]any
	if rr.Code != 200 || json.Unmarshal(rr.Body.Bytes(), &doc) != nil {
		t.Fatalf("get: %d %s", rr.Code, rr.Body.String())
	}
	return doc
}

func storedRaw(t *testing.T, s *Server) string {
	t.Helper()
	raw, ok, err := s.Store.Get("topology")
	if err != nil || !ok {
		t.Fatal(ok, err)
	}
	return raw
}

type contractRefusal struct {
	Error  string               `json:"error"`
	Code   string               `json:"code"`
	Fields []independentRefusal `json:"fields"`
}

func putDoc(s *Server, doc map[string]any, query string) *httptest.ResponseRecorder {
	return do(s, http.MethodPut, "/api/topology"+query, mustJSON(doc))
}

// expectRefused: 409 independent_resource_changed naming exactly fields
// (in order), and the stored document byte for byte as before.
func expectRefused(t *testing.T, s *Server, doc map[string]any, query string, fields ...string) contractRefusal {
	t.Helper()
	before := storedRaw(t, s)
	rr := putDoc(s, doc, query)
	var out contractRefusal
	if rr.Code != http.StatusConflict || json.Unmarshal(rr.Body.Bytes(), &out) != nil || out.Code != codeIndependentChanged {
		t.Fatalf("want 409 %s, got %d %s", codeIndependentChanged, rr.Code, rr.Body.String())
	}
	var got []string
	for _, f := range out.Fields {
		got = append(got, f.Field)
		if f.Endpoint == "" || len(f.Methods) == 0 || f.Resource == "" {
			t.Fatalf("refusal without endpoint: %+v", f)
		}
	}
	if strings.Join(got, ",") != strings.Join(fields, ",") {
		t.Fatalf("fields %v, want %v (%s)", got, fields, rr.Body.String())
	}
	if after := storedRaw(t, s); after != before {
		t.Fatal("a refused save changed the stored document")
	}
	return out
}

func expectSaved(t *testing.T, s *Server, doc map[string]any, query string) {
	t.Helper()
	if rr := putDoc(s, doc, query); rr.Code != 200 {
		t.Fatalf("want 200, got %d %s", rr.Code, rr.Body.String())
	}
}

// independentSnapshot is the stored independent blocks, for "unchanged".
func independentSnapshot(t *testing.T, s *Server) string {
	t.Helper()
	topo, _, err := s.Store.Load()
	if err != nil {
		t.Fatal(err)
	}
	return canonJSON([]any{topo.ServiceGroups, topo.RuleSets, topo.MihomoImport, topo.RemoteAccess, topo.Settings.Sniff})
}

func clone(t *testing.T, doc map[string]any) map[string]any {
	t.Helper()
	var out map[string]any
	if err := json.Unmarshal(mustJSON(doc), &out); err != nil {
		t.Fatal(err)
	}
	return out
}

func settingsOf(doc map[string]any) map[string]any { return doc["settings"].(map[string]any) }

func renameGateway(doc map[string]any, name string) {
	for _, n := range doc["nodes"].([]any) {
		if m := n.(map[string]any); m["id"] == localNodeID {
			m["name"] = name
		}
	}
}

func gatewayName(t *testing.T, s *Server) string {
	t.Helper()
	topo, _, _ := s.Store.Load()
	for _, n := range topo.Nodes {
		if n.ID == localNodeID {
			return n.Name
		}
	}
	return ""
}

// Omitted, null and equal values are accepted (the stored blocks stay);
// a different value of any independent resource refuses the whole save.
func TestTopologySaveIndependentContract(t *testing.T) {
	s := contractServer(t)
	base := independentSnapshot(t, s)
	doc := fetchDoc(t, s)
	for _, k := range []string{"service_groups", "rule_sets", "mihomo_import", "remote_access"} {
		if doc[k] == nil {
			t.Fatalf("fixture: %s not in the document", k)
		}
	}

	// An honest round trip of the fetched document, with an edit of a field
	// the save owns.
	d := clone(t, doc)
	renameGateway(d, "网关（改名）")
	expectSaved(t, s, d, "")
	if gatewayName(t, s) != "网关（改名）" || independentSnapshot(t, s) != base {
		t.Fatal("round trip did not save the edit or changed an independent block")
	}

	// Old clients: fields omitted, or null.
	d = clone(t, doc)
	for _, k := range []string{"service_groups", "rule_sets", "mihomo_import", "remote_access"} {
		delete(d, k)
	}
	delete(settingsOf(d), "sniff")
	renameGateway(d, "网关 2")
	expectSaved(t, s, d, "")
	d = clone(t, doc)
	for _, k := range []string{"service_groups", "rule_sets", "mihomo_import", "remote_access"} {
		d[k] = nil
	}
	settingsOf(d)["sniff"] = nil
	expectSaved(t, s, d, "")
	if independentSnapshot(t, s) != base {
		t.Fatal("omitted / null changed an independent block")
	}

	// Order of the ID-keyed lists carries no meaning.
	d = clone(t, doc)
	sg := d["service_groups"].([]any)
	d["service_groups"] = []any{sg[1], sg[0]}
	expectSaved(t, s, d, "")
	if independentSnapshot(t, s) != base {
		t.Fatal("reordered list changed the stored order")
	}

	// Different values: refused, nothing written (the gateway rename in the
	// same request is not saved either).
	cases := []struct {
		field string
		edit  func(d map[string]any)
		items []string
	}{
		{"service_groups", func(d map[string]any) {
			d["service_groups"].([]any)[0].(map[string]any)["target_group"] = "us"
		}, []string{"svc-a"}},
		{"service_groups", func(d map[string]any) { d["service_groups"] = []any{} }, []string{"svc-a", "svc-b"}},
		{"service_groups", func(d map[string]any) {
			d["service_groups"] = append(d["service_groups"].([]any), map[string]any{"id": "svc-new", "name": "新", "target_action": "reject"})
		}, []string{"svc-new"}},
		{"rule_sets", func(d map[string]any) {
			d["rule_sets"].([]any)[0].(map[string]any)["exclude"] = []any{"DOMAIN-SUFFIX,example.org"}
		}, []string{"rs1"}},
		{"mihomo_import", func(d map[string]any) {
			d["mihomo_import"].(map[string]any)["mapping"] = map[string]any{"Line": "direct"}
		}, nil},
		{"remote_access", func(d map[string]any) { d["remote_access"].(map[string]any)["listen_port"] = 51901 }, []string{"settings"}},
		{"remote_access", func(d map[string]any) { d["remote_access"].(map[string]any)["enabled"] = true }, []string{"settings"}},
		{"settings.sniff", func(d map[string]any) { settingsOf(d)["sniff"] = map[string]any{"enabled": false} }, nil},
	}
	for _, c := range cases {
		d := clone(t, doc)
		renameGateway(d, "不应保存")
		c.edit(d)
		out := expectRefused(t, s, d, "", c.field)
		if strings.Join(out.Fields[0].Items, ",") != strings.Join(c.items, ",") {
			t.Fatalf("%s items %v, want %v", c.field, out.Fields[0].Items, c.items)
		}
		if gatewayName(t, s) == "不应保存" {
			t.Fatal("refused save wrote a field it owns")
		}
	}
	// Every offending field at once, in a fixed order.
	d = clone(t, doc)
	d["service_groups"] = []any{}
	settingsOf(d)["sniff"] = map[string]any{"enabled": false, "ports": []any{80}}
	d["remote_access"] = map[string]any{"enabled": false}
	out := expectRefused(t, s, d, "", "service_groups", "remote_access", "settings.sniff")
	if !strings.Contains(out.Error, "/api/service-groups") || !strings.Contains(out.Error, "/api/sniff") {
		t.Fatalf("message does not name the endpoints: %s", out.Error)
	}
	// A draft save follows the same contract.
	d = clone(t, doc)
	d["service_groups"] = []any{}
	expectRefused(t, s, d, "?draft=1", "service_groups")

	// ?import=1 (an export brought back) writes the blocks it always wrote;
	// remote access stays owned by its endpoint.
	d = clone(t, doc)
	d["remote_access"].(map[string]any)["listen_port"] = 51901
	expectRefused(t, s, d, "?import=1", "remote_access")
	d = clone(t, doc)
	d["service_groups"] = []any{d["service_groups"].([]any)[1]}
	expectSaved(t, s, d, "?import=1")
	if topo, _, _ := s.Store.Load(); len(topo.ServiceGroups) != 1 || topo.ServiceGroups[0].ID != "svc-b" {
		t.Fatalf("import did not write the service groups: %+v", topo.ServiceGroups)
	}
}

// A document fetched before another client changed an independent
// resource through its own endpoint: refused with that resource named (it
// cannot be told apart from an edit, and keeping the stored value would be
// the silent drop). Re-fetching resolves it; the endpoint's change stays.
func TestTopologySaveStaleDocument(t *testing.T) {
	steps := []struct {
		field string
		via   func(t *testing.T, s *Server)
		check func(topo model.Topology) bool
	}{
		{"service_groups", func(t *testing.T, s *Server) {
			if rr := do(s, http.MethodPatch, "/api/service-groups/svc-a", []byte(`{"target":"group:us"}`)); rr.Code != 200 {
				t.Fatalf("patch: %d %s", rr.Code, rr.Body.String())
			}
		}, func(topo model.Topology) bool { return topo.ServiceGroups[0].TargetGroup == "us" }},
		{"rule_sets", func(t *testing.T, s *Server) {
			if rr := do(s, http.MethodPatch, "/api/rule-sets/rs1", []byte(`{"name":"规则集（改名）"}`)); rr.Code != 200 {
				t.Fatalf("patch: %d %s", rr.Code, rr.Body.String())
			}
		}, func(topo model.Topology) bool { return topo.RuleSets[0].Name == "规则集（改名）" }},
		{"remote_access", func(t *testing.T, s *Server) {
			raCall(t, s, http.MethodPut, "/api/remote-access", `{"listen_port":51902}`, 200)
		}, func(topo model.Topology) bool { return topo.RemoteAccess.ListenPort == 51902 }},
		{"settings.sniff", func(t *testing.T, s *Server) {
			if rr := do(s, http.MethodPut, "/api/sniff", []byte(`{"enabled":false}`)); rr.Code != 200 {
				t.Fatalf("sniff: %d %s", rr.Code, rr.Body.String())
			}
		}, func(topo model.Topology) bool { return topo.Settings.Sniff != nil && !topo.Settings.Sniff.Enabled }},
	}
	for _, st := range steps {
		t.Run(st.field, func(t *testing.T) {
			s := contractServer(t)
			stale := fetchDoc(t, s)
			st.via(t, s)
			d := clone(t, stale)
			renameGateway(d, "旧文档里的改动")
			out := expectRefused(t, s, d, "", st.field)
			if !strings.Contains(out.Error, "重新读取") {
				t.Fatalf("refusal does not say how to resolve a stale document: %s", out.Error)
			}
			// The same edit on a fresh document is saved; the endpoint's
			// change is kept.
			d = fetchDoc(t, s)
			renameGateway(d, "新文档里的改动")
			expectSaved(t, s, d, "")
			topo, _, _ := s.Store.Load()
			if !st.check(topo) || gatewayName(t, s) != "新文档里的改动" {
				t.Fatal("endpoint change lost or edit not saved")
			}
			// An old client that omits the field is not affected by staleness.
			d = clone(t, stale)
			delete(d, st.field)
			delete(settingsOf(d), "sniff")
			delete(d, "service_groups")
			delete(d, "rule_sets")
			delete(d, "remote_access")
			delete(d, "mihomo_import")
			expectSaved(t, s, d, "")
			topo, _, _ = s.Store.Load()
			if !st.check(topo) {
				t.Fatal("an omitting save turned the endpoint's change back")
			}
		})
	}
}

// The comparison itself: a rule-set URL shown without its credential is the
// stored URL; absent and zero values are equal; the store guard refuses a
// change made between the handler's check and the write.
func TestIndependentEquality(t *testing.T) {
	cur := model.Topology{
		RuleSets: []model.RuleSet{{ID: "rs", Name: "x", URL: "https://rules.example.net/a.list?token=fake-token-0000"}},
	}
	in := cur
	in.RuleSets = []model.RuleSet{{ID: "rs", Name: "x", URL: "https://rules.example.net/a.list?…"}}
	p := presenceOf([]byte(`{"rule_sets":[{}],"settings":{"sniff":{"enabled":false}},"mihomo_import":{},"remote_access":{"enabled":false}}`))
	in.Settings.Sniff = &model.SniffSettings{}
	in.MihomoImport = &model.MihomoImport{}
	in.RemoteAccess = &model.RemoteAccess{}
	if got := checkIndependent(p, in, cur, false); len(got) != 0 {
		t.Fatalf("equal values refused: %+v", got)
	}
	in.RuleSets[0].URL = "https://rules.example.net/b.list"
	if got := checkIndependent(p, in, cur, false); len(got) != 1 || got[0].Field != "rule_sets" {
		t.Fatalf("changed URL accepted: %+v", got)
	}

	// The guard: the stored document changed after the handler's check.
	sent := model.Topology{ServiceGroups: []model.ServiceGroup{{ID: "a", Name: "A", TargetAction: "direct"}}}
	sp := presenceOf([]byte(`{"service_groups":[{}]}`))
	guard := independentGuard(sp, sent, false)
	next := sent
	if err := guard(model.Topology{ServiceGroups: []model.ServiceGroup{{ID: "a", Name: "A", TargetAction: "reject"}}}, &next); err == nil {
		t.Fatal("guard accepted a document changed underneath")
	}
	next = model.Topology{}
	prev := model.Topology{ServiceGroups: sent.ServiceGroups, Settings: model.Settings{Sniff: &model.SniffSettings{Enabled: true}}}
	if err := guard(prev, &next); err != nil || len(next.ServiceGroups) != 1 || next.Settings.Sniff == nil || !next.Settings.Sniff.Enabled {
		t.Fatalf("guard did not keep the stored blocks: %v %+v", err, next)
	}
}
