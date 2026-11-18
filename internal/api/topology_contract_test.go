package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/radowitz/meridian/internal/defaults"
	"github.com/radowitz/meridian/internal/model"
)

// contractServer seeds every independent resource with synthetic values:
// two rule-sets, an import mapping and the sniff setting
// in the stored document, remote access through its own endpoint.
func contractServer(t *testing.T) *Server {
	t.Helper()
	s := newTest(t)
	do(s, http.MethodGet, "/api/topology", nil)
	topo, _, err := s.Store.Load()
	if err != nil {
		t.Fatal(err)
	}
	topo.RuleSets = []model.RuleSet{
		{ID: "rs1", Name: "规则集一", URL: "https://rules.example.net/one.list"},
		{ID: "rs2", Name: "规则集二", URL: "https://rules.example.net/two.list"},
	}
	topo.MihomoImport = &model.MihomoImport{Mapping: map[string]string{"Line": "group:hk"}, Rules: 3}
	topo.Settings.Sniff = &model.SniffSettings{Enabled: true, Ports: []int{443}}
	if err := s.Store.Save(topo); err != nil {
		t.Fatal(err)
	}
	raCall(t, s, http.MethodPut, "/api/remote-access", `{"endpoint":"home.example.net","listen_port":51999}`, 200)
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
	return canonJSON([]any{topo.RuleSets, topo.MihomoImport, topo.RemoteAccess, topo.Settings.Sniff})
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
	for _, k := range []string{"rule_sets", "mihomo_import", "remote_access"} {
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
	for _, k := range []string{"rule_sets", "mihomo_import", "remote_access"} {
		delete(d, k)
	}
	delete(settingsOf(d), "sniff")
	renameGateway(d, "网关 2")
	expectSaved(t, s, d, "")
	d = clone(t, doc)
	for _, k := range []string{"rule_sets", "mihomo_import", "remote_access"} {
		d[k] = nil
	}
	settingsOf(d)["sniff"] = nil
	expectSaved(t, s, d, "")
	if independentSnapshot(t, s) != base {
		t.Fatal("omitted / null changed an independent block")
	}

	// Order of the ID-keyed lists carries no meaning.
	d = clone(t, doc)
	rsl := d["rule_sets"].([]any)
	d["rule_sets"] = []any{rsl[1], rsl[0]}
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
		{"rule_sets", func(d map[string]any) { d["rule_sets"] = []any{} }, []string{"rs1", "rs2"}},
		{"rule_sets", func(d map[string]any) {
			d["rule_sets"] = append(d["rule_sets"].([]any), map[string]any{"id": "rs-new", "name": "新", "url": "https://rules.example.net/new.list"})
		}, []string{"rs-new"}},
		{"rule_sets", func(d map[string]any) {
			d["rule_sets"].([]any)[0].(map[string]any)["exclude"] = []any{"DOMAIN-SUFFIX,example.org"}
		}, []string{"rs1"}},
		{"mihomo_import", func(d map[string]any) {
			d["mihomo_import"].(map[string]any)["mapping"] = map[string]any{"Line": "direct"}
		}, nil},
		{"remote_access", func(d map[string]any) { d["remote_access"].(map[string]any)["listen_port"] = 51998 }, []string{"settings"}},
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
	d["rule_sets"] = []any{}
	settingsOf(d)["sniff"] = map[string]any{"enabled": false, "ports": []any{80}}
	d["remote_access"] = map[string]any{"enabled": false}
	out := expectRefused(t, s, d, "", "rule_sets", "remote_access", "settings.sniff")
	if !strings.Contains(out.Error, "/api/rule-sets") || !strings.Contains(out.Error, "/api/sniff") {
		t.Fatalf("message does not name the endpoints: %s", out.Error)
	}
	// A draft save follows the same contract.
	d = clone(t, doc)
	d["rule_sets"] = []any{}
	expectRefused(t, s, d, "?draft=1", "rule_sets")

	// ?import=1 (an export brought back) writes the blocks it always wrote;
	// remote access stays owned by its endpoint.
	d = clone(t, doc)
	d["remote_access"].(map[string]any)["listen_port"] = 51998
	expectRefused(t, s, d, "?import=1", "remote_access")
	d = clone(t, doc)
	d["rule_sets"] = []any{d["rule_sets"].([]any)[1]}
	expectSaved(t, s, d, "?import=1")
	if topo, _, _ := s.Store.Load(); len(topo.RuleSets) != 1 || topo.RuleSets[0].ID != "rs2" {
		t.Fatalf("import did not write the rule-sets: %+v", topo.RuleSets)
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
	sent := model.Topology{RuleSets: []model.RuleSet{{ID: "a", Name: "A", URL: "https://rules.example.net/a.list"}}}
	sp := presenceOf([]byte(`{"rule_sets":[{}]}`))
	guard := independentGuard(sp, sent, false)
	next := sent
	if err := guard(model.Topology{RuleSets: []model.RuleSet{{ID: "a", Name: "B", URL: "https://rules.example.net/a.list"}}}, &next); err == nil {
		t.Fatal("guard accepted a document changed underneath")
	}
	next = model.Topology{}
	prev := model.Topology{RuleSets: sent.RuleSets, Settings: model.Settings{Sniff: &model.SniffSettings{Enabled: true}}}
	if err := guard(prev, &next); err != nil || len(next.RuleSets) != 1 || next.Settings.Sniff == nil || !next.Settings.Sniff.Enabled {
		t.Fatalf("guard did not keep the stored blocks: %v %+v", err, next)
	}
}

// The exported document (GET /api/topology) of a gateway with the query
// journal on, the forwarder recording names, device labels and a rotated
// SOCKS credential: it carries switches and references — the journal's
// switch, the forwarder's settings, the credential's id — and nothing else
// of them: no credential version or baseline, no device label, no setting
// of the link journal (it has none), no username or password. Importing it
// back is accepted, changes no node's digest and keeps what the document
// does not hold: the credential's version, the labels, the switch.
func TestExportHoldsSwitchesAndReferencesOnly(t *testing.T) {
	s := newTest(t)
	s.DNSLog = &fakeDNSLog{st: verifiedStatus()}
	user, pass := "su-"+rnd(t, 8), "sp-"+rnd(t, 10)
	var sc struct{ Credential struct{ ID string } }
	decode(t, do(s, http.MethodPost, "/api/socks-credentials", mustJSON(map[string]any{"name": "路由器", "username": user, "password": pass})), &sc)
	topo := defaults.ExternalExample()
	for i := range topo.Nodes {
		if topo.Nodes[i].External != nil {
			topo.Nodes[i].External.CredentialID = sc.Credential.ID
		}
	}
	for _, step := range []struct {
		method, path string
		body         any
	}{
		{http.MethodPut, "/api/topology", topo},
		{http.MethodPut, "/api/sniff", map[string]any{"enabled": true, "record_names": true}},
		{http.MethodPut, "/api/dns-log", map[string]any{"enabled": true, "acknowledge": true}},
		{http.MethodPut, "/api/sniff/devices/192.0.2.10/label", map[string]string{"label": "label-of-a-device"}},
		{http.MethodPut, "/api/socks-credentials/" + sc.Credential.ID + "/secret", map[string]any{"username": user + "2", "password": pass + "2"}},
	} {
		if rr := do(s, step.method, step.path, mustJSON(step.body)); rr.Code != 200 {
			t.Fatalf("%s %s: %d %s", step.method, step.path, rr.Code, rr.Body.String())
		}
	}
	before := nodeDigests(t, s)
	doc := fetchDoc(t, s)
	raw := string(mustJSON(doc))
	settings := settingsOf(doc)
	if on, _ := settings["dns_log"].(map[string]any); on["enabled"] != true {
		t.Fatalf("the export lacks the query journal's switch: %v", settings["dns_log"])
	}
	if sn, _ := settings["sniff"].(map[string]any); sn["enabled"] != true || sn["record_names"] != true {
		t.Fatalf("the export lacks the forwarder's settings: %v", settings["sniff"])
	}
	if !strings.Contains(raw, `"credential_id":"`+sc.Credential.ID+`"`) {
		t.Fatal("the export lacks the SOCKS credential's id")
	}
	for _, bad := range []string{user, pass, "socks_version", strings.TrimSpace(socksVersionMarker), "baseline", "label-of-a-device", deviceLabelsKey, "link_log", "link-journal", "linklog", "dnslog", "audit", "journal"} {
		if strings.Contains(raw, bad) {
			t.Errorf("the export carries %q", bad)
		}
	}
	// Imported back as it is: accepted, and nothing compiled changes.
	if rr := putDoc(s, doc, "?import=1"); rr.Code != 200 {
		t.Fatalf("import of the export: %d %s", rr.Code, rr.Body.String())
	}
	if diff := changedNodes(before, nodeDigests(t, s)); diff != "" {
		t.Fatalf("importing the export changed the digest of: %s", diff)
	}
	tp, err := s.topology()
	if err != nil || !tp.DNSLogOn() {
		t.Fatalf("the import turned the query journal off (%v)", err)
	}
	b, err := s.compileTopo(tp)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for p, body := range b.Files {
		if isExtProxyConfig(p) {
			found = strings.Contains(body, socksVersionMarker+sc.Credential.ID+"=2 ")
		}
	}
	if !found {
		t.Fatal("after the import the carrier's config no longer carries the credential's version 2")
	}
	if ls, err := s.deviceLabels(); err != nil || len(ls) != 1 || ls[0].Label != "label-of-a-device" {
		t.Fatalf("the import lost the device label: %v %v", ls, err)
	}
}
