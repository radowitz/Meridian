package api

import (
	"encoding/json"
	"net/http"
	"testing"
)

func TestTemplatesAPI(t *testing.T) {
	s := newTest(t)
	rr := do(s, http.MethodGet, "/api/templates", nil)
	var list struct {
		Templates []struct {
			ID     string `json:"id"`
			Fields []struct {
				Key      string `json:"key"`
				Required bool   `json:"required"`
			} `json:"fields"`
		} `json:"templates"`
	}
	if rr.Code != 200 || json.Unmarshal(rr.Body.Bytes(), &list) != nil || len(list.Templates) != 4 {
		t.Fatalf("list: %d %s", rr.Code, rr.Body.String())
	}
	ids := ""
	for _, tp := range list.Templates {
		ids += tp.ID + " "
		for _, f := range tp.Fields {
			if tp.ID == "direct" && (f.Key == "relay.name" || f.Key == "hub.name") {
				t.Fatalf("direct asks for %s", f.Key)
			}
		}
	}
	if ids != "direct relay relay_hub ix " {
		t.Fatalf("templates %q", ids)
	}

	body := []byte(`{"gateway":{"lan_interface":"eth0","lan_ipv4":"192.0.2.88/24","router_ipv4":"192.0.2.1"},
		"exits":[{"name":"出口 A","region":"jp","endpoint_v4":"203.0.113.41","wan_interface":"eth0"},{"name":"出口 B","region":"us","endpoint_v4":"198.51.100.20","wan_interface":"eth0"}],
		"default_region":"jp"}`)
	before, _, _ := s.Store.Get("topology")
	rr = do(s, http.MethodPost, "/api/templates/direct/preview", body)
	var prev templatePreview
	if rr.Code != 200 || json.Unmarshal(rr.Body.Bytes(), &prev) != nil || !prev.Valid || len(prev.Paths) != 2 || !prev.Topology.DirectExits() {
		t.Fatalf("preview: %d %s", rr.Code, rr.Body.String())
	}
	if after, _, _ := s.Store.Get("topology"); after != before {
		t.Fatal("a preview changed the stored topology")
	}
	// The preview saves like any topology.
	if rr := do(s, http.MethodPut, "/api/topology", mustJSON(prev.Topology)); rr.Code != 200 {
		t.Fatalf("save preview: %d %s", rr.Code, rr.Body.String())
	}

	if rr := do(s, http.MethodPost, "/api/templates/relay/preview", body); rr.Code != 422 {
		t.Fatalf("relay without relay: %d %s", rr.Code, rr.Body.String())
	}
	if rr := do(s, http.MethodPost, "/api/templates/nope/preview", body); rr.Code != 404 {
		t.Fatalf("unknown: %d", rr.Code)
	}
	if rr := do(s, http.MethodPost, "/api/templates/direct/preview", []byte(`{"gateway":{},"extra":1}`)); rr.Code != 400 {
		t.Fatalf("unknown field: %d", rr.Code)
	}
}

// Every server in a template input needs its WAN NIC: an empty (or blank)
// one is refused with a 422 naming that server's field, for every role
// including the backup hub and backup relays; the detected name passes.
func TestTemplatePreviewRequiresWANInterface(t *testing.T) {
	s := newTest(t)
	srv := func(name, ip, wan string) map[string]any {
		return map[string]any{"name": name, "endpoint_v4": ip, "wan_interface": wan}
	}
	build := func(blank string, wan string) []byte {
		w := func(k string) string {
			if k == blank {
				return wan
			}
			return "ens3"
		}
		exit := srv("出口 A", "203.0.113.41", w("exits[0]"))
		exit["region"] = "jp"
		in := map[string]any{
			"gateway":        map[string]string{"lan_interface": "eth0", "lan_ipv4": "192.0.2.88/24", "router_ipv4": "192.0.2.1"},
			"exits":          []any{exit},
			"relay":          srv("中继", "203.0.113.10", w("relay")),
			"hub":            srv("枢纽", "203.0.113.20", w("hub")),
			"backup_hub":     srv("备用枢纽", "203.0.113.30", w("backup_hub")),
			"backup_relays":  []any{srv("备用中继 1", "203.0.113.12", w("backup_relays[0]")), srv("备用中继 2", "203.0.113.13", w("backup_relays[1]"))},
			"default_region": "jp",
		}
		return mustJSON(in)
	}
	rr := do(s, http.MethodPost, "/api/templates/relay_hub/preview", build("", ""))
	var prev templatePreview
	if rr.Code != 200 || json.Unmarshal(rr.Body.Bytes(), &prev) != nil {
		t.Fatalf("detected names: %d %s", rr.Code, rr.Body.String())
	}
	// A stored topology without WAN names is not a template input: it saves.
	for i := range prev.Topology.Nodes {
		prev.Topology.Nodes[i].WANInterface = ""
	}
	if rr := do(s, http.MethodPut, "/api/topology", mustJSON(prev.Topology)); rr.Code != 200 {
		t.Fatalf("stored without wan: %d %s", rr.Code, rr.Body.String())
	}
	for _, key := range []string{"exits[0]", "relay", "hub", "backup_hub", "backup_relays[0]", "backup_relays[1]"} {
		for _, wan := range []string{"", "  "} {
			rr := do(s, http.MethodPost, "/api/templates/relay_hub/preview", build(key, wan))
			var res map[string]string
			_ = json.Unmarshal(rr.Body.Bytes(), &res)
			if rr.Code != 422 || res["field"] != key+".wan_interface" {
				t.Errorf("%s %q: %d %s", key, wan, rr.Code, rr.Body.String())
			}
		}
	}
	if rr := do(s, http.MethodPost, "/api/templates/relay_hub/preview", build("hub", "bad/nic")); rr.Code != 422 {
		t.Errorf("bad name: %d", rr.Code)
	}
}
