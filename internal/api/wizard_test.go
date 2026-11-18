package api

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/radowitz/meridian/internal/defaults"
	"github.com/radowitz/meridian/internal/hubstate"
)

func wizardGet(t *testing.T, s *Server) wizardView {
	t.Helper()
	rr := do(s, http.MethodGet, "/api/setup/wizard", nil)
	var v wizardView
	if rr.Code != 200 || json.Unmarshal(rr.Body.Bytes(), &v) != nil {
		t.Fatalf("get: %d %s", rr.Code, rr.Body.String())
	}
	return v
}

func TestWizardFreshResumeAndInvalidate(t *testing.T) {
	s := newTest(t)
	v := wizardGet(t, s)
	if !v.Active || v.State.Step != "gateway" || len(v.State.Done) != 0 {
		t.Fatalf("fresh: %+v", v)
	}
	st := wizardState{Step: "servers", Done: []string{"gateway", "template"}, Template: "direct",
		Gateway: wizardGateway{LANInterface: "eth0", LANIPv4: "192.0.2.88/24", RouterIPv4: "192.0.2.1"}}
	if rr := do(s, http.MethodPut, "/api/setup/wizard", mustJSON(st)); rr.Code != 200 {
		t.Fatalf("put: %d %s", rr.Code, rr.Body.String())
	}
	// A save of the topology half way does not end the wizard.
	topo, err := defaults.GenerateTemplate("direct", defaults.TemplateInput{
		Gateway:       defaults.TemplateGateway{LANInterface: "eth0", LANIPv4: "192.0.2.88/24", RouterIPv4: "192.0.2.1"},
		Exits:         []defaults.TemplateServer{{Name: "出口 A", Region: "jp", EndpointV4: "203.0.113.41", WANInterface: "eth0"}},
		DefaultRegion: "jp"})
	if err != nil {
		t.Fatal(err)
	}
	if rr := do(s, http.MethodPut, "/api/topology", mustJSON(topo)); rr.Code != 200 {
		t.Fatalf("save: %d %s", rr.Code, rr.Body.String())
	}
	st.Step, st.Done, st.TopologyVersion, st.PreflightID = "install", []string{"gateway", "template", "servers", "topology", "preflight"}, "v1", "pf1"
	if rr := do(s, http.MethodPut, "/api/setup/wizard", mustJSON(st)); rr.Code != 200 {
		t.Fatalf("put 2: %d %s", rr.Code, rr.Body.String())
	}
	v = wizardGet(t, s)
	if !v.Active || v.State.Step != "install" || v.State.PreflightID != "pf1" || len(v.State.Done) != 5 {
		t.Fatalf("resume: %+v", v)
	}
	// Back to the template step and a different template: later steps,
	// the saved version and the reviewed preflight are dropped.
	st.Step, st.Template = "template", "relay"
	rr := do(s, http.MethodPut, "/api/setup/wizard", mustJSON(st))
	v = wizardView{}
	if rr.Code != 200 || json.Unmarshal(rr.Body.Bytes(), &v) != nil {
		t.Fatalf("put 3: %d %s", rr.Code, rr.Body.String())
	}
	if strings.Join(v.State.Done, ",") != "gateway" || v.State.PreflightID != "" || v.State.TopologyVersion != "" {
		t.Fatalf("not invalidated: %+v", v.State)
	}
	if rr := do(s, http.MethodPut, "/api/setup/wizard", []byte(`{"step":"nope","done":[]}`)); rr.Code != 422 {
		t.Fatalf("bad step: %d", rr.Code)
	}
	if rr := do(s, http.MethodPut, "/api/setup/wizard", []byte(`{"step":"gateway","password":"x"}`)); rr.Code != 400 {
		t.Fatalf("unknown field: %d", rr.Code)
	}
	if rr := do(s, http.MethodPost, "/api/setup/wizard/complete", nil); rr.Code != 200 {
		t.Fatalf("complete: %d", rr.Code)
	}
	if v := wizardGet(t, s); v.Active {
		t.Fatal("completed wizard still active")
	}
}

func TestWizardExistingDeploymentInactive(t *testing.T) {
	s := newTest(t)
	if rr := do(s, http.MethodPut, "/api/topology", mustJSON(defaults.Example())); rr.Code != 200 {
		t.Fatalf("save: %d %s", rr.Code, rr.Body.String())
	}
	if v := wizardGet(t, s); v.Active {
		t.Fatal("existing deployment sees the wizard")
	}
	if rr := do(s, http.MethodPut, "/api/setup/wizard", []byte(`{"step":"gateway","done":[]}`)); rr.Code != http.StatusConflict {
		t.Fatalf("put on existing deployment: %d", rr.Code)
	}
}

type fakeGatewayGroups struct{ out string }

func (f fakeGatewayGroups) GatewayGroupState(context.Context) (string, error) { return f.out, nil }

func TestDirectExitGroupStateFromGateway(t *testing.T) {
	s := newTest(t)
	topo, err := defaults.GenerateTemplate("direct", defaults.TemplateInput{
		Gateway:       defaults.TemplateGateway{LANInterface: "eth0", LANIPv4: "192.0.2.88/24", RouterIPv4: "192.0.2.1"},
		Exits:         []defaults.TemplateServer{{Name: "出口 A", Region: "jp", EndpointV4: "203.0.113.41", WANInterface: "eth0"}},
		DefaultRegion: "jp"})
	if err != nil {
		t.Fatal(err)
	}
	if rr := do(s, http.MethodPut, "/api/topology", mustJSON(topo)); rr.Code != 200 {
		t.Fatalf("save: %d %s", rr.Code, rr.Body.String())
	}
	// Without the host agent: not readable, but no longer "no hub".
	rr := do(s, http.MethodGet, "/api/region-groups", nil)
	if rr.Code != 200 || strings.Contains(rr.Body.String(), `"`+hubstate.CodeNoHub+`"`) {
		t.Fatalf("no agent: %d %s", rr.Code, rr.Body.String())
	}
	s.GatewayGroups = fakeGatewayGroups{out: "meridian-group-state 1\nnow 1900000000\nmeridian-group-state-end\n"}
	rr = do(s, http.MethodPost, "/api/region-groups/runtime/refresh", nil)
	if rr.Code != 200 || strings.Contains(rr.Body.String(), `"`+hubstate.CodeNoHub+`"`) {
		t.Fatalf("refresh: %d %s", rr.Code, rr.Body.String())
	}
	rd := s.loadGroupHub("primary")
	if rd == nil || rd.Snapshot == nil || rd.ErrorCode != "" || rd.Identity.ServerID != gatewayStateServer {
		t.Fatalf("stored read: %+v", rd)
	}
}

// The stored wizard input round-trips through the real API without a
// gateway block, so the panel's preview body (input + the wizard gateway)
// generates every template. An echoed empty "input.gateway" is refused.
func TestWizardInputRoundTripPreviewsAllTemplates(t *testing.T) {
	gw := map[string]string{"lan_interface": "eth0", "lan_ipv4": "192.0.2.88/24", "router_ipv4": "192.0.2.1"}
	exits := []map[string]string{{"name": "出口 A", "region": "jp", "endpoint_v4": "203.0.113.41", "wan_interface": "eth0"}}
	relay := map[string]string{"name": "国内中继", "endpoint_v4": "203.0.113.10", "wan_interface": "eth0"}
	inputs := map[string]map[string]any{
		"direct":    {"exits": exits, "default_region": "jp"},
		"relay":     {"exits": exits, "relay": relay, "default_region": "jp"},
		"relay_hub": {"exits": exits, "relay": relay, "hub": map[string]string{"name": "枢纽", "endpoint_v4": "203.0.113.20", "wan_interface": "eth0"}, "default_region": "jp"},
		"ix":        {"exits": exits, "relay": relay, "hub": map[string]string{"name": "专线枢纽", "ingress_v4": "198.51.100.10", "endpoint_v4": "203.0.113.20", "wan_interface": "eth0"}, "default_region": "jp"},
	}
	for id, in := range inputs {
		t.Run(id, func(t *testing.T) {
			s := newTest(t)
			st := map[string]any{"step": "topology", "done": []string{"gateway", "template", "servers"},
				"gateway": gw, "template": id, "input": in}
			if rr := do(s, http.MethodPut, "/api/setup/wizard", mustJSON(st)); rr.Code != 200 {
				t.Fatalf("put: %d %s", rr.Code, rr.Body.String())
			}
			rr := do(s, http.MethodGet, "/api/setup/wizard", nil)
			var view struct {
				State struct {
					Gateway map[string]string          `json:"gateway"`
					Input   map[string]json.RawMessage `json:"input"`
				} `json:"state"`
			}
			if rr.Code != 200 || json.Unmarshal(rr.Body.Bytes(), &view) != nil {
				t.Fatalf("get: %d %s", rr.Code, rr.Body.String())
			}
			if _, ok := view.State.Input["gateway"]; ok {
				t.Fatalf("stored input carries a gateway: %s", rr.Body.String())
			}
			// What the panel sends: the stored input, then the wizard gateway.
			body := map[string]any{}
			for k, v := range view.State.Input {
				body[k] = v
			}
			body["gateway"] = view.State.Gateway
			if rr := do(s, http.MethodPost, "/api/templates/"+id+"/preview", mustJSON(body)); rr.Code != 200 {
				t.Fatalf("preview: %d %s", rr.Code, rr.Body.String())
			}
			st["input"] = map[string]any{"gateway": map[string]string{}, "exits": exits, "default_region": "jp"}
			if rr := do(s, http.MethodPut, "/api/setup/wizard", mustJSON(st)); rr.Code != 400 {
				t.Fatalf("input.gateway accepted: %d", rr.Code)
			}
		})
	}
}
