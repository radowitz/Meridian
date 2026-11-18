package compile

import (
	"errors"
	"testing"

	"github.com/radowitz/meridian/internal/defaults"
	"github.com/radowitz/meridian/internal/model"
	"github.com/radowitz/meridian/internal/validate"
)

// TemplateSamples are synthetic inputs for every template shape
// (documentation addresses only).
func templateSamples() map[string]defaults.TemplateInput {
	gw := defaults.TemplateGateway{LANInterface: "eth0", LANIPv4: "192.0.2.88/24", RouterIPv4: "192.0.2.1"}
	exits := []defaults.TemplateServer{
		{Name: "出口 A", Region: "jp", EndpointV4: "203.0.113.41", WANInterface: "eth0"},
		{Name: "出口 B", Region: "jp", EndpointV4: "203.0.113.42", WANInterface: "eth0"},
		{Name: "出口 C", Region: "us", EndpointV4: "198.51.100.20", WANInterface: "eth0"},
	}
	relay := &defaults.TemplateServer{Name: "国内中继", EndpointV4: "203.0.113.10", WANInterface: "eth0"}
	hub := &defaults.TemplateServer{Name: "枢纽", EndpointV4: "203.0.113.20", WANInterface: "eth0"}
	ix := &defaults.TemplateServer{Name: "专线枢纽", IngressV4: "198.51.100.10", EndpointV4: "203.0.113.20", WANInterface: "eth0"}
	backup := &defaults.TemplateServer{Name: "备用枢纽", EndpointV4: "203.0.113.30", WANInterface: "eth0"}
	return map[string]defaults.TemplateInput{
		"direct":             {Gateway: gw, Exits: exits, DefaultRegion: "jp"},
		"relay":              {Gateway: gw, Exits: exits, Relay: relay, DefaultRegion: "jp"},
		"relay_hub":          {Gateway: gw, Exits: exits, Relay: relay, Hub: hub, DefaultRegion: "jp"},
		"relay_hub+backup":   {Gateway: gw, Exits: exits, Relay: relay, Hub: hub, BackupHub: backup, DefaultRegion: "us"},
		"relay_hub+bkrelays": {Gateway: gw, Exits: exits, Relay: relay, Hub: hub, BackupHub: backup, DefaultRegion: "jp", BackupRelays: []defaults.TemplateServer{{Name: "备用中继 1", EndpointV4: "203.0.113.12", WANInterface: "eth0"}, {Name: "备用中继 2", EndpointV4: "203.0.113.13", WANInterface: "eth0"}}},
		"ix":                 {Gateway: gw, Exits: exits, Relay: relay, Hub: ix, DefaultRegion: "jp"},
		"ix+backup":          {Gateway: gw, Exits: exits, Relay: relay, Hub: ix, BackupHub: backup, DefaultRegion: "jp"},
	}
}

func templateOf(sample string) string {
	for i := range sample {
		if sample[i] == '+' {
			return sample[:i]
		}
	}
	return sample
}

// Every template's output passes validation and compiles; each has the
// shape it promises (no relay or hub where the template has none).
func TestTemplatesValidateAndCompile(t *testing.T) {
	if len(defaults.Templates()) != 4 {
		t.Fatal("four templates")
	}
	for name, in := range templateSamples() {
		id := templateOf(name)
		topo, err := defaults.GenerateTemplate(id, in)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		res := validate.Run(topo)
		if res.HasErrors() {
			for _, is := range res.Issues {
				if is.Severity == validate.SeverityError {
					t.Errorf("%s: %s %s", name, is.Code, is.Message)
				}
			}
			continue
		}
		if _, err := Compile(topo); err != nil {
			t.Errorf("%s: compile: %v", name, err)
		}
		roles := map[model.Role]int{}
		for _, n := range topo.Nodes {
			roles[n.Role]++
		}
		switch id {
		case defaults.TemplateDirect:
			if !topo.DirectExits() || roles[model.RoleRelay]+roles[model.RoleHub] != 0 {
				t.Errorf("%s: not direct: %v", name, roles)
			}
		case defaults.TemplateRelay:
			if roles[model.RoleRelay] != 0 || roles[model.RoleHub] != 1 {
				t.Errorf("%s: one domestic server expected: %v", name, roles)
			}
		case defaults.TemplateIX:
			if !topo.HasIX() {
				t.Errorf("%s: no IX", name)
			}
		}
		if in.BackupHub != nil && !topo.DualHub() {
			t.Errorf("%s: no backup hub", name)
		}
		if len(in.BackupRelays) > 0 && !topo.RelayBackup() {
			t.Errorf("%s: backup hub not reached through relays", name)
		}
		if topo.Settings.DefaultGroup != in.DefaultRegion {
			t.Errorf("%s: default group %q", name, topo.Settings.DefaultGroup)
		}
	}
}

// Inputs a template does not have, or misses, are refused by field.
func TestTemplateInputRefusals(t *testing.T) {
	s := templateSamples()
	cases := map[string]struct {
		id    string
		in    defaults.TemplateInput
		field string
	}{
		"direct with relay": {"direct", s["relay"], "relay"},
		"relay without":     {"relay", s["direct"], "relay"},
		"hub missing":       {"relay_hub", s["relay"], "hub"},
		"ix no ingress":     {"ix", s["relay_hub"], "hub.ingress_v4"},
		"unknown":           {"nope", s["direct"], "template"},
	}
	bad := s["direct"]
	bad.DefaultRegion = "sg"
	cases["default region"] = struct {
		id    string
		in    defaults.TemplateInput
		field string
	}{"direct", bad, "default_region"}
	router := s["direct"]
	router.Gateway.RouterIPv4 = "198.51.100.1"
	cases["router outside"] = struct {
		id    string
		in    defaults.TemplateInput
		field string
	}{"direct", router, "gateway.router_ipv4"}
	for name, c := range cases {
		_, err := defaults.GenerateTemplate(c.id, c.in)
		var te *defaults.TemplateError
		if !errors.As(err, &te) || te.Field != c.field {
			t.Errorf("%s: %v, want field %s", name, err, c.field)
		}
	}
}

// Single relay (the domestic server is the hub, no relays): the gateway's
// way to it is one plain WireGuard; a UDP/WSS pair or a backup hub is
// refused instead of compiling to a hub with no way home.
func TestRelaylessRefusals(t *testing.T) {
	in := templateSamples()["relay"]
	for name, edit := range map[string]func(*model.Topology){
		"udp_wss_failover": func(topo *model.Topology) { topo.Links[0].Transport = model.TransportUDPWSSFailover },
		"backup hub": func(topo *model.Topology) {
			topo.Nodes = append(topo.Nodes, model.Node{ID: "hub-b", Name: "备用", Role: model.RoleHub, HubTier: model.HubBackup, Managed: true,
				EndpointV4: "203.0.113.30", PathV4: true, WSSListenPort: 443})
			topo.Links = append(topo.Links, model.Link{ID: "gw-hub-b", From: "gw", To: "hub-b", Transport: model.TransportIXReplacementWSS, Enabled: true, Standby: true})
		},
	} {
		topo, err := defaults.GenerateTemplate("relay", in)
		if err != nil {
			t.Fatal(err)
		}
		edit(&topo)
		found := false
		for _, is := range validate.Run(topo).Issues {
			found = found || is.Code == "relayless_unsupported"
		}
		if !found {
			t.Errorf("%s: not refused", name)
		}
	}
}
