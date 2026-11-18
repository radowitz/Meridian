package validate

import (
	"strings"
	"testing"

	"github.com/radowitz/meridian/internal/defaults"
	"github.com/radowitz/meridian/internal/model"
)

func noixErrs(r Result) map[string]Issue {
	out := map[string]Issue{}
	for _, i := range r.Issues {
		if i.Severity == SeverityError {
			out[i.Code] = i
		}
	}
	return out
}

func noixSetLink(topo *model.Topology, id string, fn func(l *model.Link)) {
	for i := range topo.Links {
		if topo.Links[i].ID == id {
			fn(&topo.Links[i])
		}
	}
}

func noixDropLink(topo *model.Topology, id string) {
	var out []model.Link
	for _, l := range topo.Links {
		if l.ID != id {
			out = append(out, l)
		}
	}
	topo.Links = out
}

func TestHasIX(t *testing.T) {
	if defaults.NoIXExample().HasIX() {
		t.Fatal("no-IX example has an IX")
	}
	if !defaults.Example().HasIX() || !defaults.DualHubExample().HasIX() {
		t.Fatal("IX examples without IX")
	}
	// Disabled links do not remove the IX.
	ex := defaults.Example()
	for i := range ex.Links {
		ex.Links[i].Enabled = false
	}
	if !ex.HasIX() {
		t.Fatal("IX with disabled links not counted")
	}
}

func TestNoIXMainPath(t *testing.T) {
	r := Run(defaults.NoIXExample())
	if errs := noixErrs(r); len(errs) != 0 {
		t.Fatalf("errors: %+v", errs)
	}
	want := map[string]string{"dc1": "gw,access,hub,dc1", "dc2": "gw,access,hub,dc2"}
	for _, p := range r.Paths {
		if got := strings.Join(p.Nodes, ","); got != want[p.ExitID] {
			t.Fatalf("%s path %s, want %s", p.ExitID, got, want[p.ExitID])
		}
	}
	// Relay → plain hub: each transport, and dial_egress (it names the
	// hub's endpoint_v4, the only address there is).
	for _, tr := range []model.Transport{model.TransportDirectWG, model.TransportUDPWSSFailover, model.TransportWGOverWSS} {
		topo := defaults.NoIXExample()
		noixSetLink(&topo, "access-hub", func(l *model.Link) { l.Transport = tr; l.DialEgress = true })
		if errs := noixErrs(Run(topo)); len(errs) != 0 {
			t.Fatalf("%s: %+v", tr, errs)
		}
	}
	// Two enabled relays share.
	topo := defaults.NoIXExample()
	noixSetLink(&topo, "gw-access2", func(l *model.Link) { l.Enabled = true })
	noixSetLink(&topo, "access2-hub", func(l *model.Link) { l.Enabled = true })
	if errs := noixErrs(Run(topo)); len(errs) != 0 {
		t.Fatalf("two relays: %+v", errs)
	}
}

func TestNoIXMainPathRefused(t *testing.T) {
	noIX := func(t *testing.T, topo model.Topology, code string) Issue {
		t.Helper()
		iss, ok := noixErrs(Run(topo))[code]
		if !ok {
			t.Fatalf("want %s, got %+v", code, noixErrs(Run(topo)))
		}
		for _, w := range []string{"阿里云", "IX 专线", "IX"} {
			if strings.Contains(iss.Message, w) {
				t.Fatalf("%s names %q: %s", code, w, iss.Message)
			}
		}
		return iss
	}
	// Missing relay: the gateway straight to the hub.
	topo := defaults.NoIXExample()
	noixDropLink(&topo, "gw-access")
	topo.Links = append(topo.Links, model.Link{ID: "gw-hub", From: "gw", To: "hub", Transport: model.TransportDirectWG, Enabled: true})
	if iss := noIX(t, topo, "path_missing_relay"); !strings.Contains(iss.Message, "主枢纽 主枢纽") {
		t.Fatalf("message without the hub's name: %s", iss.Message)
	}
	// Missing hub: the relay straight to an exit.
	topo = defaults.NoIXExample()
	noixDropLink(&topo, "access-hub")
	topo.Links = append(topo.Links, model.Link{ID: "access-dc1", From: "access", To: "dc1", Transport: model.TransportDirectWG, Enabled: true})
	noIX(t, topo, "path_missing_hub")
	// All links of the main path disabled.
	topo = defaults.NoIXExample()
	noixSetLink(&topo, "gw-access", func(l *model.Link) { l.Enabled = false })
	noixSetLink(&topo, "access-hub", func(l *model.Link) { l.Enabled = false })
	noIX(t, topo, "path_not_found")
	// Only the disabled relay's links: still nothing.
	topo = defaults.NoIXExample()
	noixDropLink(&topo, "access-hub")
	noIX(t, topo, "path_not_found")
	// The standby WSS to the backup hub does not stand in for the main path.
	topo = defaults.NoIXExample()
	noixSetLink(&topo, "access-hub", func(l *model.Link) { l.Standby = true })
	noIX(t, topo, "path_not_found")
	// Mesh bypass from the relay.
	topo = defaults.NoIXExample()
	topo.Links = append(topo.Links, model.Link{ID: "access-dc1-mesh", From: "access", To: "dc1", Transport: model.TransportCFMesh, Enabled: true, Standby: true})
	noIX(t, topo, "mesh_bypasses_ix")
	// The backup hub posing as the main path.
	topo = defaults.NoIXExample()
	noixDropLink(&topo, "access-hub")
	topo.Links = append(topo.Links, model.Link{ID: "access-hkb", From: "access", To: "hkb", Transport: model.TransportDirectWG, Enabled: true})
	noIX(t, topo, "path_missing_hub")
}

// With an IX the rules and every message are unchanged, also when the IX's
// links are disabled.
func TestIXPathRulesUnchanged(t *testing.T) {
	topo := defaults.DualHubExample()
	noixDropLink(&topo, "access-ix")
	topo.Links = append(topo.Links, model.Link{ID: "access-hkb", From: "access", To: "hkb", Transport: model.TransportDirectWG, Enabled: true})
	iss, ok := noixErrs(Run(topo))["path_missing_ix"]
	if !ok || !strings.Contains(iss.Message, "国内中继") || !strings.Contains(iss.Message, "IX") {
		t.Fatalf("IX bypass by the backup hub: %+v", noixErrs(Run(topo)))
	}
	ex := defaults.Example()
	for i, l := range ex.Links {
		if l.From == "ix" || l.To == "ix" {
			ex.Links[i].Enabled = false
		}
	}
	ex.Links = append(ex.Links, model.Link{ID: "access-hub", From: "access", To: "hk-hub", Transport: model.TransportDirectWG, Enabled: true})
	iss, ok = noixErrs(Run(ex))["path_missing_ix"]
	if !ok || !strings.Contains(iss.Message, "IX") {
		t.Fatalf("disabled IX bypassed: %+v", noixErrs(Run(ex)))
	}
	// dial_egress keeps its IX restriction.
	ex = defaults.Example()
	noixSetLink(&ex, ex.Links[0].ID, func(l *model.Link) { l.DialEgress = true })
	if _, ok := noixErrs(Run(ex))["dial_egress_not_relay_ix"]; !ok {
		t.Fatalf("dial_egress outside relay → IX hub accepted: %+v", noixErrs(Run(ex)))
	}
	sh := defaults.DualHubExample()
	noixSetLink(&sh, "gw-access", func(l *model.Link) { l.DialEgress = true })
	if _, ok := noixErrs(Run(sh))["dial_egress_not_relay_ix"]; !ok {
		t.Fatal("dial_egress on gateway link accepted")
	}
	// Without IX, dial_egress on the gateway's link is still refused.
	n := defaults.NoIXExample()
	noixSetLink(&n, "gw-access", func(l *model.Link) { l.DialEgress = true })
	if _, ok := noixErrs(Run(n))["dial_egress_not_relay_ix"]; !ok {
		t.Fatal("no IX: dial_egress on gateway link accepted")
	}
}
