package preflight

import (
	"net/netip"
	"strings"
	"testing"
)

func findCode(ev Evaluation, code string) *Finding {
	for i := range ev.Findings {
		if ev.Findings[i].Code == code {
			return &ev.Findings[i]
		}
	}
	return nil
}

// The carrier's preflight checks the external exit's interface, its route
// and one TCP connect to the proxy, read-only.
func TestExternalProxyChecks(t *testing.T) {
	fp := Footprint{External: []ExternalPlan{{ID: "my1", SOCKS: netip.MustParseAddr("192.0.2.66"), Port: 1080, Iface: "wg9"}}}
	if p := fp.PreflightProbes(); len(p) != 1 || p[0] != "tcp4:192.0.2.66:1080" {
		t.Fatalf("probes %v", p)
	}
	base := func() Report {
		r := newReport()
		r.Complete = true
		r.Links = []string{"lo", "eth0", "wg9"}
		r.Routes = []Route{
			{Family: 4, Dst: netip.MustParsePrefix("0.0.0.0/0"), Dev: "eth0"},
			{Family: 4, Dst: netip.MustParsePrefix("192.0.2.64/30"), Dev: "wg9"},
		}
		r.TCPConnect = map[string]bool{"192.0.2.66:1080": true}
		return r
	}
	ctx := Context{NodeID: "dc2"}
	if f := findCode(Evaluate(base(), fp, ctx), CodeExternal); f == nil || f.Severity != Info {
		t.Fatalf("healthy carrier: %+v", f)
	}
	r := base()
	r.Links = []string{"lo", "eth0"}
	if f := findCode(Evaluate(r, fp, ctx), CodeExternalIface); f == nil || f.Severity != Blocking {
		t.Fatalf("missing interface: %+v", f)
	}
	r = base()
	r.Routes = r.Routes[:1] // only the default route: it would leave over eth0
	if f := findCode(Evaluate(r, fp, ctx), CodeExternalIface); f == nil || f.Severity != Blocking || !strings.Contains(f.Message, "eth0") {
		t.Fatalf("route via the WAN: %+v", f)
	}
	r = base()
	r.TCPConnect["192.0.2.66:1080"] = false
	if f := findCode(Evaluate(r, fp, ctx), CodeExternalProxy); f == nil || f.Severity != Blocking {
		t.Fatalf("proxy unreachable: %+v", f)
	}
	// The report line is parsed; a malformed one is ignored.
	rep := Parse("meridian-preflight 1\ntcpconnect 192.0.2.66 1080 ok\ntcpconnect 192.0.2.67 x ok\nmeridian-preflight-end\n")
	if len(rep.TCPConnect) != 1 || !rep.TCPConnect["192.0.2.66:1080"] {
		t.Fatalf("parsed %v", rep.TCPConnect)
	}
	// Probe arguments are strictly shaped.
	for _, bad := range []string{"tcp4:192.0.2.66", "tcp4:192.0.2.66:0", "tcp4:host:80", "tcp4:192.0.2.66:80;id", "tcp6:[::1]:80"} {
		if ValidProbe(bad) {
			t.Errorf("probe %q accepted", bad)
		}
	}
	if _, err := ArgsWithProbes(nil, []string{"tcp4:192.0.2.66:1080;rm"}); err == nil {
		t.Error("bad probe passed ArgsWithProbes")
	}
}
