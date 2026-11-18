package preflight

import (
	"strings"
	"testing"

	"github.com/radowitz/meridian/internal/compile"
	"github.com/radowitz/meridian/internal/defaults"
)

func ixHubFiles(t *testing.T, iface string) map[string]string {
	t.Helper()
	topo := defaults.DualHubExample()
	for i := range topo.Nodes {
		if topo.Nodes[i].ID == "ix" {
			topo.Nodes[i].IngressInterface = iface
		}
	}
	b, err := compile.Compile(topo)
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]string{}
	for p, body := range b.Files {
		if strings.HasPrefix(p, "nodes/ix/") {
			out["/"+strings.TrimPrefix(p, "nodes/ix/")] = body
		}
	}
	return out
}

// The IX hub: the WAN check covers the Hong Kong side; the ingress
// address must sit on the named ingress interface; addresses that are on
// no interface are warnings (a NAT in front is possible).
func TestIXHubAddresses(t *testing.T) {
	fp := FootprintOf(ixHubFiles(t, ""))
	if fp.IXIngress != "198.51.100.10" || fp.IXEgress != "203.0.113.20" || fp.IXIngressIface != "" || fp.WAN != "eth0" {
		t.Fatalf("footprint: %+v", fp)
	}
	ev := Evaluate(fixture(t, "clean-debian13.txt", fp, nil, ""), fp, remote("ix"))
	if !has(ev, Warning, CodeIXIngressNotLocal) || !has(ev, Warning, CodeIXEgressNotLocal) || has(ev, Blocking, CodeIXIngressIface) {
		t.Fatalf("not local: %v", codes(ev, ""))
	}
	ev = Evaluate(fixture(t, "clean-debian13.txt", fp, nil, "addr eth0 198.51.100.10/32\naddr eth0 203.0.113.20/32\n"), fp, remote("ix"))
	if has(ev, "", CodeIXIngressNotLocal) || has(ev, "", CodeIXEgressNotLocal) || !has(ev, Info, CodeIXHub) {
		t.Fatalf("local: %v", codes(ev, ""))
	}
	fp = FootprintOf(ixHubFiles(t, "ens5"))
	if fp.IXIngressIface != "ens5" || !containsStr(fp.SysctlIfaces, "ens5") {
		t.Fatalf("iface: %+v", fp)
	}
	ev = Evaluate(fixture(t, "clean-debian13.txt", fp, nil, ""), fp, remote("ix"))
	if !has(ev, Blocking, CodeIXIngressIface) {
		t.Fatalf("missing ingress interface not blocked: %v", codes(ev, ""))
	}
	ev = Evaluate(fixture(t, "clean-debian13.txt", fp, nil, "link ens5\naddr eth0 198.51.100.10/32\n"), fp, remote("ix"))
	if !has(ev, Blocking, CodeIXIngressIface) {
		t.Fatalf("ingress on the wrong interface not blocked: %v", codes(ev, ""))
	}
	ev = Evaluate(fixture(t, "clean-debian13.txt", fp, nil, "link ens5\naddr ens5 198.51.100.10/32\n"), fp, remote("ix"))
	if has(ev, Blocking, CodeIXIngressIface) || !has(ev, Info, CodeIXHub) {
		t.Fatalf("correct ingress interface: %v", codes(ev, ""))
	}
	// A plain hub has no IX marker.
	if FootprintOf(nodeFiles(t, "hk-hub")).IXIngress != "" {
		t.Fatal("plain hub carries the IX marker")
	}
}
