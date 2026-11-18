package compile

import (
	"reflect"
	"strings"
	"testing"

	"github.com/radowitz/meridian/internal/defaults"
	"github.com/radowitz/meridian/internal/model"
)

func dialEgressTopo(set func(*model.Link)) model.Topology {
	topo := defaults.DualHubExample()
	model.MigrateRegionGroups(&topo)
	for i := range topo.Links {
		if topo.Links[i].ID == "access-ix" {
			set(&topo.Links[i])
		}
	}
	return topo
}

func compileOK(t *testing.T, topo model.Topology) *Bundle {
	t.Helper()
	b, err := Compile(topo)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// Unset and explicit false compile byte-identically to the example.
func TestDialEgressDefaultUnchanged(t *testing.T) {
	base := dualBundle(t)
	off := compileOK(t, dialEgressTopo(func(l *model.Link) { l.DialEgress = false }))
	if !reflect.DeepEqual(base.Files, off.Files) {
		t.Fatal("dial_egress=false changed the bundle")
	}
}

// With dial_egress the relay dials the IX egress (both UDP and WSS), the IX
// still listens and keeps its per-tunnel return path, and the exit identity
// digest of both ends changes.
func TestDialEgressRelayDialsIXEgress(t *testing.T) {
	base := dualBundle(t)
	topo := dialEgressTopo(func(l *model.Link) { l.DialEgress = true })
	b := compileOK(t, topo)
	ifc := dualIface(t, b, "access", "ix")
	conf := b.File("nodes/access/etc/wireguard/" + ifc + ".conf")
	if !strings.Contains(conf, "Endpoint = 203.0.113.20:") || strings.Contains(conf, "198.51.100.10") {
		t.Errorf("relay must dial the IX egress address:\n%s", conf)
	}
	ixIfc := dualIface(t, b, "ix", "access")
	ixConf := b.File("nodes/ix/etc/wireguard/" + ixIfc + ".conf")
	if !strings.Contains(ixConf, "ListenPort = ") {
		t.Errorf("IX must listen for the relay:\n%s", ixConf)
	}
	if ixConf != base.File("nodes/ix/etc/wireguard/"+ixIfc+".conf") {
		t.Error("IX side of the tunnel must not change (it listens on all addresses)")
	}
	if b.File("nodes/ix/etc/nftables.d/meridian.nft") != base.File("nodes/ix/etc/nftables.d/meridian.nft") {
		t.Error("IX nft changed: the egress side already accepts WireGuard")
	}
	// Gateway: the IX egress stays a foreign endpoint (LAN traffic tunnelled),
	// the ingress stays domestic; the gateway bundle is unchanged.
	if b.File("nodes/gw/etc/nftables.d/meridian.nft") != base.File("nodes/gw/etc/nftables.d/meridian.nft") {
		t.Error("gateway nft changed")
	}
	for _, a := range endpointAccessOf(t, topo) {
		if a == "203.0.113.20=direct" {
			t.Error("IX egress must not be classified domestic")
		}
	}
	on, err := EgressLegs(topo)
	if err != nil {
		t.Fatal(err)
	}
	off, _ := EgressLegs(dialEgressTopo(func(*model.Link) {}))
	for _, id := range []string{"access", "ix"} {
		if reflect.DeepEqual(on[id], off[id]) {
			t.Errorf("%s: egress legs unchanged by dial_egress", id)
		}
		if !strings.Contains(strings.Join(on[id], "\n"), "ep=203.0.113.20:") {
			t.Errorf("%s: legs lack the egress endpoint: %v", id, on[id])
		}
	}
}

func TestDialEgressValidation(t *testing.T) {
	cases := []struct {
		code string
		mut  func(*model.Topology)
	}{
		{"dial_egress_not_relay_ix", func(tp *model.Topology) {
			for i := range tp.Links {
				if tp.Links[i].ID == "gw-hkb" {
					tp.Links[i].DialEgress = true
				}
			}
		}},
		{"dial_egress_without_endpoint", func(tp *model.Topology) {
			setNode(tp, "ix", func(n *model.Node) { n.EndpointV4 = "" })
			for i := range tp.Links {
				if tp.Links[i].ID == "access-ix" {
					tp.Links[i].DialEgress = true
				}
			}
		}},
	}
	for _, c := range cases {
		if iss := dualValidate(t, c.mut); !hasIssue(iss, c.code) {
			t.Errorf("%s: not reported", c.code)
		}
	}
	if iss := dualValidate(t, func(tp *model.Topology) {
		for i := range tp.Links {
			if tp.Links[i].ID == "access-ix" {
				tp.Links[i].DialEgress = true
			}
		}
	}); hasIssue(iss, "dial_egress_not_relay_ix") || hasIssue(iss, "dial_egress_without_endpoint") || hasIssue(iss, "dial_egress_without_ingress") {
		t.Errorf("valid dial_egress rejected: %+v", iss)
	}
}

// endpointAccessOf lists addr=class of the compiled endpoint classification.
func endpointAccessOf(t *testing.T, topo model.Topology) []string {
	t.Helper()
	tunnels, err := buildTunnels(topo)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, a := range endpointAccess(topo, tunnels, nil) {
		out = append(out, a.Addr+"="+a.Class)
	}
	return out
}
