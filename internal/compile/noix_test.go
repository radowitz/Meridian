package compile

import (
	"regexp"
	"strings"
	"testing"

	"github.com/radowitz/meridian/internal/defaults"
	"github.com/radowitz/meridian/internal/model"
)

// A topology without IX (defaults.NoIXExample, synthetic addresses):
// gateway → relay → plain primary hub (endpoint_v4) → exits, a backup hub
// over the gateway's standby WG over WSS, a second relay whose links are
// disabled.

func noIXTopo(mut func(t *model.Topology)) model.Topology {
	t := defaults.NoIXExample()
	if mut != nil {
		mut(&t)
	}
	model.MigrateRegionGroups(&t)
	return t
}

func noIXLink(t *model.Topology, id string, fn func(l *model.Link)) {
	for i := range t.Links {
		if t.Links[i].ID == id {
			fn(&t.Links[i])
		}
	}
}

func enableAli2(t *model.Topology) {
	noIXLink(t, "gw-access2", func(l *model.Link) { l.Enabled = true })
	noIXLink(t, "access2-hub", func(l *model.Link) { l.Enabled = true })
}

func noIXCompile(t *testing.T, topo model.Topology) *Bundle {
	t.Helper()
	b, err := Compile(topo)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// wgConf: node's WireGuard config of link in mode (udp | wss).
func wgConf(t *testing.T, b *Bundle, node, link, mode string) string {
	t.Helper()
	head := "# meridian link " + link + " mode " + mode + " "
	for p, body := range b.Files {
		if strings.HasPrefix(p, "nodes/"+node+"/etc/wireguard/") && strings.HasPrefix(body, head) {
			return body
		}
	}
	t.Fatalf("%s: no %s %s config", node, link, mode)
	return ""
}

func confAddr(conf string) string {
	m := regexp.MustCompile(`Address = ([0-9.]+)/`).FindStringSubmatch(conf)
	if m == nil {
		return ""
	}
	return m[1]
}

func confIface(conf string) string {
	m := regexp.MustCompile(`iface (\S+)`).FindStringSubmatch(conf)
	return m[1]
}

func TestGoldenNoIX(t *testing.T) {
	checkGolden(t, "noix_example.golden", noIXCompile(t, noIXTopo(nil)))
}

// The relay dials the plain hub's endpoint_v4 over each transport; the hub
// listens for it and routes the home prefixes back through the tunnel.
func TestNoIXRelayDialsPlainHub(t *testing.T) {
	for _, tr := range []model.Transport{model.TransportDirectWG, model.TransportUDPWSSFailover, model.TransportWGOverWSS} {
		b := noIXCompile(t, noIXTopo(func(t *model.Topology) {
			noIXLink(t, "access-hub", func(l *model.Link) { l.Transport = tr })
		}))
		hasUDP := tr != model.TransportWGOverWSS
		if hasUDP {
			c := wgConf(t, b, "access", "access-hub", "udp")
			if !strings.Contains(c, "Endpoint = 203.0.113.20:") {
				t.Fatalf("%s: relay does not dial the hub's endpoint_v4:\n%s", tr, c)
			}
			hc := wgConf(t, b, "hub", "access-hub", "udp")
			if strings.Contains(hc, "Endpoint = ") || !strings.Contains(hc, "ListenPort = ") {
				t.Fatalf("%s: hub side:\n%s", tr, hc)
			}
			routes := b.Files["nodes/hub/usr/local/sbin/meridian-routes.sh"]
			if !strings.Contains(routes, "ip route replace 192.0.2.0/24 dev "+confIface(hc)+"\n") {
				t.Fatalf("%s: hub has no return route over %s", tr, confIface(hc))
			}
		}
		if tr != model.TransportDirectWG {
			svc := b.Files["nodes/access/etc/systemd/system/wstunnel-client-access-hub.service"]
			if !strings.Contains(svc, "wss://203.0.113.20:8444") {
				t.Fatalf("%s: relay WSS client:\n%s", tr, svc)
			}
			if s := b.Files["nodes/hub/etc/systemd/system/wstunnel-meridian.service"]; !strings.Contains(s, "wss://0.0.0.0:8444") {
				t.Fatalf("%s: hub WSS server:\n%s", tr, s)
			}
		}
		if tr == model.TransportUDPWSSFailover {
			// The relay's own east failover: UDP leg first, its WSS leg
			// next; the hub answers on the leg a connection arrived on.
			udp, wss := wgConf(t, b, "access", "access-hub", "udp"), wgConf(t, b, "access", "access-hub", "wss")
			hudp, hwss := wgConf(t, b, "hub", "access-hub", "udp"), wgConf(t, b, "hub", "access-hub", "wss")
			fo := b.Files["nodes/access/usr/local/sbin/meridian-failover.sh"]
			for _, want := range []string{
				`EAST_IX="` + confIface(udp) + `"`, `EAST_WSS="` + confIface(wss) + `"`,
				`EAST_PEER_IX="` + confAddr(hudp) + `"`, `EAST_PEER_WSS="` + confAddr(hwss) + `"`,
			} {
				if !strings.Contains(fo, want) {
					t.Fatalf("relay failover lacks %s:\n%s", want, fo)
				}
			}
			if r := b.Files["nodes/access/usr/local/sbin/meridian-routes.sh"]; !strings.Contains(r, "ip route replace default dev "+confIface(udp)+" table 150") {
				t.Fatal("relay's east table does not use the hub tunnel")
			}
			nft := b.Files["nodes/hub/etc/nftables.d/meridian.nft"]
			for _, c := range []string{hudp, hwss} {
				if !strings.Contains(nft, "iifname \""+confIface(c)+"\" ct direction original ct mark set") {
					t.Fatalf("hub: no ingress mark for %s", confIface(c))
				}
			}
		} else if r := b.Files["nodes/access/usr/local/sbin/meridian-routes.sh"]; !strings.Contains(r, "table 150") || strings.Contains(r, "ip route replace default dev  table 150") {
			t.Fatalf("%s: relay east table:\n%s", tr, r)
		}
		for _, f := range []string{"nodes/hub/usr/local/sbin/meridian-routes.sh", "nodes/access/usr/local/sbin/meridian-routes.sh"} {
			if strings.Contains(b.Files[f], "preferred: ix") {
				t.Fatalf("%s: %s names an IX", tr, f)
			}
		}
	}
}

// Gateway: probe targets are the hub ends of the relay → hub tunnels; a
// disabled relay is not probed and does not share.
func TestNoIXGatewayProbesAndSharing(t *testing.T) {
	b := noIXCompile(t, noIXTopo(nil))
	fo := b.Files["nodes/gw/usr/local/sbin/meridian-failover.sh"]
	hubEnd := confAddr(wgConf(t, b, "hub", "access-hub", "udp"))
	backupEnd := confAddr(wgConf(t, b, "hkb", "gw-hkb", "wss"))
	if want := "UP_PROBE=('" + hubEnd + "' '" + hubEnd + "' '" + backupEnd + "')"; !strings.Contains(fo, want) {
		t.Fatalf("probes: want %s in\n%s", want, fo)
	}
	if !strings.Contains(fo, "UP_HUB=('hub' 'hub' 'hkb')") {
		t.Fatal("upstream hubs are not the actual hubs")
	}
	if strings.Contains(fo, "SH_NAME") || strings.Contains(fo, "access2") {
		t.Fatal("disabled relay in the gateway's failover")
	}

	b = noIXCompile(t, noIXTopo(enableAli2))
	fo = b.Files["nodes/gw/usr/local/sbin/meridian-failover.sh"]
	p1 := confAddr(wgConf(t, b, "hub", "access-hub", "udp"))
	p2 := confAddr(wgConf(t, b, "hub", "access2-hub", "udp"))
	if !strings.Contains(fo, "SH_NAME=('access' 'access2')") || !strings.Contains(fo, "SH_PROBE=('"+p1+"' '"+p2+"')") {
		t.Fatalf("sharing: want probes %s %s in\n%s", p1, p2, fo)
	}
	routes := b.Files["nodes/hub/usr/local/sbin/meridian-routes.sh"]
	nft := b.Files["nodes/hub/etc/nftables.d/meridian.nft"]
	for _, link := range []string{"access-hub", "access2-hub"} {
		ifc := confIface(wgConf(t, b, "hub", link, "udp"))
		if !strings.Contains(routes, "ip route replace 192.0.2.0/24 dev "+ifc+" table ") {
			t.Fatalf("hub: no ingress return table over %s", ifc)
		}
		if !strings.Contains(nft, "iifname \""+ifc+"\" ct direction original ct mark set") {
			t.Fatalf("hub: no ingress return mark for %s", ifc)
		}
	}
}

// Exit links in both dial directions, the gateway's endpoint policy and
// the egress legs.
func TestNoIXExitLinksEndpointsAndLegs(t *testing.T) {
	topo := noIXTopo(nil)
	b := noIXCompile(t, topo)
	if c := wgConf(t, b, "hub", "hub-dc1", "udp"); !strings.Contains(c, "Endpoint = 203.0.113.41:") {
		t.Fatalf("hub does not dial dc1:\n%s", c)
	}
	if c := wgConf(t, b, "dc2", "dc2-hub", "udp"); !strings.Contains(c, "Endpoint = 203.0.113.20:") {
		t.Fatalf("dc2 does not dial the hub:\n%s", c)
	}
	if c := wgConf(t, b, "hub", "dc2-hub", "udp"); strings.Contains(c, "Endpoint = ") {
		t.Fatalf("hub dials a NAT exit:\n%s", c)
	}
	nft := b.Files["nodes/gw/etc/nftables.d/meridian.nft"]
	direct := regexp.MustCompile(`set endpoint_direct4 \{[^}]*elements = \{ ([^}]*) \}`).FindStringSubmatch(nft)
	tunnel := regexp.MustCompile(`set endpoint_tunnel4 \{[^}]*elements = \{ ([^}]*) \}`).FindStringSubmatch(nft)
	if direct == nil || direct[1] != "203.0.113.10" {
		t.Fatalf("domestic relay endpoint not direct: %v", direct)
	}
	if tunnel == nil || !strings.Contains(tunnel[1], "203.0.113.20") || strings.Contains(tunnel[1], "203.0.113.11") {
		t.Fatalf("hub endpoint not tunnelled (or disabled relay listed): %v", tunnel)
	}
	// The gateway dials the backup hub itself: that endpoint keeps its
	// host route over the home uplink (no recursion through the tunnel).
	if r := b.Files["nodes/gw/usr/local/sbin/meridian-routes.sh"]; !strings.Contains(r, "ip route replace '203.0.113.30/32' via '192.0.2.1'") {
		t.Fatal("no dial exception for the backup hub")
	}
	legs, err := EgressLegs(topo)
	if err != nil {
		t.Fatal(err)
	}
	for _, l := range legs["access"] {
		if strings.HasPrefix(l, "access-hub|") && !strings.Contains(l, "access>hub|ep=203.0.113.20:") {
			t.Fatalf("relay leg %s", l)
		}
	}
	for id, ls := range legs {
		for _, l := range ls {
			if strings.Contains(l, ">ix|") || strings.Contains(l, "access2") {
				t.Fatalf("%s: leg %s", id, l)
			}
		}
	}
	if len(legs["access"]) == 0 || len(legs["dc2"]) == 0 {
		t.Fatalf("legs: %v", legs)
	}
}
