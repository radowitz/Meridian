package compile

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/radowitz/meridian/internal/defaults"
	"github.com/radowitz/meridian/internal/model"
	"github.com/radowitz/meridian/internal/validate"
)

// ------------------------------------------------ topologies without Mesh

// withoutMeshEdges removes every Mesh edge of t and everything that only
// exists through one (the pure-IPv6 Mesh exit, the group it is alone in and
// the rules aimed at them).
func withoutMeshEdges(t model.Topology) model.Topology {
	gone := map[string]bool{}
	var nodes []model.Node
	for _, n := range t.Nodes {
		if n.V6Workaround == model.WorkaroundMesh {
			gone[n.ID] = true
			continue
		}
		nodes = append(nodes, n)
	}
	t.Nodes = nodes
	var links []model.Link
	for _, l := range t.Links {
		if l.Transport == model.TransportCFMesh || gone[l.From] || gone[l.To] {
			continue
		}
		links = append(links, l)
	}
	t.Links = links
	goneGroup := map[string]bool{}
	var groups []model.RegionGroup
	for _, g := range t.Groups {
		var members []string
		for _, m := range g.Members {
			if !gone[m] {
				members = append(members, m)
			}
		}
		if len(members) == 0 {
			goneGroup[g.ID] = true
			continue
		}
		g.Members = members
		groups = append(groups, g)
	}
	t.Groups = groups
	var rules []model.Rule
	for _, r := range t.Rules {
		if gone[r.TargetExit] || goneGroup[r.TargetGroup] || goneGroup[r.TargetPool] {
			continue
		}
		rules = append(rules, r)
	}
	t.Rules = rules
	return t
}

// noMeshCompile pins the whole compile output (one SHA-256 over the apply
// order and the "<sha256> <path>" line of every file of every node,
// goldenDigest) of topologies without any Mesh edge to what the compiler
// produced before a cf_mesh link became a WireGuard leg carried over the
// Mesh (commit 516d115, the last one before that change; generated there
// with exactly the constructors of noMeshCases).
//
// These digests are not to be regenerated together with the example's
// golden files: a change that moves one of them changes what a topology
// without Mesh edges installs. If such a change is intended, it is a change
// of its own and this table is updated by hand, entry by entry.
var noMeshCompile = map[string]string{
	"example":                    "8b663a95b7b02c474cfb92000134aea48bdec0a24cc9420d581f55d44f470618",
	"example_sniff":              "8f59f43702e506de4330696bc056f66778af0a4ce94740e2e706cde8e190bbdd",
	"example_groupdns":           "0e80476bd002211317cabd97d099a9c06d604224ac8726dc10aff0f3b9708a79",
	"example_remote_access":      "560a9807baec33f4ee53c4a8414dd0b360e20d00a771b334677712fa9a1fe45c",
	"example_stored_allocations": "8b663a95b7b02c474cfb92000134aea48bdec0a24cc9420d581f55d44f470618",
	"dual_hub":                   "e3017a4ca0ee1747475cbd9d93e7a581f1718ecdf7b71be11af5a39e415a0b5f",
	"dual_hub_sniff":             "372b3c3c7b768aa5db391cdc9934567ae898d20bcb31b0d2be1d59c40171d051",
	"shared_relays":              "1a70c63b78c88a75b018ce0dd284891e78983d7cfea70974824f027b4e9781c0", // R2: relay speed-test endpoint, QoS shell, config fields; T2 review-391aa50: protected switch transaction; QA: fallback counters, pending commit finish
	"nested":                     "7d0a6740d5365f888b9725bd20ac2963e5e7cfcbac4a40e0d3b816090eabac1b",
	"external":                   "86d27393e3f64c6d473e543f4a8babe2761a4aa2ca96dc24daeeb4f2c4d5e189",
}

func noMeshCases(t *testing.T) map[string]func() (model.Topology, map[string]string) {
	return map[string]func() (model.Topology, map[string]string){
		"example": func() (model.Topology, map[string]string) { return withoutMeshEdges(defaults.Example()), nil },
		"example_sniff": func() (model.Topology, map[string]string) {
			topo := withoutMeshEdges(defaults.Example())
			topo.Settings.Sniff = &model.SniffSettings{Enabled: true}
			return topo, nil
		},
		"example_groupdns": func() (model.Topology, map[string]string) {
			topo, dec := groupDNSExample()
			return withoutMeshEdges(topo), dec
		},
		"example_remote_access": func() (model.Topology, map[string]string) {
			topo, _ := raExample(t)
			// Fixed keys: raExample generates fresh ones.
			for i := range topo.RemoteAccess.Devices {
				topo.RemoteAccess.Devices[i].PublicKey = base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{byte(i + 1)}, 32))
			}
			topo.RemoteAccess.PublicKey = base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{9}, 32))
			return withoutMeshEdges(topo), nil
		},
		// The same document as a store holds it: region groups migrated and
		// the allocation table written.
		"example_stored_allocations": func() (model.Topology, map[string]string) {
			topo := withoutMeshEdges(defaults.Example())
			model.MigrateRegionGroups(&topo)
			model.ReconcileAllocations(nil, &topo)
			return topo, nil
		},
		"dual_hub":      func() (model.Topology, map[string]string) { return defaults.DualHubExample(), nil },
		"shared_relays": func() (model.Topology, map[string]string) { return defaults.SharedRelaysExample(), nil },
		"nested":        func() (model.Topology, map[string]string) { return defaults.NestedExample(), nil },
		"external":      func() (model.Topology, map[string]string) { return defaults.ExternalExample(), nil },
		"dual_hub_sniff": func() (model.Topology, map[string]string) {
			topo := defaults.DualHubExample()
			topo.Settings.Sniff = &model.SniffSettings{Enabled: true}
			return topo, nil
		},
	}
}

// TestNoMeshCompileUnchangedByMeshTransport: a topology without Mesh edges
// compiles byte for byte to what it compiled to before the Mesh became the
// underlay of a WireGuard leg — every file of every node, the gateway's
// included. This is the one assertion of that; it shares no golden file
// with a topology that has Mesh edges and has no update switch.
func TestNoMeshCompileUnchangedByMeshTransport(t *testing.T) {
	cases := noMeshCases(t)
	if len(cases) != len(noMeshCompile) {
		t.Fatal("a case has no pinned digest")
	}
	for name, mk := range cases {
		topo, dec := mk()
		model.MigrateRegionGroups(&topo)
		for _, l := range topo.Links {
			if l.Transport == model.TransportCFMesh {
				t.Fatalf("%s: still has the Mesh edge %s", name, l.ID)
			}
		}
		if topo.HasMeshLegs() {
			t.Fatalf("%s: has Mesh legs", name)
		}
		b, err := CompileWithDecisions(topo, dec)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		sum := sha256.Sum256([]byte(goldenDigest(withLegacyFailoverComments(withoutTrafficCounters(t, topo, withoutProbeDNSException(t, topo, withoutDNSHostsInclude(b)))))))
		if got := hex.EncodeToString(sum[:]); got != noMeshCompile[name] {
			t.Errorf("%s: a topology without Mesh edges compiles differently than before the Mesh underlay (%s, pinned %s)", name, got, noMeshCompile[name])
		}
		// Nothing of the Mesh transport in it: no Mesh leg, no underlay
		// route, no Mesh files, no return table of a Mesh leg.
		for p, body := range b.Files {
			for _, bad := range []string{"mesh_underlay", "# mesh leg ", "meridian_return_mesh", "mesh_veth_", "meridian-mesh-publish", "never a next hop", model.DefaultMeshUnderlayPrefix[:8]} {
				if strings.Contains(body, bad) {
					t.Errorf("%s: %s carries %q", name, p, bad)
				}
			}
			if strings.Contains(p, "mesh") {
				t.Errorf("%s: file %s", name, p)
			}
		}
		// And nothing in the reports or the stored table.
		for _, p := range b.Paths {
			if len(p.MeshLinks) != 0 {
				t.Errorf("%s: path %s reports Mesh links", name, p.ExitID)
			}
		}
		for _, g := range b.GroupPaths {
			if g.Mesh || g.MeshMTU != 0 || len(g.MeshLinks) != 0 {
				t.Errorf("%s: group %s reports a Mesh hop", name, g.GroupID)
			}
		}
		if a := model.EffectiveAllocations(topo); a.Mesh != nil {
			t.Errorf("%s: a Mesh slot table without Mesh edges: %v", name, a.Mesh)
		}
	}
}

// Removing the Mesh edges of a topology gives exactly the no-Mesh output:
// the links that remain keep their interfaces, ports and addresses.
func TestMeshEdgesDoNotMoveOtherLinks(t *testing.T) {
	with := mustTunnels(t, defaults.Example())
	without := mustTunnels(t, withoutMeshEdges(defaults.Example()))
	byLink := map[string]Tunnel{}
	for _, tun := range with {
		byLink[tun.LinkID+"/"+tun.Mode] = tun
	}
	for _, tun := range without {
		got, ok := byLink[tun.LinkID+"/"+tun.Mode]
		if !ok || got.Iface() != tun.Iface() || got.WGPort != tun.WGPort || got.WestV4 != tun.WestV4 || got.EastULA != tun.EastULA || got.MTU != tun.MTU {
			t.Errorf("link %s (%s): %s port %d %s with Mesh edges, %s port %d %s without", tun.LinkID, tun.Mode, got.Iface(), got.WGPort, got.WestV4, tun.Iface(), tun.WGPort, tun.WestV4)
		}
	}
}

// ------------------------------------------------------- the WireGuard leg

func meshExample(t *testing.T) (model.Topology, *Bundle, []Tunnel) {
	t.Helper()
	topo := defaults.Example()
	return topo, mustCompile(t, topo), mustTunnels(t, topo)
}

// dualHubMesh is the dual-hub example with a Mesh leg from the primary hub
// (the IX) to dc1, and tw: a dial-out exit that also gets one.
func dualHubMesh() model.Topology {
	topo := defaults.DualHubExample()
	topo.Links = append(topo.Links, model.Link{ID: "ix-dc1-mesh", Name: "IX → dc1 Mesh", From: "ix", To: "dc1", Transport: model.TransportCFMesh, Enabled: true, Standby: true})
	return topo
}

// A cf_mesh link is a WireGuard tunnel between the hub and the exit: its
// own interface, port and subnet; the hub dials the exit's Mesh address,
// the exit listens (also when it is behind NAT); inside it is a direct
// leg. It is standby next to the hub's direct leg and the one tunnel of a
// pure-IPv6 Mesh exit.
func TestMeshLegIsAWireGuardLeg(t *testing.T) {
	topo, b, tunnels := meshExample(t)
	pool := netip.MustParsePrefix(model.DefaultMeshUnderlayPrefix)
	legs := 0
	seenAddr, seenIface := map[string]bool{}, map[string]bool{}
	for _, tun := range tunnels {
		if !tun.MeshLeg() {
			if tun.MeshAddr != "" {
				t.Fatalf("link %s is not a Mesh leg but has a Mesh address", tun.LinkID)
			}
			seenIface[tun.Iface()] = true
			continue
		}
		legs++
		addr, err := netip.ParseAddr(tun.MeshAddr)
		if err != nil || !pool.Contains(addr) || seenAddr[tun.MeshAddr] {
			t.Fatalf("leg %s: Mesh address %q", tun.LinkID, tun.MeshAddr)
		}
		seenAddr[tun.MeshAddr] = true
		if tun.Mode != "udp" || tun.West.ID != "hk-hub" || tun.East.Role != model.RoleExit || tun.DialOut || tun.OuterV6 ||
			tun.Dialer().ID != "hk-hub" || tun.Listener().ID != tun.East.ID || tun.MTU != 1280 || tun.WGPort == 0 || seenIface[tun.Iface()] {
			t.Fatalf("leg %+v", tun)
		}
		sole := tun.East.ID == "v6-v4out"
		if tun.Standby == sole {
			t.Fatalf("leg %s: standby %v, sole %v", tun.LinkID, tun.Standby, sole)
		}
		hub := b.File("nodes/hk-hub/etc/wireguard/" + tun.Iface() + ".conf")
		exit := b.File("nodes/" + tun.East.ID + "/etc/wireguard/" + tun.Iface() + ".conf")
		for _, want := range []string{
			fmt.Sprintf("Endpoint = %s:%d\n", tun.MeshAddr, tun.WGPort), "AllowedIPs = 0.0.0.0/0, ::/0\n", "PersistentKeepalive = 25\n", "MTU = 1280\n", "Table = off\n",
			"Address = " + tun.WestV4 + "/30, " + tun.WestULA + "/64\n",
		} {
			if !strings.Contains(hub, want) {
				t.Errorf("hub %s lacks %q:\n%s", tun.Iface(), want, hub)
			}
		}
		if strings.Contains(hub, "ListenPort") {
			t.Errorf("the hub listens on its Mesh leg %s", tun.Iface())
		}
		for _, want := range []string{
			fmt.Sprintf("ListenPort = %d\n", tun.WGPort), "# Endpoint omitted", "MTU = 1280\n", "Table = off\n",
			"AllowedIPs = 192.0.2.0/24, 10.66.200.0/24, " + tun.WestV4 + "/32, fd66::/48",
		} {
			if !strings.Contains(exit, want) {
				t.Errorf("exit %s %s lacks %q:\n%s", tun.East.ID, tun.Iface(), want, exit)
			}
		}
		if strings.Contains(exit, "\nEndpoint =") || strings.Contains(exit, "PersistentKeepalive") {
			t.Errorf("exit %s dials on its Mesh leg:\n%s", tun.East.ID, exit)
		}
		// The hub never dials a public address of the exit on this leg.
		for _, pub := range []string{tun.East.EndpointV4, tun.East.EndpointV6, tun.East.EndpointHost} {
			if pub != "" && strings.Contains(hub, pub) {
				t.Errorf("hub %s names the exit's public endpoint %s", tun.Iface(), pub)
			}
		}
		// Both ends bring the interface up with the others.
		for _, n := range []string{"hk-hub", tun.East.ID} {
			if up := b.File("nodes/" + n + "/usr/local/sbin/meridian-up.sh"); !regexp.MustCompile(`(?m)^for iface in .*\b` + tun.Iface() + `\b.*; do$`).MatchString(up) {
				t.Errorf("%s does not bring %s up", n, tun.Iface())
			}
		}
	}
	if legs != 4 {
		t.Fatalf("%d Mesh legs, want 4", legs)
	}
	// A dial-out exit: still the hub dials, the exit listens.
	nat := defaults.Example()
	nat.Links = append(nat.Links, model.Link{ID: "hub-tw-mesh", From: "hk-hub", To: "tw", Transport: model.TransportCFMesh, Enabled: true, Standby: true})
	nb := mustCompile(t, nat)
	leg := hubMeshLeg(mustTunnels(t, nat), "tw", "hk-hub")
	if leg.LinkID != "hub-tw-mesh" || leg.DialOut || leg.Listener().ID != "tw" {
		t.Fatalf("Mesh leg to the dial-out exit: %+v", leg)
	}
	if conf := nb.File("nodes/tw/etc/wireguard/" + leg.Iface() + ".conf"); !strings.Contains(conf, fmt.Sprintf("ListenPort = %d\n", leg.WGPort)) || strings.Contains(conf, "# NAT dial-out: this node dials the hub") {
		t.Fatalf("dial-out exit's Mesh leg:\n%s", conf)
	}
	// The link's resources name the address the exit publishes.
	for _, r := range LinkResources(topo) {
		l, _ := topo.LinkByID(r.LinkID)
		if (l.Transport == model.TransportCFMesh) != (r.Mesh != nil) {
			t.Fatalf("link %s: Mesh resource %+v", r.LinkID, r.Mesh)
		}
		if r.Mesh != nil && (r.State != "allocated" || !seenAddr[r.Mesh.Addr] || r.Mesh.Route != r.Mesh.Addr+"/32" || r.Mesh.PathMTU != 1280 || r.Mesh.PayloadMTU != 1216 || r.Mesh.DeviceMTU != 1280 || r.Listener != r.Mesh.Exit || r.Dialer != "hk-hub") {
			t.Fatalf("link %s: %+v %+v", r.LinkID, r, r.Mesh)
		}
	}
}

// Client traffic stays on WireGuard: the hub's table of an exit with both
// legs points at the direct leg, the table of the pure-IPv6 Mesh exit at
// its Mesh leg's interface, and every exit decapsulates and NATs to its own
// WAN exactly as without the Mesh leg (same resolver, same masquerade).
func TestMeshExitEgressIsTheExitsOwnUplink(t *testing.T) {
	topo, b, tunnels := meshExample(t)
	exits := planExits(topo, tunnels)
	plain := mustCompile(t, withoutMeshEdges(defaults.Example()))
	hubRoutes := b.File("nodes/hk-hub/usr/local/sbin/meridian-routes.sh")
	for _, e := range exits {
		if e.MeshIface == "" {
			continue
		}
		want := hubDirect(tunnels, e.Node.ID, "hk-hub").Iface()
		if e.MeshSole {
			want = e.MeshIface
		}
		if e.HubIface != want || !switchable(e) || e.DNSULA == "" {
			t.Fatalf("exit %s: hub iface %q, want %q (plan %+v)", e.Node.ID, e.HubIface, want, e)
		}
		for _, line := range []string{
			fmt.Sprintf("ip route replace default dev %s table %d\n", want, e.Table),
			fmt.Sprintf("ip -6 route replace default dev %s table %d\n", want, e.Table),
			fmt.Sprintf("ip route replace blackhole default metric 32767 table %d\n", e.Table),
		} {
			if !strings.Contains(hubRoutes, line) {
				t.Errorf("hub: exit %s table lacks %q", e.Node.ID, line)
			}
		}
		nft := b.File("nodes/" + e.Node.ID + "/etc/nftables.d/meridian.nft")
		dns := b.File("nodes/" + e.Node.ID + "/etc/smartdns/smartdns.conf")
		if !strings.Contains(nft, `oifname "eth0" ip saddr { 192.0.2.0/24, 10.66.200.0/24 } masquerade`) {
			t.Errorf("exit %s does not NAT to its own WAN:\n%s", e.Node.ID, chainBlock(nft, "srcnat"))
		}
		if strings.Contains(chainBlock(nft, "srcnat"), "mmesh") {
			t.Errorf("exit %s NATs onto the Mesh veth", e.Node.ID)
		}
		if e.MeshSole {
			continue
		}
		// With both legs: the exit's public NAT and its resolver are what
		// they are without the Mesh leg.
		pn := plain.File("nodes/" + e.Node.ID + "/etc/nftables.d/meridian.nft")
		if chainBlock(nft, "srcnat") != chainBlock(pn, "srcnat") {
			t.Errorf("exit %s: the Mesh leg changed its public NAT", e.Node.ID)
		}
		if dns != plain.File("nodes/"+e.Node.ID+"/etc/smartdns/smartdns.conf") {
			t.Errorf("exit %s: the Mesh leg changed its resolver config", e.Node.ID)
		}
	}
}

// ------------------------------------------------ no route onto the veth

// A route command with "default" that names the Mesh veth, its next-hops or
// the shell variables that stand for them.
var reMeshDefault = regexp.MustCompile(`(?m)^[^#\n]*\broute\b[^\n]*\bdefault\b[^\n]*(mmesh|169\.254\.66\.|fe80::66:|MESH_DEV|MESH_NH)`)

// A command that names the host end of the veth as a device (not mmesh-c,
// the sidecar's end, which only the sealing block inside the sidecar uses).
var reHostVeth = regexp.MustCompile(`dev mmesh(\s|"|$)`)

// No routing table on any host gets a default route onto the Mesh veth:
// not an exit's table, not a region group's, not main, static or dynamic.
// The only routes onto mmesh are the hub's /32 routes to its exits' Mesh
// addresses.
func TestMeshNoDefaultRouteOntoVeth(t *testing.T) {
	for name, topo := range map[string]model.Topology{"example": defaults.Example(), "dual_hub": dualHubMesh()} {
		b := mustCompile(t, topo)
		tunnels := mustTunnels(t, topo)
		hub := primaryHubID(topo)
		for p, body := range b.Files {
			if !strings.HasSuffix(p, ".sh") {
				continue
			}
			if m := reMeshDefault.FindString(body); m != "" {
				t.Errorf("%s %s: a default route onto the Mesh veth: %q", name, p, m)
			}
			for _, line := range strings.Split(body, "\n") {
				trim := strings.TrimSpace(line)
				if strings.HasPrefix(trim, "#") || !reHostVeth.MatchString(trim) || !strings.Contains(trim, "ip ") {
					continue
				}
				// Outside mesh-up, the only commands naming "dev mmesh" are
				// the underlay ones (a /32 via the sidecar, or the exit's
				// own address).
				if strings.HasSuffix(p, "meridian-mesh-up.sh") && !strings.Contains(trim, "route") {
					continue
				}
				ok := strings.Contains(trim, `"$a/32" via 169.254.66.2 dev mmesh`) || strings.Contains(trim, `"$a" via 169.254.66.2 dev mmesh`) ||
					strings.Contains(trim, "ip -4 route show dev mmesh") || regexp.MustCompile(`^ip addr replace 10\.68\.0\.\d+/32 dev mmesh`).MatchString(trim)
				if !ok {
					t.Errorf("%s %s: unexpected command onto the Mesh veth: %s", name, p, trim)
				}
			}
		}
		// The hub: every underlay route is gated on the seal and backed by
		// a blackhole of the same /32.
		routes := b.File("nodes/" + hub + "/usr/local/sbin/meridian-routes.sh")
		pt := withPendingMeshHosts(topo)
		tunnels = mustTunnels(t, pt)
		fn := meshUnderlayShell(mustNode(t, pt, hub), tunnels)
		if !strings.Contains(routes, fn+"mesh_underlay\n") {
			t.Fatalf("%s: the hub's routes script does not run mesh_underlay", name)
		}
		if _, ok := b.Files["nodes/"+hub+"/usr/local/sbin/meridian-mesh-up.sh"]; ok {
			t.Fatalf("%s: a sidecar script is still compiled", name)
		}
		for _, tun := range meshLegsOn(tunnels, hub) {
			if !strings.Contains(fn, tun.MeshAddr) {
				t.Errorf("%s: mesh_underlay lacks %s", name, tun.MeshAddr)
			}
		}
		// The hub blackholes the exits' Mesh addresses before any WireGuard
		// interface comes up (a leg starts its handshake at once), and the
		// sidecar is sealed before the routes script runs.
		up := b.File("nodes/" + hub + "/usr/local/sbin/meridian-up.sh")
		guard := meshUnderlayGuard(mustNode(t, pt, hub), tunnels)
		for _, tun := range meshLegsOn(tunnels, hub) {
			if !strings.Contains(guard, "ip route replace blackhole "+tun.MeshAddr+"/32 metric 32767\n") {
				t.Errorf("%s: no early blackhole for %s", name, tun.MeshAddr)
			}
		}
		gAt, wgAt, meshAt, routesAt := strings.Index(up, guard), strings.Index(up, "wg-quick up"), strings.Index(up, "meridian-mesh-up.sh"), strings.Index(up, "/usr/local/sbin/meridian-routes.sh\n")
		if guard == "" || gAt < 0 || !(gAt < wgAt && wgAt < meshAt && meshAt < routesAt) { // meshAt: the legacy-script hook, unchanged
			t.Errorf("%s: hub up order: blackholes %d, WireGuard %d, seal %d, routes %d", name, gAt, wgAt, meshAt, routesAt)
		}
		// An exit only listens on its Mesh leg: nothing to guard.
		for _, m := range topo.MeshLegs() {
			if g := meshUnderlayGuard(mustNode(t, topo, m.Exit), tunnels); g != "" {
				t.Errorf("%s: exit %s got an underlay guard: %s", name, m.Exit, g)
			}
		}
		// The group switch refuses the veth on every hub of a topology with
		// Mesh legs (the backup hub included, which has no veth at all), in
		// the static script and in the failover script alike.
		fail := b.File("nodes/" + hub + "/usr/local/sbin/meridian-failover.sh")
		for _, n := range topo.Nodes {
			if n.Role != model.RoleHub {
				continue
			}
			for _, f := range []string{"meridian-routes.sh", "meridian-failover.sh"} {
				body := b.File("nodes/" + n.ID + "/usr/local/sbin/" + f)
				if !strings.Contains(body, "never a next hop") || strings.Contains(body, "mmesh is not sealed; table") {
					t.Errorf("%s: group_hop in %s's %s can still point a table at the Mesh veth", name, n.ID, f)
				}
			}
		}
		// No group policy asks for a Mesh hop.
		groups := planGroups(topo, planExits(topo, tunnels))
		for _, g := range groups {
			if g.Policy().Mesh {
				t.Errorf("%s: group %s has a Mesh fallback", name, g.Group.ID)
			}
			if g.Dynamic && !regexp.MustCompile(`(?m)^  group_step `+regexp.QuoteMeta(shQuote(g.Group.ID))+` \d+ \S+ 0 `).MatchString(fail) {
				t.Errorf("%s: group %s is not stepped with mesh=0", name, g.Group.ID)
			}
		}
	}
}

func mustNode(t *testing.T, topo model.Topology, id string) model.Node {
	t.Helper()
	n, ok := topo.NodeByID(id)
	if !ok {
		t.Fatalf("no node %s", id)
	}
	return n
}

// mesh_underlay on the hub under bash with a stub ip: sealed, the routes
// to the exits' Mesh addresses go via the sidecar; unsealed or without the
// veth they are removed and only the blackholes stay; a route via the
// sidecar to anything else (a default route, a peer that is gone) is
// removed; nothing else is ever touched.
func TestMeshUnderlayRoutesFollowTheSeal(t *testing.T) {
	if !bashOK() {
		t.Skip("bash not available")
	}
	topo, _, tunnels := meshExample(t)
	fn := meshUnderlayShell(mustNode(t, topo, "hk-hub"), tunnels)
	addrs := meshUnderlayAddrs(mustNode(t, topo, "hk-hub"), tunnels)
	if len(addrs) != 4 {
		t.Fatalf("hub underlay addresses %v", addrs)
	}
	for _, c := range []struct {
		name         string
		link, sealed bool
	}{{"sealed", true, true}, {"not sealed", true, false}, {"no veth", false, true}} {
		dir := t.TempDir()
		run, bin := filepath.Join(dir, "run"), filepath.Join(dir, "bin")
		for _, d := range []string{run, bin} {
			if err := os.MkdirAll(d, 0o755); err != nil {
				t.Fatal(err)
			}
		}
		if c.sealed {
			writeFile(t, filepath.Join(run, "mesh-sealed"), "")
		}
		link := "1"
		if c.link {
			link = "0"
		}
		// "ip -4 route show dev mmesh" lists what an older install left.
		stub := fmt.Sprintf(`#!/bin/bash
if [ "$1" = link ]; then exit %s; fi
if [ "$1 $2 $3" = "-4 route show" ]; then
  echo "default via 169.254.66.2"
  echo "10.68.0.1 via 169.254.66.2"
  echo "10.68.0.99 via 169.254.66.2"
  echo "169.254.66.0/30 proto kernel scope link src 169.254.66.1"
  exit 0
fi
echo "ip $*" >> %q
exit 0
`, link, filepath.Join(dir, "ip.log"))
		if err := os.WriteFile(filepath.Join(bin, "ip"), []byte(stub), 0o755); err != nil {
			t.Fatal(err)
		}
		script := "set -euo pipefail\n" + strings.ReplaceAll(fn, "/run/meridian", run) + "mesh_underlay\n"
		cmd := exec.Command("bash", "-c", script)
		cmd.Env = append(os.Environ(), "PATH="+bin+":"+os.Getenv("PATH"))
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("%s: %v\n%s", c.name, err, out)
		}
		logb, _ := os.ReadFile(filepath.Join(dir, "ip.log"))
		log := string(logb)
		live := c.link && c.sealed
		for _, a := range addrs {
			if !strings.Contains(log, "ip route replace blackhole "+a+"/32 metric 32767\n") {
				t.Errorf("%s: no blackhole behind %s:\n%s", c.name, a, log)
			}
			add := "ip route replace " + a + "/32 via 169.254.66.2 dev mmesh\n"
			del := "ip route del " + a + "/32 via 169.254.66.2 dev mmesh\n"
			if strings.Contains(log, add) != live || strings.Contains(log, del) == live {
				t.Errorf("%s: route to %s (live %v):\n%s", c.name, a, live, log)
			}
		}
		// Leftovers via the sidecar that are not a current peer go away.
		for _, stale := range []string{"ip route del default via 169.254.66.2 dev mmesh\n", "ip route del 10.68.0.99 via 169.254.66.2 dev mmesh\n"} {
			if !strings.Contains(log, stale) {
				t.Errorf("%s: %q not removed:\n%s", c.name, strings.TrimSpace(stale), log)
			}
		}
		for _, line := range strings.Split(strings.TrimSpace(log), "\n") {
			if strings.Contains(line, "table ") || strings.Contains(line, "ip rule") || strings.Contains(line, " replace default") ||
				(strings.Contains(line, "route replace") && !strings.Contains(line, "/32")) {
				t.Errorf("%s: mesh_underlay touched something else: %s", c.name, line)
			}
		}
	}
}

// --------------------------------------------------------------- the seal

// sealBlock is the part of a compiled meridian-mesh-up.sh that runs inside
// the sidecar's network namespace.
func sealBlock(t *testing.T, script string) string {
	t.Helper()
	start := strings.Index(script, "<<'EOS'\n")
	end := strings.Index(script, "\nEOS\n")
	if start < 0 || end < start {
		t.Fatal("no sealing block")
	}
	return script[start+len("<<'EOS'\n") : end+1]
}

// runSeal runs a sealing block under bash with stub ip and nft and returns
// the ip commands and the nft batch it loaded. warp: the sidecar has a WARP
// device of that name ("" none).
func runSeal(t *testing.T, block, warp string) (ipLog, nft string) {
	t.Helper()
	dir := t.TempDir()
	bin := filepath.Join(dir, "bin")
	if err := os.MkdirAll(bin, 0o755); err != nil {
		t.Fatal(err)
	}
	links := "1: lo: <LOOPBACK>\\n2: eth0@if9: <UP>\\n3: mmesh-c@if7: <UP>\\n"
	if warp != "" {
		links += "4: " + warp + ": <POINTOPOINT,UP>\\n"
	}
	// An older seal left a copied default route, a foreign prefix and the
	// veth link route in table 170.
	stub := fmt.Sprintf(`#!/bin/bash
case "$*" in
  "-o link show") printf '%s'; exit 0 ;;
  "-d link show %s") echo "    link/none"; exit 0 ;;
  "-d link show"*) echo "    link/ether"; exit 0 ;;
  "rule show"|"-6 rule show") exit 0 ;;
  "route show table 170") printf 'unreachable default metric 32767\ndefault dev %s scope link\n198.51.100.0/24 dev %s scope link\n169.254.66.0/30 dev mmesh-c scope link\n10.68.0.3 dev %s scope link\n100.96.0.0/12 dev %s scope link\n'; exit 0 ;;
  "-6 route show table 170") printf 'unreachable default metric 32767\nfd66::53:d dev %s metric 1024\n'; exit 0 ;;
esac
echo "ip $*" >> %q
exit 0
`, links, warp, warp, warp, warp, warp, warp, filepath.Join(dir, "ip.log"))
	if err := os.WriteFile(filepath.Join(bin, "ip"), []byte(stub), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(bin, "nft"), []byte(fmt.Sprintf("#!/bin/bash\ncat >> %q\n", filepath.Join(dir, "nft.in"))), 0o755); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("bash", "-s")
	cmd.Stdin = strings.NewReader(block)
	cmd.Env = append(os.Environ(), "PATH="+bin+":"+os.Getenv("PATH"))
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("sealing block: %v\n%s", err, out)
	}
	a, _ := os.ReadFile(filepath.Join(dir, "ip.log"))
	n, _ := os.ReadFile(filepath.Join(dir, "nft.in"))
	return string(a), string(n)
}

// chainRules are the rule lines of chain name in an nft batch (the first
// table that has it), without the "type …" line.
func chainRules(nft, name string) []string {
	start := strings.Index(nft, "  chain "+name+" {\n")
	if start < 0 {
		return nil
	}
	body := nft[start+len("  chain "+name+" {\n"):]
	end := strings.Index(body, "\n  }")
	if end >= 0 {
		body = body[:end]
	}
	var out []string
	for _, l := range strings.Split(body, "\n") {
		l = strings.TrimSpace(l)
		if l == "" || strings.HasPrefix(l, "type ") {
			continue
		}
		out = append(out, l)
	}
	return out
}

// An exit with both legs answers through the leg a connection arrived on
// (connection mark by ingress interface, one table per leg), answers the
// region-group resolver addresses on both, takes its Mesh leg's WireGuard
// only from the Mesh veth and forwards nothing to or from the veth.
func TestMeshExitReturnAndVeth(t *testing.T) {
	topo, b, tunnels := meshExample(t)
	direct, leg := hubDirect(tunnels, "us", "hk-hub"), hubMeshLeg(tunnels, "us", "hk-hub")
	nft := b.File("nodes/us/etc/nftables.d/meridian.nft")
	routes := b.File("nodes/us/usr/local/sbin/meridian-routes.sh")
	rt := b.File("nodes/us/etc/iproute2/rt_tables.d/meridian.conf")
	in := chainBlock(nft, "hub_return_in")
	for _, want := range []string{
		fmt.Sprintf(`iifname "%s" ct direction original ct mark set %#x`, direct.Iface(), markHubReturnPrimary),
		fmt.Sprintf(`iifname "%s" ct direction original ct mark set %#x`, leg.Iface(), markHubReturnMesh),
		fmt.Sprintf(`ct direction reply ct mark %#x meta mark set %#x`, markHubReturnMesh, markHubReturnMesh),
		fmt.Sprintf(`ct direction reply ct mark %#x meta mark set %#x`, markHubReturnPrimary, markHubReturnPrimary),
	} {
		if !strings.Contains(in, want) {
			t.Errorf("us hub_return_in lacks %q:\n%s", want, in)
		}
	}
	if out := chainBlock(nft, "hub_return_out"); !strings.Contains(out, fmt.Sprintf("ct mark %#x meta mark set %#x", markHubReturnMesh, markHubReturnMesh)) {
		t.Errorf("us local replies do not follow the Mesh leg:\n%s", out)
	}
	for _, want := range []string{
		fmt.Sprintf("ip route replace 10.66.0.0/16 dev %s table %d\n", leg.Iface(), tableHubReturnMesh),
		fmt.Sprintf("ip -6 route replace fd66::/48 dev %s table %d\n", leg.Iface(), tableHubReturnMesh),
		fmt.Sprintf("ip route replace blackhole default metric 32767 table %d\n", tableHubReturnMesh),
		fmt.Sprintf("ip rule add fwmark %#x lookup %d priority %d\n", markHubReturnMesh, tableHubReturnMesh, prioHubReturn+2),
		fmt.Sprintf("ip route replace 10.66.0.0/16 dev %s table %d\n", direct.Iface(), tableHubReturnPrimary),
		// The exit's unmarked routes home are the direct leg's, as before.
		fmt.Sprintf("ip route replace %s dev %s\n", transitV4Net(), direct.Iface()),
	} {
		if !strings.Contains(routes, want) {
			t.Errorf("us routes lack %q", strings.TrimSpace(want))
		}
	}
	// The return tables never hold a default route out of the WAN or onto
	// the veth.
	for _, line := range strings.Split(routes, "\n") {
		if (strings.Contains(line, fmt.Sprintf("table %d", tableHubReturnMesh)) || strings.Contains(line, fmt.Sprintf("table %d", tableHubReturnPrimary))) &&
			strings.Contains(line, " default ") && !strings.Contains(line, "blackhole default metric 32767") {
			t.Errorf("a return table gets a default route: %s", line)
		}
	}
	if !strings.Contains(rt, fmt.Sprintf("%d\tmeridian_return_mesh\n", tableHubReturnMesh)) || !strings.Contains(rt, fmt.Sprintf("%d\tmeridian_return_primary\n", tableHubReturnPrimary)) {
		t.Errorf("us rt_tables:\n%s", rt)
	}
	// Group resolver addresses: answered on both legs.
	if dns := chainBlock(nft, "group_dns"); !strings.Contains(dns, fmt.Sprintf(`iifname { "%s", "%s" } ip6 daddr %s udp dport 53 dnat`, direct.Iface(), leg.Iface(), validate.GroupResolverNet)) {
		t.Errorf("us group_dns:\n%s", dns)
	}
	// No sidecar veth any more. The exit has no Mesh node yet (pending):
	// its Mesh leg's WireGuard port is closed on every interface.
	if strings.Contains(nft, "mesh_veth") || strings.Contains(nft, `"mmesh"`) {
		t.Errorf("us still has sidecar veth rules")
	}
	if in := chainRules(nft, "mesh_host_input"); len(in) != 1 || !strings.HasPrefix(in[0], fmt.Sprintf(`udp dport { %d } drop`, leg.WGPort)) {
		t.Errorf("us mesh_host_input (pending): %v", in)
	}
	hub := b.File("nodes/hk-hub/etc/nftables.d/meridian.nft")
	if out := chainRules(hub, "mesh_host_output"); len(out) == 0 || !strings.HasPrefix(out[0], "ip daddr ") || !strings.Contains(out[0], " drop") {
		t.Errorf("hub mesh_host_output (pending): %v", out)
	}
	// Docker coexistence: the veth is never a forwarding interface, the
	// leg's WireGuard interface is one like the direct leg's.
	for _, n := range []string{"hk-hub", "us"} {
		fw := b.File("nodes/" + n + "/usr/local/sbin/meridian-fwcompat.sh")
		if strings.Contains(fw, "mmesh") || !strings.Contains(fw, leg.Iface()) {
			t.Errorf("%s fwcompat: mmesh or missing %s", n, leg.Iface())
		}
	}
	// The pure-IPv6 Mesh exit has one leg: its routes home are the leg's,
	// and it needs no per-leg tables.
	sole := hubMeshLeg(tunnels, "v6-v4out", "hk-hub")
	sr := b.File("nodes/v6-v4out/usr/local/sbin/meridian-routes.sh")
	if !strings.Contains(sr, fmt.Sprintf("ip route replace %s dev %s\n", transitV4Net(), sole.Iface())) || strings.Contains(sr, "hub return paths") ||
		strings.Contains(b.File("nodes/v6-v4out/etc/nftables.d/meridian.nft"), "hub_return_in") {
		t.Errorf("pure-IPv6 Mesh exit routes:\n%s", sr)
	}
	// No sidecar: no re-seal timer, no sidecar files on any Mesh end.
	for _, m := range topo.MeshLegs() {
		for _, id := range []string{m.Exit, m.Hub} {
			if b.File("nodes/"+id+"/etc/systemd/system/meridian-mesh-seal.timer") != "" || b.File("nodes/"+id+"/etc/meridian/mesh-sidecar.compose.yml") != "" {
				t.Errorf("%s still has sidecar files", id)
			}
		}
	}
}

// With a backup hub the primary hub's Mesh leg is a third way into the
// exit: three return tables, the hub-independent resolver address answered
// on all three, and the backup hub knows nothing of the Mesh.
func TestMeshLegWithBackupHub(t *testing.T) {
	topo := dualHubMesh()
	b := mustCompile(t, topo)
	tunnels := mustTunnels(t, topo)
	leg := hubMeshLeg(tunnels, "dc1", "ix")
	if leg.LinkID == "" || !leg.Standby || hubMeshLeg(tunnels, "dc1", "hkb").LinkID != "" {
		t.Fatalf("Mesh leg %+v", leg)
	}
	n, _ := topo.NodeByID("dc1")
	rets := exitHubReturns(topo, n, tunnels)
	if len(rets) != 3 || rets[0].Table != tableHubReturnPrimary || rets[1].Table != tableHubReturnBackup || rets[2].Table != tableHubReturnMesh || !rets[2].Mesh || rets[2].Iface != leg.Iface() {
		t.Fatalf("dc1 return paths %+v", rets)
	}
	nft := b.File("nodes/dc1/etc/nftables.d/meridian.nft")
	e, _ := exitByID(planExits(topo, tunnels), "dc1")
	if dns := chainBlock(nft, "exit_dns"); !strings.Contains(dns, `"`+leg.Iface()+`"`) || !strings.Contains(dns, e.Resolver) {
		t.Errorf("dc1 does not answer its resolver address on the Mesh leg:\n%s", dns)
	}
	// dc2 and the relay have no Mesh leg: their files are what they are
	// without the edge. The backup hub's change by one thing only: its
	// group_hop refuses the Mesh veth, like the primary's.
	plain := mustCompile(t, defaults.DualHubExample())
	for p, body := range plain.Files {
		if strings.HasPrefix(p, "nodes/dc2/") || strings.HasPrefix(p, "nodes/access/") {
			if b.Files[p] != body {
				t.Errorf("%s changed although the node has no Mesh leg", p)
			}
		}
		if strings.HasPrefix(p, "nodes/hkb/") && b.Files[p] != body {
			if !strings.HasSuffix(p, "meridian-routes.sh") && !strings.HasSuffix(p, "meridian-failover.sh") {
				t.Errorf("backup hub file %s changed", p)
			} else if meshGroupHopShell(body) != b.Files[p] {
				t.Errorf("backup hub file %s changed by more than group_hop's refusal of the veth", p)
			}
		}
	}
	for p := range b.Files {
		if (strings.HasPrefix(p, "nodes/hkb/") || strings.HasPrefix(p, "nodes/dc2/") || strings.HasPrefix(p, "nodes/gw/")) && strings.Contains(p, "mesh") {
			t.Errorf("a node without a Mesh leg got %s", p)
		}
	}
	// The gateway changes only by the clamps of dc1's mark and its group's.
	for p, body := range plain.Files {
		if strings.HasPrefix(p, "nodes/gw/") && b.Files[p] != body && !strings.HasSuffix(p, "meridian.nft") && !strings.HasSuffix(p, "meridian-verify.sh") {
			t.Errorf("gateway file %s changed", p)
		}
	}
}

// A hub whose groups switch to members behind another exit's tunnel (the
// next-hop form of group_hop) and that also has a Mesh leg: both shell
// variants compose, and the veth is still refused.
func TestMeshLegWithSharedHops(t *testing.T) {
	topo := defaults.NestedExample()
	topo.Links = append(topo.Links, model.Link{ID: "ix-dc2-mesh", From: "ix", To: "dc2", Transport: model.TransportCFMesh, Enabled: true, Standby: true})
	b := mustCompile(t, topo)
	fail := b.File("nodes/ix/usr/local/sbin/meridian-failover.sh")
	for _, want := range []string{"never a next hop", `ip route replace default via "$nh4" dev "$dev" onlink table "$table"`, `if [ "${dev%%|*}" = "$MESH_DEV" ]; then`} {
		if !strings.Contains(fail, want) {
			t.Errorf("hub failover lacks %q", want)
		}
	}
	if reMeshDefault.MatchString(fail) {
		t.Error("a default route onto the Mesh veth")
	}
	if bashOK() {
		p := filepath.Join(t.TempDir(), "f.sh")
		writeFile(t, p, fail)
		if out, err := exec.Command("bash", "-n", p).CombinedOutput(); err != nil {
			t.Fatalf("hub failover does not parse: %v\n%s", err, out)
		}
	}
}

// ------------------------------------------------------------ MTU and MSS

// The Mesh leg's MTU enters every clamp that can carry it: the exit's own
// mark, the mark of each group that can switch to the exit, the exit's own
// TCP and the hub's own TCP into the leg — and nothing else moves: the
// floor and the exits and groups without a Mesh leg keep their values.
func TestMeshLegMTUClamps(t *testing.T) {
	topo, b, tunnels := meshExample(t)
	plain := mustCompile(t, withoutMeshEdges(defaults.Example()))
	gw := b.File("nodes/gw/etc/nftables.d/meridian.nft")
	if got, want := clampOf(t, gw), clampOf(t, plain.File("nodes/gw/etc/nftables.d/meridian.nft")); got != want || got != "1320/1300" {
		t.Fatalf("the floor moved with the Mesh legs: %s (without them %s)", got, want)
	}
	exits := planExits(topo, tunnels)
	groups := planGroups(topo, exits)
	meshExits := meshLegExits(topo)
	if len(meshExits) != 4 {
		t.Fatalf("exits with a Mesh leg: %v", meshExits)
	}
	for _, p := range b.Paths {
		want := 1360
		if meshExits[p.ExitID] {
			want = 1216
		}
		if p.MTU != want || p.MSS4 != want-40 || p.MSS6 != want-60 {
			t.Errorf("path %s: %d %d/%d, want %d", p.ExitID, p.MTU, p.MSS4, p.MSS6, want)
		}
	}
	for _, e := range exits {
		m := markPlan{e.Mark, e.Index, e.TransitV4, e.TransitV6}
		for _, c := range []string{"mss", "local_mss", "local_mss_in"} {
			got := strings.Join(mssValues(strings.Join(markRules(gw, c, m), "\n")), "/")
			want := ""
			if meshExits[e.Node.ID] {
				want = "1176/1156"
			}
			if got != want {
				t.Errorf("exit %s chain %s: clamp %q, want %q", e.Node.ID, c, got, want)
			}
		}
	}
	reports := map[string]validate.GroupPathReport{}
	for _, r := range b.GroupPaths {
		reports[r.GroupID] = r
	}
	clamped := 0
	for _, g := range groups {
		if !g.Dynamic {
			continue
		}
		hasLeg := false
		for _, e := range g.Try {
			hasLeg = hasLeg || meshExits[e.Node.ID]
		}
		r := reports[g.Group.ID]
		if r.Mesh != hasLeg || (hasLeg && (r.MTU != 1216 || r.MeshMTU != 1216 || len(r.MeshLinks) == 0 || r.MSS4 != 1176 || r.MSS6 != 1156)) || (!hasLeg && (r.MTU != 1360 || r.MeshMTU != 0)) {
			t.Errorf("group %s report %+v (member with a Mesh leg: %v)", g.Group.ID, r, hasLeg)
		}
		m := markPlan{g.Mark, g.Index, g.TransitV4, g.TransitV6}
		for _, c := range []string{"mss", "local_mss", "local_mss_in"} {
			got := strings.Join(mssValues(strings.Join(markRules(gw, c, m), "\n")), "/")
			want := ""
			if hasLeg {
				want = "1176/1156"
			}
			if got != want {
				t.Errorf("group %s chain %s: clamp %q, want %q", g.Group.ID, c, got, want)
			}
		}
		if hasLeg {
			clamped++
		}
	}
	if clamped < 3 {
		t.Fatalf("%d groups with a Mesh leg checked", clamped)
	}
	// The hub's own TCP into a Mesh leg; an exit's own TCP.
	hub := b.File("nodes/hk-hub/etc/nftables.d/meridian.nft")
	for _, tun := range meshLegsOn(tunnels, "hk-hub") {
		for _, chain := range []string{"tunnel_mss_out", "tunnel_mss_in"} {
			dir := map[string]string{"tunnel_mss_out": "oifname", "tunnel_mss_in": "iifname"}[chain]
			if body := chainBlock(hub, chain); !strings.Contains(body, fmt.Sprintf(`%s "%s" tcp flags syn meta nfproto ipv4 tcp option maxseg size > 1176 tcp option maxseg size set 1176`, dir, tun.Iface())) ||
				!strings.Contains(body, fmt.Sprintf(`%s "%s" tcp flags syn meta nfproto ipv6 tcp option maxseg size > 1156 tcp option maxseg size set 1156`, dir, tun.Iface())) {
				t.Errorf("hub %s does not clamp its Mesh leg %s:\n%s", chain, tun.Iface(), body)
			}
		}
	}
	if got := strings.Join(mssValues(chainBlock(b.File("nodes/us/etc/nftables.d/meridian.nft"), "tunnel_mss_out")), " "); got != "1176 1156" {
		t.Errorf("us clamps its own TCP to %s", got)
	}
	if got := strings.Join(mssValues(chainBlock(b.File("nodes/jp/etc/nftables.d/meridian.nft"), "tunnel_mss_out")), " "); got != "1320 1300" {
		t.Errorf("jp (no Mesh leg) clamps its own TCP to %s", got)
	}

	// A larger Mesh path: 1340 leaves exactly 1280 (no fragment, the
	// interface follows); 1420 leaves 1360, the members' own MTU, and the
	// clamp is gone.
	for path, want := range map[int][3]int{1340: {1280, 1240, 1220}, 1420: {1360, 0, 0}} {
		topo := defaults.Example()
		for i := range topo.Links {
			if topo.Links[i].ID == "hub-us-mesh" {
				topo.Links[i].MTU = path
			}
		}
		nb := mustCompile(t, topo)
		leg := hubMeshLeg(mustTunnels(t, topo), "us", "hk-hub")
		if leg.MTU != want[0] || !strings.Contains(nb.File("nodes/us/etc/wireguard/"+leg.Iface()+".conf"), fmt.Sprintf("\nMTU = %d\n", want[0])) {
			t.Errorf("Mesh path %d: leg MTU %d, want %d", path, leg.MTU, want[0])
		}
		got := mssValues(chainBlockMark(t, topo, nb, "us"))
		if want[1] == 0 && len(got) != 0 || want[1] != 0 && strings.Join(got, " ") != fmt.Sprintf("%d %d", want[1], want[2]) {
			t.Errorf("Mesh path %d: us clamp %v, want %v", path, got, want)
		}
	}
}

// Adding a Mesh leg to a topology changes the two hosts at its ends and the
// gateway's clamps for the marks that can use it; every other node's files
// stay byte for byte what they were.
func TestMeshLegChangesOnlyItsEnds(t *testing.T) {
	base := withoutMeshEdges(defaults.Example())
	model.MigrateRegionGroups(&base)
	model.ReconcileAllocations(nil, &base)
	before := mustCompile(t, base)
	with := base
	with.Links = append(append([]model.Link(nil), base.Links...), model.Link{ID: "hub-jp-mesh", Name: "枢纽到日本 Mesh", From: "hk-hub", To: "jp", Transport: model.TransportCFMesh, Enabled: true, Standby: true})
	model.ReconcileAllocations(base.Allocations, &with)
	after := mustCompile(t, with)
	changed := map[string]bool{}
	for p, body := range after.Files {
		if before.Files[p] != body {
			changed[strings.Split(strings.TrimPrefix(p, "nodes/"), "/")[0]] = true
		}
	}
	for p := range before.Files {
		if _, ok := after.Files[p]; !ok {
			t.Errorf("%s disappeared", p)
		}
	}
	for n := range changed {
		if n != "hk-hub" && n != "jp" && n != "gw" {
			t.Errorf("node %s changed by a Mesh leg between hk-hub and jp", n)
		}
	}
	if !changed["hk-hub"] || !changed["jp"] || !changed["gw"] {
		t.Fatalf("changed nodes %v", changed)
	}
	// On the gateway: the firewall (clamps) and its verify script only.
	for p, body := range after.Files {
		if strings.HasPrefix(p, "nodes/gw/") && before.Files[p] != body && !strings.HasSuffix(p, "etc/nftables.d/meridian.nft") && !strings.HasSuffix(p, "meridian-verify.sh") {
			t.Errorf("gateway file %s changed", p)
		}
	}
	// The allocation: one link slot after the existing ones, one address.
	if with.Allocations.Mesh["jp"].Slot != 0 || len(with.Allocations.Mesh) != 1 {
		t.Fatalf("Mesh slots %v", with.Allocations.Mesh)
	}
	for id, s := range base.Allocations.Links {
		if with.Allocations.Links[id] != s {
			t.Errorf("link %s moved from slot %d to %d", id, s.Slot, with.Allocations.Links[id].Slot)
		}
	}
}

// meshReuseTopo is the example with the primary hub and/or one Mesh exit
// marked as reusing a host-level Mesh node (synthetic addresses).
func meshReuseTopo(t *testing.T, hubReuse, exitReuse bool) (model.Topology, string, string) {
	t.Helper()
	topo := defaults.Example()
	hub := primaryHubID(topo)
	var exit string
	for _, m := range topo.MeshLegs() {
		if m.Hub == hub {
			exit = m.Exit
			break
		}
	}
	for i := range topo.Nodes {
		switch {
		case hubReuse && topo.Nodes[i].ID == hub:
			topo.Nodes[i].MeshHost = &model.NodeMeshHost{Addr: "100.96.0.10", Iface: "CloudflareWARP"}
		case exitReuse && topo.Nodes[i].ID == exit:
			topo.Nodes[i].MeshHost = &model.NodeMeshHost{Addr: "100.96.0.11", Iface: "CloudflareWARP"}
		}
	}
	return topo, hub, exit
}

func TestMeshReuseCompile(t *testing.T) {
	// Every combination of ownership: both ends host-level nodes (found
	// or panel-installed: the compile does not distinguish them), one end
	// still to be installed (pending), or neither.
	for _, tc := range []struct {
		name          string
		hub, exitSide bool
	}{{"both", true, true}, {"hub", true, false}, {"exit", false, true}, {"none", false, false}} {
		topo, hub, exit := meshReuseTopo(t, tc.hub, tc.exitSide)
		b, err := Compile(topo)
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		f := b.Files
		leg, _ := topo.MeshLegOf(hub, exit)
		var conf string
		for k, v := range f {
			if strings.HasPrefix(k, "nodes/"+hub+"/etc/wireguard/") && strings.Contains(v, "# peer-node "+exit+"\n") && strings.Contains(v, "Mesh leg") {
				conf = v
			}
		}
		want := leg.Addr.String()
		if tc.exitSide {
			want = "100.96.0.11"
		}
		if !strings.Contains(conf, "Endpoint = "+want+":") {
			t.Fatalf("%s: hub Endpoint must be %s:\n%s", tc.name, want, conf)
		}
		for _, id := range []string{hub, exit} {
			for k := range f {
				if strings.HasPrefix(k, "nodes/"+id+"/") && (strings.Contains(k, "mesh-sidecar") || strings.Contains(k, "meridian-mesh-up.sh") || strings.Contains(k, "mesh-seal")) {
					t.Fatalf("%s: sidecar file %s still compiled", tc.name, k)
				}
			}
		}
		routes := f["nodes/"+hub+"/usr/local/sbin/meridian-routes.sh"]
		nft := f["nodes/"+hub+"/etc/nftables.d/meridian.nft"]
		live := tc.hub && tc.exitSide
		if !strings.Contains(routes, `ip route replace blackhole "$a/32" metric 32767`) || strings.Contains(routes, "dev mmesh") {
			t.Fatalf("%s: hub underlay not blackholed or still on mmesh:\n%s", tc.name, routes)
		}
		liveSet := "live=" + shQuote(want)
		if live != strings.Contains(routes, liveSet) {
			t.Fatalf("%s: live set (%v) wrong in:\n%s", tc.name, live, routes)
		}
		if live && !strings.Contains(nft, `oifname != "CloudflareWARP" ip daddr `+want+` udp dport`) {
			t.Fatalf("%s: hub nft does not keep outer packets on the Mesh interface", tc.name)
		}
		if !live && !strings.Contains(nft, "ip daddr "+want+" udp dport") || !live && strings.Contains(nft, `oifname != "CloudflareWARP" ip daddr `+want) {
			t.Fatalf("%s: a pending leg is not closed on the hub:\n%s", tc.name, chainBlock(nft, "mesh_host_output"))
		}
		if !strings.Contains(f["nodes/"+hub+"/usr/local/sbin/meridian-failover.sh"], "  mesh_underlay\n  check_mesh_legs") {
			t.Fatalf("%s: failover loop does not follow the Mesh interface", tc.name)
		}
		en := f["nodes/"+exit+"/etc/nftables.d/meridian.nft"]
		if tc.exitSide {
			if !strings.Contains(en, `iifname "CloudflareWARP" ip daddr 100.96.0.11 udp dport`) || !strings.Contains(en, `iifname != "CloudflareWARP" udp dport`) {
				t.Fatalf("%s: exit nft does not restrict the leg to its Mesh interface:\n%s", tc.name, en)
			}
		} else if r := chainRules(en, "mesh_host_input"); len(r) != 1 || !strings.Contains(r[0], "drop") || strings.Contains(r[0], "accept") {
			t.Fatalf("%s: a pending exit does not close its Mesh leg port: %v", tc.name, r)
		}
	}
}

// A node marked as reusing a host Mesh node changes nothing in a topology
// without Mesh edges.
func TestMeshReuseNoMeshTopologyUnchanged(t *testing.T) {
	plain := withoutMeshEdges(defaults.Example())
	a, err := Compile(plain)
	if err != nil {
		t.Fatal(err)
	}
	marked := withoutMeshEdges(defaults.Example())
	marked.Nodes = append([]model.Node(nil), marked.Nodes...)
	for i := range marked.Nodes {
		marked.Nodes[i].MeshHost = &model.NodeMeshHost{Addr: "100.96.0.10", Iface: "CloudflareWARP"}
	}
	b, err := Compile(marked)
	if err != nil {
		t.Fatal(err)
	}
	if len(a.Files) != len(b.Files) {
		t.Fatal("file sets differ")
	}
	for k, v := range a.Files {
		if b.Files[k] != v {
			t.Fatalf("%s differs", k)
		}
	}
}

// mesh_underlay of a host-level node under bash with a stub ip: a live leg
// gets its /32 onto the WARP interface only while the interface is up (WARP
// gone: the route is removed, the blackhole stays, so the outer packets are
// dropped rather than following the default route); a leg with a pending
// end never gets a route at all.
func TestMeshHostUnderlayFollowsWARPInterface(t *testing.T) {
	if !bashOK() {
		t.Skip("no bash")
	}
	topo, hub, exit := meshReuseTopo(t, true, true)
	pt := withPendingMeshHosts(topo)
	tunnels := mustTunnels(t, pt)
	fn := meshUnderlayShell(mustNode(t, pt, hub), tunnels)
	leg, _ := pt.MeshLegOf(hub, exit)
	var pending string
	for _, tun := range meshLegsOn(tunnels, hub) {
		if !meshLegLive(tun) {
			pending = tun.MeshAddr
			break
		}
	}
	if pending == "" || leg.Link.ID == "" {
		t.Fatal("fixture needs a live and a pending leg")
	}
	run := func(up bool) string {
		dir := t.TempDir()
		log := filepath.Join(dir, "log")
		upOut := ""
		if up {
			upOut = "5: CloudflareWARP: <POINTOPOINT,UP> mtu 1280"
		}
		writeFile(t, filepath.Join(dir, "ip"), "#!/bin/bash\necho \"$*\" >> "+shQuote(log)+"\ncase \"$*\" in \"link show CloudflareWARP up\") echo "+shQuote(upOut)+";; esac\nexit 0\n")
		if err := os.Chmod(filepath.Join(dir, "ip"), 0o755); err != nil {
			t.Fatal(err)
		}
		cmd := exec.Command("bash", "-c", fn+"mesh_underlay")
		cmd.Env = []string{"PATH=" + dir + ":/usr/bin:/bin"}
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("%v %s", err, out)
		}
		b, _ := os.ReadFile(log)
		return string(b)
	}
	liveAddr := "100.96.0.11"
	on := run(true)
	if !strings.Contains(on, "route replace blackhole "+liveAddr+"/32 metric 32767") || !strings.Contains(on, "route replace "+liveAddr+"/32 dev CloudflareWARP") {
		t.Fatalf("live leg with WARP up:\n%s", on)
	}
	if !strings.Contains(on, "route replace blackhole "+pending+"/32 metric 32767") || strings.Contains(on, "route replace "+pending+"/32 dev") {
		t.Fatalf("pending leg got a route:\n%s", on)
	}
	off := run(false)
	if strings.Contains(off, "/32 dev CloudflareWARP") && !strings.Contains(off, "route del "+liveAddr+"/32 dev CloudflareWARP") || strings.Contains(off, "route replace "+liveAddr+"/32 dev") {
		t.Fatalf("WARP gone, the route stays:\n%s", off)
	}
	if !strings.Contains(off, "route replace blackhole "+liveAddr+"/32 metric 32767") {
		t.Fatalf("WARP gone without blackhole:\n%s", off)
	}
}

// An exit that is a host-level Mesh node protects the hub's Mesh address
// the way the hub protects the exit's: blackhole, "dev <iface>" only while
// it is up (refreshed by a timer), and an output drop on other interfaces.
func TestMeshHostExitProtectsHubAddress(t *testing.T) {
	topo, hub, exit := meshReuseTopo(t, true, true)
	b, err := Compile(topo)
	if err != nil {
		t.Fatal(err)
	}
	leg, _ := topo.MeshLegOf(hub, exit)
	pt := withPendingMeshHosts(topo)
	var port int
	for _, tun := range meshLegsOn(mustTunnels(t, pt), exit) {
		if tun.LinkID == leg.Link.ID {
			port = tun.WGPort
		}
	}
	if port == 0 {
		t.Fatal("no leg port")
	}
	p := "nodes/" + exit + "/"
	routes := b.File(p + "usr/local/sbin/meridian-routes.sh")
	if !strings.Contains(routes, "keep='100.96.0.10'") || !strings.Contains(routes, "live='100.96.0.10'") {
		t.Fatalf("exit routes lack the hub Mesh address:\n%s", routes)
	}
	nft := b.File(p + "etc/nftables.d/meridian.nft")
	want := fmt.Sprintf("oifname != \"CloudflareWARP\" ip daddr 100.96.0.10 udp sport %d drop", port)
	if !strings.Contains(nft, "chain mesh_host_output") || !strings.Contains(nft, want) {
		t.Fatalf("exit nft lacks %q:\n%s", want, nft)
	}
	up := b.File(p + "usr/local/sbin/meridian-up.sh")
	if !strings.Contains(up, "ip route replace blackhole 100.96.0.10/32 metric 32767") || !strings.Contains(up, "enable_unit meridian-mesh-underlay.timer") {
		t.Fatalf("exit up.sh lacks guard or timer:\n%s", up)
	}
	for _, f := range []string{"usr/local/sbin/meridian-mesh-underlay.sh", "etc/systemd/system/meridian-mesh-underlay.service", "etc/systemd/system/meridian-mesh-underlay.timer"} {
		if b.File(p+f) == "" {
			t.Fatalf("missing %s", f)
		}
	}
	if !strings.Contains(b.File(p+"usr/local/sbin/meridian-mesh-underlay.sh"), "keep='100.96.0.10'") {
		t.Fatal("refresh script does not cover the hub address")
	}
	// Hub still waiting for its node: no address to protect, nothing new.
	topo2, _, exit2 := meshReuseTopo(t, false, true)
	b2, err := Compile(topo2)
	if err != nil {
		t.Fatal(err)
	}
	if b2.File("nodes/"+exit2+"/etc/systemd/system/meridian-mesh-underlay.timer") != "" || strings.Contains(b2.File("nodes/"+exit2+"/etc/nftables.d/meridian.nft"), "mesh_host_output") {
		t.Fatal("pending hub without address got exit protection")
	}
}

func TestMeshHostExitUnderlayFollowsWARPInterface(t *testing.T) {
	if !bashOK() {
		t.Skip("no bash")
	}
	topo, _, exit := meshReuseTopo(t, true, true)
	pt := withPendingMeshHosts(topo)
	fn := meshUnderlayShell(mustNode(t, pt, exit), mustTunnels(t, pt))
	run := func(up bool) string {
		dir := t.TempDir()
		log := filepath.Join(dir, "log")
		upOut := ""
		if up {
			upOut = "5: CloudflareWARP: <POINTOPOINT,UP> mtu 1280"
		}
		writeFile(t, filepath.Join(dir, "ip"), "#!/bin/bash\necho \"$*\" >> "+shQuote(log)+"\ncase \"$*\" in \"link show CloudflareWARP up\") echo "+shQuote(upOut)+";; esac\nexit 0\n")
		if err := os.Chmod(filepath.Join(dir, "ip"), 0o755); err != nil {
			t.Fatal(err)
		}
		cmd := exec.Command("bash", "-c", fn+"mesh_underlay")
		cmd.Env = []string{"PATH=" + dir + ":/usr/bin:/bin"}
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("%v %s", err, out)
		}
		b, _ := os.ReadFile(log)
		return string(b)
	}
	hubAddr := "100.96.0.10"
	on := run(true)
	if !strings.Contains(on, "route replace blackhole "+hubAddr+"/32 metric 32767") || !strings.Contains(on, "route replace "+hubAddr+"/32 dev CloudflareWARP") {
		t.Fatalf("exit with WARP up:\n%s", on)
	}
	off := run(false)
	if !strings.Contains(off, "route del "+hubAddr+"/32 dev CloudflareWARP") || strings.Contains(off, "route replace "+hubAddr+"/32 dev") {
		t.Fatalf("WARP removed on the exit, the route stays:\n%s", off)
	}
	if !strings.Contains(off, "route replace blackhole "+hubAddr+"/32 metric 32767") {
		t.Fatalf("WARP removed on the exit without blackhole:\n%s", off)
	}
}
