package compile

import (
	"fmt"
	"os/exec"
	"strings"
	"testing"

	"github.com/radowitz/meridian/internal/defaults"
	"github.com/radowitz/meridian/internal/model"
)

// dualHubBothMesh is dualHubMesh plus a Mesh leg from the backup hub (hkb)
// to the same exit, with every end a live host-level Mesh node.
func dualHubBothMesh(live bool) model.Topology {
	topo := dualHubMesh()
	topo.Links = append(topo.Links, model.Link{ID: "hkb-dc1-mesh", Name: "hkb → dc1 Mesh", From: "hkb", To: "dc1", Transport: model.TransportCFMesh, Enabled: true, Standby: true})
	if live {
		addr := map[string]string{"ix": "100.96.0.10", "hkb": "100.96.0.12", "dc1": "100.96.0.11"}
		for i := range topo.Nodes {
			if a, ok := addr[topo.Nodes[i].ID]; ok {
				topo.Nodes[i].MeshHost = &model.NodeMeshHost{Addr: a, Iface: "CloudflareWARP"}
			}
		}
	}
	return topo
}

// The backup hub's Mesh leg has the primary's semantics: an ordinary
// WireGuard leg dialling the exit's Mesh address, its own interface, port,
// subnet, return mark and table on the exit, its own quality loop on hkb,
// and outer packets sealed onto the WARP interface on both ends.
func TestMeshLegFromBackupHub(t *testing.T) {
	topo := dualHubBothMesh(true)
	b := mustCompile(t, topo)
	tunnels := mustTunnels(t, withPendingMeshHosts(topo))
	pl, bl := hubMeshLeg(tunnels, "dc1", "ix"), hubMeshLeg(tunnels, "dc1", "hkb")
	if pl.LinkID == "" || bl.LinkID == "" || !bl.Standby {
		t.Fatalf("legs %+v / %+v", pl, bl)
	}
	if pl.Iface() == bl.Iface() || pl.WGPort == bl.WGPort || pl.EastV4 == bl.EastV4 || pl.EastULA == bl.EastULA {
		t.Fatalf("the two Mesh legs on dc1 collide: %s:%d %s / %s:%d %s", pl.Iface(), pl.WGPort, pl.EastV4, bl.Iface(), bl.WGPort, bl.EastV4)
	}
	if pl.MeshAddr == "" || pl.MeshAddr != bl.MeshAddr {
		t.Fatalf("both hubs must dial dc1's one Mesh address: %q / %q", pl.MeshAddr, bl.MeshAddr)
	}
	// hkb dials dc1's Mesh address; no route is published, no default onto
	// the WARP interface.
	wg := b.File("nodes/hkb/etc/wireguard/" + bl.Iface() + ".conf")
	if !strings.Contains(wg, fmt.Sprintf("Endpoint = %s:%d", bl.MeshAddr, bl.WGPort)) {
		t.Fatalf("hkb Mesh leg endpoint:\n%s", wg)
	}
	for p, body := range b.Files {
		for _, line := range strings.Split(body, "\n") {
			if strings.Contains(line, "default") && strings.Contains(line, "dev CloudflareWARP") {
				t.Errorf("%s: default route onto the WARP interface: %s", p, line)
			}
		}
	}
	nft := b.File("nodes/hkb/etc/nftables.d/meridian.nft")
	if want := fmt.Sprintf(`oifname != "CloudflareWARP" ip daddr %s udp dport %d drop`, bl.MeshAddr, bl.WGPort); !strings.Contains(nft, want) {
		t.Errorf("hkb does not seal its outer packets (%q):\n%s", want, chainBlock(nft, "mesh_host_output"))
	}
	routes := b.File("nodes/hkb/usr/local/sbin/meridian-routes.sh")
	if !strings.Contains(routes, "mesh_underlay()") || !strings.Contains(routes, bl.MeshAddr) {
		t.Errorf("hkb routes lack the Mesh underlay of %s", bl.MeshAddr)
	}
	// Quality switching on hkb's own failover loop, bound to hkb's plan.
	fo := b.File("nodes/hkb/usr/local/sbin/meridian-failover.sh")
	hk5Plan, ixPlan := MeshQualityPlanIDForHub(topo, "hkb"), MeshQualityPlanIDForHub(topo, "ix")
	if hk5Plan == "" || hk5Plan == ixPlan || !strings.Contains(fo, "MQ_PLAN="+hk5Plan+"\n") {
		t.Fatalf("hkb quality plan %q (ix %q)", hk5Plan, ixPlan)
	}
	direct := hubDirect(tunnels, "dc1", "hkb")
	if !strings.Contains(fo, fmt.Sprintf("mesh_leg_step 'dc1' ")) || !strings.Contains(fo, fmt.Sprintf("'%s' '%s'", bl.Iface(), bl.EastV4)) || !strings.Contains(fo, "'"+direct.Iface()+"'") {
		t.Errorf("hkb failover lacks dc1's leg step")
	}
	if !strings.Contains(fo, "  mesh_underlay\n  check_mesh_legs || true\n  check_groups") {
		t.Errorf("hkb loop does not run the Mesh steps")
	}
	// dc1: four return paths, each its own mark/table/priority.
	n, _ := topo.NodeByID("dc1")
	rets := exitHubReturns(topo, n, tunnels)
	if len(rets) != 4 || rets[3].Hub != "hkb" || !rets[3].Mesh || rets[3].Iface != bl.Iface() || rets[3].Table != tableHubReturnMeshBackup || rets[3].Mark != markHubReturnMeshBackup {
		t.Fatalf("dc1 return paths %+v", rets)
	}
	seen := map[string]bool{}
	for _, r := range rets {
		for _, k := range []string{r.Iface, fmt.Sprint(r.Mark), fmt.Sprint(r.Table), fmt.Sprint(r.Prio)} {
			if seen[k] {
				t.Fatalf("return paths share %s: %+v", k, rets)
			}
			seen[k] = true
		}
	}
	rt := b.File("nodes/dc1/etc/iproute2/rt_tables.d/meridian.conf")
	if !strings.Contains(rt, fmt.Sprintf("%d\tmeridian_return_mesh_backup\n", tableHubReturnMeshBackup)) {
		t.Errorf("dc1 rt_tables:\n%s", rt)
	}
	dnft := b.File("nodes/dc1/etc/nftables.d/meridian.nft")
	if in := chainBlock(dnft, "hub_return_in"); !strings.Contains(in, fmt.Sprintf(`iifname "%s" ct direction original ct mark set %#x`, bl.Iface(), markHubReturnMeshBackup)) {
		t.Errorf("dc1 hub_return_in:\n%s", in)
	}
	if dns := chainBlock(dnft, "exit_dns"); !strings.Contains(dns, `"`+bl.Iface()+`"`) {
		t.Errorf("dc1 does not answer its resolver on hkb's Mesh leg:\n%s", dns)
	}
	// Exit seal: both legs' ports only via WARP, outer packets to both hubs
	// only via WARP.
	if in := chainBlock(dnft, "mesh_host_input"); !strings.Contains(in, fmt.Sprint(pl.WGPort)) || !strings.Contains(in, fmt.Sprint(bl.WGPort)) {
		t.Errorf("dc1 mesh_host_input:\n%s", in)
	}
	for _, want := range []string{
		fmt.Sprintf(`oifname != "CloudflareWARP" ip daddr 100.96.0.10 udp sport %d drop`, pl.WGPort),
		fmt.Sprintf(`oifname != "CloudflareWARP" ip daddr 100.96.0.12 udp sport %d drop`, bl.WGPort),
	} {
		if !strings.Contains(dnft, want) {
			t.Errorf("dc1 nft lacks %q", want)
		}
	}
	if r := b.File("nodes/dc1/usr/local/sbin/meridian-routes.sh"); !strings.Contains(r, "keep='100.96.0.10 100.96.0.12'") {
		t.Errorf("dc1 underlay does not protect both hub addresses")
	}
	// MTU: dc1's path and its groups count hkb's Mesh leg.
	for _, p := range b.Paths {
		if p.ExitID == "dc1" && !strings.Contains(strings.Join(p.MeshLinks, ","), "hkb-dc1-mesh") {
			t.Errorf("dc1 path report lacks hkb's Mesh leg: %+v", p)
		}
	}
	for _, g := range b.GroupPaths {
		for _, m := range g.Members {
			if m == "dc1" && !strings.Contains(strings.Join(g.MeshLinks, ","), "hkb-dc1-mesh") {
				t.Errorf("group %s lacks hkb's Mesh leg: %+v", g.GroupID, g)
			}
		}
	}
	for _, p := range []string{"nodes/hkb/usr/local/sbin/meridian-failover.sh", "nodes/hkb/usr/local/sbin/meridian-routes.sh", "nodes/dc1/usr/local/sbin/meridian-routes.sh", "nodes/hkb/usr/local/sbin/meridian-up.sh", "nodes/dc1/usr/local/sbin/meridian-up.sh"} {
		bashSyntax(t, p, b.File(p))
	}
	// Ends still waiting for their Mesh node compile too: the legs stay
	// blackholed / closed.
	pb := mustCompile(t, dualHubBothMesh(false))
	if in := chainRules(pb.File("nodes/dc1/etc/nftables.d/meridian.nft"), "mesh_host_input"); len(in) != 1 || !strings.Contains(in[0], fmt.Sprint(bl.WGPort)) || !strings.Contains(in[0], " drop") {
		t.Errorf("pending dc1 mesh_host_input: %v", in)
	}
}

func bashSyntax(t *testing.T, name, body string) {
	t.Helper()
	cmd := exec.Command("bash", "-n")
	cmd.Stdin = strings.NewReader(body)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Errorf("%s: bash -n: %v %s", name, err, out)
	}
}

// Only the backup hub has a Mesh leg: the primary hub knows nothing of the
// Mesh, dc2 and the relay are unchanged, dc1 has three return paths.
func TestMeshLegOnlyFromBackupHub(t *testing.T) {
	topo := defaults.DualHubExample()
	topo.Links = append(topo.Links, model.Link{ID: "hkb-dc1-mesh", From: "hkb", To: "dc1", Transport: model.TransportCFMesh, Enabled: true, Standby: true})
	b := mustCompile(t, topo)
	tunnels := mustTunnels(t, topo)
	n, _ := topo.NodeByID("dc1")
	rets := exitHubReturns(topo, n, tunnels)
	if len(rets) != 3 || rets[2].Table != tableHubReturnMeshBackup || rets[2].Hub != "hkb" {
		t.Fatalf("dc1 return paths %+v", rets)
	}
	plain := mustCompile(t, defaults.DualHubExample())
	for p, body := range plain.Files {
		if strings.HasPrefix(p, "nodes/dc2/") || strings.HasPrefix(p, "nodes/access/") {
			if b.Files[p] != body {
				t.Errorf("%s changed although the node has no Mesh leg", p)
			}
		}
	}
	if strings.Contains(b.File("nodes/ix/usr/local/sbin/meridian-failover.sh"), "MQ_PLAN=") {
		t.Error("the primary hub got a quality loop without a Mesh leg")
	}
	if !strings.Contains(b.File("nodes/hkb/usr/local/sbin/meridian-failover.sh"), "MQ_PLAN=") {
		t.Error("the backup hub has no quality loop")
	}
	if strings.Contains(b.File("nodes/dc1/etc/iproute2/rt_tables.d/meridian.conf"), "meridian_return_mesh\n") {
		t.Error("dc1 got the primary's Mesh return table")
	}
}
