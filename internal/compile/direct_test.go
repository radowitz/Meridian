package compile

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/radowitz/meridian/internal/defaults"
	"github.com/radowitz/meridian/internal/model"
	"github.com/radowitz/meridian/internal/validate"
)

// Direct exits (no relay, no hub, no IX): the gateway is the hub for its
// own tunnels. docs/architecture.md「直连出口与单中继」.

func directBundle(t *testing.T) (*Bundle, model.Topology) {
	t.Helper()
	topo := defaults.DirectExample()
	model.MigrateRegionGroups(&topo)
	return mustCompile(t, topo), topo
}

func TestDirectExampleShape(t *testing.T) {
	topo := defaults.DirectExample()
	if !topo.DirectExits() {
		t.Fatal("DirectExample is not a direct-exit topology")
	}
	for _, n := range topo.Nodes {
		if n.Role == model.RoleRelay || n.Role == model.RoleHub || n.Role == model.RoleIX {
			t.Fatalf("DirectExample has a %s: %s", n.Role, n.ID)
		}
	}
	for _, ex := range []func() model.Topology{defaults.Example, defaults.NoIXExample, defaults.RelayBackupExample, defaults.DualHubExample,
		defaults.SharedRelaysExample, defaults.NestedExample, defaults.ExternalExample, defaults.Empty} {
		if topo := ex(); topo.DirectExits() && len(topo.Nodes) > 0 {
			t.Fatal("a relay or hub topology counts as direct")
		}
	}
	res := validate.Run(topo)
	if res.HasErrors() {
		t.Fatalf("DirectExample does not validate: %+v", res.Issues)
	}
	if len(res.Paths) != 3 {
		t.Fatalf("paths: %+v", res.Paths)
	}
	for _, p := range res.Paths {
		if len(p.Nodes) != 2 || p.Nodes[0] != "gw" {
			t.Errorf("path to %s is not gateway → exit: %v", p.ExitID, p.Nodes)
		}
	}
	if len(topo.SharingRelays()) != 0 || topo.RelaySharing() || topo.RelayBackup() || topo.DualHub() {
		t.Fatal("a direct topology has relay sharing, a relay backup group or a backup hub")
	}
}

func TestGoldenDirect(t *testing.T) {
	b, _ := directBundle(t)
	checkGolden(t, "direct_example.golden", b)
}

// Rule routing and leak protection: every exit and group mark looks up its
// own table on the gateway; each table's default is that exit's tunnel with
// a blackhole under it, so a tunnel that goes away drops instead of
// leaving through the home router; table 102 carries nothing.
func TestDirectGatewayRoutesAndLeakProtection(t *testing.T) {
	b, topo := directBundle(t)
	routes := b.Files["nodes/gw/usr/local/sbin/meridian-routes.sh"]
	tunnels, err := buildTunnels(topo)
	if err != nil {
		t.Fatal(err)
	}
	exits := planExits(topo, tunnels)
	if len(exits) != 3 {
		t.Fatalf("exits: %+v", exits)
	}
	for _, e := range exits {
		if e.HubIface == "" || e.Hub != "gw" {
			t.Fatalf("exit %s is not planned on the gateway's own tunnel: %+v", e.Node.ID, e)
		}
		for _, want := range []string{
			"ip route replace default dev " + e.HubIface + " table " + itoa(e.Table) + "\n",
			"ip route replace blackhole default metric 32767 table " + itoa(e.Table) + "\n",
			"ip -6 route replace blackhole default metric 32767 table " + itoa(e.Table) + "\n",
			"ip rule add fwmark " + hexMarkS(e.Mark) + " lookup " + itoa(e.Table) + " priority",
			"ip rule add fwmark " + hexMarkS(e.Mark) + " unreachable priority",
		} {
			if !strings.Contains(routes, want) {
				t.Errorf("gateway routes lack %q", want)
			}
		}
	}
	for _, bad := range []string{"lookup 102 priority", "default dev  table", "default dev '' table"} {
		if strings.Contains(routes, bad) {
			t.Errorf("gateway routes carry %q", bad)
		}
	}
	if !strings.Contains(routes, "ip route replace blackhole default metric 32767 table 102\n") {
		t.Error("table 102 is not a blackhole")
	}
	// No exit or group table ever points at the home router.
	for _, l := range strings.Split(routes, "\n") {
		if strings.Contains(l, "via '192.0.2.1'") && !strings.Contains(l, "table 100") && !strings.Contains(l, "/32'") {
			t.Errorf("a non-domestic route leaves through the home router: %s", l)
		}
	}
	// Ciphertext to each exit leaves through the home uplink, never a tunnel.
	for _, ep := range []string{"203.0.113.41", "203.0.113.42", "198.51.100.20"} {
		if !strings.Contains(routes, "ip route replace '"+ep+"/32' via '192.0.2.1' dev 'eth0'") {
			t.Errorf("no underlay route to %s", ep)
		}
	}
	nft := b.Files["nodes/gw/etc/nftables.d/meridian.nft"]
	if !strings.Contains(nft, "exit marks: WireGuard only") {
		t.Error("the forward guard does not confine exit marks to the tunnels")
	}
}

// Failover: the gateway switches region group "jp" between its two
// members (its own tunnels), in the group's order; there is no west path.
func TestDirectGroupFailover(t *testing.T) {
	b, topo := directBundle(t)
	fo := b.Files["nodes/gw/usr/local/sbin/meridian-failover.sh"]
	tunnels, _ := buildTunnels(topo)
	exits := planExits(topo, tunnels)
	a, _ := exitByID(exits, "exit-a")
	bb, _ := exitByID(exits, "exit-b")
	want := "group_step 'jp' "
	i := strings.Index(fo, want)
	if i < 0 {
		t.Fatalf("no switch for group jp:\n%s", fo)
	}
	line := fo[i : i+strings.Index(fo[i:], "\n")]
	if !strings.Contains(line, "'exit-a' '"+a.HubIface+"'") || !strings.Contains(line, "'exit-b' '"+bb.HubIface+"'") ||
		strings.Index(line, "'exit-a' '") > strings.Index(line, "'exit-b' '") {
		t.Errorf("group jp does not switch exit-a → exit-b over the gateway's tunnels: %s", line)
	}
	for _, bad := range []string{"apply_west", "IX_MODE", "UDP_PEER"} {
		if strings.Contains(fo, bad) {
			t.Errorf("direct failover carries west-path logic %q", bad)
		}
	}
	if !strings.Contains(fo, "while true; do\n  rule_heal\n  check_groups || true") || !strings.Contains(fo, "reset_groups\n") {
		t.Error("the loop does not run the group checks")
	}
	if !strings.Contains(b.Files["nodes/gw/usr/local/sbin/meridian-routes.sh"], "group_hop "+itoa(groupTable(t, b, topo, "jp"))+" '"+a.HubIface+"'") {
		t.Error("group jp does not start on exit-a")
	}
}

func groupTable(t *testing.T, b *Bundle, topo model.Topology, id string) int {
	t.Helper()
	tunnels, _ := buildTunnels(topo)
	for _, g := range planGroups(topo, planExits(topo, tunnels)) {
		if g.Group.ID == id {
			return g.Table
		}
	}
	t.Fatalf("no group %s", id)
	return 0
}

// UDP and IPv6: each exit is one WireGuard tunnel (UDP outside, any
// protocol inside), never a WSS pair; an exit with IPv6 egress keeps IPv6,
// one without drops it at its WAN; region-group resolver queries from the
// gateway's tunnel are answered by the member exit.
func TestDirectTransportsAndFamilies(t *testing.T) {
	b, _ := directBundle(t)
	for p := range b.Files {
		if strings.Contains(p, "wstunnel") || strings.Contains(p, "/wss/") {
			t.Errorf("direct bundle has a WSS file: %s", p)
		}
	}
	if strings.Contains(b.Files["nodes/exit-a/etc/nftables.d/meridian.nft"], "chain drop_v6") {
		t.Error("exit-a has IPv6 egress but drops IPv6")
	}
	if !strings.Contains(b.Files["nodes/exit-c/etc/nftables.d/meridian.nft"], "chain drop_v6") {
		t.Error("exit-c has no IPv6 egress but forwards IPv6")
	}
	for _, id := range []string{"exit-a", "exit-b"} {
		if !strings.Contains(b.Files["nodes/"+id+"/etc/nftables.d/meridian.nft"], "chain group_dns") {
			t.Errorf("%s does not answer region-group resolver queries from the gateway", id)
		}
	}
	dns := b.Files["nodes/gw/etc/smartdns/smartdns.conf"]
	for _, g := range []string{"g_exit_a", "g_exit_b", "g_exit_c"} {
		if !strings.Contains(dns, "-group "+g+" ") {
			t.Errorf("no resolver for %s", g)
		}
	}
	for p := range b.Files {
		if strings.HasPrefix(p, "nodes/exit-") && strings.Contains(p, "routes.sh") && strings.Contains(b.Files[p], "exit has no hub tunnel") {
			t.Errorf("%s has no way home", p)
		}
	}
}

// Speed tests and relay sharing measure relays; a direct topology has none,
// so nothing of either is compiled.
func TestDirectNoRelayMachinery(t *testing.T) {
	b, _ := directBundle(t)
	for p := range b.Files {
		for _, bad := range []string{SpeedSocketUnit, SpeedServiceUnit, strings.TrimPrefix(SharePathConfig, "/"), "nat64.reserved.conf"} {
			if strings.HasSuffix(p, bad) {
				t.Errorf("direct bundle has %s", p)
			}
		}
	}
}

// What the gateway does not carry yet as a hub is refused, not compiled
// into something broken; adding a relay makes it an ordinary relay
// topology again with its own path rules.
func TestDirectUnsupportedRefused(t *testing.T) {
	cases := map[string]func(*model.Topology){
		"udp_wss_failover link": func(topo *model.Topology) { topo.Links[0].Transport = model.TransportUDPWSSFailover },
		"wg_over_wss link":      func(topo *model.Topology) { topo.Links[0].Transport = model.TransportWGOverWSS },
		"standby link":          func(topo *model.Topology) { topo.Links[0].Standby = true },
		"nested exit": func(topo *model.Topology) {
			topo.Nodes = append(topo.Nodes, model.Node{ID: "exit-n", Name: "嵌套", Role: model.RoleExit, Region: "jp", Managed: true,
				WANInterface: "eth0", PathV4: true, EgressV4: true, NatDialOut: true, ViaExit: "exit-a"})
			topo.Links = append(topo.Links, model.Link{ID: "n-a", From: "exit-n", To: "exit-a", Transport: model.TransportDirectWG, Enabled: true})
		},
	}
	for name, edit := range cases {
		topo := defaults.DirectExample()
		edit(&topo)
		found := false
		for _, is := range validate.Run(topo).Issues {
			found = found || is.Code == "direct_unsupported" && is.Severity == validate.SeverityError
		}
		if !found {
			t.Errorf("%s: not refused as direct_unsupported", name)
		}
	}
	topo := defaults.DirectExample()
	topo.Nodes = append(topo.Nodes, model.Node{ID: "relay", Name: "中继", Role: model.RoleRelay, Region: "cn", Managed: true, WANInterface: "eth0", EndpointV4: "203.0.113.10", PathV4: true})
	if topo.DirectExits() {
		t.Fatal("a topology with a relay is direct")
	}
	if !validate.Run(topo).HasErrors() {
		t.Fatal("gateway → exit links next to a relay validate")
	}
}

func hexMarkS(m uint32) string { return fmt.Sprintf("%#x", m) }

func TestDirectScriptsSyntax(t *testing.T) {
	if !bashOK() {
		t.Skip("bash not available")
	}
	b, _ := directBundle(t)
	for p, body := range b.Files {
		if !strings.HasSuffix(p, ".sh") {
			continue
		}
		f := filepath.Join(t.TempDir(), "s.sh")
		if err := os.WriteFile(f, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		if out, err := exec.Command("bash", "-n", f).CombinedOutput(); err != nil {
			t.Errorf("%s: bash -n: %v %s", p, err, out)
		}
	}
}
