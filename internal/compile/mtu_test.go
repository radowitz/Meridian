package compile

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/radowitz/meridian/internal/defaults"
	"github.com/radowitz/meridian/internal/model"
	"github.com/radowitz/meridian/internal/mtu"
	"github.com/radowitz/meridian/internal/validate"
)

// The tunnel legs each node asks its host about (UplinkCarriers): the
// address its outer packets go to, the outer family, the carrier, the
// field that sets the MTU, the gateway's underlay mark.
func TestUplinkCarriersExample(t *testing.T) {
	topo := defaults.Example()
	get := func(node, link, mode string) mtu.Carrier {
		t.Helper()
		cs, err := UplinkCarriers(topo, node)
		if err != nil {
			t.Fatal(err)
		}
		for _, c := range cs {
			if c.LinkID == link && c.Mode == mode {
				return c
			}
		}
		t.Fatalf("%s has no %s/%s leg: %+v", node, link, mode, cs)
		return mtu.Carrier{}
	}
	hub, _ := topo.NodeByID("hk-hub")
	// A dialing exit: the hub's endpoint.
	if c := get("hk-resi", "hkresi-hub", "udp"); !c.Dials || c.Peer != hub.EndpointV4 || c.Family != 4 || c.TunnelMTU != 1420 || c.Field != "mtu" || c.Mark != "" || c.RouteArg() != "route4:"+hub.EndpointV4 {
		t.Fatalf("hk-resi %+v", c)
	}
	// The hub listening for it: the exit dials in from no fixed address,
	// so the default route stands in (no route lookup).
	if c := get("hk-hub", "hkresi-hub", "udp"); c.Dials || c.Peer != "" || c.PeerWhy == "" || c.RouteArg() != "" {
		t.Fatalf("hk-hub listener %+v", c)
	}
	// The hub with several exits: one leg each, each with its own peer.
	if c := get("hk-hub", "hub-jp", "udp"); !c.Dials || c.Peer == "" || c.PeerNode != "jp" {
		t.Fatalf("hub-jp %+v", c)
	}
	// The gateway: its outer packets carry the underlay mark; the failover
	// link has a UDP leg (field mtu) and a WSS leg (field wss_mtu) whose
	// carrier is wstunnel's TCP to the same peer.
	udp, wss := get("gw", "gw-access", "udp"), get("gw", "gw-access", "wss")
	if udp.Mark != "0x4d72" || udp.Field != "mtu" || udp.TunnelMTU != 1412 || udp.Iface != "m02" {
		t.Fatalf("gw udp %+v", udp)
	}
	if wss.Field != "wss_mtu" || wss.TunnelMTU != 1360 || wss.Iface != "m02w" || wss.Peer != udp.Peer || wss.Family != 4 {
		t.Fatalf("gw wss %+v", wss)
	}
	// Outer IPv6 past the dual-stack relay.
	v6, _ := topo.NodeByID("v6-exit")
	if c := get("ds-relay", "dsrelay-v6", "udp"); c.Family != 6 || c.Peer != v6.EndpointV6 || c.RouteArg() != "route6:"+v6.EndpointV6 {
		t.Fatalf("outer v6 %+v", c)
	}
	// Every leg's MTU is the one written into its WireGuard config.
	b := mustCompile(t, topo)
	for _, n := range managedNodes(topo) {
		cs, err := UplinkCarriers(topo, n.ID)
		if err != nil {
			t.Fatal(err)
		}
		for _, c := range cs {
			conf := b.File("nodes/" + n.ID + "/etc/wireguard/" + c.Iface + ".conf")
			m := reConfMTUAny.FindStringSubmatch(conf)
			if m == nil || m[1] != strconv.Itoa(c.TunnelMTU) {
				t.Fatalf("%s %s: carrier MTU %d, config %v", n.ID, c.Iface, c.TunnelMTU, m)
			}
		}
	}
}

var reConfMTUAny = regexp.MustCompile(`(?m)^MTU = (\d+)$`)

func clampOf(t *testing.T, nft string) string {
	t.Helper()
	m := regexp.MustCompile(`# mss-clamp v4 (\d+) v6 (\d+)`).FindStringSubmatch(nft)
	if m == nil {
		t.Fatal("no mss-clamp header")
	}
	return m[1] + "/" + m[2]
}

// Adopting a lower tunnel MTU on a link of the path moves every clamp that
// derives from the path minimum: the gateway's forward clamp (chain mss),
// the sniffer's (sniff_mss), M1's local clamps (local_mss / local_mss_in)
// and every remote node's tunnel_mss_out / tunnel_mss_in, and the two ends'
// WireGuard MTU. One computation (validate.LegMTU → path MTU → mssFloor).
func TestClampsFollowAdoptedLinkMTU(t *testing.T) {
	topo := sniffTopologies(t)["example"]
	topo.Settings.Sniff = &model.SniffSettings{Enabled: true} // with the sniffing forwarder
	before := mustCompile(t, topo)
	gw0 := before.File("nodes/gw/etc/nftables.d/meridian.nft")
	if chainBlock(gw0, "sniff_mss") == "" {
		t.Fatal("no sniff_mss: the test does not exercise the sniffer's clamp")
	}
	for i := range topo.Links {
		if topo.Links[i].ID == "hub-jp" {
			topo.Links[i].MTU = 1344 // below every other path's MTU (1360)
		}
	}
	b := mustCompile(t, topo)
	gw := b.File("nodes/gw/etc/nftables.d/meridian.nft")
	if clampOf(t, gw0) == clampOf(t, gw) || clampOf(t, gw) != "1304/1284" {
		t.Fatalf("forward clamp %s → %s, want 1304/1284", clampOf(t, gw0), clampOf(t, gw))
	}
	// Every gateway clamp carries the new floor (a Mesh exit's own smaller
	// per-mark clamp stays next to it) and none the old one.
	old := strings.Split(clampOf(t, gw0), "/")
	for _, c := range []string{"mss", "sniff_mss", "local_mss", "local_mss_in"} {
		body := chainBlock(gw, c)
		for _, v := range []string{"1304", "1284"} {
			if !strings.Contains(body, "maxseg size set "+v) {
				t.Errorf("gateway %s does not follow the path minimum (%s):\n%s", c, v, body)
			}
		}
		for _, v := range old {
			if strings.Contains(body, "maxseg size set "+v+"\n") || strings.Contains(body, "maxseg size set "+v+" ") {
				t.Errorf("gateway %s still clamps to the old %s:\n%s", c, v, body)
			}
		}
	}
	for _, n := range managedNodes(topo) {
		if n.Role == model.RoleGateway {
			continue
		}
		nft := b.File("nodes/" + n.ID + "/etc/nftables.d/meridian.nft")
		out := chainBlock(nft, "tunnel_mss_out")
		if out == "" {
			continue
		}
		if meshLegExits(topo)[n.ID] {
			// An exit with a Mesh leg clamps to its own, smaller path.
			if !strings.Contains(out, "maxseg size set 1176") || !strings.Contains(out, "maxseg size set 1156") {
				t.Errorf("%s (Mesh leg) tunnel_mss_out does not clamp to its own path:\n%s", n.ID, out)
			}
			continue
		}
		if !strings.Contains(out, "maxseg size set 1304") || !strings.Contains(out, "maxseg size set 1284") {
			t.Errorf("%s tunnel_mss_out does not follow the path minimum:\n%s", n.ID, out)
		}
	}
	for _, p := range []string{"nodes/hk-hub/etc/wireguard/m09.conf", "nodes/jp/etc/wireguard/m09.conf"} {
		if !strings.Contains(b.File(p), "\nMTU = 1344\n") {
			t.Errorf("%s does not carry the adopted MTU", p)
		}
	}
	// Only the link's two ends' WireGuard configs change.
	for path, body := range b.Files {
		if strings.Contains(path, "/etc/wireguard/") && before.Files[path] != body && !strings.HasSuffix(path, "/m09.conf") {
			t.Errorf("%s changed", path)
		}
	}
}

// A WSS leg's own MTU field is the interface's MTU and the path's: before
// LegMTU the path ignored wss_mtu on wg_over_wss / ix_replacement_wss and
// the clamps could stay above the interface.
func TestWSSLegMTUIsThePathMTU(t *testing.T) {
	topo := defaults.Example()
	for i := range topo.Links {
		if topo.Links[i].ID == "gw-hub-wss" {
			topo.Links[i].WSSMTU = 1320
		}
	}
	b := mustCompile(t, topo)
	if !strings.Contains(b.File("nodes/gw/etc/wireguard/m03.conf"), "\nMTU = 1320\n") {
		t.Fatal("m03 does not carry wss_mtu")
	}
	l, _ := linkByID(topo, "gw-hub-wss")
	if m, field, _ := validate.LegMTU(l, "wss"); m != 1320 || field != "wss_mtu" {
		t.Fatalf("LegMTU %d %s", m, field)
	}
	if got := clampOf(t, b.File("nodes/gw/etc/nftables.d/meridian.nft")); got != "1280/1260" {
		t.Fatalf("forward clamp %s, want 1280/1260 (path MTU 1320)", got)
	}
}

func linkByID(t model.Topology, id string) (model.Link, bool) {
	for _, l := range t.Links {
		if l.ID == id {
			return l, true
		}
	}
	return model.Link{}, false
}

// With no MTU set anywhere, every leg gets the transport default it always
// had (the goldens prove the rendered files are byte-identical).
func TestLegMTUDefaults(t *testing.T) {
	for _, c := range []struct {
		tr         model.Transport
		mtu, wss   int
		mode, want string
		val        int
	}{
		{model.TransportDirectWG, 0, 0, "udp", "mtu", 1420},
		{model.TransportUDPWSSFailover, 0, 0, "udp", "mtu", 1412},
		{model.TransportUDPWSSFailover, 1400, 0, "wss", "wss_mtu", 1360},
		{model.TransportWGOverWSS, 0, 0, "wss", "mtu", 1360},
		{model.TransportWGOverWSS, 1340, 0, "wss", "mtu", 1340},
		{model.TransportWGOverWSS, 1340, 1300, "wss", "wss_mtu", 1300},
		{model.TransportIXReplacementWSS, 0, 0, "wss", "mtu", 1360},
	} {
		got, field, _ := validate.LegMTU(model.Link{Transport: c.tr, MTU: c.mtu, WSSMTU: c.wss}, c.mode)
		if got != c.val || field != c.want {
			t.Errorf("%s mtu=%d wss=%d %s: %d %s, want %d %s", c.tr, c.mtu, c.wss, c.mode, got, field, c.val, c.want)
		}
	}
}

// TestActivationAlignsTunnelMTU: every node's meridian-up.sh knows, for
// each tunnel interface it brings up, exactly the MTU that interface's
// config sets ("MTU =", from the same Tunnel.MTU), and nothing for the
// remote-access interface (remoteUpCommands sets that one); an adopted
// Link.MTU changes the config and that value together, and nothing else
// changes a value.
func TestActivationAlignsTunnelMTU(t *testing.T) {
	reConf := regexp.MustCompile(`(?m)^MTU = (\d+)$`)
	reArm := regexp.MustCompile(`(?m)^    ([a-z0-9]+)\) echo (\d+) ;;$`)
	check := func(t *testing.T, topo model.Topology) map[string]string {
		t.Helper()
		b := mustCompile(t, topo)
		all := map[string]string{}
		for _, n := range managedNodes(topo) {
			up := b.File("nodes/" + n.ID + "/usr/local/sbin/meridian-up.sh")
			arms := map[string]string{}
			for _, m := range reArm.FindAllStringSubmatch(up, -1) {
				arms[m[1]] = m[2]
			}
			confs := map[string]string{}
			for p, body := range b.Files {
				dir := "nodes/" + n.ID + "/etc/wireguard/"
				if !strings.HasPrefix(p, dir) || !strings.HasSuffix(p, ".conf") {
					continue
				}
				name := strings.TrimSuffix(strings.TrimPrefix(p, dir), ".conf")
				if name == model.RemoteAccessIface {
					continue
				}
				m := reConf.FindStringSubmatch(body)
				if m == nil {
					t.Fatalf("%s has no MTU line", p)
				}
				confs[name] = m[1]
				all[n.ID+"/"+name] = m[1]
			}
			if len(confs) != len(arms) {
				t.Fatalf("%s: configs %v, activation MTUs %v", n.ID, confs, arms)
			}
			for name, v := range confs {
				if arms[name] != v {
					t.Errorf("%s/%s: config MTU %s, activation sets %q", n.ID, name, v, arms[name])
				}
			}
			if _, ok := arms[model.RemoteAccessIface]; ok {
				t.Errorf("%s: the activation sets the remote-access interface's MTU in the tunnel loop", n.ID)
			}
			if len(confs) > 0 && !strings.Contains(up, wgActivateCommands(tunnelIfacesWithRA(t, topo, n), tunnelMTUs(tunnelsFor(mustTunnels(t, topo), n.ID)))) {
				t.Errorf("%s: meridian-up.sh does not carry wgActivateCommands", n.ID)
			}
		}
		return all
	}
	ra, _ := raExample(t)
	for name, topo := range map[string]model.Topology{"example": defaults.Example(), "remote_access": ra, "dual_hub": defaults.DualHubExample(), "shared_relays": defaults.SharedRelaysExample()} {
		t.Run(name, func(t *testing.T) { check(t, topo) })
	}
	t.Run("adopted MTU", func(t *testing.T) {
		before := check(t, defaults.Example())
		topo := defaults.Example()
		setLink(t, &topo, "hub-jp", func(l *model.Link) { l.MTU = 1408 })
		after := check(t, topo)
		for k, v := range after {
			if before[k] != v && !strings.HasSuffix(k, "/"+mustIface(t, topo, "hub-jp")) {
				t.Errorf("%s: %s → %s although only hub-jp was adopted", k, before[k], v)
			}
		}
		if after["jp/"+mustIface(t, topo, "hub-jp")] != "1408" || after["hk-hub/"+mustIface(t, topo, "hub-jp")] != "1408" {
			t.Errorf("hub-jp not adopted on both ends: %v", after)
		}
	})
}

func mustIface(t *testing.T, topo model.Topology, link string) string {
	t.Helper()
	for _, tun := range mustTunnels(t, topo) {
		if tun.LinkID == link && tun.Mode != "wss" {
			return tun.Iface()
		}
	}
	t.Fatalf("no tunnel for %s", link)
	return ""
}

// tunnelIfacesWithRA: the interface list renderUp hands wgActivateCommands.
func tunnelIfacesWithRA(t *testing.T, topo model.Topology, n model.Node) []string {
	t.Helper()
	ifaces := tunnelIfaces(tunnelsFor(mustTunnels(t, topo), n.ID))
	if n.Role == model.RoleGateway {
		if rp := planRemote(topo); rp != nil {
			ifaces = append([]string{rp.Iface}, ifaces...)
		}
	}
	return ifaces
}

// TestActivationMTUScript runs the generated WireGuard step in bash against
// stub ip/wg/wg-quick and a fake sysfs: an existing interface whose running
// MTU differs from its config is synced and then set in place (no
// wg-quick, no link deletion); an equal one is only synced; a missing one
// is created by wg-quick from its config and not touched afterwards.
func TestActivationMTUScript(t *testing.T) {
	bash, err := exec.LookPath("bash")
	if err != nil {
		t.Skip("bash not installed")
	}
	dir := t.TempDir()
	conf, sys, bin := filepath.Join(dir, "wg")+"/", filepath.Join(dir, "sys")+"/", filepath.Join(dir, "bin")
	for _, d := range []string{conf, sys + "m02", sys + "m03", bin} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	for _, n := range []string{"m02", "m03", "m04"} {
		writeTestFile(t, conf+n+".conf", "[Interface]\nMTU = 1380\n")
	}
	writeTestFile(t, sys+"m02/mtu", "1412\n")
	writeTestFile(t, sys+"m03/mtu", "1380\n")
	log := filepath.Join(dir, "log")
	stub := func(name, body string) {
		writeTestFile(t, filepath.Join(bin, name), "#!/bin/bash\necho \""+name+" $*\" >> '"+log+"'\n"+body)
		if err := os.Chmod(filepath.Join(bin, name), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	stub("ip", `if [ "$1 $2" = "link show" ]; then [ -d '`+sys+`'"$3" ]; exit; fi
if [ "$1 $2 $3" = "link set dev" ] && [ "$5" = mtu ]; then echo "$6" > '`+sys+`'"$4/mtu"; fi
`)
	stub("wg", "")
	stub("wg-quick", `if [ "$1" = strip ]; then cat "$2"; fi
`)
	script := "set -euo pipefail\n" + wgActivateCommands([]string{"m02", "m03", "m04"}, map[string]int{"m02": 1380, "m03": 1380, "m04": 1380})
	script = strings.ReplaceAll(strings.ReplaceAll(script, "/etc/wireguard/", conf), "/sys/class/net/", sys)
	cmd := exec.Command(bash, "-c", script)
	cmd.Env = append(os.Environ(), "PATH="+bin+":"+os.Getenv("PATH"))
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	raw, _ := os.ReadFile(log)
	calls := string(raw)
	if !strings.Contains(string(out), "meridian-wg-mtu: m02 1412 -> 1380") || strings.Contains(string(out), "m03 ") || strings.Contains(string(out), "m04 ") {
		t.Errorf("output %q", out)
	}
	for _, want := range []string{"wg syncconf m02", "ip link set dev m02 mtu 1380", "wg syncconf m03", "wg-quick up " + conf + "m04.conf"} {
		if !strings.Contains(calls, want) {
			t.Errorf("missing call %q in\n%s", want, calls)
		}
	}
	for _, bad := range []string{"ip link set dev m03", "ip link set dev m04", "wg-quick up " + conf + "m02", "wg-quick down", "ip link del"} {
		if strings.Contains(calls, bad) {
			t.Errorf("unexpected call %q in\n%s", bad, calls)
		}
	}
	if b, _ := os.ReadFile(sys + "m02/mtu"); strings.TrimSpace(string(b)) != "1380" {
		t.Errorf("m02 runs at %s", b)
	}
}

func writeTestFile(t *testing.T, path, body string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}
