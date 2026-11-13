package compile

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/radowitz/meridian/internal/defaults"
	"github.com/radowitz/meridian/internal/model"
	"github.com/radowitz/meridian/internal/verify"
)

func TestPhase2And3Bundle(t *testing.T) {
	b, err := Compile(defaults.Example())
	if err != nil {
		t.Fatal(err)
	}
	hub := b.File("nodes/hk-hub/usr/local/sbin/meridian-failover.sh")
	for _, needle := range []string{
		"FAILS_NEED=3",
		"RECOVERS_NEED=5",
		"COOLDOWN=120",
		"refused on table",
		"100|102|150",
		"group_step",
		"group_hop",
	} {
		if !strings.Contains(hub, needle) {
			t.Errorf("hub failover missing %q", needle)
		}
	}
	gwFail := b.File("nodes/gw/usr/local/sbin/meridian-failover.sh")
	if !strings.Contains(gwFail, "Mesh is not a candidate") || strings.Contains(gwFail, "dev mmesh") {
		t.Fatal("gateway failover must not use mesh")
	}
	if b.File("nodes/gw/etc/meridian/mesh-sidecar.compose.yml") != "" {
		t.Fatal("mesh compose must not be installed on the gateway")
	}
	compose := b.File("nodes/hk-hub/etc/meridian/mesh-sidecar.compose.yml")
	if strings.Contains(compose, "network_mode: host") || strings.Contains(compose, "network_mode: \"host\"") {
		t.Fatal("mesh sidecar must not use the host network namespace")
	}
	for _, needle := range []string{"cloudflare/mesh", "NET_ADMIN", "SRCNAT_ENABLED", "/var/lib/cloudflare-warp", "meridian_mesh"} {
		if !strings.Contains(compose, needle) {
			t.Errorf("mesh compose missing %q", needle)
		}
	}
	if strings.Contains(compose, "MESH_NODE_TOKEN=") && strings.Contains(compose, "token-") {
		t.Fatal("compose must not embed a token")
	}
	env := b.File("nodes/hk-hub/etc/meridian/mesh.env.example")
	if strings.Contains(env, "MESH_NODE_TOKEN=ey") || strings.Contains(env, "MESH_NODE_TOKEN=cf") {
		t.Fatal("example env looks like a real token")
	}
	v6 := fileContaining(b, "nodes/ds-relay/etc/wireguard/", "outer v6")
	if !strings.Contains(v6, "[2001:db8::70]:") {
		t.Fatalf("dual-stack relay must dial the pure-v6 exit:\n%s", v6)
	}
	for path, body := range b.Files {
		if strings.Contains(path, "nodes/hk-hub/etc/wireguard/") && strings.Contains(body, "2001:db8::70") {
			t.Fatalf("hub wireguard dials a pure-v6 endpoint: %s", path)
		}
		if strings.Contains(path, "nodes/gw/") && strings.Contains(body, "cloudflare/mesh") {
			t.Fatalf("gateway file references the mesh image: %s", path)
		}
	}
	hubRoutes := b.File("nodes/hk-hub/usr/local/sbin/meridian-routes.sh")
	if !strings.Contains(hubRoutes, "pure-v6 v6-exit via dualstack ds-relay") || !strings.Contains(hubRoutes, "fd66:0:0:70::2/128") {
		t.Fatalf("hub does not forward the pure-v6 exit via the relay:\n%s", hubRoutes)
	}
	if !strings.Contains(hubRoutes, "dev mmesh") || !strings.Contains(hubRoutes, "mesh-sealed") {
		t.Fatal("mesh exit must be gated on the sidecar seal")
	}
	if strings.Contains(gwFail, "meridian-mesh-up.sh") {
		t.Fatal("gateway failover must not start the mesh sidecar")
	}
	up := b.File("nodes/hk-hub/usr/local/sbin/meridian-up.sh")
	meshAt := strings.Index(up, "meridian-mesh-up.sh")
	routeAt := strings.Index(up, "meridian-routes.sh")
	if meshAt < 0 || routeAt < 0 || meshAt > routeAt {
		t.Fatal("hub must seal mesh before installing policy routes")
	}
	if strings.Contains(b.File("nodes/gw/usr/local/sbin/meridian-up.sh"), "meridian-mesh-up.sh") {
		t.Fatal("gateway up script starts mesh")
	}
	meshUp := b.File("nodes/hk-hub/usr/local/sbin/meridian-mesh-up.sh")
	for _, needle := range []string{
		"169.254.66.1/30",
		"unreachable default",
		"iif mmesh-c lookup 170 priority 17000",
		"mesh-sealed",
		"refusing to start mesh on the home gateway",
		"oifname !=",
	} {
		if !strings.Contains(meshUp, needle) {
			t.Errorf("mesh-up missing %q", needle)
		}
	}
	if strings.Contains(meshUp, "10.66.254.") || strings.Contains(meshUp, "flush ruleset") || strings.Contains(meshUp, "network_mode") {
		t.Fatal("mesh-up uses the tunnel aggregate, flushes nft, or joins the host netns")
	}
	probe := b.File("nodes/us/usr/local/sbin/meridian-unlock-probe.sh")
	for _, needle := range []string{"--entrypoint /check.sh", "-R 66", "-M \"$family\"", "lmc999/regioncheck:latest", "http://192.168.100.88:8787"} {
		if !strings.Contains(probe, needle) {
			t.Errorf("unlock probe missing %q\n%s", needle, probe)
		}
	}
	if strings.Contains(probe, "MERIDIAN_PANEL_TOKEN=") && strings.Contains(probe, "eyJ") {
		t.Fatal("probe embeds a token")
	}
	if !strings.Contains(b.File("nodes/us/etc/systemd/system/meridian-unlock.service"), "TimeoutStartSec=55min") {
		t.Fatal("unlock oneshot can hang the 6-hour timer")
	}
	for _, line := range strings.Split(hubRoutes, "\n") {
		if strings.Contains(line, "fd66") && strings.Contains(line, "192.168.100.1") && !strings.HasPrefix(strings.TrimSpace(line), "#") {
			t.Fatalf("ULA via ROS: %s", line)
		}
	}
	nat := b.File("nodes/hk-hub/etc/meridian/nat64.reserved.conf")
	if !strings.Contains(nat, "NAT64 reservation") || !strings.Contains(nat, "enabled=false") {
		t.Fatalf("nat64 placeholder:\n%s", nat)
	}
	for path, body := range b.Files {
		if !strings.HasSuffix(path, "meridian-routes.sh") {
			continue
		}
		for _, line := range strings.Split(body, "\n") {
			trim := strings.TrimSpace(line)
			if strings.HasPrefix(trim, "#") {
				continue
			}
			if strings.Contains(strings.ToLower(trim), "nat64") || strings.Contains(trim, "64:ff9b") {
				t.Fatalf("route script installed NAT64: %s: %s", path, trim)
			}
		}
	}
	timer := b.File("nodes/us/etc/systemd/system/meridian-unlock.timer")
	if !strings.Contains(timer, "OnUnitActiveSec=21600") {
		t.Fatalf("unlock timer:\n%s", timer)
	}
	if b.File("nodes/gw/usr/local/sbin/meridian-unlock-probe.sh") != "" {
		t.Fatal("unlock probe must not run on the gateway")
	}
	decisions := map[string]string{"auto-openai": "us-2", "manual-example": "jp"}
	moved, err := CompileWithDecisions(defaults.Example(), decisions)
	if err != nil {
		t.Fatal(err)
	}
	dns := moved.File("nodes/gw/etc/smartdns/smartdns.conf")
	if !strings.Contains(dns, "# rule auto-openai -> us-2 ") {
		t.Fatalf("unlock should move openai inside the US pool:\n%s", lineWith(dns, "auto-openai"))
	}
	if !strings.Contains(dns, "# rule manual-example -> us ") {
		t.Fatalf("pinned rule followed the unlock map:\n%s", lineWith(dns, "manual-example"))
	}
	items := verify.CheckBundle(defaults.Example(), b.Files)
	for _, it := range items {
		if it.Status == verify.Fail {
			t.Errorf("checklist %s: %s", it.ID, it.Detail)
		}
	}
}

func TestHubDoesNotDialPureV6(t *testing.T) {
	topo := defaults.Example()
	topo.Links = append(topo.Links, model.Link{
		ID: "hub-v6-direct", From: "hk-hub", To: "v6-exit",
		Transport: model.TransportDirectWG, Enabled: true,
		MTU: 1420, WGPort: 51871,
		FromV4: "10.66.71.1", ToV4: "10.66.71.2",
		FromULA: "fd66:0:0:71::1", ToULA: "fd66:0:0:71::2",
	})
	b, err := Compile(topo)
	if err != nil {
		t.Fatal(err)
	}
	for path, body := range b.Files {
		if strings.Contains(path, "nodes/hk-hub/etc/wireguard/") && strings.Contains(body, "2001:db8::70") {
			t.Fatalf("hub wireguard dials a pure-v6 endpoint: %s\n%s", path, body)
		}
	}
	relay := fileContaining(b, "nodes/ds-relay/etc/wireguard/", "[2001:db8::70]:")
	if !strings.Contains(relay, "[2001:db8::70]:") {
		t.Fatal("dual-stack relay lost the v6 dial")
	}
}

func ifaceFor(b *Bundle, node, peer string) string {
	prefix := "nodes/" + node + "/etc/wireguard/"
	for path, body := range b.Files {
		if strings.HasPrefix(path, prefix) && strings.Contains(body, "peer-node "+peer) {
			return path[len(prefix):]
		}
	}
	return "missing.conf"
}

// The hub installs Mesh routes with explicit veth next-hops (IPv4 and the
// link-local IPv6 scoped to mmesh), in the static routes and in the dynamic
// pool switch; "default dev mmesh" never appears. The sidecar gets fixed
// MACs, permanent neighbours, return routes via the host end, and an
// atomic meridian_mesh nft replace. The gateway guard never admits mmesh.
func TestMeshVethNextHops(t *testing.T) {
	b, err := Compile(defaults.Example())
	if err != nil {
		t.Fatal(err)
	}
	hubRoutes := b.File("nodes/hk-hub/usr/local/sbin/meridian-routes.sh")
	hubFail := b.File("nodes/hk-hub/usr/local/sbin/meridian-failover.sh")
	for _, f := range []string{hubRoutes, hubFail} {
		if strings.Contains(f, "default dev mmesh") || strings.Contains(f, `default dev "$MESH_DEV"`) {
			t.Fatal("a route onto the mmesh veth has no next-hop")
		}
	}
	for _, needle := range []string{"default via 169.254.66.2 dev mmesh table", "default via fe80::66:2 dev mmesh table"} {
		if !strings.Contains(hubRoutes, needle) {
			t.Errorf("hub routes missing %q", needle)
		}
	}
	for _, needle := range []string{
		"MESH_DEV=mmesh", "MESH_NH4=169.254.66.2", "MESH_NH6=fe80::66:2",
		`default via "$MESH_NH4" dev "$MESH_DEV" table "$table"`,
		`default via "$MESH_NH6" dev "$MESH_DEV" table "$table"`,
	} {
		if !strings.Contains(hubFail, needle) {
			t.Errorf("hub pool switch missing %q", needle)
		}
	}
	meshUp := b.File("nodes/hk-hub/usr/local/sbin/meridian-mesh-up.sh")
	for _, needle := range []string{
		"ip -6 addr replace fe80::66:1/64 dev mmesh nodad",
		"ip -6 addr replace fe80::66:2/64 dev mmesh-c nodad",
		"ip neigh replace 169.254.66.2 lladdr 02:6d:65:73:68:02 dev mmesh nud permanent",
		"ip -6 neigh replace fe80::66:2 lladdr 02:6d:65:73:68:02 dev mmesh nud permanent",
		"ip neigh replace 169.254.66.1 lladdr 02:6d:65:73:68:01 dev mmesh-c nud permanent",
		"ip -6 neigh replace fe80::66:1 lladdr 02:6d:65:73:68:01 dev mmesh-c nud permanent",
		`ip route replace "$p" via 169.254.66.1 dev mmesh-c`,
		`ip -6 route replace "$p" via fe80::66:1 dev mmesh-c`,
		"for p in 192.168.100.0/24 10.66.0.0/16; do",
		"ping -6 -c 1 -W 2 -n fe80::66:2%mmesh",
		"nft -f - <<NFT",
	} {
		if !strings.Contains(meshUp, needle) {
			t.Errorf("mesh-up missing %q", needle)
		}
	}
	// Atomic replace: no standalone delete followed by separate adds.
	if strings.Contains(meshUp, "nft delete table inet meridian_mesh") || strings.Contains(meshUp, "nft add table inet meridian_mesh") {
		t.Fatal("meridian_mesh is still replaced with a separate delete and adds")
	}
	nftAt := strings.Index(meshUp, "nft -f - <<NFT")
	batch := meshUp[nftAt:]
	if !strings.Contains(batch, "table inet meridian_mesh\ndelete table inet meridian_mesh\ntable inet meridian_mesh {") {
		t.Fatal("meridian_mesh batch is not create/delete/recreate in one transaction")
	}
	// The seal follows the next-hop pings.
	if strings.Index(meshUp, "ping -c 1 -W 2 -n -I mmesh 169.254.66.2") > strings.Index(meshUp, ": > /run/meridian/mesh-sealed") {
		t.Fatal("seal is written before the next-hops are checked")
	}
	gwNft := b.File("nodes/gw/etc/nftables.d/meridian.nft")
	if gwNft == "" || strings.Contains(gwNft, "mmesh") {
		t.Fatal("the gateway guard must not admit a Mesh interface")
	}
	compose := b.File("nodes/hk-hub/etc/meridian/mesh-sidecar.compose.yml")
	if !strings.Contains(compose, "name: meridian_mesh_lib") || !strings.Contains(compose, "name: meridian-mesh") {
		t.Fatal("compose must use the fixed project and volume names the deployer restores")
	}
	if bashOK() {
		for _, p := range []string{"nodes/hk-hub/usr/local/sbin/meridian-mesh-up.sh", "nodes/hk-hub/usr/local/sbin/meridian-failover.sh", "nodes/hk-hub/usr/local/sbin/meridian-routes.sh"} {
			f := filepath.Join(t.TempDir(), "s.sh")
			_ = os.WriteFile(f, []byte(b.File(p)), 0o600)
			if out, err := exec.Command("bash", "-n", f).CombinedOutput(); err != nil {
				t.Errorf("%s: bash -n: %v %s", p, err, out)
			}
		}
	}
}

func bashOK() bool {
	_, err := exec.LookPath("bash")
	return err == nil
}

// The compiled meridian-mesh-up.sh under bash with stubs (docker, nsenter,
// ip, ping, sysctl): the seal file is written only when the sealing block
// inside the sidecar netns succeeded and both next-hops answer. A failed
// block must leave the host unsealed. (Until 2026-11-13 the condition was
// inverted: a successful block unsealed, a failed one sealed.)
func TestMeshUpSealFollowsSidecarBlock(t *testing.T) {
	if !bashOK() {
		t.Skip("bash not available")
	}
	b, err := Compile(defaults.Example())
	if err != nil {
		t.Fatal(err)
	}
	for _, node := range []string{"hk-hub", "us"} {
		body := b.File("nodes/" + node + "/usr/local/sbin/meridian-mesh-up.sh")
		for _, c := range []struct {
			block, ping string
			sealed      bool
			says        string
		}{
			{"0", "0", true, "mesh sidecar sealed"},
			{"1", "0", false, "mesh seal failed"},
			{"0", "1", false, "does not answer"},
		} {
			dir := t.TempDir()
			run, etc, bin := filepath.Join(dir, "run"), filepath.Join(dir, "etc"), filepath.Join(dir, "bin")
			for _, d := range []string{run, etc, bin} {
				if err := os.MkdirAll(d, 0o755); err != nil {
					t.Fatal(err)
				}
			}
			writeFile(t, filepath.Join(etc, "mesh.env"), "MESH_NODE_TOKEN=stub\n")
			writeFile(t, filepath.Join(etc, "mesh-sidecar.compose.yml"), "# stub\n")
			stubs := map[string]string{
				"docker": "case \"$1 $2\" in \"compose -f\") shift 3; [ \"$1\" = ps ] && echo cid; exit 0 ;; \"inspect -f\") echo 999999; exit 0 ;; esac\nexit 1\n",
				// "ip link show mmesh-c" inside the netns: present; the
				// sealing block (bash -s) exits with the case's status.
				"nsenter": "while [ $# -gt 0 ] && [ \"$1\" != bash ] && [ \"$1\" != ip ]; do shift; done\nif [ \"$1\" = bash ]; then cat >/dev/null; exit " + c.block + "; fi\nexit 0\n",
				"ip":      "exit 0\n",
				"ping":    "exit " + c.ping + "\n",
				"sysctl":  "exit 0\n",
			}
			for name, s := range stubs {
				if err := os.WriteFile(filepath.Join(bin, name), []byte("#!/bin/bash\n"+s), 0o755); err != nil {
					t.Fatal(err)
				}
			}
			script := strings.ReplaceAll(body, "/run/meridian", run)
			script = strings.ReplaceAll(script, "/etc/meridian/", etc+"/")
			p := filepath.Join(dir, "mesh-up.sh")
			writeFile(t, p, script)
			cmd := exec.Command("bash", p)
			cmd.Env = append(os.Environ(), "PATH="+bin+":"+os.Getenv("PATH"))
			out, err := cmd.CombinedOutput()
			if err != nil {
				t.Fatalf("%s block=%s ping=%s: %v\n%s", node, c.block, c.ping, err, out)
			}
			_, serr := os.Stat(filepath.Join(run, "mesh-sealed"))
			if (serr == nil) != c.sealed || !strings.Contains(string(out), c.says) {
				t.Fatalf("%s block=%s ping=%s: sealed=%v (want %v)\n%s", node, c.block, c.ping, serr == nil, c.sealed, out)
			}
		}
	}
}

func writeFile(t *testing.T, path, body string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}
