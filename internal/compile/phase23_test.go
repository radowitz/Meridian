package compile

import (
	"os"
	"os/exec"
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
	// No Docker sidecar on any host any more: Mesh nodes are host-level.
	for path := range b.Files {
		if strings.Contains(path, "mesh-sidecar.compose.yml") || strings.Contains(path, "meridian-mesh-up.sh") {
			t.Fatalf("sidecar file still compiled: %s", path)
		}
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
	// The Mesh legs' underlay routes are blackholed and never on mmesh.
	if strings.Contains(hubRoutes, "dev mmesh") || !strings.Contains(hubRoutes, `ip route replace blackhole "$a/32" metric 32767`) {
		t.Fatal("the Mesh legs' underlay must be blackholed and never use mmesh")
	}
	if strings.Contains(gwFail, "meridian-mesh-up.sh") {
		t.Fatal("gateway failover must not start the mesh sidecar")
	}
	up := b.File("nodes/hk-hub/usr/local/sbin/meridian-up.sh")
	meshAt := strings.Index(up, "meridian-mesh-up.sh")
	routeAt := strings.Index(up, "meridian-routes.sh")
	if meshAt < 0 || routeAt < 0 || meshAt > routeAt {
		t.Fatal("hub must seal mesh before installing its routes")
	}
	if strings.Contains(b.File("nodes/gw/usr/local/sbin/meridian-up.sh"), "meridian-mesh-up.sh") {
		t.Fatal("gateway up script starts mesh")
	}
	probe := b.File("nodes/us/usr/local/sbin/meridian-unlock-probe.sh")
	for _, needle := range []string{"--entrypoint /check.sh", "-R 66", "-M \"$family\"", "lmc999/regioncheck:latest", "http://192.0.2.88:8787"} {
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
		if strings.Contains(line, "fd66") && strings.Contains(line, "192.0.2.1") && !strings.HasPrefix(strings.TrimSpace(line), "#") {
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

func bashOK() bool {
	_, err := exec.LookPath("bash")
	return err == nil
}

func writeFile(t *testing.T, path, body string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}
