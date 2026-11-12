package compile

import (
	"strings"
	"testing"

	"github.com/radowitz/meridian/internal/defaults"
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
		"pool_step",
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
	if !strings.Contains(hubRoutes, "dev mmesh") {
		t.Fatal("mesh exit has no hub next hop")
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

func ifaceFor(b *Bundle, node, peer string) string {
	prefix := "nodes/" + node + "/etc/wireguard/"
	for path, body := range b.Files {
		if strings.HasPrefix(path, prefix) && strings.Contains(body, "peer-node "+peer) {
			return path[len(prefix):]
		}
	}
	return "missing.conf"
}
