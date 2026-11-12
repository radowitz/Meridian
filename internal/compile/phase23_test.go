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

// TestVerifyScriptExecutedChecks runs the generated meridian-verify.sh in
// bash against stub sysctl/ip/nft/ssh programs. It proves the script's
// decision logic only: a missing firewall fails, unexecuted client/ROS
// checks are never reported as passed, and the success line is limited to
// local checks. It is not evidence about a real gateway or a real leak.
func TestVerifyScriptExecutedChecks(t *testing.T) {
	bash, err := exec.LookPath("bash")
	if err != nil {
		t.Skip("bash not installed")
	}
	b, err := Compile(defaults.Example())
	if err != nil {
		t.Fatal(err)
	}
	script := b.File("nodes/gw/usr/local/sbin/meridian-verify.sh")
	nftFile := b.File("nodes/gw/etc/nftables.d/meridian.nft")
	guardAt := strings.Index(nftFile, "table inet meridian_guard {")
	mainAt := strings.Index(nftFile, "table inet meridian {")
	if guardAt < 0 || mainAt < guardAt {
		t.Fatal("unexpected nft layout")
	}
	guardTable := nftFile[guardAt:strings.LastIndex(nftFile[:mainAt], "table inet meridian\n")]
	mainTable := nftFile[mainAt:]
	goodSysctl := map[string]string{
		"net.ipv4.conf.all.rp_filter": "2", "net.ipv4.conf.default.rp_filter": "2", "net.ipv4.conf.eth0.rp_filter": "2",
		"net.ipv4.conf.all.send_redirects": "0", "net.ipv4.conf.eth0.send_redirects": "0",
		"net.ipv4.conf.all.accept_redirects": "0", "net.ipv6.conf.all.accept_redirects": "0",
		"net.ipv4.ip_forward": "1", "net.ipv6.conf.all.forwarding": "1",
	}
	type tc struct {
		name      string
		noNft     bool
		noSysctl  bool
		noIP      bool
		noMain    bool
		noGuard   bool
		sysctl    map[string]string
		ip6       string
		rosSSH    string
		sshOut    string
		sshFail   bool
		wantCode  int
		want      []string
		forbidden []string
	}
	pendings := []string{"PENDING-HUMAN dns_leak_client", "PENDING-HUMAN webrtc_srflx", "PENDING-HUMAN tunnel_cut", "PENDING-HUMAN redirect_on_wire", "NOT-RUN-HERE netns_reload_no_leak"}
	cases := []tc{
		{name: "all local checks pass", wantCode: 0,
			want:      append([]string{"meridian-verify-local-ok", "PASS nft_guard", "PASS dns_hijack_853", "PASS ula_not_via_ros", "PENDING-HUMAN ros_ula_blackhole"}, pendings...),
			forbidden: []string{"PASS dns_leak", "PASS webrtc", "PASS ros_ula", "meridian-verify-ok"}},
		{name: "nft not installed", noNft: true, wantCode: 1, want: []string{"FAIL nft:", "meridian-verify-failed"}, forbidden: []string{"local-ok"}},
		{name: "main table missing", noMain: true, wantCode: 1, want: []string{"FAIL nft_meridian", "PASS nft_guard"}, forbidden: []string{"local-ok"}},
		{name: "guard table missing", noGuard: true, wantCode: 1, want: []string{"FAIL nft_guard"}, forbidden: []string{"local-ok"}},
		{name: "forwarding off", sysctl: map[string]string{"net.ipv4.ip_forward": "0"}, wantCode: 1, want: []string{"FAIL sysctl net.ipv4.ip_forward: 0, want 1"}},
		{name: "not a gateway", noSysctl: true, noIP: true, wantCode: 2, want: []string{"UNKNOWN sysctl", "UNKNOWN routes", "meridian-verify-incomplete"}, forbidden: []string{"local-ok"}},
		{name: "ula via ros", ip6: "fd66::/48 via fe80::1 dev eth0 metric 1024\n", wantCode: 1, want: []string{"FAIL ula_not_via_ros"}},
		{name: "ros blackhole present", rosSSH: "admin@192.168.100.1", sshOut: " 0 Xb  dst-address=fd00::/8 blackhole distance=1\n", wantCode: 0, want: []string{"PASS ros_ula_blackhole", "local-ok"}},
		{name: "ros blackhole absent", rosSSH: "admin@192.168.100.1", sshOut: " 0 As  dst-address=::/0 gateway=fe80::2\n", wantCode: 1, want: []string{"FAIL ros_ula_blackhole"}},
		{name: "ros unreachable", rosSSH: "admin@192.168.100.1", sshFail: true, wantCode: 2, want: []string{"UNKNOWN ros_ula_blackhole"}, forbidden: []string{"PASS ros_ula", "local-ok"}},
		{name: "ros target refused", rosSSH: "-oProxyCommand=x", wantCode: 1, want: []string{"FAIL ros_ula_blackhole: MERIDIAN_ROS_SSH refused"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			dir := t.TempDir()
			bin := filepath.Join(dir, "bin")
			ev := filepath.Join(dir, "evidence")
			if err := os.MkdirAll(bin, 0o755); err != nil {
				t.Fatal(err)
			}
			for _, tool := range []string{"date", "mkdir", "grep", "mktemp", "cat"} {
				p, err := exec.LookPath(tool)
				if err != nil {
					t.Skip(tool + " not installed")
				}
				if err := os.Symlink(p, filepath.Join(bin, tool)); err != nil {
					t.Fatal(err)
				}
			}
			write := func(name, body string) {
				if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			stub := func(name, body string) {
				if err := os.WriteFile(filepath.Join(bin, name), []byte("#!/bin/bash\n"+body), 0o755); err != nil {
					t.Fatal(err)
				}
			}
			vals := map[string]string{}
			for k, v := range goodSysctl {
				vals[k] = v
			}
			for k, v := range c.sysctl {
				vals[k] = v
			}
			var sb strings.Builder
			for k, v := range vals {
				sb.WriteString(k + "=" + v + "\n")
			}
			write("sysctl.txt", sb.String())
			write("guard.txt", guardTable)
			write("main.txt", mainTable)
			write("ip6.txt", "default via fe80::1 dev eth0 proto ra metric 1024\nfd66:0:0:2::/64 dev m02 proto kernel metric 256\n"+c.ip6)
			write("ssh.txt", c.sshOut)
			if !c.noSysctl {
				stub("sysctl", `[ "$1" = "-n" ] || exit 2
while IFS='=' read -r k v; do [ "$k" = "$2" ] && { echo "$v"; exit 0; }; done < "$D/sysctl.txt"
exit 1
`)
			}
			if !c.noIP {
				stub("ip", `case "$*" in
"-4 -o addr show dev eth0") echo "2: eth0    inet 192.168.100.88/24 brd 192.168.100.255 scope global eth0" ;;
"-4 route get 192.168.100.1") echo "192.168.100.1 dev eth0 src 192.168.100.88 uid 0" ;;
"-6 route show table all") while IFS= read -r l; do echo "$l"; done < "$D/ip6.txt" ;;
*) exit 2 ;;
esac
`)
			}
			if !c.noNft {
				guard := `while IFS= read -r l; do echo "$l"; done < "$D/guard.txt"`
				if c.noGuard {
					guard = `echo "Error: No such file or directory" >&2; exit 1`
				}
				main := `while IFS= read -r l; do echo "$l"; done < "$D/main.txt"`
				if c.noMain {
					main = `echo "Error: No such file or directory" >&2; exit 1`
				}
				stub("nft", `case "$*" in
"list table inet meridian_guard") `+guard+` ;;
"list table inet meridian") `+main+` ;;
*) exit 2 ;;
esac
`)
			}
			sshBody := `while IFS= read -r l; do echo "$l"; done < "$D/ssh.txt"`
			if c.sshFail {
				sshBody = `echo "ssh: connect to host: timed out" >&2; exit 255`
			}
			stub("ssh", sshBody+"\n")
			cmd := exec.Command(bash, "-c", script)
			cmd.Env = []string{"PATH=" + bin, "D=" + dir, "MERIDIAN_VERIFY_EVIDENCE_DIR=" + ev}
			if c.rosSSH != "" {
				cmd.Env = append(cmd.Env, "MERIDIAN_ROS_SSH="+c.rosSSH)
			}
			out, err := cmd.CombinedOutput()
			code := 0
			if ee, ok := err.(*exec.ExitError); ok {
				code = ee.ExitCode()
			} else if err != nil {
				t.Fatal(err)
			}
			if code != c.wantCode {
				t.Fatalf("exit %d, want %d\n%s", code, c.wantCode, out)
			}
			for _, w := range c.want {
				if !strings.Contains(string(out), w) {
					t.Errorf("output missing %q\n%s", w, out)
				}
			}
			for _, f := range c.forbidden {
				if strings.Contains(string(out), f) {
					t.Errorf("output must not contain %q\n%s", f, out)
				}
			}
			summary, err := os.ReadFile(filepath.Join(ev, "summary.txt"))
			if err != nil || !strings.Contains(string(summary), "evidence: "+ev) {
				t.Fatalf("no evidence summary: %v\n%s", err, summary)
			}
			if !c.noNft && !c.noMain {
				if raw, err := os.ReadFile(filepath.Join(ev, "nft-meridian.txt")); err != nil || !strings.Contains(string(raw), "redirect to :853") {
					t.Fatalf("nft evidence not saved: %v", err)
				}
			}
		})
	}
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
