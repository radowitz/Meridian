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
	"github.com/radowitz/meridian/internal/pathquality"
)

// Only synthetic ping output and recording route stubs; never a listener or
// a real network interface. Runs the actual generated remote-hub controller.
func TestMeshQualityShellMatchesSelector(t *testing.T) {
	root := t.TempDir()
	put := func(name, body string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(root, name), []byte(body), 0700); err != nil {
			t.Fatal(err)
		}
	}
	put("date", "#!/bin/sh\ncat \"$CONTROL/now\"\n")
	put("ping", `#!/bin/sh
while [ $# -gt 0 ]; do
 if [ "$1" = -I ]; then shift; iface="$1"; fi
 shift
done
read received rtt < "$CONTROL/$iface"
echo "5 packets transmitted, $received received, 0% packet loss, time 800ms"
echo "rtt min/avg/max/mdev = $rtt/$rtt/$rtt/0.0 ms"
`)
	put("ip", "#!/bin/sh\nprintf '%s\\n' \"$*\" >> \"$CONTROL/routes\"\nif [ -f \"$CONTROL/fail-route\" ]; then case \"$*\" in *'default dev'*) exit 1 ;; esac; fi\nif [ -f \"$CONTROL/fail-dns\" ]; then case \"$*\" in *'fd66:1::2/128 dev'*) exit 1 ;; esac; fi\n")
	topo := defaults.Example()
	topo.Settings.PathQuality = &model.PathQuality{MeshWindowSamples: 2, MinDwellSec: 20, ReturnAfterSec: 10}
	ts, err := buildTunnels(topo)
	if err != nil {
		t.Fatal(err)
	}
	shell := renderMeshQuality(topo, planExits(topo, ts))
	// Each invocation supplies only the synthetic exit and tables below.
	shell = shell[:strings.Index(shell, "mesh_managed()")]
	shell = strings.ReplaceAll(shell, "/run/meridian", filepath.Join(root, "run"))
	put("step", shell+"\nmesh_leg_step synthetic 209 d 192.0.2.1 m 192.0.2.2 fd66:1::2 fd66:1::1 fd66:2::1\n")
	p := *topo.Settings.PathQuality
	var st pathquality.MeshLegState
	samples := []struct{ at, drecv, drtt, mrecv, mrtt int }{
		{100, 5, 300, 5, 20}, {105, 5, 300, 5, 20}, {110, 5, 20, 5, 20}, {115, 5, 20, 5, 20},
		{120, 0, 0, 5, 20}, {125, 5, 20, 5, 20}, {130, 5, 20, 5, 20}, {135, 5, 20, 5, 20},
		{140, 5, 20, 5, 20}, {141, 0, 0, 5, 20}, {142, 0, 0, 0, 0}, {143, 5, 20, 0, 0},
	}
	for _, v := range samples {
		put("now", fmt.Sprint(v.at))
		put("d", fmt.Sprintf("%d %d", v.drecv, v.drtt))
		put("m", fmt.Sprintf("%d %d", v.mrecv, v.mrtt))
		cmd := exec.Command("bash", filepath.Join(root, "step"))
		cmd.Env = append(os.Environ(), "PATH="+root+":"+os.Getenv("PATH"), "CONTROL="+root)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("%d: %v %s", v.at, err, out)
		}
		st, _, _, _ = pathquality.StepMesh(p, st, pathquality.LegSample{Sent: 5, Recv: v.drecv, RTTus: int64(v.drtt) * 1000}, pathquality.LegSample{Sent: 5, Recv: v.mrecv, RTTus: int64(v.mrtt) * 1000}, int64(v.at))
		raw, err := os.ReadFile(filepath.Join(root, "run/exit-legs/synthetic/state"))
		if err != nil {
			t.Fatal(err)
		}
		if got := strings.Fields(string(raw))[0]; got != st.Active {
			t.Fatalf("at %d shell=%s Go=%s", v.at, got, st.Active)
		}
		routes, _ := os.ReadFile(filepath.Join(root, "routes"))
		// Synthetic IPv6 main lookup for an unmarked, unbound socket:
		// the connected direct /64 and WAN default lose to the /128.
		// Replay route replacements, including the persistent high-metric
		// guard, rather than merely checking whether route text exists.
		live, source, guard := "d", "fd66:1::1", false
		for _, line := range strings.Split(string(routes), "\n") {
			f := strings.Fields(line)
			if len(f) < 5 || f[0] != "-6" || f[1] != "route" {
				continue
			}
			if f[3] == "blackhole" && f[4] == "fd66:1::2/128" {
				if strings.Contains(line, "metric 32767") {
					guard = true
				} else {
					live, source = "blackhole", ""
				}
			} else if f[3] == "fd66:1::2/128" && len(f) == 8 && f[4] == "dev" && f[6] == "src" {
				live, source = f[5], f[7]
			}
		}
		wantDev, wantSrc := "d", "fd66:1::1"
		if st.Active == "mesh" {
			wantDev, wantSrc = "m", "fd66:2::1"
		}
		if st.Active == "blackhole" {
			wantDev, wantSrc = "blackhole", ""
		}
		if !guard || live != wantDev || source != wantSrc {
			t.Fatalf("unmarked/unbound main lookup at %d: dev=%s src=%s guard=%v; want %s %s", v.at, live, source, guard, wantDev, wantSrc)
		}
		if strings.Contains(string(routes), "dev mmesh") || strings.Contains(string(routes), "table 102") {
			t.Fatal("controller escaped its exit hop")
		}
	}
	events, err := os.ReadFile(filepath.Join(root, "run/exit-legs/synthetic/events"))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"quality", "direct_recovered", "direct_down", "both_down"} {
		if !strings.Contains(string(events), want) {
			t.Errorf("missing event %s: %s", want, events)
		}
	}
	routes, _ := os.ReadFile(filepath.Join(root, "routes"))
	for _, fam := range []string{"-4", "-6"} {
		if !strings.Contains(string(routes), fam+" route replace blackhole default table 209") {
			t.Fatal("missing blackhole", fam)
		}
	}
	// A failed route update is reported as failed and attempts blackholes
	// in both families; it must never publish the desired live leg.
	put("now", "150")
	put("d", "5 20")
	put("m", "5 20")
	put("fail-route", "1")
	cmd := exec.Command("bash", filepath.Join(root, "step"))
	cmd.Env = append(os.Environ(), "PATH="+root+":"+os.Getenv("PATH"), "CONTROL="+root)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("route failure: %v %s", err, out)
	}
	routeReport, err := os.ReadFile(filepath.Join(root, "run/exit-legs/synthetic/report"))
	if err != nil || !strings.Contains(string(routeReport), "blackhole route_failed") || !strings.HasSuffix(strings.TrimSpace(string(routeReport)), "failed") {
		t.Fatalf("failed route claimed success: %s %v", routeReport, err)
	}
	// Destination route failure must also close both the exit table and
	// the main-table DNS /128, not leave the previously live leg installed.
	if err := os.Remove(filepath.Join(root, "fail-route")); err != nil {
		t.Fatal(err)
	}
	put("fail-dns", "1")
	cmd = exec.Command("bash", filepath.Join(root, "step"))
	cmd.Env = append(os.Environ(), "PATH="+root+":"+os.Getenv("PATH"), "CONTROL="+root)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("DNS route failure: %v %s", err, out)
	}
	failedRoutes, _ := os.ReadFile(filepath.Join(root, "routes"))
	if !strings.HasSuffix(strings.TrimSpace(string(failedRoutes)), "-6 route replace blackhole fd66:1::2/128") {
		t.Fatal("DNS route failure left a live main route")
	}
	report, err := os.ReadFile(filepath.Join(root, "run/exit-legs/synthetic/report"))
	if err != nil || !strings.Contains(string(report), "blackhole route_failed") || !strings.HasSuffix(strings.TrimSpace(string(report)), "failed") {
		t.Fatalf("failed route claimed success: %s %v", report, err)
	}
}

func TestMeshQualityCompiledOnlyOnItsHub(t *testing.T) {
	topo := defaults.Example()
	b, err := Compile(topo)
	if err != nil {
		t.Fatal(err)
	}
	script := b.File("nodes/hk-hub/usr/local/sbin/meridian-failover.sh")
	for _, want := range []string{"mesh_leg_step", "check_mesh_legs || true\n  check_groups", `mesh_member_alive "$id"`, `dev=$(mesh_selected "$dev")`} {
		if !strings.Contains(script, want) {
			t.Errorf("missing %s", want)
		}
	}
	for path, body := range b.Files {
		if strings.Contains(body, "MQ_PLAN=") && path != "nodes/hk-hub/usr/local/sbin/meridian-failover.sh" {
			t.Errorf("controller on %s", path)
		}
	}
	id := MeshQualityPlanID(topo)
	topo.Settings.PathQuality = &model.PathQuality{MeshWindowSamples: 8}
	if MeshQualityPlanID(topo) == id {
		t.Fatal("quality policy change must invalidate old reports")
	}
}

func TestMeshGroupKeepsSameExitWhenBothLegsDown(t *testing.T) {
	topo := defaults.Example()
	b, err := Compile(topo)
	if err != nil {
		t.Fatal(err)
	}
	body := b.File("nodes/hk-hub/usr/local/sbin/meridian-failover.sh")
	body = body[:strings.Index(body, "# --- main loop ---")]
	ts, _ := buildTunnels(topo)
	var us ExitPlan
	for _, e := range planExits(topo, ts) {
		if e.Node.ID == "us" {
			us = e
		}
	}
	root := t.TempDir()
	body = strings.ReplaceAll(body, "/run/meridian", root)
	body += fmt.Sprintf(`
mkdir -p '%s/exit-legs/us' '%s/group/synthetic'
echo blackhole > '%s/exit-legs/us/iface'
echo us > '%s/group/synthetic/active'
# The selected member stays selected; a dead preferred member must not
# attract a group that currently uses another member.
mesh_member_alive us %s %s synthetic us || exit 10
echo us-2 > '%s/group/synthetic/active'
if mesh_member_alive us %s %s synthetic us; then exit 11; fi
[ "$(mesh_selected %s)" = blackhole ] || exit 12
`, root, root, root, root, shQuote(us.HubIface), shQuote(us.PeerV4), root, shQuote(us.HubIface), shQuote(us.PeerV4), shQuote(us.HubIface))
	cmd := exec.Command("bash", "-c", body)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("%v: %s", err, out)
	}
}

// Verify the real SmartDNS call site, sources and reply plumbing, alongside
// the synthetic controller execution above. No kernel/network claims here.
func TestMeshSmartDNSActualTargetAndReturnPath(t *testing.T) {
	topo := defaults.Example()
	ts, err := buildTunnels(topo)
	if err != nil {
		t.Fatal(err)
	}
	b, err := Compile(topo)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range planExits(topo, ts) {
		if e.MeshIface == "" {
			continue
		}
		target, ds, ms := meshDNSRoute(topo, e)
		if target != e.DNSULA || ds == "" || ms == "" {
			t.Fatalf("bad DNS route: %s %s %s", target, ds, ms)
		}
		controller := b.File("nodes/hk-hub/usr/local/sbin/meridian-failover.sh")
		if !strings.Contains(controller, shQuote(target)+" "+shQuote(ds)+" "+shQuote(ms)+" &") {
			t.Fatal("controller does not route actual DNS target/source")
		}
		routes := b.File("nodes/hk-hub/usr/local/sbin/meridian-routes.sh")
		if !strings.Contains(routes, fmt.Sprintf("%s/128 dev %s src %s", target, e.HubIface, ds)) {
			t.Fatal("initial DNS route missing source")
		}
		dns := renderExitDNS(topo, e.Node, ts, planExits(topo, ts))
		if !strings.Contains(dns, "bind ["+target+"]:53") {
			t.Fatal("exit does not listen on actual target")
		}
		nft := b.File("nodes/" + e.Node.ID + "/etc/nftables.d/meridian.nft")
		if !e.MeshSole && (!strings.Contains(nft, fmt.Sprintf(`iifname "%s" ct direction original ct mark set %#x`, e.MeshIface, markHubReturnMesh)) || !strings.Contains(nft, "type route hook output")) {
			t.Fatal("local DNS reply not routed by ingress connection mark")
		}
		for _, tun := range ts {
			if tun.Iface() == e.MeshIface && !strings.Contains(allowedIPs(topo, tun, false), "fd66::/48") {
				t.Fatal("WireGuard rejects DNS source/reply")
			}
		}
	}
}
