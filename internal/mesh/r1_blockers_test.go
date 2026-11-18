package mesh_test

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/radowitz/meridian/internal/mesh"
	"github.com/radowitz/meridian/internal/model"
)

// ---- A: account match for every node, at deploy and at health.

func TestMeshDeployInstalledNodeAccountChangedAtHealthBlocks(t *testing.T) {
	for name, acct := range map[string]string{"mismatch": strings.Repeat("b", 32), "unreadable": "-"} {
		t.Run(name, func(t *testing.T) {
			f, srv := newFakeCF(t)
			rem := &fakeRemote{accounts: map[string]string{"us": acct}}
			d := newDeployer(t, f, srv, rem)
			_, err := d.Deploy(context.Background(), meshPlan(t))
			if err == nil || !strings.Contains(err.Error(), "health") && !strings.Contains(err.Error(), "us") {
				t.Fatalf("installed node in another account accepted: %v", err)
			}
			if len(f.nodes) != 0 {
				t.Fatal("compensation kept Cloudflare nodes")
			}
		})
	}
}

func TestMeshDeployReusedNodeAfterAccountSwitchBlocks(t *testing.T) {
	hub, exits := meshEnds(t, meshTopo(t))
	hm := map[string]model.HostMeshDetection{hub: reusable(hub, reuseAddr(0))}
	rem := &fakeRemote{detect: map[string]string{hub: detectOut(reuseAddr(0))}}
	for i, e := range exits {
		hm[e] = reusable(e, reuseAddr(i+1))
		rem.detect[e] = detectOut(reuseAddr(i + 1))
	}
	_, p := reusePlan(t, hm)
	mesh.ApplyHostMesh(&p, hm, false)
	d, _, _ := lifecycleDeployer(t)
	d.Remote = rem
	// The panel's account was switched: the reused hub still reports the
	// old one. The run must stop at preflight, before anything is created.
	rem.account = d.AccountID
	rem.accounts = map[string]string{hub: strings.Repeat("c", 32)}
	_, err := d.Deploy(context.Background(), p)
	if err == nil || !strings.Contains(err.Error(), hub) {
		t.Fatalf("reused node of another account accepted: %v", err)
	}
	for _, c := range rem.calls {
		if strings.HasPrefix(c, "connector_install/") {
			t.Fatalf("install ran despite the account mismatch: %v", rem.calls)
		}
	}
	if rem.count(mesh.ActConnectorRemove) != 0 || rem.count(mesh.ActRestore) != 0 {
		t.Fatalf("compensation touched a reused node: %v", rem.calls)
	}
	// Unreadable account of a reused node blocks too.
	rem2 := &fakeRemote{detect: rem.detect, account: d.AccountID, accounts: map[string]string{exits[0]: "-"}}
	d2, _, _ := lifecycleDeployer(t)
	d2.Remote = rem2
	if _, err := d2.Deploy(context.Background(), p); err == nil {
		t.Fatal("reused node with unreadable account accepted")
	}
}

// ---- C: IPv4 and IPv6 default takeover.

func TestHostMeshIPv6OnlyDefaultRouteBlocks(t *testing.T) {
	for name, line := range map[string]string{
		"v6 default in warp table": "MESHHOST default 6 default dev CloudflareWARP table 65743 metric 1024",
		"v6 default via warp dev":  "MESHHOST default 6 default dev CloudflareWARP metric 1",
		"v4 default via warp dev":  "MESHHOST default 4 default dev CloudflareWARP metric 1",
	} {
		d := mesh.ParseHostMesh(hostOut(append(append([]string(nil), meshHost...), line)...), acct, mesh.Reserved{})
		if d.Coexist.OK || !d.Coexist.GlobalDefault || d.Reusable {
			t.Fatalf("%s: takeover not blocked: %+v", name, d.Coexist)
		}
	}
	// An ordinary IPv6 default via the uplink is fine.
	d := mesh.ParseHostMesh(hostOut(append(append([]string(nil), meshHost...), "MESHHOST default 6 default via fe80::1 dev eth0 metric 1024")...), acct, mesh.Reserved{})
	if !d.Coexist.OK {
		t.Fatalf("uplink default flagged: %+v", d.Coexist)
	}
	s := mesh.DetectScript()
	if !strings.Contains(s, "for f in 4 6") || !strings.Contains(s, `ip -N -$f route show table all`) {
		t.Fatal("detection does not read both families' default routes")
	}
}

func TestMeshDeployIPv6DefaultAtHealthBlocks(t *testing.T) {
	f, srv := newFakeCF(t)
	rem := &fakeRemote{}
	rem.after = func(r *fakeRemote, key string) {
		if key == "connector_install/us" {
			a := r.installed["us"]
			if r.detect == nil {
				r.detect = map[string]string{}
			}
			r.detect["us"] = hostOut("MESHHOST svc running", "MESHHOST cli present", "MESHHOST mode Mode: WarpConnector",
				"MESHHOST addr CloudflareWARP "+a+"/32", "MESHHOST rule 6 5209: not from all fwmark 0x100cf lookup 65743",
				"MESHHOST default 6 default dev CloudflareWARP table 65743")
		}
	}
	d := newDeployer(t, f, srv, rem)
	if _, err := d.Deploy(context.Background(), meshPlan(t)); err == nil {
		t.Fatal("IPv6 full tunnel accepted at health")
	}
	if len(f.nodes) != 0 {
		t.Fatal("installed nodes not compensated")
	}
}

func TestConnectorInstallIPv6DefaultFails(t *testing.T) {
	h := newConnHost(t)
	h.stub("ip", `case "$*" in
"-6 route show table 65743") echo "default dev CloudflareWARP metric 1024";;
*) echo "5: CloudflareWARP    inet 100.96.0.7/32 scope global CloudflareWARP";;
esac`)
	out := h.install()
	if !strings.Contains(out, "MESH_INSTALL_FAIL global_default_v6") {
		t.Fatalf("install:\n%s", out)
	}
	h.clean(t, h.remove())
}

// ---- B: strict official source, key set and candidate.

func TestConnectorExtraSourceLineRefused(t *testing.T) {
	h := newConnHost(t)
	p := h.root + "/sources/l.list"
	b, _ := os.ReadFile(p)
	h.write(p, string(b)+"deb https://evil.example/apt stable main\n", 0o644)
	if out := h.install(); !strings.Contains(out, "MESH_INSTALL_FAIL repo_list_differs") {
		t.Fatalf("extra source line accepted:\n%s", out)
	}
	// Comments and blank lines alone are fine.
	h2 := newConnHost(t)
	p2 := h2.root + "/sources/l.list"
	b2, _ := os.ReadFile(p2)
	h2.write(p2, "# official\n\n"+string(b2), 0o644)
	if out := h2.install(); !strings.Contains(out, "MESH_INSTALL_OK") {
		t.Fatalf("commented list refused:\n%s", out)
	}
}

func TestConnectorExtraKeyRefused(t *testing.T) {
	h := newConnHost(t)
	h.set("keys", "pub:-:255:22:AAAA:::::::scESC:\nfpr:::::::::"+stubFpr+":\npub:-:4096:1:CCCC:::::::scESC:\nfpr:::::::::DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD:\n")
	if out := h.install(); !strings.Contains(out, "MESH_INSTALL_FAIL key_set_differs") {
		t.Fatalf("extra key accepted:\n%s", out)
	}
}

func TestConnectorHigherVersionElsewhereIgnored(t *testing.T) {
	h := newConnHost(t)
	h.set("other", "1")
	out := h.install()
	if !strings.Contains(out, "MESH_INSTALL_OK") {
		t.Fatalf("install:\n%s", out)
	}
	ver, _ := os.ReadFile(h.st + "/ver")
	if strings.TrimSpace(string(ver)) != "2026.1.2" {
		t.Fatalf("installed %q, not the official candidate", ver)
	}
	args, _ := os.ReadFile(h.st + "/aptargs")
	for _, l := range strings.Split(strings.TrimSpace(string(args)), "\n") {
		if strings.Contains(l, " install ") && !strings.Contains(l, "Dir::Etc::preferences=") {
			t.Fatalf("apt-get install without the pin: %s", l)
		}
	}
	// No official candidate at all: stop before installing anything.
	h2 := newConnHost(t)
	h2.set("other", "1")
	h2.set("noofficial", "1")
	if out := h2.install(); !strings.Contains(out, "MESH_INSTALL_FAIL candidate_not_official") || strings.Contains(out, "MESH_INTENT package") {
		t.Fatalf("install without official candidate:\n%s", out)
	}
}

// A freshly installed end whose health shows a WARP default route in
// either family is withdrawn on that host (package/source/service via
// connector_remove), and the run's Cloudflare registrations are removed.
func TestMeshDeployNewInstallDualStackConflictCompensatesHost(t *testing.T) {
	for _, fam := range []string{"4", "6"} {
		t.Run("v"+fam, func(t *testing.T) {
			f, srv := newFakeCF(t)
			rem := &fakeRemote{}
			rem.after = func(r *fakeRemote, key string) {
				if key == "connector_install/us" {
					a := r.installed["us"]
					if r.detect == nil {
						r.detect = map[string]string{}
					}
					r.detect["us"] = hostOut("MESHHOST svc running", "MESHHOST cli present", "MESHHOST mode Mode: WarpConnector",
						"MESHHOST addr CloudflareWARP "+a+"/32", "MESHHOST rule "+fam+" 5209: not from all fwmark 0x100cf lookup 65743",
						"MESHHOST default "+fam+" default dev CloudflareWARP metric 1")
				}
			}
			d := newDeployer(t, f, srv, rem)
			if _, err := d.Deploy(context.Background(), meshPlan(t)); err == nil {
				t.Fatal("full-tunnel default accepted at health")
			}
			if len(f.nodes) != 0 {
				t.Fatal("registrations not compensated")
			}
			if !rem.has("connector_remove/us") {
				t.Fatalf("newly installed host not withdrawn: %v", rem.calls)
			}
		})
	}
}
