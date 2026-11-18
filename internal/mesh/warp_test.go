package mesh_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/radowitz/meridian/internal/mesh"
	"github.com/radowitz/meridian/internal/model"
)

// A host-level WARP client next to the sidecar: the Mesh preflight refuses
// the host (S1); without one the same host passes. Commands are stubs.
func TestPreflightRefusesHostWARP(t *testing.T) {
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("no bash")
	}
	run := "0123456789abcdef"
	s, err := mesh.PreflightScript(run, model.RoleExit, mesh.DefaultAddressing())
	if err != nil {
		t.Fatal(err)
	}
	for name, warp := range map[string]bool{"warp": true, "clean": false} {
		t.Run(name, func(t *testing.T) {
			bin := t.TempDir()
			stub := func(n, body string) {
				if err := os.WriteFile(filepath.Join(bin, n), []byte("#!/bin/bash\n"+body+"\n"), 0o755); err != nil {
					t.Fatal(err)
				}
			}
			stub("ip", `exit 1`)
			stub("nsenter", `exit 0`)
			stub("ping", `exit 0`)
			stub("systemctl", `exit 3`)
			if warp {
				stub("pgrep", `[ "$2" = warp-svc ] && exit 0; exit 1`)
			} else {
				stub("pgrep", `exit 1`)
				// The source check never leaves the test: curl is a stub.
				stub("curl", `printf 200`)
			}
			// No docker on this stub host: the sidecar tools check reports
			// it, which is not what this test is about.
			cmd := exec.Command("bash", "-s")
			cmd.Stdin = strings.NewReader(strings.ReplaceAll(s, "[ -e /dev/net/tun ]", "true"))
			cmd.Env = []string{"PATH=" + bin + ":/usr/bin:/bin", "LC_ALL=C"}
			out, _ := cmd.CombinedOutput()
			got := strings.Contains(string(out), "MESH_CONFLICT host_warp")
			if got != warp {
				t.Fatalf("host_warp conflict %v, want %v:\n%s", got, warp, out)
			}
			if warp && strings.Contains(string(out), "MESH_PREFLIGHT_OK") {
				t.Fatalf("refused host passed:\n%s", out)
			}
		})
	}
}

const acct = "0123456789abcdef0123456789abcdef"

func hostOut(lines ...string) string {
	return strings.Join(append(lines, "MESHHOST done 1"), "\n") + "\n"
}

var meshHost = []string{
	"MESHHOST svc running",
	"MESHHOST cli present",
	"MESHHOST status Status update: Connected",
	"MESHHOST mode Mode: WarpConnector",
	"MESHHOST reg Account ID: " + acct,
	"MESHHOST addr CloudflareWARP 100.96.0.7/32",
	"MESHHOST rule 4 5209: not from all fwmark 0x100cf lookup 65743",
	"MESHHOST rule 4 32766: from all lookup 254",
	"MESHHOST docker present",
	"MESHHOST memavail 66560",
}

// Synthetic SSH output: mode, account, address, conflicts and missing
// dependencies (N1).
func TestParseHostMesh(t *testing.T) {
	res := mesh.Reserved{Tables: []int{100, 110}, Marks: []string{"0x66"}, Priorities: []int{100, 110}}
	d := mesh.ParseHostMesh(hostOut(meshHost...), acct, res)
	if d.State != model.HostMeshExisting || !d.Reusable || d.Mode != "connector" || d.Account != model.AccountMatched ||
		d.MeshAddr != "100.96.0.7" || d.Iface != "CloudflareWARP" || d.Origin != model.MeshOriginExisting || d.PanelOwned || d.MemAvailMB != 65 || d.Install != nil {
		t.Fatalf("existing node: %+v", d)
	}
	if !d.Coexist.OK || len(d.Coexist.Tables) != 1 || d.Coexist.Tables[0] != 65743 {
		t.Fatalf("coexist: %+v", d.Coexist)
	}

	// Account mismatch / unknown are reported separately and not reusable.
	d = mesh.ParseHostMesh(hostOut(meshHost...), "ffffffffffffffffffffffffffffffff", res)
	if d.Account != model.AccountMismatch || d.Reusable || d.State != model.HostMeshExisting {
		t.Fatalf("mismatch: %+v", d)
	}
	d = mesh.ParseHostMesh(hostOut(meshHost...), "", res)
	if d.Account != model.AccountUnknown || !strings.Contains(d.AccountReason, "没有选定") || d.Reusable {
		t.Fatalf("no selection: %+v", d)
	}
	noID := append([]string{}, meshHost...)
	noID[4] = "MESHHOST reg Organization: example-team"
	d = mesh.ParseHostMesh(hostOut(noID...), acct, res)
	if d.Account != model.AccountUnknown || !strings.Contains(d.AccountReason, "example-team") {
		t.Fatalf("org only: %+v", d)
	}

	// Mesh mode without a readable address; an address outside 100.96/12.
	bad := append([]string{}, meshHost...)
	bad[5] = "MESHHOST addr CloudflareWARP 100.64.0.7/32"
	bad[3] = "MESHHOST mode Mode: Mesh"
	d = mesh.ParseHostMesh(hostOut(bad...), acct, res)
	if d.State != model.HostMeshExisting || d.Mode != "mesh" || d.MeshAddr != "" || d.Reusable {
		t.Fatalf("no address: %+v", d)
	}

	// Conflicts block: shared table, priority, mark, full-tunnel default.
	d = mesh.ParseHostMesh(hostOut(append(meshHost, "MESHHOST default default dev CloudflareWARP table 65743")...), acct,
		mesh.Reserved{Tables: []int{65743}, Marks: []string{"65743", "0x100cf/0xffffffff"}, Priorities: []int{5209}})
	if d.Coexist.OK || d.Reusable || !d.Coexist.GlobalDefault || len(d.Coexist.Conflicts) != 4 {
		t.Fatalf("conflicts: %+v", d.Coexist)
	}

	// Plain WARP client (not a Mesh node): the connector is not installed
	// next to it.
	d = mesh.ParseHostMesh(hostOut("MESHHOST svc running", "MESHHOST cli present", "MESHHOST mode Mode: Warp", "MESHHOST memavail 900000"), acct, res)
	if d.State != model.HostMeshNone || d.Mode != "warp" || d.Install == nil || len(d.Install.Options) != 1 || d.Install.Options[0].Feasible {
		t.Fatalf("warp client: %+v", d)
	}

	// ix without Docker, enough memory, supported system, source reachable,
	// pinned key: the host-level connector is the only option, feasible,
	// with the full install content; operator confirmation required.
	t.Setenv(mesh.RepoKeyFingerprintEnv, testFpr)
	ok := []string{"MESHHOST svc stopped", "MESHHOST cli absent", "MESHHOST memavail 2097152", "MESHHOST os ubuntu noble", "MESHHOST arch aarch64", "MESHHOST apt present", "MESHHOST systemd present", "MESHHOST repo 200"}
	d = mesh.ParseHostMesh(hostOut(ok...), acct, res)
	if d.State != model.HostMeshNone || d.Install == nil || !d.Install.RequiresConfirmation || d.Install.Recommended != model.InstallHostConnector || len(d.Install.Options) != 1 {
		t.Fatalf("ix: %+v", d.Install)
	}
	o := d.Install.Options[0]
	if !o.Feasible || o.Kind != model.InstallHostConnector || o.Repo != mesh.RepoURL || o.KeyFingerprint != testFpr || o.Packages[0] != "cloudflare-warp" ||
		o.Services[0] != "warp-svc.service" || o.MemEstimateMB != mesh.ConnectorMinMemMB || !strings.Contains(o.MemNote, "估计") {
		t.Fatalf("install content: %+v", o)
	}
	if strings.Contains(strings.Join(o.Installs, " "), "Docker") || d.Codename != "noble" || d.Arch != "aarch64" || d.RepoReach != "ok" {
		t.Fatalf("no Docker, prerequisites read: %+v / %+v", o, d)
	}
	block := func(name string, mut func([]string) []string, want string) {
		t.Helper()
		x := mesh.ParseHostMesh(hostOut(mut(append([]string{}, ok...))...), acct, res)
		bl := strings.Join(x.Install.Options[0].Blockers, " ")
		if x.Install.Options[0].Feasible || x.Install.Recommended != "" || !strings.Contains(bl, want) {
			t.Fatalf("%s: %+v", name, x.Install.Options[0])
		}
	}
	block("source unreachable", func(l []string) []string { l[7] = "MESHHOST repo 000"; return l }, "连不上官方软件源")
	block("no curl", func(l []string) []string { l[7] = "MESHHOST repo nocurl"; return l }, "可达性")
	block("unsupported os", func(l []string) []string { l[3] = "MESHHOST os centos"; return l }, "不受支持")
	block("unsupported arch", func(l []string) []string { l[4] = "MESHHOST arch armv7l"; return l }, "架构")
	block("low memory", func(l []string) []string { l[2] = "MESHHOST memavail 66560"; return l }, "低于估计")
	block("no apt", func(l []string) []string { return append(l[:5], l[6:]...) }, "apt-get")
	t.Setenv(mesh.RepoKeyFingerprintEnv, "not-a-fingerprint")
	block("key not pinned", func(l []string) []string { return l }, mesh.RepoKeyFingerprintEnv)
	t.Setenv(mesh.RepoKeyFingerprintEnv, testFpr)
	x := mesh.ParseHostMesh(hostOut(ok...), acct, mesh.Reserved{Tables: []int{65743}})
	if x.Install.Options[0].Feasible || !strings.Contains(strings.Join(x.Install.Options[0].Blockers, " "), "65743") {
		t.Fatalf("WARP table conflict: %+v", x.Install.Options[0])
	}

	// Incomplete output is a detection failure, not "no node".
	d = mesh.ParseHostMesh("MESHHOST svc running\n", acct, res)
	if d.State != model.HostMeshFailed || len(d.Reasons) == 0 {
		t.Fatalf("incomplete: %+v", d)
	}
	// Junk values are rejected.
	d = mesh.ParseHostMesh(hostOut("MESHHOST svc running", "MESHHOST addr bad;name 100.96.0.1/32", "MESHHOST memavail x"), acct, res)
	if d.MeshAddr != "" || d.MemAvailMB != -1 {
		t.Fatalf("junk: %+v", d)
	}
}

// The detection script is read-only and runs against stub commands; a
// warp-svc inside a container does not count as a host node.
func TestDetectScriptStubs(t *testing.T) {
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("no bash")
	}
	s := mesh.DetectScript()
	for _, w := range []string{"rm ", "install ", "> /", "connector new", "warp-cli --accept-tos connect", "registration new", "systemctl stop", "docker run"} {
		if strings.Contains(s, w) {
			t.Fatalf("detection script contains %q", w)
		}
	}
	bin := t.TempDir()
	stub := func(n, body string) {
		if err := os.WriteFile(filepath.Join(bin, n), []byte("#!/bin/bash\n"+body+"\n"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	stub("pgrep", `exit 1`)
	// The source check never leaves the test: curl is a stub.
	stub("curl", `printf 200`)
	stub("systemctl", `exit 0`)
	stub("warp-cli", `case "$2" in status) echo "Status update: Connected";; settings) echo "Mode: WarpConnector";; registration) echo "Account ID: `+acct+`";; esac`)
	stub("ip", `case "$*" in "-o -4 addr show") echo "3: CloudflareWARP    inet 100.96.0.9/32 scope global CloudflareWARP";; "-4 rule show") echo "5209:	not from all fwmark 0x100cf lookup 65743";; esac`)
	cmd := exec.Command("bash", "-s")
	cmd.Stdin = strings.NewReader(s)
	cmd.Env = []string{"PATH=" + bin + ":/usr/bin:/bin", "LC_ALL=C"}
	out, _ := cmd.CombinedOutput()
	d := mesh.ParseHostMesh(string(out), acct, mesh.Reserved{})
	if d.State != model.HostMeshExisting || d.MeshAddr != "100.96.0.9" || !d.Reusable {
		t.Fatalf("%+v\n%s", d, out)
	}
}
