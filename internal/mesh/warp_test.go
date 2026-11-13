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
