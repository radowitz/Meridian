package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/radowitz/meridian/internal/compile"
	"github.com/radowitz/meridian/internal/sniff"
)

// The hidden render command writes the units, the account script and the
// rule pair from the install's renderers, refuses names it would not
// accept, and never overwrites a file.
func TestSniffVerifyRender(t *testing.T) {
	dir := t.TempDir()
	for _, bad := range []string{"/tmp", "/var/tmp", "/run"} {
		if dir == bad || strings.HasPrefix(dir, bad+"/") {
			t.Skipf("temporary directory %s is under %s, which the spec refuses", dir, bad)
		}
	}
	units, work := filepath.Join(dir, "u"), filepath.Join(dir, "w")
	for _, d := range []string{units, work} {
		if err := os.Mkdir(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	args := []string{"--unit-dir", units, "--fixture-dir", work, "--unit", "meridian-vfy-sniff-t.service", "--account-unit", "meridian-vfy-sniff-t-account.service",
		"--user", "mvfysnt", "--uid", "65521", "--script", filepath.Join(work, "account.sh"), "--runtime-dir", "meridian-vfy-sniff-t",
		"--listen", "127.0.0.1:25001", "--neigh-if", "lo", "--fwmark-accept-on", "0", "--fwmark-accept-off", "0"}
	if code := sniffVerifyRender(args); code != 0 {
		t.Fatalf("exit %d", code)
	}
	spec := compile.SniffUnitSpec{Unit: "meridian-vfy-sniff-t.service", AccountUnit: "meridian-vfy-sniff-t-account.service", User: "mvfysnt", UID: 65521,
		AccountScript: filepath.Join(work, "account.sh"), RuntimeDir: "meridian-vfy-sniff-t", StateDir: "meridian-vfy-sniff-t", Binary: "/usr/local/bin/meridian", Listen: "127.0.0.1:25001",
		Snapshot: filepath.Join(work, "decide.json"), Targets: filepath.Join(work, "targets.json"), ListsDir: work, NeighIf: "lo", Ports: []int{80, 443},
		FwmarkAcceptOn: "0", FwmarkAcceptOff: "0"}
	snap, targets := sniff.VerifyFixture()
	for path, want := range map[string]string{
		filepath.Join(units, spec.Unit):        compile.RenderSniffUnit(spec),
		filepath.Join(units, spec.AccountUnit): compile.RenderSniffAccountUnit(spec),
		spec.AccountScript:                     compile.RenderSniffAccountScript(spec),
		spec.Snapshot:                          string(snap),
		spec.Targets:                           string(targets),
	} {
		b, err := os.ReadFile(path)
		if err != nil || string(b) != want {
			t.Fatalf("%s: %v", path, err)
		}
	}
	if fi, _ := os.Stat(spec.AccountScript); fi.Mode().Perm() != 0o755 {
		t.Fatalf("script mode %v", fi.Mode())
	}
	if code := sniffVerifyRender(args); code == 0 {
		t.Fatal("existing files overwritten")
	}
	bad := append([]string(nil), args...)
	for i, a := range bad {
		if a == "--script" {
			bad[i+1] = "/run/x/account.sh"
		}
	}
	if code := sniffVerifyRender(bad); code != 2 {
		t.Fatalf("a script under /run accepted: %d", code)
	}
	if code := sniffVerifyRead([]string{"--socket", filepath.Join(dir, "absent.sock")}); code != 1 {
		t.Fatalf("absent socket: %d", code)
	}
}

// deploy/verify-sniff-systemd.sh: renders through the hidden commands
// (no hand-written unit copy), cleans up through a trap, never touches nft
// or the network, and its fallback reader sandbox is the agent unit's.
func TestSniffVerifyScriptStatic(t *testing.T) {
	b, err := os.ReadFile(filepath.Join("..", "..", "deploy", "verify-sniff-systemd.sh"))
	if err != nil {
		t.Fatal(err)
	}
	script := string(b)
	for _, w := range []string{"sniff-verify-render", "sniff-verify-read", "trap cleanup EXIT", "meridian-sniff-user-conflict", "systemctl reload", "--flip-sysctl", "systemctl is-active --quiet meridian-sniff.service", "journal_dir", "rm -rf \"/var/lib/${rtdir:?}\""} {
		if !strings.Contains(script, w) {
			t.Errorf("script lacks %q", w)
		}
	}
	var code []string
	for _, l := range strings.Split(script, "\n") {
		if !strings.HasPrefix(strings.TrimSpace(l), "#") {
			code = append(code, l)
		}
	}
	for _, w := range []string{"curl ", "wget ", "nft ", "ping ", "ExecStart=", "[Service]", "iptables"} {
		if strings.Contains(strings.Join(code, "\n"), w) {
			t.Errorf("script contains %q", w)
		}
	}
	agent, err := os.ReadFile(filepath.Join("..", "..", "deploy", "debian", "meridian-host.service"))
	if err != nil {
		t.Fatal(err)
	}
	for _, kv := range []string{"User=root", "CapabilityBoundingSet=CAP_NET_ADMIN", "AmbientCapabilities=", "NoNewPrivileges=yes", "ProtectSystem=strict", "ProtectHome=yes",
		"PrivateTmp=yes", "PrivateDevices=yes", "UMask=0077", "ReadWritePaths=-/var/lib/meridian/geosite -/var/lib/meridian/keywords -/var/lib/meridian/lists -/var/lib/meridian-dnslog",
		"RestrictAddressFamilies=AF_UNIX AF_NETLINK AF_INET AF_INET6"} {
		if !strings.Contains(string(agent), "\n"+kv+"\n") {
			t.Errorf("meridian-host.service lacks %q", kv)
		}
		if !strings.Contains(script, kv) {
			t.Errorf("script's agent sandbox lacks %q", kv)
		}
	}
	if bash, err := exec.LookPath("bash"); err == nil {
		if out, err := exec.Command(bash, "-n", filepath.Join("..", "..", "deploy", "verify-sniff-systemd.sh")).CombinedOutput(); err != nil {
			t.Fatalf("bash -n: %v %s", err, out)
		}
	}
}
