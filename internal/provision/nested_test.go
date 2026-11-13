package provision

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/radowitz/meridian/internal/compile"
	"github.com/radowitz/meridian/internal/defaults"
	"github.com/radowitz/meridian/internal/model"
	"github.com/radowitz/meridian/internal/preflight"
	"github.com/radowitz/meridian/internal/wsstest"
)

// nodeScript compiles topo, injects the node key, the WSS secrets and the
// given SOCKS secrets, and builds the node's provision script.
func nodeScript(t *testing.T, topo model.Topology, node string, socks map[string]string) (string, map[string]string, map[string]string) {
	t.Helper()
	model.MigrateRegionGroups(&topo)
	b := wsstest.StableCompile(t, topo)
	files := FilesFor(b.Files, node)
	kp, _ := GenerateKeypair()
	sec := wsstest.StableSecrets()
	for k, v := range socks {
		sec[k] = v
	}
	injected, err := InjectPrivateWSS(files, kp.Private, sec)
	if err != nil {
		t.Fatal(err)
	}
	o := Options{NodeID: node, Deployment: "dep-1", ServerID: "srv-1", Bundle: preflight.BundleDigest(files), Run: "run-1", Expect: "none", Artifacts: fakeArtifacts(files)}
	if err := CheckOptions(o); err != nil {
		t.Fatal(err)
	}
	return ScriptWith("test", injected, o), injected, files
}

// loAddrStub extends the withdraw stubs' ip with addresses on lo
// ($SANDBOX/lo-<addr with / as _>), so lo ranges can be checked.
func loAddrStub(t *testing.T, sb *sandbox) {
	t.Helper()
	p := filepath.Join(sb.bin, "ip")
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	body := strings.Replace(string(b), "case \"$*\" in\n", `case "$*" in
  "-o -4 addr show dev lo to "*|"-o -6 addr show dev lo to "*) n=$8; pat=none; case "$n" in 10.66.201.*) pat='10.66.201.' ;; 10.66.202.*) pat='10.66.202.' ;; fd66::55:*) pat='fd66::55:' ;; esac; for f in "$SANDBOX"/lo-*; do [ -f "$f" ] || continue; a=${f##*/lo-}; a=${a//_//}; case "$a" in "$pat"*) echo "1: lo    inet $a scope host lo" ;; esac; done ;;
  "-o addr show dev lo") for f in "$SANDBOX"/lo-*; do [ -f "$f" ] || continue; a=${f##*/lo-}; echo "1: lo    inet ${a//_//} scope host lo"; done ;;
  "-4 addr del "*|"-6 addr del "*) rm -f "$SANDBOX/lo-${4//\//_}" ;;
`, 1)
	// The routes script's del_rule loops while "ip rule del" succeeds.
	body = strings.Replace(body, "\nesac\nexit 0", "\n  *\"rule del \"*) exit 1 ;;\nesac\nexit 0", 1)
	if err := os.WriteFile(p, []byte(body), 0o755); err != nil {
		t.Fatal(err)
	}
}

// A carrier of an external SOCKS exit: the credential reaches only the
// redirector configuration (0600 in a 0700 directory), the manifest names
// gost, the units and the lo ranges, the run checks that the redirector
// and the health probe are active; the withdraw removes all of it, the
// addresses in the lo ranges included, and nothing else.
func TestCarrierProvisionAndWithdraw(t *testing.T) {
	user, pass := "carrier-user", "Carrier.Pass-1"
	socks := map[string]string{"socks-example1-user": user, "socks-example1-pass": pass}
	script, files, raw := nodeScript(t, defaults.ExternalExample(), "dc2", socks)
	for p, body := range raw {
		if strings.Contains(body, pass) {
			t.Fatalf("compiled file %s carries the password", p)
		}
	}
	if !strings.Contains(files[compile.ExtProxyConfig], "password: \""+pass+"\"") {
		t.Fatal("credential not injected into the redirector configuration")
	}
	for p, body := range files {
		if p != compile.ExtProxyConfig && (strings.Contains(body, pass) || strings.Contains(body, user)) {
			t.Fatalf("credential injected into %s", p)
		}
	}
	// A preview (not injected) refuses to run.
	if prev := ScriptWith("test", raw, Options{}); !strings.Contains(prev, "PREVIEW ONLY") {
		t.Fatal("a script with placeholders must refuse")
	}
	sb := newSandbox(t)
	withdrawStubs(t, sb)
	loAddrStub(t, sb)
	out, code := sb.run(script)
	if code != 0 || !strings.Contains(out, "MERIDIAN_PROVISION_OK") || !strings.Contains(out, "MERIDIAN_EXT_ACTIVE") {
		t.Fatalf("provision %d\n%s", code, out)
	}
	if strings.Contains(out, pass) {
		t.Fatal("password in the provision output")
	}
	fi, err := os.Stat(filepath.Join(sb.root, compile.ExtProxyConfig))
	if err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("redirector config mode %v %v", fi, err)
	}
	if di, _ := os.Stat(filepath.Join(sb.root, compile.ExtDir)); di == nil || di.Mode().Perm() != 0o700 {
		t.Fatalf("ext dir mode %v", di)
	}
	man := sb.read("/var/lib/meridian/node/manifest")
	for _, want := range []string{"artifact gost ", "/usr/local/sbin/meridian-gost ", "unit " + compile.ExtProxyUnit, "unit " + compile.ExtHealthUnit,
		compile.ExtProxyConfig + " ", "lonet 10.66.201.0/24", "lonet 10.66.202.0/24", "lonet fd66::55:0/112"} {
		if !strings.Contains(man, want) {
			t.Fatalf("manifest lacks %q:\n%s", want, man)
		}
	}
	if strings.Contains(man, pass) || strings.Contains(sb.read("/var/lib/meridian/node/journal"), pass) {
		t.Fatal("password in the manifest or journal")
	}
	// Addresses the routes script / health probe would have put on lo,
	// one foreign address next to them.
	sb.touch("lo-10.66.201.12_32", "lo-10.66.202.12_32", "lo-fd66::55:3_128", "lo-192.0.2.200_32")
	sb.hostPaths("/var/lib/meridian/node/manifest")
	p := plan(t, sb, wopts("dc2", WithdrawManifest, WithdrawPlan, ""))
	joined := strings.Join(p.Plan, "\n")
	for _, want := range []string{"lonet 10.66.201.0/24 1 addresses", "lonet 10.66.202.0/24 1 addresses", "file " + compile.ExtProxyConfig + " present", "unit " + compile.ExtProxyUnit} {
		if !strings.Contains(joined, want) {
			t.Fatalf("plan lacks %q:\n%s", want, joined)
		}
	}
	out, code = sb.runRaw(WithdrawScript(wopts("dc2", WithdrawManifest, WithdrawRun, p.Digest)))
	w := ParseWithdrawOutput(out)
	if code != 0 || !w.OK || len(w.Leftovers) != 0 {
		t.Fatalf("withdraw %d\n%s", code, out)
	}
	for _, gone := range []string{compile.ExtProxyConfig, compile.ExtDir, "/usr/local/sbin/meridian-gost", "/lo-10.66.201.12_32", "/lo-10.66.202.12_32", "/lo-fd66::55:3_128"} {
		if sb.exists(gone) {
			t.Fatalf("%s left after withdraw", gone)
		}
	}
	if !sb.exists("/lo-192.0.2.200_32") {
		t.Fatal("a foreign lo address was removed")
	}
}

// A carrier whose redirector does not come up: the run fails and is
// compensated (files gone, units disabled).
func TestCarrierProvisionCompensatesWhenRedirectorFails(t *testing.T) {
	socks := map[string]string{"socks-example1-user": "u", "socks-example1-pass": "p"}
	script, _, _ := nodeScript(t, defaults.ExternalExample(), "dc2", socks)
	sb := newSandbox(t)
	withdrawStubs(t, sb)
	loAddrStub(t, sb)
	// systemctl: is-active of the redirector fails.
	stub := filepath.Join(sb.bin, "systemctl")
	b, _ := os.ReadFile(stub)
	_ = os.WriteFile(stub, []byte(strings.Replace(string(b), "case \"$1\" in\n", "case \"$1 $last\" in\n  \"is-active "+compile.ExtProxyUnit+"\") exit 3 ;;\nesac\ncase \"$1\" in\n", 1)), 0o755)
	out, code := sb.run(script)
	if code == 0 || !strings.Contains(out, "is not active after provision") || !strings.Contains(out, "MERIDIAN_COMPENSATED") {
		t.Fatalf("exit %d\n%s", code, out)
	}
	if sb.exists(compile.ExtProxyConfig) || sb.exists("/var/lib/meridian/node/manifest") {
		t.Fatal("compensation left the carrier's files")
	}
}

// The relay exit and the nested exit provision like any exit.
func TestRelayAndNestedProvision(t *testing.T) {
	for _, node := range []string{"dc1", "tw2"} {
		script, _, _ := nodeScript(t, defaults.NestedExample(), node, nil)
		sb := newSandbox(t)
		withdrawStubs(t, sb)
		loAddrStub(t, sb)
		out, code := sb.run(script)
		if code != 0 || !strings.Contains(out, "MERIDIAN_PROVISION_OK") {
			t.Fatalf("%s: exit %d\n%s", node, code, out)
		}
		sb.hostPaths("/var/lib/meridian/node/manifest")
		p := plan(t, sb, wopts(node, WithdrawManifest, WithdrawPlan, ""))
		out, code = sb.runRaw(WithdrawScript(wopts(node, WithdrawManifest, WithdrawRun, p.Digest)))
		if w := ParseWithdrawOutput(out); code != 0 || !w.OK {
			t.Fatalf("%s withdraw %d\n%s", node, code, out)
		}
	}
}
