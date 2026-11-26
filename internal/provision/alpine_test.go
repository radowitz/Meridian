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

// alpineSandbox is a sandbox without systemd: OpenRC's rc-service and
// rc-update (state in the sandbox: runlevel links under etc/runlevels,
// running services as up-<name>) and apk instead of apt-get.
func alpineSandbox(t *testing.T) *sandbox {
	t.Helper()
	sb := newSandbox(t)
	withdrawStubs(t, sb)
	for _, n := range []string{"systemctl", "apt-get"} {
		os.Remove(filepath.Join(sb.bin, n))
	}
	os.RemoveAll(filepath.Join(sb.root, "run/systemd"))
	os.WriteFile(filepath.Join(sb.root, "etc/alpine-release"), []byte("3.19.1\n"), 0o644)
	write := func(name, body string) {
		script := "#!/bin/bash\necho \"" + name + " $*\" >> \"$SANDBOX/calls.log\"\n" + body + "\n"
		if err := os.WriteFile(filepath.Join(sb.bin, name), []byte(script), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	write("rc-update", `case "$1" in
  add) mkdir -p "$SANDBOX/etc/runlevels/$3"; ln -sf "$SANDBOX/etc/init.d/$2" "$SANDBOX/etc/runlevels/$3/$2" ;;
  del) rm -f "$SANDBOX/etc/runlevels/$3/$2" ;;
esac
exit 0`)
	write("rc-service", `case "$2" in
  status) [ -f "$SANDBOX/up-$1" ] && exit 0; exit 3 ;;
  start|restart) [ "$FAIL_RCSTART" = "$1" ] && exit 1; touch "$SANDBOX/up-$1" ;;
  stop) rm -f "$SANDBOX/up-$1" ;;
esac
exit 0`)
	// apk add iproute2 replaces BusyBox's ip (ip -V tells them apart).
	write("apk", `[ "$1" = add ] && for p in "$@"; do [ "$p" = iproute2 ] && touch "$SANDBOX/iproute2"; done
exit 0`)
	os.Rename(filepath.Join(sb.bin, "ip"), filepath.Join(sb.bin, "ip.real"))
	os.WriteFile(filepath.Join(sb.bin, "ip"), []byte(`#!/bin/bash
if [ "$1" = -V ]; then
  if [ -f "$SANDBOX/iproute2" ]; then echo 'ip utility, iproute2-6.6.0'; else echo 'BusyBox v1.36.1'; fi
  exit 0
fi
exec "$(dirname "$0")/ip.real" "$@"
`), 0o755)
	return sb
}

func alpineScript(t *testing.T, node, expect string) (string, map[string]string) {
	t.Helper()
	topo := defaults.Example()
	for i := range topo.Nodes {
		if topo.Nodes[i].ID == node {
			topo.Nodes[i].OS = model.OSAlpine
		}
	}
	b := wsstest.StableCompile(t, topo)
	files := FilesFor(b.Files, node)
	kp, _ := GenerateKeypair()
	injected, err := InjectPrivateWSS(files, kp.Private, wsstest.StableSecrets())
	if err != nil {
		t.Fatal(err)
	}
	o := Options{NodeID: node, Deployment: "dep-1", ServerID: "srv-1", Bundle: preflight.BundleDigest(files), Run: "run-1", Expect: expect, Artifacts: fakeArtifacts(files)}
	return ScriptWith("test", injected, o), injected
}

// An Alpine exit installs through apk and OpenRC: its services are enabled
// in the default runlevel, the resolver runs, the manifest names them by
// their unit names, and a withdraw removes everything again.
func TestAlpineProvisionAndWithdraw(t *testing.T) {
	sb := alpineSandbox(t)
	script, files := alpineScript(t, "jp", "none")
	out, code := sb.run(script)
	if code != 0 || !strings.Contains(out, "MERIDIAN_PROVISION_OK") || !strings.Contains(out, "MERIDIAN_SMARTDNS_ACTIVE") {
		t.Fatalf("exit %d\n%s", code, out)
	}
	calls := sb.read("/calls.log")
	// iproute2 first (before the run records the host's rules and routes),
	// then what the transaction installs.
	if !strings.Contains(calls, "apk add --no-cache iproute2\n") || !strings.Contains(calls, "apk add --no-cache ca-certificates-bundle") ||
		strings.Index(calls, "apk add --no-cache iproute2") > strings.Index(calls, "ca-certificates-bundle") ||
		strings.Contains(calls, "apt-get") || strings.Contains(calls, "\nsystemctl ") {
		t.Fatalf("package and service calls:\n%s", calls)
	}
	for _, s := range []string{"meridian-node", "meridian-smartdns"} {
		if !sb.exists("/etc/runlevels/default/" + s) {
			t.Errorf("%s not enabled in the default runlevel", s)
		}
		if st, err := os.Stat(filepath.Join(sb.root, "etc/init.d", s)); err != nil || st.Mode().Perm() != 0o755 {
			t.Errorf("/etc/init.d/%s mode %v %v", s, st, err)
		}
	}
	if !sb.exists("/up-meridian-smartdns") {
		t.Fatal("the resolver is not running")
	}
	man := strings.ReplaceAll(sb.read("/var/lib/meridian/node/manifest"), sb.root, "")
	for _, want := range []string{"unit meridian-node.service", "unit meridian-smartdns.service", "file /etc/init.d/meridian-smartdns ", "pkg iproute2"} {
		if !strings.Contains(man, want) {
			t.Fatalf("manifest lacks %q:\n%s", want, man)
		}
	}

	sb.hostPaths("/var/lib/meridian/node/manifest")
	p := plan(t, sb, wopts("jp", WithdrawManifest, WithdrawPlan, ""))
	out, code = sb.runRaw(WithdrawScript(wopts("jp", WithdrawManifest, WithdrawRun, p.Digest)))
	w := ParseWithdrawOutput(out)
	if code != 0 || !w.OK || len(w.Leftovers) != 0 {
		t.Fatalf("withdraw %d\n%s", code, out)
	}
	for path := range files {
		if sb.exists(path) {
			t.Errorf("%s left behind", path)
		}
	}
	for _, gone := range []string{"/etc/runlevels/default/meridian-node", "/etc/runlevels/default/meridian-smartdns", "/up-meridian-smartdns"} {
		if sb.exists(gone) {
			t.Errorf("%s left behind", gone)
		}
	}
}

// A resolver that does not start fails the run, which is compensated: the
// services are taken out of the runlevel again.
func TestAlpineProvisionCompensates(t *testing.T) {
	sb := alpineSandbox(t)
	script, _ := alpineScript(t, "jp", "none")
	out, code := sb.run(script, "FAIL_RCSTART=meridian-smartdns")
	if code == 0 || !strings.Contains(out, "MERIDIAN_COMPENSATED") {
		t.Fatalf("exit %d\n%s", code, out)
	}
	for _, s := range []string{"meridian-node", "meridian-smartdns"} {
		if sb.exists("/etc/runlevels/default/" + s) {
			t.Errorf("%s still enabled after compensation", s)
		}
	}
}

// The OpenRC mapping is for Alpine only: a host with rc-service and
// rc-update but no /etc/alpine-release (a Debian with OpenRC tools around
// and systemd momentarily not visible) never gets it.
func TestServiceShimOnlyOnAlpine(t *testing.T) {
	sb := alpineSandbox(t)
	os.Remove(filepath.Join(sb.root, "etc/alpine-release"))
	out, _ := sb.runRaw("M_ROOT=''\n" + compile.ServiceShim + "echo \"openrc=$M_OPENRC\"\ntype -t systemctl || echo none\n")
	if !strings.Contains(out, "openrc=0") || strings.Contains(out, "function") {
		t.Fatalf("shim active without Alpine:\n%s", out)
	}
}

// A runlevel link that cannot be removed is reported as left over and its
// script stays (a retry can still remove the link); a link the operator put
// in another runlevel is never touched and keeps the script too.
func TestAlpineWithdrawKeepsLinkedScripts(t *testing.T) {
	for _, c := range []struct {
		name  string
		setup func(sb *sandbox)
	}{
		{"default link stuck", func(sb *sandbox) {
			os.WriteFile(filepath.Join(sb.bin, "rc-update"), []byte("#!/bin/bash\nexit 1\n"), 0o755)
			os.Chmod(filepath.Join(sb.root, "etc/runlevels/default"), 0o555)
			sb.t.Cleanup(func() { os.Chmod(filepath.Join(sb.root, "etc/runlevels/default"), 0o755) })
		}},
		{"operator runlevel", func(sb *sandbox) {
			os.MkdirAll(filepath.Join(sb.root, "etc/runlevels/custom"), 0o755)
			os.Symlink(filepath.Join(sb.root, "etc/init.d/meridian-smartdns"), filepath.Join(sb.root, "etc/runlevels/custom/meridian-smartdns"))
		}},
	} {
		t.Run(c.name, func(t *testing.T) {
			sb := alpineSandbox(t)
			script, _ := alpineScript(t, "jp", "none")
			if out, code := sb.run(script); code != 0 {
				t.Fatalf("provision %d\n%s", code, out)
			}
			sb.hostPaths("/var/lib/meridian/node/manifest")
			c.setup(sb)
			p := plan(t, sb, wopts("jp", WithdrawManifest, WithdrawPlan, ""))
			out, _ := sb.runRaw(WithdrawScript(wopts("jp", WithdrawManifest, WithdrawRun, p.Digest)))
			if w := ParseWithdrawOutput(out); w.OK && len(w.Leftovers) == 0 {
				t.Fatalf("reported clean:\n%s", out)
			}
			if !sb.exists("/etc/init.d/meridian-smartdns") {
				t.Fatalf("the script of a still linked service was removed:\n%s", out)
			}
			if c.name == "operator runlevel" && !sb.exists("/etc/runlevels/custom/meridian-smartdns") {
				t.Fatal("the operator's runlevel link was removed")
			}
		})
	}
}

// An Alpine host without rc-service / rc-update: provision and withdraw
// refuse before changing anything (no package, no file).
func TestAlpineWithoutOpenRCRefuses(t *testing.T) {
	sb := alpineSandbox(t)
	os.Remove(filepath.Join(sb.bin, "rc-update"))
	script, _ := alpineScript(t, "jp", "none")
	out, code := sb.run(script)
	if code != 3 || !strings.Contains(out, "MERIDIAN_REFUSED no_service_manager") {
		t.Fatalf("provision %d\n%s", code, out)
	}
	if strings.Contains(sb.read("/calls.log"), "apk ") || sb.exists("/etc/init.d/meridian-node") || sb.exists("/var/lib/meridian/node/manifest") {
		t.Fatalf("changed the host before refusing:\n%s", sb.read("/calls.log"))
	}
	out, code = sb.runRaw(WithdrawScript(wopts("jp", WithdrawLegacy, WithdrawPlan, "")))
	if code != 3 || ParseWithdrawOutput(out).Refused != "no_service_manager" {
		t.Fatalf("withdraw %d\n%s", code, out)
	}
}

// Runlevel membership is a symbolic link only: a plain file in a runlevel
// directory is neither "enabled" nor removed. A service the operator put in
// another runlevel is not added to the default one again.
func TestServiceShimRunlevels(t *testing.T) {
	sb := alpineSandbox(t)
	os.MkdirAll(filepath.Join(sb.root, "etc/runlevels/default"), 0o755)
	os.MkdirAll(filepath.Join(sb.root, "etc/runlevels/custom"), 0o755)
	os.WriteFile(filepath.Join(sb.root, "etc/runlevels/default/meridian-node"), []byte("not a link\n"), 0o644)
	os.Symlink(filepath.Join(sb.root, "etc/init.d/meridian-smartdns"), filepath.Join(sb.root, "etc/runlevels/custom/meridian-smartdns"))
	os.MkdirAll(filepath.Join(sb.root, "etc/init.d"), 0o755)
	os.WriteFile(filepath.Join(sb.root, "etc/init.d/meridian-smartdns"), []byte("#!/sbin/openrc-run\n"), 0o755)
	out, _ := sb.runRaw("M_ROOT=\"$SANDBOX\"\n" + compile.ServiceShim + `
systemctl is-enabled meridian-node.service >/dev/null && echo node-enabled
systemctl disable meridian-node.service; echo "disable=$?"
systemctl is-enabled meridian-smartdns.service >/dev/null && echo smartdns-enabled
systemctl enable meridian-smartdns.service; echo "enable=$?"
`)
	if strings.Contains(out, "node-enabled") || !strings.Contains(out, "smartdns-enabled") || !strings.Contains(out, "enable=0") {
		t.Fatalf("shim:\n%s", out)
	}
	if !sb.exists("/etc/runlevels/default/meridian-node") {
		t.Fatal("a plain file in the runlevel was removed")
	}
	if _, err := os.Lstat(filepath.Join(sb.root, "etc/runlevels/default/meridian-smartdns")); err == nil {
		t.Fatal("a service in the operator's runlevel was added to default")
	}
}

// Legacy cleanup on Alpine plans Meridian's generated OpenRC scripts, and
// not a script there under the same name that Meridian did not write.
func TestAlpineLegacyScripts(t *testing.T) {
	sb := alpineSandbox(t)
	sb.write("/usr/local/sbin/meridian-up.sh", "#!/bin/bash\n# Meridian up\n")
	sb.write("/etc/init.d/meridian-node", "#!/sbin/openrc-run\n# Meridian node data plane at boot (meridian-up.sh), OpenRC.\n")
	sb.write("/etc/init.d/meridian-smartdns", "#!/sbin/openrc-run\n# the operator's own, mentions Meridian\n")
	joined := strings.Join(plan(t, sb, wopts("jp", WithdrawLegacy, WithdrawPlan, "")).Plan, "\n")
	if !strings.Contains(joined, "file /etc/init.d/meridian-node") || strings.Contains(joined, "meridian-smartdns") {
		t.Fatalf("legacy plan:\n%s", joined)
	}
}

// A dead runlevel link does not start the service at boot: enable adds the
// default link anyway. A plain file named nftables in a runlevel is still a
// flush risk (OpenRC starts what the names list).
func TestServiceShimDeadLinkAndNftables(t *testing.T) {
	sb := alpineSandbox(t)
	for _, d := range []string{"etc/runlevels/custom", "etc/runlevels/default", "etc/init.d"} {
		os.MkdirAll(filepath.Join(sb.root, d), 0o755)
	}
	os.Symlink("/etc/init.d/gone", filepath.Join(sb.root, "etc/runlevels/custom/meridian-node"))
	os.WriteFile(filepath.Join(sb.root, "etc/init.d/meridian-node"), []byte("#!/sbin/openrc-run\n"), 0o755)
	os.WriteFile(filepath.Join(sb.root, "etc/init.d/nftables"), []byte("#!/sbin/openrc-run\n"), 0o755)
	os.WriteFile(filepath.Join(sb.root, "etc/runlevels/default/nftables"), []byte("x\n"), 0o644)
	out, _ := sb.runRaw("M_ROOT=\"$SANDBOX\"\n" + compile.ServiceShim + `
systemctl enable meridian-node.service; echo "enable=$?"
m_openrc_nft_flush && echo flush-risk
`)
	if !strings.Contains(out, "enable=0") || !strings.Contains(out, "flush-risk") {
		t.Fatalf("shim:\n%s", out)
	}
	if _, err := os.Lstat(filepath.Join(sb.root, "etc/runlevels/default/meridian-node")); err != nil {
		t.Fatal("a dead custom link kept the service out of the default runlevel")
	}
}
