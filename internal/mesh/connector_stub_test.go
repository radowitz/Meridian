package mesh_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/radowitz/meridian/internal/mesh"
)

// Stubbed host for the connector install / removal scripts: every command
// that touches the system (dpkg-query, apt-get, systemctl, warp-cli, ip,
// gpg) is a shell stub over state files in a temporary directory, and the
// fixed paths are rewritten into it. Nothing real is contacted.
type connHost struct {
	t                      *testing.T
	dir, bin, st, bk, root string
	// sys mirrors /usr/bin and /bin without the tools the stubs stand in
	// for, so a host that "lacks" one (gpg) really lacks it even where the
	// test machine has it (Debian CI images ship gpg/gpgv).
	sys string
}

// hostOnly are commands the stubbed host provides (or deliberately lacks);
// the real ones never leak in through PATH.
func hostOnly(name string) bool {
	switch {
	case strings.HasPrefix(name, "gpg"), strings.HasPrefix(name, "apt"), strings.HasPrefix(name, "dpkg"):
		return true
	}
	switch name {
	case "curl", "wget", "systemctl", "warp-cli", "warp-svc", "ip", "sudo", "dirmngr":
		return true
	}
	return false
}

func mirrorSystemBin(t *testing.T, dst string) {
	t.Helper()
	if err := os.MkdirAll(dst, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, src := range []string{"/usr/bin", "/bin"} {
		ents, err := os.ReadDir(src)
		if err != nil {
			continue
		}
		for _, e := range ents {
			if hostOnly(e.Name()) {
				continue
			}
			l := filepath.Join(dst, e.Name())
			if _, err := os.Lstat(l); err == nil {
				continue
			}
			_ = os.Symlink(filepath.Join(src, e.Name()), l)
		}
	}
}

const stubFpr = "0123456789ABCDEF0123456789ABCDEF01234567"

func newConnHost(t *testing.T) *connHost {
	t.Helper()
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("no bash")
	}
	d := t.TempDir()
	h := &connHost{t: t, dir: d, bin: filepath.Join(d, "bin"), st: filepath.Join(d, "state"), root: filepath.Join(d, "root")}
	h.bk = filepath.Join(h.root, "mesh-deploy", run)
	h.sys = filepath.Join(d, "sys")
	mirrorSystemBin(t, h.sys)
	for _, p := range []string{h.bin, h.st, filepath.Join(h.root, "keyrings"), filepath.Join(h.root, "sources")} {
		if err := os.MkdirAll(p, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	// The key and source list already exist (keeps curl out of the test).
	h.write(filepath.Join(h.root, "keyrings", "k.gpg"), "key\n", 0o644)
	h.write(filepath.Join(h.root, "sources", "l.list"), "deb [signed-by="+filepath.Join(h.root, "keyrings", "k.gpg")+"] "+mesh.RepoURL+" bookworm main\n", 0o644)
	S := h.st
	// gpg is present by default; "nogpg" hosts lose it, and apt-get
	// installing gnupg brings it back from gpg.src.
	h.write(filepath.Join(S, "gpg.src"), "#!/bin/bash\n"+`if [ -s `+S+`/keys ]; then cat `+S+`/keys; else echo "pub:-:255:22:AAAA:::::::scESC:"; echo "fpr:::::::::`+stubFpr+`:"; echo "sub:-:255:18:BBBB:::::::e:"; echo "fpr:::::::::FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF:"; fi`+"\n", 0o755)
	h.write(filepath.Join(h.bin, "gpg"), h.read(filepath.Join(S, "gpg.src")), 0o755)
	// apt-cache honours the single-source options: restricted, it sees the
	// official source alone; otherwise also a third-party source with a
	// higher version (state "other"). policy reports the origin the apt-get
	// stub installed from (state "origin").
	h.stub("apt-cache", `case "$*" in *policy*) v=$(cat `+S+`/ver 2>/dev/null); echo "cloudflare-warp:"; echo "  Installed: $v"; echo "  Version table:"; echo " *** $v 1001"
  if [ "$(cat `+S+`/origin 2>/dev/null)" = official ]; then echo "        1001 https://pkg.cloudflareclient.com bookworm/main amd64 Packages"; else echo "        500 https://evil.example/apt stable/main amd64 Packages"; fi
  echo "        100 /var/lib/dpkg/status"; exit 0;; esac
one=0; case "$*" in *"Dir::Etc::sourceparts=-"*) one=1;; esac
[ "$one" = 1 ] || { [ -e `+S+`/other ] && echo " cloudflare-warp | 9999.1 | https://evil.example/apt stable/main amd64 Packages"; }
[ -e `+S+`/noofficial ] || echo " cloudflare-warp | 2026.1.2 | `+strings.TrimSuffix(mesh.RepoURL, "/")+` bookworm/main amd64 Packages"
exit 0`)
	// dpkg-query: "deps" are packages the install pulled from the "debian"
	// source, "prepkgs" packages the host already had.
	h.stub("dpkg-query", `n=""; for a in "$@"; do n=$a; done
case "$*" in *Package*) echo base-files; [ -e `+S+`/gnupg ] && printf 'dirmngr\ngnupg\ngpg\n'; cat `+S+`/deps `+S+`/prepkgs 2>/dev/null; [ -s `+S+`/pkg ] && echo cloudflare-warp; exit 0;; esac
case "$*" in *Status*) if grep -sqx -- "$n" `+S+`/deps `+S+`/prepkgs; then echo "install ok installed"; exit 0; fi;; esac
case "$*" in *gnupg*|*dirmngr*|*" gpg"*) [ -e `+S+`/gnupg ] || exit 1; echo "install ok installed"; exit 0;; esac
case "$*" in *Version*) cat `+S+`/ver 2>/dev/null; exit 0;; esac; [ -s `+S+`/pkg ] || exit 1; cat `+S+`/pkg`)
	// apt-get install: restricted to the official list, the Debian
	// dependencies are not installable (as on a real Debian 13 host). With
	// the normal sources, the dependencies come from "debian" and
	// cloudflare-warp from the official origin only when the pin file
	// admits that origin alone; without it a third-party source (state
	// "other") wins with its higher version.
	h.stub("apt-get", `echo "$*" >> `+S+`/aptargs
orig=("$@")
want=""; pinf=""
for a in "$@"; do case "$a" in cloudflare-warp=*) want="${a#*=}";; Dir::Etc::preferences=*) pinf="${a#*=}";; esac; done
case " $* " in
*" install "*" gnupg "*) echo gnupg >> `+S+`/gnupgops; [ -e `+S+`/gnupgfail ] && exit 100; : > `+S+`/gnupg; cp `+S+`/gpg.src `+h.bin+`/gpg; exit 0;;
*" purge "*" gnupg "*) echo purge >> `+S+`/gnupgops; echo "$*" > `+S+`/gnupgpurge; rm -f `+S+`/gnupg `+h.bin+`/gpg; exit 0;;
esac
for a in "$@"; do case "$a" in update|install|purge) set -- "$a"; break;; esac; done
case "$1" in
update) exit 0;;
install)
  case " ${orig[*]} " in *"Dir::Etc::sourceparts=-"*) echo " cloudflare-warp : Depends: libwebkit2gtk-4.1-0 but it is not installable"; exit 100;; esac
  if [ -n "$pinf" ] && grep -q 'Pin: origin "pkg.cloudflareclient.com"' "$pinf" && grep -q 'Pin-Priority: 1001' "$pinf" && grep -q 'Pin-Priority: -1' "$pinf"; then
    echo "$want" > `+S+`/ver; echo official > `+S+`/origin
  elif [ -e `+S+`/other ]; then echo 9999.1 > `+S+`/ver; echo evil > `+S+`/origin
  else echo "$want" > `+S+`/ver; echo official > `+S+`/origin; fi
  [ -e `+S+`/forceorigin ] && cat `+S+`/forceorigin > `+S+`/origin
  printf 'libwebkit2gtk-4.1-0\nlibayatana-appindicator3-1\n' > `+S+`/deps; echo debian > `+S+`/depsrc
  case "$(cat `+S+`/apt 2>/dev/null)" in
  partial) echo "install ok unpacked" > `+S+`/pkg; exit 100;;
  die) echo "install ok installed" > `+S+`/pkg; cp `+S+`/warp-cli.src `+h.bin+`/warp-cli; kill -9 $PPID; exit 0;;
  esac
  echo "install ok installed" > `+S+`/pkg; cp `+S+`/warp-cli.src `+h.bin+`/warp-cli;;
purge)
  echo "${orig[*]}" >> `+S+`/purgeargs
  for a in "${orig[@]}"; do
    case "$a" in cloudflare-warp) rm -f `+S+`/pkg `+S+`/enabled `+S+`/active `+h.bin+`/warp-cli;; esac
    for f in deps prepkgs; do [ -f `+S+`/$f ] && { grep -vx -- "$a" `+S+`/$f > `+S+`/$f.n; mv `+S+`/$f.n `+S+`/$f; }; done
  done;;
esac`)
	h.stub("systemctl", `last=""; for a in "$@"; do last=$a; done
case "$1" in
is-active) [ -e `+S+`/active ];;
is-enabled) [ -e `+S+`/enabled ];;
enable) : > `+S+`/enabled; [ "$(cat `+S+`/svc 2>/dev/null)" = startfail ] && exit 1; : > `+S+`/active;;
disable) rm -f `+S+`/enabled;;
stop) rm -f `+S+`/active;;
esac`)
	h.write(filepath.Join(S, "warp-cli.src"), `#!/bin/bash
case "$*" in
*"registration show"*) [ -e `+S+`/reg ] && exit 0; echo "Error: Missing registration"; exit 1;;
*"registration delete"*) [ -e `+S+`/regdelfail ] && exit 1; rm -f `+S+`/reg;;
*"connector new"*) : > `+S+`/reg;;
esac
exit 0
`, 0o755)
	h.stub("ip", `echo "5: CloudflareWARP    inet 100.96.0.7/32 scope global CloudflareWARP"`)
	h.stub("sleep", `exit 0`)
	return h
}

func (h *connHost) write(p, body string, mode os.FileMode) {
	h.t.Helper()
	if err := os.WriteFile(p, []byte(body), mode); err != nil {
		h.t.Fatal(err)
	}
}

func (h *connHost) read(p string) string {
	h.t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		h.t.Fatal(err)
	}
	return string(b)
}

func (h *connHost) stub(name, body string) {
	h.write(filepath.Join(h.bin, name), "#!/bin/bash\n"+body+"\n", 0o755)
}

func (h *connHost) set(name, v string) {
	if v == "" {
		os.Remove(filepath.Join(h.st, name))
		return
	}
	h.write(filepath.Join(h.st, name), v, 0o644)
}

func (h *connHost) has(name string) bool {
	_, err := os.Stat(filepath.Join(h.st, name))
	return err == nil
}

func (h *connHost) exec(script string) string {
	h.t.Helper()
	r := strings.NewReplacer(
		"/var/lib/meridian/mesh-deploy", filepath.Join(h.root, "mesh-deploy"),
		mesh.RepoKeyring, filepath.Join(h.root, "keyrings", "k.gpg"),
		mesh.RepoList, filepath.Join(h.root, "sources", "l.list"),
	)
	cmd := exec.Command("bash", "-c", r.Replace(script))
	cmd.Env = []string{"PATH=" + h.bin + ":" + h.sys, "HOME=" + h.dir}
	out, _ := cmd.CombinedOutput()
	return string(out)
}

func (h *connHost) install() string {
	s, err := mesh.ConnectorInstallScript(run, "bookworm", stubFpr, "synthetic-token")
	if err != nil {
		h.t.Fatal(err)
	}
	return h.exec(s)
}

func (h *connHost) remove() string {
	s, err := mesh.ConnectorRemoveScript(run)
	if err != nil {
		h.t.Fatal(err)
	}
	return h.exec(s)
}

func (h *connHost) clean(t *testing.T, out string) {
	t.Helper()
	if !strings.Contains(out, "MESH_RESTORE_OK") {
		t.Fatalf("not restored:\n%s", out)
	}
	if h.has("pkg") || h.has("enabled") || h.has("active") || h.has("reg") {
		t.Fatalf("leftovers after restore: pkg=%v enabled=%v active=%v reg=%v\n%s", h.has("pkg"), h.has("enabled"), h.has("active"), h.has("reg"), out)
	}
}

// apt-get unpacks the package and then fails: no created marker, but the
// intent makes the removal purge it.
func TestConnectorPartialAptFailureIsWithdrawn(t *testing.T) {
	h := newConnHost(t)
	h.set("apt", "partial")
	out := h.install()
	if !strings.Contains(out, "MESH_INSTALL_FAIL apt_install") || !strings.Contains(out, "MESH_INTENT package") || strings.Contains(out, "MESH_CREATED package") {
		t.Fatalf("install:\n%s", out)
	}
	if !h.has("pkg") {
		t.Fatal("stub did not leave an unpacked package")
	}
	h.clean(t, h.remove())
}

// systemctl enable --now enables the service and then fails to start it.
func TestConnectorEnableOkStartFailIsWithdrawn(t *testing.T) {
	h := newConnHost(t)
	h.set("pkg", "install ok installed") // package found, not ours
	data, _ := os.ReadFile(filepath.Join(h.st, "warp-cli.src"))
	h.write(filepath.Join(h.bin, "warp-cli"), string(data), 0o755)
	h.set("svc", "startfail")
	out := h.install()
	if !strings.Contains(out, "MESH_INSTALL_FAIL service") || strings.Contains(out, "MESH_CREATED service") {
		t.Fatalf("install:\n%s", out)
	}
	if !h.has("enabled") {
		t.Fatal("stub did not enable")
	}
	out = h.remove()
	if !strings.Contains(out, "MESH_RESTORE_OK") || h.has("enabled") || h.has("active") {
		t.Fatalf("service enabled by this run not disabled:\n%s", out)
	}
	if !h.has("pkg") {
		t.Fatal("a package that existed before the run was removed")
	}
}

// The process dies right after apt-get succeeded, before the marker.
func TestConnectorInterruptedBeforeMarkerIsWithdrawn(t *testing.T) {
	h := newConnHost(t)
	h.set("apt", "die")
	out := h.install()
	if strings.Contains(out, "MESH_CREATED package") || strings.Contains(out, "MESH_INSTALL_OK") {
		t.Fatalf("install was not interrupted:\n%s", out)
	}
	h.clean(t, h.remove())
}

// A marker that cannot be written stops the install before the mutation.
func TestConnectorMarkerWriteFailureStops(t *testing.T) {
	h := newConnHost(t)
	if err := os.MkdirAll(filepath.Join(h.bk, "package.intent"), 0o700); err != nil {
		t.Fatal(err)
	}
	out := h.install()
	if !strings.Contains(out, "MESH_INSTALL_FAIL marker_package") || h.has("pkg") {
		t.Fatalf("install went on without its marker:\n%s", out)
	}
}

// A registration that cannot be deleted keeps the client and its
// dependencies, and a retry stays incomplete until the deletion is
// confirmed, even when the client is gone.
func TestConnectorUnregisterFailureKeepsClient(t *testing.T) {
	h := newConnHost(t)
	out := h.install()
	if !strings.Contains(out, "MESH_INSTALL_OK") || !h.has("reg") {
		t.Fatalf("install:\n%s", out)
	}
	h.set("regdelfail", "1")
	for i := 0; i < 2; i++ {
		out = h.remove()
		if strings.Contains(out, "MESH_RESTORE_OK") || !strings.Contains(out, "MESH_RESTORE_INCOMPLETE registration") {
			t.Fatalf("try %d:\n%s", i, out)
		}
		if !h.has("pkg") || !h.has("active") {
			t.Fatalf("try %d: the client went with the registration still there:\n%s", i, out)
		}
		if _, err := os.Stat(filepath.Join(h.bk, "registration.created")); err != nil {
			t.Fatalf("try %d: registration marker dropped", i)
		}
	}
	// The client disappears (removed by hand): still not proof.
	os.Remove(filepath.Join(h.bin, "warp-cli"))
	out = h.remove()
	if strings.Contains(out, "MESH_RESTORE_OK") || !strings.Contains(out, "MESH_RESTORE_UNVERIFIED registration") {
		t.Fatalf("missing client taken as proof:\n%s", out)
	}
	if _, err := os.Stat(filepath.Join(h.bk, "registration.created")); err != nil {
		t.Fatal("registration marker dropped without a client")
	}
	// Client back, deletion works: now it is restored.
	data, _ := os.ReadFile(filepath.Join(h.st, "warp-cli.src"))
	h.write(filepath.Join(h.bin, "warp-cli"), string(data), 0o755)
	h.set("regdelfail", "")
	h.clean(t, h.remove())
	if _, err := os.Stat(filepath.Join(h.root, "keyrings", "k.gpg")); err != nil {
		t.Fatal("a key that existed before the run was removed")
	}
}

func (h *connHost) dropGpg() { os.Remove(filepath.Join(h.bin, "gpg")) }

func (h *connHost) hasGpg() bool {
	_, err := os.Stat(filepath.Join(h.bin, "gpg"))
	return err == nil
}

// A minimal host without gpg: the preflight only notes it, the install adds
// gnupg before verifying the key, and the removal purges gnupg (and what it
// pulled in) after the cloudflare-warp steps.
func TestConnectorInstallsGnupgWhenMissing(t *testing.T) {
	h := newConnHost(t)
	h.dropGpg()
	ps, err := mesh.ConnectorPreflightScript(run, "", "bookworm")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(ps, "curl gpg") || !strings.Contains(ps, "MESH_INFO gpg_install") {
		t.Fatalf("gpg still a preflight blocker:\n%s", ps)
	}
	out := h.install()
	if !strings.Contains(out, "MESH_INSTALL_OK") || !strings.Contains(out, "MESH_INTENT gnupg") || !strings.Contains(out, "MESH_CREATED gnupg") {
		t.Fatalf("install:\n%s", out)
	}
	if strings.Index(out, "MESH_CREATED gnupg") > strings.Index(out, "MESH_INTENT package") {
		t.Fatalf("gnupg not installed before the key step:\n%s", out)
	}
	if !h.has("gnupg") || !h.hasGpg() {
		t.Fatal("gnupg not installed")
	}
	if c := mesh.ParseCreated(out); len(c) == 0 || c[0] != "gnupg" {
		t.Fatalf("created: %v", c)
	}
	out = h.remove()
	h.clean(t, out)
	if h.has("gnupg") || h.hasGpg() {
		t.Fatalf("gnupg installed by the run not purged:\n%s", out)
	}
	if strings.Index(out, "MESH_REMOVED gnupg") < strings.Index(out, "MESH_REMOVED package") {
		t.Fatalf("gnupg purged before cloudflare-warp:\n%s", out)
	}
	if p := h.read(filepath.Join(h.st, "gnupgpurge")); !strings.Contains(p, "gnupg") || !strings.Contains(p, "dirmngr") || strings.Contains(p, "base-files") {
		t.Fatalf("purge args: %q", p)
	}
}

// A host that already has gpg: gnupg is never installed nor purged.
func TestConnectorLeavesExistingGpg(t *testing.T) {
	h := newConnHost(t)
	out := h.install()
	if !strings.Contains(out, "MESH_INSTALL_OK") || strings.Contains(out, "gnupg") {
		t.Fatalf("install:\n%s", out)
	}
	h.clean(t, h.remove())
	if h.has("gnupgops") || !h.hasGpg() {
		t.Fatal("gnupg touched on a host that had gpg")
	}
}

// gnupg cannot be installed: the install fails with gpg_install before any
// cloudflare-warp change, and the removal leaves nothing behind.
func TestConnectorGnupgInstallFailure(t *testing.T) {
	h := newConnHost(t)
	h.dropGpg()
	os.Remove(filepath.Join(h.root, "keyrings", "k.gpg"))
	os.Remove(filepath.Join(h.root, "sources", "l.list"))
	h.set("gnupgfail", "1")
	out := h.install()
	if !strings.Contains(out, "MESH_INSTALL_FAIL gpg_install") || strings.Contains(out, "MESH_CREATED") || strings.Contains(out, "MESH_INTENT key") {
		t.Fatalf("install:\n%s", out)
	}
	h.clean(t, h.remove())
	if h.has("gnupg") || h.hasGpg() {
		t.Fatal("gnupg left")
	}
	if _, err := os.Stat(h.bk); err == nil {
		t.Fatal("backup dir left")
	}
	for _, p := range []string{filepath.Join(h.root, "keyrings", "k.gpg"), filepath.Join(h.root, "sources", "l.list")} {
		if _, err := os.Stat(p); err == nil {
			t.Fatalf("%s left", p)
		}
	}
}

// Debian 13: the dependencies come from the host's own ("debian") sources,
// cloudflare-warp from the official origin at the official candidate, and
// the removal purges exactly the recorded dependencies, never packages the
// host already had.
func TestConnectorDepsFromHostSources(t *testing.T) {
	h := newConnHost(t)
	h.set("prepkgs", "libnss3-tools\n")
	out := h.install()
	if !strings.Contains(out, "MESH_INSTALL_OK") {
		t.Fatalf("install:\n%s", out)
	}
	if strings.TrimSpace(h.read(filepath.Join(h.st, "ver"))) != "2026.1.2" || strings.TrimSpace(h.read(filepath.Join(h.st, "origin"))) != "official" {
		t.Fatal("cloudflare-warp not the official candidate from the official origin")
	}
	if strings.TrimSpace(h.read(filepath.Join(h.st, "depsrc"))) != "debian" {
		t.Fatal("deps not from the debian source")
	}
	if d := h.read(filepath.Join(h.bk, "package.deps")); d != "libayatana-appindicator3-1\nlibwebkit2gtk-4.1-0\n" {
		t.Fatalf("package.deps = %q", d)
	}
	args := h.read(filepath.Join(h.st, "aptargs"))
	var inst string
	for _, l := range strings.Split(args, "\n") {
		if strings.Contains(l, " install ") {
			inst = l
		}
	}
	if strings.Contains(inst, "sourceparts=-") || !strings.Contains(inst, "Dir::Etc::preferences=") || !strings.Contains(inst, "--no-install-recommends") || !strings.Contains(inst, "cloudflare-warp=2026.1.2") {
		t.Fatalf("install args: %q", inst)
	}
	out = h.remove()
	h.clean(t, out)
	if h.read(filepath.Join(h.st, "deps")) != "" {
		t.Fatalf("recorded deps not purged:\n%s", out)
	}
	if !strings.Contains(h.read(filepath.Join(h.st, "prepkgs")), "libnss3-tools") {
		t.Fatal("a pre-existing package was purged")
	}
	p := h.read(filepath.Join(h.st, "purgeargs"))
	if strings.Contains(p, "libnss3-tools") || strings.Contains(p, "base-files") || strings.Contains(args+p, "autoremove") {
		t.Fatalf("purge args: %q", p)
	}
}

// A higher cloudflare-warp from another source is still not installed, and
// an installed version whose origin is not official fails the install.
func TestConnectorPinRefusesOtherOrigin(t *testing.T) {
	h := newConnHost(t)
	h.set("other", "1")
	out := h.install()
	if !strings.Contains(out, "MESH_INSTALL_OK") || strings.TrimSpace(h.read(filepath.Join(h.st, "ver"))) != "2026.1.2" || strings.TrimSpace(h.read(filepath.Join(h.st, "origin"))) != "official" {
		t.Fatalf("pin not effective:\n%s", out)
	}
	h.clean(t, h.remove())

	h2 := newConnHost(t)
	h2.set("forceorigin", "evil")
	out = h2.install()
	if !strings.Contains(out, "MESH_INSTALL_FAIL apt_install_origin") || strings.Contains(out, "MESH_CREATED package") {
		t.Fatalf("non-official origin accepted:\n%s", out)
	}
	h2.clean(t, h2.remove())
	if h2.read(filepath.Join(h2.st, "deps")) != "" {
		t.Fatal("deps of the failed install not purged (from the snapshot)")
	}
}
