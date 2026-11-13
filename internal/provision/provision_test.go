package provision

import (
	"encoding/base64"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/radowitz/meridian/internal/compile"
	"github.com/radowitz/meridian/internal/defaults"
	"github.com/radowitz/meridian/internal/preflight"
)

func TestKeypairShape(t *testing.T) {
	kp, err := GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	raw, err := base64.StdEncoding.DecodeString(kp.Private)
	if err != nil || len(raw) != 32 {
		t.Fatalf("private key %q", kp.Private)
	}
	pub, err := base64.StdEncoding.DecodeString(kp.Public)
	if err != nil || len(pub) != 32 {
		t.Fatalf("public key %q", kp.Public)
	}
	if kp.Private == kp.Public {
		t.Fatal("keys must differ")
	}
}

func TestProvisionScript(t *testing.T) {
	b, err := compile.Compile(defaults.Example())
	if err != nil {
		t.Fatal(err)
	}
	files := FilesFor(b.Files, "tw")
	script := Script("台湾出口", files)
	if strings.Contains(script, "flush ruleset") {
		t.Fatal("provision must not flush nftables")
	}
	if !strings.Contains(script, "wg syncconf") && !strings.Contains(script, "meridian-up.sh") {
		t.Fatal("NAT node updates must go through meridian-up (syncconf)")
	}
	if !strings.Contains(script, "MERIDIAN_PROVISION_OK") {
		t.Fatal("missing marker")
	}
	if strings.Contains(script, "cloudflare/mesh") {
		t.Fatal("home provision must not install mesh")
	}
	kp, err := GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	injected, err := InjectPrivate(files, kp.Private)
	if err != nil {
		t.Fatal(err)
	}
	shown := Redact(Script("台湾出口", injected), kp.Private)
	if strings.Contains(shown, kp.Private) {
		t.Fatal("redaction leaked the private key")
	}
}

func TestProvisionScriptInjectionAndGuards(t *testing.T) {
	b, err := compile.Compile(defaults.Example())
	if err != nil {
		t.Fatal(err)
	}
	files := FilesFor(b.Files, "tw")
	if _, err := InjectPrivate(files, ""); err == nil {
		t.Fatal("injecting an empty key must fail")
	}
	if _, err := InjectPrivate(files, "bad\nPostUp = id"); err == nil {
		t.Fatal("injecting a malformed key must fail")
	}

	preview := Script("台湾出口", files)
	guard := strings.Index(preview, "exit 1\n")
	firstWrite := strings.Index(preview, "cat > ")
	if guard < 0 || firstWrite < 0 || guard > firstWrite {
		t.Fatal("a preview with placeholders must refuse to run before writing files")
	}

	kp, err := GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	injected, err := InjectPrivate(files, kp.Private)
	if err != nil {
		t.Fatal(err)
	}
	script := Script("台湾出口", injected)
	if strings.Contains(script, PrivatePlaceholder) {
		t.Fatal("injected script still has the placeholder")
	}
	if !strings.Contains(script, "PrivateKey = "+kp.Private) {
		t.Fatal("key not injected")
	}
	for _, line := range strings.Split(script, "\n") {
		if strings.HasPrefix(line, "mv -f") && strings.Contains(line, "/etc/wireguard/") {
			continue
		}
		if strings.HasPrefix(line, "chmod 644") && strings.Contains(line, "wireguard") {
			t.Fatalf("WireGuard config world-readable: %s", line)
		}
	}
	if !strings.Contains(script, "install -d -m 700 '/etc/wireguard'") || !strings.Contains(script, "chmod 600 \"$tmp\"") {
		t.Fatal("WireGuard configs must be written 0600 in a 0700 dir")
	}
	// Exit nodes get a resolver install before any write and a start check after up.
	install := strings.Index(script, "apt-get install -y -o Dpkg::Options::=--force-confold smartdns")
	up := strings.Index(script, "/usr/local/sbin/meridian-up.sh\n")
	active := strings.Index(script, "MERIDIAN_SMARTDNS_ACTIVE")
	if install < 0 || install > strings.Index(script, "cat > ") || active < up {
		t.Fatal("exit provision must install SmartDNS before writing and verify it after meridian-up")
	}
	cmd := exec.Command("bash", "-n")
	cmd.Stdin = strings.NewReader(script)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("bash -n: %v\n%s", err, out)
	}
}

func TestResolveNodeKey(t *testing.T) {
	// First install: no keys, generate.
	topo := defaults.Example()
	key, changed, err := ResolveNodeKey(&topo, "gw", KeyGenerateIfMissing)
	if err != nil || !changed || key == "" {
		t.Fatalf("first install: key=%v changed=%v err=%v", key != "", changed, err)
	}
	gw, _ := topo.NodeByID("gw")
	if gw.PrivateKey != key {
		t.Fatal("generated key not stored on the node")
	}
	if pub, _ := PublicFromPrivate(key); pub != gw.PublicKey {
		t.Fatal("stored public key does not match")
	}
	// Database already has the key: reuse, no change.
	again, changed, err := ResolveNodeKey(&topo, "gw", KeyGenerateIfMissing)
	if err != nil || changed || again != key {
		t.Fatal("stored key was not reused")
	}
	reuse, changed, err := ResolveNodeKey(&topo, "gw", KeyReuse)
	if err != nil || changed || reuse != key {
		t.Fatal("generate_keys=false did not reuse the stored key")
	}
	// Rotate always makes a new one.
	rot, changed, err := ResolveNodeKey(&topo, "gw", KeyRotate)
	if err != nil || !changed || rot == key {
		t.Fatal("rotate did not generate a new key")
	}
	// Reuse with nothing stored fails without inventing a key.
	if _, _, err := ResolveNodeKey(&topo, "tw", KeyReuse); err == nil {
		t.Fatal("reuse without a stored key must fail")
	}
	if tw, _ := topo.NodeByID("tw"); tw.PrivateKey != "" {
		t.Fatal("failed reuse stored a key")
	}
	// Public key only: the private half is elsewhere, do not replace it.
	for i := range topo.Nodes {
		if topo.Nodes[i].ID == "tw" {
			topo.Nodes[i].PublicKey = gw.PublicKey
		}
	}
	if _, _, err := ResolveNodeKey(&topo, "tw", KeyGenerateIfMissing); err == nil {
		t.Fatal("public-only node must not get a fresh key silently")
	}
	// Mismatched pair and malformed keys fail, and never echo the key.
	other, _ := GenerateKeypair()
	for i := range topo.Nodes {
		if topo.Nodes[i].ID == "tw" {
			topo.Nodes[i].PrivateKey = other.Private
		}
	}
	if _, _, err := ResolveNodeKey(&topo, "tw", KeyReuse); err == nil || strings.Contains(err.Error(), other.Private) {
		t.Fatalf("mismatched pair: %v", err)
	}
	for i := range topo.Nodes {
		if topo.Nodes[i].ID == "tw" {
			topo.Nodes[i].PrivateKey = "garbage-key"
		}
	}
	if _, _, err := ResolveNodeKey(&topo, "tw", KeyReuse); err == nil || strings.Contains(err.Error(), "garbage-key") {
		t.Fatalf("malformed key: %v", err)
	}
}

func TestProvisionDoesNotExecuteFileBody(t *testing.T) {
	body := "config line\nMERIDIAN_EOF\necho INJECTED\n"
	script := Script("name\nrm -rf /\n", map[string]string{
		"/etc/sysctl.d/99-meridian.conf": body,
		"/etc/cron.d/evil":               "pwn",
		"/tmp/../etc/cron.d/evil":        "pwn",
	})
	if strings.Contains(script, "\nrm -rf /\n") {
		t.Fatal("node name broke out of the comment")
	}
	if strings.Contains(script, "cat > '/etc/cron.d/evil'") || strings.Contains(script, "cat > '/etc/cron.d/") {
		t.Fatal("provision wrote a cron file")
	}
	if !strings.Contains(script, "MERIDIAN_EOF_") {
		t.Fatal("default heredoc delimiter was not rotated")
	}
	cmd := exec.Command("bash", "-n")
	cmd.Stdin = strings.NewReader(script)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("bash -n: %v\n%s", err, out)
	}
}

// SSH provisioning never carries credential-store secrets: a config with a
// remote-access placeholder is refused instead of being shipped.
func TestInjectPrivateRefusesSecretPlaceholders(t *testing.T) {
	kp, err := GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	files := map[string]string{"/etc/wireguard/mra.conf": "[Interface]\nPrivateKey = __MERIDIAN_SECRET_ra-key-x__\n"}
	if _, err := InjectPrivate(files, kp.Private); err == nil {
		t.Fatal("a secret placeholder must not reach a provisioned host")
	}
}

// ------------------------------------------------- script in a sandbox ---

// sandbox runs a provision script with every absolute host path moved
// under a temporary root and stub commands for everything that would touch
// the real system (ip, nft, systemctl, wg, wg-quick, sysctl, apt-get, id,
// docker). It exercises the guard, the journal, compensation and the
// manifest without root or Linux. Stubs log their arguments to calls.log;
// FAIL_<NAME>=1 makes a stub fail, IP_LINKS lists interfaces "ip link
// show" reports.
type sandbox struct {
	t    *testing.T
	root string
	bin  string
}

func newSandbox(t *testing.T) *sandbox {
	t.Helper()
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("no bash")
	}
	sb := &sandbox{t: t, root: t.TempDir(), bin: t.TempDir()}
	for _, d := range []string{"etc", "var/lib", "usr/local/sbin", "usr/sbin", "run/systemd/system", "proc/sys/net/ipv4/conf/all", "proc/sys/net/ipv6/conf/all"} {
		if err := os.MkdirAll(filepath.Join(sb.root, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	for f, v := range map[string]string{
		"proc/sys/net/ipv4/ip_forward":              "0\n",
		"proc/sys/net/ipv6/conf/all/forwarding":     "0\n",
		"proc/sys/net/ipv4/conf/all/rp_filter":      "0\n",
		"proc/sys/net/ipv4/conf/all/send_redirects": "1\n",
	} {
		if err := os.WriteFile(filepath.Join(sb.root, f), []byte(v), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	stub := func(name, body string) {
		script := "#!/bin/bash\necho \"" + name + " $*\" >> \"$SANDBOX/calls.log\"\n" + body + "\n"
		if err := os.WriteFile(filepath.Join(sb.bin, name), []byte(script), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	failable := `v=FAIL_$(basename "$0" | tr 'a-z-' 'A-Z_'); if [ "${!v}" = 1 ]; then exit 1; fi; exit 0`
	stub("id", `echo 0`)
	// Interfaces exist while $SANDBOX/link-<name> exists: wg-quick up
	// creates the marker, ip link del removes it (unless FAIL_IPDEL=1).
	stub("ip", `case "$*" in
  "link show "*) [ -f "$SANDBOX/link-$3" ] && exit 0; exit 1 ;;
  "-o link show") echo "1: lo: <UP>"; echo "2: eth0: <UP>"; for f in "$SANDBOX"/link-*; do [ -f "$f" ] && echo "9: ${f##*/link-}: <UP>"; done ;;
  "link del "*) [ "$FAIL_IPDEL" = 1 ] && exit 1; rm -f "$SANDBOX/link-$3" ;;
esac
exit 0`)
	stub("wg-quick", `if [ "$1" = up ]; then n=$(basename "$2" .conf); touch "$SANDBOX/link-$n"; fi; exit 0`)
	// nft tables exist while $SANDBOX/nft-<name> exists.
	stub("nft", `case "$1" in
  -c) exit 0 ;;
  -f) for t in $(grep -oE '^table inet [a-z_]+ [{]' "$2" | awk '{print $3}'); do touch "$SANDBOX/nft-$t"; done; exit 0 ;;
  list) if [ "$2" = tables ]; then for f in "$SANDBOX"/nft-*; do [ -f "$f" ] && echo "table inet ${f##*/nft-}"; done; exit 0; fi
        [ -f "$SANDBOX/nft-$4" ] && exit 0; exit 1 ;;
  delete) rm -f "$SANDBOX/nft-$4"; exit 0 ;;
esac
exit 0`)
	for _, n := range []string{"systemctl", "wg", "sysctl", "apt-get", "docker", "smartdns"} {
		stub(n, failable)
	}
	// GNU tools the script relies on, for BSD userlands.
	if out, err := exec.Command("sed", "--version").CombinedOutput(); err != nil || !strings.Contains(string(out), "GNU") {
		os.WriteFile(filepath.Join(sb.bin, "sed"), []byte("#!/bin/bash\nif [ \"$1\" = -i ]; then shift; exec /usr/bin/sed -i '' \"$@\"; fi\nexec /usr/bin/sed \"$@\"\n"), 0o755)
	}
	if _, err := exec.LookPath("tac"); err != nil {
		os.WriteFile(filepath.Join(sb.bin, "tac"), []byte("#!/bin/bash\nexec tail -r \"$@\"\n"), 0o755)
	}
	if _, err := exec.LookPath("sha256sum"); err != nil {
		os.WriteFile(filepath.Join(sb.bin, "sha256sum"), []byte("#!/bin/bash\n[ \"$1\" = -- ] && shift\nexec shasum -a 256 \"$@\"\n"), 0o755)
	}
	return sb
}

// rooted moves the script's host paths under the sandbox root.
func (sb *sandbox) rooted(script string) string {
	r := strings.NewReplacer(
		"/etc/", sb.root+"/etc/",
		"/var/lib/meridian", sb.root+"/var/lib/meridian",
		"/usr/local/sbin/", sb.root+"/usr/local/sbin/",
		"/usr/sbin/policy-rc.d", sb.root+"/usr/sbin/policy-rc.d",
		"/proc/sys/", sb.root+"/proc/sys/",
		"/run/systemd/system", sb.root+"/run/systemd/system",
	)
	return r.Replace(script)
}

func (sb *sandbox) run(script string, env ...string) (string, int) {
	sb.t.Helper()
	cmd := exec.Command("bash", "-s")
	cmd.Stdin = strings.NewReader(sb.rooted(script))
	cmd.Env = append([]string{"PATH=" + sb.bin + ":/usr/bin:/bin:/usr/sbin:/sbin", "SANDBOX=" + sb.root, "LC_ALL=C"}, env...)
	out, err := cmd.CombinedOutput()
	code := 0
	if ee, ok := err.(*exec.ExitError); ok {
		code = ee.ExitCode()
	} else if err != nil {
		sb.t.Fatal(err)
	}
	return string(out), code
}

func (sb *sandbox) exists(p string) bool {
	_, err := os.Lstat(filepath.Join(sb.root, p))
	return err == nil
}

func (sb *sandbox) read(p string) string {
	b, _ := os.ReadFile(filepath.Join(sb.root, p))
	return string(b)
}

func testScript(t *testing.T, node, expect string) (string, map[string]string) {
	t.Helper()
	b, err := compile.Compile(defaults.Example())
	if err != nil {
		t.Fatal(err)
	}
	files := FilesFor(b.Files, node)
	kp, _ := GenerateKeypair()
	injected, err := InjectPrivate(files, kp.Private)
	if err != nil {
		t.Fatal(err)
	}
	o := Options{NodeID: node, Deployment: "dep-1", ServerID: "srv-1", Bundle: preflight.BundleDigest(files), Run: "run-1", Expect: expect}
	if err := CheckOptions(o); err != nil {
		t.Fatal(err)
	}
	return ScriptWith("test", injected, o), injected
}

func TestProvisionScriptCommitsManifest(t *testing.T) {
	sb := newSandbox(t)
	script, files := testScript(t, "tw", "none")
	out, code := sb.run(script)
	if code != 0 || !strings.Contains(out, "MERIDIAN_PROVISION_OK") {
		t.Fatalf("exit %d\n%s", code, out)
	}
	for p := range files {
		if !sb.exists(p) {
			t.Fatalf("%s not written", p)
		}
	}
	man := strings.ReplaceAll(sb.read("/var/lib/meridian/node/manifest"), sb.root, "")
	for _, want := range []string{"meridian-node-manifest 1", "node tw", "deployment dep-1", "server srv-1", "iface m14", "nft inet meridian", "table 150", "unit meridian-unlock.timer", "file /etc/wireguard/m14.conf "} {
		if !strings.Contains(man, want) {
			t.Fatalf("manifest lacks %q:\n%s", want, man)
		}
	}
	if j := sb.read("/var/lib/meridian/node/journal"); !strings.Contains(j, "state done") {
		t.Fatalf("journal %s", j)
	}
	if sb.exists("/var/lib/meridian/node/run-run-1") {
		t.Fatal("work directory left behind")
	}
	// The manifest is what the next preflight reads.
	r := preflight.Parse(preflight.Header + "\nmanifest-begin\n" + prefixLines("manifest ", man) + "manifest-end\n" + preflight.EndMarker + "\n")
	if r.Manifest == nil || r.Manifest.Node != "tw" || r.Manifest.Deployment != "dep-1" || len(r.Manifest.Files) != len(files) {
		t.Fatalf("manifest round trip %+v", r.Manifest)
	}

	// A second first-install script is refused: the manifest is there now.
	out, code = sb.run(script)
	if code != 3 || !strings.Contains(out, "MERIDIAN_REFUSED manifest_appeared") {
		t.Fatalf("second first install: %d %s", code, out)
	}
	// An update for the same node passes the guard; for another node it is refused.
	upd, _ := testScript(t, "tw", "same")
	if out, code = sb.run(upd); code != 0 {
		t.Fatalf("update: %d %s", code, out)
	}
	other := strings.Replace(upd, "M_NODE='tw'", "M_NODE='jp'", 1)
	if out, code = sb.run(other); code != 3 || !strings.Contains(out, "MERIDIAN_REFUSED manifest_changed") {
		t.Fatalf("other node: %d %s", code, out)
	}
}

func prefixLines(prefix, s string) string {
	var b strings.Builder
	for _, l := range strings.Split(strings.TrimRight(s, "\n"), "\n") {
		b.WriteString(prefix + l + "\n")
	}
	return b.String()
}

// A first install that fails after writing files is compensated: created
// files and directories removed, a replaced file restored, interfaces
// created by the run deleted, sysctls restored, packages kept and named,
// the journal says "compensated" and the script exits non-zero.
func TestProvisionScriptCompensatesFirstInstall(t *testing.T) {
	sb := newSandbox(t)
	script, files := testScript(t, "tw", "none")
	// A file at one of the paths before the run (e.g. an operator's sysctl
	// file accepted by the preflight) must come back unchanged.
	os.MkdirAll(filepath.Join(sb.root, "etc/sysctl.d"), 0o755)
	os.WriteFile(filepath.Join(sb.root, "etc/sysctl.d/99-meridian.conf"), []byte("# before\n"), 0o644)
	// wg missing → wireguard-tools gets "installed"; systemctl enable fails
	// in meridian-up.sh after the interface came up.
	os.Remove(filepath.Join(sb.bin, "wg"))
	realWG := false
	for _, d := range []string{"/usr/bin", "/bin", "/usr/sbin", "/sbin"} {
		if _, err := os.Stat(filepath.Join(d, "wg")); err == nil {
			realWG = true
		}
	}
	out, code := sb.run(script, "FAIL_SYSTEMCTL=1")
	if code == 0 || strings.Contains(out, "MERIDIAN_PROVISION_OK") || !strings.Contains(out, "MERIDIAN_COMPENSATED") {
		t.Fatalf("exit %d\n%s", code, out)
	}
	for p := range files {
		if p == "/etc/sysctl.d/99-meridian.conf" {
			continue
		}
		if sb.exists(p) {
			t.Fatalf("%s left behind", p)
		}
	}
	if got := sb.read("/etc/sysctl.d/99-meridian.conf"); got != "# before\n" {
		t.Fatalf("replaced file not restored: %q", got)
	}
	for _, d := range []string{"/etc/wireguard", "/etc/meridian", "/etc/smartdns"} {
		if sb.exists(d) {
			t.Fatalf("directory %s created by the run left behind", d)
		}
	}
	if sb.exists("/var/lib/meridian/node/manifest") {
		t.Fatal("failed run wrote a manifest")
	}
	j := strings.ReplaceAll(sb.read("/var/lib/meridian/node/journal"), sb.root, "")
	if !strings.Contains(j, "state compensated") || (!realWG && !strings.Contains(j, "leftover package wireguard-tools (kept on purpose)")) {
		t.Fatalf("journal %s", j)
	}
	calls := sb.read("/calls.log")
	if !strings.Contains(calls, "wg-quick up") || !strings.Contains(calls, "ip link del m14") || !strings.Contains(calls, "nft delete table inet meridian") ||
		!strings.Contains(calls, "systemctl disable meridian-unlock.timer") {
		t.Fatalf("interface / table / unit not compensated:\n%s", calls)
	}
	if !realWG && !strings.Contains(out, "MERIDIAN_KEPT package") {
		t.Fatalf("installed packages not named:\n%s", out)
	}
	// The journal is what the next preflight shows.
	r := preflight.Parse(preflight.Header + "\njournal-begin\n" + prefixLines("journal ", j) + "journal-end\n" + preflight.EndMarker + "\n")
	if r.Journal == nil || r.Journal.State != "compensated" || (!realWG && len(r.Journal.Leftovers) == 0) {
		t.Fatalf("journal round trip %+v", r.Journal)
	}
	if sysctl := sb.read("/proc/sys/net/ipv4/ip_forward"); strings.TrimSpace(sysctl) != "0" {
		t.Fatalf("ip_forward not restored: %q", sysctl)
	}
}

// What cannot be undone is named and the journal is "incomplete": the
// next preflight blocks until someone looks.
func TestProvisionScriptReportsLeftovers(t *testing.T) {
	sb := newSandbox(t)
	script, _ := testScript(t, "tw", "none")
	// The interface comes up during the run and cannot be deleted.
	sys := "#!/bin/bash\necho \"systemctl $*\" >> \"$SANDBOX/calls.log\"\ncase \"$*\" in \"enable --now\"*) exit 1;; esac\nexit 0\n"
	os.WriteFile(filepath.Join(sb.bin, "systemctl"), []byte(sys), 0o755)
	out, code := sb.run(script, "FAIL_IPDEL=1")
	if code == 0 || !strings.Contains(out, "MERIDIAN_LEFTOVER interface m14") || !strings.Contains(out, "MERIDIAN_COMPENSATION_INCOMPLETE") {
		t.Fatalf("exit %d\n%s", code, out)
	}
	j := sb.read("/var/lib/meridian/node/journal")
	if !strings.Contains(j, "state incomplete") || !strings.Contains(j, "leftover interface m14") {
		t.Fatalf("journal %s", j)
	}
	// Next run is refused by the script itself as well.
	out, code = sb.run(script)
	if code != 3 || !strings.Contains(out, "MERIDIAN_REFUSED previous_run_incomplete") {
		t.Fatalf("after incomplete: %d %s", code, out)
	}
}

func TestProvisionScriptUnboundRefuses(t *testing.T) {
	b, _ := compile.Compile(defaults.Example())
	files := FilesFor(b.Files, "tw")
	kp, _ := GenerateKeypair()
	injected, _ := InjectPrivate(files, kp.Private)
	s := Script("x", injected)
	guard := strings.Index(s, "provision script without a target identity")
	if guard < 0 || guard > strings.Index(s, "cat > ") {
		t.Fatal("a script without options must refuse before writing")
	}
	for _, bad := range []Options{
		{NodeID: "tw'; id; '", Deployment: "d", ServerID: "s", Run: "r", Expect: "none", Bundle: strings.Repeat("a", 64)},
		{NodeID: "tw", Deployment: "d", ServerID: "s", Run: "r", Expect: "maybe", Bundle: strings.Repeat("a", 64)},
		{NodeID: "tw", Deployment: "d", ServerID: "s", Run: "r", Expect: "none", Bundle: "zz"},
	} {
		if CheckOptions(bad) == nil {
			t.Fatalf("accepted %+v", bad)
		}
		if s := ScriptWith("x", injected, bad); !strings.Contains(s, "without a target identity") || strings.Contains(s, "; id;") {
			t.Fatalf("bad options rendered: %+v", bad)
		}
	}
	// shellcheck, when installed, on a real script.
	script, _ := testScript(t, "hk-hub", "none")
	if path, err := exec.LookPath("shellcheck"); err == nil {
		cmd := exec.Command(path, "-s", "bash", "-S", "error", "-")
		cmd.Stdin = strings.NewReader(script)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("shellcheck: %v\n%s", err, out)
		}
	}
	cmd := exec.Command("bash", "-n")
	cmd.Stdin = strings.NewReader(script)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("bash -n: %v\n%s", err, out)
	}
}
