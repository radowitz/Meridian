// Package deployscripts tests deploy/debian/{install,upgrade,rollback,api}.sh
// offline: every external command (docker, systemctl, curl) is a stub that
// records its arguments and keeps a tiny fake state in a temp directory. No
// real Docker, network or root is used.
package deployscripts

import (
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"
)

const fakeDocker = `#!/bin/bash
S="$FAKE_STATE"
echo "docker $*" >> "$S/log"
san() { echo "$1" | tr '/:@' '___'; }
img_id() { local f="$S/images/$(san "$1")"; if [[ -f "$f" ]]; then cat "$f"; return 0; fi
  grep -lx -- "$1" "$S"/images/* >/dev/null 2>&1 && { echo "$1"; return 0; }; return 1; }
cur() { cat "$S/cur_image" 2>/dev/null; }
case "$1" in
  info) exit 0 ;;
  compose)
    shift
    [[ "$1" == version ]] && exit 0
    shift 2 # -f file
    if [[ "$1" == --profile ]]; then shift 2; fi
    if [[ "$*" == *smartdns* ]]; then
      case "$1" in
        create) echo created > "$S/smartdns" ;;
        up) [[ -f "$S/smartdns_broken" ]] && echo exited > "$S/smartdns" || echo running > "$S/smartdns" ;;
      esac
      exit 0
    fi
    case "$1" in
      ps) [[ -f "$S/cur_image" ]] && echo cid1; exit 0 ;;
      stop) echo exited > "$S/state" ;;
      start) echo running > "$S/state" ;;
      up)
        ref="$(sed -n 's/^MERIDIAN_IMAGE=//p' "$MERIDIAN_ENV_FILE" | tail -n1)"
        echo "$ref" > "$S/cur_image"; echo running > "$S/state"
        if grep -qx -- "$ref" "$S/bad_images" 2>/dev/null; then echo migrated-by-bad > "$S/vol_data"; fi ;;
      build) mkdir -p "$S/images"; echo id-local > "$S/images/$(san meridian:local)" ;;
    esac ;;
  inspect)
    if [[ "$*" == *meridian-smartdns* ]]; then [[ -f "$S/smartdns" ]] || exit 1; cat "$S/smartdns"; exit 0; fi
    fmt="$3"
    case "$fmt" in
      *'.Config.Env'*) [[ -f "$S/bind_env" ]] && echo "MERIDIAN_BIND=$(cat "$S/bind_env")"; echo "PATH=/usr/bin" ;;
      *'.State.Status'*) cat "$S/state" ;;
      *'.Mounts'*) printf 'deploy_meridian-data /var/lib/meridian\ndeploy_meridian-secrets /var/lib/meridian-secrets\n' ;;
      *'.Config.Image'*) cur ;;
      *'.Image'*) img_id "$(cur)" ;;
    esac ;;
  image)
    case "$2" in
      inspect)
        if [[ "$3" == --format ]]; then ref="$5"; fmt="$4"; else ref="$3"; fmt=""; fi
        id="$(img_id "$ref")" || exit 1
        case "$fmt" in *Architecture*) cat "$S/arch" 2>/dev/null || echo amd64 ;; *'.Id'*) echo "$id" ;; esac ;;
      rm) rm -f "$S/images/$(san "$3")" ;;
    esac ;;
  pull)
    grep -qx -- "$2" "$S/pullable" 2>/dev/null || { echo "pull denied" >&2; exit 1; }
    mkdir -p "$S/images"; echo "id-$(san "$2")" > "$S/images/$(san "$2")" ;;
  tag) id="$(img_id "$2")" || exit 1; echo "$id" > "$S/images/$(san "$3")" ;;
  load) ref="$(cat "$3")"; mkdir -p "$S/images"; echo "id-$(san "$ref")" > "$S/images/$(san "$ref")"; echo "Loaded image: $ref" ;;
  create) echo "$2" > "$S/created"; echo tmpc ;;
  cp) echo "bin-of-$(cat "$S/created")" > "$3" ;;
  rm) exit 0 ;;
  start)
    if [[ "$2" == meridian-smartdns ]]; then
      [[ -f "$S/smartdns_broken" ]] && echo exited > "$S/smartdns" || echo running > "$S/smartdns"
    fi ;;
  exec)
    if [[ "$2" == -i ]]; then
      # api.sh: run the in-container shell for real (curl is the stub).
      shift 2; while [[ "$1" == -e ]]; do export "$2"; shift 2; done; shift
      "$@"; exit $?
    fi
    old=0; grep -qx -- "$(cur)" "$S/no_panel_bind" 2>/dev/null && old=1
    if [[ "$3" == grep ]]; then exit "$old"; fi
    if [[ "$*" == *"panel-bind"* ]]; then
      # An image without the subcommand would start a second, old panel.
      if [[ "$old" == 1 ]]; then echo "old-panel-started" >> "$S/log"; sleep 30; exit 0; fi
      cat "$S/bind" 2>/dev/null || echo 127.0.0.1:8787
    fi ;;
  run)
    shift; vol=""; bdir=""
    while [[ $# -gt 0 ]]; do
      case "$1" in
        -v) case "$2" in *:/v|*:/v:ro) vol="${2%%:*}" ;; *:/b|*:/b:ro) bdir="${2%%:*}" ;; esac; shift 2 ;;
        -czf) name="$(basename "$2")"; kind="${name%%.*}"; cat "$S/vol_$kind" > "$bdir/$name"; exit 0 ;;
        -c)
          # restore_backup: stage (tar into .meridian-restore), unstage, swap.
          script="$2"; kind="$4"
          case "$script" in
            *'tar -xzf'*) [[ -f "$S/tar_fail_$kind" ]] && exit 1; cat "$bdir/$kind.tar.gz" > "$S/stage_$kind" ;;
            *meridian-old*) mv "$S/stage_$kind" "$S/vol_$kind" ;;
            *) rm -f "$S/stage_$kind" ;;
          esac
          exit 0 ;;
        *) shift ;;
      esac
    done ;;
esac
exit 0
`

const fakeCurl = `#!/bin/bash
echo "curl $*" >> "$FAKE_STATE/log"
prev=""
for a in "$@"; do
  if [[ "$prev" == -K ]]; then
    ls -l "$a" | cut -c1-10 > "$FAKE_STATE/curlcfg_mode"; cat "$a" > "$FAKE_STATE/curlcfg"; echo "$a" > "$FAKE_STATE/curlcfg_path"
  fi
  prev="$a"
done
grep -qx -- "$(cat "$FAKE_STATE/cur_image")" "$FAKE_STATE/bad_images" 2>/dev/null && exit 22
exit 0
`

const fakeOK = `#!/bin/bash
echo "$(basename "$0") $*" >> "$FAKE_STATE/log"
exit 0
`

// fakeSystemctl refuses to (re)start meridian-host when the host binary is
// not executable, like systemd would (exec failure), and is-active then
// reports it inactive.
const fakeSystemctl = `#!/bin/bash
echo "systemctl $*" >> "$FAKE_STATE/log"
case "$1 $2" in
  "restart meridian-host.service"|"start meridian-host.service")
    if [[ -x "$MERIDIAN_HOST_BIN" ]]; then echo active > "$FAKE_STATE/host_unit"; exit 0; fi
    echo failed > "$FAKE_STATE/host_unit"; exit 1 ;;
  "cat smartdns.service") [[ -f "$FAKE_STATE/host_smartdns" ]]; exit $? ;;
  "list-unit-files meridian-host.service") [[ -f "$FAKE_STATE/systemctl_broken" ]] && exit 1; exit 0 ;;
  "is-active --quiet")
    if [[ "$3" == meridian-host.service ]]; then
      [[ "$(cat "$FAKE_STATE/host_unit" 2>/dev/null || echo active)" == active ]]; exit $?
    fi ;;
esac
exit 0
`

type env struct {
	t     *testing.T
	repo  string // copy of deploy/ under a temp "repo"
	state string
	bin   string
	sock  string
	extra []string
}

func setup(t *testing.T) *env {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("bash scripts")
	}
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("no bash")
	}
	tmp := t.TempDir()
	e := &env{t: t, repo: filepath.Join(tmp, "repo"), state: filepath.Join(tmp, "state"), bin: filepath.Join(tmp, "bin")}
	for _, d := range []string{filepath.Join(e.repo, "deploy", "debian"), e.state, e.bin, filepath.Join(e.state, "images"), filepath.Join(tmp, "hostbin")} {
		must(t, os.MkdirAll(d, 0o755))
	}
	src := filepath.Join("..", "..", "deploy")
	for _, f := range []string{"debian/lib.sh", "debian/install.sh", "debian/upgrade.sh", "debian/rollback.sh", "debian/api.sh", "docker-compose.yml"} {
		b, err := os.ReadFile(filepath.Join(src, f))
		must(t, err)
		must(t, os.WriteFile(filepath.Join(e.repo, "deploy", f), b, 0o755))
	}
	must(t, os.WriteFile(filepath.Join(e.bin, "docker"), []byte(fakeDocker), 0o755))
	must(t, os.WriteFile(filepath.Join(e.bin, "curl"), []byte(fakeCurl), 0o755))
	must(t, os.WriteFile(filepath.Join(e.bin, "systemctl"), []byte(fakeSystemctl), 0o755))
	// flock(1) is util-linux (absent on macOS): a stub that takes the lock
	// unless the state says another run holds it.
	must(t, os.WriteFile(filepath.Join(e.bin, "flock"), []byte("#!/bin/bash\n[[ ! -f \"$FAKE_STATE/locked\" ]]\n"), 0o755))
	// The host agent's control socket (short path: sun_path limit).
	sd, err := os.MkdirTemp("", "msock")
	must(t, err)
	t.Cleanup(func() { os.RemoveAll(sd) })
	e.sock = filepath.Join(sd, "a.sock")
	l, err := net.Listen("unix", e.sock)
	must(t, err)
	t.Cleanup(func() { l.Close() })
	return e
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func (e *env) envFile() string { return filepath.Join(e.repo, "deploy", ".env") }
func (e *env) backups() string { return filepath.Join(e.state, "..", "backups") }
func (e *env) hostBin() string { return filepath.Join(e.state, "..", "hostbin", "meridian") }
func (e *env) write(name, s string) {
	must(e.t, os.WriteFile(filepath.Join(e.state, name), []byte(s), 0o644))
}
func (e *env) read(path string) string {
	b, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return string(b)
}

// running sets up a deployed panel on image ref (pulled earlier).
func (e *env) running(ref string) {
	e.write("images/"+strings.NewReplacer("/", "_", ":", "_", "@", "_").Replace(ref), "id-"+strings.NewReplacer("/", "_", ":", "_", "@", "_").Replace(ref)+"\n")
	e.write("cur_image", ref+"\n")
	e.write("state", "running\n")
	e.write("vol_data", "data-v1\n")
	e.write("vol_secrets", "secrets-v1\n")
	must(e.t, os.WriteFile(e.envFile(), []byte("MERIDIAN_BIND=192.0.2.1:8787\nMERIDIAN_IMAGE="+ref+"\n"), 0o600))
	must(e.t, os.WriteFile(e.hostBin(), []byte("bin-of-"+ref+"\n"), 0o755))
}

func (e *env) run(script string, args ...string) (string, int) {
	cmd := exec.Command("bash", append([]string{filepath.Join(e.repo, "deploy", "debian", script)}, args...)...)
	cmd.Env = append(os.Environ(),
		"PATH="+e.bin+":"+os.Getenv("PATH"),
		"FAKE_STATE="+e.state,
		"MERIDIAN_TEST_MODE=1",
		"MERIDIAN_ENV_FILE="+e.envFile(),
		"MERIDIAN_BACKUP_DIR="+e.backups(),
		"MERIDIAN_HOST_BIN="+e.hostBin(),
		"MERIDIAN_HOST_SOCKET="+e.sock,
		"MERIDIAN_HOST_SOCKET_WAIT=1",
		"MERIDIAN_LOCK_FILE="+filepath.Join(e.state, "lock"),
		"MERIDIAN_HOST_ARCH=amd64",
		"MERIDIAN_HEALTH_INTERVAL=1",
		"MERIDIAN_HEALTH_TIMEOUT=2",
		"MERIDIAN_IMAGE_REPO=ghcr.io/example/meridian",
	)
	cmd.Env = append(cmd.Env, e.extra...)
	cmd.Stdin = strings.NewReader("")
	out, err := cmd.CombinedOutput()
	code := 0
	if ee, ok := err.(*exec.ExitError); ok {
		code = ee.ExitCode()
	} else if err != nil {
		e.t.Fatal(err)
	}
	return string(out), code
}

func TestInstallArgumentParsing(t *testing.T) {
	e := setup(t)
	out, code := e.run("install.sh", "--print-config")
	if code != 0 || !strings.Contains(out, "image_source=build") || !strings.Contains(out, "image=meridian:local") || !strings.Contains(out, "firewall=1") {
		t.Fatalf("defaults: %d\n%s", code, out)
	}
	out, code = e.run("install.sh", "--print-config", "--version", "v1.2.3", "--lan-addr", "192.0.2.1", "--allow", "10.8.0.0/24", "--allow", "fd00::/64")
	if code != 0 || !strings.Contains(out, "image=ghcr.io/example/meridian:v1.2.3") || !strings.Contains(out, "allow=10.8.0.0/24,fd00::/64") || !strings.Contains(out, "lan_addr=192.0.2.1") {
		t.Fatalf("version: %d\n%s", code, out)
	}
	e.extra = []string{"MERIDIAN_IMAGE_REPO=", "MERIDIAN_IMAGE_OWNER=acme"}
	out, _ = e.run("install.sh", "--print-config", "--version", "1.0.0")
	if !strings.Contains(out, "image=ghcr.io/acme/meridian:1.0.0") {
		t.Fatalf("owner: %s", out)
	}
	e.extra = nil
	for _, bad := range [][]string{
		{"--bogus"},
		{"--lan-addr", "999.1.1.1"},
		{"--lan-addr", "0.0.0.0"},
		{"--version", "latest"},
		{"--version", "v1.0.0", "--build"},
		{"--image", "Bad Image"},
		{"--allow", "10.0.0.1"},
		{"--lan-if", "a;b"},
		{"--version"},
	} {
		if out, code := e.run("install.sh", append([]string{"--print-config"}, bad...)...); code != 2 {
			t.Errorf("%v: want exit 2, got %d\n%s", bad, code, out)
		}
	}
	// A re-run keeps the image deploy/.env names.
	must(t, os.WriteFile(e.envFile(), []byte("MERIDIAN_IMAGE=ghcr.io/example/meridian:v0.9.0\n"), 0o600))
	out, _ = e.run("install.sh", "--print-config")
	if !strings.Contains(out, "image_source=keep") || !strings.Contains(out, "image=ghcr.io/example/meridian:v0.9.0") {
		t.Fatalf("keep: %s", out)
	}
	if out, code := e.run("install.sh", "--help"); code != 0 || !strings.Contains(out, "--lan-addr") {
		t.Fatalf("help: %d %s", code, out)
	}
}

// bashLib runs a snippet with lib.sh sourced.
func (e *env) bashLib(snippet string) (string, int) {
	script := filepath.Join(e.state, "snippet.sh")
	must(e.t, os.WriteFile(script, []byte("set -euo pipefail\n. "+filepath.Join(e.repo, "deploy", "debian", "lib.sh")+"\n"+snippet), 0o755))
	return e.run("../../../state/snippet.sh")
}

// An archive saved with the panel and SmartDNS ("docker save meridian:local
// pymumu/smartdns") may list SmartDNS first; the panel image must still be
// the meridian one, never SmartDNS (it broke a real upgrade).
func TestLoadImageTarPicksPanelImage(t *testing.T) {
	e := setup(t)
	for name, c := range map[string]struct{ loaded, want string }{
		"smartdns first": {"Loaded image: pymumu/smartdns:latest\nLoaded image: meridian:local", "meridian:local"},
		"panel first":    {"Loaded image: meridian:local\nLoaded image: pymumu/smartdns:latest", "meridian:local"},
		"registry ref":   {"Loaded image: pymumu/smartdns:latest\nLoaded image: ghcr.io/example/meridian:v1.0.0", "ghcr.io/example/meridian:v1.0.0"},
		"single other":   {"Loaded image: example/panel:dev", "example/panel:dev"},
		"only smartdns":  {"Loaded image: pymumu/smartdns:latest", "meridian:local"},
	} {
		t.Run(name, func(t *testing.T) {
			snippet := "fake_docker() { printf '%s\\n' \"$LOADED\"; }\nDOCKER=fake_docker\n: > \"$MERIDIAN_ENV_FILE.tar\"\n" +
				"echo \"ref=$(load_image_tar \"$MERIDIAN_ENV_FILE.tar\" 2>/dev/null)\"\n"
			snippet = "LOADED=$'" + strings.ReplaceAll(c.loaded, "\n", "\\n") + "'\n" + snippet
			out, code := e.bashLib(snippet)
			if code != 0 || !strings.Contains(out, "ref="+c.want+"\n") {
				t.Fatalf("%d %q, want ref=%s", code, out, c.want)
			}
		})
	}
}

func TestEnvSetIdempotentAndPrivate(t *testing.T) {
	e := setup(t)
	f := e.envFile()
	must(t, os.WriteFile(f, []byte("# keep me\nOTHER=1\nMERIDIAN_BIND=192.0.2.9:8787\n"), 0o644))
	snippet := `env_set MERIDIAN_BIND 192.0.2.1:8787 "$MERIDIAN_ENV_FILE"; env_set MERIDIAN_IMAGE meridian:local "$MERIDIAN_ENV_FILE"
echo "got=$(env_get MERIDIAN_BIND "$MERIDIAN_ENV_FILE")"`
	if out, code := e.bashLib(snippet); code != 0 || !strings.Contains(out, "got=192.0.2.1:8787") {
		t.Fatalf("%d %s", code, out)
	}
	first := e.read(f)
	if _, code := e.bashLib(snippet); code != 0 {
		t.Fatal("second run")
	}
	if e.read(f) != first {
		t.Fatalf("not idempotent:\n%s\n---\n%s", first, e.read(f))
	}
	if !strings.Contains(first, "# keep me\nOTHER=1\n") || strings.Count(first, "MERIDIAN_BIND=") != 1 {
		t.Fatalf("content: %s", first)
	}
	st, _ := os.Stat(f)
	if st.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v", st.Mode())
	}
}

func TestMgmtFirewallRender(t *testing.T) {
	e := setup(t)
	const call = `render_mgmt_firewall 8787 lan0 192.168.50.0/24,fd00:50::/64,2001:db8:50::/64,fe80::/10 10.8.0.0/24 fd00:8::/64`
	out, code := e.bashLib(call)
	if code != 0 {
		t.Fatal(out)
	}
	for _, want := range []string{
		"table inet meridian_mgmt\ndelete table inet meridian_mgmt\n",
		`tcp dport 8787 iifname "lo" accept`,
		`tcp dport 8787 iifname "lan0" ip saddr @lan4 accept`,
		`tcp dport 8787 iifname "lan0" ip6 saddr @lan6 accept`,
		"tcp dport 8787 ip saddr @allow4 accept",
		"tcp dport 8787 ip6 saddr @allow6 accept",
		"tcp dport 8787 counter drop",
		"ct original proto-dst 8787 counter drop",
		"policy accept",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in\n%s", want, out)
		}
	}
	for _, never := range []string{"flush ruleset", "dport 22", "policy drop", `iifname "lan0" accept`} {
		if strings.Contains(out, never) {
			t.Errorf("must not contain %q", never)
		}
	}
	out2, _ := e.bashLib(call)
	if out != out2 {
		t.Fatal("render not deterministic")
	}
	for _, c := range []struct {
		chain, iif, src string
		want            bool
	}{
		{"input", "lan0", "192.168.50.23", true},     // LAN client
		{"input", "lan0", "203.0.113.7", false},      // port-forwarded from the WAN onto the LAN NIC
		{"input", "eth9", "192.168.50.23", false},    // LAN source on another NIC
		{"input", "lan0", "10.8.0.5", true},          // --allow
		{"input", "wan0", "10.8.0.5", true},          // --allow, any interface
		{"input", "lo", "127.0.0.1", true},           // loopback
		{"input", "mra", "10.77.0.2", true},          // remote-access device
		{"input", "lan0", "fd00:50::9", true},        // IPv6 ULA on the LAN
		{"input", "lan0", "2001:db8:50::9", true},    // IPv6 LAN prefix
		{"input", "lan0", "fe80::1234", true},        // link-local
		{"input", "lan0", "2001:db8:dead::1", false}, // public IPv6 on the LAN NIC
		{"input", "wan0", "fd00:8::3", true},         // --allow IPv6
		{"forward", "lan0", "192.168.50.23", true},   // Docker DNAT, LAN client
		{"forward", "lan0", "203.0.113.7", false},    // Docker DNAT, WAN source
		{"forward", "lan0", "2001:db8:dead::1", false},
	} {
		if got := nftVerdict(t, out, c.chain, c.iif, c.src); got != c.want {
			t.Errorf("%s iif=%s src=%s: accept=%v, want %v", c.chain, c.iif, c.src, got, c.want)
		}
	}
	lo, _ := e.bashLib(`render_mgmt_firewall 8787 "" ""`)
	if strings.Contains(lo, "iifname \"\"") || strings.Contains(lo, "@allow") || strings.Contains(lo, "@lan") || !strings.Contains(lo, "counter drop") {
		t.Fatalf("loopback-only render:\n%s", lo)
	}
	if nftVerdict(t, lo, "input", "eth0", "192.168.1.2") || !nftVerdict(t, lo, "input", "lo", "127.0.0.1") {
		t.Fatal("loopback-only verdicts")
	}
}

// nftVerdict walks one chain of a rendered management firewall for a
// panel-port TCP packet (iif, src) and reports whether it is accepted.
// It knows only the matches render_mgmt_firewall writes.
func nftVerdict(t *testing.T, ruleset, chain, iif, src string) bool {
	t.Helper()
	addr := netip.MustParseAddr(src)
	sets := map[string][]netip.Prefix{}
	setRe := regexp.MustCompile(`(?s)set (\w+) \{.*?elements = \{ ([^}]*) \}`)
	for _, m := range setRe.FindAllStringSubmatch(ruleset, -1) {
		for _, el := range strings.Split(m[2], ",") {
			sets[m[1]] = append(sets[m[1]], netip.MustParsePrefix(strings.TrimSpace(el)))
		}
	}
	i := strings.Index(ruleset, "chain "+chain+" {")
	if i < 0 {
		t.Fatalf("no chain %s", chain)
	}
	body := ruleset[i:]
	body = body[:strings.Index(body, "\n  }")]
	iifRe := regexp.MustCompile(`iifname "([^"]*)"`)
	saddrRe := regexp.MustCompile(`ip(6?) saddr @(\w+)`)
	for _, line := range strings.Split(body, "\n") {
		line = strings.TrimSpace(line)
		if !strings.Contains(line, "8787") || strings.HasPrefix(line, "type ") || strings.HasPrefix(line, "#") {
			continue
		}
		if m := iifRe.FindStringSubmatch(line); m != nil && m[1] != iif {
			continue
		}
		if m := saddrRe.FindStringSubmatch(line); m != nil {
			if (m[1] == "6") != addr.Is6() {
				continue
			}
			hit := false
			for _, p := range sets[m[2]] {
				hit = hit || p.Contains(addr)
			}
			if !hit {
				continue
			}
		}
		switch {
		case strings.Contains(line, " accept"):
			return true
		case strings.Contains(line, " drop"):
			return false
		}
	}
	return true // policy accept
}

func TestLANSources(t *testing.T) {
	e := setup(t)
	out, code := e.bashLib(`ip() {
  case "$*" in
    "-4 route show dev lan0 proto kernel scope link") echo "192.168.50.0/24 proto kernel scope link src 192.168.50.2" ;;
    "-6 route show dev lan0 proto kernel") printf '%s\n' "fd00:50::/64 proto kernel metric 256 pref medium" "fe80::/64 proto kernel metric 256 pref medium" ;;
  esac
}
echo "src=$(lan_sources lan0)"
echo "none=$(lan_sources "")"`)
	if code != 0 || !strings.Contains(out, "src=192.168.50.0/24,fd00:50::/64,fe80::/10\n") || !strings.Contains(out, "none=\n") {
		t.Fatalf("%d %s", code, out)
	}
}

func TestUpgradeSuccess(t *testing.T) {
	e := setup(t)
	e.running("ghcr.io/example/meridian:v1.0.0")
	e.write("pullable", "ghcr.io/example/meridian:v1.1.0\n")
	e.extra = []string{"MERIDIAN_BACKUP_ID=20261118T000001Z"}
	out, code := e.run("upgrade.sh", "v1.1.0")
	if code != 0 {
		t.Fatalf("%d\n%s", code, out)
	}
	if got := e.read(e.envFile()); !strings.Contains(got, "MERIDIAN_IMAGE=ghcr.io/example/meridian:v1.1.0") || !strings.Contains(got, "MERIDIAN_BIND=192.0.2.1:8787") {
		t.Fatalf("env: %s", got)
	}
	if e.read(e.hostBin()) != "bin-of-ghcr.io/example/meridian:v1.1.0\n" {
		t.Fatalf("host bin: %s", e.read(e.hostBin()))
	}
	b := filepath.Join(e.backups(), "20261118T000001Z")
	if e.read(filepath.Join(b, "data.tar.gz")) != "data-v1\n" || e.read(filepath.Join(b, "secrets.tar.gz")) != "secrets-v1\n" {
		t.Fatal("volumes not backed up")
	}
	if !strings.Contains(e.read(filepath.Join(b, "meta.env")), "IMAGE_REF=ghcr.io/example/meridian:v1.0.0") || e.read(filepath.Join(b, "SHA256SUMS")) == "" {
		t.Fatal("meta")
	}
	log := e.read(filepath.Join(e.state, "log"))
	iStop, iRun, iUp := strings.Index(log, "compose -f"+" "), strings.Index(log, "docker run"), strings.LastIndex(log, " up -d")
	iStop = strings.Index(log, " stop meridian")
	if !(iStop >= 0 && iStop < iRun && iRun < iUp) {
		t.Fatalf("order stop<backup<up broken:\n%s", log)
	}
	if !strings.Contains(log, "tag id-ghcr.io_example_meridian_v1.0.0 meridian-rollback:20261118T000001Z") {
		t.Fatalf("rollback tag missing:\n%s", log)
	}
	// Same version again: nothing to do, no new backup.
	e.extra = []string{"MERIDIAN_BACKUP_ID=20261118T000002Z"}
	if out, code := e.run("upgrade.sh", "v1.1.0"); code != 0 || !strings.Contains(out, "无需升级") {
		t.Fatalf("rerun: %d %s", code, out)
	}
	if _, err := os.Stat(filepath.Join(e.backups(), "20261118T000002Z")); err == nil {
		t.Fatal("re-run made a backup")
	}
}

func TestUpgradeFailedHealthRollsBack(t *testing.T) {
	e := setup(t)
	e.running("ghcr.io/example/meridian:v1.0.0")
	e.write("pullable", "ghcr.io/example/meridian:v2.0.0\n")
	e.write("bad_images", "ghcr.io/example/meridian:v2.0.0\n")
	e.extra = []string{"MERIDIAN_BACKUP_ID=20261118T000001Z"}
	out, code := e.run("upgrade.sh", "v2.0.0")
	if code != 1 {
		t.Fatalf("want 1, got %d\n%s", code, out)
	}
	if got := e.read(filepath.Join(e.state, "cur_image")); got != "meridian-rollback:20261118T000001Z\n" {
		t.Fatalf("running %q\n%s", got, out)
	}
	if e.read(filepath.Join(e.state, "vol_data")) != "data-v1\n" {
		t.Fatal("data volume not restored")
	}
	if e.read(e.hostBin()) != "bin-of-ghcr.io/example/meridian:v1.0.0\n" {
		t.Fatalf("host bin not restored: %s", e.read(e.hostBin()))
	}
	assertExec(t, e.hostBin())
	if !strings.Contains(out, "已回到升级前的版本") {
		t.Fatal(out)
	}
}

func assertExec(t *testing.T, p string) {
	t.Helper()
	fi, err := os.Stat(p)
	must(t, err)
	if fi.Mode().Perm() != 0o755 {
		t.Fatalf("%s mode %v, want 0755", p, fi.Mode().Perm())
	}
}

// A restored host binary meridian-host cannot start must fail the
// upgrade's auto-recovery and a manual rollback instead of reporting success.
func TestRestoreFailsWhenHostAgentDoesNotStart(t *testing.T) {
	e := setup(t)
	e.running("ghcr.io/example/meridian:v1.0.0")
	e.write("pullable", "ghcr.io/example/meridian:v2.0.0\n")
	e.write("bad_images", "ghcr.io/example/meridian:v2.0.0\n")
	e.extra = []string{"MERIDIAN_BACKUP_ID=20261118T000001Z"}
	// Simulate the old bug: an install(1) that leaves the restored binary
	// without its exec bit.
	brokenInstall := "#!/bin/bash\n/usr/bin/install \"$@\" || exit\n[[ \"$1\" == -d ]] || chmod 0600 \"${@: -1}\"\n"
	must(t, os.WriteFile(filepath.Join(e.bin, "install"), []byte(brokenInstall), 0o755))
	out, code := e.run("upgrade.sh", "v2.0.0")
	if code == 0 || strings.Contains(out, "已回到升级前的版本") || !strings.Contains(out, "meridian-host") {
		t.Fatalf("auto-recovery reported success: %d\n%s", code, out)
	}
	// Manual rollback with the same broken install also fails.
	e.extra = []string{"MERIDIAN_BACKUP_ID=20261118T000005Z"}
	out, code = e.run("rollback.sh", "20261118T000001Z", "--yes")
	if code == 0 || !strings.Contains(out, "恢复失败") {
		t.Fatalf("rollback reported success: %d\n%s", code, out)
	}
}

func TestUpgradePullFailureChangesNothing(t *testing.T) {
	e := setup(t)
	e.running("ghcr.io/example/meridian:v1.0.0")
	before := e.read(e.envFile())
	out, code := e.run("upgrade.sh", "v9.9.9")
	if code != 1 || !strings.Contains(out, "--build") || !strings.Contains(out, "不保证任何版本已经发布") {
		t.Fatalf("%d\n%s", code, out)
	}
	if e.read(e.envFile()) != before || strings.Contains(e.read(filepath.Join(e.state, "log")), " stop meridian") {
		t.Fatal("pull failure changed state")
	}
	if _, code := e.run("upgrade.sh"); code != 2 {
		t.Fatal("no args must be usage error")
	}
	if _, code := e.run("upgrade.sh", "v1.0.0", "--keep", "0"); code != 2 {
		t.Fatal("--keep 0")
	}
}

func TestUpgradeKeepsLastNBackupsAndBind(t *testing.T) {
	e := setup(t)
	e.running("ghcr.io/example/meridian:v1.0.0")
	// An older .env without MERIDIAN_BIND: the container's value is kept.
	must(t, os.WriteFile(e.envFile(), []byte("MERIDIAN_IMAGE=ghcr.io/example/meridian:v1.0.0\n"), 0o600))
	e.write("bind_env", "192.0.2.7:8787")
	e.write("pullable", "ghcr.io/example/meridian:v1.1.0\nghcr.io/example/meridian:v1.2.0\nghcr.io/example/meridian:v1.3.0\n")
	for i, v := range []string{"v1.1.0", "v1.2.0", "v1.3.0"} {
		e.extra = []string{"MERIDIAN_BACKUP_ID=20261118T00000" + string(rune('1'+i)) + "Z"}
		if out, code := e.run("upgrade.sh", v, "--keep", "2"); code != 0 {
			t.Fatalf("%s: %s", v, out)
		}
	}
	ents, _ := os.ReadDir(e.backups())
	if len(ents) != 2 || ents[0].Name() != "20261118T000002Z" {
		t.Fatalf("backups: %v", ents)
	}
	if !strings.Contains(e.read(e.envFile()), "MERIDIAN_BIND=192.0.2.7:8787") {
		t.Fatalf("bind not kept: %s", e.read(e.envFile()))
	}
}

func TestRollback(t *testing.T) {
	e := setup(t)
	e.running("ghcr.io/example/meridian:v1.0.0")
	e.write("pullable", "ghcr.io/example/meridian:v1.1.0\n")
	e.extra = []string{"MERIDIAN_BACKUP_ID=20261118T000001Z"}
	if out, code := e.run("upgrade.sh", "v1.1.0"); code != 0 {
		t.Fatal(out)
	}
	e.write("vol_data", "data-v2-changed\n")
	e.extra = []string{"MERIDIAN_BACKUP_ID=20261118T000005Z"}
	if out, code := e.run("rollback.sh"); code != 1 || !strings.Contains(out, "--yes") {
		t.Fatalf("no tty without --yes must refuse: %d %s", code, out)
	}
	out, code := e.run("rollback.sh", "--yes")
	if code != 0 {
		t.Fatalf("%d\n%s", code, out)
	}
	if e.read(filepath.Join(e.state, "vol_data")) != "data-v1\n" || e.read(filepath.Join(e.state, "cur_image")) != "meridian-rollback:20261118T000001Z\n" {
		t.Fatal("not rolled back")
	}
	assertExec(t, e.hostBin())
	if e.read(filepath.Join(e.backups(), "20261118T000005Z", "data.tar.gz")) != "data-v2-changed\n" {
		t.Fatal("no pre-rollback backup of the current state")
	}
	if out, _ := e.run("rollback.sh", "--list"); !strings.Contains(out, "pre-rollback") {
		t.Fatal(out)
	}
	// Tampered backup is refused.
	must(t, os.WriteFile(filepath.Join(e.backups(), "20261118T000001Z", "data.tar.gz"), []byte("evil"), 0o600))
	if out, code := e.run("rollback.sh", "20261118T000001Z", "--yes"); code != 1 || !strings.Contains(out, "校验失败") {
		t.Fatalf("%d %s", code, out)
	}
	// Missing image is refused.
	must(t, os.Remove(filepath.Join(e.state, "images", "meridian-rollback_20261118T000005Z")))
	if out, code := e.run("rollback.sh", "20261118T000005Z", "--yes"); code != 1 || !strings.Contains(out, "成对恢复") {
		t.Fatalf("%d %s", code, out)
	}
	if _, code := e.run("rollback.sh", "../etc"); code != 2 {
		t.Fatal("bad id")
	}
}

func TestAPIHelperKeepsTokenInContainer(t *testing.T) {
	e := setup(t)
	e.running("meridian:local")
	data := filepath.Join(e.state, "data")
	must(t, os.MkdirAll(data, 0o700))
	const token = "0123456789abcdef0123456789abcdef"
	must(t, os.WriteFile(filepath.Join(data, "panel.token"), []byte(token+"\n"), 0o600))
	e.extra = []string{"MERIDIAN_DATA=" + data, "TMPDIR=" + e.state}
	for _, bad := range []string{
		"/etc/passwd", "/api/../etc", "/api/x/..", "/api/./meta", "/api/%2e%2e/x", "/api/%2E%2e/x",
		"/api/.%2e/x", "/api/%2e/x", "/api/a%2f..%2fb", "/api/meta?x=/../y",
	} {
		if out, code := e.run("api.sh", "GET", bad); code != 2 {
			t.Errorf("%s accepted: %d %s", bad, code, out)
		}
	}
	if _, code := e.run("api.sh", "PATCH", "/api/meta"); code != 2 {
		t.Fatal("method accepted")
	}
	for _, ok := range []string{"/api/meta", "/api/files/a.b/c..d?x=1.2"} {
		out, code := e.run("api.sh", "GET", ok)
		if code != 0 {
			t.Fatalf("%s: %s", ok, out)
		}
	}
	log := e.read(filepath.Join(e.state, "log"))
	if !strings.Contains(log, "docker exec -i -e M_METHOD=GET -e M_URL=http://127.0.0.1:8787/api/meta cid1 sh -c") {
		t.Fatalf("log:\n%s", log)
	}
	// The token is on no command line (host docker exec or container curl):
	// curl gets it from a 0600 config file that is gone afterwards.
	if strings.Contains(log, token) {
		t.Fatalf("token on a command line:\n%s", log)
	}
	if !strings.Contains(log, "curl -fsS -K ") {
		t.Fatalf("curl not given a config file:\n%s", log)
	}
	if got := e.read(filepath.Join(e.state, "curlcfg")); got != "header = \"Authorization: Bearer "+token+"\"\n" {
		t.Fatalf("config %q", got)
	}
	if got := strings.TrimSpace(e.read(filepath.Join(e.state, "curlcfg_mode"))); got != "-rw-------" {
		t.Fatalf("config mode %q", got)
	}
	if _, err := os.Stat(strings.TrimSpace(e.read(filepath.Join(e.state, "curlcfg_path")))); err == nil {
		t.Fatal("config file left behind")
	}
}

// Rolling back to an image whose CLI predates "meridian panel-bind": the
// health check uses the bind saved with the backup and never runs the
// missing subcommand (which would start an old panel instead).
func TestRollbackToImageWithoutPanelBind(t *testing.T) {
	e := setup(t)
	e.running("ghcr.io/example/meridian:v1.0.0")
	e.write("pullable", "ghcr.io/example/meridian:v1.1.0\n")
	e.write("no_panel_bind", "ghcr.io/example/meridian:v1.0.0\nmeridian-rollback:20261118T000001Z\n")
	e.extra = []string{"MERIDIAN_BACKUP_ID=20261118T000001Z"}
	if out, code := e.run("upgrade.sh", "v1.1.0"); code != 0 {
		t.Fatal(out)
	}
	if !strings.Contains(e.read(filepath.Join(e.backups(), "20261118T000001Z", "meta.env")), "PANEL_BIND=192.0.2.1:8787\n") {
		t.Fatal("backup does not record the bind")
	}
	e.write("log", "")
	e.extra = []string{"MERIDIAN_BACKUP_ID=20261118T000005Z"}
	out, code := e.run("rollback.sh", "--yes")
	if code != 0 {
		t.Fatalf("%d\n%s", code, out)
	}
	log := e.read(filepath.Join(e.state, "log"))
	if strings.Contains(log, "old-panel-started") || strings.Contains(log, "meridian panel-bind") {
		t.Fatalf("ran panel-bind on an old image:\n%s", log)
	}
	if !strings.Contains(log, "http://192.0.2.1:8787/api/health") {
		t.Fatalf("health not checked on the saved bind:\n%s", log)
	}
}

func TestPanelBindOfDetectsSubcommand(t *testing.T) {
	e := setup(t)
	e.running("ghcr.io/example/meridian:v1.0.0")
	e.write("bind", "192.0.2.9:8787\n")
	if out, _ := e.bashLib(`panel_bind_of cid1`); strings.TrimSpace(out) != "192.0.2.9:8787" {
		t.Fatalf("new image: %q", out)
	}
	e.write("no_panel_bind", "ghcr.io/example/meridian:v1.0.0\n")
	if out, _ := e.bashLib(`panel_bind_of cid1`); strings.TrimSpace(out) != "127.0.0.1:8787" {
		t.Fatalf("old image without hint: %q", out)
	}
	if out, _ := e.bashLib(`panel_bind_of cid1 192.0.2.7:8787`); strings.TrimSpace(out) != "192.0.2.7:8787" {
		t.Fatalf("old image with hint: %q", out)
	}
	e.write("bind_env", "192.0.2.5:8787")
	if out, _ := e.bashLib(`panel_bind_of cid1 192.0.2.7:8787`); strings.TrimSpace(out) != "192.0.2.5:8787" {
		t.Fatalf("container env first: %q", out)
	}
	if strings.Contains(e.read(filepath.Join(e.state, "log")), "old-panel-started") {
		t.Fatal("started an old panel")
	}
}

// install.sh's SmartDNS step: a fresh install creates the resolver
// container (and starts and checks it once its config exists); an
// existing one is never recreated or restarted.
func TestSmartDNSEnsure(t *testing.T) {
	e := setup(t)
	conf := filepath.Join(e.state, "smartdns.conf")
	e.extra = []string{"MERIDIAN_SMARTDNS_CONF=" + conf, "MERIDIAN_SMARTDNS_TIMEOUT=2"}
	snippet := "compose_init " + filepath.Join(e.repo, "deploy", "docker-compose.yml") + "\nsmartdns_ensure\n"
	// Fresh, no config yet: created, not started.
	if out, code := e.bashLib(snippet); code != 0 || e.read(filepath.Join(e.state, "smartdns")) != "created\n" {
		t.Fatalf("fresh: %d %s", code, out)
	}
	if !strings.Contains(e.read(filepath.Join(e.state, "log")), "--profile dns create --no-recreate smartdns") {
		t.Fatal(e.read(filepath.Join(e.state, "log")))
	}
	// Fresh with a config: started and running.
	must(t, os.Remove(filepath.Join(e.state, "smartdns")))
	e.write("smartdns.conf", "bind :53\n")
	if out, code := e.bashLib(snippet); code != 0 || e.read(filepath.Join(e.state, "smartdns")) != "running\n" || !strings.Contains(out, "已启动") {
		t.Fatalf("fresh+conf: %d %s", code, out)
	}
	// Not running after start: the install fails.
	must(t, os.Remove(filepath.Join(e.state, "smartdns")))
	e.write("smartdns_broken", "")
	if out, code := e.bashLib(snippet); code == 0 || !strings.Contains(out, "没有运行") {
		t.Fatalf("broken: %d %s", code, out)
	}
	// Existing running container: untouched.
	must(t, os.Remove(filepath.Join(e.state, "smartdns_broken")))
	e.write("smartdns", "running\n")
	e.write("log", "")
	if out, code := e.bashLib(snippet); code != 0 || !strings.Contains(out, "保持原状") {
		t.Fatalf("existing: %d %s", code, out)
	}
	if log := e.read(filepath.Join(e.state, "log")); strings.Contains(log, "--profile dns") || strings.Contains(log, "docker start") {
		t.Fatalf("existing touched:\n%s", log)
	}
	// Existing but stopped, config present: started and checked.
	e.write("smartdns", "exited\n")
	if out, code := e.bashLib(snippet); code != 0 || e.read(filepath.Join(e.state, "smartdns")) != "running\n" || !strings.Contains(out, "已启动") {
		t.Fatalf("stopped+conf: %d %s", code, out)
	}
	if log := e.read(filepath.Join(e.state, "log")); !strings.Contains(log, "docker start meridian-smartdns") || strings.Contains(log, "--profile dns") {
		t.Fatalf("stopped+conf not started in place:\n%s", log)
	}
	// ... and fails when it does not stay up.
	e.write("smartdns", "exited\n")
	e.write("smartdns_broken", "")
	if out, code := e.bashLib(snippet); code == 0 || !strings.Contains(out, "没有运行") {
		t.Fatalf("stopped+conf broken: %d %s", code, out)
	}
	// Existing but stopped without a config: left for meridian-host.
	must(t, os.Remove(conf))
	e.write("log", "")
	if out, code := e.bashLib(snippet); code != 0 || e.read(filepath.Join(e.state, "smartdns")) != "exited\n" || !strings.Contains(out, "还没有配置") {
		t.Fatalf("stopped, no conf: %d %s", code, out)
	}
	if strings.Contains(e.read(filepath.Join(e.state, "log")), "docker start") {
		t.Fatal("started without a config")
	}
	// A host smartdns.service takes precedence: no container work at all.
	must(t, os.Remove(filepath.Join(e.state, "smartdns")))
	e.write("host_smartdns", "")
	e.write("smartdns.conf", "bind :53\n")
	e.write("log", "")
	if out, code := e.bashLib(snippet); code != 0 || !strings.Contains(out, "smartdns.service") {
		t.Fatalf("host unit: %d %s", code, out)
	}
	for _, l := range strings.Split(e.read(filepath.Join(e.state, "log")), "\n") {
		if strings.HasPrefix(l, "docker ") && strings.Contains(l, "smartdns") {
			t.Fatalf("container touched despite host unit: %s", l)
		}
	}
}

// A failing "systemctl list-unit-files" cannot prove meridian-host runs:
// the restore fails instead of reporting success.
func TestRestoreFailsWhenSystemctlFails(t *testing.T) {
	e := setup(t)
	e.running("ghcr.io/example/meridian:v1.0.0")
	e.write("pullable", "ghcr.io/example/meridian:v1.1.0\n")
	e.extra = []string{"MERIDIAN_BACKUP_ID=20261118T000001Z"}
	if out, code := e.run("upgrade.sh", "v1.1.0"); code != 0 {
		t.Fatal(out)
	}
	e.write("systemctl_broken", "")
	e.extra = []string{"MERIDIAN_BACKUP_ID=20261118T000005Z"}
	out, code := e.run("rollback.sh", "20261118T000001Z", "--yes")
	if code == 0 || !strings.Contains(out, "list-unit-files") || !strings.Contains(out, "恢复失败") {
		t.Fatalf("rollback with broken systemctl: %d\n%s", code, out)
	}
}

// A tar failure on the second volume leaves both volumes as they were.
func TestRestoreVolumesAllOrNothing(t *testing.T) {
	e := setup(t)
	e.running("ghcr.io/example/meridian:v1.0.0")
	e.write("pullable", "ghcr.io/example/meridian:v1.1.0\n")
	e.extra = []string{"MERIDIAN_BACKUP_ID=20261118T000001Z"}
	if out, code := e.run("upgrade.sh", "v1.1.0"); code != 0 {
		t.Fatal(out)
	}
	e.write("vol_data", "data-v2\n")
	e.write("vol_secrets", "secrets-v2\n")
	e.write("tar_fail_secrets", "")
	e.extra = []string{"MERIDIAN_BACKUP_ID=20261118T000005Z"}
	out, code := e.run("rollback.sh", "20261118T000001Z", "--yes")
	if code == 0 || !strings.Contains(out, "两个卷都保持原样") {
		t.Fatalf("%d\n%s", code, out)
	}
	if e.read(filepath.Join(e.state, "vol_data")) != "data-v2\n" || e.read(filepath.Join(e.state, "vol_secrets")) != "secrets-v2\n" {
		t.Fatal("a volume changed after a failed restore")
	}
	if _, err := os.Stat(filepath.Join(e.state, "stage_data")); err == nil {
		t.Fatal("staged data not cleaned up")
	}
	// Both stage, then both swap.
	must(t, os.Remove(filepath.Join(e.state, "tar_fail_secrets")))
	e.extra = []string{"MERIDIAN_BACKUP_ID=20261118T000006Z"}
	if out, code := e.run("rollback.sh", "20261118T000001Z", "--yes"); code != 0 {
		t.Fatalf("%d\n%s", code, out)
	}
	if e.read(filepath.Join(e.state, "vol_data")) != "data-v1\n" || e.read(filepath.Join(e.state, "vol_secrets")) != "secrets-v1\n" {
		t.Fatal("not restored")
	}
}

// install.sh, upgrade.sh and rollback.sh share one lock; without flock
// they refuse to run.
func TestSharedLock(t *testing.T) {
	e := setup(t)
	e.running("ghcr.io/example/meridian:v1.0.0")
	e.write("pullable", "ghcr.io/example/meridian:v1.1.0\n")
	e.write("locked", "")
	for _, c := range [][]string{{"upgrade.sh", "v1.1.0"}, {"rollback.sh", "--yes"}} {
		if out, code := e.run(c[0], c[1:]...); code == 0 || !strings.Contains(out, "正在进行") {
			t.Errorf("%v while locked: %d %s", c, code, out)
		}
	}
	must(t, os.Remove(filepath.Join(e.state, "locked")))
	e.extra = []string{"MERIDIAN_FLOCK=meridian-no-such-flock"}
	if out, code := e.run("upgrade.sh", "v1.1.0"); code == 0 || !strings.Contains(out, "flock") {
		t.Fatalf("no flock: %d %s", code, out)
	}
	if strings.Contains(e.read(filepath.Join(e.state, "log")), " stop meridian") {
		t.Fatal("ran without a lock")
	}
	for _, f := range []string{"install.sh", "upgrade.sh", "rollback.sh"} {
		b, err := os.ReadFile(filepath.Join("..", "..", "deploy", "debian", f))
		must(t, err)
		if !strings.Contains(string(b), "\nacquire_lock\n") {
			t.Errorf("%s does not take the shared lock", f)
		}
	}
}

// A management firewall that fails "nft -c" is never installed or loaded,
// and install.sh stops before the panel is started.
func TestMgmtFirewallInstallRefusesBadRules(t *testing.T) {
	e := setup(t)
	mg, units := filepath.Join(e.state, "mgmt"), filepath.Join(e.state, "units")
	must(t, os.MkdirAll(units, 0o755))
	must(t, os.WriteFile(filepath.Join(e.repo, "deploy", "debian", "meridian-mgmt-firewall.service"), []byte("[Unit]\n"), 0o644))
	must(t, os.WriteFile(filepath.Join(e.bin, "nft"), []byte("#!/bin/bash\necho \"nft $*\" >> \"$FAKE_STATE/log\"\n[[ ! -f \"$FAKE_STATE/nft_bad\" ]]\n"), 0o755))
	e.extra = []string{"MERIDIAN_MGMT_DIR=" + mg, "MERIDIAN_UNIT_DIR=" + units}
	call := `mgmt_firewall_install 8787 lan0 192.168.50.0/24 && echo installed`
	e.write("nft_bad", "")
	out, code := e.bashLib(call)
	if code == 0 || strings.Contains(out, "installed") {
		t.Fatalf("bad rules accepted: %d %s", code, out)
	}
	if _, err := os.Stat(filepath.Join(mg, "mgmt-firewall.nft")); err == nil {
		t.Fatal("rules installed")
	}
	if _, err := os.Stat(filepath.Join(mg, "mgmt-firewall.nft.new")); err == nil {
		t.Fatal("candidate left behind")
	}
	if strings.Contains(e.read(filepath.Join(e.state, "log")), "mgmt-firewall.service") {
		t.Fatal("unit touched")
	}
	must(t, os.Remove(filepath.Join(e.state, "nft_bad")))
	if out, code := e.bashLib(call); code != 0 || !strings.Contains(out, "installed") {
		t.Fatalf("good rules: %d %s", code, out)
	}
	if !strings.Contains(e.read(filepath.Join(e.state, "log")), "systemctl restart meridian-mgmt-firewall.service") {
		t.Fatal("not loaded")
	}
	// install.sh: the failure aborts before the panel container is started.
	b, err := os.ReadFile(filepath.Join("..", "..", "deploy", "debian", "install.sh"))
	must(t, err)
	src := string(b)
	iFW := strings.Index(src, "if ! mgmt_firewall_install ")
	iDie := strings.Index(src, `die "管理防火墙规则没有通过 nft -c 检查`)
	iUp := strings.Index(src, `up -d --no-build meridian`)
	if iFW < 0 || iDie < iFW || iUp < iDie {
		t.Fatal("install.sh must abort on a failed firewall check before starting the panel")
	}
}
