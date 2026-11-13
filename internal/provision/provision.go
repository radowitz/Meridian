// Package provision builds the SSH bootstrap for a node the operator added.
// It never embeds real keys. Dry-run returns a script full of placeholders.
package provision

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"path"
	"regexp"
	"sort"
	"strings"

	"golang.org/x/crypto/curve25519"

	"github.com/radowitz/meridian/internal/apply"
	"github.com/radowitz/meridian/internal/artifacts"
	"github.com/radowitz/meridian/internal/compile"
	"github.com/radowitz/meridian/internal/model"
	"github.com/radowitz/meridian/internal/preflight"
)

const PrivatePlaceholder = compile.PrivateKeyPlaceholder

// Keypair is a WireGuard key generated in-process (not by shelling out).
type Keypair struct {
	Private string
	Public  string
}

func GenerateKeypair() (Keypair, error) {
	var priv [32]byte
	if _, err := rand.Read(priv[:]); err != nil {
		return Keypair{}, err
	}
	priv[0] &= 248
	priv[31] &= 127
	priv[31] |= 64
	pub, err := curve25519.X25519(priv[:], curve25519.Basepoint)
	if err != nil {
		return Keypair{}, err
	}
	return Keypair{
		Private: base64.StdEncoding.EncodeToString(priv[:]),
		Public:  base64.StdEncoding.EncodeToString(pub),
	}, nil
}

// Script is ScriptWith without a target identity: the result refuses to
// run on a host (it is only good for review and syntax checks). Real
// provisioning always goes through ScriptWith.
func Script(nodeName string, files map[string]string) string {
	return ScriptWith(nodeName, files, Options{})
}

// Options binds a provision script to the target and to what the preflight
// saw immediately before execution.
type Options struct {
	NodeID     string
	Deployment string // this panel's deployment id
	ServerID   string
	Bundle     string // preflight.BundleDigest of the files (hex)
	Run        string // run id (journal, work directory)
	// Expect is the ownership the preflight found: "none" (first install:
	// no manifest, no planned interface or nft table may exist when the
	// script starts) or "same" (the manifest must still name this node and
	// deployment).
	Expect string
	// Artifacts are the panel-delivered binaries the node's units run
	// (preflight.Footprint.Binaries), for the host's architecture. Every
	// binary the bundle needs must be listed, or the script refuses.
	Artifacts []Artifact
}

// Artifact is one panel-delivered binary of a provision run.
type Artifact struct {
	Name    string
	Version string
	SHA256  string
	Size    int64
	// Staged: the panel sent the bytes to artifacts.StagePath(Name) on this
	// host before the script runs (sshexec.Connector.Stage); the script
	// verifies them and installs them at artifacts.HostPath(Name). Not
	// staged: the preflight saw exactly SHA256 at the host path already,
	// the script verifies that and keeps the file.
	Staged bool
}

var optRe = regexp.MustCompile(`^[A-Za-z0-9._-]{1,64}$`)

// CheckOptions validates every value that is placed into the script.
func CheckOptions(o Options) error {
	for name, v := range map[string]string{"node": o.NodeID, "deployment": o.Deployment, "server": o.ServerID, "run": o.Run} {
		if !optRe.MatchString(v) {
			return fmt.Errorf("provision %s %q 不合法", name, v)
		}
	}
	if len(o.Bundle) != 64 || strings.Trim(o.Bundle, "0123456789abcdef") != "" {
		return errors.New("provision bundle 摘要不合法")
	}
	if o.Expect != "none" && o.Expect != "same" {
		return errors.New("provision expect 只能是 none 或 same")
	}
	seen := map[string]bool{}
	for _, a := range o.Artifacts {
		switch {
		case !artifacts.ValidName(a.Name) || seen[a.Name]:
			return fmt.Errorf("provision 二进制 %q 不合法或重复", a.Name)
		case !optRe.MatchString(a.Version) || !strings.ContainsAny(a.Version[:1], "0123456789"):
			return fmt.Errorf("provision 二进制 %s 的版本不合法", a.Name)
		case !artifacts.ValidSHA256(a.SHA256):
			return fmt.Errorf("provision 二进制 %s 的摘要不合法", a.Name)
		case a.Size <= 0 || a.Size > artifacts.MaxSize:
			return fmt.Errorf("provision 二进制 %s 的大小不合法", a.Name)
		}
		seen[a.Name] = true
	}
	return nil
}

// missingArtifacts lists the binaries the files need that o does not carry.
func missingArtifacts(fp preflight.Footprint, o Options) []string {
	var out []string
	for _, b := range fp.Binaries {
		found := false
		for _, a := range o.Artifacts {
			found = found || a.Name == b
		}
		if !found {
			out = append(out, b)
		}
	}
	return out
}

var (
	ifaceNameRe = regexp.MustCompile(`^[a-z][a-z0-9-]{0,14}$`)
	unitNameRe  = regexp.MustCompile(`^[a-z0-9][a-z0-9@.-]{0,80}\.(service|timer)$`)
	nftNameRe   = regexp.MustCompile(`^inet [a-z][a-z0-9_]{0,40}$`)
	// sysctlPathRe: a /proc/sys path of a forwarding or per-interface key.
	ifaceNameAnyRe = regexp.MustCompile(`^[A-Za-z0-9_.@-]{1,15}$`)
	sysctlPathRe   = regexp.MustCompile(`^/proc/sys/net/ipv[46]/(ip_forward|conf/[A-Za-z0-9_.@-]{1,15}/[a-z_]{1,32})$`)
)

// ScriptWith writes the node's rendered files and reloads WireGuard with
// syncconf when the interface already exists, so a NAT mapping is not torn
// down.
//
// Before anything is changed it re-validates, on the host, what the
// preflight saw (root, no unfinished earlier run, manifest ownership, and
// for a first install that no planned interface or nft table appeared).
// Then it keeps a journal under /var/lib/meridian/node and, if any step
// fails or the session is cut, compensates: units it enabled are
// disabled, interfaces and nft tables it created are deleted, rules and
// routes it added are removed, sysctls are restored, files it created are
// removed and files it replaced are restored (an update re-runs the
// restored meridian-up.sh). What cannot be undone is printed as
// MERIDIAN_LEFTOVER and recorded in the journal; packages it installed are
// kept and recorded (MERIDIAN_KEPT). Success writes the ownership manifest
// and prints MERIDIAN_PROVISION_OK.
//
// WireGuard configs are written 0600 through a temp file. If a config still
// holds the private-key placeholder (a preview), the script refuses to run
// before it writes anything. When the node has a SmartDNS config, the
// resolver is installed before any file is written and must be active at the end.
func ScriptWith(nodeName string, files map[string]string, o Options) string {
	var sb strings.Builder
	sb.WriteString("#!/bin/bash\n")
	sb.WriteString("# Meridian provision\n")
	sb.WriteString("# node: " + oneLine(nodeName) + "\n")
	sb.WriteString("# Does not flush nftables, does not touch unrelated WireGuard interfaces,\n")
	sb.WriteString("# and does not install Cloudflare Mesh on the home gateway.\n")
	sb.WriteString("set -euo pipefail\n")
	sb.WriteString("umask 022\n")
	if apply.NeedsPrivateKey(files) {
		sb.WriteString("# PREVIEW ONLY: WireGuard configs still contain " + PrivatePlaceholder + ".\n")
		sb.WriteString("echo 'meridian: preview script still has the private-key placeholder; refusing to overwrite configs' >&2\n")
		sb.WriteString("exit 1\n")
	} else if needsSecrets(files) {
		sb.WriteString("# PREVIEW ONLY: WSS files still contain credential-store placeholders or unresolved WSS tokens.\n")
		sb.WriteString("echo 'meridian: preview script still has secret placeholders; refusing to overwrite configs' >&2\n")
		sb.WriteString("exit 1\n")
	}
	if err := CheckOptions(o); err != nil {
		sb.WriteString("# NOT BOUND to a target: built without a node, deployment and preflight.\n")
		sb.WriteString("echo 'meridian: provision script without a target identity; refusing to run' >&2\n")
		sb.WriteString("exit 1\n")
		o = Options{NodeID: "unbound", Deployment: "unbound", ServerID: "unbound", Run: "unbound", Expect: "none", Bundle: strings.Repeat("0", 64)}
	}
	fp := preflight.FootprintOf(files)
	if miss := missingArtifacts(fp, o); len(miss) > 0 {
		sb.WriteString("# The node's units run panel-delivered binaries this script does not carry: " + strings.Join(miss, " ") + "\n")
		sb.WriteString("echo 'MERIDIAN_REFUSED artifact_missing'\n")
		sb.WriteString("echo 'meridian: the provision script does not carry the binaries the units need; refusing to run' >&2\n")
		sb.WriteString("exit 3\n")
	}
	var ifaces, units, nfts, tables, prios, dsts []string
	for _, i := range fp.Interfaces {
		if ifaceNameRe.MatchString(i.Name) {
			ifaces = append(ifaces, i.Name)
		}
	}
	if _, ok := files["/etc/meridian/mesh-sidecar.compose.yml"]; ok {
		ifaces = append(ifaces, "mmesh", "mmesh-c")
	}
	for _, u := range fp.Units {
		if unitNameRe.MatchString(u) {
			units = append(units, u)
		}
	}
	for _, t := range fp.NFTTables {
		if nftNameRe.MatchString(t) {
			nfts = append(nfts, strings.TrimPrefix(t, "inet "))
		}
	}
	for _, n := range fp.Tables {
		tables = append(tables, fmt.Sprint(n))
	}
	seenPrio := map[int]bool{}
	for _, r := range fp.Rules {
		if !seenPrio[r.Priority] {
			seenPrio[r.Priority] = true
			prios = append(prios, fmt.Sprint(r.Priority))
		}
	}
	seenDst := map[string]bool{}
	for _, r := range fp.Routes {
		if r.Table == 0 && !seenDst[r.Dst.String()] {
			seenDst[r.Dst.String()] = true
			dsts = append(dsts, r.Dst.String())
		}
	}
	sort.Strings(dsts)
	// The kernel keys this bundle may write (scoped: the managed sysctl
	// files and the hardened interfaces), as /proc/sys paths. Their values
	// are recorded before anything changes and restored by a failed run's
	// compensation; no other key is read or written.
	var sysPaths []string
	for _, k := range fp.SysctlKeys {
		if p := preflight.SysctlProcPath(k); sysctlPathRe.MatchString(p) {
			sysPaths = append(sysPaths, p)
		}
	}
	fw := "0"
	if _, ok := files[compile.FWCompatPath]; ok {
		fw = "1"
	}
	var bootUnits []string
	for _, u := range []string{compile.NodeUnit, compile.FWCompatUnit} {
		if _, ok := files["/etc/systemd/system/"+u]; ok {
			bootUnits = append(bootUnits, u)
		}
	}
	var artPaths, artLines []string
	for _, a := range o.Artifacts {
		artPaths = append(artPaths, artifacts.HostPath(a.Name))
		artLines = append(artLines, a.Name+" "+a.Version+" "+artifacts.HostPath(a.Name)+" "+a.SHA256)
	}
	fmt.Fprintf(&sb, "M_NODE=%s\nM_DEPLOYMENT=%s\nM_SERVER=%s\nM_BUNDLE=%s\nM_RUN=%s\nM_EXPECT=%s\n",
		shellQuote(o.NodeID), shellQuote(o.Deployment), shellQuote(o.ServerID), shellQuote(o.Bundle), shellQuote(o.Run), shellQuote(o.Expect))
	fmt.Fprintf(&sb, "M_IFACES=%s\nM_UNITS=%s\nM_NFT=%s\nM_TABLES=%s\nM_PRIOS=%s\nM_DSTS=%s\n",
		shellQuote(strings.Join(ifaces, " ")), shellQuote(strings.Join(units, " ")), shellQuote(strings.Join(nfts, " ")),
		shellQuote(strings.Join(tables, " ")), shellQuote(strings.Join(prios, " ")), shellQuote(strings.Join(dsts, " ")))
	fmt.Fprintf(&sb, "M_STAGE=%s\nM_ARTPATHS=%s\nM_ARTLINES=%s\n", shellQuote(artifacts.StageDir), shellQuote(strings.Join(artPaths, " ")), shellQuote(strings.Join(artLines, "\n")))
	fmt.Fprintf(&sb, "M_SYSCTL=%s\nM_FW=%s\n", shellQuote(strings.Join(sysPaths, " ")), fw)
	// The WAN interface the scripts name and the default routes it must
	// carry: re-checked on the host before anything changes.
	wan, need := "", ""
	if ifaceNameAnyRe.MatchString(fp.WAN) {
		wan = fp.WAN
		for _, n := range fp.WANNeed {
			if n == "4" || n == "6" || n == "any" {
				need += n + " "
			}
		}
	}
	fmt.Fprintf(&sb, "M_WAN=%s\nM_WAN_NEED=%s\n", shellQuote(wan), shellQuote(strings.TrimSpace(need)))
	sb.WriteString(provisionPrelude)
	_, hasDNS := files["/etc/smartdns/smartdns.conf"]
	if hasDNS && !resolverBindsTunnelOnly(fp) {
		// The remote resolver binds tunnel addresses only: without a bind
		// line SmartDNS binds [::]:53, a wildcard answers the internet.
		sb.WriteString("m_refuse resolver_bind_unsafe 'the resolver config binds a wildcard address or nothing (SmartDNS would answer on [::]:53)'\n")
	}
	// Panel-delivered binaries: verified on the host before anything
	// changes (the staged bytes, or the copy the preflight saw).
	for _, a := range o.Artifacts {
		mode := "present"
		if a.Staged {
			mode = "staged"
		}
		fmt.Fprintf(&sb, "m_art_check %s %s %s %s\n", shellQuote(a.Name), shellQuote(artifacts.HostPath(a.Name)), shellQuote(a.SHA256), mode)
	}
	sb.WriteString("{\n")
	sb.WriteString("m_begin\n")
	sb.WriteString("export DEBIAN_FRONTEND=noninteractive\n")
	sb.WriteString(packageInstall)
	// Installing nftables must not leave a service that flushes the
	// ruleset (the preflight saw none; a package could have enabled it).
	sb.WriteString("if m_nft_flush_risk; then echo 'meridian: nftables.service is enabled or running and flushes the whole ruleset (stop/reload); refusing to activate (see the preflight finding nftables_flush_on_reload)' >&2; exit 1; fi\n")
	for _, a := range o.Artifacts {
		if a.Staged {
			fmt.Fprintf(&sb, "m_art_install %s %s %s\n", shellQuote(a.Name), shellQuote(artifacts.HostPath(a.Name)), shellQuote(a.SHA256))
		}
	}
	if hasDNS {
		sb.WriteString(legacySmartDNSStop)
	}
	paths := make([]string, 0, len(files))
	for p := range files {
		paths = append(paths, p)
	}
	sortStrings(paths)
	for _, p := range paths {
		clean, ok := safeHostPath(p)
		if !ok {
			fmt.Fprintf(&sb, "# rejected path %s\n", shellQuote(oneLine(p)))
			continue
		}
		body := files[p]
		delim := heredocDelim(body)
		mode, dirMode := "644", "755"
		switch {
		case strings.HasPrefix(clean, "/etc/wireguard/"):
			mode, dirMode = "600", "700"
		case strings.HasPrefix(clean, compile.WSSDir+"/"):
			// The WSS directory holds the path prefixes and the private
			// key: 0700, secret files 0600, certificates 0644.
			dirMode = "700"
			if compile.WSSSecretFile(clean) {
				mode = "600"
			}
		case strings.HasSuffix(clean, ".sh") || strings.Contains(clean, "/usr/local/sbin/"):
			mode = "755"
		}
		dir := dirOf(clean)
		fmt.Fprintf(&sb, "m_track %s\n", shellQuote(clean))
		fmt.Fprintf(&sb, "install -d -m %s %s\n", dirMode, shellQuote(dir))
		fmt.Fprintf(&sb, "tmp=$(mktemp %s)\n", shellQuote(dir+"/.meridian.XXXXXX"))
		sb.WriteString("m_note tmp \"$tmp\"\n")
		fmt.Fprintf(&sb, "chmod %s \"$tmp\"\n", mode)
		fmt.Fprintf(&sb, "cat > \"$tmp\" <<'%s'\n%s%s\n", delim, ensureNL(body), delim)
		fmt.Fprintf(&sb, "mv -f \"$tmp\" %s\n", shellQuote(clean))
	}
	sb.WriteString("if [ -x /usr/local/sbin/meridian-up.sh ]; then\n")
	sb.WriteString("  /usr/local/sbin/meridian-up.sh\n")
	sb.WriteString("fi\n")
	// The boot unit and the Docker re-assert unit are enabled, not started:
	// meridian-up.sh just ran, and meridian-node.service runs it again at
	// boot (it must never be started from meridian-up.sh itself).
	if len(bootUnits) > 0 {
		sb.WriteString("if [ -d /run/systemd/system ] && command -v systemctl >/dev/null 2>&1; then\n")
		sb.WriteString("  systemctl daemon-reload\n")
		for _, u := range bootUnits {
			if u == compile.FWCompatUnit {
				// The re-assert unit is WantedBy=docker.service. On a host
				// without Docker there is nothing to re-assert after, and
				// systemd 257 (Debian 13) makes "enable" fail for a unit
				// whose install target does not exist ("added as a
				// dependency to a non-existent unit docker.service", exit
				// status 1) — seen on a real hub without Docker, where it
				// failed the whole install. meridian-up.sh still runs the
				// compatibility script itself on every start and boot; a
				// later update enables the unit once Docker is there.
				fmt.Fprintf(&sb, "  if systemctl cat docker.service >/dev/null 2>&1; then systemctl enable %s; else echo 'meridian: no docker.service on this host; %s is installed but not enabled'; fi\n", shellQuote(u), u)
				continue
			}
			fmt.Fprintf(&sb, "  systemctl enable %s\n", shellQuote(u))
		}
		sb.WriteString("else\n")
		sb.WriteString("  echo 'meridian: no systemd; the boot unit cannot be enabled' >&2\n")
		sb.WriteString("  exit 1\n")
		sb.WriteString("fi\n")
	}
	// A replaced binary only takes effect when its units restart (enable
	// --now in meridian-up.sh leaves a running unit alone).
	for _, a := range o.Artifacts {
		if !a.Staged {
			continue
		}
		var us []string
		for _, u := range artifactUnits(files, a.Name) {
			us = append(us, shellQuote(u))
		}
		if len(us) > 0 {
			fmt.Fprintf(&sb, "if grep -qx %s \"$M_WORK/actions\"; then systemctl try-restart %s; fi\n", shellQuote("file-replaced "+artifacts.HostPath(a.Name)), strings.Join(us, " "))
		}
	}
	// wstunnel units whose unit file, restrictions, certificate, key,
	// environment or trust file changed are restarted (enable --now in
	// meridian-up.sh leaves a running unit alone; a rotation stage must
	// take effect in this run). The restart briefly interrupts that WSS
	// carrier; a unit that does not come back fails the run (compensated).
	for _, w := range wssUnitFiles(files) {
		var q []string
		for _, f := range w.files {
			q = append(q, "m_changed "+shellQuote(f))
		}
		fmt.Fprintf(&sb, "if %s; then\n"+
			"  m_note unit-restarted %s\n"+
			"  systemctl restart %s\n"+
			"  sleep 1\n"+
			"  systemctl is-active --quiet %s || { echo 'meridian: %s is not active after its WSS files changed' >&2; systemctl status --no-pager %s >&2 || true; exit 1; }\n"+
			"  echo MERIDIAN_WSS_RESTARTED %s\n"+
			"fi\n",
			strings.Join(q, " || "), shellQuote(w.unit), shellQuote(w.unit), shellQuote(w.unit), w.unit, shellQuote(w.unit), w.unit)
	}
	if hasDNS {
		sb.WriteString(smartDNSStart)
	}
	sb.WriteString("m_commit\n")
	sb.WriteString("echo MERIDIAN_PROVISION_OK\n")
	sb.WriteString("} </dev/null\n")
	return sb.String()
}

// provisionPrelude defines the guard, journal, compensation and commit
// helpers and re-validates the target before anything changes. The part
// that changes the host is one { … } </dev/null group: bash reads it whole
// before running it, and no command in it can consume the script that
// bash reads from stdin.
const provisionPrelude = provisionGuard + compensateLib + provisionTxn + artifactLib

// provisionGuard re-validates the target before anything changes.
const provisionGuard = `M_ROOT=''
M_STATE=$M_ROOT/var/lib/meridian/node
M_MANIFEST=$M_STATE/manifest
M_JOURNAL=$M_STATE/journal
M_WORK=$M_STATE/run-$M_RUN
M_DONE=0
M_LEFT=0
m_refuse() {
  echo "MERIDIAN_REFUSED $1"
  echo "meridian: $2; nothing was changed" >&2
  exit 3
}
# m_nft_flush_risk: nftables.service is enabled or running and would flush
# the whole ruleset (Meridian's tables with it) on reload (/etc/nftables.conf
# starts with a whole-ruleset flush) or on stop/restart (its ExecStop flushes).
m_nft_flush_risk() {
  local stop
  command -v systemctl >/dev/null 2>&1 || return 1
  systemctl is-enabled --quiet nftables.service 2>/dev/null || systemctl is-active --quiet nftables.service 2>/dev/null || return 1
  if [ -f /etc/nftables.conf ] && grep -qE '^[[:space:]]*flush[[:space:]]+ruleset' /etc/nftables.conf 2>/dev/null; then return 0; fi
  stop=$(systemctl show -p ExecStop --value nftables.service 2>/dev/null | tr -d '\n')
  case "$stop" in *flush*ruleset*) return 0 ;; esac
  return 1
}
# Re-validate, immediately before changing anything, what the preflight saw.
[ "$(id -u)" = 0 ] || m_refuse not_root 'provisioning needs root'
if m_nft_flush_risk; then
  m_refuse nftables_flush_on_reload 'nftables.service is enabled or running and flushes the whole ruleset on reload/stop; fix that first (see the preflight)'
fi
# The WAN interface the node's NAT, IPv6 drop, DOCKER-USER rules and sysctls
# name must exist and carry the default route(s) the node needs.
if [ -n "$M_WAN" ]; then
  ip link show "$M_WAN" >/dev/null 2>&1 || m_refuse wan_interface_missing "the WAN interface $M_WAN does not exist on this host; set wan_interface in the topology"
  for m_fam in $M_WAN_NEED; do
    case "$m_fam" in
      4|6) m_out=$(ip -"$m_fam" route show default 2>/dev/null | tr '\n' ' ') || m_out="" ;;
      *) m_out="$(ip -4 route show default 2>/dev/null | tr '\n' ' ') $(ip -6 route show default 2>/dev/null | tr '\n' ' ')" ;;
    esac
    case " $m_out " in
      *" dev $M_WAN "*) ;;
      *) m_refuse wan_no_default_route "the WAN interface $M_WAN does not carry the default route (IPv$m_fam) this node needs; set wan_interface in the topology" ;;
    esac
  done
fi
if [ -f "$M_JOURNAL" ] && ! grep -qx 'state done' "$M_JOURNAL" && ! grep -qx 'state compensated' "$M_JOURNAL" && ! grep -qx 'state withdrawn' "$M_JOURNAL"; then
  if grep -qx 'kind withdraw' "$M_JOURNAL"; then
    m_refuse withdraw_incomplete "an earlier withdraw did not finish (see $M_JOURNAL); finish it from the panel's deploy page"
  fi
  m_refuse previous_run_incomplete "an earlier run did not finish cleanly (see $M_JOURNAL)"
fi
case "$M_EXPECT" in
  none)
    [ ! -e "$M_MANIFEST" ] || m_refuse manifest_appeared 'a Meridian manifest appeared since the preflight'
    for i in $M_IFACES; do
      if ip link show "$i" >/dev/null 2>&1; then m_refuse interface_appeared "interface $i appeared since the preflight"; fi
    done
    for t in $M_NFT; do
      if command -v nft >/dev/null 2>&1 && nft list table inet "$t" >/dev/null 2>&1; then m_refuse nft_table_appeared "nft table inet $t appeared since the preflight"; fi
    done ;;
  same)
    if ! grep -qx "node $M_NODE" "$M_MANIFEST" 2>/dev/null || ! grep -qx "deployment $M_DEPLOYMENT" "$M_MANIFEST" 2>/dev/null; then
      m_refuse manifest_changed 'the Meridian manifest on this host no longer names this node and deployment'
    fi ;;
  *) m_refuse bad_expectation 'unknown expectation' ;;
esac
`

// compensateLib undoes a provision run from its work directory
// ($M_WORK: actions, backups and the pre-* state recorded by m_begin). It
// is shared by the provision script (trap on failure) and the withdraw
// script's journal mode (panel-driven recovery of an interrupted run), so
// both undo exactly the same way. It expects M_WORK, M_JOURNAL, M_DONE,
// M_EXPECT, M_IFACES, M_UNITS, M_NFT, M_TABLES, M_PRIOS, M_DSTS and M_ROOT
// (empty on a host). Every step is idempotent: running it again after a
// partial compensation only retries what is still there.
const compensateLib = compile.FWShellLib + `# m_fw_del_line FAM LINE: delete one tagged rule as -S printed it.
m_fw_del_line() {
  local tool
  local -a args
  tool=$(m_fw_tool "$1")
  case "$2" in "-A DOCKER-USER "*--comment*meridian-fw-*) ;; *) return 1 ;; esac
  set -f
  read -r -a args <<< "$2"
  set +f
  args[0]=-D
  "$tool" -w 5 "${args[@]}" >/dev/null 2>&1
}
m_note() { printf '%s\n' "$*" >> "$M_WORK/actions"; }
m_jot() { printf '%s\n' "$*" >> "$M_JOURNAL"; }
m_left() { echo "MERIDIAN_LEFTOVER $*"; m_jot "leftover $*"; M_LEFT=1; }
m_kept() { echo "MERIDIAN_KEPT $*"; m_jot "leftover $* (kept on purpose)"; }
m_pre_unit() { awk -v u="$1" -v c="$2" '$1==u {print $c}' "$M_WORK/pre-units"; }
m_compensate() {
  local rc=$?
  local kind p u i t fam line prio sel tbl d v
  trap - EXIT
  # The SSH session may be gone: ignore hangups and broken pipes so the
  # compensation runs to the end and lands in the journal.
  trap '' HUP INT TERM PIPE
  set +eu
  if [ "$M_DONE" = 1 ]; then exit "$rc"; fi
  [ "$rc" != 0 ] || rc=1
  echo "MERIDIAN_COMPENSATING exit=$rc"
  m_jot "failed exit $rc"
  for u in $M_UNITS; do
    if [ "$(m_pre_unit "$u" 2)" != enabled ]; then systemctl disable "$u" >/dev/null 2>&1; fi
    if [ "$(m_pre_unit "$u" 3)" != active ] && systemctl is-active --quiet "$u" 2>/dev/null; then
      systemctl stop "$u" >/dev/null 2>&1 || m_left unit "$u still running"
    fi
  done
  if grep -qx 'pkg smartdns' "$M_WORK/actions" 2>/dev/null; then
    systemctl disable --now smartdns.service >/dev/null 2>&1 || m_left unit 'smartdns.service still running'
  fi
  # An earlier version's smartdns.service this run stopped: back to how it was.
  if grep -qx 'unit-stopped smartdns.service' "$M_WORK/actions" 2>/dev/null; then
    if [ "$(m_pre_unit smartdns.service 2)" = enabled ]; then systemctl enable smartdns.service >/dev/null 2>&1 || m_left unit 'smartdns.service could not be re-enabled'; fi
    if [ "$(m_pre_unit smartdns.service 3)" = active ]; then systemctl start smartdns.service >/dev/null 2>&1 || m_left unit 'smartdns.service could not be restarted'; fi
  fi
  if grep -qx "file-new $M_ROOT/etc/meridian/mesh-sidecar.compose.yml" "$M_WORK/actions" 2>/dev/null && command -v docker >/dev/null 2>&1; then
    docker compose -f "$M_ROOT/etc/meridian/mesh-sidecar.compose.yml" down >/dev/null 2>&1 || m_left container 'mesh sidecar (docker compose down failed)'
  fi
  for i in $M_IFACES; do
    if ! grep -qx "$i" "$M_WORK/pre-links" && ip link show "$i" >/dev/null 2>&1; then
      ip link del "$i" >/dev/null 2>&1 || m_left interface "$i"
    fi
  done
  for t in $M_NFT; do
    if ! grep -qx "table inet $t" "$M_WORK/pre-nft" && nft list table inet "$t" >/dev/null 2>&1; then
      nft delete table inet "$t" >/dev/null 2>&1 || m_left nft "inet $t"
    fi
  done
  for fam in 4 6; do
    ip -"$fam" rule show 2>/dev/null | while IFS= read -r line; do
      grep -qxF -- "$line" "$M_WORK/pre-rule$fam" && continue
      prio=${line%%:*}
      sel=${line#*:}
      case " $M_PRIOS " in *" $prio "*) ;; *) continue ;; esac
      # shellcheck disable=SC2086
      ip -"$fam" rule del priority "$prio" $sel >/dev/null 2>&1 || m_left rule "IPv$fam $line"
    done
    for tbl in $M_TABLES; do
      if ! grep -Eq "table ($tbl|meridian_[a-z0-9_]+)( |\$)" "$M_WORK/pre-route$fam"; then
        ip -"$fam" route flush table "$tbl" >/dev/null 2>&1
      fi
    done
    ip -"$fam" route show table main 2>/dev/null | while IFS= read -r line; do
      grep -qxF -- "$line" "$M_WORK/pre-route$fam" && continue
      d=${line#blackhole }
      d=${d%% *}
      case " $M_DSTS " in *" $d "*) ;; *) continue ;; esac
      # shellcheck disable=SC2086
      ip -"$fam" route del $line >/dev/null 2>&1 || m_left route "IPv$fam $line"
    done
  done
  # Coexistence rules this run added (tagged, not there before it). An
  # update's previous rules are re-asserted by the restored meridian-up.sh.
  for fam in 4 6; do
    [ -f "$M_WORK/pre-fw$fam" ] || continue
    m_fw_tagged "$fam" | while IFS= read -r line; do
      grep -qxF -- "$line" "$M_WORK/pre-fw$fam" && continue
      m_fw_del_line "$fam" "$line" || m_left firewall "IPv$fam ${line#-A }"
    done
  done
  # A first install's record of the interfaces it switched to accept_ra=2
  # goes with it (their values are restored just below).
  if [ "$M_EXPECT" = none ]; then rm -f -- "$M_STATE/ra-accept"; fi
  while read -r p v; do
    [ -w "$p" ] || continue
    if [ "$(head -c 32 "$p")" != "$v" ]; then printf '%s\n' "$v" > "$p" 2>/dev/null || m_left sysctl "$p"; fi
  done < "$M_WORK/pre-sysctl"
  tac "$M_WORK/actions" 2>/dev/null | while read -r kind p; do
    case "$kind" in
      tmp) rm -f -- "$p" ;;
      file-new) rm -f -- "$p" || m_left file "$p" ;;
      file-replaced) cp -a -- "$M_WORK/backup$p" "$p" || m_left file "$p (backup in $M_WORK/backup$p)" ;;
      dir-new) [ ! -d "$p" ] || rmdir -- "$p" 2>/dev/null || m_left dir "$p" ;;
      pkg) m_kept package "$p" ;;
    esac
  done
  # A wstunnel unit this run restarted with new WSS files runs with what it
  # read at start: restart it on the restored files (it was active before).
  awk '$1=="unit-restarted" {print $2}' "$M_WORK/actions" 2>/dev/null | while read -r u; do
    if [ "$(m_pre_unit "$u" 3)" = active ]; then systemctl restart "$u" >/dev/null 2>&1 || m_left unit "$u could not be restarted on the restored WSS files"; fi
  done
  if [ "$M_EXPECT" = same ] && [ -x "$M_ROOT/usr/local/sbin/meridian-up.sh" ]; then
    if "$M_ROOT/usr/local/sbin/meridian-up.sh" >/dev/null 2>&1; then
      echo MERIDIAN_RESTORED_PREVIOUS
    else
      m_left runtime 'previous meridian-up.sh failed after the files were restored'
    fi
  fi
  if grep -q '^leftover ' "$M_JOURNAL" && grep -v 'kept on purpose' "$M_JOURNAL" | grep -q '^leftover '; then
    sed -i 's/^state running$/state incomplete/' "$M_JOURNAL"
    echo MERIDIAN_COMPENSATION_INCOMPLETE
  else
    sed -i 's/^state running$/state compensated/' "$M_JOURNAL"
    rm -rf "$M_WORK"
    echo MERIDIAN_COMPENSATED
  fi
  exit "$rc"
}
`

// provisionTxn opens the journal, tracks files and commits the manifest.
const provisionTxn = `m_begin() {
  install -d -m 700 "$M_STATE"
  rm -rf "$M_WORK"
  install -d -m 700 "$M_WORK" "$M_WORK/backup"
  printf 'meridian-node-journal 1\nstate running\nnode %s\ndeployment %s\nrun %s\nstarted %s\n' "$M_NODE" "$M_DEPLOYMENT" "$M_RUN" "$(date +%s)" > "$M_JOURNAL"
  : > "$M_WORK/actions"
  { ip -o link show 2>/dev/null || true; } | awk -F': ' '{print $2}' | sed 's/@.*//' > "$M_WORK/pre-links"
  { nft list tables 2>/dev/null || true; } > "$M_WORK/pre-nft"
  for fam in 4 6; do
    { ip -"$fam" rule show 2>/dev/null || true; } > "$M_WORK/pre-rule$fam"
    { ip -"$fam" route show table all 2>/dev/null || true; } > "$M_WORK/pre-route$fam"
  done
  # Only the keys this bundle may write (M_SYSCTL): the global forwarding
  # and redirect keys and the managed interfaces' keys. Interfaces created
  # by this run have nothing to record (they are deleted on failure).
  for f in $M_SYSCTL; do
    if [ -r "$f" ]; then printf '%s %s\n' "$f" "$(head -c 32 "$f")"; fi
  done > "$M_WORK/pre-sysctl"
  for fam in 4 6; do m_fw_tagged "$fam" > "$M_WORK/pre-fw$fam"; done
  # accept_ra of every interface meridian-up.sh may switch to 2 (RA-learned
  # routes now, or recorded by an earlier run).
  { ip -6 route show table main proto ra 2>/dev/null | awk '{for (i=1;i<NF;i++) if ($i=="dev") print $(i+1)}'; cat "$M_STATE/ra-accept" 2>/dev/null || true; } | sort -u | while read -r d; do
    case "$d" in ''|*[!A-Za-z0-9_.@-]*) continue ;; esac
    f=/proc/sys/net/ipv6/conf/$d/accept_ra
    if [ -r "$f" ]; then printf '%s %s\n' "$f" "$(head -c 32 "$f")"; fi
  done >> "$M_WORK/pre-sysctl" || true
  for u in $M_UNITS smartdns.service; do
    printf '%s %s %s\n' "$u" "$(systemctl is-enabled "$u" 2>/dev/null || true)" "$(systemctl is-active "$u" 2>/dev/null || true)"
  done > "$M_WORK/pre-units"
  # Written last: its presence means the pre-* state above is complete, so
  # a panel-driven recovery (withdraw script, journal mode) can compensate.
  # Without it, nothing of this run changed the host yet.
  printf 'ifaces %s\nunits %s\nnft %s\ntables %s\nprios %s\ndsts %s\nexpect %s\n' "$M_IFACES" "$M_UNITS" "$M_NFT" "$M_TABLES" "$M_PRIOS" "$M_DSTS" "$M_EXPECT" > "$M_WORK/params.next"
  mv -f "$M_WORK/params.next" "$M_WORK/params"
  trap m_compensate EXIT
  trap 'exit 129' HUP
  trap 'exit 130' INT
  trap 'exit 143' TERM
}
# m_track records whether a file is new or replaced (and backs it up) and
# which directories this run creates.
m_track() {
  local p=$1 d missing=""
  d=${p%/*}
  while [ -n "$d" ] && [ ! -d "$d" ]; do missing="$d $missing"; d=${d%/*}; done
  # Outermost first, so compensation (which replays in reverse) removes
  # the innermost directory first.
  for d in $missing; do m_note "dir-new $d"; done
  if [ -e "$p" ] || [ -L "$p" ]; then
    install -d -m 700 "$M_WORK/backup${p%/*}"
    cp -a -- "$p" "$M_WORK/backup$p"
    m_note "file-replaced $p"
  else
    m_note "file-new $p"
  fi
}
# m_changed: this run created the file, or replaced it with different content.
m_changed() {
  grep -qxF "file-new $1" "$M_WORK/actions" && return 0
  grep -qxF "file-replaced $1" "$M_WORK/actions" || return 1
  ! cmp -s -- "$M_WORK/backup$1" "$1"
}
# m_commit writes the ownership manifest (what the next preflight reads to
# tell "ours, same node" from everything else, and what a withdraw removes)
# and closes the journal.
m_commit() {
  local next=$M_MANIFEST.next p
  {
    echo 'meridian-node-manifest 1'
    echo "node $M_NODE"
    echo "deployment $M_DEPLOYMENT"
    echo "server $M_SERVER"
    echo "bundle $M_BUNDLE"
    echo "installed $(date +%s)"
    awk '$1=="file-new" || $1=="file-replaced" {print $2}' "$M_WORK/actions" | sort -u | while read -r p; do
      echo "file $p $(sha256sum -- "$p" | cut -c1-64)"
    done
    # Panel-delivered binaries this run kept (already the pinned digest)
    # are still installed files of this node.
    for p in $M_ARTPATHS; do
      grep -qE "^(file-new|file-replaced) $p\$" "$M_WORK/actions" || echo "file $p $(sha256sum -- "$p" | cut -c1-64)"
    done
    if [ -f "$M_MANIFEST" ]; then
      awk '$1=="file" || $1=="orphan" {print $2}' "$M_MANIFEST" | sort -u | while read -r p; do
        grep -qE "^(file-new|file-replaced) $p\$" "$M_WORK/actions" && continue
        case " $M_ARTPATHS " in *" $p "*) continue ;; esac
        echo "orphan $p"
      done
      grep '^pkg ' "$M_MANIFEST" || true
    fi
    printf '%s\n' "$M_ARTLINES" | while read -r p_name p_ver p_path p_sum; do
      # "|| true": a node that needs no panel-delivered binary has an empty
      # list, and a loop whose last test is false would fail the script
      # under "set -e" (seen on a real hub: the whole install was undone at
      # the very last step).
      if [ -n "$p_name" ]; then echo "artifact $p_name $p_ver $p_path $p_sum"; fi
    done
    for p in $M_IFACES; do echo "iface $p"; done
    for p in $M_UNITS; do echo "unit $p"; done
    for p in $M_NFT; do echo "nft inet $p"; done
    for p in $M_TABLES; do echo "table $p"; done
    for p in $M_PRIOS; do echo "prio $p"; done
    for p in $M_DSTS; do echo "route $p"; done
    if [ "$M_FW" = 1 ]; then echo 'fw ipv4 DOCKER-USER'; echo 'fw ipv6 DOCKER-USER'; fi
    awk '$1=="pkg" {print "pkg " $2}' "$M_WORK/actions"
  } > "$next"
  chmod 600 "$next"
  mv -f "$next" "$M_MANIFEST"
  sed -i 's/^state running$/state done/' "$M_JOURNAL"
  M_DONE=1
  rm -rf "$M_WORK"
  rmdir -- "$M_STAGE" 2>/dev/null || true
}
`

// packageInstall installs only what is missing, one package per missing
// command, and records each for the manifest (never removed on failure).
// --no-install-recommends: on Ubuntu 20.04 wireguard-tools recommends
// wireguard-dkms, which the 5.15 kernel does not need; nothing here
// installs iptables or changes its alternatives (the legacy backend stays).
const packageInstall = `m_need=""
command -v wg >/dev/null 2>&1 || m_need="$m_need wireguard-tools"
command -v nft >/dev/null 2>&1 || m_need="$m_need nftables"
command -v ip >/dev/null 2>&1 || m_need="$m_need iproute2"
if [ -n "$m_need" ]; then
  apt-get update -y
  # shellcheck disable=SC2086
  apt-get install -y --no-install-recommends $m_need
  for m_p in $m_need; do m_note "pkg $m_p"; done
fi
`

// resolverBindsTunnelOnly: the resolver config has at least one bind and
// none on a wildcard address (SmartDNS binds [::]:53 when none is given).
func resolverBindsTunnelOnly(fp preflight.Footprint) bool {
	n := 0
	for _, l := range fp.Listens {
		if l.Owner != "smartdns" {
			continue
		}
		if l.Wildcard {
			return false
		}
		n++
	}
	return n > 0
}

// artifactCheck and artifactInstall verify and install a panel-delivered
// binary. m_art_check runs before the journal opens (a refusal changes
// nothing): a staged copy must have the pinned digest (a wrong one is
// deleted), the host path must not be somebody else's file; a kept copy
// must still have the pinned digest. m_art_install runs inside the
// transaction: the old file is backed up by m_track, the new one is copied
// next to its destination, checked again and renamed into place.
const artifactLib = `m_art_check() {
  local name=$1 path=$2 sum=$3 mode=$4 got f
  if [ "$mode" = staged ]; then
    f=$M_STAGE/$name
    if [ ! -f "$f" ] || [ -L "$f" ]; then m_refuse artifact_missing "the panel-delivered $name was not staged at $f"; fi
    got=$(sha256sum -- "$f" | cut -c1-64)
    if [ "$got" != "$sum" ]; then rm -f -- "$f"; m_refuse artifact_digest_mismatch "the staged $name has SHA-256 $got, pinned $sum"; fi
    if [ -e "$path" ] || [ -L "$path" ]; then
      if [ "$M_EXPECT" != same ] || ! grep -q "^file $path " "$M_MANIFEST" 2>/dev/null; then
        m_refuse artifact_path_foreign "$path exists and is not recorded in the Meridian manifest"
      fi
    fi
  else
    if [ ! -f "$path" ] || [ -L "$path" ]; then m_refuse artifact_missing "$path is gone since the preflight"; fi
    got=$(sha256sum -- "$path" | cut -c1-64)
    if [ "$got" != "$sum" ]; then m_refuse artifact_changed "$path has SHA-256 $got since the preflight, pinned $sum"; fi
  fi
}
m_art_install() {
  local name=$1 path=$2 sum=$3 tmp
  m_track "$path"
  install -d -m 755 "${path%/*}"
  tmp=$(mktemp "${path%/*}/.meridian.XXXXXX")
  m_note tmp "$tmp"
  cp -- "$M_STAGE/$name" "$tmp"
  chmod 755 "$tmp"
  if [ "$(sha256sum -- "$tmp" | cut -c1-64)" != "$sum" ]; then
    echo "meridian: $name changed while it was installed; nothing was activated" >&2
    exit 1
  fi
  mv -f "$tmp" "$path"
  rm -f -- "$M_STAGE/$name"
}
`

// legacySmartDNSStop: a node an earlier version provisioned ran the
// distribution's smartdns.service (manifest "pkg smartdns": Meridian
// installed the package). It holds the tunnel addresses' port 53, so it is
// stopped and disabled before the panel-delivered resolver starts; a
// failed run restores its previous state (m_compensate). The package stays
// installed. A smartdns.service Meridian did not install is never touched
// (the preflight refuses a foreign config at /etc/smartdns/smartdns.conf).
const legacySmartDNSStop = `if [ "$M_EXPECT" = same ] && grep -qx 'pkg smartdns' "$M_MANIFEST" 2>/dev/null && command -v systemctl >/dev/null 2>&1; then
  if systemctl is-active --quiet smartdns.service 2>/dev/null || systemctl is-enabled --quiet smartdns.service 2>/dev/null; then
    m_note "unit-stopped smartdns.service"
    systemctl disable --now smartdns.service >/dev/null 2>&1 || { echo 'meridian: could not stop the previous smartdns.service' >&2; exit 1; }
  fi
fi
`

// smartDNSStart runs after meridian-up.sh, when the tunnel addresses the
// resolver binds to exist. meridian-up.sh on exits restarts it already; this
// proves the unit is active. A resolver that does not come up fails the run
// (compensated): the node is never reported as working without it.
const smartDNSStart = `if [ -d /run/systemd/system ] && command -v systemctl >/dev/null 2>&1; then
  systemctl enable ` + compile.SmartDNSUnit + ` >/dev/null 2>&1 || true
  if ! systemctl is-active --quiet ` + compile.SmartDNSUnit + `; then
    systemctl restart ` + compile.SmartDNSUnit + `
  fi
  if ! systemctl is-active --quiet ` + compile.SmartDNSUnit + `; then
    echo '` + compile.SmartDNSUnit + ` is not active after provision' >&2
    systemctl status --no-pager ` + compile.SmartDNSUnit + ` >&2 || true
    exit 1
  fi
  echo MERIDIAN_SMARTDNS_ACTIVE
else
  echo 'no systemd: the exit resolver cannot run' >&2
  exit 1
fi
`

// artifactUnits are the units of files whose ExecStart runs name.
func artifactUnits(files map[string]string, name string) []string {
	var out []string
	needle := "ExecStart=" + artifacts.HostPath(name)
	for p, body := range files {
		if strings.HasPrefix(p, "/etc/systemd/system/") && strings.Contains(body, needle) {
			out = append(out, strings.TrimPrefix(p, "/etc/systemd/system/"))
		}
	}
	sort.Strings(out)
	return out
}

type wssUnit struct {
	unit  string
	files []string
}

// wssUnitFiles maps each wstunnel unit of files to the files it reads.
func wssUnitFiles(files map[string]string) []wssUnit {
	var out []wssUnit
	srv := "/etc/systemd/system/" + compile.WSSServerUnit
	if _, ok := files[srv]; ok {
		out = append(out, wssUnit{unit: compile.WSSServerUnit, files: []string{srv, compile.WSSServerYAML, compile.WSSServerCert, compile.WSSServerKey}})
	}
	var links []string
	for p := range files {
		name := strings.TrimPrefix(p, "/etc/systemd/system/")
		if name != p && strings.HasPrefix(name, "wstunnel-client-") && strings.HasSuffix(name, ".service") {
			links = append(links, strings.TrimSuffix(strings.TrimPrefix(name, "wstunnel-client-"), ".service"))
		}
	}
	sort.Strings(links)
	for _, l := range links {
		out = append(out, wssUnit{unit: compile.WSSClientUnit(l), files: []string{"/etc/systemd/system/" + compile.WSSClientUnit(l), compile.WSSClientEnv(l), compile.WSSClientTrust(l)}})
	}
	return out
}

// needsSecrets reports whether any file still carries a credential-store
// placeholder or an unresolved WSS token (a preview).
func needsSecrets(files map[string]string) bool {
	for _, body := range files {
		if model.SecretPlaceholderRe.MatchString(body) || compile.HasWSSTokens(body) {
			return true
		}
	}
	return false
}

// FilesFor returns host paths (no nodes/<id> prefix) for one node.
func FilesFor(bundle map[string]string, nodeID string) map[string]string {
	prefix := "nodes/" + nodeID + "/"
	out := map[string]string{}
	for path, body := range bundle {
		if strings.HasPrefix(path, prefix) {
			out["/"+strings.TrimPrefix(path, prefix)] = body
		}
	}
	return out
}

// InjectPrivate replaces the placeholder in WireGuard configs. It fails when a
// config needs a key and private is empty or malformed, so a caller never
// ships a placeholder to a host.
//
// A remote-access secret placeholder (gateway only) is refused: SSH
// provisioning never carries credential-store secrets.
func InjectPrivate(files map[string]string, private string) (map[string]string, error) {
	return InjectPrivateWSS(files, private, nil)
}

// InjectPrivateWSS is InjectPrivate plus the node's WSS secrets (path
// prefixes, the listener's private key). Only WSS secrets are accepted;
// any other credential-store id (remote-access keys) is never passed to
// a remote node, so a placeholder naming one is refused.
func InjectPrivateWSS(files map[string]string, private string, wss map[string]string) (map[string]string, error) {
	out, err := apply.InjectPrivateKeys(files, private)
	if err != nil {
		return nil, err
	}
	only := map[string]string{}
	for id, v := range wss {
		if apply.IsWSSSecretID(id) {
			only[id] = v
		}
	}
	for p, body := range out {
		v, err := apply.InjectSecrets(strings.TrimPrefix(p, "/"), body, only)
		if err != nil {
			return nil, err
		}
		out[p] = v
	}
	return out, nil
}

// KeyPolicy says how ResolveNodeKey may obtain a node's WireGuard key.
type KeyPolicy int

const (
	// KeyReuse uses the stored private key and fails when there is none
	// (remote provision with generate_keys=false, local rollback).
	KeyReuse KeyPolicy = iota
	// KeyGenerateIfMissing reuses a stored key, or generates one on the first
	// install when the node has neither a private nor a public key. A node
	// with only a public key fails: its private half lives elsewhere.
	KeyGenerateIfMissing
	// KeyRotate always generates a new pair (remote generate_keys=true).
	KeyRotate
)

// ResolveNodeKey returns the node's private key under policy. When it
// generates a key or fills in a missing public key, t is updated in place and
// changed is true; the caller must persist t. Errors never contain the key.
func ResolveNodeKey(t *model.Topology, nodeID string, policy KeyPolicy) (key string, changed bool, err error) {
	idx := -1
	for i := range t.Nodes {
		if t.Nodes[i].ID == nodeID {
			idx = i
			break
		}
	}
	if idx < 0 {
		return "", false, fmt.Errorf("节点 %s 不存在", nodeID)
	}
	n := &t.Nodes[idx]
	stored := strings.TrimSpace(n.PrivateKey)
	if stored == "***" {
		stored = ""
	}
	if policy != KeyRotate && stored != "" {
		pub, err := PublicFromPrivate(stored)
		if err != nil {
			return "", false, fmt.Errorf("节点 %s 已保存的私钥无效: %w", nodeID, err)
		}
		if strings.TrimSpace(n.PublicKey) == "" {
			n.PublicKey = pub
			return stored, true, nil
		}
		if strings.TrimSpace(n.PublicKey) != pub {
			return "", false, fmt.Errorf("节点 %s 已保存的私钥与公钥不匹配，拒绝安装", nodeID)
		}
		return stored, false, nil
	}
	switch policy {
	case KeyReuse:
		return "", false, fmt.Errorf("节点 %s 没有已保存的 WireGuard 私钥；首次装机请生成密钥", nodeID)
	case KeyGenerateIfMissing:
		if strings.TrimSpace(n.PublicKey) != "" {
			return "", false, fmt.Errorf("节点 %s 只有公钥没有私钥；请在拓扑中补私钥或清空公钥后重新生成", nodeID)
		}
	}
	kp, err := GenerateKeypair()
	if err != nil {
		return "", false, err
	}
	n.PrivateKey = kp.Private
	n.PublicKey = kp.Public
	return kp.Private, true, nil
}

// PublicFromPrivate derives the WireGuard public key.
func PublicFromPrivate(private string) (string, error) {
	if !apply.ValidPrivateKey(private) {
		return "", apply.ErrBadPrivateKey
	}
	raw, _ := base64.StdEncoding.DecodeString(private)
	pub, err := curve25519.X25519(raw, curve25519.Basepoint)
	if err != nil {
		return "", apply.ErrBadPrivateKey
	}
	return base64.StdEncoding.EncodeToString(pub), nil
}

// Redact hides private keys in a script before it is shown in the panel.
func Redact(script, private string) string {
	return apply.RedactSecret(script, private)
}

// SSH execution lives in internal/sshexec: provisioning connects only
// through a managed server with a stored credential and a confirmed host
// key. This package builds the script and never dials.

func safeHostPath(p string) (string, bool) {
	if !strings.HasPrefix(p, "/") || strings.Contains(p, "..") || strings.ContainsAny(p, "\r\n\x00") {
		return "", false
	}
	clean := path.Clean(p)
	if clean != p || !apply.HostPathAllowed(clean) {
		return "", false
	}
	return clean, true
}

func oneLine(s string) string {
	s = strings.ReplaceAll(s, "\r", " ")
	s = strings.ReplaceAll(s, "\n", " ")
	return s
}

func heredocDelim(body string) string {
	delim := "MERIDIAN_EOF"
	for strings.Contains(body, delim) {
		var buf [6]byte
		if _, err := rand.Read(buf[:]); err != nil {
			return "MERIDIAN_EOF_FALLBACK"
		}
		delim = "MERIDIAN_EOF_" + hex.EncodeToString(buf[:])
	}
	return delim
}

func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

func dirOf(p string) string {
	i := strings.LastIndex(p, "/")
	if i <= 0 {
		return "/"
	}
	return p[:i]
}

func ensureNL(s string) string {
	if strings.HasSuffix(s, "\n") {
		return s
	}
	return s + "\n"
}

func sortStrings(s []string) {
	for i := 1; i < len(s); i++ {
		j := i
		for j > 0 && s[j] < s[j-1] {
			s[j], s[j-1] = s[j-1], s[j]
			j--
		}
	}
}
