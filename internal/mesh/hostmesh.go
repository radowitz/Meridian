package mesh

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/radowitz/meridian/internal/model"
)

// ActDetect is the fixed, read-only detection of a host-level Cloudflare
// Mesh node (DetectScript). It writes nothing on the host.
const ActDetect Action = "detect"

// The host-level Linux connector (docs/architecture.md「主机级 Mesh 节点」).
const (
	// ConnectorMinMemMB: MemAvailable needed to install and run the
	// host-level WARP client. An estimate, not a measurement: warp-svc
	// resident roughly 60-100 MB plus apt during the install about 50 MB.
	ConnectorMinMemMB = 160
	// ConnectorMemNote says what ConnectorMinMemMB is.
	ConnectorMemNote = "估计值（未实机测量）：warp-svc 常驻约 60–100 MB，安装时 apt 另需约 50 MB；依赖的桌面库另占磁盘约数百 MB（估计），撤回时全部移除"
	// warpMark is the fwmark the WARP client excludes from its table.
	warpMark = "0x100cf"
	// warpTable is the routing table the Linux client uses.
	warpTable = 65743

	// Fixed official package source; nothing of it comes from a request.
	RepoURL     = "https://pkg.cloudflareclient.com/"
	RepoKeyURL  = "https://pkg.cloudflareclient.com/pubkey.gpg"
	RepoKeyring = "/usr/share/keyrings/cloudflare-warp-archive-keyring.gpg"
	RepoList    = "/etc/apt/sources.list.d/cloudflare-client.list"
	PackageName = "cloudflare-warp"
	ServiceName = "warp-svc.service"

	// RepoKeyFingerprintEnv names an operator override (environment of the
	// panel process, never a request field) for the signing key's
	// fingerprint. Unset: RepoKeyFingerprintDefault is used. Set but
	// malformed: every install is blocked.
	RepoKeyFingerprintEnv = "MERIDIAN_CF_REPO_KEY_FPR"

	// RepoKeyFingerprintDefault is the primary key of "Cloudflare Package
	// Repository <support@cloudflare.com>" served at RepoKeyURL, checked on
	// 2026-11-16: key id 6E2DD2174FA1C3BA, created 2021-12-05 (the
	// repository's published RPM key label gpg-pubkey(4fa1c3ba-61abda35)
	// names the same key and creation time); its 2025 re-signing removed the
	// expiry without changing the fingerprint. The install script refuses a
	// downloaded key whose primary fingerprint differs.
	RepoKeyFingerprintDefault = "C068A2B5771775193CBE1F2F6E2DD2174FA1C3BA"
)

var fprRe = regexp.MustCompile(`^[0-9A-F]{40}$`)

// RepoKeyFingerprint is the pinned signing key fingerprint (40 upper-case
// hex characters), or "" when it is not configured or malformed.
func RepoKeyFingerprint() string {
	raw, set := os.LookupEnv(RepoKeyFingerprintEnv)
	if !set || strings.TrimSpace(raw) == "" {
		return RepoKeyFingerprintDefault
	}
	v := strings.ToUpper(strings.ReplaceAll(strings.TrimSpace(raw), " ", ""))
	if !fprRe.MatchString(v) {
		return ""
	}
	return v
}

// Supported systems of the connector install (apt-based, two arches).
var (
	supportedOS   = map[string]bool{"debian": true, "ubuntu": true}
	supportedArch = map[string]bool{"x86_64": true, "amd64": true, "aarch64": true, "arm64": true}
)

// DetectScript is the fixed read-only detection. It takes no parameter: no
// caller input reaches the host. Every value it prints is filtered to a small
// charset and length on the host and parsed strictly by ParseHostMesh.
func DetectScript() string {
	return `#!/bin/bash
# Meridian Mesh host detection, fixed and read-only: it changes nothing.
set -u
export LC_ALL=C
o() { printf 'MESHHOST %s %s\n' "$1" "$(printf '%s' "$2" | tr -cd 'A-Za-z0-9._:/@+=, -' | cut -c1-160)"; }
t() { if command -v timeout >/dev/null 2>&1; then timeout 5 "$@"; else "$@"; fi; }
svc=stopped
# Only a host-level warp-svc counts: one in a container (the panel's own
# sidecar) is not a host node.
for p in $(pgrep -x warp-svc 2>/dev/null); do
  grep -qE 'docker|containerd|libpod|kubepods' "/proc/$p/cgroup" 2>/dev/null || svc=running
done
if [ "$svc" = stopped ] && systemctl is-active --quiet warp-svc.service 2>/dev/null; then svc=running; fi
o svc "$svc"
if command -v warp-cli >/dev/null 2>&1; then
  o cli present
  o status "$(t warp-cli --accept-tos status 2>&1 | head -n 4 | tr '\n' ' ')"
  t warp-cli --accept-tos settings 2>/dev/null | grep -iE '^[[:space:]]*\(?[a-z ]*\)?[[:space:]]*mode' | head -n 2 | while IFS= read -r l; do o mode "$l"; done
  t warp-cli --accept-tos registration show 2>/dev/null | grep -iE '^[[:space:]]*(account id|account type|organization)' | head -n 3 | while IFS= read -r l; do o reg "$l"; done
else
  o cli absent
fi
ip -o -4 addr show 2>/dev/null | awk '{print $2, $4}' | while read -r i a; do
  case "$a" in 100.*) o addr "$i $a";; esac
done
# Policy rules of both families, read in full: the host keeps the rules
# that are WARP's (its fwmark) and every rule into a table those rules look
# up (table 65743 always counts), so ordinary rules cannot push a WARP rule
# out of the output. A failed read or more relevant rules than printed is
# reported and blocks. wt4/wt6 carry the same WARP table set to the default
# route filter below.
wt4="65743"; wt6="65743"
for f in 4 6; do
  if ! rr=$(ip -N -$f rule show 2>/dev/null); then o ruleread "$f fail"; continue; fi
  if ! a=$(printf '%s\n' "$rr" | awk '
    { gsub(/\t/, " "); L[NR] = $0 }
    tolower($0) ~ /fwmark (0x0*100cf|65743)([\/ ]|$)/ { for (i = 1; i < NF; i++) if ($i == "lookup" || $i == "table") T[$(i+1)] = 1 }
    END {
      T["65743"] = 1; tl = ""; for (t in T) tl = tl " " t; print "T" tl
      for (k = 1; k <= NR; k++) { l = L[k]; m = (tolower(l) ~ /fwmark (0x0*100cf|65743)([\/ ]|$)/)
        nf = split(l, w, " "); for (i = 1; i < nf; i++) if ((w[i] == "lookup" || w[i] == "table") && (w[i+1] in T)) m = 1
        if (m) { n++; if (length(l) > 150) long++; if (n <= 64) print "R " l } }
      print "L " long+0
      print "C " n+0
      for (k = 1; k <= NR; k++) if (L[k] ~ /(lookup|table) [A-Za-z_]/) { print "N"; break } }'); then o ruleread "$f fail"; continue; fi
  c=""
  while IFS= read -r l; do
    case "$l" in
      "T "*) if [ "$f" = 4 ]; then wt4=${l#T }; else wt6=${l#T }; fi; o warptables "$f ${l#T }";;
      "L "*) [ "${l#L }" -gt 0 ] && o rulelong "$f ${l#L }";;
      "R "*) o rule "$f ${l#R }";;
      "C "*) c=${l#C };;
      N) o rulenamed "$f";;
    esac
  done <<EOF3
$a
EOF3
  case "$c" in
    "") o ruleread "$f fail";;
    *) [ "$c" -gt 64 ] && o ruletrunc "$f $c";;
  esac
done
# Default routes of both families in every table: WARP taking over the
# default traffic in either family (its table or a default via its
# interface) blocks. The host filters all default routes down to the
# relevant ones (via CloudflareWARP or a 100.x Mesh interface, or in table
# 65743 or a table WARP's mark rules look up), so ordinary exit/region
# tables cannot push a WARP route out of the output. A failed read or more
# relevant routes than printed is reported and blocks.
devs="CloudflareWARP $(ip -o -4 addr show 2>/dev/null | awk '$4 ~ /^100\./ {print $2}' | tr '\n' ' ')"
for f in 4 6; do
  if ! r=$(ip -N -$f route show table all 2>/dev/null); then o defread "$f fail"; continue; fi
  if [ "$f" = 4 ]; then tb="$wt4"; else tb="$wt6"; fi
  if ! a=$(printf '%s\n' "$r" | awk -v tb="$tb" -v dv="$devs" '
    BEGIN { split(tb, x, " "); for (i in x) T[x[i]] = 1; split(dv, y, " "); for (i in y) D[y[i]] = 1 }
    /^default / { m = 0; for (i = 2; i < NF; i++) { if ($i == "table" && ($(i+1) in T)) m = 1; if ($i == "dev" && ($(i+1) in D)) m = 1 }
      if (m) { n++; if (n <= 32) print "M " $0 } }
    END { print "C " n+0 }'); then o defread "$f fail"; continue; fi
  c=""
  while IFS= read -r l; do
    case "$l" in
      "M "*) o default "$f ${l#M }";;
      "C "*) c=${l#C };;
    esac
  done <<EOF2
$a
EOF2
  case "$c" in
    "") o defread "$f fail";;
    *) [ "$c" -gt 32 ] && o deftrunc "$f $c";;
  esac
done
if command -v docker >/dev/null 2>&1; then
  o docker present
  docker compose version >/dev/null 2>&1 && o compose present
fi
o memavail "$(awk '/^MemAvailable:/{print $2}' /proc/meminfo 2>/dev/null)"
# Install prerequisites, read on the host itself. The source check is one
# HEAD-less download of the fixed signing key to /dev/null.
o os "$( (. /etc/os-release 2>/dev/null; printf '%s %s' "${ID:-unknown}" "${VERSION_CODENAME:-}") )"
o arch "$(uname -m 2>/dev/null)"
command -v apt-get >/dev/null 2>&1 && o apt present
command -v systemctl >/dev/null 2>&1 && o systemd present
if command -v curl >/dev/null 2>&1; then
  o repo "$(t curl -s -o /dev/null -w '%{http_code}' --max-time 5 ` + RepoKeyURL + ` 2>/dev/null || true)"
else
  o repo nocurl
fi
o done 1
`
}

// Reserved are the policy-routing resources Meridian uses on a node.
type Reserved struct {
	Tables     []int
	Marks      []string
	Priorities []int
}

var (
	hostLineRe  = regexp.MustCompile(`^MESHHOST ([a-z]+) ?(.*)$`)
	acctIDRe    = regexp.MustCompile(`(?i)^\s*account id\s*:\s*([0-9a-f]{32})\s*$`)
	addrLineRe  = regexp.MustCompile(`^([A-Za-z0-9_.-]{1,15}) ([0-9./]{9,18})$`)
	ruleLineRe  = regexp.MustCompile(`^([46]) ([0-9]{1,5}):\s*(.*)$`)
	ruleMarkRe  = regexp.MustCompile(`fwmark (0x[0-9a-fA-F]+|[0-9]+)(/0x[0-9a-fA-F]+)?`)
	ruleTableRe = regexp.MustCompile(`lookup ([0-9]+)\b`)
	defTableRe  = regexp.MustCompile(`table ([0-9]+)\b`)
	// namedTableRe: a table given by name (ip without -N, or a host whose
	// ip ignores it). Names cannot be mapped to numbers here, so it blocks.
	namedTableRe = regexp.MustCompile(`\b(?:lookup|table) [A-Za-z_][A-Za-z0-9_.-]*`)
)

func normMark(m string) string {
	m = strings.ToLower(m)
	if i := strings.Index(m, "/"); i >= 0 {
		m = m[:i]
	}
	base := 10
	if strings.HasPrefix(m, "0x") {
		base, m = 16, m[2:]
	}
	n, err := strconv.ParseUint(m, base, 32)
	if err != nil {
		return ""
	}
	return fmt.Sprintf("0x%x", n)
}

func intIn(xs []int, v int) bool {
	for _, x := range xs {
		if x == v {
			return true
		}
	}
	return false
}

// ParseHostMesh evaluates the output of DetectScript. account is the
// Cloudflare account ID of the Mesh account selected in the panel ("" when
// none is selected); res are Meridian's resources on that node.
func ParseHostMesh(out, account string, res Reserved) model.HostMeshDetection {
	d := model.HostMeshDetection{State: model.HostMeshFailed, Mode: "unknown", Account: model.AccountUnknown, MemAvailMB: -1, Reasons: []string{}, Origin: model.MeshOriginNone}
	d.Coexist = model.HostMeshCoexist{OK: true, WARPRules: []string{}, Tables: []int{}, Conflicts: []string{}}
	cgnat := netip.MustParsePrefix(model.MeshCGNAT)
	var modes, regs []string
	var rules [][3]string // family, prio, rest
	var defaults, defBad []string
	hostWarpTables := map[int]bool{}
	done := false
	for _, raw := range strings.Split(out, "\n") {
		m := hostLineRe.FindStringSubmatch(strings.TrimRight(raw, "\r"))
		if m == nil {
			continue
		}
		k, v := m[1], strings.TrimSpace(m[2])
		switch k {
		case "svc":
			d.WarpSvc = v == "running"
		case "cli":
			d.WarpCLI = v == "present"
		case "status":
			d.Status = v
		case "mode":
			modes = append(modes, v)
		case "reg":
			regs = append(regs, v)
		case "addr":
			a := addrLineRe.FindStringSubmatch(v)
			if a == nil || !ifaceName(strings.ToLower(a[1])) && a[1] != "CloudflareWARP" {
				continue
			}
			p, err := netip.ParsePrefix(a[2])
			if err != nil || !p.Addr().Is4() || !cgnat.Contains(p.Addr()) || d.MeshAddr != "" {
				continue
			}
			d.MeshAddr, d.Iface = p.Addr().String(), a[1]
		case "rule":
			if namedTableRe.MatchString(v) {
				defBad = append(defBad, "策略规则里有非数字的路由表名，无法确认共存")
			}
			if r := ruleLineRe.FindStringSubmatch(v); r != nil {
				rules = append(rules, [3]string{r[1], r[2], r[3]})
			}
		case "default":
			if namedTableRe.MatchString(v) {
				defBad = append(defBad, "默认路由里有非数字的路由表名，无法确认 WARP 没有接管默认流量")
			}
			defaults = append(defaults, v)
		case "warptables":
			// The host's own complete WARP table set (from every rule, so a
			// rule cut by the line limit cannot hide its table).
			f := strings.Fields(v)
			for _, x := range f[min(1, len(f)):] {
				if n, err := strconv.Atoi(x); err == nil && n > 0 {
					hostWarpTables[n] = true
				} else {
					defBad = append(defBad, "WARP 规则查询的路由表不是数字表号（"+x+"），无法确认共存")
				}
			}
		case "rulenamed":
			defBad = append(defBad, "IPv"+strings.TrimSpace(v)+" 策略规则里有非数字的路由表名，无法确认共存")
		case "rulelong":
			f := strings.Fields(v)
			fam := "?"
			if len(f) > 0 {
				fam = f[0]
			}
			defBad = append(defBad, "IPv"+fam+" 有与 WARP 相关的策略规则超过输出长度上限，内容不完整，无法确认共存")
		case "ruleread", "ruletrunc":
			// A family's policy rules could not be read in full: WARP's
			// tables and rule conflicts cannot be known, so coexistence
			// cannot pass.
			f := strings.Fields(v)
			fam := "?"
			if len(f) > 0 {
				fam = f[0]
			}
			why := "读不到 IPv" + fam + " 策略规则，无法确认 WARP 的规则与路由表"
			if k == "ruletrunc" {
				why = "IPv" + fam + " 与 WARP 相关的策略规则太多（" + strings.Join(f[1:], "") + " 条），输出被截断，无法确认共存"
			}
			defBad = append(defBad, why)
		case "defread", "deftrunc":
			// A family's default routes could not be read in full: the
			// takeover check cannot pass.
			f := strings.Fields(v)
			fam := "?"
			if len(f) > 0 {
				fam = f[0]
			}
			why := "读不到 IPv" + fam + " 默认路由，无法确认 WARP 没有接管默认流量"
			if k == "deftrunc" {
				why = "IPv" + fam + " 相关默认路由太多（" + strings.Join(f[1:], "") + " 条），输出被截断，无法确认 WARP 没有接管默认流量"
			}
			defBad = append(defBad, why)
		case "docker":
			d.Docker = v == "present"
		case "compose":
			d.Compose = v == "present"
		case "memavail":
			if kb, err := strconv.Atoi(v); err == nil && kb >= 0 {
				d.MemAvailMB = kb / 1024
			}
		case "os":
			f := strings.Fields(v)
			if len(f) > 0 {
				d.OS = strings.ToLower(f[0])
			}
			if len(f) > 1 {
				d.Codename = strings.ToLower(f[1])
			}
		case "arch":
			d.Arch = v
		case "apt":
			d.Apt = v == "present"
		case "systemd":
			d.Systemd = v == "present"
		case "repo":
			switch {
			case v == "200":
				d.RepoReach = "ok"
			case v == "nocurl" || v == "":
				d.RepoReach = "unknown"
			default:
				d.RepoReach = "unreachable"
			}
		case "done":
			done = v == "1"
		}
	}
	if !done {
		d.Reasons = append(d.Reasons, "检测输出不完整（没有结束标记），不能判断这台主机")
		return d
	}
	// Mode: wording of warp-cli settings is not specified; recognise words.
	for _, l := range modes {
		ll := strings.ToLower(l)
		switch {
		case strings.Contains(ll, "connector"):
			d.Mode = "connector"
		case strings.Contains(ll, "mesh"):
			d.Mode = "mesh"
		case strings.Contains(ll, "proxy"):
			d.Mode = "proxy"
		case strings.Contains(ll, "warp") && d.Mode == "unknown":
			d.Mode = "warp"
		}
	}
	// Account.
	var org string
	for _, l := range regs {
		if a := acctIDRe.FindStringSubmatch(l); a != nil {
			d.AccountID = strings.ToLower(a[1])
		} else if i := strings.Index(l, ":"); i > 0 && strings.EqualFold(strings.TrimSpace(l[:i]), "organization") {
			org = strings.TrimSpace(l[i+1:])
		}
	}
	switch {
	case !d.WarpCLI:
		d.AccountReason = "主机上没有 warp-cli，读不到账户"
	case d.AccountID == "" && org != "":
		d.AccountReason = "warp-cli 只给出组织名「" + org + "」，没有账户 ID，无法与面板选定的账户比对"
	case d.AccountID == "":
		d.AccountReason = "warp-cli 没有给出账户 ID（未注册或该版本不显示），无法比对"
	case account == "":
		d.AccountReason = "面板还没有选定 Mesh 账户，无法比对"
	case strings.EqualFold(account, d.AccountID):
		d.Account = model.AccountMatched
	default:
		d.Account = model.AccountMismatch
		d.AccountReason = "主机所在的 Mesh 账户与面板选定的账户不一致"
	}
	// Coexistence: WARP's rules are those excluding its mark, and any other
	// rule into the tables they use.
	warpTables := map[int]bool{}
	for _, r := range rules {
		if mk := ruleMarkRe.FindStringSubmatch(r[2]); mk != nil && normMark(mk[1]) == warpMark {
			if t := ruleTableRe.FindStringSubmatch(r[2]); t != nil {
				n, _ := strconv.Atoi(t[1])
				warpTables[n] = true
			}
		}
	}
	for n := range hostWarpTables {
		if n != warpTable {
			warpTables[n] = true
		}
	}
	res.Tables = append(append([]int(nil), res.Tables...), SidecarTable)
	for _, r := range rules {
		t := ruleTableRe.FindStringSubmatch(r[2])
		mk := ruleMarkRe.FindStringSubmatch(r[2])
		isWarp := mk != nil && normMark(mk[1]) == warpMark
		if t != nil {
			n, _ := strconv.Atoi(t[1])
			isWarp = isWarp || warpTables[n] || n == warpTable
		}
		if !isWarp {
			continue
		}
		d.Coexist.WARPRules = append(d.Coexist.WARPRules, "IPv"+r[0]+" "+r[1]+": "+r[2])
		if p, _ := strconv.Atoi(r[1]); intIn(res.Priorities, p) {
			d.Coexist.Conflicts = append(d.Coexist.Conflicts, fmt.Sprintf("Meridian 也用规则优先级 %d", p))
		}
	}
	for n := range warpTables {
		d.Coexist.Tables = append(d.Coexist.Tables, n)
		if intIn(res.Tables, n) {
			d.Coexist.Conflicts = append(d.Coexist.Conflicts, fmt.Sprintf("Meridian 也用路由表 %d", n))
		}
	}
	sort.Ints(d.Coexist.Tables)
	for _, m := range res.Marks {
		if normMark(m) == warpMark {
			d.Coexist.Conflicts = append(d.Coexist.Conflicts, "Meridian 的标记 "+warpMark+" 与 WARP 相同")
			break
		}
	}
	// Default routes, both families: a default route in a WARP table
	// (its fixed table always counts) or one via the WARP interface in any
	// table is WARP taking over the host's default traffic.
	seenDef := map[string]bool{}
	for _, l := range defaults {
		fam := "4"
		if f := strings.Fields(l); len(f) > 0 && (f[0] == "4" || f[0] == "6") {
			fam, l = f[0], strings.TrimSpace(l[1:])
		}
		var why string
		if t := defTableRe.FindStringSubmatch(l); t != nil {
			if n, _ := strconv.Atoi(t[1]); warpTables[n] || n == warpTable {
				why = fmt.Sprintf("WARP 的表 %d 有 IPv%s 默认路由（全局模式）：经隧道进来的出口流量会从 WARP 出去，而不是本机上联", n, fam)
			}
		}
		if why == "" && warpDefaultDev(l, d.Iface) {
			why = "IPv" + fam + " 默认路由经 WARP 接口（全局模式）：主机默认流量被 WARP 接管"
		}
		if why != "" && !seenDef[why] {
			seenDef[why] = true
			d.Coexist.GlobalDefault = true
			d.Coexist.Conflicts = append(d.Coexist.Conflicts, why)
		}
	}
	for _, why := range defBad {
		if !seenDef[why] {
			seenDef[why] = true
			d.Coexist.Conflicts = append(d.Coexist.Conflicts, why)
		}
	}
	d.Coexist.OK = len(d.Coexist.Conflicts) == 0

	// State.
	node := d.WarpSvc && (d.Mode == "mesh" || d.Mode == "connector" || d.MeshAddr != "")
	switch {
	case node:
		d.State, d.Origin = model.HostMeshExisting, model.MeshOriginExisting
		if d.MeshAddr == "" {
			d.Reasons = append(d.Reasons, "是 Mesh 节点但没有读到 100.96.0.0/12 内的 Mesh 地址")
		}
		if d.Account != model.AccountMatched {
			d.Reasons = append(d.Reasons, "账户："+d.AccountReason)
		}
		if !d.Coexist.OK {
			d.Reasons = append(d.Reasons, "与 Meridian 冲突，阻断："+strings.Join(d.Coexist.Conflicts, "；"))
		}
		d.Reusable = d.MeshAddr != "" && d.Account == model.AccountMatched && d.Coexist.OK
		if d.Reusable {
			d.Reasons = append(d.Reasons, "已有主机级 Mesh 节点，可沿用；面板不改它的注册和设置")
		}
	case d.WarpSvc:
		d.State = model.HostMeshNone
		d.Reasons = append(d.Reasons, "warp-svc 在运行，但不是 Mesh/connector 模式，也没有 Mesh 地址（模式 "+d.Mode+"）")
	case d.WarpCLI:
		d.State = model.HostMeshNone
		d.Reasons = append(d.Reasons, "装了 warp-cli，但 warp-svc 没有运行")
	default:
		d.State = model.HostMeshNone
		d.Reasons = append(d.Reasons, "主机上没有 WARP 客户端")
	}
	if d.State == model.HostMeshNone {
		d.Install = installPlan(d, res)
	}
	return d
}

// warpDefaultDev reports whether a default route leaves via the WARP
// interface (the client's fixed name or the detected Mesh interface).
func warpDefaultDev(l, iface string) bool {
	f := strings.Fields(l)
	for i := 0; i+1 < len(f); i++ {
		if f[i] == "dev" && (f[i+1] == "CloudflareWARP" || (iface != "" && f[i+1] == iface)) {
			return true
		}
	}
	return false
}

// installPlan is the full host-level connector install a host without a
// node would need (InstallHostConnector, the only kind): the fixed source,
// signing key, package, service and the estimated memory, and every reason
// the install cannot run. An unreachable source stops it.
func installPlan(d model.HostMeshDetection, res Reserved) *model.HostMeshInstallPlan {
	fpr := RepoKeyFingerprint()
	o := model.HostMeshInstallOption{Kind: model.InstallHostConnector,
		Installs:       []string{"gnupg（仅当主机缺少 gpg 时从主机现有 apt 源安装，用于校验签名公钥；移除时只清除本次装的）", "Cloudflare 官方软件源与签名公钥", PackageName + " 软件包（只从 Cloudflare 官方源、官方候选版本安装，临时 apt pin 禁止其他来源）", "官方包依赖的桌面库（如 libwebkit2gtk-4.1、libayatana-appindicator3、libnss3-tools、libtss2 等）从主机现有 Debian 源安装；会刷新主机的 apt 软件包列表（移除时不回退）；本次新装的依赖在撤回时全部清除", "以 connector 模式注册到面板选定的 Mesh 账户（不接管默认路由）"},
		Needs:          []string{fmt.Sprintf("可用内存 ≥ %d MB（估计）", ConnectorMinMemMB), "Debian/Ubuntu（apt）、x86_64 或 aarch64、systemd", "主机自己能访问 " + RepoURL, "主机现有 Debian/Ubuntu apt 源可用（提供依赖）", "磁盘约数百 MB（估计，未实机测量：官方包会拉入 webkit2gtk、appindicator 等桌面库）"},
		Blockers:       []string{},
		Repo:           RepoURL,
		KeyURL:         RepoKeyURL,
		KeyFingerprint: fpr,
		Packages:       []string{PackageName},
		Services:       []string{ServiceName},
		Files:          []string{RepoKeyring, RepoList},
		MemEstimateMB:  ConnectorMinMemMB,
		MemNote:        ConnectorMemNote,
	}
	block := func(s string) { o.Blockers = append(o.Blockers, s) }
	switch {
	case d.MemAvailMB < 0:
		block("读不到可用内存")
	case d.MemAvailMB < ConnectorMinMemMB:
		block(fmt.Sprintf("可用内存约 %d MB，低于估计需要的 %d MB", d.MemAvailMB, ConnectorMinMemMB))
	}
	if d.WarpSvc || d.WarpCLI {
		block("主机上已有非 Mesh 模式的 WARP 客户端：面板不改它的设置")
	}
	if !supportedOS[d.OS] || d.Codename == "" {
		block(fmt.Sprintf("系统 %q %q 不受支持（只支持带发行代号的 Debian / Ubuntu）", d.OS, d.Codename))
	}
	if !supportedArch[d.Arch] {
		block(fmt.Sprintf("架构 %q 不受支持（只支持 x86_64 / aarch64）", d.Arch))
	}
	if !d.Apt {
		block("主机上没有 apt-get")
	}
	if !d.Systemd {
		block("主机上没有 systemd")
	}
	switch d.RepoReach {
	case "ok":
	case "unreachable":
		block("主机连不上官方软件源 " + RepoURL + "：停止，不安装")
	default:
		block("没能检查主机到官方软件源的可达性（没有 curl 或检测未输出）：停止，不安装")
	}
	if fpr == "" {
		block("没有配置签名公钥指纹（面板进程环境变量 " + RepoKeyFingerprintEnv + "，40 位十六进制）：不能校验软件源，停止")
	}
	// The Linux client's own policy routing: table 65743, mark 0x100cf.
	if intIn(res.Tables, warpTable) {
		block(fmt.Sprintf("Meridian 也用路由表 %d（WARP 客户端固定使用）", warpTable))
	}
	for _, m := range res.Marks {
		if normMark(m) == warpMark {
			block("Meridian 的标记 " + warpMark + " 与 WARP 客户端相同")
			break
		}
	}
	o.Feasible = len(o.Blockers) == 0
	p := &model.HostMeshInstallPlan{Options: []model.HostMeshInstallOption{o}, RequiresConfirmation: true}
	if o.Feasible {
		p.Recommended = o.Kind
	}
	return p
}

// MarkRemoved turns the stored detection of a panel-installed node that was
// withdrawn into a stale result that must be detected again.
func MarkRemoved(d *model.HostMeshDetection) {
	d.State, d.Reusable, d.Origin, d.PanelOwned = model.HostMeshFailed, false, model.MeshOriginNone, false
	d.Install = nil
	d.Reasons = []string{"面板安装的 Mesh 节点已撤回；重新检测这台主机"}
}

// DetectFailed is the record of a detection that could not run.
func DetectFailed(nodeID, reason string) model.HostMeshDetection {
	d := ParseHostMesh("", "", Reserved{})
	d.NodeID = nodeID
	d.Reasons = []string{reason}
	return d
}

// HostMeshFile holds the last detection per node (meshDir/host-mesh.json).
const HostMeshFile = "host-mesh.json"

// LoadHostMesh reads the stored detections (empty when none).
func LoadHostMesh(dir string) (map[string]model.HostMeshDetection, error) {
	out := map[string]model.HostMeshDetection{}
	b, err := os.ReadFile(filepath.Join(dir, HostMeshFile))
	if errors.Is(err, os.ErrNotExist) {
		return out, nil
	}
	if err != nil {
		return out, err
	}
	if err := json.Unmarshal(b, &out); err != nil {
		return map[string]model.HostMeshDetection{}, err
	}
	return out, nil
}

// SaveHostMesh stores the detections.
func SaveHostMesh(dir string, m map[string]model.HostMeshDetection) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	b, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	return writeAtomic(filepath.Join(dir, HostMeshFile), b, 0o600)
}

const (
	reasonPanelHost     = "这个节点是面板安装的（panel-owned）：撤回时只撤销面板创建的注册、软件包、源和服务"
	reasonLegacySidecar = "这台主机上有旧版 Mesh sidecar 部署记录：只能撤回；撤回后改为主机级节点（迁移）"
)

// ApplyOwnership sets the origin of a detection from the deployment journal.
// A host-level node is panel-owned only when a panel run recorded that it
// installed the connector on that very host (OwnedRemote kind
// host_connector, created); any other host-level node is existing_host and
// never panel-owned. A legacy sidecar record makes a host without a
// host-level node panel_sidecar (withdraw only).
func ApplyOwnership(d *model.HostMeshDetection, j *Journal) {
	wasPanel := d.Origin == model.MeshOriginPanelHost
	d.Origin, d.PanelOwned = model.MeshOriginNone, false
	kept := d.Reasons[:0:0]
	for _, r := range d.Reasons {
		if r != reasonPanelHost && r != reasonLegacySidecar {
			kept = append(kept, r)
		}
	}
	d.Reasons = kept
	var connector, sidecar bool
	if j != nil {
		for _, r := range j.Remotes {
			if r.NodeID != d.NodeID || r.State != ResCreated {
				continue
			}
			if r.Kind == RemoteConnector {
				connector = true
			} else {
				sidecar = true
			}
		}
	}
	switch {
	case d.State == model.HostMeshExisting && connector:
		d.Origin, d.PanelOwned = model.MeshOriginPanelHost, true
		d.Reasons = append(d.Reasons, reasonPanelHost)
	case d.State == model.HostMeshExisting && wasPanel:
		// The panel installed this node and the journal no longer holds
		// it (withdrawn): the stored result is stale, never "existing".
		MarkRemoved(d)
	case d.State == model.HostMeshExisting:
		d.Origin = model.MeshOriginExisting
	case sidecar:
		d.Origin, d.PanelOwned = model.MeshOriginPanel, true
		d.Reasons = append(d.Reasons, reasonLegacySidecar)
	}
}
