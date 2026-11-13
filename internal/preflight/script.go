package preflight

import (
	"errors"
	"fmt"
	"path"
	"strings"
)

// MaxPaths is the largest number of paths one preflight may ask about.
const MaxPaths = 256

// pathPrefixes are the only directories a path argument may name: the
// places a Meridian bundle writes (internal/apply allowedPrefixes) plus the
// node's own state directory.
var pathPrefixes = []string{
	"/etc/wireguard/",
	"/etc/nftables.d/",
	"/etc/sysctl.d/",
	"/etc/smartdns/",
	"/etc/meridian/",
	"/etc/systemd/system/",
	"/etc/iproute2/rt_tables.d/",
	"/usr/local/sbin/",
	"/var/lib/meridian/",
}

// ValidPath reports whether p may be passed to the script: absolute,
// already clean, only letters, digits and ._@+- between slashes, no "..",
// under one of the fixed prefixes, at most 200 bytes.
func ValidPath(p string) bool {
	if len(p) < 2 || len(p) > 200 || p[0] != '/' || strings.Contains(p, "..") || strings.HasSuffix(p, "/") {
		return false
	}
	if path.Clean(p) != p {
		return false
	}
	for _, c := range p {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.ContainsRune("._/@+-", c)) {
			return false
		}
	}
	for _, pre := range pathPrefixes {
		if strings.HasPrefix(p, pre) && len(p) > len(pre) {
			return true
		}
	}
	return false
}

// ErrBadArgs is returned for any argument the script must not receive.
var ErrBadArgs = errors.New("预检参数不合法")

// ValidatePaths checks every path argument (and the count) before the
// script is sent anywhere.
func ValidatePaths(paths []string) error {
	if len(paths) > MaxPaths {
		return fmt.Errorf("%w：路径数 %d 超过上限 %d", ErrBadArgs, len(paths), MaxPaths)
	}
	seen := map[string]bool{}
	for _, p := range paths {
		if !ValidPath(p) {
			return fmt.Errorf("%w：%q 不是允许的路径", ErrBadArgs, Clean(p))
		}
		if seen[p] {
			return fmt.Errorf("%w：%s 重复", ErrBadArgs, p)
		}
		seen[p] = true
	}
	return nil
}

// Args returns the argument vector for the script ("bash -s -- <paths>")
// after ValidatePaths. Each path is single-quoted, although a valid path
// has no character the shell would interpret.
func Args(paths []string) ([]string, error) {
	if err := ValidatePaths(paths); err != nil {
		return nil, err
	}
	out := make([]string, 0, len(paths))
	for _, p := range paths {
		out = append(out, "'"+p+"'")
	}
	return out, nil
}

// Script returns the fixed preflight script. It is sent on stdin to
// "bash -s -- <paths>" and is the same text for every node: nothing of the
// topology, the target or a request is interpolated into it.
func Script() string { return script }

// The script is read-only. It runs only commands that print state (id,
// uname, ip … show, ss -l / ss state established, nft list, iptables -S,
// systemctl is-*/show,
// dpkg-query, apt-cache policy, nft/wg/wstunnel --version, sha256sum,
// head, grep) with stdin from
// /dev/null and a 15 s bound each, writes nothing, never prints file
// contents (a WireGuard config holds a private key: only "does the head
// mention Meridian" and a SHA-256 are reported), and cuts its whole output
// at MaxReport+1 bytes. Path arguments are re-checked here against the
// same rules as ValidPath; a refused one is reported, never touched.
const script = `#!/bin/bash
# Meridian preflight: read-only inventory before an install. Changes nothing.
set +e
export LC_ALL=C LANG=C
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

q() { timeout 15 "$@" </dev/null 2>/dev/null; }
have() { command -v "$1" >/dev/null 2>&1; }
yn() { if "$@"; then echo yes; else echo no; fi; }
first() { head -n 1 | tr -d '\r'; }
ustate() {
  a=$(q systemctl is-active "$1" | first); e=$(q systemctl is-enabled "$1" | first); m=$(q systemctl show -p MainPID --value "$1" | first)
  echo "unit $1 ${a:--} ${e:--} ${m:-0}"
}

meridian_preflight() {
  echo 'meridian-preflight 1'
  echo "uid $(id -u 2>/dev/null)"
  echo "arch $(uname -m 2>/dev/null)"
  echo "kernel $(uname -r 2>/dev/null)"
  if [ -r /etc/os-release ]; then
    echo "os-id $(sed -n 's/^ID=//p' /etc/os-release | first)"
    echo "os-version $(sed -n 's/^VERSION_ID=//p' /etc/os-release | first)"
    echo "os-codename $(sed -n 's/^VERSION_CODENAME=//p' /etc/os-release | first)"
    echo "os-pretty $(sed -n 's/^PRETTY_NAME=//p' /etc/os-release | first)"
  fi
  if [ -d /run/systemd/system ] && have systemctl; then echo 'systemd yes'; else echo 'systemd no'; fi
  echo "mem-total-kb $(awk '/^MemTotal:/ {print $2}' /proc/meminfo 2>/dev/null)"
  echo "mem-avail-kb $(awk '/^MemAvailable:/ {print $2}' /proc/meminfo 2>/dev/null)"
  echo "disk-avail-kb $(df -Pk / 2>/dev/null | awk 'NR==2 {print $4}')"
  for c in wg wg-quick nft ip ss iptables ip6tables apt-get dpkg-query systemctl smartdns wstunnel docker curl python3 sha256sum timeout flock warp-cli; do
    echo "cmd $c $(yn have "$c")"
  done
  if have iptables; then
    echo "iptables-version $(q iptables -V | first)"
    for ch in INPUT FORWARD; do
      q iptables -w 5 -S "$ch" | grep -m 1 -E -- '^-P ' | sed 's/^/ipt ipv4 /'
      q ip6tables -w 5 -S "$ch" | grep -m 1 -E -- '^-P ' | sed 's/^/ipt ipv6 /'
    done
  fi
  # Docker FORWARD DROP coexistence: does DOCKER-USER exist, what does
  # FORWARD jump to (targets only, in order), how many Meridian-tagged
  # rules are there already.
  for t in iptables ip6tables; do
    have "$t" || continue
    n=ipv4; [ "$t" = ip6tables ] && n=ipv6
    if q "$t" -w 5 -S DOCKER-USER >/dev/null; then echo "iptchain $n DOCKER-USER yes"; else echo "iptchain $n DOCKER-USER no"; fi
    q "$t" -w 5 -S FORWARD | awk '$1=="-A" {t="-"; for (i=1;i<NF;i++) if ($i=="-j" || $i=="-g") t=$(i+1); print t, (NF<5 ? "plain" : "match")}' | head -n 40 | awk -v n="$n" '{print "iptfwd", n, NR, $1, $2}'
    c=$(q "$t" -w 5 -S DOCKER-USER | grep -cE -- '--comment "?meridian-fw-[0-9a-f]{8}"?( |$)')
    echo "iptours $n ${c:-0}"
  done
  for k in net/ipv4/ip_forward net/ipv6/conf/all/forwarding net/ipv4/conf/all/rp_filter; do
    if [ -r "/proc/sys/$k" ]; then echo "sysctl $(echo "$k" | tr / .) $(head -c 32 "/proc/sys/$k")"; fi
  done
  if have ip; then
    q ip -o link show | awk -F': ' '{print $2}' | sed 's/@.*//' | head -n 400 | sed 's/^/link /'
    q ip -o link show type wireguard | awk -F': ' '{print $2}' | sed 's/@.*//' | head -n 200 | sed 's/^/wglink /'
    q ip -o addr show | awk '{sub(/@.*/, "", $2); print $2, $4}' | head -n 600 | sed 's/^/addr /'
    q ip -4 route show table main | head -n 600 | sed 's/^/route4 /'
    q ip -6 route show table main | head -n 600 | sed 's/^/route6 /'
    q ip -4 rule show | head -n 300 | sed 's/^/rule4 /'
    q ip -6 rule show | head -n 300 | sed 's/^/rule6 /'
    q ip -4 route show table all | awk '{t=""; for (i=1;i<NF;i++) if ($i=="table") t=$(i+1); if (t!="") print t, ($1=="default" ? "default" : "route")}' | sort -u | head -n 400 | sed 's/^/rtable4 /'
    q ip -6 route show table all | awk '{t=""; for (i=1;i<NF;i++) if ($i=="table") t=$(i+1); if (t!="") print t, ($1=="default" ? "default" : "route")}' | sort -u | head -n 400 | sed 's/^/rtable6 /'
  fi
  # Interfaces whose IPv6 routes come from router advertisements, with
  # their accept_ra: with IPv6 forwarding on, accept_ra=1 stops RA.
  if have ip; then
    q ip -6 route show table main proto ra | awk '{d=""; for (i=1;i<NF;i++) if ($i=="dev") d=$(i+1); if (d!="") print d, ($1=="default" ? "default" : "prefix")}' | sort -u | head -n 50 | while read -r d k; do
      case "$d" in *[!A-Za-z0-9_.@-]*) continue ;; esac
      a=$(head -c 8 "/proc/sys/net/ipv6/conf/$d/accept_ra" 2>/dev/null)
      echo "ra6 $d ${a:--} $k"
    done
  fi
  if have wg; then q wg show all listen-port | head -n 200 | sed 's/^/wgport /'; fi
  for f in /usr/share/iproute2/rt_tables /etc/iproute2/rt_tables /etc/iproute2/rt_tables.d/*.conf; do
    if [ -f "$f" ]; then grep -E '^[[:space:]]*[0-9]+[[:space:]]+[A-Za-z0-9_.-]+' "$f" 2>/dev/null | head -n 200 | awk '{print "rtname", $1, $2}'; fi
  done
  if have ss; then
    q ss -Hlntup | head -n 600 | sed 's/^/ss /'
    q ss -Hlntu --cgroup | head -n 600 | sed 's/^/ssc /'
  fi
  if have nft; then q nft list chains | grep -E '^[[:space:]]*(table|chain|type) ' | head -n 1500 | sed 's/^[[:space:]]*/nft /'; fi
  if have systemctl; then
    for u in docker.service containerd.service nftables.service netfilter-persistent.service ufw.service firewalld.service smartdns.service systemd-resolved.service warp-svc.service; do
      ustate "$u"
    done
    q systemctl list-units --type=service --state=active --no-legend --plain 'wg-quick@*' | awk '{print $1}' | head -n 50 | while read -r u; do
      echo "unit $u active enabled 0"
    done
  fi
  # Whether nftables.service flushes the whole ruleset when it stops
  # (Debian's unit runs a whole-ruleset flush as its ExecStop).
  if have systemctl; then
    s=$(q systemctl show -p ExecStop --value nftables.service | tr -d '\n')
    case "$s" in *flush*ruleset*) echo 'nftables-stop flush' ;; '') ;; *) echo 'nftables-stop noflush' ;; esac
  fi
  # Host WARP dependency clues (names and addresses only): processes with
  # connections to its local listeners, a resolv.conf pointing at it.
  if have ss; then
    q ss -Htnp state established | awk '$4 ~ /^127[.]0[.]2[.][23]:/ || $4 ~ /:40000$/ {p="-"; if (match($0, /users:[(][(]"[^"]+"/)) p=substr($0, RSTART+9, RLENGTH-10); print $4, p}' | sort -u | head -n 30 | sed 's/^/warpdep conn /'
  fi
  if [ -r /etc/resolv.conf ]; then
    grep -E '^[[:space:]]*nameserver[[:space:]]+127[.]0[.]2[.][23]([[:space:]]|$)' /etc/resolv.conf 2>/dev/null | awk '{print "warpdep resolv", $2}' | head -n 4
  fi
  if [ -f /etc/nftables.conf ]; then
    if grep -qE '^[[:space:]]*flush[[:space:]]+ruleset' /etc/nftables.conf 2>/dev/null; then echo 'nftables-conf flush'; else echo 'nftables-conf noflush'; fi
  else
    echo 'nftables-conf absent'
  fi
  for p in warp-svc dockerd smartdns wstunnel; do
    echo "proc $p $(yn q pgrep -x "$p")"
  done
  if have wstunnel; then echo "version wstunnel $(q wstunnel --version | first)"; fi
  if have nft; then echo "version nft $(q nft --version | first)"; fi
  if have wg; then echo "version wg $(q wg --version | first)"; fi
  # Distribution packages a provision may need: present version and the
  # apt candidate ("-" when none). Read-only (dpkg-query, apt-cache policy).
  for p in wireguard-tools nftables iproute2 smartdns; do
    i=-; c=-
    if have dpkg-query; then i=$(q dpkg-query -W -f='${Status} ${Version}\n' "$p" | awk '$3=="installed" {print $4}' | first); fi
    if have apt-cache; then c=$(q apt-cache policy "$p" | sed -n 's/^ *Candidate: *//p' | first); fi
    [ "$c" = '(none)' ] && c=-
    echo "pkg $p ${i:--} ${c:--}"
  done
  if have dpkg-query; then
    v=$(q dpkg-query -W -f='${Version}' smartdns)
    [ -n "$v" ] && echo "version smartdns $v"
  fi
  if have apt-cache; then
    v=$(q apt-cache policy smartdns | sed -n 's/^ *Candidate: *//p' | first)
    [ -n "$v" ] && echo "candidate smartdns $v"
  fi
  for p in "$@"; do
    case "$p" in
      /etc/wireguard/?*|/etc/nftables.d/?*|/etc/sysctl.d/?*|/etc/smartdns/?*|/etc/meridian/?*|/etc/systemd/system/?*|/etc/iproute2/rt_tables.d/?*|/usr/local/sbin/?*|/var/lib/meridian/?*) ;;
      *) echo 'note path argument refused'; continue ;;
    esac
    case "$p" in
      *..*|*/|*[!A-Za-z0-9._/@+-]*) echo 'note path argument refused'; continue ;;
    esac
    if [ -L "$p" ]; then
      echo "path $p link 0 no -"
    elif [ -f "$p" ]; then
      size=$(stat -c %s -- "$p" 2>/dev/null)
      marker=no
      if head -n 12 -- "$p" 2>/dev/null | grep -qi meridian; then marker=yes; fi
      sum=-
      # Panel-delivered binaries are hashed up to 64 MiB (the delivery
      # bound), every other file up to 4 MiB.
      lim=4194304
      case "$p" in /usr/local/sbin/meridian-wstunnel|/usr/local/sbin/meridian-smartdns) lim=67108864 ;; esac
      if [ -n "$size" ] && [ "$size" -le "$lim" ]; then sum=$(sha256sum -- "$p" 2>/dev/null | cut -c1-64); fi
      echo "path $p file ${size:-0} $marker ${sum:--}"
    elif [ -d "$p" ]; then
      echo "path $p dir 0 no -"
    elif [ -e "$p" ]; then
      echo "path $p other 0 no -"
    else
      echo "path $p absent"
    fi
    case "$p" in
      /etc/systemd/system/*.service|/etc/systemd/system/*.timer)
        if have systemctl; then
          ustate "${p##*/}"
        fi ;;
    esac
  done
  if [ -f /var/lib/meridian/node/manifest ]; then
    echo 'manifest-begin'
    head -c 65536 /var/lib/meridian/node/manifest 2>/dev/null | head -n 600 | sed 's/^/manifest /'
    echo 'manifest-end'
  fi
  if [ -f /var/lib/meridian/node/journal ]; then
    echo 'journal-begin'
    head -c 16384 /var/lib/meridian/node/journal 2>/dev/null | head -n 200 | sed 's/^/journal /'
    echo 'journal-end'
  fi
  echo 'meridian-preflight-end'
}

meridian_preflight "$@" </dev/null 2>/dev/null | head -c 262145
exit 0
`
