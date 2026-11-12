package compile

import (
	"fmt"
	"strings"

	"github.com/radowitz/meridian/internal/model"
)

// SmartDNSSharedDirs are the host directories the gateway SmartDNS config
// reads from: its config, the DoT certificate pair, and the geosite and
// keyword domain sets written by meridian-up.sh / meridian-update-geosite.sh.
// A resolver running in its own container must mount every one of them at the
// same path (deploy/docker-compose.yml), and needs CAP_NET_ADMIN for nftset.
// smartDNSCertFile and smartDNSKeyFile are created by install.sh and, when
// missing, by the gateway meridian-up.sh.
const (
	smartDNSCertFile = "/etc/meridian/dns/cert.pem"
	smartDNSKeyFile  = "/etc/meridian/dns/key.pem"
)

var SmartDNSSharedDirs = []string{
	"/etc/smartdns",
	"/etc/meridian/dns",
	"/var/lib/meridian/geosite",
	"/var/lib/meridian/keywords",
}

// SmartDNSFileRefs lists the files a SmartDNS config loads, in order of
// appearance: "-file" arguments (domain-set) and the global DoT certificate
// directives "bind-cert-file" and "bind-cert-key-file". SmartDNS has no
// per-bind certificate options; "bind-tls ... -cert-file" is rejected
// ("unknown bind option").
func SmartDNSFileRefs(conf string) []string {
	var out []string
	for _, line := range strings.Split(conf, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) >= 2 {
			switch fields[0] {
			case "bind-cert-file", "bind-cert-key-file":
				out = append(out, fields[1])
				continue
			}
		}
		for i := 0; i+1 < len(fields); i++ {
			if fields[i] == "-file" {
				out = append(out, fields[i+1])
			}
		}
	}
	return out
}

func renderGatewayDNS(t model.Topology, exits []ExitPlan, decisions map[string]string) string {
	def, _ := defaultExit(t, exits)
	rules := planRules(t, exits, decisions)
	var sb strings.Builder
	sb.WriteString("# Meridian SmartDNS. Real answers, no fake-ip.\n")
	sb.WriteString("# ECS is intentionally unset so the family prefix is not attached to queries.\n")
	sb.WriteString("# Queries to an exit resolver leave from that exit's WAN, so DNS and the data path share a region.\n")
	sb.WriteString("speed-check-mode none\n")
	sb.WriteString("dualstack-ip-selection no\n")
	sb.WriteString("cache-size 65536\n")
	sb.WriteString("serve-expired yes\n")
	sb.WriteString("rr-ttl-min 60\n")
	// One wildcard listener per port and protocol. In SmartDNS "[::]" is a
	// dual-stack socket: an extra IPv4-specific bind on the same port (the
	// LAN address or 127.0.0.1) fails with "Address already in use" and the
	// resolver does not start. The wildcard also has to exist for hijacked
	// IPv6 queries, which nft redirect delivers to this host's GUA.
	// So SmartDNS answers on every address of this host. Who may ask is
	// decided by the input chain of table inet meridian: 53/853 only from
	// the LAN prefixes and from loopback (this host itself); everything else
	// is dropped. That chain is loaded by meridian.service; between Docker
	// starting this resolver at boot and meridian.service the only
	// restriction is that this host sits on the LAN behind ROS.
	sb.WriteString("bind [::]:53\n")
	sb.WriteString("bind-tcp [::]:53\n")
	sb.WriteString("# DoT certificate will not match the name the client dialed. Strict clients fail closed and fall back to port 53.\n")
	sb.WriteString("# The certificate is global in SmartDNS (bind-cert-*); bind-tls takes no certificate options.\n")
	sb.WriteString("bind-cert-file " + smartDNSCertFile + "\n")
	sb.WriteString("bind-cert-key-file " + smartDNSKeyFile + "\n")
	sb.WriteString("bind-tls [::]:853\n")
	sb.WriteString("\n")

	dots := t.Settings.DomesticDoT
	if len(dots) == 0 {
		dots = []string{"223.5.5.5", "1.12.12.12"}
	}
	for _, ip := range dots {
		fmt.Fprintf(&sb, "server-tls %s:853 -group domestic -exclude-default-group\n", ip)
		fmt.Fprintf(&sb, "server %s -group domestic -exclude-default-group\n", ip)
	}
	sb.WriteString("\n")
	for _, e := range exits {
		if e.DNSULA == "" {
			fmt.Fprintf(&sb, "# exit %s has no tunnel DNS address\n", e.Node.ID)
			continue
		}
		excl := " -exclude-default-group"
		if e.Node.ID == def.Node.ID {
			excl = ""
		}
		// ULA only. The tunnel v4 address is not routed past the first hop,
		// so a v4 query would follow the relay's public default route.
		fmt.Fprintf(&sb, "server %s -group %s%s\n", e.DNSULA, e.Group, excl)
	}
	sb.WriteString("\n")
	sb.WriteString("nftset #4:inet#meridian#default4\n")
	sb.WriteString("nftset #6:inet#meridian#default6\n")
	sb.WriteString("\n")
	sb.WriteString("domain-set -name gs_cn -file /var/lib/meridian/geosite/cn.txt\n")
	sb.WriteString("domain-set -name gs_apple -file /var/lib/meridian/geosite/apple.txt\n")
	sb.WriteString("domain-rules /domain-set:gs_cn/ -nameserver domestic -nftset #4:inet#meridian#direct4,#6:inet#meridian#direct6\n")
	sb.WriteString("domain-rules /domain-set:gs_apple/ -nameserver domestic -nftset #4:inet#meridian#direct4,#6:inet#meridian#direct6\n")
	sb.WriteString("\n")

	// Known DoH names return SOA. This list is not exhaustive.
	for _, name := range []string{
		"dns.google", "dns.google.com", "cloudflare-dns.com", "mozilla.cloudflare-dns.com",
		"dns.quad9.net", "dns.adguard-dns.com", "doh.opendns.com",
	} {
		fmt.Fprintf(&sb, "address /%s/#\n", name)
	}
	sb.WriteString("\n")

	for _, rp := range rules {
		nset := fmt.Sprintf("#4:inet#meridian#%s", rp.Set4)
		if !rp.FilterAAAA {
			nset += fmt.Sprintf(",#6:inet#meridian#%s", rp.Set6)
		}
		flag := ""
		if rp.FilterAAAA {
			flag = " -address #6"
		}
		sb.WriteString(fmt.Sprintf("# rule %s -> %s manual=%v\n", rp.Rule.ID, rp.Exit.Node.ID, rp.Rule.Manual))
		// No tunnel resolver (Mesh-only exit): return SOA. Falling through
		// would ask another country's DNS, or the default group.
		if rp.Exit.DNSULA == "" {
			sb.WriteString("# no in-tunnel resolver; SOA so the query does not leave via another exit\n")
			switch rp.Rule.MatchType {
			case model.MatchGeosite:
				if rp.Rule.Geosite != "" {
					fmt.Fprintf(&sb, "domain-set -name gs_%s -file /var/lib/meridian/geosite/%s.txt\n", sanitize(rp.Rule.Geosite), sanitize(rp.Rule.Geosite))
					fmt.Fprintf(&sb, "domain-rules /domain-set:gs_%s/ -address #\n", sanitize(rp.Rule.Geosite))
				}
			case model.MatchKeyword:
				fmt.Fprintf(&sb, "domain-set -name kw_%s -file /var/lib/meridian/keywords/%s.txt\n", sanitize(rp.Rule.ID), sanitize(rp.Rule.ID))
				fmt.Fprintf(&sb, "domain-rules /domain-set:kw_%s/ -address #\n", sanitize(rp.Rule.ID))
			case model.MatchCIDR, model.MatchGeoIP, model.MatchASN:
				fmt.Fprintf(&sb, "# %s %s is installed in nft set %s, not in SmartDNS\n", rp.Rule.MatchType, rp.Rule.MatchValue, rp.Set4)
			}
			for _, d := range rp.Rule.Domains {
				d = strings.TrimPrefix(d, ".")
				fmt.Fprintf(&sb, "address /%s/#\n", d)
			}
			if len(rp.Rule.Domains) == 0 && (rp.Rule.MatchType == model.MatchDomain || rp.Rule.MatchType == model.MatchSuffix) && rp.Rule.MatchValue != "" {
				fmt.Fprintf(&sb, "address /%s/#\n", strings.TrimPrefix(rp.Rule.MatchValue, "."))
			}
			continue
		}
		switch rp.Rule.MatchType {
		case model.MatchGeosite:
			if rp.Rule.Geosite != "" {
				fmt.Fprintf(&sb, "domain-set -name gs_%s -file /var/lib/meridian/geosite/%s.txt\n", sanitize(rp.Rule.Geosite), sanitize(rp.Rule.Geosite))
				fmt.Fprintf(&sb, "domain-rules /domain-set:gs_%s/ -nameserver %s%s -nftset %s\n", sanitize(rp.Rule.Geosite), rp.Exit.Group, flag, nset)
			}
		case model.MatchKeyword:
			fmt.Fprintf(&sb, "# keyword %q is expanded by meridian-update-geosite into /var/lib/meridian/keywords/%s.txt\n", rp.Rule.MatchValue, sanitize(rp.Rule.ID))
			fmt.Fprintf(&sb, "domain-set -name kw_%s -file /var/lib/meridian/keywords/%s.txt\n", sanitize(rp.Rule.ID), sanitize(rp.Rule.ID))
			fmt.Fprintf(&sb, "domain-rules /domain-set:kw_%s/ -nameserver %s%s -nftset %s\n", sanitize(rp.Rule.ID), rp.Exit.Group, flag, nset)
		case model.MatchCIDR, model.MatchGeoIP, model.MatchASN:
			fmt.Fprintf(&sb, "# %s %s is installed in nft set %s, not in SmartDNS\n", rp.Rule.MatchType, rp.Rule.MatchValue, rp.Set4)
		}
		for _, d := range rp.Rule.Domains {
			d = strings.TrimPrefix(d, ".")
			fmt.Fprintf(&sb, "domain-rules /%s/ -nameserver %s%s -nftset %s\n", d, rp.Exit.Group, flag, nset)
		}
		if len(rp.Rule.Domains) == 0 && (rp.Rule.MatchType == model.MatchDomain || rp.Rule.MatchType == model.MatchSuffix) && rp.Rule.MatchValue != "" {
			fmt.Fprintf(&sb, "domain-rules /%s/ -nameserver %s%s -nftset %s\n", strings.TrimPrefix(rp.Rule.MatchValue, "."), rp.Exit.Group, flag, nset)
		}
	}
	return sb.String()
}

func renderExitDNS(n model.Node, tunnels []Tunnel) string {
	tun := exitIngress(n, tunnels)
	var sb strings.Builder
	sb.WriteString("# Resolver bound to the tunnel. Upstream queries use this host's WAN, not the tunnel.\n")
	sb.WriteString("speed-check-mode none\n")
	sb.WriteString("cache-size 4096\n")
	if tun.EastV4 != "" {
		fmt.Fprintf(&sb, "bind %s:53\nbind-tcp %s:53\n", tun.EastV4, tun.EastV4)
	}
	if tun.EastULA != "" {
		fmt.Fprintf(&sb, "bind [%s]:53\nbind-tcp [%s]:53\n", tun.EastULA, tun.EastULA)
	}
	sb.WriteString("server 1.1.1.1\n")
	sb.WriteString("server 8.8.8.8\n")
	return sb.String()
}

// listFetchShell is shared by the list update scripts: every download has a
// connect timeout, a total timeout and a small retry, and goes to a
// temporary file first. The base URLs and timeouts can be overridden with
// environment variables (docs/install-debian13.md) without editing the
// generated scripts; nothing is read from a file, because /etc/meridian is
// writable from the panel container and these scripts run as root.
const listFetchShell = `connect_timeout=${MERIDIAN_FETCH_CONNECT_TIMEOUT:-10}
max_time=${MERIDIAN_FETCH_MAX_TIME:-120}
retries=${MERIDIAN_FETCH_RETRIES:-2}
for v in "$connect_timeout" "$max_time" "$retries"; do
  case "$v" in ''|*[!0-9]*) echo "MERIDIAN_FETCH_* must be whole numbers" >&2; exit 1 ;; esac
done
check_base() {
  case "$1" in
    http://*|https://*) ;;
    *) echo "refusing base URL $1: only http:// or https://" >&2; exit 1 ;;
  esac
}
# fetch URL OUT: complete download to OUT, or non-zero (OUT may be partial).
fetch() {
  curl -fsSL --connect-timeout "$connect_timeout" --max-time "$max_time" \
    --retry "$retries" --retry-delay 3 -o "$2" "$1"
}
`

func renderChnrouteScript() string {
	return `#!/bin/bash
# Download the MIT-licensed China IP lists (gaoyifan/china-operator-ip) and
# load them into sets chnroute / chnroute6 of table inet meridian. The rest
# of the ruleset is not touched.
#
# A set is only replaced when its list downloaded completely, is non-empty
# and every line is an address or prefix of the right family. The flush and
# the new elements go into one nft transaction, so a failed load keeps the
# old elements; a failed or empty download never empties a populated set and
# never overwrites the saved list in /var/lib/meridian.
#
# Overrides (environment, no file is read):
#   MERIDIAN_CHNROUTE_BASE_URL  directory holding china.txt and china6.txt
#                               (default: the project's raw GitHub branch)
#   MERIDIAN_FETCH_CONNECT_TIMEOUT / MERIDIAN_FETCH_MAX_TIME / MERIDIAN_FETCH_RETRIES
# Exit status: 0 both sets updated, 1 nothing updated, 2 only one family updated.
set -euo pipefail
dir=/var/lib/meridian
base=${MERIDIAN_CHNROUTE_BASE_URL:-https://raw.githubusercontent.com/gaoyifan/china-operator-ip/ip-lists}
base=${base%/}
` + listFetchShell + `check_base "$base"
mkdir -p "$dir"
tmp=$(mktemp -d "$dir/.chnroute.XXXXXX")
trap 'rm -rf "$tmp"' EXIT
# valid FAMILY IN OUT: entries only; fails on an empty list or a stray line
# (an HTML error page, a captive portal, a truncated line).
valid() {
  awk -v fam="$1" '
    /^[[:space:]]*(#|$)/ { next }
    { e = $1 }
    fam == "4" && e ~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+(\/[0-9]+)?$/ { print e; n++; next }
    fam == "6" && e ~ /^[0-9A-Fa-f:.]*:[0-9A-Fa-f:.]*(\/[0-9]+)?$/ { print e; n++; next }
    { bad++ }
    END { if (bad > 0 || n == 0) exit 1 }
  ' "$2" > "$3"
}
updated=0
failed=0
batch="$tmp/chnroute.nft"
: > "$batch"
for fam in 4 6; do
  if [ "$fam" = 4 ]; then name=china.txt; set=chnroute; else name=china6.txt; set=chnroute6; fi
  if ! fetch "$base/$name" "$tmp/$name"; then
    echo "chnroute: download of $base/$name failed or timed out; set $set and $dir/$name left unchanged" >&2
    failed=$((failed + 1))
    continue
  fi
  if ! valid "$fam" "$tmp/$name" "$tmp/$name.ok"; then
    echo "chnroute: $base/$name is empty or not an IPv$fam list; set $set and $dir/$name left unchanged" >&2
    failed=$((failed + 1))
    continue
  fi
  echo "flush set inet meridian $set" >> "$batch"
  awk -v s="$set" '{ printf "add element inet meridian %s { %s }\n", s, $1 }' "$tmp/$name.ok" >> "$batch"
  updated=$((updated + 1))
  echo "$name" >> "$tmp/updated"
done
if [ "$updated" -eq 0 ]; then
  echo "chnroute-not-updated: nothing could be fetched from $base (set MERIDIAN_CHNROUTE_BASE_URL to a reachable copy); nft sets unchanged" >&2
  exit 1
fi
if ! nft -f "$batch"; then
  echo "chnroute-not-updated: nft rejected the batch; the sets keep their previous elements" >&2
  exit 1
fi
while IFS= read -r name; do
  mv -f "$tmp/$name" "$dir/$name"
done < "$tmp/updated"
cp -f "$batch" "$dir/chnroute.nft"
if [ "$failed" -ne 0 ]; then
  echo "chnroute-partial: $updated of 2 lists updated" >&2
  exit 2
fi
echo chnroute-updated
`
}

func renderGeositeScript(t model.Topology) string {
	names := map[string]bool{"cn": true, "apple": true}
	for _, r := range t.Rules {
		if r.Geosite != "" {
			names[sanitize(r.Geosite)] = true
		}
	}
	var list []string
	for name := range names {
		list = append(list, name)
	}
	// Stable order for tests and diffs.
	sortStrings(list)
	var sb strings.Builder
	sb.WriteString("#!/bin/bash\n")
	sb.WriteString("# Pull v2fly/domain-list-community category files (MIT) and strip them for SmartDNS.\n")
	sb.WriteString("# GPL rule packs are not vendored.\n")
	sb.WriteString("# A list file is only replaced when its download completed and produced at\n")
	sb.WriteString("# least one domain; otherwise the previous file stays (an empty one is only\n")
	sb.WriteString("# created when none exists, so SmartDNS can start).\n")
	sb.WriteString("#\n")
	sb.WriteString("# Overrides (environment, no file is read):\n")
	sb.WriteString("#   MERIDIAN_GEOSITE_BASE_URL  directory holding the category files\n")
	sb.WriteString("#                              (default: the project's raw GitHub data directory)\n")
	sb.WriteString("#   MERIDIAN_FETCH_CONNECT_TIMEOUT / MERIDIAN_FETCH_MAX_TIME / MERIDIAN_FETCH_RETRIES\n")
	sb.WriteString("# Exit status: 0 every category updated, 1 nothing fetched, 2 some categories failed.\n")
	sb.WriteString("set -u\n")
	sb.WriteString("shopt -s nullglob\n")
	sb.WriteString("dir=/var/lib/meridian\nmkdir -p \"$dir/geosite\" \"$dir/raw\" \"$dir/keywords\"\n")
	sb.WriteString("base=${MERIDIAN_GEOSITE_BASE_URL:-https://raw.githubusercontent.com/v2fly/domain-list-community/master/data}\n")
	sb.WriteString("base=${base%/}\n")
	sb.WriteString(listFetchShell)
	sb.WriteString("check_base \"$base\"\n")
	sb.WriteString("tmp=$(mktemp -d \"$dir/.geosite.XXXXXX\") || exit 1\n")
	sb.WriteString("trap 'rm -rf \"$tmp\"' EXIT\n")
	sb.WriteString("ok=0\nfailed=0\n")
	sb.WriteString("keep() {\n")
	sb.WriteString("  [ -f \"$dir/geosite/$1.txt\" ] || : > \"$dir/geosite/$1.txt\"\n")
	sb.WriteString("}\n")
	sb.WriteString("get() {\n")
	sb.WriteString("  name=\"$1\"\n")
	sb.WriteString("  if ! fetch \"$base/$name\" \"$tmp/$name.raw\"; then\n")
	sb.WriteString("    echo \"geosite: $name download failed or timed out; previous list kept\" >&2\n")
	sb.WriteString("    failed=$((failed + 1)); keep \"$name\"; return 0\n")
	sb.WriteString("  fi\n")
	sb.WriteString("  awk '\n")
	sb.WriteString("    /^full:/ { sub(/^full:/, \"\"); sub(/@.*$/, \"\"); print; next }\n")
	sb.WriteString("    /^domain:/ { sub(/^domain:/, \"\"); sub(/@.*$/, \"\"); print; next }\n")
	sb.WriteString("    /^keyword:/ || /^regexp:/ || /^include:/ || /^#/ { next }\n")
	sb.WriteString("    NF { sub(/@.*$/, \"\"); print }\n")
	sb.WriteString("  ' \"$tmp/$name.raw\" | awk 'NF { print $1 }' | sort -u > \"$tmp/$name.txt\"\n")
	sb.WriteString("  if [ ! -s \"$tmp/$name.txt\" ]; then\n")
	sb.WriteString("    echo \"geosite: $name has no domains (empty or not a category file); previous list kept\" >&2\n")
	sb.WriteString("    failed=$((failed + 1)); keep \"$name\"; return 0\n")
	sb.WriteString("  fi\n")
	sb.WriteString("  mv -f \"$tmp/$name.raw\" \"$dir/raw/$name\"\n")
	sb.WriteString("  mv -f \"$tmp/$name.txt\" \"$dir/geosite/$name.txt\"\n")
	sb.WriteString("  ok=$((ok + 1))\n")
	sb.WriteString("}\n")
	for _, name := range list {
		fmt.Fprintf(&sb, "get %s\n", name)
	}
	sb.WriteString("keyword_rule() {\n")
	sb.WriteString("  id=\"$1\"\n")
	sb.WriteString("  kw=\"$2\"\n")
	sb.WriteString("  out=\"$dir/keywords/${id}.txt\"\n")
	sb.WriteString("  files=(\"$dir\"/geosite/*.txt)\n")
	sb.WriteString("  : > \"$tmp/kw\"\n")
	sb.WriteString("  if [ ${#files[@]} -gt 0 ]; then\n")
	sb.WriteString("    grep -F -i -h -e \"$kw\" \"${files[@]}\" | sort -u > \"$tmp/kw\" || true\n")
	sb.WriteString("  fi\n")
	sb.WriteString("  # An empty result never replaces a populated keyword list.\n")
	sb.WriteString("  if [ -s \"$tmp/kw\" ]; then\n")
	sb.WriteString("    mv -f \"$tmp/kw\" \"$out\"\n")
	sb.WriteString("  elif [ ! -f \"$out\" ]; then\n")
	sb.WriteString("    : > \"$out\"\n")
	sb.WriteString("  fi\n")
	sb.WriteString("}\n")
	for _, r := range t.Rules {
		if !r.Enabled || r.MatchType != model.MatchKeyword || strings.TrimSpace(r.MatchValue) == "" {
			continue
		}
		fmt.Fprintf(&sb, "keyword_rule %s %s\n", shQuote(sanitize(r.ID)), shQuote(r.MatchValue))
	}
	sb.WriteString("if [ \"$ok\" -eq 0 ]; then\n")
	sb.WriteString("  echo \"geosite-not-updated: nothing could be fetched from $base (set MERIDIAN_GEOSITE_BASE_URL to a reachable copy); lists unchanged\" >&2\n")
	sb.WriteString("  exit 1\n")
	sb.WriteString("fi\n")
	sb.WriteString("if [ \"$failed\" -ne 0 ]; then\n")
	sb.WriteString("  echo \"geosite-partial: $ok updated, $failed kept from before\" >&2\n")
	sb.WriteString("  exit 2\n")
	sb.WriteString("fi\n")
	sb.WriteString("echo geosite-updated\n")
	return sb.String()
}

// dnsSeedCommands creates the files SmartDNS refuses to start without.
// Names are sanitized and sorted so the rendered script is stable.
func dnsSeedCommands(t model.Topology) string {
	names := map[string]bool{"cn": true, "apple": true}
	var keywords []string
	for _, r := range t.Rules {
		if r.Geosite != "" {
			names[sanitize(r.Geosite)] = true
		}
		if r.Enabled && r.MatchType == model.MatchKeyword && r.ID != "" {
			keywords = append(keywords, sanitize(r.ID))
		}
	}
	var geos []string
	for name := range names {
		geos = append(geos, name)
	}
	sortStrings(geos)
	sortStrings(keywords)
	var sb strings.Builder
	sb.WriteString("install -d /var/lib/meridian/geosite /var/lib/meridian/keywords /etc/meridian/dns\n")
	for _, name := range geos {
		fmt.Fprintf(&sb, "[ -f /var/lib/meridian/geosite/%s.txt ] || : > /var/lib/meridian/geosite/%s.txt\n", name, name)
	}
	for _, id := range keywords {
		fmt.Fprintf(&sb, "[ -f /var/lib/meridian/keywords/%s.txt ] || : > /var/lib/meridian/keywords/%s.txt\n", id, id)
	}
	return sb.String()
}

func sanitize(s string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(s) {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
		} else {
			b.WriteByte('_')
		}
	}
	if b.Len() == 0 {
		return "x"
	}
	return b.String()
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
