package compile

import (
	"fmt"
	"strings"

	"github.com/radowitz/meridian/internal/model"
)

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
	fmt.Fprintf(&sb, "bind %s:53\n", lanHost(t))
	fmt.Fprintf(&sb, "bind-tcp %s:53\n", lanHost(t))
	// [::] is required so hijacked IPv6 queries, which nft redirect delivers
	// to this host's GUA, have a listener. The nft input chain drops
	// port 53/853 from sources outside the LAN, so this is not an open resolver.
	sb.WriteString("bind [::]:53\n")
	sb.WriteString("bind-tcp [::]:53\n")
	sb.WriteString("bind 127.0.0.1:53\n")
	sb.WriteString("bind-tcp 127.0.0.1:53\n")
	sb.WriteString("# DoT certificate will not match the name the client dialed. Strict clients fail closed and fall back to port 53.\n")
	fmt.Fprintf(&sb, "bind-tls %s:853 -cert-file /etc/meridian/dns/cert.pem -key-file /etc/meridian/dns/key.pem\n", lanHost(t))
	sb.WriteString("bind-tls [::]:853 -cert-file /etc/meridian/dns/cert.pem -key-file /etc/meridian/dns/key.pem\n")
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

func renderChnrouteScript() string {
	return `#!/bin/bash
# Download the MIT-licensed China IP list and load it into the meridian sets.
# This does not flush the rest of the nftables ruleset.
set -euo pipefail
dir=/var/lib/meridian
mkdir -p "$dir"
curl -fsSL -o "$dir/china.txt" https://raw.githubusercontent.com/gaoyifan/china-operator-ip/ip-lists/china.txt
curl -fsSL -o "$dir/china6.txt" https://raw.githubusercontent.com/gaoyifan/china-operator-ip/ip-lists/china6.txt
nft flush set inet meridian chnroute
nft flush set inet meridian chnroute6
awk 'NF && $1 !~ /^#/ { printf "add element inet meridian chnroute { %s }\n", $1 }' "$dir/china.txt" > "$dir/chnroute.nft"
awk 'NF && $1 !~ /^#/ { printf "add element inet meridian chnroute6 { %s }\n", $1 }' "$dir/china6.txt" >> "$dir/chnroute.nft"
nft -f "$dir/chnroute.nft"
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
	sb.WriteString("# GPL rule packs are not vendored. A missing category is skipped, not fatal.\n")
	sb.WriteString("set -u\n")
	sb.WriteString("shopt -s nullglob\n")
	sb.WriteString("dir=/var/lib/meridian\nmkdir -p \"$dir/geosite\" \"$dir/raw\" \"$dir/keywords\"\n")
	sb.WriteString("base=https://raw.githubusercontent.com/v2fly/domain-list-community/master/data\n")
	sb.WriteString("fetch() {\n")
	sb.WriteString("  name=\"$1\"\n")
	sb.WriteString("  if ! curl -fsSL -o \"$dir/raw/$name\" \"$base/$name\"; then\n")
	sb.WriteString("    echo \"skip $name\" >&2\n")
	sb.WriteString("    [ -f \"$dir/geosite/$name.txt\" ] || : > \"$dir/geosite/$name.txt\"\n")
	sb.WriteString("    return 0\n")
	sb.WriteString("  fi\n")
	sb.WriteString("  awk '\n")
	sb.WriteString("    /^full:/ { sub(/^full:/, \"\"); sub(/@.*$/, \"\"); print; next }\n")
	sb.WriteString("    /^domain:/ { sub(/^domain:/, \"\"); sub(/@.*$/, \"\"); print; next }\n")
	sb.WriteString("    /^keyword:/ || /^regexp:/ || /^include:/ || /^#/ { next }\n")
	sb.WriteString("    NF { sub(/@.*$/, \"\"); print }\n")
	sb.WriteString("  ' \"$dir/raw/$name\" | sort -u > \"$dir/geosite/$name.txt\"\n")
	sb.WriteString("}\n")
	for _, name := range list {
		fmt.Fprintf(&sb, "fetch %s\n", name)
	}
	sb.WriteString("keyword_rule() {\n")
	sb.WriteString("  id=\"$1\"\n")
	sb.WriteString("  kw=\"$2\"\n")
	sb.WriteString("  out=\"$dir/keywords/${id}.txt\"\n")
	sb.WriteString("  : > \"$out\"\n")
	sb.WriteString("  files=(\"$dir\"/geosite/*.txt)\n")
	sb.WriteString("  if [ ${#files[@]} -gt 0 ]; then\n")
	sb.WriteString("    grep -F -i -h -e \"$kw\" \"${files[@]}\" | sort -u > \"$out\" || true\n")
	sb.WriteString("  fi\n")
	sb.WriteString("}\n")
	for _, r := range t.Rules {
		if !r.Enabled || r.MatchType != model.MatchKeyword || strings.TrimSpace(r.MatchValue) == "" {
			continue
		}
		fmt.Fprintf(&sb, "keyword_rule %s %s\n", shQuote(sanitize(r.ID)), shQuote(r.MatchValue))
	}
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
