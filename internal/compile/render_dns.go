package compile

import (
	"fmt"
	"strings"

	"github.com/radowitz/meridian/internal/lists"
	"github.com/radowitz/meridian/internal/model"
)

// SmartDNSSharedDirs are the host directories the gateway SmartDNS config
// reads from: its config, the DoT certificate pair, and the geosite and
// keyword domain sets written by meridian-up.sh and the list update
// (internal/lists through meridian-host).
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

func renderGatewayDNS(t model.Topology, exits []ExitPlan, groups []GroupPlan, decisions map[string]string) string {
	defT, _ := defaultExit(t, groups)
	def := defT.Exit
	rules := planRules(t, exits, groups, decisions)
	var sb strings.Builder
	sb.WriteString("# Meridian SmartDNS. Real answers, no fake-ip.\n")
	sb.WriteString("# ECS is intentionally unset so the family prefix is not attached to queries.\n")
	sb.WriteString("# Queries to an exit resolver leave from that exit's WAN, so DNS and the data path share a region.\n")
	sb.WriteString("# A region group the hub switches resolves through its own data path (group mark, group\n")
	sb.WriteString("# resolver address), so its DNS always reaches the member the hub currently uses.\n")
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
		if defT.Group == nil && e.Node.ID == def.Node.ID {
			excl = ""
		}
		// ULA only. The tunnel v4 address is not routed past the first hop,
		// so a v4 query would follow the relay's public default route.
		fmt.Fprintf(&sb, "server %s -group %s%s\n", e.DNSULA, e.Group, excl)
	}
	sb.WriteString("\n")
	writeGroupResolvers(&sb, groups, defT.Group)
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
		ns := rp.Exit.Group
		if rp.ViaGroup != nil {
			ns = rp.ViaGroup.DNSGroup
			sb.WriteString(fmt.Sprintf("# rule %s -> %s manual=%v via group %s (switched by the hub; resolved at %s on the member in use)\n", rp.Rule.ID, rp.Exit.Node.ID, rp.Rule.Manual, rp.ViaGroup.Group.ID, rp.ViaGroup.Resolver))
		} else {
			sb.WriteString(fmt.Sprintf("# rule %s -> %s manual=%v\n", rp.Rule.ID, rp.Exit.Node.ID, rp.Rule.Manual))
		}
		// No tunnel resolver (Mesh-only exit): return SOA. Falling through
		// would ask another country's DNS, or the default group. A
		// switchable group always has its resolver address.
		if rp.ViaGroup == nil && rp.Exit.DNSULA == "" {
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
				fmt.Fprintf(&sb, "domain-rules /domain-set:gs_%s/ -nameserver %s%s -nftset %s\n", sanitize(rp.Rule.Geosite), ns, flag, nset)
			}
		case model.MatchKeyword:
			fmt.Fprintf(&sb, "# keyword %q is expanded by the list update into /var/lib/meridian/keywords/%s.txt\n", rp.Rule.MatchValue, sanitize(rp.Rule.ID))
			fmt.Fprintf(&sb, "domain-set -name kw_%s -file /var/lib/meridian/keywords/%s.txt\n", sanitize(rp.Rule.ID), sanitize(rp.Rule.ID))
			fmt.Fprintf(&sb, "domain-rules /domain-set:kw_%s/ -nameserver %s%s -nftset %s\n", sanitize(rp.Rule.ID), ns, flag, nset)
		case model.MatchCIDR, model.MatchGeoIP, model.MatchASN:
			fmt.Fprintf(&sb, "# %s %s is installed in nft set %s, not in SmartDNS\n", rp.Rule.MatchType, rp.Rule.MatchValue, rp.Set4)
		}
		for _, d := range rp.Rule.Domains {
			d = strings.TrimPrefix(d, ".")
			fmt.Fprintf(&sb, "domain-rules /%s/ -nameserver %s%s -nftset %s\n", d, ns, flag, nset)
		}
		if len(rp.Rule.Domains) == 0 && (rp.Rule.MatchType == model.MatchDomain || rp.Rule.MatchType == model.MatchSuffix) && rp.Rule.MatchValue != "" {
			fmt.Fprintf(&sb, "domain-rules /%s/ -nameserver %s%s -nftset %s\n", strings.TrimPrefix(rp.Rule.MatchValue, "."), ns, flag, nset)
		}
	}
	return sb.String()
}

// writeGroupResolvers adds one upstream group per region group the hub can
// switch. Its only server is the group's resolver address, an address no
// node owns (validate.GroupResolverNet). SmartDNS puts the group's fwmark on
// the upstream socket (-set-mark, which needs CAP_NET_ADMIN), so the query
// takes the group's data path on this host: "fwmark <group mark> lookup
// 102" into the west tunnel, or "unreachable" behind it, never main or
// table 100. transit_snat (render_nft.go) gives it the group's transit
// source, the hub routes it by that source into the member its group
// table currently points at, and that member DNATs it to its own tunnel
// resolver (renderExitNFT). The group's DNS therefore follows every hub
// switch with no state on this host, and fails, with no fallback, while
// the group is on the Mesh hop or blackholed.
//
// The mark is written in decimal. SmartDNS 1.2026.11.09 accepts
// "-set-mark 0x4d70" without complaint and applies no mark at all (seen
// with nft output counters on a real gateway); decimal is applied.
//
// Only the default group, when it is switchable, leaves out
// -exclude-default-group: it is then the one upstream for names no rule
// matches. Every other group upstream is reached only by its own rules.
func writeGroupResolvers(sb *strings.Builder, groups []GroupPlan, def *GroupPlan) {
	n := 0
	for _, g := range groups {
		if !g.Dynamic {
			continue
		}
		if n == 0 {
			sb.WriteString("# region groups switched by the hub: the group's resolver address, the group mark on the socket\n")
		}
		n++
		excl := " -exclude-default-group"
		if def != nil && def.Group.ID == g.Group.ID {
			excl = ""
		}
		fmt.Fprintf(sb, "server %s -group %s%s -set-mark %d\n", g.Resolver, g.DNSGroup, excl, g.Mark)
	}
	if n > 0 {
		sb.WriteString("\n")
	}
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

// GeositeNames are the v2fly categories the gateway SmartDNS config loads
// (cn, apple and every rule's geosite), lower case, sorted. Each is
// published as /var/lib/meridian/geosite/<lists.FileName(name)>.txt.
func GeositeNames(t model.Topology) []string {
	names := map[string]bool{"cn": true, "apple": true}
	for _, r := range t.Rules {
		if r.Geosite != "" {
			names[strings.ToLower(r.Geosite)] = true
		}
	}
	var list []string
	for name := range names {
		list = append(list, name)
	}
	sortStrings(list)
	return list
}

// KeywordSpecs are the enabled keyword rules: file stem and substring.
func KeywordSpecs(t model.Topology) []lists.Keyword {
	var out []lists.Keyword
	seen := map[string]bool{}
	for _, r := range t.Rules {
		if !r.Enabled || r.MatchType != model.MatchKeyword || strings.TrimSpace(r.MatchValue) == "" {
			continue
		}
		id := sanitize(r.ID)
		if seen[id] {
			continue
		}
		seen[id] = true
		out = append(out, lists.Keyword{ID: id, Value: r.MatchValue})
	}
	return out
}

// The list update scripts are thin wrappers around the host agent's fixed
// list action (meridian lists-update -> meridian-host /v1/lists), the same
// path as the panel's "update now". Downloading, include expansion,
// content checks and atomic publication live in internal/lists; nothing is
// fetched by the shell. The source policy is compiled in from the topology
// and may be overridden for one run with MERIDIAN_LIST_SOURCE (the CLI
// accepts only the three policy values).
const listWrapperHead = `#!/bin/bash
# Source URLs are fixed in the meridian binary (internal/lists); a LAN copy
# can replace the domestic source through MERIDIAN_GEOSITE_BASE_URL /
# MERIDIAN_CHNROUTE_BASE_URL in the environment of meridian-host.service.
# Exit status: 0 every list updated, 1 nothing updated, 2 some lists kept
# their previous version.
set -u
`

func renderChnrouteScript(t model.Topology) string {
	var sb strings.Builder
	sb.WriteString(listWrapperHead)
	sb.WriteString("# China IP lists (gaoyifan/china-operator-ip, MIT) into nft sets chnroute /\n")
	sb.WriteString("# chnroute6: each family is checked, then flush+add for every valid family go\n")
	sb.WriteString("# into one nft transaction; a failed family keeps its elements.\n")
	fmt.Fprintf(&sb, "policy=${MERIDIAN_LIST_SOURCE:-%s}\n", lists.Effective(t.Settings.ListSource))
	sb.WriteString("exec /usr/local/bin/meridian lists-update --lists chnroute --policy \"$policy\"\n")
	return sb.String()
}

func renderGeositeScript(t model.Topology) string {
	var sb strings.Builder
	sb.WriteString(listWrapperHead)
	sb.WriteString("# v2fly/domain-list-community categories (MIT), include: expanded, into\n")
	sb.WriteString("# SmartDNS domain-set files; keyword lists are rebuilt from them.\n")
	fmt.Fprintf(&sb, "policy=${MERIDIAN_LIST_SOURCE:-%s}\n", lists.Effective(t.Settings.ListSource))
	sb.WriteString("exec /usr/local/bin/meridian lists-update --lists geosite --policy \"$policy\"")
	fmt.Fprintf(&sb, " \\\n  --geosite %s", shQuote(strings.Join(GeositeNames(t), ",")))
	for _, k := range KeywordSpecs(t) {
		fmt.Fprintf(&sb, " \\\n  --keyword %s", shQuote(k.ID+"="+k.Value))
	}
	sb.WriteString("\n")
	return sb.String()
}

// dnsSeedCommands creates the files SmartDNS refuses to start without.
// Names are sanitized and sorted so the rendered script is stable.
func dnsSeedCommands(t model.Topology) string {
	var geos, keywords []string
	seen := map[string]bool{}
	for _, n := range GeositeNames(t) {
		if f := lists.FileName(n); !seen[f] {
			seen[f] = true
			geos = append(geos, f)
		}
	}
	for _, r := range t.Rules {
		if r.Enabled && r.MatchType == model.MatchKeyword && r.ID != "" {
			keywords = append(keywords, sanitize(r.ID))
		}
	}
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
