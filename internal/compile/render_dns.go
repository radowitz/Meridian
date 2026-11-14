package compile

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"strings"

	"github.com/radowitz/meridian/internal/dnssplit"
	"github.com/radowitz/meridian/internal/lists"
	"github.com/radowitz/meridian/internal/model"
	"github.com/radowitz/meridian/internal/ordered"
	"github.com/radowitz/meridian/internal/ruleset"
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

// The China IP lists as the list update saves them (internal/lists,
// chnFamilies). meridian-dns-split (internal/dnssplit) reads them on the
// host; SmartDNS does not.
const (
	chinaListFile4 = "/var/lib/meridian/lists/china.txt"
	chinaListFile6 = "/var/lib/meridian/lists/china6.txt"
)

// The unlisted-name check (Settings.UnlistedDomesticDNS): a host service
// on loopback that the gateway SmartDNS asks for names no list and no rule
// matches. Port 5356 is reserved (validate.reservedUDP/TCP).
const (
	DNSSplitUnit   = "meridian-dns-split.service"
	DNSSplitListen = "127.0.0.1:5356"
)

// SmartDNSUsesDNSSplit reports whether a gateway SmartDNS config sends
// unlisted names to meridian-dns-split (the host agent then restarts both
// after the China lists changed).
func SmartDNSUsesDNSSplit(conf string) bool {
	for _, l := range strings.Split(conf, "\n") {
		if strings.HasPrefix(l, "server "+DNSSplitListen+" ") {
			return true
		}
	}
	return false
}

// dnsSplitUpstream is the resolver unlisted names are asked at today: the
// default group's resolver address with its mark, or the static default
// exit's tunnel resolver. ok is false when the default has none (the split
// is then not rendered; unlisted names keep the strict path).
func dnsSplitUpstream(t model.Topology, exits []ExitPlan, def target) (addr string, mark uint32, ok bool) {
	if def.Group != nil {
		return def.Group.Resolver, def.Group.Mark, def.Group.Resolver != ""
	}
	for _, e := range exits {
		if e.Node.ID != def.Exit.Node.ID || e.DNSULA == "" {
			continue
		}
		if t.DualHub() {
			return e.Resolver, 0, e.Resolver != ""
		}
		return e.DNSULA, 0, true
	}
	return "", 0, false
}

func bracketHostPort(addr string, port int) string {
	if strings.Contains(addr, ":") {
		return fmt.Sprintf("[%s]:%d", addr, port)
	}
	return fmt.Sprintf("%s:%d", addr, port)
}

// renderDNSSplitUnit runs "meridian dns-split" (internal/dnssplit) with the
// compiled upstreams. Root for SO_MARK (CAP_NET_ADMIN only).
func renderDNSSplitUnit(t model.Topology, exits []ExitPlan, groups []GroupPlan) (string, bool) {
	if !t.Settings.UnlistedDomesticDNS {
		return "", false
	}
	defT, ok := defaultExit(t, groups)
	if !ok {
		return "", false
	}
	addr, mark, ok := dnsSplitUpstream(t, exits, defT)
	if !ok {
		return "", false
	}
	var dom []string
	for _, ip := range domesticDoT(t) {
		dom = append(dom, bracketHostPort(ip, 53))
	}
	return fmt.Sprintf(`# Unlisted names (settings unlisted_domestic_dns): the gateway SmartDNS asks
# this service; it uses a domestic answer only when every address in it is
# a China address (chnroute lists), otherwise the default exit's resolver's
# answer. See docs/architecture.md「未列名单域名的国内解析」.
[Unit]
Description=Meridian unlisted-name DNS check
After=network-online.target
Wants=network-online.target

[Service]
# An older host binary has no dns-split and would start the panel instead:
# refuse to start until install.sh has copied a binary that has it.
ExecStartPre=/bin/grep -q meridian-dns-split-ready /usr/local/bin/meridian
# Timings (defaults of internal/dnssplit): a qualifying domestic answer is
# used at once; otherwise the exit's answer as soon as the exit answered and
# a domestic resolver that replied has settled (--settle after its first
# non-qualifying reply, for an injected reply followed by the genuine one);
# --domestic-timeout only caps domestic resolvers that never reply;
# --stats-interval is a summary log line of counts and decision times
# (no names).
ExecStart=/usr/local/bin/meridian dns-split --listen %s --domestic %s --exit %s --exit-mark %d --china4 %s --china6 %s --domestic-timeout %s --settle %s --exit-timeout %s --stats-interval %s
Restart=always
RestartSec=2
NoNewPrivileges=yes
CapabilityBoundingSet=CAP_NET_ADMIN
AmbientCapabilities=
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes

[Install]
WantedBy=multi-user.target
`, DNSSplitListen, strings.Join(dom, ","), bracketHostPort(addr, 53), mark, chinaListFile4, chinaListFile6,
		dnssplit.DefaultDomesticTimeout, dnssplit.DefaultSettle, dnssplit.DefaultExitTimeout, dnssplit.DefaultStatsInterval), true
}

func domesticDoT(t model.Topology) []string {
	if len(t.Settings.DomesticDoT) == 0 {
		return []string{"223.5.5.5", "1.12.12.12"}
	}
	return t.Settings.DomesticDoT
}

// dnsAAAAPolicy is how the gateway resolver treats AAAA (and the IPv6 hints
// of HTTPS records). SmartDNS 1.2026.08.05 (Release48.4) decides an AAAA
// SOA from the domain rules before any upstream is asked:
//
//   - forceSOA: "force-AAAA-SOA yes" answers every AAAA with an empty
//     NOERROR (SOA), unless the matching domain rule carries
//     "-address -6" (DOMAIN_FLAG_ADDR_IPV6_IGN, checked first in
//     _dns_server_is_return_soa_qtype, src/dns_server/soa.c).
//   - a rule whose AAAA must stay empty carries "-address #6", which wins
//     over everything else.
//
// The catch-all (names no list and no rule matches) gets AAAA only when
// the operator stated that clients route IPv6 through this gateway AND the
// default exit/group carries IPv6; otherwise forceSOA is on and only the
// domestic sets and the rules allowed IPv6 are exempt.
type dnsAAAAPolicy struct {
	clientsV6 bool
	forceSOA  bool
}

func aaaaPolicy(t model.Topology, def target) dnsAAAAPolicy {
	v6 := t.Settings.ClientsIPv6ViaGateway
	return dnsAAAAPolicy{clientsV6: v6, forceSOA: !(v6 && def.V6)}
}

// domesticFlag is appended to a domestic (direct) domain rule: domestic
// names keep their AAAA, IPv6 to them goes direct through the home router.
func (p dnsAAAAPolicy) domesticFlag() string {
	if p.forceSOA {
		return " -address -6"
	}
	return ""
}

// ruleAAAA: whether a tunnelled rule returns AAAA, and its address flag.
func (p dnsAAAAPolicy) ruleAAAA(rp rulePlan) (bool, string) {
	if rp.FilterAAAA || !p.clientsV6 {
		return false, " -address #6"
	}
	if p.forceSOA {
		return true, " -address -6"
	}
	return true, ""
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
	// The cache must not outlive a restart: by default (cache-persist
	// auto) SmartDNS saves it to /var/cache/smartdns inside the container
	// and loads it on start, so answers of an old policy (an AAAA, an
	// unlisted answer, an old list) survived the restart an install does.
	sb.WriteString("cache-persist no\n")
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

	aaaa := aaaaPolicy(t, defT)
	if aaaa.forceSOA {
		if aaaa.clientsV6 {
			sb.WriteString("# AAAA: the default exit/group has no IPv6 end to end, so names no rule matches get\n")
		} else {
			sb.WriteString("# AAAA: clients take IPv6 from the home router, not from this gateway (settings\n")
			sb.WriteString("# clients_ipv6_via_gateway off): IPv6 to a tunnelled name would leave over the home line.\n")
		}
		sb.WriteString("# No AAAA (empty NOERROR, IPv6 hints dropped from HTTPS records) for any name except the\n")
		sb.WriteString("# domestic sets and the rules allowed IPv6, which carry \"-address -6\".\n")
		sb.WriteString("force-AAAA-SOA yes\n")
		sb.WriteString("\n")
	}

	_, split := renderDNSSplitUnit(t, exits, groups)
	dots := domesticDoT(t)
	for _, ip := range dots {
		fmt.Fprintf(&sb, "server-tls %s:853 -group domestic -exclude-default-group\n", ip)
		fmt.Fprintf(&sb, "server %s -group domestic -exclude-default-group\n", ip)
	}
	sb.WriteString("\n")
	if split {
		writeUnlistedDomestic(&sb)
	}
	for _, e := range exits {
		if e.DNSULA == "" {
			fmt.Fprintf(&sb, "# exit %s has no tunnel DNS address\n", e.Node.ID)
			continue
		}
		excl := " -exclude-default-group"
		isDefault := defT.Group == nil && e.Node.ID == def.Node.ID
		if isDefault && !split {
			excl = ""
		}
		// ULA only. The tunnel v4 address is not routed past the first hop,
		// so a v4 query would follow the relay's public default route.
		addr := e.DNSULA
		if t.DualHub() {
			// The exit's tunnel address is on the primary hub's tunnel; its
			// hub-independent resolver address reaches it through whichever
			// hub carries the traffic (ExitPlan.Resolver).
			addr = e.Resolver
		}
		fmt.Fprintf(&sb, "server %s -group %s%s\n", addr, e.Group, excl)
	}
	sb.WriteString("\n")
	writeGroupResolvers(&sb, groups, defT.Group, split)
	sb.WriteString("nftset #4:inet#meridian#default4\n")
	if aaaa.forceSOA {
		sb.WriteString("# default6 stays empty: names no rule matches get no AAAA.\n")
	} else {
		sb.WriteString("nftset #6:inet#meridian#default6\n")
	}
	sb.WriteString("\n")
	// The built-in domestic list comes after every rule (lowest
	// precedence): its derived file holds only the names no rule matches.
	sb.WriteString("# Built-in domestic list (geosite cn), after every rule: names a rule matches were removed\n")
	sb.WriteString("# from it on the host (meridian lists-derive), so a rule always wins over it.\n")
	fmt.Fprintf(&sb, "domain-set -name %s -file %s/%s.txt\n", domesticSet, OrderedDir, domesticSet)
	fmt.Fprintf(&sb, "domain-rules /domain-set:%s/ -nameserver domestic%s -nftset #4:inet#meridian#direct4,#6:inet#meridian#direct6\n", domesticSet, aaaa.domesticFlag())
	sb.WriteString("\n")

	// Known DoH names return SOA. This list is not exhaustive.
	for _, name := range []string{
		"dns.google", "dns.google.com", "cloudflare-dns.com", "mozilla.cloudflare-dns.com",
		"dns.quad9.net", "dns.adguard-dns.com", "doh.opendns.com",
	} {
		fmt.Fprintf(&sb, "address /%s/#\n", name)
	}
	sb.WriteString("\n")

	if len(rules) > 0 {
		sb.WriteString("# Rules in list order, first match wins. Each rule's names are the domain-set the host derives\n")
		fmt.Fprintf(&sb, "# from %s (meridian lists-derive): a name belongs to the first rule that\n", lists.ManifestPath)
		sb.WriteString("# matches it, so SmartDNS's longest-name choice gives the same rule as list order.\n")
	}
	for _, rp := range rules {
		if rp.QUIC {
			sb.WriteString("# QUIC switch (UDP 443 refused for tunnelled traffic of the rules below and the default): nft only\n")
			continue
		}
		nset := fmt.Sprintf("#4:inet#meridian#%s", rp.Set4)
		withAAAA, flag := aaaa.ruleAAAA(rp)
		ns := rp.Exit.Group
		switch {
		case rp.Action == model.ActionDirect:
			ns, flag, withAAAA = "domestic", aaaa.domesticFlag(), true
			fmt.Fprintf(&sb, "# rule %s -> direct (domestic resolvers, routed direct) manual=%v\n", rp.Rule.ID, rp.Rule.Manual)
		case rp.Action == model.ActionReject:
			// Resolved by the default target's resolver; the gateway refuses
			// the connections (render_nft.go). No AAAA: an IPv6 answer could
			// be used over the home line, past the refusal.
			ns, flag, withAAAA = defT.dnsGroup(), " -address #6", false
			fmt.Fprintf(&sb, "# rule %s -> reject (connections to the answers are refused by the gateway) manual=%v\n", rp.Rule.ID, rp.Rule.Manual)
		case rp.ViaGroup != nil:
			ns = rp.ViaGroup.DNSGroup
			sb.WriteString(fmt.Sprintf("# rule %s -> %s manual=%v via group %s (switched by the hub; resolved at %s on the member in use)\n", rp.Rule.ID, rp.Exit.Node.ID, rp.Rule.Manual, rp.ViaGroup.Group.ID, rp.ViaGroup.Resolver))
		default:
			sb.WriteString(fmt.Sprintf("# rule %s -> %s manual=%v\n", rp.Rule.ID, rp.Exit.Node.ID, rp.Rule.Manual))
		}
		if withAAAA {
			nset += fmt.Sprintf(",#6:inet#meridian#%s", rp.Set6)
		}
		if !hasDomainSource(rp.Rule) {
			fmt.Fprintf(&sb, "# %s %s is installed in nft set %s, not in SmartDNS\n", rp.Rule.MatchType, rp.Rule.MatchValue, rp.Set4)
			continue
		}
		fmt.Fprintf(&sb, "domain-set -name %s -file %s/%s.txt\n", rp.Set4, OrderedDir, rp.Set4)
		// No tunnel resolver (Mesh-only exit): return SOA. Falling through
		// would ask another country's DNS, or the default group. A
		// switchable group always has its resolver address.
		if rp.Action == "" && rp.ViaGroup == nil && rp.Exit.DNSULA == "" {
			sb.WriteString("# no in-tunnel resolver; SOA so the query does not leave via another exit\n")
			fmt.Fprintf(&sb, "domain-rules /domain-set:%s/ -address #\n", rp.Set4)
			continue
		}
		fmt.Fprintf(&sb, "domain-rules /domain-set:%s/ -nameserver %s%s -nftset %s\n", rp.Set4, ns, flag, nset)
	}
	return sb.String()
}

// The derived domain-sets (internal/ordered, lists.DeriveOrdered) and the
// name of the built-in domestic list's set.
const (
	OrderedDir  = "/var/lib/meridian/" + lists.OrderedSubdir
	domesticSet = "gs_cn"
)

// RuleSetExclusions are the exclusions of rule-set id as the manifest and
// decide.json carry them (both from this one function, applied on the host
// by ordered.ApplyExclusions); nil without any.
func RuleSetExclusions(t model.Topology, id string) []ordered.Entry {
	rs, ok := t.RuleSetByID(id)
	if !ok || len(rs.Exclude) == 0 {
		return nil
	}
	return ruleset.ExclusionEntries(rs.Exclude)
}

// hasDomainSource: the rule matches names (it has a domain-set).
func hasDomainSource(r model.Rule) bool {
	if len(r.Domains) > 0 {
		return true
	}
	switch r.MatchType {
	case model.MatchDomain, model.MatchSuffix:
		return strings.TrimSpace(r.MatchValue) != ""
	case model.MatchGeosite:
		return r.Geosite != ""
	case model.MatchKeyword:
		return strings.TrimSpace(r.MatchValue) != ""
	case model.MatchRuleSet:
		return true
	}
	return false
}

// renderRuleManifest is the ordered list of domain sources the host derives
// the rule domain-sets from (/etc/meridian/rules/order.conf, see
// internal/ordered): one set per rule with names, in list order, then the
// built-in domestic list.
func renderRuleManifest(t model.Topology, rules []rulePlan) string {
	var m ordered.Manifest
	for _, rp := range rules {
		if rp.QUIC || !hasDomainSource(rp.Rule) {
			continue
		}
		r := rp.Rule
		set := ordered.ManifestSet{Name: rp.Set4, CIDR4: rp.CIDR4, CIDR6: rp.CIDR6}
		v := strings.TrimPrefix(strings.ToLower(strings.TrimSpace(r.MatchValue)), ".")
		switch r.MatchType {
		case model.MatchDomain:
			if d, ok := ordered.NormDomain(v); ok {
				set.Add(ordered.SrcExact, d)
			}
		case model.MatchSuffix:
			if d, ok := ordered.NormDomain(v); ok {
				set.Add(ordered.SrcSuffix, d)
			}
		case model.MatchGeosite:
			if r.Geosite != "" {
				set.Add(ordered.SrcGeosite, lists.FileName(r.Geosite))
			}
		case model.MatchKeyword:
			set.Add(ordered.SrcKeyword, sanitize(r.ID))
		case model.MatchRuleSet:
			set.AddRuleSet(r.RuleSet, RuleSetExclusions(t, r.RuleSet))
		}
		// Explicit names of a rule match the name and everything under it.
		for _, d := range r.Domains {
			if d, ok := ordered.NormDomain(strings.TrimPrefix(d, ".")); ok {
				set.Add(ordered.SrcSuffix, d)
			}
		}
		m.Sets = append(m.Sets, set)
	}
	dom := ordered.ManifestSet{Name: domesticSet}
	dom.Add(ordered.SrcGeosite, "cn")
	m.Sets = append(m.Sets, dom)
	return m.Render()
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
// switch with no state on this host. On the Mesh hop the query crosses the
// Mesh to the group's Mesh resolver member (GroupPlan.MeshResolver), which
// answers it on its Mesh ingress and replies back over the Mesh; while the
// Mesh carries nothing, the sidecar is not sealed or the group has no Mesh
// resolver, and while the table is blackholed, it fails, with no fallback
// to a domestic resolver, another member or the LAN.
//
// The mark is written in decimal. SmartDNS 1.2026.11.09 accepts
// "-set-mark 0x4d70" without complaint and applies no mark at all (seen
// with nft output counters on a real gateway); decimal is applied.
//
// Only the default group, when it is switchable, leaves out
// -exclude-default-group: it is then the one upstream for names no rule
// matches. Every other group upstream is reached only by its own rules.
// With split (Settings.UnlistedDomesticDNS) the default group's entry is
// excluded too: unlisted names go to meridian-dns-split, which asks the
// same resolver with the same mark itself.
func writeGroupResolvers(sb *strings.Builder, groups []GroupPlan, def *GroupPlan, split bool) {
	n := 0
	for _, g := range groups {
		if !g.Dynamic {
			continue
		}
		if n == 0 {
			sb.WriteString("# region groups switched by the hub: the group's resolver address, the group mark on the socket\n")
		}
		n++
		isDefault := def != nil && def.Group.ID == g.Group.ID
		excl := " -exclude-default-group"
		if isDefault && !split {
			excl = ""
		}
		fmt.Fprintf(sb, "server %s -group %s%s -set-mark %d\n", g.Resolver, g.DNSGroup, excl, g.Mark)
	}
	if n > 0 {
		sb.WriteString("\n")
	}
}

// writeUnlistedDomestic makes meridian-dns-split (internal/dnssplit) the
// only upstream of the default group: names no list and no rule matches
// go there, and it returns either a domestic answer made only of China
// addresses or the default exit's answer. SmartDNS 1.2026.08.05 cannot do
// this itself: with -whitelist-ip on the domestic servers and the exit as
// -fallback, a domestic "CNAME + foreign A" keeps the CNAME, the request's
// rcode is no longer SERVFAIL, the "all addresses skipped, retry" branch
// of _dns_server_process_answer does not run, the fallback is never asked,
// and the client gets (and SmartDNS caches) the address-less CNAME
// (reproduced with the pinned binary, TestSmartDNSRealBinary). AAAA is
// still decided here first (force-AAAA-SOA), so only allowed AAAA queries
// reach the check.
func writeUnlistedDomestic(sb *strings.Builder) {
	sb.WriteString("# Unlisted names (settings unlisted_domestic_dns) go to meridian-dns-split on loopback: it\n")
	sb.WriteString("# uses a domestic answer only when every address in it is a China address, otherwise the\n")
	sb.WriteString("# default exit's answer. The domestic resolvers see every unlisted name, foreign ones included.\n")
	fmt.Fprintf(sb, "server %s -group unlisted_split\n", DNSSplitListen)
	sb.WriteString("\n")
}

func renderExitDNS(t model.Topology, n model.Node, tunnels []Tunnel, exits []ExitPlan) string {
	tun := exitIngress(n, tunnels, primaryHubID(t))
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
	renderCarrierDNS(&sb, exits, n.ID)
	return sb.String()
}

// GeositeNames are the v2fly categories the gateway needs (cn and every
// rule's geosite), lower case, sorted. Each is
// published as /var/lib/meridian/geosite/<lists.FileName(name)>.txt.
func GeositeNames(t model.Topology) []string {
	// apple is no longer built in: Apple names are not domestic. A rule
	// can still use the apple category (with any target).
	names := map[string]bool{"cn": true}
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

// DecidePath is the serialized ordered rule list (ordered.Snapshot) for a
// process that decides by name (ordered.LoadSnapshot / Compiled.Decide).
const DecidePath = "/etc/meridian/rules/decide.json"

// renderDecideSnapshot serializes the rule list in evaluation order with
// every target resolved (through its service group) to its mark.
func renderDecideSnapshot(t model.Topology, rules []rulePlan, def target) string {
	s := ordered.Snapshot{Version: ordered.SnapshotVersion, QUICAt: -1,
		Tail: ordered.SnapshotTail{DomesticGeosite: "cn", DirectMark: markDomestic, Default: "group:" + t.Settings.DefaultGroup, DefaultMark: def.Mark}}
	n := 0
	for _, rp := range rules {
		if rp.QUIC {
			s.QUICAt = n
			continue
		}
		n++
		r := rp.Rule
		tg := t.ResolveTarget(r)
		sr := ordered.SnapshotRule{ID: r.ID, Target: tg.Kind, Mark: rp.Mark, Action: rp.Action, GeoIPCN: isGeoIPCN(r), SourceMAC: r.SourceMAC}
		if tg.ID != "" {
			sr.Target += ":" + tg.ID
		}
		var es []ordered.Entry
		v := strings.TrimPrefix(strings.ToLower(strings.TrimSpace(r.MatchValue)), ".")
		switch r.MatchType {
		case model.MatchDomain:
			if d, ok := ordered.NormDomain(v); ok {
				es = append(es, ordered.Entry{Kind: ordered.Exact, Value: d})
			}
		case model.MatchSuffix:
			if d, ok := ordered.NormDomain(v); ok {
				es = append(es, ordered.Entry{Kind: ordered.Suffix, Value: d})
			}
		case model.MatchCIDR:
			if p, err := netip.ParsePrefix(v); err == nil {
				es = append(es, ordered.Entry{Kind: ordered.CIDR, Prefix: p.Masked()})
			} else if a, err := netip.ParseAddr(v); err == nil {
				es = append(es, ordered.Entry{Kind: ordered.CIDR, Prefix: netip.PrefixFrom(a, a.BitLen())})
			}
		case model.MatchGeosite:
			if r.Geosite != "" {
				sr.Sources = append(sr.Sources, ordered.Source{Kind: ordered.SrcGeosite, Value: lists.FileName(r.Geosite)})
			}
		case model.MatchKeyword:
			// The keyword itself (substring match, as mihomo) for a process
			// that decides by the connection's name (internal/sniff); the
			// list expansion the DNS path uses stays as a source (every name
			// in it contains the keyword, so it adds nothing to the match).
			if k, ok := ordered.NormKeyword(v); ok {
				es = append(es, ordered.Entry{Kind: ordered.Keyword, Value: k})
			}
			sr.Sources = append(sr.Sources, ordered.Source{Kind: ordered.SrcKeyword, Value: sanitize(r.ID)})
		case model.MatchRuleSet:
			sr.Sources = append(sr.Sources, ordered.Source{Kind: ordered.SrcRuleSet, Value: r.RuleSet, Exclude: RuleSetExclusions(t, r.RuleSet)})
		}
		for _, d := range r.Domains {
			if d, ok := ordered.NormDomain(strings.TrimPrefix(d, ".")); ok {
				es = append(es, ordered.Entry{Kind: ordered.Suffix, Value: d})
			}
		}
		if len(es) > 0 {
			sr.Entries = string(ordered.MarshalEntries(es))
		}
		for _, a := range []string{r.SourceIPv4, r.SourceIPv6} {
			if a != "" {
				sr.SourceAddrs = append(sr.SourceAddrs, a)
			}
		}
		s.Rules = append(s.Rules, sr)
	}
	b, _ := json.MarshalIndent(s, "", " ")
	return string(b) + "\n"
}
