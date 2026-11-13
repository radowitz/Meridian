package compile

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/radowitz/meridian/internal/defaults"
	"github.com/radowitz/meridian/internal/dnssplit"
	"github.com/radowitz/meridian/internal/model"
	"github.com/radowitz/meridian/internal/validate"
)

// The resolver policy across every kind of default this compiler has
// (docs/architecture.md「客户端 IPv6 与 AAAA」「未列名单域名的国内解析」):
// a static default exit, a group the hub switches (single hub, two hubs,
// two sharing relays), a default group whose preferred member is a nested
// exit behind a relay exit, a default group that is the relay exit's, a
// default group of one external TCP-only SOCKS exit and one mixing an
// IPv6-capable exit with an external one; each for every combination of
// clients_ipv6_via_gateway and unlisted_domestic_dns. Every topology also
// has a rule aimed at its own default group. Checked on the rendered files:
//
//   - names no list and no rule matches have exactly one upstream: the
//     default's resolver line, or (unlisted_domestic_dns) meridian-dns-split,
//     whose --exit and --exit-mark are exactly that resolver line's address
//     and -set-mark (the mark decides the path on this host and the hubs);
//   - a rule-targeted name is resolved only by its own target's upstream
//     group, which never contains a domestic resolver or meridian-dns-split,
//     with the split on as well (no silent fallback to the domestic
//     resolvers); only the domestic sets use the domestic group;
//   - AAAA: the catch-all returns AAAA only with clients_ipv6_via_gateway
//     and a default that carries IPv6 end to end; a default or rule target
//     that can reach an external exit never gets AAAA, whatever the
//     settings;
//   - every -set-mark is decimal;
//   - with an external member, the dns-split's plain-UDP exit query has a
//     path: the gateway SNATs the group-marked query to the group's
//     transit source, the carrier DNATs UDP and TCP 53 from the member's
//     transit source to the member's resolver group ahead of the rule that
//     refuses the member's other UDP and IPv6, and that resolver binds UDP
//     and TCP;
//   - with a nested member, the nested exit DNATs the group resolver range
//     to its own resolver (resolution happens there, not on the relay exit).
type dnsPolicyTopo struct {
	name string
	topo func() model.Topology
	// static: the default is not switchable (an exit server line, no mark).
	static bool
	// external, nested: the default group holds such a member.
	external, nested bool
}

func dnsPolicyTopos() []dnsPolicyTopo {
	return []dnsPolicyTopo{
		{name: "single-hub switchable", topo: func() model.Topology { t, _ := groupDNSExample(); return t }},
		{name: "single-hub static", static: true, topo: func() model.Topology {
			t, _ := groupDNSExample()
			t.Settings.DefaultGroup = "v6"
			return t
		}},
		{name: "dual-hub switchable", topo: defaults.DualHubExample},
		{name: "shared relays", topo: defaults.SharedRelaysExample},
		{name: "nested member first", nested: true, topo: func() model.Topology {
			t := defaults.NestedExample()
			t.Settings.DefaultGroup = "tw"
			return t
		}},
		{name: "relay exit's group", topo: defaults.NestedExample},
		{name: "external only", external: true, topo: func() model.Topology {
			t := defaults.ExternalExample()
			t.Settings.DefaultGroup = "my"
			return t
		}},
		{name: "external with an IPv6 exit", external: true, topo: func() model.Topology {
			t := defaults.ExternalExample()
			for i := range t.Nodes {
				if t.Nodes[i].ID == "dc2" {
					t.Nodes[i].EgressV6 = true
				}
			}
			t.Groups = append(t.Groups, model.RegionGroup{ID: "mx", Name: "混合", Region: "hk", Members: []string{"dc2", "my1"}, Mode: model.GroupAuto})
			t.Settings.DefaultGroup = "mx"
			return t
		}},
	}
}

var (
	reDomainRule = regexp.MustCompile(`^domain-rules /([^/]+)/ (.*)$`)
	reNameserver = regexp.MustCompile(`(?:^| )-nameserver (\S+)`)
	reSetMark    = regexp.MustCompile(` -set-mark (\S+)`)
)

func TestGatewayDNSPolicyAcrossDefaults(t *testing.T) {
	for _, tp := range dnsPolicyTopos() {
		for _, v6 := range []bool{false, true} {
			for _, split := range []bool{false, true} {
				name := fmt.Sprintf("%s/v6=%v,split=%v", tp.name, v6, split)
				t.Run(name, func(t *testing.T) {
					topo := tp.topo()
					topo.Settings.ClientsIPv6ViaGateway = v6
					topo.Settings.UnlistedDomesticDNS = split
					topo.Rules = append(topo.Rules, model.Rule{ID: "rule-default", Name: "default group rule", Manual: true, Priority: 3, Enabled: true,
						MatchType: model.MatchDomain, MatchValue: "def-rule.example.net", TargetGroup: topo.Settings.DefaultGroup})
					checkDNSPolicy(t, tp, topo, v6, split)
				})
			}
		}
	}
}

func checkDNSPolicy(t *testing.T, tp dnsPolicyTopo, topo model.Topology, v6, split bool) {
	t.Helper()
	b := mustCompile(t, topo)
	conf := b.File("nodes/gw/etc/smartdns/smartdns.conf")
	if conf == "" {
		t.Fatal("no gateway resolver config")
	}
	exits, groups := plans(t, topo)
	defT, ok := defaultExit(topo, groups)
	if !ok {
		t.Fatal("no default target")
	}
	if tp.static != (defT.Group == nil) {
		t.Fatalf("default switchable=%v, want static=%v", defT.Group != nil, tp.static)
	}
	var members []ExitPlan
	if defT.Group != nil {
		members = defT.Group.Try
	} else {
		members = []ExitPlan{defT.Exit}
	}
	hasExt, hasNested := false, false
	for _, e := range members {
		hasExt = hasExt || e.External
		hasNested = hasNested || e.Nested != ""
	}
	if hasExt != tp.external || hasNested != tp.nested {
		t.Fatalf("default members %v: external=%v nested=%v, want %v %v", ids(members), hasExt, hasNested, tp.external, tp.nested)
	}
	if tp.nested && members[0].Nested == "" {
		t.Fatalf("the nested exit is not the preferred member: %v", ids(members))
	}

	// AAAA of the catch-all.
	force := strings.Contains(conf, "\nforce-AAAA-SOA yes\n")
	if force == (v6 && defT.V6) {
		t.Fatalf("force-AAAA-SOA=%v with clients_v6=%v and default v6=%v", force, v6, defT.V6)
	}
	if hasExt && (defT.V6 || !force || strings.Contains(conf, "#6:inet#meridian#default6")) {
		t.Fatalf("a default that can reach an external (IPv4 TCP only) exit returns AAAA: v6=%v force=%v", defT.V6, force)
	}

	// Upstream groups and their servers.
	servers := confServers(t, conf)
	byGroup := map[string][]confServer{}
	var inDefault []confServer
	domestic := map[string]bool{}
	for _, d := range domesticDoT(topo) {
		domestic[d] = true
		domestic[d+":853"] = true
	}
	for _, s := range servers {
		byGroup[s.group] = append(byGroup[s.group], s)
		if !s.excl {
			inDefault = append(inDefault, s)
		}
		if s.mark != "" && !regexp.MustCompile(`^[0-9]+$`).MatchString(s.mark) {
			t.Fatalf("-set-mark not decimal (SmartDNS ignores a hex mark): %+v", s)
		}
		if domestic[s.addr] && s.group != "domestic" {
			t.Fatalf("a domestic resolver outside the domestic group: %+v", s)
		}
		if s.addr == DNSSplitListen && s.group != "unlisted_split" {
			t.Fatalf("meridian-dns-split in another group: %+v", s)
		}
	}
	for _, m := range reSetMark.FindAllStringSubmatch(conf, -1) {
		if _, err := strconv.ParseUint(m[1], 10, 32); err != nil {
			t.Fatalf("-set-mark %q is not decimal", m[1])
		}
	}
	defServers := byGroup[defT.dnsGroup()]
	if len(defServers) != 1 {
		t.Fatalf("default upstream group %s has %d servers: %+v", defT.dnsGroup(), len(defServers), defServers)
	}
	defLine := defServers[0]
	if defT.Group != nil && defLine.mark != strconv.FormatUint(uint64(defT.Group.Mark), 10) {
		t.Fatalf("default group line mark %q, want the group mark %d", defLine.mark, defT.Group.Mark)
	}
	if defT.Group == nil && defLine.mark != "" {
		t.Fatalf("static default line carries a mark: %+v", defLine)
	}
	if len(inDefault) != 1 {
		t.Fatalf("names no rule matches have %d upstreams: %+v", len(inDefault), inDefault)
	}
	unit := b.File("nodes/gw/etc/systemd/system/" + DNSSplitUnit)
	if split {
		if inDefault[0].addr != DNSSplitListen || !defLine.excl {
			t.Fatalf("unlisted names: upstream %+v, default line %+v", inDefault[0], defLine)
		}
		m := regexp.MustCompile(`(?m)^ExecStart=/usr/local/bin/meridian dns-split (.*)$`).FindStringSubmatch(unit)
		if m == nil {
			t.Fatalf("no dns-split unit:\n%s", unit)
		}
		cfg, err := dnssplit.ParseArgs(strings.Fields(m[1]))
		if err != nil {
			t.Fatal(err)
		}
		mark := 0
		if defLine.mark != "" {
			mark, _ = strconv.Atoi(defLine.mark)
		}
		if cfg.Exit != bracketHostPort(defLine.addr, 53) || cfg.ExitMark != mark {
			t.Fatalf("dns-split asks %s mark %d; the default's resolver line is %s mark %d", cfg.Exit, cfg.ExitMark, defLine.addr, mark)
		}
		for _, d := range cfg.Domestic {
			if !domestic[strings.TrimSuffix(d, ":53")] {
				t.Fatalf("dns-split domestic %s is not a domestic_dot resolver", d)
			}
		}
		for _, l := range []string{"CapabilityBoundingSet=CAP_NET_ADMIN\n", "AmbientCapabilities=\n", "NoNewPrivileges=yes\n", "ProtectSystem=strict\n"} {
			if !strings.Contains(unit, "\n"+l) {
				t.Fatalf("dns-split unit lacks %q", l)
			}
		}
	} else {
		if inDefault[0].addr != defLine.addr || defLine.excl || unit != "" || len(byGroup["unlisted_split"]) != 0 {
			t.Fatalf("strict: upstream %+v, default line %+v, unit %v", inDefault[0], defLine, unit != "")
		}
	}

	// Every domain rule: the domestic group only for the domestic sets;
	// every other rule's upstream group holds neither a domestic resolver
	// nor meridian-dns-split.
	rules := planRules(topo, exits, groups, nil)
	sets := map[string]rulePlan{}
	for _, rp := range rules {
		sets[rp.Set4] = rp
	}
	sawDefaultRule := false
	for _, l := range strings.Split(conf, "\n") {
		m := reDomainRule.FindStringSubmatch(l)
		if m == nil {
			continue
		}
		ns := reNameserver.FindStringSubmatch(m[2])
		if ns == nil {
			continue
		}
		switch m[1] {
		case "domain-set:gs_cn", "domain-set:gs_apple":
			if ns[1] != "domestic" {
				t.Fatalf("domestic set not on the domestic group: %s", l)
			}
			continue
		}
		if ns[1] == "domestic" || ns[1] == "unlisted_split" {
			t.Fatalf("a rule's names go to %s: %s", ns[1], l)
		}
		ups := byGroup[ns[1]]
		if len(ups) == 0 {
			t.Fatalf("rule upstream group %s has no server: %s", ns[1], l)
		}
		for _, s := range ups {
			if domestic[s.addr] || s.addr == DNSSplitListen {
				t.Fatalf("rule upstream group %s contains %s: %s", ns[1], s.addr, l)
			}
		}
		sm := reRuleSet4.FindStringSubmatch(l)
		if sm == nil {
			t.Fatalf("rule line without an IPv4 set: %s", l)
		}
		rp, ok := sets[sm[1]]
		if !ok {
			t.Fatalf("unknown rule set %s: %s", sm[1], l)
		}
		if rp.Rule.ID == "rule-default" {
			sawDefaultRule = true
			if ns[1] != defT.dnsGroup() {
				t.Fatalf("a rule on the default group resolves through %s, want %s: %s", ns[1], defT.dnsGroup(), l)
			}
		}
		if ruleReachesExternal(rp) && (!rp.FilterAAAA || !strings.Contains(l, " -address #6") || strings.Contains(l, "#6:inet#meridian#")) {
			t.Fatalf("rule %s can reach an external exit but returns AAAA: %s", rp.Rule.ID, l)
		}
	}
	if !sawDefaultRule {
		t.Fatal("the rule on the default group has no domain-rules line")
	}

	// External member: the dns-split's UDP exit query has a path.
	for _, e := range members {
		if e.External && defT.Group != nil {
			g := defT.Group
			nft := b.File("nodes/gw/etc/nftables.d/meridian.nft")
			want := fmt.Sprintf("ip6 daddr %s meta mark %#x meta l4proto { tcp, udp } th dport 53 snat ip6 to %s", g.Resolver, g.Mark, g.TransitV6)
			if !strings.Contains(nft, want) {
				t.Fatalf("gateway transit_snat lacks the group's own-query rule %q", want)
			}
			carrier := e.Node.External.Carrier
			cnft := b.File("nodes/" + carrier + "/etc/nftables.d/meridian.nft")
			dnsUDP := strings.Index(cnft, fmt.Sprintf("ip6 saddr %s ip6 daddr %s udp dport 53 dnat ip6 to [%s]:53", e.TransitV6, validate.GroupResolverNet, e.PeerULA))
			dnsTCP := strings.Index(cnft, fmt.Sprintf("ip6 saddr %s ip6 daddr %s tcp dport 53 dnat ip6 to [%s]:53", e.TransitV6, validate.GroupResolverNet, e.PeerULA))
			refuse6 := strings.Index(cnft, fmt.Sprintf("ip6 saddr %s meta l4proto { tcp, udp } dnat ip6 to [%s]:%d", e.TransitV6, e.PeerULA, ExtRefusePort))
			refuse4 := strings.Index(cnft, fmt.Sprintf("ip saddr %s meta l4proto udp dnat ip to %s:%d", e.TransitV4, e.ExtService, ExtRefusePort))
			if dnsUDP < 0 || dnsTCP < 0 || refuse6 < 0 || refuse4 < 0 || dnsUDP > refuse6 || dnsTCP > refuse6 {
				t.Fatalf("carrier %s: group DNS DNAT udp=%d tcp=%d must precede the refusal (v6 %d, v4 udp %d)", carrier, dnsUDP, dnsTCP, refuse6, refuse4)
			}
			cdns := b.File("nodes/" + carrier + "/etc/smartdns/smartdns.conf")
			for _, bind := range []string{"bind", "bind-tcp"} {
				if !strings.Contains(cdns, fmt.Sprintf("\n%s [%s]:53 -group ", bind, e.PeerULA)) {
					t.Fatalf("carrier %s resolver for %s has no %s listener", carrier, e.Node.ID, bind)
				}
			}
		}
		if e.Nested != "" && defT.Group != nil {
			nnft := b.File("nodes/" + e.Node.ID + "/etc/nftables.d/meridian.nft")
			if !strings.Contains(nnft, fmt.Sprintf("ip6 daddr %s udp dport 53 dnat ip6 to %s", validate.GroupResolverNet, e.DNSULA)) {
				t.Fatalf("nested exit %s does not answer the group resolver range itself", e.Node.ID)
			}
		}
	}
}

func ids(es []ExitPlan) []string {
	var out []string
	for _, e := range es {
		out = append(out, e.Node.ID)
	}
	return out
}

// ruleReachesExternal: the rule's mark can carry its names to an external
// exit (its own exit, or a member its group may switch to).
func ruleReachesExternal(rp rulePlan) bool {
	if rp.ViaGroup != nil {
		for _, e := range rp.ViaGroup.Try {
			if e.External {
				return true
			}
		}
		return false
	}
	return rp.Exit.External
}

// Remote-access devices ask the same resolver (the gateway's address on
// mra) and get the same policy: enabling remote access changes neither the
// resolver config nor the dns-split unit, for any setting combination.
func TestGatewayDNSPolicyRemoteAccessSame(t *testing.T) {
	for _, v6 := range []bool{false, true} {
		for _, split := range []bool{false, true} {
			with, _ := raExample(t)
			without := defaults.Example()
			for _, tp := range []*model.Topology{&with, &without} {
				tp.Settings.ClientsIPv6ViaGateway = v6
				tp.Settings.UnlistedDomesticDNS = split
			}
			bw, bo := mustCompile(t, with), mustCompile(t, without)
			for _, p := range []string{"nodes/gw/etc/smartdns/smartdns.conf", "nodes/gw/etc/systemd/system/" + DNSSplitUnit} {
				if bw.File(p) != bo.File(p) {
					t.Fatalf("v6=%v split=%v: remote access changes %s", v6, split, p)
				}
			}
			// And the devices' DNS is held to this resolver: hijacked to it
			// and admitted only from the device pool, like the LAN.
			nft := bw.File("nodes/gw/etc/nftables.d/meridian.nft")
			if !strings.Contains(nft, "mra") {
				t.Fatal("remote access not rendered")
			}
		}
	}
}

// An external exit never carries IPv6, even if egress_v6 slipped past
// validation (external_v6): targets that reach it never allow AAAA.
func TestExternalExitNeverCarriesV6(t *testing.T) {
	e := ExitPlan{Node: model.Node{ID: "x", EgressV6: true}, External: true}
	if carriesV6(e) {
		t.Fatal("external exit with egress_v6 counted as IPv6-capable")
	}
	plain := ExitPlan{Node: model.Node{ID: "y", EgressV6: true}}
	if !carriesV6(plain) {
		t.Fatal("a plain IPv6 exit is IPv6-capable")
	}
	gp := GroupPlan{HasTarget: true, Dynamic: true, Target: plain, Try: []ExitPlan{plain, e}}
	if tg, _ := groupTarget(gp); tg.V6 {
		t.Fatal("a switchable group that may switch to an external exit allows AAAA")
	}
	gp = GroupPlan{HasTarget: true, Target: e}
	if tg, _ := groupTarget(gp); tg.V6 {
		t.Fatal("a static external target allows AAAA")
	}
}
