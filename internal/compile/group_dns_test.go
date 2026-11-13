package compile

import (
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/radowitz/meridian/internal/defaults"
	"github.com/radowitz/meridian/internal/mesh"
	"github.com/radowitz/meridian/internal/model"
	"github.com/radowitz/meridian/internal/validate"
)

// Region-group DNS (docs/architecture.md「地区组的解析」): a group the hub
// switches resolves through its own resolver address, with its own mark,
// SNATed to its transit address on the gateway and DNATed to the member's
// resolver on whichever member the hub uses. These tests pin every compiled
// piece; TestNetnsGroupDNSFailover (Linux, root, opt-in) runs them together.

// groupDNSExample is the example plus a rule pinned to hk-2, a rule on the
// static (relay-reached) group v6, and the unlock map moving auto-openai to
// us-2 inside the automatic group us.
func groupDNSExample() (model.Topology, map[string]string) {
	topo := defaults.Example()
	topo.Rules = append(topo.Rules,
		model.Rule{ID: "pin-hk2", Name: "pin", Manual: true, Priority: 5, Enabled: true,
			MatchType: model.MatchDomain, MatchValue: "pin.example.com", TargetExit: "hk-2"},
		model.Rule{ID: "static-v6", Name: "static", Manual: true, Priority: 6, Enabled: true,
			MatchType: model.MatchDomain, MatchValue: "v6only.example.com", TargetGroup: "v6"},
	)
	return topo, map[string]string{"auto-openai": "us-2"}
}

var reServer = regexp.MustCompile(`^server(?:-tls|-tcp)? (\S+)(.*)$`)

type dnsServer struct {
	addr, group string
	excl        bool
	mark        string
	line        string
}

func smartDNSServers(t *testing.T, conf string) []dnsServer {
	t.Helper()
	var out []dnsServer
	for _, l := range strings.Split(conf, "\n") {
		m := reServer.FindStringSubmatch(l)
		if m == nil {
			continue
		}
		f := strings.Fields(m[2])
		s := dnsServer{addr: m[1], line: l}
		for i := 0; i < len(f); i++ {
			switch f[i] {
			case "-group":
				s.group = f[i+1]
				i++
			case "-exclude-default-group":
				s.excl = true
			case "-set-mark":
				s.mark = f[i+1]
				i++
			default:
				t.Fatalf("unexpected server option %q in %s", f[i], l)
			}
		}
		if s.group == "" {
			t.Fatalf("server without a group: %s", l)
		}
		out = append(out, s)
	}
	return out
}

// nameserverOf returns the -nameserver of the domain-rules line for domain.
func nameserverOf(t *testing.T, conf, domain string) string {
	t.Helper()
	re := regexp.MustCompile(`(?m)^domain-rules /` + regexp.QuoteMeta(domain) + `/ -nameserver (\S+) `)
	m := re.FindStringSubmatch(conf)
	if m == nil {
		t.Fatalf("no domain-rules for %s", domain)
	}
	return m[1]
}

func TestGroupResolverAddresses(t *testing.T) {
	topo, _ := groupDNSExample()
	exits, groups := plans(t, topo)
	tunnels, err := buildTunnels(topo)
	if err != nil {
		t.Fatal(err)
	}
	if validate.GroupResolverNet.String() != "fd66::53:0/112" {
		t.Fatalf("reserved range moved: %s", validate.GroupResolverNet)
	}
	seen := map[string]string{}
	for _, g := range groups {
		a := netip.MustParseAddr(g.Resolver)
		if !validate.GroupResolverNet.Contains(a) || a.String() != g.Resolver {
			t.Fatalf("group %s resolver %s outside %s or not canonical", g.Group.ID, g.Resolver, validate.GroupResolverNet)
		}
		if prev, dup := seen[g.Resolver]; dup {
			t.Fatalf("groups %s and %s share resolver %s", prev, g.Group.ID, g.Resolver)
		}
		seen[g.Resolver] = g.Group.ID
		if !strings.HasPrefix(g.DNSGroup, "rg_") {
			t.Fatalf("group %s DNS group %q", g.Group.ID, g.DNSGroup)
		}
		for _, e := range exits {
			if e.Group == g.DNSGroup {
				t.Fatalf("group %s DNS group collides with exit %s", g.Group.ID, e.Node.ID)
			}
		}
	}
	// No node owns an address in fd66::/64: no tunnel address, no transit
	// address, so no node has an on-link route to a resolver address.
	res64 := netip.MustParsePrefix("fd66::/64")
	for _, tun := range tunnels {
		for _, s := range []string{tun.WestULA, tun.EastULA} {
			if res64.Contains(netip.MustParseAddr(s)) {
				t.Fatalf("tunnel %s address %s inside the reserved %s", tun.Iface(), s, res64)
			}
		}
	}
	for _, m := range markPlans(exits, groups) {
		if res64.Contains(netip.MustParseAddr(m.TransitV6)) {
			t.Fatalf("transit %s inside %s", m.TransitV6, res64)
		}
	}
	// The tunnel allocator's own addresses (links without explicit ULAs,
	// and every WSS companion) stay out of the reserved /64 for any count.
	for i := 0; i < 256; i++ {
		_, _, w, e := allocatedAddrs(i)
		_, _, cw, ce := companionAddrs(i)
		for _, s := range []string{w, e, cw, ce} {
			if res64.Contains(netip.MustParseAddr(s)) {
				t.Fatalf("allocator address %s (link %d) inside %s", s, i, res64)
			}
		}
	}
}

// SmartDNS: one upstream group per switchable region group with only the
// group's resolver address, the group mark in decimal (hex is silently
// ignored by SmartDNS); rules on such a group use it; pinned rules,
// unlock-moved rules and static groups keep the exit's resolver; no
// domestic resolver is ever in a group's upstream set, and only the
// default group's upstream is in SmartDNS's default group.
func TestGroupDNSSmartDNS(t *testing.T) {
	topo, decisions := groupDNSExample()
	exits, groups := plans(t, topo)
	b, err := CompileWithDecisions(topo, decisions)
	if err != nil {
		t.Fatal(err)
	}
	conf := b.File("nodes/gw/etc/smartdns/smartdns.conf")
	if regexp.MustCompile(`-set-mark 0[xX]`).MatchString(conf) {
		t.Fatal("a hex -set-mark: SmartDNS 1.2026.11.09 accepts it and applies no mark")
	}
	servers := smartDNSServers(t, conf)
	byGroup := map[string][]dnsServer{}
	for _, s := range servers {
		byGroup[s.group] = append(byGroup[s.group], s)
	}
	def := mustGroup(t, groups, topo.Settings.DefaultGroup)
	if !def.Dynamic {
		t.Fatal("the example's default group must be switchable for this test")
	}
	dynamic := 0
	for _, g := range groups {
		ss := byGroup[g.DNSGroup]
		if !g.Dynamic {
			if len(ss) != 0 {
				t.Fatalf("static group %s has a resolver upstream: %v", g.Group.ID, ss)
			}
			continue
		}
		dynamic++
		if len(ss) != 1 {
			t.Fatalf("group %s: want exactly one upstream, got %v", g.Group.ID, ss)
		}
		s := ss[0]
		if s.addr != g.Resolver || s.mark != strconv.FormatUint(uint64(g.Mark), 10) {
			t.Fatalf("group %s upstream %q: want %s with -set-mark %d", g.Group.ID, s.line, g.Resolver, g.Mark)
		}
		if s.excl == (g.Group.ID == def.Group.ID) {
			t.Fatalf("group %s upstream default-group membership wrong: %s", g.Group.ID, s.line)
		}
	}
	if dynamic < 5 {
		t.Fatalf("only %d switchable groups in the example", dynamic)
	}
	// Default group: exactly the default region group's resolver. Domestic
	// servers only in "domestic"; marks only on group resolvers.
	var inDefault []string
	for _, s := range servers {
		if !s.excl {
			inDefault = append(inDefault, s.line)
		}
		a, err := netip.ParseAddr(strings.Split(s.addr, ":853")[0])
		isGroupAddr := err == nil && validate.GroupResolverNet.Contains(a)
		if isGroupAddr != (s.mark != "") || isGroupAddr != strings.HasPrefix(s.group, "rg_") {
			t.Fatalf("mark / group / address disagree: %s", s.line)
		}
		for _, d := range topo.Settings.DomesticDoT {
			if strings.HasPrefix(s.addr, d) && s.group != "domestic" {
				t.Fatalf("domestic resolver outside group domestic: %s", s.line)
			}
		}
	}
	if len(inDefault) != 1 || !strings.HasPrefix(inDefault[0], "server "+def.Resolver+" -group "+def.DNSGroup+" ") {
		t.Fatalf("default group members: %v", inDefault)
	}
	us, usPin := mustGroup(t, groups, "us"), mustGroup(t, groups, "us-pin")
	us2, _ := exitByID(exits, "us-2")
	hk2, _ := exitByID(exits, "hk-2")
	v6 := mustGroup(t, groups, "v6")
	for domain, want := range map[string]string{
		"claude.ai":          us.DNSGroup,     // automatic group, not moved
		"openai.com":         us2.Group,       // moved by the unlock map: pinned to us-2's own resolver
		"api.example.com":    usPin.DNSGroup,  // manual group with fallback: follows the hub too
		"pin.example.com":    hk2.Group,       // pinned exit
		"v6only.example.com": v6.Target.Group, // static group: its member's resolver
		"netflix.com":        mustGroup(t, groups, "hk-residential").DNSGroup,
	} {
		if got := nameserverOf(t, conf, domain); got != want {
			t.Errorf("%s resolved by %s, want %s", domain, got, want)
		}
	}
	// Every -nameserver names a defined upstream group.
	for _, m := range regexp.MustCompile(`-nameserver (\S+)`).FindAllStringSubmatch(conf, -1) {
		if len(byGroup[m[1]]) == 0 {
			t.Errorf("-nameserver %s has no server", m[1])
		}
	}
}

// natRule is one rule of the gateway's transit_snat chain, parsed into the
// predicates the chain uses.
type natRule struct {
	saddr, daddr netip.Prefix
	mark         uint32
	hasMark      bool
	l4           []string
	dport        string
	oif          string
	to           string
	text         string
}

type natPkt struct {
	v6           bool
	saddr, daddr string
	mark         uint32
	l4           string
	dport        int
	oif          string
}

func parseSNAT(t *testing.T, nft string) []natRule {
	t.Helper()
	main := nftBlock(t, nft, "meridian")
	i := strings.Index(main, "  chain transit_snat {\n")
	if i < 0 {
		t.Fatal("no transit_snat")
	}
	j := strings.Index(main[i:], "\n  }\n")
	var out []natRule
	for _, l := range strings.Split(main[i:i+j], "\n")[2:] {
		rule, _, _ := strings.Cut(strings.TrimSpace(l), " comment ")
		f := strings.Fields(rule)
		r := natRule{text: rule}
		pfx := func(s string) netip.Prefix {
			if p, err := netip.ParsePrefix(s); err == nil {
				return p
			}
			a := netip.MustParseAddr(s)
			return netip.PrefixFrom(a, a.BitLen())
		}
		for k := 0; k < len(f); k++ {
			switch {
			case (f[k] == "ip" || f[k] == "ip6") && f[k+1] == "saddr":
				r.saddr = pfx(f[k+2])
				k += 2
			case (f[k] == "ip" || f[k] == "ip6") && f[k+1] == "daddr":
				r.daddr = pfx(f[k+2])
				k += 2
			case f[k] == "meta" && f[k+1] == "mark":
				v, _ := strconv.ParseUint(f[k+2], 0, 32)
				r.mark, r.hasMark = uint32(v), true
				k += 2
			case f[k] == "meta" && f[k+1] == "l4proto":
				r.l4 = []string{"tcp", "udp"}
				if f[k+2] != "{" || f[k+3] != "tcp," || f[k+4] != "udp" || f[k+5] != "}" {
					t.Fatalf("unparsed l4proto: %s", rule)
				}
				k += 5
			case f[k] == "th" && f[k+1] == "dport":
				r.dport = f[k+2]
				k += 2
			case f[k] == "oifname":
				r.oif = strings.Trim(f[k+1], `"`)
				k++
			case f[k] == "snat":
				r.to = f[len(f)-1]
				k = len(f)
			case f[k] == "masquerade":
				r.to = "masquerade"
			default:
				t.Fatalf("unparsed snat token %q in %s", f[k], rule)
			}
		}
		out = append(out, r)
	}
	return out
}

// snatOf evaluates transit_snat for p: the first matching rule's
// translation, or "" (untranslated).
func snatOf(rules []natRule, p natPkt) string {
	for _, r := range rules {
		if r.saddr.IsValid() && (r.saddr.Addr().Is6() != p.v6 || !r.saddr.Contains(netip.MustParseAddr(p.saddr))) {
			continue
		}
		if r.daddr.IsValid() && (r.daddr.Addr().Is6() != p.v6 || !r.daddr.Contains(netip.MustParseAddr(p.daddr))) {
			continue
		}
		if r.hasMark && r.mark != p.mark {
			continue
		}
		if r.l4 != nil && !in(r.l4, p.l4) {
			continue
		}
		if r.dport != "" && r.dport != strconv.Itoa(p.dport) {
			continue
		}
		if r.oif != "" && r.oif != p.oif {
			continue
		}
		return r.to
	}
	return ""
}

// Gateway: the resolver SNAT is exactly as narrow as documented, and the
// paths that could carry a group-resolver packet anywhere else are closed:
// LAN and device ingress drop every fc00::/7 destination before any rule
// can mark it, the guard drops forwarded DNS, and the marked output lookup
// has only the west tunnel or a blackhole/unreachable behind it.
func TestGroupDNSGatewaySNAT(t *testing.T) {
	for _, tc := range []struct {
		name string
		topo func() model.Topology
	}{
		{"global LAN prefix, remote access", func() model.Topology { tp, _ := raExample(t); return tp }},
		{"ULA LAN prefix", func() model.Topology { return ulaLANExample(t) }},
		{"example", func() model.Topology { return defaults.Example() }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			topo := tc.topo()
			b := mustCompile(t, topo)
			nft := b.File("nodes/gw/etc/nftables.d/meridian.nft")
			routes := b.File("nodes/gw/usr/local/sbin/meridian-routes.sh")
			rules := parseSNAT(t, nft)
			exits, groups := plans(t, topo)
			tunnels, _ := buildTunnels(topo)
			var tunULA string
			for _, tun := range tunnels {
				if tun.West.Role == model.RoleGateway {
					tunULA = tun.WestULA
					break
				}
			}
			us, hk := mustGroup(t, groups, "us"), mustGroup(t, groups, "hk")
			usExit, _ := exitByID(exits, "us")
			lan6 := "2001:db8:100::50"
			if p, ok := lanULAPrefix(topo); ok {
				lan6 = p.Addr().Next().String()
			}
			cases := []struct {
				what string
				p    natPkt
				want string
			}{
				{"own UDP query, group mark, group resolver", natPkt{true, tunULA, us.Resolver, us.Mark, "udp", 53, "m02"}, us.TransitV6},
				{"own TCP query", natPkt{true, tunULA, us.Resolver, us.Mark, "tcp", 53, "m02"}, us.TransitV6},
				{"source already the transit address", natPkt{true, us.TransitV6, us.Resolver, us.Mark, "udp", 53, "m02"}, us.TransitV6},
				{"default group", natPkt{true, tunULA, hk.Resolver, hk.Mark, "udp", 53, "m02"}, hk.TransitV6},
				{"other port", natPkt{true, tunULA, us.Resolver, us.Mark, "udp", 853, "m02"}, ""},
				{"unmarked", natPkt{true, tunULA, us.Resolver, 0, "udp", 53, "m02"}, ""},
				{"another group's mark", natPkt{true, tunULA, us.Resolver, hk.Mark, "udp", 53, "m02"}, ""},
				{"the member's own mark", natPkt{true, tunULA, us.Resolver, usExit.Mark, "udp", 53, "m02"}, ""},
				{"domestic mark", natPkt{true, tunULA, us.Resolver, markDomestic, "udp", 53, "eth0"}, ""},
				{"group mark to a per-exit resolver", natPkt{true, tunULA, usExit.DNSULA, us.Mark, "udp", 53, "m02"}, ""},
				{"group mark to another resolver address", natPkt{true, tunULA, validate.GroupResolverAddr(200).String(), us.Mark, "udp", 53, "m02"}, ""},
				{"icmp", natPkt{true, tunULA, us.Resolver, us.Mark, "icmpv6", 0, "m02"}, ""},
			}
			for _, c := range cases {
				if got := snatOf(rules, c.p); got != c.want {
					t.Errorf("%s: %+v translated to %q, want %q", c.what, c.p, got, c.want)
				}
			}
			// A LAN client's v6 with the group mark would match the group's
			// data SNAT, but it can never carry that mark to a resolver
			// address: the classifier drops fc00::/7 first.
			if topo.Settings.LANIPv6Prefix != "" {
				if got := snatOf(rules, natPkt{true, lan6, us.Resolver, us.Mark, "udp", 53, "m02"}); got != us.TransitV6 {
					t.Fatalf("model check: LAN data SNAT %q", got)
				}
			}
			chain := classifyChain(t, nft)
			for _, g := range groups {
				if !g.Dynamic {
					if strings.Contains(nft, g.Resolver+" ") {
						t.Fatalf("static group %s has a resolver SNAT", g.Group.ID)
					}
					continue
				}
				if v := classify6(t, chain, g.Resolver); v != "drop" {
					t.Fatalf("LAN ingress to %s classified %s, want drop", g.Resolver, v)
				}
			}
			guard := parseGuard(t, nftBlock(t, nft, tableGuard))
			for _, iif := range []string{gatewayLAN(topo), model.RemoteAccessIface} {
				if v := verdict(guard, pkt{iif: iif, oif: "m02", mark: us.Mark, daddr: us.Resolver, dns: true}); v != "drop" && (iif == gatewayLAN(topo) || planRemote(topo) != nil) {
					t.Fatalf("guard lets forwarded DNS from %s to %s through: %s", iif, us.Resolver, v)
				}
			}
			// Output path of a marked query: "fwmark M lookup 102" then
			// "fwmark M unreachable"; table 102 (v6) has the west tunnel and
			// a blackhole default, and nothing else that covers fd66::53:0/112;
			// main (unmarked) has fd66::/48 into the tunnel and a blackhole.
			for _, g := range groups {
				if !g.Dynamic {
					continue
				}
				for _, want := range []string{
					fmt.Sprintf("ip -6 rule add fwmark %#x lookup 102 priority %d\n", g.Mark, prioExitBase+g.Index),
					fmt.Sprintf("ip -6 rule add fwmark %#x unreachable priority %d\n", g.Mark, prioExitDrop+g.Index),
				} {
					if !strings.Contains(routes, want) {
						t.Fatalf("routes lack %q", want)
					}
				}
			}
			udp, wss, _ := gatewayIfaces(tunnels)
			if udp.LinkID == "" {
				udp = wss
			}
			res := netip.MustParseAddr(us.Resolver)
			saw102 := map[string]bool{}
			reRoute := regexp.MustCompile(`(?m)^ip -6 route replace (blackhole )?(\S+) (?:dev (\S+) )?(?:metric \d+ )?table 102$`)
			for _, m := range reRoute.FindAllStringSubmatch(routes, -1) {
				dst := strings.Trim(m[2], "'")
				covers := dst == "default"
				if p, err := netip.ParsePrefix(dst); err == nil {
					covers = p.Contains(res)
				}
				if !covers {
					continue
				}
				switch {
				case m[1] != "":
					saw102["blackhole"] = true
				case strings.Trim(m[3], "'") == udp.Iface():
					saw102["west"] = true
				default:
					t.Fatalf("table 102 sends the resolver address elsewhere: %s", m[0])
				}
			}
			if !saw102["west"] || !saw102["blackhole"] {
				t.Fatalf("table 102 (v6) must hold the west tunnel and a blackhole for %s: %v", res, saw102)
			}
			for _, want := range []string{"ip -6 route replace fd66::/48 dev '" + udp.Iface() + "'\n", "ip -6 route replace blackhole fd66::/48 metric 32767\n"} {
				if !strings.Contains(routes, want) {
					t.Fatalf("routes lack %q", want)
				}
			}
		})
	}
}

// Exits: every exit the hub can switch a group to DNATs the whole resolver
// range, from its hub tunnel, to the address its resolver binds; a group's
// Mesh resolver member does the same from mmesh, and only it. Nothing else
// is translated and other exits are unchanged.
func TestGroupDNSExitDNAT(t *testing.T) {
	topo, _ := groupDNSExample()
	b := mustCompile(t, topo)
	exits, groups := plans(t, topo)
	tunnels, _ := buildTunnels(topo)
	members := map[string]bool{}
	for _, g := range groups {
		for _, e := range g.Try {
			members[e.Node.ID] = true
		}
	}
	reDNAT := regexp.MustCompile(`(?m)^    iifname \{ ("[^"]+"(?:, "[^"]+")*) \} ip6 daddr (\S+) meta l4proto \{ tcp, udp \} th dport 53 dnat ip6 to (\S+) comment `)
	reMesh := regexp.MustCompile(`(?m)^    iifname "mmesh" ip6 daddr (\S+) meta l4proto \{ tcp, udp \} th dport 53 dnat ip6 to (\S+) comment `)
	meshExits := 0
	for _, e := range exits {
		nft := b.File("nodes/" + e.Node.ID + "/etc/nftables.d/meridian.nft")
		dns := b.File("nodes/" + e.Node.ID + "/etc/smartdns/smartdns.conf")
		meshIn := len(meshDNSGroups(groups, e.Node.ID)) > 0
		has := strings.Contains(nft, "chain group_dns {")
		if members[e.Node.ID] && !has {
			t.Fatalf("group member %s does not answer the group resolver addresses", e.Node.ID)
		}
		if has != (switchable(e) || meshIn) {
			t.Fatalf("exit %s: group_dns chain %v, switchable %v, Mesh resolver %v", e.Node.ID, has, switchable(e), meshIn)
		}
		if !has {
			if strings.Contains(nft, "fd66::53") || strings.Contains(nft, "mmesh") {
				t.Fatalf("exit %s mentions the resolver range or mmesh without the chain", e.Node.ID)
			}
			continue
		}
		ms := reDNAT.FindAllStringSubmatch(nft, -1)
		mm := reMesh.FindAllStringSubmatch(nft, -1)
		wantHub, wantMesh := 0, 0
		if switchable(e) {
			wantHub = 1
		}
		if meshIn {
			wantMesh = 1
			meshExits++
		}
		if len(ms) != wantHub || len(mm) != wantMesh || strings.Count(nft, " dnat ") != wantHub+wantMesh {
			t.Fatalf("exit %s: want %d hub-tunnel and %d Mesh DNAT rules:\n%s", e.Node.ID, wantHub, wantMesh, nft)
		}
		for _, m := range ms {
			if m[2] != validate.GroupResolverNet.String() || m[3] != e.DNSULA {
				t.Fatalf("exit %s DNAT %s -> %s, want %s -> %s", e.Node.ID, m[2], m[3], validate.GroupResolverNet, e.DNSULA)
			}
			want := `"` + hubDirect(tunnels, e.Node.ID).Iface() + `"`
			if m[1] != want || strings.Contains(m[1], `"`+e.Node.WANInterface+`"`) {
				t.Fatalf("exit %s DNAT ingress %s, want only the hub tunnel %s", e.Node.ID, m[1], want)
			}
			// The reply goes to a transit address: routed back into the tunnel.
			routes := b.File("nodes/" + e.Node.ID + "/usr/local/sbin/meridian-routes.sh")
			if !strings.Contains(routes, "ip -6 route replace "+transitV6Net()+" dev "+strings.Trim(want, `"`)+"\n") {
				t.Fatalf("exit %s does not route the transit prefix back into its hub tunnel", e.Node.ID)
			}
		}
		for _, m := range mm {
			if m[1] != validate.GroupResolverNet.String() || m[2] != e.DNSULA {
				t.Fatalf("exit %s Mesh DNAT %s -> %s, want %s -> %s", e.Node.ID, m[1], m[2], validate.GroupResolverNet, e.DNSULA)
			}
		}
		if !strings.Contains(dns, "bind ["+e.DNSULA+"]:53\n") || !strings.Contains(dns, "bind-tcp ["+e.DNSULA+"]:53\n") {
			t.Fatalf("exit %s resolver does not bind the DNAT target %s:\n%s", e.Node.ID, e.DNSULA, dns)
		}
		if !strings.Contains(nft, "type nat hook prerouting priority dstnat; policy accept;") {
			t.Fatalf("exit %s DNAT chain hook:\n%s", e.Node.ID, nft)
		}
		mark := fmt.Sprintf("%#x", markMeshDNS)
		if meshIn != strings.Contains(nft, mark) {
			t.Fatalf("exit %s: Mesh return mark %s present=%v, Mesh resolver %v", e.Node.ID, mark, strings.Contains(nft, mark), meshIn)
		}
		if !meshIn {
			continue
		}
		for _, line := range []string{
			"    type filter hook prerouting priority mangle; policy accept;\n    iifname \"mmesh\" ip6 daddr " + validate.GroupResolverNet.String() + " meta l4proto { tcp, udp } th dport 53 ct mark set " + mark + " comment ",
			"    type nat hook input priority 100; policy accept;\n    iifname \"mmesh\" ct mark " + mark + " ip6 daddr " + e.DNSULA + " meta l4proto { tcp, udp } th dport 53 snat ip6 to " + meshDNSAnchor + " comment ",
			"    type route hook output priority mangle; policy accept;\n    ct direction reply ct mark " + mark + " meta mark set " + mark + " comment ",
		} {
			if !strings.Contains(nft, line) {
				t.Fatalf("exit %s misses %q:\n%s", e.Node.ID, line, nft)
			}
		}
		// The mark and the anchor rewrite are only ever applied to what
		// arrived on mmesh: every rule naming the mark is one of the three.
		if n := strings.Count(nft, mark); n != 4 {
			t.Fatalf("exit %s names the Mesh mark %d times, want 4:\n%s", e.Node.ID, n, nft)
		}
	}
	if meshExits == 0 {
		t.Fatal("the example has no Mesh resolver exit")
	}
}

// Hub: the group's transit source selects the group table before anything
// else could catch an fd66 destination, and the group table sends the
// resolver address to the member it points at (group_hop installs the
// same default for v4 and v6). No hub change was needed for this.
func TestGroupDNSHubPath(t *testing.T) {
	topo := defaults.Example()
	b := mustCompile(t, topo)
	_, groups := plans(t, topo)
	routes := b.File("nodes/hk-hub/usr/local/sbin/meridian-routes.sh")
	failover := b.File("nodes/hk-hub/usr/local/sbin/meridian-failover.sh")
	for _, g := range groups {
		if !g.Dynamic {
			continue
		}
		prio := prioHubExitFrom + g.Index
		if !strings.Contains(routes, fmt.Sprintf("ip -6 rule add from %s/128 lookup %d priority %d\n", g.TransitV6, g.Table, prio)) {
			t.Fatalf("no v6 source rule for group %s", g.Group.ID)
		}
		for _, m := range regexp.MustCompile(`(?m)^ip -6 rule add (.+) priority (\d+)$`).FindAllStringSubmatch(routes, -1) {
			p, _ := strconv.Atoi(m[2])
			if p < prio && !strings.HasPrefix(m[1], "from fd66:0:0:ff::") {
				t.Fatalf("v6 rule ahead of group %s: %s", g.Group.ID, m[0])
			}
		}
		res := netip.MustParseAddr(g.Resolver)
		re := regexp.MustCompile(fmt.Sprintf(`(?m)^ip -6 route replace (\S+) .*table %d$`, g.Table))
		for _, m := range re.FindAllStringSubmatch(routes, -1) {
			if p, err := netip.ParsePrefix(strings.Trim(m[1], "'")); err == nil && p.Contains(res) {
				t.Fatalf("group %s table has a specific route over its resolver: %s", g.Group.ID, m[0])
			}
		}
		if !strings.Contains(routes, fmt.Sprintf("group_hop %d '%s'\n", g.Table, g.Target.HubIface)) {
			t.Fatalf("group %s not hopped to its target", g.Group.ID)
		}
	}
	if !strings.Contains(failover, `ip -6 route replace default dev "$dev" table "$table"`) {
		t.Fatal("group_hop no longer moves the IPv6 default with the member")
	}
}

// Without a switchable group nothing of this exists anywhere.
func TestGroupDNSAbsentWithoutSwitchableGroup(t *testing.T) {
	topo := defaults.Example()
	var keep []model.RegionGroup
	for _, g := range topo.Groups {
		if g.ID == "v6" {
			keep = append(keep, g)
		}
	}
	topo.Groups = keep
	topo.Settings.DefaultGroup = "v6"
	for i := range topo.Rules {
		switch {
		case topo.Rules[i].TargetGroup == "":
		case topo.Rules[i].RequireResidential:
			topo.Rules[i].TargetGroup, topo.Rules[i].TargetExit = "", "hk-resi"
		default:
			topo.Rules[i].TargetGroup = "v6"
		}
	}
	b := mustCompile(t, topo)
	_, groups := plans(t, topo)
	if len(groups) != 1 || groups[0].Dynamic {
		t.Fatalf("want one static group: %+v", groups)
	}
	verify := b.File("nodes/gw/usr/local/sbin/meridian-verify.sh")
	if !strings.Contains(verify, "\ngrp_dns=''\n") {
		t.Fatal("the verify script expects group resolvers without a switchable group")
	}
	for path, body := range b.Files {
		if strings.HasSuffix(path, "/meridian-verify.sh") {
			continue // its fixed check code names the options; grp_dns is empty
		}
		for _, bad := range []string{"fd66::53", "-set-mark", "rg_", "group_dns", "resolver: this host's own queries", "Region groups resolve through"} {
			if strings.Contains(body, bad) {
				t.Fatalf("%s contains %q without a switchable group", path, bad)
			}
		}
	}
	conf := b.File("nodes/gw/etc/smartdns/smartdns.conf")
	v6exit, _ := exitByID(planExits(topo, mustTunnels(t, topo)), "v6-exit")
	if !strings.Contains(conf, "server "+v6exit.DNSULA+" -group "+v6exit.Group+"\n") {
		t.Fatalf("the static default target's resolver must stay the default upstream:\n%s", conf)
	}
}

func mustTunnels(t *testing.T, topo model.Topology) []Tunnel {
	t.Helper()
	tunnels, err := buildTunnels(topo)
	if err != nil {
		t.Fatal(err)
	}
	return tunnels
}

// Mesh backup (docs/architecture.md「地区组的解析」): each switchable group
// with a Mesh hop has one Mesh resolver member (the first member of its
// order that has a standby Mesh edge and a tunnel resolver); that exit's
// compiled meridian-mesh-up.sh names the group's resolver/128 for its Mesh
// node to publish, and mesh.BuildPlan turns exactly those lines into
// Cloudflare routes of that exit. Nobody else publishes or answers.
func TestGroupDNSMeshResolverPublication(t *testing.T) {
	topo, _ := groupDNSExample()
	b := mustCompile(t, topo)
	exits, groups := plans(t, topo)
	want := map[string]string{} // resolver/128 -> exit
	for _, g := range groups {
		if !g.Dynamic || !g.Mesh {
			if g.MeshResolver != "" {
				t.Fatalf("group %s without a Mesh hop has a Mesh resolver %s", g.Group.ID, g.MeshResolver)
			}
			continue
		}
		first := ""
		for _, id := range g.Selection.Order {
			if e, ok := exitByID(exits, id); ok && e.DNSULA != "" && hubMeshStandby(topo, id) {
				first = id
				break
			}
		}
		if g.MeshResolver != first {
			t.Fatalf("group %s Mesh resolver %q, want the first capable member %q", g.Group.ID, g.MeshResolver, first)
		}
		if first != "" {
			want[g.Resolver+"/128"] = first
		}
	}
	if want[mustGroup(t, groups, "us").Resolver+"/128"] != "us" || want[mustGroup(t, groups, "hk").Resolver+"/128"] != "hk-ix" {
		t.Fatalf("example Mesh resolvers: %v", want)
	}
	reMarker := regexp.MustCompile(`(?m)^` + regexp.QuoteMeta(mesh.PublishMarker) + ` (\S+) group=(\S+)$`)
	got := map[string]string{}
	for path, body := range b.Files {
		for _, m := range reMarker.FindAllStringSubmatch(body, -1) {
			if !strings.HasSuffix(path, "/usr/local/sbin/meridian-mesh-up.sh") {
				t.Fatalf("%s carries a publish line", path)
			}
			node := strings.Split(strings.TrimPrefix(path, "nodes/"), "/")[0]
			if prev, dup := got[m[1]]; dup {
				t.Fatalf("%s published by %s and %s", m[1], prev, node)
			}
			got[m[1]] = node
			g := mustGroup(t, groups, m[2])
			if m[1] != g.Resolver+"/128" {
				t.Fatalf("%s: publish line for group %s names %s, its resolver is %s", path, m[2], m[1], g.Resolver)
			}
		}
	}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("publish lines %v, want %v", got, want)
	}
	plan := mesh.BuildPlan(topo, b.Files)
	pub := map[string]string{}
	for _, r := range plan.Routes {
		if r.Purpose != mesh.PurposeGroupResolver {
			if strings.HasPrefix(r.Network, "fd66:") {
				t.Fatalf("operator route in fd66::/48: %+v", r)
			}
			continue
		}
		pub[r.Network] = r.ExitID
		if want[r.Network] != r.ExitID || r.Group == "" {
			t.Fatalf("plan publishes %+v", r)
		}
	}
	if fmt.Sprint(pub) != fmt.Sprint(want) {
		t.Fatalf("plan routes %v, want %v", pub, want)
	}
	for _, is := range plan.Issues {
		if is.Code == "mesh_publish_invalid" || (is.Code == "mesh_route_overlap" && strings.Contains(is.Message, "fd66::53")) {
			t.Fatalf("plan rejects the compiled publication: %+v", is)
		}
	}
	if mesh.GroupResolverNet != validate.GroupResolverNet {
		t.Fatalf("mesh.GroupResolverNet %s != validate.GroupResolverNet %s", mesh.GroupResolverNet, validate.GroupResolverNet)
	}
}

// The exit's return path for queries that came over the Mesh: table 171
// holds only "default via <sidecar> dev mmesh" (while sealed) and a
// blackhole, reached by the reply mark and the anchor address; the routes
// script and meridian-mesh-up.sh run the same mesh_dns_return; the exit
// re-seals on a timer. Exits that are no group's Mesh resolver have none
// of it.
func TestGroupDNSMeshReturnPath(t *testing.T) {
	topo, _ := groupDNSExample()
	b := mustCompile(t, topo)
	exits, groups := plans(t, topo)
	fn := meshDNSReturnShell()
	ma := mesh.DefaultAddressing()
	reTable := regexp.MustCompile(fmt.Sprintf(`(?m)^.*\btable %d\b.*$`, tableMeshDNS))
	n := 0
	for _, e := range exits {
		pre := "nodes/" + e.Node.ID + "/"
		routes := b.File(pre + "usr/local/sbin/meridian-routes.sh")
		up := b.File(pre + "usr/local/sbin/meridian-up.sh")
		meshUp := b.Files[pre+"usr/local/sbin/meridian-mesh-up.sh"]
		rt := b.File(pre + "etc/iproute2/rt_tables.d/meridian.conf")
		_, unit := b.Files[pre+"etc/systemd/system/meridian-mesh-seal.timer"]
		if len(meshDNSGroups(groups, e.Node.ID)) == 0 {
			if strings.Contains(routes, "mesh_dns_return") || strings.Contains(meshUp, "mesh_dns_return") || strings.Contains(rt, "171") || unit || strings.Contains(up, "meridian-mesh-seal") {
				t.Fatalf("exit %s is no Mesh resolver but has the Mesh DNS return path", e.Node.ID)
			}
			continue
		}
		n++
		if !strings.Contains(routes, fn+"mesh_dns_return\n") || !strings.Contains(meshUp, fn+"trap mesh_dns_return EXIT\n") {
			t.Fatalf("exit %s: routes script and mesh-up do not share mesh_dns_return", e.Node.ID)
		}
		for _, l := range []string{
			fmt.Sprintf("ip -6 rule add fwmark %#x lookup %d priority %d\n", markMeshDNS, tableMeshDNS, prioMeshDNS),
			fmt.Sprintf("ip -6 rule add to %s/128 lookup %d priority %d\n", meshDNSAnchor, tableMeshDNS, prioMeshDNS+1),
		} {
			if !strings.Contains(routes, l) {
				t.Fatalf("exit %s routes miss %q", e.Node.ID, l)
			}
		}
		// Every route of table 171, in either script: the sidecar next-hop
		// on mmesh or a blackhole. Never the hub tunnel, never the WAN.
		for _, body := range []string{routes, meshUp} {
			for _, l := range reTable.FindAllString(body, -1) {
				l = strings.TrimSpace(l)
				switch {
				case strings.Contains(l, "rule add"), strings.Contains(l, "rule del"), strings.HasPrefix(l, "echo "), strings.HasPrefix(l, "#"):
				case strings.Contains(l, "route replace blackhole default metric 32767 table 171"):
				case strings.Contains(l, "route replace default via "+ma.NextHopV6()+" dev mmesh table 171"),
					strings.Contains(l, "route del default via "+ma.NextHopV6()+" dev mmesh table 171"):
				default:
					t.Fatalf("exit %s: unexpected table 171 line %q", e.Node.ID, l)
				}
				if strings.Contains(l, " dev "+hubDirect(mustTunnels(t, topo), e.Node.ID).Iface()) || strings.Contains(l, "eth0") {
					t.Fatalf("exit %s: table 171 leaves through the tunnel or WAN: %q", e.Node.ID, l)
				}
			}
		}
		if !strings.Contains(rt, fmt.Sprintf("%d\tmeridian_mesh_dns\n", tableMeshDNS)) {
			t.Fatalf("exit %s rt_tables:\n%s", e.Node.ID, rt)
		}
		if !unit || !strings.Contains(up, "enable_unit meridian-mesh-seal.timer\n") ||
			!strings.Contains(b.File(pre+"etc/systemd/system/meridian-mesh-seal.service"), "meridian-mesh-up.sh --seal-only") {
			t.Fatalf("exit %s does not re-seal its sidecar on a timer", e.Node.ID)
		}
		if bashOK() {
			dir := t.TempDir()
			for name, body := range map[string]string{"routes.sh": routes, "mesh-up.sh": meshUp} {
				p := filepath.Join(dir, name)
				if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
					t.Fatal(err)
				}
				if out, err := exec.Command("bash", "-n", p).CombinedOutput(); err != nil {
					t.Fatalf("exit %s %s: bash -n: %v\n%s", e.Node.ID, name, err, out)
				}
			}
		}
	}
	if n == 0 {
		t.Fatal("no Mesh resolver exit in the example")
	}
	// The hub's sidecar seal still never leaves table 170, and its
	// copy_routes keeps the warp device on each copied route.
	hubUp := b.File("nodes/hk-hub/usr/local/sbin/meridian-mesh-up.sh")
	if strings.Contains(hubUp, "mesh_dns_return") || strings.Contains(hubUp, mesh.PublishMarker) {
		t.Fatal("the hub's mesh-up carries exit-only Mesh DNS parts")
	}
	if !strings.Contains(hubUp, `*) spec="$spec dev $dev" ;;`) {
		t.Fatal("copy_routes drops the warp device from copied routes")
	}
}

// mesh_dns_return under bash with a stub ip: the table points at the
// sidecar only while mmesh exists and the seal is present, and loses that
// route as soon as either is gone; the blackhole is always there.
func TestGroupDNSMeshReturnFollowsSeal(t *testing.T) {
	if !bashOK() {
		t.Skip("bash not available")
	}
	dir := t.TempDir()
	run, ctrl, bin := filepath.Join(dir, "run"), filepath.Join(dir, "ctrl"), filepath.Join(dir, "bin")
	for _, d := range []string{run, ctrl, bin} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	stub := "#!/bin/bash\nif [ \"$1\" = link ]; then [ -f " + ctrl + "/link ]; exit; fi\necho \"ip $*\" >> " + ctrl + "/ip.log\nexit 0\n"
	if err := os.WriteFile(filepath.Join(bin, "ip"), []byte(stub), 0o755); err != nil {
		t.Fatal(err)
	}
	script := "export PATH=" + bin + ":$PATH\n" + strings.ReplaceAll(meshDNSReturnShell(), "/run/meridian", run) + "mesh_dns_return\n"
	call := func() string {
		_ = os.Remove(filepath.Join(ctrl, "ip.log"))
		p := filepath.Join(dir, "drive.sh")
		if err := os.WriteFile(p, []byte(script), 0o600); err != nil {
			t.Fatal(err)
		}
		if out, err := exec.Command("bash", p).CombinedOutput(); err != nil {
			t.Fatalf("%v %s", err, out)
		}
		log, _ := os.ReadFile(filepath.Join(ctrl, "ip.log"))
		return string(log)
	}
	via := "ip -6 route replace default via fe80::66:2 dev mmesh table 171"
	del := "ip -6 route del default via fe80::66:2 dev mmesh table 171"
	floor := "ip -6 route replace blackhole default metric 32767 table 171"
	set := func(name string, on bool) {
		p := filepath.Join(map[string]string{"link": ctrl, "mesh-sealed": run}[name], name)
		if on {
			_ = os.WriteFile(p, nil, 0o644)
		} else {
			_ = os.Remove(p)
		}
	}
	for _, c := range []struct {
		link, sealed bool
		want, not    string
	}{
		{false, false, del, via},
		{true, false, del, via},
		{false, true, del, via},
		{true, true, via, del},
	} {
		set("link", c.link)
		set("mesh-sealed", c.sealed)
		log := call()
		if !strings.Contains(log, floor) || !strings.Contains(log, c.want) || strings.Contains(log, c.not) {
			t.Fatalf("link=%v sealed=%v:\n%s", c.link, c.sealed, log)
		}
	}
}
