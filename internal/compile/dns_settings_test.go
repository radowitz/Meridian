package compile

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/radowitz/meridian/internal/defaults"
	"github.com/radowitz/meridian/internal/dnssplit"
	"github.com/radowitz/meridian/internal/hostexec"
	"github.com/radowitz/meridian/internal/model"
)

// The two resolver settings (docs/architecture.md「客户端 IPv6 与 AAAA」
// and「未列名单域名的国内解析」), checked on the rendered gateway config for
// every combination and for both kinds of default (a group the hub switches
// and a static one). What the directives do in the pinned SmartDNS is
// TestSmartDNSRealBinary's job; this pins which lines carry them.

type dnsSettingsCase struct {
	name      string
	clientsV6 bool
	split     bool
	// staticDefault points the default at the static group "v6" (its
	// resolver is an exit server line, not a region-group line).
	staticDefault bool
}

func dnsSettingsCases() []dnsSettingsCase {
	var out []dnsSettingsCase
	for _, st := range []bool{false, true} {
		for _, v6 := range []bool{false, true} {
			for _, sp := range []bool{false, true} {
				n := "v6=" + map[bool]string{false: "off", true: "on"}[v6] + ",split=" + map[bool]string{false: "off", true: "on"}[sp]
				if st {
					n += ",static-default"
				}
				out = append(out, dnsSettingsCase{name: n, clientsV6: v6, split: sp, staticDefault: st})
			}
		}
	}
	return out
}

func (c dnsSettingsCase) topo() model.Topology {
	topo, _ := groupDNSExample()
	topo.Settings.ClientsIPv6ViaGateway = c.clientsV6
	topo.Settings.UnlistedDomesticDNS = c.split
	if c.staticDefault {
		topo.Settings.DefaultGroup = "v6"
	}
	return topo
}

var reRuleSet4 = regexp.MustCompile(`-nftset #4:inet#meridian#(r\d+)(,|$)`)

var reServerLine = regexp.MustCompile(`^(server(?:-tls)?) (\S+)((?: \S+)*)$`)

type confServer struct {
	kind, addr, group string
	excl, whitelist   bool
	fallback          bool
	mark              string
}

func confServers(t *testing.T, conf string) []confServer {
	t.Helper()
	var out []confServer
	for _, l := range strings.Split(conf, "\n") {
		m := reServerLine.FindStringSubmatch(l)
		if m == nil {
			continue
		}
		s := confServer{kind: m[1], addr: m[2]}
		f := strings.Fields(m[3])
		for i := 0; i < len(f); i++ {
			switch f[i] {
			case "-group":
				s.group = f[i+1]
				i++
			case "-exclude-default-group":
				s.excl = true
			case "-whitelist-ip":
				s.whitelist = true
			case "-fallback":
				s.fallback = true
			case "-set-mark":
				s.mark = f[i+1]
				i++
			default:
				t.Fatalf("unexpected server option %q in %s", f[i], l)
			}
		}
		out = append(out, s)
	}
	return out
}

func TestGatewayDNSSettingsCombinations(t *testing.T) {
	for _, c := range dnsSettingsCases() {
		t.Run(c.name, func(t *testing.T) {
			topo := c.topo()
			b := mustCompile(t, topo)
			conf := b.File("nodes/gw/etc/smartdns/smartdns.conf")
			exits, groups := plans(t, topo)
			defT, ok := defaultExit(topo, groups)
			if !ok {
				t.Fatal("no default target")
			}
			if c.staticDefault && defT.Group != nil {
				t.Fatal("the static default resolved to a switchable group")
			}
			if !c.staticDefault && defT.Group == nil {
				t.Fatal("the example default is not switchable")
			}
			catchAll := c.clientsV6 && defT.V6
			force := strings.Contains(conf, "\nforce-AAAA-SOA yes\n")
			if force == catchAll {
				t.Fatalf("force-AAAA-SOA=%v, want %v (clients_v6=%v default v6=%v)", force, !catchAll, c.clientsV6, defT.V6)
			}
			if strings.Contains(conf, "nftset #6:inet#meridian#default6") != catchAll {
				t.Fatalf("default6 nftset present=%v, catch-all AAAA=%v", !catchAll, catchAll)
			}

			// Domestic sets: never #6; exempt from force-AAAA-SOA.
			for _, set := range []string{"gs_cn", "gs_apple"} {
				l := lineWith(conf, "domain-rules /domain-set:"+set+"/")
				if strings.Contains(l, "#6 ") || strings.Contains(l, "-address #") {
					t.Fatalf("domestic set filters AAAA: %s", l)
				}
				if strings.Contains(l, "-address -6") != force {
					t.Fatalf("domestic set exemption %v, force %v: %s", strings.Contains(l, "-address -6"), force, l)
				}
				if !strings.Contains(l, "#6:inet#meridian#direct6") {
					t.Fatalf("domestic IPv6 not routed direct: %s", l)
				}
			}

			// Every rule line: AAAA only with clients_v6 and a v6 target.
			rules := planRules(topo, exits, groups, nil)
			if len(rules) == 0 {
				t.Fatal("no rules")
			}
			nRuleLines := 0
			for _, rp := range rules {
				allowed := c.clientsV6 && !rp.FilterAAAA
				for _, l := range strings.Split(conf, "\n") {
					m := reRuleSet4.FindStringSubmatch(l)
					if !strings.HasPrefix(l, "domain-rules ") || m == nil || m[1] != rp.Set4 {
						continue
					}
					nRuleLines++
					if strings.Contains(l, "-address #6") == allowed {
						t.Fatalf("rule %s (allowed AAAA %v): %s", rp.Rule.ID, allowed, l)
					}
					if strings.Contains(l, "#6:inet#meridian#"+rp.Set6) != allowed {
						t.Fatalf("rule %s v6 nftset (allowed %v): %s", rp.Rule.ID, allowed, l)
					}
					if strings.Contains(l, "-address -6") != (allowed && force) {
						t.Fatalf("rule %s exemption (allowed %v force %v): %s", rp.Rule.ID, allowed, force, l)
					}
					if strings.Contains(l, "-whitelist-ip") || strings.Contains(l, "-fallback") {
						t.Fatalf("rule line carries a server option: %s", l)
					}
				}
			}
			if nRuleLines == 0 {
				t.Fatal("no rule lines matched")
			}
			if !c.clientsV6 && strings.Contains(conf, "#6:inet#meridian#r") {
				t.Fatal("a rule fills an IPv6 set although clients do not route IPv6 through the gateway")
			}

			// Servers: who is in the default group, with which flags.
			var defAddr string
			var defMark uint32
			if defT.Group != nil {
				defAddr, defMark = defT.Group.Resolver, defT.Group.Mark
			} else {
				defAddr = defT.Exit.DNSULA
			}
			if defAddr == "" {
				t.Fatal("default has no resolver address")
			}
			var inDefault []confServer
			for _, s := range confServers(t, conf) {
				if !s.excl {
					inDefault = append(inDefault, s)
				}
				if s.whitelist || s.fallback {
					t.Fatalf("SmartDNS's own answer filtering is not used (it returns address-less CNAMEs): %+v", s)
				}
				if s.group == "domestic" && !s.excl {
					t.Fatalf("domestic-set server in the default group: %+v", s)
				}
			}
			if len(inDefault) != 1 {
				t.Fatalf("default group has %d servers, want 1: %+v", len(inDefault), inDefault)
			}
			unit := b.File("nodes/gw/etc/systemd/system/" + DNSSplitUnit)
			if c.split {
				if inDefault[0].addr != DNSSplitListen || inDefault[0].mark != "" {
					t.Fatalf("unlisted names do not go to meridian-dns-split: %+v", inDefault[0])
				}
				// The resolver's own entry (its rules) stays, excluded.
				found := false
				for _, s := range confServers(t, conf) {
					found = found || s.addr == defAddr
				}
				if !found {
					t.Fatal("default resolver has no entry for its own rules")
				}
				if !SmartDNSUsesDNSSplit(conf) {
					t.Fatal("SmartDNSUsesDNSSplit = false")
				}
				m := regexp.MustCompile(`(?m)^ExecStart=/usr/local/bin/meridian (dns-split .*)$`).FindStringSubmatch(unit)
				if m == nil {
					t.Fatalf("no dns-split unit:\n%s", unit)
				}
				// The guard against an older host binary greps for the
				// marker the dns-split code itself logs.
				if !strings.Contains(unit, "ExecStartPre=/bin/grep -q meridian-dns-split-ready /usr/local/bin/meridian") {
					t.Fatal("no guard against a host binary without dns-split")
				}
				src, err := os.ReadFile(filepath.Join("..", "dnssplit", "dnssplit.go"))
				if err != nil || !strings.Contains(string(src), `"meridian-dns-split-ready: `) {
					t.Fatal("dnssplit no longer logs the marker the unit greps for")
				}
				args := strings.Fields(m[1])[1:]
				cfg, err := dnssplit.ParseArgs(args)
				if err != nil {
					t.Fatalf("rendered flags do not parse: %v (%s)", err, m[1])
				}
				want := "[" + defAddr + "]:53"
				if !strings.Contains(defAddr, ":") {
					want = defAddr + ":53"
				}
				if cfg.Listen != DNSSplitListen || cfg.Exit != want || cfg.ExitMark != int(defMark) {
					t.Fatalf("dns-split upstream %+v, want exit %s mark %d", cfg, want, defMark)
				}
				if strings.Join(cfg.Domestic, ",") != "223.5.5.5:53,1.12.12.12:53" {
					t.Fatalf("domestic %v", cfg.Domestic)
				}
				if cfg.DomesticTimeout != dnssplit.DefaultDomesticTimeout || cfg.Settle != dnssplit.DefaultSettle ||
					cfg.ExitTimeout != dnssplit.DefaultExitTimeout || cfg.StatsInterval != dnssplit.DefaultStatsInterval ||
					!strings.Contains(m[1], " --settle 30ms ") || !strings.Contains(m[1], " --domestic-timeout 400ms ") {
					t.Fatalf("timings not written out with their defaults: %s", m[1])
				}
				if cfg.China4 != chinaListFile4 || cfg.China6 != chinaListFile6 {
					t.Fatalf("lists %s %s", cfg.China4, cfg.China6)
				}
			} else {
				if inDefault[0].addr != defAddr {
					t.Fatalf("default group, want only %s: %+v", defAddr, inDefault)
				}
				if unit != "" || SmartDNSUsesDNSSplit(conf) || strings.Contains(conf, "unlisted_split") {
					t.Fatal("dns-split rendered without unlisted_domestic_dns")
				}
			}

			// The host agent has its own copy of this predicate and the
			// unit name (it cannot import this package); they must agree
			// on every rendering.
			if hostexec.UsesDNSSplit(conf) != SmartDNSUsesDNSSplit(conf) {
				t.Fatalf("hostexec.UsesDNSSplit disagrees with SmartDNSUsesDNSSplit (split=%v)", c.split)
			}
			if hostexec.DNSSplitUnit != DNSSplitUnit {
				t.Fatalf("hostexec.DNSSplitUnit %q, compile %q", hostexec.DNSSplitUnit, DNSSplitUnit)
			}
			for _, n := range []string{"ip-set ", "whitelist-ip", "-fallback"} {
				if strings.Contains(conf, n) {
					t.Fatalf("%q in the gateway config", n)
				}
			}
			if !strings.Contains(conf, "\ncache-persist no\n") {
				t.Fatal("the answer cache may survive a restart (cache-persist not off)")
			}
			for _, r := range SmartDNSFileRefs(conf) {
				under := false
				for _, d := range SmartDNSSharedDirs {
					under = under || strings.HasPrefix(r, d+"/")
				}
				if !under {
					t.Fatalf("%s outside SmartDNSSharedDirs", r)
				}
			}
		})
	}
}

// The default (both settings off) for the operator's situation: a single
// IPv4-only exit as the default. No AAAA leaves the resolver for anything
// but the domestic sets.
func TestGatewayDNSDefaultsIPv4OnlyExit(t *testing.T) {
	topo := defaults.Example()
	if topo.Settings.ClientsIPv6ViaGateway || topo.Settings.UnlistedDomesticDNS {
		t.Fatal("the example must keep both settings at their defaults")
	}
	for i := range topo.Nodes {
		if topo.Nodes[i].Role == model.RoleExit {
			topo.Nodes[i].EgressV6 = false
		}
	}
	conf := mustCompile(t, topo).File("nodes/gw/etc/smartdns/smartdns.conf")
	if !strings.Contains(conf, "\nforce-AAAA-SOA yes\n") {
		t.Fatal("no catch-all AAAA suppression")
	}
	for _, l := range strings.Split(conf, "\n") {
		if strings.HasPrefix(l, "domain-rules ") && strings.Contains(l, "-address -6") && !strings.Contains(l, "/domain-set:gs_cn/") && !strings.Contains(l, "/domain-set:gs_apple/") {
			t.Fatalf("AAAA exemption outside the domestic sets: %s", l)
		}
	}
	// Turning clients_ipv6_via_gateway on does not help an IPv4-only exit.
	topo.Settings.ClientsIPv6ViaGateway = true
	conf = mustCompile(t, topo).File("nodes/gw/etc/smartdns/smartdns.conf")
	if !strings.Contains(conf, "\nforce-AAAA-SOA yes\n") || !strings.Contains(conf, "default exit/group has no IPv6 end to end") {
		t.Fatal("an IPv4-only default must stay AAAA-suppressed with clients_ipv6_via_gateway on")
	}
}
