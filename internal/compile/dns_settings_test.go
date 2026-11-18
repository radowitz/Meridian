package compile

import (
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/radowitz/meridian/internal/defaults"
	"github.com/radowitz/meridian/internal/dnssplit"
	"github.com/radowitz/meridian/internal/hostexec"
	"github.com/radowitz/meridian/internal/model"
	"github.com/radowitz/meridian/internal/validate"
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

			// The domestic set: never #6; exempt from force-AAAA-SOA. Apple
			// is not built in any more (Apple names are not domestic).
			if strings.Contains(conf, "gs_apple") {
				t.Fatal("built-in Apple-direct set rendered")
			}
			for _, set := range []string{"gs_cn"} {
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

// ------------------------------------------------------ exit upstream ---

const testDNSCred = "dnsacct-0a1b2c3d4e5f"

func exitUpstreamDoT() *model.ExitDNSUpstream {
	return &model.ExitDNSUpstream{Protocol: model.ExitDNSDoT, Addresses: []string{"192.0.2.53", "2001:db8::53"},
		TLSHostName: "{account}.dns.example.net", AccountCredential: testDNSCred}
}

func exitUpstreamDoH() *model.ExitDNSUpstream {
	return &model.ExitDNSUpstream{Protocol: model.ExitDNSDoH, Addresses: []string{"198.51.100.53"}, Port: 8443,
		TLSHostName: "dns.example.net", Path: "/{account}", AccountCredential: testDNSCred}
}

func compileFiles(t *testing.T, topo model.Topology) map[string]string {
	t.Helper()
	b, err := Compile(topo)
	if err != nil {
		t.Fatal(err)
	}
	return b.Files
}

// Nothing configured, or every exit overridden to builtin while nothing
// global is set, compiles byte-identically to a topology without the
// setting (the goldens pin that text); a configured upstream changes
// exactly the exits' SmartDNS configs and nothing else (not the gateway's,
// not the forwarder's targets, nft or verify script).
func TestExitDNSUnconfiguredIdentical(t *testing.T) {
	for _, base := range []model.Topology{defaults.Example(), defaults.DualHubExample(), defaults.ExternalExample(), defaults.NestedExample()} {
		plain := compileFiles(t, base)
		ovr := base
		ovr.Nodes = append([]model.Node(nil), base.Nodes...)
		for i := range ovr.Nodes {
			if ovr.Nodes[i].Role == model.RoleExit && !model.IsExternal(ovr.Nodes[i]) {
				ovr.Nodes[i].ExitDNS = &model.ExitDNSUpstream{Protocol: model.ExitDNSBuiltin}
			}
		}
		for p, body := range compileFiles(t, ovr) {
			if plain[p] != body {
				t.Fatalf("builtin override changed %s", p)
			}
		}
		set := base
		set.Settings.ExitDNS = exitUpstreamDoT()
		got := compileFiles(t, set)
		if len(got) != len(plain) {
			t.Fatalf("file set changed: %d -> %d", len(plain), len(got))
		}
		changed := 0
		for p, body := range got {
			if plain[p] == body {
				continue
			}
			if !strings.HasSuffix(p, "/etc/smartdns/smartdns.conf") || strings.HasPrefix(p, "nodes/gw/") {
				t.Fatalf("configuring the exit upstream changed %s", p)
			}
			changed++
		}
		if changed == 0 {
			t.Fatal("no exit config changed")
		}
	}
}

// The exits' upstream and the gateway's two journals do not reach each
// other. Whatever the exits' upstream is (none, one for all, one exit's
// own), turning the query journal on changes the same three gateway files
// to the same bytes, and no node but the gateway differs by a byte from the
// same topology with the journal off; the link journal's object list is
// the same in every combination. So collecting logs never makes an exit,
// a relay, a hub or a carrier show a pending change.
func TestJournalsAndExitUpstreamAreIndependent(t *testing.T) {
	upstreams := map[string]func(*model.Topology){
		"none":                       func(*model.Topology) {},
		"global DoT with an account": func(topo *model.Topology) { topo.Settings.ExitDNS = exitUpstreamDoT() },
		"one exit's own DoH": func(topo *model.Topology) {
			topo.Nodes = append([]model.Node(nil), topo.Nodes...)
			for i := range topo.Nodes {
				if topo.Nodes[i].Role == model.RoleExit && !model.IsExternal(topo.Nodes[i]) {
					topo.Nodes[i].ExitDNS = exitUpstreamDoH()
					return
				}
			}
		},
	}
	for name, base := range sniffTopologies(t) {
		for _, sniffed := range []bool{false, true} {
			gw := gatewayID(t, base)
			pre := "nodes/" + gw + "/"
			gwOn := map[string]map[string]string{} // upstream variant -> the gateway's files with the journal on
			for uname, set := range upstreams {
				topo := base
				if sniffed {
					topo = sniffOn(topo)
				}
				set(&topo)
				off := compileFiles(t, topo)
				topo.Settings.DNSLog = &model.DNSLogSettings{Enabled: true}
				on := compileFiles(t, topo)
				gwOn[uname] = map[string]string{}
				var differ []string
				for p, body := range on {
					if strings.HasPrefix(p, pre) {
						gwOn[uname][p] = body
					}
					if off[p] != body {
						differ = append(differ, p)
					}
				}
				for p := range off {
					if _, ok := on[p]; !ok {
						differ = append(differ, p+" (removed)")
					}
				}
				sort.Strings(differ)
				want := []string{pre + "etc/smartdns/smartdns.conf", pre + "etc/systemd/system/" + DNSJournalUnit, pre + "usr/local/sbin/meridian-verify.sh"}
				if strings.Join(differ, " ") != strings.Join(want, " ") {
					t.Fatalf("%s (sniff %v, upstream %s): the query journal changed %v, want only %v", name, sniffed, uname, differ, want)
				}
				if on[pre+strings.TrimPrefix(LinkJournalConfigPath, "/")] != off[pre+strings.TrimPrefix(LinkJournalConfigPath, "/")] {
					t.Fatalf("%s (sniff %v, upstream %s): the link journal's object list depends on the query journal", name, sniffed, uname)
				}
			}
			for uname, files := range gwOn {
				if !reflect.DeepEqual(files, gwOn["none"]) {
					t.Fatalf("%s (sniff %v): the gateway's files with the journal on depend on the exits' upstream (%s)", name, sniffed, uname)
				}
			}
		}
	}
}

var reUpstreamLine = regexp.MustCompile(`(?m)^(server\S*) .*$`)

// The rendered upstream: only the configured server-tls / server-https
// lines (no plain server, no fallback, no mark, proxy or interface: the
// queries leave by the exit's main table, its own uplink), certificate
// verification against the host name and the CA bundle, the placeholder
// and the restricted marker; an external exit's carrier groups unchanged.
func TestExitDNSRendered(t *testing.T) {
	topo := defaults.ExternalExample()
	topo.Settings.ExitDNS = exitUpstreamDoT()
	files := compileFiles(t, topo)
	n := 0
	for p, conf := range files {
		if !strings.HasSuffix(p, "/etc/smartdns/smartdns.conf") || strings.HasPrefix(p, "nodes/gw/") {
			continue
		}
		n++
		ph := "__MERIDIAN_SECRET_" + testDNSCred + "__.dns.example.net"
		for _, want := range []string{
			ExitDNSRestrictedMarker + "\n",
			"ca-file /etc/ssl/certs/ca-certificates.crt\n",
			"server-tls 192.0.2.53:853 -host-name " + ph + " -tls-host-verify " + ph + "\n",
			"server-tls [2001:db8::53]:853 -host-name " + ph + " -tls-host-verify " + ph + "\n",
		} {
			if !strings.Contains(conf, want) {
				t.Fatalf("%s lacks %q:\n%s", p, want, conf)
			}
		}
		for _, forbidden := range []string{"server 1.1.1.1", "server 8.8.8.8", "-fallback", "-set-mark", "-proxy", "-interface", "-no-check-certificate", "-bootstrap-dns", "223.5.5.5", "1.12.12.12"} {
			if strings.Contains(conf, forbidden) {
				t.Fatalf("%s carries %q", p, forbidden)
			}
		}
		for _, m := range reUpstreamLine.FindAllStringSubmatch(conf, -1) {
			line := m[0]
			switch {
			case m[1] == "server-tls" && strings.Contains(line, ph):
			case m[1] == "server-tcp" && strings.Contains(line, "-group ext_"):
				// the external exit's own group (renderCarrierDNS), unchanged
			default:
				t.Fatalf("%s: unexpected upstream line %q", p, line)
			}
		}
	}
	if n == 0 {
		t.Fatal("no exit config")
	}

	// DoH, a per-exit override and a per-exit builtin.
	topo = defaults.Example()
	topo.Settings.ExitDNS = exitUpstreamDoH()
	var exits []string
	for _, x := range topo.Nodes {
		if x.Role == model.RoleExit && !model.IsExternal(x) {
			exits = append(exits, x.ID)
		}
	}
	if len(exits) < 2 {
		t.Fatal("example has fewer than two exits")
	}
	for i := range topo.Nodes {
		switch topo.Nodes[i].ID {
		case exits[0]:
			topo.Nodes[i].ExitDNS = &model.ExitDNSUpstream{Protocol: model.ExitDNSBuiltin}
		case exits[1]:
			topo.Nodes[i].ExitDNS = &model.ExitDNSUpstream{Protocol: model.ExitDNSDoT, Addresses: []string{"203.0.113.9"}, TLSHostName: "resolver.example.org"}
		}
	}
	files = compileFiles(t, topo)
	c0 := files["nodes/"+exits[0]+"/etc/smartdns/smartdns.conf"]
	if !strings.Contains(c0, "server 1.1.1.1\nserver 8.8.8.8\n") || strings.Contains(c0, "server-") {
		t.Fatalf("builtin override:\n%s", c0)
	}
	c1 := files["nodes/"+exits[1]+"/etc/smartdns/smartdns.conf"]
	if !strings.Contains(c1, "server-tls 203.0.113.9:853 -host-name resolver.example.org -tls-host-verify resolver.example.org\n") || strings.Contains(c1, ExitDNSRestrictedMarker) || strings.Contains(c1, "__MERIDIAN_SECRET_") {
		t.Fatalf("own override without account:\n%s", c1)
	}
	for _, id := range exits[2:] {
		c := files["nodes/"+id+"/etc/smartdns/smartdns.conf"]
		want := "server-https https://198.51.100.53:8443/__MERIDIAN_SECRET_" + testDNSCred + "__ -host-name dns.example.net -http-host dns.example.net -tls-host-verify dns.example.net\n"
		if !strings.Contains(c, want) {
			t.Fatalf("%s DoH:\n%s", id, c)
		}
	}
	if d := DescribeExitUpstream(exitUpstreamDoH()); !strings.Contains(d, "https://dns.example.net/"+MaskedAccount) || strings.Contains(d, "__MERIDIAN") {
		t.Fatalf("describe: %s", d)
	}
}

// The upstream model has no switch that would turn certificate checking
// off, and validation refuses every shape that could reach the domestic
// side, a tunnel, the LAN or this host, or misplace the account.
func TestExitDNSValidation(t *testing.T) {
	rt := reflect.TypeOf(model.ExitDNSUpstream{})
	for i := 0; i < rt.NumField(); i++ {
		name := strings.ToLower(rt.Field(i).Name + " " + rt.Field(i).Tag.Get("json"))
		for _, f := range []string{"skip", "insecure", "nocheck", "no_check", "fallback", "bootstrap"} {
			if strings.Contains(name, f) {
				t.Fatalf("upstream field %s", rt.Field(i).Name)
			}
		}
	}
	base := defaults.Example()
	ok := func(u model.ExitDNSUpstream) []string { return validate.CheckExitDNSUpstream(base, u, "") }
	if m := ok(*exitUpstreamDoT()); len(m) != 0 {
		t.Fatalf("valid DoT refused: %v", m)
	}
	if m := ok(*exitUpstreamDoH()); len(m) != 0 {
		t.Fatalf("valid DoH refused: %v", m)
	}
	bad := map[string]model.ExitDNSUpstream{
		"private":        {Protocol: "dot", Addresses: []string{"192.168.1.1"}, TLSHostName: "a.example.net"},
		"ula":            {Protocol: "dot", Addresses: []string{"fd66::54:1"}, TLSHostName: "a.example.net"},
		"loopback":       {Protocol: "dot", Addresses: []string{"127.0.0.1"}, TLSHostName: "a.example.net"},
		"cgnat":          {Protocol: "dot", Addresses: []string{"100.64.0.1"}, TLSHostName: "a.example.net"},
		"domestic":       {Protocol: "dot", Addresses: []string{base.Settings.DomesticDoT[0]}, TLSHostName: "a.example.net"},
		"none":           {Protocol: "dot", TLSHostName: "a.example.net"},
		"three":          {Protocol: "dot", Addresses: []string{"192.0.2.1", "192.0.2.2", "192.0.2.3"}, TLSHostName: "a.example.net"},
		"no host":        {Protocol: "dot", Addresses: []string{"192.0.2.1"}},
		"bad host":       {Protocol: "dot", Addresses: []string{"192.0.2.1"}, TLSHostName: "a b"},
		"token inside":   {Protocol: "dot", Addresses: []string{"192.0.2.1"}, TLSHostName: "a.{account}.example.net", AccountCredential: testDNSCred},
		"token twice":    {Protocol: "doh", Addresses: []string{"192.0.2.1"}, TLSHostName: "{account}.example.net", Path: "/{account}/{account}", AccountCredential: testDNSCred},
		"no credential":  {Protocol: "dot", Addresses: []string{"192.0.2.1"}, TLSHostName: "{account}.example.net"},
		"stray cred":     {Protocol: "dot", Addresses: []string{"192.0.2.1"}, TLSHostName: "a.example.net", AccountCredential: testDNSCred},
		"dot path":       {Protocol: "dot", Addresses: []string{"192.0.2.1"}, TLSHostName: "a.example.net", Path: "/x"},
		"doh no path":    {Protocol: "doh", Addresses: []string{"192.0.2.1"}, TLSHostName: "a.example.net"},
		"doh query":      {Protocol: "doh", Addresses: []string{"192.0.2.1"}, TLSHostName: "a.example.net", Path: "/q?a=1"},
		"protocol":       {Protocol: "plain", Addresses: []string{"192.0.2.1"}, TLSHostName: "a.example.net"},
		"global builtin": {Protocol: "builtin"},
		"port":           {Protocol: "dot", Addresses: []string{"192.0.2.1"}, TLSHostName: "a.example.net", Port: 70000},
		"multicast":      {Protocol: "dot", Addresses: []string{"224.0.0.1"}, TLSHostName: "a.example.net"},
		"link-local v6":  {Protocol: "dot", Addresses: []string{"fe80::1"}, TLSHostName: "a.example.net"},
		"bad credential": {Protocol: "dot", Addresses: []string{"192.0.2.1"}, TLSHostName: "{account}.example.net", AccountCredential: "socks-1"},
	}
	for name, u := range bad {
		if m := ok(u); len(m) == 0 {
			t.Errorf("%s accepted", name)
		}
	}
	// On a node: only a managed exit; builtin allowed there.
	topo := defaults.ExternalExample()
	for i := range topo.Nodes {
		if model.IsExternal(topo.Nodes[i]) || topo.Nodes[i].Role == model.RoleGateway {
			topo.Nodes[i].ExitDNS = &model.ExitDNSUpstream{Protocol: model.ExitDNSBuiltin}
		}
	}
	n := 0
	for _, is := range validate.Run(topo).Issues {
		if is.Code == "exit_dns_invalid" {
			n++
		}
	}
	if n < 2 {
		t.Fatalf("override on gateway / external exit not refused (%d)", n)
	}
}

// The resolution view: one row per kind of name, the exits' upstream with
// the account masked, nothing of the placeholder or a value.
func TestResolutionPlanView(t *testing.T) {
	topo := defaults.ExternalExample()
	topo.Settings.ExitDNS = exitUpstreamDoH()
	p, err := ResolutionPlan(topo, nil)
	if err != nil {
		t.Fatal(err)
	}
	scopes := map[string]int{}
	for _, r := range p.Paths {
		scopes[r.Scope]++
		for _, u := range r.Upstreams {
			if strings.Contains(u.Address, "__MERIDIAN") {
				t.Fatalf("placeholder in view: %+v", u)
			}
		}
		if r.Scope == "exit" && (len(r.Upstreams) != 1 || r.Upstreams[0].Transport != "doh" || !strings.Contains(r.Upstreams[0].Address, MaskedAccount)) {
			t.Fatalf("exit row %+v", r)
		}
		if r.Scope == "external_exit" && r.Upstreams[0].Transport != "plain" {
			t.Fatalf("external row %+v", r)
		}
	}
	for _, s := range []string{"clients", "domestic", "unlisted", "exit", "external_exit", "reject", "doh_block", "gateway"} {
		if scopes[s] == 0 {
			t.Fatalf("no %s row", s)
		}
	}
	for _, e := range p.Exits {
		if e.Source != "global" || e.Transport != "doh" || !e.Checkable && e.Resolver != "" {
			t.Fatalf("exit %+v", e)
		}
	}
}
