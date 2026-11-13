package compile

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/netip"
	"os/exec"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/radowitz/meridian/internal/defaults"
	"github.com/radowitz/meridian/internal/model"
	"github.com/radowitz/meridian/internal/ordered"
	"github.com/radowitz/meridian/internal/sniff"
	"github.com/radowitz/meridian/internal/validate"
)

// sniffOn returns topo with the forwarder enabled.
func sniffOn(topo model.Topology) model.Topology {
	topo.Settings.Sniff = &model.SniffSettings{Enabled: true}
	return topo
}

// sniffRules adds what every sniff topology test needs on top of a
// topology's own rules: a direct rule, a reject rule, a rule through a
// service group, a CIDR rule and a keyword rule.
func sniffRules(topo model.Topology, group string) model.Topology {
	topo.ServiceGroups = append(topo.ServiceGroups, model.ServiceGroup{ID: "svc-ai", Name: "AI", TargetGroup: group})
	topo.Rules = append(topo.Rules,
		model.Rule{ID: "sn-direct", Name: "direct", Enabled: true, MatchType: model.MatchSuffix, MatchValue: "home.example.org", TargetAction: model.ActionDirect, Priority: 1},
		model.Rule{ID: "sn-reject", Name: "reject", Enabled: true, MatchType: model.MatchSuffix, MatchValue: "ads.example.com", TargetAction: model.ActionReject, Priority: 2},
		model.Rule{ID: "sn-svc", Name: "svc", Enabled: true, MatchType: model.MatchSuffix, MatchValue: "ai.example.org", TargetService: "svc-ai", Priority: 3},
		model.Rule{ID: "sn-cidr", Name: "cidr", Enabled: true, MatchType: model.MatchCIDR, MatchValue: "203.0.113.128/25", TargetGroup: group, Priority: 4},
		model.Rule{ID: "sn-kw", Name: "kw", Enabled: true, MatchType: model.MatchKeyword, MatchValue: "stream", TargetGroup: group, Priority: 5},
	)
	return topo
}

// sniffTopologies are the shapes the real deployment has or will have:
// IPv4-only and dual-stack targets, dynamic and static groups, a single hub
// and a backup hub, relay sharing, remote access, a nested exit and a
// TCP-only external exit, each with direct, reject and service-group rules.
func sniffTopologies(t *testing.T) map[string]model.Topology {
	t.Helper()
	ra, _ := raExample(t)
	shared := defaults.SharedRelaysExample()
	model.MigrateRegionGroups(&shared)
	out := map[string]model.Topology{
		"example":       sniffRules(defaults.Example(), "jp"),
		"remote_access": sniffRules(ra, "us"),
		"dual_hub":      sniffRules(defaults.DualHubExample(), "hk"),
		"shared_relays": sniffRules(shared, "hk"),
		"nested":        sniffRules(defaults.NestedExample(), "tw"),
		"external":      sniffRules(defaults.ExternalExample(), "my"),
	}
	// An IPv4-only target (sg has no IPv6) pinned by a rule, and a static
	// (non-switchable) group.
	ex := out["example"]
	ex.Rules = append(ex.Rules, model.Rule{ID: "sn-sg", Name: "sg", Enabled: true, MatchType: model.MatchSuffix, MatchValue: "sg.example.net", TargetExit: "sg", Priority: 6})
	out["example"] = ex
	return out
}

// Off (absent, or present and disabled with every field set) compiles
// every node byte for byte like a topology that never had the setting.
func TestSniffOffByteIdentical(t *testing.T) {
	for name, topo := range sniffTopologies(t) {
		base := mustCompile(t, topo).Canonical()
		off := topo
		off.Settings.Sniff = &model.SniffSettings{Enabled: false, Ports: []int{443}, ECHPublicNames: []string{"ech.example.net"}, RecordNames: true}
		if got := mustCompile(t, off).Canonical(); got != base {
			t.Errorf("%s: a disabled sniff setting changed the compiled output", name)
		}
		if strings.Contains(base, "sniff_") || strings.Contains(base, SniffUser) {
			t.Errorf("%s: the forwarder appears in a bundle without the setting", name)
		}
		if got := mustCompile(t, sniffOn(topo)).Canonical(); got == base {
			t.Errorf("%s: enabling sniff changed nothing", name)
		}
	}
}

// sniffBundle compiles topo with the forwarder on and returns the gateway
// files it adds.
type sniffFiles struct {
	nft, unit, targets, decide, up, guard string
}

func sniffCompile(t *testing.T, topo model.Topology) (*Bundle, sniffFiles) {
	t.Helper()
	b := mustCompile(t, sniffOn(topo))
	gw := "nodes/gw/"
	f := sniffFiles{
		nft:     b.File(gw + "etc/nftables.d/meridian.nft"),
		unit:    b.File(gw + "etc/systemd/system/" + SniffUnit),
		targets: b.File(gw + strings.TrimPrefix(SniffTargetsPath, "/")),
		decide:  b.File(gw + strings.TrimPrefix(DecidePath, "/")),
		up:      b.File(gw + "usr/local/sbin/meridian-up.sh"),
		guard:   b.File(gw + "etc/nftables.d/meridian-guard.nft"),
	}
	if f.unit == "" || f.targets == "" || f.decide == "" {
		t.Fatal("the forwarder's files are missing")
	}
	return b, f
}

var nftMarkSet = regexp.MustCompile(`meta mark set (0x[0-9a-f]+)`)

// The target file is complete for what the forwarder and the address
// classifier can decide: the core's own Install accepts the compiled
// snapshot with it, every classification mark has an entry (so an
// unnamed connection's AddrMark is always known), resolvers follow the
// gateway resolver (exit: its tunnel resolver unmarked, group: its
// resolver address with the group mark, direct: the domestic resolvers
// with the domestic mark, reject: none), the pair hash matches, and the
// output chain allows exactly those resolvers.
func TestSniffTargetsComplete(t *testing.T) {
	for name, topo := range sniffTopologies(t) {
		t.Run(name, func(t *testing.T) {
			b, f := sniffCompile(t, topo)
			var tf sniff.TargetsFile
			dec := json.NewDecoder(strings.NewReader(f.targets))
			dec.DisallowUnknownFields()
			if err := dec.Decode(&tf); err != nil {
				t.Fatal(err)
			}
			sum := sha256.Sum256([]byte(f.decide))
			if tf.SnapshotSHA256 != hex.EncodeToString(sum[:]) {
				t.Fatal("the target file is not paired with the compiled snapshot")
			}
			c, err := ordered.LoadSnapshot([]byte(f.decide), ordered.MemReader{}, nil)
			if err != nil {
				t.Fatal(err)
			}
			if err := sniff.New(sniff.Config{}).Install(c, tf.Targets); err != nil {
				t.Fatalf("the forwarder refuses the compiled pair: %v", err)
			}
			byMark := map[uint32]sniff.Target{}
			for _, tg := range tf.Targets {
				byMark[tg.Mark] = tg
			}
			// Every mark the classifier sets (minus the device-pool and LAN
			// prefix rules, whose destinations are never intercepted).
			for _, m := range nftMarkSet.FindAllStringSubmatch(f.nft, -1) {
				v, _ := strconv.ParseUint(m[1], 0, 32)
				if v == 0 || uint32(v) == markSniff || v > 0xffff {
					continue
				}
				if _, ok := byMark[uint32(v)]; !ok && !strings.Contains(f.nft, "meta mark set meta mark | "+m[1]) {
					t.Errorf("classification mark %s has no target entry", m[1])
				}
			}
			exits := planExits(topo, mustTunnels(t, topo))
			groups := planGroups(topo, exits)
			for _, tg := range tf.Targets {
				switch {
				case tg.Name == "direct":
					if tg.Mark != markDomestic || *tg.DNSMark != markDomestic || len(tg.Resolvers) == 0 {
						t.Errorf("direct %+v", tg)
					}
				case tg.Name == "reject":
					if !tg.Reject || len(tg.Resolvers) != 0 || tg.Mark != markReject {
						t.Errorf("reject %+v", tg)
					}
				case strings.HasPrefix(tg.Name, "group:"):
					g, ok := groupByID(groups, strings.TrimPrefix(tg.Name, "group:"))
					if !ok || !g.Dynamic || tg.Mark != g.Mark || *tg.DNSMark != g.Mark || len(tg.Resolvers) != 1 || tg.Resolvers[0] != bracketHostPort(g.Resolver, 53) {
						t.Errorf("group target %+v (plan %+v)", tg, g.Mark)
					}
				case strings.HasPrefix(tg.Name, "exit:"):
					e, ok := exitByID(exits, strings.TrimPrefix(tg.Name, "exit:"))
					if !ok || tg.Mark != e.Mark || *tg.DNSMark != 0 || tg.IPv6 != carriesV6(e) {
						t.Errorf("exit target %+v", tg)
					}
					want := e.DNSULA
					if topo.DualHub() && want != "" {
						want = e.Resolver
					}
					if want == "" && len(tg.Resolvers) != 0 || want != "" && (len(tg.Resolvers) != 1 || tg.Resolvers[0] != bracketHostPort(want, 53)) {
						t.Errorf("exit %s resolvers %v, want %s", e.Node.ID, tg.Resolvers, want)
					}
					// The same address is what the gateway resolver asks.
					if want != "" && !strings.Contains(b.File("nodes/gw/etc/smartdns/smartdns.conf"), "server "+want+" ") {
						t.Errorf("exit %s: resolver %s is not the gateway resolver's", e.Node.ID, want)
					}
				default:
					t.Errorf("unknown target %+v", tg)
				}
				for _, r := range tg.Resolvers {
					ap := netip.MustParseAddrPort(r)
					fam := "ip"
					if ap.Addr().Is6() {
						fam = "ip6"
					}
					if !strings.Contains(f.nft, fmt.Sprintf("%s daddr %s meta mark %s meta l4proto { tcp, udp } th dport 53 accept", fam, ap.Addr(), hexMark(*tg.DNSMark))) {
						t.Errorf("the output chain does not allow resolver %s with mark %#x", r, *tg.DNSMark)
					}
				}
			}
			// IPv4-only and dual-stack targets both present where the
			// topology has them.
			var v4only, v6 bool
			for _, tg := range tf.Targets {
				if !tg.Reject && tg.Name != "direct" {
					v4only = v4only || !tg.IPv6
					v6 = v6 || tg.IPv6
				}
			}
			if name == "example" && !(v4only && v6) {
				t.Errorf("example: want IPv4-only and dual-stack targets, v4only=%v v6=%v", v4only, v6)
			}
		})
	}
}

// The compiled nft text: the chains, their order relative to classify and
// relay_share, the guard untouched, the user created before the load,
// every exit/group mark with a forwarder SNAT to its transit address.
func TestSniffNFTShape(t *testing.T) {
	for name, topo := range sniffTopologies(t) {
		t.Run(name, func(t *testing.T) {
			b0 := mustCompile(t, topo)
			_, f := sniffCompile(t, topo)
			if f.guard != b0.File("nodes/gw/etc/nftables.d/meridian-guard.nft") {
				t.Fatal("the early-boot guard changed")
			}
			guard0 := b0.File("nodes/gw/etc/nftables.d/meridian.nft")
			gStart := strings.Index(guard0, "table inet meridian_guard {")
			gEnd := strings.Index(guard0[gStart:], "\n}\n") + gStart
			if !strings.Contains(f.nft, guard0[gStart:gEnd]) {
				t.Fatal("the guard table in meridian.nft changed")
			}
			for _, want := range []string{"chain sniff_mark {", "chain sniff_redirect {", "chain sniff_input {", "chain sniff_out {", "chain sniff_confine {", "chain sniff_mss {",
				fmt.Sprintf("redirect to :%d", validate.SniffListenPort), "counter name \"sniff_denied\" drop comment \"fail closed"} {
				if !strings.Contains(f.nft, want) {
					t.Errorf("missing %q", want)
				}
			}
			pre := f.nft[strings.Index(f.nft, "chain prerouting {"):]
			ci, si := strings.Index(pre, "jump classify"), strings.Index(pre, "jump sniff_mark")
			if ci < 0 || si < ci {
				t.Fatalf("sniff_mark must follow classify in prerouting:\n%s", pre[:400])
			}
			if ri := strings.Index(pre, "jump relay_share"); ri >= 0 && ri < si {
				t.Fatal("relay_share runs before sniff_mark")
			}
			if topo.RelaySharing() != strings.Contains(f.nft, "chain sniff_route {") {
				t.Fatalf("sniff_route must exist exactly with relay sharing (%v)", topo.RelaySharing())
			}
			// Chains referenced before definition would make the batch fail.
			if strings.Index(f.nft, "chain sniff_mark {") > strings.Index(f.nft, "chain prerouting {") {
				t.Fatal("sniff_mark is defined after prerouting jumps to it")
			}
			exits := planExits(topo, mustTunnels(t, topo))
			for _, m := range markPlans(exits, planGroups(topo, exits)) {
				for _, w := range []string{
					fmt.Sprintf("meta skuid %d meta mark & 0xff00ffff == %s meta nfproto ipv4 snat ip to %s ", SniffUID, hexMark(m.Mark), m.TransitV4),
					fmt.Sprintf("meta skuid %d meta mark & 0xff00ffff == %s meta nfproto ipv6 snat ip6 to %s\n", SniffUID, hexMark(m.Mark), m.TransitV6),
				} {
					if !strings.Contains(f.nft, w) {
						t.Errorf("missing forwarder SNAT %q", w)
					}
				}
			}
			if f.up != b0.File("nodes/gw/usr/local/sbin/meridian-up.sh") {
				t.Fatal("meridian-up.sh changed: the ruleset matches the forwarder by uid, nothing to prepare")
			}
			// Every gateway tunnel (failover companions included) is a legal
			// exit path in the output chain, and nothing else.
			for _, ifc := range gatewayTunnelIfaces(mustTunnels(t, topo)) {
				if !regexp.MustCompile(`oifname \{[^}]*"` + ifc + `"`).MatchString(f.nft[strings.Index(f.nft, "chain sniff_confine"):]) {
					t.Errorf("tunnel %s missing from the forwarder's legal paths", ifc)
				}
			}
		})
	}
}

// The unit's command line is accepted by the forwarder's own flag parser
// with the intended values.
func TestSniffUnitArgs(t *testing.T) {
	topo := sniffOn(sniffRules(defaults.Example(), "jp"))
	topo.Settings.Sniff.Ports = []int{8443, 443, 80}
	topo.Settings.Sniff.RecordNames = true
	b := mustCompile(t, topo)
	unit := b.File("nodes/gw/etc/systemd/system/" + SniffUnit)
	m := regexp.MustCompile(`(?m)^ExecStart=/usr/local/bin/meridian sniff (.+)$`).FindStringSubmatch(unit)
	if m == nil {
		t.Fatalf("no ExecStart:\n%s", unit)
	}
	cfg, err := sniff.ParseArgs(strings.Fields(m[1]))
	if err != nil {
		t.Fatal(err)
	}
	ports := append([]uint16(nil), cfg.SniffPorts...)
	sort.Slice(ports, func(i, j int) bool { return ports[i] < ports[j] })
	if cfg.Mode != "redirect" || cfg.Listen != fmt.Sprintf("[::]:%d", validate.SniffListenPort) || cfg.TargetsPath != SniffTargetsPath || cfg.SnapshotPath != DecidePath ||
		!cfg.ECHOuter || strings.Join(cfg.ECHPublicNames, ",") != "cloudflare-ech.com" || cfg.AddrMarkBit != markSniff || !cfg.RecordNames ||
		fmt.Sprint(ports) != "[80 443 8443]" || strings.Join(cfg.NeighIfaces, ",") != gatewayLAN(topo) || cfg.StatusSocket != SniffStatusSocket {
		t.Fatalf("%+v", cfg)
	}
	for _, w := range []string{"User=" + SniffUser, "AmbientCapabilities=CAP_NET_ADMIN", "CapabilityBoundingSet=CAP_NET_ADMIN", "Restart=always",
		"ExecReload=/bin/kill -HUP $MAINPID", "net.ipv4.tcp_fwmark_accept=1", "ExecStartPre=+" + SniffUserScript + " add", "ExecStopPost=+" + SniffUserScript + " del", "ExecStopPost=+/usr/sbin/sysctl -q -w net.ipv4.tcp_fwmark_accept=0", "NoNewPrivileges=yes"} {
		if !strings.Contains(unit, w) {
			t.Errorf("unit lacks %q", w)
		}
	}
	nft := b.File("nodes/gw/etc/nftables.d/meridian.nft")
	if !strings.Contains(nft, "tcp dport != { 80, 443, 8443 } return") {
		t.Fatal("the ports are not the intercepted ones")
	}
	// An empty public-name list turns the flag off, ECH stays outer-name.
	topo.Settings.Sniff.ECHPublicNames = []string{}
	unit = mustCompile(t, topo).File("nodes/gw/etc/systemd/system/" + SniffUnit)
	if strings.Contains(unit, "--ech-public-names") || !strings.Contains(unit, "--ech-outer") {
		t.Fatal(unit)
	}
}

// Validation refuses settings that cannot work.
func TestSniffValidation(t *testing.T) {
	base := sniffOn(defaults.Example())
	cases := map[string]func(*model.Topology){
		"dns port":   func(t *model.Topology) { t.Settings.Sniff.Ports = []int{443, 53} },
		"own port":   func(t *model.Topology) { t.Settings.Sniff.Ports = []int{validate.SniffListenPort} },
		"bad port":   func(t *model.Topology) { t.Settings.Sniff.Ports = []int{0} },
		"dup port":   func(t *model.Topology) { t.Settings.Sniff.Ports = []int{443, 443} },
		"many ports": func(t *model.Topology) { t.Settings.Sniff.Ports = make([]int, model.MaxSniffPorts+1) },
		"bad ech":    func(t *model.Topology) { t.Settings.Sniff.ECHPublicNames = []string{"not a name"} },
		"panel clash": func(t *model.Topology) {
			t.Settings.PanelBind = fmt.Sprintf("192.168.100.88:%d", validate.SniffListenPort)
		},
	}
	for name, f := range cases {
		topo := base
		s := *base.Settings.Sniff
		topo.Settings.Sniff = &s
		f(&topo)
		res := validate.Run(topo)
		found := false
		for _, is := range res.Issues {
			found = found || is.Severity == validate.SeverityError && (is.Code == "sniff_invalid" || is.Code == "port_conflict")
		}
		if !found {
			t.Errorf("%s: no error", name)
		}
		if _, err := Compile(topo); err == nil {
			t.Errorf("%s: compiled", name)
		}
	}
	if res := validate.Run(base); res.HasErrors() {
		t.Fatalf("defaults refused: %+v", res.Issues)
	}
}

// The gateway verify script gains the forwarder's checks only with the
// setting on, and still parses.
func TestSniffVerifyScript(t *testing.T) {
	topo := sniffRules(defaults.Example(), "jp")
	off := mustCompile(t, topo).File("nodes/gw/usr/local/sbin/meridian-verify.sh")
	on := mustCompile(t, sniffOn(topo)).File("nodes/gw/usr/local/sbin/meridian-verify.sh")
	if strings.Contains(off, "sniff") || !strings.Contains(on, "pass sniff_active") || !strings.Contains(on, "notrun netns_sniff") {
		t.Fatal("verify script sniff block")
	}
	if bash, err := exec.LookPath("bash"); err == nil {
		cmd := exec.Command(bash, "-n")
		cmd.Stdin = strings.NewReader(on)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("bash -n: %v %s", err, out)
		}
	}
}

// Found while building the netns lab: with 17 or more rules, rule 1's IPv6
// set "r16" and rule 16's IPv4 set "r16" were declared twice and the
// gateway ruleset did not load (whenever rule 1's target carries IPv6).
// A colliding IPv6 set is now "r1_6"; short lists keep their names.
func TestRuleSetNamesUnique(t *testing.T) {
	topo := defaults.Example()
	for i := 0; i < 30; i++ {
		topo.Rules = append(topo.Rules, model.Rule{ID: fmt.Sprintf("n%d", i), Name: fmt.Sprintf("n%d", i), Enabled: true, MatchType: model.MatchSuffix,
			MatchValue: fmt.Sprintf("n%d.example.net", i), TargetGroup: "jp", Priority: i})
	}
	b := mustCompile(t, topo)
	nft := b.File("nodes/gw/etc/nftables.d/meridian.nft")
	seen := map[string]bool{}
	for _, m := range regexp.MustCompile(`(?m)^  set (\S+) \{`).FindAllStringSubmatch(nft, -1) {
		if seen[m[1]] {
			t.Fatalf("set %s declared twice", m[1])
		}
		seen[m[1]] = true
	}
	if !seen["r1_6"] && !strings.Contains(nft, "r1 ") {
		t.Log("rule 1 has no IPv6 set in this topology")
	}
	short := mustCompile(t, defaults.Example()).File("nodes/gw/etc/nftables.d/meridian.nft")
	if strings.Contains(short, "_6 {") {
		t.Fatal("a short list's set names changed")
	}
}
