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
// topology's own rules: a direct rule, a reject rule, a rule imported
// from a mihomo policy group, a CIDR rule and a keyword rule.
func sniffRules(topo model.Topology, group string) model.Topology {
	topo.Rules = append(topo.Rules,
		model.Rule{ID: "sn-direct", Name: "direct", Enabled: true, MatchType: model.MatchSuffix, MatchValue: "home.example.org", TargetAction: model.ActionDirect, Priority: 1},
		model.Rule{ID: "sn-reject", Name: "reject", Enabled: true, MatchType: model.MatchSuffix, MatchValue: "ads.example.com", TargetAction: model.ActionReject, Priority: 2},
		model.Rule{ID: "sn-svc", Name: "svc", Enabled: true, MatchType: model.MatchSuffix, MatchValue: "ai.example.org", TargetGroup: group, MihomoGroup: "AI", Priority: 3},
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
			// sniff_input: refuse what was not redirected, then put the
			// takeover bit back on a redirected SYN without it (its own
			// classification, relay bits cleared), then clear every other
			// unbitted TCP mark. The order matters: after the clearing rule
			// the classification would be gone.
			in := f.nft[strings.Index(f.nft, "chain sniff_input {"):]
			in = in[:strings.Index(in, "\n  }\n")]
			drop := strings.Index(in, fmt.Sprintf("tcp dport %d ct status & dnat == 0 drop", validate.SniffListenPort))
			resyn := strings.Index(in, fmt.Sprintf("tcp dport %d ct status & dnat != 0 tcp flags & (fin | syn | rst | ack) == syn meta mark & 0x01000000 == 0x00000000 meta mark & 0xfe00ffff != 0x00000000 meta mark set meta mark & 0xfe00ffff | 0x01000000 counter name \"sniff_resyn\"", validate.SniffListenPort))
			clear := strings.Index(in, "meta l4proto tcp meta mark & 0x01000000 == 0x00000000 meta mark set 0x00000000")
			if drop < 0 || resyn < drop || clear < resyn || strings.Count(in, "meta mark set") != 2 || !strings.Contains(f.nft, "counter sniff_resyn {") {
				t.Fatalf("sniff_input:\n%s", in)
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
		"ExecReload=/bin/kill -HUP $MAINPID", "ExecStartPre=+/usr/sbin/sysctl -q -w net.ipv4.tcp_fwmark_accept=1", "ExecStopPost=+/usr/sbin/sysctl -q -w net.ipv4.tcp_fwmark_accept=0", "NoNewPrivileges=yes"} {
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
			t.Settings.PanelBind = fmt.Sprintf("192.0.2.88:%d", validate.SniffListenPort)
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

var (
	wgOuterAcceptRe = regexp.MustCompile(`(?m)^    meta mark 0x00004d72 oifname "([^"]+)" (ip6?) daddr (\S+) udp dport (\d+) counter name "sniff_wg_outer" accept comment "WireGuard outer packets of ([^:"]+): [^"]+"$`)
	wgEndpointRe    = regexp.MustCompile(`(?m)^Endpoint = (\S+)$`)
	wstunnelLocalRe = regexp.MustCompile(`-L 'udp://127\.0\.0\.1:(\d+):`)
)

// sniffConfine is the chain sniff_confine of a compiled gateway ruleset.
func sniffConfine(t *testing.T, nft string) string {
	t.Helper()
	i := strings.Index(nft, "  chain sniff_confine {\n")
	if i < 0 {
		t.Fatal("no chain sniff_confine")
	}
	return nft[i : i+strings.Index(nft[i:], "\n  }\n")]
}

// The forwarder's chain accepts WireGuard's outer packets exactly for the
// gateway's own tunnels, from the same plan data as the WireGuard configs
// and the wstunnel units: every gateway tunnel's Endpoint (address and
// port, out of the LAN NIC) and every gateway wstunnel client's local port
// (127.0.0.1, out of lo) has its accept, and there is no other accept and
// no other rule with the WireGuard fwmark. The configs carry that fwmark,
// and the routes script pins every direct endpoint to the LAN NIC.
func TestSniffWGOuterEndpoints(t *testing.T) {
	for name, topo := range sniffTopologies(t) {
		t.Run(name, func(t *testing.T) {
			b, f := sniffCompile(t, topo)
			confine := sniffConfine(t, f.nft)
			lan := gatewayLAN(topo)
			type ep struct{ oif, addr, port string }
			got := map[ep][]string{}
			for _, m := range wgOuterAcceptRe.FindAllStringSubmatch(confine, -1) {
				a := netip.MustParseAddr(m[3])
				if (m[2] == "ip6") != a.Is6() {
					t.Errorf("family %s for %s", m[2], a)
				}
				got[ep{m[1], m[3], m[4]}] = strings.Fields(m[5])
			}
			if n := strings.Count(confine, "0x00004d72"); n != len(got) {
				t.Fatalf("%d lines with the WireGuard fwmark, %d are the exact accepts:\n%s", n, len(got), confine)
			}
			if strings.Count(confine, "sniff_wg_outer") != len(got) {
				t.Fatal("sniff_wg_outer on a rule that is not an exact accept")
			}
			want := map[ep]bool{}
			named := map[string]bool{}
			for _, ifs := range got {
				for _, i := range ifs {
					named[i] = true
				}
			}
			for _, ifc := range gatewayTunnelIfaces(mustTunnels(t, sniffOn(topo))) {
				conf := b.File("nodes/gw/etc/wireguard/" + ifc + ".conf")
				if !strings.Contains(conf, fmt.Sprintf("\nFwMark = %#x\n", markUnderlay)) {
					t.Errorf("%s: the config does not carry FwMark %#x", ifc, markUnderlay)
				}
				m := wgEndpointRe.FindStringSubmatch(conf)
				if m == nil {
					t.Errorf("%s: no Endpoint (these examples dial every tunnel)", ifc)
					continue
				}
				ap := netip.MustParseAddrPort(m[1])
				oif := lan
				if ap.Addr().IsLoopback() {
					oif = "lo"
				} else if !strings.Contains(f.up+b.File("nodes/gw/usr/local/sbin/meridian-routes.sh"), fmt.Sprintf("ip route replace '%s/32' via ", ap.Addr())) {
					t.Errorf("%s: endpoint %s is not pinned to the LAN NIC by the routes script", ifc, ap.Addr())
				}
				want[ep{oif, ap.Addr().String(), fmt.Sprint(ap.Port())}] = true
				if !named[ifc] {
					t.Errorf("tunnel %s has no outer-packet accept", ifc)
				}
			}
			// The wstunnel clients' local ports are the WSS Endpoints.
			wss := 0
			for path, body := range b.Files {
				if strings.HasPrefix(path, "nodes/gw/etc/systemd/system/wstunnel-client-") {
					m := wstunnelLocalRe.FindStringSubmatch(body)
					if m == nil {
						t.Fatalf("%s: no local UDP port", path)
					}
					wss++
					if !want[ep{"lo", "127.0.0.1", m[1]}] {
						t.Errorf("%s listens on 127.0.0.1:%s, which no gateway tunnel's Endpoint names", path, m[1])
					}
				}
			}
			if wss == 0 {
				t.Fatal("the example has no WSS carrier")
			}
			for e := range want {
				if _, ok := got[e]; !ok {
					t.Errorf("no accept for endpoint %v", e)
				}
			}
			for e := range got {
				if !want[e] {
					t.Errorf("accept for %v, which is no gateway tunnel's endpoint", e)
				}
			}
			// Before the rule that would drop them, after the reply accept.
			if strings.Index(confine, "sniff_wg_outer") > strings.Index(confine, `meta l4proto != tcp counter name "sniff_denied" drop`) {
				t.Fatal("the outer-packet accepts come after the non-TCP drop")
			}
		})
	}
}

// A tunnel whose outer packets have no fixed destination gets no accept:
// the forwarder's traffic through it fails closed (sniff_denied), and the
// chain says why. An IPv6 endpoint gets an ip6 accept.
func TestSniffWGOuterFailClosed(t *testing.T) {
	topo := sniffOn(defaults.Example())
	gw := model.Node{ID: "gw", Role: model.RoleGateway}
	tunnels := []Tunnel{
		{LinkID: "l1", Base: "m10", Mode: "udp", WGPort: 51820, West: gw, East: model.Node{ID: "r1", Role: model.RoleRelay, EndpointV4: "203.0.113.40"}},
		{LinkID: "l2", Base: "m11", Mode: "udp", WGPort: 51821, West: gw, East: model.Node{ID: "r2", Role: model.RoleRelay}},
		{LinkID: "l3", Base: "m12", Mode: "udp", WGPort: 51822, DialOut: true, West: gw, East: model.Node{ID: "r3", Role: model.RoleRelay, EndpointV4: "203.0.113.42"}},
		{LinkID: "l4", Base: "m13", Mode: "udp", WGPort: 51823, West: gw, East: model.Node{ID: "x1", Role: model.RoleExit, EndpointHost: "exit.example.net"}},
		{LinkID: "l5", Base: "m14", Mode: "udp", WGPort: 51824, OuterV6: true, West: gw, East: model.Node{ID: "r5", Role: model.RoleRelay, EndpointV6: "2001:db8::44"}},
		{LinkID: "l6", Base: "m15", Mode: "wss", Transport: model.TransportWGOverWSS, WGPort: 51825, ClientUDP: 52015, West: gw, East: model.Node{ID: "r6", Role: model.RoleRelay, EndpointV4: "203.0.113.45"}},
		{LinkID: "l7", Base: "m16", Mode: "udp", WGPort: 51826, West: model.Node{ID: "relay", Role: model.RoleRelay}, East: model.Node{ID: "hub", Role: model.RoleHub, EndpointV4: "203.0.113.46"}},
	}
	outer, none := gatewayWGOuter(topo, tunnels)
	var sb strings.Builder
	writeSniffWGOuter(&sb, outer, none)
	got := sb.String()
	lan := gatewayLAN(topo)
	for _, w := range []string{
		`meta mark 0x00004d72 oifname "` + lan + `" ip daddr 203.0.113.40 udp dport 51820 counter name "sniff_wg_outer" accept comment "WireGuard outer packets of m10: its peer endpoint"`,
		`meta mark 0x00004d72 oifname "` + lan + `" ip6 daddr 2001:db8::44 udp dport 51824 counter name "sniff_wg_outer" accept`,
		`meta mark 0x00004d72 oifname "lo" ip daddr 127.0.0.1 udp dport 52015 counter name "sniff_wg_outer" accept comment "WireGuard outer packets of m15: its local wstunnel client"`,
		"# m11: no Endpoint in its configuration",
		"# m12: no Endpoint in its configuration",
		"# m13: its Endpoint is a name, not an address",
	} {
		if !strings.Contains(got, w) {
			t.Errorf("missing %q in\n%s", w, got)
		}
	}
	if strings.Count(got, " accept ") != 3 || strings.Contains(got, "203.0.113.42") || strings.Contains(got, "203.0.113.46") || strings.Contains(got, "exit.example.net") {
		t.Fatalf("accepts beyond the three literal endpoints of gateway tunnels:\n%s", got)
	}
}

// The audit of every owner match (meta skuid) in the gateway ruleset
// against WireGuard's outer packets, which carry the forwarder's uid, UDP
// and the mark markUnderlay: sniff_route and sniff_mss match TCP only;
// transit_snat matches only the exit and region-group marks (relay bits
// masked), and markUnderlay is none of them and has no relay or sniff bit,
// so an outer packet is never rerouted, re-marked, clamped or SNATed to a
// transit address; sniff_out sends it to sniff_confine, which accepts only
// the exact endpoints (TestSniffWGOuterEndpoints); the traffic counters
// (traffic_sniff_out/in) match TCP only and only count. There is no other
// owner match.
func TestSniffOwnerRulesSkipOuterPackets(t *testing.T) {
	if markUnderlay&(markShareMask|markSniff) != 0 {
		t.Fatalf("markUnderlay %#x overlaps the relay or sniff bits", markUnderlay)
	}
	if last := markExitBase + model.MaxMarkSlots - 1; markUnderlay >= markExitBase && markUnderlay <= uint32(last) {
		t.Fatalf("markUnderlay %#x is inside the exit and group mark range", markUnderlay)
	}
	snat := regexp.MustCompile(`^meta skuid \d+ meta mark & 0xff00ffff == (0x[0-9a-f]+) meta nfproto ipv[46] snat ip6? to \S+`)
	for name, topo := range sniffTopologies(t) {
		t.Run(name, func(t *testing.T) {
			_, f := sniffCompile(t, topo)
			exits := planExits(sniffOn(topo), mustTunnels(t, sniffOn(topo)))
			marks := map[uint32]bool{}
			for _, m := range markPlans(exits, planGroups(sniffOn(topo), exits)) {
				marks[m.Mark] = true
			}
			if marks[markUnderlay] || marks[markUnderlay&markNoShare] {
				t.Fatal("markUnderlay is an exit or group mark")
			}
			n := 0
			for _, line := range strings.Split(f.nft, "\n") {
				s := strings.TrimSpace(line)
				if !strings.Contains(s, "meta skuid") {
					continue
				}
				n++
				switch {
				case s == fmt.Sprintf("meta skuid %d jump sniff_confine", SniffUID):
				case strings.HasPrefix(s, fmt.Sprintf("meta skuid %d meta l4proto tcp tcp dport != 53 meta mark 0x101-", SniffUID)) && strings.HasSuffix(s, "jump relay_share comment \"the forwarder's connections share the relays like forwarded ones\""):
				case strings.HasPrefix(s, fmt.Sprintf("meta skuid %d tcp flags syn ", SniffUID)) && strings.Contains(s, "tcp option maxseg size set"):
				case strings.HasPrefix(s, fmt.Sprintf("meta skuid %d ct direction original meta l4proto tcp tcp dport != 53 ", SniffUID)) && strings.Contains(s, " counter name \"traffic_up_") && !strings.Contains(s, " set "):
					// traffic_sniff_out: TCP only, count only.
				case strings.HasPrefix(s, "ct direction reply meta l4proto tcp tcp sport != 53 meta skuid ") && strings.Contains(s, " counter name \"traffic_down_") && !strings.Contains(s, " set "):
					// traffic_sniff_in: TCP only, count only.
				default:
					m := snat.FindStringSubmatch(s)
					if m == nil {
						t.Fatalf("owner match not covered by the audit: %s", s)
					}
					v, _ := strconv.ParseUint(m[1], 0, 32)
					if !marks[uint32(v)] {
						t.Fatalf("forwarder SNAT for %s, which is no exit or group mark: %s", m[1], s)
					}
				}
			}
			if n == 0 {
				t.Fatal("no owner match at all")
			}
		})
	}
}
