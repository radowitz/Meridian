//go:build linux

package compile

import (
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/radowitz/meridian/internal/defaults"
	"github.com/radowitz/meridian/internal/dnssplit"
	"github.com/radowitz/meridian/internal/model"
)

// TestSmartDNSRealBinary runs the pinned SmartDNS (1.2026.08.05-0921,
// Release48.4) with the gateway config this compiler renders, for every
// combination of clients_ipv6_via_gateway and unlisted_domestic_dns,
// against stub upstreams on loopback: two "domestic" resolvers (the two
// domestic_dot addresses; they can answer differently) and one "exit"
// (every exit and region-group resolver). With unlisted_domestic_dns on,
// meridian-dns-split (internal/dnssplit) runs in this process with the
// flags of the rendered meridian-dns-split.service; only its upstream
// addresses, its mark and its list paths are pointed at the test's stubs
// and files. Edits to the rendered SmartDNS config: listeners on one
// loopback port, upstream addresses pointed at the stubs (server-tls lines
// dropped), -set-mark and nftset removed (no CAP_NET_ADMIN, no nft table
// here), domain-set files and the cache file moved into a temporary
// directory. China is 198.51.100.0/24 and 2001:db8:c::/48 in the China
// lists; every other address is foreign. It checks, with real queries:
//
//   - a listed domestic name (gs_cn) gets the domestic answer, AAAA included;
//   - an unlisted name with the setting off: the exit's answer. With it on:
//     the domestic answer only when every address in it is a China address
//     (bare A or at the end of a CNAME chain, even when the domestic
//     resolver is slower than the exit, and when the other domestic
//     resolver answered first with a poisoned address and the China answer
//     came within its settle time); the exit's answer when that China
//     answer came only after the decision; the exit's answer
//     for a CNAME chain ending in a foreign address (the case that returned
//     an address-less CNAME on a real gateway with SmartDNS's own
//     -whitelist-ip/-fallback), a mixed answer, NODATA, a poisoned bare A
//     and a silent domestic resolver; no address at all when the exit does
//     not answer, never a domestic foreign address; never a CNAME-only
//     answer for a resolvable name;
//   - AAAA (and the IPv6 hints of HTTPS records) for unlisted and rule names
//     only with clients_ipv6_via_gateway on and an IPv6 target;
//   - a rule-targeted name (also one aimed at the default group itself,
//     with unlisted_domestic_dns on) is never asked from a domestic resolver
//     (the stubs count every query), even when its domestic answer would
//     qualify; when its group resolver is silent it fails instead of
//     falling back;
//   - empty China lists accept no domestic answer;
//   - a policy change survives no restart: an answer cached under one
//     config is not served after SIGTERM and a start with another config
//     (what an install does with "docker restart"), while a control without
//     "cache-persist no" (the default, auto) serves the stale answer;
//   - a control run of the old config (no force-AAAA-SOA) returns the
//     catch-all AAAA.
//
// Opt-in; skipped unless MERIDIAN_SMARTDNS_BIN names the binary:
//
//	MERIDIAN_SMARTDNS_BIN=/usr/share/meridian/artifacts/smartdns-x86_64 \
//	  go test ./internal/compile -run TestSmartDNSRealBinary -v
//
// On a machine without it, in the panel image (linux/amd64; the image has
// no Go, so the test binary is built outside and mounted):
//
//	GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go test -c -o /tmp/compile.test ./internal/compile
//	docker run --rm --network none --platform linux/amd64 -v /tmp/compile.test:/compile.test:ro \
//	  -e MERIDIAN_SMARTDNS_BIN=/usr/share/meridian/artifacts/smartdns-x86_64 \
//	  --entrypoint /compile.test meridian:local -test.run TestSmartDNSRealBinary -test.v
//
// The gateway's container image: the same command with pymumu/smartdns:latest
// and MERIDIAN_SMARTDNS_BIN=/usr/sbin/smartdns.
func TestSmartDNSRealBinary(t *testing.T) {
	bin := os.Getenv("MERIDIAN_SMARTDNS_BIN")
	if bin == "" {
		t.Skip("MERIDIAN_SMARTDNS_BIN not set (path to the pinned SmartDNS 1.2026.08.05-0921)")
	}
	if out, err := exec.Command(bin, "-v").CombinedOutput(); err != nil {
		t.Fatalf("%s -v: %v %s", bin, err, out)
	} else {
		t.Logf("binary: %s", strings.TrimSpace(string(out)))
	}
	lab := &dnsLab{dom: startDNSStub(t), dom2: startDNSStub(t), exit: startDNSStub(t)}
	lab.setNames()

	for _, c := range []struct{ v6, split bool }{{false, false}, {false, true}, {true, false}, {true, true}} {
		c := c
		t.Run(fmt.Sprintf("clients_v6=%v,unlisted_domestic=%v", c.v6, c.split), func(t *testing.T) {
			topo := realDNSTopo()
			topo.Settings.ClientsIPv6ViaGateway = c.v6
			topo.Settings.UnlistedDomesticDNS = c.split
			exits, groups := plans(t, topo)
			defT, _ := defaultExit(topo, groups)
			catchAllV6 := c.v6 && defT.V6
			rule4, rule6 := realDNSRules(t, topo, exits, groups)
			if rule4.FilterAAAA != true || rule6.FilterAAAA != false {
				t.Fatalf("test topology: rule4 FilterAAAA=%v rule6 FilterAAAA=%v", rule4.FilterAAAA, rule6.FilterAAAA)
			}
			sd := startSmartDNS(t, bin, lab.conf(t, topo, mustCompile(t, topo), labOpts{}))
			// pick: the domestic answer with the check on, the exit's off.
			pick := func(domestic, exit string) string {
				if c.split {
					return domestic
				}
				return exit
			}

			// Listed domestic name: domestic answer, AAAA kept (direct).
			sd.expect(t, "cnlisted.example.net", qA, "198.51.100.20")
			sd.expect(t, "cnlisted.example.net", qAAAA, "2001:db8:f::20")

			// Unlisted, domestic answer all China.
			sd.expect(t, "unl-cn.example.net", qA, pick("198.51.100.30", "203.0.113.30"))
			switch {
			case !catchAllV6:
				sd.expect(t, "unl-cn.example.net", qAAAA)
			default:
				sd.expect(t, "unl-cn.example.net", qAAAA, pick("2001:db8:c::30", "2001:db8:e::30"))
			}
			sd.expect(t, "unl-cn-slow.example.net", qA, pick("198.51.100.31", "203.0.113.31"))
			sd.expect(t, "cname-cn.example.net", qA, pick("198.51.100.92", "203.0.113.92"))
			// One domestic resolver poisoned and fast, the other China.
			sd.expect(t, "split-dom.example.net", qA, pick("198.51.100.93", "203.0.113.93"))
			sd.expect(t, "split-dom-late.example.net", qA, "203.0.113.97")

			// Unlisted, domestic answer not all China: the exit's, decided
			// when the exit answered (50 ms) and the domestic resolvers
			// settled (reply + 30 ms), not after the 400 ms cap.
			if r := sd.expect(t, "cname-foreign.example.net", qA, "203.0.113.90"); r.elapsed > 200*time.Millisecond {
				t.Fatalf("cold foreign name decided after %v (the 400 ms domestic cap?)", r.elapsed)
			}
			sd.expect(t, "cname-mixed.example.net", qA, "203.0.113.94")
			sd.expect(t, "nodata.example.net", qA, "203.0.113.95")
			sd.expect(t, "poison.example.net", qA, "203.0.113.40")
			sd.expect(t, "mixed.example.net", qA, "203.0.113.80")
			if catchAllV6 {
				sd.expect(t, "poison.example.net", qAAAA, "2001:db8:e::40")
				sd.expect(t, "cname-foreign.example.net", qAAAA, "2001:db8:e::90")
			} else {
				sd.expect(t, "poison.example.net", qAAAA)
				sd.expect(t, "cname-foreign.example.net", qAAAA)
			}
			sd.expectNoHint6(t, "poison.example.net", !catchAllV6)
			sd.expectNoHint6(t, "cname-foreign.example.net", !catchAllV6)

			// Domestic resolvers silent: the exit answers.
			sd.expect(t, "domtimeout.example.net", qA, "203.0.113.50")

			// Exit resolver silent: no address, never the domestic foreign one.
			sd.expectFail(t, "exitdown.example.net", qA, "192.0.2.67")
			sd.expectFail(t, "exitdown-cname.example.net", qA, "203.0.113.96")
			if c.split {
				sd.expect(t, "exitdown-cn.example.net", qA, "198.51.100.68")
			} else {
				sd.expectFail(t, "exitdown-cn.example.net", qA, "198.51.100.68")
			}

			// Rules: IPv4-only group never has AAAA; an IPv6 group only
			// when clients route IPv6 through the gateway.
			sd.expect(t, "rule4.example.net", qA, "203.0.113.60")
			sd.expect(t, "rule4.example.net", qAAAA)
			sd.expectNoHint6(t, "rule4.example.net", true)
			sd.expect(t, "rule6.example.net", qA, "203.0.113.61")
			if c.v6 {
				sd.expect(t, "rule6.example.net", qAAAA, "2001:db8:e::61")
			} else {
				sd.expect(t, "rule6.example.net", qAAAA)
			}
			sd.expectNoHint6(t, "rule6.example.net", !c.v6)
			// A rule on the default group itself: its group resolver only,
			// never meridian-dns-split; a rule whose group resolver is
			// silent fails, it does not fall back to a domestic resolver.
			sd.expect(t, "ruledef.example.net", qA, "203.0.113.62")
			if catchAllV6 {
				sd.expect(t, "ruledef.example.net", qAAAA, "2001:db8:e::62")
			} else {
				sd.expect(t, "ruledef.example.net", qAAAA)
			}
			sd.expectFail(t, "ruledown.example.net", qA, "198.51.100.63")
			for _, n := range ruleNames {
				if got := lab.dom.count(n) + lab.dom2.count(n); got != 0 {
					t.Fatalf("rule name %s was asked from the domestic resolvers %d times", n, got)
				}
				if lab.exit.count(n) == 0 {
					t.Fatalf("rule name %s never reached its group resolver", n)
				}
			}
			// Repeated (cached) answers stay the same.
			sd.expect(t, "cname-foreign.example.net", qA, "203.0.113.90")
			for _, q := range sd.log() {
				if strings.Contains(q, "192.0.2.") || strings.Contains(q, "203.0.113.9]") || strings.Contains(q, "203.0.113.9 ") {
					t.Fatalf("a domestic foreign address was returned: %s", q)
				}
			}
		})
	}

	t.Run("unlisted_domestic=true with empty China lists", func(t *testing.T) {
		topo := realDNSTopo()
		topo.Settings.UnlistedDomesticDNS = true
		sd := startSmartDNS(t, bin, lab.conf(t, topo, mustCompile(t, topo), labOpts{emptyLists: true}))
		sd.expect(t, "unl-cn.example.net", qA, "203.0.113.30")
		sd.expect(t, "cname-cn.example.net", qA, "203.0.113.92")
		sd.expect(t, "poison.example.net", qA, "203.0.113.40")
		sd.expect(t, "cnlisted.example.net", qA, "198.51.100.20")
	})

	// A policy change and the answer cache: answer cached with the check
	// on (domestic China answer), SIGTERM, start with the check off. The
	// rendered config ("cache-persist no") answers with the new policy; the
	// control without that line (SmartDNS's default) serves the old answer.
	for _, persistDefault := range []bool{false, true} {
		persistDefault := persistDefault
		name := "policy change across a restart"
		if persistDefault {
			name += " (control: cache-persist default)"
		}
		t.Run(name, func(t *testing.T) {
			cache := filepath.Join(t.TempDir(), "smartdns.cache")
			on, off := realDNSTopo(), realDNSTopo()
			on.Settings.UnlistedDomesticDNS = true
			o := labOpts{cacheFile: cache, persistDefault: persistDefault}
			sd := startSmartDNS(t, bin, lab.conf(t, on, mustCompile(t, on), o))
			sd.expect(t, "unl-cn.example.net", qA, "198.51.100.30")
			sd.stop()
			sd = startSmartDNS(t, bin, lab.conf(t, off, mustCompile(t, off), o))
			if persistDefault {
				sd.expect(t, "unl-cn.example.net", qA, "198.51.100.30")
				t.Log("control: the default persists the cache; the old policy's answer survived the restart")
			} else {
				sd.expect(t, "unl-cn.example.net", qA, "203.0.113.30")
			}
		})
	}

	// Control: the config as rendered before force-AAAA-SOA returns the
	// catch-all AAAA that phones then use over the home line.
	t.Run("control without force-AAAA-SOA", func(t *testing.T) {
		topo := realDNSTopo()
		b := mustCompile(t, topo)
		const p = "nodes/gw/etc/smartdns/smartdns.conf"
		conf := strings.Replace(b.Files[p], "\nforce-AAAA-SOA yes\n", "\n", 1)
		b.Files[p] = strings.ReplaceAll(conf, " -address -6", "")
		sd := startSmartDNS(t, bin, lab.conf(t, topo, b, labOpts{}))
		sd.expect(t, "poison.example.net", qAAAA, "2001:db8:e::40")
	})
}

// realDNSTopo: the example plus four manual rules: one to the IPv4-only
// group tw, one to the IPv6-capable group hk-residential, one to the
// default group itself, and one more to tw for a name its resolver does
// not answer.
func realDNSTopo() model.Topology {
	topo := defaults.Example()
	topo.Rules = append(topo.Rules,
		model.Rule{ID: "lab-rule4", Name: "lab4", Manual: true, Priority: 1, Enabled: true,
			MatchType: model.MatchDomain, MatchValue: "rule4.example.net", TargetGroup: "tw"},
		model.Rule{ID: "lab-rule6", Name: "lab6", Manual: true, Priority: 2, Enabled: true,
			MatchType: model.MatchDomain, MatchValue: "rule6.example.net", TargetGroup: "hk-residential", RequireResidential: true},
		model.Rule{ID: "lab-ruledef", Name: "labdef", Manual: true, Priority: 3, Enabled: true,
			MatchType: model.MatchDomain, MatchValue: "ruledef.example.net", TargetGroup: topo.Settings.DefaultGroup},
		model.Rule{ID: "lab-ruledown", Name: "labdown", Manual: true, Priority: 4, Enabled: true,
			MatchType: model.MatchDomain, MatchValue: "ruledown.example.net", TargetGroup: "tw"},
	)
	return topo
}

func realDNSRules(t *testing.T, topo model.Topology, exits []ExitPlan, groups []GroupPlan) (rule4, rule6 rulePlan) {
	t.Helper()
	for _, rp := range planRules(topo, exits, groups, nil) {
		switch rp.Rule.ID {
		case "lab-rule4":
			rule4 = rp
		case "lab-rule6":
			rule6 = rp
		}
	}
	if rule4.Rule.ID == "" || rule6.Rule.ID == "" {
		t.Fatal("lab rules not planned")
	}
	return rule4, rule6
}

type dnsLab struct{ dom, dom2, exit *dnsStub }

func (l *dnsLab) setNames() {
	both := func(n string, d, e stubAnswer) { l.dom.set(n, d); l.dom2.set(n, d); l.exit.set(n, e) }
	both("ready.example.net", stubAnswer{A: []string{"203.0.113.1"}}, stubAnswer{A: []string{"203.0.113.1"}})
	both("cnlisted.example.net",
		stubAnswer{A: []string{"198.51.100.20"}, AAAA: []string{"2001:db8:f::20"}},
		stubAnswer{A: []string{"203.0.113.20"}, AAAA: []string{"2001:db8:e::20"}})
	both("unl-cn.example.net",
		stubAnswer{A: []string{"198.51.100.30"}, AAAA: []string{"2001:db8:c::30"}},
		stubAnswer{A: []string{"203.0.113.30"}, AAAA: []string{"2001:db8:e::30"}, Delay: 100 * time.Millisecond})
	both("unl-cn-slow.example.net",
		stubAnswer{A: []string{"198.51.100.31"}, Delay: 80 * time.Millisecond},
		stubAnswer{A: []string{"203.0.113.31"}})
	both("cname-cn.example.net",
		stubAnswer{CNAME: "edge.cdn.example.cn", A: []string{"198.51.100.92"}},
		stubAnswer{CNAME: "edge.cdn.example.org", A: []string{"203.0.113.92"}})
	// One domestic resolver poisoned at once, the other China within the
	// first one's settle time (30 ms): the China answer. Arriving after
	// that (the first resolver settled, the exit answered): the exit's,
	// the documented safe direction (tunnelled instead of direct).
	both("split-dom.example.net",
		stubAnswer{A: []string{"198.51.100.93"}, Delay: 15 * time.Millisecond},
		stubAnswer{A: []string{"203.0.113.93"}})
	l.dom.set("split-dom.example.net", stubAnswer{A: []string{"192.0.2.93"}})
	both("split-dom-late.example.net",
		stubAnswer{A: []string{"198.51.100.97"}, Delay: 120 * time.Millisecond},
		stubAnswer{A: []string{"203.0.113.97"}, Delay: 10 * time.Millisecond})
	l.dom.set("split-dom-late.example.net", stubAnswer{A: []string{"192.0.2.97"}})
	// The real-gateway failure: an honest domestic CNAME chain ending in a
	// foreign address.
	both("cname-foreign.example.net",
		stubAnswer{CNAME: "dyna.cdn.example.org", A: []string{"203.0.113.9"}, AAAA: []string{"2001:db8:bad::9"}},
		stubAnswer{CNAME: "edge.cdn.example.org", A: []string{"203.0.113.90"}, AAAA: []string{"2001:db8:e::90"}, Delay: 50 * time.Millisecond})
	both("cname-mixed.example.net",
		stubAnswer{CNAME: "edge.cdn.example.cn", A: []string{"198.51.100.94", "192.0.2.94"}},
		stubAnswer{A: []string{"203.0.113.94"}, Delay: 50 * time.Millisecond})
	both("nodata.example.net", stubAnswer{}, stubAnswer{A: []string{"203.0.113.95"}, Delay: 30 * time.Millisecond})
	both("poison.example.net",
		stubAnswer{A: []string{"192.0.2.66"}, AAAA: []string{"2001:db8:bad::66"}},
		stubAnswer{A: []string{"203.0.113.40"}, AAAA: []string{"2001:db8:e::40"}, Delay: 150 * time.Millisecond})
	both("mixed.example.net",
		stubAnswer{A: []string{"198.51.100.80", "192.0.2.80"}},
		stubAnswer{A: []string{"203.0.113.80"}, Delay: 100 * time.Millisecond})
	both("domtimeout.example.net", stubAnswer{Drop: true}, stubAnswer{A: []string{"203.0.113.50"}})
	both("exitdown.example.net", stubAnswer{A: []string{"192.0.2.67"}, AAAA: []string{"2001:db8:bad::67"}}, stubAnswer{Drop: true})
	both("exitdown-cname.example.net", stubAnswer{CNAME: "dyna.cdn.example.org", A: []string{"203.0.113.96"}}, stubAnswer{Drop: true})
	both("exitdown-cn.example.net", stubAnswer{A: []string{"198.51.100.68"}}, stubAnswer{Drop: true})
	both("rule4.example.net", stubAnswer{A: []string{"192.0.2.60"}}, stubAnswer{A: []string{"203.0.113.60"}, AAAA: []string{"2001:db8:e::60"}})
	both("rule6.example.net", stubAnswer{A: []string{"192.0.2.61"}}, stubAnswer{A: []string{"203.0.113.61"}, AAAA: []string{"2001:db8:e::61"}})
	// Rule names whose domestic answer would qualify (all China): they
	// must still never be asked from the domestic resolvers, also when the
	// rule's group resolver does not answer (no fallback).
	both("ruledef.example.net", stubAnswer{A: []string{"198.51.100.62"}, AAAA: []string{"2001:db8:c::62"}}, stubAnswer{A: []string{"203.0.113.62"}, AAAA: []string{"2001:db8:e::62"}})
	both("ruledown.example.net", stubAnswer{A: []string{"198.51.100.63"}}, stubAnswer{Drop: true})
}

// ruleNames are the names only rules match (realDNSTopo).
var ruleNames = []string{"rule4.example.net", "rule6.example.net", "ruledef.example.net", "ruledown.example.net"}

type labOpts struct {
	// emptyLists: a gateway where no list update has run yet.
	emptyLists bool
	// cacheFile, when set, is the SmartDNS cache file; persistDefault
	// drops the rendered "cache-persist no" (SmartDNS's default, auto).
	cacheFile      string
	persistDefault bool
}

var (
	reLabServer = regexp.MustCompile(`^server (\S+)( .*)?$`)
	reLabMark   = regexp.MustCompile(` -set-mark \d+`)
	reLabFile   = regexp.MustCompile(` -file (\S+)`)
	reLabSplit  = regexp.MustCompile(`(?m)^ExecStart=/usr/local/bin/meridian dns-split (.*)$`)
)

// conf rewrites the bundle's gateway SmartDNS config for loopback (see the
// test's comment for the complete list of edits) and, when the bundle has
// meridian-dns-split, starts it from the rendered unit's flags.
func (l *dnsLab) conf(t *testing.T, topo model.Topology, b *Bundle, o labOpts) string {
	t.Helper()
	conf := b.File("nodes/gw/etc/smartdns/smartdns.conf")
	dir := t.TempDir()
	dots := domesticDoT(topo)
	if len(dots) != 2 {
		t.Fatalf("lab expects two domestic resolvers: %v", dots)
	}
	domFor := map[string]string{dots[0]: l.dom.addr, dots[1]: l.dom2.addr}
	// China lists of the real lists' size (6217 IPv4 / 3423 IPv6 prefixes
	// were observed): 8192 IPv4 /28 of 198.18.0.0/15 and 4096 IPv6 /48 of
	// 2001:db8::/32 next to the test's China prefixes.
	var v4, v6 strings.Builder
	v4.WriteString("# test list\n198.51.100.0/24\n")
	for i := 0; i < 8192; i++ {
		fmt.Fprintf(&v4, "198.%d.%d.%d/28\n", 18+i>>12, (i>>4)&0xff, (i&0xf)<<4)
	}
	v6.WriteString("2001:db8:c::/48\n")
	for i := 0; i < 4096; i++ {
		fmt.Fprintf(&v6, "2001:db8:%x::/48\n", 0x1000+i)
	}
	if o.emptyLists {
		v4.Reset()
		v6.Reset()
	}
	files := map[string]string{
		"/var/lib/meridian/geosite/cn.txt": "cnlisted.example.net\n",
		chinaListFile4:                     v4.String(),
		chinaListFile6:                     v6.String(),
	}
	local := func(p string) string {
		lp := filepath.Join(dir, strings.NewReplacer("/", "_").Replace(p))
		if err := os.WriteFile(lp, []byte(files[p]), 0o644); err != nil {
			t.Fatal(err)
		}
		return lp
	}
	splitAddr := ""
	if unit := b.File("nodes/gw/etc/systemd/system/" + DNSSplitUnit); unit != "" {
		m := reLabSplit.FindStringSubmatch(unit)
		if m == nil {
			t.Fatalf("no dns-split ExecStart:\n%s", unit)
		}
		cfg, err := dnssplit.ParseArgs(strings.Fields(m[1]))
		if err != nil {
			t.Fatalf("rendered dns-split flags: %v", err)
		}
		if len(cfg.Domestic) != 2 {
			t.Fatalf("dns-split domestic %v", cfg.Domestic)
		}
		for i, d := range cfg.Domestic {
			ap := netip.MustParseAddrPort(d)
			cfg.Domestic[i] = domFor[ap.Addr().String()]
		}
		cfg.Listen, cfg.Exit, cfg.ExitMark = "127.0.0.1:0", l.exit.addr, 0
		cfg.China4, cfg.China6 = local(cfg.China4), local(cfg.China6)
		s := dnssplit.New(cfg)
		if err := s.Start(); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(s.Close)
		splitAddr = s.Addr()
	}
	port := freeUDPPort(t)
	out := []string{fmt.Sprintf("bind 127.0.0.1:%d", port), "log-level info", "log-file " + filepath.Join(dir, "smartdns.log")}
	if o.cacheFile != "" {
		out = append(out, "cache-file "+o.cacheFile)
	}
	for _, line := range strings.Split(conf, "\n") {
		switch {
		case strings.HasPrefix(line, "bind"), strings.HasPrefix(line, "server-tls "),
			strings.HasPrefix(line, "nftset "):
			continue
		case o.persistDefault && line == "cache-persist no":
			continue
		}
		if i := strings.Index(line, " -nftset "); i >= 0 {
			line = line[:i] // always the last option of a domain-rules line
		}
		line = reLabMark.ReplaceAllString(line, "")
		if m := reLabServer.FindStringSubmatch(line); m != nil {
			addr := l.exit.addr
			switch {
			case domFor[m[1]] != "":
				addr = domFor[m[1]]
			case m[1] == DNSSplitListen:
				if splitAddr == "" {
					t.Fatal("config uses meridian-dns-split but the bundle has no unit")
				}
				addr = splitAddr
			}
			line = "server " + addr + m[2]
		}
		if m := reLabFile.FindStringSubmatch(line); m != nil {
			line = strings.Replace(line, m[1], local(m[1]), 1)
		}
		out = append(out, line)
	}
	return strings.Join(out, "\n") + "\n"
}

func freeUDPPort(t *testing.T) int {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	return pc.LocalAddr().(*net.UDPAddr).Port
}

type smartDNSRun struct {
	addr string
	// stop ends the process with SIGTERM (what "docker restart" sends)
	// and waits for it.
	stop func()
	mu   sync.Mutex
	seen []string
}

func startSmartDNS(t *testing.T, bin, conf string) *smartDNSRun {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, "smartdns.conf")
	if err := os.WriteFile(p, []byte(conf), 0o644); err != nil {
		t.Fatal(err)
	}
	var addr string
	for _, l := range strings.Split(conf, "\n") {
		if strings.HasPrefix(l, "bind ") {
			// The address, without the listener's options (-group …).
			addr = strings.Fields(strings.TrimPrefix(l, "bind "))[0]
		}
	}
	cmd := exec.Command(bin, "-f", "-x", "-p", "-", "-c", p)
	logf, err := os.Create(filepath.Join(dir, "stdout.log"))
	if err != nil {
		t.Fatal(err)
	}
	cmd.Stdout, cmd.Stderr = logf, logf
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	exited := make(chan error, 1)
	go func() { exited <- cmd.Wait() }()
	var once sync.Once
	end := func(sig os.Signal) {
		once.Do(func() {
			_ = cmd.Process.Signal(sig)
			select {
			case <-exited:
			case <-time.After(10 * time.Second):
				_ = cmd.Process.Kill()
				<-exited
			}
		})
	}
	t.Cleanup(func() {
		end(os.Kill)
		logf.Close()
		if t.Failed() {
			b, _ := os.ReadFile(logf.Name())
			t.Logf("smartdns output:\n%s\nconfig:\n%s", b, conf)
		}
	})
	sd := &smartDNSRun{addr: addr, stop: func() { end(syscall.SIGTERM) }}
	deadline := time.Now().Add(15 * time.Second)
	for {
		select {
		case err := <-exited:
			b, _ := os.ReadFile(logf.Name())
			t.Fatalf("smartdns exited: %v\n%s\nconfig:\n%s", err, b, conf)
		default:
		}
		if r, err := dnsQuery(addr, "ready.example.net", qA, time.Second); err == nil && len(r.addrs) > 0 {
			t.Logf("smartdns answering %v after start", time.Since(deadline.Add(-15*time.Second)).Round(time.Millisecond))
			return sd
		}
		if time.Now().After(deadline) {
			t.Fatal("smartdns did not answer within 15 s")
		}
		time.Sleep(100 * time.Millisecond)
	}
}

func (sd *smartDNSRun) record(s string) {
	sd.mu.Lock()
	sd.seen = append(sd.seen, s)
	sd.mu.Unlock()
}

func (sd *smartDNSRun) log() []string {
	sd.mu.Lock()
	defer sd.mu.Unlock()
	return append([]string(nil), sd.seen...)
}

// expect: rcode NOERROR and exactly the addresses want (none: an empty
// answer, which is what an AAAA SOA is).
func (sd *smartDNSRun) expect(t *testing.T, name string, qt uint16, want ...string) dnsResult {
	t.Helper()
	r, err := dnsQuery(sd.addr, name, qt, 6*time.Second)
	sd.record(fmt.Sprintf("%s %s rcode=%d %v %v", name, qtypeName(qt), r.rcode, r.addrs, r.elapsed.Round(time.Millisecond)))
	t.Logf("%-26s %-5s rcode=%d %v %v", name, qtypeName(qt), r.rcode, r.addrs, r.elapsed.Round(time.Millisecond))
	if err != nil {
		t.Fatalf("%s %s: %v", name, qtypeName(qt), err)
	}
	if r.rcode != 0 || strings.Join(r.addrs, ",") != strings.Join(want, ",") {
		t.Fatalf("%s %s: rcode %d %v, want NOERROR %v", name, qtypeName(qt), r.rcode, r.addrs, want)
	}
	return r
}

// expectFail: no address at all (SERVFAIL, an empty NOERROR or no reply),
// and never the address forbidden.
func (sd *smartDNSRun) expectFail(t *testing.T, name string, qt uint16, forbidden string) {
	t.Helper()
	r, err := dnsQuery(sd.addr, name, qt, 6*time.Second)
	sd.record(fmt.Sprintf("%s %s rcode=%d %v %v", name, qtypeName(qt), r.rcode, r.addrs, r.elapsed.Round(time.Millisecond)))
	t.Logf("%-26s %-5s rcode=%d %v %v err=%v", name, qtypeName(qt), r.rcode, r.addrs, r.elapsed.Round(time.Millisecond), err)
	if len(r.addrs) > 0 {
		t.Fatalf("%s %s: got %v, want no address (never %s)", name, qtypeName(qt), r.addrs, forbidden)
	}
}

// expectNoHint6: the HTTPS record of name carries no IPv6 hint when
// noHint is set (the stub always offers one).
func (sd *smartDNSRun) expectNoHint6(t *testing.T, name string, noHint bool) {
	t.Helper()
	r, err := dnsQuery(sd.addr, name, qHTTPS, 6*time.Second)
	if err != nil {
		t.Fatalf("%s HTTPS: %v", name, err)
	}
	t.Logf("%-26s HTTPS rcode=%d hints=%v", name, r.rcode, r.addrs)
	has6 := false
	for _, a := range r.addrs {
		if strings.Contains(a, ":") {
			has6 = true
		}
		if strings.HasPrefix(a, "192.0.2.") {
			t.Fatalf("%s HTTPS: poisoned hint %v", name, r.addrs)
		}
	}
	if noHint && has6 {
		t.Fatalf("%s HTTPS: IPv6 hint %v although AAAA is suppressed", name, r.addrs)
	}
}

// ------------------------------------------------------------ DNS stub ---

const (
	qA     uint16 = 1
	qAAAA  uint16 = 28
	qHTTPS uint16 = 65
)

func qtypeName(q uint16) string {
	return map[uint16]string{qA: "A", qAAAA: "AAAA", qHTTPS: "HTTPS"}[q]
}

type stubAnswer struct {
	// CNAME: the answer starts with qname CNAME CNAME, and the addresses
	// are owned by the CNAME target (what real CDNs answer).
	CNAME   string
	A, AAAA []string
	Delay   time.Duration
	// Drop: never answer.
	Drop bool
}

type dnsStub struct {
	addr  string
	mu    sync.Mutex
	names map[string]stubAnswer
	// asked counts every query received per name (answered or not).
	asked map[string]int
}

// count is how many queries for name this stub has received.
func (s *dnsStub) count(name string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.asked[name]
}

func (s *dnsStub) set(name string, a stubAnswer) {
	s.mu.Lock()
	s.names[name] = a
	s.mu.Unlock()
}

// startDNSStub answers A, AAAA and HTTPS (ipv4hint/ipv6hint) for the names
// it was given; an empty answer carries an SOA. Unknown names are dropped.
func startDNSStub(t *testing.T) *dnsStub {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { pc.Close() })
	s := &dnsStub{addr: pc.LocalAddr().String(), names: map[string]stubAnswer{}, asked: map[string]int{}}
	go func() {
		buf := make([]byte, 4096)
		for {
			n, from, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			q := append([]byte(nil), buf[:n]...)
			name, qt, end, ok := dnsQuestion(q)
			if !ok {
				continue
			}
			s.mu.Lock()
			a, found := s.names[name]
			s.asked[name]++
			s.mu.Unlock()
			if !found || a.Drop {
				continue
			}
			go func() {
				time.Sleep(a.Delay)
				_, _ = pc.WriteTo(dnsReply(q, end, qt, a), from)
			}()
		}
	}()
	return s
}

func dnsQuestion(b []byte) (string, uint16, int, bool) {
	if len(b) < 12 {
		return "", 0, 0, false
	}
	i := 12
	var labels []string
	for i < len(b) {
		l := int(b[i])
		i++
		if l == 0 {
			break
		}
		if l&0xc0 != 0 || i+l > len(b) {
			return "", 0, 0, false
		}
		labels = append(labels, strings.ToLower(string(b[i:i+l])))
		i += l
	}
	if i+4 > len(b) {
		return "", 0, 0, false
	}
	return strings.Join(labels, "."), binary.BigEndian.Uint16(b[i:]), i + 4, true
}

func encodeName(n string) []byte {
	var b []byte
	for _, l := range strings.Split(strings.TrimSuffix(n, "."), ".") {
		b = append(b, byte(len(l)))
		b = append(b, l...)
	}
	return append(b, 0)
}

func dnsRR(qtype uint16, rd []byte) []byte { return dnsRROwner(nil, qtype, rd) }

// dnsRROwner: owner nil is the question name (compression pointer).
func dnsRROwner(owner []byte, qtype uint16, rd []byte) []byte {
	rr := []byte{0xc0, 12}
	if owner != nil {
		rr = append([]byte(nil), owner...)
	}
	rr = binary.BigEndian.AppendUint16(rr, qtype)
	rr = binary.BigEndian.AppendUint16(rr, 1)
	rr = binary.BigEndian.AppendUint32(rr, 300)
	rr = binary.BigEndian.AppendUint16(rr, uint16(len(rd)))
	return append(rr, rd...)
}

func addrBytes(list []string) []byte {
	var v []byte
	for _, s := range list {
		a := netip.MustParseAddr(s)
		v = append(v, a.AsSlice()...)
	}
	return v
}

func dnsReply(q []byte, qend int, qtype uint16, a stubAnswer) []byte {
	out := append([]byte(nil), q[:qend]...)
	out[2], out[3] = 0x81, 0x80 // QR RD, RA NOERROR
	binary.BigEndian.PutUint16(out[4:], 1)
	var rrs [][]byte
	var owner []byte
	if a.CNAME != "" && (qtype == qA || qtype == qAAAA || qtype == qHTTPS) {
		owner = encodeName(a.CNAME)
		rrs = append(rrs, dnsRR(5, owner))
	}
	switch qtype {
	case qA:
		for _, s := range a.A {
			rrs = append(rrs, dnsRROwner(owner, qA, addrBytes([]string{s})))
		}
	case qAAAA:
		for _, s := range a.AAAA {
			rrs = append(rrs, dnsRROwner(owner, qAAAA, addrBytes([]string{s})))
		}
	case qHTTPS:
		if len(a.A)+len(a.AAAA) > 0 {
			rd := []byte{0, 1, 0} // priority 1, target "."
			if len(a.A) > 0 {
				v := addrBytes(a.A)
				rd = binary.BigEndian.AppendUint16(rd, 4)
				rd = binary.BigEndian.AppendUint16(rd, uint16(len(v)))
				rd = append(rd, v...)
			}
			v6 := a.AAAA
			if len(v6) == 0 {
				v6 = []string{"2001:db8:e::ff"}
			}
			v := addrBytes(v6)
			rd = binary.BigEndian.AppendUint16(rd, 6)
			rd = binary.BigEndian.AppendUint16(rd, uint16(len(v)))
			rd = append(rd, v...)
			rrs = append(rrs, dnsRROwner(owner, qHTTPS, rd))
		}
	}
	binary.BigEndian.PutUint16(out[6:], uint16(len(rrs)))
	binary.BigEndian.PutUint16(out[8:], 0)
	binary.BigEndian.PutUint16(out[10:], 0)
	for _, rr := range rrs {
		out = append(out, rr...)
	}
	if len(rrs) == 0 {
		binary.BigEndian.PutUint16(out[8:], 1)
		rd := []byte{2, 'n', 's', 0, 2, 'h', 'm', 0}
		for i := 0; i < 5; i++ {
			rd = binary.BigEndian.AppendUint32(rd, 60)
		}
		out = append(out, dnsRR(6, rd)...)
	}
	return out
}

type dnsResult struct {
	// cname: the answer section held a CNAME.
	cname   bool
	rcode   int
	addrs   []string
	elapsed time.Duration
}

// dnsQuery sends one query; addrs are the A/AAAA answers, or for HTTPS the
// addresses of its ipv4hint/ipv6hint parameters.
func dnsQuery(addr, name string, qtype uint16, timeout time.Duration) (dnsResult, error) {
	var r dnsResult
	c, err := net.Dial("udp", addr)
	if err != nil {
		return r, err
	}
	defer c.Close()
	q := []byte{0x4d, 0x52, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0}
	for _, l := range strings.Split(name, ".") {
		q = append(q, byte(len(l)))
		q = append(q, l...)
	}
	q = append(q, 0)
	q = binary.BigEndian.AppendUint16(q, qtype)
	q = binary.BigEndian.AppendUint16(q, 1)
	t0 := time.Now()
	if _, err := c.Write(q); err != nil {
		return r, err
	}
	_ = c.SetReadDeadline(time.Now().Add(timeout))
	buf := make([]byte, 4096)
	n, err := c.Read(buf)
	r.elapsed = time.Since(t0)
	r.rcode = -1
	if err != nil {
		return r, err
	}
	b := buf[:n]
	r.rcode = int(b[3] & 0x0f)
	an := int(binary.BigEndian.Uint16(b[6:]))
	_, _, i, ok := dnsQuestion(b)
	if !ok {
		return r, fmt.Errorf("bad reply")
	}
	for k := 0; k < an && i < len(b); k++ {
		for i < len(b) {
			if b[i]&0xc0 == 0xc0 {
				i += 2
				break
			}
			if b[i] == 0 {
				i++
				break
			}
			i += int(b[i]) + 1
		}
		if i+10 > len(b) {
			return r, fmt.Errorf("short reply")
		}
		typ := binary.BigEndian.Uint16(b[i:])
		rdl := int(binary.BigEndian.Uint16(b[i+8:]))
		if i+10+rdl > len(b) {
			return r, fmt.Errorf("short reply")
		}
		rd := b[i+10 : i+10+rdl]
		i += 10 + rdl
		switch {
		case typ == 5:
			r.cname = true
		case typ == qA && rdl == 4:
			r.addrs = append(r.addrs, netip.AddrFrom4([4]byte(rd)).String())
		case typ == qAAAA && rdl == 16:
			r.addrs = append(r.addrs, netip.AddrFrom16([16]byte(rd)).String())
		case typ == qHTTPS && qtype == qHTTPS:
			r.addrs = append(r.addrs, httpsHints(rd)...)
		}
	}
	return r, nil
}

// httpsHints: the addresses in an HTTPS record's ipv4hint and ipv6hint.
func httpsHints(rd []byte) []string {
	if len(rd) < 3 {
		return nil
	}
	i := 2
	for i < len(rd) && rd[i] != 0 { // target name
		i += int(rd[i]) + 1
	}
	i++
	var out []string
	for i+4 <= len(rd) {
		key := binary.BigEndian.Uint16(rd[i:])
		l := int(binary.BigEndian.Uint16(rd[i+2:]))
		i += 4
		if i+l > len(rd) {
			break
		}
		v := rd[i : i+l]
		i += l
		switch key {
		case 4:
			for j := 0; j+4 <= len(v); j += 4 {
				out = append(out, netip.AddrFrom4([4]byte(v[j:j+4])).String())
			}
		case 6:
			for j := 0; j+16 <= len(v); j += 16 {
				out = append(out, netip.AddrFrom16([16]byte(v[j:j+16])).String())
			}
		}
	}
	return out
}
