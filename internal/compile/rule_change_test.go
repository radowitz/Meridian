package compile

import (
	"strings"
	"testing"

	"github.com/radowitz/meridian/internal/model"
)

// ruleEdits are rule-list changes the automatic rule install must accept:
// they reuse targets the topology already routes to.
var ruleEdits = map[string]func(tp *model.Topology){
	"add suffix rule": func(tp *model.Topology) {
		r := tp.Rules[0]
		r.ID, r.MatchType, r.MatchValue, r.Manual = "zz-suffix", model.MatchSuffix, "synth.example.org", true
		tp.Rules = append(tp.Rules, r)
	},
	"add cidr rule": func(tp *model.Topology) {
		r := tp.Rules[0]
		r.ID, r.MatchType, r.MatchValue, r.Manual = "zz-cidr", model.MatchCIDR, "198.51.100.0/24", true
		tp.Rules = append(tp.Rules, r)
	},
	"change a value": func(tp *model.Topology) {
		tp.Rules = append([]model.Rule(nil), tp.Rules...)
		for i := range tp.Rules {
			if tp.Rules[i].MatchType == model.MatchSuffix {
				tp.Rules[i].MatchValue = "changed.example.org"
				return
			}
		}
	},
	"disable a suffix rule": func(tp *model.Topology) {
		// (Disabling a geosite or keyword rule also changes the list
		// download scripts: refused, a full install.)
		tp.Rules = append([]model.Rule(nil), tp.Rules...)
		for i := len(tp.Rules) - 1; i >= 0; i-- {
			if tp.Rules[i].MatchType == model.MatchSuffix {
				tp.Rules[i].Enabled = false
				return
			}
		}
	},
	"retarget a rule to another rule's target": func(tp *model.Topology) {
		tp.Rules = append([]model.Rule(nil), tp.Rules...)
		a, b := &tp.Rules[0], tp.Rules[len(tp.Rules)-1]
		a.TargetGroup, a.TargetExit, a.TargetAction = b.TargetGroup, b.TargetExit, b.TargetAction
		a.RequireResidential, a.RequireV6 = b.RequireResidential, b.RequireV6
	},
}

// TestRuleChangeAllowlist: across the example topologies (sniffing on and
// off), rule edits change only allowlisted files and sections.
func TestRuleChangeAllowlist(t *testing.T) {
	seen := 0
	for name, topo := range sniffTopologies(t) {
		for _, sniffed := range []bool{false, true} {
			tp := topo
			if sniffed {
				tp = sniffOn(tp)
			}
			base := compileDec(t, tp, nil)
			for en, edit := range ruleEdits {
				nt := tp
				edit(&nt)
				next, err := CompileWithDecisions(nt, nil)
				if err != nil {
					continue // an edit the topology's validation refuses
				}
				changed, refused := RuleChange(base, next, "gw")
				if len(refused) > 0 {
					t.Errorf("%s (sniff %v) %s: refused %v", name, sniffed, en, refused)
				}
				if len(changed) > 0 {
					seen++
				}
				for _, p := range changed {
					if !strings.HasPrefix(p, "nodes/gw/") {
						t.Errorf("%s %s: non-gateway file accepted: %s", name, en, p)
					}
				}
			}
		}
	}
	if seen == 0 {
		t.Fatal("no edit changed anything")
	}
}

// Outside the allowlist: every kind of difference is refused.
func TestRuleChangeRefusesOutside(t *testing.T) {
	topo := sniffTopologies(t)["example"]
	base := compileDec(t, topo, nil)
	nt := topo
	ruleEdits["add suffix rule"](&nt)
	good := compileDec(t, nt, nil)
	if c, r := RuleChange(base, good, "gw"); len(r) > 0 || len(c) == 0 {
		t.Fatalf("baseline edit: changed %v refused %v", c, r)
	}
	dns, nft := "nodes/gw/"+RuleDNSFile, "nodes/gw/"+RuleNFTFile
	mut := func(f func(files map[string]string)) *Bundle {
		b := &Bundle{Files: map[string]string{}}
		for k, v := range good.Files {
			b.Files[k] = v
		}
		f(b.Files)
		return b
	}
	cases := map[string]*Bundle{
		"resolver server line": mut(func(m map[string]string) {
			m[dns] = strings.Replace(m[dns], "cache-size 65536", "cache-size 1024", 1)
		}),
		"unknown line in the rule section": mut(func(m map[string]string) { m[dns] += "server 192.0.2.1 -group rogue\n" }),
		"rule with an unknown nameserver": mut(func(m map[string]string) {
			m[dns] += "domain-rules /domain-set:r99/ -nameserver rogue -nftset #4:inet#meridian#r99\n"
		}),
		"ruleset non-rule line": mut(func(m map[string]string) {
			m[nft] = strings.Replace(m[nft], "chain prerouting {", "chain prerouting {\n    meta mark set 0x1", 1)
		}),
		"rule line with a new mark": mut(func(m map[string]string) {
			i := strings.Index(m[nft], "    ip daddr @r0 meta mark set ")
			j := i + strings.Index(m[nft][i:], "\n")
			m[nft] = m[nft][:i] + "    ip daddr @r0 meta mark set 0xdead return" + m[nft][j:]
		}),
		"rule set with a foreign line": mut(func(m map[string]string) {
			m[nft] = strings.Replace(m[nft], "  set r0 {\n", "  set r0 {\n    policy memory\n", 1)
		}),
		"comment right before the rule block": mut(func(m map[string]string) {
			m[dns] = strings.Replace(m[dns], "# Rules in list order,", "# rogue\n# Rules in list order,", 1)
		}),
		"ruleset comment before the classify rules": mut(func(m map[string]string) {
			i := strings.Index(m[nft], "    ip daddr @r0 meta mark set ")
			m[nft] = m[nft][:i] + "    # rogue\n" + m[nft][i:]
		}),
		"another gateway file": mut(func(m map[string]string) { m["nodes/gw/etc/sysctl.d/99-meridian.conf"] += "# x\n" }),
		"a file added":         mut(func(m map[string]string) { m["nodes/gw/etc/meridian/rules/extra.conf"] = "x" }),
		"a file removed":       mut(func(m map[string]string) { delete(m, "nodes/gw/"+RuleWholeFiles[0]) }),
	}
	// Another node's file.
	for k := range good.Files {
		if !strings.HasPrefix(k, "nodes/gw/") {
			kk := k
			cases["another node's file"] = mut(func(m map[string]string) { m[kk] += "\n" })
			break
		}
	}
	for name, b := range cases {
		if _, r := RuleChange(base, b, "gw"); len(r) == 0 {
			t.Errorf("%s: accepted", name)
		}
	}
}

// QA regression: from zero rules to the first one, and from one back to
// zero, the rule sections mask the same way, so the change stays a pure
// rule change (accepted), in both directions.
func TestRuleChangeZeroToOneRule(t *testing.T) {
	for name, topo := range sniffTopologies(t) {
		var tmpl *model.Rule
		for i := range topo.Rules {
			if topo.Rules[i].MatchType == model.MatchSuffix && topo.Rules[i].Enabled {
				r := topo.Rules[i]
				tmpl = &r
				break
			}
		}
		if tmpl == nil {
			continue
		}
		zero := topo
		zero.Rules = nil
		one := topo
		r := *tmpl
		r.ID, r.MatchValue, r.Manual = "zz-first", "first.example.org", true
		one.Rules = []model.Rule{r}
		a, err := CompileWithDecisions(zero, nil)
		if err != nil {
			continue
		}
		b, err := CompileWithDecisions(one, nil)
		if err != nil {
			continue
		}
		if _, refused := RuleChange(a, b, "gw"); len(refused) > 0 {
			t.Errorf("%s 0→1: refused %v", name, refused)
		}
		if _, refused := RuleChange(b, a, "gw"); len(refused) > 0 {
			t.Errorf("%s 1→0: refused %v", name, refused)
		}
		// Negative: the 0↔1 normalisation must not hide a non-rule
		// difference in either mixed file.
		dns, nft := "nodes/gw/"+RuleDNSFile, "nodes/gw/"+RuleNFTFile
		for _, f := range []string{dns, nft} {
			bad := &Bundle{Files: map[string]string{}}
			for k, v := range a.Files {
				bad.Files[k] = v
			}
			if f == dns {
				bad.Files[f] = strings.Replace(bad.Files[f], "\n\n", "\n# rogue\n\n", 1) + "# trailing rogue\n"
			} else {
				bad.Files[f] += "# rogue\n"
			}
			if _, refused := RuleChange(bad, b, "gw"); len(refused) == 0 {
				t.Errorf("%s 0→1 with a non-rule change in %s: accepted", name, f)
			}
			if _, refused := RuleChange(b, bad, "gw"); len(refused) == 0 {
				t.Errorf("%s 1→0 with a non-rule change in %s: accepted", name, f)
			}
		}
	}
}

// With remote access the QUIC exemption lines name a set of interfaces
// (iifname { "lan", "mra" }); renumbered rules must still mask alike.
func TestMaskNFTQUICInterfaceSet(t *testing.T) {
	head := "table inet meridian {\n  chain forward {\n"
	tail := "    iifname { \"ens192\", \"mra\" } meta mark 0x101-0x140 udp dport 443 reject with icmpx port-unreachable comment \"QUIC switch: tunnelled UDP 443 refused\"\n  }\n}\n"
	a := head + "    iifname { \"ens192\", \"mra\" } udp dport 443 ip daddr @r16c return comment \"above the QUIC switch: exempt\"\n" + tail
	b := head + "    iifname { \"ens192\", \"mra\" } udp dport 443 ip daddr @r17c return comment \"above the QUIC switch: exempt\"\n" +
		"    iifname { \"ens192\", \"mra\" } udp dport 443 ip6 daddr @r1_6 return comment \"above the QUIC switch: exempt\"\n" + tail
	ma, okA := maskNFT(a, nil)
	mb, okB := maskNFT(b, nil)
	if !okA || !okB || ma != mb {
		t.Fatalf("masked differ (ok %v %v):\n%s\n---\n%s", okA, okB, ma, mb)
	}
	c := strings.ReplaceAll(b, `"mra" } meta`, `"wg9" } meta`)
	if mc, _ := maskNFT(c, nil); mc == ma {
		t.Fatal("a change of the QUIC switch interfaces was masked")
	}
}
