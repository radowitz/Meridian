package compile

import (
	"encoding/json"
	"regexp"
	"strings"
	"testing"

	"github.com/radowitz/meridian/internal/defaults"
	"github.com/radowitz/meridian/internal/model"
	"github.com/radowitz/meridian/internal/ordered"
	"github.com/radowitz/meridian/internal/sniff"
	"github.com/radowitz/meridian/internal/unlock"
)

// A service group in automatic selection is switched by one decision key
// (unlock.ServiceKey): every rule through it moves to the decided member
// on that member's own mark and resolver, in the address path (nft sets
// and marks), the gateway resolver and the sniffing forwarder's pair,
// with every set name still derived in planRules alone.

var (
	nftSetRef  = regexp.MustCompile(`@([A-Za-z0-9_]+)`)
	nftSetDecl = regexp.MustCompile(`(?m)^\s*set ([A-Za-z0-9_]+) \{`)
)

// checkSetsDeclared: every set the gateway ruleset references is declared
// exactly once, and every address set the manifest names is declared.
func checkSetsDeclared(t *testing.T, b *Bundle) {
	t.Helper()
	nft := b.File("nodes/gw/etc/nftables.d/meridian.nft")
	declared := map[string]int{}
	for _, m := range nftSetDecl.FindAllStringSubmatch(nft, -1) {
		declared[m[1]]++
	}
	for name, n := range declared {
		if n > 1 {
			t.Errorf("set %s declared %d times", name, n)
		}
	}
	for _, m := range nftSetRef.FindAllStringSubmatch(nft, -1) {
		if declared[m[1]] == 0 {
			t.Errorf("set @%s is referenced but not declared", m[1])
		}
	}
	man, err := ordered.ParseManifest([]byte(b.File("nodes/gw/etc/meridian/rules/order.conf")))
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range man.Sets {
		for _, name := range []string{s.CIDR4, s.CIDR6} {
			if name != "" && declared[name] == 0 {
				t.Errorf("the manifest names set %s, which the ruleset does not declare", name)
			}
		}
	}
}

func selectTopo(base model.Topology, group string, members []string) model.Topology {
	topo := base
	topo.Settings.ClientsIPv6ViaGateway = true
	if group != "" {
		topo.Groups = append(append([]model.RegionGroup(nil), topo.Groups...), model.RegionGroup{ID: group, Name: group, Region: "us", Mode: model.GroupAuto, Members: members})
	}
	return topo
}

func addAutoService(topo *model.Topology, id, group, suffix string, probes ...string) {
	topo.ServiceGroups = append(topo.ServiceGroups, model.ServiceGroup{ID: id, Name: id, TargetGroup: group, Select: model.SelectAuto, Probes: probes})
	rs := "rs-" + id
	topo.RuleSets = append(topo.RuleSets, model.RuleSet{ID: rs, Name: rs, URL: "https://example.org/" + rs + ".list"})
	topo.Rules = append([]model.Rule{
		{ID: "r-" + id, Name: id, Enabled: true, MatchType: model.MatchSuffix, MatchValue: suffix, TargetService: id},
		{ID: "rs-" + id, Name: rs, Enabled: true, MatchType: model.MatchRuleSet, RuleSet: rs, TargetService: id},
	}, topo.Rules...)
	topo.RulesOrdered = true
}

func compileDec(t *testing.T, topo model.Topology, dec map[string]string) *Bundle {
	t.Helper()
	b, err := CompileWithDecisions(topo, dec)
	if err != nil {
		t.Fatalf("compile: %v %+v", err, b.Issues)
	}
	return b
}

func ruleMark(t *testing.T, b *Bundle, ruleID string) uint32 {
	t.Helper()
	var s ordered.Snapshot
	if err := json.Unmarshal([]byte(b.File("nodes/gw/"+strings.TrimPrefix(DecidePath, "/"))), &s); err != nil {
		t.Fatal(err)
	}
	for _, r := range s.Rules {
		if r.ID == ruleID {
			return r.Mark
		}
	}
	t.Fatalf("rule %s not in the snapshot", ruleID)
	return 0
}

func checkSniffPair(t *testing.T, b *Bundle) {
	t.Helper()
	decide := b.File("nodes/gw/" + strings.TrimPrefix(DecidePath, "/"))
	var tf sniff.TargetsFile
	if err := json.Unmarshal([]byte(b.File("nodes/gw/"+strings.TrimPrefix(SniffTargetsPath, "/"))), &tf); err != nil {
		t.Fatal(err)
	}
	c, err := ordered.LoadSnapshot([]byte(decide), ordered.MemReader{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := sniff.New(sniff.Config{}).Install(c, tf.Targets); err != nil {
		t.Fatalf("the forwarder refuses the compiled pair after a switch: %v", err)
	}
}

func TestServiceGroupDecisionSwitchesAllPaths(t *testing.T) {
	// "mix": dual-stack us first, IPv4-only sg second.
	topo := selectTopo(defaults.Example(), "mix", []string{"us", "sg"})
	addAutoService(&topo, "svc-mix", "mix", "mix.example.net", "youtube-premium")
	addAutoService(&topo, "svc-us", "us", "us-svc.example.net", "peacock")
	// A single-exit service group (fixed) and a pinned rule on sg to
	// compare resolver lines with.
	topo.ServiceGroups = append(topo.ServiceGroups, model.ServiceGroup{ID: "svc-sg", Name: "sg", TargetExit: "sg"})
	topo.Rules = append([]model.Rule{
		{ID: "r-svc-sg", Name: "sg fixed", Enabled: true, MatchType: model.MatchSuffix, MatchValue: "fixed-sg.example.net", TargetService: "svc-sg"},
		{ID: "r-pin-sg", Name: "pin", Enabled: true, MatchType: model.MatchSuffix, MatchValue: "pin-sg.example.net", TargetExit: "sg"},
	}, topo.Rules...)
	topo = sniffOn(topo)

	exits := planExits(topo, mustTunnels(t, topo))
	sgExit, _ := exitByID(exits, "sg")

	base := compileDec(t, topo, nil)
	checkSetsDeclared(t, base)
	checkSniffPair(t, base)
	if ruleMark(t, base, "r-svc-mix") == sgExit.Mark {
		t.Fatal("without a decision the service group is already on sg")
	}

	// A decision keyed by the rule's own ID moves nothing: the service
	// group is the one place the decision lives.
	byRule := compileDec(t, topo, map[string]string{"r-svc-mix": "sg", "rs-svc-mix": "sg"})
	if ruleMark(t, byRule, "r-svc-mix") == sgExit.Mark || byRule.File("nodes/gw/etc/nftables.d/meridian.nft") != base.File("nodes/gw/etc/nftables.d/meridian.nft") {
		t.Fatal("a rule-keyed decision moved a rule that goes through a service group")
	}

	moved := compileDec(t, topo, map[string]string{unlock.ServiceKey("svc-mix"): "sg"})
	checkSetsDeclared(t, moved)
	checkSniffPair(t, moved)
	for _, id := range []string{"r-svc-mix", "rs-svc-mix"} {
		if got := ruleMark(t, moved, id); got != sgExit.Mark {
			t.Fatalf("%s: mark %#x after the switch, want sg's %#x", id, got, sgExit.Mark)
		}
	}
	// The resolver follows the member: the switched name is asked of sg's
	// resolver exactly like a name pinned to sg (never the domestic one).
	pin := resolverLine(t, moved, "pin-sg.example.net")
	sw := resolverLine(t, moved, "mix.example.net")
	before := resolverLine(t, base, "mix.example.net")
	server := regexp.MustCompile(`-nameserver ([^ ]+)`)
	ns := func(line string) string {
		if m := server.FindStringSubmatch(line); m != nil {
			return m[1]
		}
		return ""
	}
	if ns(sw) == "" || ns(sw) != ns(pin) || ns(sw) == ns(before) {
		t.Fatalf("switched name resolves through %q (before %q), a name pinned to sg through %q", ns(sw), ns(before), ns(pin))
	}
	// sg carries no IPv6: AAAA stays filtered on it.
	if !strings.Contains(sw, "-address #6") {
		t.Fatalf("AAAA not filtered on the IPv4-only member: %q", sw)
	}
	// A dual-stack group switched to its dual-stack second member keeps
	// AAAA and its IPv6 sets.
	us2 := compileDec(t, topo, map[string]string{unlock.ServiceKey("svc-mix"): "sg", unlock.ServiceKey("svc-us"): "us-2"})
	checkSetsDeclared(t, us2)
	checkSniffPair(t, us2)
	line := resolverLine(t, us2, "us-svc.example.net")
	if strings.Contains(line, "-address #6") || !strings.Contains(line, "#6:inet") {
		t.Fatalf("dual-stack member lost IPv6: %q", line)
	}
	u2, _ := exitByID(exits, "us-2")
	if ruleMark(t, us2, "r-svc-us") != u2.Mark {
		t.Fatal("svc-us did not move to us-2")
	}
	// A decision for an exit outside the group is ignored.
	outside := compileDec(t, topo, map[string]string{unlock.ServiceKey("svc-mix"): "jp"})
	if outside.File("nodes/gw/etc/nftables.d/meridian.nft") != base.File("nodes/gw/etc/nftables.d/meridian.nft") {
		t.Fatal("a decision outside the candidates changed the ruleset")
	}
	// A fixed service group (exit target) ignores a decision.
	fixed := compileDec(t, topo, map[string]string{unlock.ServiceKey("svc-sg"): "us"})
	if ruleMark(t, fixed, "r-svc-sg") != sgExit.Mark {
		t.Fatal("a fixed service group moved")
	}
}

// Nested exit, TCP-only external exit, dual hub: a switch between a nested
// member and a plain one keeps every set declared and the forwarder pair
// consistent; a group whose only member is the external exit stays put.
func TestServiceGroupDecisionNestedAndExternal(t *testing.T) {
	topo := defaults.NestedExample()
	ext := defaults.ExternalExample()
	for _, n := range ext.Nodes {
		if n.ID == "my1" {
			topo.Nodes = append(topo.Nodes, n)
		}
	}
	for _, g := range ext.Groups {
		if g.ID == "my" {
			topo.Groups = append(topo.Groups, g)
		}
	}
	addAutoService(&topo, "svc-tw", "tw", "tw-svc.example.net", "auto-kktv")
	addAutoService(&topo, "svc-my", "my", "my-svc.example.net", "auto-netflix")
	topo = sniffOn(topo)
	exits := planExits(topo, mustTunnels(t, topo))
	for _, dec := range []map[string]string{
		nil,
		{unlock.ServiceKey("svc-tw"): "dc2"},
		{unlock.ServiceKey("svc-tw"): "tw2", unlock.ServiceKey("svc-my"): "dc2"},
	} {
		b := compileDec(t, topo, dec)
		checkSetsDeclared(t, b)
		checkSniffPair(t, b)
		if id := dec[unlock.ServiceKey("svc-tw")]; id != "" && id != "tw2" {
			e, _ := exitByID(exits, id)
			if got := ruleMark(t, b, "r-svc-tw"); got != e.Mark {
				t.Fatalf("svc-tw → %s: mark %#x, want %#x", id, got, e.Mark)
			}
		}
		// dc2 is not a member of "my": the external group does not move.
		if dc2, _ := exitByID(exits, "dc2"); ruleMark(t, b, "r-svc-my") == dc2.Mark {
			t.Fatal("a decision outside the external group's members moved it")
		}
	}
}

// A decision change touches only the rule-derived gateway files
// (DecisionFiles): across the sniff test topologies (IPv4-only and
// dual-stack, single and backup hub, relay sharing, remote access,
// nested and external exits), with the forwarder on and off, moving a
// built-in rule and a service group changes no other file and no other
// node. DecisionChange reports a forged change elsewhere as refused.
func TestDecisionChangeTouchesOnlyRuleFiles(t *testing.T) {
	cases := 0
	for name, topo := range sniffTopologies(t) {
		for _, sniffed := range []bool{false, true} {
			tp := topo
			if sniffed {
				tp = sniffOn(tp)
			}
			exits := planExits(tp, mustTunnels(t, tp))
			groups := planGroups(tp, exits)
			base := compileDec(t, tp, nil)
			// Every automatic group with two or more members: move each
			// rule aimed at it, and its service group, to the second member.
			for _, gp := range groups {
				if gp.Group.Mode != model.GroupAuto || len(gp.Selection.Order) < 2 {
					continue
				}
				alt := gp.Selection.Order[1]
				dec := map[string]string{}
				for _, r := range tp.Rules {
					if r.Enabled && r.TargetGroup == gp.Group.ID {
						dec[r.ID] = alt
					}
				}
				for _, sg := range tp.ServiceGroups {
					if sg.TargetGroup == gp.Group.ID {
						dec[unlock.ServiceKey(sg.ID)] = alt
					}
				}
				if len(dec) == 0 {
					continue
				}
				next := compileDec(t, tp, dec)
				changed, refused := DecisionChange(base, next, "gw")
				if len(refused) > 0 {
					t.Errorf("%s (sniff %v) group %s → %s: files outside the allow-list changed: %v", name, sniffed, gp.Group.ID, alt, refused)
				}
				if len(changed) > 0 {
					cases++
				}
			}
		}
	}
	if cases == 0 {
		t.Fatal("no decision changed any file: the test proves nothing")
	}
	a := &Bundle{Files: map[string]string{"nodes/gw/etc/nftables.d/meridian.nft": "a", "nodes/gw/etc/systemd/system/x.service": "u", "nodes/hk/etc/x": "1"}}
	b := &Bundle{Files: map[string]string{"nodes/gw/etc/nftables.d/meridian.nft": "b", "nodes/gw/etc/systemd/system/x.service": "v", "nodes/hk/etc/x": "2", "nodes/gw/etc/wireguard/m00.conf": "new"}}
	changed, refused := DecisionChange(a, b, "gw")
	if len(changed) != 1 || len(refused) != 3 {
		t.Fatalf("changed %v refused %v", changed, refused)
	}
}
