package compile

import (
	"fmt"
	"sort"
	"strings"

	"github.com/radowitz/meridian/internal/model"
	"github.com/radowitz/meridian/internal/validate"
)

// ExitPlan is one foreign next hop. Mark and transit address are how the
// gateway's choice survives encapsulation.
type ExitPlan struct {
	Node      model.Node
	Index     int
	Mark      uint32
	Table     int
	TransitV4 string
	TransitV6 string
	DNSV4     string
	DNSULA    string
	HubIface  string // iface name on the hub toward this exit
	Group     string // smartdns group
}

func planExits(t model.Topology, tunnels []Tunnel) []ExitPlan {
	var exits []model.Node
	for _, n := range t.Nodes {
		if n.Role == model.RoleExit {
			exits = append(exits, n)
		}
	}
	sort.Slice(exits, func(i, j int) bool { return exits[i].ID < exits[j].ID })
	out := make([]ExitPlan, 0, len(exits))
	for i, n := range exits {
		p := ExitPlan{
			Node:      n,
			Index:     i,
			Mark:      exitMark(i),
			Table:     201 + i,
			TransitV4: fmt.Sprintf("10.66.200.%d", 10+i),
			TransitV6: fmt.Sprintf("fd66:0:0:ff::%x", 10+i),
			Group:     "g_" + strings.ReplaceAll(n.ID, "-", "_"),
		}
		for _, tun := range tunnels {
			if tun.Standby || tun.East.ID != n.ID || tun.West.Role != model.RoleHub {
				continue
			}
			if tun.Mode == "wss" && p.HubIface != "" {
				continue
			}
			p.DNSV4 = tun.EastV4
			p.DNSULA = tun.EastULA
			p.HubIface = tun.Iface()
			if tun.Mode != "wss" {
				break
			}
		}
		out = append(out, p)
	}
	return out
}

func exitByID(exits []ExitPlan, id string) (ExitPlan, bool) {
	for _, e := range exits {
		if e.Node.ID == id {
			return e, true
		}
	}
	return ExitPlan{}, false
}

func defaultExit(t model.Topology, exits []ExitPlan) (ExitPlan, bool) {
	n, ok := validate.SelectExit(t, "hk")
	if !ok {
		return ExitPlan{}, false
	}
	return exitByID(exits, n.ID)
}

type rulePlan struct {
	Rule       model.Rule
	Exit       ExitPlan
	Set4       string
	Set6       string
	FilterAAAA bool
}

func planRules(t model.Topology, exits []ExitPlan) []rulePlan {
	rules := append([]model.Rule(nil), t.Rules...)
	sort.SliceStable(rules, func(i, j int) bool {
		if rules[i].Manual != rules[j].Manual {
			return rules[i].Manual
		}
		if rules[i].Priority != rules[j].Priority {
			return rules[i].Priority < rules[j].Priority
		}
		return rules[i].ID < rules[j].ID
	})
	var out []rulePlan
	n := 0
	for _, r := range rules {
		if !r.Enabled {
			continue
		}
		target, ok := ruleExit(t, r, exits)
		if !ok {
			continue
		}
		rp := rulePlan{
			Rule:       r,
			Exit:       target,
			Set4:       fmt.Sprintf("r%d", n),
			Set6:       fmt.Sprintf("r%d6", n),
			FilterAAAA: !target.Node.EgressV6,
		}
		n++
		out = append(out, rp)
	}
	return out
}

func ruleExit(t model.Topology, r model.Rule, exits []ExitPlan) (ExitPlan, bool) {
	if r.TargetExit != "" {
		return exitByID(exits, r.TargetExit)
	}
	n, ok := validate.SelectExit(t, r.TargetPool)
	if !ok {
		return ExitPlan{}, false
	}
	return exitByID(exits, n.ID)
}

func transitV4Net() string { return "10.66.200.0/24" }
func transitV6Net() string { return "fd66:0:0:ff::/64" }
