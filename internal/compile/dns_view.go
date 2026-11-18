package compile

import (
	"fmt"
	"sort"
	"strings"

	"github.com/radowitz/meridian/internal/model"
	"github.com/radowitz/meridian/internal/validate"
)

// The read-only「解析配置」view (api/dns.go, docs/architecture.md「解析配置
// 视图」): who answers which names, which upstream, which transport and from
// which line the query leaves, derived from the same plans the SmartDNS
// configs are rendered from (planExits, planGroups, planRules,
// renderGatewayDNS, renderExitDNS). It never names an account value: an
// exit upstream's account part is shown as MaskedAccount.

// DNSPlan is the compiled resolution of one topology.
type DNSPlan struct {
	Paths []DNSPathRow `json:"paths"`
	// Exits are the managed exits' resolver upstreams (the setting each one
	// uses), for the panel's upstream form and the fixed check.
	Exits []DNSExitRow `json:"exits"`
}

// DNSPathRow is one kind of name and how it is resolved.
type DNSPathRow struct {
	// Scope: clients | domestic | unlisted | group | exit | external_exit |
	// reject | doh_block | gateway.
	Scope      string           `json:"scope"`
	ID         string           `json:"id,omitempty"`
	Label      string           `json:"label"`
	AnsweredBy string           `json:"answered_by"`
	Upstreams  []DNSUpstreamRow `json:"upstreams,omitempty"`
	// Egress is the line the query to the upstream leaves by.
	Egress   string      `json:"egress"`
	Switches []DNSSwitch `json:"switches,omitempty"`
	Notes    []string    `json:"notes,omitempty"`
	// Nodes are the nodes whose SmartDNS configs hold this row's lines.
	Nodes []string `json:"nodes,omitempty"`
}

// DNSUpstreamRow is one upstream server.
type DNSUpstreamRow struct {
	Address string `json:"address"`
	// Transport: plain | dot | doh | tunnel (plain DNS inside a WireGuard
	// tunnel to an exit or group resolver).
	Transport string `json:"transport"`
	Verify    string `json:"verify,omitempty"`
}

// DNSSwitch is one setting that changes resolution, with its value.
type DNSSwitch struct {
	Name  string `json:"name"`
	Label string `json:"label"`
	Value string `json:"value"`
}

// DNSExitRow is one managed exit's resolver.
type DNSExitRow struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	// Source: global (Settings.ExitDNS), own (Node.ExitDNS), builtin (the
	// node keeps the built-in resolvers) or default (nothing configured).
	Source string `json:"source"`
	// Upstream is the effective upstream (nil: built-in), account token
	// unchanged ("{account}"; the value is never part of it).
	Upstream    *model.ExitDNSUpstream `json:"upstream,omitempty"`
	Description string                 `json:"description"`
	Transport   string                 `json:"transport"`
	// Resolver is the exit's tunnel resolver address the gateway asks.
	Resolver string `json:"resolver,omitempty"`
	// Checkable: the fixed check can ask this exit's resolver (it has a
	// tunnel resolver and an exit mark).
	Checkable bool `json:"checkable"`
}

func onOff(b bool) string {
	if b {
		return "开"
	}
	return "关"
}

// ExitUpstreamTransport is plain, dot or doh.
func ExitUpstreamTransport(u *model.ExitDNSUpstream) string {
	if u == nil {
		return "plain"
	}
	return u.Protocol
}

func exitUpstreamRows(u *model.ExitDNSUpstream) []DNSUpstreamRow {
	if u == nil {
		return []DNSUpstreamRow{{Address: BuiltinExitResolvers[0] + ":53", Transport: "plain"}, {Address: BuiltinExitResolvers[1] + ":53", Transport: "plain"}}
	}
	host := strings.Replace(u.TLSHostName, model.ExitDNSAccountToken, MaskedAccount, 1)
	var out []DNSUpstreamRow
	for _, a := range u.Addresses {
		addr := bracketHostPort(a, u.EffectivePort())
		if u.Protocol == model.ExitDNSDoH {
			addr = strings.Replace(ExitUpstreamURL(*u, a), model.SecretPlaceholder(u.AccountCredential), MaskedAccount, 1)
			if u.AccountCredential == "" {
				addr = ExitUpstreamURL(*u, a)
			}
		}
		out = append(out, DNSUpstreamRow{Address: addr, Transport: u.Protocol, Verify: "证书链按系统 CA（" + ExitDNSCAFile + "），主机名必须是 " + host})
	}
	return out
}

func exitSource(t model.Topology, n model.Node) string {
	switch {
	case n.ExitDNS != nil && n.ExitDNS.Protocol == model.ExitDNSBuiltin:
		return "builtin"
	case n.ExitDNS != nil:
		return "own"
	case t.Settings.ExitDNS != nil:
		return "global"
	}
	return "default"
}

// ResolutionPlan derives the view from t (decisions: the unlock map the
// install compiles with). It fails like Compile on an invalid topology.
func ResolutionPlan(t model.Topology, decisions map[string]string) (*DNSPlan, error) {
	res := validate.Run(t)
	if res.HasErrors() {
		return nil, &ValidationError{Result: res}
	}
	tunnels, err := buildTunnels(t)
	if err != nil {
		return nil, err
	}
	exits := planExits(t, tunnels)
	groups := planGroups(t, exits)
	rules := planRules(t, exits, groups, decisions)
	defT, hasDef := defaultExit(t, groups)
	_, split := renderDNSSplitUnit(t, exits, groups)
	gw := ""
	for _, n := range t.Nodes {
		if n.Role == model.RoleGateway {
			gw = n.ID
		}
	}
	p := &DNSPlan{Paths: []DNSPathRow{}, Exits: []DNSExitRow{}}
	add := func(r DNSPathRow) { p.Paths = append(p.Paths, r) }

	add(DNSPathRow{Scope: "clients", Label: "局域网和远程接入设备的查询", AnsweredBy: "网关上的 SmartDNS（53 明文、853 DoT；劫持的 53 也送到这里）",
		Egress: "—（按下面各类名字分别发往上游）", Nodes: []string{gw},
		Switches: []DNSSwitch{{Name: "clients_ipv6_via_gateway", Label: "客户端经网关走 IPv6（决定是否返回 AAAA）", Value: onOff(t.Settings.ClientsIPv6ViaGateway)}},
		Notes:    []string{"网关的 853 证书与客户端拨的名字不符：严格模式的客户端会回落到 53", "不做 fake-ip，不附加 ECS；缓存不跨重启保留（cache-persist no）"}})

	var dom []DNSUpstreamRow
	for _, ip := range domesticDoT(t) {
		dom = append(dom, DNSUpstreamRow{Address: ip + ":853", Transport: "dot", Verify: "SmartDNS 的 server-tls 没有设 -host-name / -tls-host-verify：不按主机名校验（与改动前相同）"})
		dom = append(dom, DNSUpstreamRow{Address: ip + ":53", Transport: "plain"})
	}
	add(DNSPathRow{Scope: "domestic", Label: "国内名字（内置 geosite cn 名单、直连规则）", AnsweredBy: "网关 SmartDNS 的 domestic 组：每个国内解析器同时用 DoT 和明文问，取最快的回答",
		Upstreams: dom, Egress: "网关自己的上联（家宽）", Nodes: []string{gw},
		Switches: []DNSSwitch{{Name: "domestic_dot", Label: "国内解析器", Value: strings.Join(domesticDoT(t), "、")}},
		Notes:    []string{"嗅探转发服务的「直连」目标用同一组国内解析器的明文 53（UDP，截断时 TCP），多个解析器并行竞速，不应答的会被降级；它没有 DoT 客户端"}})

	unl := DNSPathRow{Scope: "unlisted", Label: "没有名单、没有规则命中的名字", Egress: "经隧道到默认组的出口，再从该出口自己的上联发出", Nodes: []string{gw},
		Switches: []DNSSwitch{{Name: "unlisted_domestic_dns", Label: "未列名单的名字也问国内解析器（只在回答全是国内地址时采用）", Value: onOff(t.Settings.UnlistedDomesticDNS)},
			{Name: "default_group", Label: "默认境外组", Value: t.Settings.DefaultGroup}}}
	switch {
	case !hasDef:
		unl.AnsweredBy = "没有可用的默认组：这些名字没有上游"
	case defT.Group != nil:
		unl.AnsweredBy = fmt.Sprintf("默认组 %s 当前成员出口上的 SmartDNS（组解析地址 %s，组标记 %#x）", defT.Group.Group.ID, defT.Group.Resolver, defT.Group.Mark)
		unl.Upstreams = []DNSUpstreamRow{{Address: bracketHostPort(defT.Group.Resolver, 53), Transport: "tunnel"}}
	default:
		addr, _, _ := dnsSplitUpstream(t, exits, defT)
		unl.AnsweredBy = fmt.Sprintf("默认出口 %s 上的 SmartDNS", defT.Exit.Node.ID)
		if addr != "" {
			unl.Upstreams = []DNSUpstreamRow{{Address: bracketHostPort(addr, 53), Transport: "tunnel"}}
		}
	}
	if split {
		unl.AnsweredBy = "网关上的 meridian-dns-split（" + DNSSplitListen + "）：同时问国内解析器和" + unl.AnsweredBy + "，国内回答全是国内地址才用它"
		unl.Egress = "国内解析器：网关自己的上联；默认组：经隧道到出口，再从出口的上联发出"
	}
	add(unl)

	for _, g := range groups {
		if !g.Dynamic {
			continue
		}
		var members []string
		for _, e := range g.Try {
			members = append(members, e.Node.ID)
		}
		add(DNSPathRow{Scope: "group", ID: g.Group.ID, Label: "地区组 " + g.Group.ID + " 的规则名字",
			AnsweredBy: fmt.Sprintf("当前承载组 %s 的成员出口上的 SmartDNS（经组解析地址 %s，组标记 %#x，随中枢切换）", g.Group.ID, g.Resolver, g.Mark),
			Upstreams:  []DNSUpstreamRow{{Address: bracketHostPort(g.Resolver, 53), Transport: "tunnel"}},
			Egress:     "经隧道到当前成员出口，再从该出口自己的上联发出（上游见各出口行）",
			Notes:      []string{"成员：" + strings.Join(members, "、"), "组的解析地址不通时这些名字失败，不回落到国内解析器或其它成员"}, Nodes: []string{gw}})
	}

	// Per exit: the gateway's server line and the exit's own upstream.
	byID := map[string]ExitPlan{}
	for _, e := range exits {
		byID[e.Node.ID] = e
	}
	ids := make([]string, 0, len(byID))
	for id := range byID {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		e := byID[id]
		n := e.Node
		if e.External {
			add(DNSPathRow{Scope: "external_exit", ID: id, Label: "外部 SOCKS 出口 " + id + " 的规则名字",
				AnsweredBy: "承载出口 " + n.External.Carrier + " 上的 SmartDNS（组 ext_" + strings.ReplaceAll(id, "-", "_") + "）",
				Upstreams:  []DNSUpstreamRow{{Address: ExtUpstream1 + ":53", Transport: "plain"}, {Address: ExtUpstream2 + ":53", Transport: "plain"}},
				Egress:     "经该外部出口的 SOCKS 代理（TCP），不从承载出口自己的上联发出",
				Notes:      []string{"出口解析上游的设置不作用于外部 SOCKS 出口"}, Nodes: []string{gw, n.External.Carrier}})
			continue
		}
		u := t.ExitUpstream(n)
		resolver := e.DNSULA
		if t.DualHub() {
			resolver = e.Resolver
		}
		row := DNSPathRow{Scope: "exit", ID: id, Label: "出口 " + id + " 的规则名字（以及以它为成员的组）",
			AnsweredBy: "出口 " + id + " 上的 SmartDNS（网关经隧道问 " + resolver + "）",
			Upstreams:  exitUpstreamRows(u), Egress: "出口 " + id + " 自己的上联（主路由表，无标记）",
			Switches: []DNSSwitch{{Name: "exit_dns", Label: "出口解析上游的来源", Value: map[string]string{"global": "全局设置", "own": "本出口单独设置", "builtin": "本出口保持内置", "default": "未设置（内置）"}[exitSource(t, n)]}},
			Nodes:    []string{gw, id}}
		if u != nil {
			row.Notes = append(row.Notes, "只用配置的上游；它不应答时这个出口的名字解析失败（不回落到内置公共解析器、国内解析器或网关）")
		} else {
			row.Notes = append(row.Notes, "内置：两个公共解析器明文查询，从出口自己的上联发出")
		}
		if resolver == "" {
			row.AnsweredBy = "没有隧道解析器（出口还没有接上隧道）：规则名字直接返回空（SOA）"
		}
		add(row)
		p.Exits = append(p.Exits, DNSExitRow{ID: id, Name: n.Name, Source: exitSource(t, n), Upstream: u, Description: DescribeExitUpstream(u),
			Transport: ExitUpstreamTransport(u), Resolver: resolver, Checkable: resolver != "" && e.DNSULA != "" && e.Mark != 0})
	}

	rej := DNSPathRow{Scope: "reject", Label: "拒绝规则的名字（包括操作者自建的广告拒绝规则）", Egress: "与默认组相同",
		AnsweredBy: "默认目标的解析器照常解析（不返回 AAAA），到这些地址的连接由网关拒绝", Nodes: []string{gw},
		Notes: []string{"产品没有内置的广告名单：只有规则里动作为「拒绝」的名字"}}
	n := 0
	for _, rp := range rules {
		if rp.Action == model.ActionReject {
			n++
		}
	}
	rej.Switches = []DNSSwitch{{Name: "reject_rules", Label: "启用的拒绝规则", Value: fmt.Sprint(n)}}
	add(rej)
	add(DNSPathRow{Scope: "doh_block", Label: "已知公共 DoH 服务的名字", AnsweredBy: "网关 SmartDNS 直接返回空（address /…/#），并拒绝到已知 DoH 地址的 443",
		Egress: "不发出", Nodes: []string{gw}, Notes: []string{"dns.google、cloudflare-dns.com、dns.quad9.net 等；名单不完整"}})
	add(DNSPathRow{Scope: "gateway", Label: "网关主机自己的程序（面板、宿主代理、名单下载）", AnsweredBy: "主机系统的解析器（/etc/resolv.conf）：不由 Meridian 管理",
		Egress: "网关自己的上联", Nodes: []string{gw}, Notes: []string{"面板只能显示它不由 Meridian 管理；具体指向哪里没有读取（未验证）"}})
	return p, nil
}
