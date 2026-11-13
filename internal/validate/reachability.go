package validate

import (
	"fmt"
	"net/netip"
	"strings"

	"github.com/radowitz/meridian/internal/model"
)

// checkLANIPv4 refuses a gateway LAN IPv4 network that overlaps the tunnel
// and transit space. The gateway's classify chain drops
// `ip daddr 10.66.0.0/16` before the private-range rule that marks the LAN
// domestic, so LAN hosts inside it would be unreachable from the LAN side of
// the gateway (and the transit SNAT addresses would collide with real
// hosts).
func checkLANIPv4(t model.Topology) []Issue {
	type named struct {
		p    netip.Prefix
		what string
	}
	space := []named{{remoteTunnelV4, "隧道和中转地址段 10.66.0.0/16"}}
	if tp, err := netip.ParsePrefix(strings.TrimSpace(t.Settings.TransitV4Prefix)); err == nil && tp.Addr().Is4() {
		space = append(space, named{tp.Masked(), "中转前缀 " + tp.Masked().String()})
	}
	var out []Issue
	check := func(raw, field, nodeID, label string) {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			return
		}
		var lan netip.Prefix
		if p, err := netip.ParsePrefix(raw); err == nil {
			lan = p.Masked()
		} else if a, err := netip.ParseAddr(raw); err == nil {
			lan = netip.PrefixFrom(a, a.BitLen())
		} else {
			return
		}
		if !lan.Addr().Is4() {
			return
		}
		for _, s := range space {
			if lan.Overlaps(s.p) {
				out = append(out, Issue{
					Code: "prefix_conflict", Severity: SeverityError, Field: field, NodeID: nodeID,
					Message: fmt.Sprintf("%s %s 与%s重叠。网关的分类链在把局域网判为国内之前就丢弃发往 10.66.0.0/16 的流量，局域网主机会不可达；换一个不在 10.66.0.0/16 里的局域网网段。", label, lan, s.what),
				})
				return
			}
		}
	}
	check(t.Settings.GatewayLANIP, "gateway_lan_ipv4", "", "网关局域网地址")
	for _, n := range t.Nodes {
		if n.Role == model.RoleGateway {
			check(n.LANIPv4, "lan_ipv4", n.ID, "网关节点 "+n.Name+" 的局域网地址")
		}
	}
	return out
}

// classifyShadow is one destination range the gateway's classify chain
// settles (drops or returns) before it reaches the rule sets.
type classifyShadow struct {
	p      netip.Prefix
	reason string
}

// classifyShadows lists, in classify-chain order, what is decided ahead of
// the rules (see compile.renderNFT): remote-access device pools, tunnel
// underlay endpoints, 10.66.0.0/16, a ULA LAN prefix, fc00::/7, link-local,
// multicast and loopback.
func classifyShadows(t model.Topology) []classifyShadow {
	var out []classifyShadow
	if ra := t.RemoteAccess; ra.Active() {
		if _, p4, ok := ra.GatewayV4(); ok {
			if _, p6, ok6 := ra.GatewayV6(); ok6 {
				out = append(out,
					classifyShadow{p4.Masked(), "它在远程接入设备地址池 " + p4.Masked().String() + " 里，分类链先把它交给远程设备"},
					classifyShadow{p6.Masked(), "它在远程接入设备地址池 " + p6.Masked().String() + " 里，分类链先把它交给远程设备"})
			}
		}
	}
	for _, ep := range underlayEndpoints(t) {
		out = append(out, classifyShadow{netip.PrefixFrom(ep, 32), "它是隧道端点 " + ep.String() + "，分类链丢弃发往隧道端点的局域网流量（防止绕过隧道）"})
	}
	out = append(out, classifyShadow{remoteTunnelV4, "它在隧道地址段 10.66.0.0/16 里，分类链丢弃这段目的地址"})
	if lan, err := netip.ParsePrefix(strings.TrimSpace(t.Settings.LANIPv6Prefix)); err == nil && lan.Addr().Is6() && lan.Bits() >= 48 && ulaRange.Contains(lan.Addr()) {
		out = append(out, classifyShadow{lan.Masked(), "它在局域网 ULA 前缀 " + lan.Masked().String() + " 里，分类链先把它判为局域网（国内）"})
	}
	out = append(out,
		classifyShadow{ulaRange, "它在 ULA 段 fc00::/7 里（不在局域网前缀内），分类链丢弃这段目的地址"},
		classifyShadow{netip.MustParsePrefix("fe80::/10"), "它是 IPv6 链路本地地址，分类链不给它打出口标记"},
		classifyShadow{netip.MustParsePrefix("ff00::/8"), "它是 IPv6 组播地址，分类链不给它打出口标记"},
		classifyShadow{netip.MustParsePrefix("::1/128"), "它是 IPv6 环回地址，分类链不给它打出口标记"},
		classifyShadow{netip.MustParsePrefix("224.0.0.0/4"), "它是 IPv4 组播地址，分类链不给它打出口标记"},
		classifyShadow{netip.MustParsePrefix("255.255.255.255/32"), "它是 IPv4 广播地址，分类链不给它打出口标记"},
	)
	return out
}

// underlayEndpoints approximates the compiler's underlay4 set: the IPv4
// endpoints of the nodes at both ends of every enabled WireGuard link. An
// IX end is replaced by its dedicated-line neighbours, as the compiler does.
func underlayEndpoints(t model.Topology) []netip.Addr {
	seen := map[netip.Addr]bool{}
	var out []netip.Addr
	add := func(n model.Node) {
		if a, err := netip.ParseAddr(strings.TrimSpace(n.EndpointV4)); err == nil && a.Is4() && !seen[a] {
			seen[a] = true
			out = append(out, a)
		}
	}
	end := func(id string) {
		n, ok := t.NodeByID(id)
		if !ok {
			return
		}
		if n.Role != model.RoleIX {
			add(n)
			if model.IsIXHub(n) {
				// Relays dial the IX hub's domestic ingress address.
				if a, err := netip.ParseAddr(strings.TrimSpace(n.IngressV4)); err == nil && a.Is4() && !seen[a] {
					seen[a] = true
					out = append(out, a)
				}
			}
			return
		}
		for _, l := range t.Links {
			if !l.Enabled || l.Transport != model.TransportDedicatedLine {
				continue
			}
			other := ""
			switch id {
			case l.From:
				other = l.To
			case l.To:
				other = l.From
			}
			if p, ok := t.NodeByID(other); ok && other != "" {
				add(p)
			}
		}
	}
	for _, l := range t.Links {
		if !l.Enabled {
			continue
		}
		switch l.Transport {
		case model.TransportDirectWG, model.TransportWGOverWSS, model.TransportUDPWSSFailover, model.TransportIXReplacementWSS:
			end(l.From)
			end(l.To)
		}
	}
	return out
}

// checkRuleReachable reports enabled CIDR rules whose whole destination is
// settled by the classify chain before the rule sets are consulted: such a
// rule can never apply.
func checkRuleReachable(t model.Topology) []Issue {
	var shadows []classifyShadow
	var out []Issue
	for _, r := range t.Rules {
		if !r.Enabled || r.MatchType != model.MatchCIDR {
			continue
		}
		var dst netip.Prefix
		raw := strings.TrimSpace(r.MatchValue)
		if p, err := netip.ParsePrefix(raw); err == nil {
			dst = p.Masked()
		} else if a, err := netip.ParseAddr(raw); err == nil {
			dst = netip.PrefixFrom(a, a.BitLen())
		} else {
			continue
		}
		if dst.Addr().Is4In6() {
			continue
		}
		if shadows == nil {
			shadows = classifyShadows(t)
		}
		for _, s := range shadows {
			if s.p.Addr().Is4() != dst.Addr().Is4() {
				continue
			}
			if s.p.Bits() <= dst.Bits() && s.p.Contains(dst.Addr()) {
				out = append(out, Issue{
					Code: "rule_unreachable", Severity: SeverityError, RuleID: r.ID, Field: "match_value",
					Message: fmt.Sprintf("规则「%s」的目的地址 %s 永远不会命中：%s，轮不到这条规则。删除或改成别的目的地址。", r.Name, dst, s.reason),
				})
				break
			}
		}
	}
	return out
}
