package validate

import (
	"fmt"
	"net/netip"
	"sort"
	"strings"

	"github.com/radowitz/meridian/internal/model"
)

// Allocation and address-plan checks (docs/architecture.md「接口名、端口和
// 网段的分配」). Manual link addresses and the addresses a link's slot gives
// it are checked together: two links never share a subnet, whichever of
// them was typed in, and no tunnel address sits in a range the gateway
// already uses for something else. Ports are checked by checkPorts from the
// same slots (TunnelPorts).

// Reserved interface names an operator-entered interface may not take: the
// remote-access interface and the Mesh sidecar's veth pair.
var reservedIfaces = map[string]string{
	model.RemoteAccessIface: "远程接入接口",
	"mmesh":                 "Mesh sidecar 的 veth",
	"mmesh-c":               "Mesh sidecar 的 veth（容器端）",
}

// checkAllocations: the stored table is well formed and every tunnel link,
// exit and group has a slot.
func checkAllocations(t model.Topology) []Issue {
	var out []Issue
	if a := t.Allocations; a != nil {
		ids := make([]string, 0, len(a.Links))
		for id := range a.Links {
			ids = append(ids, id)
		}
		sort.Strings(ids)
		owner := map[int]string{}
		for _, id := range ids {
			s := a.Links[id].Slot
			switch {
			case s < 0 || s >= model.MaxLinkSlots:
				out = append(out, Issue{Code: "link_alloc_invalid", Severity: SeverityError, LinkID: id, Field: "allocation",
					Message: fmt.Sprintf("链路 %s 的分配序号 %d 不在 0–%d 之间（分配表被手工改过？）。", id, s, model.MaxLinkSlots-1)})
			case owner[s] != "":
				out = append(out, Issue{Code: "link_alloc_invalid", Severity: SeverityError, LinkID: id, Field: "allocation",
					Message: fmt.Sprintf("链路 %s 和 %s 的分配序号都是 %d：两条链路会得到同一个接口名 %s、同样的默认端口和网段（分配表被手工改过？）。", owner[s], id, s, model.LinkIface(s))})
			default:
				owner[s] = id
			}
		}
		type entry struct {
			kind, id string
			slot     int
		}
		var marks []entry
		for id, s := range a.Exits {
			marks = append(marks, entry{"exit", id, s.Slot})
		}
		for id, s := range a.Groups {
			marks = append(marks, entry{"group", id, s.Slot})
		}
		sort.Slice(marks, func(i, j int) bool {
			if marks[i].kind != marks[j].kind {
				return marks[i].kind < marks[j].kind // "exit" before "group"
			}
			return marks[i].id < marks[j].id
		})
		mowner := map[int]string{}
		for _, m := range marks {
			is := Issue{Code: "mark_alloc_invalid", Severity: SeverityError, Field: "allocation"}
			if m.kind == "exit" {
				is.NodeID = m.id
			} else {
				is.GroupID = m.id
			}
			switch {
			case m.slot < 0 || m.slot >= model.MaxMarkSlots:
				is.Message = fmt.Sprintf("%s 的标记分配序号 %d 不在 0–%d 之间（分配表被手工改过？）。", m.id, m.slot, model.MaxMarkSlots-1)
				out = append(out, is)
			case mowner[m.slot] != "":
				is.Message = fmt.Sprintf("%s 和 %s 的标记分配序号都是 %d：会得到同一个 fwmark、中转地址和枢纽路由表（分配表被手工改过？）。", mowner[m.slot], m.id, m.slot)
				out = append(out, is)
			default:
				mowner[m.slot] = m.id
			}
		}
	}
	eff := model.EffectiveAllocations(t)
	for _, l := range tunnelLinks(t) {
		if _, ok := eff.LinkSlot(l.ID); !ok && l.ID != "" {
			out = append(out, Issue{Code: "link_alloc_exhausted", Severity: SeverityError, LinkID: l.ID,
				Message: fmt.Sprintf("链路 %s 分不到接口：%d 个接口序号都已占用，或剩下的与手工填写的地址、端口冲突（已删除链路的序号在下一次保存之后才会复用）。删掉不用的链路、停用后再保存一次，或改掉冲突的手工地址/端口。", l.ID, model.MaxLinkSlots)})
		}
	}
	for _, n := range t.Nodes {
		if n.Role != model.RoleExit || n.ID == "" {
			continue
		}
		if _, ok := eff.ExitSlot(n.ID); !ok {
			out = append(out, Issue{Code: "mark_alloc_exhausted", Severity: SeverityError, NodeID: n.ID,
				Message: fmt.Sprintf("出口 %s 分不到标记：%d 个标记、中转地址和路由表都已占用（已删除出口和地区组的序号在下一次保存之后才会复用）。", n.ID, model.MaxMarkSlots)})
		}
	}
	for _, g := range t.Groups {
		if g.ID == "" {
			continue
		}
		if _, ok := eff.GroupSlot(g.ID); !ok {
			out = append(out, Issue{Code: "mark_alloc_exhausted", Severity: SeverityError, GroupID: g.ID,
				Message: fmt.Sprintf("地区组 %s 分不到标记：%d 个标记、中转地址和路由表都已占用（已删除出口和地区组的序号在下一次保存之后才会复用）。", g.ID, model.MaxMarkSlots)})
		}
	}
	return out
}

// addrBlock is one subnet (or single address) a link's tunnel uses.
type addrBlock struct {
	prefix netip.Prefix
	link   string
	leg    string // "主腿" or "WSS 腿"
	// manual names the link fields that typed it in (from_v4 …); empty:
	// the slot's automatic subnet.
	manual []string
}

func (b addrBlock) describe() string {
	if len(b.manual) == 0 {
		return fmt.Sprintf("链路 %s %s自动分配的 %s", b.link, b.leg, b.prefix)
	}
	return fmt.Sprintf("链路 %s 手工填写的 %s（%s）", b.link, b.prefix, strings.Join(b.manual, "、"))
}

// fromIsWest: the link's From end is the west (home-side) tunnel end, the
// one that gets the .1 / ::1 default address. Unresolvable ends: assume so.
func fromIsWest(t model.Topology, l model.Link) bool {
	west, _, ok := TunnelEnds(t, l)
	if !ok {
		return true
	}
	from, ok := t.NodeByID(l.From)
	if !ok {
		return true
	}
	if from.Role == model.RoleIX {
		if p, ok := dedicatedPeer(t, from.ID, l.To); ok {
			from = p
		}
	}
	return west.ID == from.ID
}

// pairBlocks turns a leg's two addresses into blocks: the /bits holding both,
// or one host block each when they are not in one.
func pairBlocks(link, leg string, a, b string, fa, fb string, bits int) []addrBlock {
	pa, errA := netip.ParseAddr(strings.TrimSpace(a))
	pb, errB := netip.ParseAddr(strings.TrimSpace(b))
	var out []addrBlock
	manual := func(fs ...string) []string {
		var m []string
		for _, f := range fs {
			if f != "" {
				m = append(m, f)
			}
		}
		return m
	}
	if errA == nil && errB == nil && pa.Is4() == pb.Is4() {
		p := netip.PrefixFrom(pa, bits).Masked()
		if p.Contains(pb) {
			return []addrBlock{{prefix: p, link: link, leg: leg, manual: manual(fa, fb)}}
		}
	}
	if errA == nil {
		out = append(out, addrBlock{prefix: netip.PrefixFrom(pa, pa.BitLen()), link: link, leg: leg, manual: manual(fa)})
	}
	if errB == nil {
		out = append(out, addrBlock{prefix: netip.PrefixFrom(pb, pb.BitLen()), link: link, leg: leg, manual: manual(fb)})
	}
	return out
}

// linkBlocks are every subnet the links' tunnels use: manual addresses of
// any link (as the old check read them) and, for tunnel links with a slot,
// the slot's addresses where no manual one replaces them.
func linkBlocks(t model.Topology) []addrBlock {
	eff := model.EffectiveAllocations(t)
	var out []addrBlock
	links := append([]model.Link(nil), t.Links...)
	sort.SliceStable(links, func(i, j int) bool { return links[i].ID < links[j].ID })
	for _, l := range links {
		slot, ok := eff.LinkSlot(l.ID)
		if !ok || !model.TunnelTransport(l.Transport) {
			// Manual addresses only (as before).
			if l.FromV4 != "" && l.ToV4 != "" {
				out = append(out, pairBlocks(l.ID, "主腿", l.FromV4, l.ToV4, "from_v4", "to_v4", 30)...)
			}
			if l.FromULA != "" && l.ToULA != "" {
				out = append(out, pairBlocks(l.ID, "主腿", l.FromULA, l.ToULA, "from_ula", "to_ula", 64)...)
			}
			continue
		}
		w4, e4, w6, e6 := model.LinkAutoAddrs(slot)
		f4, t4, f6, t6 := w4, e4, w6, e6
		if !fromIsWest(t, l) {
			f4, t4, f6, t6 = e4, w4, e6, w6
		}
		ff4, ft4, ff6, ft6 := "", "", "", ""
		if l.FromV4 != "" {
			f4, ff4 = l.FromV4, "from_v4"
		}
		if l.ToV4 != "" {
			t4, ft4 = l.ToV4, "to_v4"
		}
		if l.FromULA != "" {
			f6, ff6 = l.FromULA, "from_ula"
		}
		if l.ToULA != "" {
			t6, ft6 = l.ToULA, "to_ula"
		}
		out = append(out, pairBlocks(l.ID, "主腿", f4, t4, ff4, ft4, 30)...)
		out = append(out, pairBlocks(l.ID, "主腿", f6, t6, ff6, ft6, 64)...)
		if l.Transport == model.TransportUDPWSSFailover {
			c4, _, c6, _ := model.LinkCompanionAddrs(slot)
			out = append(out,
				addrBlock{prefix: netip.PrefixFrom(netip.MustParseAddr(c4), 30).Masked(), link: l.ID, leg: "WSS 腿"},
				addrBlock{prefix: netip.PrefixFrom(netip.MustParseAddr(c6), 64).Masked(), link: l.ID, leg: "WSS 腿"})
		}
	}
	return out
}

// checkSubnets: no two tunnel subnets overlap, manual or automatic. The
// issue goes to a link whose manual field caused it (that field is what
// to change); two automatic subnets never overlap unless the table is
// broken (link_alloc_invalid).
func checkSubnets(t model.Topology) []Issue {
	var out []Issue
	blocks := linkBlocks(t)
	seen := map[string]bool{}
	for i := 0; i < len(blocks); i++ {
		for j := i + 1; j < len(blocks); j++ {
			a, b := blocks[i], blocks[j]
			if a.link == b.link && a.leg == b.leg {
				continue
			}
			if a.prefix.Addr().Is4() != b.prefix.Addr().Is4() || !a.prefix.Overlaps(b.prefix) {
				continue
			}
			if len(a.manual) == 0 && len(b.manual) == 0 {
				continue
			}
			on, other := a, b
			if len(on.manual) == 0 {
				on, other = b, a
			}
			key := on.link + "|" + on.manual[0] + "|" + other.link
			if seen[key] {
				continue
			}
			seen[key] = true
			out = append(out, Issue{
				Code: "subnet_overlap", Severity: SeverityError, LinkID: on.link, Field: on.manual[0],
				Message: fmt.Sprintf("%s 与%s重叠：两个隧道接口会落在同一个网段里。换一个不重叠的地址，或清空手工地址用自动分配的网段。", on.describe(), other.describe()),
			})
		}
	}
	return out
}

// checkLinkAddrReserved: a manual tunnel address is not in a range the
// gateway uses for something else. (The LAN IPv4, the ROS address, the
// ULA prefix and the resolver range fd66::/64 have their own checks:
// prefix_conflict, ula_via_ros, group_resolver_conflict.)
func checkLinkAddrReserved(t model.Topology) []Issue {
	type named struct {
		p    netip.Prefix
		what string
	}
	var res []named
	add := func(s, what string) {
		if p, err := netip.ParsePrefix(strings.TrimSpace(s)); err == nil {
			res = append(res, named{p.Masked(), what + " " + p.Masked().String()})
		}
	}
	add(or(t.Settings.TransitV4Prefix, "10.66.200.0/24"), "中转前缀（各出口与地区组的中转地址、探测源地址 10.66.200.2）")
	add(or(t.Settings.TransitV6Prefix, "fd66:0:0:ff::/64"), "IPv6 中转前缀")
	add(ExternalServiceNet.String(), "外部 SOCKS 出口在承载节点上的服务地址段")
	add(ExternalHealthNet.String(), "外部 SOCKS 出口的健康探测地址段")
	add("169.254.0.0/16", "链路本地地址（Mesh veth 用 169.254.66.0/30）")
	add("fe80::/10", "IPv6 链路本地地址（Mesh veth 用 fe80::66:1 / fe80::66:2）")
	add("100.96.0.0/12", "Cloudflare Mesh 地址段")
	add("127.0.0.0/8", "环回地址")
	add("::1/128", "环回地址")
	add("0.0.0.0/8", "未指定地址")
	add("224.0.0.0/3", "组播/保留地址")
	add("ff00::/8", "IPv6 组播")
	add(t.Settings.LANIPv6Prefix, "局域网 IPv6 前缀")
	add(t.Settings.NAT64.Prefix, "NAT64 前缀")
	for _, n := range t.Nodes {
		add(n.LANIPv4, "节点 "+n.ID+" 的局域网")
		add(n.LANIPv6Prefix, "节点 "+n.ID+" 的局域网 IPv6 前缀")
	}
	if ra := t.RemoteAccess; ra != nil {
		add(ra.V4Prefix(), "远程接入设备地址池")
		add(ra.V6Prefix(), "远程接入设备 IPv6 地址池")
	}
	lan, lanErr := netip.ParsePrefix(lanPrefix(t))
	var out []Issue
	for _, l := range t.Links {
		for _, f := range []struct{ field, val string }{{"from_v4", l.FromV4}, {"to_v4", l.ToV4}, {"from_ula", l.FromULA}, {"to_ula", l.ToULA}} {
			a, err := netip.ParseAddr(strings.TrimSpace(f.val))
			if err != nil {
				continue
			}
			for _, r := range res {
				if r.p.Addr().Is4() != a.Is4() || !r.p.Contains(a) {
					continue
				}
				// The gateway LAN IPv4 has its own check (prefix_conflict).
				if lanErr == nil && a.Is4() && lan.Masked() == r.p {
					continue
				}
				out = append(out, Issue{Code: "link_addr_reserved", Severity: SeverityError, LinkID: l.ID, Field: f.field,
					Message: fmt.Sprintf("链路 %s 的隧道地址 %s（%s）落在%s里，这一段另有用途。换一个地址，或清空它用自动分配的网段。", l.ID, a, f.field, r.what)})
				break
			}
		}
	}
	return out
}

// NodeTunnelIfaces lists the tunnel interface names each node gets, from
// the links' slots (both ends; the WSS leg of udp_wss_failover adds the
// "w" name). Links whose ends cannot be resolved are skipped.
func NodeTunnelIfaces(t model.Topology) map[string][]string {
	eff := model.EffectiveAllocations(t)
	out := map[string][]string{}
	for _, l := range tunnelLinks(t) {
		slot, ok := eff.LinkSlot(l.ID)
		if !ok {
			continue
		}
		w, e, ok := TunnelEnds(t, l)
		if !ok {
			continue
		}
		names := []string{model.LinkIface(slot)}
		if l.Transport == model.TransportUDPWSSFailover {
			names = append(names, model.LinkIface(slot)+"w")
		}
		out[w.ID] = append(out[w.ID], names...)
		out[e.ID] = append(out[e.ID], names...)
	}
	return out
}

// checkIfaceNames: the interface names an operator typed on a node are
// neither one of that node's tunnel interfaces nor a reserved name.
func checkIfaceNames(t model.Topology) []Issue {
	tun := NodeTunnelIfaces(t)
	var out []Issue
	for _, n := range t.Nodes {
		mine := map[string]bool{}
		for _, name := range tun[n.ID] {
			mine[name] = true
		}
		fields := []struct{ field, val string }{
			{"lan_interface", n.LANInterface}, {"wan_interface", n.WANInterface}, {"ingress_interface", n.IngressInterface},
		}
		for _, f := range fields {
			name := strings.TrimSpace(f.val)
			if name == "" {
				continue
			}
			if mine[name] {
				out = append(out, Issue{Code: "iface_name_conflict", Severity: SeverityError, NodeID: n.ID, Field: f.field,
					Message: fmt.Sprintf("节点 %s 的 %s 叫 %s，与这台主机上一条链路的隧道接口同名。隧道接口名由链路的分配序号决定（m00、m01…）；这里填主机上真实的接口名。", n.ID, f.field, name)})
				continue
			}
			if why, ok := reservedIfaces[name]; ok {
				out = append(out, Issue{Code: "iface_name_conflict", Severity: SeverityError, NodeID: n.ID, Field: f.field,
					Message: fmt.Sprintf("节点 %s 的 %s 不能叫 %s：这个名字留给%s。", n.ID, f.field, name, why)})
			}
		}
	}
	if gw := firstRole(t, model.RoleGateway); gw.ID != "" {
		name := strings.TrimSpace(t.Settings.LANInterface)
		mine := map[string]bool{}
		for _, x := range tun[gw.ID] {
			mine[x] = true
		}
		if name != "" && mine[name] {
			out = append(out, Issue{Code: "iface_name_conflict", Severity: SeverityError, Field: "lan_interface",
				Message: fmt.Sprintf("网关局域网接口叫 %s，与网关上一条链路的隧道接口同名。", name)})
		}
	}
	return out
}
