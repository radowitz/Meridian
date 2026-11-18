package validate

import (
	"fmt"
	"net/netip"
	"sort"
	"strings"

	"github.com/radowitz/meridian/internal/model"
	"github.com/radowitz/meridian/internal/mtu"
)

// Cloudflare Mesh legs (docs/architecture.md「Cloudflare Mesh：WireGuard 的
// 底层承载」). A cf_mesh link is a WireGuard leg from a hub (primary or backup) to an
// exit whose outer packets cross the Cloudflare Mesh: the exit's Mesh node
// publishes one address allocated by the panel (model.Allocations.Mesh) and
// the hub dials it. The checks here keep that the only thing a Mesh edge can
// be: what a link from before this structure still carries is refused with
// the way to migrate, and the published address stays clear of every
// address plan Meridian or the topology already uses.

// meshUnderlayFixed are the ranges the Mesh underlay pool may never touch,
// whatever the topology says.
var meshUnderlayFixed = []struct {
	p    netip.Prefix
	what string
}{
	{netip.MustParsePrefix("10.66.0.0/16"), "隧道地址规划 10.66.0.0/16"},
	{netip.MustParsePrefix("100.96.0.0/12"), "Cloudflare Mesh 地址段 100.96.0.0/12"},
	{netip.MustParsePrefix("169.254.0.0/16"), "链路本地地址（Mesh veth 用 169.254.66.0/30）"},
}

// MeshUnderlayReserved lists every range and address of topology t that an
// exit's Mesh underlay address must stay clear of: the fixed plans above,
// the transit prefix, the LANs, the remote-access pool and every address
// the topology names (node endpoints, manual tunnel addresses, the home
// router, resolver upstreams, external SOCKS servers). IPv4 only: the pool
// is IPv4. The tunnel ULA fd66::/48 can therefore never be touched.
func MeshUnderlayReserved(t model.Topology) []NamedPrefix {
	var out []NamedPrefix
	for _, f := range meshUnderlayFixed {
		out = append(out, NamedPrefix{f.p, f.what})
	}
	prefix := func(s, what string) {
		if p, err := netip.ParsePrefix(strings.TrimSpace(s)); err == nil && p.Addr().Is4() {
			out = append(out, NamedPrefix{p.Masked(), what + " " + p.Masked().String()})
		}
	}
	host := func(s, what string) {
		if a, err := netip.ParseAddr(hostOf(s)); err == nil && a.Is4() {
			out = append(out, NamedPrefix{netip.PrefixFrom(a, 32), what + " " + a.String()})
		}
	}
	prefix(lanPrefix(t), "网关局域网")
	prefix(or(t.Settings.TransitV4Prefix, "10.66.200.0/24"), "中转前缀")
	host(t.Settings.ROSIPv4, "ROS 地址")
	for _, s := range t.Settings.DomesticDoT {
		host(s, "国内解析器")
	}
	if ra := t.RemoteAccess; ra != nil {
		prefix(ra.V4Prefix(), "远程接入设备地址池")
	}
	upstream := func(u *model.ExitDNSUpstream, what string) {
		if u == nil {
			return
		}
		for _, a := range u.Addresses {
			host(a, what)
		}
	}
	upstream(t.Settings.ExitDNS, "出口解析上游")
	for _, n := range t.Nodes {
		prefix(n.LANIPv4, "节点 "+n.ID+" 的局域网")
		host(n.EndpointV4, "节点 "+n.ID+" 的端点")
		host(n.IngressV4, "节点 "+n.ID+" 的境内入口")
		host(n.UnderlayNextHop, "节点 "+n.ID+" 的下层下一跳")
		upstream(n.ExitDNS, "节点 "+n.ID+" 的解析上游")
		if n.External != nil {
			host(n.External.SOCKSAddress, "外部出口 "+n.ID+" 的 SOCKS 地址")
		}
	}
	for _, l := range t.Links {
		host(l.FromV4, "链路 "+l.ID+" 的隧道地址")
		host(l.ToV4, "链路 "+l.ID+" 的隧道地址")
	}
	return out
}

// NamedPrefix is a reserved range and what it is.
type NamedPrefix struct {
	Prefix netip.Prefix
	What   string
}

// meshHasLinks: the topology has a cf_mesh link at all (enabled or not).
func meshHasLinks(t model.Topology) bool {
	for _, l := range t.Links {
		if l.Transport == model.TransportCFMesh {
			return true
		}
	}
	return false
}

// checkMeshLegs: the Mesh edges are WireGuard legs the compiler can build
// and their underlay addresses are usable. Nothing is reported for a
// topology without a cf_mesh link.
func checkMeshLegs(t model.Topology, nodes map[string]model.Node) []Issue {
	if !meshHasLinks(t) {
		return nil
	}
	var out []Issue
	add := func(code, sev, nodeID, linkID, field, format string, a ...any) {
		out = append(out, Issue{Code: code, Severity: sev, NodeID: nodeID, LinkID: linkID, Field: field, Message: fmt.Sprintf(format, a...)})
	}
	links := append([]model.Link(nil), t.Links...)
	sort.SliceStable(links, func(i, j int) bool { return links[i].ID < links[j].ID })

	// What a link from before this structure may still carry.
	for _, l := range links {
		if l.Transport != model.TransportCFMesh || len(l.MeshRoutes) == 0 {
			continue
		}
		add("mesh_legacy_routes", SeverityError, "", l.ID, "mesh_routes",
			"Mesh 边 %s 还带着 mesh_routes（%s）。这是旧结构：出口的 Mesh 节点发布这些网段，枢纽把地区组表或出口表的默认路由指向 sidecar，流量从 Cloudflare 的出口出去，而不是从这个出口自己的公网地址出去。现在 Mesh 边是架在 Mesh 上的一条 WireGuard 腿，出口的 Mesh 节点只发布面板分配的一个专用地址（/32），不发布别的网段，也不发布默认路由。迁移：清空这条链路的 mesh_routes 并保存；重新下发枢纽和这个出口；再到「部署 → Mesh」重新部署（旧的 Cloudflare 路由在那里撤回，换成新的专用地址）。",
			linkName(l), strings.Join(l.MeshRoutes, "、"))
	}

	pool, perr := t.MeshUnderlayPrefix()
	if perr != nil {
		add("mesh_underlay_prefix", SeverityError, "", "", "mesh_underlay_prefix",
			"Mesh 底层地址池（settings.mesh_underlay_prefix）不可用：%v。它是各出口 Mesh 专用地址的来源，要写成 /16 到 /30 的 IPv4 网络地址（留空用默认的 %s）。这一版只分配 IPv4 /32：Mesh 对 IPv6 路由的承载还没有实机确认。", perr, model.DefaultMeshUnderlayPrefix)
	} else {
		private := false
		for _, r := range rfc1918 {
			private = private || (r.Bits() <= pool.Bits() && r.Contains(pool.Addr()))
		}
		if !private {
			add("mesh_underlay_prefix", SeverityError, "", "", "mesh_underlay_prefix",
				"Mesh 底层地址池 %s 必须在 10.0.0.0/8、172.16.0.0/12 或 192.168.0.0/16 里：出口把其中的地址发布成 Mesh 路由，公网网段会劫持真实目的地。", pool)
			perr = fmt.Errorf("not private")
		}
	}
	if perr == nil {
		for _, r := range MeshUnderlayReserved(t) {
			if r.Prefix.Overlaps(pool) {
				add("mesh_underlay_conflict", SeverityError, "", "", "mesh_underlay_prefix",
					"Mesh 底层地址池 %s 与%s重叠。出口发布的 Mesh 专用地址必须在已有地址规划之外；把 settings.mesh_underlay_prefix 改成一个不重叠的私有网段。", pool, r.What)
			}
		}
	}

	// The stored table.
	if a := t.Allocations; a != nil && len(a.Mesh) > 0 {
		ids := make([]string, 0, len(a.Mesh))
		for id := range a.Mesh {
			ids = append(ids, id)
		}
		sort.Strings(ids)
		owner := map[int]string{}
		for _, id := range ids {
			s := a.Mesh[id].Slot
			switch {
			case s < 0 || s >= model.MaxMeshSlots:
				add("mesh_alloc_invalid", SeverityError, id, "", "allocation", "出口 %s 的 Mesh 地址分配序号 %d 不在 0–%d 之间（分配表被手工改过？）。", id, s, model.MaxMeshSlots-1)
			case owner[s] != "":
				add("mesh_alloc_invalid", SeverityError, id, "", "allocation", "出口 %s 和 %s 的 Mesh 地址分配序号都是 %d：两个出口会发布同一个地址（分配表被手工改过？）。", owner[s], id, s)
			default:
				owner[s] = id
			}
		}
	}

	eff := model.EffectiveAllocations(t)
	seenPair := map[string]string{}
	relayExit := map[string]bool{}
	carrier := map[string]bool{}
	for _, n := range t.Nodes {
		if model.IsNested(n) {
			relayExit[n.ViaExit] = true
		}
		if model.IsExternal(n) {
			carrier[n.External.Carrier] = true
		}
	}
	for _, l := range links {
		if l.Transport != model.TransportCFMesh || !l.Enabled {
			continue
		}
		a, b := nodes[l.From], nodes[l.To]
		var hub, exit model.Node
		switch {
		case a.Role == model.RoleHub && b.Role == model.RoleExit:
			hub, exit = a, b
		case b.Role == model.RoleHub && a.Role == model.RoleExit:
			hub, exit = b, a
		default:
			continue // mesh_not_hub_exit (checkMesh)
		}
		key := hub.ID + "|" + exit.ID
		if other, dup := seenPair[key]; dup {
			add("mesh_leg_duplicate", SeverityError, exit.ID, l.ID, "", "Mesh 边 %s 和 %s 都连着枢纽 %s 与出口 %s。同一个枢纽到同一个出口只能有一条 Mesh 腿（一台主机只运行一个 Mesh sidecar，出口只发布一个专用地址）。", other, linkName(l), hub.Name, exit.Name)
			continue
		}
		seenPair[key] = linkName(l)

		switch {
		case model.IsNested(exit) || model.IsExternal(exit):
			// via_exit_link / external checks report these.
			continue
		case relayExit[exit.ID]:
			add("mesh_leg_unsupported_exit", SeverityError, exit.ID, l.ID, "", "出口 %s 是中继出口（后面挂着别的出口）。这一版 Mesh 腿只用于枢纽直连的普通出口：切到 Mesh 腿时它后面的出口没有对应的路径。", exit.Name)
			continue
		case carrier[exit.ID]:
			add("mesh_leg_unsupported_exit", SeverityError, exit.ID, l.ID, "", "出口 %s 承载着外部 SOCKS 出口。这一版 Mesh 腿只用于枢纽直连的普通出口：切到 Mesh 腿时它承载的外部出口没有对应的路径。", exit.Name)
			continue
		case exit.DualstackRelay:
			add("mesh_leg_unsupported_exit", SeverityError, exit.ID, l.ID, "", "出口 %s 是双栈中继。这一版 Mesh 腿只用于枢纽直连的普通出口。", exit.Name)
			continue
		case pureV6(exit) && exit.V6Workaround != model.WorkaroundMesh:
			add("mesh_leg_unsupported_exit", SeverityError, exit.ID, l.ID, "", "出口 %s 是纯 IPv6 出口，选的绕行不是 Mesh。纯 IPv6 出口要用 Mesh 腿，把它的 v6_workaround 设为 mesh（Mesh 腿就是枢纽到它的唯一一腿）；否则删掉这条 Mesh 边。", exit.Name)
			continue
		}
		if !model.MeshSoleExit(exit) && !hubTunnelTo(t, hub.ID, exit.ID) {
			add("mesh_leg_no_direct", SeverityError, exit.ID, l.ID, "", "Mesh 边 %s 连着出口 %s，但枢纽 %s 没有到它的直连 WireGuard（启用、非待命）。Mesh 腿是直连腿的备用承载：两条腿都在枢纽和这个出口之间，按链路质量选用；先画上直连的那一条。只有选了 Mesh 绕行的纯 IPv6 出口可以只有 Mesh 腿。", linkName(l), exit.Name, hub.Name)
		}
		slot, ok := eff.MeshSlot(exit.ID)
		if !ok {
			add("mesh_alloc_exhausted", SeverityError, exit.ID, l.ID, "", "出口 %s 分不到 Mesh 专用地址：%d 个序号都已占用（已删除的 Mesh 边的序号在下一次保存之后才会复用）。", exit.Name, model.MaxMeshSlots)
			continue
		}
		if perr == nil {
			if _, ok := model.MeshUnderlayAddr(pool, slot); !ok {
				add("mesh_alloc_exhausted", SeverityError, exit.ID, l.ID, "mesh_underlay_prefix", "Mesh 底层地址池 %s 放不下出口 %s 的专用地址（分配序号 %d）。把 settings.mesh_underlay_prefix 换成更大的网段。", pool, exit.Name, slot)
			}
		}
		if payload, device := MeshLegMTU(l); payload < device {
			add("mesh_leg_fragments", SeverityWarning, exit.ID, l.ID, "mtu",
				"Mesh 边 %s 按 Mesh 路径 MTU %d 规划：扣掉 WireGuard 的 %d 字节后只剩 %d，低于承载 IPv6 所需的 %d。接口保持 %d（出口解析地址是 IPv6），TCP 按 %d 钳制（MSS %d / %d），不会分片；%d 到 %d 字节之间的非 TCP 包靠 WireGuard 外层包分片通过，这一点还没有在真实 Mesh 上验证。Mesh 路径实际能承载 %d 以上时，把这条链路的 MTU 改成实际值即可免去分片。",
				linkName(l), model.MeshLegPathMTU(l), mtu.UDPOverhead(4), model.MeshLegPathMTU(l)-mtu.UDPOverhead(4), mtu.MinTunnel, device, payload, payload-40, payload-60, payload+1, device, mtu.MinTunnel+mtu.UDPOverhead(4))
		}
	}
	return out
}
