// Package mesh holds the Cloudflare Mesh sidecar addressing, the panel's
// staged deployment of it (remote sidecar, Cloudflare node, Cloudflare
// routes) and the compensation that undoes a failed or withdrawn run.
//
// Data plane: on the hub (and on each Mesh exit) the sidecar container has
// its own network namespace. The host reaches it over an Ethernet veth pair,
// mmesh (host) and mmesh-c (sidecar). An Ethernet veth is not a
// point-to-point device: "default dev mmesh" without a gateway makes the
// kernel ARP / neighbour-solicit for every public destination on the veth,
// and nothing answers. Every route Meridian installs onto mmesh therefore
// names an explicit next-hop that the sidecar owns:
//
//	IPv4  host 169.254.66.1/30  ->  via 169.254.66.2 dev mmesh
//	IPv6  host fe80::66:1/64    ->  via fe80::66:2 dev mmesh (link scope, so
//	                                 the interface is always given)
//
// Both ends get fixed locally administered MAC addresses and permanent
// neighbour entries for each other, so resolution of the next-hop does not
// depend on ARP/ND timing, and no proxy ARP/ND is needed. The sidecar's
// return path towards Meridian prefixes uses the host end as its next-hop
// in the same way.
//
// None of this has been exercised on a Linux host from this repository.
// deploy/verify-mesh-veth.sh is the isolated dual-stack check of the hop;
// until its output is archived, the Mesh data plane is "未验证", and a
// successful Cloudflare route publication is not evidence that Mesh works.
package mesh

import (
	"fmt"
	"net"
	"net/netip"
	"sort"
	"strings"

	"github.com/radowitz/meridian/internal/model"
)

const (
	HostIface    = "mmesh"
	SidecarIface = "mmesh-c"
	// SidecarTable is the policy table inside the sidecar netns for packets
	// the host injects on mmesh-c.
	SidecarTable = 170
)

// MeshIPRange is the range Cloudflare assigns Mesh IPs from
// (developers.cloudflare.com/mesh/get-started/). Published routes and the
// veth must not overlap it.
var MeshIPRange = netip.MustParsePrefix("100.96.0.0/12")

// Addressing is the host <-> sidecar link of one Mesh node.
type Addressing struct {
	LinkV4     netip.Prefix `json:"link_v4"`
	HostV4     netip.Addr   `json:"host_v4"`
	SidecarV4  netip.Addr   `json:"sidecar_v4"`
	HostV6     netip.Addr   `json:"host_v6"`
	SidecarV6  netip.Addr   `json:"sidecar_v6"`
	V6Bits     int          `json:"v6_bits"`
	HostMAC    string       `json:"host_mac"`
	SidecarMAC string       `json:"sidecar_mac"`
	HostIface  string       `json:"host_iface"`
	PeerIface  string       `json:"sidecar_iface"`
}

// DefaultAddressing is what the compiler renders and the deployer checks.
func DefaultAddressing() Addressing {
	return Addressing{
		LinkV4:     netip.MustParsePrefix("169.254.66.0/30"),
		HostV4:     netip.MustParseAddr("169.254.66.1"),
		SidecarV4:  netip.MustParseAddr("169.254.66.2"),
		HostV6:     netip.MustParseAddr("fe80::66:1"),
		SidecarV6:  netip.MustParseAddr("fe80::66:2"),
		V6Bits:     64,
		HostMAC:    "02:6d:65:73:68:01",
		SidecarMAC: "02:6d:65:73:68:02",
		HostIface:  HostIface,
		PeerIface:  SidecarIface,
	}
}

// NextHopV4 / NextHopV6 are the gateways the host uses on mmesh.
func (a Addressing) NextHopV4() string { return a.SidecarV4.String() }
func (a Addressing) NextHopV6() string { return a.SidecarV6.String() }

// HostV4CIDR etc. are the interface addresses as ip(8) wants them.
func (a Addressing) HostV4CIDR() string {
	return fmt.Sprintf("%s/%d", a.HostV4, a.LinkV4.Bits())
}
func (a Addressing) SidecarV4CIDR() string {
	return fmt.Sprintf("%s/%d", a.SidecarV4, a.LinkV4.Bits())
}
func (a Addressing) HostV6CIDR() string    { return fmt.Sprintf("%s/%d", a.HostV6, a.V6Bits) }
func (a Addressing) SidecarV6CIDR() string { return fmt.Sprintf("%s/%d", a.SidecarV6, a.V6Bits) }

// Issue is one plan or preflight finding. Every issue stops a deployment.
type Issue struct {
	Code    string `json:"code"`
	Message string `json:"message"`
	NodeID  string `json:"node_id,omitempty"`
	LinkID  string `json:"link_id,omitempty"`
}

// Validate checks that the two ends are usable next-hops for each other.
func (a Addressing) Validate() []Issue {
	var out []Issue
	bad := func(code, msg string) { out = append(out, Issue{Code: code, Message: msg}) }
	if !a.LinkV4.IsValid() || !a.LinkV4.Addr().Is4() || a.LinkV4.Bits() < 24 || a.LinkV4.Bits() > 30 {
		bad("mesh_v4_link", "veth IPv4 链路必须是 /24 到 /30 的 IPv4 前缀")
		return out
	}
	if a.LinkV4 != a.LinkV4.Masked() {
		bad("mesh_v4_link", "veth IPv4 链路前缀不是网络地址")
	}
	if !netip.MustParsePrefix("169.254.0.0/16").Contains(a.LinkV4.Addr()) {
		bad("mesh_v4_link", "veth IPv4 链路必须在 169.254.0.0/16（只在 veth 上有效，不会被路由出去）")
	}
	for name, ip := range map[string]netip.Addr{"主机端": a.HostV4, "sidecar 端": a.SidecarV4} {
		if !ip.Is4() || !a.LinkV4.Contains(ip) {
			bad("mesh_v4_addr", name+" IPv4 不在 veth 链路前缀里")
			continue
		}
		if ip == a.LinkV4.Addr() || ip == lastAddr(a.LinkV4) {
			bad("mesh_v4_addr", name+" IPv4 是网络地址或广播地址")
		}
	}
	if a.HostV4 == a.SidecarV4 {
		bad("mesh_v4_addr", "主机端和 sidecar 端 IPv4 相同，下一跳会指向自己")
	}
	ll := netip.MustParsePrefix("fe80::/64")
	if a.V6Bits != 64 {
		bad("mesh_v6_link", "veth IPv6 链路本地前缀必须是 /64")
	}
	for name, ip := range map[string]netip.Addr{"主机端": a.HostV6, "sidecar 端": a.SidecarV6} {
		if !ip.Is6() || ip.Is4In6() || !ll.Contains(ip) || ip.Zone() != "" {
			bad("mesh_v6_addr", name+" IPv6 必须是不带 zone 的 fe80::/64 链路本地地址（作用域由 dev "+a.HostIface+" 给出）")
		}
	}
	if a.HostV6 == a.SidecarV6 {
		bad("mesh_v6_addr", "主机端和 sidecar 端 IPv6 相同，下一跳会指向自己")
	}
	hm, err1 := net.ParseMAC(a.HostMAC)
	sm, err2 := net.ParseMAC(a.SidecarMAC)
	if err1 != nil || err2 != nil || len(hm) != 6 || len(sm) != 6 {
		bad("mesh_mac", "veth MAC 无法解析")
	} else {
		for _, m := range []net.HardwareAddr{hm, sm} {
			if m[0]&0x01 != 0 || m[0]&0x02 == 0 {
				bad("mesh_mac", "veth MAC 必须是本地管理的单播地址")
			}
		}
		if hm.String() == sm.String() {
			bad("mesh_mac", "veth 两端 MAC 相同")
		}
	}
	if !ifaceName(a.HostIface) || !ifaceName(a.PeerIface) || a.HostIface == a.PeerIface {
		bad("mesh_iface", "veth 接口名无效或两端相同")
	}
	return out
}

func lastAddr(p netip.Prefix) netip.Addr {
	b := p.Masked().Addr().As4()
	host := 32 - p.Bits()
	v := uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
	v |= (1 << host) - 1
	return netip.AddrFrom4([4]byte{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)})
}

func ifaceName(s string) bool {
	if s == "" || len(s) > 15 {
		return false
	}
	for _, r := range s {
		if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-' || r == '_') {
			return false
		}
	}
	return true
}

// ReturnPrefixes are the Meridian prefixes the sidecar must send back to
// the host (via the host end of the veth), not out of its docker bridge.
func ReturnPrefixes(t model.Topology) (v4, v6 []string) {
	v4 = []string{LANNet(t), "10.66.0.0/16"}
	v6 = []string{"fd66::/48"}
	if p, err := netip.ParsePrefix(strings.TrimSpace(t.Settings.LANIPv6Prefix)); err == nil && p.Addr().Is6() {
		v6 = append(v6, p.Masked().String())
	}
	return dedupe(v4), dedupe(v6)
}

// LANNet mirrors compile.lanNet (the gateway LAN network).
func LANNet(t model.Topology) string {
	if p, err := netip.ParsePrefix(t.Settings.GatewayLANIP); err == nil {
		return p.Masked().String()
	}
	return "192.168.100.0/24"
}

func dedupe(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		if s == "" || seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	return out
}

// reserved lists ranges no published route and no veth address may touch.
func reserved(t model.Topology, a Addressing) map[string]netip.Prefix {
	out := map[string]netip.Prefix{
		"隧道聚合 10.66.0.0/16": netip.MustParsePrefix("10.66.0.0/16"),
		"隧道 ULA fd66::/48":  netip.MustParsePrefix("fd66::/48"),
		"Mesh IP 段":         MeshIPRange,
		"IPv6 链路本地":         netip.MustParsePrefix("fe80::/10"),
		"veth 链路":           a.LinkV4,
		"回环":                netip.MustParsePrefix("127.0.0.0/8"),
		"IPv6 回环":           netip.MustParsePrefix("::1/128"),
		"组播":                netip.MustParsePrefix("224.0.0.0/4"),
		"IPv6 组播":           netip.MustParsePrefix("ff00::/8"),
	}
	if p, err := netip.ParsePrefix(LANNet(t)); err == nil {
		out["网关局域网"] = p
	}
	for name, raw := range map[string]string{"局域网 IPv6 前缀": t.Settings.LANIPv6Prefix, "ULA 前缀": t.Settings.ULAPrefix, "中转 IPv4": t.Settings.TransitV4Prefix, "中转 IPv6": t.Settings.TransitV6Prefix} {
		if p, err := netip.ParsePrefix(strings.TrimSpace(raw)); err == nil {
			out[name] = p.Masked()
		}
	}
	return out
}

func overlaps(a, b netip.Prefix) bool {
	if a.Addr().Is4() != b.Addr().Is4() {
		return false
	}
	return a.Overlaps(b)
}

// RoutePlan is one Cloudflare CIDR route this deployment publishes for the
// exit end of a Mesh link. Purpose is "" for a route the operator listed on
// the link (mesh_routes) and PurposeGroupResolver for a region group's
// resolver address the compiled files ask this exit to answer (Group names
// the group).
type RoutePlan struct {
	LinkID  string `json:"link_id"`
	ExitID  string `json:"exit_id"`
	Network string `json:"network"`
	Purpose string `json:"purpose,omitempty"`
	Group   string `json:"group,omitempty"`
}

// PurposeGroupResolver marks the route of a region group's resolver
// address (docs/architecture.md「地区组的解析」): while the hub has the group
// on the Mesh hop, its queries to fd66::53:<k> cross the Mesh to the exit
// that publishes fd66::53:<k>/128, which answers them on its Mesh ingress.
const PurposeGroupResolver = "group_resolver"

// PublishMarker starts a line of an exit's compiled meridian-mesh-up.sh
// naming a route its Mesh node publishes: "<marker> <cidr> group=<id>".
// The compiler writes it only for the group's Mesh resolver member; the
// operator does not list these routes.
const PublishMarker = "# meridian-mesh-publish"

// GroupResolverNet mirrors validate.GroupResolverNet: the only range a
// PublishMarker line may name (one /128 per line).
var GroupResolverNet = netip.MustParsePrefix("fd66::53:0/112")

// NodeTarget is one host that gets a sidecar.
type NodeTarget struct {
	ID   string     `json:"id"`
	Name string     `json:"name"`
	Role model.Role `json:"role"`
	// ServerID and CredentialID name the managed server and SSH credential
	// the panel connects through (filled in by the panel, not BuildPlan).
	ServerID     string `json:"server_id,omitempty"`
	CredentialID string `json:"credential_id,omitempty"`
	SSHHost      string `json:"ssh_host,omitempty"`
	SSHPort      int    `json:"ssh_port,omitempty"`
	SSHUser      string `json:"ssh_user,omitempty"`
	// HostKey, when set, is the SSH host key fingerprint the host must
	// present (pinned by the deployer on first contact of a run).
	HostKey string `json:"host_key,omitempty"`
	// Files are the compiled sidecar files (host path -> body). They hold
	// no secret: the Mesh node token is added only by InstallScript.
	Files map[string]string `json:"-"`
}

// Plan is the side-effect-free first stage of a deployment.
type Plan struct {
	Addressing Addressing   `json:"addressing"`
	Nodes      []NodeTarget `json:"nodes"`
	Routes     []RoutePlan  `json:"routes"`
	ReturnV4   []string     `json:"return_v4"`
	ReturnV6   []string     `json:"return_v6"`
	Issues     []Issue      `json:"issues"`
}

// OK reports whether the plan may proceed.
func (p Plan) OK() bool { return len(p.Issues) == 0 }

// Node returns a node target by id.
func (p Plan) Node(id string) (NodeTarget, bool) {
	for _, n := range p.Nodes {
		if n.ID == id {
			return n, true
		}
	}
	return NodeTarget{}, false
}

// Hub returns the hub node of the plan.
func (p Plan) Hub() (NodeTarget, bool) {
	for _, n := range p.Nodes {
		if n.Role == model.RoleHub {
			return n, true
		}
	}
	return NodeTarget{}, false
}

// Managed sidecar files on a Mesh host. The deployer writes, backs up and
// restores exactly these paths and nothing else.
const (
	PathCompose = "/etc/meridian/mesh-sidecar.compose.yml"
	PathUp      = "/usr/local/sbin/meridian-mesh-up.sh"
	PathEnv     = "/etc/meridian/mesh.env"
)

// BuildPlan computes and validates both ends' addressing, the nodes that
// need a sidecar and the routes to publish. bundle is the compiled file map
// (nodes/<id>/...). It does not touch any host or Cloudflare.
func BuildPlan(t model.Topology, bundle map[string]string) Plan {
	a := DefaultAddressing()
	p := Plan{Addressing: a}
	p.ReturnV4, p.ReturnV6 = ReturnPrefixes(t)
	p.Issues = append(p.Issues, a.Validate()...)
	p.Issues = append(p.Issues, linkConflicts(t, a)...)

	// Mesh edges join the primary hub only (validation refuses one to the
	// backup hub).
	hub, _ := t.PrimaryHub()
	var links []model.Link
	for _, l := range t.Links {
		if l.Transport == model.TransportCFMesh && l.Enabled {
			links = append(links, l)
		}
	}
	sort.Slice(links, func(i, j int) bool { return links[i].ID < links[j].ID })
	if len(links) == 0 {
		p.Issues = append(p.Issues, Issue{Code: "mesh_no_links", Message: "拓扑里没有启用的 Mesh 边，没有可部署的 sidecar"})
		return p
	}
	if hub.ID == "" {
		p.Issues = append(p.Issues, Issue{Code: "mesh_no_hub", Message: "拓扑里没有香港枢纽"})
		return p
	}
	addNode := func(n model.Node) {
		if _, ok := p.Node(n.ID); ok {
			return
		}
		if n.Role == model.RoleGateway {
			p.Issues = append(p.Issues, Issue{Code: "mesh_on_gateway", NodeID: n.ID, Message: "家宽网关不运行 Mesh sidecar"})
			return
		}
		files := map[string]string{}
		prefix := "nodes/" + n.ID + "/"
		for _, hp := range []string{PathCompose, PathUp} {
			body, ok := bundle[prefix+strings.TrimPrefix(hp, "/")]
			if !ok || body == "" {
				p.Issues = append(p.Issues, Issue{Code: "mesh_files_missing", NodeID: n.ID, Message: fmt.Sprintf("%s 的编译结果里没有 %s", n.ID, hp)})
				continue
			}
			files[hp] = body
		}
		if up := files[PathUp]; up != "" && (strings.Contains(up, "default dev "+HostIface) || !strings.Contains(up, a.SidecarV6.String())) {
			p.Issues = append(p.Issues, Issue{Code: "mesh_stale_up", NodeID: n.ID, Message: "meridian-mesh-up.sh 没有配置 IPv6 下一跳，拒绝部署"})
		}
		p.Nodes = append(p.Nodes, NodeTarget{ID: n.ID, Name: n.Name, Role: n.Role, SSHHost: n.SSHHost, SSHPort: n.SSHPort, SSHUser: n.SSHUser, Files: files})
	}
	addNode(hub)
	res := reserved(t, a)
	var all []owned
	published := map[string]bool{}
	for _, l := range links {
		var exitID string
		switch {
		case l.From == hub.ID:
			exitID = l.To
		case l.To == hub.ID:
			exitID = l.From
		default:
			p.Issues = append(p.Issues, Issue{Code: "mesh_not_hub_exit", LinkID: l.ID, Message: "Mesh 边必须一端是枢纽"})
			continue
		}
		exit, ok := t.NodeByID(exitID)
		if !ok || exit.Role != model.RoleExit {
			p.Issues = append(p.Issues, Issue{Code: "mesh_not_hub_exit", LinkID: l.ID, Message: "Mesh 边的另一端必须是出口"})
			continue
		}
		addNode(exit)
		if len(l.MeshRoutes) == 0 {
			p.Issues = append(p.Issues, Issue{Code: "mesh_routes_empty", LinkID: l.ID, Message: fmt.Sprintf("Mesh 边 %s 没有填写要由出口 %s 发布的 CIDR 路由；没有路由时枢纽 sidecar 的表 %d 只会是 unreachable", l.ID, exitID, SidecarTable)})
		}
		for _, raw := range l.MeshRoutes {
			pr, err := netip.ParsePrefix(strings.TrimSpace(raw))
			if err != nil {
				p.Issues = append(p.Issues, Issue{Code: "mesh_route_invalid", LinkID: l.ID, Message: fmt.Sprintf("%q 不是 CIDR", raw)})
				continue
			}
			if pr != pr.Masked() {
				p.Issues = append(p.Issues, Issue{Code: "mesh_route_invalid", LinkID: l.ID, Message: fmt.Sprintf("%s 不是网络地址，应为 %s", pr, pr.Masked())})
				continue
			}
			if pr.Bits() == 0 {
				// Cloudflare documents private and public CIDR routes but
				// not a default route; refuse it rather than guess.
				p.Issues = append(p.Issues, Issue{Code: "mesh_route_default", LinkID: l.ID, Message: "不发布默认路由（0.0.0.0/0、::/0）：Cloudflare 文档没有说明 Mesh 节点可以作为默认出口"})
				continue
			}
			for name, r := range res {
				if overlaps(pr, r) {
					p.Issues = append(p.Issues, Issue{Code: "mesh_route_conflict", LinkID: l.ID, Message: fmt.Sprintf("%s 与%s %s 重叠", pr, name, r)})
				}
			}
			for _, o := range all {
				if overlaps(pr, o.prefix) {
					p.Issues = append(p.Issues, Issue{Code: "mesh_route_overlap", LinkID: l.ID, Message: fmt.Sprintf("%s 与 Mesh 边 %s 的 %s 重叠；同一虚拟网络里一个 CIDR 只能交给一个节点", pr, o.link, o.prefix)})
				}
			}
			all = append(all, owned{pr, l.ID})
			p.Routes = append(p.Routes, RoutePlan{LinkID: l.ID, ExitID: exitID, Network: pr.String()})
		}
		if !published[exitID] {
			published[exitID] = true
			p.Routes = append(p.Routes, groupResolverRoutes(&p, l.ID, exitID, all)...)
		}
	}
	return p
}

// groupResolverRoutes reads the PublishMarker lines of exitID's compiled
// meridian-mesh-up.sh. Each must name one address of GroupResolverNet as a
// /128 that no other route of the plan covers; anything else is a plan
// issue (the files were not produced by this compiler).
func groupResolverRoutes(p *Plan, linkID, exitID string, taken []owned) []RoutePlan {
	n, ok := p.Node(exitID)
	if !ok {
		return nil
	}
	var out []RoutePlan
	for _, line := range strings.Split(n.Files[PathUp], "\n") {
		rest, ok := strings.CutPrefix(line, PublishMarker+" ")
		if !ok {
			continue
		}
		f := strings.Fields(rest)
		group := ""
		if len(f) == 2 {
			group, _ = strings.CutPrefix(f[1], "group=")
		}
		pr, err := netip.ParsePrefix(firstField(f))
		if err != nil || len(f) != 2 || group == "" || pr.Bits() != 128 || !GroupResolverNet.Contains(pr.Addr()) {
			p.Issues = append(p.Issues, Issue{Code: "mesh_publish_invalid", NodeID: exitID, LinkID: linkID, Message: fmt.Sprintf("meridian-mesh-up.sh 的发布行 %q 无效：只允许 %s 里的单个 /128 地区组解析地址", strings.TrimSpace(line), GroupResolverNet)})
			continue
		}
		dup := false
		for _, o := range taken {
			if overlaps(pr, o.prefix) {
				dup = true
			}
		}
		for _, r := range p.Routes {
			if r.Network == pr.String() {
				dup = true
			}
		}
		for _, r := range out {
			if r.Network == pr.String() {
				dup = true
			}
		}
		if dup {
			p.Issues = append(p.Issues, Issue{Code: "mesh_route_overlap", NodeID: exitID, LinkID: linkID, Message: fmt.Sprintf("地区组 %s 的解析地址 %s 已由别的路由覆盖；同一虚拟网络里一个 CIDR 只能交给一个节点", group, pr)})
			continue
		}
		out = append(out, RoutePlan{LinkID: linkID, ExitID: exitID, Network: pr.String(), Purpose: PurposeGroupResolver, Group: group})
	}
	return out
}

func firstField(f []string) string {
	if len(f) == 0 {
		return ""
	}
	return f[0]
}

// owned is a route prefix the plan already gives to a Mesh link.
type owned struct {
	prefix netip.Prefix
	link   string
}

// linkConflicts finds topology addresses inside the veth link.
func linkConflicts(t model.Topology, a Addressing) []Issue {
	var out []Issue
	check := func(raw, what string, node, link string) {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			return
		}
		var pr netip.Prefix
		if p, err := netip.ParsePrefix(raw); err == nil {
			pr = p.Masked()
		} else if ip, err := netip.ParseAddr(raw); err == nil {
			pr = netip.PrefixFrom(ip, ip.BitLen())
		} else {
			return
		}
		v6hit := pr.Addr().Is6() && pr.Bits() >= 64 && (pr.Contains(a.HostV6) || pr.Contains(a.SidecarV6))
		if overlaps(pr, a.LinkV4) || v6hit {
			out = append(out, Issue{Code: "mesh_link_conflict", NodeID: node, LinkID: link, Message: fmt.Sprintf("%s %s 与 Mesh veth 地址冲突", what, raw)})
		}
	}
	for _, n := range t.Nodes {
		check(n.LANIPv4, "节点局域网地址", n.ID, "")
		check(n.EndpointV4, "节点公网地址", n.ID, "")
		check(n.UnderlayNextHop, "节点下层下一跳", n.ID, "")
	}
	for _, l := range t.Links {
		check(l.FromV4, "隧道地址", "", l.ID)
		check(l.ToV4, "隧道地址", "", l.ID)
	}
	check(t.Settings.GatewayLANIP, "网关局域网", "", "")
	check(t.Settings.ROSIPv4, "ROS", "", "")
	check(t.Settings.TransitV4Prefix, "中转 IPv4", "", "")
	if v := strings.TrimSpace(t.Settings.ROSv6LLA); v != "" {
		if ip, err := netip.ParseAddr(v); err == nil && (ip.WithZone("") == a.HostV6 || ip.WithZone("") == a.SidecarV6) {
			out = append(out, Issue{Code: "mesh_link_conflict", Message: "ROS 链路本地地址与 Mesh veth 的 IPv6 地址相同，换一个以免排障时混淆"})
		}
	}
	if overlaps(a.LinkV4, MeshIPRange) {
		out = append(out, Issue{Code: "mesh_link_conflict", Message: "veth 链路与 Mesh IP 段重叠"})
	}
	return out
}
