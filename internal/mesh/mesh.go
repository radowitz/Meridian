// Package mesh holds the Cloudflare Mesh sidecar addressing, the panel's
// staged deployment of it (remote sidecar, Cloudflare node, Cloudflare
// routes) and the compensation that undoes a failed or withdrawn run.
//
// What the Mesh is for: it is the underlay of a WireGuard leg between the
// primary or backup hub and an exit (docs/architecture.md「Cloudflare Mesh：WireGuard
// 的底层承载」). Each exit with a cf_mesh link publishes exactly one route,
// its Mesh underlay address as a /32 (model.MeshLeg, allocated by the
// panel); the hub's WireGuard leg dials that address. Client traffic is
// decapsulated on the exit and leaves from the exit's own uplink. No
// default route and no other prefix is published, and no routing table on
// any host points an exit's or a region group's traffic at the sidecar.
//
// Data plane: on the hub (and on each exit with a Mesh leg) one sidecar
// container has its own network namespace. The host reaches it over an
// Ethernet veth pair, mmesh (host) and mmesh-c (sidecar). An Ethernet veth
// is not a point-to-point device: a route onto it without a gateway makes
// the kernel ARP / neighbour-solicit for the destination on the veth, and
// nothing answers. Every route Meridian installs onto mmesh therefore names
// an explicit next-hop that the sidecar owns:
//
//	IPv4  host 169.254.66.1/30  ->  via 169.254.66.2 dev mmesh
//	IPv6  host fe80::66:1/64    ->  via fe80::66:2 dev mmesh (link scope, so
//	                                 the interface is always given)
//
// Both ends get fixed locally administered MAC addresses and permanent
// neighbour entries for each other, so resolution of the next-hop does not
// depend on ARP/ND timing, and no proxy ARP/ND is needed.
//
// Whether the Cloudflare Mesh carries WireGuard's UDP to an exit's
// published address has not been exercised on a real Mesh from this
// repository: until that evidence is archived the Mesh data plane is
// "未验证", and a successful Cloudflare route publication is not evidence
// that a Mesh leg works.
package mesh

import (
	"fmt"
	"net"
	"net/netip"
	"sort"
	"strings"

	"github.com/radowitz/meridian/internal/model"
	"github.com/radowitz/meridian/internal/mtu"
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
	return model.UnsetLANPrefix
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
// exit end of a Mesh link: the exit's Mesh underlay address as a /32
// (Purpose PurposeWGUnderlay). An exit publishes exactly one.
type RoutePlan struct {
	LinkID  string `json:"link_id"`
	ExitID  string `json:"exit_id"`
	Network string `json:"network"`
	Purpose string `json:"purpose,omitempty"`
	// Group is only set in the journal of a deployment made before the Mesh
	// became an underlay (PurposeGroupResolver).
	Group string `json:"group,omitempty"`
}

// PurposeWGUnderlay marks the one route of an exit's Mesh node: the address
// the hub's WireGuard leg to that exit dials (model.MeshLeg.Route).
const PurposeWGUnderlay = "wg_underlay"

// PurposeGroupResolver marked the route of a region group's resolver
// address in deployments made while a group's table could point at the
// sidecar. No plan produces it any more; a journal of such a deployment
// still carries it, and its routes are withdrawn like any other.
const PurposeGroupResolver = "group_resolver"

// PublishMarker starts the line of an exit's compiled meridian-mesh-up.sh
// naming the one route its Mesh node publishes: "<marker> <addr>/32
// leg=<link id>". BuildPlan compares it with the topology's allocation.
const PublishMarker = "# meridian-mesh-publish"

// GroupResolverNet mirrors validate.GroupResolverNet. Nothing inside it is
// ever published.
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
	// Origin is model.MeshOriginExisting for a host that already runs a
	// reusable host-level Mesh node (model.Node.MeshHost): the run never
	// registers, installs, re-seals or withdraws anything there. Otherwise
	// model.MeshOriginPanel (a sidecar this run installs or shares).
	Origin    string `json:"origin"`
	MeshAddr  string `json:"mesh_addr,omitempty"`
	MeshIface string `json:"mesh_iface,omitempty"`
	// Install: the host has no Mesh node; this run installs the host-level
	// Linux connector there (Origin MeshOriginPanelHost) after the operator
	// confirmed the install plan.
	Install bool `json:"install,omitempty"`
	// Codename is the release codename the detection read on an Install
	// host (the official source's suite).
	Codename string `json:"codename,omitempty"`
	// Reserved are Meridian's tables, marks and rule priorities on this
	// node (from its compiled files), for the coexistence check of a node
	// the run installs. Filled in by the panel.
	Reserved Reserved `json:"-"`
}

// Existing reports whether the target reuses a host-level Mesh node found
// on the host (never touched by the panel).
func (n NodeTarget) Existing() bool { return n.Origin == model.MeshOriginExisting }

// PanelHost reports whether the target is a host-level node a panel run
// installed earlier (it is reused by this run, and withdrawn with it).
func (n NodeTarget) PanelHost() bool { return n.Origin == model.MeshOriginPanelHost && !n.Install }

// HostNode reports whether the target already is a host-level Mesh node
// with a known address (existing or panel-installed).
func (n NodeTarget) HostNode() bool { return n.MeshAddr != "" && !n.Install }

// Plan is the side-effect-free first stage of a deployment.
type Plan struct {
	Addressing Addressing   `json:"addressing"`
	Legs       []LegPlan    `json:"legs"`
	Nodes      []NodeTarget `json:"nodes"`
	Routes     []RoutePlan  `json:"routes"`
	ReturnV4   []string     `json:"return_v4"`
	ReturnV6   []string     `json:"return_v6"`
	Issues     []Issue      `json:"issues"`
	// Install lists the hosts that get the host-level Linux connector;
	// the deploy request must confirm their install plan (ApplyHostMesh).
	Install []string `json:"install_confirm,omitempty"`
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
//
// Every Mesh node is host-level: an end whose host already is a node
// (Node.MeshHost, found there or installed by an earlier panel run) is
// used as it is; every other end gets the official Linux connector
// (NodeTarget.Install). No sidecar is planned and no route is published.
func BuildPlan(t model.Topology, bundle map[string]string) Plan {
	a := DefaultAddressing()
	p := Plan{Addressing: a, Routes: []RoutePlan{}}
	p.ReturnV4, p.ReturnV6 = ReturnPrefixes(t)

	// Mesh edges join an exit to the primary hub or to the backup hub; both
	// hubs are host-level Mesh ends under the same detect/reuse/install
	// rules. The backup hub joins the plan only when an edge touches it.
	hub, _ := t.PrimaryHub()
	backup, hasBackup := t.BackupHub()
	var links []model.Link
	for _, l := range t.Links {
		if l.Transport == model.TransportCFMesh && l.Enabled {
			links = append(links, l)
		}
	}
	sort.Slice(links, func(i, j int) bool { return links[i].ID < links[j].ID })
	if len(links) == 0 {
		p.Issues = append(p.Issues, Issue{Code: "mesh_no_links", Message: "拓扑里没有启用的 Mesh 边，没有可部署的 Mesh 节点"})
		return p
	}
	if hub.ID == "" {
		p.Issues = append(p.Issues, Issue{Code: "mesh_no_hub", Message: "拓扑里没有枢纽"})
		return p
	}
	addNode := func(n model.Node) {
		if _, ok := p.Node(n.ID); ok {
			return
		}
		if n.Role == model.RoleGateway {
			p.Issues = append(p.Issues, Issue{Code: "mesh_on_gateway", NodeID: n.ID, Message: "网关不运行 Mesh 节点"})
			return
		}
		nt := NodeTarget{ID: n.ID, Name: n.Name, Role: n.Role, SSHHost: n.SSHHost, SSHPort: n.SSHPort, SSHUser: n.SSHUser, Files: map[string]string{}}
		switch h := n.MeshHost; {
		case h != nil && !h.Pending && h.PanelOwned:
			nt.Origin, nt.MeshAddr, nt.MeshIface = model.MeshOriginPanelHost, h.Addr, h.Iface
		case h != nil && !h.Pending:
			// Reused host-level node: nothing is written to this host.
			nt.Origin, nt.MeshAddr, nt.MeshIface = model.MeshOriginExisting, h.Addr, h.Iface
		default:
			nt.Origin, nt.Install = model.MeshOriginPanelHost, true
		}
		p.Nodes = append(p.Nodes, nt)
	}
	_ = bundle
	// The primary hub is planned only when a Mesh edge touches it: a
	// topology whose only Mesh edges start at the backup hub never plans
	// (detects, installs, checks or withdraws) the primary.
	for _, l := range links {
		if l.From == hub.ID || l.To == hub.ID {
			addNode(hub)
			break
		}
	}
	legs := map[string]model.MeshLeg{}
	for _, m := range t.MeshLegs() {
		legs[m.Link.ID] = m
	}
	published := map[string]bool{}
	for _, l := range links {
		var exitID string
		legHub := hub
		switch {
		case l.From == hub.ID:
			exitID = l.To
		case l.To == hub.ID:
			exitID = l.From
		case hasBackup && l.From == backup.ID:
			exitID, legHub = l.To, backup
		case hasBackup && l.To == backup.ID:
			exitID, legHub = l.From, backup
		default:
			p.Issues = append(p.Issues, Issue{Code: "mesh_not_hub_exit", LinkID: l.ID, Message: "Mesh 边必须一端是枢纽"})
			continue
		}
		exit, ok := t.NodeByID(exitID)
		if !ok || exit.Role != model.RoleExit {
			p.Issues = append(p.Issues, Issue{Code: "mesh_not_hub_exit", LinkID: l.ID, Message: "Mesh 边的另一端必须是出口"})
			continue
		}
		if legHub.ID != hub.ID {
			addNode(legHub)
		}
		addNode(exit)
		if len(l.MeshRoutes) > 0 {
			// The structure in which a Mesh node published operator routes
			// and a table's default route pointed at the sidecar.
			p.Issues = append(p.Issues, Issue{Code: "mesh_legacy_routes", LinkID: l.ID, Message: fmt.Sprintf("Mesh 边 %s 还带着 mesh_routes：Mesh 节点不发布任何网段。清空 mesh_routes、保存并重新下发后再部署。", l.ID)})
			continue
		}
		// One leg per hub and exit: the exit's one Mesh address answers
		// both hubs' legs, each on its own interface and port.
		if published[legHub.ID+"|"+exitID] {
			p.Issues = append(p.Issues, Issue{Code: "mesh_route_overlap", LinkID: l.ID, Message: fmt.Sprintf("枢纽 %s 到出口 %s 已有一条 Mesh 腿：同一枢纽到同一出口只有一条 Mesh 腿", legHub.ID, exitID)})
			continue
		}
		published[legHub.ID+"|"+exitID] = true
		leg, ok := legs[l.ID]
		if !ok || !leg.Addr.IsValid() {
			p.Issues = append(p.Issues, Issue{Code: "mesh_underlay_unallocated", LinkID: l.ID, NodeID: exitID, Message: fmt.Sprintf("出口 %s 没有分配到 Mesh 专用地址（地址池不可用或已用完）", exitID)})
			continue
		}
		hubT, _ := p.Node(legHub.ID)
		exitT, _ := p.Node(exitID)
		reuse, network := ReuseBoth, ""
		if exitT.HostNode() {
			network = exitT.MeshAddr + "/32"
		}
		if !hubT.HostNode() || !exitT.HostNode() {
			// The leg is used once both ends are nodes and the hub was
			// re-provisioned with the exit's Mesh address.
			reuse = ReusePending
		}
		slot, allocated := model.EffectiveAllocations(t).LinkSlot(l.ID)
		if !allocated {
			p.Issues = append(p.Issues, Issue{Code: "mesh_leg_unallocated", LinkID: l.ID, Message: "Mesh 腿没有接口分配"})
			continue
		}
		port := l.WGPort
		if port == 0 {
			port = model.LinkDefaultWGPort(slot)
		}
		payload, device := mtu.MeshLeg(model.MeshLegPathMTU(l), 4)
		// The path between the two Mesh addresses is the Cloudflare Mesh
		// path between two host-level nodes.
		p.Legs = append(p.Legs, LegPlan{LinkID: l.ID, HubID: legHub.ID, ExitID: exitID, Network: network, Interface: model.LinkIface(slot), Port: port, PathMTU: model.MeshLegPathMTU(l), DeviceMTU: device, PayloadMTU: payload, Reuse: reuse})
	}
	return p
}

// Kinds of a leg (LegPlan.Reuse).
const (
	// ReuseBoth: both ends are host-level nodes with known Mesh addresses;
	// the hub's WireGuard dials the exit's Mesh address. No route.
	ReuseBoth = "both"
	// ReusePending: an end gets the connector in this run; the leg's
	// checks run in the deployment after the hub and exit were
	// re-provisioned with the new Mesh address.
	ReusePending = "pending"
	// ReuseHub / ReuseExit: legacy (sidecar on the other end); only found
	// in journals of earlier deployments.
	ReuseHub  = "hub"
	ReuseExit = "exit"
)

// OverlayHostMesh returns t with Node.MeshHost set on every end of an
// enabled cf_mesh link whose last detection is a reusable host-level node
// (model.MeshHostOf). Other nodes and topologies without Mesh edges are
// returned unchanged. t's node slice is not modified.
func OverlayHostMesh(t model.Topology, hm map[string]model.HostMeshDetection) model.Topology {
	ends := map[string]bool{}
	for _, l := range t.Links {
		if l.Transport == model.TransportCFMesh && l.Enabled {
			ends[l.From], ends[l.To] = true, true
		}
	}
	if len(ends) == 0 || len(hm) == 0 {
		return t
	}
	nodes := append([]model.Node(nil), t.Nodes...)
	for i := range nodes {
		nodes[i].MeshHost = nil
		if d, ok := hm[nodes[i].ID]; ok && ends[nodes[i].ID] && nodes[i].Role != model.RoleGateway {
			nodes[i].MeshHost = model.MeshHostOf(d)
		}
	}
	t.Nodes = nodes
	return t
}

// ApplyHostMesh checks every host the plan installs the connector on:
// its last detection must be "no node" with a feasible host_connector
// install plan (supported system, the host reaches the official source,
// pinned signing key, memory, no WARP/Meridian conflict), and the operator
// must have confirmed the full install plan (confirm). The same holds when
// both ends of a leg get a connector.
func ApplyHostMesh(p *Plan, hm map[string]model.HostMeshDetection, confirm bool) {
	for i := range p.Nodes {
		n := &p.Nodes[i]
		if !n.Install {
			continue
		}
		id := n.ID
		p.Install = append(p.Install, id)
		d, ok := hm[id]
		n.Codename = d.Codename
		switch {
		case !ok || d.State != model.HostMeshNone || d.Install == nil || len(d.Install.Options) == 0:
			p.Issues = append(p.Issues, Issue{Code: "mesh_install_undetected", NodeID: id, Message: fmt.Sprintf("%s 没有 Mesh 节点，但没有可用的检测结果（应为「没有节点」并附安装计划）；先检测这台主机", id)})
		case d.Install.Recommended != model.InstallHostConnector:
			var bl []string
			for _, o := range d.Install.Options {
				bl = append(bl, o.Blockers...)
			}
			p.Issues = append(p.Issues, Issue{Code: "mesh_install_blocked", NodeID: id, Message: fmt.Sprintf("%s 不能安装主机级 Mesh 节点：%s", id, strings.Join(bl, "；"))})
		case !confirm:
			p.Issues = append(p.Issues, Issue{Code: "mesh_install_confirm_required", NodeID: id, Message: fmt.Sprintf("在 %s 上安装主机级 Mesh 节点（cloudflare-warp connector）需要操作员确认完整安装计划：请求里给出 confirm_install=true", id)})
		}
	}
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
