package compile

import (
	"fmt"
	"net/netip"
	"sort"
	"strings"

	"github.com/radowitz/meridian/internal/model"
)

// Tunnel management addresses (docs/architecture.md「经隧道管理的地址候选」).
//
// A server whose management channel is "tunnel" is reached by the panel —
// which runs on the gateway — at one of its node's tunnel addresses. Which
// of those addresses actually work is not a property of the address but of
// the routing on every hop in both directions: the gateway needs a route
// into a tunnel it has, every hop needs a route onward, WireGuard on each
// hop sends a packet only to a destination inside the peer's AllowedIPs and
// accepts one only from a source inside them, the IPv4 reverse-path check
// (rp_filter=2) drops a packet whose source has no route back, and the
// reply has to make the same way home (on a node with return marks, back
// through the tunnel the connection came in on).
//
// ManagementCandidates derives exactly that from the plan the WireGuard
// configurations and the routes scripts are rendered from: the same
// tunnels and addresses (buildTunnels), the same AllowedIPs (allowedIPs),
// and the main-table routes, source rules and return tables that
// renderRoutes writes for each role, for every state the gateway's own
// failover can put its tunnel prefixes in (the main path legs, the
// home-to-hub WSS of a single hub, the backup hub; with relay sharing each
// designated relay). It walks a packet from the gateway to the address and
// the reply back, hop by hop, and says for each address under which
// carrying states both directions work, and why it does not otherwise.
//
// What it does not model: the relays' and hubs' own failover (the static
// install state is assumed: the relay's IX leg, the hub's west tunnel), a
// tunnel that is down, the remote host's own firewall or sshd settings, and
// anything outside Meridian's configuration. A case the walk cannot decide
// (an unmanaged peer, a hop through something that is not a Meridian
// tunnel) is "unknown", never usable. The test of this file checks the walk
// against the rendered files themselves (mgmt_reach_test.go).

// Candidate states.
const (
	MgmtUsable      = "usable"
	MgmtUnreachable = "unreachable"
	MgmtUnknown     = "unknown"
)

// What a usable candidate depends on.
const (
	MgmtDependsOwnLink  = "own_link"   // a tunnel of the gateway itself ends on the node
	MgmtDependsAny      = "any"        // works in every carrying state
	MgmtDependsMain     = "main"       // only while the gateway carries over the main path (relay → IX → primary hub)
	MgmtDependsBackup   = "backup_hub" // only while the gateway carries over the backup hub
	MgmtDependsFallback = "fallback"   // only on the single hub's home-to-hub WSS fallback
	MgmtDependsMixed    = "mixed"      // some of the states, of different kinds
)

// MgmtState is one state of the gateway's tunnel prefixes (10.66.0.0/16
// and fd66::/48 in its main table), as its failover loop sets them.
type MgmtState struct {
	ID    string `json:"id"`
	Label string `json:"label"`
	// Tier: main | backup | fallback.
	Tier  string `json:"tier"`
	Iface string `json:"iface"`
	Hub   string `json:"hub,omitempty"`
}

// MgmtPath is how a candidate is reached in one carrying state.
type MgmtPath struct {
	State string `json:"state"`
	// Source is the gateway's source address toward the candidate.
	Source string `json:"source"`
	// Iface is the gateway's interface the request leaves on.
	Iface string `json:"iface"`
	// Hops: the request's way, "node (iface) → node".
	Hops []string `json:"hops"`
	// ReplyHops: the reply's way back.
	ReplyHops []string `json:"reply_hops"`
	// Static: the gateway's route does not follow the carrying state (a
	// tunnel of the gateway's own, or a host route).
	Static bool `json:"static"`
	// Kind is what the way depends on, by the gateway's tunnel it leaves
	// on: own_link (a tunnel of the gateway ends on the node), main (a leg
	// to a relay: the main path), backup_hub (the gateway's tunnel to the
	// backup hub), fallback (a single hub's home-to-hub WSS).
	Kind string `json:"kind"`
}

// MgmtFailure says why a candidate does not work in one carrying state.
type MgmtFailure struct {
	State   string `json:"state"`
	Reason  string `json:"reason"`
	Unknown bool   `json:"unknown,omitempty"`
}

// MgmtCandidate is one tunnel address of a node.
type MgmtCandidate struct {
	NodeID  string `json:"node_id"`
	Address string `json:"address"`
	// Family: ipv4 | ipv6.
	Family   string `json:"family"`
	LinkID   string `json:"link_id"`
	LinkName string `json:"link_name,omitempty"`
	Iface    string `json:"iface"`
	// Mode of the tunnel the address lives on: udp | wss.
	Mode     string `json:"mode"`
	PeerID   string `json:"peer_id"`
	PeerName string `json:"peer_name,omitempty"`
	Standby  bool   `json:"standby,omitempty"`
	Status   string `json:"status"`
	// Depends (usable only): own_link | any | main | backup_hub | fallback | mixed.
	Depends string        `json:"depends,omitempty"`
	Works   []MgmtPath    `json:"works,omitempty"`
	Fails   []MgmtFailure `json:"fails,omitempty"`
	// Reason: why it is not usable (the failure of the preferred state).
	Reason string `json:"reason,omitempty"`
}

// MgmtReach is the derivation for one node.
type MgmtReach struct {
	NodeID     string          `json:"node_id"`
	States     []MgmtState     `json:"states"`
	Candidates []MgmtCandidate `json:"candidates"`
	// Notes: what the derivation assumes.
	Notes []string `json:"notes"`
}

// mgmtNotes are the assumptions of every derivation.
var mgmtNotes = []string{
	"按安装时的首选链路推导：中继走 IX 腿、枢纽走它的西侧隧道；中继或枢纽自己的切换不在推导里",
	"推导的是 Meridian 自己的路由、AllowedIPs 和反向路径检查；隧道是否真的握手、服务器自己的防火墙和 sshd 是否接受这个来源，推导不了，要靠连接测试",
	"「能用」只说明配置上两个方向都走得通，不是连接测试",
}

// ManagementCandidates derives the tunnel management addresses of node id.
// The topology must compile (the caller validates it).
func ManagementCandidates(t model.Topology, nodeID string) (*MgmtReach, error) {
	n, ok := t.NodeByID(nodeID)
	if !ok {
		return nil, fmt.Errorf("没有节点 %s", nodeID)
	}
	tunnels, err := buildTunnels(t)
	if err != nil {
		return nil, err
	}
	out := &MgmtReach{NodeID: nodeID, States: mgmtStates(t, tunnels), Candidates: []MgmtCandidate{}, Notes: mgmtNotes}
	gw, hasGW := gatewayNode(t)
	if n.Role == model.RoleGateway || !hasGW {
		return out, nil
	}
	nets := map[string]*rNet{}
	for _, st := range out.States {
		nets[st.ID] = planNet(t, tunnels, gw.ID, st)
	}
	backup, _ := t.BackupHub()
	kindOf, own := map[string]string{}, map[string]bool{}
	for _, tun := range tunnelsFor(tunnels, gw.ID) {
		own[tun.Iface()] = tun.East.ID == nodeID
		switch {
		case tun.East.Role == model.RoleRelay:
			kindOf[tun.Iface()] = MgmtDependsMain
		case backup.ID != "" && tun.East.ID == backup.ID:
			kindOf[tun.Iface()] = MgmtDependsBackup
		default:
			kindOf[tun.Iface()] = MgmtDependsFallback
		}
	}
	for _, tun := range tunnelsFor(tunnels, nodeID) {
		peer := tun.West
		v4, ula := tun.EastV4, tun.EastULA
		if tun.West.ID == nodeID {
			peer = tun.East
			v4, ula = tun.WestV4, tun.WestULA
		}
		for _, a := range []string{v4, ula} {
			addr, err := netip.ParseAddr(a)
			if err != nil {
				continue
			}
			c := MgmtCandidate{NodeID: nodeID, Address: addr.String(), Family: "ipv4", LinkID: tun.LinkID, LinkName: tun.Name, Iface: tun.Iface(),
				Mode: tun.Mode, PeerID: peer.ID, PeerName: peer.Name, Standby: tun.Standby}
			if addr.Is6() {
				c.Family = "ipv6"
			}
			for _, st := range out.States {
				r := nets[st.ID].roundTrip(gw.ID, nodeID, tun.Iface(), addr)
				if r.ok {
					// A connected route into a tunnel of the gateway that ends on
					// this node: nothing else carries it. Otherwise the way depends
					// on the kind of the gateway's tunnel it leaves on.
					kind := kindOf[r.gwIface]
					if own[r.gwIface] && r.static && len(r.hops) == 1 {
						kind = MgmtDependsOwnLink
					}
					c.Works = append(c.Works, MgmtPath{State: st.ID, Source: r.src.String(), Iface: r.gwIface, Hops: r.hops, ReplyHops: r.replyHops, Static: r.static, Kind: kind})
				} else {
					c.Fails = append(c.Fails, MgmtFailure{State: st.ID, Reason: r.reason, Unknown: r.unknown})
				}
			}
			classify(&c)
			out.Candidates = append(out.Candidates, c)
		}
	}
	// Usable first, then unknown, then unreachable; otherwise link order.
	rank := map[string]int{MgmtUsable: 0, MgmtUnknown: 1, MgmtUnreachable: 2}
	sort.SliceStable(out.Candidates, func(i, j int) bool {
		a, b := out.Candidates[i], out.Candidates[j]
		if rank[a.Status] != rank[b.Status] {
			return rank[a.Status] < rank[b.Status]
		}
		return false
	})
	if len(out.Candidates) == 0 {
		out.Notes = append(append([]string{}, out.Notes...), "这个节点没有 WireGuard 隧道（外部出口，或还没有接上隧道）：没有可以管理它的隧道地址")
	}
	if len(out.States) == 0 {
		out.Notes = append(append([]string{}, out.Notes...), "网关没有通向中继或枢纽的隧道：经隧道管理不可用")
	}
	return out, nil
}

func gatewayNode(t model.Topology) (model.Node, bool) {
	for _, n := range t.Nodes {
		if n.Role == model.RoleGateway {
			return n, true
		}
	}
	return model.Node{}, false
}

// classify sets Status, Depends and Reason from Works and Fails.
func classify(c *MgmtCandidate) {
	if len(c.Works) == 0 {
		c.Status = MgmtUnreachable
		for _, f := range c.Fails {
			if f.Unknown {
				c.Status = MgmtUnknown
			}
		}
		if len(c.Fails) > 0 {
			c.Reason = c.Fails[0].Reason
		} else {
			c.Status, c.Reason = MgmtUnknown, "网关没有通向中继或枢纽的隧道，无法推导"
		}
		return
	}
	c.Status = MgmtUsable
	kinds := map[string]bool{}
	for _, w := range c.Works {
		kinds[w.Kind] = true
	}
	switch {
	case len(kinds) == 1 && kinds[MgmtDependsOwnLink]:
		c.Depends = MgmtDependsOwnLink
	case len(kinds) == 1 && kinds[MgmtDependsMain]:
		c.Depends = MgmtDependsMain
	case len(kinds) == 1 && kinds[MgmtDependsBackup]:
		c.Depends = MgmtDependsBackup
	case len(kinds) == 1 && kinds[MgmtDependsFallback]:
		c.Depends = MgmtDependsFallback
	case len(c.Fails) == 0:
		c.Depends = MgmtDependsAny
	default:
		c.Depends = MgmtDependsMixed
	}
}

// mgmtStates lists the states of the gateway's tunnel prefixes in the
// order its failover prefers them (the first is the installed one).
func mgmtStates(t model.Topology, tunnels []Tunnel) []MgmtState {
	var out []MgmtState
	primary, _ := t.PrimaryHub()
	if sp := planShare(t, tunnels); sp != nil {
		for _, r := range sp.Relays {
			if len(r.Legs) == 0 {
				continue
			}
			if r.Group == model.RelayGroupBackup {
				out = append(out, MgmtState{ID: "relay:" + r.Node.ID, Label: fmt.Sprintf("备用组，经中继 %s 到备用枢纽", nameOr(r.Node)), Tier: "backup", Iface: r.Legs[0].Iface(), Hub: sp.BackupHub.ID})
				continue
			}
			out = append(out, MgmtState{ID: "relay:" + r.Node.ID, Label: fmt.Sprintf("主链路，经中继 %s 承载", nameOr(r.Node)), Tier: "main", Iface: r.Legs[0].Iface(), Hub: sp.Primary.ID})
		}
		if t.DualHub() {
			for _, p := range planUpstream(t, tunnels).Paths {
				if p.Tier == model.HubBackup {
					out = append(out, MgmtState{ID: "backup", Label: "备用枢纽承载（网关直连备用枢纽的 WSS）", Tier: "backup", Iface: p.Iface, Hub: p.Hub})
				}
			}
		}
		return out
	}
	if t.DualHub() {
		for _, p := range planUpstream(t, tunnels).Paths {
			if p.Iface == "" {
				continue
			}
			s := MgmtState{ID: p.Name, Tier: "main", Iface: p.Iface, Hub: p.Hub}
			switch {
			case p.Tier == model.HubBackup:
				s.Tier, s.Label = "backup", "备用枢纽承载（网关直连备用枢纽的 WSS）"
			case p.Name == "wss":
				s.Label = "主链路，网关到中继走 WSS 腿"
			default:
				s.Label = "主链路，网关到中继走 UDP 腿"
			}
			out = append(out, s)
		}
		return out
	}
	udp, wss, direct := gatewayIfaces(tunnels)
	if udp.LinkID != "" {
		out = append(out, MgmtState{ID: "udp", Label: "主链路，网关到中继走 UDP 腿", Tier: "main", Iface: udp.Iface(), Hub: primary.ID})
	}
	if wss.LinkID != "" {
		out = append(out, MgmtState{ID: "wss", Label: "主链路，网关到中继走 WSS 腿", Tier: "main", Iface: wss.Iface(), Hub: primary.ID})
	}
	if direct.LinkID != "" {
		out = append(out, MgmtState{ID: "direct", Label: "备路：网关直连枢纽的 WSS", Tier: "fallback", Iface: direct.Iface(), Hub: direct.East.ID})
	}
	return out
}

func nameOr(n model.Node) string {
	if n.Name != "" {
		return n.Name
	}
	return n.ID
}

// ----------------------------------------------------------------- network ---

// rRoute is one route of a table. blackhole routes have no dev.
type rRoute struct {
	dst       netip.Prefix
	dev       string
	src       netip.Addr
	metric    int
	blackhole bool
}

// rRule is a source rule ("from P lookup T").
type rRule struct {
	from  netip.Prefix
	table int
	prio  int
}

type rIface struct {
	name, peer, link string
	addrs            []netip.Prefix
	allowed          []netip.Prefix
}

type rNode struct {
	id     string
	fwd6   bool
	ifaces map[string]*rIface
	main   []rRoute
	rules  []rRule
	tables map[int][]rRoute
	// ret: the reply table of a connection that arrived on an interface
	// (connection mark restored on every reply packet).
	ret   map[string][]rRoute
	local []netip.Addr
}

// rNet is the routing of every managed node in one carrying state.
type rNet struct {
	nodes map[string]*rNode
}

func newRNode(id string) *rNode {
	return &rNode{id: id, ifaces: map[string]*rIface{}, tables: map[int][]rRoute{}, ret: map[string][]rRoute{}}
}

func mustPrefix(s string) (netip.Prefix, bool) {
	if !strings.Contains(s, "/") {
		a, err := netip.ParseAddr(s)
		if err != nil {
			return netip.Prefix{}, false
		}
		return netip.PrefixFrom(a, a.BitLen()), true
	}
	p, err := netip.ParsePrefix(s)
	if err != nil {
		return netip.Prefix{}, false
	}
	return p, true
}

func (n *rNode) add(table *[]rRoute, dst, dev string) {
	if p, ok := mustPrefix(dst); ok && dev != "" {
		*table = append(*table, rRoute{dst: p.Masked(), dev: dev})
	}
}

func (n *rNode) hole(table *[]rRoute, dst string) {
	if p, ok := mustPrefix(dst); ok {
		*table = append(*table, rRoute{dst: p.Masked(), blackhole: true, metric: 32767})
	}
}

// addIface adds a tunnel interface with its addresses (the connected
// routes follow from them) and its peer's AllowedIPs.
func (n *rNode) addIface(name, peer, link string, addrs []string, allowed string) {
	ifc := &rIface{name: name, peer: peer, link: link}
	for _, a := range addrs {
		if p, ok := mustPrefix(strings.TrimSpace(a)); ok {
			ifc.addrs = append(ifc.addrs, p)
			n.local = append(n.local, p.Addr())
		}
	}
	for _, a := range strings.Split(allowed, ",") {
		if p, ok := mustPrefix(strings.TrimSpace(a)); ok {
			ifc.allowed = append(ifc.allowed, p.Masked())
		}
	}
	n.ifaces[name] = ifc
}

// connected adds the prefix routes of the interface addresses (a /32 or
// /128 address has none).
func (n *rNode) connected() {
	names := make([]string, 0, len(n.ifaces))
	for k := range n.ifaces {
		names = append(names, k)
	}
	sort.Strings(names)
	for _, k := range names {
		for _, a := range n.ifaces[k].addrs {
			if a.Bits() < a.Addr().BitLen() {
				n.main = append(n.main, rRoute{dst: a.Masked(), dev: k})
			}
		}
	}
}

func (n *rNode) isLocal(a netip.Addr) bool {
	for _, l := range n.local {
		if l == a {
			return true
		}
	}
	return false
}

// best is the longest-prefix match of a table, lowest metric among equals.
func best(table []rRoute, dst netip.Addr) (rRoute, bool) {
	var found rRoute
	ok := false
	for _, r := range table {
		if r.dst.Addr().Is4() != dst.Is4() || !r.dst.Contains(dst) {
			continue
		}
		if !ok || r.dst.Bits() > found.dst.Bits() || (r.dst.Bits() == found.dst.Bits() && r.metric < found.metric) {
			found, ok = r, true
		}
	}
	return found, ok
}

// lookup is the policy routing of one packet: the reply table of the
// connection's ingress interface (when the node marks it), then the
// source rules by priority, then the main table.
func (n *rNode) lookup(dst, src netip.Addr, ingress string) (rRoute, bool) {
	if ingress != "" {
		if t, ok := n.ret[ingress]; ok {
			return best(t, dst)
		}
	}
	rules := append([]rRule(nil), n.rules...)
	sort.SliceStable(rules, func(i, j int) bool { return rules[i].prio < rules[j].prio })
	for _, r := range rules {
		if !src.IsValid() || r.from.Addr().Is4() != src.Is4() || !r.from.Contains(src) {
			continue
		}
		if rt, ok := best(n.tables[r.table], dst); ok {
			return rt, true
		}
	}
	return best(n.main, dst)
}

func containsAny(ps []netip.Prefix, a netip.Addr) bool {
	for _, p := range ps {
		if p.Addr().Is4() == a.Is4() && p.Contains(a) {
			return true
		}
	}
	return false
}

func (ifc *rIface) addrOf(v4 bool) netip.Addr {
	for _, a := range ifc.addrs {
		if a.Addr().Is4() == v4 {
			return a.Addr()
		}
	}
	return netip.Addr{}
}

// walkResult is one round trip.
type walkResult struct {
	ok, unknown     bool
	reason          string
	src             netip.Addr
	gwIface         string
	static          bool
	hops, replyHops []string
	target          string
}

// walk sends one packet from node `from` (ingress "": originated there)
// toward dst with source src (invalid: chosen at the first hop). in maps
// node → the interface the request arrived on (the reply direction uses
// it for the return tables); arrived records it for the request.
func (w *rNet) walk(from string, src, dst netip.Addr, reply bool, in map[string]string, res *walkResult) (target string, usedSrc netip.Addr, hops []string, ok bool) {
	cur, ingress := from, ""
	dir := "去程"
	if reply {
		dir = "回程"
	}
	visited := map[string]bool{}
	for i := 0; i < 16; i++ {
		if visited[cur] {
			res.reason = fmt.Sprintf("%s：%s 没有比 %s 更具体的路由，包又回到了 %s（路由成环），到不了终点", dir, strings.Join(hopNodes(hops), "、"), "隧道总前缀", cur)
			return "", src, hops, false
		}
		visited[cur] = true
		n := w.nodes[cur]
		if n == nil {
			res.unknown = true
			res.reason = fmt.Sprintf("%s：%s 不是受管节点，面板不知道它的配置", dir, cur)
			return "", src, hops, false
		}
		if n.isLocal(dst) {
			return cur, src, hops, true
		}
		if ingress != "" && dst.Is6() && !n.fwd6 {
			res.reason = fmt.Sprintf("%s：%s 不转发 IPv6（它没有 IPv6 出口，也不中转 IPv6）", dir, cur)
			return "", src, hops, false
		}
		retKey := ""
		if reply {
			retKey = in[cur]
		}
		r, found := n.lookup(dst, src, retKey)
		if !found {
			res.reason = fmt.Sprintf("%s：%s 没有到 %s 的路由", dir, cur, dst)
			return "", src, hops, false
		}
		if r.blackhole {
			res.reason = fmt.Sprintf("%s：%s 上到 %s 的路由是黑洞（%s），包被丢弃", dir, cur, dst, r.dst)
			return "", src, hops, false
		}
		ifc := n.ifaces[r.dev]
		if ifc == nil {
			res.unknown = true
			res.reason = fmt.Sprintf("%s：%s 把 %s 交给 %s，它不是 Meridian 的隧道，推导不了", dir, cur, dst, r.dev)
			return "", src, hops, false
		}
		if !src.IsValid() {
			src = r.src
			if !src.IsValid() {
				src = ifc.addrOf(dst.Is4())
			}
			if !src.IsValid() {
				res.reason = fmt.Sprintf("%s：%s 在 %s 上没有这个地址族的地址", dir, cur, r.dev)
				return "", src, hops, false
			}
			if !reply {
				res.gwIface = r.dev
				res.static = r.dst.Bits() > 16 && !(r.dst.Addr().Is6() && r.dst.Bits() == 48)
			}
		}
		if !containsAny(ifc.allowed, dst) {
			res.reason = fmt.Sprintf("%s：%s 在链路 %s（%s）上对 %s 的 AllowedIPs 不包含目的地址 %s，WireGuard 不会把它发出去", dir, cur, ifc.link, ifc.name, ifc.peer, dst)
			return "", src, hops, false
		}
		p := w.nodes[ifc.peer]
		if p == nil {
			res.unknown = true
			res.reason = fmt.Sprintf("%s：隧道对端 %s 不是受管节点，面板不知道它的配置", dir, ifc.peer)
			return "", src, hops, false
		}
		pif := p.ifaces[ifc.name]
		if pif == nil {
			res.unknown = true
			res.reason = fmt.Sprintf("%s：%s 上没有隧道 %s 的另一端", dir, ifc.peer, ifc.name)
			return "", src, hops, false
		}
		if !containsAny(pif.allowed, src) {
			if reply {
				res.reason = fmt.Sprintf("%s：%s 在链路 %s 上对 %s 的 AllowedIPs 不包含应答的源地址 %s，应答被丢弃", dir, ifc.peer, ifc.link, cur, src)
			} else {
				res.reason = fmt.Sprintf("%s：%s 在链路 %s 上对 %s 的 AllowedIPs 不包含网关的源地址 %s，包被丢弃", dir, ifc.peer, ifc.link, cur, src)
			}
			return "", src, hops, false
		}
		if src.Is4() {
			if back, ok := p.lookup(src, dst, ""); !ok || back.blackhole {
				res.reason = fmt.Sprintf("%s：%s 的反向路径检查（rp_filter=2）找不到回到源地址 %s 的路由（落到黑洞），包被丢弃", dir, ifc.peer, src)
				return "", src, hops, false
			}
		}
		hops = append(hops, fmt.Sprintf("%s（%s）→ %s", cur, ifc.name, ifc.peer))
		if !reply && in != nil {
			in[p.id] = ifc.name
		}
		cur, ingress = p.id, ifc.name
	}
	res.reason = fmt.Sprintf("%s：经过的节点太多，包回不到终点", dir)
	return "", src, hops, false
}

// hopNodes are the nodes a walk forwarded through, in order, once each.
func hopNodes(hops []string) []string {
	var out []string
	seen := map[string]bool{}
	for _, h := range hops {
		n := h
		if i := strings.Index(h, "（"); i >= 0 {
			n = h[:i]
		}
		if !seen[n] {
			seen[n] = true
			out = append(out, n)
		}
	}
	return out
}

// roundTrip: the gateway's request to dst (an address of node on its
// interface iface) and the reply. When the request does not get there, the
// reply is still walked from the node (as if the request had arrived on
// iface) so that every reason that blocks the address is named.
func (w *rNet) roundTrip(gw, node, iface string, dst netip.Addr) walkResult {
	var res walkResult
	in := map[string]string{}
	target, src, hops, ok := w.walk(gw, netip.Addr{}, dst, false, in, &res)
	res.src, res.hops = src, hops
	if !ok {
		if src.IsValid() && !res.unknown {
			if _, seen := in[node]; !seen {
				in[node] = iface
			}
			var back walkResult
			if _, _, _, rok := w.walk(node, dst, src, true, in, &back); !rok && back.reason != "" {
				res.reason += "；" + back.reason
			}
		}
		return res
	}
	res.target = target
	// The reply: from the address the node was asked on, to the gateway's
	// source, starting on the node itself.
	back, _, rhops, ok := w.walk(target, dst, src, true, in, &res)
	res.replyHops = rhops
	if !ok {
		return res
	}
	if back != gw {
		res.reason = fmt.Sprintf("回程：应答到了 %s，不是网关", back)
		return res
	}
	res.ok = true
	return res
}

// ------------------------------------------------------------- the model ---

// planNet builds every managed node's routing in carrying state st, as
// renderRoutes writes it (main table, source rules, return tables) and as
// renderWG writes the tunnels.
func planNet(t model.Topology, tunnels []Tunnel, gw string, st MgmtState) *rNet {
	w := &rNet{nodes: map[string]*rNode{}}
	for _, n := range managedNodes(t) {
		rn := newRNode(n.ID)
		rn.fwd6 = n.Role != model.RoleExit || forwards6In(t, n)
		for _, tun := range tunnelsFor(tunnels, n.ID) {
			west := tun.West.ID == n.ID
			self4, peer4, selfULA, peer := tun.EastV4, tun.WestV4, tun.EastULA, tun.West.ID
			if west {
				self4, peer4, selfULA, peer = tun.WestV4, tun.EastV4, tun.WestULA, tun.East.ID
			}
			local, _ := v4PairPrefix(self4, peer4)
			rn.addIface(tun.Iface(), peer, tun.LinkID, []string{local, selfULA + "/64"}, allowedIPs(t, tun, west))
		}
		rn.connected()
		switch n.Role {
		case model.RoleGateway:
			gatewayRoutes(rn, t, tunnels, st)
		case model.RoleRelay:
			relayRoutes(rn, t, n, tunnels)
		case model.RoleHub:
			hubRoutes(rn, t, n, tunnels)
		case model.RoleExit:
			exitRoutes(rn, t, n, tunnels)
		}
		w.nodes[n.ID] = rn
	}
	return w
}

func prefixHoles(n *rNode, t model.Topology) {
	n.hole(&n.main, lanNet(t))
	n.hole(&n.main, transitV4Net())
	n.hole(&n.main, "10.66.0.0/16")
	n.hole(&n.main, "fd66::/48")
	n.hole(&n.main, transitV6Net())
	if t.Settings.LANIPv6Prefix != "" {
		n.hole(&n.main, t.Settings.LANIPv6Prefix)
	}
}

// homeTable is a return table: the home prefixes on iface, blackhole
// otherwise (renderIngressReturnRoutes, renderExitHubReturnRoutes).
func homeTable(n *rNode, t model.Topology, iface string) []rRoute {
	var tb []rRoute
	n.add(&tb, lanNet(t), iface)
	n.add(&tb, "10.66.0.0/16", iface)
	n.add(&tb, "fd66::/48", iface)
	if t.Settings.LANIPv6Prefix != "" {
		n.add(&tb, t.Settings.LANIPv6Prefix, iface)
	}
	n.hole(&tb, "0.0.0.0/0")
	n.hole(&tb, "::/0")
	return tb
}

func gatewayRoutes(n *rNode, t model.Topology, tunnels []Tunnel, st MgmtState) {
	metric := 10
	probeRoute := func(probe, iface string) {
		if p, ok := mustPrefix(probe); ok && iface != "" {
			src, _ := netip.ParseAddr(upstreamProbeSrc)
			n.main = append(n.main, rRoute{dst: p, dev: iface, src: src, metric: metric})
			metric++
		}
	}
	if sp := planShare(t, tunnels); sp != nil {
		for _, r := range sp.Relays {
			for _, l := range r.Legs {
				probeRoute(r.Probe, l.Iface())
			}
		}
		n.local = append(n.local, netip.MustParseAddr(upstreamProbeSrc))
	} else if t.DualHub() {
		for _, u := range planUpstream(t, tunnels).Paths {
			if u.ProbeVia && u.Probe != "" && u.Iface != "" {
				probeRoute(u.Probe, u.Iface)
			}
		}
		n.local = append(n.local, netip.MustParseAddr(upstreamProbeSrc))
	}
	if st.Iface != "" {
		n.add(&n.main, "10.66.0.0/16", st.Iface)
		n.add(&n.main, "fd66::/48", st.Iface)
	}
	n.hole(&n.main, "10.66.0.0/16")
	n.hole(&n.main, "fd66::/48")
}

func relayRoutes(n *rNode, t model.Topology, node model.Node, tunnels []Tunnel) {
	westUDP, westWSS, eastIX, eastWSS := relayIfaces(tunnelsFor(tunnels, node.ID))
	preferred := eastIX
	if t.Settings.IXReplacementMode && eastWSS.Iface() != "" {
		preferred = eastWSS
	}
	west := westUDP
	if west.Iface() == "" {
		west = westWSS
	}
	if legs := relayWestLegs(tunnels, node.ID); t.RelaySharing() && west.Iface() == "" && len(legs) > 0 {
		west = legs[0]
	}
	w, p := west.Iface(), preferred.Iface()
	n.add(&n.main, lanNet(t), w)
	n.add(&n.main, transitV4Net(), w)
	if t.Settings.LANIPv6Prefix != "" {
		n.add(&n.main, t.Settings.LANIPv6Prefix, w)
	}
	n.add(&n.main, transitV6Net(), w)
	n.add(&n.main, "fd66::/48", p)
	prefixHoles(n, t)
	tb := []rRoute{}
	n.add(&tb, "0.0.0.0/0", p)
	n.add(&tb, lanNet(t), w)
	n.add(&tb, transitV4Net(), w)
	n.add(&tb, "::/0", p)
	if t.Settings.LANIPv6Prefix != "" {
		n.add(&tb, t.Settings.LANIPv6Prefix, w)
	}
	n.add(&tb, transitV6Net(), w)
	n.hole(&tb, "0.0.0.0/0")
	n.hole(&tb, "::/0")
	n.tables[150] = tb
	addRule := func(from string, prio int) {
		if p, ok := mustPrefix(from); ok {
			n.rules = append(n.rules, rRule{from: p.Masked(), table: 150, prio: prio})
		}
	}
	addRule(lanNet(t), prioRelayFrom)
	addRule(transitV4Net(), prioRelayFrom+1)
	if t.Settings.LANIPv6Prefix != "" {
		addRule(t.Settings.LANIPv6Prefix, prioRelayFrom)
	}
	addRule(transitV6Net(), prioRelayFrom+1)
	for _, r := range ingressReturns(t, node, tunnels) {
		n.ret[r.Iface] = homeTable(n, t, r.Iface)
	}
}

func hubRoutes(n *rNode, t model.Topology, node model.Node, tunnels []Tunnel) {
	west := hubWestTunnel(tunnels, node.ID, t.Settings.IXReplacementMode).Iface()
	n.add(&n.main, lanNet(t), west)
	n.add(&n.main, transitV4Net(), west)
	if t.Settings.LANIPv6Prefix != "" {
		n.add(&n.main, t.Settings.LANIPv6Prefix, west)
	}
	n.add(&n.main, transitV6Net(), west)
	n.add(&n.main, "10.66.0.0/16", west)
	n.add(&n.main, "fd66::/48", west)
	prefixHoles(n, t)
	for _, e := range planExitsHub(t, tunnels, node.ID) {
		if e.HubIface == "" {
			continue
		}
		if e.ViaRelay != "" || e.sharedHop() {
			if e.PeerV4 != "" {
				n.add(&n.main, e.PeerV4+"/32", e.HubIface)
				n.hole(&n.main, e.PeerV4+"/32")
			}
			if e.PeerULA != "" {
				n.add(&n.main, e.PeerULA+"/128", e.HubIface)
				n.hole(&n.main, e.PeerULA+"/128")
			}
		}
		if t.DualHub() && e.ViaRelay == "" {
			n.add(&n.main, e.Resolver+"/128", e.HubIface)
			n.hole(&n.main, e.Resolver+"/128")
		}
	}
	for _, r := range ingressReturns(t, node, tunnels) {
		n.ret[r.Iface] = homeTable(n, t, r.Iface)
	}
}

func exitRoutes(n *rNode, t model.Topology, node model.Node, tunnels []Tunnel) {
	tun := exitIngress(node, tunnels, primaryHubID(t))
	if tun.Iface() == "" {
		prefixHoles(n, t)
		return
	}
	i := tun.Iface()
	n.add(&n.main, lanNet(t), i)
	n.add(&n.main, transitV4Net(), i)
	if t.Settings.LANIPv6Prefix != "" {
		n.add(&n.main, t.Settings.LANIPv6Prefix, i)
	}
	n.add(&n.main, transitV6Net(), i)
	n.add(&n.main, "fd66::/48", i)
	if model.IsNested(node) {
		n.add(&n.main, "10.66.0.0/16", i)
	}
	prefixHoles(n, t)
	for _, r := range exitHubReturns(t, node, tunnels) {
		n.ret[r.Iface] = homeTable(n, t, r.Iface)
	}
	// A relay exit's main-table routes toward its nested exits' resolver
	// addresses (renderRelayExitRoutes); not tunnel addresses, kept for
	// completeness.
	if t.DualHub() {
		exits := planExits(t, tunnels)
		for _, e := range exits {
			if e.Nested != node.ID {
				continue
			}
			down := nestedTunnel(e.Node, tunnels)
			if down.Iface() != "" {
				n.add(&n.main, e.Resolver+"/128", down.Iface())
				n.hole(&n.main, e.Resolver+"/128")
			}
		}
	}
}
