package api

// Tunnel management address candidates: GET /api/servers/{id}/tunnel-candidates.
//
// For a server whose node has WireGuard tunnels, the addresses the panel
// (on the gateway) can manage it at, derived from the topology and the
// allocation by compile.ManagementCandidates — which tunnel and peer each
// address lives on, whether it depends on the main path or the backup hub,
// and why the others cannot be reached — together with the gateway's
// current carrying state when it can be read. Nothing is contacted; the
// connection test of a candidate is POST /api/servers/{id}/test with
// {"channel": {...}} (ssh_ops.go). See docs/architecture.md「经隧道管理的地址候选」.

import (
	"context"
	"fmt"
	"net/http"
	"net/netip"
	"time"

	"github.com/radowitz/meridian/internal/compile"
	"github.com/radowitz/meridian/internal/credentials"
	"github.com/radowitz/meridian/internal/model"
	"github.com/radowitz/meridian/internal/validate"
)

// mgmtCarry is the gateway's carrying state as one of the derivation's
// states, when it can be read.
type mgmtCarry struct {
	Known bool   `json:"known"`
	State string `json:"state,omitempty"`
	Label string `json:"label,omitempty"`
	Tier  string `json:"tier,omitempty"`
	// Message: why it is not known, or a caveat.
	Message string `json:"message,omitempty"`
}

// mgmtNode is the derivation for one node on the server.
type mgmtNode struct {
	NodeID   string `json:"node_id"`
	NodeName string `json:"node_name"`
	Role     string `json:"role"`
	*compile.MgmtReach
}

// mgmtCurrent judges the server's saved tunnel address.
type mgmtCurrent struct {
	Address string `json:"address"`
	// Derived: the address is one of the candidates.
	Derived bool   `json:"derived"`
	Status  string `json:"status,omitempty"`
	Depends string `json:"depends,omitempty"`
}

type mgmtView struct {
	ServerID string       `json:"server_id"`
	Nodes    []mgmtNode   `json:"nodes"`
	Carrying mgmtCarry    `json:"carrying"`
	Current  *mgmtCurrent `json:"current,omitempty"`
	Message  string       `json:"message,omitempty"`
}

// mgmtCarrying reads which state of states the gateway is in. With a
// backup hub or relay sharing the gateway records the path in use
// (upstream.go); a single hub with one relay records nothing, so the leg
// in use is not known.
func (s *Server) mgmtCarrying(ctx context.Context, t model.Topology, states []compile.MgmtState) mgmtCarry {
	match := func(iface string) mgmtCarry {
		for _, st := range states {
			if st.Iface == iface {
				return mgmtCarry{Known: true, State: st.ID, Label: st.Label, Tier: st.Tier}
			}
		}
		return mgmtCarry{Message: fmt.Sprintf("网关记录的承载接口 %s 不是当前拓扑的承载路径之一：网关可能还没有按当前拓扑安装", orDashS(iface))}
	}
	switch {
	case t.DualHub():
		v := s.carryingHub(ctx, t)
		if !v.Known {
			return mgmtCarry{Message: "读不到网关当前的承载路径：" + orDashS(v.Message)}
		}
		return match(v.Iface)
	case t.RelaySharing():
		if s.Upstream == nil {
			return mgmtCarry{Message: "读不到网关当前的承载路径：没有配置 host agent"}
		}
		cctx, cancel := context.WithTimeout(ctx, statusAgentTimeout)
		defer cancel()
		st, err := s.Upstream.UpstreamStatus(cctx)
		switch {
		case err != nil:
			return mgmtCarry{Message: "读不到网关当前的承载路径：" + err.Error()}
		case !st.Present || st.Record == nil:
			return mgmtCarry{Message: "读不到网关当前的承载路径：网关还没有上游记录"}
		case time.Since(time.Unix(st.Record.Beat, 0)) > upstreamFresh:
			return mgmtCarry{Message: "读不到网关当前的承载路径：网关的上游记录已超过 60 秒没有更新"}
		}
		return match(st.Record.Iface)
	}
	return mgmtCarry{Message: "单枢纽、单中继的网关不记录它在中继的 UDP 腿、WSS 腿和直连枢纽的 WSS 之间用的是哪条：面板读不到当前承载路径"}
}

// mgmtFor derives the candidates of every node on server sv.
func (s *Server) mgmtFor(ctx context.Context, t model.Topology, sv model.Server) (*mgmtView, error) {
	v := &mgmtView{ServerID: sv.ID, Nodes: []mgmtNode{}}
	var states []compile.MgmtState
	for _, n := range t.Nodes {
		if n.ServerID != sv.ID || !n.Managed || n.Role == model.RoleGateway {
			continue
		}
		r, err := compile.ManagementCandidates(t, n.ID)
		if err != nil {
			return nil, err
		}
		states = r.States
		v.Nodes = append(v.Nodes, mgmtNode{NodeID: n.ID, NodeName: n.Name, Role: string(n.Role), MgmtReach: r})
	}
	if len(v.Nodes) == 0 {
		v.Message = "这台服务器还没有关联拓扑里的节点：没有隧道地址可以推导。先在拓扑里为节点选择这台服务器"
		v.Carrying = mgmtCarry{Message: "没有节点，不读取承载路径"}
		return v, nil
	}
	v.Carrying = s.mgmtCarrying(ctx, t, states)
	if sv.Channel.ChannelMode() == model.ChannelTunnel {
		cur := &mgmtCurrent{Address: sv.Channel.Address}
		if c := findCandidate(v.Nodes, sv.Channel.Address); c != nil {
			cur.Derived, cur.Status, cur.Depends = true, c.Status, c.Depends
		}
		v.Current = cur
	}
	return v, nil
}

func findCandidate(nodes []mgmtNode, addr string) *compile.MgmtCandidate {
	a, err := netip.ParseAddr(addr)
	if err != nil {
		return nil
	}
	for _, n := range nodes {
		for i := range n.Candidates {
			if c := &n.Candidates[i]; c.Address == a.String() {
				return c
			}
		}
	}
	return nil
}

func (s *Server) getTunnelCandidates(w http.ResponseWriter, r *http.Request) {
	cs, t, ok := s.resCtx(w)
	if !ok {
		return
	}
	sv, err := cs.Server(r.PathValue("id"))
	if err != nil {
		writeResErr(w, err)
		return
	}
	// The candidates come from the plan the configurations are rendered
	// from (tunnels, addresses, AllowedIPs, routes): a topology that does
	// not validate has none. Validation alone, not the whole bundle: the
	// derivation needs only the plan.
	if res := validate.Run(t); res.HasErrors() {
		refuseInvalid(w, &compile.ValidationError{Result: res})
		return
	}
	v, err := s.mgmtFor(r.Context(), t, sv)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, v)
}

// depText says in words what a candidate depends on.
func depText(d string) string {
	switch d {
	case compile.MgmtDependsOwnLink:
		return "网关自己到这个节点的隧道"
	case compile.MgmtDependsAny:
		return "网关当前承载的任一路径"
	case compile.MgmtDependsMain:
		return "主链路（网关经中继到主枢纽）"
	case compile.MgmtDependsBackup:
		return "备用枢纽（网关直连备用枢纽的 WSS）"
	case compile.MgmtDependsFallback:
		return "网关直连枢纽的 WSS 备路"
	case compile.MgmtDependsMixed:
		return "部分承载路径"
	}
	return "—"
}

// tunnelPathNote explains a failed connection over tunnel address addr of
// server sv against the gateway's current carrying state. It never
// suggests that the panel switches channels by itself.
func (s *Server) tunnelPathNote(ctx context.Context, sv model.Server, addr string) map[string]any {
	t, err := s.topology()
	if err != nil {
		return nil
	}
	v, err := s.mgmtFor(ctx, t, sv)
	if err != nil || len(v.Nodes) == 0 {
		return map[string]any{"text": "这台服务器没有关联拓扑里的节点：面板判断不了这个隧道地址经哪条路径。面板不会自动改走其它管理通道。", "derived": false, "carrying": v.Carrying}
	}
	return tunnelNote(v, addr)
}

func tunnelNote(v *mgmtView, addr string) map[string]any {
	const never = "面板不会自动改走其它管理通道。"
	out := map[string]any{"carrying": v.Carrying, "derived": false}
	c := findCandidate(v.Nodes, addr)
	if c == nil {
		out["text"] = fmt.Sprintf("%s 不是从拓扑推导出的这台服务器的隧道地址（手工填写，未经推导）：面板判断不了它经哪条路径、依赖主链路还是备用枢纽。%s", addr, never)
		return out
	}
	out["derived"], out["status"], out["depends"] = true, c.Status, c.Depends
	works := map[string]bool{}
	for _, w := range c.Works {
		works[w.State] = true
	}
	reasonIn := func(state string) string {
		for _, f := range c.Fails {
			if f.State == state {
				return f.Reason
			}
		}
		return c.Reason
	}
	var text string
	cr := v.Carrying
	switch {
	case c.Status != compile.MgmtUsable:
		text = fmt.Sprintf("按配置推导，%s 从网关到不了：%s", addr, c.Reason)
	case !cr.Known:
		text = fmt.Sprintf("这个地址依赖%s；%s，无法判断失败是不是因为网关切换了承载路径", depText(c.Depends), cr.Message)
	case works[cr.State]:
		text = fmt.Sprintf("网关当前经「%s」承载，按配置推导这个地址在这种状态下两个方向都走得通：失败不是因为承载路径切换（看隧道是否握手、服务器上的 sshd 和防火墙）", cr.Label)
	case c.Depends == compile.MgmtDependsMain && cr.Tier == "backup":
		text = fmt.Sprintf("这个地址依赖%s，而网关现在经备用枢纽承载（%s）：主链路可能不通，经它到不了这个地址。%s", depText(c.Depends), cr.Label, reasonIn(cr.State))
	case c.Depends == compile.MgmtDependsBackup && cr.Tier != "backup":
		text = fmt.Sprintf("这个地址依赖%s，而网关现在经「%s」承载，不经备用枢纽：%s", depText(c.Depends), cr.Label, reasonIn(cr.State))
	default:
		text = fmt.Sprintf("这个地址依赖%s；网关当前经「%s」承载，这种状态下按配置推导到不了它：%s", depText(c.Depends), cr.Label, reasonIn(cr.State))
	}
	out["text"] = text + "。" + never
	return out
}

// tunnelChannelBody is the optional body of the connection test and of the
// host-key discovery: a tunnel channel tried before it is saved.
type tunnelChannelBody struct {
	Channel *model.ManagementChannel `json:"channel"`
}

// candidateChannel reads the optional body; nil when there is none.
func candidateChannel(w http.ResponseWriter, r *http.Request) (*model.ManagementChannel, bool) {
	var body tunnelChannelBody
	if err := decodeStrict(w, r, &body, []string{"channel"}, nil, true); err != nil {
		writeResErr(w, err)
		return nil, false
	}
	if body.Channel == nil {
		return nil, true
	}
	ch, err := credentials.CheckTunnelChannel(*body.Channel)
	if err != nil {
		writeResErr(w, err)
		return nil, false
	}
	return &ch, true
}
