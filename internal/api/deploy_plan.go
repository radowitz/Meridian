package api

// The ordered deployment guide: GET /api/deploy and POST /api/deploy/runs….
//
// It replaces "click preflight and install on fourteen nodes in the right
// order by hand, then find the affected nodes again after every topology
// change". It adds no capability: every step is the existing single-node
// flow, called in-process —
//
//   - a remote node: POST /api/provision/preflight, then POST
//     /api/provision with the reviewed preflight_id (same credentials,
//     pinned host key, management channel, pooled login, install
//     transaction with compensation, host-record read-back);
//   - the gateway: POST /api/host/preflight, then the install of POST
//     /api/apply {install:true} (meridian-host's fixed actions, the host
//     transaction with compensation and health checks), with the gateway
//     node lock held across the preflight re-run and the install.
//
// What the guide adds is the plan (which nodes need an install, in which
// order and why), the binding of every confirmation to what was reviewed,
// and a stored run that survives a page reload and a panel restart.
//
// Plan. The nodes whose own install state (node_state.go) is not in sync,
// ordered by distance from the gateway, farthest first: nested exits →
// exits (relay exits, carriers of external SOCKS exits) → backup hub →
// primary hub → IX → relays → gateway. Management channels add
// constraints (a node managed through another node of the plan goes
// before it). Nodes without changes, external SOCKS exits and unmanaged
// hops get no step and are listed as skipped. See deployOrder.
//
// Run. One at a time (a second one is refused while one is active or
// stopped). Only the current step — the first one not done — can be acted
// on, and nothing is installed without the operator's confirmation of
// that node's reviewed preflight (there is no "confirm all"; see
// docs/architecture.md「按顺序部署引导」). A failure, a compensation or an
// unknown outcome stops the run at that node; nodes already done stay
// done. The next action on a stopped node is a fresh preflight, which
// reads the node's actual install record (remote: the host's manifest and
// journal; gateway: the installed manifest): content that is already
// there is adopted, never installed again.
//
// Binding. A run is bound to the topology version (a hash of the stored
// topology without node positions, private keys and the independent
// remote-access block); a reviewed step to the digest of the node's files
// and the server identity (address, port, user, pinned fingerprint,
// credential) its preflight ran against. Any difference refuses the
// install and says why; a changed topology needs an explicit re-plan that
// keeps what is still valid.
//
// Restart. A step's in-flight phase carries the panel process's boot id; a
// stored in-flight step from another boot is an interrupted step: an
// interrupted preflight (read-only) goes back to pending, an interrupted
// install becomes unknown — never done.

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/radowitz/meridian/internal/compile"
	"github.com/radowitz/meridian/internal/credentials"
	"github.com/radowitz/meridian/internal/hostexec"
	"github.com/radowitz/meridian/internal/model"
	"github.com/radowitz/meridian/internal/preflight"
	"github.com/radowitz/meridian/internal/provision"
	"github.com/radowitz/meridian/internal/sshexec"
)

const (
	deployRunKey = "deploy_run"

	codeDeployRunActive   = "deploy_run_active"
	codeDeployRunClosed   = "deploy_run_closed"
	codeDeployStepRunning = "deploy_step_running"
	codeDeployNotCurrent  = "deploy_step_not_current"
	codeDeployPlanStale   = "deploy_plan_stale"
	codeDeployWait        = "deploy_wait"
	codeDeployNotReviewed = "deploy_not_reviewed"
	codeDeployInvalidated = "deploy_confirmation_invalid"
	codeDeployNothing     = "deploy_nothing_to_do"

	// Run states.
	runActive    = "active"
	runStopped   = "stopped"
	runDone      = "done"
	runCancelled = "cancelled"

	// Step phases.
	phasePending    = "pending"      // needs a preflight
	phasePreflight  = "preflighting" // preflight in flight
	phaseReview     = "review"       // reviewed preflight without blocking findings: awaits the operator's confirmation
	phaseBlocked    = "blocked"      // the preflight has blocking findings
	phaseInstalling = "installing"   // install in flight
	phaseDone       = "done"
	phaseFailed     = "failed"  // refused, compensated or left behind after the script / transaction ran
	phaseUnknown    = "unknown" // the outcome is not known (lost, interrupted, record mismatch): never done

	deployStepTimeout = 20 * time.Minute
	maxDeployEvents   = 100
)

// deployLimits says what a finished step proves and what it does not.
var deployLimits = struct {
	Proves       []string `json:"proves"`
	DoesNotProve []string `json:"does_not_prove"`
	Independent  []string `json:"independent"`
}{
	Proves: []string{
		"在这次运行中实际安装的网关：meridian-host 的安装事务已提交——文件写入、接口与防火墙激活、服务启动，事务里的健康检查通过",
		"在这次运行中实际下发的远端节点：装机脚本完成激活并写下清单，面板在同一登录里读回服务器上的记录，与装上去的内容一致（读回失败、不完整或不一致时这一步是「结果不明」，不算装好）",
		"「已在服务器上（采纳）」：预检完整读到的服务器记录（网关是安装清单）已经是这份内容；没有重新执行，也没有重新检查健康——服务现在是否在运行没有核实",
	},
	DoesNotProve: []string{
		"隧道真的握手、流量真的经出口出去（端到端连通）",
		"分流结果、DNS / IPv6 / WebRTC 不泄漏（「防泄露」页的验收要实际执行才算）",
		"流媒体与 AI 服务的解锁（「解锁」页的探测）",
		"远程接入的设备能从外网拨入",
	},
	Independent: []string{
		"远程接入（开关与设备）是独立资源：保存拓扑、本引导的任何一步都不会打开、关闭或修改它；它的改动随网关的安装生效",
		"Cloudflare Mesh 备路的部署和撤回在 Cloudflare 页，不在本引导里",
	},
}

// ------------------------------------------------------------------ plan ---

// orderedStep is one node of the computed order.
type orderedStep struct {
	ID       string
	Tier     int
	Reason   string
	Warnings []string
}

// Tiers: farther from the gateway first.
const (
	tierNested = iota
	tierExit
	tierBackupHub
	tierPrimaryHub
	tierIX
	tierRelay
	tierGateway
)

func deployTier(t model.Topology, n model.Node) int {
	switch n.Role {
	case model.RoleGateway:
		return tierGateway
	case model.RoleRelay:
		return tierRelay
	case model.RoleIX:
		return tierIX
	case model.RoleHub:
		if t.EffectiveHubTier(n) == model.HubBackup {
			return tierBackupHub
		}
		return tierPrimaryHub
	case model.RoleExit:
		if model.IsNested(n) {
			return tierNested
		}
		return tierExit
	}
	return tierPrimaryHub
}

func nodeLabel(t model.Topology, id string) string {
	if n, ok := t.NodeByID(id); ok && n.Name != "" {
		return n.Name
	}
	return id
}

func joinLabels(t model.Topology, ids []string) string {
	out := make([]string, 0, len(ids))
	for _, id := range ids {
		out = append(out, nodeLabel(t, id))
	}
	return strings.Join(out, "、")
}

// tierReason explains a node's place in the base order.
func tierReason(t model.Topology, n model.Node, pending map[string]bool) string {
	switch deployTier(t, n) {
	case tierNested:
		r := nodeLabel(t, n.ViaExit)
		return fmt.Sprintf("挂在中继出口 %s 后面：最远的一端先装，%s 装好时它要转发的那一端已经是新配置", r, r)
	case tierExit:
		var b strings.Builder
		if nested := model.NestedExitsOf(t, n.ID); len(nested) > 0 {
			ids := make([]string, 0, len(nested))
			for _, x := range nested {
				ids = append(ids, x.ID)
			}
			fmt.Fprintf(&b, "中继出口（转发 %s）：在挂在它后面的出口之后、枢纽之前", joinLabels(t, ids))
		} else {
			b.WriteString("出口：先于枢纽、中继和网关——网关的地区组解析经组的隧道地址到出口，只有已经装了新配置的出口才会应答")
		}
		if ext := model.ExternalExitsOf(t, n.ID); len(ext) > 0 {
			ids := make([]string, 0, len(ext))
			for _, x := range ext {
				ids = append(ids, x.ID)
			}
			fmt.Fprintf(&b, "；承载外部 SOCKS 出口 %s（它们没有自己的装机步骤，相关配置随这台下发）", joinLabels(t, ids))
		}
		return b.String()
	case tierBackupHub:
		return "备用枢纽：在出口之后、主枢纽之前——主枢纽重装出问题、主链路整体失败时，接管的备用枢纽已经是新配置"
	case tierPrimaryHub:
		if model.IsIXHub(n) {
			return "主枢纽（IX 线路上的受管服务器）：在出口和备用枢纽之后、中继之前"
		}
		return "主枢纽：在出口和备用枢纽之后、中继之前"
	case tierIX:
		return "IX：在枢纽之后、中继之前"
	case tierRelay:
		relays := 0
		for _, o := range t.Nodes {
			if o.Role == model.RoleRelay && o.Managed && pending[o.ID] {
				relays++
			}
		}
		if relays > 1 {
			return fmt.Sprintf("国内中继：在枢纽之后、网关之前；这次有 %d 台中继要装，一台一台进行——正在重装的那台由分担的健康检查剔除，其余中继照常承载", relays)
		}
		return "国内中继：在枢纽之后、网关之前"
	case tierGateway:
		return "网关最后：它的配置要用到每个对端的公钥；路由到可切换地区组的名字经组的隧道地址解析，只有出口装好新配置后才会应答"
	}
	return ""
}

// deployOrder orders the pending managed nodes (pending: node ID → true).
// servers are the managed servers by ID; gwInstalled says whether the
// gateway has an install (a tunnel management channel needs it). It is
// pure: no host is contacted, nothing is stored.
//
// Management channels (model.ManagementChannel) add "A before B" edges:
//
//   - jump through the server of node M: the node goes before M, so it is
//     installed while M still runs the configuration that was proven to
//     carry the jump; M's own reinstall restarts its tunnels and services
//     (not its sshd), and once M is done nothing else in the run needs
//     the jump;
//   - a direct channel whose address is node M's public endpoint on
//     another port (a TCP port-forward on M's host, as the IX reached
//     through a relay): the node goes before M, for the same reason;
//   - a tunnel channel depends on the gateway and every hop to the node,
//     which the base order already puts after it; the node's own install
//     restarts the tunnel carrying the SSH session, which can cut the
//     session mid-install (warned; the outcome would then be unknown and
//     the run stops there).
//
// Edges win over the base tiers; ties are broken by tier, then ID. A cycle
// (contradicting channels) falls back to the base order with a note.
func deployOrder(t model.Topology, servers map[string]model.Server, pending map[string]bool, gwInstalled bool) ([]orderedStep, []string) {
	var ids []string
	for _, n := range t.Nodes {
		if n.Managed && pending[n.ID] && !model.IsExternal(n) {
			ids = append(ids, n.ID)
		}
	}
	sort.Strings(ids)
	steps := map[string]*orderedStep{}
	for _, id := range ids {
		n, _ := t.NodeByID(id)
		steps[id] = &orderedStep{ID: id, Tier: deployTier(t, n), Reason: tierReason(t, n, pending)}
	}
	serverNode := map[string]string{}
	for _, n := range t.Nodes {
		if n.ServerID != "" {
			serverNode[n.ServerID] = n.ID
		}
	}
	before := map[string]map[string]bool{} // a → set of b: a before b
	edge := func(a, b string) {
		if before[a] == nil {
			before[a] = map[string]bool{}
		}
		before[a][b] = true
	}
	var notes []string
	for _, id := range ids {
		n, _ := t.NodeByID(id)
		st := steps[id]
		if n.Role == model.RoleGateway {
			continue
		}
		if n.ServerID == "" {
			st.Warnings = append(st.Warnings, "这个节点还没有选择服务器：在拓扑里为它选择服务器后才能预检")
			continue
		}
		sv, ok := servers[n.ServerID]
		if !ok {
			st.Warnings = append(st.Warnings, "这个节点引用的服务器不存在")
			continue
		}
		if sv.HostKey.State != model.HostKeyTrusted || sv.CredentialID == "" {
			st.Warnings = append(st.Warnings, "服务器还没就绪（主机指纹没有确认或没有选择凭据）：先在服务器页处理")
		}
		switch sv.Channel.ChannelMode() {
		case model.ChannelJump:
			via := sv.Channel.ViaServerID
			m := serverNode[via]
			switch {
			case m == "" || m == id:
			case pending[m]:
				edge(id, m)
				st.Warnings = append(st.Warnings, fmt.Sprintf("经 %s 的服务器跳转管理：排在 %s 之前，在它重装、隧道和服务重启之前装好这台", nodeLabel(t, m), nodeLabel(t, m)))
				if ms := steps[m]; ms != nil {
					ms.Warnings = append(ms.Warnings, fmt.Sprintf("%s 经这台服务器跳转管理，已排在前面", nodeLabel(t, id)))
				}
			default:
				st.Warnings = append(st.Warnings, fmt.Sprintf("经 %s 的服务器跳转管理（它没有变化，这次不重装）", nodeLabel(t, m)))
			}
		case model.ChannelTunnel:
			st.Warnings = append(st.Warnings, fmt.Sprintf("经隧道地址 %s 管理：这个节点自己的安装会重启隧道接口，SSH 会话可能在安装中途断开——那时结果不明（服务器上的补偿在断线时运行），引导停在这里。稳妥的做法是在服务器页暂时改为直连或经中继跳转", sv.Channel.Address))
			if !gwInstalled {
				st.Warnings = append(st.Warnings, "网关上还没有安装 Meridian，隧道还不存在：经隧道连不到这台，第一次安装要先改为直连或经中继跳转")
			}
		default:
			for _, m := range ids {
				if m == id {
					continue
				}
				mn, _ := t.NodeByID(m)
				msv, ok := servers[mn.ServerID]
				if !ok || msv.Address != sv.Address || msv.Port == sv.Port {
					continue
				}
				if mn.EndpointV4 == sv.Address || mn.EndpointV6 == sv.Address {
					edge(id, m)
					st.Warnings = append(st.Warnings, fmt.Sprintf("SSH 经 %s 主机上的端口转发到达（地址相同、端口不同）：排在 %s 之前", nodeLabel(t, m), nodeLabel(t, m)))
					if ms := steps[m]; ms != nil {
						ms.Warnings = append(ms.Warnings, fmt.Sprintf("%s 的 SSH 经这台主机的端口转发到达，已排在前面；这台的安装不应改动那条转发（面板不管理它）", nodeLabel(t, id)))
					}
				} else {
					st.Warnings = append(st.Warnings, fmt.Sprintf("和 %s 用同一个 SSH 地址（端口不同）：可能经同一台主机转发，面板无法判断由哪台承载，没有据此调整顺序", nodeLabel(t, m)))
				}
			}
		}
	}
	// Kahn's algorithm, ties by tier then ID.
	indeg := map[string]int{}
	for _, id := range ids {
		indeg[id] += 0
		for b := range before[id] {
			indeg[b]++
		}
	}
	less := func(a, b string) bool {
		if steps[a].Tier != steps[b].Tier {
			return steps[a].Tier < steps[b].Tier
		}
		return a < b
	}
	var ready []string
	for _, id := range ids {
		if indeg[id] == 0 {
			ready = append(ready, id)
		}
	}
	var out []string
	for len(ready) > 0 {
		sort.Slice(ready, func(i, j int) bool { return less(ready[i], ready[j]) })
		id := ready[0]
		ready = ready[1:]
		out = append(out, id)
		for b := range before[id] {
			indeg[b]--
			if indeg[b] == 0 {
				ready = append(ready, b)
			}
		}
	}
	if len(out) != len(ids) {
		out = append([]string(nil), ids...)
		sort.Slice(out, func(i, j int) bool { return less(out[i], out[j]) })
		notes = append(notes, "管理通道之间的依赖互相矛盾（成环）：按基本顺序排列，没有按管理通道调整；检查服务器页的管理通道")
	} else {
		// Say where an edge moved a node ahead of its tier.
		for _, id := range out {
			var ahead []string
			for b := range before[id] {
				if steps[b].Tier < steps[id].Tier {
					ahead = append(ahead, b)
				}
			}
			sort.Strings(ahead)
			if len(ahead) > 0 {
				steps[id].Reason += fmt.Sprintf("（因管理通道提前到 %s 之前）", joinLabels(t, ahead))
			}
		}
	}
	res := make([]orderedStep, 0, len(out))
	for _, id := range out {
		res = append(res, *steps[id])
	}
	return res, notes
}

// planSkip is a node that gets no step.
type planSkip struct {
	NodeID   string `json:"node_id"`
	NodeName string `json:"node_name"`
	Role     string `json:"role"`
	// Kind: in_sync | done_in_run | external | unmanaged
	Kind string `json:"kind"`
	Why  string `json:"why"`
}

// planStep is one node of a computed plan.
type planStep struct {
	NodeID          string          `json:"node_id"`
	NodeName        string          `json:"node_name"`
	Role            string          `json:"role"`
	Kind            string          `json:"kind"` // remote | gateway
	Reason          string          `json:"reason"`
	Warnings        []string        `json:"warnings,omitempty"`
	PlanState       string          `json:"plan_state"`
	PlanStateReason string          `json:"plan_state_reason,omitempty"`
	PlanBundle      string          `json:"plan_bundle,omitempty"`
	PlanTarget      *targetIdentity `json:"plan_target,omitempty"`
}

type deployPlan struct {
	TopologyVersion string     `json:"topology_version"`
	Steps           []planStep `json:"steps"`
	Skipped         []planSkip `json:"skipped"`
	Notes           []string   `json:"notes,omitempty"`
}

// topologyVersion identifies the stored topology a plan was made from. Node
// positions on the canvas, private keys and the remote-access block (an
// independent resource, owned by /api/remote-access) do not count; their
// effect on the gateway's files is caught by the gateway step's own
// bundle binding.
func topologyVersion(t model.Topology) string {
	c := t
	c.Nodes = make([]model.Node, len(t.Nodes))
	for i, n := range t.Nodes {
		n.X, n.Y, n.PrivateKey = 0, 0, ""
		c.Nodes[i] = n
	}
	c.RemoteAccess = nil
	raw, _ := json.Marshal(c)
	h := sha256.Sum256(raw)
	return hex.EncodeToString(h[:])[:16]
}

// deployLive is the current state the plan and the bindings are checked
// against: topology version, every node's bundle digest and server
// identity, and every node's install state.
type deployLive struct {
	t       model.Topology
	version string
	b       *compile.Bundle
	gw      statusInstall
	states  map[string]nodeInstallState
	bundles map[string]string
	idents  map[string]targetIdentity
	servers map[string]model.Server
}

func (s *Server) liveDeploy() (*deployLive, error) {
	t, err := s.topology()
	if err != nil {
		return nil, err
	}
	b, err := s.compileTopo(t)
	if err != nil {
		return nil, err
	}
	l := &deployLive{t: t, version: topologyVersion(t), b: b, states: map[string]nodeInstallState{}, bundles: map[string]string{},
		idents: map[string]targetIdentity{}, servers: map[string]model.Server{}}
	ap := s.applier(true)
	l.gw = statusInstall{State: "unknown"}
	if inst, err := ap.Installed(); err == nil {
		l.gw = s.installState(ap, inst, func() (*compile.Bundle, error) { return b, nil })
	}
	for _, st := range s.nodeStates(t, b, l.gw) {
		l.states[st.NodeID] = st
	}
	if cs, err := s.credStore(); err == nil {
		for _, sv := range cs.Servers() {
			l.servers[sv.ID] = sv
		}
		for _, n := range t.Nodes {
			if n.ServerID != "" && n.Managed {
				if id, err := identityOf(cs, n); err == nil {
					l.idents[n.ID] = id
				}
			}
		}
	}
	for _, n := range t.Nodes {
		if !n.Managed || model.IsExternal(n) {
			continue
		}
		id := n.ID
		if n.Role == model.RoleGateway {
			id = localNodeID
		}
		l.bundles[n.ID] = preflight.BundleDigest(provision.FilesFor(b.Files, id))
	}
	return l, nil
}

func (l *deployLive) identity(node string) *targetIdentity {
	if id, ok := l.idents[node]; ok {
		return &id
	}
	return nil
}

// plan computes the plan from the live state.
// verifiedInSync: the node's own state is in sync AND, for a remote node,
// the last read-back of the host's record matched (verify = verified). An
// install whose record was never read back, or read back differently, is
// not taken as done by the guide (the single-node flow keeps its own
// "installed" outcome; the guide does not inherit it): the node gets a step
// whose preflight reads the record and adopts the content without
// reinstalling when it is there.
func verifiedInSync(n model.Node, st nodeInstallState) bool {
	if st.Pending {
		return false
	}
	if n.Role == model.RoleGateway {
		return true
	}
	return st.Verify != nil && st.Verify.State == verifyOK
}

// plan computes the plan from the live state. extra forces nodes into it
// (a re-plan keeps a failed or unknown step until its record is re-checked).
func (l *deployLive) plan(extra ...map[string]bool) *deployPlan {
	t := l.t
	p := &deployPlan{TopologyVersion: l.version, Steps: []planStep{}, Skipped: []planSkip{}}
	pending := map[string]bool{}
	for _, n := range t.Nodes {
		switch {
		case model.IsExternal(n):
			p.Skipped = append(p.Skipped, planSkip{NodeID: n.ID, NodeName: n.Name, Role: string(n.Role), Kind: "external",
				Why: fmt.Sprintf("外部 SOCKS 出口：面板不登录、不装机；它的配置随承载节点 %s 下发", nodeLabel(t, n.External.Carrier))})
		case !n.Managed:
			p.Skipped = append(p.Skipped, planSkip{NodeID: n.ID, NodeName: n.Name, Role: string(n.Role), Kind: "unmanaged", Why: "不受管（例如 IX 专线）：不需要装机"})
		default:
			st, ok := l.states[n.ID]
			forced := false
			for _, x := range extra {
				forced = forced || x[n.ID]
			}
			if ok && verifiedInSync(n, st) && !forced {
				p.Skipped = append(p.Skipped, planSkip{NodeID: n.ID, NodeName: n.Name, Role: string(n.Role), Kind: "in_sync", Why: "没有变化：与它上一次成功安装的内容一致"})
				continue
			}
			pending[n.ID] = true
		}
	}
	gwInstalled := l.gw.State != "not_installed" && l.gw.State != "withdrawn"
	order, notes := deployOrder(t, l.servers, pending, gwInstalled)
	p.Notes = notes
	for _, o := range order {
		n, _ := t.NodeByID(o.ID)
		st := l.states[n.ID]
		ps := planStep{NodeID: n.ID, NodeName: n.Name, Role: string(n.Role), Kind: "remote", Reason: o.Reason, Warnings: o.Warnings,
			PlanState: st.State, PlanStateReason: st.Reason, PlanBundle: l.bundles[n.ID], PlanTarget: l.identity(n.ID)}
		if n.Role == model.RoleGateway {
			ps.Kind = "gateway"
			ps.PlanTarget = nil
		}
		switch st.State {
		case nodeTargetChanged:
			ps.Warnings = append(ps.Warnings, "这个节点装在之前的服务器或身份上：先在「部署记录与撤回」里撤回旧的安装，否则预检会拒绝")
		case nodeUnknown:
			ps.Warnings = append(ps.Warnings, "状态不明：预检会先读取服务器上的安装记录；内容已经装上就直接采纳，不重做")
		case nodeInSync:
			if n.Role != model.RoleGateway {
				ps.Warnings = append(ps.Warnings, "面板的记录说内容已一致，但没有读回服务器上一致的安装记录：预检会读取它，内容已经在就直接采纳，不重装")
			}
		}
		p.Steps = append(p.Steps, ps)
	}
	sort.SliceStable(p.Skipped, func(i, j int) bool { return p.Skipped[i].NodeID < p.Skipped[j].NodeID })
	return p
}

// ------------------------------------------------------------------- run ---

// deployHealth is what the install reported about activation and health.
type deployHealth struct {
	// Source: gateway_transaction | remote_script | host_record
	Source    string          `json:"source"`
	Committed bool            `json:"committed"`
	Steps     []hostexec.Step `json:"steps,omitempty"`
	Warnings  []string        `json:"warnings,omitempty"`
	Verify    string          `json:"verify,omitempty"`
	Detail    string          `json:"detail,omitempty"`
}

type deployStep struct {
	planStep
	Phase string `json:"phase"`
	// Completion (done steps only) says how the step became done:
	//   installed — installed in this run, and the activation / health
	//               result was read back (remote: verify = verified;
	//               gateway: the committed host transaction with its
	//               health checks);
	//   adopted   — the host's install record (remote manifest, gateway
	//               installed manifest) already held this content: nothing
	//               was executed and health was NOT re-checked;
	//   in_sync   — already installed and verified outside this run
	//               (the panel's verified record): nothing was executed
	//               and health was not re-checked.
	// Only "installed" steps may be described as health-checked.
	Completion string `json:"completion,omitempty"`
	// The reviewed preflight the operator confirms, and what it was bound
	// to: the node's bundle digest and the server identity it ran against.
	PreflightID   string          `json:"preflight_id,omitempty"`
	ReviewBundle  string          `json:"review_bundle,omitempty"`
	ReviewTarget  *targetIdentity `json:"review_target,omitempty"`
	ReviewExpires *time.Time      `json:"review_expires,omitempty"`
	// Outcome of the last attempt: installed | refused | compensated |
	// left_behind | unknown | interrupted | not_started | adopted.
	Outcome     string        `json:"outcome,omitempty"`
	Code        string        `json:"code,omitempty"`
	Message     string        `json:"message,omitempty"`
	Evidence    string        `json:"evidence,omitempty"`
	Run         string        `json:"run,omitempty"`
	Health      *deployHealth `json:"health,omitempty"`
	Leftovers   []string      `json:"leftovers,omitempty"`
	NotExecuted bool          `json:"not_executed,omitempty"`
	SafeToRetry bool          `json:"safe_to_retry,omitempty"`
	// RetryAt: the server refused the panel's source address (rate limit);
	// the guide does not connect to it before this time.
	RetryAt *time.Time `json:"retry_at,omitempty"`
	// Invalidated says why the last reviewed preflight no longer counts.
	Invalidated string     `json:"invalidated,omitempty"`
	Attempts    int        `json:"attempts"`
	StartedAt   *time.Time `json:"started_at,omitempty"`
	FinishedAt  *time.Time `json:"finished_at,omitempty"`
	// Boot is the panel process that runs the in-flight phase.
	Boot string `json:"boot,omitempty"`
}

type deployEvent struct {
	At   time.Time `json:"at"`
	Node string    `json:"node,omitempty"`
	Text string    `json:"text"`
}

type deployRun struct {
	ID              string        `json:"id"`
	State           string        `json:"state"`
	CreatedAt       time.Time     `json:"created_at"`
	UpdatedAt       time.Time     `json:"updated_at"`
	TopologyVersion string        `json:"topology_version"`
	Steps           []deployStep  `json:"steps"`
	Skipped         []planSkip    `json:"skipped"`
	Notes           []string      `json:"notes,omitempty"`
	StopReason      string        `json:"stop_reason,omitempty"`
	Events          []deployEvent `json:"events,omitempty"`
	// Summary is the completion statement of a finished run, computed from
	// the steps' Completion (never from their wording).
	Summary *runSummary `json:"summary,omitempty"`
}

const (
	completionInstalled = "installed"
	completionAdopted   = "adopted"
	completionInSync    = "in_sync"
)

// completionOf is a done step's Completion; steps stored before the field
// existed fall back on their stored outcome and evidence codes.
func completionOf(st deployStep) string {
	switch {
	case st.Phase != phaseDone:
		return ""
	case st.Completion != "":
		return st.Completion
	case st.Outcome == "installed":
		return completionInstalled
	case st.Evidence == "panel_record":
		return completionInSync
	}
	return completionAdopted
}

// runSummary says how the steps of a finished run became done. Installed
// are the only nodes the run installed and health-checked.
type runSummary struct {
	// AllChecked: every step was installed and health-checked in this run.
	AllChecked bool     `json:"all_checked"`
	Installed  []string `json:"installed"`
	Adopted    []string `json:"adopted"`
	InSync     []string `json:"in_sync"`
	Text       string   `json:"text"`
}

func summarize(r *deployRun) *runSummary {
	sum := &runSummary{Installed: []string{}, Adopted: []string{}, InSync: []string{}}
	total := 0
	for _, st := range r.Steps {
		if st.Phase != phaseDone {
			continue
		}
		total++
		name := st.NodeName
		if name == "" {
			name = st.NodeID
		}
		switch completionOf(st) {
		case completionInstalled:
			sum.Installed = append(sum.Installed, name)
		case completionInSync:
			sum.InSync = append(sum.InSync, name)
		default:
			sum.Adopted = append(sum.Adopted, name)
		}
	}
	sum.AllChecked = total > 0 && len(sum.Installed) == total
	if sum.AllChecked {
		sum.Text = fmt.Sprintf("全部 %d 个节点都在这次运行中安装：服务已启动、健康检查通过（端到端验证另做）", total)
		return sum
	}
	var parts []string
	if len(sum.Installed) > 0 {
		parts = append(parts, fmt.Sprintf("%d 个节点在这次运行中安装并通过健康检查：%s", len(sum.Installed), strings.Join(sum.Installed, "、")))
	} else {
		parts = append(parts, "没有节点在这次运行中安装")
	}
	if len(sum.Adopted) > 0 {
		parts = append(parts, fmt.Sprintf("%d 个节点依据服务器上的安装记录采纳，没有重新执行、没有重新检查健康：%s", len(sum.Adopted), strings.Join(sum.Adopted, "、")))
	}
	if len(sum.InSync) > 0 {
		parts = append(parts, fmt.Sprintf("%d 个节点在引导之外已装好、读回记录一致，这次没有执行、没有重新检查健康：%s", len(sum.InSync), strings.Join(sum.InSync, "、")))
	}
	sum.Text = strings.Join(parts, "；") + "。没有重新检查的节点，服务现在是否在运行没有核实（端到端验证另做）"
	return sum
}

// completeRun ends a run whose steps are all done, with its summary.
func completeRun(r *deployRun, now time.Time) {
	r.State = runDone
	r.Summary = summarize(r)
	r.event(now, "", "全部步骤完成："+r.Summary.Text)
}

func (r *deployRun) open() bool { return r != nil && (r.State == runActive || r.State == runStopped) }

func (r *deployRun) event(at time.Time, node, text string) {
	r.Events = append(r.Events, deployEvent{At: at, Node: node, Text: text})
	if len(r.Events) > maxDeployEvents {
		r.Events = r.Events[len(r.Events)-maxDeployEvents:]
	}
}

// current is the index of the first step not done (-1: none).
func (r *deployRun) current() int {
	for i, st := range r.Steps {
		if st.Phase != phaseDone {
			return i
		}
	}
	return -1
}

func inFlight(phase string) bool { return phase == phasePreflight || phase == phaseInstalling }

func (s *Server) bootID() string {
	s.deployBootOnce.Do(func() { s.deployBoot = "boot-" + randHex(6) })
	return s.deployBoot
}

// loadRunLocked reads the stored run and turns in-flight steps of another
// panel process into interrupted ones (persisted). Caller holds deployMu.
func (s *Server) loadRunLocked() *deployRun {
	raw, ok, err := s.Store.Get(deployRunKey)
	if err != nil || !ok || raw == "" {
		return nil
	}
	var r deployRun
	if json.Unmarshal([]byte(raw), &r) != nil {
		return nil
	}
	boot := s.bootID()
	changed := false
	now := s.now()
	for i := range r.Steps {
		st := &r.Steps[i]
		if !inFlight(st.Phase) || st.Boot == boot {
			continue
		}
		changed = true
		st.FinishedAt = &now
		if st.Phase == phasePreflight {
			st.Phase, st.Outcome, st.Code = phasePending, "interrupted", ""
			st.Message = "面板在预检进行中重启了：预检是只读的，服务器上没有改动；重新预检即可"
			r.event(now, st.NodeID, "预检被面板重启打断（只读，没有改动）")
		} else {
			st.Phase, st.Outcome, st.Code = phaseUnknown, "interrupted", ""
			st.Message = "面板在下发进行中重启了：结果不明，不当作完成。先重新预检——它会读取这个节点实际的安装记录，内容已经装上就直接采纳，否则按预检结果处理"
			r.State, r.StopReason = runStopped, fmt.Sprintf("%s 的下发被面板重启打断，结果不明", st.NodeName)
			r.event(now, st.NodeID, "下发被面板重启打断：结果不明")
		}
		st.PreflightID, st.ReviewBundle, st.ReviewTarget, st.ReviewExpires = "", "", nil, nil
		st.Boot = ""
	}
	if changed {
		r.UpdatedAt = now
		s.saveRunLocked(&r)
	}
	return &r
}

func (s *Server) saveRunLocked(r *deployRun) {
	if b, err := json.Marshal(r); err == nil {
		_ = s.Store.Put(deployRunKey, string(b))
	}
}

// deployRunOpen returns the ID of the active or stopped run ("" when none):
// the unattended unlock install defers while one is open.
func (s *Server) deployRunOpen() string {
	s.deployMu.Lock()
	defer s.deployMu.Unlock()
	if r := s.loadRunLocked(); r.open() {
		return r.ID
	}
	return ""
}

// ------------------------------------------------------------------ view ---

type deployStepView struct {
	deployStep
	Position      int             `json:"position"`
	Current       bool            `json:"current"`
	InFlight      bool            `json:"in_flight"`
	CurrentBundle string          `json:"current_bundle,omitempty"`
	CurrentTarget *targetIdentity `json:"current_target,omitempty"`
	// Changes are live differences from what the plan or the review was
	// bound to, in words.
	Changes []string `json:"changes,omitempty"`
	// ConfirmationValid: the reviewed preflight still matches the node's
	// content and server identity (and has not expired).
	ConfirmationValid bool `json:"confirmation_valid"`
	CanPreflight      bool `json:"can_preflight"`
	CanInstall        bool `json:"can_install"`
	WaitSeconds       int  `json:"wait_seconds,omitempty"`
}

type deployRunView struct {
	deployRun
	Steps       []deployStepView `json:"steps"`
	Stale       bool             `json:"stale"`
	StaleReason string           `json:"stale_reason,omitempty"`
	// Affected are the not-done steps whose content or server identity
	// differs from what they were planned or reviewed with.
	Affected  []string         `json:"affected,omitempty"`
	Current   string           `json:"current,omitempty"`
	InFlight  string           `json:"in_flight,omitempty"`
	Preflight *preflightRecord `json:"preflight,omitempty"`
	// Pending: nodes that are not in sync now but are not steps of this
	// run (added or changed after it was planned): a re-plan adds them.
	Pending []string `json:"pending_outside,omitempty"`
}

func sameTarget(a, b *targetIdentity) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return a.same(*b)
}

func targetText(t *targetIdentity) string {
	if t == nil {
		return "—"
	}
	return fmt.Sprintf("%s@%s:%d（%s，凭据 %s）", t.User, t.Address, t.Port, orDashS(t.Fingerprint), orDashS(t.CredentialID))
}

// confirmationProblem says why step's reviewed preflight no longer counts
// ("" when it does).
func (s *Server) confirmationProblem(st deployStep, l *deployLive, now time.Time) string {
	if st.PreflightID == "" {
		return "还没有审阅过的预检"
	}
	if cur := l.bundles[st.NodeID]; st.ReviewBundle != cur {
		return "预检之后这个节点要下发的内容变了（拓扑、密钥、WSS 材料或解锁决定改了它的文件）"
	}
	if st.Kind == "remote" && !sameTarget(st.ReviewTarget, l.identity(st.NodeID)) {
		return fmt.Sprintf("预检之后服务器身份变了：预检时是 %s，现在是 %s", targetText(st.ReviewTarget), targetText(l.identity(st.NodeID)))
	}
	if st.ReviewExpires != nil && now.After(*st.ReviewExpires) {
		return fmt.Sprintf("预检结果已过期（有效 %d 分钟）", int(preflightTTL.Minutes()))
	}
	return ""
}

func (s *Server) runView(r *deployRun, l *deployLive) *deployRunView {
	if r == nil {
		return nil
	}
	now := s.now()
	v := &deployRunView{deployRun: *r, Steps: []deployStepView{}}
	if l != nil && r.open() && l.version != r.TopologyVersion {
		v.Stale = true
		v.StaleReason = "计划之后拓扑被保存过：继续之前先「按当前拓扑重新计划」（已完成的节点保持完成；内容和服务器身份都没变的节点保留预检）"
	}
	cur := r.current()
	inSteps := map[string]bool{}
	for i, st := range r.Steps {
		inSteps[st.NodeID] = true
		sv := deployStepView{deployStep: st, Position: i + 1, Current: i == cur && r.open(), InFlight: inFlight(st.Phase)}
		if sv.InFlight {
			v.InFlight = st.NodeID
		}
		if l != nil {
			sv.CurrentBundle = l.bundles[st.NodeID]
			if st.Kind == "remote" {
				sv.CurrentTarget = l.identity(st.NodeID)
			}
			if st.Phase != phaseDone {
				if st.PlanBundle != "" && sv.CurrentBundle != st.PlanBundle {
					sv.Changes = append(sv.Changes, "计划之后这个节点要下发的内容变了")
				}
				if st.Kind == "remote" && st.PlanTarget != nil && !sameTarget(st.PlanTarget, sv.CurrentTarget) {
					sv.Changes = append(sv.Changes, fmt.Sprintf("计划之后服务器身份变了：计划时 %s，现在 %s", targetText(st.PlanTarget), targetText(sv.CurrentTarget)))
				}
				if st.Phase == phaseReview || st.Phase == phaseBlocked {
					if p := s.confirmationProblem(st, l, now); p != "" {
						sv.Changes = append(sv.Changes, "预检不再有效："+p)
					} else {
						sv.ConfirmationValid = st.Phase == phaseReview
					}
				}
				if len(sv.Changes) > 0 {
					v.Affected = append(v.Affected, st.NodeID)
				}
			} else if ns, ok := l.states[st.NodeID]; ok && ns.Pending {
				sv.Changes = append(sv.Changes, "在这次运行中装好之后，它的内容或服务器又变了：重新计划会把它重新加进来")
			}
		}
		if st.RetryAt != nil && st.RetryAt.After(now) {
			sv.WaitSeconds = int(st.RetryAt.Sub(now).Seconds()) + 1
		}
		if sv.Current && !v.Stale && v.InFlight == "" && sv.WaitSeconds == 0 {
			sv.CanPreflight = st.Phase != phaseInstalling && st.Phase != phasePreflight
			sv.CanInstall = st.Phase == phaseReview && sv.ConfirmationValid
		}
		v.Steps = append(v.Steps, sv)
	}
	if cur >= 0 && r.open() {
		v.Current = r.Steps[cur].NodeID
		st := r.Steps[cur]
		if st.PreflightID != "" {
			pid := st.NodeID
			if st.Kind == "gateway" {
				pid = localNodeID
			}
			if rec := s.loadPreflight(pid); rec != nil && rec.ID == st.PreflightID {
				v.Preflight = rec
			}
		}
	}
	if l != nil && r.open() {
		for _, n := range l.t.Nodes {
			if ns, ok := l.states[n.ID]; ok && ns.Pending && !inSteps[n.ID] {
				v.Pending = append(v.Pending, n.ID)
			}
		}
	}
	return v
}

// -------------------------------------------------------------- handlers ---

func (s *Server) registerDeploy(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/deploy", s.getDeploy)
	mux.HandleFunc("POST /api/deploy/runs", s.postDeployRun)
	mux.HandleFunc("POST /api/deploy/runs/{id}/preflight", s.postDeployPreflight)
	mux.HandleFunc("POST /api/deploy/runs/{id}/install", s.postDeployInstall)
	mux.HandleFunc("POST /api/deploy/runs/{id}/replan", s.postDeployReplan)
	mux.HandleFunc("POST /api/deploy/runs/{id}/cancel", s.postDeployCancel)
}

// deployView is GET /api/deploy and the answer of every action.
func (s *Server) deployView(r *deployRun) map[string]any {
	out := map[string]any{"limits": deployLimits, "run": nil}
	l, err := s.liveDeploy()
	if err != nil {
		out["plan_error"] = err.Error()
		var ve *compile.ValidationError
		if errors.As(err, &ve) {
			out["plan_error_code"] = codeTopologyInvalid
			out["issues"] = ve.Result.Issues
		}
	} else {
		out["plan"] = l.plan()
		out["topology_version"] = l.version
	}
	if r != nil {
		out["run"] = s.runView(r, l)
	}
	return out
}

func (s *Server) getDeploy(w http.ResponseWriter, r *http.Request) {
	s.deployMu.Lock()
	run := s.loadRunLocked()
	s.deployMu.Unlock()
	writeJSON(w, http.StatusOK, s.deployView(run))
}

type deployRunBody struct {
	// TopologyVersion, when given, must equal the current one: the plan the
	// operator looked at is the plan that starts.
	TopologyVersion string `json:"topology_version"`
}

func (s *Server) postDeployRun(w http.ResponseWriter, r *http.Request) {
	var body deployRunBody
	if err := decodeStrict(w, r, &body, []string{"topology_version"}, nil, true); err != nil {
		writeResErr(w, err)
		return
	}
	s.deployMu.Lock()
	defer s.deployMu.Unlock()
	if cur := s.loadRunLocked(); cur.open() {
		writeCoded(w, http.StatusConflict, codeDeployRunActive,
			fmt.Sprintf("已经有一个部署引导在进行（%s，%s）：继续它，或先取消它再开始新的", cur.ID, runStateText(cur.State)), map[string]any{"run_id": cur.ID})
		return
	}
	// Every managed node gets its WireGuard key now (panel-side only, the
	// same thing every preflight does), so the bundles the plan binds stay
	// the same while the nodes are installed one by one.
	if _, _, err := s.ensureNodeKeys(); err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	l, err := s.liveDeploy()
	if err != nil {
		if refuseInvalid(w, err) {
			return
		}
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	if body.TopologyVersion != "" && body.TopologyVersion != l.version {
		writeCoded(w, http.StatusConflict, codeDeployPlanStale, "你看到的计划之后拓扑变了：刷新后看新的计划再开始", nil)
		return
	}
	p := l.plan()
	if len(p.Steps) == 0 {
		writeCoded(w, http.StatusConflict, codeDeployNothing, "所有受管节点都与它们上一次成功安装的内容一致，没有要部署的", nil)
		return
	}
	now := s.now()
	run := &deployRun{ID: "deploy-" + randHex(6), State: runActive, CreatedAt: now, UpdatedAt: now, TopologyVersion: p.TopologyVersion,
		Skipped: p.Skipped, Notes: p.Notes}
	for _, ps := range p.Steps {
		run.Steps = append(run.Steps, deployStep{planStep: ps, Phase: phasePending})
	}
	run.event(now, "", fmt.Sprintf("开始：%d 个节点要装，%d 个跳过", len(run.Steps), len(run.Skipped)))
	s.saveRunLocked(run)
	writeJSON(w, http.StatusOK, s.deployView(run))
}

func runStateText(st string) string {
	switch st {
	case runActive:
		return "进行中"
	case runStopped:
		return "已停在失败或结果不明的节点"
	case runDone:
		return "已完成"
	case runCancelled:
		return "已取消"
	}
	return st
}

type deployStepBody struct {
	NodeID      string `json:"node_id"`
	PreflightID string `json:"preflight_id"`
}

// beginStep checks that the step may be acted on and marks it in flight.
// It writes the refusal and returns nil when not.
func (s *Server) beginStep(w http.ResponseWriter, runID, node, phase string, check func(st *deployStep, l *deployLive) (int, string, string)) (*deployRun, int, *deployLive) {
	s.deployMu.Lock()
	defer s.deployMu.Unlock()
	run := s.loadRunLocked()
	if run == nil || run.ID != runID {
		writeCoded(w, http.StatusNotFound, credentials.CodeNotFound, "没有这个部署引导", nil)
		return nil, 0, nil
	}
	if !run.open() {
		writeCoded(w, http.StatusConflict, codeDeployRunClosed, "这个部署引导"+runStateText(run.State)+"：开始一个新的", nil)
		return nil, 0, nil
	}
	for _, st := range run.Steps {
		if inFlight(st.Phase) {
			writeCoded(w, http.StatusConflict, codeDeployStepRunning, fmt.Sprintf("%s 正在%s：等它结束", st.NodeName, map[bool]string{true: "预检", false: "下发"}[st.Phase == phasePreflight]), nil)
			return nil, 0, nil
		}
	}
	idx := run.current()
	if idx < 0 || run.Steps[idx].NodeID != node {
		want := "—"
		if idx >= 0 {
			want = run.Steps[idx].NodeName
		}
		writeCoded(w, http.StatusConflict, codeDeployNotCurrent, fmt.Sprintf("只能按顺序操作：现在轮到 %s", want), nil)
		return nil, 0, nil
	}
	l, err := s.liveDeploy()
	if err != nil {
		if refuseInvalid(w, err) {
			return nil, 0, nil
		}
		writeErr(w, http.StatusInternalServerError, err)
		return nil, 0, nil
	}
	if l.version != run.TopologyVersion {
		writeCoded(w, http.StatusConflict, codeDeployPlanStale, "计划之后拓扑被保存过：先「按当前拓扑重新计划」再继续", map[string]any{"deploy": s.deployView(run)})
		return nil, 0, nil
	}
	st := &run.Steps[idx]
	now := s.now()
	if st.RetryAt != nil && st.RetryAt.After(now) {
		left := int(st.RetryAt.Sub(now).Seconds()) + 1
		writeCoded(w, http.StatusConflict, codeDeployWait,
			fmt.Sprintf("服务器暂时拒绝面板的来源地址（限速）：%d 秒后（%s）再试；面板在那之前不会连接它", left, st.RetryAt.Format(time.RFC3339)),
			map[string]any{"retry_after": left})
		return nil, 0, nil
	}
	if status, code, msg := check(st, l); code != "" {
		if code == codeDeployInvalidated {
			// The confirmation no longer counts: back to a fresh preflight.
			st.Phase, st.Invalidated = phasePending, msg
			st.PreflightID, st.ReviewBundle, st.ReviewTarget, st.ReviewExpires = "", "", nil, nil
			run.event(now, st.NodeID, "确认失效："+msg)
			run.UpdatedAt = now
			s.saveRunLocked(run)
		}
		writeCoded(w, status, code, msg, map[string]any{"deploy": s.deployView(run)})
		return nil, 0, nil
	}
	st.Phase, st.Boot, st.StartedAt, st.FinishedAt = phase, s.bootID(), &now, nil
	st.Attempts++
	run.UpdatedAt = now
	s.saveRunLocked(run)
	return run, idx, l
}

// finishStep records the result of the step's in-flight phase.
func (s *Server) finishStep(runID, node string, f func(run *deployRun, st *deployStep, now time.Time)) *deployRun {
	s.deployMu.Lock()
	defer s.deployMu.Unlock()
	run := s.loadRunLocked()
	if run == nil || run.ID != runID {
		return run
	}
	now := s.now()
	for i := range run.Steps {
		if run.Steps[i].NodeID == node {
			st := &run.Steps[i]
			st.Boot, st.FinishedAt = "", &now
			f(run, st, now)
			break
		}
	}
	if run.State == runActive && run.current() < 0 {
		completeRun(run, now)
	}
	run.UpdatedAt = now
	s.saveRunLocked(run)
	return run
}

// callJSON runs an in-process handler and decodes its answer.
func callJSON(h func(http.ResponseWriter, *http.Request), ctx context.Context, path string, body any) (int, map[string]any, []byte) {
	raw, _ := json.Marshal(body)
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, path, bytes.NewReader(raw))
	req.Header.Set("Content-Type", "application/json")
	cw := &captureWriter{header: http.Header{}}
	h(cw, req)
	out := map[string]any{}
	_ = json.Unmarshal(cw.body, &out)
	if cw.status == 0 {
		cw.status = http.StatusOK
	}
	return cw.status, out, cw.body
}

func strOf(m map[string]any, k string) string {
	v, _ := m[k].(string)
	return v
}

func boolOf(m map[string]any, k string) bool {
	v, _ := m[k].(bool)
	return v
}

// deployNotStarted records an attempt that did not get to execute anything.
func deployNotStarted(st *deployStep, body map[string]any, now time.Time) {
	st.Outcome, st.Code, st.Message = "not_started", strOf(body, "code"), strOf(body, "error")
	st.NotExecuted, st.SafeToRetry = true, boolOf(body, "safe_to_retry")
	if st.Code == sshexec.CodeRateLimited {
		ra := 0
		if f, ok := body["retry_after"].(float64); ok {
			ra = int(f)
		}
		if ra <= 0 {
			ra = int(sshexec.DefaultCooldown.Seconds())
		}
		at := now.Add(time.Duration(ra) * time.Second)
		st.RetryAt = &at
	}
}

func clearAttempt(st *deployStep) {
	st.Outcome, st.Code, st.Message, st.Evidence = "", "", "", ""
	st.NotExecuted, st.SafeToRetry, st.RetryAt, st.Leftovers = false, false, nil, nil
}

func (s *Server) busyMessage(node string) string {
	if node == localNodeID && s.autoInstalling.Load() {
		return "无人值守的解锁自动安装正在安装网关：等它结束（通常一两分钟）后再点这一步；两者不会同时执行"
	}
	return "这个节点正在预检、装机或撤回（另一个操作占用）：等它结束后再试"
}

// --------------------------------------------------------------- preflight ---

func (s *Server) postDeployPreflight(w http.ResponseWriter, r *http.Request) {
	var body deployStepBody
	if err := decodeStrict(w, r, &body, []string{"node_id"}, nil, false); err != nil {
		writeResErr(w, err)
		return
	}
	runID := r.PathValue("id")
	run, idx, l := s.beginStep(w, runID, body.NodeID, phasePreflight, func(st *deployStep, l *deployLive) (int, string, string) {
		return 0, "", ""
	})
	if run == nil {
		return
	}
	st := run.Steps[idx]
	retry := st.Phase == phaseFailed || st.Phase == phaseUnknown || st.Attempts > 1 || st.PlanState == nodeUnknown
	ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), deployStepTimeout)
	defer cancel()

	// Already there? Never contact the host for a node whose own record says
	// it is in sync on a first visit; after a failure or an unknown outcome
	// the host's actual record decides (below).
	if n, nok := l.t.NodeByID(st.NodeID); nok && !retry {
		if ns, ok := l.states[st.NodeID]; ok && verifiedInSync(n, ns) {
			run = s.finishStep(runID, st.NodeID, func(run *deployRun, st *deployStep, now time.Time) {
				clearAttempt(st)
				st.Phase, st.Outcome, st.Evidence, st.Completion = phaseDone, "adopted", "panel_record", completionInSync
				st.Message = "这个节点已经与上一次成功安装的内容一致（在引导之外装好的，读回的服务器记录也一致）：不重做"
				run.event(now, st.NodeID, "已一致，跳过")
			})
			writeJSON(w, http.StatusOK, s.deployView(run))
			return
		}
	}

	if st.Kind == "gateway" {
		s.deployGatewayPreflight(ctx, runID, st)
	} else {
		s.deployRemotePreflight(ctx, runID, st)
	}
	s.deployMu.Lock()
	run = s.loadRunLocked()
	s.deployMu.Unlock()
	writeJSON(w, http.StatusOK, s.deployView(run))
}

// reviewed records a preflight result on the step.
func reviewed(run *deployRun, st *deployStep, rec *preflightRecord, now time.Time) {
	clearAttempt(st)
	st.PreflightID, st.ReviewBundle, st.ReviewTarget = rec.ID, rec.Bundle, rec.Target
	exp := rec.ExpiresAt
	st.ReviewExpires = &exp
	st.Invalidated = ""
	if rec.Blocking {
		st.Phase = phaseBlocked
		st.Message = fmt.Sprintf("预检有 %d 个阻断项：按每一项的处理办法解决后重新预检", rec.Counts.Blocking)
		run.event(now, st.NodeID, "预检有阻断项")
	} else {
		st.Phase = phaseReview
		st.Message = "预检完成：审阅要做的变更和冲突，确认后下发"
		run.event(now, st.NodeID, "预检完成，等待确认")
	}
	if run.State == runStopped {
		run.State, run.StopReason = runActive, ""
	}
}

func (s *Server) deployRemotePreflight(ctx context.Context, runID string, st deployStep) {
	status, body, raw := callJSON(s.postProvisionPreflight, ctx, "/api/provision/preflight", map[string]any{"node_id": st.NodeID})
	s.finishStep(runID, st.NodeID, func(run *deployRun, step *deployStep, now time.Time) {
		if status != http.StatusOK {
			step.Phase = phasePendingOr(step.Phase)
			deployNotStarted(step, body, now)
			run.event(now, step.NodeID, "预检没有完成："+clipText(step.Message, 200))
			return
		}
		var out struct{ Preflight preflightRecord }
		if json.Unmarshal(raw, &out) != nil || out.Preflight.ID == "" {
			step.Phase = phasePendingOr(step.Phase)
			step.Outcome, step.Message = "not_started", "预检的回答无法读取"
			return
		}
		rec := &out.Preflight
		// The node's actual install record: content already installed by
		// this panel for this node, on this server, is adopted — not
		// installed again.
		if h := rec.HostRecord; h != nil && rec.Target != nil && h.Node == step.NodeID && h.Deployment == rec.Deployment &&
			(h.Server == "" || h.Server == rec.Target.ServerID) && h.Bundle == rec.Bundle && (h.JournalState == "" || h.JournalState == "done") {
			s.adoptRemote(step.NodeID, rec)
			clearAttempt(step)
			step.Phase, step.Outcome, step.Evidence, step.Completion = phaseDone, "adopted", "host_record", completionAdopted
			step.PreflightID, step.ReviewBundle, step.ReviewTarget = rec.ID, rec.Bundle, rec.Target
			step.Health = &deployHealth{Source: "host_record", Committed: true, Verify: verifyOK,
				Detail: "服务器上的安装记录（清单）已经是这份内容" + map[bool]string{true: "（运行 " + h.JournalRun + " 的 journal 为 done）", false: ""}[h.JournalRun != ""] + "：没有重新执行，也没有重新做健康检查"}
			step.Message = "服务器上已经装着这份内容：采纳，不重做"
			if run.State == runStopped {
				run.State, run.StopReason = runActive, ""
			}
			run.event(now, step.NodeID, "服务器记录显示内容已装上：采纳")
			return
		}
		reviewed(run, step, rec, now)
	})
}

// phasePendingOr keeps a failed / unknown phase (the run stays stopped
// until a preflight completes) and turns anything else into pending.
func phasePendingOr(p string) string {
	if p == phaseFailed || p == phaseUnknown {
		return p
	}
	return phasePending
}

// adoptRemote records a node's install from the host's own record, read
// by a preflight on the pinned identity.
func (s *Server) adoptRemote(node string, rec *preflightRecord) {
	h, t := rec.HostRecord, rec.Target
	at := rec.At
	if h.Installed > 0 {
		at = time.Unix(h.Installed, 0).UTC()
	}
	o := provisionOutcome{NodeID: node, ServerID: t.ServerID, Address: t.Address, Port: t.Port, Fingerprint: t.Fingerprint,
		Run: h.JournalRun, Bundle: rec.Bundle, At: at, OK: true, User: t.User, CredentialID: t.CredentialID, Deployment: rec.Deployment,
		NodeName: rec.NodeName, Outcome: "installed", Evidence: "host_record",
		Verify: &nodeVerify{At: rec.At, State: verifyOK, Source: "preflight", HostBundle: h.Bundle}}
	s.saveOutcome(o)
}

func (s *Server) deployGatewayPreflight(ctx context.Context, runID string, st deployStep) {
	// The gateway's actual install record is local (the installed
	// manifest): already in sync means nothing to do.
	ap := s.applier(true)
	if inst, err := ap.Installed(); err == nil {
		if b, err := s.liveGatewayBundle(); err == nil {
			if d, err := ap.InstalledDiff(b); err == nil && d != nil && d.Empty() && !inst.Empty() && !inst.Withdrawn() {
				s.finishStep(runID, st.NodeID, func(run *deployRun, step *deployStep, now time.Time) {
					clearAttempt(step)
					step.Phase, step.Outcome, step.Evidence, step.Completion = phaseDone, "adopted", "installed_manifest", completionAdopted
					step.Message = "网关上安装的文件已经是这份内容（按安装清单的哈希比较）：不重做"
					step.Health = &deployHealth{Source: "host_record", Committed: true, Detail: "依据网关的安装清单；没有重新执行，也没有重新做健康检查"}
					if run.State == runStopped {
						run.State, run.StopReason = runActive, ""
					}
					run.event(now, step.NodeID, "网关已是这份内容：采纳")
				})
				return
			}
		}
	}
	status, body, raw := callJSON(s.postHostPreflight, ctx, "/api/host/preflight", map[string]any{})
	s.finishStep(runID, st.NodeID, func(run *deployRun, step *deployStep, now time.Time) {
		if status != http.StatusOK {
			step.Phase = phasePendingOr(step.Phase)
			deployNotStarted(step, body, now)
			if step.Code == codeNodeBusy {
				step.Message = s.busyMessage(localNodeID)
			}
			run.event(now, step.NodeID, "预检没有完成："+clipText(step.Message, 200))
			return
		}
		var out struct{ Preflight preflightRecord }
		if json.Unmarshal(raw, &out) != nil || out.Preflight.ID == "" {
			step.Phase = phasePendingOr(step.Phase)
			step.Outcome, step.Message = "not_started", "预检的回答无法读取"
			return
		}
		reviewed(run, step, &out.Preflight, now)
	})
}

func (s *Server) liveGatewayBundle() (*compile.Bundle, error) {
	t, err := s.topology()
	if err != nil {
		return nil, err
	}
	return s.compileTopo(t)
}

// ----------------------------------------------------------------- install ---

func (s *Server) postDeployInstall(w http.ResponseWriter, r *http.Request) {
	var body deployStepBody
	if err := decodeStrict(w, r, &body, []string{"node_id", "preflight_id"}, nil, false); err != nil {
		writeResErr(w, err)
		return
	}
	runID := r.PathValue("id")
	run, idx, _ := s.beginStep(w, runID, body.NodeID, phaseInstalling, func(st *deployStep, l *deployLive) (int, string, string) {
		if st.Phase != phaseReview {
			return http.StatusConflict, codeDeployNotReviewed, "这个节点还没有可以确认的预检：先预检并审阅结果"
		}
		if body.PreflightID == "" || body.PreflightID != st.PreflightID {
			return http.StatusConflict, codeDeployNotReviewed, "确认的不是这个节点最近一次审阅的预检：刷新后审阅最新的结果再确认"
		}
		if p := s.confirmationProblem(*st, l, s.now()); p != "" {
			return http.StatusConflict, codeDeployInvalidated, p + "：重新预检并审阅后再确认"
		}
		return 0, "", ""
	})
	if run == nil {
		return
	}
	st := run.Steps[idx]
	ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), deployStepTimeout)
	defer cancel()
	if st.Kind == "gateway" {
		s.deployGatewayInstall(ctx, runID, st)
	} else {
		s.deployRemoteInstall(ctx, runID, st)
	}
	s.deployMu.Lock()
	run = s.loadRunLocked()
	s.deployMu.Unlock()
	writeJSON(w, http.StatusOK, s.deployView(run))
}

// stopAt stops the run at step.
func stopAt(run *deployRun, step *deployStep, phase, why string, now time.Time) {
	step.Phase = phase
	step.PreflightID, step.ReviewBundle, step.ReviewTarget, step.ReviewExpires = "", "", nil, nil
	run.State, run.StopReason = runStopped, why
	run.event(now, step.NodeID, why)
}

func (s *Server) deployRemoteInstall(ctx context.Context, runID string, st deployStep) {
	status, body, _ := callJSON(s.postProvision, ctx, "/api/provision", map[string]any{"node_id": st.NodeID, "preflight_id": st.PreflightID})
	s.finishStep(runID, st.NodeID, func(run *deployRun, step *deployStep, now time.Time) {
		clearAttempt(step)
		outcome := strOf(body, "outcome")
		step.Run, step.Code, step.Message = strOf(body, "run"), strOf(body, "code"), strOf(body, "error")
		step.Evidence = strOf(body, "evidence")
		if lo, ok := body["leftovers"].([]any); ok {
			for _, x := range lo {
				if s, ok := x.(string); ok {
					step.Leftovers = append(step.Leftovers, s)
				}
			}
		}
		switch {
		case status == http.StatusOK && outcome == "installed":
			step.Outcome = "installed"
			h := &deployHealth{Source: "remote_script", Committed: true}
			if v, ok := body["verify"].(map[string]any); ok {
				h.Verify, h.Detail = strOf(v, "state"), strOf(v, "detail")
			}
			step.Health = h
			switch h.Verify {
			case verifyOK:
			case verifyMismatch:
				step.Outcome = "unknown"
				stopAt(run, step, phaseUnknown, fmt.Sprintf("%s：脚本报告成功，但读回的服务器记录与装上去的内容不一致（%s）：不当作完成", step.NodeName, h.Detail), now)
				return
			default:
				// Missing, unverified or unparsable read-back: the script said it
				// succeeded, but nothing confirmed what is on the host.
				step.Outcome = "unknown"
				detail := h.Detail
				if detail == "" {
					detail = "回答里没有可用的核对结果"
				}
				stopAt(run, step, phaseUnknown, fmt.Sprintf("%s：脚本报告成功，但没有读回服务器上的安装记录（%s）：不当作完成。不用盲目重装——「重新核对」会再读一次记录，内容已经在就直接采纳", step.NodeName, detail), now)
				return
			}
			step.Phase, step.Completion = phaseDone, completionInstalled
			step.Message = "已下发：脚本完成激活，读回的服务器记录与装上去的内容一致"
			run.event(now, step.NodeID, "已下发")
		case outcome == "refused" || outcome == "compensated" || outcome == "left_behind":
			step.Outcome = outcome
			why := map[string]string{
				"refused":     "服务器上的执行前复核拒绝了这次装机，没有改动",
				"compensated": "装机失败，已补偿（服务器回到这次下发之前）",
				"left_behind": "装机失败，补偿没有全部完成（有残留）",
			}[outcome]
			stopAt(run, step, phaseFailed, step.NodeName+"："+why, now)
		case outcome == "unknown":
			step.Outcome = "unknown"
			stopAt(run, step, phaseUnknown, step.NodeName+"：结果不明，不当作完成", now)
		default:
			// Nothing ran on the host (refused by the gate before the script,
			// the login failed, or rate limited).
			deployNotStarted(step, body, now)
			if step.Code == codeNodeBusy {
				step.Message = s.busyMessage(step.NodeID)
			}
			if fresh, ok := body["preflight"].(map[string]any); ok && strOf(fresh, "id") != "" && (step.Code == codePreflightChanged || step.Code == codePreflightBlocked) {
				// The re-run right before execution found something new: it is
				// the result to review now.
				raw, _ := json.Marshal(fresh)
				var rec preflightRecord
				if json.Unmarshal(raw, &rec) == nil {
					code, msg := step.Code, step.Message
					reviewed(run, step, &rec, now)
					step.Outcome, step.Code, step.Message, step.NotExecuted = "not_started", code, msg, true
					return
				}
			}
			step.Phase = phasePending
			step.Invalidated = "下发没有执行：" + clipText(step.Message, 300)
			step.PreflightID, step.ReviewBundle, step.ReviewTarget, step.ReviewExpires = "", "", nil, nil
			run.event(now, step.NodeID, "下发没有执行："+clipText(step.Message, 200))
		}
	})
}

func (s *Server) deployGatewayInstall(ctx context.Context, runID string, st deployStep) {
	status, body := s.gatedGatewayInstall(ctx, st.PreflightID)
	s.finishStep(runID, st.NodeID, func(run *deployRun, step *deployStep, now time.Time) {
		clearAttempt(step)
		code := strOf(body, "code")
		step.Code, step.Message = code, strOf(body, "error")
		if status == http.StatusOK {
			step.Outcome = "installed"
			h := &deployHealth{Source: "gateway_transaction"}
			if host, ok := body["host"]; ok {
				raw, _ := json.Marshal(host)
				var rep struct {
					Committed bool            `json:"committed"`
					Steps     []hostexec.Step `json:"steps"`
					Warnings  []string        `json:"warnings"`
				}
				if json.Unmarshal(raw, &rep) == nil {
					h.Committed, h.Steps, h.Warnings = rep.Committed, rep.Steps, rep.Warnings
				}
			}
			step.Health = h
			if !h.Committed {
				// A 200 always carries the committed transaction report; anything
				// else is not evidence of an install.
				step.Outcome = "unknown"
				stopAt(run, step, phaseUnknown, "网关：安装的回答里没有已提交的事务报告：结果不明，不当作完成；「重新核对」会按安装清单比较", now)
				return
			}
			step.Phase, step.Completion = phaseDone, completionInstalled
			step.Message = "已安装到网关：事务已提交，服务已启动，健康检查通过"
			run.event(now, step.NodeID, "已安装到网关")
			return
		}
		switch code {
		case codeActivationCompensated:
			step.Outcome = "compensated"
			stopAt(run, step, phaseFailed, "网关：安装失败，已补偿回安装前", now)
		case codeActivationUncompensate:
			step.Outcome = "left_behind"
			stopAt(run, step, phaseFailed, "网关：安装失败，补偿没有完成——先在本页「恢复」未完成的宿主事务", now)
		case codeCommitFailed, codeApplyFailed, codeHostStateMalformed, "":
			step.Outcome = "unknown"
			stopAt(run, step, phaseUnknown, "网关：结果不明（"+orDashS(code)+"），不当作完成", now)
		case codeHostUnavailable:
			if status == http.StatusServiceUnavailable {
				deployNotStarted(step, body, now)
				step.Phase = phasePending
				step.PreflightID, step.ReviewBundle, step.ReviewTarget, step.ReviewExpires = "", "", nil, nil
				return
			}
			step.Outcome = "unknown"
			stopAt(run, step, phaseUnknown, "网关：宿主执行通道在安装中出错，结果不明", now)
		default:
			// Refused before anything was written (gate, keys, validation,
			// a pending transaction, busy).
			deployNotStarted(step, body, now)
			if code == codeNodeBusy {
				step.Message = s.busyMessage(localNodeID)
			}
			if fresh, ok := body["preflight"].(map[string]any); ok && strOf(fresh, "id") != "" {
				raw, _ := json.Marshal(fresh)
				var rec preflightRecord
				if json.Unmarshal(raw, &rec) == nil && (code == codePreflightChanged || code == codePreflightBlocked) {
					c, m := step.Code, step.Message
					reviewed(run, step, &rec, now)
					step.Outcome, step.Code, step.Message, step.NotExecuted = "not_started", c, m, true
					return
				}
			}
			step.Phase = phasePending
			step.Invalidated = "安装没有执行：" + clipText(step.Message, 300)
			step.PreflightID, step.ReviewBundle, step.ReviewTarget, step.ReviewExpires = "", "", nil, nil
			run.event(now, step.NodeID, "安装没有执行："+clipText(step.Message, 200))
		}
	})
}

// gatedGatewayInstall is the operator's gateway install with the gateway
// node lock held from the preflight re-run through the end of the host
// transaction, so the unattended unlock install (which takes the same
// lock) cannot interleave.
func (s *Server) gatedGatewayInstall(ctx context.Context, preflightID string) (int, map[string]any) {
	cw := &captureWriter{header: http.Header{}}
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, "/api/apply", nil)
	if !s.lockNode(localNodeID) {
		return http.StatusConflict, map[string]any{"code": codeNodeBusy, "error": s.busyMessage(localNodeID)}
	}
	defer s.unlockNode(localNodeID)
	// The same pre-checks as applyGateway's, in the same order, but under
	// the lock this caller already holds.
	if pre, err := s.topology(); err == nil {
		if pb, err := s.compileTopo(pre); err == nil {
			if refusePeerKeys(cw, pb) {
				return decodeCapture(cw)
			}
			if !s.gateGatewayInstallLocked(cw, ctx, provision.FilesFor(pb.Files, localNodeID), preflightID) {
				return decodeCapture(cw)
			}
		}
	}
	// gated: the preflight gate above ran under the lock; a topology that
	// no longer compiles is refused by applyGateway itself.
	s.applyGateway(cw, req, applyBody{Install: true, PreflightID: preflightID, gated: true}, nil)
	return decodeCapture(cw)
}

func decodeCapture(cw *captureWriter) (int, map[string]any) {
	out := map[string]any{}
	_ = json.Unmarshal(cw.body, &out)
	st := cw.status
	if st == 0 {
		st = http.StatusOK
	}
	return st, out
}

// ------------------------------------------------------- replan / cancel ---

func (s *Server) postDeployReplan(w http.ResponseWriter, r *http.Request) {
	if err := decodeStrict(w, r, &struct{}{}, nil, nil, true); err != nil {
		writeResErr(w, err)
		return
	}
	s.deployMu.Lock()
	defer s.deployMu.Unlock()
	run := s.loadRunLocked()
	if run == nil || run.ID != r.PathValue("id") {
		writeCoded(w, http.StatusNotFound, credentials.CodeNotFound, "没有这个部署引导", nil)
		return
	}
	if !run.open() {
		writeCoded(w, http.StatusConflict, codeDeployRunClosed, "这个部署引导"+runStateText(run.State)+"：开始一个新的", nil)
		return
	}
	for _, st := range run.Steps {
		if inFlight(st.Phase) {
			writeCoded(w, http.StatusConflict, codeDeployStepRunning, st.NodeName+" 正在执行：等它结束后再重新计划", nil)
			return
		}
	}
	if _, _, err := s.ensureNodeKeys(); err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	l, err := s.liveDeploy()
	if err != nil {
		if refuseInvalid(w, err) {
			return
		}
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	now := s.now()
	keep := map[string]bool{}
	for _, st := range run.Steps {
		if st.Phase == phaseFailed || st.Phase == phaseUnknown {
			keep[st.NodeID] = true
		}
	}
	p := l.plan(keep)
	old := map[string]deployStep{}
	for _, st := range run.Steps {
		old[st.NodeID] = st
	}
	var steps []deployStep
	inPlan := map[string]bool{}
	for _, ps := range p.Steps {
		inPlan[ps.NodeID] = true
	}
	// Done steps whose node is still in sync stay, in their order.
	for _, st := range run.Steps {
		if st.Phase == phaseDone && !inPlan[st.NodeID] {
			steps = append(steps, st)
		}
	}
	var kept, reset []string
	for _, ps := range p.Steps {
		ns := deployStep{planStep: ps, Phase: phasePending}
		if o, ok := old[ps.NodeID]; ok {
			ns.Attempts, ns.Health = o.Attempts, o.Health
			switch {
			case o.Phase == phaseDone:
				ns.Invalidated = "在这次运行中装好之后，它的内容或服务器又变了"
				reset = append(reset, ps.NodeID)
			case o.Phase == phaseFailed || o.Phase == phaseUnknown:
				// Still needs the re-check of its actual record.
				ns.Phase, ns.Outcome, ns.Code, ns.Message, ns.Leftovers = o.Phase, o.Outcome, o.Code, o.Message, o.Leftovers
			case (o.Phase == phaseReview || o.Phase == phaseBlocked) && o.ReviewBundle == ps.PlanBundle && (ps.Kind == "gateway" || sameTarget(o.ReviewTarget, ps.PlanTarget)):
				ns.Phase, ns.PreflightID, ns.ReviewBundle, ns.ReviewTarget, ns.ReviewExpires, ns.Message = o.Phase, o.PreflightID, o.ReviewBundle, o.ReviewTarget, o.ReviewExpires, o.Message
				kept = append(kept, ps.NodeID)
			case o.Phase == phaseReview || o.Phase == phaseBlocked:
				if o.ReviewBundle != ps.PlanBundle {
					ns.Invalidated = "重新计划时发现预检之后这个节点要下发的内容变了：预检作废"
				} else {
					ns.Invalidated = "重新计划时发现预检之后服务器身份变了：预检作废"
				}
				reset = append(reset, ps.NodeID)
			default:
				ns.RetryAt, ns.Message, ns.Code = o.RetryAt, o.Message, o.Code
			}
		}
		steps = append(steps, ns)
	}
	run.Steps, run.Skipped, run.Notes, run.TopologyVersion, run.UpdatedAt = steps, p.Skipped, p.Notes, p.TopologyVersion, now
	stopped := false
	for _, st := range steps {
		if st.Phase == phaseFailed || st.Phase == phaseUnknown {
			stopped = true
		}
	}
	if !stopped {
		run.State, run.StopReason = runActive, ""
	}
	if run.current() < 0 && run.State != runDone {
		completeRun(run, now)
	}
	run.event(now, "", fmt.Sprintf("按当前拓扑重新计划：%d 个步骤，保留预检 %d 个，预检作废 %d 个", len(steps), len(kept), len(reset)))
	s.saveRunLocked(run)
	writeJSON(w, http.StatusOK, s.deployView(run))
}

func (s *Server) postDeployCancel(w http.ResponseWriter, r *http.Request) {
	if err := decodeStrict(w, r, &struct{}{}, nil, nil, true); err != nil {
		writeResErr(w, err)
		return
	}
	s.deployMu.Lock()
	defer s.deployMu.Unlock()
	run := s.loadRunLocked()
	if run == nil || run.ID != r.PathValue("id") {
		writeCoded(w, http.StatusNotFound, credentials.CodeNotFound, "没有这个部署引导", nil)
		return
	}
	if !run.open() {
		writeCoded(w, http.StatusConflict, codeDeployRunClosed, "这个部署引导"+runStateText(run.State), nil)
		return
	}
	for _, st := range run.Steps {
		if inFlight(st.Phase) {
			writeCoded(w, http.StatusConflict, codeDeployStepRunning, st.NodeName+" 正在执行：等它结束后再取消（执行中的一步不能中途撤销）", nil)
			return
		}
	}
	now := s.now()
	run.State, run.UpdatedAt = runCancelled, now
	run.event(now, "", "已取消：已完成的节点保持不变，没有撤回任何东西")
	s.saveRunLocked(run)
	writeJSON(w, http.StatusOK, s.deployView(run))
}

// deployStatus is the short form for GET /api/status.
type deployStatus struct {
	ID      string `json:"id"`
	State   string `json:"state"`
	Current string `json:"current,omitempty"`
	Done    int    `json:"done"`
	Total   int    `json:"total"`
	// Installed: done steps installed and health-checked in this run;
	// Adopted: done steps adopted from a record (not executed, health
	// not re-checked), including those already in sync.
	Installed int `json:"installed"`
	Adopted   int `json:"adopted"`
}

func (s *Server) deployStatusOf() *deployStatus {
	s.deployMu.Lock()
	defer s.deployMu.Unlock()
	r := s.loadRunLocked()
	if !r.open() {
		return nil
	}
	ds := &deployStatus{ID: r.ID, State: r.State, Total: len(r.Steps)}
	for _, st := range r.Steps {
		if st.Phase == phaseDone {
			ds.Done++
			if completionOf(st) == completionInstalled {
				ds.Installed++
			} else {
				ds.Adopted++
			}
		}
	}
	if i := r.current(); i >= 0 {
		ds.Current = r.Steps[i].NodeID
	}
	return ds
}
