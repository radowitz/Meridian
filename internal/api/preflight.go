package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/radowitz/meridian/internal/apply"
	"github.com/radowitz/meridian/internal/compile"
	"github.com/radowitz/meridian/internal/credentials"
	"github.com/radowitz/meridian/internal/hostexec"
	"github.com/radowitz/meridian/internal/model"
	"github.com/radowitz/meridian/internal/preflight"
	"github.com/radowitz/meridian/internal/provision"
	"github.com/radowitz/meridian/internal/sshexec"
	"github.com/radowitz/meridian/internal/validate"
)

// The install pre-check ("preflight") before a remote node is provisioned
// and before the gateway install. See docs/architecture.md「装机前预检」.
//
//   - POST /api/provision/preflight {node_id} runs the fixed, read-only
//     preflight script on the node's server (pinned host key) and stores
//     the result bound to the target identity (server, address, port,
//     user, pinned fingerprint, credential) and to the digest of the
//     node's bundle, valid for preflightTTL.
//   - POST /api/host/preflight {} does the same for the gateway through
//     meridian-host's fixed preflight action.
//   - POST /api/provision and POST /api/apply {install:true} take the
//     reviewed preflight_id. A first install without one is refused
//     (preflight_required). Immediately before executing, the preflight is
//     run again; execution is refused when it has blocking findings
//     (preflight_blocked), when the reviewed result is stale
//     (preflight_stale), when the target identity changed
//     (target_changed), when the node's bundle changed (bundle_changed) or
//     when new warnings or blocking findings appeared (preflight_changed).
//     Blocking findings cannot be overridden.

const (
	codePreflightRequired = "preflight_required"
	codePreflightStale    = "preflight_stale"
	codePreflightBlocked  = "preflight_blocked"
	codePreflightChanged  = "preflight_changed"
	codePreflightFailed   = "preflight_failed"
	codeBundleChanged     = "bundle_changed"
	codeNodeBusy          = "node_busy"

	codeProvisionRefused     = "provision_refused"
	codeProvisionCompensated = "provision_failed_compensated"
	codeProvisionLeftovers   = "provision_failed_leftovers"

	// preflightTTL is how long a reviewed result may be used.
	preflightTTL = 10 * time.Minute

	deploymentKey     = "panel_deployment_id"
	provisionStateKey = "provision_state"
)

// notChecked is shown with every result: what the preflight does not
// establish.
var notChecked = []string{
	"不检查放行规则是否覆盖 Meridian 的端口（只看 INPUT/FORWARD 的默认策略、DOCKER-USER 是否存在和 FORWARD 跳转的先后，以及别的表的 drop 链）",
	"不检查云厂商安全组、上游防火墙或 NAT：端口能否从外面到达要在装好后看握手",
	"不预测别的服务以后的改动：Docker 重启时 meridian-fwcompat.service 会重新加上 DOCKER-USER 规则；WARP 重连、有人手动启动或重载 nftables.service 不在预检之内（会清空规则集的 nftables.service 已启用或在运行时直接拒绝）",
	"不检查 SmartDNS 上游是否可用，也不建立 WSS 连接（WSS 证书和路径由面板生成，预检不验证两端能否握手）；面板下发的 wstunnel / SmartDNS 只核对架构、路径和 SHA-256，不在预检里执行它们",
	"不在预检里执行 nft：远端规则集已避开 nft 0.9.3（Ubuntu 20.04）不确定的写法，装机时 meridian-up.sh 仍先 nft -c，失败会在激活前停止并补偿",
	"iptables-legacy 主机只看 filter 表 INPUT/FORWARD 的默认策略、DOCKER-USER 和 FORWARD 的跳转，不逐条检查 legacy 规则、nat 改写和 MARK",
	"WARP 只读进程名和地址作为依赖线索（连到它本地监听的进程、指向它的 resolv.conf），不读它的配置和账户",
	"不检查 sudo：只接受 root 登录",
	"面板只改它自己的东西：受管文件、接口、nft 表、路由，以及在 Docker 的 FORWARD DROP 可以安全共存时 DOCKER-USER 里带 Meridian 注释的放行规则；不改 Docker、ufw、firewalld、nftables.service 的配置和策略（面板只下发并安装它自己的固定版本 wstunnel / SmartDNS 到 /usr/local/sbin/meridian-*，主机不需要自己下载）",
}

// targetIdentity is what a preflight result is bound to.
type targetIdentity struct {
	ServerID       string `json:"server_id"`
	ServerName     string `json:"server_name"`
	Address        string `json:"address"`
	Port           int    `json:"port"`
	User           string `json:"user"`
	Fingerprint    string `json:"fingerprint"`
	KeyType        string `json:"key_type,omitempty"`
	CredentialID   string `json:"credential_id"`
	CredentialName string `json:"credential_name,omitempty"`
	AuthMethod     string `json:"auth_method,omitempty"`
}

func (a targetIdentity) same(b targetIdentity) bool {
	return a.ServerID == b.ServerID && a.Address == b.Address && a.Port == b.Port && a.User == b.User &&
		a.Fingerprint == b.Fingerprint && a.CredentialID == b.CredentialID
}

type hostSummary struct {
	OS         string   `json:"os,omitempty"`
	Arch       string   `json:"arch,omitempty"`
	Kernel     string   `json:"kernel,omitempty"`
	MemTotalKB int64    `json:"mem_total_kb"`
	MemAvailKB int64    `json:"mem_avail_kb"`
	Complete   bool     `json:"complete"`
	Notes      []string `json:"notes,omitempty"`
}

// preflightRecord is one stored result. It holds no secret: addresses,
// names, ports and hashes only.
type preflightRecord struct {
	ID           string              `json:"id"`
	Kind         string              `json:"kind"` // remote | gateway
	NodeID       string              `json:"node_id"`
	NodeName     string              `json:"node_name"`
	Role         string              `json:"role"`
	Target       *targetIdentity     `json:"target,omitempty"`
	Deployment   string              `json:"deployment"`
	Bundle       string              `json:"bundle"`
	FirstInstall bool                `json:"first_install"`
	At           time.Time           `json:"at"`
	ExpiresAt    time.Time           `json:"expires_at"`
	Host         hostSummary         `json:"host"`
	Footprint    preflight.Footprint `json:"footprint"`
	NotChecked   []string            `json:"not_checked"`
	// HostRecord (remote) is what the host's own install record says: the
	// manifest header and the journal state. The ordered deployment guide
	// reads it before retrying a node, so content that is already there is
	// adopted instead of installed again. No secret: names and digests.
	HostRecord *hostRecord `json:"host_record,omitempty"`
	preflight.Evaluation
}

// hostRecord is the header of a remote node's manifest and its journal.
type hostRecord struct {
	Node         string `json:"node,omitempty"`
	Deployment   string `json:"deployment,omitempty"`
	Server       string `json:"server,omitempty"`
	Bundle       string `json:"bundle,omitempty"`
	Installed    int64  `json:"installed,omitempty"`
	JournalState string `json:"journal_state,omitempty"`
	JournalRun   string `json:"journal_run,omitempty"`
}

func hostRecordOf(r preflight.Report) *hostRecord {
	if !r.Complete || (r.Manifest == nil && r.Journal == nil) {
		return nil
	}
	h := &hostRecord{}
	if m := r.Manifest; m != nil {
		h.Node, h.Deployment, h.Server, h.Bundle, h.Installed = m.Node, m.Deployment, m.Server, m.Bundle, m.Installed
	}
	if j := r.Journal; j != nil {
		h.JournalState, h.JournalRun = j.State, j.Run
	}
	return h
}

func preflightKey(node string) string { return "preflight/" + node }

func (s *Server) savePreflight(rec *preflightRecord) error {
	b, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	return s.Store.Put(preflightKey(rec.NodeID), string(b))
}

func (s *Server) loadPreflight(node string) *preflightRecord {
	raw, ok, err := s.Store.Get(preflightKey(node))
	if err != nil || !ok || raw == "" {
		return nil
	}
	var rec preflightRecord
	if json.Unmarshal([]byte(raw), &rec) != nil {
		return nil
	}
	return &rec
}

// deploymentID identifies this panel installation in node manifests, so a
// host provisioned by another panel is not taken for ours.
func (s *Server) deploymentID() (string, error) {
	s.provMu.Lock()
	defer s.provMu.Unlock()
	if v, ok, err := s.Store.Get(deploymentKey); err != nil {
		return "", err
	} else if ok && v != "" {
		return v, nil
	}
	id := "dep-" + randHex(8)
	return id, s.Store.Put(deploymentKey, id)
}

// lockNode keeps one preflight or provision per node at a time.
func (s *Server) lockNode(id string) bool {
	s.provMu.Lock()
	defer s.provMu.Unlock()
	if s.provBusy == nil {
		s.provBusy = map[string]bool{}
	}
	if s.provBusy[id] {
		return false
	}
	s.provBusy[id] = true
	return true
}

func (s *Server) unlockNode(id string) {
	s.provMu.Lock()
	delete(s.provBusy, id)
	s.provMu.Unlock()
}

func refuseBusy(w http.ResponseWriter, node string) {
	writeCoded(w, http.StatusConflict, codeNodeBusy, fmt.Sprintf("节点 %s 正在预检或装机，等它结束再试", node), nil)
}

// identityOf is the node's current target: its server's address, port,
// user, pinned fingerprint and credential.
func identityOf(cs *credentials.Store, n model.Node) (targetIdentity, error) {
	sv, err := cs.Server(n.ServerID)
	if err != nil {
		return targetIdentity{}, err
	}
	id := targetIdentity{ServerID: sv.ID, ServerName: sv.Name, Address: sv.Address, Port: sv.Port, User: sv.User,
		Fingerprint: sv.HostKey.Fingerprint, KeyType: sv.HostKey.KeyType, CredentialID: sv.CredentialID, AuthMethod: sv.Auth}
	if c, err := cs.SSHCredential(sv.CredentialID); err == nil {
		id.CredentialName = c.Name
	}
	return id, nil
}

func (t targetIdentity) target() sshexec.Target {
	return sshexec.Target{ServerID: t.ServerID, CredentialID: t.CredentialID, Address: t.Address, Port: t.Port, User: t.User, Fingerprint: t.Fingerprint}
}

// portSources tells the evaluation which topology field sets each port the
// node's bundle binds (validate.NodePorts, the same plan compile uses), so
// a port_in_use finding names the field to change.
func (s *Server) portSources(nodeID string) []preflight.PortSource {
	t, err := s.topology()
	if err != nil {
		return nil
	}
	if nodeID == localNodeID {
		if gw, ok := firstNodeOfRole(t, model.RoleGateway); ok {
			nodeID = gw.ID
		}
	}
	var out []preflight.PortSource
	for _, u := range validate.NodePorts(t, nodeID) {
		out = append(out, preflight.PortSource{Proto: u.Proto, Port: u.Port, Loopback: u.Loopback, What: u.What, Kind: u.Kind, ID: u.ID, Field: u.Field})
	}
	return out
}

func firstNodeOfRole(t model.Topology, r model.Role) (model.Node, bool) {
	for _, n := range t.Nodes {
		if n.Role == r {
			return n, true
		}
	}
	return model.Node{}, false
}

func summaryOf(r preflight.Report) hostSummary {
	return hostSummary{OS: r.OSPretty, Arch: r.Arch, Kernel: r.Kernel, MemTotalKB: r.MemTotalKB, MemAvailKB: r.MemAvailKB, Complete: r.Complete, Notes: r.Notes}
}

// ------------------------------------------------------------ remote ---

// runRemotePreflight runs the fixed preflight on the node's server, pinned
// to ident, and stores the evaluated result.
func (s *Server) runRemotePreflight(ctx context.Context, cs *credentials.Store, n model.Node, files map[string]string, ident targetIdentity, first bool) (*preflightRecord, error) {
	dep, err := s.deploymentID()
	if err != nil {
		return nil, err
	}
	fp := preflight.FootprintOf(files)
	args, err := preflight.ArgsWithProbes(fp.PreflightPaths(), fp.PreflightProbes())
	if err != nil {
		return nil, &credentials.Error{Code: codePreflightFailed, Msg: "节点的文件路径不能交给预检：" + err.Error()}
	}
	res, err := s.connector(cs).RunPreflight(ctx, ident.target(), args)
	if err != nil {
		return nil, err
	}
	rep := preflight.Parse(res.Output)
	rep.Source = "ssh"
	ev := preflight.Evaluate(rep, fp, preflight.Context{NodeID: n.ID, Deployment: dep, Ports: s.portSources(n.ID), Artifacts: s.artifactContext()})
	now := time.Now().UTC()
	if res.AuthMethod != "" {
		ident.AuthMethod = res.AuthMethod
	}
	rec := &preflightRecord{ID: "pf-" + randHex(8), Kind: "remote", NodeID: n.ID, NodeName: n.Name, Role: string(n.Role), Target: &ident,
		Deployment: dep, Bundle: preflight.BundleDigest(files), FirstInstall: first, At: now, ExpiresAt: now.Add(preflightTTL),
		Host: summaryOf(rep), Footprint: fp, NotChecked: notChecked, Evaluation: ev, HostRecord: hostRecordOf(rep)}
	if err := s.savePreflight(rec); err != nil {
		return nil, err
	}
	if rep.Complete {
		// The host's manifest is a read-back of what was installed there.
		s.recordHostManifest(n.ID, ident, dep, rep.Manifest, now)
	}
	return rec, nil
}

type preflightBody struct {
	NodeID       string `json:"node_id"`
	GenerateKeys bool   `json:"generate_keys"`
}

func (s *Server) postProvisionPreflight(w http.ResponseWriter, r *http.Request) {
	var body preflightBody
	if err := decodeStrict(w, r, &body, []string{"node_id", "generate_keys"}, provisionRemoved, false); err != nil {
		writeResErr(w, err)
		return
	}
	t, err := s.topology()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	node, ok := t.NodeByID(body.NodeID)
	if !ok {
		writeResErr(w, &credentials.Error{Code: credentials.CodeNotFound, Field: "node_id", Msg: "节点不存在"})
		return
	}
	if !node.Managed || node.Role == model.RoleGateway {
		writeResErr(w, &credentials.Error{Code: codeBadRequest, Field: "node_id", Msg: "该节点不经 SSH 装机（网关用「安装到网关」，IX 专线不需要装机）"})
		return
	}
	cs, err := s.credStore()
	if err != nil {
		writeResErr(w, err)
		return
	}
	if err := checkServerOperable(cs, node); err != nil {
		writeResErr(w, err)
		return
	}
	if !s.lockNode(node.ID) {
		refuseBusy(w, node.ID)
		return
	}
	defer s.unlockNode(node.ID)
	if s.refuseDeployedElsewhere(w, node) {
		return
	}
	// Every managed node gets its WireGuard key now (panel-side only), so the
	// reviewed bundle already names real peer keys and stays the same when
	// the peers are installed later.
	t, _, err = s.ensureNodeKeys()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	node, _ = t.NodeByID(body.NodeID)
	b, err := s.compileTopo(t)
	if err != nil {
		writeErr(w, http.StatusUnprocessableEntity, err)
		return
	}
	if refuseNodePeerKeys(w, b, node.ID) {
		return
	}
	ident, err := identityOf(cs, node)
	if err != nil {
		writeResErr(w, err)
		return
	}
	rec, err := s.runRemotePreflight(r.Context(), cs, node, provision.FilesFor(b.Files, node.ID), ident, !s.provisionedOK(node, ident))
	if err != nil {
		s.writeSSHErrHelp(w, cs, node.ServerID, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"preflight": rec})
}

func (s *Server) getProvisionPreflight(w http.ResponseWriter, r *http.Request) {
	rec := s.loadPreflight(r.PathValue("node"))
	if rec == nil {
		writeResErr(w, &credentials.Error{Code: credentials.CodeNotFound, Msg: "这个节点还没有预检记录"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"preflight": rec, "stale": time.Now().After(rec.ExpiresAt)})
}

// gateReviewed checks a reviewed result before anything is re-run. It
// writes the refusal and returns nil, false when execution must not go on.
func (s *Server) gateReviewed(w http.ResponseWriter, node, id, bundle string, ident *targetIdentity) (*preflightRecord, bool) {
	rec := s.loadPreflight(node)
	dep, _ := s.deploymentID()
	switch {
	case rec == nil || rec.ID != id || rec.NodeID != node:
		writeCoded(w, http.StatusConflict, codePreflightStale, "这条预检记录不存在，或已被更新的预检替换：重新预检后再执行", nil)
	case rec.Deployment != dep:
		writeCoded(w, http.StatusConflict, codePreflightStale, "预检记录属于另一个面板实例：重新预检", nil)
	case time.Now().After(rec.ExpiresAt):
		writeCoded(w, http.StatusConflict, codePreflightStale,
			fmt.Sprintf("预检结果已过期（%s 做的，有效 %d 分钟）：重新预检后再执行", rec.At.Format(time.RFC3339), int(preflightTTL.Minutes())), map[string]any{"preflight": rec})
	case ident != nil && (rec.Target == nil || !rec.Target.same(*ident)):
		was := "—"
		if rec.Target != nil {
			was = fmt.Sprintf("%s@%s:%d（%s，凭据 %s）", rec.Target.User, rec.Target.Address, rec.Target.Port, rec.Target.Fingerprint, rec.Target.CredentialID)
		}
		writeCoded(w, http.StatusConflict, sshexec.CodeTargetChanged,
			fmt.Sprintf("预检之后目标变了：预检时是 %s，现在是 %s@%s:%d（%s，凭据 %s）。重新预检后再执行", was, ident.User, ident.Address, ident.Port, ident.Fingerprint, ident.CredentialID),
			map[string]any{"preflight": rec})
	case rec.Bundle != bundle:
		writeCoded(w, http.StatusConflict, codeBundleChanged, "预检之后这个节点要下发的配置变了（拓扑被修改）：重新预检后再执行", map[string]any{"preflight": rec})
	case rec.Blocking:
		writeCoded(w, http.StatusConflict, codePreflightBlocked, "预检有阻断项，不能执行：按每一项的处理办法解决后重新预检", map[string]any{"preflight": rec})
	default:
		return rec, true
	}
	return nil, false
}

// newConcerns lists warnings and blocking findings of fresh that the
// reviewed result did not have.
func newConcerns(reviewed, fresh *preflightRecord) []preflight.Finding {
	seen := map[string]bool{}
	for _, f := range reviewed.Findings {
		seen[f.Code+"\x00"+f.Resource] = true
	}
	var out []preflight.Finding
	for _, f := range fresh.Findings {
		if f.Severity != preflight.Info && !seen[f.Code+"\x00"+f.Resource] {
			out = append(out, f)
		}
	}
	return out
}

// gateFresh refuses on the result of the re-run right before execution.
func gateFresh(w http.ResponseWriter, reviewed, fresh *preflightRecord) bool {
	if fresh.Blocking {
		writeCoded(w, http.StatusConflict, codePreflightBlocked, "执行前重新预检发现阻断项，没有执行：按每一项的处理办法解决后重新预检", map[string]any{"preflight": fresh})
		return false
	}
	if reviewed != nil {
		if added := newConcerns(reviewed, fresh); len(added) > 0 {
			var codes []string
			for _, f := range added {
				codes = append(codes, f.Code)
			}
			writeCoded(w, http.StatusConflict, codePreflightChanged,
				"执行前重新预检出现了审阅时没有的问题（"+strings.Join(codes, "、")+"）：请审阅新的结果后再执行", map[string]any{"preflight": fresh})
			return false
		}
	}
	return true
}

// ------------------------------------------------------ provision state ---

// provisionOutcome is the last provision of a node, as the panel saw it.
type provisionOutcome struct {
	NodeID      string    `json:"node_id"`
	ServerID    string    `json:"server_id"`
	Address     string    `json:"address"`
	Port        int       `json:"port"`
	Fingerprint string    `json:"fingerprint"`
	Run         string    `json:"run"`
	Bundle      string    `json:"bundle"`
	At          time.Time `json:"at"`
	OK          bool      `json:"ok"`
	Code        string    `json:"code,omitempty"`
	Reason      string    `json:"reason,omitempty"`
	Leftovers   []string  `json:"leftovers,omitempty"`
	Kept        []string  `json:"kept,omitempty"`
	Restored    bool      `json:"restored_previous,omitempty"`
	// Installed: a provision of this node on this server succeeded before
	// (kept across later failures; "first install" means it never did).
	// A verified withdraw clears it.
	Installed bool `json:"installed"`
	// The rest of the identity the run was bound to, so a withdraw reaches
	// exactly that host with exactly that credential even after the node
	// was removed from the topology or moved to another server.
	User         string `json:"user,omitempty"`
	CredentialID string `json:"credential_id,omitempty"`
	Deployment   string `json:"deployment,omitempty"`
	NodeName     string `json:"node_name,omitempty"`
	// Outcome is the last provision's: installed, refused, compensated,
	// left_behind or unknown.
	Outcome string `json:"outcome,omitempty"`
	// Evidence says where Outcome came from when the script's own markers
	// did not reach the panel: "host_journal" (the host's journal for this
	// run, read on the same login right after the script ended).
	Evidence string `json:"evidence,omitempty"`
	// What the last successful install of this node put on the host, kept
	// across later failed attempts on the same server: the digest of the
	// node's files (preflight.BundleDigest, the same digest the host's
	// manifest records as "bundle"), when, which run, and the identity it
	// was installed to. The node's pending changes are computed against
	// InstalledBundle, never against another node's install or the
	// gateway's snapshot. Empty on records written before it existed until
	// migrateOutcome or a preflight fills it.
	InstalledBundle string          `json:"installed_bundle,omitempty"`
	InstalledAt     *time.Time      `json:"installed_at,omitempty"`
	InstalledRun    string          `json:"installed_run,omitempty"`
	InstalledTarget *targetIdentity `json:"installed_target,omitempty"`
	// Verify is the last read-back of the host's own record of the
	// install (after the install on the same login, or by a preflight).
	Verify *nodeVerify `json:"verify,omitempty"`
	// Withdraw is the last withdraw / recovery of this node (withdraw.go).
	Withdraw *withdrawRecord `json:"withdraw,omitempty"`
}

func (s *Server) loadOutcomes() map[string]provisionOutcome {
	out := map[string]provisionOutcome{}
	if raw, ok, err := s.Store.Get(provisionStateKey); err == nil && ok {
		_ = json.Unmarshal([]byte(raw), &out)
	}
	for k, o := range out {
		out[k] = migrateOutcome(o)
	}
	return out
}

func (s *Server) saveOutcome(o provisionOutcome) {
	s.provMu.Lock()
	defer s.provMu.Unlock()
	all := s.loadOutcomes()
	if prev, ok := all[o.NodeID]; ok && prev.Installed && prev.ServerID == o.ServerID {
		o.Installed = true
		if !o.OK {
			// A failed attempt leaves the previous install in place (the
			// script compensates back to it): its record stays.
			o.InstalledBundle, o.InstalledAt, o.InstalledRun, o.InstalledTarget = prev.InstalledBundle, prev.InstalledAt, prev.InstalledRun, prev.InstalledTarget
			if o.Verify == nil {
				o.Verify = prev.Verify
			}
		}
	}
	if prev, ok := all[o.NodeID]; ok && !o.OK && prev.ServerID == o.ServerID && prev.Withdraw != nil && o.Withdraw == nil {
		// A failed provision does not erase what a withdraw left behind.
		o.Withdraw = prev.Withdraw
	}
	if o.OK {
		o.Installed = true
		at := o.At
		o.InstalledBundle, o.InstalledAt, o.InstalledRun = o.Bundle, &at, o.Run
		o.InstalledTarget = &targetIdentity{ServerID: o.ServerID, Address: o.Address, Port: o.Port, User: o.User, Fingerprint: o.Fingerprint, CredentialID: o.CredentialID}
	}
	all[o.NodeID] = o
	if b, err := json.Marshal(all); err == nil {
		_ = s.Store.Put(provisionStateKey, string(b))
	}
}

// provisionedOK: this node was successfully provisioned on this server
// (same address and pinned key) before.
func (s *Server) provisionedOK(n model.Node, ident targetIdentity) bool {
	o, ok := s.loadOutcomes()[n.ID]
	return ok && o.Installed && o.ServerID == ident.ServerID && o.Address == ident.Address && o.Fingerprint == ident.Fingerprint
}

// updateOutcome changes one node's record under the lock.
func (s *Server) updateOutcome(node string, f func(o *provisionOutcome)) {
	s.provMu.Lock()
	defer s.provMu.Unlock()
	all := s.loadOutcomes()
	o, ok := all[node]
	if !ok {
		o = provisionOutcome{NodeID: node}
	}
	f(&o)
	all[node] = o
	if b, err := json.Marshal(all); err == nil {
		_ = s.Store.Put(provisionStateKey, string(b))
	}
}

// getProvisionState returns the provision records (nodes, by node ID) and
// every managed node's install state (states, see node_state.go).
func (s *Server) getProvisionState(w http.ResponseWriter, r *http.Request) {
	out := map[string]any{"nodes": s.loadOutcomes()}
	if t, err := s.topology(); err == nil {
		b, cerr := s.compileTopo(t)
		if cerr != nil {
			b = nil
		}
		ap := s.applier(true)
		gw := statusInstall{State: "unknown"}
		if inst, err := ap.Installed(); err == nil {
			gw = s.installState(ap, inst, func() (*compile.Bundle, error) { return b, cerr })
		}
		states := s.nodeStates(t, b, gw)
		if states == nil {
			states = []nodeInstallState{}
		}
		out["states"] = states
	}
	writeJSON(w, http.StatusOK, out)
}

// scriptOutcome reads the markers the provision script prints.
type scriptOutcome struct {
	OK, Compensated, Incomplete, Restored bool
	Refused                               string
	Leftovers, Kept                       []string
}

func parseScriptOutcome(out string) scriptOutcome {
	var o scriptOutcome
	for _, l := range strings.Split(out, "\n") {
		l = strings.TrimSpace(l)
		switch {
		case l == "MERIDIAN_PROVISION_OK":
			o.OK = true
		case l == "MERIDIAN_COMPENSATED":
			o.Compensated = true
		case l == "MERIDIAN_COMPENSATION_INCOMPLETE":
			o.Incomplete = true
		case l == "MERIDIAN_RESTORED_PREVIOUS":
			o.Restored = true
		case strings.HasPrefix(l, "MERIDIAN_REFUSED "):
			o.Refused = preflight.Clean(strings.TrimPrefix(l, "MERIDIAN_REFUSED "))
		case strings.HasPrefix(l, "MERIDIAN_LEFTOVER "):
			if len(o.Leftovers) < 64 {
				o.Leftovers = append(o.Leftovers, preflight.Clean(strings.TrimPrefix(l, "MERIDIAN_LEFTOVER ")))
			}
		case strings.HasPrefix(l, "MERIDIAN_KEPT "):
			if len(o.Kept) < 64 {
				o.Kept = append(o.Kept, preflight.Clean(strings.TrimPrefix(l, "MERIDIAN_KEPT ")))
			}
		}
	}
	return o
}

// ----------------------------------------------------------- gateway ---

// HostPreflightRuntime is meridian-host's read-only preflight action
// (hostexec.Client).
type HostPreflightRuntime interface {
	Preflight(ctx context.Context, paths []string) (string, error)
}

func (s *Server) hostPreflighter() HostPreflightRuntime {
	if s.HostPreflight != nil {
		return s.HostPreflight
	}
	if p, ok := s.Host.(HostPreflightRuntime); ok {
		return p
	}
	return nil
}

// gatewayGateActive: installs go to a real host (or a test fake), so the
// pre-check applies. Without Host the install itself is refused
// (host_unavailable) or runs against the test shim.
func (s *Server) gatewayGateActive() bool {
	return s.Host != nil || s.HostPreflight != nil
}

func ownedOf(m apply.Manifest) *preflight.Owned {
	if m.Empty() {
		return nil
	}
	o := &preflight.Owned{Files: map[string]string{}, Interfaces: m.Interfaces, Units: m.Units, NFTTables: m.NFTTables, Tables: m.RouteTables, DNS: m.DNS}
	for _, f := range m.Files {
		// The installed copy holds the placeholder, the host the injected
		// key: hashes are not comparable, so none is given.
		o.Files["/"+strings.TrimPrefix(f.Path, "/")] = ""
	}
	for _, x := range m.Artifacts {
		o.Files["/"+strings.TrimPrefix(x.Path, "/")] = x.SHA256
	}
	return o
}

func (s *Server) runHostPreflight(ctx context.Context, files map[string]string) (*preflightRecord, error) {
	p := s.hostPreflighter()
	if p == nil {
		return nil, hostexec.ErrUnavailable
	}
	dep, err := s.deploymentID()
	if err != nil {
		return nil, err
	}
	inst, err := s.applier(true).Installed()
	if err != nil {
		return nil, err
	}
	fp := preflight.FootprintOf(files)
	paths := fp.PreflightPaths()
	if err := preflight.ValidatePaths(paths); err != nil {
		return nil, &credentials.Error{Code: codePreflightFailed, Msg: "网关的文件路径不能交给预检：" + err.Error()}
	}
	text, err := p.Preflight(ctx, paths)
	if err != nil {
		return nil, err
	}
	rep := preflight.Parse(text)
	rep.Source = "host-agent"
	ev := preflight.Evaluate(rep, fp, preflight.Context{NodeID: localNodeID, Deployment: dep, Gateway: true, Owned: ownedOf(inst), Ports: s.portSources(localNodeID), Artifacts: s.artifactContext()})
	now := time.Now().UTC()
	rec := &preflightRecord{ID: "pf-" + randHex(8), Kind: "gateway", NodeID: localNodeID, NodeName: "网关", Role: string(model.RoleGateway),
		Deployment: dep, Bundle: preflight.BundleDigest(files), FirstInstall: inst.Empty() || inst.Withdrawn(), At: now, ExpiresAt: now.Add(preflightTTL),
		Host: summaryOf(rep), Footprint: fp, NotChecked: notChecked, Evaluation: ev}
	if err := s.savePreflight(rec); err != nil {
		return nil, err
	}
	return rec, nil
}

func writeHostPreflightErr(w http.ResponseWriter, err error) {
	var ce *credentials.Error
	switch {
	case errors.As(err, &ce):
		writeCoded(w, http.StatusUnprocessableEntity, ce.Code, ce.Msg, nil)
	case errors.Is(err, hostexec.ErrUnavailable):
		writeCoded(w, http.StatusServiceUnavailable, codeHostUnavailable, "宿主执行通道不可用，不能做安装前预检："+err.Error(), nil)
	case errors.Is(err, hostexec.ErrPreflightUnsupported):
		writeCoded(w, http.StatusServiceUnavailable, codeHostUnavailable, err.Error(), nil)
	default:
		writeCoded(w, http.StatusBadGateway, codePreflightFailed, "安装前预检失败："+err.Error(), nil)
	}
}

func (s *Server) gatewayFiles() (map[string]string, error) {
	t, err := s.topology()
	if err != nil {
		return nil, err
	}
	b, err := s.compileTopo(t)
	if err != nil {
		return nil, err
	}
	return provision.FilesFor(b.Files, localNodeID), nil
}

func (s *Server) postHostPreflight(w http.ResponseWriter, r *http.Request) {
	if err := decodeStrict(w, r, &struct{}{}, nil, nil, true); err != nil {
		writeResErr(w, err)
		return
	}
	if s.hostPreflighter() == nil {
		writeHostPreflightErr(w, hostexec.ErrUnavailable)
		return
	}
	if !s.lockNode(localNodeID) {
		refuseBusy(w, localNodeID)
		return
	}
	defer s.unlockNode(localNodeID)
	files, err := s.gatewayFiles()
	if err != nil {
		if refuseInvalid(w, err) {
			return
		}
		writeCoded(w, http.StatusUnprocessableEntity, codeTopologyInvalid, err.Error(), nil)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Minute)
	defer cancel()
	rec, err := s.runHostPreflight(ctx, files)
	if err != nil {
		writeHostPreflightErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"preflight": rec})
}

// gateGatewayInstall runs the gateway pre-check gate for POST /api/apply
// {install:true}. files are the gateway's files compiled before any key
// is generated. It writes the refusal and returns false when the install
// must not go on.
func (s *Server) gateGatewayInstall(w http.ResponseWriter, r *http.Request, files map[string]string, reviewedID string) bool {
	if !s.gatewayGateActive() {
		return true
	}
	if s.hostPreflighter() == nil {
		writeCoded(w, http.StatusServiceUnavailable, codeHostUnavailable, "宿主执行通道不支持安装前预检（meridian-host 未运行、不可用或版本过旧），拒绝安装；宿主上没有写入任何文件", nil)
		return false
	}
	if !s.lockNode(localNodeID) {
		refuseBusy(w, localNodeID)
		return false
	}
	defer s.unlockNode(localNodeID)
	return s.gateGatewayInstallLocked(w, r.Context(), files, reviewedID)
}

// gateGatewayInstallLocked is gateGatewayInstall for a caller that already
// holds the gateway node lock (the ordered deployment guide keeps it until
// the host transaction has ended).
func (s *Server) gateGatewayInstallLocked(w http.ResponseWriter, ctx context.Context, files map[string]string, reviewedID string) bool {
	if !s.gatewayGateActive() {
		return true
	}
	if s.hostPreflighter() == nil {
		writeCoded(w, http.StatusServiceUnavailable, codeHostUnavailable, "宿主执行通道不支持安装前预检（meridian-host 未运行、不可用或版本过旧），拒绝安装；宿主上没有写入任何文件", nil)
		return false
	}
	inst, err := s.applier(true).Installed()
	if err != nil {
		writeCoded(w, http.StatusInternalServerError, codeHostStateMalformed, err.Error(), nil)
		return false
	}
	bundle := preflight.BundleDigest(files)
	var reviewed *preflightRecord
	switch {
	case reviewedID != "":
		var ok bool
		if reviewed, ok = s.gateReviewed(w, localNodeID, reviewedID, bundle, nil); !ok {
			return false
		}
	case inst.Empty() || inst.Withdrawn():
		writeCoded(w, http.StatusConflict, codePreflightRequired, "第一次安装到网关前（或撤回之后重新安装前）必须先做安装前预检并审阅结果（POST /api/host/preflight），再带上 preflight_id 安装", nil)
		return false
	}
	pctx, cancel := context.WithTimeout(ctx, 3*time.Minute)
	defer cancel()
	fresh, err := s.runHostPreflight(pctx, files)
	if err != nil {
		writeHostPreflightErr(w, err)
		return false
	}
	return gateFresh(w, reviewed, fresh)
}

// ------------------------------------------------------- login help ---

// keyHint is a panel-held key credential's public half.
type keyHint struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	PublicKey string `json:"public_key"`
}

// loginHelp tells the operator how to get a login the server accepts. It
// carries only public keys, and only when the server offers publickey
// login: a password-only server (for example one reached through a port
// forward that only allows passwords) stays fully usable with its
// password credential and is never told to switch to a key.
type loginHelp struct {
	Code           string    `json:"code"`
	Method         string    `json:"method"` // the credential's: password | key
	User           string    `json:"user"`
	Address        string    `json:"address"`
	CredentialID   string    `json:"credential_id,omitempty"`
	CredentialName string    `json:"credential_name,omitempty"`
	PublicKey      string    `json:"public_key,omitempty"`
	KeyCredentials []keyHint `json:"key_credentials,omitempty"`
	// Offered are the login methods the server offered (as far as the
	// handshake learned them); KeyOffered says whether publickey is one.
	Offered    []string `json:"offered_methods,omitempty"`
	KeyOffered bool     `json:"publickey_offered"`
	Steps      []string `json:"steps"`
}

func (s *Server) loginHelpFor(cs *credentials.Store, serverID, code string, offered []string) *loginHelp {
	if code != sshexec.CodeAuthFailed && code != sshexec.CodeAuthMethodUnavailable {
		return nil
	}
	sv, err := cs.Server(serverID)
	if err != nil {
		return nil
	}
	c, err := cs.SSHCredential(sv.CredentialID)
	if err != nil {
		return nil
	}
	keyOK := false
	pwOK := false
	for _, m := range offered {
		keyOK = keyOK || m == "publickey"
		pwOK = pwOK || m == "password" || m == "keyboard-interactive"
	}
	h := &loginHelp{Code: code, User: sv.User, Address: sv.Address, CredentialID: c.ID, CredentialName: c.Name, Offered: offered, KeyOffered: keyOK, Steps: []string{}}
	where := fmt.Sprintf("%s@%s 的 ~/.ssh/authorized_keys", sv.User, sv.Address)
	offeredText := "服务器没有告诉面板它接受哪些方式"
	if len(offered) > 0 {
		offeredText = "服务器提供的登录方式：" + strings.Join(offered, "、")
	}
	keys := func() {
		for _, k := range cs.SSHCredentials() {
			if k.Kind == credentials.KindPrivateKey && k.PublicKey != "" && len(h.KeyCredentials) < 8 {
				h.KeyCredentials = append(h.KeyCredentials, keyHint{ID: k.ID, Name: k.Name, PublicKey: k.PublicKey})
			}
		}
		sort.Slice(h.KeyCredentials, func(i, j int) bool { return h.KeyCredentials[i].Name < h.KeyCredentials[j].Name })
	}
	if c.Kind == credentials.KindPrivateKey {
		h.Method = model.AuthKey
		if code == sshexec.CodeAuthMethodUnavailable {
			// The server does not offer publickey at all: its public key is
			// of no use there, so none is shown.
			if pwOK {
				h.Steps = append(h.Steps, "服务器不提供公钥登录（"+offeredText+"）：在凭据页添加这台服务器的密码凭据，在服务器页把认证方式改为密码并选它；用密码登录，面板的全部功能都可以用",
					"想改用密钥时，先在服务器的 sshd_config 里设 PubkeyAuthentication yes 并重载 sshd，再重新「测试连接」")
			} else {
				h.Steps = append(h.Steps, "服务器既没有提供公钥登录，也没有提供密码登录（"+offeredText+"）：检查服务器的 sshd_config 后重新「测试连接」")
			}
			return h
		}
		h.PublicKey = c.PublicKey
		h.KeyOffered = true
		h.Steps = append(h.Steps, "服务器接受公钥登录，但没有接受这把密钥：把下面这把公钥追加到 "+where+"（一行，权限 600，目录 700）", "然后在服务器页重新「测试连接」")
		return h
	}
	h.Method = model.AuthPassword
	if code == sshexec.CodeAuthFailed {
		h.Steps = append(h.Steps, "服务器接受密码登录，但这份密码没有通过：在凭据页更新密码后重新测试")
		if keyOK {
			keys()
			if len(h.KeyCredentials) > 0 {
				h.Steps = append(h.Steps, "这台服务器也提供公钥登录：也可以把下面一把密钥的公钥追加到 "+where+"，再在服务器页把认证方式改为密钥并选这份凭据")
			}
		}
		return h
	}
	if !keyOK {
		// Password not offered and no publickey either: no key advice.
		h.Steps = append(h.Steps, "服务器不接受密码登录，也没有提供公钥登录（"+offeredText+"）：检查服务器的 sshd_config（PasswordAuthentication / PubkeyAuthentication）后重新「测试连接」")
		return h
	}
	keys()
	if len(h.KeyCredentials) > 0 {
		h.Steps = append(h.Steps, "服务器只接受密钥登录：把面板里一把密钥的公钥追加到 "+where+"，再在服务器页把认证方式改为密钥并选这份凭据")
	} else {
		h.Steps = append(h.Steps, "服务器只接受密钥登录：在凭据页「生成密钥」，把显示的公钥追加到 "+where+"，再在服务器页把认证方式改为密钥并选这份凭据")
	}
	return h
}

// writeSSHErrHelp is writeSSHErr plus login help for login failures.
func (s *Server) writeSSHErrHelp(w http.ResponseWriter, cs *credentials.Store, serverID string, err error) {
	if h := s.loginHelpFor(cs, serverID, sshexec.CodeOf(err), sshexec.OfferedOf(err)); h != nil {
		body := map[string]any{"error": err.Error(), "code": sshexec.CodeOf(err), "login_help": h}
		execFlags(body, err)
		writeJSON(w, http.StatusBadGateway, body)
		return
	}
	var ce *credentials.Error
	if errors.As(err, &ce) && ce.Code == codePreflightFailed {
		writeCoded(w, http.StatusUnprocessableEntity, ce.Code, ce.Msg, nil)
		return
	}
	writeSSHErr(w, err)
}

func (s *Server) registerPreflight(mux *http.ServeMux) {
	mux.HandleFunc("POST /api/provision/preflight", s.postProvisionPreflight)
	mux.HandleFunc("GET /api/provision/preflight/{node}", s.getProvisionPreflight)
	mux.HandleFunc("GET /api/provision/state", s.getProvisionState)
	mux.HandleFunc("POST /api/host/preflight", s.postHostPreflight)
}
