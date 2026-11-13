package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"time"

	"github.com/radowitz/meridian/internal/apply"
	"github.com/radowitz/meridian/internal/credentials"
	"github.com/radowitz/meridian/internal/mesh"
	"github.com/radowitz/meridian/internal/model"
	"github.com/radowitz/meridian/internal/provision"
	"github.com/radowitz/meridian/internal/sshexec"
)

// Withdraw ("撤回") and recovery from the panel. See docs/architecture.md
// 「撤回与失败后的恢复」.
//
// Deleting a node from the topology and withdrawing what was installed on
// its server are separate. A node's deployment record (provision_state) keeps
// the server identity the install was bound to (server id, address, port,
// user, pinned host key, credential); while anything may still be on that
// host the record pins the server and the credential (they cannot be
// deleted or repointed), and a provision of the node on another server is
// refused (deployed_elsewhere). A withdraw always goes to the recorded
// identity, never to whatever the node points at now.
//
// Remote node:
//
//	POST /api/provision/withdraw/plan {node_id, mode}     read-only plan
//	POST /api/provision/withdraw {node_id, plan_id, confirm} run it
//	POST /api/provision/withdraw/abandon {node_id, confirm}  give up (server gone)
//	DELETE /api/provision/state/{node}                     forget a finished record
//
// mode is manifest (default), journal (recover an interrupted provision) or
// legacy (pre-manifest install, fixed well-known paths only). The plan runs
// the fixed withdraw script read-only; the run re-runs it with the plan's
// digest and is refused when the host changed (plan_changed). confirm is
// the node id typed by the operator.
//
// Gateway:
//
//	POST /api/host/withdraw {confirm:"gw", release_guard?}
//
// GET /api/deployments lists every record and the gateway's state.

const (
	codeWithdrawRefused     = "withdraw_refused"
	codeWithdrawPartial     = "withdraw_partial"
	codeWithdrawUnknown     = "withdraw_unknown"
	codeRecoveryIncomplete  = "recovery_incomplete"
	codeWithdrawPlanStale   = "withdraw_plan_stale"
	codeConfirmRequired     = "confirm_required"
	codeMeshDeployed        = "mesh_deployed"
	codeDeployedElsewhere   = "deployed_elsewhere"
	codeNothingInstalled    = "nothing_installed"
	codeGatewayLegacy       = "legacy_install"
	codeGuardMissing        = "guard_missing"
	codeNotWithdrawn        = "not_withdrawn"
	codeGatewayWithdrawn    = "gateway_withdrawn"
	codeStillOnHost         = "still_on_host"
	withdrawPlanTTL         = 10 * time.Minute
	gatewayWithdrawKey      = "gateway_withdraw"
	withdrawScriptTimeout   = 10 * time.Minute
	withdrawStateRunning    = "running"
	withdrawStateDone       = "withdrawn"
	withdrawStateAlready    = "already_withdrawn"
	withdrawStatePartial    = "partial"
	withdrawStateRefused    = "refused"
	withdrawStateNotStarted = "not_started"
	withdrawStateUnknown    = "unknown"
	withdrawStateRecovered  = "recovered"
	withdrawStateRecoverInc = "recovery_incomplete"
	withdrawStateAbandoned  = "abandoned"
)

// withdrawRecord is the last withdraw (or recovery) of a node, persisted
// before the script runs ("running") and updated with what it reported.
type withdrawRecord struct {
	State     string    `json:"state"`
	Mode      string    `json:"mode"`
	Run       string    `json:"run"`
	At        time.Time `json:"at"`
	Finished  time.Time `json:"finished,omitempty"`
	Code      string    `json:"code,omitempty"`
	Reason    string    `json:"reason,omitempty"`
	Message   string    `json:"message,omitempty"`
	Removed   []string  `json:"removed,omitempty"`
	Kept      []string  `json:"kept,omitempty"`
	Leftovers []string  `json:"leftovers,omitempty"`
	Restored  bool      `json:"restored_previous,omitempty"`
	// RetryAfter (seconds) comes with code ssh_rate_limited.
	RetryAfter int `json:"retry_after,omitempty"`
}

// onHost: something of this deployment may still be on its server, so the
// identity stays pinned and the record cannot be forgotten.
func (o provisionOutcome) onHost() bool {
	if w := o.Withdraw; w != nil {
		switch w.State {
		case withdrawStateDone, withdrawStateAlready, withdrawStateAbandoned:
			return false
		case withdrawStateRunning, withdrawStatePartial, withdrawStateUnknown, withdrawStateRecoverInc:
			return true
		case withdrawStateRecovered:
			return o.Installed
		}
	}
	if o.Installed {
		return true
	}
	switch o.Outcome {
	case "left_behind", "unknown":
		return true
	case "":
		// Records from before the outcome was stored.
		return o.Code == codeProvisionLeftovers || o.Code == sshexec.CodeCommandFailed || o.Code == sshexec.CodeTimeout
	}
	return false
}

// status is the one word the deploy page shows.
func (o provisionOutcome) status(busy bool) string {
	if w := o.Withdraw; w != nil {
		switch w.State {
		case withdrawStateRunning:
			if busy {
				return "withdrawing"
			}
			return "withdraw_interrupted"
		case withdrawStateDone, withdrawStateAlready:
			return "withdrawn"
		case withdrawStateAbandoned:
			return "abandoned"
		case withdrawStatePartial:
			return "withdraw_partial"
		case withdrawStateUnknown:
			return "withdraw_unknown"
		case withdrawStateRecoverInc:
			return "left_behind"
		}
	}
	switch {
	case o.Installed:
		return "installed"
	case o.onHost() && o.Outcome == "unknown":
		return "unknown"
	case o.onHost():
		return "left_behind"
	}
	return "not_installed"
}

// refuseDeployedElsewhere refuses a preflight or provision of a node whose
// deployment may still be on another server than the one it points at now.
func (s *Server) refuseDeployedElsewhere(w http.ResponseWriter, n model.Node) bool {
	o, ok := s.loadOutcomes()[n.ID]
	if !ok || !o.onHost() || o.ServerID == "" || o.ServerID == n.ServerID {
		return false
	}
	writeCoded(w, http.StatusConflict, codeDeployedElsewhere,
		fmt.Sprintf("节点 %s 之前装在服务器 %s（%s:%d）上，还没有撤回：先在部署页撤回那台服务器上的安装（或在服务器确实已不存在时选择「放弃」），再装到新服务器", n.ID, o.ServerID, o.Address, o.Port),
		map[string]any{"deployment": o})
	return true
}

// nodeDeploymentPins are the hosts node deployments still need (see
// deploymentPins); read from the panel store only.
func (s *Server) nodeDeploymentPins() []credentials.PinnedHost {
	var out []credentials.PinnedHost
	for _, o := range s.loadOutcomes() {
		if !o.onHost() || o.ServerID == "" {
			continue
		}
		name := o.NodeName
		if name == "" {
			name = o.NodeID
		}
		out = append(out, credentials.PinnedHost{
			Deployment: credentials.Ref{Kind: "node_deployment", ID: o.NodeID, Name: "节点 " + name + " 的安装（未撤回）"},
			ServerID:   o.ServerID, CredentialID: o.CredentialID, Address: o.Address, Port: o.Port, User: o.User,
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Deployment.ID < out[j].Deployment.ID })
	return out
}

// meshBinds reports why a node's withdraw must wait for the Mesh
// withdrawal: Mesh runs on its host (sidecar on its interfaces) with its
// own binding to that host and the Cloudflare account. Order: Mesh first.
func (s *Server) meshBinds(node string) (string, bool) {
	j, err := (&mesh.Deployer{Dir: s.meshDir()}).Load()
	if err != nil {
		return "Mesh 部署记录无法读取：在弄清 Mesh 是否还部署在这台主机上之前不撤回（" + err.Error() + "）", true
	}
	if j == nil || !j.Busy() {
		return "", false
	}
	for _, h := range j.Hosts {
		if h.NodeID == node {
			return fmt.Sprintf("Mesh 部署（%s，状态 %s）还在这个节点的主机上：先在 Mesh 部署卡片里撤回 Mesh（按部署时绑定的主机和 Cloudflare 账户），成功后再撤回节点", j.RunID, j.State), true
		}
	}
	return "", false
}

// withdrawTarget is the identity a withdraw of node goes to: the recorded
// one when the node was provisioned, else (legacy or interrupted runs of a
// node without a record) the node's current server.
func (s *Server) withdrawTarget(cs *credentials.Store, t model.Topology, node string) (targetIdentity, *provisionOutcome, error) {
	if o, ok := s.loadOutcomes()[node]; ok && o.ServerID != "" {
		sv, err := cs.Server(o.ServerID)
		if err != nil {
			return targetIdentity{}, &o, &credentials.Error{Code: sshexec.CodeTargetChanged, Field: "node_id",
				Msg: fmt.Sprintf("部署时绑定的服务器 %s 已不存在：面板无法再连到那台主机。服务器确实已不存在时可以选择「放弃」", o.ServerID)}
		}
		user := o.User
		if user == "" {
			user = "root"
		}
		id := targetIdentity{ServerID: sv.ID, ServerName: sv.Name, Address: o.Address, Port: o.Port, User: user,
			Fingerprint: o.Fingerprint, CredentialID: o.CredentialID}
		if sv.Address != o.Address || sv.Port != o.Port || sv.User != user {
			return id, &o, &credentials.Error{Code: sshexec.CodeTargetChanged, Field: "node_id",
				Msg: fmt.Sprintf("服务器 %s 现在是 %s@%s:%d，不是部署时的 %s@%s:%d：撤回只去部署时的主机，已拒绝", sv.Name, sv.User, sv.Address, sv.Port, user, o.Address, o.Port)}
		}
		if sv.HostKey.State != model.HostKeyTrusted || sv.HostKey.Fingerprint != o.Fingerprint {
			return id, &o, &credentials.Error{Code: sshexec.CodePinMismatch, Field: "node_id",
				Msg: fmt.Sprintf("服务器 %s 现在信任的主机指纹（%s，状态 %s）不是部署时固定的 %s：可能已是另一台主机，已拒绝撤回", sv.Name, sv.HostKey.Fingerprint, sv.HostKey.State, o.Fingerprint)}
		}
		if id.CredentialID == "" {
			id.CredentialID = sv.CredentialID
		}
		if c, err := cs.SSHCredential(id.CredentialID); err == nil {
			id.CredentialName = c.Name
		} else {
			return id, &o, &credentials.Error{Code: credentials.CodeNoCredential, Field: "node_id",
				Msg: fmt.Sprintf("部署时使用的 SSH 凭据 %s 已不存在", id.CredentialID)}
		}
		return id, &o, nil
	}
	n, ok := t.NodeByID(node)
	if !ok {
		return targetIdentity{}, nil, &credentials.Error{Code: credentials.CodeNotFound, Field: "node_id", Msg: "这个节点既不在拓扑里，也没有部署记录"}
	}
	if err := checkServerOperable(cs, n); err != nil {
		return targetIdentity{}, nil, err
	}
	id, err := identityOf(cs, n)
	return id, nil, err
}

// withdrawPlanRecord is a reviewed plan, bound to the target and digest.
type withdrawPlanRecord struct {
	ID         string         `json:"id"`
	NodeID     string         `json:"node_id"`
	Mode       string         `json:"mode"`
	Target     targetIdentity `json:"target"`
	Deployment string         `json:"deployment"`
	Digest     string         `json:"digest"`
	Owner      string         `json:"owner,omitempty"`
	Items      []string       `json:"items"`
	At         time.Time      `json:"at"`
	ExpiresAt  time.Time      `json:"expires_at"`
	// Already: the host says this node was withdrawn already.
	Already bool `json:"already"`
}

func withdrawPlanKey(node string) string { return "withdraw_plan/" + node }

func (s *Server) loadWithdrawPlan(node string) *withdrawPlanRecord {
	raw, ok, err := s.Store.Get(withdrawPlanKey(node))
	if err != nil || !ok || raw == "" {
		return nil
	}
	var p withdrawPlanRecord
	if json.Unmarshal([]byte(raw), &p) != nil {
		return nil
	}
	return &p
}

func (s *Server) saveWithdrawPlan(p *withdrawPlanRecord) error {
	b, err := json.Marshal(p)
	if err != nil {
		return err
	}
	return s.Store.Put(withdrawPlanKey(p.NodeID), string(b))
}

// refusalText explains a script refusal code.
func refusalText(code string) string {
	switch code {
	case "manifest_missing":
		return "服务器上没有 Meridian 节点清单：没有可按清单撤回的安装（可能从未装成功，或已在别处清理）"
	case "manifest_other":
		return "服务器上的清单属于另一个节点或另一个面板部署：不撤回别人的安装"
	case "manifest_other_server":
		return "服务器上的清单是为本面板的另一台服务器写的：拒绝撤回"
	case "manifest_unreadable":
		return "服务器上的清单读不懂：请登录服务器检查 /var/lib/meridian/node/manifest"
	case "bad_manifest_entry":
		return "清单里有撤回脚本不接受的条目（不是 Meridian 的名字或路径）：整次拒绝，请登录服务器检查清单"
	case "legacy_install":
		return "服务器上是旧版 Meridian（没有清单）：可以用「旧版清理」，先只读列出固定路径上带 Meridian 标记的内容，确认后移除"
	case "legacy_none":
		return "固定路径上没有带 Meridian 标记的文件：没有可清理的旧版内容"
	case "manifest_present":
		return "服务器上有清单：按清单撤回，不用旧版清理"
	case "journal_incomplete":
		return "服务器上有一次没有正常结束的装机：先用「恢复中断的装机」补偿它"
	case "journal_clean", "journal_missing":
		return "服务器上没有未结束的装机，不需要恢复"
	case "journal_other":
		return "服务器上未结束的运行属于另一个节点或面板部署：拒绝"
	case "journal_unrecoverable":
		return "未结束的装机缺少工作目录或参数，面板无法据此补偿：请登录服务器按 /var/lib/meridian/node/journal 手动处理"
	case "plan_changed":
		return "审阅计划之后服务器上的状态变了：重新生成计划再确认"
	case "not_root":
		return "登录用户不是 root"
	}
	return "服务器上的撤回脚本拒绝执行（" + code + "）"
}

type withdrawPlanBody struct {
	NodeID string `json:"node_id"`
	Mode   string `json:"mode"`
}

func (s *Server) postWithdrawPlan(w http.ResponseWriter, r *http.Request) {
	var body withdrawPlanBody
	if err := decodeStrict(w, r, &body, []string{"node_id", "mode"}, provisionRemoved, false); err != nil {
		writeResErr(w, err)
		return
	}
	if body.NodeID == localNodeID {
		writeResErr(w, &credentials.Error{Code: codeBadRequest, Field: "node_id", Msg: "网关用 POST /api/host/withdraw 撤回"})
		return
	}
	if body.Mode == "" {
		body.Mode = provision.WithdrawManifest
	}
	cs, t, ok := s.resCtx(w)
	if !ok {
		return
	}
	if !s.lockNode(body.NodeID) {
		refuseBusy(w, body.NodeID)
		return
	}
	defer s.unlockNode(body.NodeID)
	ident, _, err := s.withdrawTarget(cs, t, body.NodeID)
	if err != nil {
		writeTargetErr(w, err)
		return
	}
	dep, err := s.deploymentID()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	o := provision.WithdrawOptions{NodeID: body.NodeID, Deployment: dep, ServerID: ident.ServerID, Run: "plan-" + randHex(4), Mode: body.Mode, Action: provision.WithdrawPlan}
	if err := provision.CheckWithdrawOptions(o); err != nil {
		writeResErr(w, &credentials.Error{Code: codeBadRequest, Msg: err.Error()})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Minute)
	defer cancel()
	res, err := s.connector(cs).RunScript(ctx, ident.target(), provision.WithdrawScript(o))
	wo := provision.ParseWithdrawOutput(res.Output)
	if wo.Refused != "" {
		writeCoded(w, http.StatusConflict, codeWithdrawRefused, refusalText(wo.Refused), map[string]any{"reason": wo.Refused, "owner": wo.Owner, "target": ident})
		return
	}
	now := time.Now().UTC()
	p := &withdrawPlanRecord{ID: "wp-" + randHex(6), NodeID: body.NodeID, Mode: body.Mode, Target: ident, Deployment: dep,
		Digest: wo.Digest, Owner: wo.Owner, Items: wo.Plan, At: now, ExpiresAt: now.Add(withdrawPlanTTL), Already: wo.Already}
	if p.Items == nil {
		p.Items = []string{}
	}
	if err != nil && !wo.Already {
		s.writeSSHErrHelp(w, cs, ident.ServerID, err)
		return
	}
	if !wo.Already && (!wo.PlanOK || wo.Digest == "") {
		writeCoded(w, http.StatusBadGateway, codeWithdrawUnknown, "撤回计划没有完整返回：不当作可执行，重试一次", nil)
		return
	}
	if wo.Already {
		// Nothing to confirm: record it so the deploy page is accurate.
		s.updateOutcome(body.NodeID, func(oc *provisionOutcome) {
			if oc.ServerID == "" {
				oc.ServerID, oc.Address, oc.Port, oc.Fingerprint, oc.User, oc.CredentialID = ident.ServerID, ident.Address, ident.Port, ident.Fingerprint, ident.User, ident.CredentialID
			}
			oc.Installed = false
			oc.Withdraw = &withdrawRecord{State: withdrawStateAlready, Mode: body.Mode, Run: o.Run, At: now, Finished: now,
				Message: "服务器上的 journal 显示这个节点已经撤回（清单已删除）"}
		})
		writeJSON(w, http.StatusOK, map[string]any{"plan": p, "already_withdrawn": true})
		return
	}
	if err := s.saveWithdrawPlan(p); err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"plan": p})
}

type withdrawRunBody struct {
	NodeID  string `json:"node_id"`
	PlanID  string `json:"plan_id"`
	Confirm string `json:"confirm"`
}

func (s *Server) postWithdraw(w http.ResponseWriter, r *http.Request) {
	var body withdrawRunBody
	if err := decodeStrict(w, r, &body, []string{"node_id", "plan_id", "confirm"}, provisionRemoved, false); err != nil {
		writeResErr(w, err)
		return
	}
	if body.Confirm != body.NodeID || body.NodeID == "" {
		writeCoded(w, http.StatusBadRequest, codeConfirmRequired, "撤回要输入节点 ID 确认（confirm 等于 node_id）", nil)
		return
	}
	cs, t, ok := s.resCtx(w)
	if !ok {
		return
	}
	if !s.lockNode(body.NodeID) {
		refuseBusy(w, body.NodeID)
		return
	}
	defer s.unlockNode(body.NodeID)
	p := s.loadWithdrawPlan(body.NodeID)
	dep, err := s.deploymentID()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	switch {
	case p == nil || p.ID != body.PlanID:
		writeCoded(w, http.StatusConflict, codeWithdrawPlanStale, "这份撤回计划不存在或已被新的计划替换：重新生成计划", nil)
		return
	case time.Now().After(p.ExpiresAt):
		writeCoded(w, http.StatusConflict, codeWithdrawPlanStale, fmt.Sprintf("撤回计划已过期（有效 %d 分钟）：重新生成计划", int(withdrawPlanTTL.Minutes())), map[string]any{"plan": p})
		return
	case p.Deployment != dep:
		writeCoded(w, http.StatusConflict, codeWithdrawPlanStale, "撤回计划属于另一个面板部署", nil)
		return
	}
	ident, _, err := s.withdrawTarget(cs, t, body.NodeID)
	if err != nil {
		writeTargetErr(w, err)
		return
	}
	if !p.Target.same(ident) {
		writeCoded(w, http.StatusConflict, sshexec.CodeTargetChanged, "生成计划之后撤回目标变了（服务器、地址、端口、用户、主机指纹或凭据）：重新生成计划", map[string]any{"plan": p, "target": ident})
		return
	}
	if p.Mode != provision.WithdrawJournal {
		// Recovering an interrupted provision only undoes that run; a Mesh
		// sidecar of an earlier, complete install is not touched by it.
		if why, bound := s.meshBinds(body.NodeID); bound {
			writeCoded(w, http.StatusConflict, codeMeshDeployed, why, nil)
			return
		}
	}
	run := "wd-" + randHex(6)
	o := provision.WithdrawOptions{NodeID: body.NodeID, Deployment: dep, ServerID: ident.ServerID, Run: run, Mode: p.Mode, Action: provision.WithdrawRun, Digest: p.Digest}
	if err := provision.CheckWithdrawOptions(o); err != nil {
		writeResErr(w, &credentials.Error{Code: codeBadRequest, Msg: err.Error()})
		return
	}
	// Single use, and recorded as running before anything is sent: a panel
	// that dies mid-run shows "interrupted", never "done".
	_ = s.Store.Put(withdrawPlanKey(body.NodeID), "")
	started := time.Now().UTC()
	nodeName := nodeName(t, body.NodeID)
	s.updateOutcome(body.NodeID, func(oc *provisionOutcome) {
		if oc.ServerID == "" {
			oc.ServerID, oc.Address, oc.Port, oc.Fingerprint, oc.User, oc.CredentialID = ident.ServerID, ident.Address, ident.Port, ident.Fingerprint, ident.User, ident.CredentialID
			oc.Deployment, oc.At = dep, started
		}
		if oc.NodeName == "" && nodeName != body.NodeID {
			oc.NodeName = nodeName
		}
		oc.Withdraw = &withdrawRecord{State: withdrawStateRunning, Mode: p.Mode, Run: run, At: started}
	})
	ctx, cancel := context.WithTimeout(r.Context(), withdrawScriptTimeout)
	defer cancel()
	res, err := s.connector(cs).RunScript(ctx, ident.target(), provision.WithdrawScript(o))
	wo := provision.ParseWithdrawOutput(res.Output)
	rec := &withdrawRecord{Mode: p.Mode, Run: run, At: started, Finished: time.Now().UTC(), Removed: wo.Removed, Kept: wo.Kept, Leftovers: wo.Leftovers, Restored: wo.Restored}
	status := http.StatusOK
	var installed *bool
	f := false
	switch {
	case wo.Refused != "":
		rec.State, rec.Code, rec.Reason, rec.Message = withdrawStateRefused, codeWithdrawRefused, wo.Refused, refusalText(wo.Refused)
		status = http.StatusConflict
	case wo.OK && err == nil:
		rec.State, rec.Message = withdrawStateDone, "撤回完成：清单列出的内容已移除并复核"
		installed = &f
	case wo.Already && err == nil:
		rec.State, rec.Message = withdrawStateAlready, "服务器上的 journal 显示已经撤回过"
		installed = &f
	case wo.Partial:
		rec.State, rec.Code = withdrawStatePartial, codeWithdrawPartial
		rec.Message = "撤回没有全部完成：下面列出了没能移除的内容；清单保留，处理后可以再次撤回（只处理还在的东西）"
		status = http.StatusBadGateway
	case wo.Compensated && !wo.Incomplete:
		rec.State, rec.Message = withdrawStateRecovered, "中断的装机已补偿：这次装机新建的内容已撤掉，被替换的文件已恢复"
		if wo.Restored {
			rec.Message += "；之前的安装已重新生效"
		}
	case wo.Incomplete:
		rec.State, rec.Code = withdrawStateRecoverInc, codeRecoveryIncomplete
		rec.Message = "补偿没有全部完成：下面列出了留在服务器上的东西，可以再次恢复"
		status = http.StatusBadGateway
	case err != nil && notStarted(sshexec.CodeOf(err)):
		rec.State, rec.Code, rec.Message = withdrawStateNotStarted, sshexec.CodeOf(err), err.Error()
		status = http.StatusBadGateway
		if c := sshexec.CodeOf(err); c == sshexec.CodeTargetChanged || c == sshexec.CodePinMismatch || c == sshexec.CodeMismatch || c == sshexec.CodeUntrusted {
			status = http.StatusConflict
		} else if c == sshexec.CodeRateLimited {
			status = rateLimitHeaders(w, err)
			rec.RetryAfter = sshexec.RetryAfterOf(err)
		}
	default:
		rec.State, rec.Code = withdrawStateUnknown, codeWithdrawUnknown
		rec.Message = "撤回脚本没有给出结论（连接中断或超时）：结果不明，不当作完成。重新生成计划会读出服务器上的状态"
		if err != nil {
			rec.Message += "（" + err.Error() + "）"
		}
		status = http.StatusBadGateway
	}
	s.updateOutcome(body.NodeID, func(oc *provisionOutcome) {
		// A refused or not-started attempt changed nothing on the host;
		// onHost() then falls back to what the provision record says.
		oc.Withdraw = rec
		if installed != nil {
			oc.Installed = *installed
		}
		// A recovered interrupted run is undone; an earlier complete
		// install (Installed) is what is on the host now.
		if rec.State == withdrawStateRecovered && (oc.Outcome == "unknown" || oc.Outcome == "left_behind" || oc.Outcome == "") {
			oc.Outcome, oc.Code = "compensated", ""
		}
	})
	writeJSON(w, status, map[string]any{
		"node_id": body.NodeID, "mode": p.Mode, "outcome": rec.State, "code": rec.Code, "reason": rec.Reason,
		"error": errOrEmpty(status, rec.Message), "message": rec.Message,
		"removed": nonNil(rec.Removed), "kept": nonNil(rec.Kept), "leftovers": nonNil(rec.Leftovers),
		"restored_previous": rec.Restored, "output": res.Output, "target": ident, "retry_after": rec.RetryAfter,
	})
}

// writeTargetErr: a binding that no longer matches is a conflict (409).
func writeTargetErr(w http.ResponseWriter, err error) {
	var ce *credentials.Error
	if errors.As(err, &ce) && (ce.Code == sshexec.CodeTargetChanged || ce.Code == sshexec.CodePinMismatch) {
		body := map[string]any{"error": ce.Msg, "code": ce.Code}
		if ce.Field != "" {
			body["field"] = ce.Field
		}
		writeJSON(w, http.StatusConflict, body)
		return
	}
	writeResErr(w, err)
}

func errOrEmpty(status int, msg string) string {
	if status == http.StatusOK {
		return ""
	}
	return msg
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

func notStarted(code string) bool {
	switch code {
	case sshexec.CodeUntrusted, sshexec.CodeMismatch, sshexec.CodeNoCredential, sshexec.CodeTargetChanged, sshexec.CodePinMismatch,
		sshexec.CodeNotFound, sshexec.CodeUnreachable, sshexec.CodeAuthFailed, sshexec.CodeAuthMethodUnavailable, sshexec.CodeNotSSH,
		sshexec.CodeRateLimited:
		return true
	}
	return false
}

type confirmBody struct {
	NodeID  string `json:"node_id"`
	Confirm string `json:"confirm"`
}

// postWithdrawAbandon records that the operator gives up on a deployment
// whose server cannot be reached any more. It releases the pins; it never
// claims anything was removed.
func (s *Server) postWithdrawAbandon(w http.ResponseWriter, r *http.Request) {
	var body confirmBody
	if err := decodeStrict(w, r, &body, []string{"node_id", "confirm"}, nil, false); err != nil {
		writeResErr(w, err)
		return
	}
	if body.Confirm != body.NodeID || body.NodeID == "" {
		writeCoded(w, http.StatusBadRequest, codeConfirmRequired, "放弃要输入节点 ID 确认（confirm 等于 node_id）", nil)
		return
	}
	if !s.lockNode(body.NodeID) {
		refuseBusy(w, body.NodeID)
		return
	}
	defer s.unlockNode(body.NodeID)
	o, ok := s.loadOutcomes()[body.NodeID]
	if !ok {
		writeResErr(w, &credentials.Error{Code: credentials.CodeNotFound, Msg: "这个节点没有部署记录"})
		return
	}
	if !o.onHost() {
		writeJSON(w, http.StatusOK, map[string]any{"deployment": o, "changed": false})
		return
	}
	now := time.Now().UTC()
	s.updateOutcome(body.NodeID, func(oc *provisionOutcome) {
		oc.Installed = false
		oc.Withdraw = &withdrawRecord{State: withdrawStateAbandoned, Mode: "abandon", Run: "abandon-" + randHex(4), At: now, Finished: now,
			Message: "操作员放弃了这次部署：面板没有连到服务器，未核实服务器上是否还留有安装；服务器和凭据的绑定已解除"}
	})
	o = s.loadOutcomes()[body.NodeID]
	writeJSON(w, http.StatusOK, map[string]any{"deployment": o, "changed": true})
}

// deleteProvisionState forgets a record once nothing of it can be on the
// host (withdrawn, abandoned or never installed).
func (s *Server) deleteProvisionState(w http.ResponseWriter, r *http.Request) {
	node := r.PathValue("node")
	if !s.lockNode(node) {
		refuseBusy(w, node)
		return
	}
	defer s.unlockNode(node)
	s.provMu.Lock()
	all := s.loadOutcomes()
	o, ok := all[node]
	if !ok {
		s.provMu.Unlock()
		writeResErr(w, &credentials.Error{Code: credentials.CodeNotFound, Msg: "这个节点没有部署记录"})
		return
	}
	if o.onHost() {
		s.provMu.Unlock()
		writeCoded(w, http.StatusConflict, codeStillOnHost, "这个节点的安装可能还在服务器上：先撤回（或在服务器已不存在时放弃），再删除记录", map[string]any{"deployment": o})
		return
	}
	delete(all, node)
	b, _ := json.Marshal(all)
	err := s.Store.Put(provisionStateKey, string(b))
	s.provMu.Unlock()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	_ = s.Store.Put(withdrawPlanKey(node), "")
	writeJSON(w, http.StatusOK, map[string]any{"deleted": node})
}

// ------------------------------------------------------------- gateway ---

type gatewayWithdrawRecord struct {
	State       string             `json:"state"` // withdrawn | guard_released | already_withdrawn | failed | compensated | uncompensated | refused
	At          time.Time          `json:"at"`
	Code        string             `json:"code,omitempty"`
	Message     string             `json:"message,omitempty"`
	Removed     apply.WithdrawSet  `json:"removed"`
	Kept        []string           `json:"kept"`
	Host        *apply.HostReport  `json:"host,omitempty"`
	Compensated bool               `json:"compensated,omitempty"`
	Guard       bool               `json:"release_guard,omitempty"`
	Pending     *apply.PendingView `json:"pending,omitempty"`
}

func (s *Server) saveGatewayWithdraw(rec gatewayWithdrawRecord) {
	if b, err := json.Marshal(rec); err == nil {
		_ = s.Store.Put(gatewayWithdrawKey, string(b))
	}
}

func (s *Server) loadGatewayWithdraw() *gatewayWithdrawRecord {
	raw, ok, err := s.Store.Get(gatewayWithdrawKey)
	if err != nil || !ok || raw == "" {
		return nil
	}
	var rec gatewayWithdrawRecord
	if json.Unmarshal([]byte(raw), &rec) != nil {
		return nil
	}
	return &rec
}

type hostWithdrawBody struct {
	Confirm      string `json:"confirm"`
	ReleaseGuard bool   `json:"release_guard"`
}

func (s *Server) postHostWithdraw(w http.ResponseWriter, r *http.Request) {
	var body hostWithdrawBody
	if err := decodeStrict(w, r, &body, []string{"confirm", "release_guard"}, nil, false); err != nil {
		writeResErr(w, err)
		return
	}
	if body.Confirm != localNodeID {
		writeCoded(w, http.StatusBadRequest, codeConfirmRequired, "撤回网关要输入 "+localNodeID+" 确认", nil)
		return
	}
	if why, bound := s.meshBinds(localNodeID); bound {
		writeCoded(w, http.StatusConflict, codeMeshDeployed, why, nil)
		return
	}
	if !s.lockNode(localNodeID) {
		refuseBusy(w, localNodeID)
		return
	}
	defer s.unlockNode(localNodeID)
	ap := s.applier(true)
	// The key and secrets are only needed to compensate a failed withdraw
	// (re-install from the installed copy); Withdraw refuses without them.
	if _, key, err := s.resolveKey(localNodeID, provision.KeyReuse); err == nil {
		ap.PrivateKey = key
	}
	ap.Secrets = s.wgSecrets()
	var res *apply.WithdrawResult
	var err error
	if body.ReleaseGuard {
		res, err = ap.WithdrawGuard()
	} else {
		res, err = ap.Withdraw()
	}
	rec := gatewayWithdrawRecord{At: time.Now().UTC(), Guard: body.ReleaseGuard, Kept: apply.GatewayKept(!body.ReleaseGuard)}
	if err != nil {
		msg := apply.RedactSecrets(err.Error(), ap.PrivateKey, ap.Secrets)
		rec.State, rec.Message = "refused", msg
		var te *apply.TxnError
		if errors.As(err, &te) {
			rec.Host, rec.Compensated = te.Report, te.Compensated
			rec.State = "uncompensated"
			if te.Compensated {
				rec.State = "compensated"
			}
		}
		if res != nil && res.Host != nil {
			rec.Host = res.Host
			rec.State = "check_failed"
		}
		rec.Pending, _ = ap.Pending()
		s.saveGatewayWithdraw(rec)
		writeWithdrawErr(w, err, ap)
		return
	}
	rec.State, rec.Removed, rec.Kept, rec.Host = res.State, res.Removed, res.Kept, res.Host
	s.saveGatewayWithdraw(rec)
	writeJSON(w, http.StatusOK, map[string]any{"status": res.State, "removed": res.Removed, "kept": res.Kept, "host": res.Host})
}

func writeWithdrawErr(w http.ResponseWriter, err error, ap apply.Applier) {
	msg := apply.RedactSecrets(err.Error(), ap.PrivateKey, ap.Secrets)
	switch {
	case errors.Is(err, apply.ErrNothingInstalled):
		writeCoded(w, http.StatusConflict, codeNothingInstalled, msg, nil)
	case errors.Is(err, apply.ErrWithdrawLegacy):
		writeCoded(w, http.StatusConflict, codeGatewayLegacy, msg, nil)
	case errors.Is(err, apply.ErrNoGuardFile):
		writeCoded(w, http.StatusConflict, codeGuardMissing, msg, nil)
	case errors.Is(err, apply.ErrNotWithdrawn):
		writeCoded(w, http.StatusConflict, codeNotWithdrawn, msg, nil)
	default:
		writeTxnErr(w, err, ap.PrivateKey, http.StatusConflict, ap.Secrets)
	}
}

// ---------------------------------------------------------- listing ---

type deploymentView struct {
	provisionOutcome
	NodeName        string              `json:"node_name"`
	InTopology      bool                `json:"in_topology"`
	ServerName      string              `json:"server_name,omitempty"`
	CurrentServerID string              `json:"current_server_id,omitempty"`
	OnHost          bool                `json:"on_host"`
	Status          string              `json:"status"`
	IdentityProblem string              `json:"identity_problem,omitempty"`
	MeshBound       string              `json:"mesh_bound,omitempty"`
	Plan            *withdrawPlanRecord `json:"plan,omitempty"`
}

type gatewayDeploymentView struct {
	Installed bool                   `json:"installed"`
	Withdrawn bool                   `json:"withdrawn"`
	Version   int64                  `json:"version,omitempty"`
	Origin    string                 `json:"origin,omitempty"`
	Plan      apply.WithdrawSet      `json:"plan"`
	Kept      []string               `json:"kept"`
	Pending   *apply.PendingView     `json:"pending"`
	Last      *gatewayWithdrawRecord `json:"last"`
	MeshBound string                 `json:"mesh_bound,omitempty"`
	Error     string                 `json:"error,omitempty"`
}

func (s *Server) getDeployments(w http.ResponseWriter, r *http.Request) {
	t, err := s.topology()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	cs, _ := s.credStore()
	s.provMu.Lock()
	busy := map[string]bool{}
	for k, v := range s.provBusy {
		busy[k] = v
	}
	s.provMu.Unlock()
	out := []deploymentView{}
	for _, o := range s.loadOutcomes() {
		v := deploymentView{provisionOutcome: o, NodeName: o.NodeName, OnHost: o.onHost(), Status: o.status(busy[o.NodeID])}
		if n, ok := t.NodeByID(o.NodeID); ok {
			v.InTopology, v.NodeName, v.CurrentServerID = true, n.Name, n.ServerID
		}
		if v.NodeName == "" {
			v.NodeName = o.NodeID
		}
		if cs != nil && o.ServerID != "" {
			if _, _, err := s.withdrawTarget(cs, t, o.NodeID); err != nil {
				v.IdentityProblem = err.Error()
			}
			if sv, err := cs.Server(o.ServerID); err == nil {
				v.ServerName = sv.Name
			}
		}
		if v.OnHost {
			v.MeshBound, _ = s.meshBinds(o.NodeID)
		}
		if p := s.loadWithdrawPlan(o.NodeID); p != nil && time.Now().Before(p.ExpiresAt) {
			v.Plan = p
		}
		out = append(out, v)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].NodeID < out[j].NodeID })
	gw := gatewayDeploymentView{Kept: []string{}}
	ap := s.applier(true)
	if inst, err := ap.Installed(); err != nil {
		gw.Error = err.Error()
	} else {
		gw.Installed, gw.Withdrawn, gw.Version, gw.Origin = !inst.Empty() && !inst.Withdrawn(), inst.Withdrawn(), inst.Version, inst.Origin
		gw.Plan = apply.WithdrawPlan(inst)
		gw.Kept = apply.GatewayKept(!inst.Empty())
	}
	gw.Pending, _ = ap.Pending()
	gw.Last = s.loadGatewayWithdraw()
	gw.MeshBound, _ = s.meshBinds(localNodeID)
	writeJSON(w, http.StatusOK, map[string]any{"nodes": out, "gateway": gw})
}

func (s *Server) registerWithdraw(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/deployments", s.getDeployments)
	mux.HandleFunc("POST /api/provision/withdraw/plan", s.postWithdrawPlan)
	mux.HandleFunc("POST /api/provision/withdraw", s.postWithdraw)
	mux.HandleFunc("POST /api/provision/withdraw/abandon", s.postWithdrawAbandon)
	mux.HandleFunc("DELETE /api/provision/state/{node}", s.deleteProvisionState)
	mux.HandleFunc("POST /api/host/withdraw", s.postHostWithdraw)
}
