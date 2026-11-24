package api

// Verify-only steps of the deployment guide (deploy_plan.go「Verify-only
// steps」): POST /api/deploy/runs/{id}/verify with {"node_id": …} for one
// step or {"all": true} for every verify-only step that is not done yet.
//
// A verify is the read-only remote preflight (POST /api/provision/preflight
// in-process: the pinned host key, the server's credential, its management
// channel, one pooled login) followed by the comparison of the host's own
// record with what the plan was computed for. It never installs anything.
// A batch runs the steps one after another, never two at a time, never
// retries, does not contact a server inside its rate-limit wait (it is
// reported as waiting), and goes on past a server that cannot be reached.

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/radowitz/meridian/internal/credentials"
	"github.com/radowitz/meridian/internal/model"
)

// Results of one verify in a batch.
const (
	verifyResVerified    = "verified"
	verifyResDiffers     = "differs"
	verifyResUnreachable = "unreachable"
	verifyResWaiting     = "waiting"
	verifyResRefused     = "refused" // the step could not be started (busy, stale plan, identity changed)
)

type verifyBody struct {
	NodeID string `json:"node_id"`
	All    bool   `json:"all"`
}

// verifyOutcome is one step's result of a verify request.
type verifyOutcome struct {
	NodeID      string `json:"node_id"`
	NodeName    string `json:"node_name"`
	Result      string `json:"result"`
	Code        string `json:"code,omitempty"`
	Message     string `json:"message,omitempty"`
	WaitSeconds int    `json:"wait_seconds,omitempty"`
}

// isVerifyOnly: node's step in run runID is a verify-only step.
func (s *Server) isVerifyOnly(runID, node string) bool {
	s.deployMu.Lock()
	defer s.deployMu.Unlock()
	run := s.loadRunLocked()
	if run == nil || run.ID != runID {
		return false
	}
	for _, st := range run.Steps {
		if st.NodeID == node {
			return st.VerifyOnly
		}
	}
	return false
}

func (s *Server) postDeployVerify(w http.ResponseWriter, r *http.Request) {
	var body verifyBody
	if err := decodeStrict(w, r, &body, []string{"node_id", "all"}, nil, false); err != nil {
		writeResErr(w, err)
		return
	}
	runID := r.PathValue("id")
	if body.All == (body.NodeID != "") {
		writeCoded(w, http.StatusBadRequest, credentials.CodeInvalid, "要么给 node_id 核对一台，要么 all: true 核对全部只需核对的步骤", nil)
		return
	}
	if !body.All {
		s.verifyOne(w, r, runID, body.NodeID)
		return
	}
	// The batch: the verify-only steps not done, in the plan's order.
	s.deployMu.Lock()
	run := s.loadRunLocked()
	s.deployMu.Unlock()
	if run == nil || run.ID != runID {
		writeCoded(w, http.StatusNotFound, credentials.CodeNotFound, "没有这个部署引导", nil)
		return
	}
	var nodes []string
	for _, st := range run.Steps {
		if st.VerifyOnly && st.Phase != phaseDone {
			nodes = append(nodes, st.NodeID)
		}
	}
	results := []verifyOutcome{}
	for _, node := range nodes {
		results = append(results, s.verifyStep(r.Context(), runID, node))
	}
	s.deployMu.Lock()
	run = s.loadRunLocked()
	s.deployMu.Unlock()
	out := s.deployView(run)
	out["verify"] = results
	writeJSON(w, http.StatusOK, out)
}

// verifyOne answers a single verify: refusals that touched nothing are
// answered as such (409), any result that was recorded with 200.
func (s *Server) verifyOne(w http.ResponseWriter, r *http.Request, runID, node string) {
	res := s.verifyStep(r.Context(), runID, node)
	s.deployMu.Lock()
	run := s.loadRunLocked()
	s.deployMu.Unlock()
	if res.Result == verifyResRefused || res.Result == verifyResWaiting && res.Code == codeDeployWait {
		extra := map[string]any{"deploy": s.deployView(run)}
		if res.WaitSeconds > 0 {
			extra["retry_after"] = res.WaitSeconds
		}
		status := http.StatusConflict
		if res.Code == credentials.CodeNotFound {
			status = http.StatusNotFound
		}
		writeCoded(w, status, res.Code, res.Message, extra)
		return
	}
	out := s.deployView(run)
	out["verify"] = []verifyOutcome{res}
	writeJSON(w, http.StatusOK, out)
}

// verifyStep verifies one verify-only step. It marks the step in flight
// (refusing while any step is), runs the read-only preflight and records
// the result: adopted when the host's record is exactly what the plan was
// computed for, an install step in the order when it differs, the reason
// when the server could not be reached (with the rate-limit wait).
func (s *Server) verifyStep(ctx context.Context, runID, node string) verifyOutcome {
	out := verifyOutcome{NodeID: node, Result: verifyResRefused}
	s.deployMu.Lock()
	run := s.loadRunLocked()
	if run == nil || run.ID != runID {
		s.deployMu.Unlock()
		out.Code, out.Message = credentials.CodeNotFound, "没有这个部署引导"
		return out
	}
	if !run.open() {
		s.deployMu.Unlock()
		out.Code, out.Message = codeDeployRunClosed, "这个部署引导"+runStateText(run.State)+"：开始一个新的"
		return out
	}
	idx := -1
	for i, st := range run.Steps {
		if inFlight(st.Phase) {
			s.deployMu.Unlock()
			out.Code, out.Message = codeDeployStepRunning, fmt.Sprintf("%s 正在%s：等它结束（一次只连一台服务器）", st.NodeName, map[bool]string{true: "预检或核对", false: "下发"}[st.Phase == phasePreflight])
			return out
		}
		if st.NodeID == node {
			idx = i
		}
	}
	if idx < 0 {
		s.deployMu.Unlock()
		out.Code, out.Message = credentials.CodeNotFound, "这次引导里没有这个节点"
		return out
	}
	st := &run.Steps[idx]
	out.NodeName = st.NodeName
	if !st.VerifyOnly || st.Phase == phaseDone {
		s.deployMu.Unlock()
		out.Code, out.Message = codeDeployNotVerify, "这一步不是待核对的「只需核对」步骤（已完成，或需要按顺序安装）"
		return out
	}
	l, err := s.liveDeploy()
	if err != nil {
		s.deployMu.Unlock()
		out.Code, out.Message = codeTopologyInvalid, err.Error()
		return out
	}
	if l.version != run.TopologyVersion {
		s.deployMu.Unlock()
		out.Code, out.Message = codeDeployPlanStale, "计划之后拓扑被保存过：核对结果只对它所属的计划有效，先「按当前拓扑重新计划」"
		return out
	}
	if cur := l.identity(node); st.PlanTarget == nil || !sameTarget(st.PlanTarget, cur) || l.bundles[node] != st.PlanBundle {
		s.deployMu.Unlock()
		out.Code, out.Message = codeDeployPlanStale, "计划之后这个节点的内容或服务器身份变了：核对结果只对计划时的节点、服务器和主机指纹有效，先重新计划"
		return out
	}
	now := s.now()
	if st.RetryAt != nil && st.RetryAt.After(now) {
		left := int(st.RetryAt.Sub(now).Seconds()) + 1
		s.deployMu.Unlock()
		out.Result, out.Code, out.WaitSeconds = verifyResWaiting, codeDeployWait, left
		out.Message = fmt.Sprintf("服务器暂时拒绝面板的来源地址（限速）：%d 秒后再核对；面板在那之前不会连接它", left)
		return out
	}
	st.Phase, st.Boot, st.StartedAt, st.FinishedAt = phasePreflight, s.bootID(), &now, nil
	st.Attempts++
	planVersion := run.TopologyVersion
	planned := *st
	run.UpdatedAt = now
	s.saveRunLocked(run)
	s.deployMu.Unlock()

	cctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), deployStepTimeout)
	defer cancel()
	status, body, raw := callJSON(s.postProvisionPreflight, cctx, "/api/provision/preflight", map[string]any{"node_id": node})
	var note string
	if status != http.StatusOK && boolOf(body, "not_executed") {
		note = s.stepPathNote(cctx, l.t, node)
	}
	s.finishStep(runID, node, func(run *deployRun, step *deployStep, now time.Time) {
		if status != http.StatusOK {
			step.Phase = phasePending
			deployNotStarted(step, body, now)
			step.PathNote = note
			out.Result, out.Code, out.Message = verifyResUnreachable, step.Code, step.Message
			if step.Code == codeNodeBusy {
				// Another operation holds the node: nothing was tried.
				step.Outcome, step.Message = "", s.busyMessage(step.NodeID)
				out.Result, out.Message = verifyResRefused, step.Message
			}
			if step.RetryAt != nil {
				out.Result, out.WaitSeconds = verifyResWaiting, int(step.RetryAt.Sub(now).Seconds())+1
			}
			run.event(now, step.NodeID, "核对没有完成（没有执行任何操作）："+clipText(step.Message, 200))
			return
		}
		var resp struct{ Preflight preflightRecord }
		if json.Unmarshal(raw, &resp) != nil || resp.Preflight.ID == "" {
			step.Phase = phasePending
			step.Outcome, step.Message = "not_started", "预检的回答无法读取"
			out.Result, out.Message = verifyResUnreachable, step.Message
			return
		}
		rec := &resp.Preflight
		clearAttempt(step)
		step.PathNote = ""
		// Bound to what the plan was computed for: this plan's bundle, this
		// node, the server and pinned host key planned (the preflight ran
		// against the live identity, which beginning the verify checked
		// equals the planned one).
		if rec.Target == nil || rec.Bundle != planned.PlanBundle || !sameTarget(rec.Target, planned.PlanTarget) {
			step.Phase = phasePending
			step.Outcome, step.Message = "not_started", "核对时的内容或服务器身份与计划不同：结果不算核对，重新计划后再核对"
			out.Result, out.Code, out.Message = verifyResRefused, codeDeployPlanStale, step.Message
			run.event(now, step.NodeID, "核对结果不属于这个计划，没有采用")
			return
		}
		h := rec.HostRecord
		why := hostRecordDiff(h, step.NodeID, rec)
		if why == "" {
			s.adoptRemote(step.NodeID, rec)
			step.Phase, step.Outcome, step.Evidence, step.Completion = phaseDone, "adopted", "host_record", completionAdopted
			step.PreflightID, step.ReviewBundle, step.ReviewTarget = rec.ID, rec.Bundle, rec.Target
			step.Verified = &verifyBinding{Plan: planVersion, Bundle: rec.Bundle, NodeID: step.NodeID, ServerID: rec.Target.ServerID,
				Fingerprint: rec.Target.Fingerprint, PreflightID: rec.ID, At: now}
			step.Health = &deployHealth{Source: "host_record", Committed: true, Verify: verifyOK,
				Detail: "服务器上的安装记录（清单）已经是这份内容" + map[bool]string{true: "（运行 " + h.JournalRun + " 的 journal 为 done）", false: ""}[h.JournalRun != ""] + "：只读核对，没有执行任何安装，也没有重新做健康检查"}
			step.Message = "核对：服务器上已经装着这份内容，采纳（没有安装任何东西）"
			out.Result, out.Message = verifyResVerified, step.Message
			run.event(now, step.NodeID, "核对：服务器记录与计划一致，采纳")
			return
		}
		// The host differs: never adopted. The step joins the install
		// order with this reviewed preflight; installing it needs the
		// operator's confirmation in its turn, like any other.
		state, reason := run.State, run.StopReason
		step.VerifyOnly = false
		step.VerifyDiff = why
		reviewed(run, step, rec, now)
		run.State, run.StopReason = state, reason
		step.Message = "核对发现服务器上的记录与计划不同（" + why + "）：这一步变成按顺序安装的一步，轮到它时审阅预检并确认后才下发"
		out.Result, out.Message = verifyResDiffers, step.Message
		run.event(now, step.NodeID, "核对：服务器记录不同（"+why+"），改为按顺序安装")
		placeInOrder(run, step.NodeID, l.t)
	})
	return out
}

// placeInOrder moves node's step (just turned into an install step) to its
// place in the install order: before the first install step not done yet
// that the base order puts after it (farther from the gateway first), else
// after the last install step. Steps already done keep their place.
func placeInOrder(run *deployRun, node string, t model.Topology) {
	from := -1
	for i, st := range run.Steps {
		if st.NodeID == node {
			from = i
		}
	}
	if from < 0 {
		return
	}
	moved := run.Steps[from]
	rest := append(append([]deployStep{}, run.Steps[:from]...), run.Steps[from+1:]...)
	n, _ := t.NodeByID(node)
	tier := deployTier(t, n)
	at := -1
	for i, st := range rest {
		if st.VerifyOnly {
			continue
		}
		on, _ := t.NodeByID(st.NodeID)
		if st.Phase != phaseDone && deployTier(t, on) > tier {
			at = i
			break
		}
		at = i + 1
	}
	if at < 0 {
		at = 0
	}
	run.Steps = append(append(append([]deployStep{}, rest[:at]...), moved), rest[at:]...)
}

// hostRecordDiff says why the host's record is not exactly node's planned
// content on this server ("" when it is).
func hostRecordDiff(h *hostRecord, node string, rec *preflightRecord) string {
	switch {
	case h == nil:
		return "服务器上没有这个节点的安装记录，或没有读全"
	case h.Node != node || h.Deployment != rec.Deployment:
		return fmt.Sprintf("服务器上的记录属于节点 %s / 部署 %s", orDashS(h.Node), orDashS(h.Deployment))
	case h.Server != "" && rec.Target != nil && h.Server != rec.Target.ServerID:
		return fmt.Sprintf("服务器上的记录属于服务器 %s", h.Server)
	case h.Bundle != rec.Bundle:
		return "服务器上记录的内容摘要与计划的不同"
	case h.JournalState != "" && h.JournalState != "done":
		return "服务器上最近一次下发的 journal 是 " + h.JournalState
	}
	return ""
}

// stepPathNote is the carrying-state note of a node whose server is managed
// through a tunnel address ("" otherwise).
func (s *Server) stepPathNote(ctx context.Context, t model.Topology, node string) string {
	n, ok := t.NodeByID(node)
	if !ok || n.ServerID == "" {
		return ""
	}
	cs, err := s.credStore()
	if err != nil {
		return ""
	}
	sv, err := cs.Server(n.ServerID)
	if err != nil || sv.Channel.ChannelMode() != model.ChannelTunnel {
		return ""
	}
	note := s.tunnelPathNote(ctx, sv, sv.Channel.Address)
	if note == nil {
		return ""
	}
	text, _ := note["text"].(string)
	return text
}
