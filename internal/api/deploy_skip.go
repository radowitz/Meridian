package api

// Skipping a step of the deployment guide (deploy_plan.go「Skip」and
// 「Dependencies」):
//
//   - POST /api/deploy/runs/{id}/skip {node_id}: the current install step,
//     when its preflight is blocked or its server cannot be reached / is in
//     its rate-limit wait (nothing was executed), is skipped for this run.
//     Refused for any other step: in flight, failed or unknown (resolve it
//     first), done, verify-only (outside the order, it holds nothing up),
//     reviewed without blocking findings, not tried yet, or not current.
//     Nothing is contacted; the step stays pending.
//   - POST /api/deploy/runs/{id}/unskip {node_id}: back to a skipped step
//     (also from a run that ended partial, which reopens). It needs a fresh
//     preflight; a rate-limit wait it had still holds.
//
// Both are recorded in the run's events.

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/radowitz/meridian/internal/credentials"
)

// notCurrentText says why node is not the step to act on (idx: the current
// step, -1 none).
func (r *deployRun) notCurrentText(node string, idx int) string {
	if i := r.stepIndex(node); i >= 0 {
		st := r.Steps[i]
		if st.Skip != nil {
			return fmt.Sprintf("%s 在这次运行中已跳过：要处理它，先「回到这一台」", stepName(st))
		}
		if w := r.waits()[i]; len(w) > 0 {
			return fmt.Sprintf("%s 依赖已跳过的 %s，在等它：先回到 %s 并装好，它才会轮到", stepName(st), strings.Join(r.namesOf(w), "、"), strings.Join(r.namesOf(w), "、"))
		}
	}
	want := "—"
	if idx >= 0 {
		want = stepName(r.Steps[idx])
	}
	return fmt.Sprintf("只能按顺序操作：现在轮到 %s", want)
}

func (s *Server) postDeploySkip(w http.ResponseWriter, r *http.Request) {
	var body deployStepBody
	if err := decodeStrict(w, r, &body, []string{"node_id"}, nil, false); err != nil {
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
			writeCoded(w, http.StatusConflict, codeDeployStepRunning, stepName(st)+" 正在执行：等它结束（执行中的一步不能跳过）", nil)
			return
		}
	}
	idx := run.stepIndex(body.NodeID)
	if idx < 0 {
		writeCoded(w, http.StatusNotFound, credentials.CodeNotFound, "这次引导里没有这个节点", nil)
		return
	}
	st := &run.Steps[idx]
	refuse := func(code, msg string) {
		writeCoded(w, http.StatusConflict, code, msg, map[string]any{"deploy": s.deployView(run)})
	}
	switch {
	case st.VerifyOnly:
		refuse(codeDeploySkipRefused, "只需核对的步骤不受安装顺序约束，不会挡住其它节点：不需要跳过")
		return
	case st.Phase == phaseDone:
		refuse(codeDeploySkipRefused, stepName(*st)+" 已经完成：不能跳过")
		return
	case st.Skip != nil:
		refuse(codeDeploySkipRefused, stepName(*st)+" 已经跳过了")
		return
	case st.Phase == phaseFailed || st.Phase == phaseUnknown:
		refuse(codeDeploySkipUnknown, fmt.Sprintf("%s 的上一次下发%s：不能跳过它继续——先「重新核对」读取服务器上实际的安装记录，把结果弄清楚", stepName(*st), map[bool]string{true: "结果不明", false: "失败了"}[st.Phase == phaseUnknown]))
		return
	}
	if cur := run.current(); cur != idx {
		refuse(codeDeployNotCurrent, run.notCurrentText(body.NodeID, cur))
		return
	}
	now := s.now()
	kind, reason := s.skipKindOf(*st, now)
	if kind == "" {
		refuse(codeDeploySkipRefused, fmt.Sprintf("%s 没有被预检阻断，也没有连不上：只有预检有阻断项、服务器连不上或登录不了、或在限速等待的一步可以跳过", stepName(*st)))
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
	if l.version != run.TopologyVersion {
		refuse(codeDeployPlanStale, "计划之后拓扑被保存过：先「按当前拓扑重新计划」，再决定跳过哪一台")
		return
	}
	holds := run.holdsIfSkipped(idx)
	st.Skip = &stepSkip{Kind: kind, Reason: reason, Code: st.Code, At: now}
	text := fmt.Sprintf("跳过 %s（%s），继续不依赖它的节点", stepName(*st), clipText(reason, 200))
	if len(holds) > 0 {
		text += "；依赖它、继续等待的：" + strings.Join(run.namesOf(holds), "、")
	}
	run.event(now, st.NodeID, text)
	run.UpdatedAt = now
	settle(run, now)
	s.saveRunLocked(run)
	writeJSON(w, http.StatusOK, s.deployView(run))
}

func (s *Server) postDeployUnskip(w http.ResponseWriter, r *http.Request) {
	var body deployStepBody
	if err := decodeStrict(w, r, &body, []string{"node_id"}, nil, false); err != nil {
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
	if !run.open() && run.State != runPartial {
		writeCoded(w, http.StatusConflict, codeDeployRunClosed, "这个部署引导"+runStateText(run.State)+"：开始一个新的", nil)
		return
	}
	for _, st := range run.Steps {
		if inFlight(st.Phase) {
			writeCoded(w, http.StatusConflict, codeDeployStepRunning, stepName(st)+" 正在执行：等它结束", nil)
			return
		}
	}
	idx := run.stepIndex(body.NodeID)
	if idx < 0 {
		writeCoded(w, http.StatusNotFound, credentials.CodeNotFound, "这次引导里没有这个节点", nil)
		return
	}
	st := &run.Steps[idx]
	if st.Skip == nil {
		writeCoded(w, http.StatusConflict, codeDeployNotSkipped, stepName(*st)+" 没有被跳过", map[string]any{"deploy": s.deployView(run)})
		return
	}
	now := s.now()
	was := st.Skip
	st.Skip = nil
	// Back to a fresh preflight in its place; a rate-limit wait (RetryAt)
	// still holds, the last attempt's outcome stays visible.
	if st.Phase == phaseBlocked || st.Phase == phaseReview {
		st.Phase = phasePending
		st.Invalidated = "跳过之后回到这一台：之前的预检不再使用，重新预检"
	}
	st.PreflightID, st.ReviewBundle, st.ReviewTarget, st.ReviewExpires = "", "", nil, nil
	if run.State == runPartial {
		run.State, run.Summary, run.StopReason = runActive, nil, ""
	}
	run.event(now, st.NodeID, fmt.Sprintf("回到 %s（之前跳过：%s）", stepName(*st), clipText(was.Reason, 200)))
	run.UpdatedAt = now
	s.saveRunLocked(run)
	writeJSON(w, http.StatusOK, s.deployView(run))
}
