package api

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/radowitz/meridian/internal/credentials"
	"github.com/radowitz/meridian/internal/preflight"
	"github.com/radowitz/meridian/internal/provision"
	"github.com/radowitz/meridian/internal/sshexec"
)

type provisionBody struct {
	NodeID       string `json:"node_id"`
	DryRun       bool   `json:"dry_run"`
	GenerateKeys bool   `json:"generate_keys"`
	// PreflightID is the reviewed preflight (POST /api/provision/preflight).
	// Required for a first install; the preflight is re-run before every run.
	PreflightID string `json:"preflight_id"`
}

// provisionRemoved are request fields of the pre-server API. They are
// refused (400 field_removed), never silently ignored: the target and the
// SSH credential now come from the node's managed server.
var provisionRemoved = []string{"ssh_host", "ssh_port", "ssh_user", "private_key_pem", "trust_new_host"}

// postProvision previews (dry_run) or runs the node's provision script.
//
// A run is gated (see preflight.go): the server must be operable; a first
// install needs a reviewed preflight_id; a given preflight_id must be
// fresh, bound to the same target identity and bundle, without blocking
// findings; and the preflight is re-run immediately before the script, on
// the same pinned identity. Only then is a key generated or rotated. The
// script itself re-checks ownership on the host, keeps a journal and
// compensates a failed run; the response says exactly what happened
// (installed / refused / compensated / left behind / unknown).
func (s *Server) postProvision(w http.ResponseWriter, r *http.Request) {
	var body provisionBody
	if err := decodeStrict(w, r, &body, []string{"node_id", "dry_run", "generate_keys", "preflight_id"}, provisionRemoved, false); err != nil {
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
	if !node.Managed {
		writeResErr(w, &credentials.Error{Code: codeBadRequest, Field: "node_id", Msg: "该节点不需要装机（例如 IX 专线）"})
		return
	}
	dep, err := s.deploymentID()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	if body.DryRun {
		b, err := s.compileTopo(t)
		if err != nil {
			writeErr(w, http.StatusUnprocessableEntity, err)
			return
		}
		files := provision.FilesFor(b.Files, node.ID)
		srv := node.ServerID
		if srv == "" {
			srv = "none"
		}
		// Preview: built from the redacted files, so it carries the
		// placeholder and refuses to run if copied to a host.
		opts := provision.Options{NodeID: node.ID, Deployment: dep, ServerID: srv, Bundle: preflight.BundleDigest(files), Run: "preview", Expect: "none", Artifacts: s.previewArtifacts(node.ID, files)}
		writeJSON(w, http.StatusOK, map[string]any{
			"dry_run":   true,
			"node_id":   node.ID,
			"server_id": node.ServerID,
			"script":    provision.ScriptWith(node.Name, files, opts),
		})
		return
	}

	// Everything about the target is checked before a key is generated or
	// rotated and before anything is compiled for the host.
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
	ident, err := identityOf(cs, node)
	if err != nil {
		writeResErr(w, err)
		return
	}
	b0, err := s.compileTopo(t)
	if err != nil {
		writeErr(w, http.StatusUnprocessableEntity, err)
		return
	}
	files0 := provision.FilesFor(b0.Files, node.ID)
	bundle := preflight.BundleDigest(files0)
	first := !s.provisionedOK(node, ident)
	var reviewed *preflightRecord
	switch {
	case body.PreflightID != "":
		if reviewed, ok = s.gateReviewed(w, node.ID, body.PreflightID, bundle, &ident); !ok {
			return
		}
	case first:
		writeCoded(w, http.StatusConflict, codePreflightRequired,
			fmt.Sprintf("节点 %s 在服务器 %s 上还没有成功装过：第一次装机前必须先预检并审阅结果（POST /api/provision/preflight），再带上 preflight_id 执行", node.ID, ident.ServerName), nil)
		return
	}
	// Re-run immediately before execution, pinned to the same identity.
	fresh, err := s.runRemotePreflight(r.Context(), cs, node, files0, ident, first)
	if err != nil {
		if sshexec.CodeOf(err) == sshexec.CodeRateLimited {
			// Refused before the SSH banner at the re-run: nothing ran.
			writeJSON(w, rateLimitHeaders(w, err), map[string]any{"error": err.Error(), "code": sshexec.CodeRateLimited,
				"retry_after": sshexec.RetryAfterOf(err), "outcome": "not_started", "node_id": node.ID, "server_id": node.ServerID})
			return
		}
		s.writeSSHErrHelp(w, cs, node.ServerID, err)
		return
	}
	if !gateFresh(w, reviewed, fresh) {
		return
	}
	expect := "none"
	if fresh.Ownership == preflight.OwnSame {
		expect = "same"
	}

	var key, pub string
	if body.GenerateKeys {
		// Rotate: store the new pair before compiling so peer configs carry
		// the matching public key.
		t, key, err = s.resolveKey(node.ID, provision.KeyRotate)
		if err != nil {
			writeErr(w, http.StatusInternalServerError, err)
			return
		}
		node, _ = t.NodeByID(node.ID)
		pub = node.PublicKey
	} else {
		// generate_keys=false reuses the stored key. A node without one fails
		// here, before the script runs or any remote config is overwritten.
		t, key, err = s.resolveKey(node.ID, provision.KeyReuse)
		if err != nil {
			writeErr(w, http.StatusConflict, err)
			return
		}
	}
	b, err := s.compileTopo(t)
	if err != nil {
		writeErr(w, http.StatusUnprocessableEntity, err)
		return
	}
	files := provision.FilesFor(b.Files, node.ID)
	if preflight.BundleDigest(files) != bundle {
		writeCoded(w, http.StatusConflict, codeBundleChanged, "预检之后这个节点要下发的配置变了：重新预检后再执行", nil)
		return
	}
	injected, err := provision.InjectPrivate(files, key)
	if err != nil {
		writeErr(w, http.StatusConflict, err)
		return
	}
	// Panel-delivered binaries: transferred (when the host does not have
	// the pinned digest yet) over the same pooled login, verified on the
	// host by the script before anything is activated.
	arts, err := s.stageArtifacts(r.Context(), cs, ident, fresh)
	if err != nil {
		var ce *credentials.Error
		switch {
		case errors.As(err, &ce):
			writeJSON(w, http.StatusConflict, map[string]any{"error": ce.Msg, "code": ce.Code, "outcome": "not_started", "node_id": node.ID, "server_id": node.ServerID})
		case sshexec.CodeOf(err) == sshexec.CodeRateLimited:
			writeJSON(w, rateLimitHeaders(w, err), map[string]any{"error": err.Error(), "code": sshexec.CodeRateLimited,
				"retry_after": sshexec.RetryAfterOf(err), "outcome": "not_started", "node_id": node.ID, "server_id": node.ServerID})
		default:
			code := sshexec.CodeOf(err)
			if code == "" {
				code = sshexec.CodeStageFailed
			}
			writeJSON(w, http.StatusBadGateway, map[string]any{"error": "传输面板下发的二进制失败，没有执行装机：" + err.Error(), "code": code, "outcome": "not_started", "node_id": node.ID, "server_id": node.ServerID})
		}
		return
	}
	run := "run-" + randHex(6)
	opts := provision.Options{NodeID: node.ID, Deployment: fresh.Deployment, ServerID: ident.ServerID, Bundle: bundle, Run: run, Expect: expect, Artifacts: arts}
	if err := provision.CheckOptions(opts); err != nil {
		writeErr(w, http.StatusUnprocessableEntity, err)
		return
	}
	script := provision.ScriptWith(node.Name, injected, opts)
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Minute)
	defer cancel()
	res, err := s.connector(cs).RunScript(ctx, ident.target(), script)
	out := provision.Redact(res.Output, key)
	so := parseScriptOutcome(out)
	oc := provisionOutcome{NodeID: node.ID, ServerID: ident.ServerID, Address: ident.Address, Port: ident.Port, Fingerprint: ident.Fingerprint,
		Run: run, Bundle: bundle, At: time.Now().UTC(), Leftovers: so.Leftovers, Kept: so.Kept, Restored: so.Restored,
		User: ident.User, CredentialID: ident.CredentialID, Deployment: fresh.Deployment, NodeName: node.Name}
	base := map[string]any{
		"node_id":      node.ID,
		"server_id":    node.ServerID,
		"auth_method":  res.AuthMethod,
		"output":       out,
		"preflight_id": fresh.ID,
		"run":          run,
	}
	if err == nil && so.OK {
		oc.OK = true
		oc.Outcome = "installed"
		s.saveOutcome(oc)
		base["dry_run"] = false
		base["outcome"] = "installed"
		base["host_key"] = res.Fingerprint
		base["public_key"] = pub
		writeJSON(w, http.StatusOK, base)
		return
	}
	code := sshexec.CodeOf(err)
	status := http.StatusBadGateway
	msg := ""
	if err != nil {
		msg = provision.Redact(err.Error(), key)
	}
	switch {
	case so.Refused != "":
		code, status = codeProvisionRefused, http.StatusConflict
		base["outcome"] = "refused"
		base["reason"] = so.Refused
		msg = fmt.Sprintf("服务器上的执行前复核拒绝了这次装机（%s），没有改动任何东西：重新预检查看原因", so.Refused)
	case so.Incomplete:
		code = codeProvisionLeftovers
		base["outcome"] = "left_behind"
		msg = "装机失败，补偿没有全部完成：下面列出了留在服务器上的东西（也记录在服务器的 /var/lib/meridian/node/journal）。处理之前，下一次预检会阻止再次装机"
	case so.Compensated:
		code = codeProvisionCompensated
		base["outcome"] = "compensated"
		msg = "装机失败，已补偿：这次新建的文件、接口、表、规则和服务已撤掉，被替换的文件已恢复"
		if len(so.Kept) > 0 {
			msg += "；按设计保留了安装的软件包（见 kept）"
		}
		if so.Restored {
			msg += "；更新前的配置已重新生效"
		}
	case err == nil:
		// Exit 0 without the success marker: never claim success.
		code = sshexec.CodeCommandFailed
		base["outcome"] = "unknown"
		msg = "脚本结束了，但没有输出成功标记：结果不明，不当作成功。重新预检查看服务器上的 journal"
	default:
		switch code {
		case sshexec.CodeUntrusted, sshexec.CodeMismatch, sshexec.CodeNoCredential, sshexec.CodeTargetChanged, sshexec.CodePinMismatch:
			status = http.StatusConflict
			base["outcome"] = "not_started"
		case sshexec.CodeNotFound:
			status = http.StatusNotFound
			base["outcome"] = "not_started"
		case sshexec.CodeUnreachable, sshexec.CodeAuthFailed, sshexec.CodeAuthMethodUnavailable, sshexec.CodeNotSSH:
			base["outcome"] = "not_started"
		case sshexec.CodeRateLimited:
			// Refused before the SSH banner: nothing was sent. With the
			// pooled connection of the preflight re-run this happens only
			// when that connection was lost in between.
			status = rateLimitHeaders(w, err)
			base["outcome"] = "not_started"
			base["retry_after"] = sshexec.RetryAfterOf(err)
		default:
			base["outcome"] = "unknown"
			msg += "。脚本可能在执行中被中断：结果不明，不当作成功；服务器上的补偿会在断线时运行，重新预检会显示它的 journal"
		}
	}
	if base["outcome"] != "not_started" {
		oc.Outcome, _ = base["outcome"].(string)
		oc.Code = code
		oc.Reason = so.Refused
		s.saveOutcome(oc)
	}
	base["error"] = msg
	base["code"] = code
	base["leftovers"] = so.Leftovers
	base["kept"] = so.Kept
	if h := s.loginHelpFor(cs, node.ServerID, code, sshexec.OfferedOf(err)); h != nil {
		base["login_help"] = h
	}
	writeJSON(w, status, base)
}
