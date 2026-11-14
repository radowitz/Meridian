package api

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/radowitz/meridian/internal/apply"
	"github.com/radowitz/meridian/internal/compile"
	"github.com/radowitz/meridian/internal/credentials"
	"github.com/radowitz/meridian/internal/model"
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
// ensureNodeKeys gives every managed node that has neither a private nor a
// public key a WireGuard pair. It only touches the panel's stored topology:
// no host is contacted. A first deployment installs nodes one at a time, and
// each node's configuration names its peers' public keys; without this the
// first node would be sent the placeholder for a peer that has never been
// installed, and WireGuard on the host would refuse the file.
func (s *Server) ensureNodeKeys() (model.Topology, []string, error) {
	s.keyMu.Lock()
	defer s.keyMu.Unlock()
	t, err := s.topology()
	if err != nil {
		return model.Topology{}, nil, err
	}
	var made []string
	for i := range t.Nodes {
		n := t.Nodes[i]
		priv := strings.TrimSpace(n.PrivateKey)
		if priv == "***" {
			priv = ""
		}
		if !n.Managed || priv != "" || strings.TrimSpace(n.PublicKey) != "" {
			continue
		}
		if _, changed, err := provision.ResolveNodeKey(&t, n.ID, provision.KeyGenerateIfMissing); err != nil {
			return model.Topology{}, nil, err
		} else if changed {
			made = append(made, n.ID)
		}
	}
	if len(made) > 0 {
		if err := s.Store.Save(t); err != nil {
			return model.Topology{}, nil, err
		}
	}
	return t, made, nil
}

// refuseNodePeerKeys answers 422 when nodeID's own WireGuard configs in b
// name a peer without a usable public key (an unmanaged peer whose key was
// never entered, or a node that has a public key from elsewhere but an
// invalid one). Nothing has been sent to the host at that point.
func refuseNodePeerKeys(w http.ResponseWriter, b *compile.Bundle, nodeID string) bool {
	probs := b.PeerKeyProblems(nodeID)
	if len(probs) == 0 {
		return false
	}
	seen := map[string]bool{}
	var peers []string
	for _, p := range probs {
		if !seen[p.Peer] {
			seen[p.Peer] = true
			peers = append(peers, p.Peer)
		}
	}
	writeJSON(w, http.StatusUnprocessableEntity, map[string]any{
		"code": codePeerKeysMissing,
		"error": fmt.Sprintf("拒绝装机：节点 %s 的 WireGuard 配置里这些对端没有可用的公钥（缺失、仍是占位符或格式不对）：%s。"+
			"受管节点的密钥由面板自动生成；这里列出的是不受管的对端，或公钥是手工填写且无效的节点：在拓扑里填入 44 字符的 base64 公钥，或清空后让面板生成。没有连接服务器。",
			nodeID, strings.Join(peers, "、")),
		"peer_key_problems": probs,
		"outcome":           "not_started",
		"node_id":           nodeID,
	})
	return true
}

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
				"retry_after": sshexec.RetryAfterOf(err), "outcome": "not_started", "node_id": node.ID, "server_id": node.ServerID,
				"not_executed": true, "safe_to_retry": true})
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

	// Peers that have never been installed still need a key before this
	// node's configuration is compiled. A key made here changes the bundle,
	// so the comparison with the reviewed preflight below refuses and the
	// operator reviews again; the preflight itself normally made them.
	if _, _, err := s.ensureNodeKeys(); err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
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
	if refuseNodePeerKeys(w, b, node.ID) {
		return
	}
	files := provision.FilesFor(b.Files, node.ID)
	if preflight.BundleDigest(files) != bundle {
		writeCoded(w, http.StatusConflict, codeBundleChanged, "预检之后这个节点要下发的配置变了：重新预检后再执行", nil)
		return
	}
	// The node's WSS secrets (its listener's key and accepted prefixes,
	// its clients' prefixes) are injected here, in memory, into the
	// script that is sent over the pinned SSH session; nothing else
	// (remote-access keys) is ever passed to a remote node.
	wssSec, err := cs.WSSSecrets()
	if err != nil {
		writeResErr(w, err)
		return
	}
	// A carrier of external SOCKS exits also gets their proxy credentials
	// (only those its own files name), the same way: in memory, at this
	// boundary only. A missing credential stops here, before anything runs.
	if ids := carrierSOCKSCredentials(t, node.ID); len(ids) > 0 {
		sec, err := cs.SOCKSSecrets(ids)
		if err != nil {
			writeCoded(w, http.StatusConflict, "external_credential_missing", "这个节点承载的外部 SOCKS 出口引用的凭据不存在或不可读："+err.Error()+"。在「凭据」里补上（或让出口改用别的凭据）后重新预检。", nil)
			return
		}
		merged := make(map[string]string, len(wssSec)+len(sec))
		for k, v := range wssSec {
			merged[k] = v
		}
		for k, v := range sec {
			merged[k] = v
		}
		wssSec = merged
	}
	injected, err := provision.InjectPrivateWSS(files, key, wssSec)
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
				"retry_after": sshexec.RetryAfterOf(err), "outcome": "not_started", "node_id": node.ID, "server_id": node.ServerID,
				"not_executed": true, "safe_to_retry": true})
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
	// The script and, right after it ended, the host's own record of this
	// run are read on the same login (no second connection).
	res, stateText, stateOK, err := s.connector(cs).RunScriptAndRead(ctx, ident.target(), script)
	out := redactRemote(res.Output, key, wssSec)
	// Markers come from the script's standard output alone (sshexec
	// collects them line by line): stderr interleaving or a long output
	// cannot break or cut them.
	so := parseScriptOutcome(redactRemote(strings.Join(res.Markers, "\n"), key, wssSec))
	var hostState *preflight.NodeState
	if stateOK {
		st := preflight.ParseNodeState(stateText)
		hostState = &st
	}
	now := time.Now().UTC()
	oc := provisionOutcome{NodeID: node.ID, ServerID: ident.ServerID, Address: ident.Address, Port: ident.Port, Fingerprint: ident.Fingerprint,
		Run: run, Bundle: bundle, At: now, Leftovers: so.Leftovers, Kept: so.Kept, Restored: so.Restored,
		User: ident.User, CredentialID: ident.CredentialID, Deployment: fresh.Deployment, NodeName: node.Name}
	base := map[string]any{
		"node_id":      node.ID,
		"server_id":    node.ServerID,
		"auth_method":  res.AuthMethod,
		"output":       out,
		"preflight_id": fresh.ID,
		"run":          run,
	}
	if res.Channel != "" && res.Channel != model.ChannelDirect {
		base["channel"] = res.Channel
	}
	// The script's markers did not say how it ended (the output was cut or
	// lost, or the script exited without them) but it did end: the host's
	// journal for this very run decides.
	finished := err == nil || sshexec.CodeOf(err) == sshexec.CodeCommandFailed
	if finished && !so.OK && !so.Compensated && !so.Incomplete && so.Refused == "" {
		switch ev := evidenceOf(hostState, node.ID, fresh.Deployment, bundle, run); ev.Outcome {
		case "compensated":
			so.Compensated, oc.Evidence = true, "host_journal"
			if len(so.Leftovers) == 0 {
				so.Leftovers = ev.Leftovers
			}
		case "left_behind":
			so.Incomplete, oc.Evidence = true, "host_journal"
			so.Leftovers = ev.Leftovers
		case "installed":
			so.OK, oc.Evidence = true, "host_journal"
			err = nil
		}
		oc.Leftovers = so.Leftovers
		if oc.Evidence != "" {
			base["evidence"] = oc.Evidence
		}
	}
	if err == nil && so.OK {
		oc.OK = true
		oc.Outcome = "installed"
		oc.Verify = verifyAgainst(hostState, node.ID, fresh.Deployment, ident.ServerID, bundle, run, "post_install", now)
		s.saveOutcome(oc)
		s.recordWSS(node.ID, b, true, false, "")
		base["dry_run"] = false
		base["outcome"] = "installed"
		base["host_key"] = res.Fingerprint
		base["public_key"] = pub
		base["verify"] = oc.Verify
		writeJSON(w, http.StatusOK, base)
		return
	}
	code := sshexec.CodeOf(err)
	status := http.StatusBadGateway
	msg := ""
	if err != nil {
		msg = redactRemote(err.Error(), key, wssSec)
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
		if oc.Evidence == "host_journal" {
			msg += "（面板没有收到脚本的补偿标记，这个结论来自脚本结束后在同一登录里读取的服务器 journal：这次运行的状态是 compensated）"
		}
	case err == nil:
		// Exit 0 without the success marker: never claim success.
		code = sshexec.CodeCommandFailed
		base["outcome"] = "unknown"
		msg = "脚本结束了，但没有输出成功标记：结果不明，不当作成功。重新预检查看服务器上的 journal"
	case sshexec.NotExecutedOf(err):
		// The login of the script step failed (the connection of the
		// preflight re-run was lost in between): nothing was sent.
		switch code {
		case sshexec.CodeUntrusted, sshexec.CodeMismatch, sshexec.CodeNoCredential, sshexec.CodeTargetChanged, sshexec.CodePinMismatch, sshexec.CodeChannelNotAllowed:
			status = http.StatusConflict
		case sshexec.CodeNotFound:
			status = http.StatusNotFound
		case sshexec.CodeRateLimited:
			status = rateLimitHeaders(w, err)
			base["retry_after"] = sshexec.RetryAfterOf(err)
		}
		base["outcome"] = "not_started"
	default:
		switch code {
		case sshexec.CodeUntrusted, sshexec.CodeMismatch, sshexec.CodeNoCredential, sshexec.CodeTargetChanged, sshexec.CodePinMismatch:
			status = http.StatusConflict
			base["outcome"] = "not_started"
		case sshexec.CodeNotFound:
			status = http.StatusNotFound
			base["outcome"] = "not_started"
		default:
			base["outcome"] = "unknown"
			msg += "。脚本可能在执行中被中断：结果不明，不当作成功，面板也不会自动重试；服务器上的补偿会在断线时运行，重新预检会显示它的 journal"
		}
	}
	switch base["outcome"] {
	case "refused", "compensated":
		s.recordWSS(node.ID, b, false, false, msg)
	case "left_behind", "unknown":
		s.recordWSS(node.ID, b, false, true, msg)
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
	if base["outcome"] == "not_started" {
		execFlags(base, err)
	}
	if h := s.loginHelpFor(cs, node.ServerID, code, sshexec.OfferedOf(err)); h != nil {
		base["login_help"] = h
	}
	writeJSON(w, status, base)
}

// redactRemote hides the node key and every WSS secret (whole values and,
// for a PEM key echoed in pieces, its longer lines) in script output.
func redactRemote(text, key string, wss map[string]string) string {
	text = apply.RedactSecrets(text, key, wss)
	vals := make([]string, 0, len(wss))
	for _, v := range wss {
		vals = append(vals, v)
	}
	return credentials.Scrub(text, vals...)
}

// carrierSOCKSCredentials lists the SOCKS credential ids of the external
// exits carried by nodeID (sorted, unique).
func carrierSOCKSCredentials(t model.Topology, nodeID string) []string {
	seen := map[string]bool{}
	var out []string
	for _, n := range model.ExternalExitsOf(t, nodeID) {
		if id := n.External.CredentialID; id != "" && !seen[id] {
			seen[id] = true
			out = append(out, id)
		}
	}
	sort.Strings(out)
	return out
}
