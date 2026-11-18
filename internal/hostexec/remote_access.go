package hostexec

// The remote-access peer sync (POST /v1/remote-access/sync).
//
// It is the activation step of the panel's fast path for a remote-access
// device change (add / delete / regenerate): the install transaction has
// just written /etc/wireguard/mra.conf (mode 0600, secrets injected at the
// install boundary) and asks the agent to make the running interface carry
// exactly the [Peer] set of that file, without restarting it:
//
//	ip -o link show dev mra                  (the interface must be up)
//	wg-quick strip mra                       (to a 0600 temp file beside the config)
//	wg syncconf mra <temp file>
//	wg show mra peers                        (must equal the file's peers)
//
// The request carries only the transaction id and the SHA-256 of the file
// the panel wrote: no interface name, path, command or option. The agent
// refuses unless the file on disk is a regular file with mode 0600 and that
// digest. Neither the file nor the stripped config (which hold the private
// and pre-shared keys) ever appear in a step, a warning or an error.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

// ActionPeerSync names the peer sync in results and the request cache.
const ActionPeerSync = "remote_access_sync"

// RemoteAccessConf is the fixed config the peer sync applies.
const RemoteAccessConf = "etc/wireguard/mra.conf"

// PeerSyncRequest is the whole parameter set of the peer sync.
type PeerSyncRequest struct {
	Transaction string `json:"transaction"`
	Digest      string `json:"digest"`
}

var digestRe = regexp.MustCompile(`^[0-9a-f]{64}$`)

// ValidatePeerSync checks a peer sync request before anything runs.
func ValidatePeerSync(req PeerSyncRequest) error {
	if !requestIDRe.MatchString(req.Transaction) {
		return errors.New("transaction 不合法")
	}
	if !digestRe.MatchString(req.Digest) {
		return errors.New("digest 必须是 64 位小写十六进制 SHA-256")
	}
	return nil
}

// FileDigest is the digest the peer sync compares: SHA-256 of the bytes.
func FileDigest(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

var wgKeyRe = regexp.MustCompile(`[A-Za-z0-9+/]{42,43}=`)

// redactKeys removes anything shaped like a WireGuard key from tool output.
func redactKeys(s string) string { return wgKeyRe.ReplaceAllString(s, "[已隐去]") }

// confPeers lists the PublicKey values of the [Peer] sections of a config.
func confPeers(body string) []string {
	var out []string
	inPeer := false
	for _, line := range strings.Split(body, "\n") {
		l := strings.TrimSpace(line)
		if strings.HasPrefix(l, "[") {
			inPeer = strings.EqualFold(l, "[Peer]")
			continue
		}
		if !inPeer {
			continue
		}
		k, v, ok := strings.Cut(l, "=")
		if ok && strings.EqualFold(strings.TrimSpace(k), "PublicKey") {
			out = append(out, strings.TrimSpace(v))
		}
	}
	sort.Strings(out)
	return out
}

func (a *Agent) serveRemoteAccessSync(w http.ResponseWriter, r *http.Request) {
	if !a.authorize(w, r) {
		return
	}
	var req PeerSyncRequest
	dec := json.NewDecoder(io.LimitReader(r.Body, 1024))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, Result{Action: ActionPeerSync, Error: "请求格式不正确（只接受 transaction 与 digest）"})
		return
	}
	res, code := a.PeerSync(r.Context(), req)
	writeJSON(w, code, res)
}

// PeerSync validates, serialises (same action lock and drill gate as
// /v1/action) and runs one peer sync.
func (a *Agent) PeerSync(ctx context.Context, req PeerSyncRequest) (Result, int) {
	a.init()
	base := Result{RequestID: req.Transaction, Action: ActionPeerSync}
	if err := ValidatePeerSync(req); err != nil {
		base.Error = err.Error()
		return base, http.StatusBadRequest
	}
	if err := a.drillGate(); err != nil {
		base.Error = err.Error()
		return base, http.StatusConflict
	}
	wait, cancel := context.WithTimeout(ctx, a.LockWait)
	defer cancel()
	select {
	case a.sem <- struct{}{}:
	case <-wait.Done():
		base.Error = "宿主正在执行上一个动作，等待超时"
		return base, http.StatusServiceUnavailable
	}
	defer func() { <-a.sem }()
	if err := a.drillGate(); err != nil {
		base.Error = err.Error()
		return base, http.StatusConflict
	}
	id := "peer-sync/" + req.Transaction
	fp := FileDigest([]byte(ActionPeerSync + "\n" + req.Digest))
	if c, ok := a.cache[id]; ok {
		if c.fp != fp {
			base.Error = "transaction 已用于另一个 digest"
			return base, http.StatusConflict
		}
		res := c.res
		res.Replayed = true
		return res, http.StatusOK
	}
	a.beginAction()
	defer a.endAction()
	actx, acancel := context.WithTimeout(context.Background(), a.ActionTimeout)
	defer acancel()
	res := a.peerSync(actx, req.Digest)
	res.RequestID, res.Action = req.Transaction, ActionPeerSync
	a.remember(id, fp, res)
	return res, http.StatusOK
}

func (a *Agent) peerSync(ctx context.Context, digest string) Result {
	x := &run{a: a, ctx: ctx}
	root := a.PreflightRoot
	if root == "" {
		root = "/"
	}
	conf := filepath.Join(root, filepath.FromSlash(RemoteAccessConf))
	fi, err := os.Lstat(conf)
	if err != nil || !fi.Mode().IsRegular() {
		x.step("check /"+RemoteAccessConf, false, "不是普通文件或不存在")
		return x.finish()
	}
	if fi.Mode().Perm() != 0o600 {
		x.step("check /"+RemoteAccessConf, false, fmt.Sprintf("权限是 %04o，必须是 0600", fi.Mode().Perm()))
		return x.finish()
	}
	body, err := os.ReadFile(conf)
	if err != nil {
		x.step("check /"+RemoteAccessConf, false, "读取失败")
		return x.finish()
	}
	if FileDigest(body) != digest {
		x.step("check /"+RemoteAccessConf, false, "文件摘要与事务写入的不一致")
		return x.finish()
	}
	x.step("check /"+RemoteAccessConf, true, "0600，摘要一致")
	if _, err := x.cmd(a.StepTimeout, "ip", "-o", "link", "show", "dev", "mra"); err != nil {
		x.step("interface mra", false, "接口 mra 不在运行：快速生效不启动接口，需要完整安装")
		return x.finish()
	}
	x.step("interface mra", true, "")
	stripped, err := x.cmd(a.StepTimeout, "wg-quick", "strip", "mra")
	if err != nil {
		x.step("wg-quick strip mra", false, redactKeys(err.Error()))
		return x.finish()
	}
	x.step("wg-quick strip mra", true, "")
	// The stripped config goes to the agent's private temporary directory:
	// under the unit's ProtectSystem=strict sandbox /etc/wireguard is
	// read-only to the agent (PrivateTmp=yes keeps /tmp private and
	// writable). Never next to the config.
	tmp, err := os.CreateTemp("", ".mra-sync-*.conf")
	if err != nil {
		x.step("wg syncconf mra", false, "临时文件创建失败")
		return x.finish()
	}
	name := tmp.Name()
	defer os.Remove(name)
	werr := tmp.Chmod(0o600)
	if werr == nil {
		_, werr = tmp.WriteString(stripped)
	}
	if cerr := tmp.Close(); werr == nil {
		werr = cerr
	}
	if werr != nil {
		x.step("wg syncconf mra", false, "临时文件写入失败")
		return x.finish()
	}
	if out, err := x.cmd(a.StepTimeout, "wg", "syncconf", "mra", name); err != nil {
		x.step("wg syncconf mra", false, redactKeys(strings.TrimSpace(err.Error()+"\n"+out)))
		return x.finish()
	}
	x.step("wg syncconf mra", true, "接口未重启")
	out, err := x.cmd(a.StepTimeout, "wg", "show", "mra", "peers")
	if err != nil {
		x.step("verify peers", false, redactKeys(err.Error()))
		return x.finish()
	}
	running := strings.Fields(out)
	sort.Strings(running)
	want := confPeers(string(body))
	if strings.Join(running, ",") != strings.Join(want, ",") {
		x.step("verify peers", false, fmt.Sprintf("运行中的 peer 数 %d，配置里 %d，不一致", len(running), len(want)))
		return x.finish()
	}
	x.step("verify peers", true, fmt.Sprintf("%d 个 peer", len(want)))
	return x.finish()
}

// PeerSync asks the agent for the remote-access peer sync.
func (c *Client) PeerSync(ctx context.Context, req PeerSyncRequest) (Result, error) {
	if err := ValidatePeerSync(req); err != nil {
		return Result{}, err
	}
	var res Result
	code, err := c.post(ctx, "/v1/remote-access/sync", req, 3*time.Minute, &res)
	if err != nil {
		return res, err
	}
	if code != http.StatusOK {
		return res, fmt.Errorf("host agent 拒绝远程接入快速生效（%d）：%s", code, res.Error)
	}
	if !res.OK {
		return res, fmt.Errorf("远程接入快速生效失败：%s", res.Error)
	}
	return res, nil
}
