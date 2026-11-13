package hostexec

// The gateway's name-sniffing forwarder (compile/render_sniff.go,
// internal/sniff) as the host agent sees it:
//
//   - POST /v1/sniff/status: no parameters. Reads the forwarder's status
//     socket (SniffSocket, fixed) — GET /v1/health and GET /v1/recent —
//     bounded to MaxSniffStatus bytes each, checks both are JSON and hands
//     them to the panel unchanged. Read-only, no action lock. The recent
//     record holds names only when the operator turned name recording on;
//     it lives in the forwarder's memory, never on disk.
//   - After a list or rule-set update the agent sends the running
//     forwarder SIGHUP (systemctl try-reload-or-restart), so it re-reads the
//     rule-set and list files after nft has the new sets (reloadSniff).
//   - Installs reload it instead of restarting it when its unit file did
//     not change (Resources.Reload, apply.converge): rule changes keep the
//     open connections.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"time"
)

// Fixed names (compile.SniffUnit / compile.SniffStatusSocket; a test keeps
// them equal).
const (
	SniffUnit   = "meridian-sniff.service"
	SniffSocket = "/run/meridian-sniff/status.sock"
	// MaxSniffStatus bounds each of the two reads.
	MaxSniffStatus = 1 << 20
)

// SniffStatus is the agent's answer. Present is false when the socket does
// not exist (the forwarder is off, stopped or not installed).
type SniffStatus struct {
	Present bool            `json:"present"`
	Active  string          `json:"active,omitempty"` // systemctl is-active
	Health  json.RawMessage `json:"health,omitempty"`
	Recent  json.RawMessage `json:"recent,omitempty"`
	ReadAt  string          `json:"read_at"`
	Error   string          `json:"error,omitempty"`
}

func (a *Agent) sniffSocket() string {
	if a.SniffSocketPath != "" {
		return a.SniffSocketPath
	}
	return SniffSocket
}

// SniffStatus reads the forwarder's status socket.
func (a *Agent) SniffStatus(ctx context.Context) SniffStatus {
	a.init()
	st := SniffStatus{ReadAt: time.Now().UTC().Format(time.RFC3339)}
	x := &run{a: a, ctx: ctx}
	if out, _ := x.cmd(a.StepTimeout, "systemctl", "is-active", SniffUnit); out != "" {
		st.Active = firstLine(out)
	}
	path := a.sniffSocket()
	if fi, err := os.Stat(path); err != nil || fi.Mode()&os.ModeSocket == 0 {
		return st
	}
	st.Present = true
	hc := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				var d net.Dialer
				return d.DialContext(ctx, "unix", path)
			},
			DisableKeepAlives: true,
		},
	}
	get := func(p string) (json.RawMessage, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://meridian-sniff"+p, nil)
		if err != nil {
			return nil, err
		}
		resp, err := hc.Do(req)
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()
		b, err := io.ReadAll(io.LimitReader(resp.Body, MaxSniffStatus+1))
		if err != nil {
			return nil, err
		}
		if len(b) > MaxSniffStatus {
			return nil, errors.New("回答过长")
		}
		// /v1/health answers 503 with a body while not ready.
		if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusServiceUnavailable {
			return nil, fmt.Errorf("状态 %d", resp.StatusCode)
		}
		if !json.Valid(b) {
			return nil, errors.New("回答不是 JSON")
		}
		return json.RawMessage(b), nil
	}
	var err error
	if st.Health, err = get("/v1/health"); err != nil {
		st.Error = "读不到嗅探服务的健康状态：" + clip(firstLine(err.Error()))
		return st
	}
	if st.Recent, err = get("/v1/recent"); err != nil {
		st.Error = "读不到嗅探服务的近期决策：" + clip(firstLine(err.Error()))
	}
	return st
}

func (a *Agent) serveSniffStatus(w http.ResponseWriter, r *http.Request) {
	if !a.authorize(w, r) {
		return
	}
	dec := json.NewDecoder(io.LimitReader(r.Body, 1024))
	dec.DisallowUnknownFields()
	var empty struct{}
	if err := dec.Decode(&empty); err != nil && !errors.Is(err, io.EOF) {
		writeJSON(w, http.StatusBadRequest, SniffStatus{Error: "请求格式不正确（不接受任何参数）"})
		return
	}
	writeJSON(w, http.StatusOK, a.SniffStatus(r.Context()))
}

// SniffStatus asks the agent for the forwarder's state.
func (c *Client) SniffStatus(ctx context.Context) (SniffStatus, error) {
	var st SniffStatus
	code, err := c.post(ctx, "/v1/sniff/status", struct{}{}, 15*time.Second, &st)
	if err != nil {
		return st, err
	}
	if code != http.StatusOK {
		return st, fmt.Errorf("host agent 读取嗅探服务状态失败（%d）：%s", code, st.Error)
	}
	return st, nil
}

// reloadSniff signals a running forwarder to re-read its files (no-op when
// it is not running). Returns a warning, "" on success or when not running.
func (x *run) reloadSniff() string {
	if _, err := x.cmd(x.a.StepTimeout, "systemctl", "is-active", "--quiet", SniffUnit); err != nil {
		return ""
	}
	if out, err := x.cmd(x.a.StepTimeout, "systemctl", "try-reload-or-restart", SniffUnit); err != nil {
		return "名单已发布，但通知 " + SniffUnit + " 重新读取失败：" + clip(firstLine(err.Error()+" "+out))
	}
	return ""
}
