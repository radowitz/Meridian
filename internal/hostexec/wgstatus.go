package hostexec

// The remote-access status read (POST /v1/remote-access/status).
//
// It has no parameters at all: the interface is the fixed remote-access
// interface "mra" and the commands are fixed. It runs
//
//	ip -o link show dev mra
//	wg show mra latest-handshakes
//	wg show mra transfer
//
// and returns, per peer, the public key, the latest handshake (unix
// seconds, 0 = never) and the transfer counters. "wg show … dump" and
// anything else that prints a private or pre-shared key is never run. Like
// the list status it is read-only and takes no action lock.

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"
)

// WGPeer is one peer of the remote-access interface.
type WGPeer struct {
	PublicKey string `json:"public_key"`
	// LatestHandshake is unix seconds; 0 means no handshake yet.
	LatestHandshake int64 `json:"latest_handshake"`
	RxBytes         int64 `json:"rx_bytes"`
	TxBytes         int64 `json:"tx_bytes"`
}

// WGStatus is the agent's answer.
type WGStatus struct {
	Interface string   `json:"interface"`
	Present   bool     `json:"present"`
	Peers     []WGPeer `json:"peers"`
	ReadAt    string   `json:"read_at"`
	Error     string   `json:"error,omitempty"`
}

func validWGKey(s string) bool {
	if len(s) != 44 {
		return false
	}
	b, err := base64.StdEncoding.DecodeString(s)
	return err == nil && len(b) == 32
}

// ParseLatestHandshakes parses "wg show <if> latest-handshakes":
// "<public key>\t<unix seconds>" per line.
func ParseLatestHandshakes(out string) (map[string]int64, error) {
	m := map[string]int64{}
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		f := strings.Fields(line)
		if len(f) != 2 || !validWGKey(f[0]) {
			return nil, fmt.Errorf("latest-handshakes 输出无法解析")
		}
		v, err := strconv.ParseInt(f[1], 10, 64)
		if err != nil || v < 0 {
			return nil, fmt.Errorf("latest-handshakes 输出无法解析")
		}
		m[f[0]] = v
	}
	return m, nil
}

// ParseTransfer parses "wg show <if> transfer":
// "<public key>\t<rx bytes>\t<tx bytes>" per line.
func ParseTransfer(out string) (map[string][2]int64, error) {
	m := map[string][2]int64{}
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		f := strings.Fields(line)
		if len(f) != 3 || !validWGKey(f[0]) {
			return nil, fmt.Errorf("transfer 输出无法解析")
		}
		rx, err1 := strconv.ParseInt(f[1], 10, 64)
		tx, err2 := strconv.ParseInt(f[2], 10, 64)
		if err1 != nil || err2 != nil || rx < 0 || tx < 0 {
			return nil, fmt.Errorf("transfer 输出无法解析")
		}
		m[f[0]] = [2]int64{rx, tx}
	}
	return m, nil
}

// RemoteAccessStatus reads the remote-access interface's peers.
func (a *Agent) RemoteAccessStatus(ctx context.Context) WGStatus {
	a.init()
	st := WGStatus{Interface: RemoteAccessIface, Peers: []WGPeer{}, ReadAt: time.Now().UTC().Format(time.RFC3339)}
	timeout := a.StepTimeout
	if timeout > 10*time.Second {
		timeout = 10 * time.Second
	}
	x := &run{a: a, ctx: ctx}
	if _, err := x.cmd(timeout, "ip", "-o", "link", "show", "dev", RemoteAccessIface); err != nil {
		return st // interface absent: Present false, no error
	}
	st.Present = true
	hs, err := x.cmd(timeout, "wg", "show", RemoteAccessIface, "latest-handshakes")
	if err != nil {
		st.Error = "wg show latest-handshakes 失败：" + clip(firstLine(err.Error()))
		return st
	}
	tr, err := x.cmd(timeout, "wg", "show", RemoteAccessIface, "transfer")
	if err != nil {
		st.Error = "wg show transfer 失败：" + clip(firstLine(err.Error()))
		return st
	}
	hm, err := ParseLatestHandshakes(hs)
	if err != nil {
		st.Error = err.Error()
		return st
	}
	tm, err := ParseTransfer(tr)
	if err != nil {
		st.Error = err.Error()
		return st
	}
	for k, v := range hm {
		p := WGPeer{PublicKey: k, LatestHandshake: v}
		if t, ok := tm[k]; ok {
			p.RxBytes, p.TxBytes = t[0], t[1]
		}
		st.Peers = append(st.Peers, p)
	}
	sort.Slice(st.Peers, func(i, j int) bool { return st.Peers[i].PublicKey < st.Peers[j].PublicKey })
	return st
}

func (a *Agent) serveRemoteAccessStatus(w http.ResponseWriter, r *http.Request) {
	if !a.authorize(w, r) {
		return
	}
	// The only accepted body is an empty object: no caller-supplied value.
	dec := json.NewDecoder(io.LimitReader(r.Body, 1024))
	dec.DisallowUnknownFields()
	var empty struct{}
	if err := dec.Decode(&empty); err != nil && !errors.Is(err, io.EOF) {
		writeJSON(w, http.StatusBadRequest, WGStatus{Error: "请求格式不正确（不接受任何参数）"})
		return
	}
	writeJSON(w, http.StatusOK, a.RemoteAccessStatus(r.Context()))
}

// RemoteAccessStatus asks the agent for the remote-access peer status.
func (c *Client) RemoteAccessStatus(ctx context.Context) (WGStatus, error) {
	var st WGStatus
	code, err := c.post(ctx, "/v1/remote-access/status", struct{}{}, 20*time.Second, &st)
	if err != nil {
		return st, err
	}
	if code != http.StatusOK {
		return st, fmt.Errorf("host agent 读取远程接入状态失败（%d）：%s", code, st.Error)
	}
	if st.Error != "" {
		return st, errors.New(st.Error)
	}
	return st, nil
}
