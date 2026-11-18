package sniff

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"time"
)

// The status socket's client side: the host agent's reads and the install's
// self-check request (hostexec), "meridian sniff-selfcheck" (the generated
// verify script) and the namespace tests. Every answer is bounded to
// MaxStatusAnswer bytes.

// MaxStatusAnswer bounds one answer of the status socket.
const MaxStatusAnswer = 1 << 20

// StatusCall makes one request to the status socket at path and returns
// the body (bounded) and the HTTP status.
func StatusCall(ctx context.Context, path, method, p string) ([]byte, int, error) {
	hc := &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				var d net.Dialer
				return d.DialContext(ctx, "unix", path)
			},
			DisableKeepAlives: true,
		},
	}
	req, err := http.NewRequestWithContext(ctx, method, "http://meridian-sniff"+p, nil)
	if err != nil {
		return nil, 0, err
	}
	resp, err := hc.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, MaxStatusAnswer+1))
	if err != nil {
		return nil, resp.StatusCode, err
	}
	if len(b) > MaxStatusAnswer {
		return nil, resp.StatusCode, errors.New("answer too long")
	}
	return b, resp.StatusCode, nil
}

// Codes of InstalledSelfCheck when it has no result.
const (
	CheckNoSocket  = "no_socket"  // the status socket never appeared
	CheckNotLoaded = "not_loaded" // the forwarder answered but never reported the expected rule pair
	CheckNoAnswer  = "no_answer"  // the self-check request failed or was not answered in time
)

// InstalledSelfCheck waits (up to wait) until the forwarder behind path
// reports the rule pair whose target file hashes to wantSHA, then has it run
// a self-check and returns the result. Without a result it returns one of
// the Check codes and why.
func InstalledSelfCheck(ctx context.Context, path, wantSHA string, wait time.Duration) (*SelfCheck, string, error) {
	deadline := time.Now().Add(wait)
	var last Health
	seen := false
	for {
		if fi, err := os.Stat(path); err == nil && fi.Mode()&os.ModeSocket != 0 {
			hctx, cancel := context.WithTimeout(ctx, 3*time.Second)
			b, code, err := StatusCall(hctx, path, http.MethodGet, "/v1/health")
			cancel()
			if err == nil && (code == http.StatusOK || code == http.StatusServiceUnavailable) && json.Unmarshal(b, &last) == nil {
				seen = true
				if wantSHA != "" && strings.EqualFold(last.TargetsSHA256, wantSHA) {
					break
				}
			}
		}
		if time.Now().After(deadline) || ctx.Err() != nil {
			switch {
			case !seen:
				return nil, CheckNoSocket, fmt.Errorf("嗅探服务的状态套接字在 %s 内没有出现或没有回答", wait.Round(time.Second))
			case last.LastReloadError != "":
				return nil, CheckNotLoaded, fmt.Errorf("嗅探服务没有载入本次安装的规则（仍是 %.12s…），上次重载失败：%s", last.TargetsSHA256, clipText(last.LastReloadError))
			default:
				return nil, CheckNotLoaded, fmt.Errorf("嗅探服务在 %s 内没有载入本次安装的规则（仍是 %.12s…）", wait.Round(time.Second), last.TargetsSHA256)
			}
		}
		select {
		case <-ctx.Done():
		case <-time.After(200 * time.Millisecond):
		}
	}
	rctx, cancel := context.WithTimeout(ctx, SelfCheckBudget+10*time.Second)
	defer cancel()
	b, code, err := StatusCall(rctx, path, http.MethodPost, "/v1/selfcheck")
	if err != nil {
		return nil, CheckNoAnswer, fmt.Errorf("自检请求没有得到回答：%s", clipText(err.Error()))
	}
	if code != http.StatusOK {
		return nil, CheckNoAnswer, fmt.Errorf("自检请求失败（%d）：%s", code, clipText(strings.TrimSpace(string(b))))
	}
	var res SelfCheck
	if err := json.Unmarshal(b, &res); err != nil {
		return nil, CheckNoAnswer, errors.New("自检回答不是有效的 JSON")
	}
	return &res, "", nil
}

func clipText(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = s[:i]
	}
	if len(s) > 200 {
		s = s[:200] + "…"
	}
	return s
}
