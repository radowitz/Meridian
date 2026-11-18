package hostexec

// The gateway's link journal (internal/linkjournal; docs/architecture.md
// 「链路日志」) as the host agent sees it. Every request is fixed: no path,
// no command, no unit, interface or file name and no free-form parameter
// comes from a caller. The agent never opens the journal's files; it asks
// the collector on its status socket (which answers uid 0 only) and passes
// the answer on unchanged.
//
//   - POST /v1/link/journal/status: no parameters. Read-only: whether the
//     collector's unit is active ("systemctl is-active", fixed unit name),
//     whether its status socket and its object list exist, and its
//     /v1/health (sources, bounds, counts).
//   - POST /v1/link/journal/current: no parameters. The collector's
//     /v1/current: every tracked object's state now.
//   - POST /v1/link/journal: one page of events (linkjournal.Query, every
//     field validated here and again by the collector).
//   - POST /v1/link/journal/clear: no parameters. The collector's fixed
//     clear (every event, the tracked states and the checkpoint). Without a
//     running collector nothing is cleared and the answer says so: the agent
//     does not touch the journal's directory itself.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/radowitz/meridian/internal/linkjournal"
	"github.com/radowitz/meridian/internal/sniff"
)

// LinkJournalUnit is the collector's unit (compile.LinkJournalUnit; a test
// keeps them equal).
const LinkJournalUnit = linkjournal.Unit

// LinkJournalStatus is the agent's answer to the status read.
type LinkJournalStatus struct {
	ReadAt string `json:"read_at"`
	// UnitActive is "systemctl is-active" of the collector's unit; Present
	// whether its status socket exists; ConfigInstalled whether its object
	// list is on the host; Health its /v1/health.
	UnitActive      string          `json:"unit_active,omitempty"`
	Present         bool            `json:"present"`
	ConfigInstalled bool            `json:"config_installed"`
	Health          json.RawMessage `json:"health,omitempty"`
	Error           string          `json:"error,omitempty"`
}

// LinkJournalAnswer is the agent's answer to a journal request: the
// collector's answer unchanged (Body, JSON), or why there is none (Code:
// "no_socket" the collector is not running, "bad_request", "read_failed").
type LinkJournalAnswer struct {
	Present bool            `json:"present"`
	Code    string          `json:"code,omitempty"`
	Error   string          `json:"error,omitempty"`
	Body    json.RawMessage `json:"body,omitempty"`
}

func (a *Agent) linkJournalSocket() string {
	if a.LinkJournalSocketPath != "" {
		return a.LinkJournalSocketPath
	}
	return linkjournal.StatusSocket
}

// LinkJournalStatus reads the collector's state. Read-only.
func (a *Agent) LinkJournalStatus(ctx context.Context) LinkJournalStatus {
	a.init()
	st := LinkJournalStatus{ReadAt: time.Now().UTC().Format(time.RFC3339)}
	x := &run{a: a, ctx: ctx}
	if out, _ := x.cmd(a.StepTimeout, "systemctl", "is-active", LinkJournalUnit); out != "" {
		st.UnitActive = firstLine(out)
	}
	if fi, err := os.Stat(a.hostPath(linkjournal.ConfigPath)); err == nil && fi.Mode().IsRegular() {
		st.ConfigInstalled = true
	}
	sock := a.linkJournalSocket()
	if fi, err := os.Stat(sock); err == nil && fi.Mode()&os.ModeSocket != 0 {
		st.Present = true
		hctx, cancel := context.WithTimeout(ctx, 5*time.Second)
		b, code, err := sniff.StatusCall(hctx, sock, http.MethodGet, "/v1/health")
		cancel()
		switch {
		case err != nil:
			st.Error = "读不到链路日志采集服务的状态：" + clip(firstLine(err.Error()))
		case code != http.StatusOK || !json.Valid(b):
			st.Error = fmt.Sprintf("链路日志采集服务的状态回答不可用（%d）", code)
		default:
			st.Health = json.RawMessage(b)
		}
	}
	return st
}

func (a *Agent) linkJournalCall(ctx context.Context, method, p string) LinkJournalAnswer {
	path := a.linkJournalSocket()
	if fi, err := os.Stat(path); err != nil || fi.Mode()&os.ModeSocket == 0 {
		return LinkJournalAnswer{Code: "no_socket", Error: "链路日志采集服务没有运行（没有状态套接字）"}
	}
	ans := LinkJournalAnswer{Present: true}
	cctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	b, code, err := sniff.StatusCall(cctx, path, method, p)
	switch {
	case err != nil:
		ans.Code, ans.Error = "read_failed", "读不到链路日志："+clip(firstLine(err.Error()))
	case code == http.StatusBadRequest:
		ans.Code, ans.Error = "bad_request", "请求被链路日志采集服务拒绝："+clip(firstLine(strings.TrimSpace(string(b))))
	case code != http.StatusOK:
		ans.Code, ans.Error = "read_failed", fmt.Sprintf("链路日志采集服务回答状态 %d", code)
	case !json.Valid(b):
		ans.Code, ans.Error = "read_failed", "链路日志采集服务的回答不是 JSON"
	default:
		ans.Body = json.RawMessage(b)
	}
	return ans
}

func (a *Agent) serveLinkJournalStatus(w http.ResponseWriter, r *http.Request) {
	if !a.authorize(w, r) {
		return
	}
	var empty struct{}
	if err := decodeJournalRequest(r, &empty); err != nil {
		writeJSON(w, http.StatusBadRequest, LinkJournalStatus{Error: "请求格式不正确（不接受任何参数）"})
		return
	}
	writeJSON(w, http.StatusOK, a.LinkJournalStatus(r.Context()))
}

func (a *Agent) serveLinkJournalCurrent(w http.ResponseWriter, r *http.Request) {
	if !a.authorize(w, r) {
		return
	}
	var empty struct{}
	if err := decodeJournalRequest(r, &empty); err != nil {
		writeJSON(w, http.StatusBadRequest, LinkJournalAnswer{Code: "bad_request", Error: "请求格式不正确（不接受任何参数）"})
		return
	}
	a.init()
	writeJSON(w, http.StatusOK, a.linkJournalCall(r.Context(), http.MethodGet, "/v1/current"))
}

func (a *Agent) serveLinkJournal(w http.ResponseWriter, r *http.Request) {
	if !a.authorize(w, r) {
		return
	}
	var q linkjournal.Query
	if err := decodeJournalRequest(r, &q); err != nil {
		writeJSON(w, http.StatusBadRequest, LinkJournalAnswer{Code: "bad_request", Error: "请求格式不正确"})
		return
	}
	if err := q.Validate(); err != nil {
		writeJSON(w, http.StatusBadRequest, LinkJournalAnswer{Code: "bad_request", Error: "查询条件不正确：" + clip(err.Error())})
		return
	}
	p := "/v1/events"
	if v := q.Values(); len(v) > 0 {
		p += "?" + v.Encode()
	}
	a.init()
	writeJSON(w, http.StatusOK, a.linkJournalCall(r.Context(), http.MethodGet, p))
}

func (a *Agent) serveLinkJournalClear(w http.ResponseWriter, r *http.Request) {
	if !a.authorize(w, r) {
		return
	}
	var empty struct{}
	if err := decodeJournalRequest(r, &empty); err != nil {
		writeJSON(w, http.StatusBadRequest, LinkJournalAnswer{Code: "bad_request", Error: "请求格式不正确（不接受任何参数）"})
		return
	}
	a.init()
	ans := a.linkJournalCall(r.Context(), http.MethodPost, "/v1/clear")
	if ans.Code == "no_socket" {
		ans.Error = "链路日志采集服务没有运行，没有清空：它的数据留在网关的 " + linkjournal.StateDir + "（最多 16 MiB），服务运行后可以再清空"
	}
	writeJSON(w, http.StatusOK, ans)
}

// ErrLinkJournalUnsupported: the agent has no link-journal requests (an
// older binary on the host).
var ErrLinkJournalUnsupported = errors.New("宿主上的 meridian-host 没有链路日志的请求（版本过旧）：在网关上重新运行 deploy/debian/install.sh 升级后再试")

// LinkJournalStatus asks the agent for the collector's state (no
// parameters).
func (c *Client) LinkJournalStatus(ctx context.Context) (LinkJournalStatus, error) {
	var st LinkJournalStatus
	code, err := c.post(ctx, "/v1/link/journal/status", struct{}{}, 30*time.Second, &st)
	switch {
	case code == http.StatusNotFound || code == http.StatusMethodNotAllowed:
		return st, ErrLinkJournalUnsupported
	case err != nil:
		return st, err
	case code != http.StatusOK:
		return st, fmt.Errorf("host agent 读取链路日志状态失败（%d）：%s", code, st.Error)
	}
	return st, nil
}

func (c *Client) linkJournalPost(ctx context.Context, path string, body any) (LinkJournalAnswer, error) {
	var ans LinkJournalAnswer
	code, err := c.post(ctx, path, body, 30*time.Second, &ans)
	switch {
	case code == http.StatusNotFound || code == http.StatusMethodNotAllowed:
		return ans, ErrLinkJournalUnsupported
	case err != nil:
		return ans, err
	case code != http.StatusOK && code != http.StatusBadRequest:
		return ans, fmt.Errorf("host agent 读取链路日志失败（%d）：%s", code, ans.Error)
	}
	if code == http.StatusBadRequest && ans.Code == "" {
		ans.Code = "bad_request"
	}
	return ans, nil
}

// LinkJournalCurrent asks the agent for every tracked object's state now.
func (c *Client) LinkJournalCurrent(ctx context.Context) (LinkJournalAnswer, error) {
	return c.linkJournalPost(ctx, "/v1/link/journal/current", struct{}{})
}

// LinkJournal asks the agent for one page of the link journal.
func (c *Client) LinkJournal(ctx context.Context, q linkjournal.Query) (LinkJournalAnswer, error) {
	return c.linkJournalPost(ctx, "/v1/link/journal", q)
}

// LinkJournalClear asks the agent to clear the link journal (no
// parameters).
func (c *Client) LinkJournalClear(ctx context.Context) (LinkJournalAnswer, error) {
	return c.linkJournalPost(ctx, "/v1/link/journal/clear", struct{}{})
}
