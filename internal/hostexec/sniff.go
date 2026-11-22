package hostexec

// The gateway's name-sniffing forwarder (compile/render_sniff.go,
// internal/sniff) as the host agent sees it:
//
//   - POST /v1/sniff/status: no parameters. Reads the forwarder's status
//     socket (SniffSocket, fixed) — GET /v1/health and GET /v1/recent —
//     bounded to MaxSniffStatus bytes each, checks both are JSON and hands
//     them to the panel unchanged. Read-only, no action lock. The recent
//     record holds names only when the operator turned name recording on;
//     it lives in the forwarder's memory (the on-disk journal is below).
//   - After a list or rule-set update the agent sends the running
//     forwarder SIGHUP (systemctl try-reload-or-restart), so it re-reads the
//     rule-set and list files after nft has the new sets (reloadSniff).
//   - Installs reload it instead of restarting it when its unit files and
//     account script did not change (Resources.Reload, apply.converge):
//     rule changes keep the open connections.
//   - Its account comes from SniffAccountUnit, a root oneshot the
//     forwarder's unit requires and is ordered after (systemd resolves
//     User= before any Exec line, so the forwarder's own unit cannot create
//     the account). That unit is never named by a caller (reservedUnits):
//     the agent starts and stops it only together with SniffUnit, with
//     fixed steps (sniffActivate, sniffRemove, the health check).
//   - Status socket access: the agent is root with CAP_NET_ADMIN only, so
//     it reaches the socket through its "other" bits (directory 0755,
//     socket 0666); the forwarder answers only uid 0 (sniff.ListenStatus,
//     SO_PEERCRED). The agent's unit needs no group, capability or path.
//   - Path self-check (sniff/selfcheck.go). activate, after the forwarder
//     was started or reloaded and the health samples passed, waits until the
//     forwarder reports the rule pair just written (the SHA-256 of the
//     target file on disk), asks it for a self-check (POST /v1/selfcheck on
//     the same socket: no parameters) and attaches the result to its answer
//     (Result.SniffCheck) without judging it: the install transaction does
//     (apply, EvaluateSniffCheck), so a compensation restoring an older
//     version is not blocked by a tunnel that is down. A list publish that
//     reloads the forwarder does the same and turns a failure into
//     warnings of the list job. POST /v1/sniff/selfcheck runs it on demand
//     (no parameters, bounded answer, no action lock: it changes nothing).
//   - The status read adds the nft counters sniff_denied and sniff_wg_outer
//     (fixed "nft list counter" reads) and an earlier sample of
//     sniff_denied, so the panel can say whether it is growing.
//   - Connection journal (sniff/journal.go): POST /v1/sniff/journal (one
//     page: sniff.JournalQuery, every field validated here and again by the
//     forwarder), POST /v1/sniff/journal/summary (sniff.JournalSummaryQuery)
//     and POST /v1/sniff/journal/clear (no parameters). Each is one fixed
//     request to the same status socket (GET /v1/journal, GET
//     /v1/journal/summary, POST /v1/journal/clear), its answer bounded and
//     checked to be JSON, passed on unchanged. The agent never opens the
//     journal's files (it cannot: they are 0600 in a 0700 directory of the
//     forwarder's uid and it has no CAP_DAC_OVERRIDE), takes no path, no
//     command and no free-form parameter, and logs nothing of an answer.
//     Removing the forwarder (sniffRemove) also removes the journal:
//     "systemctl clean --what=state" of SniffUnit (PID 1 deletes its
//     StateDirectory).

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/radowitz/meridian/internal/sniff"
)

// Fixed names (compile.SniffUnit / compile.SniffStatusSocket; a test keeps
// them equal).
const (
	SniffUnit = "meridian-sniff.service"
	// SniffAccountUnit is the forwarder's account unit
	// (compile.SniffAccountUnit).
	SniffAccountUnit = "meridian-sniff-account.service"
	SniffSocket      = "/run/meridian-sniff/status.sock"
	// SniffTargets is the forwarder's target file (compile.SniffTargetsPath):
	// its SHA-256 is the identity of the rule pair a self-check must name.
	SniffTargets = "/etc/meridian/sniff/targets.json"
	// MaxSniffStatus bounds each of the two reads.
	MaxSniffStatus = 1 << 20
	// DefaultSniffSelfCheckWait bounds the wait for the forwarder to report
	// the rule pair just written before its self-check is asked for.
	DefaultSniffSelfCheckWait = 20 * time.Second
	// sniffDeniedMin / Max: the earlier sample of sniff_denied the status
	// read reports is at least Min and at most Max old.
	sniffDeniedMin = 30 * time.Second
	sniffDeniedMax = 30 * time.Minute
)

// NFTCounter is one named nft counter of table inet meridian.
type NFTCounter struct {
	Present bool   `json:"present"`
	Packets uint64 `json:"packets"`
	Bytes   uint64 `json:"bytes"`
}

// CounterSample is an earlier reading of a counter.
type CounterSample struct {
	At      time.Time `json:"at"`
	Packets uint64    `json:"packets"`
}

// SniffCheckReport is a self-check as the agent obtained it: the result, or
// why there is none (Code: sniff.CheckNoSocket, CheckNotLoaded,
// CheckNoAnswer, or "no_targets" when the target file cannot be read).
type SniffCheckReport struct {
	RequestedAt time.Time `json:"requested_at"`
	ReadAt      time.Time `json:"read_at"`
	// TargetsSHA256 is the hash of the target file on disk when asked.
	TargetsSHA256 string           `json:"targets_sha256,omitempty"`
	Code          string           `json:"code,omitempty"`
	Error         string           `json:"error,omitempty"`
	Result        *sniff.SelfCheck `json:"result,omitempty"`
}

// EvaluateSniffCheck judges a report as evidence for the rule pair whose
// target file hashes to want: no report, no result (each reason distinct)
// or a stale one fails; a failed default target fails; other targets that
// failed are warnings (sniff.EvaluateSelfCheck). Times are the host's own.
func EvaluateSniffCheck(r *SniffCheckReport, want string) sniff.Verdict {
	switch {
	case r == nil:
		return sniff.Verdict{Code: sniff.VerdictUnavailable, Reason: "宿主代理没有返回嗅探服务的自检结果（代理版本过旧，或没有执行自检）"}
	case r.Code == sniff.CheckNoAnswer || r.Code == sniff.CheckNotLoaded:
		return sniff.Verdict{Code: sniff.VerdictTimeout, Reason: "嗅探服务的自检没有按时完成：" + r.Error}
	case r.Code != "" || r.Result == nil:
		return sniff.Verdict{Code: sniff.VerdictUnavailable, Reason: "嗅探服务的自检无法执行：" + r.Error}
	}
	return sniff.EvaluateSelfCheck(r.Result, want, r.RequestedAt, r.ReadAt)
}

// SniffStatus is the agent's answer. Present is false when the socket does
// not exist (the forwarder is off, stopped or not installed).
type SniffStatus struct {
	Present bool            `json:"present"`
	Active  string          `json:"active,omitempty"` // systemctl is-active
	Health  json.RawMessage `json:"health,omitempty"`
	Recent  json.RawMessage `json:"recent,omitempty"`
	ReadAt  string          `json:"read_at"`
	Error   string          `json:"error,omitempty"`
	// Counters are sniff_denied and sniff_wg_outer of table inet meridian;
	// DeniedSince an earlier reading of sniff_denied by this agent (nil
	// when it has none between sniffDeniedMin and sniffDeniedMax old).
	Counters    map[string]NFTCounter `json:"nft_counters,omitempty"`
	DeniedSince *CounterSample        `json:"denied_since,omitempty"`
	// TargetsSHA256 is the hash of the installed target file (the rule pair
	// a current self-check names); "" when there is none.
	TargetsSHA256 string `json:"targets_sha256,omitempty"`
}

// sniffCounters are the nft counters the status read reports.
var sniffCounters = []string{"sniff_denied", "sniff_wg_outer"}

var counterRe = regexp.MustCompile(`packets (\d+) bytes (\d+)`)

// sniffHistory keeps the agent's recent readings of sniff_denied.
type sniffHistory struct {
	mu      sync.Mutex
	samples []CounterSample
}

// note records a reading at now and returns the oldest kept one between
// sniffDeniedMin and sniffDeniedMax old (a counter that went down, a ruleset
// reload, drops the history).
func (h *sniffHistory) note(now time.Time, packets uint64) *CounterSample {
	h.mu.Lock()
	defer h.mu.Unlock()
	var keep []CounterSample
	for _, s := range h.samples {
		if now.Sub(s.At) <= sniffDeniedMax && s.Packets <= packets {
			keep = append(keep, s)
		}
	}
	var out *CounterSample
	for _, s := range keep {
		if now.Sub(s.At) >= sniffDeniedMin {
			c := s
			out = &c
			break
		}
	}
	keep = append(keep, CounterSample{At: now, Packets: packets})
	if len(keep) > 64 {
		keep = keep[len(keep)-64:]
	}
	h.samples = keep
	return out
}

func (a *Agent) hostPath(p string) string {
	if a.PreflightRoot != "" {
		return filepath.Join(a.PreflightRoot, filepath.FromSlash(strings.TrimPrefix(p, "/")))
	}
	return p
}

// sniffTargetsSHA is the hash of the target file on disk ("" absent).
func (a *Agent) sniffTargetsSHA() (string, error) {
	b, err := os.ReadFile(a.hostPath(SniffTargets))
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:]), nil
}

// sniffSelfCheck asks the forwarder for a self-check of the rule pair on
// disk (bounded by wait for the pair to be loaded and by the self-check's
// own budget).
func (a *Agent) sniffSelfCheck(ctx context.Context, wait time.Duration) *SniffCheckReport {
	rep := &SniffCheckReport{RequestedAt: time.Now()}
	sha, err := a.sniffTargetsSHA()
	if err != nil {
		rep.Code, rep.Error, rep.ReadAt = "no_targets", "读不到嗅探服务的目标文件："+clip(firstLine(err.Error())), time.Now()
		return rep
	}
	rep.TargetsSHA256 = sha
	res, code, err := sniff.InstalledSelfCheck(ctx, a.sniffSocket(), sha, wait)
	rep.ReadAt = time.Now()
	if err != nil {
		rep.Code, rep.Error = code, clip(err.Error())
		return rep
	}
	rep.Result = res
	return rep
}

func (a *Agent) sniffWait() time.Duration {
	if a.SniffSelfCheckWait > 0 {
		return a.SniffSelfCheckWait
	}
	return DefaultSniffSelfCheckWait
}

// readSniffCounters reads the fixed nft counters.
func (x *run) readSniffCounters() map[string]NFTCounter {
	out := map[string]NFTCounter{}
	for _, n := range sniffCounters {
		o, err := x.cmd(x.a.StepTimeout, "nft", "list", "counter", "inet", "meridian", n)
		m := counterRe.FindStringSubmatch(o)
		if err != nil || m == nil {
			out[n] = NFTCounter{}
			continue
		}
		p, _ := strconv.ParseUint(m[1], 10, 64)
		b, _ := strconv.ParseUint(m[2], 10, 64)
		out[n] = NFTCounter{Present: true, Packets: p, Bytes: b}
	}
	return out
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
	r := ReadSniffSocket(ctx, a.sniffSocket())
	r.Active, r.ReadAt = st.Active, st.ReadAt
	r.Counters = x.readSniffCounters()
	if d := r.Counters["sniff_denied"]; d.Present {
		r.DeniedSince = a.sniffDenied.note(time.Now(), d.Packets)
	}
	r.TargetsSHA256, _ = a.sniffTargetsSHA()
	return r
}

func (a *Agent) serveSniffSelfCheck(w http.ResponseWriter, r *http.Request) {
	if !a.authorize(w, r) {
		return
	}
	dec := json.NewDecoder(io.LimitReader(r.Body, 1024))
	dec.DisallowUnknownFields()
	var empty struct{}
	if err := dec.Decode(&empty); err != nil && !errors.Is(err, io.EOF) {
		writeJSON(w, http.StatusBadRequest, SniffCheckReport{Error: "请求格式不正确（不接受任何参数）"})
		return
	}
	a.init()
	// On demand the forwarder is expected to run the pair on disk already:
	// a short wait only.
	writeJSON(w, http.StatusOK, a.sniffSelfCheck(r.Context(), 3*time.Second))
}

// SniffSelfCheck asks the agent to have the forwarder run its self-check
// now (no parameters).
func (c *Client) SniffSelfCheck(ctx context.Context) (SniffCheckReport, error) {
	var rep SniffCheckReport
	code, err := c.post(ctx, "/v1/sniff/selfcheck", struct{}{}, sniff.SelfCheckBudget+30*time.Second, &rep)
	if err != nil {
		return rep, err
	}
	if code != http.StatusOK {
		return rep, fmt.Errorf("host agent 执行嗅探自检失败（%d）：%s", code, rep.Error)
	}
	return rep, nil
}

// ReadSniffSocket reads the forwarder's status socket at path: the agent's
// own read (SniffStatus) and "meridian sniff-verify-read", which
// deploy/verify-sniff-systemd.sh runs inside the agent's sandbox.
func ReadSniffSocket(ctx context.Context, path string) SniffStatus {
	st := SniffStatus{ReadAt: time.Now().UTC().Format(time.RFC3339)}
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

// SniffJournalAnswer is the agent's answer to a journal request: the
// forwarder's answer unchanged (Body, JSON), or why there is none (Code:
// "no_socket" the forwarder is not running, "no_journal" it runs without a
// journal, "bad_request" the request was refused, "read_failed").
type SniffJournalAnswer struct {
	Present bool            `json:"present"`
	Code    string          `json:"code,omitempty"`
	Error   string          `json:"error,omitempty"`
	Body    json.RawMessage `json:"body,omitempty"`
}

// maxJournalRequest bounds a journal request's body.
const maxJournalRequest = 2048

// journalCall makes one fixed request to the forwarder's journal.
func (a *Agent) journalCall(ctx context.Context, method, p string) SniffJournalAnswer {
	path := a.sniffSocket()
	if fi, err := os.Stat(path); err != nil || fi.Mode()&os.ModeSocket == 0 {
		return SniffJournalAnswer{Code: "no_socket", Error: "嗅探服务没有运行（没有状态套接字）"}
	}
	ans := SniffJournalAnswer{Present: true}
	cctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	b, code, err := sniff.StatusCall(cctx, path, method, p)
	switch {
	case err != nil:
		ans.Code, ans.Error = "read_failed", "读不到嗅探服务的连接日志："+clip(firstLine(err.Error()))
	case code == http.StatusNotFound:
		ans.Code, ans.Error = "no_journal", "嗅探服务没有连接日志（旧版本，或日志目录无法打开）"
	case code == http.StatusBadRequest:
		ans.Code, ans.Error = "bad_request", "请求被嗅探服务拒绝："+clip(firstLine(strings.TrimSpace(string(b))))
	case code != http.StatusOK:
		ans.Code, ans.Error = "read_failed", fmt.Sprintf("嗅探服务回答状态 %d", code)
	case !json.Valid(b):
		ans.Code, ans.Error = "read_failed", "嗅探服务的回答不是 JSON"
	default:
		ans.Body = json.RawMessage(b)
	}
	return ans
}

// decodeJournalRequest reads a bounded request body into v (unknown
// fields refused; an empty body is the zero value).
func decodeJournalRequest(r *http.Request, v any) error {
	dec := json.NewDecoder(io.LimitReader(r.Body, maxJournalRequest))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil && !errors.Is(err, io.EOF) {
		return err
	}
	return nil
}

func (a *Agent) serveSniffJournal(w http.ResponseWriter, r *http.Request) {
	if !a.authorize(w, r) {
		return
	}
	var q sniff.JournalQuery
	if err := decodeJournalRequest(r, &q); err != nil {
		writeJSON(w, http.StatusBadRequest, SniffJournalAnswer{Code: "bad_request", Error: "请求格式不正确"})
		return
	}
	if err := q.Validate(); err != nil {
		writeJSON(w, http.StatusBadRequest, SniffJournalAnswer{Code: "bad_request", Error: "查询条件不正确：" + clip(err.Error())})
		return
	}
	a.init()
	writeJSON(w, http.StatusOK, a.journalCall(r.Context(), http.MethodGet, "/v1/journal?"+q.Values().Encode()))
}

func (a *Agent) serveSniffJournalSummary(w http.ResponseWriter, r *http.Request) {
	if !a.authorize(w, r) {
		return
	}
	var q sniff.JournalSummaryQuery
	if err := decodeJournalRequest(r, &q); err != nil {
		writeJSON(w, http.StatusBadRequest, SniffJournalAnswer{Code: "bad_request", Error: "请求格式不正确"})
		return
	}
	if err := q.Validate(); err != nil {
		writeJSON(w, http.StatusBadRequest, SniffJournalAnswer{Code: "bad_request", Error: "时间范围不正确：" + clip(err.Error())})
		return
	}
	v := url.Values{}
	if q.From != "" {
		v.Set("from", q.From)
	}
	if q.To != "" {
		v.Set("to", q.To)
	}
	p := "/v1/journal/summary"
	if len(v) > 0 {
		p += "?" + v.Encode()
	}
	a.init()
	writeJSON(w, http.StatusOK, a.journalCall(r.Context(), http.MethodGet, p))
}

func (a *Agent) serveSniffJournalClear(w http.ResponseWriter, r *http.Request) {
	if !a.authorize(w, r) {
		return
	}
	var empty struct{}
	if err := decodeJournalRequest(r, &empty); err != nil {
		writeJSON(w, http.StatusBadRequest, SniffJournalAnswer{Code: "bad_request", Error: "请求格式不正确（不接受任何参数）"})
		return
	}
	a.init()
	writeJSON(w, http.StatusOK, a.journalCall(r.Context(), http.MethodPost, "/v1/journal/clear"))
}

func (a *Agent) serveSniffDisconnect(w http.ResponseWriter, r *http.Request) {
	if !a.authorize(w, r) {
		return
	}
	var empty struct{}
	if err := decodeJournalRequest(r, &empty); err != nil {
		writeJSON(w, http.StatusBadRequest, SniffJournalAnswer{Code: "bad_request", Error: "请求格式不正确"})
		return
	}
	a.init()
	writeJSON(w, http.StatusOK, a.journalCall(r.Context(), http.MethodPost, "/v1/connections/disconnect"))
}

func (c *Client) SniffDisconnect(ctx context.Context) (SniffJournalAnswer, error) {
	return c.journalPost(ctx, "/v1/sniff/connections/disconnect", struct{}{})
}

func (c *Client) journalPost(ctx context.Context, path string, body any) (SniffJournalAnswer, error) {
	var ans SniffJournalAnswer
	code, err := c.post(ctx, path, body, 30*time.Second, &ans)
	if err != nil {
		return ans, err
	}
	if code != http.StatusOK && code != http.StatusBadRequest {
		return ans, fmt.Errorf("host agent 读取连接日志失败（%d）：%s", code, ans.Error)
	}
	if code == http.StatusBadRequest && ans.Code == "" {
		ans.Code = "bad_request"
	}
	return ans, nil
}

// SniffJournal asks the agent for one page of the connection journal.
func (c *Client) SniffJournal(ctx context.Context, q sniff.JournalQuery) (SniffJournalAnswer, error) {
	return c.journalPost(ctx, "/v1/sniff/journal", q)
}

// SniffJournalSummary asks the agent for the per-device summary.
func (c *Client) SniffJournalSummary(ctx context.Context, q sniff.JournalSummaryQuery) (SniffJournalAnswer, error) {
	return c.journalPost(ctx, "/v1/sniff/journal/summary", q)
}

// SniffJournalClear asks the agent to have the forwarder clear its
// journal (no parameters).
func (c *Client) SniffJournalClear(ctx context.Context) (SniffJournalAnswer, error) {
	return c.journalPost(ctx, "/v1/sniff/journal/clear", struct{}{})
}

// reloadSniff signals a running forwarder to re-read its files (no-op when
// it is not running), then has it run its self-check on the reloaded rules.
// A list publish has no transaction to undo, so a failure is reported as
// warnings of the list job (and shows in the panel's last self-check).
// Returns the warnings, none on success or when not running.
func (x *run) reloadSniff() []string {
	if _, err := x.cmd(x.a.StepTimeout, "systemctl", "is-active", "--quiet", SniffUnit); err != nil {
		return nil
	}
	before := time.Now()
	if out, err := x.cmd(x.a.StepTimeout, "systemctl", "try-reload-or-restart", SniffUnit); err != nil {
		return []string{"名单已发布，但通知 " + SniffUnit + " 重新读取失败：" + clip(firstLine(err.Error()+" "+out))}
	}
	rep := x.sniffReloadCheck(before)
	if rep == nil {
		return nil
	}
	v := EvaluateSniffCheck(rep, rep.TargetsSHA256)
	var w []string
	if !v.OK {
		w = append(w, "名单已发布并已通知 "+SniffUnit+" 重新读取，但嗅探转发服务自检未通过（不会自动撤回名单；请在面板的嗅探状态里查看）："+v.Reason)
	}
	for _, f := range v.Failing {
		w = append(w, "嗅探转发服务自检：目标 "+f)
	}
	return w
}

// sniffReloadCheck waits for the forwarder to finish the reload (its health
// reports a reload at or after before) and asks for a self-check. A list
// publish keeps the target file, so the rule pair's identity is unchanged;
// what matters is that the run used the reloaded lists.
func (x *run) sniffReloadCheck(before time.Time) *SniffCheckReport {
	deadline := time.Now().Add(x.a.sniffWait())
	for time.Now().Before(deadline) && x.ctx.Err() == nil {
		hctx, cancel := context.WithTimeout(x.ctx, 3*time.Second)
		b, code, err := sniff.StatusCall(hctx, x.a.sniffSocket(), http.MethodGet, "/v1/health")
		cancel()
		var h sniff.Health
		if err == nil && (code == http.StatusOK || code == http.StatusServiceUnavailable) && json.Unmarshal(b, &h) == nil &&
			h.LastReloadAt != nil && !h.LastReloadAt.Before(before.Add(-time.Second)) {
			break
		}
		select {
		case <-x.ctx.Done():
		case <-time.After(200 * time.Millisecond):
		}
	}
	return x.a.sniffSelfCheck(x.ctx, x.a.sniffWait())
}

// sniffRestart (re)starts the forwarder with a fresh account, in a fixed
// order: stop the forwarder (its ExecStopPost turns tcp_fwmark_accept off),
// stop its account unit (the account is removed; a changed script or unit
// file is used from the next start), clear both failed states, start the
// forwarder (systemd starts the account unit first: Requires=, After=). A
// failed start reports both units' journals; the caller compensates.
func (x *run) sniffRestart() bool {
	t := x.a.StepTimeout
	if out, err := x.cmd(t, "systemctl", "stop", SniffUnit); err != nil {
		x.step("stop "+SniffUnit, false, err.Error()+"\n"+out)
		return false
	}
	if !x.stopSniffAccount() {
		return false
	}
	_, _ = x.cmd(t, "systemctl", "reset-failed", SniffUnit, SniffAccountUnit)
	if out, err := x.cmd(t, "systemctl", "start", SniffUnit); err != nil {
		x.step("start "+SniffUnit, false, err.Error()+"\n"+out+"\n"+x.journal(SniffAccountUnit)+"\n"+x.journal(SniffUnit))
		return false
	}
	x.step("start "+SniffUnit, true, "")
	return true
}

// sniffRemove runs after SniffUnit was disabled and stopped (rollback,
// withdraw, compensation): its account unit is stopped explicitly (the
// account is removed now, not whenever systemd gets to StopWhenUnneeded),
// then both units' failed states are cleared, so systemd unloads them once
// their files are gone, and the forwarder's StateDirectory (the connection
// journal) is removed by PID 1: no journal outlives the forwarder. A failed
// clean (an older systemd, a unit file already gone) is reported, not a
// failure of the removal.
func (x *run) sniffRemove() {
	if !x.stopSniffAccount() {
		return
	}
	_, _ = x.cmd(x.a.StepTimeout, "systemctl", "reset-failed", SniffUnit, SniffAccountUnit)
	if out, err := x.cmd(x.a.StepTimeout, "systemctl", "clean", "--what=state", SniffUnit); err != nil {
		x.skip("clean "+SniffUnit+" state", "连接日志目录没有删除："+clip(firstLine(err.Error()+" "+out)))
		return
	}
	x.step("clean "+SniffUnit+" state", true, "")
}

// stopSniffAccount stops SniffAccountUnit and checks that its ExecStop (the
// account removal) succeeded: a failing ExecStop leaves the unit "failed"
// although "systemctl stop" succeeds. A unit that is already failed is
// started once more first (its "add" accepts our own account and refuses
// anyone else's), so a removal that failed earlier is retried; when that
// start fails there is no account of ours (a conflict, or "add" undid
// itself) and nothing to remove.
func (x *run) stopSniffAccount() bool {
	t := x.a.StepTimeout
	name := "stop " + SniffAccountUnit
	if _, err := x.cmd(t, "systemctl", "cat", SniffAccountUnit); err != nil {
		x.skip(name, "不存在")
		return true
	}
	if _, err := x.cmd(t, "systemctl", "is-failed", "--quiet", SniffAccountUnit); err == nil {
		_, _ = x.cmd(t, "systemctl", "reset-failed", SniffAccountUnit)
		if _, err := x.cmd(t, "systemctl", "start", SniffAccountUnit); err != nil {
			_, _ = x.cmd(t, "systemctl", "reset-failed", SniffAccountUnit)
			x.skip(name, "账户单元无法启动（账户冲突或创建失败已撤销）：没有本服务的账户可删")
			return true
		}
	}
	if out, err := x.cmd(t, "systemctl", "stop", SniffAccountUnit); err != nil {
		x.step(name, false, err.Error()+"\n"+out+"\n"+x.journal(SniffAccountUnit))
		return false
	}
	if _, err := x.cmd(t, "systemctl", "is-failed", "--quiet", SniffAccountUnit); err == nil {
		x.step(name, false, "删除嗅探服务账户失败\n"+x.journal(SniffAccountUnit))
		return false
	}
	x.step(name, true, "")
	return true
}
