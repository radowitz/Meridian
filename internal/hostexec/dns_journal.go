package hostexec

// The gateway's DNS query journal (internal/dnsjournal; docs/architecture.md
// 「网关解析日志」) as the host agent sees it. Every request is fixed: no
// path, no command, no container name, no file name and no free-form
// parameter comes from a caller.
//
//   - POST /v1/dns/journal/status: no parameters. Read-only: which resolver
//     the gateway runs, the version the running container's binary reports
//     ("docker exec meridian-smartdns /usr/sbin/smartdns -v", a fixed argv),
//     the image it was created from and its mounts (one "docker inspect"
//     with a fixed format), this host's own verification records
//     (dnsjournal.LocalVerifiedFile), the capability gate's verdict over
//     those facts (dnsjournal.Evaluate), what the installed resolver config
//     says about the audit log, the state of the audit sink, the reader's
//     unit and health, and how much data the two fixed directories hold.
//   - POST /v1/dns/journal (one page: dnsjournal.Query, every field
//     validated here and again by the reader) and POST
//     /v1/dns/journal/summary (dnsjournal.SummaryQuery): one fixed request
//     each to the reader's status socket, the answer bounded, checked to be
//     JSON and passed on unchanged. The agent never opens the journal's
//     files for these and logs nothing of an answer.
//   - POST /v1/dns/journal/clear: no parameters. With the reader running,
//     its fixed clear (records, rotated audit copies, the audit file's
//     content). Without it — the journal was turned off and the install
//     removed the reader, or the reader is stopped — the agent deletes the
//     data itself from the two fixed directories (dnsjournal.PurgeData),
//     which is the only thing it ever writes there (the unit file's
//     ReadWritePaths names exactly that directory). Either way the answer
//     is a success only when everything went: a clear that left something
//     (a file that could not be deleted or emptied, a directory that could
//     not be listed) is answered with the code "clear_incomplete", the
//     counts of what is left and the reason in fixed words — never a path,
//     a file name or the system's error text — and can be asked again. A
//     reader too old to say whether it removed everything is answered
//     "clear_unconfirmed", not as a success.
//   - activate, when the resolver is about to be restarted with a config
//     that enables the audit log (dnsAuditGuard): the config must name
//     exactly dnsjournal.AuditFile, the capability gate must hold for the
//     running container, and the sink must be a real 0700 directory with a
//     regular 0600 file, both root's (the reader's unit, restarted earlier
//     in the same activate, prepared it). Otherwise the step fails, the
//     resolver is NOT restarted and the install is compensated. After the
//     restart the agent asks the resolver one fixed question on loopback
//     (dnsLiveness): a resolver that runs but does not answer after it was
//     given an audit log fails the install as well, whatever the cause.
//   - The data is not removed when the reader's unit is removed (a later
//     compensation may bring it back): the panel asks for the clear once
//     the install that turned the journal off has succeeded.

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/radowitz/meridian/internal/dnsjournal"
	"github.com/radowitz/meridian/internal/sniff"
)

// DNSJournalUnit is the reader's unit (compile.DNSJournalUnit; a test keeps
// them equal).
const DNSJournalUnit = dnsjournal.Unit

// DNSLivenessName is the one question the agent asks the gateway's resolver
// after it restarted it with the audit log on: a name the generated config
// answers itself (its DoH block list), so nothing is sent upstream. Any
// well-formed reply counts.
const DNSLivenessName = "dns.google"

// dnsLivenessWait bounds the wait for the restarted resolver's answer.
const dnsLivenessWait = 20 * time.Second

// dnsInspectFormat is the one "docker inspect" format of the status read.
const dnsInspectFormat = `{{.State.Running}}|{{.Image}}|{{range .Mounts}}{{.Source}}>{{.Destination}}>{{.RW}};{{end}}`

// DNSJournalStatus is the agent's answer to the status read.
type DNSJournalStatus struct {
	ReadAt     string                `json:"read_at"`
	Facts      dnsjournal.Facts      `json:"facts"`
	Capability dnsjournal.Capability `json:"capability"`
	// AuditInstalled: the installed resolver config enables the audit log
	// into the fixed file. AuditForeign: it enables an audit log elsewhere
	// (not written by this version; never read).
	AuditInstalled bool `json:"audit_installed"`
	AuditForeign   bool `json:"audit_foreign,omitempty"`
	// UnitActive is "systemctl is-active" of the reader's unit; Present
	// whether its status socket exists; Health its /v1/health.
	UnitActive string          `json:"unit_active,omitempty"`
	Present    bool            `json:"present"`
	Health     json.RawMessage `json:"health,omitempty"`
	// Sink is the audit directory and file as found (meaningful while the
	// audit is installed).
	Sink dnsjournal.SinkState `json:"sink"`
	// DataFiles / DataBytes: regular files in the two fixed directories.
	DataFiles int    `json:"data_files"`
	DataBytes int64  `json:"data_bytes"`
	Error     string `json:"error,omitempty"`
}

// DNSJournalAnswer is the agent's answer to a journal request: the reader's
// answer unchanged (Body, JSON), or why there is none (Code: "no_socket"
// the reader is not running, "no_journal" it runs without a journal,
// "bad_request", "read_failed"). A clear has two more codes, both with the
// dnsjournal.ClearResult in Body: DNSClearIncomplete and
// DNSClearUnconfirmed.
type DNSJournalAnswer struct {
	Present bool            `json:"present"`
	Code    string          `json:"code,omitempty"`
	Error   string          `json:"error,omitempty"`
	Body    json.RawMessage `json:"body,omitempty"`
}

// Codes of a clear that is not a success.
const (
	// DNSClearIncomplete: something a clear removes is still there (Body:
	// the dnsjournal.ClearResult with what is left and why).
	DNSClearIncomplete = "clear_incomplete"
	// DNSClearUnconfirmed: the reader's answer does not say whether
	// everything went (a reader from before it reported that).
	DNSClearUnconfirmed = "clear_unconfirmed"
)

// DNSClearOutcome turns a clear's result (ans.Body, a
// dnsjournal.ClearResult) into the agent's answer: a success only when the
// result says everything went.
func DNSClearOutcome(ans DNSJournalAnswer) DNSJournalAnswer {
	if ans.Code != "" {
		return ans
	}
	var probe struct {
		Complete *bool `json:"complete"`
	}
	var res dnsjournal.ClearResult
	switch {
	case json.Unmarshal(ans.Body, &probe) != nil || probe.Complete == nil || json.Unmarshal(ans.Body, &res) != nil:
		ans.Code, ans.Error = DNSClearUnconfirmed, "解析日志服务的回答没有说明是否全部清除（服务的版本过旧）：不能当作已经清空。升级网关上的程序并重启 "+DNSJournalUnit+" 之后再清空一次"
	case !res.Complete:
		ans.Code, ans.Error = DNSClearIncomplete, "解析日志没有全部清除："+res.Problem()+"。排除原因后可以再清空一次"
	}
	return ans
}

func (a *Agent) dnsJournalSocket() string {
	if a.DNSJournalSocketPath != "" {
		return a.DNSJournalSocketPath
	}
	return dnsjournal.StatusSocket
}

func (a *Agent) smartDNSConfPath() string {
	if a.SmartDNSConf != "" {
		return a.SmartDNSConf
	}
	return a.hostPath("/etc/smartdns/smartdns.conf")
}

// readBounded reads a small file (at most max bytes; "" when absent or
// larger).
func readBounded(path string, max int64) string {
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, max+1))
	if err != nil || int64(len(b)) > max {
		return ""
	}
	return string(b)
}

// installedAudit is what the installed gateway resolver config says about
// the audit log.
func (a *Agent) installedAudit() dnsjournal.AuditConfig {
	return dnsjournal.ReadAuditConfig(readBounded(a.smartDNSConfPath(), 8<<20))
}

// dnsFacts reads the facts the capability gate judges. provider is
// dnsProvider's answer.
func (x *run) dnsFacts(provider string) dnsjournal.Facts {
	f := dnsjournal.Facts{Provider: provider}
	f.Local = dnsjournal.ParseLocalVerified(readBounded(x.a.hostPath(dnsjournal.LocalVerifiedFile), 16<<10))
	if provider != "container" {
		return f
	}
	out, err := x.cmd(x.a.StepTimeout, "docker", "inspect", "--type", "container", "-f", dnsInspectFormat, SmartDNSContainer)
	if err != nil {
		return f
	}
	parts := strings.SplitN(firstLine(out), "|", 3)
	if len(parts) != 3 {
		return f
	}
	f.Running = parts[0] == "true"
	f.ImageID = parts[1]
	for _, m := range strings.Split(parts[2], ";") {
		p := strings.Split(m, ">")
		if len(p) == 3 && p[0] == dnsjournal.RawDir && p[1] == dnsjournal.RawDir {
			f.MountFound, f.MountRW = true, p[2] == "true"
		}
	}
	if f.Running {
		if v, err := x.cmd(15*time.Second, "docker", "exec", SmartDNSContainer, dnsjournal.ResolverBinary, "-v"); err == nil {
			f.Version = dnsjournal.ParseVersion(v)
		}
	}
	return f
}

// DNSJournalStatus reads the feature's state. Read-only.
func (a *Agent) DNSJournalStatus(ctx context.Context) DNSJournalStatus {
	a.init()
	st := DNSJournalStatus{ReadAt: time.Now().UTC().Format(time.RFC3339)}
	x := &run{a: a, ctx: ctx}
	st.Facts = x.dnsFacts(x.dnsProvider())
	st.Capability = dnsjournal.Evaluate(st.Facts)
	ac := a.installedAudit()
	st.AuditInstalled, st.AuditForeign = ac.Managed(), ac.Enabled && !ac.Managed()
	st.Sink = dnsjournal.CheckSink(a.hostPath(dnsjournal.RawDir), a.dnsSinkUID())
	st.DataFiles, st.DataBytes = dnsjournal.DataUsage(a.hostPath(dnsjournal.RawDir), a.hostPath(dnsjournal.JournalDir))
	if out, _ := x.cmd(a.StepTimeout, "systemctl", "is-active", DNSJournalUnit); out != "" {
		st.UnitActive = firstLine(out)
	}
	sock := a.dnsJournalSocket()
	if fi, err := os.Stat(sock); err == nil && fi.Mode()&os.ModeSocket != 0 {
		st.Present = true
		hctx, cancel := context.WithTimeout(ctx, 5*time.Second)
		b, code, err := sniff.StatusCall(hctx, sock, http.MethodGet, "/v1/health")
		cancel()
		switch {
		case err != nil:
			st.Error = "读不到解析日志服务的状态：" + clip(firstLine(err.Error()))
		case code != http.StatusOK || !json.Valid(b):
			st.Error = fmt.Sprintf("解析日志服务的状态回答不可用（%d）", code)
		default:
			st.Health = json.RawMessage(b)
		}
	}
	return st
}

func (a *Agent) dnsJournalCall(ctx context.Context, method, p string) DNSJournalAnswer {
	path := a.dnsJournalSocket()
	if fi, err := os.Stat(path); err != nil || fi.Mode()&os.ModeSocket == 0 {
		return DNSJournalAnswer{Code: "no_socket", Error: "解析日志服务没有运行（没有状态套接字）"}
	}
	ans := DNSJournalAnswer{Present: true}
	cctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	b, code, err := sniff.StatusCall(cctx, path, method, p)
	switch {
	case err != nil:
		ans.Code, ans.Error = "read_failed", "读不到解析日志："+clip(firstLine(err.Error()))
	case code == http.StatusNotFound:
		ans.Code, ans.Error = "no_journal", "解析日志服务没有可用的日志（日志目录无法打开）"
	case code == http.StatusBadRequest:
		ans.Code, ans.Error = "bad_request", "请求被解析日志服务拒绝："+clip(firstLine(strings.TrimSpace(string(b))))
	case code != http.StatusOK:
		ans.Code, ans.Error = "read_failed", fmt.Sprintf("解析日志服务回答状态 %d", code)
	case !json.Valid(b):
		ans.Code, ans.Error = "read_failed", "解析日志服务的回答不是 JSON"
	default:
		ans.Body = json.RawMessage(b)
	}
	return ans
}

// dnsJournalClear clears through the reader when it runs, and deletes the
// data directly when it does not. The answer is a success only when
// everything went (DNSClearOutcome).
func (a *Agent) dnsJournalClear(ctx context.Context) DNSJournalAnswer {
	a.init()
	sock := a.dnsJournalSocket()
	if fi, err := os.Stat(sock); err == nil && fi.Mode()&os.ModeSocket != 0 {
		return DNSClearOutcome(a.dnsJournalCall(ctx, http.MethodPost, "/v1/journal/clear"))
	}
	x := &run{a: a, ctx: ctx}
	if _, err := x.cmd(a.StepTimeout, "systemctl", "is-active", "--quiet", DNSJournalUnit); err == nil {
		return DNSJournalAnswer{Code: "read_failed", Error: "解析日志服务在运行但没有状态套接字：没有清空（稍后重试）"}
	}
	res := dnsjournal.PurgeData(a.hostPath(dnsjournal.RawDir), a.hostPath(dnsjournal.JournalDir), a.installedAudit().Enabled, dnsjournal.Fault(a.DNSPurgeFault))
	b, _ := json.Marshal(res)
	return DNSClearOutcome(DNSJournalAnswer{Body: b})
}

func (a *Agent) serveDNSJournalStatus(w http.ResponseWriter, r *http.Request) {
	if !a.authorize(w, r) {
		return
	}
	var empty struct{}
	if err := decodeJournalRequest(r, &empty); err != nil {
		writeJSON(w, http.StatusBadRequest, DNSJournalStatus{Error: "请求格式不正确（不接受任何参数）"})
		return
	}
	writeJSON(w, http.StatusOK, a.DNSJournalStatus(r.Context()))
}

func (a *Agent) serveDNSJournal(w http.ResponseWriter, r *http.Request) {
	if !a.authorize(w, r) {
		return
	}
	var q dnsjournal.Query
	if err := decodeJournalRequest(r, &q); err != nil {
		writeJSON(w, http.StatusBadRequest, DNSJournalAnswer{Code: "bad_request", Error: "请求格式不正确"})
		return
	}
	if err := q.Validate(); err != nil {
		writeJSON(w, http.StatusBadRequest, DNSJournalAnswer{Code: "bad_request", Error: "查询条件不正确：" + clip(err.Error())})
		return
	}
	a.init()
	writeJSON(w, http.StatusOK, a.dnsJournalCall(r.Context(), http.MethodGet, "/v1/journal?"+q.Values().Encode()))
}

func (a *Agent) serveDNSJournalSummary(w http.ResponseWriter, r *http.Request) {
	if !a.authorize(w, r) {
		return
	}
	var q dnsjournal.SummaryQuery
	if err := decodeJournalRequest(r, &q); err != nil {
		writeJSON(w, http.StatusBadRequest, DNSJournalAnswer{Code: "bad_request", Error: "请求格式不正确"})
		return
	}
	if err := q.Validate(); err != nil {
		writeJSON(w, http.StatusBadRequest, DNSJournalAnswer{Code: "bad_request", Error: "时间范围不正确：" + clip(err.Error())})
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
	writeJSON(w, http.StatusOK, a.dnsJournalCall(r.Context(), http.MethodGet, p))
}

func (a *Agent) serveDNSJournalClear(w http.ResponseWriter, r *http.Request) {
	if !a.authorize(w, r) {
		return
	}
	var empty struct{}
	if err := decodeJournalRequest(r, &empty); err != nil {
		writeJSON(w, http.StatusBadRequest, DNSJournalAnswer{Code: "bad_request", Error: "请求格式不正确（不接受任何参数）"})
		return
	}
	a.init()
	writeJSON(w, http.StatusOK, a.dnsJournalClear(r.Context()))
}

// ErrDNSJournalUnsupported: the agent has no query-journal requests (an
// older binary on the host).
var ErrDNSJournalUnsupported = errors.New("宿主上的 meridian-host 没有解析日志的请求（版本过旧）：在网关上重新运行 deploy/debian/install.sh 升级后再试")

// DNSJournalStatus asks the agent for the feature's state (no parameters).
func (c *Client) DNSJournalStatus(ctx context.Context) (DNSJournalStatus, error) {
	var st DNSJournalStatus
	code, err := c.post(ctx, "/v1/dns/journal/status", struct{}{}, 60*time.Second, &st)
	switch {
	case code == http.StatusNotFound || code == http.StatusMethodNotAllowed:
		return st, ErrDNSJournalUnsupported
	case err != nil:
		return st, err
	case code != http.StatusOK:
		return st, fmt.Errorf("host agent 读取解析日志状态失败（%d）：%s", code, st.Error)
	}
	return st, nil
}

func (c *Client) dnsJournalPost(ctx context.Context, path string, body any) (DNSJournalAnswer, error) {
	var ans DNSJournalAnswer
	code, err := c.post(ctx, path, body, 30*time.Second, &ans)
	switch {
	case code == http.StatusNotFound || code == http.StatusMethodNotAllowed:
		return ans, ErrDNSJournalUnsupported
	case err != nil:
		return ans, err
	case code != http.StatusOK && code != http.StatusBadRequest:
		return ans, fmt.Errorf("host agent 读取解析日志失败（%d）：%s", code, ans.Error)
	}
	if code == http.StatusBadRequest && ans.Code == "" {
		ans.Code = "bad_request"
	}
	return ans, nil
}

// DNSJournal asks the agent for one page of the query journal.
func (c *Client) DNSJournal(ctx context.Context, q dnsjournal.Query) (DNSJournalAnswer, error) {
	return c.dnsJournalPost(ctx, "/v1/dns/journal", q)
}

// DNSJournalSummary asks the agent for the per-device summary.
func (c *Client) DNSJournalSummary(ctx context.Context, q dnsjournal.SummaryQuery) (DNSJournalAnswer, error) {
	return c.dnsJournalPost(ctx, "/v1/dns/journal/summary", q)
}

// DNSJournalClear asks the agent to clear the query journal (no
// parameters).
func (c *Client) DNSJournalClear(ctx context.Context) (DNSJournalAnswer, error) {
	return c.dnsJournalPost(ctx, "/v1/dns/journal/clear", struct{}{})
}

// dnsAuditGuard runs right before activate restarts the resolver. It
// returns whether the installed config enables the audit log; when it does,
// a failing step means the resolver must not be restarted.
func (x *run) dnsAuditGuard(provider string) bool {
	ac := x.a.installedAudit()
	if !ac.Enabled {
		return false
	}
	if !ac.Managed() {
		x.step("dns audit config", false, "解析器配置开启了审计日志，但写入的不是固定文件 "+dnsjournal.AuditFile+"：不重启解析器")
		return true
	}
	c := dnsjournal.Evaluate(x.dnsFacts(provider))
	if !c.Available {
		x.step("dns audit gate", false, c.Reason+"；没有重启解析器")
		return true
	}
	x.step("dns audit gate", true, "SmartDNS "+c.Version+"（"+c.VerifiedBy+"，"+c.VerifiedOn+"）")
	// The reader's unit, restarted earlier in this activate, prepared the
	// sink in ExecStartPre. A file the resolver rotated a moment ago is 0640
	// until the reader's next pass: look up to three times.
	var st dnsjournal.SinkState
	for i := 0; i < 3; i++ {
		if st = dnsjournal.CheckSink(x.a.hostPath(dnsjournal.RawDir), x.a.dnsSinkUID()); st.OK {
			break
		}
		select {
		case <-x.ctx.Done():
		case <-time.After(x.a.dnsSinkRetry()):
		}
	}
	if !st.OK {
		x.step("dns audit sink", false, st.Error+"（"+dnsjournal.RawDir+"；由 "+DNSJournalUnit+" 在启动前准备）：没有重启解析器")
		return true
	}
	x.step("dns audit sink", true, "目录 0700、审计文件是 0600 的普通文件")
	return true
}

func (a *Agent) dnsSinkRetry() time.Duration {
	if a.DNSSinkRetry > 0 {
		return a.DNSSinkRetry
	}
	return 700 * time.Millisecond
}

func (a *Agent) dnsSinkUID() uint32 {
	if a.PreflightRoot != "" {
		return uint32(os.Getuid()) // tests
	}
	return 0
}

func dnsQuery(name string) ([]byte, uint16, error) {
	var idb [2]byte
	if _, err := io.ReadFull(randReader, idb[:]); err != nil {
		return nil, 0, err
	}
	id := binary.BigEndian.Uint16(idb[:])
	b := make([]byte, 12, 64)
	binary.BigEndian.PutUint16(b[0:], id)
	b[2] = 0x01
	binary.BigEndian.PutUint16(b[4:], 1)
	for _, l := range strings.Split(name, ".") {
		b = append(b, byte(len(l)))
		b = append(b, l...)
	}
	b = append(b, 0, 0, 1, 0, 1) // A IN
	return b, id, nil
}

// dnsLiveness asks the restarted resolver one fixed question on loopback
// and accepts any well-formed reply to it. It fails the action when none
// comes within dnsLivenessWait: the resolver is running but not serving.
func (x *run) dnsLiveness() {
	if x.fails {
		return
	}
	ex := x.a.DNSCheckExchange
	if ex == nil {
		ex = sniff.ExchangeNet
	}
	wait := dnsLivenessWait
	if x.a.DNSLivenessWait > 0 {
		wait = x.a.DNSLivenessWait
	}
	deadline := time.Now().Add(wait)
	last := "没有回答"
	for {
		q, id, err := dnsQuery(DNSLivenessName)
		if err == nil {
			cctx, cancel := context.WithTimeout(x.ctx, min(3*time.Second, wait))
			var resp []byte
			resp, err = ex(cctx, "127.0.0.1:53", 0, q)
			cancel()
			if err == nil && len(resp) >= 12 && binary.BigEndian.Uint16(resp) == id && resp[2]&0x80 != 0 {
				x.step("resolver answers after restart", true, "")
				return
			}
		}
		if err != nil {
			last = clipShort(firstLine(err.Error()))
		}
		if !time.Now().Before(deadline) || x.ctx.Err() != nil {
			break
		}
		select {
		case <-x.ctx.Done():
		case <-time.After(300 * time.Millisecond):
		}
	}
	x.step("resolver answers after restart", false, "开启审计日志后重启的解析器在 "+wait.Round(time.Second).String()+" 内没有应答本机的查询（"+last+"）：解析器在运行但没有服务，这次安装不保留")
}
