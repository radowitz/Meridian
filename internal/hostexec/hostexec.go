// Package hostexec is the only path from the panel to host runtime actions
// (systemd units, WireGuard interfaces, Meridian nft tables, policy route
// tables) and to the read-only unlock probe. The panel never runs a command
// on the host itself.
//
// The boundary is deliberately small:
//
//   - A fixed action set: activate, health, rollback, plus the read-only
//     probe (probe.go: one managed exit, one forced address family, services
//     from a fixed catalog) and the list update (lists.go: a source policy,
//     list kinds and managed category names; URLs come from package lists)
//     and the parameterless remote-access status read (wgstatus.go) and the
//     read-only install pre-check (preflight.go: paths validated by
//     preflight.ValidatePaths, fixed programs). There is no generic "run", no shell, and no
//     caller-supplied path, URL, host or argument string.
//   - Parameters only name managed resources, and every name must match the
//     pattern compile can produce (ValidUnit, ValidInterface, ...). Paths and
//     argv are derived here from those names.
//   - rollback (removal) is further restricted to names this agent has been
//     asked to activate before (the host-side ledger), so it cannot remove a
//     pattern-matching resource Meridian never managed.
//   - Callers authenticate with a bearer token over a root-only Unix socket;
//     on Linux the peer must also be uid 0 (SO_PEERCRED).
//   - One action at a time (serialised), each step and each action bounded by
//     a timeout, results cached per request_id so a retried request after a
//     lost response replays the earlier outcome instead of running twice.
//
// Agent runs on the host (meridian host-agent, deploy/debian/meridian-host.service).
// Client is what the panel uses, in a container or on the bare host.
package hostexec

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/radowitz/meridian/internal/lists"
)

// Actions. The unlock probe has its own endpoint and parameter set
// (ProbeRequest, probe.go); nothing else is accepted.
const (
	ActionActivate = "activate"
	ActionHealth   = "health"
	ActionRollback = "rollback"
	// ActionWithdraw takes the gateway data plane down to the LAN guard
	// (see withdraw below and restore.go GuardTable).
	ActionWithdraw = "withdraw"
)

var actions = map[string]bool{ActionActivate: true, ActionHealth: true, ActionRollback: true, ActionWithdraw: true}

// Defaults for the deployment (see deploy/debian/meridian-host.service and
// deploy/docker-compose.yml).
const (
	DefaultSocket    = "/run/meridian-host/agent.sock"
	DefaultTokenFile = "/etc/meridian-host/agent.token"
	DefaultLedger    = "/var/lib/meridian-host/ledger.json"
	// SmartDNSContainer is the fixed container name of the Compose dns profile.
	SmartDNSContainer = "meridian-smartdns"
	coreUnit          = "meridian.service"
	guardUnit         = "meridian-guard.service"
)

// Resources names the managed runtime resources an action applies to.
type Resources struct {
	Units       []string `json:"units,omitempty"`
	Interfaces  []string `json:"interfaces,omitempty"`
	NFTTables   []string `json:"nft_tables,omitempty"`
	RouteTables []int    `json:"route_tables,omitempty"`
	// DNS asks activate/health to restart/check the gateway resolver: the
	// host smartdns.service if installed, else the meridian-smartdns container.
	DNS bool `json:"dns,omitempty"`
}

// Empty reports whether no resource is named.
func (r Resources) Empty() bool {
	return len(r.Units) == 0 && len(r.Interfaces) == 0 && len(r.NFTTables) == 0 && len(r.RouteTables) == 0 && !r.DNS
}

type Request struct {
	Action    string    `json:"action"`
	RequestID string    `json:"request_id"`
	Resources Resources `json:"resources"`
}

type Step struct {
	Name    string `json:"name"`
	OK      bool   `json:"ok"`
	Skipped bool   `json:"skipped,omitempty"`
	Detail  string `json:"detail,omitempty"`
}

type Result struct {
	RequestID string   `json:"request_id"`
	Action    string   `json:"action"`
	OK        bool     `json:"ok"`
	Steps     []Step   `json:"steps"`
	Warnings  []string `json:"warnings,omitempty"`
	Error     string   `json:"error,omitempty"`
	// Replayed is set when the result came from the request_id cache.
	Replayed bool `json:"replayed,omitempty"`
}

// ErrUnavailable means the panel has no host execution capability: the agent
// socket or its token is missing, or nothing listens on the socket.
var ErrUnavailable = errors.New("面板没有宿主执行能力（meridian-host 未运行或未挂载），宿主上的服务不会被启动")

var (
	unitRe      = regexp.MustCompile(`^(meridian-[a-z0-9][a-z0-9-]{0,40}|wstunnel-meridian|wstunnel-client-[a-z0-9][a-z0-9-]{0,40})\.(service|timer)$`)
	ifaceRe     = regexp.MustCompile(`^(m[0-9]{2,3}w?|mmesh|mra)$`)
	requestIDRe = regexp.MustCompile(`^[A-Za-z0-9._:/-]{1,160}$`)
	// Units started by fixed steps, never by name from a caller.
	reservedUnits = map[string]bool{
		coreUnit:                 true,
		"meridian-host.service":  true,
		"meridian-guard.service": true,
	}
	nftTables = map[string]bool{"inet meridian": true, "inet meridian_guard": true}
)

// ValidUnit reports whether name is a unit Meridian generates.
func ValidUnit(name string) bool { return unitRe.MatchString(name) && !reservedUnits[name] }

// ValidInterface reports whether name is a Meridian WireGuard or Mesh
// interface: a tunnel (mNN, mNNw), the Mesh veth or the remote-access
// interface mra (one fixed name, nothing else).
func ValidInterface(name string) bool { return ifaceRe.MatchString(name) }

// ValidNFTTable reports whether name is one of Meridian's own nft tables.
func ValidNFTTable(name string) bool { return nftTables[name] }

// ValidRouteTable reports whether n is a policy table Meridian may own
// (never main/local/default or the unspec 0).
func ValidRouteTable(n int) bool { return n >= 100 && n <= 252 }

const maxItems = 64

// Validate checks a request completely before any step runs.
func Validate(req Request) error {
	if !actions[req.Action] {
		return fmt.Errorf("不支持的宿主动作 %q", req.Action)
	}
	if !requestIDRe.MatchString(req.RequestID) {
		return errors.New("request_id 不合法")
	}
	r := req.Resources
	if len(r.Units) > maxItems || len(r.Interfaces) > maxItems || len(r.RouteTables) > maxItems || len(r.NFTTables) > len(nftTables) {
		return errors.New("资源数量超出上限")
	}
	if err := uniq("unit", r.Units, ValidUnit); err != nil {
		return err
	}
	if err := uniq("interface", r.Interfaces, ValidInterface); err != nil {
		return err
	}
	if err := uniq("nft table", r.NFTTables, ValidNFTTable); err != nil {
		return err
	}
	seen := map[int]bool{}
	for _, n := range r.RouteTables {
		if !ValidRouteTable(n) || seen[n] {
			return fmt.Errorf("route table %d 不是受管表或重复", n)
		}
		seen[n] = true
	}
	if (req.Action == ActionRollback || req.Action == ActionWithdraw) && r.DNS {
		return errors.New("rollback / withdraw 不管理解析器的生命周期")
	}
	if req.Action == ActionWithdraw && contains(r.NFTTables, GuardTable) {
		return errors.New("withdraw 保留局域网兜底表 " + GuardTable + "；移除兜底表只能经 rollback（先关转发）")
	}
	return nil
}

func uniq(kind string, names []string, ok func(string) bool) error {
	seen := map[string]bool{}
	for _, n := range names {
		if !ok(n) {
			return fmt.Errorf("%s %q 不是 Meridian 受管资源名", kind, n)
		}
		if seen[n] {
			return fmt.Errorf("%s %q 重复", kind, n)
		}
		seen[n] = true
	}
	return nil
}

func fingerprint(req Request) string {
	r := req.Resources
	norm := Resources{
		Units: sortedCopy(r.Units), Interfaces: sortedCopy(r.Interfaces), NFTTables: sortedCopy(r.NFTTables),
		RouteTables: append([]int(nil), r.RouteTables...), DNS: r.DNS,
	}
	sort.Ints(norm.RouteTables)
	b, _ := json.Marshal(struct {
		A string
		R Resources
	}{req.Action, norm})
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func sortedCopy(s []string) []string {
	out := append([]string(nil), s...)
	sort.Strings(out)
	return out
}

// Runner runs one program from the fixed table (systemctl, ip, nft, sysctl,
// journalctl, docker) with arguments built by the agent. Tests use a fake.
type Runner interface {
	Run(ctx context.Context, prog string, args ...string) (string, error)
}

// programs maps the logical names to absolute candidates. PATH is never used.
var programs = map[string][]string{
	"systemctl":  {"/usr/bin/systemctl", "/bin/systemctl"},
	"journalctl": {"/usr/bin/journalctl", "/bin/journalctl"},
	"ip":         {"/usr/sbin/ip", "/usr/bin/ip", "/sbin/ip", "/bin/ip"},
	"nft":        {"/usr/sbin/nft", "/sbin/nft"},
	"sysctl":     {"/usr/sbin/sysctl", "/sbin/sysctl"},
	"docker":     {"/usr/bin/docker"},
	// wg is used only by the remote-access status read, with two fixed
	// subcommands that print public keys and counters (never "dump").
	"wg": {"/usr/bin/wg", "/usr/sbin/wg", "/bin/wg"},
	// The install pre-check (preflight.go) reads listeners and firewall
	// policies with fixed, read-only argument lists.
	"ss":        {"/usr/bin/ss", "/usr/sbin/ss", "/bin/ss", "/sbin/ss"},
	"iptables":  {"/usr/sbin/iptables", "/sbin/iptables"},
	"ip6tables": {"/usr/sbin/ip6tables", "/sbin/ip6tables"},
}

// ExecRunner runs real binaries with a fixed minimal environment.
type ExecRunner struct{}

func (ExecRunner) Run(ctx context.Context, prog string, args ...string) (string, error) {
	cands, ok := programs[prog]
	if !ok {
		return "", fmt.Errorf("程序 %q 不在白名单", prog)
	}
	path := ""
	for _, c := range cands {
		if st, err := os.Stat(c); err == nil && !st.IsDir() {
			path = c
			break
		}
	}
	if path == "" {
		return "", fmt.Errorf("宿主上没有 %s", prog)
	}
	cmd := exec.CommandContext(ctx, path, args...)
	cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C", "SYSTEMD_PAGER=", "SYSTEMD_COLORS=0"}
	cmd.Dir = "/"
	cmd.WaitDelay = 2 * time.Second
	var buf bytes.Buffer
	cmd.Stdout = &limitedWriter{w: &buf, n: 16 << 10}
	cmd.Stderr = cmd.Stdout
	err := cmd.Run()
	if ctx.Err() != nil {
		return buf.String(), fmt.Errorf("超时：%s %s", prog, strings.Join(args, " "))
	}
	return buf.String(), err
}

type limitedWriter struct {
	w io.Writer
	n int
}

func (l *limitedWriter) Write(p []byte) (int, error) {
	if l.n <= 0 {
		return len(p), nil
	}
	q := p
	if len(q) > l.n {
		q = q[:l.n]
	}
	l.n -= len(q)
	_, _ = l.w.Write(q)
	return len(p), nil
}

// Agent executes validated requests on the host.
type Agent struct {
	// Token returns the expected bearer token. Required.
	Token func() (string, error)
	// Runner runs host programs. Nil means ExecRunner.
	Runner Runner
	// LedgerPath persists the names of resources ever activated. Empty keeps
	// the ledger in memory (tests).
	LedgerPath string
	// PeerUID, when non-nil, is the uid a Unix-socket peer must have (Linux).
	PeerUID *int

	StepTimeout   time.Duration // one program run; default 60s
	UpTimeout     time.Duration // restart meridian.service (runs meridian-up.sh); default 180s
	ActionTimeout time.Duration // whole action; default 5m
	LockWait      time.Duration // waiting for the previous action; default 6m
	// Settle is the gap between the two health samples; both must pass so a
	// crash-looping unit that is briefly "active" is not reported healthy.
	Settle time.Duration

	// MaxProbes caps concurrent probes (each one exit + family); default 2.
	MaxProbes int
	// ProbeTimeout bounds one probe request; default 3m (14 services, four
	// at a time, 20 s each, plus the two egress checks).
	ProbeTimeout time.Duration
	// ProbeTargetTimeout bounds one service inside a probe; default 20s.
	ProbeTargetTimeout time.Duration
	// ProbeRootCAs nil means the system roots (tests inject their own CA).
	ProbeRootCAs *x509.CertPool
	// ProbeNetwork replaces the pinned network (tests only).
	ProbeNetwork ProbeNetworkFunc

	// List updates (lists.go). ListsDir holds geosite/, keywords/ and
	// lists/; default /var/lib/meridian. ListsGetter and ListsSources
	// replace the downloader and the source table (tests only).
	ListsDir     string
	ListsGetter  lists.Getter
	ListsSources func(lists.Policy) ([]lists.Source, error)
	// ListsTimeout bounds one whole update; default 15m.
	ListsTimeout time.Duration
	// SmartDNSConf is the gateway resolver config a list update reads to
	// decide whether new China lists need a SmartDNS restart; default
	// /etc/smartdns/smartdns.conf (tests only).
	SmartDNSConf string
	listsBusy    chan struct{}

	// PreflightRoot replaces "/" for the files the install pre-check and
	// the upstream status read (tests only).
	PreflightRoot string

	once   sync.Once
	sem    chan struct{}
	cache  map[string]cached
	order  []string
	ledger *ledger

	// Probe/action interlock (probe.go).
	pmu          sync.Mutex
	actionActive bool
	probes       map[int]context.CancelFunc
	probeSeq     int
	probeWG      sync.WaitGroup
}

type cached struct {
	fp  string
	res Result
}

func (a *Agent) init() {
	a.once.Do(func() {
		a.sem = make(chan struct{}, 1)
		a.cache = map[string]cached{}
		if a.Runner == nil {
			a.Runner = ExecRunner{}
		}
		if a.StepTimeout == 0 {
			a.StepTimeout = 60 * time.Second
		}
		if a.UpTimeout == 0 {
			a.UpTimeout = 180 * time.Second
		}
		if a.ActionTimeout == 0 {
			a.ActionTimeout = 5 * time.Minute
		}
		if a.LockWait == 0 {
			a.LockWait = 6 * time.Minute
		}
		if a.MaxProbes <= 0 {
			a.MaxProbes = 2
		}
		if a.ProbeTimeout <= 0 {
			a.ProbeTimeout = 3 * time.Minute
		}
		a.probes = map[int]context.CancelFunc{}
		a.listsBusy = make(chan struct{}, 1)
		if a.ListsTimeout <= 0 {
			a.ListsTimeout = 15 * time.Minute
		}
		a.ledger = &ledger{path: a.LedgerPath}
	})
}

// Handler serves POST /v1/action, /v1/probe, /v1/lists, /v1/lists/status,
// /v1/remote-access/status, /v1/upstream/status and /v1/preflight.
func (a *Agent) Handler() http.Handler {
	a.init()
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/action", a.serveAction)
	mux.HandleFunc("POST /v1/probe", a.serveProbe)
	mux.HandleFunc("POST /v1/lists", a.serveLists)
	mux.HandleFunc("POST /v1/lists/status", a.serveListsStatus)
	mux.HandleFunc("POST /v1/remote-access/status", a.serveRemoteAccessStatus)
	mux.HandleFunc("POST /v1/upstream/status", a.serveUpstreamStatus)
	mux.HandleFunc("POST /v1/preflight", a.servePreflight)
	return mux
}

type ctxKey struct{}

// Serve accepts on l until it is closed. Each connection's peer credentials
// are checked against PeerUID (Linux only).
func (a *Agent) Serve(l net.Listener) error {
	srv := &http.Server{
		Handler:           a.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		ConnContext: func(ctx context.Context, c net.Conn) context.Context {
			return context.WithValue(ctx, ctxKey{}, c)
		},
	}
	return srv.Serve(l)
}

// authorize checks the peer uid (Linux) and the bearer token.
func (a *Agent) authorize(w http.ResponseWriter, r *http.Request) bool {
	if a.PeerUID != nil {
		c, _ := r.Context().Value(ctxKey{}).(net.Conn)
		uid, err := peerUID(c)
		if err != nil || uid != *a.PeerUID {
			writeJSON(w, http.StatusForbidden, Result{Error: "peer uid 不允许"})
			return false
		}
	}
	want, err := a.Token()
	if err != nil || want == "" {
		writeJSON(w, http.StatusServiceUnavailable, Result{Error: "agent 口令不可用"})
		return false
	}
	got := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	if len(got) != len(want) || subtle.ConstantTimeCompare([]byte(got), []byte(want)) != 1 {
		writeJSON(w, http.StatusUnauthorized, Result{Error: "需要 host agent 口令"})
		return false
	}
	return true
}

func (a *Agent) serveAction(w http.ResponseWriter, r *http.Request) {
	if !a.authorize(w, r) {
		return
	}
	var req Request
	dec := json.NewDecoder(io.LimitReader(r.Body, 64<<10))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, Result{Error: "请求格式不正确"})
		return
	}
	res, code := a.Execute(r.Context(), req)
	writeJSON(w, code, res)
}

// Execute validates, serialises and runs one request. The HTTP status is
// 200 for an executed action (check Result.OK), 4xx for a refused request.
func (a *Agent) Execute(ctx context.Context, req Request) (Result, int) {
	a.init()
	base := Result{RequestID: req.RequestID, Action: req.Action}
	if err := Validate(req); err != nil {
		base.Error = err.Error()
		return base, http.StatusBadRequest
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

	fp := fingerprint(req)
	if c, ok := a.cache[req.RequestID]; ok {
		if c.fp != fp {
			base.Error = "request_id 已用于另一组参数"
			return base, http.StatusConflict
		}
		res := c.res
		res.Replayed = true
		return res, http.StatusOK
	}
	// No probe traffic while an action changes rules, routes or the
	// firewall: running probes are cancelled and new ones refused. health
	// only reads, so it neither waits for nor disturbs probes.
	if req.Action != ActionHealth {
		a.beginAction()
		defer a.endAction()
	}
	// The action runs to its own deadline even if the caller disconnects,
	// so a retry finds a finished result instead of a half-done host.
	actx, acancel := context.WithTimeout(context.Background(), a.ActionTimeout)
	defer acancel()
	var res Result
	switch req.Action {
	case ActionActivate:
		res = a.activate(actx, req.Resources)
	case ActionHealth:
		res = a.health(actx, req.Resources)
	case ActionRollback, ActionWithdraw:
		r, skipped, err := a.owned(actx, req.Resources)
		if err != nil {
			base.Error = err.Error()
			return base, http.StatusForbidden
		}
		if req.Action == ActionWithdraw {
			res = a.withdraw(actx, r)
		} else {
			res = a.rollback(actx, r)
		}
		res.Steps = append(skipped, res.Steps...)
	}
	res.RequestID, res.Action = req.RequestID, req.Action
	a.remember(req.RequestID, fp, res)
	return res, http.StatusOK
}

func (a *Agent) remember(id, fp string, res Result) {
	if _, ok := a.cache[id]; !ok {
		a.order = append(a.order, id)
	}
	a.cache[id] = cached{fp: fp, res: res}
	for len(a.order) > 128 {
		delete(a.cache, a.order[0])
		a.order = a.order[1:]
	}
}

type run struct {
	a     *Agent
	ctx   context.Context
	res   Result
	fails bool
}

func (x *run) cmd(timeout time.Duration, prog string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(x.ctx, timeout)
	defer cancel()
	out, err := x.a.Runner.Run(ctx, prog, args...)
	if ctx.Err() != nil {
		err = fmt.Errorf("超时（%s）：%s %s", timeout, prog, strings.Join(args, " "))
	}
	return out, err
}

func (x *run) step(name string, ok bool, detail string) bool {
	x.res.Steps = append(x.res.Steps, Step{Name: name, OK: ok, Detail: clip(detail)})
	if !ok {
		x.fails = true
		if x.res.Error == "" {
			x.res.Error = name + " 失败"
			if detail != "" {
				x.res.Error += "：" + clip(firstLine(detail))
			}
		}
	}
	return ok
}

func (x *run) skip(name, detail string) {
	x.res.Steps = append(x.res.Steps, Step{Name: name, OK: true, Skipped: true, Detail: clip(detail)})
}

// do runs one program as a named step; a failure records the output and
// stops the action.
func (x *run) do(name string, timeout time.Duration, prog string, args ...string) bool {
	if x.fails {
		return false
	}
	out, err := x.cmd(timeout, prog, args...)
	if err != nil {
		return x.step(name, false, strings.TrimSpace(err.Error()+"\n"+out))
	}
	return x.step(name, true, "")
}

func (x *run) journal(unit string) string {
	out, _ := x.cmd(x.a.StepTimeout, "journalctl", "-u", unit, "-n", "60", "--no-pager", "-o", "cat")
	return out
}

func (x *run) finish() Result {
	x.res.OK = !x.fails
	return x.res
}

func (a *Agent) activate(ctx context.Context, r Resources) Result {
	x := &run{a: a, ctx: ctx}
	// Record ownership before anything can create the resources.
	if err := a.ledger.add(r); err != nil {
		x.step("ledger", false, err.Error())
		return x.finish()
	}
	if _, err := x.cmd(a.StepTimeout, "systemctl", "cat", coreUnit); err != nil {
		x.step("check "+coreUnit, false, coreUnit+" 未安装：先在宿主上运行 deploy/debian/install.sh")
		return x.finish()
	}
	x.do("daemon-reload", a.StepTimeout, "systemctl", "daemon-reload")
	x.do("enable "+coreUnit, a.StepTimeout, "systemctl", "enable", coreUnit)
	if !x.fails {
		// Boot-time retries (RestartForceExitStatus in meridian.service) may
		// have used up the start limit; an explicit activation starts afresh.
		_, _ = x.cmd(a.StepTimeout, "systemctl", "reset-failed", coreUnit)
		// meridian.service runs meridian-up.sh: the same path as at boot.
		if out, err := x.cmd(a.UpTimeout, "systemctl", "restart", coreUnit); err != nil {
			x.step("restart "+coreUnit+"（meridian-up.sh）", false, err.Error()+"\n"+out+"\n"+x.journal(coreUnit))
			// Cancel a pending automatic retry (or a start job still running
			// after our timeout), so meridian-up.sh cannot run concurrently
			// with the compensation that follows. The unit has no ExecStop:
			// stopping it undoes nothing on the host.
			if _, err := x.cmd(a.StepTimeout, "systemctl", "stop", coreUnit); err != nil {
				x.res.Warnings = append(x.res.Warnings, "未能取消 "+coreUnit+" 的自动重试："+err.Error())
			}
		} else {
			x.step("restart "+coreUnit+"（meridian-up.sh）", true, "")
		}
	}
	for _, u := range r.Units {
		x.do("enable "+u, a.StepTimeout, "systemctl", "enable", u)
		if x.fails {
			break
		}
		if out, err := x.cmd(a.StepTimeout, "systemctl", "restart", u); err != nil {
			x.step("restart "+u, false, err.Error()+"\n"+out+"\n"+x.journal(u))
			break
		}
		x.step("restart "+u, true, "")
	}
	dns := ""
	if r.DNS && !x.fails {
		dns = x.dnsProvider()
		switch dns {
		case "unit":
			x.do("restart smartdns.service", a.StepTimeout, "systemctl", "restart", "smartdns.service")
		case "container":
			x.do("restart "+SmartDNSContainer, a.StepTimeout, "docker", "restart", SmartDNSContainer)
		default:
			msg := "SmartDNS 既没有宿主 smartdns.service 也没有 " + SmartDNSContainer + " 容器：DNS 分流未生效，" +
				"请用 docker compose --profile dns up -d 启动后再执行一次安装"
			x.skip("restart smartdns", msg)
			x.res.Warnings = append(x.res.Warnings, msg)
		}
	}
	if x.fails {
		return x.finish()
	}
	x.checks(r, dns)
	return x.finish()
}

func (x *run) dnsProvider() string {
	if _, err := x.cmd(x.a.StepTimeout, "systemctl", "cat", "smartdns.service"); err == nil {
		return "unit"
	}
	if _, err := x.cmd(x.a.StepTimeout, "docker", "inspect", "--type", "container", "-f", "{{.State.Status}}", SmartDNSContainer); err == nil {
		return "container"
	}
	return ""
}

func (a *Agent) health(ctx context.Context, r Resources) Result {
	x := &run{a: a, ctx: ctx}
	if r.Empty() {
		// Capability probe: the agent is reachable and authenticated.
		x.step("agent", true, "reachable")
		return x.finish()
	}
	dns := ""
	if r.DNS {
		dns = x.dnsProvider()
		if dns == "" {
			x.res.Warnings = append(x.res.Warnings, "SmartDNS 未运行（没有宿主单元也没有 "+SmartDNSContainer+" 容器）")
		}
	}
	x.checks(r, dns)
	return x.finish()
}

// checks samples every resource twice, Settle apart; both samples must pass.
func (x *run) checks(r Resources, dns string) {
	for sample := 0; sample < 2 && !x.fails; sample++ {
		if sample == 1 && x.a.Settle > 0 {
			select {
			case <-time.After(x.a.Settle):
			case <-x.ctx.Done():
				x.step("health", false, "超时")
				return
			}
		}
		x.sample(r, dns, sample == 1)
	}
}

func (x *run) sample(r Resources, dns string, record bool) {
	check := func(name string, ok bool, detail string) {
		if !ok || record {
			x.step(name, ok, detail)
		}
	}
	active := func(unit string) {
		out, err := x.cmd(x.a.StepTimeout, "systemctl", "is-active", unit)
		state := strings.TrimSpace(out)
		ok := err == nil && state == "active"
		detail := state
		if !ok {
			detail = state + "\n" + x.journal(unit)
		}
		check("health "+unit, ok, detail)
	}
	active(coreUnit)
	for _, u := range r.Units {
		active(u)
	}
	for _, i := range r.Interfaces {
		_, err := x.cmd(x.a.StepTimeout, "ip", "link", "show", "dev", i)
		check("health link "+i, err == nil, errText(err))
	}
	for _, t := range r.NFTTables {
		fam, name, _ := strings.Cut(t, " ")
		_, err := x.cmd(x.a.StepTimeout, "nft", "list", "table", fam, name)
		check("health nft "+t, err == nil, errText(err))
	}
	switch dns {
	case "unit":
		active("smartdns.service")
	case "container":
		out, err := x.cmd(x.a.StepTimeout, "docker", "inspect", "--type", "container", "-f", "{{.State.Status}}", SmartDNSContainer)
		check("health "+SmartDNSContainer, err == nil && strings.TrimSpace(out) == "running", strings.TrimSpace(out))
	}
}

// rollback removes the named runtime resources. Each removal is idempotent:
// an absent resource is a skipped step, not a failure. Any real failure is
// reported and stops the action; the caller must not report success.
func (a *Agent) rollback(ctx context.Context, r Resources) Result {
	x := &run{a: a, ctx: ctx}
	for _, t := range r.NFTTables {
		if t == "inet meridian_guard" {
			// The LAN guard is about to go: turn forwarding off first so the
			// host cannot forward LAN traffic unguarded (fail closed).
			x.do("forwarding off (ipv4)", a.StepTimeout, "sysctl", "-w", "net.ipv4.ip_forward=0")
			x.do("forwarding off (ipv6)", a.StepTimeout, "sysctl", "-w", "net.ipv6.conf.all.forwarding=0")
		}
	}
	for _, u := range r.Units {
		if x.fails {
			break
		}
		if _, err := x.cmd(a.StepTimeout, "systemctl", "cat", u); err != nil {
			x.skip("disable "+u, "不存在")
			continue
		}
		x.do("disable --now "+u, a.StepTimeout, "systemctl", "disable", "--now", u)
	}
	for _, i := range r.Interfaces {
		if x.fails {
			break
		}
		if _, err := x.cmd(a.StepTimeout, "ip", "link", "show", "dev", i); err != nil {
			x.skip("delete link "+i, "不存在")
			continue
		}
		x.do("delete link "+i, a.StepTimeout, "ip", "link", "del", "dev", i)
	}
	for _, n := range r.RouteTables {
		if x.fails {
			break
		}
		tbl := fmt.Sprint(n)
		for _, fam := range []string{"-4", "-6"} {
			// Rules first, so nothing looks the table up while it empties.
			// "rule del" fails once no rule is left; that ends the loop.
			for i := 0; i < maxItems; i++ {
				if _, err := x.cmd(a.StepTimeout, "ip", fam, "rule", "del", "lookup", tbl); err != nil {
					break
				}
			}
			out, err := x.cmd(a.StepTimeout, "ip", fam, "route", "flush", "table", tbl)
			if err != nil && !strings.Contains(out, "does not exist") {
				x.step("flush table "+tbl+" "+fam, false, err.Error()+"\n"+out)
				break
			}
			x.step("flush table "+tbl+" "+fam, true, "")
		}
	}
	for _, t := range r.NFTTables {
		if x.fails {
			break
		}
		fam, name, _ := strings.Cut(t, " ")
		if _, err := x.cmd(a.StepTimeout, "nft", "list", "table", fam, name); err != nil {
			x.skip("delete nft "+t, "不存在")
			continue
		}
		x.do("delete nft "+t, a.StepTimeout, "nft", "delete", "table", fam, name)
	}
	return x.finish()
}

// withdraw takes the gateway data plane down to the LAN guard (the panel's
// "撤回" of the gateway). Fixed steps, in this order:
//
//  1. forwarding off, IPv4 and IPv6, before anything is removed: with the
//     classification gone nothing may forward LAN traffic;
//  2. meridian.service is stopped (it has no ExecStop: this cancels a
//     pending boot retry so meridian-up.sh cannot run concurrently and
//     clears its "active" state; the unit stays enabled and is skipped at
//     boot once meridian-up.sh is gone);
//  3. the named resources are removed exactly like rollback (ledger-checked
//     by the caller, absent ones skipped);
//  4. inet meridian_guard must still be loaded. When it is not, the fixed
//     meridian-guard.service is restarted (it loads only that table from
//     /etc/nftables.d/meridian-guard.nft) and checked again. A guard that
//     cannot be loaded fails the action, so the panel never reports a
//     withdrawn gateway without its fail-closed guard.
//
// It never names the guard for removal (Validate refuses that) and never
// turns forwarding on.
func (a *Agent) withdraw(ctx context.Context, r Resources) Result {
	x := &run{a: a, ctx: ctx}
	x.do("forwarding off (ipv4)", a.StepTimeout, "sysctl", "-w", "net.ipv4.ip_forward=0")
	x.do("forwarding off (ipv6)", a.StepTimeout, "sysctl", "-w", "net.ipv6.conf.all.forwarding=0")
	if !x.fails {
		if out, err := x.cmd(a.StepTimeout, "systemctl", "stop", coreUnit); err != nil {
			x.step("stop "+coreUnit, false, err.Error()+"\n"+out)
		} else {
			x.step("stop "+coreUnit, true, "")
		}
	}
	if !x.fails && !r.Empty() {
		rb := a.rollback(ctx, r)
		x.res.Steps = append(x.res.Steps, rb.Steps...)
		x.res.Warnings = append(x.res.Warnings, rb.Warnings...)
		if !rb.OK {
			x.fails = true
			x.res.Error = rb.Error
		}
	}
	if x.fails {
		return x.finish()
	}
	fam, name, _ := strings.Cut(GuardTable, " ")
	if _, err := x.cmd(a.StepTimeout, "nft", "list", "table", fam, name); err == nil {
		x.step("guard "+GuardTable+" loaded", true, "")
		return x.finish()
	}
	if out, err := x.cmd(a.StepTimeout, "systemctl", "restart", guardUnit); err != nil {
		x.step("restart "+guardUnit, false, err.Error()+"\n"+out+"\n"+x.journal(guardUnit))
		return x.finish()
	}
	_, err := x.cmd(a.StepTimeout, "nft", "list", "table", fam, name)
	x.step("guard "+GuardTable+" loaded", err == nil, errText(err))
	return x.finish()
}

func errText(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

func firstLine(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return s
}

func clip(s string) string {
	s = strings.TrimSpace(s)
	if len(s) > 4000 {
		return "…" + s[len(s)-4000:]
	}
	return s
}

// ledger is the host-side record of resources Meridian activated.
type ledger struct {
	path   string
	loaded bool
	data   ledgerData
}

type ledgerData struct {
	Units       []string `json:"units"`
	Interfaces  []string `json:"interfaces"`
	NFTTables   []string `json:"nft_tables"`
	RouteTables []int    `json:"route_tables"`
}

func (l *ledger) load() error {
	if l.loaded {
		return nil
	}
	if l.path != "" {
		b, err := os.ReadFile(l.path)
		if err != nil && !os.IsNotExist(err) {
			return err
		}
		if err == nil {
			if err := json.Unmarshal(b, &l.data); err != nil {
				return fmt.Errorf("ledger 损坏: %w", err)
			}
		}
	}
	l.loaded = true
	return nil
}

func (l *ledger) add(r Resources) error {
	if err := l.load(); err != nil {
		return err
	}
	d := l.data
	d.Units = union(d.Units, r.Units)
	d.Interfaces = union(d.Interfaces, r.Interfaces)
	d.NFTTables = union(d.NFTTables, r.NFTTables)
	seen := map[int]bool{}
	for _, n := range d.RouteTables {
		seen[n] = true
	}
	for _, n := range r.RouteTables {
		if !seen[n] {
			d.RouteTables = append(d.RouteTables, n)
			seen[n] = true
		}
	}
	sort.Ints(d.RouteTables)
	if l.path != "" {
		b, _ := json.MarshalIndent(d, "", "  ")
		if err := writeFileAtomic(l.path, b, 0o600); err != nil {
			return err
		}
	}
	l.data = d
	return nil
}

// owned splits a removal request by the ledger, before anything changes.
// A name Meridian activated before is kept. A name it never activated is
// dropped as a skipped step when the resource does not exist (a compensation
// may name resources a failed activation never created), and refuses the
// whole request when it does exist: that resource is not Meridian's.
func (a *Agent) owned(ctx context.Context, r Resources) (Resources, []Step, error) {
	if err := a.ledger.load(); err != nil {
		return Resources{}, nil, err
	}
	d := a.ledger.data
	x := &run{a: a, ctx: ctx}
	exists := func(args ...string) bool {
		_, err := x.cmd(a.StepTimeout, args[0], args[1:]...)
		return err == nil
	}
	var out Resources
	var skipped []Step
	refuse := func(kind, name string) error {
		return fmt.Errorf("拒绝：%s %s 存在但从未由 Meridian 激活，不是受管资源；未做任何改动", kind, name)
	}
	for _, u := range r.Units {
		switch {
		case contains(d.Units, u):
			out.Units = append(out.Units, u)
		// Judged by runtime state, not by the unit file: the panel may have
		// written a file whose activation never happened. Such a unit is
		// neither running nor enabled, so there is nothing to undo here
		// (the panel deletes its own file). A running or enabled one that
		// Meridian never activated is someone else's.
		case exists("systemctl", "is-active", "--quiet", u) || exists("systemctl", "is-enabled", "--quiet", u):
			return Resources{}, nil, refuse("unit", u)
		default:
			skipped = append(skipped, Step{Name: "disable " + u, OK: true, Skipped: true, Detail: "未运行也未启用"})
		}
	}
	for _, i := range r.Interfaces {
		switch {
		case contains(d.Interfaces, i):
			out.Interfaces = append(out.Interfaces, i)
		case exists("ip", "link", "show", "dev", i):
			return Resources{}, nil, refuse("接口", i)
		default:
			skipped = append(skipped, Step{Name: "delete link " + i, OK: true, Skipped: true, Detail: "不存在"})
		}
	}
	for _, t := range r.NFTTables {
		fam, name, _ := strings.Cut(t, " ")
		switch {
		case contains(d.NFTTables, t):
			out.NFTTables = append(out.NFTTables, t)
		case exists("nft", "list", "table", fam, name):
			return Resources{}, nil, refuse("nft 表", t)
		default:
			skipped = append(skipped, Step{Name: "delete nft " + t, OK: true, Skipped: true, Detail: "不存在"})
		}
	}
	for _, n := range r.RouteTables {
		found := false
		for _, v := range d.RouteTables {
			found = found || v == n
		}
		if found {
			out.RouteTables = append(out.RouteTables, n)
			continue
		}
		// A policy table has no cheap existence check that is not also a
		// claim on it; a table Meridian never activated is left alone.
		skipped = append(skipped, Step{Name: fmt.Sprintf("flush table %d", n), OK: true, Skipped: true, Detail: "从未由 Meridian 激活，不处理"})
	}
	return out, skipped, nil
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

func union(a, b []string) []string {
	out := append([]string(nil), a...)
	for _, s := range b {
		found := false
		for _, v := range out {
			found = found || v == s
		}
		if !found {
			out = append(out, s)
		}
	}
	sort.Strings(out)
	return out
}

func writeFileAtomic(path string, b []byte, mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".tmp-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer os.Remove(name)
	if err := tmp.Chmod(mode); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(b); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(name, path)
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

// LoadOrCreateToken reads the agent token, creating a random one (0600) on
// first start. The value is never logged.
func LoadOrCreateToken(path string) (string, error) {
	if b, err := os.ReadFile(path); err == nil {
		tok := strings.TrimSpace(string(b))
		if len(tok) >= 32 && !strings.ContainsAny(tok, " \t\r\n") {
			return tok, nil
		}
		return "", fmt.Errorf("%s 内容不合法", path)
	} else if !os.IsNotExist(err) {
		return "", err
	}
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	tok := hex.EncodeToString(raw)
	if err := writeFileAtomic(path, []byte(tok+"\n"), 0o600); err != nil {
		return "", err
	}
	return tok, nil
}

// ListenUnix creates a root-only socket: its directory is 0700 and the
// socket itself 0600. A stale socket from a previous run is replaced.
func ListenUnix(path string) (net.Listener, error) {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		return nil, err
	}
	if st, err := os.Lstat(path); err == nil {
		if st.Mode()&os.ModeSocket == 0 {
			return nil, fmt.Errorf("%s 已存在且不是 socket", path)
		}
		_ = os.Remove(path)
	}
	l, err := net.Listen("unix", path)
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(path, 0o600); err != nil {
		l.Close()
		return nil, err
	}
	return l, nil
}

// Client is the panel side. It holds no state between calls; the token is
// re-read on every call so an agent restart with a new token is picked up.
type Client struct {
	Socket    string
	TokenFile string
	// Timeout bounds one HTTP exchange; default 7m (longer than the agent's
	// action timeout plus its lock wait would be too long; the agent replies
	// 503 after its lock wait and the client retries).
	Timeout time.Duration
	// Retries is how many times a transport failure or a busy agent is
	// retried with the same request_id. Default 3.
	Retries int
	Backoff time.Duration
}

// Do sends one request. A transport error is retried with the same
// request_id: if the agent already ran it, the cached result is replayed,
// so a retry never executes an action twice.
func (c *Client) Do(ctx context.Context, req Request) (Result, error) {
	if err := Validate(req); err != nil {
		return Result{}, err
	}
	sock := c.Socket
	if sock == "" {
		sock = DefaultSocket
	}
	tokPath := c.TokenFile
	if tokPath == "" {
		tokPath = DefaultTokenFile
	}
	if st, err := os.Stat(sock); err != nil || st.Mode()&os.ModeSocket == 0 {
		return Result{}, fmt.Errorf("%w：没有 %s", ErrUnavailable, sock)
	}
	raw, err := os.ReadFile(tokPath)
	if err != nil {
		return Result{}, fmt.Errorf("%w：读不到口令文件 %s", ErrUnavailable, tokPath)
	}
	token := strings.TrimSpace(string(raw))
	body, _ := json.Marshal(req)
	timeout := c.Timeout
	if timeout == 0 {
		timeout = 7 * time.Minute
	}
	retries := c.Retries
	if retries == 0 {
		retries = 3
	}
	backoff := c.Backoff
	if backoff == 0 {
		backoff = time.Second
	}
	hc := &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				var d net.Dialer
				return d.DialContext(ctx, "unix", sock)
			},
			DisableKeepAlives: true,
		},
	}
	var lastErr error
	for attempt := 0; attempt <= retries; attempt++ {
		if attempt > 0 {
			select {
			case <-time.After(backoff * time.Duration(attempt)):
			case <-ctx.Done():
				return Result{}, ctx.Err()
			}
		}
		hreq, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://meridian-host/v1/action", bytes.NewReader(body))
		if err != nil {
			return Result{}, err
		}
		hreq.Header.Set("Authorization", "Bearer "+token)
		hreq.Header.Set("Content-Type", "application/json")
		resp, err := hc.Do(hreq)
		if err != nil {
			lastErr = err
			if attempt == 0 && isDialErr(err) {
				lastErr = fmt.Errorf("%w：%v", ErrUnavailable, err)
			}
			continue
		}
		var res Result
		derr := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&res)
		resp.Body.Close()
		switch {
		case resp.StatusCode == http.StatusServiceUnavailable:
			lastErr = fmt.Errorf("host agent 忙：%s", res.Error)
			continue
		case resp.StatusCode != http.StatusOK:
			if res.Error == "" {
				res.Error = resp.Status
			}
			return res, fmt.Errorf("host agent 拒绝请求（%d）：%s", resp.StatusCode, res.Error)
		case derr != nil:
			lastErr = derr
			continue
		}
		if !res.OK {
			return res, fmt.Errorf("宿主动作 %s 失败：%s", req.Action, res.Error)
		}
		return res, nil
	}
	return Result{}, fmt.Errorf("宿主动作 %s 未完成（重试 %d 次）：%w", req.Action, retries, lastErr)
}

func isDialErr(err error) bool {
	var op *net.OpError
	return errors.As(err, &op) && op.Op == "dial"
}
