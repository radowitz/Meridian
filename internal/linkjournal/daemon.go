package linkjournal

// "meridian link-journal": the collector process (Unit, rendered by
// compile.RenderLinkJournalUnit). Every IntervalS seconds it reads the
// sources of sources.go, hands the readings to the Journal and answers
// fixed requests on a status socket that answers uid 0 only (the host
// agent):
//
//	GET  /v1/health   Health
//	GET  /v1/current  Current: every object's state now
//	GET  /v1/events   one Page (Query as query parameters)
//	POST /v1/clear    no parameters: every event, state and the checkpoint
//
// Why a process of its own (and not the failover script, the forwarder, the
// host agent or the panel): it has to keep sampling while the panel
// container is down or being upgraded; it must not be able to disturb
// forwarding or failover, so it shares no process, no file it writes and no
// lock with them (it only reads what they publish) and runs at low CPU and
// idle I/O priority under a memory cap; the host agent stays a
// request-driven boundary without a background job; and a crash here loses
// readings, nothing else.
//
// Its log lines carry counts and fixed texts only.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/radowitz/meridian/internal/sniff"
)

// programs maps the three programs to absolute candidates. PATH is never
// used.
var programs = map[string][]string{
	"wg":        {"/usr/bin/wg", "/usr/sbin/wg", "/bin/wg"},
	"systemctl": {"/usr/bin/systemctl", "/bin/systemctl"},
	"ip":        {"/usr/sbin/ip", "/usr/bin/ip", "/sbin/ip", "/bin/ip"},
}

// ExecRunner runs the real programs with a fixed minimal environment and a
// bounded output.
type ExecRunner struct{}

type capWriter struct {
	buf bytes.Buffer
	n   int
}

func (w *capWriter) Write(p []byte) (int, error) {
	if room := w.n - w.buf.Len(); room > 0 {
		if len(p) > room {
			w.buf.Write(p[:room])
		} else {
			w.buf.Write(p)
		}
	}
	return len(p), nil
}

func (ExecRunner) Run(ctx context.Context, prog string, args ...string) (string, error) {
	cands, ok := programs[prog]
	if !ok {
		return "", fmt.Errorf("program %q is not in the table", prog)
	}
	path := ""
	for _, c := range cands {
		if st, err := os.Stat(c); err == nil && !st.IsDir() {
			path = c
			break
		}
	}
	if path == "" {
		return "", fmt.Errorf("%s is not installed", prog)
	}
	cmd := exec.CommandContext(ctx, path, args...)
	cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C", "SYSTEMD_PAGER=", "SYSTEMD_COLORS=0"}
	cmd.Dir = "/"
	cmd.WaitDelay = 2 * time.Second
	w := &capWriter{n: 16 << 10}
	cmd.Stdout, cmd.Stderr = w, w
	err := cmd.Run()
	if ctx.Err() != nil {
		return w.buf.String(), errors.New("timed out")
	}
	return w.buf.String(), err
}

func (r Reader) runner() Runner {
	if r.Runner != nil {
		return r.Runner
	}
	return ExecRunner{}
}

func readBounded(path string, max int64) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, max+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > max {
		return nil, errors.New("file too large")
	}
	return b, nil
}

// readTimeout bounds one read of one source.
const readTimeout = 5 * time.Second

// Upstream reads and parses the failover loop's record.
func (r Reader) Upstream() (UpstreamRecord, error) {
	path := r.UpstreamFile
	if path == "" {
		path = UpstreamFile
	}
	read := r.ReadFile
	if read == nil {
		read = readBounded
	}
	b, err := read(path, MaxUpstreamFile)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return UpstreamRecord{}, errors.New("没有记录文件（故障切换服务还没有写过）")
		}
		return UpstreamRecord{}, errors.New("记录文件读不到")
	}
	rec, err := ParseUpstreamRecord(string(b))
	if err != nil {
		return rec, errors.New("记录文件的格式不对")
	}
	return rec, nil
}

// RouteDefault reads the interface of the foreign table's default route.
func (r Reader) RouteDefault(ctx context.Context) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, readTimeout)
	defer cancel()
	out, err := r.runner().Run(ctx, "ip", routeArgs()...)
	if err != nil {
		// An empty or missing table is "no route", not a failed read.
		if strings.Contains(out, "does not exist") || strings.Contains(out, "FIB table") {
			return "", nil
		}
		return "", errors.New("ip route show 执行失败")
	}
	return ParseRouteDefault(out), nil
}

// Handshake reads the newest handshake of one tunnel interface (ErrAbsent
// when the interface does not exist).
func (r Reader) Handshake(ctx context.Context, iface string) (int64, error) {
	if !IfaceRe.MatchString(iface) {
		return 0, errors.New("不是受管的隧道接口名")
	}
	ctx, cancel := context.WithTimeout(ctx, readTimeout)
	defer cancel()
	out, err := r.runner().Run(ctx, "wg", wgArgs(iface)...)
	if err != nil {
		if strings.Contains(out, "No such device") {
			return 0, ErrAbsent
		}
		return 0, errors.New("wg show 执行失败（没有安装 wg，或没有读取接口的权限）")
	}
	latest, _, err := ParseHandshakes(out)
	if err != nil {
		return 0, errors.New("wg show 的输出无法解析")
	}
	return latest, nil
}

var unitStates = map[string]bool{"active": true, "inactive": true, "failed": true, "activating": true, "deactivating": true, "reloading": true, "unknown": true, "maintenance": true}

// UnitState reads "systemctl is-active" of one wstunnel client unit.
func (r Reader) UnitState(ctx context.Context, unit string) (string, error) {
	if !UnitRe.MatchString(unit) {
		return "", errors.New("不是 wstunnel 客户端单元名")
	}
	ctx, cancel := context.WithTimeout(ctx, readTimeout)
	defer cancel()
	// is-active exits non-zero for every state but active; the word it
	// prints is the answer.
	out, _ := r.runner().Run(ctx, "systemctl", unitArgs(unit)...)
	state := strings.TrimSpace(out)
	if i := strings.IndexByte(state, '\n'); i >= 0 {
		state = state[:i]
	}
	if !unitStates[state] {
		return "", errors.New("systemctl is-active 没有给出单元状态")
	}
	return state, nil
}

// SelfCheck reads the forwarder's last self-check from its status socket.
func (r Reader) SelfCheck(ctx context.Context) (*sniff.SelfCheck, error) {
	sock := r.SniffSocket
	if sock == "" {
		sock = SniffSocket
	}
	call := r.Status
	if call == nil {
		call = func(ctx context.Context, socket, path string) ([]byte, int, error) {
			if fi, err := os.Stat(socket); err != nil || fi.Mode()&os.ModeSocket == 0 {
				return nil, 0, errors.New("没有状态套接字（嗅探转发服务没有运行）")
			}
			return sniff.StatusCall(ctx, socket, http.MethodGet, path)
		}
	}
	ctx, cancel := context.WithTimeout(ctx, readTimeout)
	defer cancel()
	b, code, err := call(ctx, sock, "/v1/health")
	if err != nil {
		return nil, errors.New(clipBytes(err.Error(), 120))
	}
	// 503: the forwarder answers but is not ready; its self-check still counts.
	if code != http.StatusOK && code != http.StatusServiceUnavailable {
		return nil, fmt.Errorf("状态套接字回答 %d", code)
	}
	var h struct {
		SelfCheck *sniff.SelfCheck `json:"self_check"`
	}
	if err := json.Unmarshal(b, &h); err != nil {
		return nil, errors.New("状态套接字的回答不是 JSON")
	}
	if h.SelfCheck == nil {
		return nil, errors.New("转发服务还没有自检结果")
	}
	return h.SelfCheck, nil
}

// SourceState is one source as the collector last saw it.
type SourceState struct {
	Source string `json:"source"`
	// OK: the last read gave readings. Fails: failed reads in a row.
	OK     bool       `json:"ok"`
	Fails  int        `json:"fails,omitempty"`
	Error  string     `json:"error,omitempty"`
	LastOK *time.Time `json:"last_ok,omitempty"`
	ReadAt *time.Time `json:"read_at,omitempty"`
}

// Collector samples the sources of one object list into a Journal.
type Collector struct {
	Cfg Config
	J   *Journal
	R   Reader

	mu      sync.Mutex
	pass    int
	src     map[string]*SourceState
	started time.Time
	lastMS  int64
}

// NewCollector binds an object list to a journal: objects the list no
// longer names are forgotten and a changed list is recorded.
func NewCollector(cfg Config, j *Journal, r Reader) *Collector {
	j.SetDigest(cfg.Digest(), cfg.Known)
	return &Collector{Cfg: cfg, J: j, R: r, src: map[string]*SourceState{}, started: time.Now().UTC().Truncate(time.Second)}
}

var sourceLabels = map[string]string{
	SourceUpstream:  "来源：故障切换服务的记录",
	SourceRoute:     "来源：路由表 102",
	SourceHandshake: "来源：隧道握手（wg）",
	SourceWSSUnit:   "来源：wstunnel 客户端单元",
	SourceSelfCheck: "来源：嗅探转发服务的自检",
}

// source records one read of a source and returns its availability reading
// (none while it has failed fewer than SourceFailPasses times in a row).
func (c *Collector) source(now time.Time, name string, err error) Observation {
	s := c.src[name]
	if s == nil {
		s = &SourceState{Source: name}
		c.src[name] = s
	}
	s.ReadAt = tp(now)
	o := Observation{Class: ClassCollector, Kind: KindSource, ID: name, Label: sourceLabels[name], Source: SourceCollector}
	if err == nil {
		s.OK, s.Fails, s.Error, s.LastOK = true, 0, "", tp(now)
		o.State, o.Evidence = StateSourceOK, "这个来源可以读取"
		return o
	}
	s.OK, s.Fails, s.Error = false, s.Fails+1, clipBytes(err.Error(), 160)
	if s.Fails < SourceFailPasses {
		return Observation{}
	}
	o.State, o.Reason = StateUnavailable, "read_failed"
	o.Evidence = fmt.Sprintf("连续 %d 次读不到（%s）：依赖它的对象没有新的读数，超过空窗阈值后状态记为未知", s.Fails, s.Error)
	return o
}

// Step is one pass at now.
func (c *Collector) Step(ctx context.Context, now time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	start := time.Now()
	slow := c.pass%c.Cfg.SlowEvery == 0
	c.pass++
	var obs []Observation
	add := func(o ...Observation) {
		for _, x := range o {
			if x.State != "" {
				obs = append(obs, x)
			}
		}
	}
	// The carrying path: the failover loop's record, or the route table
	// where the loop records nothing.
	if c.Cfg.Mode == ModeSingle {
		iface, err := c.R.RouteDefault(ctx)
		add(c.source(now, SourceRoute, err))
		if err == nil {
			add(c.Cfg.routeObservation(iface))
		}
	} else {
		rec, err := c.R.Upstream()
		if err == nil {
			want := 1
			if c.Cfg.Mode == ModeShare {
				want = 2
			}
			age := now.Unix() - rec.Beat
			switch {
			case rec.Version != want:
				err = fmt.Errorf("记录是第 %d 种格式，已安装的对象清单对应第 %d 种（可能正在安装）", rec.Version, want)
			case age > int64(c.Cfg.UpstreamStaleS):
				err = fmt.Errorf("故障切换服务的心跳已停 %d 秒（阈值 %d 秒），它可能没有运行", age, c.Cfg.UpstreamStaleS)
			case age < -int64(c.Cfg.UpstreamStaleS):
				err = errors.New("记录里的心跳时间在未来（系统时钟被调回？）")
			}
		}
		add(c.source(now, SourceUpstream, err))
		if err == nil {
			add(c.Cfg.upstreamObservations(rec)...)
		}
	}
	if slow {
		// Tunnels first: a WSS carrier's state uses its tunnel's. A tunnel
		// without keepalive is not read (its handshake age says nothing).
		tunnel, judged := map[string]string{}, map[string]bool{}
		read, failed := 0, 0
		var lastErr error
		for _, t := range c.Cfg.Tunnels {
			if t.KeepaliveS <= 0 {
				continue
			}
			judged[t.Iface] = true
			latest, err := c.R.Handshake(ctx, t.Iface)
			var state, reason, ev string
			switch {
			case errors.Is(err, ErrAbsent):
				state, reason, ev = TunnelAbsent, "no_interface", "接口 "+t.Iface+" 不存在（wg 回答 No such device）"
			case err != nil:
				failed++
				lastErr = err
				continue
			default:
				state, reason, ev = tunnelState(latest, now, c.Cfg.HandshakeStaleS)
			}
			read++
			tunnel[t.Iface] = state
			add(c.Cfg.tunnelObservation(t, state, reason, ev, latest))
		}
		if read+failed > 0 {
			if read > 0 {
				lastErr = nil
			}
			add(c.source(now, SourceHandshake, lastErr))
		}
		read, failed, lastErr = 0, 0, nil
		for _, w := range c.Cfg.WSS {
			st, err := c.R.UnitState(ctx, w.Unit)
			if err != nil {
				failed++
				lastErr = err
				continue
			}
			read++
			add(c.Cfg.wssObservation(w, st, tunnel[w.Iface], judged[w.Iface]))
		}
		if read+failed > 0 {
			if read > 0 {
				lastErr = nil
			}
			add(c.source(now, SourceWSSUnit, lastErr))
		}
		if c.Cfg.Sniff != nil {
			sc, err := c.R.SelfCheck(ctx)
			if err == nil {
				if age := now.Sub(sc.FinishedAt); age > time.Duration(c.Cfg.Sniff.SelfCheckMaxAgeS)*time.Second {
					err = fmt.Errorf("最近一次自检已是 %d 分钟前，不再算作读数", int(age/time.Minute))
				}
			}
			add(c.source(now, SourceSelfCheck, err))
			if err == nil {
				add(c.Cfg.selfCheckObservations(sc)...)
			}
		}
	}
	c.J.Observe(now, obs)
	c.lastMS = time.Since(start).Milliseconds()
}

// Health is the collector's state.
type Health struct {
	Ready     bool      `json:"ready"`
	StartedAt time.Time `json:"started_at"`
	Gateway   string    `json:"gateway"`
	Mode      string    `json:"mode"`
	// Digest identifies the object list in use.
	Digest    string `json:"config_digest"`
	IntervalS int    `json:"interval_s"`
	SlowS     int    `json:"slow_interval_s"`
	Passes    int    `json:"passes"`
	// LastPassMS: how long the last pass took.
	LastPassMS int64         `json:"last_pass_ms"`
	Sources    []SourceState `json:"sources"`
	Journal    Stats         `json:"journal"`
}

// Health describes the collector now.
func (c *Collector) Health() Health {
	c.mu.Lock()
	h := Health{StartedAt: c.started, Gateway: c.Cfg.Gateway, Mode: c.Cfg.Mode, Digest: c.Cfg.Digest(), IntervalS: c.Cfg.IntervalS,
		SlowS: c.Cfg.IntervalS * c.Cfg.SlowEvery, Passes: c.pass, LastPassMS: c.lastMS, Sources: []SourceState{}}
	for _, s := range c.src {
		h.Sources = append(h.Sources, *s)
	}
	c.mu.Unlock()
	sort.Slice(h.Sources, func(a, b int) bool { return h.Sources[a].Source < h.Sources[b].Source })
	h.Journal = c.J.Stats()
	h.Ready = h.Passes > 0
	return h
}

// ClearResult is the answer of a clear.
type ClearResult struct {
	Cleared int   `json:"cleared"`
	Stats   Stats `json:"stats"`
}

// Clear removes every event, the tracked states and the checkpoint; the
// sources' failure counts start again.
func (c *Collector) Clear() ClearResult {
	c.mu.Lock()
	defer c.mu.Unlock()
	n := c.J.Clear()
	c.src = map[string]*SourceState{}
	return ClearResult{Cleared: n, Stats: c.J.Stats()}
}

// StatusHandler serves the fixed requests. Every answer stays below
// sniff.MaxStatusAnswer (a page holds at most PageMax events of at most
// MaxLine bytes; the current view at most MaxObjects objects).
func (c *Collector) StatusHandler() http.Handler {
	mux := http.NewServeMux()
	write := func(w http.ResponseWriter, v any) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(v)
	}
	only := func(w http.ResponseWriter, r *http.Request, method string) bool {
		if r.Method != method {
			http.Error(w, method+" only", http.StatusMethodNotAllowed)
			return false
		}
		return true
	}
	bare := func(w http.ResponseWriter, r *http.Request) bool {
		if r.ContentLength > 0 || r.URL.RawQuery != "" {
			http.Error(w, "no parameters", http.StatusBadRequest)
			return false
		}
		return true
	}
	mux.HandleFunc("/v1/health", func(w http.ResponseWriter, r *http.Request) {
		if only(w, r, http.MethodGet) && bare(w, r) {
			write(w, c.Health())
		}
	})
	mux.HandleFunc("/v1/current", func(w http.ResponseWriter, r *http.Request) {
		if only(w, r, http.MethodGet) && bare(w, r) {
			write(w, c.J.Current())
		}
	})
	mux.HandleFunc("/v1/events", func(w http.ResponseWriter, r *http.Request) {
		if !only(w, r, http.MethodGet) {
			return
		}
		q, err := QueryFrom(r.URL.Query())
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		page, err := c.J.Query(q)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		write(w, page)
	})
	mux.HandleFunc("/v1/clear", func(w http.ResponseWriter, r *http.Request) {
		if only(w, r, http.MethodPost) && bare(w, r) {
			write(w, c.Clear())
		}
	})
	return mux
}

// DaemonConfig is the collector's command line.
type DaemonConfig struct {
	ConfigPath   string
	Dir          string
	StatusSocket string
	MaxEvents    int
	MaxAge       time.Duration
	MaxBytes     int64
}

func cleanAbs(name, p string) error {
	if p == "" || !filepath.IsAbs(p) || filepath.Clean(p) != p {
		return fmt.Errorf("%s: a clean absolute path", name)
	}
	return nil
}

// ParseArgs parses the collector's flags.
func ParseArgs(args []string) (DaemonConfig, error) {
	var c DaemonConfig
	fs := flag.NewFlagSet("link-journal", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	fs.StringVar(&c.ConfigPath, "config", ConfigPath, "the compiled object list")
	fs.StringVar(&c.Dir, "dir", StateDir, "the journal's directory")
	fs.StringVar(&c.StatusSocket, "status-socket", "", "status socket (answers uid 0 only)")
	fs.IntVar(&c.MaxEvents, "max-events", DefaultMaxEvents, "events kept")
	fs.DurationVar(&c.MaxAge, "max-age", DefaultMaxAge, "age kept")
	fs.Int64Var(&c.MaxBytes, "max-bytes", DefaultMaxBytes, "bytes for the events, the checkpoint and their temporary copies together")
	if err := fs.Parse(args); err != nil {
		return c, err
	}
	if fs.NArg() > 0 {
		return c, errors.New("unexpected arguments")
	}
	if err := cleanAbs("config", c.ConfigPath); err != nil {
		return c, err
	}
	if err := cleanAbs("dir", c.Dir); err != nil {
		return c, err
	}
	if c.StatusSocket != "" {
		if err := cleanAbs("status-socket", c.StatusSocket); err != nil {
			return c, err
		}
	}
	if c.MaxEvents < 16 || c.MaxAge < time.Hour || c.MaxBytes < MinBytes {
		return c, fmt.Errorf("max-events >= 16, max-age >= 1h, max-bytes >= %d", MinBytes)
	}
	return c, nil
}

// LoadConfig reads the object list at path (bounded, strict).
func LoadConfig(path string) (Config, error) {
	b, err := readBounded(path, MaxConfig)
	if err != nil {
		return Config{}, err
	}
	return ParseConfig(b)
}

// Main runs "meridian link-journal" until SIGTERM / SIGINT. Exit 2 usage,
// 1 failure to start.
func Main(args []string) int {
	dc, err := ParseArgs(args)
	if err != nil {
		fmt.Fprintln(os.Stderr, "meridian link-journal:", err)
		return 2
	}
	cfg, err := LoadConfig(dc.ConfigPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "meridian-link-journal-failed: object list:", err)
		return 1
	}
	j, err := Open(Options{Dir: dc.Dir, MaxEvents: dc.MaxEvents, MaxAge: dc.MaxAge, MaxBytes: dc.MaxBytes})
	if err != nil {
		fmt.Fprintln(os.Stderr, "meridian-link-journal-failed: journal:", err)
		return 1
	}
	defer j.Close()
	c := NewCollector(cfg, j, Reader{})
	if dc.StatusSocket != "" {
		sl, err := sniff.ListenStatus(dc.StatusSocket, sniff.StatusRootOnly)
		if err != nil {
			fmt.Fprintln(os.Stderr, "meridian-link-journal-failed: status socket:", err)
			return 1
		}
		go func() { _ = (&http.Server{Handler: c.StatusHandler(), ReadHeaderTimeout: 5 * time.Second}).Serve(sl) }()
	}
	st := j.Stats()
	log.Printf("%s: object list %s (mode %s, %d tunnels, %d WSS carriers, self-check targets %v), journal %s (%d events kept; at most %d events, %s, %d bytes), restored %v",
		ReadyMarker, cfg.Digest(), cfg.Mode, len(cfg.Tunnels), len(cfg.WSS), cfg.Sniff != nil, dc.Dir, st.Events, dc.MaxEvents, dc.MaxAge, dc.MaxBytes, st.Restored)
	sig := make(chan os.Signal, 2)
	signal.Notify(sig, syscall.SIGTERM, syscall.SIGINT)
	tick := time.NewTicker(time.Duration(cfg.IntervalS) * time.Second)
	defer tick.Stop()
	pass := func() {
		// One pass may not outlast its period by much: a hung program is
		// cut off by its own timeout, the pass by this one.
		ctx, cancel := context.WithTimeout(context.Background(), time.Duration(cfg.IntervalS)*time.Second+30*time.Second)
		defer cancel()
		c.Step(ctx, time.Now())
	}
	pass()
	for {
		select {
		case <-tick.C:
			pass()
		case <-sig:
			return 0
		}
	}
}
