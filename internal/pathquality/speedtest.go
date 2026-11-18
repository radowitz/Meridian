package pathquality

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// The download speed test (docs/architecture.md「多中继同时分担」).
//
// Every sharing relay runs a fixed endpoint (compile/relay_speedtest.go): a
// systemd socket bound only to the relay's tunnel addresses toward the
// gateway, accepting only the gateway's tunnel addresses, that writes
// exactly speed_test_mb MiB of zeros to whoever connects and closes. It
// takes no input at all: no URL, path, size or command.
//
// "meridian path-speedtest" runs on the gateway, kicked by the failover
// loop about once a minute; it does at most one test per run, under an
// exclusive lock, so only one test runs on the gateway at any time. The
// relays are staggered: relay i (of n) is first due interval·i/n after the
// log was started, then every interval after its previous test; a failed
// test is retried after a sixth of the interval (at least two minutes).
// The test connects from the leg's gateway address to the relay's, on the
// leg the controller uses, with the relay's route mark (SO_MARK: its own
// table, which only points at that leg) and bound to the leg (SO_BINDTODEVICE):
// it can never leave through another relay or the WAN. Before connecting
// the route the kernel would pick for that mark is checked ("ip route get").
//
// Each result (or "not measured" with its reason) is appended to the
// bounded log SpeedLogPath; the QoS verdict (qos.go) is updated and written
// to QoSPath.

// Default paths on the gateway.
// speedStall: no data for this long during a speed test is a stall
// ("not measured"), not a slow sample. A variable only so tests can shorten it.
var speedStall = 10 * time.Second

const (
	SpeedLogPath  = "/var/lib/meridian-pathq/speed.json"
	SpeedLockPath = "/run/meridian/pathq/speedtest.lock"
	// SpeedPort is the relays' endpoint port (inside the tunnels only).
	SpeedPort = 9277
)

const (
	// SpeedTimeout bounds one test; a test that has received at least
	// speedMinBytes when it runs out is a valid (slow) measurement.
	SpeedTimeout  = 60 * time.Second
	speedMinBytes = 1 << 20
	// speedConnectTimeout bounds the TCP handshake.
	speedConnectTimeout = 5 * time.Second
	// speedMinRetrySec: a failed test is retried after interval/6, at least this.
	speedMinRetrySec = 120
)

// SpeedRelayLog is one relay's part of the log.
type SpeedRelayLog struct {
	LastAttempt int64         `json:"last_attempt"`
	Samples     []SpeedSample `json:"samples"`
	Verdict     QoSVerdict    `json:"verdict"`
}

// SpeedLog is the persistent, bounded log of the speed tests.
type SpeedLog struct {
	Version int                       `json:"version"`
	Started int64                     `json:"started"`
	LastRun int64                     `json:"last_run"`
	Relays  map[string]*SpeedRelayLog `json:"relays"`
}

// LoadSpeedLog reads the log (an empty one when missing or unreadable).
func LoadSpeedLog(path string) *SpeedLog {
	l := &SpeedLog{Version: 1, Relays: map[string]*SpeedRelayLog{}}
	b, err := os.ReadFile(path)
	if err != nil || len(b) > 4<<20 {
		return l
	}
	var x SpeedLog
	if json.Unmarshal(b, &x) != nil || x.Version != 1 {
		return l
	}
	if x.Relays == nil {
		x.Relays = map[string]*SpeedRelayLog{}
	}
	return &x
}

// relay returns (creating) a relay's log.
func (l *SpeedLog) relay(id string) *SpeedRelayLog {
	r := l.Relays[id]
	if r == nil {
		r = &SpeedRelayLog{}
		l.Relays[id] = r
	}
	return r
}

// prune keeps the configured relays and, per relay, the tests of the
// baseline window (plus a day), at most MaxSpeedSamples.
func (l *SpeedLog) prune(c Config, now int64) {
	keep := map[string]bool{}
	for _, r := range c.Relays {
		keep[r.ID] = true
	}
	for id := range l.Relays {
		if !keep[id] {
			delete(l.Relays, id)
		}
	}
	from := now - QoSMaxAge(c.Settings) - 86400
	for _, r := range l.Relays {
		out := r.Samples[:0]
		for _, s := range r.Samples {
			if s.At > from {
				out = append(out, s)
			}
		}
		if len(out) > MaxSpeedSamples {
			out = out[len(out)-MaxSpeedSamples:]
		}
		r.Samples = out
	}
}

// interval is the configured test period.
func speedInterval(c Config) int64 {
	v := int64(c.Settings.SpeedTestIntervalSec)
	if v < 60 {
		v = 1800
	}
	return v
}

// DueRelay picks the relay to test now ("" when none is due). Disabled
// relays are not tested.
func DueRelay(c Config, l *SpeedLog, now int64) string {
	if c.SpeedPort == 0 || c.Settings.SpeedTestOff {
		return ""
	}
	iv := speedInterval(c)
	n := int64(len(c.Relays))
	// Staggering also between runs: at least interval/(2n) since the
	// previous test of any relay.
	gap := iv / (2 * n)
	if gap < 30 {
		gap = 30
	}
	if l.LastRun > 0 && now-l.LastRun < gap && now >= l.LastRun {
		return ""
	}
	best, bestAt := "", int64(0)
	for i, r := range c.Relays {
		if disabledRelay(c, r.ID) {
			continue
		}
		rl := l.Relays[r.ID]
		var dueAt int64
		switch {
		case rl == nil || rl.LastAttempt == 0:
			dueAt = l.Started + iv*int64(i)/n
		default:
			wait := iv
			if k := len(rl.Samples); k > 0 && !rl.Samples[k-1].OK {
				wait = iv / 6
				if wait < speedMinRetrySec {
					wait = speedMinRetrySec
				}
			}
			dueAt = rl.LastAttempt + wait
			if rl.LastAttempt > now {
				// Clock went back: due now.
				dueAt = now
			}
		}
		if dueAt <= now && (best == "" || dueAt < bestAt) {
			best, bestAt = r.ID, dueAt
		}
	}
	return best
}

func disabledRelay(c Config, id string) bool {
	for _, o := range c.Settings.Overrides {
		if o.Relay == id && o.Disabled {
			return true
		}
	}
	return false
}

// Dialer opens the test connection on one leg with the relay's mark.
type Dialer func(ctx context.Context, leg Leg, mark uint32, port int) (net.Conn, error)

// SpeedTester runs one test.
type SpeedTester struct {
	// Dial defaults to the marked, device-bound dialer (dialMarked).
	Dial Dialer
	// Run checks the route ("ip route get"); nil: ExecRunner.
	Run Runner
	// Clock times the transfer (tests may fix it).
	Clock func() time.Time
	// Timeout bounds the transfer (default SpeedTimeout).
	Timeout time.Duration
}

func (t SpeedTester) now() time.Time {
	if t.Clock != nil {
		return t.Clock()
	}
	return time.Now()
}

// RouteMatches checks "ip -o route get <remote> from <local> mark <mark>"
// names the leg's interface.
func RouteMatches(out, iface string) bool {
	f := strings.Fields(out)
	for i := 0; i+1 < len(f); i++ {
		if f[i] == "dev" {
			return f[i+1] == iface
		}
	}
	return false
}

// Test downloads from relay r on leg (one of r's legs) and returns the
// sample (OK false with a reason when nothing usable was measured).
func (t SpeedTester) Test(ctx context.Context, c Config, r RelayConfig, leg Leg, at int64) SpeedSample {
	x := SpeedSample{At: at, Leg: leg.Iface}
	fail := func(reason string) SpeedSample { x.OK, x.Reason = false, reason; return x }
	known := false
	for _, l := range r.Legs {
		known = known || l == leg
	}
	if !known || leg.Local == "" || leg.Remote == "" || c.SpeedPort == 0 {
		return fail(SpeedFailPath)
	}
	run := t.Run
	if run == nil {
		run = ExecRunner{}
	}
	out, err := run.Run(ctx, "ip", "-o", "route", "get", leg.Remote, "from", leg.Local, "mark", fmt.Sprintf("0x%x", r.Value))
	if err != nil || !RouteMatches(out, leg.Iface) {
		return fail(SpeedFailPath)
	}
	dial := t.Dial
	if dial == nil {
		dial = dialMarked
	}
	timeout := t.Timeout
	if timeout <= 0 {
		timeout = SpeedTimeout
	}
	cctx, cancel := context.WithTimeout(ctx, speedConnectTimeout)
	conn, err := dial(cctx, leg, r.Value, c.SpeedPort)
	cancel()
	if err != nil {
		return fail(SpeedFailConnect)
	}
	defer conn.Close()
	want := int64(c.Settings.SpeedTestMB) << 20
	start := t.now()
	deadline := time.Now().Add(timeout)
	// Read in chunks, never more than the endpoint is compiled to send
	// (plus slack). A slow but steady transfer that reaches the overall
	// deadline is a valid (slow) sample: a throttled path may never finish
	// 20 MB in time. A stall (no data for speedStall) or any read error other
	// than reaching the overall deadline is "not measured", never a slow
	// sample.
	var n int64
	buf := make([]byte, 64<<10)
	limit := want + 64<<10
	stalled, readErr := false, false
	for n < limit {
		next := time.Now().Add(speedStall)
		if next.After(deadline) {
			next = deadline
		}
		_ = conn.SetReadDeadline(next)
		k, err := conn.Read(buf[:min(int64(len(buf)), limit-n)])
		n += int64(k)
		if err == nil {
			continue
		}
		if err == io.EOF {
			break
		}
		var ne net.Error
		if errors.As(err, &ne) && ne.Timeout() {
			if time.Now().Before(deadline.Add(-50 * time.Millisecond)) {
				stalled = true // no data for speedStall before the deadline
			}
			break
		}
		readErr = true
		break
	}
	el := t.now().Sub(start)
	x.Bytes, x.ElapsedMS = n, el.Milliseconds()
	complete := n >= want
	timedOut := !complete && !stalled && !readErr && el >= timeout-50*time.Millisecond
	if stalled || readErr || (!complete && !(timedOut && n >= speedMinBytes)) {
		return fail(SpeedFailShort)
	}
	if x.ElapsedMS <= 0 {
		x.ElapsedMS = 1
	}
	x.OK = true
	x.Kbps = int(n * 8 / x.ElapsedMS) // bytes·8 / ms = kbit/s
	return x
}

// SpeedRun is one run of "meridian path-speedtest": pick the due relay,
// test it, record. reachable(id) reports whether the controller saw the
// relay answer (nil: assume yes); leg(id) the leg in use ("" → first).
func SpeedRun(ctx context.Context, c Config, l *SpeedLog, now int64, tester SpeedTester, reachable func(string) bool, legOf func(string) string) (string, bool) {
	if l.Started == 0 {
		l.Started = now
	}
	id := DueRelay(c, l, now)
	if id == "" {
		return "", false
	}
	r, _ := c.RelayByID(id)
	leg := r.Legs[0]
	if legOf != nil {
		if want := legOf(id); want != "" {
			for _, x := range r.Legs {
				if x.Iface == want {
					leg = x
				}
			}
		}
	}
	var x SpeedSample
	if reachable != nil && !reachable(id) {
		x = SpeedSample{At: now, Leg: leg.Iface, Reason: SpeedFailUnreachable}
	} else {
		x = tester.Test(ctx, c, r, leg, now)
	}
	rl := l.relay(id)
	x = FoldSample(&rl.Verdict, rl.Samples, x, c.Settings, NominalKbps(c.Settings, id))
	rl.Samples = append(rl.Samples, x)
	rl.LastAttempt = now
	l.LastRun = now
	l.prune(c, now)
	return id, true
}

// Verdicts maps the log onto the verdict file's input.
func (l *SpeedLog) Verdicts() map[string]*QoSVerdict {
	out := map[string]*QoSVerdict{}
	for id, r := range l.Relays {
		v := r.Verdict
		out[id] = &v
	}
	return out
}

// RunSpeedTest is "meridian path-speedtest":
//
//	meridian path-speedtest --config F --state F --log F --qos F [--now EPOCH]
//
// It exits 0 when nothing was due, when another run holds the lock, or
// after one recorded test.
func RunSpeedTest(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("path-speedtest", flag.ContinueOnError)
	fs.SetOutput(stderr)
	cfgPath := fs.String("config", ConfigPath, "compiled path-quality config")
	statePath := fs.String("state", StatePath, "controller state file (leg in use, reachability)")
	logPath := fs.String("log", SpeedLogPath, "speed-test log")
	qosPath := fs.String("qos", QoSPath, "QoS verdict file")
	lockPath := fs.String("lock", SpeedLockPath, "lock file")
	nowFlag := fs.Int64("now", 0, "run time (epoch seconds; tests)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 0 {
		fmt.Fprintln(stderr, "path-speedtest: unexpected arguments")
		return 2
	}
	c, err := LoadConfig(*cfgPath)
	if err != nil {
		fmt.Fprintln(stderr, "path-speedtest:", err)
		return 2
	}
	if c.SpeedPort == 0 || c.Settings.SpeedTestOff {
		return 0
	}
	unlock, ok, err := lockFile(*lockPath)
	if err != nil {
		fmt.Fprintln(stderr, "path-speedtest: lock:", err)
		return 3
	}
	if !ok {
		return 0 // another test is running
	}
	defer unlock()
	now := time.Now().Unix()
	if *nowFlag > 0 {
		now = *nowFlag
	}
	l := LoadSpeedLog(*logPath)
	st := LoadState(*statePath)
	reach := func(id string) bool {
		if st == nil || st.ConfigHash != c.Hash() || st.Relays[id] == nil || st.Passes == 0 {
			return true
		}
		return st.Relays[id].Reachable
	}
	legOf := func(id string) string {
		if st == nil || st.ConfigHash != c.Hash() || st.Relays[id] == nil {
			return ""
		}
		return st.Relays[id].Leg
	}
	ctx, cancel := context.WithTimeout(context.Background(), SpeedTimeout+15*time.Second)
	defer cancel()
	id, ran := SpeedRun(ctx, c, l, now, SpeedTester{}, reach, legOf)
	if !ran {
		if l.LastRun == 0 && l.Started == now {
			// First run: remember the stagger origin.
			_ = saveSpeedLog(*logPath, l)
		}
		return 0
	}
	if err := saveSpeedLog(*logPath, l); err != nil {
		fmt.Fprintln(stderr, "path-speedtest: log:", err)
	}
	if err := writeAtomic(*qosPath, []byte(FormatQoS(c, l.Verdicts())), 0o644); err != nil {
		fmt.Fprintln(stderr, "path-speedtest: qos:", err)
		return 4
	}
	x := l.Relays[id].Samples[len(l.Relays[id].Samples)-1]
	if x.OK {
		fmt.Fprintf(stdout, "%s %d kbit/s\n", id, x.Kbps)
	} else {
		fmt.Fprintf(stdout, "%s not measured: %s\n", id, x.Reason)
	}
	return 0
}

func saveSpeedLog(path string, l *SpeedLog) error {
	b, err := json.Marshal(l)
	if err != nil {
		return err
	}
	return writeAtomic(path, b, 0o600)
}

// lockFile takes an exclusive lock (O_EXCL lock file holding the pid; a
// lock whose process is gone, or older than twice the test timeout, is
// taken over).
func lockFile(path string) (func(), bool, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, false, err
	}
	for try := 0; try < 2; try++ {
		f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if err == nil {
			fmt.Fprintf(f, "%d\n", os.Getpid())
			f.Close()
			return func() { os.Remove(path) }, true, nil
		}
		if !errors.Is(err, os.ErrExist) {
			return nil, false, err
		}
		if !staleLock(path) {
			return nil, false, nil
		}
		os.Remove(path)
	}
	return nil, false, nil
}

func staleLock(path string) bool {
	fi, err := os.Stat(path)
	if err != nil {
		return true
	}
	if time.Since(fi.ModTime()) > 2*(SpeedTimeout+15*time.Second) {
		return true
	}
	b, _ := os.ReadFile(path)
	pid, err := strconv.Atoi(strings.TrimSpace(string(b)))
	if err != nil || pid <= 0 {
		return true
	}
	return !processAlive(pid)
}
