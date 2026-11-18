package pathquality

import (
	"bytes"
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/radowitz/meridian/internal/model"
)

// routeRunner answers "ip route get" with a fixed device and records calls.
type routeRunner struct {
	dev   string
	calls []string
}

func (r *routeRunner) Run(_ context.Context, prog string, args ...string) (string, error) {
	r.calls = append(r.calls, prog+" "+strings.Join(args, " "))
	return args[3] + " from x dev " + r.dev + " table 111 src x uid 0\n", nil
}

// server serves n bytes then closes (a stand-in for the relay endpoint);
// pace slows it.
func server(t *testing.T, n int, pace time.Duration) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 64<<10)
				for sent := 0; sent < n; sent += len(buf) {
					if _, err := c.Write(buf[:min(len(buf), n-sent)]); err != nil {
						return
					}
					if pace > 0 {
						time.Sleep(pace)
					}
				}
			}(c)
		}
	}()
	return ln.Addr().String()
}

// trickleServer sends burst bytes at full speed, then 1 KiB every pace until
// the client goes away: a steady transfer that never completes, independent
// of how fast the machine is.
func trickleServer(t *testing.T, burst int, pace time.Duration) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				if _, err := c.Write(make([]byte, burst)); err != nil {
					return
				}
				small := make([]byte, 1<<10)
				for {
					time.Sleep(pace)
					if _, err := c.Write(small); err != nil {
						return
					}
				}
			}(c)
		}
	}()
	return ln.Addr().String()
}

type dialRec struct {
	addr string
	leg  Leg
	mark uint32
	port int
}

func loopDial(addr string, rec *dialRec) Dialer {
	return func(ctx context.Context, leg Leg, mark uint32, port int) (net.Conn, error) {
		rec.leg, rec.mark, rec.port = leg, mark, port
		var d net.Dialer
		return d.DialContext(ctx, "tcp", addr)
	}
}

func smallConfig(t *testing.T) Config {
	c := speedConfig(t, func(p *model.PathQuality) { p.SpeedTestMB = 5 })
	return c
}

func TestSpeedTestMeasuresOnTheRelayMarkAndLeg(t *testing.T) {
	c := smallConfig(t)
	var rec dialRec
	rr := &routeRunner{dev: "m02w"}
	tester := SpeedTester{Dial: loopDial(server(t, 5<<20, 0), &rec), Run: rr}
	r := c.Relays[0]
	x := tester.Test(context.Background(), c, r, r.Legs[1], 100)
	if !x.OK || x.Bytes != 5<<20 || x.Kbps <= 0 || x.Leg != "m02w" {
		t.Fatalf("%+v", x)
	}
	if rec.mark != RelayMark(1) || rec.leg.Iface != "m02w" || rec.leg.Remote != "10.66.102.2" || rec.port != SpeedPort {
		t.Fatalf("dial %+v", rec)
	}
	if len(rr.calls) != 1 || rr.calls[0] != "ip -o route get 10.66.102.2 from 10.66.102.1 mark 0x10000" {
		t.Fatalf("route check %v", rr.calls)
	}
}

func TestSpeedTestNeverDialsOffPath(t *testing.T) {
	c := smallConfig(t)
	r := c.Relays[0]
	dialed := false
	d := func(context.Context, Leg, uint32, int) (net.Conn, error) { dialed = true; return nil, errors.New("x") }
	// The mark leads to another interface (another relay, the WAN).
	x := SpeedTester{Dial: d, Run: &routeRunner{dev: "eth0"}}.Test(context.Background(), c, r, r.Legs[0], 1)
	if x.OK || x.Reason != SpeedFailPath || dialed {
		t.Fatalf("%+v dialed=%v", x, dialed)
	}
	// A leg that is not the relay's.
	x = SpeedTester{Dial: d, Run: &routeRunner{dev: "m03"}}.Test(context.Background(), c, r, c.Relays[1].Legs[0], 1)
	if x.OK || x.Reason != SpeedFailPath || dialed {
		t.Fatalf("foreign leg: %+v", x)
	}
	// Connect fails: not measured, no slow sample.
	x = SpeedTester{Dial: d, Run: &routeRunner{dev: "m02"}}.Test(context.Background(), c, r, r.Legs[0], 1)
	if x.OK || x.Reason != SpeedFailConnect || x.Kbps != 0 {
		t.Fatalf("%+v", x)
	}
}

func TestSpeedTestShortAndTimeout(t *testing.T) {
	c := smallConfig(t)
	r := c.Relays[1]
	var rec dialRec
	// Closed after 100 KiB: not measured.
	x := SpeedTester{Dial: loopDial(server(t, 100<<10, 0), &rec), Run: &routeRunner{dev: "m03"}}.Test(context.Background(), c, r, r.Legs[0], 1)
	if x.OK || x.Reason != SpeedFailShort {
		t.Fatalf("%+v", x)
	}
	// Throttled: times out with more than 1 MiB received: a valid slow sample.
	// The burst guarantees >1 MiB arrives early even on a loaded machine;
	// the trickle keeps the transfer steady (no stall) until the deadline.
	x = SpeedTester{Dial: loopDial(trickleServer(t, 3<<19, 20*time.Millisecond), &rec), Run: &routeRunner{dev: "m03"}, Timeout: 600 * time.Millisecond}.Test(context.Background(), c, r, r.Legs[0], 1)
	if !x.OK || x.Bytes >= 5<<20 || x.Bytes < 1<<20 {
		t.Fatalf("slow: %+v", x)
	}
}

func TestSpeedScheduleStaggeredOneAtATime(t *testing.T) {
	c := speedConfig(t, nil) // 1800 s, two relays
	l := &SpeedLog{Version: 1, Started: 1000, Relays: map[string]*SpeedRelayLog{}}
	if id := DueRelay(c, l, 1000); id != "access" {
		t.Fatalf("first due %q", id)
	}
	l.relay("access").LastAttempt, l.LastRun = 1000, 1000
	l.relay("access").Samples = []SpeedSample{{At: 1000, OK: true, Kbps: 1}}
	if id := DueRelay(c, l, 1000+899); id != "" {
		t.Fatalf("access2 before its slot: %q", id)
	}
	if id := DueRelay(c, l, 1000+900); id != "access2" {
		t.Fatalf("access2 at +900: %q", id)
	}
	l.relay("access2").LastAttempt, l.LastRun = 1900, 1900
	l.relay("access2").Samples = []SpeedSample{{At: 1900, Reason: SpeedFailConnect}}
	// access2 failed: retried after interval/6 = 300 s, but the global gap
	// (450 s) keeps the tests apart.
	if id := DueRelay(c, l, 2200); id != "" {
		t.Fatalf("gap not kept: %q", id)
	}
	if id := DueRelay(c, l, 2350); id != "access2" {
		t.Fatalf("retry %q", id)
	}
	off := speedConfig(t, func(p *model.PathQuality) { p.SpeedTestOff = true })
	if DueRelay(off, l, 99999) != "" {
		t.Fatal("tests while off")
	}
	dis := speedConfig(t, func(p *model.PathQuality) { p.Overrides = []model.RelayOverride{{Relay: "access", Disabled: true}} })
	if id := DueRelay(dis, &SpeedLog{Started: 1, Relays: map[string]*SpeedRelayLog{}}, 99999); id != "access2" {
		t.Fatalf("disabled relay tested: %q", id)
	}
}

func TestSpeedRunUnreachableIsNotMeasured(t *testing.T) {
	c := smallConfig(t)
	l := &SpeedLog{Version: 1, Relays: map[string]*SpeedRelayLog{}}
	dialed := false
	tester := SpeedTester{Dial: func(context.Context, Leg, uint32, int) (net.Conn, error) { dialed = true; return nil, errors.New("x") }, Run: &routeRunner{dev: "m02"}}
	id, ran := SpeedRun(context.Background(), c, l, 5000, tester, func(string) bool { return false }, nil)
	if !ran || id != "access" || dialed {
		t.Fatal("unreachable relay dialed")
	}
	x := l.Relays["access"].Samples[0]
	if x.OK || x.Reason != SpeedFailUnreachable || l.Relays["access"].Verdict.State != QoSUnknown {
		t.Fatalf("%+v %+v", x, l.Relays["access"].Verdict)
	}
}

func TestSpeedTestCommandRefusesArgumentsAndLocks(t *testing.T) {
	var out, errb bytes.Buffer
	if RunSpeedTest([]string{"--url", "http://x"}, &out, &errb) != 2 {
		t.Fatal("unknown flag accepted")
	}
	if RunSpeedTest([]string{"extra"}, &out, &errb) != 2 {
		t.Fatal("positional argument accepted")
	}
	dir := t.TempDir()
	lock := filepath.Join(dir, "l")
	unlock, ok, err := lockFile(lock)
	if err != nil || !ok {
		t.Fatal(err)
	}
	if _, ok2, _ := lockFile(lock); ok2 {
		t.Fatal("second lock taken while held")
	}
	unlock()
	// A lock of a dead process is taken over.
	os.WriteFile(lock, []byte("999999\n"), 0o600)
	if u, ok, _ := lockFile(lock); !ok {
		t.Fatal("stale lock not taken over")
	} else {
		u()
	}
}

// stallServer sends n bytes, then keeps the connection open without sending.
func stallServer(t *testing.T, n int) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	t.Cleanup(func() { close(done); ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_, _ = c.Write(make([]byte, n))
				<-done
			}(c)
		}
	}()
	return ln.Addr().String()
}

// QA regression: a transfer that delivers part of the file and then stalls
// is "not measured", never a slow sample, so two such tests cannot throttle.
func TestSpeedTestPartialThenStallIsNotMeasured(t *testing.T) {
	old := speedStall
	speedStall = 200 * time.Millisecond
	t.Cleanup(func() { speedStall = old })
	c := testConfig(t, nil)
	c.Settings.SpeedTestMB = 5
	r := c.Relays[1]
	var rec dialRec
	for i := 0; i < 2; i++ {
		x := SpeedTester{Dial: loopDial(stallServer(t, 2<<20), &rec), Run: &routeRunner{dev: "m03"}, Timeout: 2 * time.Second}.Test(context.Background(), c, r, r.Legs[0], 1)
		if x.OK {
			t.Fatalf("partial-then-stall counted as a sample: %+v", x)
		}
	}
}

// Review regression: the stall reason is "short" (not measured) and two
// such results neither start nor extend a slow streak; a throttled path
// that reaches the deadline with less than 1 MiB is not measured either;
// a connection reset mid-transfer is a read error, not a slow sample.
func TestSpeedTestStallAndResetDoNotThrottle(t *testing.T) {
	old := speedStall
	speedStall = 200 * time.Millisecond
	t.Cleanup(func() { speedStall = old })
	c := smallConfig(t)
	r := c.Relays[1]
	var rec dialRec
	v := &QoSVerdict{}
	var samples []SpeedSample
	for i := 0; i < 2; i++ {
		x := SpeedTester{Dial: loopDial(stallServer(t, 2<<20), &rec), Run: &routeRunner{dev: "m03"}, Timeout: 2 * time.Second}.Test(context.Background(), c, r, r.Legs[0], int64(100+i))
		if x.OK || x.Reason != SpeedFailShort {
			t.Fatalf("stall: %+v", x)
		}
		x = FoldSample(v, samples, x, c.Settings, 200000)
		samples = append(samples, x)
	}
	if v.State == QoSThrottled || v.LowStreak != 0 {
		t.Fatalf("stalls moved the verdict: %+v", v)
	}
	// Slow and steady but under 1 MiB by the deadline: not measured.
	x := SpeedTester{Dial: loopDial(server(t, 5<<20, 100*time.Millisecond), &rec), Run: &routeRunner{dev: "m03"}, Timeout: 500 * time.Millisecond}.Test(context.Background(), c, r, r.Legs[0], 1)
	if x.OK || x.Reason != SpeedFailShort {
		t.Fatalf("under 1 MiB at the deadline: %+v", x)
	}
	// Reset after part of the file: a read error, not measured.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		cn, err := ln.Accept()
		if err != nil {
			return
		}
		_, _ = cn.Write(make([]byte, 2<<20))
		if tc, ok := cn.(*net.TCPConn); ok {
			_ = tc.SetLinger(0)
		}
		cn.Close()
	}()
	x = SpeedTester{Dial: loopDial(ln.Addr().String(), &rec), Run: &routeRunner{dev: "m03"}, Timeout: 2 * time.Second}.Test(context.Background(), c, r, r.Legs[0], 1)
	if x.OK {
		t.Fatalf("reset counted as a sample: %+v", x)
	}
}
