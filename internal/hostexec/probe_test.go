package hostexec

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/radowitz/meridian/internal/probe"
	"github.com/radowitz/meridian/internal/unlock"
)

func goodProbe() ProbeRequest {
	return ProbeRequest{
		RequestID: "job-1/hk-resi/ipv4", ExitID: "hk-resi", Family: "ipv4", Mark: 0x103,
		TransitV4: "10.66.200.12", TransitV6: "fd66:0:0:ff::c", Resolver: "fd66:0:0:12::2",
		Region: "hk", ExpectAddr: "203.0.113.5", Services: []string{"auto-netflix", "auto-disney"},
	}
}

func TestValidateProbeIsClosed(t *testing.T) {
	if err := ValidateProbe(goodProbe()); err != nil {
		t.Fatal(err)
	}
	bad := map[string]func(*ProbeRequest){
		"family any":           func(r *ProbeRequest) { r.Family = "any" },
		"family empty":         func(r *ProbeRequest) { r.Family = "" },
		"mark domestic":        func(r *ProbeRequest) { r.Mark = 0x64 },
		"mark underlay":        func(r *ProbeRequest) { r.Mark = 0x4d72 },
		"mark beyond exits":    func(r *ProbeRequest) { r.Mark = 0x141 },
		"transit4 lan":         func(r *ProbeRequest) { r.TransitV4 = "192.168.100.88" },
		"transit4 public":      func(r *ProbeRequest) { r.TransitV4 = "1.1.1.1" },
		"transit6 outside":     func(r *ProbeRequest) { r.TransitV6 = "fd66:0:1::1" },
		"resolver public":      func(r *ProbeRequest) { r.Resolver = "2001:4860:4860::8888" },
		"resolver v4":          func(r *ProbeRequest) { r.Resolver = "223.5.5.5" },
		"resolver transit":     func(r *ProbeRequest) { r.Resolver = "fd66:0:0:ff::1" },
		"expect private":       func(r *ProbeRequest) { r.ExpectAddr = "192.168.1.1" },
		"expect wrong family":  func(r *ProbeRequest) { r.ExpectAddr = "2001:db8::1" },
		"no egress identity":   func(r *ProbeRequest) { r.Region, r.ExpectAddr = "", "" },
		"region shaped":        func(r *ProbeRequest) { r.Region = "hk;rm" },
		"url as service":       func(r *ProbeRequest) { r.Services = []string{"https://evil.example/"} },
		"service w/o adapter":  func(r *ProbeRequest) { r.Services = []string{"auto-bahamut"} },
		"duplicate service":    func(r *ProbeRequest) { r.Services = []string{"auto-netflix", "auto-netflix"} },
		"no services":          func(r *ProbeRequest) { r.Services = nil },
		"exit id with slash":   func(r *ProbeRequest) { r.ExitID = "../etc" },
		"request id shell":     func(r *ProbeRequest) { r.RequestID = "x; rm -rf /" },
		"too many services":    func(r *ProbeRequest) { r.Services = make([]string, 17) },
		"transit6 is v4mapped": func(r *ProbeRequest) { r.TransitV6 = "::ffff:10.66.200.12" },
	}
	for name, mut := range bad {
		r := goodProbe()
		mut(&r)
		if err := ValidateProbe(r); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// probeRunner answers the two read-only ip commands the probe uses.
type probeRunner struct {
	mu   sync.Mutex
	lo4  string
	lo6  string
	dev  string
	cmds []string
}

func (p *probeRunner) Run(_ context.Context, prog string, args ...string) (string, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	line := prog + " " + strings.Join(args, " ")
	p.cmds = append(p.cmds, line)
	switch {
	case strings.HasPrefix(line, "ip -4 -o addr show dev lo"):
		return "1: lo    inet 127.0.0.1/8 scope host lo\n" + p.lo4, nil
	case strings.HasPrefix(line, "ip -6 -o addr show dev lo"):
		return "1: lo    inet6 ::1/128 scope host\n" + p.lo6, nil
	case strings.Contains(line, "route get"):
		if p.dev == "" {
			return "RTNETLINK answers: Network is unreachable", errors.New("exit status 2")
		}
		return args[3] + " from " + args[5] + " dev " + p.dev + " table 102 mark 0x103 uid 0\n    cache", nil
	}
	return "", errors.New("unexpected " + line)
}

func installedLo() *probeRunner {
	return &probeRunner{
		lo4: "1: lo    inet 10.66.200.12/32 scope global lo\\       valid_lft forever preferred_lft forever\n",
		lo6: "1: lo    inet6 fd66:0:0:ff::c/128 scope global \\       valid_lft forever preferred_lft forever\n",
		dev: "m00",
	}
}

// blockNet is a probe.Network whose every call waits for the context.
type blockNet struct {
	started chan struct{}
	once    sync.Once
}

func (b *blockNet) Resolve(ctx context.Context, _ string) ([]netip.Addr, error) {
	b.once.Do(func() { close(b.started) })
	<-ctx.Done()
	return nil, ctx.Err()
}
func (b *blockNet) Route(context.Context, netip.Addr) (string, error) { return "m00", nil }
func (b *blockNet) Dial(ctx context.Context, _ netip.AddrPort) (net.Conn, error) {
	<-ctx.Done()
	return nil, ctx.Err()
}

func TestProbeRefusesExitNotInstalled(t *testing.T) {
	r := &probeRunner{dev: "m00"} // lo has no transit addresses
	called := false
	a := &Agent{Token: func() (string, error) { return "x", nil }, Runner: r,
		ProbeNetwork: func(ProbeRequest, probe.Network) probe.Network {
			called = true
			return &blockNet{started: make(chan struct{})}
		}}
	rep, code := a.Probe(context.Background(), goodProbe())
	if code != http.StatusOK || called {
		t.Fatalf("code %d, network used=%v", code, called)
	}
	for _, res := range rep.Results {
		if res.Category != probe.CatFailed || !strings.Contains(res.Error, "中转地址") {
			t.Fatalf("%+v", res)
		}
	}
}

func TestHostRouteCheck(t *testing.T) {
	r := installedLo()
	a := &Agent{Runner: r}
	h := &hostNet{a: a, pin: probe.Pinned{Mark: 0x103}, src: netip.MustParseAddr("10.66.200.12"), fam: unlock.FamilyIPv4}
	dev, err := h.Route(context.Background(), netip.MustParseAddr("203.0.113.80"))
	if err != nil || dev != "m00" {
		t.Fatal(dev, err)
	}
	if got := r.cmds[len(r.cmds)-1]; got != "ip -4 route get 203.0.113.80 from 10.66.200.12 mark 0x103" {
		t.Fatalf("route query: %q", got)
	}
	r.dev = ""
	if _, err := h.Route(context.Background(), netip.MustParseAddr("203.0.113.80")); err == nil {
		t.Fatal("unreachable must be an error, not a fallback")
	}
	r.dev = "eth0"
	dev, _ = h.Route(context.Background(), netip.MustParseAddr("203.0.113.80"))
	if ValidInterface(dev) {
		t.Fatal("eth0 must not count as a Meridian tunnel")
	}
}

func TestActionPreemptsProbeAndProbeNeverBlocksAction(t *testing.T) {
	f := newFakeHost()
	f.links["m02"], f.links["m02w"] = true, true
	f.nft["inet meridian"], f.nft["inet meridian_guard"] = true, true
	pr := installedLo()
	bn := &blockNet{started: make(chan struct{})}
	a := newAgent(f)
	a.Runner = runnerMux{f, pr}
	a.ProbeNetwork = func(ProbeRequest, probe.Network) probe.Network { return bn }
	a.ProbeTargetTimeout = time.Minute

	type out struct {
		rep  probe.Report
		code int
	}
	done := make(chan out, 1)
	go func() {
		rep, code := a.Probe(context.Background(), goodProbe())
		done <- out{rep, code}
	}()
	select {
	case <-bn.started:
	case o := <-done:
		t.Fatalf("probe did not start: %+v", o)
	}
	start := time.Now()
	res, code := a.Execute(context.Background(), Request{Action: ActionActivate, RequestID: "a1", Resources: gwResources()})
	if code != http.StatusOK || !res.OK {
		t.Fatalf("activate: %d %+v", code, res)
	}
	if time.Since(start) > 10*time.Second {
		t.Fatal("activate waited for the probe")
	}
	select {
	case o := <-done:
		if o.code != http.StatusOK || o.rep.Egress.Confirmed {
			t.Fatalf("%+v", o)
		}
		for _, r := range o.rep.Results {
			if r.Category != probe.CatFailed {
				t.Fatalf("a preempted probe must not report a verdict: %+v", r)
			}
		}
	case <-time.After(5 * time.Second):
		t.Fatal("probe not cancelled by the action")
	}
}

func TestProbeRefusedDuringActionAndCapped(t *testing.T) {
	f := newFakeHost()
	f.block["systemctl restart meridian.service"] = true
	pr := installedLo()
	a := newAgent(f)
	a.Runner = runnerMux{f, pr}
	a.UpTimeout = 2 * time.Second
	actDone := make(chan struct{})
	go func() {
		a.Execute(context.Background(), Request{Action: ActionActivate, RequestID: "a2", Resources: gwResources()})
		close(actDone)
	}()
	deadline := time.Now().Add(2 * time.Second)
	for f.ran("systemctl restart meridian.service") == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if _, code := a.Probe(context.Background(), goodProbe()); code != http.StatusServiceUnavailable {
		t.Fatalf("probe during an activate: %d", code)
	}
	<-actDone

	// health only reads: it does not refuse or cancel probes.
	bn := &blockNet{started: make(chan struct{})}
	a.ProbeNetwork = func(ProbeRequest, probe.Network) probe.Network { return bn }
	a.MaxProbes = 1
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { a.Probe(ctx, goodProbe()); close(done) }()
	select {
	case <-bn.started:
	case <-time.After(5 * time.Second):
		t.Fatal("probe did not start")
	}
	if _, code := a.Execute(context.Background(), Request{Action: ActionHealth, RequestID: "h1"}); code != http.StatusOK {
		t.Fatal("health refused while probing")
	}
	select {
	case <-done:
		t.Fatal("health cancelled a probe")
	default:
	}
	if _, code := a.Probe(context.Background(), goodProbe()); code != http.StatusServiceUnavailable {
		t.Fatalf("MaxProbes not enforced: %d", code)
	}
	// Caller going away cancels the probe.
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("probe ignored caller cancellation")
	}
}

// runnerMux sends the probe's ip queries to pr and everything else to f.
type runnerMux struct {
	f  *fakeHost
	pr *probeRunner
}

func (m runnerMux) Run(ctx context.Context, prog string, args ...string) (string, error) {
	line := prog + " " + strings.Join(args, " ")
	if strings.Contains(line, "addr show dev lo") || strings.Contains(line, "route get") {
		return m.pr.Run(ctx, prog, args...)
	}
	return m.f.Run(ctx, prog, args...)
}

func TestProbeEndpointAuthAndStrictBody(t *testing.T) {
	sock := shortSocket(t)
	l, err := ListenUnix(sock)
	if err != nil {
		t.Fatal(err)
	}
	tok := strings.Repeat("k", 64)
	a := &Agent{Token: func() (string, error) { return tok, nil }, Runner: &probeRunner{dev: "m00"}}
	go func() { _ = a.Serve(l) }()
	t.Cleanup(func() { l.Close() })
	hc := unixHTTP(sock)
	post := func(auth string, body []byte) int {
		req, _ := http.NewRequest(http.MethodPost, "http://x/v1/probe", bytes.NewReader(body))
		if auth != "" {
			req.Header.Set("Authorization", "Bearer "+auth)
		}
		resp, err := hc.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}
	good, _ := json.Marshal(goodProbe())
	if code := post("", good); code != http.StatusUnauthorized {
		t.Fatalf("no token: %d", code)
	}
	var m map[string]any
	_ = json.Unmarshal(good, &m)
	m["url"] = "https://evil.example/"
	extra, _ := json.Marshal(m)
	if code := post(tok, extra); code != http.StatusBadRequest {
		t.Fatalf("unknown field accepted: %d", code)
	}
	m = map[string]any{}
	_ = json.Unmarshal(good, &m)
	m["command"] = "curl"
	extra, _ = json.Marshal(m)
	if code := post(tok, extra); code != http.StatusBadRequest {
		t.Fatalf("command field accepted: %d", code)
	}

	// The client round trip: not installed → a report of failures, no error.
	tf := filepath.Join(t.TempDir(), "tok")
	if err := os.WriteFile(tf, []byte(tok+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	c := &Client{Socket: sock, TokenFile: tf}
	rep, err := c.Probe(context.Background(), goodProbe())
	if err != nil || len(rep.Results) != 2 || rep.Results[0].Category != probe.CatFailed {
		t.Fatalf("%v %+v", err, rep)
	}
	if _, err := (&Client{Socket: filepath.Join(t.TempDir(), "none.sock"), TokenFile: tf}).Probe(context.Background(), goodProbe()); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("missing agent: %v", err)
	}
}
