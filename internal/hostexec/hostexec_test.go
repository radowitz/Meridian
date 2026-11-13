package hostexec

import (
	"context"
	"errors"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeHost is a Runner that models just enough host state: loaded units,
// links, nft tables and an optional SmartDNS provider. It records every
// command and never runs anything.
type fakeHost struct {
	mu       sync.Mutex
	cmds     []string
	units    map[string]string // unit -> is-active state; present means installed
	enabled  map[string]bool
	links    map[string]bool
	nft      map[string]bool
	dns      string // "", "unit", "container"
	fail     map[string]bool
	block    map[string]bool // command prefix blocks until ctx is done
	delay    time.Duration
	inflight int
	maxIn    int
}

func newFakeHost() *fakeHost {
	return &fakeHost{
		units:   map[string]string{"meridian.service": "inactive"},
		enabled: map[string]bool{},
		links:   map[string]bool{}, nft: map[string]bool{},
		fail: map[string]bool{}, block: map[string]bool{},
	}
}

func (f *fakeHost) Run(ctx context.Context, prog string, args ...string) (string, error) {
	line := prog + " " + strings.Join(args, " ")
	f.mu.Lock()
	f.cmds = append(f.cmds, line)
	f.inflight++
	if f.inflight > f.maxIn {
		f.maxIn = f.inflight
	}
	delay := f.delay
	var blocked bool
	for p := range f.block {
		blocked = blocked || strings.HasPrefix(line, p)
	}
	f.mu.Unlock()
	defer func() { f.mu.Lock(); f.inflight--; f.mu.Unlock() }()
	if blocked {
		<-ctx.Done()
		return "", ctx.Err()
	}
	if delay > 0 {
		time.Sleep(delay)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	for p := range f.fail {
		if strings.HasPrefix(line, p) {
			return "boom: " + line, errors.New("exit status 1")
		}
	}
	switch {
	case prog == "systemctl" && args[0] == "cat":
		if _, ok := f.units[args[1]]; ok || (args[1] == "smartdns.service" && f.dns == "unit") {
			return "[Unit]", nil
		}
		return "No files found", errors.New("exit status 1")
	case prog == "systemctl" && args[0] == "restart":
		f.units[args[1]] = "active"
	case prog == "systemctl" && args[0] == "is-enabled":
		if !f.enabled[args[len(args)-1]] {
			return "disabled", errors.New("exit status 1")
		}
		return "enabled", nil
	case prog == "systemctl" && args[0] == "enable":
		f.enabled[args[1]] = true
	case prog == "systemctl" && args[0] == "is-active" && args[1] == "--quiet":
		if f.units[args[2]] != "active" {
			return "", errors.New("exit status 3")
		}
	case prog == "systemctl" && args[0] == "is-active":
		st, ok := f.units[args[1]]
		if !ok {
			st = "inactive"
		}
		if st != "active" {
			return st, errors.New("exit status 3")
		}
		return st, nil
	case prog == "systemctl" && args[0] == "disable":
		delete(f.units, args[len(args)-1])
		delete(f.enabled, args[len(args)-1])
	case prog == "ip" && args[0] == "link" && args[1] == "show":
		if !f.links[args[3]] {
			return "does not exist", errors.New("exit status 1")
		}
	case prog == "ip" && args[0] == "link" && args[1] == "del":
		delete(f.links, args[3])
	case prog == "ip" && len(args) > 1 && args[1] == "rule":
		return "", errors.New("no more rules")
	case prog == "nft" && args[0] == "list":
		if !f.nft[args[2]+" "+args[3]] {
			return "No such file", errors.New("exit status 1")
		}
	case prog == "nft" && args[0] == "delete":
		delete(f.nft, args[2]+" "+args[3])
	case prog == "docker" && args[0] == "inspect":
		if f.dns != "container" {
			return "", errors.New("no such container")
		}
		return "running", nil
	}
	return "", nil
}

func (f *fakeHost) commands() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.cmds...)
}

func (f *fakeHost) ran(prefix string) int {
	n := 0
	for _, c := range f.commands() {
		if strings.HasPrefix(c, prefix) {
			n++
		}
	}
	return n
}

func newAgent(f *fakeHost) *Agent {
	return &Agent{Token: func() (string, error) { return strings.Repeat("t", 64), nil }, Runner: f}
}

func gwResources() Resources {
	return Resources{
		Units:       []string{"meridian-failover.service"},
		Interfaces:  []string{"m02", "m02w"},
		NFTTables:   []string{"inet meridian", "inet meridian_guard"},
		RouteTables: []int{100, 102, 150},
	}
}

func TestValidateRejectsAnythingButManagedNames(t *testing.T) {
	ok := Request{Action: ActionActivate, RequestID: "tx-1/0/fwd-activate", Resources: gwResources()}
	if err := Validate(ok); err != nil {
		t.Fatal(err)
	}
	bad := []Request{
		{Action: "run", RequestID: "x"},
		{Action: "exec", RequestID: "x"},
		{Action: ActionHealth, RequestID: "has space"},
		{Action: ActionHealth, RequestID: ""},
	}
	for _, u := range []string{"sshd.service", "../../etc/passwd", "/etc/systemd/system/x.service", "meridian.service",
		"meridian-host.service", "meridian-guard.service", "meridian-x.service; rm -rf /", "meridian-$(id).service",
		"docker.service", "wstunnel-client-A.service", "meridian-x.socket"} {
		bad = append(bad, Request{Action: ActionActivate, RequestID: "x", Resources: Resources{Units: []string{u}}})
	}
	for _, i := range []string{"eth0", "lo", "m00; reboot", "wg0", "m0", "docker0", "../m00"} {
		bad = append(bad, Request{Action: ActionRollback, RequestID: "x", Resources: Resources{Interfaces: []string{i}}})
	}
	for _, n := range []string{"inet filter", "ip nat", "inet meridian; flush ruleset", "meridian"} {
		bad = append(bad, Request{Action: ActionRollback, RequestID: "x", Resources: Resources{NFTTables: []string{n}}})
	}
	for _, n := range []int{0, 99, 253, 254, 255, 1000} {
		bad = append(bad, Request{Action: ActionRollback, RequestID: "x", Resources: Resources{RouteTables: []int{n}}})
	}
	bad = append(bad,
		Request{Action: ActionRollback, RequestID: "x", Resources: Resources{DNS: true}},
		Request{Action: ActionActivate, RequestID: "x", Resources: Resources{Interfaces: []string{"m00", "m00"}}},
	)
	f := newFakeHost()
	a := newAgent(f)
	for _, req := range bad {
		if err := Validate(req); err == nil {
			t.Errorf("accepted %+v", req)
		}
		if _, code := a.Execute(context.Background(), req); code != http.StatusBadRequest {
			t.Errorf("Execute(%+v) = %d", req, code)
		}
	}
	if n := len(f.commands()); n != 0 {
		t.Fatalf("a refused request ran %d commands", n)
	}
}

// The request body is decoded strictly: no extra fields (e.g. a "command"
// or "path"), so the parameter set cannot be widened by a caller.
func TestAgentRejectsUnknownFieldsAndBadToken(t *testing.T) {
	f := newFakeHost()
	a := newAgent(f)
	sock := shortSocket(t)
	l, err := ListenUnix(sock)
	if err != nil {
		t.Fatal(err)
	}
	go a.Serve(l)
	t.Cleanup(func() { l.Close() })
	if st, err := os.Stat(sock); err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("socket mode %v %v", st.Mode(), err)
	}
	hc := unixHTTP(sock)
	post := func(tok, body string) int {
		req, _ := http.NewRequest(http.MethodPost, "http://x/v1/action", strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+tok)
		resp, err := hc.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}
	good := strings.Repeat("t", 64)
	if c := post("wrong", `{"action":"health","request_id":"a"}`); c != http.StatusUnauthorized {
		t.Fatalf("bad token: %d", c)
	}
	if c := post(good, `{"action":"health","request_id":"a","command":"id"}`); c != http.StatusBadRequest {
		t.Fatalf("unknown field: %d", c)
	}
	if c := post(good, `{"action":"health","request_id":"a","resources":{"path":"/etc/shadow"}}`); c != http.StatusBadRequest {
		t.Fatalf("unknown nested field: %d", c)
	}
	if c := post(good, `{"action":"health","request_id":"a"}`); c != http.StatusOK {
		t.Fatalf("good request: %d", c)
	}
	if len(f.commands()) != 0 {
		t.Fatal("refused requests ran commands")
	}
}

func TestClientUnavailableIsExplicit(t *testing.T) {
	dir := t.TempDir()
	c := &Client{Socket: filepath.Join(dir, "none.sock"), TokenFile: filepath.Join(dir, "tok")}
	_, err := c.Do(context.Background(), Request{Action: ActionHealth, RequestID: "p"})
	if !errors.Is(err, ErrUnavailable) {
		t.Fatalf("missing socket: %v", err)
	}
	sock := shortSocket(t)
	l, err := ListenUnix(sock)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	c = &Client{Socket: sock, TokenFile: filepath.Join(dir, "tok")}
	if _, err := c.Do(context.Background(), Request{Action: ActionHealth, RequestID: "p"}); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("missing token: %v", err)
	}
}

func TestClientRoundTripAndBadToken(t *testing.T) {
	f := newFakeHost()
	a := newAgent(f)
	sock := shortSocket(t)
	l, err := ListenUnix(sock)
	if err != nil {
		t.Fatal(err)
	}
	go a.Serve(l)
	t.Cleanup(func() { l.Close() })
	tok := filepath.Join(t.TempDir(), "tok")
	if err := os.WriteFile(tok, []byte(strings.Repeat("t", 64)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	c := &Client{Socket: sock, TokenFile: tok, Backoff: time.Millisecond}
	res, err := c.Do(context.Background(), Request{Action: ActionHealth, RequestID: "probe-1"})
	if err != nil || !res.OK {
		t.Fatal(res, err)
	}
	if err := os.WriteFile(tok, []byte(strings.Repeat("u", 64)), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Do(context.Background(), Request{Action: ActionHealth, RequestID: "probe-2"}); err == nil || !strings.Contains(err.Error(), "401") {
		t.Fatalf("wrong token accepted: %v", err)
	}
}

func TestActivateRunsFixedSequenceAndHealth(t *testing.T) {
	f := newFakeHost()
	f.units["meridian-failover.service"] = "inactive"
	f.links["m02"], f.links["m02w"] = true, true
	f.nft["inet meridian"], f.nft["inet meridian_guard"] = true, true
	a := newAgent(f)
	res, code := a.Execute(context.Background(), Request{Action: ActionActivate, RequestID: "r1", Resources: gwResources()})
	if code != 200 || !res.OK {
		t.Fatalf("%d %+v", code, res)
	}
	want := []string{
		"systemctl cat meridian.service",
		"systemctl daemon-reload",
		"systemctl enable meridian.service",
		"systemctl reset-failed meridian.service",
		"systemctl restart meridian.service",
		"systemctl enable meridian-failover.service",
		"systemctl restart meridian-failover.service",
		"systemctl is-active meridian.service",
	}
	cmds := f.commands()
	for i, w := range want {
		if i >= len(cmds) || cmds[i] != w {
			t.Fatalf("command %d = %q, want %q\nall: %v", i, at(cmds, i), w, cmds)
		}
	}
	// Health is sampled twice; both pass.
	if f.ran("ip link show dev m02w") != 2 || f.ran("nft list table inet meridian_guard") != 2 {
		t.Fatalf("health not sampled twice: %v", cmds)
	}
	for _, c := range cmds {
		if strings.Contains(c, "sh -c") || strings.HasPrefix(c, "bash") || strings.HasPrefix(c, "sh ") {
			t.Fatalf("agent ran a shell: %s", c)
		}
	}
}

func at(s []string, i int) string {
	if i < len(s) {
		return s[i]
	}
	return "<none>"
}

func TestActivateStopsAtFirstFailure(t *testing.T) {
	f := newFakeHost()
	f.fail["systemctl restart meridian.service"] = true
	a := newAgent(f)
	res, _ := a.Execute(context.Background(), Request{Action: ActionActivate, RequestID: "r1", Resources: gwResources()})
	if res.OK || !strings.Contains(res.Error, "meridian.service") {
		t.Fatalf("%+v", res)
	}
	if f.ran("systemctl restart meridian-failover.service") != 0 || f.ran("systemctl is-active") != 0 {
		t.Fatal("continued after a failed step")
	}
	if f.ran("journalctl -u meridian.service") != 1 {
		t.Fatal("failure detail should include the unit journal")
	}
	// A pending boot-style automatic retry (RestartForceExitStatus) must
	// not run meridian-up.sh concurrently with the compensation.
	if f.ran("systemctl stop meridian.service") != 1 {
		t.Fatalf("failed activation did not cancel the unit's retry: %v", f.commands())
	}
}

func TestActivateWithoutCoreUnitFails(t *testing.T) {
	f := newFakeHost()
	delete(f.units, "meridian.service")
	res, _ := newAgent(f).Execute(context.Background(), Request{Action: ActionActivate, RequestID: "r1", Resources: gwResources()})
	if res.OK || !strings.Contains(res.Error, "install.sh") {
		t.Fatalf("%+v", res)
	}
	if f.ran("systemctl daemon-reload") != 0 {
		t.Fatal("continued without meridian.service")
	}
}

func TestActivateTimesOut(t *testing.T) {
	f := newFakeHost()
	f.block["systemctl restart meridian.service"] = true
	a := newAgent(f)
	a.UpTimeout = 50 * time.Millisecond
	start := time.Now()
	res, _ := a.Execute(context.Background(), Request{Action: ActionActivate, RequestID: "r1", Resources: gwResources()})
	if res.OK || !strings.Contains(res.Error, "超时") {
		t.Fatalf("%+v", res)
	}
	if time.Since(start) > 5*time.Second {
		t.Fatal("timeout not enforced")
	}
	a2 := newAgent(newFakeHost())
	a2.ActionTimeout = 30 * time.Millisecond
	f2 := a2.Runner.(*fakeHost)
	f2.block["systemctl daemon-reload"] = true
	res, _ = a2.Execute(context.Background(), Request{Action: ActionActivate, RequestID: "r2", Resources: gwResources()})
	if res.OK {
		t.Fatal("action deadline not enforced")
	}
}

func TestHealthFailureFailsActivate(t *testing.T) {
	f := newFakeHost()
	f.links["m02"], f.links["m02w"] = true, true
	f.nft["inet meridian"], f.nft["inet meridian_guard"] = true, true
	f.units["meridian-failover.service"] = "inactive"
	// restart succeeds but the unit then reports failed.
	a := newAgent(f)
	a.Runner = runnerFunc(func(ctx context.Context, prog string, args ...string) (string, error) {
		out, err := f.Run(ctx, prog, args...)
		if prog == "systemctl" && args[0] == "is-active" && args[1] == "meridian-failover.service" {
			return "failed", errors.New("exit status 3")
		}
		return out, err
	})
	res, _ := a.Execute(context.Background(), Request{Action: ActionActivate, RequestID: "r1", Resources: gwResources()})
	if res.OK || !strings.Contains(res.Error, "health meridian-failover.service") {
		t.Fatalf("%+v", res)
	}
}

type runnerFunc func(ctx context.Context, prog string, args ...string) (string, error)

func (r runnerFunc) Run(ctx context.Context, prog string, args ...string) (string, error) {
	return r(ctx, prog, args...)
}

func TestActionsAreSerialised(t *testing.T) {
	f := newFakeHost()
	f.delay = 5 * time.Millisecond
	a := newAgent(f)
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			a.Execute(context.Background(), Request{Action: ActionHealth, RequestID: "h" + string(rune('a'+i)), Resources: Resources{Interfaces: []string{"m00"}}})
		}(i)
	}
	wg.Wait()
	if f.maxIn != 1 {
		t.Fatalf("%d commands ran concurrently", f.maxIn)
	}
}

func TestLockWaitTimesOut(t *testing.T) {
	f := newFakeHost()
	f.block["systemctl daemon-reload"] = true
	a := newAgent(f)
	a.LockWait = 20 * time.Millisecond
	a.ActionTimeout = 300 * time.Millisecond
	done := make(chan struct{})
	go func() {
		a.Execute(context.Background(), Request{Action: ActionActivate, RequestID: "slow", Resources: gwResources()})
		close(done)
	}()
	time.Sleep(50 * time.Millisecond)
	if _, code := a.Execute(context.Background(), Request{Action: ActionHealth, RequestID: "second"}); code != http.StatusServiceUnavailable {
		t.Fatalf("second action while busy: %d", code)
	}
	<-done
}

func TestRequestIDReplayAndConflict(t *testing.T) {
	f := newFakeHost()
	a := newAgent(f)
	req := Request{Action: ActionActivate, RequestID: "tx/0/fwd-activate", Resources: gwResources()}
	first, _ := a.Execute(context.Background(), req)
	n := len(f.commands())
	again, code := a.Execute(context.Background(), req)
	if code != 200 || !again.Replayed || again.OK != first.OK {
		t.Fatalf("replay: %d %+v", code, again)
	}
	if len(f.commands()) != n {
		t.Fatal("a replayed request executed again")
	}
	req.Resources.Units = nil
	if _, code := a.Execute(context.Background(), req); code != http.StatusConflict {
		t.Fatalf("same id, other params: %d", code)
	}
}

func TestRollbackOnlyTouchesLedgerResources(t *testing.T) {
	f := newFakeHost()
	a := newAgent(f)
	a.LedgerPath = filepath.Join(t.TempDir(), "ledger.json")
	// An m-named interface that exists but Meridian never activated.
	f.links["m09"] = true
	res, code := a.Execute(context.Background(), Request{Action: ActionRollback, RequestID: "x1", Resources: Resources{Interfaces: []string{"m09"}}})
	if code != http.StatusForbidden || !f.links["m09"] {
		t.Fatalf("unmanaged interface: %d %+v", code, res)
	}
	if f.ran("ip link del") != 0 {
		t.Fatal("deleted an unmanaged interface")
	}
	// A running unit with a Meridian-shaped name that Meridian never
	// activated is refused too.
	f.units["meridian-other.service"] = "active"
	if _, code := a.Execute(context.Background(), Request{Action: ActionRollback, RequestID: "x0", Resources: Resources{Units: []string{"meridian-other.service"}}}); code != http.StatusForbidden {
		t.Fatalf("unmanaged running unit: %d", code)
	}
	if f.ran("systemctl disable") != 0 {
		t.Fatal("disabled an unmanaged unit")
	}
	// Never activated and absent: skipped, not refused (compensation case).
	res, code = a.Execute(context.Background(), Request{Action: ActionRollback, RequestID: "x2", Resources: Resources{Interfaces: []string{"m07"}, Units: []string{"meridian-failover.service"}}})
	if code != 200 || !res.OK || len(res.Steps) != 2 || !res.Steps[0].Skipped {
		t.Fatalf("absent unmanaged: %d %+v", code, res)
	}
	// Activated once (ledger persisted), then removable; guard removal turns
	// forwarding off first.
	f.links["m09"] = true
	f.nft["inet meridian_guard"] = true
	if res, _ := a.Execute(context.Background(), Request{Action: ActionActivate, RequestID: "x3", Resources: Resources{Interfaces: []string{"m09"}, NFTTables: []string{"inet meridian_guard"}}}); !res.OK {
		t.Fatalf("%+v", res)
	}
	b := newAgent(f) // restarted agent reads the persisted ledger
	b.LedgerPath = a.LedgerPath
	f.nft["inet meridian_guard"] = true
	res, code = b.Execute(context.Background(), Request{Action: ActionRollback, RequestID: "x4", Resources: Resources{Interfaces: []string{"m09"}, NFTTables: []string{"inet meridian_guard"}}})
	if code != 200 || !res.OK || f.links["m09"] || f.nft["inet meridian_guard"] {
		t.Fatalf("managed removal: %d %+v", code, res)
	}
	cmds := strings.Join(f.commands(), "\n")
	off := strings.Index(cmds, "sysctl -w net.ipv4.ip_forward=0")
	del := strings.Index(cmds, "nft delete table inet meridian_guard")
	if off < 0 || del < off {
		t.Fatalf("forwarding must go off before the guard is deleted:\n%s", cmds)
	}
	// Idempotent: a second removal skips everything.
	res, _ = b.Execute(context.Background(), Request{Action: ActionRollback, RequestID: "x5", Resources: Resources{Interfaces: []string{"m09"}}})
	if !res.OK || !res.Steps[0].Skipped {
		t.Fatalf("repeat removal: %+v", res)
	}
}

func TestRollbackFailureIsReported(t *testing.T) {
	f := newFakeHost()
	a := newAgent(f)
	f.links["m02"] = true
	a.Execute(context.Background(), Request{Action: ActionActivate, RequestID: "a", Resources: Resources{Interfaces: []string{"m02"}}})
	f.fail["ip link del dev m02"] = true
	res, _ := a.Execute(context.Background(), Request{Action: ActionRollback, RequestID: "b", Resources: Resources{Interfaces: []string{"m02"}}})
	if res.OK || !strings.Contains(res.Error, "m02") {
		t.Fatalf("a failed removal must not report success: %+v", res)
	}
}

func TestDNSRestartProviders(t *testing.T) {
	for _, tc := range []struct{ dns, want string }{{"unit", "systemctl restart smartdns.service"}, {"container", "docker restart meridian-smartdns"}, {"", ""}} {
		f := newFakeHost()
		f.dns = tc.dns
		res, _ := newAgent(f).Execute(context.Background(), Request{Action: ActionActivate, RequestID: "d", Resources: Resources{DNS: true}})
		if tc.want == "" {
			if !res.OK || len(res.Warnings) == 0 {
				t.Fatalf("no resolver must warn, not fail silently: %+v", res)
			}
			continue
		}
		if f.ran(tc.want) != 1 {
			t.Fatalf("%s: %v", tc.dns, f.commands())
		}
	}
}

// A lost response is retried with the same request_id; the agent replays
// the first result, so the action ran once.
func TestClientRetryReplaysInsteadOfRerunning(t *testing.T) {
	f := newFakeHost()
	a := newAgent(f)
	sock := shortSocket(t)
	l, err := ListenUnix(sock)
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	drops := 1
	inner := a.Handler()
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		drop := drops > 0
		drops--
		mu.Unlock()
		if drop {
			inner.ServeHTTP(httptestDiscard{}, r) // executes, response lost
			hj, _ := w.(http.Hijacker)
			c, _, _ := hj.Hijack()
			c.Close()
			return
		}
		inner.ServeHTTP(w, r)
	})}
	go srv.Serve(l)
	t.Cleanup(func() { srv.Close() })
	tok := filepath.Join(t.TempDir(), "tok")
	os.WriteFile(tok, []byte(strings.Repeat("t", 64)), 0o600)
	c := &Client{Socket: sock, TokenFile: tok, Backoff: time.Millisecond}
	f.links["m02"] = true
	res, err := c.Do(context.Background(), Request{Action: ActionActivate, RequestID: "tx/0/a", Resources: Resources{Interfaces: []string{"m02"}}})
	if err != nil || !res.Replayed {
		t.Fatalf("%+v %v", res, err)
	}
	if f.ran("systemctl restart meridian.service") != 1 {
		t.Fatal("retry ran the action twice")
	}
}

type httptestDiscard struct{}

func (httptestDiscard) Header() http.Header         { return http.Header{} }
func (httptestDiscard) Write(b []byte) (int, error) { return len(b), nil }
func (httptestDiscard) WriteHeader(int)             {}

func TestTokenFileCreatedPrivate(t *testing.T) {
	p := filepath.Join(t.TempDir(), "d", "agent.token")
	tok, err := LoadOrCreateToken(p)
	if err != nil || len(tok) != 64 {
		t.Fatal(tok, err)
	}
	st, _ := os.Stat(p)
	if st.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v", st.Mode())
	}
	again, _ := LoadOrCreateToken(p)
	if again != tok {
		t.Fatal("token not reused")
	}
}

func shortSocket(t *testing.T) string {
	t.Helper()
	// macOS limits socket paths to 104 bytes; t.TempDir() can exceed that.
	dir, err := os.MkdirTemp("/tmp", "mh")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	return filepath.Join(dir, "s", "agent.sock")
}

func unixHTTP(sock string) *http.Client {
	return &http.Client{Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, "unix", sock)
	}}}
}

// The deployment files must wire the boundary the way the code expects.
// Static checks only; the real systemd/Docker behaviour needs a Debian host
// (docs/verification.md, deploy/verify-host-exec.sh).
func TestDeployWiring(t *testing.T) {
	read := func(p string) string {
		b, err := os.ReadFile(filepath.Join("..", "..", p))
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}
	compose := read("deploy/docker-compose.yml")
	start := strings.Index(compose, "\n  meridian:\n")
	end := strings.Index(compose, "\n  smartdns:\n")
	if start < 0 || end < start {
		t.Fatal("compose services not found")
	}
	panel := stripComments(compose[start:end])
	for _, want := range []string{
		"- /run/meridian-host:/run/meridian-host\n",
		"- /etc/meridian-host/agent.token:/run/secrets/meridian-host.token:ro\n",
		"MERIDIAN_HOST_SOCKET: " + DefaultSocket + "\n",
		"MERIDIAN_HOST_TOKEN_FILE: /run/secrets/meridian-host.token\n",
	} {
		if !strings.Contains(panel, want) {
			t.Errorf("panel service missing %q", want)
		}
	}
	for _, bad := range []string{"NET_ADMIN", "/dev/net/tun", "docker.sock", "/run/systemd"} {
		if strings.Contains(panel, bad) {
			t.Errorf("panel container must not get %s", bad)
		}
	}
	if !strings.Contains(compose[end:], "container_name: "+SmartDNSContainer+"\n") {
		t.Error("smartdns container name must match the agent's fixed name")
	}
	agentUnit := read("deploy/debian/meridian-host.service")
	for _, want := range []string{
		"ExecStart=/usr/local/bin/meridian host-agent\n",
		"Environment=MERIDIAN_HOST_SOCKET=" + DefaultSocket + "\n",
		"Environment=MERIDIAN_HOST_TOKEN_FILE=" + DefaultTokenFile + "\n",
		"Environment=MERIDIAN_HOST_LEDGER=" + DefaultLedger + "\n",
		"CapabilityBoundingSet=CAP_NET_ADMIN\n",
		"NoNewPrivileges=yes\n",
		"ProtectSystem=strict\n",
		// The list action writes exactly these (DefaultListsDir).
		"ReadWritePaths=-" + DefaultListsDir + "/geosite -" + DefaultListsDir + "/keywords -" + DefaultListsDir + "/lists\n",
		"RuntimeDirectoryPreserve=yes\n",
		// The unlock probe needs IP sockets; still no raw/packet sockets.
		"RestrictAddressFamilies=AF_UNIX AF_NETLINK AF_INET AF_INET6\n",
	} {
		if !strings.Contains(agentUnit, want) {
			t.Errorf("meridian-host.service missing %q", want)
		}
	}
	guard := read("deploy/debian/meridian-guard.service")
	for _, want := range []string{"DefaultDependencies=no\n", "systemd-sysctl.service", "docker.service", "meridian.service",
		"ExecStart=/usr/sbin/nft -f /etc/nftables.d/meridian-guard.nft\n", "WantedBy=sysinit.target\n"} {
		if !strings.Contains(guard, want) {
			t.Errorf("meridian-guard.service missing %q", want)
		}
	}
	if !strings.Contains(read("deploy/debian/meridian.service"), "After=network-online.target docker.service meridian-guard.service\n") {
		t.Error("meridian.service must order after the guard")
	}
	// A host nftables.service that flushes the ruleset at boot runs before
	// the guard and before meridian.service, never after them.
	if !strings.Contains(guard, "After=systemd-modules-load.service nftables.service\n") || !strings.Contains(read("deploy/debian/meridian.service"), "\nAfter=nftables.service\n") {
		t.Error("the guard and meridian.service must order after nftables.service")
	}
	install := stripComments(read("deploy/debian/install.sh"))
	for _, want := range []string{"net.ipv4.ip_forward=0", "\"ip-forward\": false", "meridian-host.service", "meridian-guard.service", "/etc/meridian-host/agent.token"} {
		if !strings.Contains(install, want) {
			t.Errorf("install.sh missing %q", want)
		}
	}
	if strings.Contains(install, "ip_forward=1") || strings.Contains(install, "forwarding=1") {
		t.Error("install.sh must not enable forwarding at boot")
	}
}

func stripComments(s string) string {
	var out []string
	for _, l := range strings.Split(s, "\n") {
		if !strings.HasPrefix(strings.TrimSpace(l), "#") {
			out = append(out, l)
		}
	}
	return strings.Join(out, "\n")
}

func TestRemoteAccessInterfaceIsNarrow(t *testing.T) {
	for _, ok := range []string{"mra", "m00", "m00w", "m123", "mmesh"} {
		if !ValidInterface(ok) {
			t.Errorf("%s must be a managed interface", ok)
		}
	}
	for _, bad := range []string{"mra0", "mraa", "xmra", "mr", "mra ", "eth0", "wg0", "m0", "lo"} {
		if ValidInterface(bad) {
			t.Errorf("%q must not be a managed interface", bad)
		}
	}
	if ProbeEgressInterface("mra") {
		t.Fatal("the remote-access ingress must never count as a probe egress")
	}
	if !ProbeEgressInterface("m00") {
		t.Fatal("tunnels stay probe egresses")
	}
	if err := Validate(Request{Action: ActionRollback, RequestID: "r1", Resources: Resources{Interfaces: []string{"mra"}}}); err != nil {
		t.Fatalf("removing mra must be a valid request: %v", err)
	}
}
