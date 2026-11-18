package hostexec

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/radowitz/meridian/internal/sniff"
)

// Reload: only for activate and only for units of the request.
func TestReloadValidation(t *testing.T) {
	ok := Request{Action: ActionActivate, RequestID: "r", Resources: Resources{Units: []string{SniffUnit}, Reload: []string{SniffUnit}}}
	if err := Validate(ok); err != nil {
		t.Fatal(err)
	}
	for name, req := range map[string]Request{
		"not in units": {Action: ActionActivate, RequestID: "r", Resources: Resources{Units: []string{"meridian-failover.service"}, Reload: []string{SniffUnit}}},
		"rollback":     {Action: ActionRollback, RequestID: "r", Resources: Resources{Units: []string{SniffUnit}, Reload: []string{SniffUnit}}},
		"bad name":     {Action: ActionActivate, RequestID: "r", Resources: Resources{Units: []string{"sshd.service"}, Reload: []string{"sshd.service"}}},
	} {
		if Validate(req) == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	a, b := ok, ok
	b.Resources.Reload = nil
	if fingerprint(a) == fingerprint(b) {
		t.Fatal("reload is not part of the request fingerprint")
	}
}

// Activate reloads a unit named in Reload (after meridian.service, i.e.
// after the ruleset), restarts the others.
func TestActivateReloadsSniff(t *testing.T) {
	f := newFakeHost()
	f.units[SniffUnit] = "active"
	f.units[SniffAccountUnit] = "active"
	f.units["meridian-failover.service"] = "inactive"
	a := newAgent(f)
	res, _ := a.Execute(context.Background(), Request{Action: ActionActivate, RequestID: "r1",
		Resources: Resources{Units: []string{"meridian-failover.service", SniffUnit}, Reload: []string{SniffUnit}}})
	if !res.OK {
		t.Fatalf("%+v", res)
	}
	cmds := strings.Join(f.commands(), "\n")
	core := strings.Index(cmds, "systemctl restart meridian.service")
	rel := strings.Index(cmds, "systemctl reload-or-restart "+SniffUnit)
	if core < 0 || rel < core || strings.Contains(cmds, "systemctl restart "+SniffUnit) || !strings.Contains(cmds, "systemctl restart meridian-failover.service") {
		t.Fatalf("%s", cmds)
	}
}

// The status read: absent socket, a forwarder answering, a non-JSON
// answer; the endpoint takes no parameters.
func TestAgentSniffStatus(t *testing.T) {
	dir, err := os.MkdirTemp("", "sn")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	sock := filepath.Join(dir, "s.sock")
	f := newFakeHost()
	a := newAgent(f)
	a.SniffSocketPath = sock
	if st := a.SniffStatus(context.Background()); st.Present || st.Error != "" {
		t.Fatalf("absent: %+v", st)
	}
	l, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	health := `{"ready":true,"generation":3}`
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/health", func(w http.ResponseWriter, r *http.Request) { w.Write([]byte(health)) })
	mux.HandleFunc("/v1/recent", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"record_names":false,"connections":[]}`))
	})
	srv := &http.Server{Handler: mux}
	go srv.Serve(l)
	defer srv.Close()
	st := a.SniffStatus(context.Background())
	if !st.Present || st.Error != "" || string(st.Health) != health || !strings.Contains(string(st.Recent), "connections") {
		t.Fatalf("%+v", st)
	}
	health = "not json"
	if st := a.SniffStatus(context.Background()); st.Error == "" || st.Health != nil {
		t.Fatalf("non-JSON accepted: %+v", st)
	}
	hs := httptest.NewServer(a.Handler())
	defer hs.Close()
	req, _ := http.NewRequest("POST", hs.URL+"/v1/sniff/status", bytes.NewBufferString(`{"socket":"/etc/shadow"}`))
	req.Header.Set("Authorization", "Bearer "+strings.Repeat("t", 64))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	var out SniffStatus
	_ = json.NewDecoder(resp.Body).Decode(&out)
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("parameters accepted: %d", resp.StatusCode)
	}
}

// After a list publication the running forwarder is told to re-read; a
// stopped one is left alone.
func TestReloadSniffAfterLists(t *testing.T) {
	f := newFakeHost()
	a := newAgent(f)
	a.init()
	x := &run{a: a, ctx: context.Background()}
	if w := x.reloadSniff(); len(w) != 0 || f.ran("systemctl try-reload-or-restart") != 0 {
		t.Fatalf("stopped forwarder signalled: %q %v", w, f.commands())
	}
	f.units[SniffUnit] = "active"
	// Signalled; no forwarder answers here, so its self-check cannot run:
	// a warning, the publish stands.
	if w := x.reloadSniff(); len(w) != 1 || !strings.Contains(w[0], "自检未通过") || f.ran("systemctl try-reload-or-restart "+SniffUnit) != 1 {
		t.Fatalf("%q %v", w, f.commands())
	}
}

// The account unit is never named by a caller: the agent touches it only
// with the forwarder's unit.
func TestSniffAccountUnitReserved(t *testing.T) {
	if ValidUnit(SniffAccountUnit) || !ValidUnit(SniffUnit) {
		t.Fatal("allow-list")
	}
	for _, a := range []string{ActionActivate, ActionHealth, ActionRollback} {
		if Validate(Request{Action: a, RequestID: "r", Resources: Resources{Units: []string{SniffAccountUnit}}}) == nil {
			t.Fatalf("%s accepted the account unit by name", a)
		}
	}
}

// indexOrder checks that every command is in cmds, in this order.
func indexOrder(t *testing.T, cmds []string, want ...string) {
	t.Helper()
	i := 0
	for _, c := range cmds {
		if i < len(want) && c == want[i] {
			i++
		}
	}
	if i != len(want) {
		t.Fatalf("missing or out of order from %q on:\n%s", want[i], strings.Join(cmds, "\n"))
	}
}

// A (re)start of the forwarder: stop it, stop its account unit (account
// removed), clear failed states, start it (systemd starts the account unit
// first); never a plain restart. Health checks both units.
func TestActivateRestartsSniffWithAccount(t *testing.T) {
	f := newFakeHost()
	f.units[SniffUnit] = "active"
	f.units[SniffAccountUnit] = "active"
	a := newAgent(f)
	res, _ := a.Execute(context.Background(), Request{Action: ActionActivate, RequestID: "r1", Resources: Resources{Units: []string{SniffUnit}}})
	if !res.OK {
		t.Fatalf("%+v", res)
	}
	cmds := f.commands()
	indexOrder(t, cmds,
		"systemctl daemon-reload",
		"systemctl restart meridian.service",
		"systemctl enable "+SniffUnit,
		"systemctl stop "+SniffUnit,
		"systemctl stop "+SniffAccountUnit,
		"systemctl is-failed --quiet "+SniffAccountUnit,
		"systemctl reset-failed "+SniffUnit+" "+SniffAccountUnit,
		"systemctl start "+SniffUnit,
		"systemctl is-active "+SniffUnit,
		"systemctl is-active "+SniffAccountUnit,
	)
	if f.ran("systemctl restart "+SniffUnit) != 0 || f.ran("systemctl enable "+SniffAccountUnit) != 0 {
		t.Fatalf("%s", strings.Join(cmds, "\n"))
	}
	// A failed start fails the action with both journals.
	f = newFakeHost()
	f.units[SniffUnit] = "inactive"
	f.units[SniffAccountUnit] = "inactive"
	f.startFails[SniffUnit] = true
	a = newAgent(f)
	res, _ = a.Execute(context.Background(), Request{Action: ActionActivate, RequestID: "r2", Resources: Resources{Units: []string{SniffUnit}}})
	if res.OK || f.ran("journalctl -u "+SniffAccountUnit) != 1 || f.ran("journalctl -u "+SniffUnit) != 1 {
		t.Fatalf("%+v %v", res, f.commands())
	}
}

// Removal (rollback, withdraw, compensation): disable --now the forwarder,
// stop its account unit and check its ExecStop, clear failed states.
func TestRollbackSniffAccount(t *testing.T) {
	run := func(f *fakeHost) (Result, []string) {
		a := newAgent(f)
		a.init()
		res := a.rollback(context.Background(), Resources{Units: []string{SniffUnit}})
		return res, f.commands()
	}
	// Running pair.
	f := newFakeHost()
	f.units[SniffUnit] = "active"
	f.units[SniffAccountUnit] = "active"
	res, cmds := run(f)
	if !res.OK {
		t.Fatalf("%+v", res)
	}
	indexOrder(t, cmds,
		"systemctl disable --now "+SniffUnit,
		"systemctl is-failed --quiet "+SniffAccountUnit,
		"systemctl stop "+SniffAccountUnit,
		"systemctl is-failed --quiet "+SniffAccountUnit,
		"systemctl reset-failed "+SniffUnit+" "+SniffAccountUnit,
	)
	// The account removal fails: ExecStop leaves the unit failed.
	f = newFakeHost()
	f.units[SniffUnit] = "active"
	f.units[SniffAccountUnit] = "active"
	f.stopFails[SniffAccountUnit] = true
	if res, cmds := run(f); res.OK {
		t.Fatalf("a failed account removal passed: %s", strings.Join(cmds, "\n"))
	}
	// The account unit failed at start (a conflict): started once more,
	// still refused, nothing of ours to remove; the failed state is cleared.
	f = newFakeHost()
	f.units[SniffUnit] = "failed"
	f.units[SniffAccountUnit] = "failed"
	f.startFails[SniffAccountUnit] = true
	res, cmds = run(f)
	if !res.OK || f.units[SniffAccountUnit] == "failed" || f.units[SniffUnit] == "failed" {
		t.Fatalf("%+v %v %s", res, f.units, strings.Join(cmds, "\n"))
	}
	indexOrder(t, cmds, "systemctl disable --now "+SniffUnit, "systemctl reset-failed "+SniffAccountUnit, "systemctl start "+SniffAccountUnit, "systemctl reset-failed "+SniffUnit+" "+SniffAccountUnit)
	// An earlier removal failed (unit failed after an ExecStop error):
	// started again (add accepts our account) and stopped (del).
	f = newFakeHost()
	f.units[SniffUnit] = "inactive"
	f.units[SniffAccountUnit] = "failed"
	res, cmds = run(f)
	if !res.OK || f.ran("systemctl stop "+SniffAccountUnit) != 1 {
		t.Fatalf("%+v %s", res, strings.Join(cmds, "\n"))
	}
	// No account unit file (an install from before the account unit).
	f = newFakeHost()
	f.units[SniffUnit] = "active"
	res, cmds = run(f)
	if !res.OK || f.ran("systemctl stop "+SniffAccountUnit) != 0 {
		t.Fatalf("%+v %s", res, strings.Join(cmds, "\n"))
	}
}

// ReadSniffSocket is the agent's read; a peer that closes without an answer
// (the forwarder's peer check refusing) is an error, not a status.
func TestReadSniffSocketRefused(t *testing.T) {
	dir, err := os.MkdirTemp("", "sn")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	sock := filepath.Join(dir, "s.sock")
	l, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()
	st := ReadSniffSocket(context.Background(), sock)
	if !st.Present || st.Error == "" || st.Health != nil {
		t.Fatalf("%+v", st)
	}
	l.Close()
	<-done
}

// The connection journal through the agent: three fixed requests, every
// parameter validated before the forwarder is asked, unknown fields and
// any parameter of the clear refused, no command run, the forwarder's
// answer passed on; no socket and no journal are told apart.
func TestAgentSniffJournal(t *testing.T) {
	dir, err := os.MkdirTemp("", "sj")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	sock := filepath.Join(dir, "s.sock")
	f := newFakeHost()
	a := newAgent(f)
	a.SniffSocketPath = sock
	hs := httptest.NewServer(a.Handler())
	defer hs.Close()
	post := func(path, body string, auth bool) (int, SniffJournalAnswer) {
		t.Helper()
		req, _ := http.NewRequest("POST", hs.URL+path, bytes.NewBufferString(body))
		if auth {
			req.Header.Set("Authorization", "Bearer "+strings.Repeat("t", 64))
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		var out SniffJournalAnswer
		_ = json.NewDecoder(resp.Body).Decode(&out)
		return resp.StatusCode, out
	}
	if code, ans := post("/v1/sniff/journal", `{}`, true); code != 200 || ans.Present || ans.Code != "no_socket" {
		t.Fatalf("no socket: %d %+v", code, ans)
	}
	// A forwarder with a journal behind the socket; requests counted.
	fw := sniff.New(sniff.DefaultConfig())
	var asked []string
	var mu sync.Mutex
	h := fw.StatusHandler()
	l, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		asked = append(asked, r.Method+" "+r.URL.RequestURI())
		mu.Unlock()
		h.ServeHTTP(w, r)
	})}
	go srv.Serve(l)
	defer srv.Close()
	if code, ans := post("/v1/sniff/journal", `{}`, true); code != 200 || ans.Code != "no_journal" {
		t.Fatalf("no journal: %d %+v", code, ans)
	}
	j, err := sniff.OpenJournal(sniff.JournalConfig{Dir: filepath.Join(dir, "j")})
	if err != nil {
		t.Fatal(err)
	}
	defer j.Close()
	fw.Journal = j
	now := time.Now().UTC()
	for i := 0; i < 3; i++ {
		j.Add(sniff.ConnRecord{Start: now, Source: "192.0.2." + strconv.Itoa(10+i), Dest: "198.51.100.1:443", Target: "direct", Result: "ok", Name: "never.example.com"})
	}
	j.Flush()
	code, ans := post("/v1/sniff/journal", `{"device":"192.0.2.11","limit":10}`, true)
	var page sniff.JournalPage
	if code != 200 || ans.Code != "" || json.Unmarshal(ans.Body, &page) != nil || page.Matched != 1 || page.Records[0].Source != "192.0.2.11" {
		t.Fatalf("%d %+v", code, ans)
	}
	if strings.Contains(string(ans.Body), "never.example.com") {
		t.Fatal("a name was stored with recording off")
	}
	mu.Lock()
	n := len(asked)
	mu.Unlock()
	for _, c := range []struct{ path, body string }{
		{"/v1/sniff/journal", `{"path":"/etc/shadow"}`},
		{"/v1/sniff/journal", `{"device":"not-an-address"}`},
		{"/v1/sniff/journal", `{"target":"x; rm -rf /"}`},
		{"/v1/sniff/journal", `{"limit":100000}`},
		{"/v1/sniff/journal/summary", `{"from":"yesterday"}`},
		{"/v1/sniff/journal/summary", `{"device":"192.0.2.1"}`},
		{"/v1/sniff/journal/clear", `{"confirm":true}`},
	} {
		if code, _ := post(c.path, c.body, true); code != http.StatusBadRequest {
			t.Errorf("%s %s: %d", c.path, c.body, code)
		}
	}
	mu.Lock()
	if len(asked) != n {
		t.Fatalf("refused requests reached the forwarder: %v", asked[n:])
	}
	mu.Unlock()
	if code, _ := post("/v1/sniff/journal", `{}`, false); code != http.StatusUnauthorized {
		t.Fatalf("no token: %d", code)
	}
	code, ans = post("/v1/sniff/journal/summary", `{}`, true)
	var sum sniff.JournalSummary
	if code != 200 || json.Unmarshal(ans.Body, &sum) != nil || len(sum.Devices) != 3 {
		t.Fatalf("%d %+v", code, ans)
	}
	code, ans = post("/v1/sniff/journal/clear", `{}`, true)
	if code != 200 || !strings.Contains(string(ans.Body), `"cleared":3`) {
		t.Fatalf("%d %+v", code, ans)
	}
	mu.Lock()
	want := []string{"GET /v1/journal?device=192.0.2.11&limit=10", "GET /v1/journal/summary", "POST /v1/journal/clear"}
	for _, w := range want {
		found := false
		for _, a := range asked {
			found = found || a == w
		}
		if !found {
			t.Errorf("forwarder not asked %q: %v", w, asked)
		}
	}
	mu.Unlock()
	if len(f.commands()) != 0 {
		t.Fatalf("the journal ran commands: %v", f.commands())
	}
}

// Removing the forwarder removes its journal: PID 1 cleans its state
// directory after the account and the failed states; a failing clean is
// reported but does not fail the removal.
func TestRollbackSniffCleansJournal(t *testing.T) {
	f := newFakeHost()
	f.units[SniffUnit] = "active"
	f.units[SniffAccountUnit] = "active"
	a := newAgent(f)
	a.init()
	res := a.rollback(context.Background(), Resources{Units: []string{SniffUnit}})
	if !res.OK {
		t.Fatalf("%+v", res)
	}
	indexOrder(t, f.commands(), "systemctl disable --now "+SniffUnit, "systemctl stop "+SniffAccountUnit,
		"systemctl reset-failed "+SniffUnit+" "+SniffAccountUnit, "systemctl clean --what=state "+SniffUnit)
	f = newFakeHost()
	f.units[SniffUnit] = "active"
	f.units[SniffAccountUnit] = "active"
	f.fail["systemctl clean"] = true
	a = newAgent(f)
	a.init()
	if res := a.rollback(context.Background(), Resources{Units: []string{SniffUnit}}); !res.OK {
		t.Fatalf("a failed clean failed the removal: %+v", res)
	}
}
