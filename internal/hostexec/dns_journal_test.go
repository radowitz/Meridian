package hostexec

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/radowitz/meridian/internal/dnsjournal"
)

const testImage = "sha256:00000000000000000000000000000000000000000000000000000000000000aa"

// dnsHost is a fakeHost whose resolver container answers the two fixed
// docker reads of the capability gate.
type dnsHost struct {
	*fakeHost
	running  bool
	image    string
	mounts   string
	versionO string // output of "smartdns -v"
}

func newDNSHost() *dnsHost {
	f := newFakeHost()
	f.dns = "container"
	return &dnsHost{fakeHost: f, running: true, image: testImage, versionO: "smartdns 1.2026.11.09-1240\n",
		mounts: "/etc/smartdns>/etc/smartdns>false;" + dnsjournal.RawDir + ">" + dnsjournal.RawDir + ">true;"}
}

func (d *dnsHost) Run(ctx context.Context, prog string, args ...string) (string, error) {
	line := prog + " " + strings.Join(args, " ")
	switch {
	case prog == "docker" && args[0] == "inspect" && len(args) == 6 && args[4] == dnsInspectFormat:
		d.mu.Lock()
		d.cmds = append(d.cmds, line)
		d.mu.Unlock()
		if d.dns != "container" {
			return "", errors.New("no such container")
		}
		return fmt.Sprintf("%v|%s|%s\n", d.running, d.image, d.mounts), nil
	case prog == "docker" && args[0] == "exec":
		d.mu.Lock()
		d.cmds = append(d.cmds, line)
		d.mu.Unlock()
		if d.versionO == "" {
			return "OCI runtime exec failed", errors.New("exit status 126")
		}
		return d.versionO, nil
	}
	return d.fakeHost.Run(ctx, prog, args...)
}

type dnsFix struct {
	t    *testing.T
	h    *dnsHost
	a    *Agent
	root string
	raw  string
	jd   string
	// asked counts the liveness questions; answer says whether the resolver
	// replies.
	mu     sync.Mutex
	asked  []string
	answer bool
}

func newDNSFix(t *testing.T) *dnsFix {
	t.Helper()
	f := &dnsFix{t: t, h: newDNSHost(), root: t.TempDir(), answer: true}
	f.raw, f.jd = filepath.Join(f.root, dnsjournal.RawDir), filepath.Join(f.root, dnsjournal.JournalDir)
	f.a = &Agent{Token: func() (string, error) { return strings.Repeat("t", 64), nil }, Runner: f.h, PreflightRoot: f.root, ListsDir: filepath.Join(f.root, "lists-dir"),
		SniffSocketPath: "/nonexistent-meridian-test/status.sock", DNSJournalSocketPath: "/nonexistent-meridian-test/dns.sock",
		SniffSelfCheckWait: 100 * time.Millisecond, DNSLivenessWait: 300 * time.Millisecond, DNSSinkRetry: 5 * time.Millisecond,
		DNSCheckExchange: func(_ context.Context, server string, mark uint32, q []byte) ([]byte, error) {
			f.mu.Lock()
			defer f.mu.Unlock()
			f.asked = append(f.asked, fmt.Sprintf("%s mark=%d %q", server, mark, q[12:]))
			if !f.answer {
				return nil, errors.New("i/o timeout")
			}
			r := append([]byte(nil), q...)
			r[2] |= 0x80
			r[3] = 3 // NXDOMAIN: any well-formed reply counts
			return r, nil
		}}
	return f
}

func (f *dnsFix) conf(body string) {
	f.t.Helper()
	p := filepath.Join(f.root, "etc/smartdns/smartdns.conf")
	os.MkdirAll(filepath.Dir(p), 0o755)
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		f.t.Fatal(err)
	}
}

const auditConf = "cache-size 1\naudit-enable yes\naudit-file " + dnsjournal.AuditFile + "\naudit-size 2048k\naudit-num 1\n"

func (f *dnsFix) activate(units ...string) Result {
	for _, u := range units {
		f.h.units[u] = "inactive"
	}
	res, _ := f.a.Execute(context.Background(), Request{Action: ActionActivate, RequestID: fmt.Sprintf("r%d", time.Now().UnixNano()),
		Resources: Resources{Units: units, DNS: true}})
	return res
}

func stepOf(res Result, name string) *Step {
	for i := range res.Steps {
		if res.Steps[i].Name == name {
			return &res.Steps[i]
		}
	}
	return nil
}

// The status read: two fixed docker reads, the gate's verdict over them,
// and nothing else run against the container.
func TestDNSJournalStatusAndGate(t *testing.T) {
	f := newDNSFix(t)
	st := f.a.DNSJournalStatus(context.Background())
	if !st.Capability.Available || st.Capability.Version != "1.2026.11.09-1240" || st.Capability.VerifiedBy != "builtin" ||
		st.Facts.Provider != "container" || !st.Facts.Running || !st.Facts.MountFound || !st.Facts.MountRW || st.Facts.ImageID != testImage ||
		st.AuditInstalled || st.Present || st.Sink.OK {
		t.Fatalf("%+v", st)
	}
	var docker []string
	for _, c := range f.h.commands() {
		if strings.HasPrefix(c, "docker ") {
			docker = append(docker, c)
		}
	}
	want := []string{
		"docker inspect --type container -f {{.State.Status}} meridian-smartdns",
		"docker inspect --type container -f " + dnsInspectFormat + " meridian-smartdns",
		"docker exec meridian-smartdns /usr/sbin/smartdns -v",
	}
	if strings.Join(docker, "\n") != strings.Join(want, "\n") {
		t.Fatalf("docker commands:\n%s", strings.Join(docker, "\n"))
	}
	for _, c := range f.h.commands() {
		for _, bad := range []string{" restart ", " rm ", " run ", " cp ", "sh -c", " stop "} {
			if strings.Contains(c, bad) {
				t.Fatalf("the status read ran %q", c)
			}
		}
	}
	gate := func(mut func()) dnsjournal.Capability {
		t.Helper()
		g := newDNSFix(t)
		f = g
		mut()
		return g.a.DNSJournalStatus(context.Background()).Capability
	}
	// The version pinned for the remote nodes, or any other: not inferred.
	if c := gate(func() { f.h.versionO = "smartdns 1.2026.08.05-0921\n" }); c.Available || c.Code != dnsjournal.CodeVersionUnproven || c.Reason == "" || c.Action == "" {
		t.Fatalf("%+v", c)
	}
	if c := gate(func() { f.h.versionO = "" }); c.Available || c.Code != dnsjournal.CodeVersionUnknown {
		t.Fatalf("%+v", c)
	}
	if c := gate(func() { f.h.versionO = "something else entirely\n" }); c.Available || c.Code != dnsjournal.CodeVersionUnknown {
		t.Fatalf("%+v", c)
	}
	// A container created from the Compose file before the mount existed.
	if c := gate(func() { f.h.mounts = "/etc/smartdns>/etc/smartdns>false;" }); c.Available || c.Code != dnsjournal.CodeNoMount {
		t.Fatalf("%+v", c)
	}
	if c := gate(func() { f.h.mounts = dnsjournal.RawDir + ">" + dnsjournal.RawDir + ">false;" }); c.Available || c.Code != dnsjournal.CodeMountReadOnly {
		t.Fatalf("%+v", c)
	}
	if c := gate(func() { f.h.mounts = "/srv/other>" + dnsjournal.RawDir + ">true;" }); c.Available || c.Code != dnsjournal.CodeNoMount {
		t.Fatalf("mounted from another host path: %+v", c)
	}
	if c := gate(func() { f.h.running = false }); c.Available || c.Code != dnsjournal.CodeNotRunning {
		t.Fatalf("%+v", c)
	}
	if c := gate(func() { f.h.dns = "" }); c.Available || c.Code != dnsjournal.CodeNoResolver {
		t.Fatalf("%+v", c)
	}
	if c := gate(func() { f.h.dns = "unit" }); c.Available || c.Code != dnsjournal.CodeHostUnit {
		t.Fatalf("%+v", c)
	}
	if f.h.ran("docker exec") != 0 {
		t.Fatal("a host resolver unit: nothing may be run in a container")
	}
	// A version verified on this host, for this image only.
	local := func(image string) func() {
		return func() {
			f.h.versionO = "smartdns 1.2027.01.02-0304\n"
			p := filepath.Join(f.root, dnsjournal.LocalVerifiedFile)
			os.MkdirAll(filepath.Dir(p), 0o700)
			os.WriteFile(p, []byte("1.2027.01.02-0304 "+image+" 2027-01-05\n"), 0o600)
		}
	}
	if c := gate(local(testImage)); !c.Available || c.VerifiedBy != "host_record" || c.VerifiedOn != "2027-01-05" {
		t.Fatalf("%+v", c)
	}
	if c := gate(local(strings.Replace(testImage, "aa", "bb", 1))); c.Available || c.Code != dnsjournal.CodeVersionUnproven {
		t.Fatalf("a record for another image: %+v", c)
	}
}

// The journal through the agent: fixed requests, parameters validated
// before the reader is asked, the answer passed on; clear through the
// reader while it runs.
func TestAgentDNSJournalRequests(t *testing.T) {
	f := newDNSFix(t)
	dir, err := os.MkdirTemp("", "dj")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	sock := filepath.Join(dir, "s.sock")
	f.a.DNSJournalSocketPath = sock
	hs := httptest.NewServer(f.a.Handler())
	defer hs.Close()
	post := func(path, body string, auth bool) (int, DNSJournalAnswer) {
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
		var out DNSJournalAnswer
		_ = json.NewDecoder(resp.Body).Decode(&out)
		return resp.StatusCode, out
	}
	for _, p := range []string{"/v1/dns/journal", "/v1/dns/journal/summary", "/v1/dns/journal/clear", "/v1/dns/journal/status"} {
		if code, _ := post(p, `{}`, false); code != http.StatusUnauthorized {
			t.Fatalf("%s without the token: %d", p, code)
		}
	}
	if code, ans := post("/v1/dns/journal", `{}`, true); code != 200 || ans.Present || ans.Code != "no_socket" {
		t.Fatalf("no socket: %d %+v", code, ans)
	}

	// A reader behind the socket.
	raw, jd := filepath.Join(dir, "raw"), filepath.Join(dir, "journal")
	if err := dnsjournal.PrepareSink(raw); err != nil {
		t.Fatal(err)
	}
	d, err := dnsjournal.NewDaemon(dnsjournal.DaemonConfig{RawDir: raw, JournalDir: jd, MaxRecords: 100, MaxAge: time.Hour, MaxBytes: dnsjournal.DefaultMaxBytes}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	now := time.Now().UTC()
	line := fmt.Sprintf("[%s,000] 192.0.2.10 query one.example.test, type 1, time 2ms, speed: -0.1ms, group default, result 192.0.2.1\n", now.Format("2006-01-02 15:04:05"))
	os.WriteFile(filepath.Join(raw, dnsjournal.AuditBase), []byte(line), 0o600)
	d.Tail.Step()
	d.Journal.Flush()
	var asked []string
	var mu sync.Mutex
	l, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	h := d.StatusHandler()
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		asked = append(asked, r.Method+" "+r.URL.RequestURI())
		mu.Unlock()
		h.ServeHTTP(w, r)
	})}
	go srv.Serve(l)
	defer srv.Close()

	code, ans := post("/v1/dns/journal", `{"device":"192.0.2.10","limit":10}`, true)
	var page dnsjournal.Page
	if code != 200 || !ans.Present || ans.Code != "" || json.Unmarshal(ans.Body, &page) != nil || page.Matched != 1 || page.Records[0].Name != "one.example.test" {
		t.Fatalf("%d %+v", code, ans)
	}
	if code, ans := post("/v1/dns/journal/summary", `{}`, true); code != 200 || !bytes.Contains(ans.Body, []byte(`"device":"192.0.2.10"`)) {
		t.Fatalf("%d %+v", code, ans)
	}
	mu.Lock()
	n := len(asked)
	mu.Unlock()
	cmds := len(f.h.commands())
	for _, c := range []struct{ path, body string }{
		{"/v1/dns/journal", `{"device":"not-an-address"}`},
		{"/v1/dns/journal", `{"group":"x; rm -rf /"}`},
		{"/v1/dns/journal", `{"mac":"zz"}`},
		{"/v1/dns/journal", `{"limit":100000}`},
		{"/v1/dns/journal", `{"result":"everything"}`},
		{"/v1/dns/journal", `{"path":"/etc/shadow"}`},
		{"/v1/dns/journal", `{"file":"/var/log/smartdns.log"}`},
		{"/v1/dns/journal", `not json`},
		{"/v1/dns/journal/summary", `{"device":"192.0.2.10"}`},
		{"/v1/dns/journal/summary", `{"from":"yesterday"}`},
		{"/v1/dns/journal/clear", `{"dir":"/var/lib"}`},
		{"/v1/dns/journal/status", `{"container":"other"}`},
	} {
		if code, _ := post(c.path, c.body, true); code != http.StatusBadRequest {
			t.Errorf("%s %s: %d", c.path, c.body, code)
		}
	}
	mu.Lock()
	if len(asked) != n {
		t.Fatalf("a refused request reached the reader: %v", asked[n:])
	}
	mu.Unlock()
	if len(f.h.commands()) != cmds {
		t.Fatalf("a journal request ran a command: %v", f.h.commands()[cmds:])
	}
	// The status read shows the reader.
	st := f.a.DNSJournalStatus(context.Background())
	if !st.Present || !bytes.Contains(st.Health, []byte(`"parsed":1`)) || bytes.Contains(st.Health, []byte("example.test")) {
		t.Fatalf("%+v", st)
	}
	// Clear goes to the reader while it runs.
	code, ans = post("/v1/dns/journal/clear", `{}`, true)
	if code != 200 || ans.Code != "" || !bytes.Contains(ans.Body, []byte(`"cleared":1`)) {
		t.Fatalf("%d %+v", code, ans)
	}
	mu.Lock()
	last := asked[len(asked)-1]
	mu.Unlock()
	if last != "POST /v1/journal/clear" {
		t.Fatalf("clear asked %q", last)
	}
	// The client side.
	c := &Client{Socket: filepath.Join(dir, "none.sock"), TokenFile: filepath.Join(dir, "none")}
	if _, err := c.DNSJournalStatus(context.Background()); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("%v", err)
	}
}

// An agent without the requests (an older binary) is told apart.
func TestDNSJournalClientOldAgent(t *testing.T) {
	dir, err := os.MkdirTemp("", "dj")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	sock := filepath.Join(dir, "a.sock")
	l, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/action", func(w http.ResponseWriter, r *http.Request) {})
	srv := &http.Server{Handler: mux}
	go srv.Serve(l)
	defer srv.Close()
	tok := filepath.Join(dir, "tok")
	os.WriteFile(tok, []byte(strings.Repeat("t", 64)), 0o600)
	c := &Client{Socket: sock, TokenFile: tok}
	if _, err := c.DNSJournalStatus(context.Background()); !errors.Is(err, ErrDNSJournalUnsupported) {
		t.Fatalf("status: %v", err)
	}
	if _, err := c.DNSJournal(context.Background(), dnsjournal.Query{}); !errors.Is(err, ErrDNSJournalUnsupported) {
		t.Fatalf("journal: %v", err)
	}
	if _, err := c.DNSJournalClear(context.Background()); !errors.Is(err, ErrDNSJournalUnsupported) {
		t.Fatalf("clear: %v", err)
	}
}

// Without a reader the clear deletes the data from the two fixed
// directories itself; with the reader's unit active but no socket it does
// nothing.
func TestDNSJournalClearWithoutReader(t *testing.T) {
	f := newDNSFix(t)
	fill := func() {
		dnsjournal.PrepareSink(f.raw)
		os.MkdirAll(f.jd, 0o700)
		os.WriteFile(filepath.Join(f.raw, dnsjournal.AuditBase), []byte("x one.example.test\n"), 0o600)
		os.WriteFile(filepath.Join(f.raw, "audit.log-20261115-110000.gz"), []byte("gz"), 0o600)
		os.WriteFile(filepath.Join(f.jd, "dns-00000000000000000001.jsonl"), []byte("{}\n"), 0o600)
	}
	fill()
	other := filepath.Join(f.root, "var/lib/meridian-sniff")
	os.MkdirAll(other, 0o700)
	os.WriteFile(filepath.Join(other, "conn-00000000000000000001.jsonl"), []byte("{}\n"), 0o600)

	f.h.units[DNSJournalUnit] = "active"
	if ans := f.a.dnsJournalClear(context.Background()); ans.Code != "read_failed" {
		t.Fatalf("%+v", ans)
	}
	if n, _ := dnsjournal.DataUsage(f.raw, f.jd); n != 3 {
		t.Fatalf("data deleted while the reader's unit is active: %d files", n)
	}
	delete(f.h.units, DNSJournalUnit)
	// The journal is off (no audit in the installed config): everything goes.
	f.conf("cache-size 1\n")
	ans := f.a.dnsJournalClear(context.Background())
	if ans.Code != "" || !bytes.Contains(ans.Body, []byte(`"purged_files":3`)) {
		t.Fatalf("%+v", ans)
	}
	if n, _ := dnsjournal.DataUsage(f.raw, f.jd); n != 0 {
		t.Fatalf("%d files left", n)
	}
	if fi, err := os.Stat(f.raw); err != nil || !fi.IsDir() {
		t.Fatal("the mount directory was removed")
	}
	if _, err := os.Stat(filepath.Join(other, "conn-00000000000000000001.jsonl")); err != nil {
		t.Fatal("the clear touched another directory")
	}
	st := f.a.DNSJournalStatus(context.Background())
	if st.DataFiles != 0 || st.AuditInstalled {
		t.Fatalf("%+v", st)
	}
	// The audit still installed (the reader is stopped): the audit file is
	// emptied in place, it stays the regular file the resolver has open.
	fill()
	f.conf(auditConf)
	before, _ := os.Stat(filepath.Join(f.raw, dnsjournal.AuditBase))
	if ans := f.a.dnsJournalClear(context.Background()); ans.Code != "" {
		t.Fatalf("%+v", ans)
	}
	after, err := os.Stat(filepath.Join(f.raw, dnsjournal.AuditBase))
	if err != nil || after.Size() != 0 || !os.SameFile(before, after) {
		t.Fatalf("audit file: %v", err)
	}
	if st := f.a.DNSJournalStatus(context.Background()); !st.AuditInstalled || !st.Sink.OK {
		t.Fatalf("%+v", st)
	}
	// Idempotent, also with nothing there at all.
	os.RemoveAll(filepath.Join(f.root, dnsjournal.StateDir))
	if ans := f.a.dnsJournalClear(context.Background()); ans.Code != "" {
		t.Fatalf("%+v", ans)
	}
}

// Activate with the audit log in the resolver config: the gate and the sink
// are checked before the restart, the resolver must answer after it.
func TestActivateGuardsResolverAudit(t *testing.T) {
	// Without the audit nothing changes: no gate read, no liveness step.
	// One question confirms the answer before the loaded list digest is
	// recorded (smartdns_reload.go); it is not a step and cannot fail.
	f := newDNSFix(t)
	f.conf("cache-size 1\n")
	res := f.activate("meridian-failover.service")
	if !res.OK || f.h.ran("docker exec") != 0 || len(f.asked) != 1 || stepOf(res, "dns audit gate") != nil ||
		stepOf(res, "resolver answers after restart") != nil || f.h.ran("docker restart "+SmartDNSContainer) != 1 {
		t.Fatalf("%+v\n%s", res, strings.Join(f.h.commands(), "\n"))
	}

	// With it, everything in order.
	f = newDNSFix(t)
	f.conf(auditConf)
	dnsjournal.PrepareSink(f.raw) // what the reader's ExecStartPre does
	res = f.activate(DNSJournalUnit, "meridian-failover.service")
	if !res.OK {
		t.Fatalf("%+v", res)
	}
	for _, n := range []string{"dns audit gate", "dns audit sink", "restart " + SmartDNSContainer, "resolver answers after restart"} {
		if s := stepOf(res, n); s == nil || !s.OK {
			t.Fatalf("step %q: %+v", n, res.Steps)
		}
	}
	indexOrder(t, f.h.commands(), "systemctl restart "+DNSJournalUnit, "docker exec meridian-smartdns /usr/sbin/smartdns -v", "docker restart "+SmartDNSContainer)
	if len(f.asked) != 1 || !strings.HasPrefix(f.asked[0], "127.0.0.1:53 mark=0 ") || !strings.Contains(f.asked[0], "google") {
		t.Fatalf("liveness question: %v", f.asked)
	}

	refused := func(name string, prep func(f *dnsFix), failing string) {
		t.Helper()
		f := newDNSFix(t)
		f.conf(auditConf)
		dnsjournal.PrepareSink(f.raw)
		prep(f)
		res := f.activate(DNSJournalUnit)
		s := stepOf(res, failing)
		if res.OK || s == nil || s.OK || res.Error == "" {
			t.Fatalf("%s: %+v", name, res)
		}
		if f.h.ran("docker restart") != 0 || f.h.ran("systemctl restart smartdns.service") != 0 {
			t.Fatalf("%s: the resolver was restarted:\n%s", name, strings.Join(f.h.commands(), "\n"))
		}
		if len(f.asked) != 0 {
			t.Fatalf("%s: a liveness question without a restart", name)
		}
	}
	refused("unverified version", func(f *dnsFix) { f.h.versionO = "smartdns 1.2026.08.05-0921\n" }, "dns audit gate")
	refused("version unreadable", func(f *dnsFix) { f.h.versionO = "" }, "dns audit gate")
	refused("no writable mount", func(f *dnsFix) { f.h.mounts = "" }, "dns audit gate")
	refused("host unit", func(f *dnsFix) { f.h.dns = "unit" }, "dns audit gate")
	refused("no resolver", func(f *dnsFix) { f.h.dns = "" }, "dns audit gate")
	refused("another audit file", func(f *dnsFix) { f.conf("audit-enable yes\naudit-file /var/log/smartdns-audit.log\n") }, "dns audit config")
	refused("no sink directory", func(f *dnsFix) { os.RemoveAll(f.raw) }, "dns audit sink")
	refused("no audit file", func(f *dnsFix) { os.Remove(filepath.Join(f.raw, dnsjournal.AuditBase)) }, "dns audit sink")
	refused("open directory", func(f *dnsFix) { os.Chmod(f.raw, 0o755) }, "dns audit sink")
	refused("world-readable file", func(f *dnsFix) { os.Chmod(filepath.Join(f.raw, dnsjournal.AuditBase), 0o644) }, "dns audit sink")
	refused("symbolic link", func(f *dnsFix) {
		p := filepath.Join(f.raw, dnsjournal.AuditBase)
		os.Remove(p)
		os.Symlink("/dev/null", p)
	}, "dns audit sink")
	refused("FIFO", func(f *dnsFix) {
		p := filepath.Join(f.raw, dnsjournal.AuditBase)
		os.Remove(p)
		if err := syscall.Mkfifo(p, 0o600); err != nil {
			os.Symlink("/dev/null", p)
		}
	}, "dns audit sink")

	// The resolver runs but does not answer after the restart, whatever
	// the cause: the install fails.
	f = newDNSFix(t)
	f.conf(auditConf)
	dnsjournal.PrepareSink(f.raw)
	f.answer = false
	res = f.activate(DNSJournalUnit)
	if s := stepOf(res, "resolver answers after restart"); res.OK || s == nil || s.OK || f.h.ran("docker restart "+SmartDNSContainer) != 1 || len(f.asked) == 0 {
		t.Fatalf("%+v", res)
	}
	if stepOf(res, "health meridian.service") != nil {
		t.Fatal("health was sampled after the resolver failed to answer")
	}
}

// Removing the reader's unit keeps its data: the records go only when the
// panel asks, after the install that turned the journal off succeeded.
func TestRollbackOfReaderKeepsData(t *testing.T) {
	f := newDNSFix(t)
	dnsjournal.PrepareSink(f.raw)
	os.MkdirAll(f.jd, 0o700)
	os.WriteFile(filepath.Join(f.jd, "dns-00000000000000000001.jsonl"), []byte("{}\n"), 0o600)
	f.conf(auditConf)
	if res := f.activate(DNSJournalUnit); !res.OK {
		t.Fatalf("%+v", res)
	}
	res, code := f.a.Execute(context.Background(), Request{Action: ActionRollback, RequestID: "rb", Resources: Resources{Units: []string{DNSJournalUnit}}})
	if code != 200 || !res.OK {
		t.Fatalf("%d %+v", code, res)
	}
	if f.h.ran("systemctl disable --now "+DNSJournalUnit) != 1 || f.h.ran("systemctl clean") != 0 {
		t.Fatalf("%s", strings.Join(f.h.commands(), "\n"))
	}
	if n, _ := dnsjournal.DataUsage(f.raw, f.jd); n != 2 {
		t.Fatalf("%d files after the unit was removed", n)
	}
}

// serveReader puts h behind a status socket in a short directory and points
// the agent at it.
func (f *dnsFix) serveReader(h http.Handler) {
	f.t.Helper()
	dir, err := os.MkdirTemp("", "dj")
	if err != nil {
		f.t.Fatal(err)
	}
	sock := filepath.Join(dir, "s.sock")
	l, err := net.Listen("unix", sock)
	if err != nil {
		f.t.Fatal(err)
	}
	srv := &http.Server{Handler: h}
	go srv.Serve(l)
	f.t.Cleanup(func() {
		srv.Close()
		os.RemoveAll(dir)
	})
	f.a.DNSJournalSocketPath = sock
}

// noLeak fails when an answer of a clear carries a path, a file name, a
// journal name or the system's error text.
func (f *dnsFix) noLeak(ans DNSJournalAnswer) {
	f.t.Helper()
	b, _ := json.Marshal(ans)
	for _, leak := range []string{f.root, "/var/lib", "audit.log", "dns-0", ".jsonl", "example.test", "192.0.2.", "denied", "read-only", "unlinkat", "truncate "} {
		if strings.Contains(string(b), leak) {
			f.t.Fatalf("the answer carries %q: %s", leak, b)
		}
	}
}

// The agent's own clear (no reader) that cannot delete everything is not a
// success: clear_incomplete with what is left and why, nothing of a path;
// the status read still shows the data; the same clear asked again, once
// the fault is gone, completes.
func TestDNSJournalClearWithoutReaderIncomplete(t *testing.T) {
	f := newDNSFix(t)
	dnsjournal.PrepareSink(f.raw)
	os.MkdirAll(f.jd, 0o700)
	os.WriteFile(filepath.Join(f.raw, dnsjournal.AuditBase), []byte("x one.example.test\n"), 0o600)
	os.WriteFile(filepath.Join(f.raw, "audit.log-20261115-110000.gz"), []byte("gz"), 0o600)
	os.WriteFile(filepath.Join(f.jd, "dns-00000000000000000001.jsonl"), []byte(`{"id":1,"time":"2026-11-15T12:00:00Z","client":"192.0.2.10","name":"one.example.test","qtype":1,"result":"answered","elapsed_ms":1,"answers":1}`+"\n"), 0o600)
	f.conf(auditConf) // the audit is still installed: the audit file is emptied in place
	var mu sync.Mutex
	failing := map[string]error{"remove": syscall.EACCES, "truncate": syscall.EROFS}
	f.a.DNSPurgeFault = func(op, path string) error {
		mu.Lock()
		defer mu.Unlock()
		if err := failing[op]; err != nil {
			return &os.PathError{Op: op, Path: path, Err: err}
		}
		return nil
	}
	ans := f.a.dnsJournalClear(context.Background())
	var res dnsjournal.ClearResult
	if ans.Code != DNSClearIncomplete || json.Unmarshal(ans.Body, &res) != nil || res.Complete || res.Residual == nil ||
		res.Residual.Segments != 1 || res.Residual.Records != 1 || res.Residual.RawFiles != 2 || len(res.Errors) != 3 {
		t.Fatalf("%+v", ans)
	}
	for _, want := range []string{"没有全部清除", "1 个分段", "2 个文件", "权限不足", "文件系统只读", "再清空一次"} {
		if !strings.Contains(ans.Error, want) {
			t.Fatalf("the message lacks %q: %s", want, ans.Error)
		}
	}
	f.noLeak(ans)
	if st := f.a.DNSJournalStatus(context.Background()); st.DataFiles < 3 || st.DataBytes == 0 {
		t.Fatalf("the status read no longer shows what is left: %+v", st)
	}
	// Through the HTTP request as well: 200 with the code, never a bare success.
	hs := httptest.NewServer(f.a.Handler())
	defer hs.Close()
	req, _ := http.NewRequest("POST", hs.URL+"/v1/dns/journal/clear", bytes.NewBufferString(`{}`))
	req.Header.Set("Authorization", "Bearer "+strings.Repeat("t", 64))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	var over DNSJournalAnswer
	json.NewDecoder(resp.Body).Decode(&over)
	resp.Body.Close()
	if over.Code != DNSClearIncomplete || over.Error == "" || len(over.Body) == 0 {
		t.Fatalf("%+v", over)
	}
	// A directory that cannot be listed.
	mu.Lock()
	failing = map[string]error{"readdir": syscall.EIO}
	mu.Unlock()
	if ans = f.a.dnsJournalClear(context.Background()); ans.Code != DNSClearIncomplete || !strings.Contains(ans.Error, "目录读取失败") || !strings.Contains(ans.Error, "可能比数到的多") {
		t.Fatalf("%+v", ans)
	}
	f.noLeak(ans)
	// The retry.
	mu.Lock()
	failing = nil
	mu.Unlock()
	if ans = f.a.dnsJournalClear(context.Background()); ans.Code != "" || json.Unmarshal(ans.Body, &res) != nil || !res.Complete {
		t.Fatalf("%+v", ans)
	}
	if n, size := dnsjournal.DataUsage(f.raw, f.jd); n != 1 || size != 0 { // the emptied audit file
		t.Fatalf("%d files, %d bytes left", n, size)
	}
}

// Through a running reader: a clear it could not finish is passed on as
// clear_incomplete with its counts; a reader that does not say whether it
// finished (one from before it reported that) is never taken for a success.
func TestDNSJournalClearThroughReaderIncomplete(t *testing.T) {
	f := newDNSFix(t)
	dir := t.TempDir()
	raw, jd := filepath.Join(dir, "raw"), filepath.Join(dir, "journal")
	if err := dnsjournal.PrepareSink(raw); err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	fail := true
	d, err := dnsjournal.NewDaemon(dnsjournal.DaemonConfig{RawDir: raw, JournalDir: jd, MaxRecords: 100, MaxAge: time.Hour, MaxBytes: dnsjournal.DefaultMaxBytes,
		Fault: func(op, path string) error {
			mu.Lock()
			defer mu.Unlock()
			if fail && op == "remove" {
				return &os.PathError{Op: op, Path: path, Err: syscall.EBUSY}
			}
			return nil
		}}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	now := time.Now().UTC()
	line := fmt.Sprintf("[%s,000] 192.0.2.10 query one.example.test, type 1, time 2ms, speed: -0.1ms, group default, result 192.0.2.1\n", now.Format("2006-01-02 15:04:05"))
	os.WriteFile(filepath.Join(raw, dnsjournal.AuditBase), []byte(line), 0o600)
	d.Step()
	d.Journal.Flush()
	f.serveReader(d.StatusHandler())

	ans := f.a.dnsJournalClear(context.Background())
	var res dnsjournal.ClearResult
	if ans.Code != DNSClearIncomplete || !ans.Present || json.Unmarshal(ans.Body, &res) != nil || res.Complete || res.Residual == nil || res.Residual.Records != 1 ||
		!strings.Contains(ans.Error, "1 条记录") || !strings.Contains(ans.Error, "文件被占用") {
		t.Fatalf("%+v", ans)
	}
	f.noLeak(ans)
	// The records are still served, and the status read shows the residue.
	if page := f.a.dnsJournalCall(context.Background(), http.MethodGet, "/v1/journal"); !bytes.Contains(page.Body, []byte(`"matched":1`)) {
		t.Fatalf("%+v", page)
	}
	if st := f.a.DNSJournalStatus(context.Background()); !bytes.Contains(st.Health, []byte(`"residual":{"segments":1,"records":1`)) {
		t.Fatalf("%s", st.Health)
	}
	mu.Lock()
	fail = false
	mu.Unlock()
	if ans = f.a.dnsJournalClear(context.Background()); ans.Code != "" || json.Unmarshal(ans.Body, &res) != nil || !res.Complete || res.Cleared != 1 {
		t.Fatalf("retry: %+v", ans)
	}

	// An old reader: 200 and a body without "complete".
	for _, body := range []string{`{"cleared":1,"raw_bytes":10,"stats":{}}`, `{}`, `[]`, `null`} {
		g := newDNSFix(t)
		g.serveReader(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(body))
		}))
		if ans := g.a.dnsJournalClear(context.Background()); ans.Code != DNSClearUnconfirmed || !strings.Contains(ans.Error, "不能当作已经清空") {
			t.Fatalf("%s: %+v", body, ans)
		}
	}
}
