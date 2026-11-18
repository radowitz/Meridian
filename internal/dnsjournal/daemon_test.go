package dnsjournal

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/radowitz/meridian/internal/sniff"
)

type daemonFix struct {
	t     *testing.T
	cfg   DaemonConfig
	clock *fakeClock
	d     *Daemon
	// faults: what a clear meets (none: the real file system).
	faults []*fsFault
}

func newDaemonFix(t *testing.T) *daemonFix {
	t.Helper()
	base := t.TempDir()
	f := &daemonFix{t: t, clock: newClock(), cfg: DaemonConfig{RawDir: filepath.Join(base, "raw"), JournalDir: filepath.Join(base, "journal"),
		MaxRecords: DefaultMaxRecords, MaxAge: DefaultMaxAge, MaxBytes: DefaultMaxBytes}}
	if err := PrepareSink(f.cfg.RawDir); err != nil {
		t.Fatal(err)
	}
	f.start()
	return f
}

func (f *daemonFix) start() {
	f.t.Helper()
	cfg := f.cfg
	cfg.Fault = func(op, path string) error { return faultsOf(f.faults...)(op, path) }
	d, err := NewDaemon(cfg, func(a netip.Addr) string {
		if a.String() == "192.0.2.10" {
			return "02:00:00:00:00:01"
		}
		return ""
	}, f.clock.Now)
	if err != nil {
		f.t.Fatal(err)
	}
	f.d = d
}

func (f *daemonFix) write(client, name, result string, ms int) {
	f.t.Helper()
	p := filepath.Join(f.cfg.RawDir, AuditBase)
	fd, err := os.OpenFile(p, os.O_WRONLY|os.O_APPEND, 0)
	if err != nil {
		f.t.Fatal(err)
	}
	fd.WriteString(auditLine(f.clock.Now(), client, name, 1, ms, "default", result))
	fd.Close()
	os.Chtimes(p, f.clock.Now(), f.clock.Now())
}

func (f *daemonFix) step() {
	f.d.Tail.Step()
	f.d.Journal.Flush()
}

func (f *daemonFix) call(method, path string, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	rr := httptest.NewRecorder()
	f.d.StatusHandler().ServeHTTP(rr, req)
	return rr
}

func TestParseArgs(t *testing.T) {
	c, err := ParseArgs([]string{"--status-socket", "/run/x/status.sock", "--neigh-if", "eth0, eth1"})
	if err != nil || c.RawDir != RawDir || c.JournalDir != JournalDir || len(c.NeighIfaces) != 2 || c.MaxBytes != DefaultMaxBytes || c.Poll != time.Second || c.PrepareOnly {
		t.Fatalf("%v %+v", err, c)
	}
	for _, bad := range [][]string{
		{"--raw-dir", "relative"}, {"--raw-dir", "/a/../b"}, {"--journal-dir", ""}, {"--status-socket", "sock"},
		{"--raw-dir", "/x/raw", "--journal-dir", "/x/raw"}, {"--raw-dir", "/x/raw", "--journal-dir", "/x/raw/journal"},
		{"--max-records", "0"}, {"--max-bytes", "100"}, {"--max-age", "1s"}, {"--poll", "1ms"}, {"--unknown"}, {"extra"},
	} {
		if _, err := ParseArgs(bad); err == nil {
			t.Errorf("accepted %v", bad)
		}
	}
	dir := t.TempDir()
	raw := filepath.Join(dir, "state", "raw")
	if rc := Main([]string{"--prepare", "--raw-dir", raw, "--journal-dir", filepath.Join(dir, "state", "journal")}); rc != 0 {
		t.Fatalf("prepare: exit %d", rc)
	}
	if st := CheckSink(raw, uint32(os.Getuid())); !st.OK {
		t.Fatalf("%+v", st)
	}
	if rc := Main([]string{"--raw-dir", "relative"}); rc != 2 {
		t.Fatalf("usage error: exit %d", rc)
	}
}

func TestDaemonEndToEnd(t *testing.T) {
	var logs bytes.Buffer
	log.SetOutput(&logs)
	defer log.SetOutput(os.Stderr)
	f := newDaemonFix(t)
	defer func() { f.d.Close() }()
	f.write("192.0.2.10", "one.example.test", "192.0.2.1", 2)
	f.write("192.0.2.10", "nx.example.test", "", 3)
	f.write("192.0.2.11", "slow.example.test", "", 2100)
	f.step()

	getPage := func(path string) (Page, *httptest.ResponseRecorder) {
		t.Helper()
		var p Page
		rr := f.call(http.MethodGet, path, "")
		if rr.Code != 200 || json.Unmarshal(rr.Body.Bytes(), &p) != nil {
			t.Fatalf("%s: %d %s", path, rr.Code, rr.Body.String())
		}
		return p, rr
	}
	page, rr := getPage("/v1/journal?device=192.0.2.10")
	if page.Matched != 2 || page.Records[0].Name != "nx.example.test" ||
		page.Records[0].Result != ResultNoAnswer || page.Records[1].MAC != "02:00:00:00:00:01" || page.Stats.Budget == nil || page.Stats.Budget.Total != DefaultMaxBytes {
		t.Fatalf("%d %s", rr.Code, rr.Body.String())
	}
	if page, rr = getPage("/v1/journal?result=no_answer_slow"); page.Matched != 1 || page.Records[0].Client != "192.0.2.11" || page.Records[0].MAC != "" {
		t.Fatal(rr.Body.String())
	}
	var sum Summary
	rr = f.call(http.MethodGet, "/v1/journal/summary", "")
	if rr.Code != 200 || json.Unmarshal(rr.Body.Bytes(), &sum) != nil || len(sum.Devices) != 2 {
		t.Fatal(rr.Body.String())
	}
	for path, want := range map[string]int{
		"/v1/journal?path=/etc/passwd":           400,
		"/v1/journal?device=x":                   400,
		"/v1/journal?limit=100000":               400,
		"/v1/journal/summary?device=192.0.2.10":  400,
		"/v1/journal/summary?from=notatime":      400,
		"/v1/journal?device=192.0.2.10&device=x": 400,
	} {
		if rr := f.call(http.MethodGet, path, ""); rr.Code != want {
			t.Errorf("%s: %d", path, rr.Code)
		}
	}
	for _, c := range []struct{ method, path, body string }{
		{http.MethodPost, "/v1/journal", ""}, {http.MethodPost, "/v1/health", ""}, {http.MethodGet, "/v1/journal/clear", ""},
	} {
		if rr := f.call(c.method, c.path, c.body); rr.Code != http.StatusMethodNotAllowed {
			t.Errorf("%s %s: %d", c.method, c.path, rr.Code)
		}
	}
	if rr := f.call(http.MethodPost, "/v1/journal/clear", `{"dir":"/"}`); rr.Code != 400 {
		t.Fatalf("clear with a body: %d", rr.Code)
	}
	if rr := f.call(http.MethodPost, "/v1/journal/clear?all=1", ""); rr.Code != 400 {
		t.Fatalf("clear with a parameter: %d", rr.Code)
	}

	// Health carries counts only.
	rr = f.call(http.MethodGet, "/v1/health", "")
	var h Health
	if rr.Code != 200 || json.Unmarshal(rr.Body.Bytes(), &h) != nil || !h.Ready || !h.MACLookup || h.Journal == nil || h.Journal.Records != 3 || h.Reader.Parsed != 3 {
		t.Fatal(rr.Body.String())
	}
	for _, leak := range []string{"example.test", "192.0.2.1"} {
		if strings.Contains(rr.Body.String(), leak) {
			t.Fatalf("health carries %q: %s", leak, rr.Body.String())
		}
	}

	// A restart: the records are there, the position is kept, nothing twice.
	f.d.Close()
	f.clock.Add(time.Minute)
	f.start()
	f.write("192.0.2.10", "two.example.test", "192.0.2.2", 1)
	f.step()
	if page, rr = getPage("/v1/journal"); page.Matched != 4 || page.Records[0].Name != "two.example.test" || page.Records[0].ID != 4 {
		t.Fatal(rr.Body.String())
	}

	// Clear: the records, and the names still in the raw audit file.
	rr = f.call(http.MethodPost, "/v1/journal/clear", "")
	var cr ClearResult
	if rr.Code != 200 || json.Unmarshal(rr.Body.Bytes(), &cr) != nil || cr.Cleared != 4 || cr.RawBytes == 0 || !cr.Complete || cr.Residual != nil || cr.Errors != nil {
		t.Fatal(rr.Body.String())
	}
	filepath.Walk(filepath.Dir(f.cfg.RawDir), func(p string, fi os.FileInfo, err error) error {
		if err == nil && fi.Mode().IsRegular() {
			if b, _ := os.ReadFile(p); bytes.Contains(b, []byte("example.test")) {
				t.Errorf("%s still holds a name after clear", p)
			}
		}
		return nil
	})
	f.write("192.0.2.10", "three.example.test", "192.0.2.3", 1)
	f.step()
	if page, rr = getPage("/v1/journal"); page.Matched != 1 || page.Records[0].Name != "three.example.test" {
		t.Fatal(rr.Body.String())
	}
	// Every file of the feature is 0600 in a 0700 directory.
	filepath.Walk(filepath.Dir(f.cfg.RawDir), func(p string, fi os.FileInfo, err error) error {
		if err != nil || p == filepath.Dir(f.cfg.RawDir) {
			return nil
		}
		if want := os.FileMode(0o600); fi.IsDir() && fi.Mode().Perm() != 0o700 || !fi.IsDir() && fi.Mode().Perm() != want {
			t.Errorf("%s is %v", p, fi.Mode())
		}
		return nil
	})
	if s := logs.String(); strings.Contains(s, "example.test") || strings.Contains(s, "192.0.2.") {
		t.Fatalf("the reader logged journal content: %s", s)
	}
}

// The raw side follows the journal's configured age bound: once a query's
// record has expired, its name is in no file of the feature, although the
// resolver never rotated its audit file.
func TestDaemonRawFollowsMaxAge(t *testing.T) {
	f := newDaemonFix(t)
	f.d.Close()
	f.cfg.MaxAge = 2 * time.Hour
	f.start()
	defer func() { f.d.Close() }()
	holders := func(name string) (out []string) {
		filepath.Walk(filepath.Dir(f.cfg.RawDir), func(p string, fi os.FileInfo, err error) error {
			if err == nil && fi.Mode().IsRegular() {
				if b, _ := os.ReadFile(p); bytes.Contains(b, []byte(name)) {
					out = append(out, filepath.Base(p))
				}
			}
			return nil
		})
		return out
	}
	f.write("192.0.2.10", "old.example.test", "192.0.2.1", 2)
	f.step()
	f.clock.Add(time.Hour)
	f.write("192.0.2.10", "mid.example.test", "192.0.2.1", 2)
	f.step()
	if got := holders("old.example.test"); len(got) != 2 {
		t.Fatalf("before the bound: %v", got)
	}
	f.clock.Add(90 * time.Minute)
	f.write("192.0.2.10", "new.example.test", "192.0.2.1", 2)
	f.step()
	if got := holders("old.example.test"); len(got) != 0 {
		t.Fatalf("2.5 hours later the name is still in %v", got)
	}
	h := f.d.Health()
	if h.Reader.RawAgeTruncated != 1 || h.Reader.RawTruncated != 0 || h.Reader.Parsed != 3 || !h.Ready {
		t.Fatalf("%+v", h.Reader)
	}
	var page Page
	if rr := f.call(http.MethodGet, "/v1/journal", ""); rr.Code != 200 || json.Unmarshal(rr.Body.Bytes(), &page) != nil ||
		page.Matched != 2 || page.Records[0].Name != "new.example.test" || page.Records[1].Name != "mid.example.test" {
		t.Fatal(rr.Body.String())
	}
	// After a restart the reader goes on where the file starts again.
	f.d.Close()
	f.clock.Add(time.Minute)
	f.start()
	f.write("192.0.2.10", "next.example.test", "192.0.2.1", 2)
	f.step()
	if rr := f.call(http.MethodGet, "/v1/journal", ""); rr.Code != 200 || json.Unmarshal(rr.Body.Bytes(), &page) != nil ||
		page.Matched != 3 || page.Records[0].Name != "next.example.test" {
		t.Fatal(rr.Body.String())
	}
}

// Without a journal the reader still keeps the raw directory in order and
// says what it dropped; the journal requests answer 404.
func TestDaemonWithoutJournal(t *testing.T) {
	base := t.TempDir()
	cfg := DaemonConfig{RawDir: filepath.Join(base, "raw"), JournalDir: filepath.Join(base, "journal"), MaxRecords: 10, MaxAge: time.Hour, MaxBytes: DefaultMaxBytes}
	PrepareSink(cfg.RawDir)
	os.WriteFile(cfg.JournalDir, []byte("in the way"), 0o600)
	clock := newClock()
	d, err := NewDaemon(cfg, nil, clock.Now)
	if err == nil || d == nil || d.Journal != nil {
		t.Fatalf("%v", err)
	}
	defer d.Close()
	p := filepath.Join(cfg.RawDir, AuditBase)
	os.WriteFile(p, []byte(auditLine(clock.Now(), "192.0.2.10", "one.example.test", 1, 1, "default", "")), 0o640)
	d.Tail.Step()
	h := d.Health()
	if h.Ready || h.Journal != nil || h.NoJournalDropped != 1 || h.MACLookup {
		t.Fatalf("%+v", h)
	}
	if fi, _ := os.Stat(p); fi.Mode().Perm() != 0o600 {
		t.Fatalf("housekeeping stopped without a journal: %v", fi.Mode())
	}
	for _, path := range []string{"/v1/journal", "/v1/journal/summary"} {
		rr := httptest.NewRecorder()
		d.StatusHandler().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, path, nil))
		if rr.Code != http.StatusNotFound {
			t.Errorf("%s: %d", path, rr.Code)
		}
	}
}

// The status socket answers uid 0 only: another local user's connection is
// closed without an answer.
func TestDaemonStatusRootOnly(t *testing.T) {
	f := newDaemonFix(t)
	defer f.d.Close()
	f.write("192.0.2.10", "one.example.test", "192.0.2.1", 2)
	f.step()
	for uid, want := range map[int]bool{0: true, 1000: false, 65530: false} {
		dir, err := os.MkdirTemp("", "dj")
		if err != nil {
			t.Fatal(err)
		}
		defer os.RemoveAll(dir)
		sock := filepath.Join(dir, "s")
		l, err := net.Listen("unix", sock)
		if err != nil {
			t.Fatal(err)
		}
		pl := &sniff.PeerListener{Listener: l, Allow: sniff.StatusRootOnly, Peer: func(net.Conn) (int, error) { return uid, nil }}
		srv := &http.Server{Handler: f.d.StatusHandler()}
		go srv.Serve(pl)
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		b, code, err := sniff.StatusCall(ctx, sock, http.MethodGet, "/v1/journal")
		cancel()
		srv.Close()
		if got := err == nil && code == 200 && bytes.Contains(b, []byte("one.example.test")); got != want {
			t.Errorf("uid %d: answered %v (err %v)", uid, got, err)
		}
		if !want && pl.Refused.Load() == 0 {
			t.Errorf("uid %d: not counted as refused", uid)
		}
	}
}

func TestGate(t *testing.T) {
	const img = "sha256:0000000000000000000000000000000000000000000000000000000000000001"
	ok := Facts{Provider: "container", Running: true, Version: "1.2026.11.09-1240", ImageID: img, MountFound: true, MountRW: true}
	if c := Evaluate(ok); !c.Available || c.VerifiedBy != "builtin" || c.VerifiedOn != "2026-11-15" || c.Code != "" {
		t.Fatalf("%+v", c)
	}
	mod := func(f func(*Facts)) Facts { x := ok; f(&x); return x }
	for want, f := range map[string]Facts{
		CodeNoResolver:      mod(func(f *Facts) { f.Provider = "" }),
		CodeHostUnit:        mod(func(f *Facts) { f.Provider = "unit" }),
		CodeNotRunning:      mod(func(f *Facts) { f.Running = false }),
		CodeVersionUnknown:  mod(func(f *Facts) { f.Version = "" }),
		CodeVersionUnproven: mod(func(f *Facts) { f.Version = "1.2026.08.05-0921" }), // the version pinned for the nodes: never inferred
		CodeNoMount:         mod(func(f *Facts) { f.MountFound = false }),
		CodeMountReadOnly:   mod(func(f *Facts) { f.MountRW = false }),
	} {
		c := Evaluate(f)
		if c.Available || c.Code != want || c.Reason == "" {
			t.Errorf("%s: %+v", want, c)
		}
	}
	// A version verified on this host counts only for the same image.
	local := mod(func(f *Facts) {
		f.Version = "1.2027.01.02-0304"
		f.Local = ParseLocalVerified("# verified by deploy/verify-smartdns.sh --audit-check\n1.2027.01.02-0304 " + img + " 2027-01-05\nnot a record\n1.2 short 2027-01-05\n")
	})
	if len(local.Local) != 1 {
		t.Fatalf("%+v", local.Local)
	}
	if c := Evaluate(local); !c.Available || c.VerifiedBy != "host_record" || c.VerifiedOn != "2027-01-05" {
		t.Fatalf("%+v", c)
	}
	local.ImageID = strings.Replace(img, "1", "2", 1)
	if c := Evaluate(local); c.Available || c.Code != CodeVersionUnproven || !strings.Contains(c.Action, "--audit-check") {
		t.Fatalf("a record for another image was accepted: %+v", c)
	}
	for out, want := range map[string]string{
		"smartdns 1.2026.11.09-1240\n":               "1.2026.11.09-1240",
		"smartdns 1.2026.11.09-1240":                 "1.2026.11.09-1240",
		"warning: x\nsmartdns 1.2026.08.05-0921":     "1.2026.08.05-0921",
		"smartdns 1.2026.08.05-0921 (Release48.4)\n": "1.2026.08.05-0921",
		"smartdns":                              "",
		"OCI runtime exec failed: no such file": "",
		"smartdns $(reboot)":                    "",
	} {
		if got := ParseVersion(out); got != want {
			t.Errorf("%q: %q", out, got)
		}
	}
	for conf, want := range map[string][2]bool{
		"audit-enable yes\naudit-file " + AuditFile + "\n":  {true, true},
		"audit-enable yes\naudit-file /var/log/audit.log\n": {true, false},
		"audit-enable yes\n": {true, false},
		"# audit-enable yes\n#audit-file " + AuditFile + "\n": {false, false},
		"audit-enable no\naudit-file " + AuditFile + "\n":     {false, false},
		"cache-size 1\n": {false, false},
	} {
		a := ReadAuditConfig(conf)
		if a.Enabled != want[0] || a.Managed() != want[1] {
			t.Errorf("%q: %+v", conf, a)
		}
	}
}

// ------------------------------------------------- clear: injected faults ---

func (f *daemonFix) health() Health {
	f.t.Helper()
	var h Health
	rr := f.call(http.MethodGet, "/v1/health", "")
	if rr.Code != 200 || json.Unmarshal(rr.Body.Bytes(), &h) != nil {
		f.t.Fatalf("health: %d %s", rr.Code, rr.Body.String())
	}
	return h
}

func (f *daemonFix) clear() (ClearResult, string) {
	f.t.Helper()
	var cr ClearResult
	rr := f.call(http.MethodPost, "/v1/journal/clear", "")
	if rr.Code != 200 || json.Unmarshal(rr.Body.Bytes(), &cr) != nil {
		f.t.Fatalf("clear: %d %s", rr.Code, rr.Body.String())
	}
	return cr, rr.Body.String()
}

func (f *daemonFix) matched(query string) int {
	f.t.Helper()
	var p Page
	rr := f.call(http.MethodGet, "/v1/journal"+query, "")
	if rr.Code != 200 || json.Unmarshal(rr.Body.Bytes(), &p) != nil {
		f.t.Fatalf("journal: %d %s", rr.Code, rr.Body.String())
	}
	return p.Matched
}

// A clear that fails on both sides — a segment and a rotated copy that
// cannot be deleted, an audit file that cannot be emptied — answers
// "complete": false with what is left and why, in counts and fixed words.
// The residue stays queryable and known, nothing of it is ingested again,
// a restarted reader still knows it, and the clear asked again completes.
func TestDaemonClearPartialThenRestartThenRetry(t *testing.T) {
	var logs bytes.Buffer
	log.SetOutput(&logs)
	defer log.SetOutput(os.Stderr)
	f := newDaemonFix(t)
	defer func() { f.d.Close() }()
	f.write("192.0.2.10", "old.example.test", "192.0.2.1", 2)
	f.step()
	// The resolver rotates; one more line, read as well.
	audit := filepath.Join(f.cfg.RawDir, AuditBase)
	rotated := filepath.Join(f.cfg.RawDir, "audit.log-20261115-120000")
	if err := os.Rename(audit, rotated); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(audit, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	f.clock.Add(time.Second)
	f.write("192.0.2.11", "cur.example.test", "192.0.2.2", 2)
	f.step()
	f.step()
	if n := f.matched(""); n != 2 {
		t.Fatalf("%d records before the clear", n)
	}
	rawSize := func(p string) int64 {
		fi, err := os.Lstat(p)
		if err != nil {
			t.Fatal(err)
		}
		return fi.Size()
	}
	left := rawSize(audit) + rawSize(rotated)

	seg := newFault("remove", ".jsonl", syscall.EACCES)
	cp := newFault("remove", "audit.log-", syscall.EACCES)
	tr := newFault("truncate", AuditBase, syscall.EROFS)
	f.faults = []*fsFault{seg, cp, tr}
	f.clock.Add(time.Second)
	cr, body := f.clear()
	if cr.Complete || cr.Cleared != 0 || cr.RawBytes != 0 || cr.Residual == nil ||
		*cr.Residual != (ClearResidual{Segments: 1, Records: 2, Bytes: cr.Residual.Bytes, RawFiles: 2, RawBytes: left}) || cr.Residual.Bytes == 0 || len(cr.Errors) != 3 {
		t.Fatalf("%s", body)
	}
	for _, leak := range []string{"example.test", "192.0.2.", filepath.Dir(f.cfg.RawDir), "audit.log", "dns-0", "denied", "read-only"} {
		if strings.Contains(body+cr.Problem(), leak) {
			t.Fatalf("the answer carries %q: %s / %s", leak, body, cr.Problem())
		}
	}
	// Nothing was removed and nothing is hidden: the records still answer.
	if n := f.matched(""); n != 2 {
		t.Fatalf("%d records after the failed clear", n)
	}
	h := f.health()
	if h.Journal.Residual == nil || h.Journal.Residual.Records != 2 || h.Journal.Residual.ClearAt == nil || h.Journal.ClearedAt != nil ||
		h.Reader.ClearPendingAt == nil || h.Reader.RawResidualFiles != 2 || h.Reader.RawResidualBytes != left {
		t.Fatalf("%+v %+v", h.Journal, h.Reader)
	}

	// The audit file that could not be emptied is not read again; a new
	// line is read once.
	f.clock.Add(time.Second)
	f.write("192.0.2.10", "new.example.test", "192.0.2.3", 2)
	f.step()
	f.step()
	if n, c := f.matched(""), f.matched("?text=cur.example"); n != 3 || c != 1 {
		t.Fatalf("%d records, %d of the old line (ingested again?)", n, c)
	}

	// Restart with the faults still there: the residue is known again.
	f.d.Close()
	f.clock.Add(time.Minute)
	f.start()
	f.write("192.0.2.10", "after.example.test", "192.0.2.4", 2)
	f.step()
	f.step()
	h = f.health()
	if h.Journal.Residual == nil || h.Journal.Residual.Segments != 1 || h.Journal.Residual.Records != 2 || h.Journal.Residual.ClearAt == nil ||
		h.Reader.ClearPendingAt == nil || h.Reader.RawResidualFiles != 2 || h.Reader.RawResidualBytes != left || h.Journal.Records != 4 {
		t.Fatalf("after the restart: %+v %+v %+v", h.Journal, h.Journal.Residual, h.Reader)
	}
	for q, want := range map[string]int{"": 4, "?text=old.example": 1, "?text=cur.example": 1, "?text=new.example": 1, "?text=after.example": 1} {
		if n := f.matched(q); n != want {
			t.Fatalf("after the restart %q: %d, want %d", q, n, want)
		}
	}
	// Asked again while the faults last: still not a success, and now
	// everything that is there is what a clear could not delete.
	if cr, body = f.clear(); cr.Complete || cr.Cleared != 0 || cr.Residual == nil || cr.Residual.Records != 4 || cr.Residual.Segments != 3 || cr.Residual.RawFiles != 2 {
		t.Fatalf("%s", body)
	}
	if n := f.matched(""); n != 4 {
		t.Fatalf("%d records after the second failed clear", n)
	}

	// The faults are gone: the retry completes and nothing is left.
	f.faults = nil
	if cr, body = f.clear(); !cr.Complete || cr.Cleared != 4 || cr.Residual != nil || cr.Errors != nil || cr.RawBytes == 0 {
		t.Fatalf("%s", body)
	}
	h = f.health()
	if h.Journal.Residual != nil || h.Journal.Records != 0 || h.Journal.ClearedAt == nil || h.Reader.ClearPendingAt != nil || h.Reader.RawResidualFiles != 0 || h.Reader.RawFiles != 1 || h.Reader.RawBytes != 0 {
		t.Fatalf("%+v %+v", h.Journal, h.Reader)
	}
	filepath.Walk(filepath.Dir(f.cfg.RawDir), func(p string, fi os.FileInfo, err error) error {
		if err == nil && fi.Mode().IsRegular() {
			if b, _ := os.ReadFile(p); bytes.Contains(b, []byte("example.test")) {
				t.Errorf("%s still holds a name after the completed clear", p)
			}
		}
		return nil
	})
	if hasMark(f.cfg.JournalDir) {
		t.Fatal("the clear mark is still there")
	}
	f.clock.Add(time.Second)
	f.write("192.0.2.10", "fresh.example.test", "192.0.2.5", 2)
	f.step()
	if n := f.matched(""); n != 1 {
		t.Fatalf("%d records after the completed clear", n)
	}
	if s := logs.String(); strings.Contains(s, "example.test") || strings.Contains(s, "192.0.2.") {
		t.Fatalf("the reader logged journal content: %s", s)
	}
}

// Clears while the resolver writes and the reader reads (run with -race):
// whatever the interleaving, and with a truncation that fails in between,
// a line is never recorded twice, records keep the order they were written
// in, nothing written before the last clear is in the journal afterwards,
// and reading goes on.
func TestDaemonClearWhileWriting(t *testing.T) {
	f := newDaemonFix(t)
	defer func() { f.d.Close() }()
	tr := newFault("truncate", AuditBase, syscall.EIO)
	tr.set(false)
	f.faults = []*fsFault{tr}
	audit := filepath.Join(f.cfg.RawDir, AuditBase)
	var written atomic.Int64 // lines completely written
	stop := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { // the resolver
		defer wg.Done()
		fd, err := os.OpenFile(audit, os.O_WRONLY|os.O_APPEND, 0)
		if err != nil {
			t.Error(err)
			return
		}
		defer fd.Close()
		for i := int64(1); ; i++ {
			select {
			case <-stop:
				return
			default:
			}
			if _, err := fd.WriteString(auditLine(f.clock.Now(), "192.0.2.10", fmt.Sprintf("w%06d.example.test", i), 1, 2, "default", "192.0.2.1")); err != nil {
				t.Error(err)
				return
			}
			written.Store(i)
			if i%8 == 0 {
				time.Sleep(time.Millisecond)
			}
		}
	}()
	go func() { // the reader's ticker
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
				f.d.Step()
				time.Sleep(time.Millisecond)
			}
		}
	}()
	var before int64
	for round := 0; round < 6; round++ {
		time.Sleep(15 * time.Millisecond)
		// An empty audit file needs no truncate (a clear of it is complete
		// whatever the fault): wait for the resolver to have written into
		// it since the last clear. Only a clear makes it shorter.
		for deadline := time.Now().Add(10 * time.Second); ; time.Sleep(time.Millisecond) {
			if fi, err := os.Stat(audit); err == nil && fi.Size() > 0 {
				break
			}
			if time.Now().After(deadline) {
				t.Fatalf("round %d: nothing written", round)
			}
		}
		failing := round == 2 || round == 5 // these cannot empty the audit file; the last one is one of them
		tr.set(failing)
		before = written.Load()
		if cr := f.d.Clear(); cr.Complete == failing {
			t.Errorf("round %d: complete %v", round, cr.Complete)
		}
	}
	time.Sleep(15 * time.Millisecond)
	close(stop)
	wg.Wait()
	// One more line after everything, and a last read.
	last := written.Load() + 1
	fd, _ := os.OpenFile(audit, os.O_WRONLY|os.O_APPEND, 0)
	fd.WriteString(auditLine(f.clock.Now(), "192.0.2.10", fmt.Sprintf("w%06d.example.test", last), 1, 2, "default", "192.0.2.1"))
	fd.Close()
	for i := 0; i < 50; i++ {
		f.step()
	}
	if h := f.d.Health(); h.Journal.Dropped != 0 || h.Journal.WriteErrors != 0 {
		t.Fatalf("%+v", h.Journal)
	}
	seen := map[string]bool{}
	var prev int64
	n := 0
	f.d.Journal.each(func(r *Record) bool { // newest first
		n++
		var idx int64
		if _, err := fmt.Sscanf(r.Name, "w%06d.example.test", &idx); err != nil {
			t.Fatalf("record %q", r.Name)
		}
		switch {
		case seen[r.Name]:
			t.Fatalf("%s recorded twice", r.Name)
		case idx <= before:
			t.Fatalf("%s was written before the last clear (which had seen %d lines) and is in the journal", r.Name, before)
		case prev != 0 && idx >= prev:
			t.Fatalf("out of order: %d after %d", prev, idx)
		case n == 1 && idx != last:
			t.Fatalf("the newest record is %d, the last line written was %d", idx, last)
		}
		seen[r.Name], prev = true, idx
		return true
	})
	if n == 0 {
		t.Fatal("nothing was read after the clears")
	}
}

// A reader without a journal (its directory could not be used at start)
// still clears the segment files that are there, and still reports what it
// could not delete.
func TestDaemonClearWithoutJournal(t *testing.T) {
	f := newDaemonFix(t)
	f.write("192.0.2.10", "one.example.test", "192.0.2.1", 2)
	f.step()
	f.d.Close()
	f.d.Journal = nil // as NewDaemon leaves it when Open fails
	f.d.Tail = NewTailer(TailConfig{Dir: f.cfg.RawDir, PositionPath: filepath.Join(f.cfg.JournalDir, positionFile), Now: f.clock.Now})
	stuck := newFault("remove", ".jsonl", syscall.EACCES)
	f.d.fault = faultsOf(stuck)
	cr := f.d.Clear()
	if cr.Complete || cr.Residual == nil || cr.Residual.Segments != 1 || cr.Residual.Records != 1 || len(cr.Errors) != 1 || !hasMark(f.cfg.JournalDir) {
		t.Fatalf("%+v %+v", cr, cr.Residual)
	}
	stuck.set(false)
	if cr = f.d.Clear(); !cr.Complete || cr.PurgedFiles == 0 || len(segFiles(t, f.cfg.JournalDir)) != 0 || hasMark(f.cfg.JournalDir) {
		t.Fatalf("%+v", cr)
	}
	f.d.Tail.Close()
	f.start() // for the deferred cleanup of other tests' pattern
	f.d.Close()
}
