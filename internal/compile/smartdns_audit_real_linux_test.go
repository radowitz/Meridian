//go:build linux

package compile

import (
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/radowitz/meridian/internal/defaults"
	"github.com/radowitz/meridian/internal/dnsjournal"
	"github.com/radowitz/meridian/internal/model"
)

// TestSmartDNSAuditRealBinary runs the SmartDNS binary named by
// MERIDIAN_SMARTDNS_BIN with the four audit directives this compiler
// renders and reads its audit file with the journal's own reader
// (dnsjournal.Tailer). Not run without the variable.
//
// What it covers: THE BINARY IT IS GIVEN, and only its audit line format,
// the file it creates and that the journal's reader parses every line —
// with the pinned node artifact (SmartDNS 1.2026.08.05-0921, the binary the
// panel delivers to remote exits) when that is what the variable names. It
// says nothing about the gateway's resolver, which is a container image of
// another version: the capability gate (dnsjournal.Evaluate) never infers
// the gateway's behaviour from this binary, and whether a full or blocked
// audit filesystem delays resolution is not checked here at all
// (deploy/verify-smartdns.sh --audit-check does that, against an image).
//
//	MERIDIAN_SMARTDNS_BIN=/path/to/smartdns go test ./internal/compile -run TestSmartDNSAuditRealBinary -v
func TestSmartDNSAuditRealBinary(t *testing.T) {
	bin := os.Getenv("MERIDIAN_SMARTDNS_BIN")
	if bin == "" {
		t.Skip("MERIDIAN_SMARTDNS_BIN not set: the audit format of a real SmartDNS binary was not checked")
	}
	out, err := exec.Command(bin, "-v").CombinedOutput()
	if err != nil {
		t.Fatalf("%s -v: %v %s", bin, err, out)
	}
	version := dnsjournal.ParseVersion(string(out))
	_, verified := dnsjournal.VerifiedVersions[version]
	t.Logf("binary: %s (version %q; on the gateway allow-list: %v) — this run covers this binary only", strings.TrimSpace(string(out)), version, verified)

	// The directives exactly as the gateway config gets them, with the
	// audit file moved into a prepared temporary directory.
	topo := defaults.Example()
	topo.Settings.DNSLog = &model.DNSLogSettings{Enabled: true}
	b, err := Compile(topo)
	if err != nil {
		t.Fatal(err)
	}
	raw := filepath.Join(t.TempDir(), "raw")
	if err := dnsjournal.PrepareSink(raw); err != nil {
		t.Fatal(err)
	}
	var audit []string
	for _, l := range strings.Split(b.File("nodes/gw/etc/smartdns/smartdns.conf"), "\n") {
		if strings.HasPrefix(l, "audit-") {
			audit = append(audit, strings.Replace(l, dnsjournal.AuditFile, filepath.Join(raw, dnsjournal.AuditBase), 1))
		}
	}
	if len(audit) != 4 {
		t.Fatalf("audit directives: %q", audit)
	}
	port := freeUDPPort(t)
	dead := freeUDPPort(t) // nothing listens: the upstream never answers
	conf := fmt.Sprintf(`bind 127.0.0.1:%d
bind-tcp 127.0.0.1:%d
cache-size 0
speed-check-mode none
address /ready.example.net/192.0.2.250
address /a.example.test/192.0.2.1
address /b.example.test/2001:db8::1
address /multi.example.test/192.0.2.1,192.0.2.2,192.0.2.3
address /blocked.example.test/#
server 127.0.0.1:%d
%s
`, port, port, dead, strings.Join(audit, "\n"))
	sd := startSmartDNS(t, bin, conf)
	ask := func(name string, qt uint16) {
		_, _ = dnsQuery(sd.addr, name, qt, 5*time.Second)
	}
	ask("a.example.test", qA)
	ask("b.example.test", qAAAA)
	ask("multi.example.test", qA)
	ask("blocked.example.test", qA)
	ask("nx.example.test", qA)
	ask(strings.Repeat("l", 60)+"."+strings.Repeat("m", 60)+"."+strings.Repeat("n", 60)+".example.test", qA)

	// The journal's reader over the directory the resolver writes.
	var mu sync.Mutex
	got := map[string][]dnsjournal.Record{}
	tail := dnsjournal.NewTailer(dnsjournal.TailConfig{Dir: raw, MaxRawBytes: 8 << 20,
		Lookup: func(netip.Addr) string { return "" },
		Emit: func(r dnsjournal.Record) {
			mu.Lock()
			got[r.Name] = append(got[r.Name], r)
			mu.Unlock()
		}})
	deadline := time.Now().Add(15 * time.Second)
	for {
		tail.Step()
		mu.Lock()
		done := len(got["nx.example.test"]) > 0 && len(got["multi.example.test"]) > 0
		mu.Unlock()
		if done || time.Now().After(deadline) {
			break
		}
		time.Sleep(300 * time.Millisecond)
	}
	st := tail.Stats()
	fi, err := os.Lstat(filepath.Join(raw, dnsjournal.AuditBase))
	if err != nil || !fi.Mode().IsRegular() {
		t.Fatalf("audit file: %v", err)
	}
	zone := "not established"
	if st.ZoneOffsetS != nil {
		zone = fmt.Sprintf("%d s", *st.ZoneOffsetS)
	}
	t.Logf("reader: %d lines, %d parsed, %d bad, %d too long; zone offset %s; file mode after the reader's pass %v", st.Lines, st.Parsed, st.Bad, st.TooLong, zone, fi.Mode().Perm())
	if st.Parsed == 0 || st.Bad != 0 || st.TooLong != 0 {
		t.Fatalf("this binary's audit lines are not all in the format the journal reads: %+v", st)
	}
	mu.Lock()
	defer mu.Unlock()
	one := func(name string) dnsjournal.Record {
		t.Helper()
		if len(got[name]) == 0 {
			t.Fatalf("no audit record for %s (records for %d names)", name, len(got))
		}
		return got[name][0]
	}
	if r := one("a.example.test"); r.Result != dnsjournal.ResultAnswered || r.Answers != 1 || r.QType != 1 || r.Client != "127.0.0.1" || r.Group == "" || r.TimeApprox ||
		time.Since(r.Time).Abs() > 2*time.Minute {
		t.Errorf("answered A: %+v", r)
	}
	if r := one("b.example.test"); r.Result != dnsjournal.ResultAnswered || r.QType != 28 || r.Answers != 1 {
		t.Errorf("answered AAAA: %+v", r)
	}
	if r := one("multi.example.test"); r.Answers != 3 || r.AnswersOther != 0 {
		t.Errorf("several answers: %+v", r)
	}
	if r := one("nx.example.test"); r.Result == dnsjournal.ResultAnswered || r.Answers != 0 {
		t.Errorf("no answer: %+v", r)
	}
	if n := len(got["blocked.example.test"]); n != 0 {
		t.Errorf("this binary audits a name blocked by an address rule (%d records): the journal's scope text says such names are absent", n)
	}
	long := 0
	for name := range got {
		if strings.HasPrefix(name, "lll") && len(name) > 180 {
			long++
		}
	}
	if long != 1 {
		t.Errorf("the long name is not in the journal as one name")
	}
	mu.Unlock()
	defer mu.Lock()

	// Rotation by the real binary, followed by the journal's reader: a
	// second resolver with a small audit-size is flooded while the reader
	// takes a pass every few queries, as it does every second in service.
	// Every query must become exactly one record: nothing lost across the
	// resolver's rename-and-compress, nothing read twice.
	raw2 := filepath.Join(t.TempDir(), "raw")
	if err := dnsjournal.PrepareSink(raw2); err != nil {
		t.Fatal(err)
	}
	port2 := freeUDPPort(t)
	sd.stop()
	sd2 := startSmartDNS(t, bin, fmt.Sprintf(`bind 127.0.0.1:%d
cache-size 0
speed-check-mode none
address /ready.example.net/192.0.2.250
address /flood.example.test/192.0.2.7
audit-enable yes
audit-file %s
audit-size 32k
audit-num 2
`, port2, filepath.Join(raw2, dnsjournal.AuditBase)))
	var mu2 sync.Mutex
	flood := 0
	tail2 := dnsjournal.NewTailer(dnsjournal.TailConfig{Dir: raw2, MaxRawBytes: 8 << 20, Emit: func(r dnsjournal.Record) {
		if r.Name == "flood.example.test" {
			mu2.Lock()
			flood++
			mu2.Unlock()
		}
	}})
	const queries = 900
	for i := 0; i < queries; i++ {
		if _, err := dnsQuery(sd2.addr, "flood.example.test", qA, 5*time.Second); err != nil {
			t.Fatalf("query %d: %v", i, err)
		}
		if i%25 == 24 {
			tail2.Step()
		}
	}
	count := func() int {
		mu2.Lock()
		defer mu2.Unlock()
		return flood
	}
	for end := time.Now().Add(10 * time.Second); count() < queries && time.Now().Before(end); time.Sleep(200 * time.Millisecond) {
		tail2.Step()
	}
	st2 := tail2.Stats()
	// The resolver compresses a rotated file in the background
	// (audit.log.pending.gz while it does): wait for it to finish.
	rot := regexp.MustCompile(`^audit\.log-\d{8}-\d{6}\.gz$`)
	var names []string
	for end := time.Now().Add(15 * time.Second); ; time.Sleep(200 * time.Millisecond) {
		names = names[:0]
		pending, rotated := false, 0
		ents, _ := os.ReadDir(raw2)
		for _, e := range ents {
			names = append(names, e.Name())
			pending = pending || strings.Contains(e.Name(), "pending")
			if rot.MatchString(e.Name()) {
				rotated++
			}
		}
		if (!pending && rotated > 0) || time.Now().After(end) {
			break
		}
	}
	t.Logf("rotation: %d queries, %d records, reader saw %d rotations, %d bad lines, skipped %d bytes; files now: %v", queries, count(), st2.Rotations, st2.Bad, st2.SkippedBytes, names)
	if st2.Rotations == 0 {
		t.Errorf("this binary did not rotate at audit-size 32k after %d queries: rotation was not exercised", queries)
	}
	if count() != queries || st2.Bad != 0 {
		t.Errorf("%d queries became %d records (%d bad lines) across %d rotations", queries, count(), st2.Bad, st2.Rotations)
	}
	nrot := 0
	for _, n := range names {
		switch {
		case rot.MatchString(n):
			nrot++
		case n != dnsjournal.AuditBase:
			t.Errorf("a file the reader does not expect in the audit directory: %s", n)
		}
	}
	if nrot == 0 || nrot > 2 {
		t.Errorf("%d rotated files with audit-num 2", nrot)
	}
	// The newest rotated file is read back as the same lines.
	for _, n := range names {
		if rot.MatchString(n) {
			b, err := dnsjournal.ReadRotated(filepath.Join(raw2, n), 8<<20)
			if err != nil || len(b) == 0 {
				t.Errorf("%s: %v", n, err)
				continue
			}
			for _, l := range strings.Split(strings.TrimSuffix(string(b), "\n"), "\n") {
				if _, err := dnsjournal.ParseLine([]byte(l)); err != nil {
					t.Errorf("%s holds a line the parser refuses", n)
					break
				}
			}
		}
	}
}
