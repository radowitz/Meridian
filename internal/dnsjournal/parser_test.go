package dnsjournal

import (
	"bytes"
	"compress/gzip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// The four lines observed on 2026-11-15 with the gateway's resolver binary
// (synthetic names; the client was loopback in the throw-away container).
const observedLines = `[2026-11-15 12:09:35,961] 127.0.0.1 query a.example.test, type 1, time 0ms, speed: -0.1ms, group default, result 192.0.2.1
[2026-11-15 12:09:35,962] 127.0.0.1 query b.example.test, type 28, time 0ms, speed: -0.1ms, group default, result 2001:db8::1
[2026-11-15 12:09:35,968] 127.0.0.1 query nx.example.test, type 1, time 3ms, speed: -0.1ms, group default, result 
[2026-11-15 12:09:37,973] 127.0.0.1 query up.example.test, type 1, time 2005ms, speed: -0.1ms, group g_test, result 
`

func TestParseObservedLines(t *testing.T) {
	type want struct {
		name, group, class string
		qtype, answers     int
		elapsed            int64
		ms                 int
	}
	wants := []want{
		{"a.example.test", "default", ResultAnswered, 1, 1, 0, 961},
		{"b.example.test", "default", ResultAnswered, 28, 1, 0, 962},
		{"nx.example.test", "default", ResultNoAnswer, 1, 0, 3, 968},
		{"up.example.test", "g_test", ResultNoAnswerSlow, 1, 0, 2005, 973},
	}
	lines := strings.Split(strings.TrimSuffix(observedLines, "\n"), "\n")
	if len(lines) != len(wants) {
		t.Fatalf("%d lines", len(lines))
	}
	for i, l := range lines {
		r, err := ParseLine([]byte(l))
		if err != nil {
			t.Fatalf("line %d: %v", i, err)
		}
		w := wants[i]
		if r.Name != w.name || r.Group != w.group || r.QType != w.qtype || r.Answers != w.answers || r.Other != 0 || r.Elapsed != w.elapsed ||
			Classify(r.Answers, r.Other, r.Elapsed) != w.class || r.Client.String() != "127.0.0.1" {
			t.Errorf("line %d: %+v", i, r)
		}
		if r.Naive.Year() != 2026 || r.Naive.Hour() != 12 || r.Naive.Nanosecond()/1e6 != w.ms || r.Naive.Location() != time.UTC {
			t.Errorf("line %d: time %v", i, r.Naive)
		}
	}
}

// What was not observed is parsed tolerantly: several answers (any of the
// plausible separators), IPv6 and IPv4-mapped clients, bracketed clients
// with a port, long and odd names.
func TestParseUnobservedShapes(t *testing.T) {
	line := func(client, name, result string) string {
		return "[2026-11-15 12:09:35,961] " + client + " query " + name + ", type 1, time 12ms, speed: 3.5ms, group rg_hk, result " + result
	}
	for _, c := range []struct {
		in             string
		client, name   string
		answers, other int
	}{
		{line("192.0.2.10", "multi.example.test", "192.0.2.1, 192.0.2.2, 2001:db8::2"), "192.0.2.10", "multi.example.test", 3, 0},
		{line("192.0.2.10", "multi.example.test", "192.0.2.1,192.0.2.2"), "192.0.2.10", "multi.example.test", 2, 0},
		{line("192.0.2.10", "multi.example.test", "192.0.2.1 192.0.2.2"), "192.0.2.10", "multi.example.test", 2, 0},
		{line("192.0.2.10", "cname.example.test", "alias.example.test, 192.0.2.9"), "192.0.2.10", "cname.example.test", 1, 1},
		{line("2001:db8:1::10", "v6.example.test", "192.0.2.1"), "2001:db8:1::10", "v6.example.test", 1, 0},
		{line("::ffff:192.0.2.10", "mapped.example.test", "192.0.2.1"), "192.0.2.10", "mapped.example.test", 1, 0},
		{line("[2001:db8:1::10]:53124", "port.example.test", "192.0.2.1"), "2001:db8:1::10", "port.example.test", 1, 0},
		{line("192.0.2.10:53124", "port4.example.test", "192.0.2.1"), "192.0.2.10", "port4.example.test", 1, 0},
		{line("192.0.2.10", "UPPER.Example.TEST.", ""), "192.0.2.10", "upper.example.test", 0, 0},
		{line("192.0.2.10", "xn--bcher-kva.example", "192.0.2.1"), "192.0.2.10", "xn--bcher-kva.example", 1, 0},
		{line("192.0.2.10", "_dmarc.a_b.example.test", ""), "192.0.2.10", "_dmarc.a_b.example.test", 0, 0},
	} {
		r, err := ParseLine([]byte(c.in))
		if err != nil {
			t.Errorf("%q: %v", c.in, err)
			continue
		}
		if r.Client.String() != c.client || r.Name != c.name || r.Answers != c.answers || r.Other != c.other || r.Group != "rg_hk" || r.Elapsed != 12 {
			t.Errorf("%q: %+v", c.in, r)
		}
	}
	// A name longer than a DNS name is cut, never rejected and never longer
	// than MaxName.
	long := strings.Repeat("a", 60) + "." + strings.Repeat("b", 60) + "." + strings.Repeat("c", 60) + "." + strings.Repeat("d", 60) + "." + strings.Repeat("e", 60) + ".example.test"
	r, err := ParseLine([]byte(line("192.0.2.10", long, "")))
	if err != nil || len(r.Name) != MaxName || !strings.HasPrefix(long, r.Name) {
		t.Fatalf("long name: %v %d", err, len(r.Name))
	}
	// A name that itself contains a complete tail cannot set its line's
	// type, group or result: the last tail of the line is the real one.
	forged := `x.example.test, type 1, time 0ms, speed: -0.1ms, group domestic, result 192.0.2.66`
	r, err = ParseLine([]byte("[2026-11-15 12:09:35,961] 192.0.2.10 query " + forged + ", type 28, time 7ms, speed: -0.1ms, group g_real, result "))
	if err != nil || r.Group != "g_real" || r.QType != 28 || r.Answers != 0 || r.Elapsed != 7 || !strings.HasPrefix(r.Name, "x.example.test, type 1") {
		t.Fatalf("forged tail: %v %+v", err, r)
	}
	// Control characters never reach a record.
	r, err = ParseLine([]byte(line("192.0.2.10", "tab\there.example.test", "")))
	if err != nil || strings.ContainsAny(r.Name, "\t\r\n\x00") {
		t.Fatalf("control characters: %v %q", err, r.Name)
	}
}

func TestParseBadLines(t *testing.T) {
	for _, in := range []string{
		"",
		"smartdns starting",
		"[2026-11-15 12:09:35,961] 192.0.2.10 query a.example.test",
		"[2026-11-15 12:09:35,961] not-an-address query a.example.test, type 1, time 0ms, speed: -0.1ms, group default, result 192.0.2.1",
		"[2026-13-45 99:09:35,961] 192.0.2.10 query a.example.test, type 1, time 0ms, speed: -0.1ms, group default, result 192.0.2.1",
		"[2026-11-15 12:09:35,961] 192.0.2.10 query a.example.test, type A, time 0ms, speed: -0.1ms, group default, result 192.0.2.1",
		"[2026-11-15 12:09:35,961] 192.0.2.10 query a.example.test, type 70000, time 0ms, speed: -0.1ms, group default, result ",
		"[2026-11-15 12:09:35,961] 192.0.2.10 query , type 1, time 0ms, speed: -0.1ms, group default, result ",
		"[2026-11-15 12:09:35,961] 192.0.2.10 query a.example.test, type 1, time 0ms, speed: -0.1ms, group default",
		string([]byte{0, 0, 0, 0, 0, 0}),
		string([]byte{0xff, 0xfe, 'x'}),
		"[2026-11-15 12:09:35,961] 192.0.2.10 query " + strings.Repeat("a", MaxRawLine) + ", type 1, time 0ms, speed: -0.1ms, group default, result ",
	} {
		if _, err := ParseLine([]byte(in)); err != ErrNoMatch {
			t.Errorf("%.60q: %v", in, err)
		}
	}
}

func TestClassify(t *testing.T) {
	for _, c := range []struct {
		a, o int
		ms   int64
		want string
	}{
		{1, 0, 0, ResultAnswered}, {0, 1, 5000, ResultAnswered}, {0, 0, 0, ResultNoAnswer}, {0, 0, SlowEmptyMS - 1, ResultNoAnswer},
		{0, 0, SlowEmptyMS, ResultNoAnswerSlow}, {0, 0, 2005, ResultNoAnswerSlow},
	} {
		if got := Classify(c.a, c.o, c.ms); got != c.want {
			t.Errorf("%+v: %s", c, got)
		}
	}
}

// writeGzip writes a rotated audit file as the resolver names it.
func writeGzip(t *testing.T, path, body string) {
	t.Helper()
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	if _, err := zw.Write([]byte(body)); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, buf.Bytes(), 0o640); err != nil {
		t.Fatal(err)
	}
}

// A gzip-compressed rotated file gives the same lines; a truncated archive
// gives its readable part; the read is bounded; a special file is refused.
func TestReadRotatedGzip(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "audit.log-20261115-120940.gz")
	writeGzip(t, p, observedLines)
	b, err := ReadRotated(p, 1<<20)
	if err != nil || string(b) != observedLines {
		t.Fatalf("%v %q", err, b)
	}
	n := 0
	for _, l := range bytes.Split(b, []byte{'\n'}) {
		if len(l) == 0 {
			continue
		}
		if _, err := ParseLine(l); err != nil {
			t.Fatalf("%q: %v", l, err)
		}
		n++
	}
	if n != 4 {
		t.Fatalf("%d lines", n)
	}
	if b, _ := ReadRotated(p, 100); len(b) != 100 {
		t.Fatalf("limit: %d", len(b))
	}
	raw, _ := os.ReadFile(p)
	cut := filepath.Join(dir, "audit.log-20261115-120941.gz")
	os.WriteFile(cut, raw[:len(raw)-12], 0o600)
	if b, _ := ReadRotated(cut, 1<<20); !bytes.HasPrefix(b, []byte("[2026-11-15 12:09:35,961]")) {
		t.Fatalf("truncated archive: %q", b)
	}
	plain := filepath.Join(dir, "audit.log-20261115-120942")
	os.WriteFile(plain, []byte(observedLines), 0o600)
	if b, err := ReadRotated(plain, 1<<20); err != nil || string(b) != observedLines {
		t.Fatalf("plain rotated: %v", err)
	}
	link := filepath.Join(dir, "audit.log-20261115-120943.gz")
	if err := os.Symlink(p, link); err == nil {
		if _, err := ReadRotated(link, 1<<20); err == nil {
			t.Fatal("a symbolic link was followed")
		}
	}
}
