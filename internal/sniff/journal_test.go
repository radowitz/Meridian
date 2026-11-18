package sniff

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeClock is a settable clock.
type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *fakeClock) Now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *fakeClock) Add(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

var jT0 = time.Date(2026, 11, 14, 8, 0, 0, 0, time.UTC)

func openJ(t *testing.T, dir string, clk *fakeClock, mod func(*JournalConfig)) *Journal {
	t.Helper()
	cfg := JournalConfig{Dir: dir, Now: clk.Now}
	if mod != nil {
		mod(&cfg)
	}
	j, err := OpenJournal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(j.Close)
	return j
}

func jrec(clk *fakeClock, i int) ConnRecord {
	r := ConnRecord{Start: clk.Now(), Source: fmt.Sprintf("192.0.2.%d", 10+i%5), Dest: fmt.Sprintf("198.51.100.%d:443", i%200),
		Proto: "tls", Name: fmt.Sprintf("host%d.example.com", i), Sniffed: true, By: "name", RuleIndex: i % 7, RuleID: "r1",
		Target: []string{"direct", "group:hk", "exit:jp-a"}[i%3], Result: []string{"ok", "dial_failed", "rejected", "ok"}[i%4]}
	if r.Result == ResultOK {
		r.End, r.BytesUp, r.BytesDown = EndClientClosed, 517, 4096
	}
	return r
}

// markerBytes is the size of the journal's marker file (0: none).
func markerBytes(dir string) int64 {
	if fi, err := os.Stat(filepath.Join(dir, journalMarker)); err == nil {
		return fi.Size()
	}
	return 0
}

// dirBytes is what the journal's files hold on disk now.
func dirBytes(t *testing.T, dir string) (int64, int) {
	t.Helper()
	ents, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var n int64
	for _, e := range ents {
		fi, err := e.Info()
		if err == nil {
			n += fi.Size()
		}
	}
	return n, len(ents)
}

func allLinesParse(t *testing.T, dir string) int {
	t.Helper()
	ents, _ := os.ReadDir(dir)
	n := 0
	for _, e := range ents {
		if e.Name() == journalMarker {
			continue
		}
		b, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		if len(b) > 0 && b[len(b)-1] != '\n' {
			t.Fatalf("%s does not end with a newline", e.Name())
		}
		for _, l := range bytes.Split(bytes.TrimRight(b, "\n"), []byte{'\n'}) {
			if len(l) == 0 {
				continue
			}
			var r JournalRecord
			if err := json.Unmarshal(l, &r); err != nil || r.ID == 0 {
				t.Fatalf("%s: bad line %q", e.Name(), l)
			}
			if len(l)+1 > JournalMaxLine {
				t.Fatalf("line of %d bytes", len(l))
			}
			n++
		}
	}
	return n
}

// The record bound: never more than MaxRecords on disk or in a query;
// the newest are kept.
func TestJournalRecordBound(t *testing.T) {
	clk := &fakeClock{t: jT0}
	dir := t.TempDir()
	j := openJ(t, dir, clk, func(c *JournalConfig) { c.MaxRecords = 100 })
	for i := 0; i < 1000; i++ {
		j.Add(jrec(clk, i))
		if i%50 == 49 {
			j.Flush()
			if n := allLinesParse(t, dir); n > 100 {
				t.Fatalf("%d records on disk after %d", n, i+1)
			}
		}
	}
	j.Flush()
	st := j.Stats()
	if st.Records > 100 || st.Records < 100-100/8 {
		t.Fatalf("records %d", st.Records)
	}
	p, err := j.Query(JournalQuery{Limit: 200})
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Records) > 100 || p.Records[0].ID != 1000 || p.Records[0].ID < p.Records[1].ID {
		t.Fatalf("%d records, first id %d", len(p.Records), p.Records[0].ID)
	}
}

// The age bound: records older than MaxAge are never shown and leave the
// disk within one segment span.
func TestJournalAgeBound(t *testing.T) {
	clk := &fakeClock{t: jT0}
	dir := t.TempDir()
	j := openJ(t, dir, clk, nil)
	for i := 0; i < 30; i++ {
		j.Add(jrec(clk, i))
		clk.Add(10 * time.Minute) // 5 hours in all, several segments (span 1 h)
	}
	j.Flush()
	if j.Stats().Segments < 4 {
		t.Fatalf("segments %d: no rotation by time span", j.Stats().Segments)
	}
	clk.Add(DefaultJournalMaxAge - 2*time.Hour) // the first records are now older than 24 h
	p, _ := j.Query(JournalQuery{Limit: 200})
	for _, r := range p.Records {
		if clk.Now().Sub(r.Start) > DefaultJournalMaxAge {
			t.Fatalf("record %d of %v shown at %v", r.ID, r.Start, clk.Now())
		}
	}
	if len(p.Records) == 30 || len(p.Records) == 0 {
		t.Fatalf("%d shown", len(p.Records))
	}
	j.Add(jrec(clk, 99)) // a write prunes
	j.Flush()
	if n := allLinesParse(t, dir); n >= 31 {
		t.Fatalf("old segments not deleted: %d lines", n)
	}
	// Everything older: the disk holds only the new record after a write.
	clk.Add(48 * time.Hour)
	j.Add(jrec(clk, 100))
	j.Flush()
	if n := allLinesParse(t, dir); n != 1 {
		t.Fatalf("%d lines after 48 h", n)
	}
	// The periodic prune (no write) of a wholly old active segment.
	clk.Add(48 * time.Hour)
	j.mu.Lock()
	j.enforce(0, 0)
	j.mu.Unlock()
	if n := allLinesParse(t, dir); n != 0 {
		t.Fatalf("%d lines after the prune", n)
	}
	j.Add(jrec(clk, 101))
	j.Flush()
	if p, _ := j.Query(JournalQuery{}); len(p.Records) != 1 || p.Records[0].ID != 33 {
		t.Fatalf("%+v", p.Records)
	}
}

// The byte cap holds under a flood of maximal records, rotated segments
// included, and the segment count stays bounded.
func TestJournalByteCapFlood(t *testing.T) {
	clk := &fakeClock{t: jT0}
	dir := t.TempDir()
	const cap = 1 << 20
	j := openJ(t, dir, clk, func(c *JournalConfig) { c.MaxBytes = cap; c.MaxRecords = 1 << 30; c.RecordNames = true })
	long := strings.Repeat("a", 300)
	for i := 0; i < 20000; i++ {
		r := jrec(clk, i)
		r.Name, r.Error, r.Target, r.RuleID = long, long, long, long
		j.Add(r)
		if i%500 == 0 {
			j.Flush()
			if n, files := dirBytes(t, dir); n+int64(files)*journalBlockSlack > cap || files > JournalMaxSegments {
				t.Fatalf("after %d: %d bytes in %d files", i, n, files)
			}
		}
	}
	j.Flush()
	n, files := dirBytes(t, dir)
	if n+int64(files)*journalBlockSlack > cap || files < 2 {
		t.Fatalf("%d bytes in %d files", n, files)
	}
	if st := j.Stats(); st.Bytes != n-markerBytes(dir) || st.Records != allLinesParse(t, dir) || st.WriteErrors != 0 {
		t.Fatalf("stats %+v, %d bytes on disk", st, n)
	}
}

// Rotation names segments by their first id and a restart continues the
// ids; the records survive.
func TestJournalRestart(t *testing.T) {
	clk := &fakeClock{t: jT0}
	dir := t.TempDir()
	j, err := OpenJournal(JournalConfig{Dir: dir, Now: clk.Now, MaxRecords: 80})
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 50; i++ {
		j.Add(jrec(clk, i))
	}
	j.Close()
	ents, _ := os.ReadDir(dir)
	if len(ents) < 2 || !segNameRe.MatchString(ents[0].Name()) || ents[0].Name() != segName(1) {
		t.Fatalf("segments %v", ents)
	}
	j2 := openJ(t, dir, clk, func(c *JournalConfig) { c.MaxRecords = 80 })
	if st := j2.Stats(); st.Records != 50 {
		t.Fatalf("after restart %+v", st)
	}
	j2.Add(jrec(clk, 50))
	j2.Flush()
	p, _ := j2.Query(JournalQuery{Limit: 1})
	if p.Records[0].ID != 51 || p.Matched != 51 || p.NextBefore != 51 {
		t.Fatalf("%+v", p)
	}
}

// A torn last line (power loss in the middle of a write) is cut at open;
// a bad line in an older segment is skipped; the journal stays usable.
func TestJournalTornTail(t *testing.T) {
	clk := &fakeClock{t: jT0}
	dir := t.TempDir()
	j, _ := OpenJournal(JournalConfig{Dir: dir, Now: clk.Now, MaxRecords: 40})
	for i := 0; i < 20; i++ {
		j.Add(jrec(clk, i))
	}
	j.Close()
	ents, _ := os.ReadDir(dir)
	first := filepath.Join(dir, ents[0].Name())
	last := filepath.Join(dir, ents[len(ents)-1].Name())
	// garbage inside an older segment, a torn line at the end of the newest
	b, _ := os.ReadFile(first)
	os.WriteFile(first, append([]byte("{not json\n"), b...), 0o600)
	f, _ := os.OpenFile(last, os.O_APPEND|os.O_WRONLY, 0)
	f.WriteString(`{"id":21,"start":"2026-11-14T08:00:00Z","sour`)
	f.Close()
	j2 := openJ(t, dir, clk, func(c *JournalConfig) { c.MaxRecords = 40 })
	st := j2.Stats()
	if st.TornBytes == 0 || st.Records != 20 {
		t.Fatalf("%+v", st)
	}
	j2.Add(jrec(clk, 20))
	j2.Flush()
	p, _ := j2.Query(JournalQuery{Limit: 200})
	if len(p.Records) != 21 || p.Records[0].ID != 21 {
		t.Fatalf("%d records, newest %d", len(p.Records), p.Records[0].ID)
	}
	b, _ = os.ReadFile(last)
	for _, l := range bytes.Split(bytes.TrimRight(b, "\n"), []byte{'\n'}) {
		var r JournalRecord
		if json.Unmarshal(l, &r) != nil {
			t.Fatalf("torn line kept: %q", l)
		}
	}
}

// Clear removes every record and file; writing resumes.
func TestJournalClear(t *testing.T) {
	clk := &fakeClock{t: jT0}
	dir := t.TempDir()
	j := openJ(t, dir, clk, nil)
	for i := 0; i < 10; i++ {
		j.Add(jrec(clk, i))
	}
	j.Flush()
	if n := j.Clear(); n != 10 {
		t.Fatalf("cleared %d", n)
	}
	if _, files := dirBytes(t, dir); files != 1 || markerBytes(dir) == 0 {
		t.Fatalf("%d files left, want only the marker", files)
	}
	if p, _ := j.Query(JournalQuery{}); len(p.Records) != 0 || p.Stats.ClearedAt == nil {
		t.Fatalf("%+v", p)
	}
	j.Add(jrec(clk, 10))
	j.Flush()
	if p, _ := j.Query(JournalQuery{}); len(p.Records) != 1 {
		t.Fatalf("%+v", p)
	}
}

// Directory 0700 (also when it existed wider), files 0600.
func TestJournalPermissions(t *testing.T) {
	clk := &fakeClock{t: jT0}
	dir := filepath.Join(t.TempDir(), "state")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	os.Chmod(dir, 0o755)
	os.WriteFile(filepath.Join(dir, segName(1)), nil, 0o644)
	os.Chmod(filepath.Join(dir, segName(1)), 0o644)
	j := openJ(t, dir, clk, nil)
	j.Add(jrec(clk, 1))
	j.Flush()
	fi, _ := os.Stat(dir)
	if fi.Mode().Perm() != 0o700 {
		t.Fatalf("dir %v", fi.Mode())
	}
	ents, _ := os.ReadDir(dir)
	for _, e := range ents {
		fi, _ := e.Info()
		if fi.Mode().Perm() != 0o600 {
			t.Fatalf("%s %v", e.Name(), fi.Mode())
		}
	}
	if _, err := OpenJournal(JournalConfig{Dir: "relative"}); err == nil {
		t.Fatal("relative directory accepted")
	}
}

// Every field has a byte limit; control characters are dropped.
func TestJournalFieldBounds(t *testing.T) {
	clk := &fakeClock{t: jT0}
	dir := t.TempDir()
	j := openJ(t, dir, clk, func(c *JournalConfig) { c.RecordNames = true })
	long := strings.Repeat("é", 1000)
	r := ConnRecord{Start: clk.Now(), Source: long, Dest: long, Upstream: long, MAC: long, Proto: long, Name: long + "\n\x00x", Why: long, By: long,
		RuleID: long, Target: long, Result: long, Error: long, MarkStatus: long, RawMark: long, View: long,
		NameRule: &NameRule{ID: long, Target: long, By: long, Error: long}}
	j.Add(r)
	j.Flush()
	if n := allLinesParse(t, dir); n != 1 {
		t.Fatalf("%d lines", n)
	}
	p, _ := j.Query(JournalQuery{})
	g := p.Records[0]
	l := journalLimits
	for name, c := range map[string]struct {
		s string
		n int
	}{"source": {g.Source, l.addr}, "name": {g.Name, l.name}, "target": {g.Target, l.ident}, "error": {g.Error, l.errText},
		"result": {g.Result, l.short}, "mac": {g.MAC, l.short}, "nr.target": {g.NameRule.Target, l.ident}} {
		if len(c.s) > c.n || len(c.s) == 0 || strings.ContainsAny(c.s, "\n\x00") {
			t.Errorf("%s: %d bytes (limit %d)", name, len(c.s), c.n)
		}
	}
}

// Add never blocks: with the writer stalled the queue fills and further
// records are dropped and counted; the connection path returns at once.
func TestJournalNeverBlocks(t *testing.T) {
	clk := &fakeClock{t: jT0}
	dir := t.TempDir()
	j, err := OpenJournal(JournalConfig{Dir: dir, Now: clk.Now, Queue: 4})
	if err != nil {
		t.Fatal(err)
	}
	stall := make(chan struct{})
	entered := make(chan struct{}, 1)
	j.testHookWrite = func() {
		select {
		case entered <- struct{}{}:
		default:
		}
		<-stall
	}
	j.Add(jrec(clk, 0))
	<-entered // the writer is stuck inside a batch
	start := time.Now()
	for i := 1; i <= 1000; i++ {
		j.Add(jrec(clk, i))
	}
	if d := time.Since(start); d > 500*time.Millisecond {
		t.Fatalf("1000 Adds took %v", d)
	}
	if got := j.Stats().Dropped; got < 1000-4 {
		t.Fatalf("dropped %d", got)
	}
	// A slow disk is the same case seen from the server: finish returns.
	s := New(DefaultConfig())
	s.Journal = j
	done := make(chan struct{})
	go func() {
		rec := ConnRecord{Start: clk.Now(), Source: "192.0.2.1"}
		s.finish(&rec, "ok")
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("finish blocked on the journal")
	}
	close(stall)
	j.Close()
	if s.Health().Journal.Dropped < 996 {
		t.Fatal("health does not show the drops")
	}
}

// Names: none stored while off; turning recording off removes the names
// already on disk at the next open; the bytes are gone from the files.
func TestJournalNames(t *testing.T) {
	clk := &fakeClock{t: jT0}
	dir := t.TempDir()
	j := openJ(t, dir, clk, nil)
	r := jrec(clk, 1)
	r.Name = "secret-off.example.com"
	j.Add(r)
	j.Flush()
	if _, err := j.Query(JournalQuery{Text: "secret"}); err != ErrNamesNotRecorded {
		t.Fatalf("text search with names off: %v", err)
	}
	j.Close()
	assertNoBytes(t, dir, "secret-off")

	j, _ = OpenJournal(JournalConfig{Dir: dir, Now: clk.Now, RecordNames: true, MaxRecords: 16})
	for i := 0; i < 10; i++ {
		r := jrec(clk, i)
		r.Name = fmt.Sprintf("kept%d.example.org", i)
		j.Add(r)
	}
	j.Flush()
	if p, _ := j.Query(JournalQuery{Text: "KEPT3"}); len(p.Records) != 1 || p.Records[0].Name != "kept3.example.org" {
		t.Fatalf("%+v", p.Records)
	}
	j.Close()
	j = openJ(t, dir, clk, func(c *JournalConfig) { c.MaxRecords = 16 })
	if st := j.Stats(); st.PurgedNames != 10 || st.Records != 11 {
		t.Fatalf("%+v", st)
	}
	assertNoBytes(t, dir, "kept")
	if n := allLinesParse(t, dir); n != 11 {
		t.Fatalf("%d lines", n)
	}
	if ents, _ := os.ReadDir(dir); len(ents) == 0 || strings.HasSuffix(ents[len(ents)-1].Name(), ".tmp") {
		t.Fatalf("%v", ents)
	}
}

func assertNoBytes(t *testing.T, dir, s string) {
	t.Helper()
	ents, _ := os.ReadDir(dir)
	for _, e := range ents {
		b, _ := os.ReadFile(filepath.Join(dir, e.Name()))
		if bytes.Contains(b, []byte(s)) {
			t.Fatalf("%s still holds %q", e.Name(), s)
		}
	}
}

// Filters, paging and the per-device summary.
func TestJournalQueryAndSummary(t *testing.T) {
	clk := &fakeClock{t: jT0}
	dir := t.TempDir()
	j := openJ(t, dir, clk, func(c *JournalConfig) { c.RecordNames = true })
	for i := 0; i < 60; i++ {
		r := jrec(clk, i)
		if i%10 == 0 {
			r.Why, r.Sniffed, r.By, r.NameRule = WhyUnresolved, false, "addr", &NameRule{Index: 1, Target: "direct", Error: "nxdomain"}
		}
		if i == 7 {
			r.Result, r.MarkStatus, r.RawMark = "mark_missing", MarkWithoutBit, "0x0"
		}
		r.MAC = "02:00:00:00:00:0" + fmt.Sprint(i%5)
		j.Add(r)
		clk.Add(time.Minute)
	}
	j.Flush()
	q := func(q JournalQuery) JournalPage {
		t.Helper()
		p, err := j.Query(q)
		if err != nil {
			t.Fatal(err)
		}
		return p
	}
	if p := q(JournalQuery{Device: "192.0.2.10"}); p.Matched != 12 || len(p.Records) != 12 {
		t.Fatalf("device: %d", p.Matched)
	}
	if p := q(JournalQuery{Target: "group:hk"}); p.Matched != 20 {
		t.Fatalf("target: %d", p.Matched)
	}
	if p := q(JournalQuery{Result: ClassRejected}); p.Matched != 15 {
		t.Fatalf("rejected: %d", p.Matched)
	}
	if p := q(JournalQuery{Result: ClassFailed}); p.Matched != 16 { // 15 dial_failed, 1 mark_missing (rejected is no failure)
		t.Fatalf("failed: %d", p.Matched)
	}
	if p := q(JournalQuery{Result: ClassMark}); p.Matched != 1 || p.Records[0].RawMark != "0x0" {
		t.Fatalf("mark: %+v", p.Records)
	}
	if p := q(JournalQuery{Result: ClassNameUnresolved}); p.Matched != 6 || p.Records[0].NameRule == nil {
		t.Fatalf("unresolved: %d", p.Matched)
	}
	if p := q(JournalQuery{From: jT0.Add(10 * time.Minute).Format(time.RFC3339), To: jT0.Add(20 * time.Minute).Format(time.RFC3339)}); p.Matched != 10 {
		t.Fatalf("range: %d", p.Matched)
	}
	if p := q(JournalQuery{Text: "host4"}); p.Matched != 11 { // host4, host40..49
		t.Fatalf("text: %d", p.Matched)
	}
	// Paging: 60 records in pages of 25.
	var ids []uint64
	before := uint64(0)
	for k := 0; k < 5; k++ {
		p := q(JournalQuery{Limit: 25, Before: before})
		for _, r := range p.Records {
			ids = append(ids, r.ID)
		}
		if p.NextBefore == 0 {
			break
		}
		before = p.NextBefore
	}
	if len(ids) != 60 || ids[0] != 60 || ids[59] != 1 {
		t.Fatalf("paging: %d ids %v…", len(ids), ids[:3])
	}
	for _, bad := range []JournalQuery{{Device: "nope"}, {Target: "a b"}, {Result: "maybe"}, {From: "yesterday"}, {Limit: 201}, {Text: strings.Repeat("x", 65)}, {Text: "a\nb"}} {
		if _, err := j.Query(bad); err == nil {
			t.Errorf("accepted %+v", bad)
		}
	}
	sum, err := j.Summary(JournalSummaryQuery{})
	if err != nil {
		t.Fatal(err)
	}
	if len(sum.Devices) != 5 {
		t.Fatalf("%d devices", len(sum.Devices))
	}
	var d10 *DeviceSummary
	for i := range sum.Devices {
		if sum.Devices[i].Device == "192.0.2.10" {
			d10 = &sum.Devices[i]
		}
	}
	if d10 == nil || d10.Total != 12 || d10.MAC != "02:00:00:00:00:00" || d10.NameUnresolved != 6 || d10.ByAddress != 6 ||
		d10.ByTarget["direct"]+d10.ByTarget["group:hk"]+d10.ByTarget["exit:jp-a"] != 12 || d10.FirstSeen != jT0 || !d10.LastSeen.After(d10.FirstSeen) {
		t.Fatalf("%+v", d10)
	}
	if sum.Devices[0].LastSeen.Before(sum.Devices[4].LastSeen) {
		t.Fatal("not newest first")
	}
}

// The status socket's journal endpoints: validated parameters only, a
// parameterless clear, 404 without a journal.
func TestJournalStatusEndpoints(t *testing.T) {
	clk := &fakeClock{t: jT0}
	s := New(DefaultConfig())
	h := s.StatusHandler()
	call := func(method, target string, body string) *httptest.ResponseRecorder {
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, httptest.NewRequest(method, target, strings.NewReader(body)))
		return rr
	}
	if rr := call("GET", "/v1/journal", ""); rr.Code != http.StatusNotFound {
		t.Fatalf("no journal: %d", rr.Code)
	}
	s.Journal = openJ(t, t.TempDir(), clk, nil)
	for i := 0; i < 5; i++ {
		rec := jrec(clk, i)
		s.finish(&rec, rec.Result)
	}
	s.Journal.Flush()
	v := JournalQuery{Device: "192.0.2.11", Limit: 10}.Values()
	rr := call("GET", "/v1/journal?"+v.Encode(), "")
	var page JournalPage
	if rr.Code != 200 || json.Unmarshal(rr.Body.Bytes(), &page) != nil || page.Matched != 1 || page.Records[0].Name != "" {
		t.Fatalf("%d %s", rr.Code, rr.Body.String())
	}
	for _, bad := range []string{"/v1/journal?file=/etc/shadow", "/v1/journal?device=1&device=2", "/v1/journal?limit=x", "/v1/journal/summary?path=x"} {
		if rr := call("GET", bad, ""); rr.Code != http.StatusBadRequest {
			t.Errorf("%s: %d", bad, rr.Code)
		}
	}
	if rr := call("POST", "/v1/journal", ""); rr.Code != http.StatusMethodNotAllowed {
		t.Fatalf("POST read: %d", rr.Code)
	}
	if rr := call("GET", "/v1/journal/summary", ""); rr.Code != 200 || !strings.Contains(rr.Body.String(), `"device":"192.0.2.10"`) {
		t.Fatalf("%d %s", rr.Code, rr.Body.String())
	}
	if rr := call("POST", "/v1/journal/clear", `{"path":"/"}`); rr.Code != http.StatusBadRequest {
		t.Fatalf("clear with a body: %d", rr.Code)
	}
	if rr := call("GET", "/v1/journal/clear", ""); rr.Code != http.StatusMethodNotAllowed {
		t.Fatalf("GET clear: %d", rr.Code)
	}
	if len(s.Recent()) != 5 {
		t.Fatalf("ring %d", len(s.Recent()))
	}
	if rr := call("POST", "/v1/journal/clear", ""); rr.Code != 200 || !strings.Contains(rr.Body.String(), `"cleared":5`) {
		t.Fatalf("%d %s", rr.Code, rr.Body.String())
	}
	if len(s.Recent()) != 0 {
		t.Fatal("clear left the in-memory records")
	}
	if _, err := JournalQueryFrom(url.Values{"before": {"-1"}}); err == nil {
		t.Fatal("negative cursor")
	}
	if st := s.Health().Journal; st == nil || st.Records != 0 {
		t.Fatalf("%+v", st)
	}
}

// The journal's endpoints sit behind the same peer check as the rest of
// the status socket: only uid 0 is answered, the forwarder's own uid and
// every other user get a closed connection.
func TestJournalStatusRootOnly(t *testing.T) {
	clk := &fakeClock{t: jT0}
	for _, c := range []struct {
		uid    int
		answer bool
	}{{0, true}, {1000, false}, {65530, false}} {
		sock := filepath.Join(shortDir(t), "status.sock")
		l, err := ListenStatus(sock, StatusRootOnly)
		if err != nil {
			t.Fatal(err)
		}
		uid := c.uid
		l.Peer = func(net.Conn) (int, error) { return uid, nil }
		s := New(DefaultConfig())
		s.Journal = openJ(t, t.TempDir(), clk, nil)
		srv := &http.Server{Handler: s.StatusHandler(), ReadHeaderTimeout: time.Second}
		go srv.Serve(l)
		_, code, err := StatusCall(context.Background(), sock, http.MethodGet, "/v1/journal")
		srv.Close()
		if c.answer != (err == nil && code == 200) {
			t.Fatalf("uid %d: code %d err %v", c.uid, code, err)
		}
	}
}

// --journal-dir must be a plain absolute path.
func TestParseArgsJournalDir(t *testing.T) {
	base := []string{"--listen", "127.0.0.1:1", "--snapshot", "/s", "--targets", "/t"}
	if c, err := ParseArgs(append(base, "--journal-dir", "/var/lib/meridian-sniff")); err != nil || c.JournalDir != "/var/lib/meridian-sniff" {
		t.Fatalf("%v %+v", err, c.JournalDir)
	}
	for _, bad := range []string{"relative", "/var/lib/../etc", "/var/lib/x/"} {
		if _, err := ParseArgs(append(base, "--journal-dir", bad)); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}
