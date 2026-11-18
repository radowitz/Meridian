package dnsjournal

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

// auditLine renders one line the way the resolver was observed to.
func auditLine(naive time.Time, client, name string, qtype int, ms int, group, result string) string {
	return fmt.Sprintf("[%s,%03d] %s query %s, type %d, time %dms, speed: -0.1ms, group %s, result %s\n",
		naive.Format("2006-01-02 15:04:05"), naive.Nanosecond()/1e6, client, name, qtype, ms, group, result)
}

// tailFix is a raw directory with a reader and a collecting sink.
type tailFix struct {
	t     *testing.T
	dir   string
	state string
	clock *fakeClock
	zone  time.Duration // what the "resolver" adds to real time in its lines
	mu    sync.Mutex
	got   []Record
	tail  *Tailer
	mac   map[string]string
	// faults: what the reader's clear meets (none: the real file system).
	faults []*fsFault
}

func newTailFix(t *testing.T) *tailFix {
	t.Helper()
	base := t.TempDir()
	f := &tailFix{t: t, dir: filepath.Join(base, "raw"), state: filepath.Join(base, "journal", positionFile), clock: newClock(), mac: map[string]string{}}
	if err := PrepareSink(f.dir); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(f.state), 0o700); err != nil {
		t.Fatal(err)
	}
	f.tail = f.newTailer(8 << 20)
	return f
}

func (f *tailFix) newTailer(maxRaw int64) *Tailer {
	return NewTailer(TailConfig{Dir: f.dir, PositionPath: f.state, MaxRawBytes: maxRaw, Now: f.clock.Now,
		Fault:  func(op, path string) error { return faultsOf(f.faults...)(op, path) },
		Lookup: func(a netip.Addr) string { return f.mac[a.String()] },
		Emit: func(r Record) {
			f.mu.Lock()
			f.got = append(f.got, r)
			f.mu.Unlock()
		}})
}

func (f *tailFix) path() string { return filepath.Join(f.dir, AuditBase) }

// write appends to the audit file and stamps it with the current time, as a
// write by the resolver would.
func (f *tailFix) write(s string) {
	f.t.Helper()
	fd, err := os.OpenFile(f.path(), os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0o640)
	if err != nil {
		f.t.Fatal(err)
	}
	if _, err := fd.WriteString(s); err != nil {
		f.t.Fatal(err)
	}
	fd.Close()
	f.touch(f.path())
}

func (f *tailFix) touch(p string) {
	now := f.clock.Now()
	if err := os.Chtimes(p, now, now); err != nil {
		f.t.Fatal(err)
	}
}

// line is a query written "now" by a resolver whose clock zone is f.zone.
func (f *tailFix) line(client, name string) string {
	return auditLine(f.clock.Now().Add(f.zone), client, name, 1, 2, "default", "192.0.2.1")
}

func (f *tailFix) names() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []string
	for _, r := range f.got {
		out = append(out, r.Name)
	}
	return out
}

func (f *tailFix) expect(want ...string) {
	f.t.Helper()
	if got := f.names(); strings.Join(got, " ") != strings.Join(want, " ") {
		f.t.Fatalf("records %v, want %v", got, want)
	}
}

// rotate does what the resolver does: the audit file is renamed to its
// rotated name and a new one is created.
func (f *tailFix) rotate(gz bool) string {
	f.t.Helper()
	name := filepath.Join(f.dir, "audit.log-"+f.clock.Now().Format("20060102-150405"))
	if err := os.Rename(f.path(), name); err != nil {
		f.t.Fatal(err)
	}
	if gz {
		b, _ := os.ReadFile(name)
		os.Remove(name)
		name += ".gz"
		writeGzip(f.t, name, string(b))
		f.touch(name)
	}
	if err := os.WriteFile(f.path(), nil, 0o640); err != nil {
		f.t.Fatal(err)
	}
	return name
}

func TestTailFollowsObservedLines(t *testing.T) {
	f := newTailFix(t)
	f.mac["127.0.0.1"] = "02:00:00:00:00:0A"
	// The observed lines carry 12:09:35…37 with no zone; the file was
	// written then.
	f.clock.t = time.Date(2026, 11, 15, 12, 9, 38, 0, time.UTC)
	f.write(observedLines)
	f.tail.Step()
	f.expect("a.example.test", "b.example.test", "nx.example.test", "up.example.test")
	r := f.got[3]
	if r.Result != ResultNoAnswerSlow || r.Group != "g_test" || r.ElapsedMS != 2005 || r.Answers != 0 || r.TimeApprox ||
		!r.Time.Equal(time.Date(2026, 11, 15, 12, 9, 37, 973e6, time.UTC)) || r.Client != "127.0.0.1" || r.MAC != "02:00:00:00:00:0a" {
		t.Fatalf("%+v", r)
	}
	if f.got[0].Result != ResultAnswered || f.got[1].QType != 28 || f.got[2].Result != ResultNoAnswer {
		t.Fatalf("%+v", f.got[:3])
	}
	st := f.tail.Stats()
	if !st.Following || st.Lines != 4 || st.Parsed != 4 || st.Bad != 0 || st.ZoneOffsetS == nil || *st.ZoneOffsetS != 0 || st.NoMAC != 0 {
		t.Fatalf("%+v", st)
	}
	// Nothing new: nothing emitted twice.
	f.tail.Step()
	f.expect("a.example.test", "b.example.test", "nx.example.test", "up.example.test")
}

// The resolver container's clock zone is not the host's: the offset comes
// from the file's own modification time, in quarter hours.
func TestTailEstablishesZone(t *testing.T) {
	for _, zone := range []time.Duration{8 * time.Hour, -5 * time.Hour, 5*time.Hour + 30*time.Minute, 0} {
		f := newTailFix(t)
		f.zone = zone
		real := f.clock.Now()
		f.write(f.line("192.0.2.10", "z.example.test"))
		f.clock.Add(800 * time.Millisecond)
		f.tail.Step()
		if len(f.got) != 1 || f.got[0].TimeApprox || f.got[0].Time.Sub(real).Abs() > time.Second {
			t.Fatalf("zone %v: %+v (real %v)", zone, f.got, real)
		}
		if st := f.tail.Stats(); st.ZoneOffsetS == nil || *st.ZoneOffsetS != int(zone/time.Second) {
			t.Fatalf("zone %v: %+v", zone, st.ZoneOffsetS)
		}
	}
	// A line and a write that are far apart establish nothing: the record
	// gets the time it was read and says so.
	f := newTailFix(t)
	f.write(auditLine(f.clock.Now().Add(-3*time.Hour-7*time.Minute), "192.0.2.10", "odd.example.test", 1, 1, "default", ""))
	f.tail.Step()
	if len(f.got) != 1 || !f.got[0].TimeApprox || !f.got[0].Time.Equal(f.clock.Now()) || f.tail.Stats().TimeApprox != 1 {
		t.Fatalf("%+v", f.got)
	}
}

func TestTailPartialBadAndLongLines(t *testing.T) {
	f := newTailFix(t)
	l := f.line("192.0.2.10", "split.example.test")
	f.write(l[:40])
	f.tail.Step()
	f.expect()
	f.write(l[40:] + "smartdns: something else\n\x00\x00\x00\n")
	f.tail.Step()
	f.expect("split.example.test")
	// A line longer than MaxRawLine, arriving in pieces, then a good one.
	f.write("[2026-11-15 12:00:00,000] 192.0.2.10 query " + strings.Repeat("x", 3*MaxRawLine))
	f.tail.Step()
	f.write(strings.Repeat("y", MaxRawLine) + ", type 1, time 0ms, speed: -0.1ms, group default, result \n" + f.line("192.0.2.10", "after.example.test"))
	f.tail.Step()
	f.expect("split.example.test", "after.example.test")
	st := f.tail.Stats()
	if st.Bad != 2 || st.TooLong != 1 || st.Parsed != 2 || st.Lines != 5 {
		t.Fatalf("%+v", st)
	}
}

func TestTailSurvivesRotation(t *testing.T) {
	f := newTailFix(t)
	f.write(f.line("192.0.2.10", "one.example.test"))
	f.tail.Step()
	// Written after the last read, then rotated away and compressed, and
	// the new file already has a line: nothing is lost, nothing twice.
	f.write(f.line("192.0.2.10", "two.example.test"))
	f.clock.Add(time.Second)
	f.rotate(true)
	f.write(f.line("192.0.2.10", "three.example.test"))
	f.tail.Step()
	f.expect("one.example.test", "two.example.test", "three.example.test")
	if st := f.tail.Stats(); st.Rotations != 1 || st.SkippedBytes != 0 || !st.Following {
		t.Fatalf("%+v", st)
	}
	f.write(f.line("192.0.2.10", "four.example.test"))
	f.tail.Step()
	f.expect("one.example.test", "two.example.test", "three.example.test", "four.example.test")
	// The audit file disappears for a while (between the rename and the
	// resolver's reopen): the reader waits and picks the new one up.
	os.Remove(f.path())
	f.tail.Step()
	if st := f.tail.Stats(); st.Following || st.LastError == "" {
		t.Fatalf("%+v", st)
	}
	f.write(f.line("192.0.2.10", "five.example.test"))
	f.tail.Step()
	if n := f.names(); n[len(n)-1] != "five.example.test" || len(n) != 5 {
		t.Fatalf("%v", n)
	}
}

// The resolver truncated its file to 0 on a full filesystem.
func TestTailSurvivesTruncation(t *testing.T) {
	f := newTailFix(t)
	f.write(f.line("192.0.2.10", "one.example.test") + f.line("192.0.2.10", "two.example.test"))
	f.tail.Step()
	if err := os.Truncate(f.path(), 0); err != nil {
		t.Fatal(err)
	}
	f.write(f.line("192.0.2.10", "three.example.test"))
	f.tail.Step()
	f.expect("one.example.test", "two.example.test", "three.example.test")
	if st := f.tail.Stats(); st.Truncations != 1 {
		t.Fatalf("%+v", st)
	}
}

func TestTailRestartKeepsPosition(t *testing.T) {
	f := newTailFix(t)
	f.write(f.line("192.0.2.10", "one.example.test") + f.line("192.0.2.10", "two.example.test"))
	f.tail.Step()
	f.tail.Close()
	if fi, err := os.Stat(f.state); err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("position file: %v", err)
	}
	f.clock.Add(time.Minute)
	f.write(f.line("192.0.2.10", "three.example.test"))
	f.tail = f.newTailer(8 << 20)
	f.tail.Step()
	f.expect("one.example.test", "two.example.test", "three.example.test")
}

// The new audit file got the inode number of the one read before the
// restart (a filesystem reuses freed inodes): it is still another file, and
// the lines not read are caught up from the rotated copy.
func TestTailRestartInodeReused(t *testing.T) {
	f := newTailFix(t)
	f.write(f.line("192.0.2.10", "one.example.test") + f.line("192.0.2.10", "two.example.test"))
	f.tail.Step()
	f.tail.Close()
	f.clock.Add(time.Second)
	f.write(f.line("192.0.2.10", "three.example.test"))
	f.rotate(true)
	f.clock.Add(time.Minute)
	f.write(f.line("192.0.2.10", "four.example.test") + f.line("192.0.2.10", "five.example.test") + f.line("192.0.2.10", "six.example.test"))
	b, err := os.ReadFile(f.state)
	if err != nil {
		t.Fatal(err)
	}
	var p position
	if err := json.Unmarshal(b, &p); err != nil || p.Head == "" {
		t.Fatalf("position %s %v", b, err)
	}
	fi, err := os.Stat(f.path())
	if err != nil {
		t.Fatal(err)
	}
	p.Ino = inoOf(fi) // as if reused; the new file is longer than Offset
	if err := writePosition(f.state, p); err != nil {
		t.Fatal(err)
	}
	f.tail = f.newTailer(8 << 20)
	f.tail.Step()
	f.expect("one.example.test", "two.example.test", "three.example.test", "four.example.test", "five.example.test", "six.example.test")
}

// Rotated while the reader was down: the lines it had not read are taken
// from the gzip-compressed rotated file, the ones it had read are not.
func TestTailRestartCatchesUpFromGzip(t *testing.T) {
	f := newTailFix(t)
	f.mac["192.0.2.10"] = "02:00:00:00:00:01"
	f.write(f.line("192.0.2.10", "one.example.test"))
	f.clock.Add(time.Second)
	f.write(f.line("192.0.2.10", "two.example.test"))
	f.tail.Step()
	f.tail.Close()
	f.clock.Add(time.Second)
	f.write(f.line("192.0.2.10", "three.example.test"))
	f.clock.Add(time.Second)
	f.write(f.line("192.0.2.10", "four.example.test") + "garbage\n")
	f.rotate(true)
	f.clock.Add(10 * time.Minute)
	f.write(f.line("192.0.2.10", "five.example.test"))
	f.tail = f.newTailer(8 << 20)
	f.tail.Step()
	f.expect("one.example.test", "two.example.test", "three.example.test", "four.example.test", "five.example.test")
	st := f.tail.Stats()
	if st.CaughtUp != 2 || st.Bad != 1 {
		t.Fatalf("%+v", st)
	}
	// A line read long after it was written says nothing about who had the
	// address then: no MAC. The fresh one has it.
	if f.got[2].MAC != "" || f.got[3].MAC != "" || f.got[4].MAC != "02:00:00:00:00:01" || f.got[2].TimeApprox {
		t.Fatalf("%+v", f.got[2:])
	}
	// A first start without a position does not dig through rotated files.
	g := newTailFix(t)
	writeGzip(t, filepath.Join(g.dir, "audit.log-20261115-110000.gz"), g.line("192.0.2.10", "ancient.example.test"))
	g.write(g.line("192.0.2.10", "now.example.test"))
	g.tail.Step()
	g.expect("now.example.test")
	if st := g.tail.Stats(); st.SkippedRotated != 1 || st.CaughtUp != 0 {
		t.Fatalf("%+v", st)
	}
}

// Modes are put right on every pass; anything that is not a regular file
// is removed; the raw directory never holds more than its share.
func TestTailKeepsModesAndRawBudget(t *testing.T) {
	f := newTailFix(t)
	os.Chmod(f.dir, 0o755)
	f.write(f.line("192.0.2.10", "one.example.test"))
	os.Chmod(f.path(), 0o640) // what the resolver creates
	fifo := filepath.Join(f.dir, "audit.log.pending.gz")
	if err := syscall.Mkfifo(fifo, 0o644); err != nil {
		t.Skip("mkfifo:", err)
	}
	os.Symlink("/etc/hostname", filepath.Join(f.dir, "link"))
	f.tail.Step()
	if fi, _ := os.Stat(f.dir); fi.Mode().Perm() != 0o700 {
		t.Fatalf("directory %v", fi.Mode())
	}
	if fi, _ := os.Stat(f.path()); fi.Mode().Perm() != 0o600 {
		t.Fatalf("audit file %v", fi.Mode())
	}
	if _, err := os.Lstat(fifo); !os.IsNotExist(err) {
		t.Fatal("a FIFO was left in the raw directory")
	}
	if _, err := os.Lstat(filepath.Join(f.dir, "link")); !os.IsNotExist(err) {
		t.Fatal("a symbolic link was left in the raw directory")
	}
	if st := f.tail.Stats(); st.SpecialRemoved != 2 || st.RawFiles != 1 {
		t.Fatalf("%+v", st)
	}

	// Budget: 64 KiB. Three rotated copies of 30 KiB: the oldest go first.
	g := newTailFix(t)
	g.tail = g.newTailer(64 << 10)
	blob := strings.Repeat("x", 30<<10)
	for _, n := range []string{"audit.log-20261115-100000.gz", "audit.log-20261115-110000.gz", "audit.log-20261115-120000.gz"} {
		os.WriteFile(filepath.Join(g.dir, n), []byte(blob), 0o640)
	}
	g.write(g.line("192.0.2.10", "one.example.test"))
	g.tail.Step()
	st := g.tail.Stats()
	if st.RawBytes > 64<<10 || st.RawDeleted != 1 || st.RawTruncated != 0 {
		t.Fatalf("%+v", st)
	}
	if _, err := os.Stat(filepath.Join(g.dir, "audit.log-20261115-100000.gz")); !os.IsNotExist(err) {
		t.Fatal("the oldest rotated copy was not the one deleted")
	}
	// The audit file alone over the budget (a resolver that does not
	// rotate): it is truncated, stays the same file, and reading goes on.
	before, _ := os.Stat(g.path())
	var big strings.Builder
	for big.Len() < 80<<10 {
		big.WriteString(g.line("192.0.2.10", "flood.example.test"))
	}
	g.write(big.String())
	g.tail.Step()
	st = g.tail.Stats()
	after, _ := os.Stat(g.path())
	if st.RawBytes > 64<<10 || st.RawTruncated != 1 || after.Size() != 0 || !os.SameFile(before, after) || after.Mode().Perm() != 0o600 {
		t.Fatalf("%+v size %d", st, after.Size())
	}
	g.write(g.line("192.0.2.10", "later.example.test"))
	g.tail.Step()
	if n := g.names(); n[len(n)-1] != "later.example.test" {
		t.Fatalf("%v", n[len(n)-1])
	}
	for i := 0; i < 50; i++ {
		g.write(big.String())
		g.tail.Step()
		if st := g.tail.Stats(); st.RawBytes > 64<<10 {
			t.Fatalf("round %d: %d bytes in the raw directory", i, st.RawBytes)
		}
	}
}

// A flood: one pass reads a bounded amount, the queue to a stalled journal
// fills and the rest is dropped and counted; nothing waits.
func TestTailFloodIsBounded(t *testing.T) {
	f := newTailFix(t)
	block := make(chan struct{})
	j, err := Open(Config{Dir: filepath.Dir(f.state), Now: f.clock.Now, Queue: 64})
	if err != nil {
		t.Fatal(err)
	}
	j.testHookWrite = func() { <-block }
	f.tail = NewTailer(TailConfig{Dir: f.dir, MaxRawBytes: 8 << 20, Now: f.clock.Now, Emit: j.Add})
	var big strings.Builder
	n := 0
	for big.Len() < 2<<20 {
		big.WriteString(f.line("192.0.2.10", "flood.example.test"))
		n++
	}
	f.write(big.String())
	start := time.Now()
	f.tail.Step()
	if d := time.Since(start); d > 3*time.Second {
		t.Fatalf("one pass took %v", d)
	}
	st := f.tail.Stats()
	perLine := big.Len() / n
	if st.Lines == 0 || int(st.Lines) > maxStepBytes/perLine+1 {
		t.Fatalf("one pass read %d lines (%d bytes each, step bound %d)", st.Lines, perLine, maxStepBytes)
	}
	if d := j.Stats().Dropped; d == 0 || d > st.Parsed {
		t.Fatalf("dropped %d of %d", d, st.Parsed)
	}
	close(block)
	j.Flush()
	if got := j.Stats(); uint64(got.Records)+got.Dropped != st.Parsed {
		t.Fatalf("records %d + dropped %d != parsed %d", got.Records, got.Dropped, st.Parsed)
	}
	j.Close()
}

// A rotated file with more unread content than one pass reads is given up
// (counted), so an unlinked file is not held across passes.
func TestTailGivesUpOversizedRotatedRemainder(t *testing.T) {
	f := newTailFix(t)
	f.write(f.line("192.0.2.10", "one.example.test"))
	f.tail.Step()
	var big strings.Builder
	for big.Len() < 2*maxStepBytes {
		big.WriteString(f.line("192.0.2.10", "flood.example.test"))
	}
	f.write(big.String())
	f.rotate(false)
	f.write(f.line("192.0.2.10", "new.example.test"))
	f.tail.Step()
	st := f.tail.Stats()
	if st.SkippedBytes == 0 || st.Rotations != 1 {
		t.Fatalf("%+v", st)
	}
	f.tail.Step()
	if n := f.names(); n[len(n)-1] != "new.example.test" {
		t.Fatalf("last %v", n[len(n)-1])
	}
}

func TestTailClear(t *testing.T) {
	f := newTailFix(t)
	f.write(f.line("192.0.2.10", "one.example.test"))
	f.tail.Step()
	writeGzip(t, filepath.Join(f.dir, "audit.log-20261115-110000.gz"), f.line("192.0.2.10", "old.example.test"))
	before, _ := os.Stat(f.path())
	if res := f.tail.Clear(); res.Freed == 0 || res.Files != 0 || res.Unknown || res.Errors != nil {
		t.Fatalf("%+v", res)
	}
	if st := f.tail.Stats(); st.ClearPendingAt != nil || st.RawResidualFiles != 0 {
		t.Fatalf("a complete clear left a reminder: %+v", st)
	}
	after, err := os.Stat(f.path())
	if err != nil || after.Size() != 0 || !os.SameFile(before, after) || !after.Mode().IsRegular() {
		t.Fatalf("the audit file must stay the same regular file, empty: %v", err)
	}
	if ents, _ := os.ReadDir(f.dir); len(ents) != 1 {
		t.Fatalf("%d entries left", len(ents))
	}
	f.write(f.line("192.0.2.10", "two.example.test"))
	f.tail.Step()
	f.expect("one.example.test", "two.example.test")
}

// Rotated after the last read and cleared before the next one: the reader's
// handle names the deleted rotated file; nothing in it may come back, either
// on the next step or after a restart.
func TestTailClearAfterUnreadRotation(t *testing.T) {
	f := newTailFix(t)
	f.write(f.line("192.0.2.10", "one.example.test"))
	f.tail.Step()
	f.clock.Add(time.Second)
	f.write(f.line("192.0.2.10", "unread.example.test"))
	f.rotate(false)
	f.tail.Clear()
	f.clock.Add(time.Second)
	f.write(f.line("192.0.2.10", "two.example.test"))
	f.tail.Step()
	f.tail.Step()
	f.expect("one.example.test", "two.example.test")
	f.tail.Close()
	f.clock.Add(time.Second)
	f.write(f.line("192.0.2.10", "three.example.test"))
	f.tail = f.newTailer(8 << 20)
	f.tail.Step()
	f.expect("one.example.test", "two.example.test", "three.example.test")
}

// oldestRaw is the age of the oldest audit line anywhere in the raw
// directory (the audit file and every other file, compressed or not), and
// how many lines there are.
func (f *tailFix) oldestRaw() (time.Duration, int) {
	f.t.Helper()
	ents, err := os.ReadDir(f.dir)
	if err != nil {
		f.t.Fatal(err)
	}
	var oldest time.Duration
	n := 0
	for _, e := range ents {
		b, err := ReadRotated(filepath.Join(f.dir, e.Name()), 16<<20)
		if err != nil {
			continue // nothing in it can be read
		}
		for _, l := range strings.Split(string(b), "\n") {
			r, err := ParseLine([]byte(l))
			if err != nil {
				continue
			}
			n++
			if age := f.clock.Now().Sub(r.Naive.Add(-f.zone)); age > oldest {
				oldest = age
			}
		}
	}
	return oldest, n
}

func (f *tailFix) rawSize() int64 {
	f.t.Helper()
	fi, err := os.Lstat(f.path())
	if err != nil || !fi.Mode().IsRegular() {
		f.t.Fatalf("the audit file must stay a regular file: %v", err)
	}
	return fi.Size()
}

// A quiet resolver never fills its audit file, so it never rotates it: the
// reader keeps the file from holding anything older than the age bound,
// without losing or repeating a line, and the file stays the one the
// resolver has open.
func TestTailRawAgeLowTraffic(t *testing.T) {
	f := newTailFix(t)
	f.zone = 8 * time.Hour
	before, _ := os.Stat(f.path())
	var want []string
	for h := 0; h < 80; h++ {
		name := fmt.Sprintf("h%02d.example.test", h)
		want = append(want, name)
		f.write(f.line("192.0.2.10", name))
		f.tail.Step()
		f.expect(want...)
		if age, _ := f.oldestRaw(); age > DefaultMaxAge {
			t.Fatalf("hour %d: the raw directory holds a line %v old", h, age)
		}
		f.clock.Add(20 * time.Minute)
		f.tail.Step()
		f.clock.Add(40 * time.Minute)
	}
	after, err := os.Stat(f.path())
	if err != nil || !os.SameFile(before, after) || !after.Mode().IsRegular() || after.Mode().Perm() != 0o600 {
		t.Fatalf("the audit file must stay the same regular 0600 file: %v", err)
	}
	st := f.tail.Stats()
	if st.RawAgeTruncated != 3 || st.RawTruncated != 0 || st.Truncations != 0 || st.RawDeleted != 0 || st.Parsed != 80 || !st.Following {
		t.Fatalf("%+v", st)
	}
	// Timestamps that give no zone (so the first line's age is not known)
	// and a file that is written all the time: the bound still holds for as
	// long as the reader has been following the file.
	u := newTailFix(t)
	odd := func(name string) string {
		return auditLine(u.clock.Now().Add(-3*time.Hour-7*time.Minute), "192.0.2.10", name, 1, 1, "default", "")
	}
	want = nil
	lastEmpty := 0
	for h := 0; h < 60; h++ {
		name := fmt.Sprintf("u%02d.example.test", h)
		want = append(want, name)
		u.write(odd(name))
		u.tail.Step()
		u.expect(want...)
		if u.rawSize() == 0 {
			lastEmpty = h
		}
		if h-lastEmpty > 25 {
			t.Fatalf("hour %d: not emptied since hour %d", h, lastEmpty)
		}
		u.clock.Add(time.Hour)
	}
	if st := u.tail.Stats(); st.ZoneOffsetS != nil || st.RawAgeTruncated != 2 || st.Truncations != 0 {
		t.Fatalf("%+v", st)
	}

	// A shorter bound is the journal's configured one.
	g := newTailFix(t)
	g.tail = NewTailer(TailConfig{Dir: g.dir, PositionPath: g.state, MaxRawBytes: 8 << 20, MaxAge: time.Hour, Now: g.clock.Now})
	g.write(g.line("192.0.2.10", "one.example.test"))
	g.tail.Step()
	g.clock.Add(59 * time.Minute)
	g.write(g.line("192.0.2.10", "two.example.test"))
	g.tail.Step()
	if _, n := g.oldestRaw(); n != 2 {
		t.Fatalf("%d lines before the bound", n)
	}
	g.clock.Add(2 * time.Minute)
	g.tail.Step()
	if _, n := g.oldestRaw(); n != 0 || g.tail.Stats().RawAgeTruncated != 1 {
		t.Fatalf("%d lines after the bound: %+v", n, g.tail.Stats())
	}
}

// Nothing is written for longer than the bound: the file is emptied even
// though the reader has nothing new to read, with or without a restart in
// between, and whatever was written while the reader was down is ingested
// first.
func TestTailRawAgeIdle(t *testing.T) {
	f := newTailFix(t)
	before, _ := os.Stat(f.path())
	f.write(f.line("192.0.2.10", "one.example.test") + f.line("192.0.2.10", "two.example.test"))
	f.tail.Step()
	f.clock.Add(23 * time.Hour)
	f.tail.Step()
	if _, n := f.oldestRaw(); n != 2 || f.tail.Stats().RawAgeTruncated != 0 {
		t.Fatalf("emptied before the bound: %d lines", n)
	}
	f.clock.Add(2 * time.Hour)
	f.tail.Step()
	after, _ := os.Stat(f.path())
	if f.rawSize() != 0 || !os.SameFile(before, after) || after.Mode().Perm() != 0o600 || f.tail.Stats().RawAgeTruncated != 1 {
		t.Fatalf("size %d, %+v", f.rawSize(), f.tail.Stats())
	}
	f.tail.Step()
	f.clock.Add(100 * time.Hour)
	f.tail.Step()
	f.write(f.line("192.0.2.10", "three.example.test"))
	f.tail.Step()
	f.expect("one.example.test", "two.example.test", "three.example.test")
	if st := f.tail.Stats(); st.RawAgeTruncated != 1 || st.Truncations != 0 {
		t.Fatalf("%+v", st)
	}

	// Restart after a long idle: the reader was down, a line was written
	// that it has not read, then nothing for 30 hours.
	g := newTailFix(t)
	g.write(g.line("192.0.2.10", "one.example.test") + g.line("192.0.2.10", "two.example.test"))
	g.tail.Step()
	g.tail.Close()
	g.clock.Add(time.Minute)
	g.write(g.line("192.0.2.10", "three.example.test"))
	g.clock.Add(30 * time.Hour)
	g.tail = g.newTailer(8 << 20)
	g.tail.Step()
	g.expect("one.example.test", "two.example.test", "three.example.test")
	if g.rawSize() != 0 || g.tail.Stats().RawAgeTruncated != 1 {
		t.Fatalf("size %d, %+v", g.rawSize(), g.tail.Stats())
	}
	g.write(g.line("192.0.2.10", "four.example.test"))
	g.tail.Step()
	g.expect("one.example.test", "two.example.test", "three.example.test", "four.example.test")
	// And a restart right after the truncation, clean or not (the position
	// was saved when the file was emptied): the old offset is not looked
	// for in the new content.
	h := newTailFix(t)
	var long strings.Builder
	for i := 0; i < 40; i++ {
		long.WriteString(h.line("192.0.2.10", "early.example.test"))
	}
	h.write(long.String())
	h.tail.Step()
	h.clock.Add(24*time.Hour - time.Second)
	h.write(h.line("192.0.2.10", "early.example.test"))
	h.tail.Step() // the position is saved here, as every few seconds
	if h.rawSize() == 0 {
		t.Fatal("emptied before the bound")
	}
	h.clock.Add(2 * time.Second)
	h.tail.Step() // emptied; the reader then stops without Close
	if h.rawSize() != 0 {
		t.Fatalf("size %d", h.rawSize())
	}
	h.mu.Lock()
	h.got = nil
	h.mu.Unlock()
	for i := 0; i < 60; i++ { // longer than what was there before
		h.write(h.line("192.0.2.10", fmt.Sprintf("late%02d.example.test", i)))
	}
	h.tail = h.newTailer(8 << 20)
	h.tail.Step()
	if n := h.names(); len(n) != 60 || n[0] != "late00.example.test" || n[59] != "late59.example.test" {
		t.Fatalf("%d records after the restart: %v", len(n), n)
	}

	// Timestamps that give no zone and an unfinished last line: the file's
	// own last write is enough.
	z := newTailFix(t)
	z.write(auditLine(z.clock.Now().Add(-3*time.Hour-7*time.Minute), "192.0.2.10", "odd.example.test", 1, 1, "default", "") + "[2026-11-15 12:00:00,000] 192.0.2.10 query half.exam")
	z.tail.Step()
	if z.tail.Stats().ZoneOffsetS != nil {
		t.Fatal("a zone was established")
	}
	z.clock.Add(23 * time.Hour)
	z.tail.Step()
	if z.rawSize() == 0 {
		t.Fatal("emptied before the bound")
	}
	z.clock.Add(2 * time.Hour)
	z.tail.Step()
	if z.rawSize() != 0 {
		t.Fatalf("size %d", z.rawSize())
	}
	z.write(z.line("192.0.2.10", "next.example.test"))
	z.tail.Step()
	z.expect("odd.example.test", "next.example.test")
}

// A reader that is restarted more often than the bound still empties the
// file when its first line is too old (it reads that line's timestamp; it
// does not need to have been running since).
func TestTailRawAgeAcrossRestarts(t *testing.T) {
	f := newTailFix(t)
	f.zone = -5 * time.Hour
	var want []string
	emptied := -1
	for h := 0; h < 40; h++ {
		if h > 0 && h%10 == 0 {
			if h%20 == 0 {
				f.tail.Close()
			}
			// (h == 10, 30: stopped without saving anything more.)
			f.tail = f.newTailer(8 << 20)
		}
		name := fmt.Sprintf("h%02d.example.test", h)
		want = append(want, name)
		f.write(f.line("192.0.2.10", name))
		f.tail.Step()
		f.tail.Step()
		f.expect(want...)
		if age, _ := f.oldestRaw(); age > DefaultMaxAge {
			t.Fatalf("hour %d: the raw directory holds a line %v old", h, age)
		}
		if emptied < 0 && f.rawSize() == 0 {
			emptied = h
		}
		f.clock.Add(time.Hour)
	}
	if emptied != 25 {
		t.Fatalf("first emptied at hour %d, want 25 (the first line was written at hour 0, the reader last started at hour 20)", emptied)
	}
}

// Rotated copies age out: when they were last written longer ago than the
// bound, and already when their first line is that old. So does anything
// else left in the directory.
func TestTailRawAgeRotatedCopies(t *testing.T) {
	f := newTailFix(t)
	f.zone = 8 * time.Hour
	exists := func(p string) bool {
		_, err := os.Lstat(p)
		return err == nil
	}
	f.write(f.line("192.0.2.10", "one.example.test"))
	f.tail.Step()
	f.clock.Add(10 * time.Hour)
	f.write(f.line("192.0.2.10", "two.example.test"))
	f.tail.Step()
	copyA := f.rotate(true) // lines of hour 0 and hour 10, written at hour 10
	// A copy whose lines cannot be read, a leftover of another name, and a
	// file whose time says it is from the future: all written "now".
	opaque := filepath.Join(f.dir, "audit.log-20261115-220001.gz")
	os.WriteFile(opaque, []byte("not gzip"), 0o640)
	f.touch(opaque)
	leftover := filepath.Join(f.dir, "audit.log.pending.gz")
	os.WriteFile(leftover, []byte("x"), 0o640)
	f.touch(leftover)
	future := filepath.Join(f.dir, "audit.log-20261115-220002.gz")
	writeGzip(t, future, "nothing that parses\n")
	os.Chtimes(future, f.clock.Now().Add(1000*time.Hour), f.clock.Now().Add(1000*time.Hour))
	f.write(f.line("192.0.2.10", "three.example.test"))
	f.tail.Step()
	f.expect("one.example.test", "two.example.test", "three.example.test")
	for _, p := range []string{copyA, opaque, leftover, future} {
		if !exists(p) {
			t.Fatalf("%s deleted at once", filepath.Base(p))
		}
	}
	f.clock.Add(13 * time.Hour) // hour 23
	f.write(f.line("192.0.2.10", "four.example.test"))
	f.tail.Step()
	if !exists(copyA) || f.tail.Stats().RawExpired != 0 {
		t.Fatal("a copy whose oldest line is 23 hours old was deleted")
	}
	f.clock.Add(2 * time.Hour) // hour 25: copyA's first line is older than the bound, its last write is not
	f.write(f.line("192.0.2.10", "five.example.test"))
	f.tail.Step()
	if exists(copyA) || !exists(opaque) || !exists(leftover) || !exists(future) || f.tail.Stats().RawExpired != 1 {
		t.Fatalf("%+v", f.tail.Stats())
	}
	if age, _ := f.oldestRaw(); age > DefaultMaxAge {
		t.Fatalf("a line %v old is left", age)
	}
	f.clock.Add(8 * time.Hour) // hour 33: 23 hours after the others were written
	f.tail.Step()
	if !exists(opaque) || !exists(leftover) || !exists(future) {
		t.Fatal("deleted before the bound")
	}
	f.clock.Add(2 * time.Hour) // hour 35
	f.tail.Step()
	if exists(opaque) || exists(leftover) || exists(future) {
		t.Fatal("a file older than the bound is left")
	}
	st := f.tail.Stats()
	if st.RawExpired != 4 || st.RawDeleted != 0 || st.RawFiles != 1 || st.RawAgeTruncated != 1 {
		t.Fatalf("%+v", st)
	}
	f.write(f.line("192.0.2.10", "six.example.test"))
	f.tail.Step()
	f.expect("one.example.test", "two.example.test", "three.example.test", "four.example.test", "five.example.test", "six.example.test")

	// Rotated while the reader was down, long ago: what it had not read is
	// taken from the copy before the copy is deleted.
	g := newTailFix(t)
	g.write(g.line("192.0.2.10", "one.example.test"))
	g.tail.Step()
	g.tail.Close()
	g.clock.Add(time.Second)
	g.write(g.line("192.0.2.10", "two.example.test"))
	copyB := g.rotate(true)
	g.clock.Add(30 * time.Hour)
	g.write(g.line("192.0.2.10", "three.example.test"))
	g.tail = g.newTailer(8 << 20)
	g.tail.Step()
	g.expect("one.example.test", "two.example.test", "three.example.test")
	if st := g.tail.Stats(); exists(copyB) || st.CaughtUp != 1 || st.RawExpired != 1 {
		t.Fatalf("%+v", st)
	}
}

// The audit file is emptied for age only when every line in it has been
// handed on: not while a backlog is still being read, not while a line is
// unfinished, and not if it is no longer the file, or the length, that was
// read.
func TestTailRawAgeTruncatesOnlyAfterIngest(t *testing.T) {
	f := newTailFix(t)
	f.write(f.line("192.0.2.10", "first.example.test"))
	f.tail.Step()
	f.tail.Close()
	// A backlog of several steps, written while the reader was down, 30
	// hours ago.
	var big strings.Builder
	lines := 1
	for big.Len() < 3*maxStepBytes {
		big.WriteString(f.line("192.0.2.10", fmt.Sprintf("b%05d.example.test", lines)))
		lines++
	}
	f.write(big.String())
	size := f.rawSize()
	f.clock.Add(30 * time.Hour)
	f.tail = f.newTailer(8 << 20)
	steps := 0
	for f.tail.Stats().RawAgeTruncated == 0 {
		if steps++; steps > 20 {
			t.Fatal("never emptied")
		}
		f.tail.Step()
		st := f.tail.Stats()
		if st.RawAgeTruncated == 0 && f.rawSize() != size {
			t.Fatalf("step %d: the file changed before it was read to the end", steps)
		}
		if st.RawAgeTruncated != 0 && int(st.Lines) != lines-1 {
			t.Fatalf("emptied after %d of %d lines", st.Lines, lines-1)
		}
		f.clock.Add(time.Second)
	}
	if n := f.names(); steps < 3 || len(n) != lines || n[0] != "first.example.test" || n[1] != "b00001.example.test" || n[lines-1] != fmt.Sprintf("b%05d.example.test", lines-1) || f.rawSize() != 0 {
		t.Fatalf("%d steps, %d records of %d, size %d", steps, len(n), lines, f.rawSize())
	}

	// An unfinished line that is still being written holds it up.
	g := newTailFix(t)
	g.write(g.line("192.0.2.10", "one.example.test"))
	g.tail.Step()
	g.clock.Add(25 * time.Hour)
	l := g.line("192.0.2.10", "two.example.test")
	g.write(l[:50])
	g.tail.Step()
	g.clock.Add(time.Second)
	g.tail.Step()
	if g.rawSize() == 0 || g.tail.Stats().RawAgeTruncated != 0 {
		t.Fatal("emptied with an unfinished line pending")
	}
	g.write(l[50:])
	g.tail.Step()
	g.expect("one.example.test", "two.example.test")
	if g.rawSize() != 0 || g.tail.Stats().RawAgeTruncated != 1 {
		t.Fatalf("size %d, %+v", g.rawSize(), g.tail.Stats())
	}

	// The last look before the truncation: another file, another length, a
	// link or a special file at the path are all left alone.
	dir := t.TempDir()
	p := filepath.Join(dir, AuditBase)
	os.WriteFile(p, []byte("0123456789"), 0o600)
	fi, _ := os.Stat(p)
	for name, ok := range map[string]bool{"longer": truncateRegular(p, inoOf(fi), 9) == nil, "other file": truncateRegular(p, inoOf(fi)+1, 10) == nil} {
		if b, _ := os.ReadFile(p); ok || string(b) != "0123456789" {
			t.Fatalf("%s: truncated", name)
		}
	}
	target := filepath.Join(dir, "elsewhere")
	os.WriteFile(target, []byte("keep"), 0o600)
	link := filepath.Join(dir, "link")
	os.Symlink(target, link)
	if b, _ := os.ReadFile(target); truncateRegular(link, 0, -1) == nil || string(b) != "keep" {
		t.Fatal("a symbolic link was followed")
	}
	if fifo := filepath.Join(dir, "fifo"); syscall.Mkfifo(fifo, 0o600) == nil {
		done := make(chan bool, 1)
		go func() { done <- truncateRegular(fifo, 0, -1) == nil }()
		select {
		case ok := <-done:
			if ok {
				t.Fatal("a FIFO was accepted")
			}
		case <-time.After(5 * time.Second):
			t.Fatal("opening a FIFO blocked")
		}
	}
	if after, _ := os.Stat(p); truncateRegular(p, inoOf(fi), 10) != nil || !os.SameFile(fi, after) {
		t.Fatal("the file that was read was not truncated in place")
	}
	if after, _ := os.Stat(p); after.Size() != 0 {
		t.Fatalf("size %d", after.Size())
	}
}

func TestPrepareAndCheckSink(t *testing.T) {
	uid := uint32(os.Getuid())
	base := t.TempDir()
	dir := filepath.Join(base, "state", "raw")
	if st := CheckSink(dir, uid); st.OK || st.Error == "" {
		t.Fatalf("missing directory accepted: %+v", st)
	}
	if err := PrepareSink(dir); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(dir, AuditBase)
	check := func(wantOK bool, why string) {
		t.Helper()
		if st := CheckSink(dir, uid); st.OK != wantOK {
			t.Fatalf("%s: %+v", why, st)
		}
	}
	check(true, "prepared")
	if st := CheckSink(dir, uid+1); st.OK {
		t.Fatal("another owner accepted")
	}
	// An existing regular file keeps its content.
	os.WriteFile(file, []byte("kept\n"), 0o600)
	os.Chmod(file, 0o640)
	check(false, "0640 file")
	if err := PrepareSink(dir); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(file); string(b) != "kept\n" {
		t.Fatalf("content lost: %q", b)
	}
	check(true, "mode restored")
	os.Chmod(dir, 0o755)
	check(false, "0755 directory")
	PrepareSink(dir)
	check(true, "directory mode restored")
	// Special files at the audit path: never accepted, replaced by a
	// regular file.
	os.Remove(file)
	check(false, "missing file")
	if err := syscall.Mkfifo(file, 0o600); err == nil {
		check(false, "FIFO")
		if err := PrepareSink(dir); err != nil {
			t.Fatal(err)
		}
		if fi, _ := os.Lstat(file); !fi.Mode().IsRegular() || fi.Mode().Perm() != 0o600 {
			t.Fatalf("FIFO not replaced: %v", fi.Mode())
		}
		check(true, "FIFO replaced")
	}
	os.Remove(file)
	target := filepath.Join(base, "elsewhere")
	os.WriteFile(target, []byte("x"), 0o600)
	os.Symlink(target, file)
	check(false, "symbolic link")
	if err := PrepareSink(dir); err != nil {
		t.Fatal(err)
	}
	if fi, _ := os.Lstat(file); !fi.Mode().IsRegular() {
		t.Fatal("symbolic link not replaced")
	}
	if b, _ := os.ReadFile(target); string(b) != "x" {
		t.Fatal("the link's target was touched")
	}
	// A directory path that is something else is refused and left alone.
	os.RemoveAll(dir)
	os.Symlink(base, dir)
	if err := PrepareSink(dir); err == nil {
		t.Fatal("a symbolic link was used as the audit directory")
	}
	check(false, "directory is a link")
	os.Remove(dir)
	os.Mkdir(dir, 0o700)
	os.Mkdir(file, 0o700)
	if err := PrepareSink(dir); err == nil {
		t.Fatal("a directory was used as the audit file")
	}
	for _, bad := range []string{"", "relative/raw", "/var/lib/x/../raw"} {
		if PrepareSink(bad) == nil {
			t.Errorf("accepted %q", bad)
		}
	}
}

func TestPurgeData(t *testing.T) {
	base := t.TempDir()
	raw, jd := filepath.Join(base, "raw"), filepath.Join(base, "journal")
	fill := func() {
		PrepareSink(raw)
		os.MkdirAll(jd, 0o700)
		os.WriteFile(filepath.Join(raw, AuditBase), []byte("line\n"), 0o600)
		os.WriteFile(filepath.Join(raw, "audit.log-20261115-110000.gz"), []byte("gz"), 0o600)
		syscall.Mkfifo(filepath.Join(raw, "fifo"), 0o600)
		os.WriteFile(filepath.Join(jd, segName(1)), []byte("{}\n"), 0o600)
		os.WriteFile(filepath.Join(jd, positionFile), []byte("{}"), 0o600)
		os.WriteFile(filepath.Join(jd, "unrelated.txt"), []byte("keep"), 0o600)
	}
	fill()
	if n, size := DataUsage(raw, jd); n != 5 || size == 0 {
		t.Fatalf("usage %d %d", n, size)
	}
	// The resolver may still have the audit file open: it is emptied, not
	// removed.
	if res := PurgeData(raw, jd, true, nil); !res.Complete || res.Residual != nil || res.Errors != nil || res.PurgedFiles != 5 {
		t.Fatalf("%+v", res)
	}
	if fi, err := os.Lstat(filepath.Join(raw, AuditBase)); err != nil || fi.Size() != 0 || !fi.Mode().IsRegular() {
		t.Fatalf("audit file: %v", err)
	}
	if ents, _ := os.ReadDir(raw); len(ents) != 1 {
		t.Fatalf("raw: %d entries", len(ents))
	}
	if ents, _ := os.ReadDir(jd); len(ents) != 1 || ents[0].Name() != "unrelated.txt" {
		t.Fatalf("journal: %v", ents)
	}
	fill()
	if res := PurgeData(raw, jd, false, nil); !res.Complete {
		t.Fatalf("%+v", res)
	}
	if ents, _ := os.ReadDir(raw); len(ents) != 0 {
		t.Fatalf("raw: %d entries", len(ents))
	}
	if fi, err := os.Stat(raw); err != nil || !fi.IsDir() {
		t.Fatal("the raw directory itself must stay (it is a container mount)")
	}
	if res := PurgeData(filepath.Join(base, "none"), filepath.Join(base, "none2"), false, nil); !res.Complete || res.PurgedFiles != 0 {
		t.Fatalf("absent directories: %+v", res)
	}
}

// ------------------------------------------------- clear: injected faults ---

// withFault: the reader's clear meets these faults from now on.
func (f *tailFix) withFault(fs ...*fsFault) { f.faults = fs }

// restart replaces the reader by a new one (the position file is kept).
func (f *tailFix) restart() {
	f.tail.Close()
	f.tail = f.newTailer(8 << 20)
}

func sameErrors(got []ClearError, want ...ClearError) bool {
	if len(got) != len(want) {
		return false
	}
	for i := range got {
		if got[i] != want[i] {
			return false
		}
	}
	return true
}

// A rotated copy that cannot be deleted: the clear says so (it is not a
// success), the copy stays counted as residue, nothing of it is ever
// ingested — not on the next step, not by the catch-up after a restart —
// and a later clear removes it.
func TestTailClearCopyNotDeleted(t *testing.T) {
	f := newTailFix(t)
	f.write(f.line("192.0.2.10", "one.example.test"))
	f.tail.Step()
	f.clock.Add(time.Second)
	f.write(f.line("192.0.2.10", "unread.example.test"))
	copyPath := f.rotate(false) // holds "one" and the unread line
	copySize := fileSize(t, copyPath)
	stuck := newFault("remove", "audit.log-", syscall.EPERM)
	f.withFault(stuck)
	f.clock.Add(time.Second)

	res := f.tail.Clear()
	if res.Files != 1 || res.Bytes != copySize || res.Unknown || !sameErrors(res.Errors, ClearError{Part: PartRaw, Op: "remove", Cause: "permission", Count: 1}) {
		t.Fatalf("%+v", res)
	}
	if fileSize(t, copyPath) != copySize {
		t.Fatal("the copy changed")
	}
	st := f.tail.Stats()
	if st.ClearPendingAt == nil || st.RawResidualFiles != 1 || st.RawResidualBytes != copySize {
		t.Fatalf("%+v", st)
	}
	f.clock.Add(time.Second)
	f.write(f.line("192.0.2.10", "two.example.test"))
	f.tail.Step()
	f.tail.Step()
	f.expect("one.example.test", "two.example.test")

	// Rotated again while the reader is down: the catch-up takes the new
	// copy's unread line and nothing of the one the clear left.
	f.tail.Close()
	f.clock.Add(time.Second)
	f.write(f.line("192.0.2.10", "late.example.test"))
	f.clock.Add(time.Second)
	f.rotate(false)
	f.write(f.line("192.0.2.10", "three.example.test"))
	f.restart()
	f.tail.Step()
	f.expect("one.example.test", "two.example.test", "late.example.test", "three.example.test")
	if st = f.tail.Stats(); st.ClearPendingAt == nil || st.RawResidualFiles != 1 || st.RawResidualBytes != copySize || st.CaughtUp != 1 {
		t.Fatalf("after the restart: %+v", st)
	}

	// The retry, once the fault is gone.
	stuck.set(false)
	if res = f.tail.Clear(); res.Files != 0 || res.Unknown || res.Errors != nil || res.Freed == 0 {
		t.Fatalf("%+v", res)
	}
	if ents, _ := os.ReadDir(f.dir); len(ents) != 1 {
		t.Fatalf("%d entries left", len(ents))
	}
	if st = f.tail.Stats(); st.ClearPendingAt != nil || st.RawResidualFiles != 0 || st.RawResidualBytes != 0 {
		t.Fatalf("%+v", st)
	}
	f.clock.Add(time.Second)
	f.write(f.line("192.0.2.10", "four.example.test"))
	f.tail.Step()
	f.expect("one.example.test", "two.example.test", "late.example.test", "three.example.test", "four.example.test")
}

func fileSize(t *testing.T, p string) int64 {
	t.Helper()
	fi, err := os.Lstat(p)
	if err != nil {
		t.Fatal(err)
	}
	return fi.Size()
}

// The audit file cannot be emptied: the clear says so, the file is followed
// from where it ended (its content is never read again from the start, also
// not after a restart and not once the resolver has rotated it away), and
// a later clear empties it.
func TestTailClearAuditNotTruncated(t *testing.T) {
	for _, zoned := range []bool{true, false} {
		f := newTailFix(t)
		if !zoned {
			// A resolver whose lines are too far from the file's time for a
			// zone to be established: records get the time they were read.
			f.zone = 7 * time.Minute
		}
		f.write(f.line("192.0.2.10", "one.example.test"))
		f.tail.Step()
		f.clock.Add(time.Second)
		f.write(f.line("192.0.2.10", "unread.example.test"))
		size := fileSize(t, f.path())
		stuck := newFault("truncate", AuditBase, syscall.EIO)
		f.withFault(stuck)
		f.clock.Add(time.Second)

		res := f.tail.Clear()
		if res.Files != 1 || res.Bytes != size || res.Freed != 0 || !sameErrors(res.Errors, ClearError{Part: PartRaw, Op: "truncate", Cause: "io", Count: 1}) {
			t.Fatalf("zoned %v: %+v", zoned, res)
		}
		if fileSize(t, f.path()) != size {
			t.Fatal("the audit file changed")
		}
		st := f.tail.Stats()
		if st.ClearPendingAt == nil || st.RawResidualFiles != 1 || st.RawResidualBytes != size || (st.ZoneOffsetS != nil) != zoned {
			t.Fatalf("zoned %v: %+v", zoned, st)
		}
		f.clock.Add(time.Second)
		f.write(f.line("192.0.2.10", "two.example.test"))
		f.tail.Step()
		f.tail.Step()
		f.expect("one.example.test", "two.example.test")

		// A restart resumes after the content the clear could not remove.
		f.clock.Add(time.Second)
		f.write(f.line("192.0.2.10", "three.example.test"))
		f.restart()
		f.tail.Step()
		f.expect("one.example.test", "two.example.test", "three.example.test")
		if st = f.tail.Stats(); st.ClearPendingAt == nil || st.RawResidualFiles != 1 || st.RawResidualBytes != size {
			t.Fatalf("zoned %v, after the restart: %+v", zoned, st)
		}

		// The resolver rotates it away while the reader is down, with a line
		// the reader had not read: the copy is still residue, and what it
		// held before the clear does not come back.
		f.tail.Close()
		f.clock.Add(time.Second)
		f.write(f.line("192.0.2.10", "late.example.test"))
		f.rotate(false)
		f.clock.Add(time.Second)
		f.write(f.line("192.0.2.10", "four.example.test"))
		f.tail = f.newTailer(8 << 20)
		f.tail.Step()
		want := []string{"one.example.test", "two.example.test", "three.example.test", "late.example.test", "four.example.test"}
		if !zoned {
			// Without a zone the lines of that copy cannot be told apart by
			// time: none of it is taken, rather than any of the old ones.
			want = []string{"one.example.test", "two.example.test", "three.example.test", "four.example.test"}
		}
		f.expect(want...)
		if st = f.tail.Stats(); st.ClearPendingAt == nil || st.RawResidualFiles != 1 {
			t.Fatalf("zoned %v, after the rotation: %+v", zoned, st)
		}

		// The retry: complete.
		stuck.set(false)
		if res = f.tail.Clear(); res.Files != 0 || res.Unknown || res.Errors != nil {
			t.Fatalf("zoned %v: %+v", zoned, res)
		}
		if ents, _ := os.ReadDir(f.dir); len(ents) != 1 || fileSize(t, f.path()) != 0 {
			t.Fatalf("zoned %v: %d entries left", zoned, len(ents))
		}
		if st = f.tail.Stats(); st.ClearPendingAt != nil || st.RawResidualFiles != 0 {
			t.Fatalf("zoned %v: %+v", zoned, st)
		}
		f.tail.Close()
	}
}

// A failed truncation whose retry empties the file: reading starts at the
// file's beginning again (the offset the first clear kept is not used on
// the emptied file).
func TestTailClearRetryResetsOffset(t *testing.T) {
	f := newTailFix(t)
	f.write(f.line("192.0.2.10", "one.example.test") + f.line("192.0.2.10", "one-b.example.test"))
	f.tail.Step()
	stuck := newFault("truncate", AuditBase, syscall.EACCES)
	f.withFault(stuck)
	if res := f.tail.Clear(); res.Files != 1 {
		t.Fatalf("%+v", res)
	}
	stuck.set(false)
	if res := f.tail.Clear(); res.Files != 0 || res.Errors != nil || res.Freed == 0 {
		t.Fatalf("%+v", res)
	}
	f.clock.Add(time.Second)
	f.write(f.line("192.0.2.10", "two.example.test"))
	f.tail.Step()
	f.expect("one.example.test", "one-b.example.test", "two.example.test")
	f.restart()
	f.clock.Add(time.Second)
	f.write(f.line("192.0.2.10", "three.example.test"))
	f.tail.Step()
	f.expect("one.example.test", "one-b.example.test", "two.example.test", "three.example.test")
}

// The directory cannot be listed, or an entry cannot be looked at: the
// clear is not a success and says that more may be left than it counted;
// the audit file, reached by its fixed path, is emptied all the same.
func TestTailClearCannotListOrLook(t *testing.T) {
	for _, c := range []struct {
		op, part string
		err      error
		want     ClearError
	}{
		{"readdir", "raw", syscall.EIO, ClearError{Part: PartRaw, Op: "readdir", Cause: "io", Count: 1}},
		{"lstat", "audit.log-", syscall.EACCES, ClearError{Part: PartRaw, Op: "lstat", Cause: "permission", Count: 1}},
		{"lstat", "audit.log-", syscall.ESTALE, ClearError{Part: PartRaw, Op: "lstat", Cause: "other", Count: 1}},
	} {
		f := newTailFix(t)
		f.write(f.line("192.0.2.10", "one.example.test"))
		f.tail.Step()
		f.clock.Add(time.Second)
		f.write(f.line("192.0.2.10", "old.example.test"))
		copyPath := f.rotate(false)
		f.write(f.line("192.0.2.10", "cur.example.test"))
		fault := newFault(c.op, c.part, c.err)
		f.withFault(fault)
		f.clock.Add(time.Second)
		res := f.tail.Clear()
		if !res.Unknown || !sameErrors(res.Errors, c.want) {
			t.Fatalf("%s: %+v", c.op, res)
		}
		if fileSize(t, f.path()) != 0 {
			t.Fatalf("%s: the audit file was not emptied", c.op)
		}
		if st := f.tail.Stats(); st.ClearPendingAt == nil || st.RawResidualFiles != 1 || st.RawResidualBytes != fileSize(t, copyPath) {
			t.Fatalf("%s: %+v", c.op, st)
		}
		fault.set(false)
		if res = f.tail.Clear(); res.Unknown || res.Files != 0 || res.Errors != nil {
			t.Fatalf("%s retry: %+v", c.op, res)
		}
		if st := f.tail.Stats(); st.ClearPendingAt != nil {
			t.Fatalf("%s retry: %+v", c.op, st)
		}
		f.expect("one.example.test")
		f.tail.Close()
	}
	// The audit file itself cannot be looked at: nothing is known of it, so
	// it is followed from its end, never from its start.
	f := newTailFix(t)
	f.write(f.line("192.0.2.10", "one.example.test"))
	f.tail.Step()
	fault := newFault("lstat", AuditBase, syscall.EIO)
	f.withFault(fault)
	f.clock.Add(time.Second)
	f.write(f.line("192.0.2.10", "unread.example.test"))
	if res := f.tail.Clear(); !res.Unknown || !sameErrors(res.Errors, ClearError{Part: PartRaw, Op: "lstat", Cause: "io", Count: 1}) {
		t.Fatalf("%+v", res)
	}
	f.clock.Add(time.Second)
	f.write(f.line("192.0.2.10", "two.example.test"))
	f.tail.Step()
	f.expect("one.example.test", "two.example.test")
	if st := f.tail.Stats(); st.ClearPendingAt == nil || st.RawResidualFiles != 1 {
		t.Fatalf("%+v", st)
	}
}

// What a clear left goes with the age bound like everything else, and the
// reminder goes with it.
func TestTailClearResidueExpires(t *testing.T) {
	f := newTailFix(t)
	f.write(f.line("192.0.2.10", "one.example.test"))
	f.tail.Step()
	f.rotate(false)
	stuck := newFault("remove", "audit.log-", syscall.EACCES)
	f.withFault(stuck)
	if res := f.tail.Clear(); res.Files != 1 {
		t.Fatalf("%+v", res)
	}
	f.clock.Add(DefaultMaxAge + time.Minute)
	f.tail.Step()
	if st := f.tail.Stats(); st.ClearPendingAt != nil || st.RawResidualFiles != 0 || st.RawExpired != 1 {
		t.Fatalf("%+v", st)
	}
}

// The host agent's own clear (no reader runs): every failure is reported,
// what is left is counted, and a reader started afterwards knows the
// residue and does not ingest it; its clear then completes.
func TestPurgeDataReportsWhatIsLeft(t *testing.T) {
	c := newClock()
	base := t.TempDir()
	raw, jd := filepath.Join(base, "raw"), filepath.Join(base, "journal")
	if err := PrepareSink(raw); err != nil {
		t.Fatal(err)
	}
	// A journal with two segments and a raw side with a copy and content.
	j, err := Open(Config{Dir: jd, MaxRecords: 80, Now: c.Now})
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 15; i++ {
		j.Add(rec(c.Now(), "192.0.2.10", fmt.Sprintf("n%d.example.test", i)))
	}
	j.Flush()
	j.Close()
	audit := filepath.Join(raw, AuditBase)
	line := auditLine(c.Now(), "192.0.2.10", "raw.example.test", 1, 2, "default", "192.0.2.1")
	os.WriteFile(audit, []byte(line), 0o600)
	os.WriteFile(filepath.Join(raw, "audit.log-20261115-110000"), []byte(line), 0o600)
	os.WriteFile(filepath.Join(jd, positionFile), []byte(`{"ino":1,"offset":0,"last_naive_ms":0}`), 0o600)
	for _, p := range []string{audit, filepath.Join(raw, "audit.log-20261115-110000")} {
		os.Chtimes(p, c.Now(), c.Now())
	}

	seg := newFault("remove", segName(1), syscall.EACCES)
	cp := newFault("remove", "audit.log-", syscall.EROFS)
	tr := newFault("truncate", AuditBase, syscall.EROFS)
	res := PurgeData(raw, jd, true, faultsOf(seg, cp, tr))
	want := ClearResidual{Segments: 1, Records: 10, Bytes: fileSize(t, filepath.Join(jd, segName(1))), RawFiles: 2, RawBytes: 2 * int64(len(line))}
	if res.Complete || res.Residual == nil || *res.Residual != want || len(res.Errors) != 3 || res.PurgedFiles != 1 {
		t.Fatalf("%+v %+v", res, res.Residual)
	}
	b, _ := json.Marshal(res)
	for _, leak := range []string{base, "audit.log", "dns-", "example.test", "denied", "read-only"} {
		if strings.Contains(string(b)+res.Problem(), leak) {
			t.Fatalf("the result carries %q: %s / %s", leak, b, res.Problem())
		}
	}
	if !strings.Contains(res.Problem(), "1 个分段") || !strings.Contains(res.Problem(), "文件系统只读") || !strings.Contains(res.Problem(), "权限不足") {
		t.Fatalf("problem: %s", res.Problem())
	}
	if n, _ := DataUsage(raw, jd); n != 5 { // audit, copy, segment, clear mark, position
		t.Fatalf("%d files", n)
	}

	// A listing that fails: unknown, not success.
	if r := PurgeData(raw, jd, true, faultsOf(newFault("readdir", "journal", syscall.EIO))); r.Complete || r.Residual == nil || !r.Residual.Unknown ||
		!sameErrors(r.Errors, ClearError{Part: PartJournal, Op: "readdir", Cause: "io", Count: 1}) {
		t.Fatalf("%+v %+v", r, r.Residual)
	}
	// (That purge emptied the raw side; put it back as the first one left it.)
	os.WriteFile(audit, []byte(line), 0o600)
	os.WriteFile(filepath.Join(raw, "audit.log-20261115-110000"), []byte(line), 0o600)
	for _, p := range []string{audit, filepath.Join(raw, "audit.log-20261115-110000")} {
		os.Chtimes(p, c.Now(), c.Now())
	}
	if res = PurgeData(raw, jd, true, faultsOf(seg, cp, tr)); res.Complete || *res.Residual != want {
		t.Fatalf("%+v %+v", res, res.Residual)
	}

	// A reader started on what is left.
	c.Add(time.Minute)
	d, err := NewDaemon(DaemonConfig{RawDir: raw, JournalDir: jd, MaxRecords: 80, MaxAge: DefaultMaxAge, MaxBytes: DefaultMaxBytes}, nil, c.Now)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	fd, _ := os.OpenFile(audit, os.O_WRONLY|os.O_APPEND, 0)
	fd.WriteString(auditLine(c.Now(), "192.0.2.10", "fresh.example.test", 1, 2, "default", "192.0.2.1"))
	fd.Close()
	os.Chtimes(audit, c.Now(), c.Now())
	d.Step()
	d.Journal.Flush()
	h := d.Health()
	if h.Journal.Residual == nil || h.Journal.Residual.Segments != 1 || h.Journal.Residual.Records != 10 || h.Journal.Residual.ClearAt == nil ||
		h.Reader.ClearPendingAt == nil || h.Reader.RawResidualFiles != 2 || h.Reader.Parsed != 1 {
		t.Fatalf("%+v %+v %+v", h.Journal, h.Journal.Residual, h.Reader)
	}
	if p, _ := d.Journal.Query(Query{Text: "raw.example"}); p.Matched != 0 {
		t.Fatal("the audit content the purge could not remove was ingested")
	}
	if p, _ := d.Journal.Query(Query{Text: "fresh"}); p.Matched != 1 {
		t.Fatal("the line written after the purge was not read")
	}
	cr := d.Clear()
	if !cr.Complete || cr.Residual != nil || cr.Errors != nil || cr.Cleared != 11 {
		t.Fatalf("%+v", cr)
	}
	if h = d.Health(); h.Journal.Residual != nil || h.Reader.ClearPendingAt != nil || h.Journal.Records != 0 {
		t.Fatalf("%+v %+v", h.Journal, h.Reader)
	}
}

// A line that was in the audit file at the clear and had not been read: the
// clear could not empty the file, the resolver then rotated it away while
// the reader was down. The catch-up takes what was written after the clear
// and nothing from before it.
func TestTailClearUnreadNotCaughtUp(t *testing.T) {
	for _, zoned := range []bool{true, false} {
		f := newTailFix(t)
		if !zoned {
			f.zone = 7 * time.Minute
		}
		f.write(f.line("192.0.2.10", "one.example.test"))
		f.tail.Step()
		f.clock.Add(time.Second)
		f.write(f.line("192.0.2.10", "unread.example.test"))
		f.withFault(newFault("truncate", AuditBase, syscall.EACCES))
		f.clock.Add(time.Second)
		if res := f.tail.Clear(); res.Files != 1 {
			t.Fatalf("%+v", res)
		}
		f.tail.Close()
		f.clock.Add(time.Second)
		f.write(f.line("192.0.2.10", "late.example.test"))
		f.rotate(true)
		f.clock.Add(time.Second)
		f.write(f.line("192.0.2.10", "new.example.test"))
		f.tail = f.newTailer(8 << 20)
		f.tail.Step()
		for _, n := range f.names() {
			if n == "unread.example.test" {
				t.Fatalf("zoned %v: a line from before the clear came back: %v", zoned, f.names())
			}
		}
		if zoned {
			f.expect("one.example.test", "late.example.test", "new.example.test")
			// The compressed copy still starts with lines from before the
			// clear: it is what is left of it.
			if st := f.tail.Stats(); st.ClearPendingAt == nil || st.RawResidualFiles != 1 {
				t.Fatalf("%+v", st)
			}
		}
		f.tail.Close()
	}
}
