package dnsjournal

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func newClock() *fakeClock {
	return &fakeClock{t: time.Date(2026, 11, 15, 12, 0, 0, 0, time.UTC)}
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fakeClock) Add(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

func rec(at time.Time, client, name string) Record {
	return Record{Time: at, Client: client, MAC: "02:00:00:00:00:01", Name: name, QType: 1, Result: ResultAnswered, Group: "default", ElapsedMS: 3, Answers: 1}
}

func openTest(t *testing.T, cfg Config) *Journal {
	t.Helper()
	if cfg.Dir == "" {
		cfg.Dir = filepath.Join(t.TempDir(), "journal")
	}
	j, err := Open(cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(j.Close)
	return j
}

// diskUse sums the files of dir: content bytes, files, record lines.
func diskUse(t *testing.T, dir string) (size int64, files, lines int) {
	t.Helper()
	ents, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range ents {
		b, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			continue
		}
		size += int64(len(b))
		files++
		if segNameRe.MatchString(e.Name()) {
			lines += bytes.Count(b, []byte{'\n'})
		}
	}
	return
}

func TestJournalRecordBound(t *testing.T) {
	c := newClock()
	j := openTest(t, Config{MaxRecords: 100, Now: c.Now})
	for i := 0; i < 1000; i++ {
		j.Add(rec(c.Now(), "192.0.2.10", fmt.Sprintf("n%d.example.test", i)))
		c.Add(time.Millisecond)
		if i%50 == 49 {
			j.Flush()
			if _, _, lines := diskUse(t, j.cfg.Dir); lines > 100 {
				t.Fatalf("after %d: %d lines on disk", i+1, lines)
			}
		}
	}
	j.Flush()
	p, err := j.Query(Query{Limit: PageMax})
	if err != nil || p.Matched > 100 || len(p.Records) == 0 || p.Records[0].Name != "n999.example.test" {
		t.Fatalf("%v matched %d first %+v", err, p.Matched, p.Records[:1])
	}
	if st := j.Stats(); st.Records > 100 || st.Dropped != 0 || st.MaxRecords != 100 {
		t.Fatalf("%+v", st)
	}
}

func TestJournalAgeBound(t *testing.T) {
	c := newClock()
	j := openTest(t, Config{Now: c.Now})
	for i := 0; i < 10; i++ {
		j.Add(rec(c.Now(), "192.0.2.10", "old.example.test"))
	}
	j.Flush()
	c.Add(23 * time.Hour)
	j.Add(rec(c.Now(), "192.0.2.10", "mid.example.test"))
	j.Flush()
	if p, _ := j.Query(Query{}); p.Matched != 11 {
		t.Fatalf("matched %d", p.Matched)
	}
	c.Add(2 * time.Hour) // the first ten are 25 h old now
	if p, _ := j.Query(Query{}); p.Matched != 1 || p.Records[0].Name != "mid.example.test" {
		t.Fatalf("a record older than 24 h is shown: %+v", p)
	}
	j.Add(rec(c.Now(), "192.0.2.10", "new.example.test"))
	j.Flush()
	if _, _, lines := diskUse(t, j.cfg.Dir); lines != 2 {
		t.Fatalf("%d lines on disk after the age bound", lines)
	}
	// The only segment, wholly too old, goes on the next write as well.
	c.Add(48 * time.Hour)
	j.Add(rec(c.Now(), "192.0.2.10", "last.example.test"))
	j.Flush()
	if _, _, lines := diskUse(t, j.cfg.Dir); lines != 1 {
		t.Fatalf("%d lines on disk", lines)
	}
}

// A flood of the longest records never takes the files over the byte cap,
// block rounding included.
func TestJournalByteBoundUnderFlood(t *testing.T) {
	c := newClock()
	const max = 512 << 10
	j := openTest(t, Config{MaxBytes: max, MaxRecords: 1 << 20, Now: c.Now})
	long := strings.Repeat("a", 63) + "." + strings.Repeat("b", 63) + "." + strings.Repeat("c", 63) + "." + strings.Repeat("d", 61)
	for i := 0; i < 20000; i++ {
		r := rec(c.Now(), "2001:db8:ffff:ffff:ffff:ffff:ffff:ffff", long)
		r.Group, r.Answers, r.AnswersOther = strings.Repeat("g", MaxGroup), MaxAnswerTokens, MaxAnswerTokens
		j.Add(r)
		c.Add(time.Millisecond)
		if i%500 == 499 {
			j.Flush()
			size, files, _ := diskUse(t, j.cfg.Dir)
			if size+int64(files)*blockSlack > max || files > MaxSegments {
				t.Fatalf("after %d: %d bytes in %d files, cap %d", i+1, size, files, max)
			}
		}
	}
	j.Flush()
	if st := j.Stats(); st.Records == 0 || st.Oversized != 0 || st.WriteErrors != 0 {
		t.Fatalf("%+v", st)
	}
	if _, err := Open(Config{Dir: filepath.Join(t.TempDir(), "x"), MaxBytes: 8 << 10}); err == nil {
		t.Fatal("a cap too small for one segment was accepted")
	}
}

func TestJournalRestartTornTailAndModes(t *testing.T) {
	c := newClock()
	dir := filepath.Join(t.TempDir(), "journal")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	j, err := Open(Config{Dir: dir, Now: c.Now})
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 5; i++ {
		j.Add(rec(c.Now(), "192.0.2.10", fmt.Sprintf("n%d.example.test", i)))
	}
	j.Close()
	if fi, _ := os.Stat(dir); fi.Mode().Perm() != 0o700 {
		t.Fatalf("directory %v", fi.Mode())
	}
	ents, _ := os.ReadDir(dir)
	var seg string
	for _, e := range ents {
		fi, _ := e.Info()
		if fi.Mode().Perm() != 0o600 {
			t.Fatalf("%s is %v", e.Name(), fi.Mode())
		}
		seg = filepath.Join(dir, e.Name())
	}
	// A crash in the middle of a line, and a line that is not a record.
	f, _ := os.OpenFile(seg, os.O_WRONLY|os.O_APPEND, 0)
	f.WriteString("not json\n" + `{"id":99,"time":"2026-11-15T12:00:00Z","client":"192.0.2`)
	f.Close()
	os.Chmod(seg, 0o644)
	j2 := openTest(t, Config{Dir: dir, Now: c.Now})
	if st := j2.Stats(); st.Records != 5 || st.TornBytes == 0 {
		t.Fatalf("%+v", st)
	}
	if fi, _ := os.Stat(seg); fi.Mode().Perm() != 0o600 {
		t.Fatalf("segment mode not restored: %v", fi.Mode())
	}
	j2.Add(rec(c.Now(), "192.0.2.10", "after.example.test"))
	j2.Flush()
	p, _ := j2.Query(Query{})
	if p.Matched != 6 || p.Records[0].ID != 6 || p.Records[0].Name != "after.example.test" {
		t.Fatalf("%+v", p.Records)
	}
	b, _ := os.ReadFile(seg)
	for _, l := range bytes.Split(bytes.TrimSpace(b), []byte{'\n'}) {
		var r Record
		if string(l) != "not json" && json.Unmarshal(l, &r) != nil {
			t.Fatalf("unreadable line after recovery: %q", l)
		}
	}
	if rep := j2.Clear(); rep.Cleared != 6 || rep.Residual != nil || rep.Errors != nil {
		t.Fatalf("cleared %+v", rep)
	}
	if _, _, lines := diskUse(t, dir); lines != 0 {
		t.Fatal("records left after clear")
	}
	j2.Add(rec(c.Now(), "192.0.2.10", "again.example.test"))
	j2.Flush()
	if st := j2.Stats(); st.Records != 1 || st.ClearedAt == nil {
		t.Fatalf("%+v", st)
	}
}

// A stalled writer never makes Add wait: the queue fills, the rest is
// dropped and counted.
func TestJournalQueueFullDropsAndCounts(t *testing.T) {
	c := newClock()
	block := make(chan struct{})
	dir := filepath.Join(t.TempDir(), "journal")
	j, err := Open(Config{Dir: dir, Now: c.Now, Queue: 16})
	if err != nil {
		t.Fatal(err)
	}
	var once sync.Once
	j.testHookWrite = func() { <-block }
	start := time.Now()
	for i := 0; i < 5000; i++ {
		j.Add(rec(c.Now(), "192.0.2.10", "q.example.test"))
	}
	if d := time.Since(start); d > 2*time.Second {
		t.Fatalf("5000 Adds took %v with a stalled writer", d)
	}
	st := j.Stats()
	if st.Dropped < 5000-16-300 || st.Dropped >= 5000 {
		t.Fatalf("dropped %d", st.Dropped)
	}
	once.Do(func() { close(block) })
	j.Flush()
	if got := j.Stats(); uint64(got.Records)+got.Dropped != 5000 {
		t.Fatalf("records %d + dropped %d != 5000", got.Records, got.Dropped)
	}
	j.Close()
}

func TestJournalFieldBounds(t *testing.T) {
	c := newClock()
	j := openTest(t, Config{Now: c.Now})
	j.Add(Record{Time: c.Now(), Client: strings.Repeat("1", 200), MAC: strings.Repeat("m", 99), Name: strings.Repeat("n", 999) + "\x00\n", QType: 99999,
		Result: strings.Repeat("r", 99), Group: strings.Repeat("g", 999), ElapsedMS: -5, Answers: 9999, AnswersOther: -1})
	j.Flush()
	p, _ := j.Query(Query{})
	if len(p.Records) != 1 {
		t.Fatalf("%+v", p)
	}
	r := p.Records[0]
	if len(r.Client) > 64 || len(r.MAC) > 32 || len(r.Name) != MaxName || len(r.Result) > 32 || len(r.Group) != MaxGroup || r.QType != 0 || r.ElapsedMS != 0 ||
		r.Answers != MaxAnswerTokens || r.AnswersOther != 0 || strings.ContainsAny(r.Name, "\x00\n") {
		t.Fatalf("%+v", r)
	}
	b, _ := json.Marshal(r)
	if len(b)+1 > MaxLine {
		t.Fatalf("the longest record is %d bytes, over MaxLine", len(b))
	}
}

func TestJournalQueryFiltersPagingSummary(t *testing.T) {
	c := newClock()
	j := openTest(t, Config{Now: c.Now})
	t0 := c.Now()
	add := func(client, mac, name, result, group string, qtype int) {
		j.Add(Record{Time: c.Now(), Client: client, MAC: mac, Name: name, QType: qtype, Result: result, Group: group, ElapsedMS: 2, Answers: 1})
		c.Add(time.Second)
	}
	for i := 0; i < 30; i++ {
		add("192.0.2.10", "02:00:00:00:00:01", fmt.Sprintf("a%d.example.test", i%3), ResultAnswered, "default", 1)
	}
	add("192.0.2.10", "02:00:00:00:00:01", "nx.example.test", ResultNoAnswer, "domestic", 1)
	add("192.0.2.10", "", "slow.example.org", ResultNoAnswerSlow, "rg_hk", 28)
	// The address moved to another device.
	add("192.0.2.10", "02:00:00:00:00:02", "other.example.test", ResultAnswered, "default", 1)
	add("2001:db8:1::20", "02:00:00:00:00:03", "v6.example.test", ResultAnswered, "g_jp-a", 28)
	j.Flush()
	count := func(q Query) int {
		t.Helper()
		p, err := j.Query(q)
		if err != nil {
			t.Fatalf("%+v: %v", q, err)
		}
		return p.Matched
	}
	for _, c := range []struct {
		q    Query
		want int
	}{
		{Query{}, 34},
		{Query{Device: "192.0.2.10"}, 33},
		{Query{Device: "::ffff:192.0.2.10"}, 33},
		{Query{Device: "2001:db8:1::20"}, 1},
		{Query{MAC: "02:00:00:00:00:02"}, 1},
		{Query{Device: "192.0.2.10", MAC: "02:00:00:00:00:01"}, 31},
		{Query{Result: ResultNoAnswer}, 1},
		{Query{Result: ResultNoAnswerSlow}, 1},
		{Query{Result: ResultNoAnswerAny}, 2},
		{Query{Result: ResultAnswered}, 32},
		{Query{Group: "rg_hk"}, 1},
		{Query{Group: "domestic"}, 1},
		{Query{Text: "EXAMPLE.org"}, 1},
		{Query{Text: "a1."}, 10},
		{Query{From: t0.Add(30 * time.Second).Format(time.RFC3339)}, 4},
		{Query{To: t0.Add(30 * time.Second).Format(time.RFC3339)}, 30},
		{Query{From: t0.Add(30 * time.Second).Format(time.RFC3339), To: t0.Add(32 * time.Second).Format(time.RFC3339)}, 2},
	} {
		if got := count(c.q); got != c.want {
			t.Errorf("%+v: %d, want %d", c.q, got, c.want)
		}
	}
	// Paging by cursor, newest first, no record twice.
	seen := map[uint64]bool{}
	var before uint64
	for pages := 0; ; pages++ {
		p, err := j.Query(Query{Limit: 10, Before: before})
		if err != nil || pages > 5 {
			t.Fatal(err, pages)
		}
		for i, r := range p.Records {
			if seen[r.ID] || (i > 0 && r.ID >= p.Records[i-1].ID) {
				t.Fatalf("page %d: order or repeat at %d", pages, r.ID)
			}
			seen[r.ID] = true
		}
		if before = p.NextBefore; before == 0 {
			break
		}
	}
	if len(seen) != 34 {
		t.Fatalf("paged %d records", len(seen))
	}
	for _, bad := range []Query{{Device: "not-an-address"}, {Device: "fe80::1%eth0"}, {MAC: "02-00-00-00-00-01"}, {MAC: "zz"}, {Result: "failed"}, {Group: "a b"}, {Group: "x;rm"},
		{From: "yesterday"}, {To: "12:00"}, {Text: strings.Repeat("x", MaxText+1)}, {Text: "a\nb"}, {Limit: PageMax + 1}, {Limit: -1}} {
		if _, err := j.Query(bad); err == nil {
			t.Errorf("accepted %+v", bad)
		}
	}
	for _, v := range []url.Values{{"path": {"/etc/passwd"}}, {"device": {"192.0.2.10", "192.0.2.11"}}, {"limit": {"x"}}, {"before": {"-1"}}} {
		if _, err := QueryFrom(v); err == nil {
			t.Errorf("accepted %v", v)
		}
	}
	if q, err := QueryFrom(Query{Device: "192.0.2.10", MAC: "02:00:00:00:00:01", Result: ResultAnswered, Group: "default", Text: "a", Before: 9, Limit: 5}.Values()); err != nil || q.Before != 9 || q.Limit != 5 || q.MAC == "" {
		t.Fatalf("round trip: %v %+v", err, q)
	}
	if _, err := SummaryQueryFrom(url.Values{"device": {"192.0.2.10"}}); err == nil {
		t.Fatal("summary accepted another parameter")
	}

	sum, err := j.Summary(SummaryQuery{})
	if err != nil || len(sum.Devices) != 2 {
		t.Fatalf("%v %+v", err, sum)
	}
	// Most recently seen first.
	d6, d4 := sum.Devices[0], sum.Devices[1]
	if d6.Device != "2001:db8:1::20" || d6.Total != 1 || d6.ByGroup["g_jp-a"] != 1 {
		t.Fatalf("%+v", d6)
	}
	if d4.Device != "192.0.2.10" || d4.Total != 33 || d4.ByResult[ResultAnswered] != 31 || d4.ByResult[ResultNoAnswer] != 1 || d4.ByResult[ResultNoAnswerSlow] != 1 ||
		d4.MAC != "02:00:00:00:00:02" || len(d4.MACs) != 2 || d4.NoMAC != 1 || d4.DistinctNames != 6 || len(d4.TopNames) != 6 || d4.TopNames[0].Count != 10 ||
		d4.ByGroup["default"] != 31 || !d4.FirstSeen.Equal(t0) {
		t.Fatalf("%+v", d4)
	}
	if s2, _ := j.Summary(SummaryQuery{From: t0.Add(33 * time.Second).Format(time.RFC3339)}); len(s2.Devices) != 1 {
		t.Fatalf("%+v", s2)
	}
	if _, err := j.Summary(SummaryQuery{From: "x"}); err == nil {
		t.Fatal("bad range accepted")
	}
}

func TestSummaryBounds(t *testing.T) {
	c := newClock()
	j := openTest(t, Config{Now: c.Now})
	for i := 0; i < SummaryDevices+20; i++ {
		j.Add(rec(c.Now(), netip.AddrFrom4([4]byte{192, 0, 2, byte(i)}).String(), "many.example.test"))
		c.Add(time.Second)
	}
	for i := 0; i < summaryNameTrack+50; i++ {
		r := rec(c.Now(), "198.51.100.7", fmt.Sprintf("n%d.example.test", i))
		r.Group = fmt.Sprintf("g_%d", i%(SummaryGroups+5))
		j.Add(r)
	}
	j.Flush()
	sum, err := j.Summary(SummaryQuery{})
	if err != nil || !sum.Truncated || len(sum.Devices) != SummaryDevices {
		t.Fatalf("%v %d %v", err, len(sum.Devices), sum.Truncated)
	}
	d := sum.Devices[0]
	if d.Device != "198.51.100.7" || len(d.TopNames) != SummaryNames || d.DistinctNames != summaryNameTrack || !d.NamesTruncated || len(d.ByGroup) != SummaryGroups || d.OtherGroups == 0 {
		t.Fatalf("%+v", d)
	}
	b, _ := json.Marshal(sum)
	if len(b) > 1<<20 {
		t.Fatalf("summary is %d bytes", len(b))
	}
}

func TestSplitBudget(t *testing.T) {
	b := SplitBudget(0, 0)
	if b.Total != 32<<20 || b.Raw != 8<<20 || b.Queue != 2<<20 || b.Journal != 22<<20 || b.Raw+b.Queue+b.Journal != b.Total {
		t.Fatalf("%+v", b)
	}
	// The resolver's own rotation settings stay inside the raw share even
	// when the audit file overshoots by half and a rotated copy does not
	// compress at all.
	if worst := int64(AuditSizeKB) << 10 * 3 / 2 * int64(1+AuditNum); worst > b.Raw {
		t.Fatalf("audit-size %dk x (1+%d) with 50%% overshoot is %d, over the raw share %d", AuditSizeKB, AuditNum, worst, b.Raw)
	}
}

// --------------------------------------------------- clear: injected faults ---

// fsFault makes one kind of file-system call of a clear fail while it is on:
// op on a path containing part. The error it gives carries the path, as the
// system's would, so a test can see that none of it gets out.
type fsFault struct {
	mu   sync.Mutex
	on   bool
	op   string
	part string
	err  error
	hits int
}

func newFault(op, part string, err error) *fsFault {
	return &fsFault{on: true, op: op, part: part, err: err}
}

func (f *fsFault) set(on bool) {
	f.mu.Lock()
	f.on = on
	f.mu.Unlock()
}

func (f *fsFault) check(op, path string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if !f.on || op != f.op || !strings.Contains(path, f.part) {
		return nil
	}
	f.hits++
	return &os.PathError{Op: op, Path: path, Err: f.err}
}

// faultsOf is the Fault of several fsFaults.
func faultsOf(fs ...*fsFault) Fault {
	return func(op, path string) error {
		for _, f := range fs {
			if err := f.check(op, path); err != nil {
				return err
			}
		}
		return nil
	}
}

// segFiles lists the segment files of dir.
func segFiles(t *testing.T, dir string) []string {
	t.Helper()
	ents, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, e := range ents {
		if segNameRe.MatchString(e.Name()) {
			out = append(out, e.Name())
		}
	}
	return out
}

func hasMark(dir string) bool {
	_, err := os.Stat(filepath.Join(dir, clearMarkFile))
	return err == nil
}

// A clear whose unlink fails for one segment says so, keeps that segment
// indexed and queryable, removes only what it really deleted, and the same
// clear asked again finishes the job.
func TestJournalClearKeepsWhatItCouldNotDelete(t *testing.T) {
	c := newClock()
	dir := filepath.Join(t.TempDir(), "journal")
	stuck := newFault("remove", segName(11), syscall.EACCES)
	j := openTest(t, Config{Dir: dir, MaxRecords: 80, Now: c.Now, Fault: faultsOf(stuck)})
	for i := 0; i < 35; i++ {
		j.Add(rec(c.Now(), "192.0.2.10", fmt.Sprintf("n%d.example.test", i)))
	}
	j.Flush()
	if got := segFiles(t, dir); len(got) != 4 {
		t.Fatalf("segments %v", got)
	}

	rep := j.Clear()
	if rep.Cleared != 25 || rep.Residual == nil || rep.Residual.Segments != 1 || rep.Residual.Records != 10 || rep.Residual.Bytes == 0 || rep.Residual.ClearAt == nil {
		t.Fatalf("%+v %+v", rep, rep.Residual)
	}
	if len(rep.Errors) != 1 || rep.Errors[0] != (ClearError{Part: PartJournal, Op: "remove", Cause: "permission", Count: 1}) {
		t.Fatalf("errors %+v", rep.Errors)
	}
	if b, _ := json.Marshal(rep); bytes.Contains(b, []byte(dir)) || bytes.Contains(b, []byte("dns-")) || bytes.Contains(b, []byte("denied")) {
		t.Fatalf("the report carries a path, a file name or the system's text: %s", b)
	}
	// Only the deleted segments left the disk and the index.
	if got := segFiles(t, dir); len(got) != 1 || got[0] != segName(11) {
		t.Fatalf("on disk %v", got)
	}
	st := j.Stats()
	if st.Records != 10 || st.Segments != 1 || st.Residual == nil || st.Residual.Records != 10 || st.ClearedAt != nil {
		t.Fatalf("%+v %+v", st, st.Residual)
	}
	p, _ := j.Query(Query{})
	if p.Matched != 10 || p.Records[0].Name != "n19.example.test" {
		t.Fatalf("the residue is not queryable: %d %+v", p.Matched, p.Records)
	}
	if !hasMark(dir) {
		t.Fatal("no clear mark")
	}

	// Writing goes on next to the residue; ids go on.
	c.Add(time.Second)
	for i := 0; i < 3; i++ {
		j.Add(rec(c.Now(), "192.0.2.11", fmt.Sprintf("new%d.example.test", i)))
	}
	j.Flush()
	if p, _ = j.Query(Query{}); p.Matched != 13 || p.Records[0].Name != "new2.example.test" || p.Records[0].ID != 38 || p.Records[3].Name != "n19.example.test" {
		t.Fatalf("%d %+v", p.Matched, p.Records[:4])
	}

	// Asked again while the fault lasts: the new records go, the residue
	// stays known.
	if rep = j.Clear(); rep.Cleared != 3 || rep.Residual == nil || rep.Residual.Records != 10 || len(rep.Errors) != 1 {
		t.Fatalf("%+v", rep)
	}
	if st = j.Stats(); st.Records != 10 || st.Residual == nil {
		t.Fatalf("%+v", st)
	}

	// The fault is gone: the retry completes.
	stuck.set(false)
	if rep = j.Clear(); rep.Cleared != 10 || rep.Residual != nil || rep.Errors != nil {
		t.Fatalf("%+v", rep)
	}
	if st = j.Stats(); st.Records != 0 || st.Segments != 0 || st.Residual != nil || st.ClearedAt == nil {
		t.Fatalf("%+v", st)
	}
	if got := segFiles(t, dir); len(got) != 0 || hasMark(dir) {
		t.Fatalf("left on disk: %v, mark %v", got, hasMark(dir))
	}
	j.Add(rec(c.Now(), "192.0.2.10", "again.example.test"))
	j.Flush()
	if p, _ = j.Query(Query{}); p.Matched != 1 || p.Records[0].ID != 39 {
		t.Fatalf("%+v", p.Records)
	}
}

// What a clear could not delete is still known as residue after a restart
// (not mistaken for records written since), and the retry then succeeds.
func TestJournalClearResidueSurvivesRestart(t *testing.T) {
	c := newClock()
	dir := filepath.Join(t.TempDir(), "journal")
	stuck := newFault("remove", ".jsonl", syscall.EROFS)
	j, err := Open(Config{Dir: dir, MaxRecords: 80, Now: c.Now, Fault: faultsOf(stuck)})
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 25; i++ {
		j.Add(rec(c.Now(), "192.0.2.10", fmt.Sprintf("n%d.example.test", i)))
	}
	j.Flush()
	rep := j.Clear()
	if rep.Cleared != 0 || rep.Residual == nil || rep.Residual.Segments != 3 || rep.Residual.Records != 25 ||
		len(rep.Errors) != 1 || rep.Errors[0] != (ClearError{Part: PartJournal, Op: "remove", Cause: "read_only", Count: 3}) {
		t.Fatalf("%+v %+v", rep, rep.Residual)
	}
	asked := *rep.Residual.ClearAt
	// A record written after the failed clear is not residue.
	c.Add(time.Minute)
	j.Add(rec(c.Now(), "192.0.2.11", "later.example.test"))
	j.Flush()
	j.Close()

	// Restart, twice: the residue is the same three segments each time.
	for round := 0; round < 2; round++ {
		j, err = Open(Config{Dir: dir, MaxRecords: 80, Now: c.Now})
		if err != nil {
			t.Fatal(err)
		}
		st := j.Stats()
		if st.Records != 26 || st.Residual == nil || st.Residual.Segments != 3 || st.Residual.Records != 25 || st.Residual.ClearAt == nil || !st.Residual.ClearAt.Equal(asked) {
			t.Fatalf("round %d: %+v %+v", round, st, st.Residual)
		}
		if p, _ := j.Query(Query{Text: "later"}); p.Matched != 1 {
			t.Fatalf("round %d: %d", round, p.Matched)
		}
		if round == 0 {
			j.Close()
		}
	}
	defer j.Close()
	// The pruning tick leaves a clear's residue to the next clear (it is
	// not older than the age bound).
	j.mu.Lock()
	j.retryStuck(false)
	j.mu.Unlock()
	if st := j.Stats(); st.Residual == nil || st.Residual.Segments != 3 {
		t.Fatalf("the tick removed a clear's residue: %+v", st)
	}
	if rep = j.Clear(); rep.Cleared != 26 || rep.Residual != nil || rep.Errors != nil {
		t.Fatalf("retry after the restart: %+v", rep)
	}
	if got := segFiles(t, dir); len(got) != 0 || hasMark(dir) {
		t.Fatalf("left on disk: %v, mark %v", got, hasMark(dir))
	}
	// Ids do not go back below the cleared ones.
	j.Add(rec(c.Now(), "192.0.2.10", "again.example.test"))
	j.Flush()
	if p, _ := j.Query(Query{}); p.Matched != 1 || p.Records[0].ID != 27 {
		t.Fatalf("%+v", p.Records)
	}
}

// A bound whose unlink fails does not forget the segment either: it stays
// indexed (nothing on disk is untracked), is not called a clear's residue,
// and is deleted by the pruning tick once the fault is gone.
func TestJournalBoundKeepsUndeletableSegment(t *testing.T) {
	c := newClock()
	dir := filepath.Join(t.TempDir(), "journal")
	stuck := newFault("remove", ".jsonl", syscall.EBUSY)
	j := openTest(t, Config{Dir: dir, MaxRecords: 80, Now: c.Now, Fault: faultsOf(stuck)})
	for i := 0; i < 200; i++ {
		j.Add(rec(c.Now(), "192.0.2.10", fmt.Sprintf("n%d.example.test", i)))
	}
	j.Flush()
	st := j.Stats()
	if st.Residual == nil || st.Residual.Segments == 0 || st.Residual.ClearAt != nil || hasMark(dir) {
		t.Fatalf("%+v %+v", st, st.Residual)
	}
	if got := segFiles(t, dir); len(got) != st.Segments {
		t.Fatalf("%d files on disk, %d indexed", len(got), st.Segments)
	}
	// The record bound still holds for what a query shows.
	if p, _ := j.Query(Query{}); p.Matched > 80 || p.Records[0].Name != "n199.example.test" {
		t.Fatalf("%d", p.Matched)
	}
	stuck.set(false)
	j.mu.Lock()
	j.retryStuck(false)
	j.mu.Unlock()
	st = j.Stats()
	if st.Residual != nil || st.Records > 80 {
		t.Fatalf("%+v", st)
	}
	if got := segFiles(t, dir); len(got) != st.Segments {
		t.Fatalf("%d files on disk, %d indexed", len(got), st.Segments)
	}
}

// What was queued before a clear is not written after it: the clear runs
// in the writer and takes the queue with it.
func TestJournalClearTakesTheQueue(t *testing.T) {
	c := newClock()
	dir := filepath.Join(t.TempDir(), "journal")
	j := openTest(t, Config{Dir: dir, Now: c.Now})
	block := make(chan struct{})
	entered := make(chan struct{}, 1)
	var once sync.Once
	j.testHookWrite = func() {
		once.Do(func() {
			entered <- struct{}{}
			<-block
		})
	}
	j.Add(rec(c.Now(), "192.0.2.10", "first.example.test"))
	<-entered // the writer holds the first record and waits
	for i := 0; i < 50; i++ {
		j.Add(rec(c.Now(), "192.0.2.10", fmt.Sprintf("queued%d.example.test", i)))
	}
	done := make(chan ClearReport, 1)
	go func() { done <- j.Clear() }()
	time.Sleep(50 * time.Millisecond)
	close(block)
	rep := <-done
	if rep.Residual != nil || rep.Errors != nil {
		t.Fatalf("%+v", rep)
	}
	j.Flush()
	if st := j.Stats(); st.Records != 0 || st.Dropped != 0 {
		t.Fatalf("records written after the clear: %+v", st)
	}
	if _, _, lines := diskUse(t, dir); lines != 0 {
		t.Fatalf("%d lines on disk after the clear", lines)
	}
}

// A segment file that appeared behind the index's back is swept by the
// clear; when it cannot be deleted it is residue (counted, marked, known
// after a restart), and a later clear removes it.
func TestJournalClearSweepsUntrackedSegments(t *testing.T) {
	c := newClock()
	dir := filepath.Join(t.TempDir(), "journal")
	stray := segName(900)
	stuck := newFault("remove", stray, syscall.EBUSY)
	j := openTest(t, Config{Dir: dir, MaxRecords: 80, Now: c.Now, Fault: faultsOf(stuck)})
	for i := 0; i < 5; i++ {
		j.Add(rec(c.Now(), "192.0.2.10", fmt.Sprintf("n%d.example.test", i)))
	}
	j.Flush()
	// Copy a real segment under a name the index does not know.
	src := filepath.Join(dir, segFiles(t, dir)[0])
	b, err := os.ReadFile(src)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, stray), b, 0o600); err != nil {
		t.Fatal(err)
	}
	rep := j.Clear()
	if rep.Cleared != 5 || rep.Residual == nil || rep.Residual.Segments != 1 || rep.Residual.Records != 5 || rep.Residual.ClearAt == nil || rep.Unknown {
		t.Fatalf("%+v %+v", rep, rep.Residual)
	}
	if len(rep.Errors) != 1 || rep.Errors[0] != (ClearError{Part: PartJournal, Op: "remove", Cause: "busy", Count: 1}) {
		t.Fatalf("errors %+v", rep.Errors)
	}
	if !hasMark(dir) {
		t.Fatal("no clear mark for the stray segment")
	}
	j.Close()
	j2 := openTest(t, Config{Dir: dir, MaxRecords: 80, Now: c.Now, Fault: faultsOf(stuck)})
	if st := j2.Stats(); st.Residual == nil || st.Residual.Segments != 1 || st.Residual.ClearAt == nil {
		t.Fatalf("after restart: %+v %+v", st, st.Residual)
	}
	stuck.set(false)
	if rep = j2.Clear(); rep.Residual != nil || rep.Errors != nil || rep.Unknown {
		t.Fatalf("%+v", rep)
	}
	if got := segFiles(t, dir); len(got) != 0 || hasMark(dir) {
		t.Fatalf("left: %v mark %v", got, hasMark(dir))
	}
}

// A clear that cannot read its directory afterwards, or cannot write the
// mark that names its residue, never says it is complete.
func TestJournalClearReportsReaddirAndMarkFailures(t *testing.T) {
	c := newClock()
	dir := filepath.Join(t.TempDir(), "journal")
	rd := newFault("readdir", "journal", syscall.EIO)
	j := openTest(t, Config{Dir: dir, MaxRecords: 80, Now: c.Now, Fault: faultsOf(rd)})
	j.Add(rec(c.Now(), "192.0.2.10", "a.example.test"))
	j.Flush()
	rep := j.Clear()
	if !rep.Unknown || len(rep.Errors) != 1 || rep.Errors[0].Op != "readdir" || rep.Errors[0].Cause != "io" {
		t.Fatalf("%+v", rep)
	}
	rd.set(false)

	stuck := newFault("remove", segPrefix, syscall.EACCES)
	mark := newFault("write", clearMarkFile, syscall.EROFS)
	dir2 := filepath.Join(t.TempDir(), "journal")
	j2 := openTest(t, Config{Dir: dir2, MaxRecords: 80, Now: c.Now, Fault: faultsOf(stuck, mark)})
	j2.Add(rec(c.Now(), "192.0.2.10", "b.example.test"))
	j2.Flush()
	rep = j2.Clear()
	ops := map[string]bool{}
	for _, e := range rep.Errors {
		ops[e.Op] = true
	}
	if rep.Residual == nil || !ops["remove"] || !ops["write"] {
		t.Fatalf("%+v %+v", rep, rep.Residual)
	}
	res := ClearResult{Errors: rep.Errors}
	if p := res.Problem(); !strings.Contains(p, "清除标记写入失败") {
		t.Fatalf("problem %q", p)
	}
}
